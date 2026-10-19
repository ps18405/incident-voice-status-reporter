"""Complete Pytest Suite for Incident Voice Status Reporter.
Covers:
1. TC1 Status update: voice brief begins with timestamp, every claim contains signal/dashboard ID, state is DEGRADED when error rate > 1% with fresh signals.
2. TC2 Cached dashboard: with a cached signal, state is UNCERTAIN and the brief contains "not proof of recovery".
3. TC3 Customer data in logs: fake emails, phone numbers and card numbers are replaced by [REDACTED_*] tokens in evidence, voice brief, proposed post, and stored database rows. Assert no raw PII appears anywhere.
4. TC4 Health check failing: metrics look healthy (0.2% errors) but probe fails, state is UNCERTAIN and brief says recovery uncertain.
5. Missing evidence: when a required signal is missing, state is UNCERTAIN.
6. Approval gate: posting without approval is rejected, and a rejected update posts nothing.
7. Idempotency: approving and retrying the same message creates exactly one post.
8. Verification: verification result matches approved text, every claim links to a real signal ID, and a failed or pending check stays visible.
9. API smoke test: starts FastAPI app with TestClient and exercises main endpoints.
"""
from __future__ import annotations

import json
import re
from typing import List
import pytest
from fastapi.testclient import TestClient

from app.brief import build_voice_brief_and_post
from app.channel import (
    ChannelPostRequest,
    fetch_channel_feed,
    process_channel_approval_and_post,
    reset_mock_channel,
)
from app.collector import IncidentInput, SignalCollectionResult, SignalModel, collect_signals
from app.db import get_all_posts, get_connection, init_db
from app.main import app
from app.redact import scan_for_unredacted_pii
from app.rules import evaluate_decision_rules
from app.verify import run_post_verification


# ---------------------------------------------------------------------------
# 1. TC1 Status update
# ---------------------------------------------------------------------------
def test_tc1_status_update():
    """TC1 Status update:
    - the voice brief begins with a timestamp
    - every claim contains a signal/dashboard ID
    - state is DEGRADED when error rate > 1% with fresh signals.
    """
    inp = IncidentInput(
        incident_id="INC-TC1-PROD",
        scope="Checkout service experiencing 500 error cascade across US-East",
        dashboards=["https://grafana.internal.mock/d/checkout-metrics"],
        scenario_id="TC1",
    )
    # Collect signals and run rules
    collection = collect_signals(inp)
    decision = evaluate_decision_rules(collection)
    brief = build_voice_brief_and_post(collection, decision)

    # 1. Voice brief begins with a timestamp
    timestamp_pattern = r"^At \d{2}:\d{2}:\d{2} UTC"
    assert re.match(timestamp_pattern, brief.voice_script), (
        f"Voice brief does not begin with a timestamp. Got: {brief.voice_script[:50]}"
    )

    # 2. Every claim contains a signal/dashboard ID
    assert len(brief.claims) > 0
    signal_pattern = re.compile(r"\[SIG-[A-Z0-9-]+\]")
    for clm in brief.claims:
        assert clm.signal_id.startswith("SIG-"), f"Claim missing signal_id: {clm}"
        assert f"[{clm.signal_id}]" in clm.claim_text, f"Claim text does not cite signal ID: {clm.claim_text}"
        assert signal_pattern.search(clm.claim_text), f"No [SIG-xxx] pattern in claim text: {clm.claim_text}"

    # Also verify proposed channel post contains citations for every signal
    for clm in brief.claims:
        assert f"[{clm.signal_id}]" in brief.proposed_channel_post

    # 3. State is DEGRADED when error rate > 1% with fresh signals
    error_signal = next(s for s in collection.signals if "err" in s.signal_id.lower() or "error" in s.name.lower())
    error_val = float(error_signal.value.replace("%", "").strip())
    assert error_val > 1.0, f"Error rate should be > 1.0%, got {error_val}"
    assert not error_signal.is_cached, "Signal should be fresh, not cached"
    assert not error_signal.is_stale, "Signal should be fresh, not stale"
    assert decision.status == "DEGRADED", f"Expected DEGRADED status, got {decision.status}"


# ---------------------------------------------------------------------------
# 2. TC2 Cached dashboard
# ---------------------------------------------------------------------------
def test_tc2_cached_dashboard():
    """TC2 Cached dashboard:
    - with a cached signal, state is UNCERTAIN
    - the brief contains 'not proof of recovery'.
    """
    inp = IncidentInput(
        incident_id="INC-TC2-CACHE",
        scope="Evaluating recovery claims for checkout gateway after proxy restart",
        dashboards=["https://grafana.internal.mock/d/checkout-metrics"],
        scenario_id="TC2",
    )
    collection = collect_signals(inp)
    assert any(s.is_cached for s in collection.signals), "TC2 must contain at least one cached signal"

    decision = evaluate_decision_rules(collection)
    brief = build_voice_brief_and_post(collection, decision)

    # State is UNCERTAIN
    assert decision.status == "UNCERTAIN", f"Expected UNCERTAIN status, got {decision.status}"
    assert decision.cached_warning is True

    # Brief contains "not proof of recovery"
    assert "not proof of recovery" in brief.voice_script.lower(), (
        f"Voice brief does not contain 'not proof of recovery'. Text: {brief.voice_script}"
    )
    assert "not proof of recovery" in brief.proposed_channel_post.lower(), (
        f"Proposed post does not contain 'not proof of recovery'. Text: {brief.proposed_channel_post}"
    )


# ---------------------------------------------------------------------------
# 3. TC3 Customer data in logs
# ---------------------------------------------------------------------------
def test_tc3_customer_data_in_logs():
    """TC3 Customer data in logs:
    - fake emails, phone numbers and a card number are replaced by [REDACTED_*] tokens
      in the evidence, voice brief, proposed post and stored database rows.
    - assert no raw PII string appears anywhere.
    """
    raw_pii_strings = [
        "sarah.connor@cyberdyne.io",
        "+1-555-019-2834",
        "4532-8901-2345-6789",
        "john.doe@example.com",
        "555-432-8765",
        "5424-0000-1234-5678",
    ]

    inp = IncidentInput(
        incident_id="INC-TC3-PII",
        scope="Investigating payment failure log traces with customer account reports",
        dashboards=["https://logs.internal.mock/explorer"],
        scenario_id="TC3",
    )
    collection = collect_signals(inp, save_to_db=True)
    decision = evaluate_decision_rules(collection, save_to_db=True)
    brief = build_voice_brief_and_post(collection, decision)

    # 1. Assert [REDACTED_*] tokens are present in evidence, voice brief, and proposed post
    evidence_text = json.dumps([s.model_dump() for s in collection.signals])
    assert "[REDACTED_EMAIL]" in evidence_text
    assert "[REDACTED_PHONE]" in evidence_text
    assert "[REDACTED_CARD]" in evidence_text

    assert "[REDACTED_EMAIL]" in brief.proposed_channel_post
    assert "[REDACTED_PHONE]" in brief.proposed_channel_post
    assert "[REDACTED_CARD]" in brief.proposed_channel_post

    # 2. Inspect stored database rows
    conn = get_connection()
    cursor = conn.cursor()

    signals_rows = cursor.execute("SELECT * FROM signals WHERE incident_id = ?", (inp.incident_id,)).fetchall()
    decisions_rows = cursor.execute("SELECT * FROM decisions WHERE incident_id = ?", (inp.incident_id,)).fetchall()
    incidents_rows = cursor.execute("SELECT * FROM incidents WHERE id = ?", (inp.incident_id,)).fetchall()
    conn.close()

    assert len(signals_rows) > 0
    assert len(decisions_rows) > 0
    assert len(incidents_rows) > 0

    all_db_text = ""
    for r in signals_rows:
        all_db_text += " " + " ".join(str(val) for val in dict(r).values())
    for r in decisions_rows:
        all_db_text += " " + " ".join(str(val) for val in dict(r).values())
    for r in incidents_rows:
        all_db_text += " " + " ".join(str(val) for val in dict(r).values())

    # [REDACTED_*] tokens must exist in stored rows
    assert "[REDACTED_EMAIL]" in all_db_text
    assert "[REDACTED_PHONE]" in all_db_text
    assert "[REDACTED_CARD]" in all_db_text

    # 3. Assert NO raw PII string appears anywhere:
    combined_surfaces = (
        evidence_text
        + " "
        + brief.voice_script
        + " "
        + brief.proposed_channel_post
        + " "
        + all_db_text
    )

    for pii in raw_pii_strings:
        assert pii not in combined_surfaces, f"Raw PII string '{pii}' leaked in system output or database!"

    # Also run independent PII scanner
    violations = scan_for_unredacted_pii(brief.proposed_channel_post)
    assert len(violations) == 0, f"PII scanner detected leaks in proposed post: {violations}"


# ---------------------------------------------------------------------------
# 4. TC4 Health check failing
# ---------------------------------------------------------------------------
def test_tc4_health_check_failing():
    """TC4 Health check failing:
    - metrics look healthy (e.g. 0.2% errors) but the health probe fails
    - so state is UNCERTAIN and the brief says recovery uncertain.
    """
    inp = IncidentInput(
        incident_id="INC-TC4-PROBE",
        scope="Post-failover check: Metrics are low but probe is failing",
        dashboards=["https://grafana.internal.mock/d/checkout-metrics", "https://api.internal.mock/health/db"],
        scenario_id="TC4",
    )
    collection = collect_signals(inp)

    # Metrics look healthy
    err_signal = next(s for s in collection.signals if "err" in s.signal_id.lower() or "error" in s.name.lower())
    assert float(err_signal.value.replace("%", "").strip()) <= 1.0

    # Probe fails
    hlth_signal = next(s for s in collection.signals if s.source_type == "health_check")
    assert "failing" in hlth_signal.value.lower() or "503" in hlth_signal.value

    decision = evaluate_decision_rules(collection)
    brief = build_voice_brief_and_post(collection, decision)

    # State is UNCERTAIN
    assert decision.status == "UNCERTAIN", f"Expected UNCERTAIN status, got {decision.status}"
    assert decision.recovery_uncertain_warning is True

    # Brief says "recovery uncertain"
    assert "recovery uncertain" in brief.voice_script.lower(), (
        f"Voice brief does not contain 'recovery uncertain'. Text: {brief.voice_script}"
    )
    assert "recovery uncertain" in brief.proposed_channel_post.lower(), (
        f"Proposed post does not contain 'recovery uncertain'. Text: {brief.proposed_channel_post}"
    )


# ---------------------------------------------------------------------------
# 5. Missing evidence
# ---------------------------------------------------------------------------
def test_missing_evidence():
    """Missing evidence:
    - when a required signal is missing, state is UNCERTAIN.
    """
    # Create collection where health_check probe is completely missing
    partial_collection = SignalCollectionResult(
        incident_id="INC-MISSING-TEST",
        scope="Testing behavior when critical telemetry probes are absent",
        dashboards=["https://grafana.internal.mock/d/checkout-metrics"],
        signals=[
            SignalModel(
                signal_id="SIG-METRIC-ERR",
                source_type="metric",
                name="Error Rate",
                url="https://grafana.internal.mock/d/checkout",
                value="0.1",
                unit="%",
                source_updated_at="2026-10-19T10:00:00Z",
                retrieved_at="2026-10-19T10:00:10Z",
                age_seconds=10.0,
                is_cached=False,
                is_stale=False,
            )
            # No health_check signals!
        ],
        retrieved_at="2026-10-19T10:00:10Z",
        total_signals=1,
        stale_count=0,
        cached_count=0,
        redactions_count=0,
    )

    decision = evaluate_decision_rules(partial_collection, save_to_db=False)

    assert decision.status == "UNCERTAIN", f"Expected UNCERTAIN status when health check missing, got {decision.status}"
    assert decision.uncertainty_flag is True
    assert "missing" in decision.reason.lower()
    assert "never guessing" in decision.reason.lower()

    # Also test when metric signals are missing
    health_only_collection = SignalCollectionResult(
        incident_id="INC-MISSING-METRIC",
        scope="Testing behavior when metric dashboard is absent",
        dashboards=["https://api.internal.mock/health"],
        signals=[
            SignalModel(
                signal_id="SIG-HLTH-01",
                source_type="health_check",
                name="Health Probe",
                url="https://api.internal.mock/health",
                value="Passing (200 OK)",
                unit="probe",
                source_updated_at="2026-10-19T10:00:00Z",
                retrieved_at="2026-10-19T10:00:10Z",
                age_seconds=10.0,
                is_cached=False,
                is_stale=False,
            )
        ],
        retrieved_at="2026-10-19T10:00:10Z",
        total_signals=1,
        stale_count=0,
        cached_count=0,
        redactions_count=0,
    )

    decision_metric = evaluate_decision_rules(health_only_collection, save_to_db=False)
    assert decision_metric.status == "UNCERTAIN"
    assert decision_metric.uncertainty_flag is True


# ---------------------------------------------------------------------------
# 6. Approval gate
# ---------------------------------------------------------------------------
def test_approval_gate():
    """Approval gate:
    - posting without approval is rejected, and a rejected update posts nothing.
    """
    incident_id = "INC-GATE-TEST"
    proposed_message = "🚨 INCIDENT UPDATE: Investigating checkout degradation."

    # 1. Reject update
    reject_req = ChannelPostRequest(
        incident_id=incident_id,
        destination="#incident-response",
        message=proposed_message,
        approval_decision="REJECTED",
    )
    res = process_channel_approval_and_post(reject_req)

    # Assert rejected
    assert res.success is False
    assert res.status == "REJECTED"
    assert res.post_id is None
    assert "rejected" in res.message.lower()

    # Assert rejected update posts nothing to the channel
    all_posts = get_all_posts()
    incident_posts = [p for p in all_posts if p["incident_id"] == incident_id]
    assert len(incident_posts) == 0, f"Expected 0 posts in channel, found: {incident_posts}"

    # Independent verification on an unapproved/unposted incident must fail
    verif = run_post_verification(incident_id, proposed_message)
    assert verif.overall_status == "FAIL"
    assert any(c.name == "Post Existence in Channel" and c.status == "FAIL" for c in verif.checks)


# ---------------------------------------------------------------------------
# 7. Idempotency
# ---------------------------------------------------------------------------
def test_idempotency():
    """Idempotency:
    - approving and retrying the same message creates exactly one post.
    """
    incident_id = "INC-IDEMPOTENCY-TEST"
    message = "📢 INCIDENT UPDATE: Core database restored and verified [SIG-METRIC-ERR]."

    approve_req = ChannelPostRequest(
        incident_id=incident_id,
        destination="#incident-response",
        message=message,
        approval_decision="APPROVED",
    )

    # 1. First execution
    res1 = process_channel_approval_and_post(approve_req)
    assert res1.success is True
    assert res1.status == "POSTED"
    assert res1.post_id is not None
    assert res1.is_duplicate is False

    # 2. Retry exact same message
    res2 = process_channel_approval_and_post(approve_req)
    assert res2.success is True
    assert res2.status == "DUPLICATE_IGNORED"
    assert res2.is_duplicate is True
    assert res2.post_id == res1.post_id

    # 3. Third retry
    res3 = process_channel_approval_and_post(approve_req)
    assert res3.success is True
    assert res3.status == "DUPLICATE_IGNORED"
    assert res3.is_duplicate is True
    assert res3.post_id == res1.post_id

    # Check database: exactly one post must exist
    all_posts = get_all_posts()
    matching_posts = [p for p in all_posts if p["incident_id"] == incident_id]
    assert len(matching_posts) == 1, f"Expected exactly 1 post in channel, found {len(matching_posts)}"


# ---------------------------------------------------------------------------
# 8. Verification
# ---------------------------------------------------------------------------
def test_verification():
    """Verification:
    - the verification result matches the approved text
    - every claim links to a real signal ID
    - a failed or pending check stays visible.
    """
    inp = IncidentInput(
        incident_id="INC-VERIF-TEST",
        scope="End-to-end verification of checkout status reporting",
        dashboards=["https://grafana.internal.mock/d/checkout-metrics"],
        scenario_id="TC1",
    )
    collection = collect_signals(inp, save_to_db=True)
    decision = evaluate_decision_rules(collection, save_to_db=True)
    brief = build_voice_brief_and_post(collection, decision)

    # Approve and publish
    approve_req = ChannelPostRequest(
        incident_id=inp.incident_id,
        destination="#incident-response",
        message=brief.proposed_channel_post,
        approval_decision="APPROVED",
    )
    post_res = process_channel_approval_and_post(approve_req)
    assert post_res.success is True

    # 1. Run independent verification on clean approved post
    report_pass = run_post_verification(inp.incident_id, brief.proposed_channel_post, post_res.post_id)
    assert report_pass.overall_status == "PASS"

    # Matches approved text
    fidelity_check = next(c for c in report_pass.checks if c.name == "Content Fidelity to Approved Version")
    assert fidelity_check.status == "PASS"
    assert "exact match" in fidelity_check.observed.lower()

    # Every claim links to a real signal ID
    link_check = next(c for c in report_pass.checks if c.name == "Claims Linked to Dashboard IDs")
    assert link_check.status == "PASS"
    assert "verified" in link_check.observed.lower()

    # 2. Failed check stays visible when text is altered
    tampered_text = brief.proposed_channel_post + "\n[UNAUTHORIZED_MODIFICATION]"
    report_tampered = run_post_verification(inp.incident_id, tampered_text, post_res.post_id)
    assert report_tampered.overall_status == "FAIL"

    failed_fidelity = next(c for c in report_tampered.checks if c.name == "Content Fidelity to Approved Version")
    assert failed_fidelity.status == "FAIL"
    assert "Mismatch detected" in failed_fidelity.observed
    assert failed_fidelity in report_tampered.checks  # Check stays visible

    # 3. Failed check stays visible when post does not exist
    report_missing_post = run_post_verification("INC-GHOST-ID", "some text")
    assert report_missing_post.overall_status == "FAIL"
    missing_post_check = next(c for c in report_missing_post.checks if c.name == "Post Existence in Channel")
    assert missing_post_check.status == "FAIL"
    assert "No post found" in missing_post_check.observed


# ---------------------------------------------------------------------------
# 9. API smoke test
# ---------------------------------------------------------------------------
def test_api_smoke_test(client: TestClient):
    """API smoke test:
    - start the FastAPI app with TestClient and exercise the main endpoints.
    """
    # 1. Root HTML endpoint
    res_root = client.get("/")
    assert res_root.status_code == 200
    assert "Incident Voice Status Reporter" in res_root.text

    # 2. Favicon SVG endpoint
    res_fav = client.get("/favicon.ico")
    assert res_fav.status_code == 200
    assert "image/svg+xml" in res_fav.headers.get("content-type", "")

    # 3. Health check endpoint
    res_health = client.get("/health")
    assert res_health.status_code == 200
    assert res_health.json() == {"status": "ok"}

    # 4. Scenarios listing endpoint
    res_scenarios = client.get("/api/scenarios")
    assert res_scenarios.status_code == 200
    scenarios = res_scenarios.json()
    assert len(scenarios) >= 4
    ids = [s["id"] for s in scenarios]
    assert all(k in ids for k in ["TC1", "TC2", "TC3", "TC4"])

    # 4. Collect and analyze endpoint
    res_analyze = client.post(
        "/api/collect-and-analyze",
        json={
            "incident_id": "INC-SMOKE-01",
            "scope": "Smoke testing API pipeline execution",
            "dashboards": ["https://grafana.internal.mock/d/checkout-metrics"],
            "scenario_id": "TC1",
        },
    )
    assert res_analyze.status_code == 200
    data = res_analyze.json()
    assert data["success"] is True
    assert "collection" in data
    assert "decision" in data
    assert "brief" in data
    proposed_post = data["brief"]["proposed_channel_post"]

    # 5. Channel approval endpoint
    res_approve = client.post(
        "/api/approve",
        json={
            "incident_id": "INC-SMOKE-01",
            "destination": "#incident-response",
            "message": proposed_post,
            "approval_decision": "APPROVED",
        },
    )
    assert res_approve.status_code == 200
    app_data = res_approve.json()
    assert app_data["status"] == "POSTED"
    post_id = app_data["post_id"]

    # 6. Verify endpoint
    res_verify = client.post(
        "/api/verify",
        json={
            "incident_id": "INC-SMOKE-01",
            "approved_text": proposed_post,
            "post_id": post_id,
        },
    )
    assert res_verify.status_code == 200
    assert res_verify.json()["overall_status"] == "PASS"

    # 7. Channel feed endpoint
    res_feed = client.get("/api/channel")
    assert res_feed.status_code == 200
    feed = res_feed.json()
    assert len(feed) >= 1
    assert any(p["incident_id"] == "INC-SMOKE-01" for p in feed)

    # 8. Run official tests endpoint
    res_tests = client.post("/api/run-tests")
    assert res_tests.status_code == 200
    test_results = res_tests.json()["results"]
    assert len(test_results) == 4
    for tr in test_results:
        assert tr["status"] == "PASS"

    # 9. Get test runs endpoint
    res_runs = client.get("/api/test-runs")
    assert res_runs.status_code == 200
    assert len(res_runs.json()) >= 4

    # 10. Channel reset endpoint
    res_reset = client.post("/api/reset-channel")
    assert res_reset.status_code == 200
    assert len(client.get("/api/channel").json()) == 0
