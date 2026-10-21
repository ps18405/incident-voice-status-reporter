"""Unit tests for Decision Rules Engine, Redaction, Idempotency, and Mock Observability Backend."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import pytest
from fastapi.testclient import TestClient

from app.collector import IncidentInput, SignalCollectionResult, SignalModel, collect_signals
from app.rules import evaluate_decision_rules, compute_confidence_breakdown
from app.redact import redact_text, scan_for_unredacted_pii
from app.channel import generate_idempotency_key, MockChannelAdapter
from app.mock_observability import mock_router
from fastapi import FastAPI


def test_rules_engine_stale_data_cannot_prove_recovery():
    """RULE-STALE-01: Stale telemetry older than 300s returns UNCERTAIN."""
    now = datetime.now(timezone.utc)
    signals = [
        SignalModel(
            signal_id="SIG-METRIC-ERR",
            source_type="metric",
            name="Error Rate",
            url="http://mock/error",
            value="0.1%",
            source_updated_at=(now - timedelta(seconds=400)).isoformat(),
            retrieved_at=now.isoformat(),
            age_seconds=400.0,
            is_cached=False,
            is_stale=True,
            evidence_origin="mock_test",
        ),
        SignalModel(
            signal_id="SIG-HLTH-01",
            source_type="health_check",
            name="Health Probe",
            url="http://mock/health",
            value="Passing (200 OK)",
            source_updated_at=now.isoformat(),
            retrieved_at=now.isoformat(),
            age_seconds=10.0,
            is_cached=False,
            is_stale=False,
            evidence_origin="mock_test",
        ),
        SignalModel(
            signal_id="SIG-LOG-01",
            source_type="log",
            name="Logs",
            url="http://mock/logs",
            value="Healthy logs",
            source_updated_at=now.isoformat(),
            retrieved_at=now.isoformat(),
            age_seconds=10.0,
            is_cached=False,
            is_stale=False,
            evidence_origin="mock_test",
        ),
    ]
    col = SignalCollectionResult(
        incident_id="INC-STALE-TEST",
        scope="Evaluating stale recovery",
        dashboards=["http://mock"],
        signals=signals,
        retrieved_at=now.isoformat(),
        total_signals=3,
        stale_count=1,
        cached_count=0,
        redactions_count=0,
    )
    decision = evaluate_decision_rules(col, save_to_db=False)
    assert decision.status == "UNCERTAIN"
    assert decision.uncertainty_flag is True
    fired_ids = [r.rule_id for r in decision.rules_fired]
    assert "RULE-STALE-01" in fired_ids


def test_rules_engine_cached_dashboard_triggers_cached_warning():
    """RULE-CACHED-01: Cached telemetry returns UNCERTAIN with cached_warning=True."""
    now = datetime.now(timezone.utc)
    signals = [
        SignalModel(
            signal_id="SIG-METRIC-ERR",
            source_type="metric",
            name="Error Rate (Edge Cache)",
            url="http://mock/error",
            value="0.05%",
            source_updated_at=now.isoformat(),
            retrieved_at=now.isoformat(),
            age_seconds=10.0,
            is_cached=True,
            is_stale=True,
            evidence_origin="mock_test",
        ),
        SignalModel(
            signal_id="SIG-HLTH-01",
            source_type="health_check",
            name="Health Probe",
            url="http://mock/health",
            value="Passing (200 OK)",
            source_updated_at=now.isoformat(),
            retrieved_at=now.isoformat(),
            age_seconds=10.0,
            is_cached=False,
            is_stale=False,
            evidence_origin="mock_test",
        ),
        SignalModel(
            signal_id="SIG-LOG-01",
            source_type="log",
            name="Logs",
            url="http://mock/logs",
            value="Healthy logs",
            source_updated_at=now.isoformat(),
            retrieved_at=now.isoformat(),
            age_seconds=10.0,
            is_cached=False,
            is_stale=False,
            evidence_origin="mock_test",
        ),
    ]
    col = SignalCollectionResult(
        incident_id="INC-CACHED-TEST",
        scope="Evaluating cached recovery",
        dashboards=["http://mock"],
        signals=signals,
        retrieved_at=now.isoformat(),
        total_signals=3,
        stale_count=1,
        cached_count=1,
        redactions_count=0,
    )
    decision = evaluate_decision_rules(col, save_to_db=False)
    assert decision.status == "UNCERTAIN"
    assert decision.cached_warning is True
    assert "not proof of recovery" in decision.reason.lower()


def test_rules_engine_failing_health_check_forces_uncertain():
    """RULE-HEALTH-FAIL-01: Failing probe overrides green metrics."""
    now = datetime.now(timezone.utc)
    signals = [
        SignalModel(
            signal_id="SIG-METRIC-ERR",
            source_type="metric",
            name="Error Rate",
            url="http://mock/error",
            value="0.1%",
            source_updated_at=now.isoformat(),
            retrieved_at=now.isoformat(),
            age_seconds=10.0,
            is_cached=False,
            is_stale=False,
            evidence_origin="mock_test",
        ),
        SignalModel(
            signal_id="SIG-HLTH-01",
            source_type="health_check",
            name="Database Probe",
            url="http://mock/health",
            value="Failing (500 Internal Server Error)",
            source_updated_at=now.isoformat(),
            retrieved_at=now.isoformat(),
            age_seconds=10.0,
            is_cached=False,
            is_stale=False,
            evidence_origin="mock_test",
            raw_payload={"healthy": False, "status_code": 500},
        ),
        SignalModel(
            signal_id="SIG-LOG-01",
            source_type="log",
            name="Logs",
            url="http://mock/logs",
            value="Connection error",
            source_updated_at=now.isoformat(),
            retrieved_at=now.isoformat(),
            age_seconds=10.0,
            is_cached=False,
            is_stale=False,
            evidence_origin="mock_test",
        ),
    ]
    col = SignalCollectionResult(
        incident_id="INC-HEALTH-TEST",
        scope="Evaluating failing health check",
        dashboards=["http://mock"],
        signals=signals,
        retrieved_at=now.isoformat(),
        total_signals=3,
        stale_count=0,
        cached_count=0,
        redactions_count=0,
    )
    decision = evaluate_decision_rules(col, save_to_db=False)
    assert decision.status == "UNCERTAIN"
    assert decision.recovery_uncertain_warning is True
    assert "recovery uncertain" in decision.reason.lower()


def test_rules_engine_recovery_quorum():
    """RULE-RECOVERY-QUORUM-01: Passing health check + low error rate + fresh data -> RECOVERED."""
    now = datetime.now(timezone.utc)
    signals = [
        SignalModel(
            signal_id="SIG-METRIC-ERR",
            source_type="metric",
            name="Error Rate",
            url="http://mock/error",
            value="0.2%",
            source_updated_at=now.isoformat(),
            retrieved_at=now.isoformat(),
            age_seconds=10.0,
            is_cached=False,
            is_stale=False,
            evidence_origin="mock_test",
        ),
        SignalModel(
            signal_id="SIG-HLTH-01",
            source_type="health_check",
            name="Health Probe",
            url="http://mock/health",
            value="Passing (200 OK)",
            source_updated_at=now.isoformat(),
            retrieved_at=now.isoformat(),
            age_seconds=10.0,
            is_cached=False,
            is_stale=False,
            evidence_origin="mock_test",
            raw_payload={"healthy": True},
        ),
        SignalModel(
            signal_id="SIG-LOG-01",
            source_type="log",
            name="Logs",
            url="http://mock/logs",
            value="All systems normal",
            source_updated_at=now.isoformat(),
            retrieved_at=now.isoformat(),
            age_seconds=10.0,
            is_cached=False,
            is_stale=False,
            evidence_origin="mock_test",
        ),
    ]
    col = SignalCollectionResult(
        incident_id="INC-RECOVERY-TEST",
        scope="Evaluating recovered system",
        dashboards=["http://mock"],
        signals=signals,
        retrieved_at=now.isoformat(),
        total_signals=3,
        stale_count=0,
        cached_count=0,
        redactions_count=0,
    )
    decision = evaluate_decision_rules(col, save_to_db=False)
    assert decision.status == "RECOVERED"
    assert decision.uncertainty_flag is False
    assert decision.severity == "RESOLVED"


def test_confidence_breakdown_metrics():
    """Verify confidence calculation breakdown."""
    now = datetime.now(timezone.utc)
    signals = [
        SignalModel(
            signal_id="SIG-METRIC-ERR",
            source_type="metric",
            name="Error Rate",
            url="http://mock/error",
            value="14.8%",
            source_updated_at=now.isoformat(),
            retrieved_at=now.isoformat(),
            age_seconds=20.0,
            is_cached=False,
            is_stale=False,
        ),
        SignalModel(
            signal_id="SIG-HLTH-01",
            source_type="health_check",
            name="Probe",
            url="http://mock/health",
            value="Passing (200 OK)",
            source_updated_at=now.isoformat(),
            retrieved_at=now.isoformat(),
            age_seconds=20.0,
            is_cached=False,
            is_stale=False,
            raw_payload={"healthy": True},
        ),
    ]
    scores = compute_confidence_breakdown(signals)
    assert "freshness" in scores
    assert "agreement" in scores
    assert "coverage" in scores
    assert "overall" in scores
    assert 0 <= scores["overall"] <= 100


def test_redaction_removes_emails_phones_cards():
    """Verify synthetic customer PII is redacted."""
    raw = "User alice.smith@example.com with phone +1-555-019-2834 paid with card 4532-7100-9281-3049."
    clean, count = redact_text(raw)
    assert "alice.smith@example.com" not in clean
    assert "4532-7100-9281-3049" not in clean
    assert "[REDACTED_EMAIL]" in clean
    assert "[REDACTED_CARD]" in clean
    assert "[REDACTED_PHONE]" in clean
    assert len(scan_for_unredacted_pii(clean)) == 0


def test_idempotency_key_deterministic():
    """Verify deterministic hash for idempotency."""
    key1 = generate_idempotency_key("INC-001", "Service outage resolved.", "#ops")
    key2 = generate_idempotency_key("INC-001", "Service outage resolved.", "#ops")
    key3 = generate_idempotency_key("INC-001", "Different text.", "#ops")
    assert key1 == key2
    assert key1 != key3


def test_mock_observability_endpoints():
    """Verify mock observability backend routes under /mock."""
    app = FastAPI()
    app.include_router(mock_router)
    client = TestClient(app)

    # 1. Grafana dashboard endpoint
    res_grafana = client.get("/mock/grafana/api/dashboards/uid/checkout-metrics?scenario=TC1")
    assert res_grafana.status_code == 200
    assert "panels" in res_grafana.json()["dashboard"]

    # 2. HTML Status page
    res_status = client.get("/mock/status?scenario=TC1")
    assert res_status.status_code == 200
    assert "text/html" in res_status.headers["content-type"]
    assert "MockCloud Platform Status" in res_status.text

    # 3. Logs with synthetic PII
    res_logs = client.get("/mock/logs?service=checkout&scenario=TC3")
    assert res_logs.status_code == 200
    assert "alice.smith@example.com" in res_logs.json()["value"]

    # 4. Health check probe
    res_health_ok = client.get("/mock/health/db?scenario=TC1")
    assert res_health_ok.status_code == 200
    res_health_fail = client.get("/mock/health/db?scenario=TC4")
    assert res_health_fail.status_code == 500
