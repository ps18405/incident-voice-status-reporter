"""API Integration Tests for Incident Voice Status Reporter."""
from __future__ import annotations

import json
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.db import init_db

client = TestClient(app, headers={"Authorization": "Be" + "arer phase7-test-admin"})


def test_root_serves_html():
    response = client.get("/")
    assert response.status_code == 200
    assert "Incident Voice Status Reporter" in response.text


def test_favicon_serves_svg():
    response = client.get("/favicon.ico")
    assert response.status_code == 200
    assert "image/svg+xml" in response.headers.get("content-type", "")


def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_protected_routes_require_valid_operator_and_admin_roles(client, monkeypatch, caplog):
    from fastapi.testclient import TestClient as RawTestClient

    public_client = RawTestClient(app)
    assert public_client.get("/health").status_code == 200
    assert public_client.get("/api/channel").status_code == 401
    assert public_client.get("/api/agent-runs/1").status_code == 401
    assert public_client.get("/api/agent-runs/1/export").status_code == 401
    assert public_client.post("/api/reset-channel").status_code == 401
    assert public_client.post("/api/collect-and-analyze", json={
        "incident_id": "INC-UNAUTH",
        "scope": "Unauthenticated analysis must be blocked",
    }).status_code == 401
    approval_payload = {
        "incident_id": "INC-UNAUTH",
        "destination": "#incident-response",
        "message": "Unapproved",
        "approval_decision": "REJECTED",
        "agent_run_id": 1,
    }
    assert public_client.post("/api/approve", json=approval_payload).status_code == 401
    assert public_client.post("/api/verify", json={
        "incident_id": "INC-UNAUTH",
        "approved_text": "Unapproved",
        "agent_run_id": 1,
    }).status_code == 401
    assert public_client.post("/api/run-tests").status_code == 401
    assert public_client.post("/api/llm-summary-hook", json={"enabled": False}).status_code == 401

    invalid = RawTestClient(
        app, headers={"Authorization": "Be" + "arer invalid-expired-test-token"}
    )
    with caplog.at_level("INFO"):
        invalid_response = invalid.get("/api/channel")
    assert invalid_response.status_code == 401
    assert "invalid-expired-test-token" not in invalid_response.text
    assert "invalid-expired-test-token" not in caplog.text

    operator = RawTestClient(
        app, headers={"Authorization": "Be" + "arer phase7-test-operator"}
    )
    assert operator.get("/api/channel").status_code == 200
    assert operator.post("/api/run-tests").status_code == 403
    assert operator.post("/api/reset-channel").status_code == 403

    monkeypatch.delenv("OPERATOR_TOKEN")
    monkeypatch.delenv("ADMIN_TOKEN")
    not_configured = RawTestClient(app)
    assert not_configured.get("/api/channel").status_code == 503


def test_operator_and_admin_tokens_must_be_distinct(client, monkeypatch):
    from fastapi.testclient import TestClient as RawTestClient

    monkeypatch.setenv("OPERATOR_TOKEN", "same-test-token")
    monkeypatch.setenv("ADMIN_TOKEN", "same-test-token")
    same_token = RawTestClient(
        app, headers={"Authorization": "Be" + "arer same-test-token"}
    )
    response = same_token.post("/api/reset-channel")

    assert response.status_code == 503


def test_operator_identity_is_recorded_for_approval(client):
    from app.db import get_approval_by_agent_run

    analyzed = client.post("/api/collect-and-analyze", json={
        "incident_id": "INC-APPROVER-AUDIT",
        "scope": "Verify authenticated approver audit identity",
        "scenario_id": "TC1",
    }).json()
    response = client.post("/api/approve", json={
        "incident_id": "INC-APPROVER-AUDIT",
        "destination": analyzed["brief"]["destination"],
        "message": analyzed["brief"]["proposed_channel_post"],
        "approval_decision": "APPROVED",
        "agent_run_id": analyzed["agent"]["run_id"],
    })
    assert response.status_code == 200
    approval = get_approval_by_agent_run(analyzed["agent"]["run_id"])
    assert approval["approved_by"] == "admin"




def test_scenarios_list():
    response = client.get("/api/scenarios")
    assert response.status_code == 200
    scenarios = response.json()
    assert len(scenarios) >= 4
    scenario_ids = [s["id"] for s in scenarios]
    assert "TC1" in scenario_ids
    assert "TC2" in scenario_ids
    assert "TC3" in scenario_ids
    assert "TC4" in scenario_ids


def test_collect_and_analyze_tc1():
    payload = {
        "incident_id": "INC-API-01",
        "scope": "Payment cascade failure in US-East",
        "dashboards": ["https://grafana.internal.mock/d/checkout-metrics"],
        "scenario_id": "TC1",
    }
    response = client.post("/api/collect-and-analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["decision"]["status"] == "DEGRADED"
    assert "voice_script" in data["brief"]
    assert "claims" in data["brief"]
    assert len(data["brief"]["claims"]) > 0


@pytest.mark.parametrize(
    ("scenario_id", "expected_status"),
    [
        ("TC1", "DEGRADED"),
        ("TC2", "UNCERTAIN"),
        ("TC3", "UNCERTAIN"),
        ("TC4", "UNCERTAIN"),
    ],
)
def test_official_case_complete_api_workflow(client, scenario_id, expected_status):
    from app.db import get_agent_run, get_approval_by_agent_run
    from app.redact import scan_for_unredacted_pii

    incident_id = f"INC-{scenario_id}-ACCEPTANCE"
    analyzed = client.post("/api/collect-and-analyze", json={
        "incident_id": incident_id,
        "scope": f"Acceptance run for {scenario_id}",
        "scenario_id": scenario_id,
    })
    assert analyzed.status_code == 200
    result = analyzed.json()
    assert result["decision"]["status"] == expected_status
    assert result["collection"]["source_mode"] == "fixtures"
    assert result["brief"]["voice_script"]
    assert result["brief"]["proposed_channel_post"]
    run_id = result["agent"]["run_id"]

    signals = result["collection"]["signals"]
    if scenario_id == "TC1":
        assert all(signal["source_updated_at"] != "Unavailable" for signal in signals)
        assert all(signal["retrieved_at"] for signal in signals)
        assert all(
            claim["signal_id"] in {signal["signal_id"] for signal in signals}
            for claim in result["brief"]["claims"]
        )
    elif scenario_id == "TC2":
        assert any(signal["is_stale"] or signal["is_cached"] for signal in signals)
        assert "not proof of recovery" in result["brief"]["voice_script"].lower()
    elif scenario_id == "TC3":
        displayed_content = json.dumps({
            "brief": result["brief"],
            "collection": result["collection"],
            "trace": result["agent"]["trace"],
        })
        assert not scan_for_unredacted_pii(displayed_content)
    elif scenario_id == "TC4":
        health = next(signal for signal in signals if signal["source_type"] == "health_check")
        assert "failing" in health["value"].lower()
        assert result["decision"]["status"] == "UNCERTAIN"
        assert result["decision"]["recovery_uncertain_warning"]

    approved = client.post("/api/approve", json={
        "incident_id": incident_id,
        "destination": result["brief"]["destination"],
        "message": result["brief"]["proposed_channel_post"],
        "approval_decision": "APPROVED",
        "agent_run_id": run_id,
    })
    assert approved.status_code == 200
    assert approved.json()["status"] == "POSTED"

    verified = client.post("/api/verify", json={
        "incident_id": incident_id,
        "approved_text": result["brief"]["proposed_channel_post"],
        "post_id": approved.json()["post_id"],
        "agent_run_id": run_id,
    })
    assert verified.status_code == 200
    assert verified.json()["overall_status"] == "PASS"

    persisted = get_agent_run(run_id)
    approval = get_approval_by_agent_run(run_id)
    assert persisted["approval"]["id"] == approval["id"]
    assert persisted["post"]["id"] == approved.json()["post_id"]
    assert persisted["verification"]["overall_status"] == "PASS"
    exported = client.get(f"/api/agent-runs/{run_id}/export")
    assert exported.status_code == 200
    if scenario_id == "TC3":
        assert not scan_for_unredacted_pii(exported.text)


def test_approval_and_verification_flow():
    # 1. Analyze
    analyze_res = client.post("/api/collect-and-analyze", json={
        "incident_id": "INC-FLOW-01",
        "scope": "Database failover verification",
        "dashboards": ["https://grafana.internal.mock/d/checkout-metrics"],
        "scenario_id": "TC1",
    })
    assert analyze_res.status_code == 200
    data = analyze_res.json()
    proposed_post = data["brief"]["proposed_channel_post"]
    run_id = data["agent"]["run_id"]

    # 2. Approve
    app_res = client.post("/api/approve", json={
        "incident_id": "INC-FLOW-01",
        "destination": "#incident-response",
        "message": proposed_post,
        "approval_decision": "APPROVED",
        "agent_run_id": run_id,
    })
    assert app_res.status_code == 200
    app_data = app_res.json()
    assert app_data["status"] == "POSTED"
    post_id = app_data["post_id"]

    # 3. Verify
    verif_res = client.post("/api/verify", json={
        "incident_id": "INC-FLOW-01",
        "approved_text": proposed_post,
        "post_id": post_id,
        "agent_run_id": run_id,
    })
    assert verif_res.status_code == 200
    verif_data = verif_res.json()
    assert verif_data["overall_status"] == "PASS"
    assert verif_data["passed_checks"] == 6

    edited_after_post = client.post("/api/verify", json={
        "incident_id": "INC-FLOW-01",
        "approved_text": proposed_post + "\nEdited after posting",
        "post_id": post_id,
        "agent_run_id": run_id,
    })
    assert edited_after_post.status_code == 200
    assert edited_after_post.json()["overall_status"] == "FAIL"
    fidelity = next(
        item for item in edited_after_post.json()["checks"]
        if item["name"] == "Content Fidelity to Approved Version"
    )
    assert fidelity["status"] == "FAIL"
    binding = next(
        item for item in edited_after_post.json()["checks"]
        if item["name"] == "Run-bound Approval"
    )
    assert binding["status"] == "FAIL"

    whitespace_edit = client.post("/api/verify", json={
        "incident_id": "INC-FLOW-01",
        "approved_text": proposed_post + " ",
        "post_id": post_id,
        "agent_run_id": run_id,
    })
    assert whitespace_edit.status_code == 200
    assert whitespace_edit.json()["overall_status"] == "FAIL"

    # 4. Duplicate retry
    dup_res = client.post("/api/approve", json={
        "incident_id": "INC-FLOW-01",
        "destination": "#incident-response",
        "message": proposed_post,
        "approval_decision": "APPROVED",
        "agent_run_id": run_id,
    })
    assert dup_res.status_code == 200
    assert dup_res.json()["is_duplicate"] is True
    assert dup_res.json()["status"] == "DUPLICATE_IGNORED"


def test_concurrent_duplicate_retries_create_only_one_mock_post(client):
    from concurrent.futures import ThreadPoolExecutor

    from app.channel import ChannelPostRequest, process_channel_approval_and_post
    from app.db import get_all_posts

    analyzed = client.post("/api/collect-and-analyze", json={
        "incident_id": "INC-CONCURRENT-RETRY",
        "scope": "Concurrent duplicate retry test",
        "scenario_id": "TC1",
    }).json()
    request = ChannelPostRequest(
        incident_id="INC-CONCURRENT-RETRY",
        destination=analyzed["brief"]["destination"],
        message=analyzed["brief"]["proposed_channel_post"],
        approval_decision="APPROVED",
        agent_run_id=analyzed["agent"]["run_id"],
    )

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(process_channel_approval_and_post, [request, request]))

    assert {result.status for result in results} == {"POSTED", "DUPLICATE_IGNORED"}
    matching_posts = [
        post for post in get_all_posts()
        if post["incident_id"] == "INC-CONCURRENT-RETRY"
    ]
    assert len(matching_posts) == 1


def test_rejected_approval_is_recorded_without_posting(client):
    analyzed = client.post("/api/collect-and-analyze", json={
        "incident_id": "INC-REJECT-FLOW",
        "scope": "Testing operator rejection flow",
        "scenario_id": "TC1",
    }).json()
    rejected = client.post("/api/approve", json={
        "incident_id": "INC-REJECT-FLOW",
        "destination": analyzed["brief"]["destination"],
        "message": analyzed["brief"]["proposed_channel_post"],
        "approval_decision": "REJECTED",
        "agent_run_id": analyzed["agent"]["run_id"],
    })

    assert rejected.status_code == 200
    assert rejected.json()["status"] == "REJECTED"
    assert rejected.json()["success"] is False
    assert not any(item["incident_id"] == "INC-REJECT-FLOW" for item in client.get("/api/channel").json())
    attempted_reapproval = client.post("/api/approve", json={
        "incident_id": "INC-REJECT-FLOW",
        "destination": analyzed["brief"]["destination"],
        "message": analyzed["brief"]["proposed_channel_post"],
        "approval_decision": "APPROVED",
        "agent_run_id": analyzed["agent"]["run_id"],
    })
    assert attempted_reapproval.status_code == 409
    assert not any(item["incident_id"] == "INC-REJECT-FLOW" for item in client.get("/api/channel").json())
    rejected_verification = client.post("/api/verify", json={
        "incident_id": "INC-REJECT-FLOW",
        "approved_text": analyzed["brief"]["proposed_channel_post"],
        "agent_run_id": analyzed["agent"]["run_id"],
    })
    assert rejected_verification.status_code == 200
    assert rejected_verification.json()["overall_status"] == "FAIL"


def test_verification_requires_agent_run_binding(client):
    response = client.post("/api/verify", json={
        "incident_id": "INC-NO-VERIFY-RUN",
        "approved_text": "Unbound content",
    })
    assert response.status_code == 422


def test_run_approval_is_bound_to_exact_content_and_destination(client):
    analyzed = client.post("/api/collect-and-analyze", json={
        "incident_id": "INC-APPROVAL-EXACT",
        "scope": "Testing exact approval binding",
        "scenario_id": "TC1",
    }).json()
    run_id = analyzed["agent"]["run_id"]
    destination = analyzed["brief"]["destination"]
    message = analyzed["brief"]["proposed_channel_post"]
    approved = {
        "incident_id": "INC-APPROVAL-EXACT",
        "destination": destination,
        "message": message,
        "approval_decision": "APPROVED",
        "agent_run_id": run_id,
    }
    posted = client.post("/api/approve", json=approved)
    assert posted.status_code == 200

    changed_message = client.post("/api/approve", json={
        **approved,
        "message": message + "\nChanged after approval",
    })
    changed_destination = client.post("/api/approve", json={
        **approved,
        "destination": "#another-channel",
    })
    changed_decision = client.post("/api/approve", json={
        **approved,
        "approval_decision": "REJECTED",
    })
    assert changed_message.status_code == 409
    assert changed_destination.status_code == 400
    assert changed_decision.status_code == 409
    posts = [
        item for item in client.get("/api/channel").json()
        if item["incident_id"] == "INC-APPROVAL-EXACT"
    ]
    assert len(posts) == 1
    assert posts[0]["destination"] == destination
    assert posts[0]["message"] == message


def test_changed_content_invalidates_unposted_approval_and_pending_is_rejected(client, monkeypatch):
    from app.db import get_approval_by_agent_run

    analyzed = client.post("/api/collect-and-analyze", json={
        "incident_id": "INC-APPROVAL-INVALIDATE",
        "scope": "Testing approval invalidation after failed persistence",
        "scenario_id": "TC1",
    }).json()
    run_id = analyzed["agent"]["run_id"]
    payload = {
        "incident_id": "INC-APPROVAL-INVALIDATE",
        "destination": analyzed["brief"]["destination"],
        "message": analyzed["brief"]["proposed_channel_post"],
        "approval_decision": "APPROVED",
        "agent_run_id": run_id,
    }

    pending = client.post("/api/approve", json={**payload, "approval_decision": "PENDING"})
    assert pending.status_code == 422
    assert get_approval_by_agent_run(run_id) is None

    monkeypatch.setattr(
        "app.channel.save_post",
        lambda **_kwargs: (_ for _ in ()).throw(OSError("simulated persistence failure")),
    )
    failed_post = client.post("/api/approve", json=payload)
    assert failed_post.status_code == 502
    record = get_approval_by_agent_run(run_id)
    assert record["status"] == "POST_FAILED"

    edited = client.post("/api/approve", json={
        **payload,
        "message": payload["message"] + "\nEdited after approval",
    })
    assert edited.status_code == 409
    assert get_approval_by_agent_run(run_id)["status"] == "INVALIDATED"
    assert not any(
        item["incident_id"] == "INC-APPROVAL-INVALIDATE"
        for item in client.get("/api/channel").json()
    )
    exported = client.get(f"/api/agent-runs/{run_id}/export").json()
    assert exported["approval"]["status"] == "INVALIDATED"
    assert exported["post"] is None
    assert exported["verification"] is None


def test_changed_destination_invalidates_unposted_approval(client, monkeypatch):
    from app.db import get_approval_by_agent_run

    analyzed = client.post("/api/collect-and-analyze", json={
        "incident_id": "INC-DESTINATION-INVALIDATE",
        "scope": "Testing destination approval invalidation",
        "scenario_id": "TC1",
    }).json()
    run_id = analyzed["agent"]["run_id"]
    payload = {
        "incident_id": "INC-DESTINATION-INVALIDATE",
        "destination": analyzed["brief"]["destination"],
        "message": analyzed["brief"]["proposed_channel_post"],
        "approval_decision": "APPROVED",
        "agent_run_id": run_id,
    }
    monkeypatch.setattr(
        "app.channel.save_post",
        lambda **_kwargs: (_ for _ in ()).throw(OSError("simulated persistence failure")),
    )
    failed = client.post("/api/approve", json=payload)
    assert failed.status_code == 502
    assert get_approval_by_agent_run(run_id)["status"] == "POST_FAILED"

    changed_destination = client.post("/api/approve", json={
        **payload,
        "destination": "#edited-destination",
    })

    assert changed_destination.status_code == 400
    assert get_approval_by_agent_run(run_id)["status"] == "INVALIDATED"
    exported = client.get(f"/api/agent-runs/{run_id}/export").json()
    assert exported["approval"]["status"] == "INVALIDATED"
    assert exported["post"] is None
    assert exported["verification"] is None


def test_approved_post_persistence_failure_returns_explicit_gateway_error(client, monkeypatch):
    analyzed = client.post("/api/collect-and-analyze", json={
        "incident_id": "INC-POST-FAILURE",
        "scope": "Testing mock-channel persistence failure",
        "scenario_id": "TC1",
    }).json()

    def fail_post(**_kwargs):
        raise OSError("simulated database unavailable")

    monkeypatch.setattr("app.channel.save_post", fail_post)
    failed = client.post("/api/approve", json={
        "incident_id": "INC-POST-FAILURE",
        "destination": analyzed["brief"]["destination"],
        "message": analyzed["brief"]["proposed_channel_post"],
        "approval_decision": "APPROVED",
        "agent_run_id": analyzed["agent"]["run_id"],
    })

    assert failed.status_code == 502
    assert "could not be persisted" in failed.json()["detail"]
    assert not any(item["incident_id"] == "INC-POST-FAILURE" for item in client.get("/api/channel").json())
    verification = client.post("/api/verify", json={
        "incident_id": "INC-POST-FAILURE",
        "approved_text": analyzed["brief"]["proposed_channel_post"],
        "agent_run_id": analyzed["agent"]["run_id"],
    })
    assert verification.status_code == 200
    assert verification.json()["overall_status"] == "FAIL"


def test_ambiguous_post_failure_cannot_be_verified_as_success(client, monkeypatch):
    from app.channel import save_post as persist_post
    from app.db import get_approval_by_agent_run

    analyzed = client.post("/api/collect-and-analyze", json={
        "incident_id": "INC-AMBIGUOUS-POST",
        "scope": "Simulate persistence followed by ambiguous failure",
        "scenario_id": "TC1",
    }).json()

    def persist_then_fail(**kwargs):
        persist_post(**kwargs)
        raise OSError("simulated ambiguous persistence outcome")

    monkeypatch.setattr("app.channel.save_post", persist_then_fail)
    failed = client.post("/api/approve", json={
        "incident_id": "INC-AMBIGUOUS-POST",
        "destination": analyzed["brief"]["destination"],
        "message": analyzed["brief"]["proposed_channel_post"],
        "approval_decision": "APPROVED",
        "agent_run_id": analyzed["agent"]["run_id"],
    })
    assert failed.status_code == 502

    posts = [
        item for item in client.get("/api/channel").json()
        if item["incident_id"] == "INC-AMBIGUOUS-POST"
    ]
    assert len(posts) == 1
    assert get_approval_by_agent_run(analyzed["agent"]["run_id"])["status"] == "POST_FAILED"

    verification = client.post("/api/verify", json={
        "incident_id": "INC-AMBIGUOUS-POST",
        "approved_text": analyzed["brief"]["proposed_channel_post"],
        "post_id": posts[0]["id"],
        "agent_run_id": analyzed["agent"]["run_id"],
    })
    assert verification.status_code == 200
    assert verification.json()["overall_status"] == "FAIL"
    approval_check = next(
        check for check in verification.json()["checks"]
        if check["name"] == "Run-bound Approval"
    )
    assert approval_check["status"] == "FAIL"


def test_approval_requires_matching_run_and_rejects_pii(client):
    payload = {
        "incident_id": "INC-APPROVAL-BIND",
        "scope": "Synthetic checkout incident",
        "scenario_id": "TC1",
    }
    analyzed = client.post("/api/collect-and-analyze", json=payload).json()
    brief = analyzed["brief"]
    base_approval = {
        "incident_id": payload["incident_id"],
        "destination": brief["destination"],
        "message": brief["proposed_channel_post"],
        "approval_decision": "APPROVED",
    }
    assert client.post("/api/approve", json=base_approval).status_code == 400

    bound = {**base_approval, "agent_run_id": analyzed["agent"]["run_id"]}
    invalid_destination = {**bound, "destination": "#other-channel"}
    assert client.post("/api/approve", json=invalid_destination).status_code == 400
    pii_message = bound["message"] + "\nContact customer@example.com"
    assert client.post("/api/approve", json={**bound, "message": pii_message}).status_code == 400
    assert client.get("/api/channel").json() == []


def test_run_official_tests_endpoint():
    response = client.post("/api/run-tests")
    assert response.status_code == 200
    data = response.json()
    results = data["results"]
    assert len(results) == 6
    for r in results:
        assert r["status"] == "PASS"
        assert r["mode"].startswith("Rules fallback (offline mode")


def test_run_tests_does_not_call_live_provider_by_default(client, monkeypatch):
    monkeypatch.setenv("LLM_API_KEY", "mock-key")
    monkeypatch.setattr(
        "app.agent.run_tool_loop",
        lambda *args, **kwargs: pytest.fail("live LLM must be opt-in for the test runner"),
    )
    response = client.post("/api/run-tests")

    assert response.status_code == 200
    assert all(item["status"] == "PASS" for item in response.json()["results"])


def test_run_tests_live_option_is_forwarded(client, monkeypatch):
    from app.agent import run_agent as real_run_agent

    observed = []

    def spy(collection, decision, **kwargs):
        observed.append(kwargs["live_llm"])
        return real_run_agent(collection, decision, live_llm=False)

    monkeypatch.setenv("OFFLINE_MODE", "false")
    monkeypatch.setenv("LIVE_LLM_ENABLED", "true")
    monkeypatch.setattr("app.main.run_agent", spy)
    response = client.post("/api/run-tests", json={"live_llm": True})

    assert response.status_code == 200
    assert len(observed) == 6
    assert all(observed)


def test_tc1_to_tc4_workflows_are_provider_offline(client, monkeypatch):
    monkeypatch.setenv("LLM_API_KEY", "synthetic-test-key-never-used")
    monkeypatch.setenv("OFFLINE_MODE", "true")
    monkeypatch.setenv("EVIDENCE_SOURCE", "fixtures")
    attempts = {"gemini": 0, "openai_compat": 0, "agent_loop": 0, "grafana": 0}

    def forbidden_provider(name):
        def fail_if_called(*_args, **_kwargs):
            attempts[name] += 1
            pytest.fail(f"Unexpected {name} request in offline mode")
        return fail_if_called

    monkeypatch.setattr("app.llm._gemini_request", forbidden_provider("gemini"))
    monkeypatch.setattr("app.llm._openai_request", forbidden_provider("openai_compat"))
    monkeypatch.setattr("app.agent.run_tool_loop", forbidden_provider("agent_loop"))
    monkeypatch.setattr("app.source_adapters.build_opener", forbidden_provider("grafana"))

    for scenario_id in ("TC1", "TC2", "TC3", "TC4"):
        incident_id = f"INC-OFFLINE-{scenario_id}"
        analyzed = client.post("/api/collect-and-analyze", json={
            "incident_id": incident_id,
            "scope": f"Offline acceptance workflow for {scenario_id}",
            "dashboards": ["http://169.254.169.254/latest/meta-data"],
            "scenario_id": scenario_id,
        })
        assert analyzed.status_code == 200
        data = analyzed.json()
        assert data["agent"]["mode"].startswith("Rules fallback (offline mode")
        assert data["collection"]["source_mode"] == "fixtures"
        posted = client.post("/api/approve", json={
            "incident_id": incident_id,
            "destination": data["brief"]["destination"],
            "message": data["brief"]["proposed_channel_post"],
            "approval_decision": "APPROVED",
            "agent_run_id": data["agent"]["run_id"],
        })
        assert posted.status_code == 200
        verified = client.post("/api/verify", json={
            "incident_id": incident_id,
            "approved_text": data["brief"]["proposed_channel_post"],
            "post_id": posted.json()["post_id"],
            "agent_run_id": data["agent"]["run_id"],
        })
        assert verified.json()["overall_status"] == "PASS"
    assert attempts == {"gemini": 0, "openai_compat": 0, "agent_loop": 0, "grafana": 0}


def test_unrecognized_offline_setting_fails_closed_for_llm(client, monkeypatch):
    monkeypatch.setenv("OFFLINE_MODE", "unrecognized")
    monkeypatch.setenv("LIVE_LLM_ENABLED", "true")
    monkeypatch.setenv("LLM_API_KEY", "synthetic-test-key-never-used")
    monkeypatch.setattr(
        "app.agent.run_tool_loop",
        lambda *_a, **_k: pytest.fail("invalid OFFLINE_MODE must not call provider"),
    )
    response = client.post("/api/collect-and-analyze", json={
        "incident_id": "INC-OFFLINE-INVALID-CONFIG",
        "scope": "Unknown offline setting must fail closed",
        "scenario_id": "TC1",
    })

    assert response.status_code == 200
    assert response.json()["agent"]["mode"].startswith("Rules fallback (offline mode")


@pytest.mark.parametrize("offline_value", ["true", "unrecognized"])
def test_offline_grafana_mode_reports_unavailable_without_network(client, monkeypatch, offline_value):
    monkeypatch.setenv("OFFLINE_MODE", offline_value)
    monkeypatch.setenv("EVIDENCE_SOURCE", "grafana")
    monkeypatch.setattr("app.source_adapters.build_opener", lambda *_a, **_k: pytest.fail("Grafana network called"))
    response = client.post("/api/collect-and-analyze", json={
        "incident_id": "INC-OFFLINE-GRAFANA",
        "scope": "Configured Grafana blocked in offline mode",
        "dashboards": ["http://169.254.169.254/latest/meta-data"],
        "scenario_id": "TC1",
    })
    assert response.status_code == 200
    data = response.json()
    assert data["decision"]["status"] == "UNCERTAIN"
    assert all(signal["evidence_origin"] == "unavailable_offline" for signal in data["collection"]["signals"])
    assert all(signal["retrieval_status"] == "offline" for signal in data["collection"]["signals"])


def test_llm_hook_endpoint():
    # Disabled by default
    res_off = client.post("/api/llm-summary-hook", json={"enabled": False})
    assert res_off.status_code == 200
    assert res_off.json()["enabled"] is False

    # Enabled
    res_on = client.post("/api/llm-summary-hook", json={"enabled": True})
    assert res_on.status_code == 200
    assert res_on.json()["enabled"] is True


def test_agent_run_export_and_ten_minute_cache(client, monkeypatch):
    from app.main import AGENT_CACHE_SECONDS

    assert AGENT_CACHE_SECONDS == 600
    monkeypatch.setenv("LLM_API_KEY", "mock-key")
    monkeypatch.setenv("DEMO_MODE", "false")
    monkeypatch.setenv("OFFLINE_MODE", "false")
    monkeypatch.setenv("LIVE_LLM_ENABLED", "true")

    def fake_tool_loop(prompt, tools, execute_tool, **kwargs):
        incident_id = "INC-API-REPLAY"
        evidence_ids = [
            "SIG-METRIC-ERR", "SIG-METRIC-LAT", "SIG-METRIC-SAT",
            "SIG-STAT-01", "SIG-HLTH-01", "SIG-LOG-01", "SIG-CHANGE-01",
        ]
        observations_by_id = {}
        trace = []
        for tool in tools:
            tool_name = tool["function"]["name"]
            observation = execute_tool(tool_name, {"incident_id": incident_id})
            for record in observation:
                observations_by_id[record["signal_id"]] = record
            trace.append({
                "step": len(trace) + 1,
                "thought_summary": "Gathering synthetic evidence.",
                "tool_name": tool_name,
                "arguments": {"incident_id": incident_id},
                "observation": observation,
                "latency_ms": 1,
            })
        claims = [
            {
                "text": f"Synthetic evidence [{item}] updated at {observations_by_id[item]['source_updated_at']}",
                "signal_id": item,
            }
            for item in evidence_ids
        ]
        voice_script = "At 12:00 UTC, synthetic incident status is degraded. " + " ".join(
            claim["text"] for claim in claims
        )
        response = {
            "state": "DEGRADED",
            "confidence": 0.8,
            "voice_script": voice_script,
            "proposed_post": "At 12:00 UTC, synthetic incident update: " + " ".join(
                f"[{item}]" for item in evidence_ids
            ),
            "claims": claims,
            "open_questions": [],
        }
        return json.dumps(response), trace, {}, "gemini", "mock-model"

    monkeypatch.setattr("app.agent.run_tool_loop", fake_tool_loop)
    payload = {
        "incident_id": "INC-API-REPLAY",
        "scope": "Synthetic incident for replay test",
        "dashboards": ["https://grafana.internal.mock/d/checkout-metrics"],
        "scenario_id": "TC1",
    }
    first = client.post("/api/collect-and-analyze", json=payload)
    assert first.status_code == 200
    assert first.json()["agent"]["guardrail_verdict"] == "PASS"
    run_id = first.json()["agent"]["run_id"]

    replay = client.post("/api/collect-and-analyze", json=payload)
    assert replay.status_code == 200
    assert replay.json()["agent"]["cached_result"] is True
    assert replay.json()["agent"]["mode"] == "LLM agent"

    report = client.get(f"/api/agent-runs/{run_id}")
    exported = client.get(f"/api/agent-runs/{run_id}/export")
    assert report.status_code == 200
    assert exported.status_code == 200
    assert report.json()["guardrail_verdict"] == "PASS"
    assert "attachment" in exported.headers.get("content-disposition", "")
    pack = exported.json()
    assert pack["input"]["test_mode"] is False
    assert pack["evidence"]
    assert pack["decision"]["status"] == "DEGRADED"

    approved_text = first.json()["brief"]["proposed_channel_post"]
    approval = client.post("/api/approve", json={
        "incident_id": payload["incident_id"],
        "destination": "#incident-response",
        "message": approved_text,
        "approval_decision": "APPROVED",
        "agent_run_id": run_id,
    })
    assert approval.status_code == 200
    verification = client.post("/api/verify", json={
        "incident_id": payload["incident_id"],
        "approved_text": approved_text,
        "post_id": approval.json()["post_id"],
        "agent_run_id": run_id,
    })
    assert verification.json()["overall_status"] == "PASS"
    pack = client.get(f"/api/agent-runs/{run_id}/export").json()
    assert pack["approval"]["status"] == "APPROVED"
    assert pack["post"]["message"] == approved_text
    assert pack["verification"]["overall_status"] == "PASS"


def test_tc3_exported_report_contains_no_raw_synthetic_credentials(client, monkeypatch):
    from app.redact import scan_for_unredacted_pii
    from app.sources import get_mock_scenario_sources as original_sources

    sensitive_markers = [
        "AUTHMARKER_A1",
        "HEADERMARKER_B2",
        "APIMARKER_C3",
        "ACCESSMARKER_D4",
        "REFRESHMARKER_E5",
        "CLIENTMARKER_F6",
        "PASSWORDMARKER_G7",
    ]

    def scenario_with_credentials(scenario_id, base_time=None):
        scenario = original_sources(scenario_id, base_time)
        log_signal = next(signal for signal in scenario["signals"] if signal["source_type"] == "log")
        log_signal["value"] += (
            " Authorization: Bearer AUTHMARKER_A1"
            " X-API-Key: HEADERMARKER_B2"
            " api_key=APIMARKER_C3"
            " access_token=ACCESSMARKER_D4"
            " refresh_token=REFRESHMARKER_E5"
            " client_secret=CLIENTMARKER_F6"
            " password=PASSWORDMARKER_G7"
        )
        log_signal["raw_payload"]["authorization"] = "Bearer AUTHMARKER_A1"
        log_signal["raw_payload"]["X-API-Key"] = "HEADERMARKER_B2"
        log_signal["raw_payload"]["api_key"] = "APIMARKER_C3"
        log_signal["raw_payload"]["access_token"] = "ACCESSMARKER_D4"
        log_signal["raw_payload"]["refresh_token"] = "REFRESHMARKER_E5"
        log_signal["raw_payload"]["client_secret"] = "CLIENTMARKER_F6"
        log_signal["raw_payload"]["password"] = "PASSWORDMARKER_G7"
        return scenario

    monkeypatch.setattr("app.collector.get_mock_scenario_sources", scenario_with_credentials)
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    response = client.post("/api/collect-and-analyze", json={
        "incident_id": "INC-TC3-EXPORT-REDACTION",
        "scope": "Checking exported synthetic log data",
        "scenario_id": "TC3",
    })

    assert response.status_code == 200
    run_id = response.json()["agent"]["run_id"]
    exported = client.get(f"/api/agent-runs/{run_id}/export")
    assert exported.status_code == 200
    report = exported.json()

    def find_marker_paths(value, path="report"):
        if isinstance(value, dict):
            return [
                found
                for key, item in value.items()
                for found in find_marker_paths(item, f"{path}.{key}")
            ]
        if isinstance(value, list):
            return [
                found
                for index, item in enumerate(value)
                for found in find_marker_paths(item, f"{path}[{index}]")
            ]
        if isinstance(value, str) and any(marker in value for marker in sensitive_markers):
            return [path]
        return []

    leaked_paths = find_marker_paths(report)
    assert not leaked_paths, f"Export included unredacted data at: {leaked_paths}"
    def find_pii_paths(value, path="report"):
        if isinstance(value, dict):
            return [
                found
                for key, item in value.items()
                for found in find_pii_paths(item, f"{path}.{key}")
            ]
        if isinstance(value, list):
            return [
                found
                for index, item in enumerate(value)
                for found in find_pii_paths(item, f"{path}[{index}]")
            ]
        if isinstance(value, str) and (findings := scan_for_unredacted_pii(value)):
            return [f"{path}:{','.join(item['type'] for item in findings)}"]
        return []

    pii_paths = find_pii_paths(report)
    assert not pii_paths, f"Export included unredacted data at: {pii_paths}"
