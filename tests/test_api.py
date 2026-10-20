"""API Integration Tests for Incident Voice Status Reporter."""
from __future__ import annotations

import json
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.db import init_db

client = TestClient(app)


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


def test_approval_and_verification_flow():
    # 1. Analyze
    analyze_res = client.post("/api/collect-and-analyze", json={
        "incident_id": "INC-FLOW-01",
        "scope": "Database failover verification",
        "dashboards": ["https://grafana.internal.mock/d/checkout-metrics"],
        "scenario_id": "TC1",
    })
    data = analyze_res.json()
    proposed_post = data["brief"]["proposed_channel_post"]

    # 2. Approve
    app_res = client.post("/api/approve", json={
        "incident_id": "INC-FLOW-01",
        "destination": "#incident-response",
        "message": proposed_post,
        "approval_decision": "APPROVED",
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
    })
    assert verif_res.status_code == 200
    verif_data = verif_res.json()
    assert verif_data["overall_status"] == "PASS"
    assert verif_data["passed_checks"] == 5

    # 4. Duplicate retry
    dup_res = client.post("/api/approve", json={
        "incident_id": "INC-FLOW-01",
        "destination": "#incident-response",
        "message": proposed_post,
        "approval_decision": "APPROVED",
    })
    assert dup_res.status_code == 200
    assert dup_res.json()["is_duplicate"] is True
    assert dup_res.json()["status"] == "DUPLICATE_IGNORED"


def test_run_official_tests_endpoint():
    response = client.post("/api/run-tests")
    assert response.status_code == 200
    data = response.json()
    results = data["results"]
    assert len(results) == 6
    for r in results:
        assert r["status"] == "PASS"
        assert r["mode"].startswith("Rules fallback (live LLM disabled")


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

    monkeypatch.setattr("app.main.run_agent", spy)
    response = client.post("/api/run-tests", json={"live_llm": True})

    assert response.status_code == 200
    assert len(observed) == 6
    assert all(observed)


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
