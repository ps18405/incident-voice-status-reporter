"""API Integration Tests for Incident Voice Status Reporter."""
from __future__ import annotations

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
    assert verif_data["passed_checks"] == 4

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
    assert len(results) == 4
    for r in results:
        assert r["status"] == "PASS"


def test_llm_hook_endpoint():
    # Disabled by default
    res_off = client.post("/api/llm-summary-hook", json={"enabled": False})
    assert res_off.status_code == 200
    assert res_off.json()["enabled"] is False

    # Enabled
    res_on = client.post("/api/llm-summary-hook", json={"enabled": True})
    assert res_on.status_code == 200
    assert res_on.json()["enabled"] is True
