"""Mock Observability Backend for Incident Voice Status Reporter.

Exposes mock routes under /mock:
- /mock/grafana/api/dashboards/uid/{uid}
- /mock/grafana/api/ds/query
- /mock/status (HTML status page)
- /mock/logs (Log stream with synthetic PII in TC3)
- /mock/health/{service} (Health check probe: 200, 500, timeout)

Supports scenario switching via ?scenario= or X-Mock-Scenario header:
- TC1 / degraded
- TC2 / cached-stale
- TC3 / pii-in-logs
- TC4 / health-failing
- MIXED / mixed
- MISSING / missing-source
- RECOVERED / healthy
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Header, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

mock_router = APIRouter(prefix="/mock", tags=["mock-observability"])

SCENARIOS_MAP = {
    "tc1": "TC1",
    "degraded": "TC1",
    "tc2": "TC2",
    "cached-stale": "TC2",
    "cached": "TC2",
    "tc3": "TC3",
    "pii-in-logs": "TC3",
    "tc4": "TC4",
    "health-failing": "TC4",
    "mixed": "MIXED",
    "missing": "MISSING",
    "missing-source": "MISSING",
    "recovered": "RECOVERED",
    "healthy": "RECOVERED",
}


def _resolve_scenario(
    query_scenario: Optional[str] = None,
    header_scenario: Optional[str] = None,
) -> str:
    raw = (query_scenario or header_scenario or "TC1").strip().lower()
    return SCENARIOS_MAP.get(raw, "TC1")


def _get_scenario_timestamps(scenario: str) -> Dict[str, str]:
    now = datetime.now(timezone.utc)
    if scenario == "TC2":
        # Stale timestamps (>5 min ago, e.g. 400 seconds ago)
        stale_time = (now - timedelta(seconds=400)).isoformat()
        return {
            "metric_updated_at": stale_time,
            "status_updated_at": (now - timedelta(seconds=60)).isoformat(),
            "health_updated_at": (now - timedelta(seconds=30)).isoformat(),
            "logs_updated_at": stale_time,
            "is_cached": True,
        }
    return {
        "metric_updated_at": (now - timedelta(seconds=30)).isoformat(),
        "status_updated_at": (now - timedelta(seconds=45)).isoformat(),
        "health_updated_at": (now - timedelta(seconds=20)).isoformat(),
        "logs_updated_at": (now - timedelta(seconds=25)).isoformat(),
        "is_cached": False,
    }


# ============================================================================
# 1. Grafana Dashboard UID endpoint
# ============================================================================
@mock_router.get("/grafana/api/dashboards/uid/{uid}")
async def get_mock_grafana_dashboard(
    uid: str,
    scenario: Optional[str] = Query(None),
    x_mock_scenario: Optional[str] = Header(None),
):
    """Returns Grafana dashboard JSON with panels, series, last value, state (OK/WARN/CRIT)."""
    sc = _resolve_scenario(scenario, x_mock_scenario)
    ts = _get_scenario_timestamps(sc)
    is_cached = ts["is_cached"]

    if sc == "TC1":
        err_val = 14.8
        err_state = "CRIT"
        lat_val = 920.0
        lat_state = "WARN"
        sat_val = 78.0
        sat_state = "WARN"
    elif sc == "TC2":
        err_val = 0.1  # Edge cached low error rate!
        err_state = "OK"
        lat_val = 45.0
        lat_state = "OK"
        sat_val = 32.0
        sat_state = "OK"
    elif sc == "TC3":
        err_val = 9.4
        err_state = "WARN"
        lat_val = 650.0
        lat_state = "WARN"
        sat_val = 68.0
        sat_state = "OK"
    elif sc == "TC4":
        err_val = 1.2
        err_state = "WARN"
        lat_val = 210.0
        lat_state = "OK"
        sat_val = 45.0
        sat_state = "OK"
    elif sc == "RECOVERED":
        err_val = 0.2
        err_state = "OK"
        lat_val = 85.0
        lat_state = "OK"
        sat_val = 28.0
        sat_state = "OK"
    elif sc == "MIXED":
        err_val = 12.5
        err_state = "CRIT"
        lat_val = 840.0
        lat_state = "WARN"
        sat_val = 75.0
        sat_state = "WARN"
    else:  # MISSING
        err_val = 8.1
        err_state = "WARN"
        lat_val = 520.0
        lat_state = "WARN"
        sat_val = 60.0
        sat_state = "OK"

    return {
        "meta": {
            "type": "db",
            "canSave": False,
            "canEdit": False,
            "canAdmin": False,
            "canStar": True,
            "slug": uid,
            "url": f"/d/{uid}",
            "expires": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
            "created": "2026-01-01T00:00:00Z",
            "updated": ts["metric_updated_at"],
            "is_cached": is_cached,
        },
        "dashboard": {
            "id": 101,
            "uid": uid,
            "title": f"Observability Dashboard ({uid})",
            "timezone": "browser",
            "schemaVersion": 38,
            "version": 4,
            "panels": [
                {
                    "id": 1,
                    "title": "Checkout API Error Rate",
                    "type": "stat",
                    "unit": "%",
                    "state": err_state,
                    "last_value": err_val,
                    "last_updated": ts["metric_updated_at"],
                    "is_cached": is_cached,
                    "series": [
                        {
                            "name": "5xx_error_percentage",
                            "points": [
                                [datetime.now(timezone.utc).timestamp() - 60, err_val * 0.95],
                                [datetime.now(timezone.utc).timestamp(), err_val],
                            ],
                        }
                    ],
                },
                {
                    "id": 2,
                    "title": "P99 API Latency",
                    "type": "timeseries",
                    "unit": "ms",
                    "state": lat_state,
                    "last_value": lat_val,
                    "last_updated": ts["metric_updated_at"],
                    "is_cached": is_cached,
                    "series": [
                        {
                            "name": "p99_latency_ms",
                            "points": [
                                [datetime.now(timezone.utc).timestamp() - 60, lat_val * 0.9],
                                [datetime.now(timezone.utc).timestamp(), lat_val],
                            ],
                        }
                    ],
                },
                {
                    "id": 3,
                    "title": "Worker Pool Saturation",
                    "type": "gauge",
                    "unit": "%",
                    "state": sat_state,
                    "last_value": sat_val,
                    "last_updated": ts["metric_updated_at"],
                    "is_cached": is_cached,
                    "series": [
                        {
                            "name": "worker_saturation_pct",
                            "points": [
                                [datetime.now(timezone.utc).timestamp(), sat_val],
                            ],
                        }
                    ],
                },
            ],
        },
    }


# ============================================================================
# 2. Grafana / Prometheus Datasource Query endpoint
# ============================================================================
@mock_router.api_route("/grafana/api/ds/query", methods=["GET", "POST"])
async def query_mock_grafana_datasource(
    request: Request,
    query: Optional[str] = Query(None),
    scenario: Optional[str] = Query(None),
    x_mock_scenario: Optional[str] = Header(None),
):
    """Prometheus-compatible and Grafana ds/query endpoint returning vector results."""
    body_query = None
    if request.method == "POST":
        try:
            body = await request.json()
            if isinstance(body, dict):
                body_query = body.get("query") or body.get("queries", [{}])[0].get("expr")
                if not scenario:
                    scenario = body.get("scenario")
        except Exception:
            pass

    q = (query or body_query or "error_rate").strip().lower()
    sc = _resolve_scenario(scenario, x_mock_scenario)
    ts = _get_scenario_timestamps(sc)
    is_cached = ts["is_cached"]

    now_ts = datetime.now(timezone.utc).timestamp()
    if is_cached:
        now_ts = now_ts - 400.0  # Stale timestamp

    # Determine metric and value
    if "error" in q or "5xx" in q:
        metric_name = "http_requests_5xx_ratio"
        if sc == "TC1":
            val = "14.8"
        elif sc == "TC2":
            val = "0.1"
        elif sc == "TC3":
            val = "9.4"
        elif sc == "TC4":
            val = "1.2"
        elif sc == "RECOVERED":
            val = "0.2"
        elif sc == "MIXED":
            val = "12.5"
        else:
            val = "8.1"
    elif "lat" in q or "p99" in q:
        metric_name = "p99_latency_ms"
        if sc == "TC1":
            val = "920"
        elif sc == "TC2":
            val = "45"
        elif sc == "TC3":
            val = "650"
        elif sc == "TC4":
            val = "210"
        elif sc == "RECOVERED":
            val = "85"
        elif sc == "MIXED":
            val = "840"
        else:
            val = "520"
    else:  # saturation
        metric_name = "worker_pool_saturation"
        if sc == "TC1":
            val = "78.0"
        elif sc == "TC2":
            val = "32.0"
        elif sc == "TC3":
            val = "68.0"
        elif sc == "TC4":
            val = "45.0"
        elif sc == "RECOVERED":
            val = "28.0"
        elif sc == "MIXED":
            val = "75.0"
        else:
            val = "60.0"

    # Standard Prometheus vector format
    return {
        "status": "success",
        "data": {
            "resultType": "vector",
            "result": [
                {
                    "metric": {
                        "__name__": metric_name,
                        "service": "checkout",
                        "environment": "production",
                        "is_cached": str(is_cached).lower(),
                    },
                    "value": [now_ts, val],
                }
            ],
        },
    }


# ============================================================================
# 3. HTML Status Page endpoint
# ============================================================================
@mock_router.get("/status", response_class=HTMLResponse)
async def get_mock_status_page(
    scenario: Optional[str] = Query(None),
    x_mock_scenario: Optional[str] = Header(None),
):
    """Returns an HTML status page with component statuses and 'Last updated' timestamp."""
    sc = _resolve_scenario(scenario, x_mock_scenario)
    ts = _get_scenario_timestamps(sc)
    updated_at_str = ts["status_updated_at"]

    if sc == "TC1":
        overall_status = "Major Service Outage"
        status_class = "status-major-outage"
        checkout_status = "Major Outage"
        api_status = "Degraded Performance"
        db_status = "Operational"
        incident_msg = "Checkout Service is experiencing elevated 500 error rates and timeout spikes."
    elif sc == "TC2":
        overall_status = "Investigating Incident"
        status_class = "status-investigating"
        checkout_status = "Investigating Connection Partition"
        api_status = "Operational"
        db_status = "Operational"
        incident_msg = "Engineering is investigating connection partitions. Edge caches may show transient data."
    elif sc == "TC3":
        overall_status = "Partial System Degradation"
        status_class = "status-degraded"
        checkout_status = "Degraded Performance"
        api_status = "Degraded Performance"
        db_status = "Operational"
        incident_msg = "Upstream gateway timeouts affecting payment transactions. Investigation underway."
    elif sc == "TC4":
        overall_status = "Unhealthy Probe Alerts"
        status_class = "status-unhealthy"
        checkout_status = "Degraded Performance"
        api_status = "Degraded Performance"
        db_status = "Failing Health Check"
        incident_msg = "Database primary health probe is reporting intermittent 500 connection refused."
    elif sc == "RECOVERED":
        overall_status = "All Systems Operational"
        status_class = "status-operational"
        checkout_status = "Operational"
        api_status = "Operational"
        db_status = "Operational"
        incident_msg = "All services are operating normally. Previous incident resolved."
    elif sc == "MIXED":
        # Status page claims resolved, but metrics are still elevated!
        overall_status = "All Systems Operational (Reported)"
        status_class = "status-operational"
        checkout_status = "Operational"
        api_status = "Operational"
        db_status = "Operational"
        incident_msg = "Status page shows operational, but automated telemetry reports elevated errors."
    else:  # MISSING
        overall_status = "Service Disruption"
        status_class = "status-degraded"
        checkout_status = "Degraded Performance"
        api_status = "Operational"
        db_status = "Operational"
        incident_msg = "Partial degradation. Log telemetry service currently offline."

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>MockCloud Status - Systems Overview</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #f8fafc; padding: 24px; }}
    .container {{ max-width: 800px; margin: 0 auto; background: #1e293b; border-radius: 8px; padding: 24px; border: 1px solid #334155; }}
    .header {{ border-bottom: 1px solid #334155; padding-bottom: 16px; margin-bottom: 20px; }}
    .title {{ font-size: 1.5rem; font-weight: bold; margin: 0 0 8px 0; }}
    .status-badge {{ display: inline-block; padding: 6px 14px; border-radius: 9999px; font-weight: bold; font-size: 0.9rem; }}
    .status-major-outage {{ background: #ef4444; color: white; }}
    .status-degraded {{ background: #f59e0b; color: white; }}
    .status-investigating {{ background: #f59e0b; color: white; }}
    .status-unhealthy {{ background: #ef4444; color: white; }}
    .status-operational {{ background: #10b981; color: white; }}
    .component-list {{ margin: 20px 0; }}
    .component {{ display: flex; justify-content: space-between; padding: 12px; border-bottom: 1px solid #334155; }}
    .component-name {{ font-weight: 600; }}
    .last-updated {{ color: #94a3b8; font-size: 0.85rem; margin-top: 16px; }}
    .incident-note {{ background: #0f172a; border-left: 4px solid #38bdf8; padding: 12px; margin-top: 16px; border-radius: 4px; font-size: 0.9rem; }}
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1 class="title">MockCloud Platform Status</h1>
      <div>Current State: <span class="status-badge {status_class}" id="overall-status">{overall_status}</span></div>
    </div>
    <div class="component-list">
      <div class="component" id="comp-checkout">
        <span class="component-name">Checkout API Service</span>
        <span class="component-status" id="status-checkout">{checkout_status}</span>
      </div>
      <div class="component" id="comp-gateway">
        <span class="component-name">API Gateway Ingress</span>
        <span class="component-status" id="status-gateway">{api_status}</span>
      </div>
      <div class="component" id="comp-db">
        <span class="component-name">PostgreSQL Database Primary</span>
        <span class="component-status" id="status-db">{db_status}</span>
      </div>
    </div>
    <div class="incident-note">
      <strong>Active Incident Update:</strong> <span id="incident-description">{incident_msg}</span>
    </div>
    <p class="last-updated">Last updated: <span id="last-updated-time">{updated_at_str}</span></p>
  </div>
</body>
</html>
"""
    return HTMLResponse(content=html_content, status_code=200)


# ============================================================================
# 4. Logs endpoint (with synthetic PII for TC3)
# ============================================================================
@mock_router.get("/logs")
async def get_mock_logs(
    service: str = Query("checkout"),
    scenario: Optional[str] = Query(None),
    x_mock_scenario: Optional[str] = Header(None),
):
    """Returns log entries for the requested service.
    
    In TC3 / pii-in-logs scenario, includes realistic synthetic personal data
    (emails, phone numbers, credit card numbers) to verify redaction.
    """
    sc = _resolve_scenario(scenario, x_mock_scenario)
    ts = _get_scenario_timestamps(sc)
    updated_at_str = ts["logs_updated_at"]

    if sc == "TC3":
        # TC3: Customer data in logs - must be redacted everywhere
        lines = [
            f"[{updated_at_str}] [ERROR] [checkout-api] Payment authorization failed for customer alice.smith@example.com (tel: +1-555-019-2834) with card 4532-7100-9281-3049: Bank gateway timeout.",
            f"[{updated_at_str}] [WARN] [checkout-api] Retry attempt #2 for order #98231 customer bob.jones@acme-corp.com phone (555) 019-8765 card 4111 2222 3333 4444 failed with code 504.",
            f"[{updated_at_str}] [ERROR] [checkout-api] Connection reset by peer during checkout processing for user carol@initech.org (phone: 555-019-4433).",
        ]
        sample_log = lines[0]
        pii_present = True
    elif sc == "TC1":
        lines = [
            f"[{updated_at_str}] [ERROR] [checkout-api] DB connection pool exhausted. 500 Internal Server Error returned on /api/v1/checkout/pay.",
            f"[{updated_at_str}] [ERROR] [checkout-api] Connection pool max size (100) reached. Active connections: 100, pending requests: 42.",
        ]
        sample_log = lines[0]
        pii_present = False
    elif sc == "TC4":
        lines = [
            f"[{updated_at_str}] [WARN] [checkout-api] Database health probe failed. Dial tcp 10.0.12.44:5432: connect: connection refused.",
            f"[{updated_at_str}] [ERROR] [checkout-api] Postgres pool failover triggered, node 2 is unreachable.",
        ]
        sample_log = lines[0]
        pii_present = False
    elif sc == "RECOVERED":
        lines = [
            f"[{updated_at_str}] [INFO] [checkout-api] All database connections healthy. Latency stable at 45ms.",
            f"[{updated_at_str}] [INFO] [checkout-api] HTTP 200 OK across 1,200 requests/sec.",
        ]
        sample_log = lines[0]
        pii_present = False
    elif sc == "MISSING":
        # Simulates 404/503 for missing source
        raise HTTPException(
            status_code=503,
            detail="Log telemetry service logs.internal.mock is temporarily unreachable.",
        )
    else:
        lines = [
            f"[{updated_at_str}] [INFO] [checkout-api] Processing standard background sync.",
            f"[{updated_at_str}] [WARN] [checkout-api] Upstream latency slightly elevated.",
        ]
        sample_log = lines[0]
        pii_present = False

    return {
        "service": service,
        "scenario": sc,
        "source_updated_at": updated_at_str,
        "count": len(lines),
        "lines": lines,
        "value": sample_log,
        "pii_present_synthetic": pii_present,
    }


# ============================================================================
# 5. Health Check endpoint
# ============================================================================
@mock_router.get("/health/{service}")
async def get_mock_health(
    service: str,
    scenario: Optional[str] = Query(None),
    simulate: Optional[str] = Query(None),
    x_mock_scenario: Optional[str] = Header(None),
):
    """Health-check endpoint returning 200 OK, 500 Unhealthy, or timeout."""
    sc = _resolve_scenario(scenario, x_mock_scenario)
    ts = _get_scenario_timestamps(sc)
    updated_at_str = ts["health_updated_at"]

    if simulate == "timeout":
        # Simulate timeout by sleeping briefly then raising 504
        await asyncio.sleep(0.5)
        raise HTTPException(status_code=504, detail="Health check probe timed out after 5000ms")

    if simulate == "500" or sc == "TC4":
        return JSONResponse(
            status_code=500,
            content={
                "service": service,
                "status": "failing",
                "healthy": False,
                "status_code": 500,
                "error": "Connection pool exhausted (500 Internal Server Error)",
                "component": f"{service}-primary",
                "source_updated_at": updated_at_str,
            },
        )

    # Passing health check
    return {
        "service": service,
        "status": "Passing (200 OK)",
        "healthy": True,
        "status_code": 200,
        "latency_ms": 14,
        "component": f"{service}-primary",
        "source_updated_at": updated_at_str,
    }
