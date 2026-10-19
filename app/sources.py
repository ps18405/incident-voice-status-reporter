"""Mock data sources for dashboards, status pages, metrics, health checks, and logs.
Provides reproducible synthetic scenarios matching Grafana-style dashboards.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional


def get_mock_scenario_sources(scenario_id: str, base_time: Optional[datetime] = None) -> Dict[str, Any]:
    """Return synthetic mock data for a given scenario.
    
    All timestamps are computed relative to base_time (default: now UTC).
    """
    now = base_time or datetime.now(timezone.utc)
    t_minus_20s = (now - timedelta(seconds=20)).isoformat()
    t_minus_30s = (now - timedelta(seconds=30)).isoformat()
    t_minus_45s = (now - timedelta(seconds=45)).isoformat()
    t_minus_60s = (now - timedelta(seconds=60)).isoformat()
    t_minus_400s = (now - timedelta(seconds=400)).isoformat()  # Stale (> 5 mins)

    if scenario_id == "TC1":
        # Scenario: Status update (Fresh signals, high error rate, degraded, includes timestamps)
        return {
            "scenario_id": "TC1",
            "scenario_name": "Status update",
            "default_scope": "Checkout service experiencing elevated 500 error rates and latency degradation across US-East.",
            "dashboards": [
                "https://grafana.internal.mock/d/checkout-metrics",
                "https://status.mockcloud.io/services/checkout",
                "https://api.internal.mock/health/db",
            ],
            "signals": [
                {
                    "signal_id": "SIG-METRIC-ERR",
                    "source_type": "metric",
                    "name": "Checkout API Error Rate",
                    "url": "https://grafana.internal.mock/d/checkout-metrics?view=error_rate",
                    "value": "14.8",
                    "unit": "%",
                    "source_updated_at": t_minus_30s,
                    "is_cached": False,
                    "raw_payload": {"metric": "http_requests_5xx_ratio", "threshold": 1.0, "current": 14.8},
                },
                {
                    "signal_id": "SIG-METRIC-LAT",
                    "source_type": "metric",
                    "name": "P99 API Latency",
                    "url": "https://grafana.internal.mock/d/checkout-metrics?view=latency_p99",
                    "value": "920",
                    "unit": "ms",
                    "source_updated_at": t_minus_30s,
                    "is_cached": False,
                    "raw_payload": {"metric": "p99_latency_ms", "threshold": 250, "current": 920},
                },
                {
                    "signal_id": "SIG-STAT-01",
                    "source_type": "status_page",
                    "name": "Checkout Service Status Page",
                    "url": "https://status.mockcloud.io/services/checkout",
                    "value": "Major Outage",
                    "unit": "status",
                    "source_updated_at": t_minus_45s,
                    "is_cached": False,
                    "raw_payload": {"service": "checkout", "status": "Major Outage", "impact": "High"},
                },
                {
                    "signal_id": "SIG-HLTH-01",
                    "source_type": "health_check",
                    "name": "Database Pool Health Probe",
                    "url": "https://api.internal.mock/health/db",
                    "value": "Failing (500 Connection Refused)",
                    "unit": "probe",
                    "source_updated_at": t_minus_20s,
                    "is_cached": False,
                    "raw_payload": {"status_code": 500, "healthy": False, "component": "postgres-primary"},
                },
                {
                    "signal_id": "SIG-LOG-01",
                    "source_type": "log",
                    "name": "API Gateway Ingress Logs",
                    "url": "https://logs.internal.mock/explorer?query=checkout_errors",
                    "value": "DB connection pool exhausted. 500 Internal Server Error returned on /api/v1/checkout/pay.",
                    "unit": "log_entry",
                    "source_updated_at": t_minus_20s,
                    "is_cached": False,
                    "raw_payload": {"level": "ERROR", "cluster": "us-east-1", "count_last_5m": 1420},
                },
            ],
        }

    elif scenario_id == "TC2":
        # Scenario: Cached dashboard (Edge cache returns 0.1% error, but is_cached=True -> not proof of recovery)
        return {
            "scenario_id": "TC2",
            "scenario_name": "Cached dashboard",
            "default_scope": "Evaluating recovery claims for checkout gateway after proxy restart.",
            "dashboards": [
                "https://grafana.internal.mock/d/checkout-metrics",
                "https://status.mockcloud.io/services/checkout",
            ],
            "signals": [
                {
                    "signal_id": "SIG-METRIC-ERR",
                    "source_type": "metric",
                    "name": "Checkout API Error Rate (Edge Cache)",
                    "url": "https://grafana.internal.mock/d/checkout-metrics?view=error_rate",
                    "value": "0.1",
                    "unit": "%",
                    "source_updated_at": t_minus_400s,
                    "is_cached": True,
                    "raw_payload": {"metric": "http_requests_5xx_ratio", "cache_hit": True, "cache_ttl": 600},
                },
                {
                    "signal_id": "SIG-METRIC-LAT",
                    "source_type": "metric",
                    "name": "P99 API Latency",
                    "url": "https://grafana.internal.mock/d/checkout-metrics?view=latency_p99",
                    "value": "45",
                    "unit": "ms",
                    "source_updated_at": t_minus_400s,
                    "is_cached": True,
                    "raw_payload": {"metric": "p99_latency_ms", "cache_hit": True},
                },
                {
                    "signal_id": "SIG-STAT-01",
                    "source_type": "status_page",
                    "name": "Checkout Service Status Page",
                    "url": "https://status.mockcloud.io/services/checkout",
                    "value": "Investigating Connection Partition",
                    "unit": "status",
                    "source_updated_at": t_minus_60s,
                    "is_cached": False,
                    "raw_payload": {"service": "checkout", "status": "Investigating"},
                },
                {
                    "signal_id": "SIG-HLTH-01",
                    "source_type": "health_check",
                    "name": "Database Pool Health Probe",
                    "url": "https://api.internal.mock/health/db",
                    "value": "Passing (200 OK)",
                    "unit": "probe",
                    "source_updated_at": t_minus_30s,
                    "is_cached": False,
                    "raw_payload": {"status_code": 200, "healthy": True},
                },
            ],
        }

    elif scenario_id == "TC3":
        # Scenario: Customer data in logs (Logs contain emails, phone numbers, card numbers -> must be redacted)
        return {
            "scenario_id": "TC3",
            "scenario_name": "Customer data in logs",
            "default_scope": "Investigating failed customer transactions and payment exceptions in logs.",
            "dashboards": [
                "https://grafana.internal.mock/d/checkout-metrics",
                "https://logs.internal.mock/explorer",
            ],
            "signals": [
                {
                    "signal_id": "SIG-METRIC-ERR",
                    "source_type": "metric",
                    "name": "Checkout API Error Rate",
                    "url": "https://grafana.internal.mock/d/checkout-metrics?view=error_rate",
                    "value": "8.5",
                    "unit": "%",
                    "source_updated_at": t_minus_30s,
                    "is_cached": False,
                    "raw_payload": {"metric": "http_requests_5xx_ratio", "threshold": 1.0, "current": 8.5},
                },
                {
                    "signal_id": "SIG-HLTH-01",
                    "source_type": "health_check",
                    "name": "Payment Gateway Health Check",
                    "url": "https://api.internal.mock/health/payment",
                    "value": "Failing (503 Service Unavailable)",
                    "unit": "probe",
                    "source_updated_at": t_minus_20s,
                    "is_cached": False,
                    "raw_payload": {"status_code": 503, "healthy": False},
                },
                {
                    "signal_id": "SIG-LOG-01",
                    "source_type": "log",
                    "name": "Payment Processor Error Log 1",
                    "url": "https://logs.internal.mock/explorer?trace=91823",
                    "value": "Transaction failure for customer sarah.connor@cyberdyne.io with phone +1-555-019-2834 and card 4532-8901-2345-6789: bank gateway timeout.",
                    "unit": "log_entry",
                    "source_updated_at": t_minus_20s,
                    "is_cached": False,
                    "raw_payload": {"user": "sarah.connor@cyberdyne.io", "phone": "+1-555-019-2834", "card": "4532-8901-2345-6789"},
                },
                {
                    "signal_id": "SIG-LOG-02",
                    "source_type": "log",
                    "name": "Payment Processor Error Log 2",
                    "url": "https://logs.internal.mock/explorer?trace=91824",
                    "value": "Refund processing error: account john.doe@example.com (cell 555-432-8765, billing card 5424-0000-1234-5678) failed at stage 3.",
                    "unit": "log_entry",
                    "source_updated_at": t_minus_30s,
                    "is_cached": False,
                    "raw_payload": {"user": "john.doe@example.com", "phone": "555-432-8765", "card": "5424-0000-1234-5678"},
                },
            ],
        }

    elif scenario_id == "TC4":
        # Scenario: Health check failing (Dashboards look green, but deep health probe fails -> recovery uncertain)
        return {
            "scenario_id": "TC4",
            "scenario_name": "Health check failing",
            "default_scope": "Verifying post-failover stability for Core API cluster.",
            "dashboards": [
                "https://grafana.internal.mock/d/checkout-metrics",
                "https://api.internal.mock/health/db",
                "https://status.mockcloud.io/services/checkout",
            ],
            "signals": [
                {
                    "signal_id": "SIG-METRIC-ERR",
                    "source_type": "metric",
                    "name": "Checkout API Error Rate",
                    "url": "https://grafana.internal.mock/d/checkout-metrics?view=error_rate",
                    "value": "0.2",
                    "unit": "%",
                    "source_updated_at": t_minus_30s,
                    "is_cached": False,
                    "raw_payload": {"metric": "http_requests_5xx_ratio", "threshold": 1.0, "current": 0.2},
                },
                {
                    "signal_id": "SIG-METRIC-LAT",
                    "source_type": "metric",
                    "name": "P99 API Latency",
                    "url": "https://grafana.internal.mock/d/checkout-metrics?view=latency_p99",
                    "value": "38",
                    "unit": "ms",
                    "source_updated_at": t_minus_30s,
                    "is_cached": False,
                    "raw_payload": {"metric": "p99_latency_ms", "threshold": 250, "current": 38},
                },
                {
                    "signal_id": "SIG-STAT-01",
                    "source_type": "status_page",
                    "name": "Checkout Status Page",
                    "url": "https://status.mockcloud.io/services/checkout",
                    "value": "Operational",
                    "unit": "status",
                    "source_updated_at": t_minus_45s,
                    "is_cached": False,
                    "raw_payload": {"service": "checkout", "status": "Operational"},
                },
                {
                    "signal_id": "SIG-HLTH-01",
                    "source_type": "health_check",
                    "name": "Database Replication Health Probe",
                    "url": "https://api.internal.mock/health/db",
                    "value": "Failing (503 DB Replica Desynchronized)",
                    "unit": "probe",
                    "source_updated_at": t_minus_20s,
                    "is_cached": False,
                    "raw_payload": {"status_code": 503, "healthy": False, "error": "replica_lag_exceeded"},
                },
            ],
        }

    elif scenario_id == "RECOVERED":
        # Scenario: Complete Recovery (All fresh, health check passing, error rate <= 1.0%)
        return {
            "scenario_id": "RECOVERED",
            "scenario_name": "Full system recovery",
            "default_scope": "Post-mitigation checkout and database cluster verification.",
            "dashboards": [
                "https://grafana.internal.mock/d/checkout-metrics",
                "https://status.mockcloud.io/services/checkout",
                "https://api.internal.mock/health/db",
            ],
            "signals": [
                {
                    "signal_id": "SIG-METRIC-ERR",
                    "source_type": "metric",
                    "name": "Checkout API Error Rate",
                    "url": "https://grafana.internal.mock/d/checkout-metrics?view=error_rate",
                    "value": "0.15",
                    "unit": "%",
                    "source_updated_at": t_minus_30s,
                    "is_cached": False,
                    "raw_payload": {"metric": "http_requests_5xx_ratio", "threshold": 1.0, "current": 0.15},
                },
                {
                    "signal_id": "SIG-METRIC-LAT",
                    "source_type": "metric",
                    "name": "P99 API Latency",
                    "url": "https://grafana.internal.mock/d/checkout-metrics?view=latency_p99",
                    "value": "42",
                    "unit": "ms",
                    "source_updated_at": t_minus_30s,
                    "is_cached": False,
                    "raw_payload": {"metric": "p99_latency_ms", "threshold": 250, "current": 42},
                },
                {
                    "signal_id": "SIG-STAT-01",
                    "source_type": "status_page",
                    "name": "Checkout Status Page",
                    "url": "https://status.mockcloud.io/services/checkout",
                    "value": "Operational",
                    "unit": "status",
                    "source_updated_at": t_minus_45s,
                    "is_cached": False,
                    "raw_payload": {"service": "checkout", "status": "Operational"},
                },
                {
                    "signal_id": "SIG-HLTH-01",
                    "source_type": "health_check",
                    "name": "Database Replication Health Probe",
                    "url": "https://api.internal.mock/health/db",
                    "value": "Passing (200 OK)",
                    "unit": "probe",
                    "source_updated_at": t_minus_20s,
                    "is_cached": False,
                    "raw_payload": {"status_code": 200, "healthy": True},
                },
            ],
        }

    else:
        # Default fallback
        return get_mock_scenario_sources("TC1", base_time=now)


def list_available_scenarios() -> List[Dict[str, str]]:
    return [
        {
            "id": "TC1",
            "name": "TC1: Status update",
            "description": "Outage in progress. Signals fresh. Expected: voice brief includes source timestamps and claims linked to dashboard IDs.",
        },
        {
            "id": "TC2",
            "name": "TC2: Cached dashboard",
            "description": "Grafana panel served from edge cache. Expected: explicitly states 'this is not proof of recovery' (UNCERTAIN).",
        },
        {
            "id": "TC3",
            "name": "TC3: Customer data in logs",
            "description": "Error logs contain emails, phones, and credit card numbers. Expected: strictly redacted before display, speech, and posting.",
        },
        {
            "id": "TC4",
            "name": "TC4: Health check failing",
            "description": "Metrics appear green, but deep health check fails. Expected: states 'recovery uncertain' (UNCERTAIN).",
        },
        {
            "id": "RECOVERED",
            "name": "All Systems Recovered",
            "description": "All signals fresh, error rate <= 1.0%, health checks passing. Expected: states RECOVERED.",
        },
    ]
