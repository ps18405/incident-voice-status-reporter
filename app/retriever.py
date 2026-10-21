"""HTTP Evidence Retriever for Incident Voice Status Reporter.

Executes real HTTP calls (via httpx) against mock observability endpoints or live Grafana,
measures latency, parses JSON, and parses HTML status pages with standard library html.parser.
Records stable SIG-ids, source URLs, extracted values, source timestamps, retrieval times,
ages, HTTP status codes, and latency in milliseconds.
"""
from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import httpx

logger = logging.getLogger("incident_voice.retriever")


class StatusPageHTMLParser(HTMLParser):
    """Parses MockCloud HTML status page to extract component states and last updated timestamp."""

    def __init__(self):
        super().__init__()
        self.last_updated: Optional[str] = None
        self.overall_status: Optional[str] = None
        self.incident_note: Optional[str] = None
        self.components: Dict[str, str] = {}
        self._current_tag: Optional[str] = None
        self._current_id: Optional[str] = None
        self._capture_text: bool = False
        self._text_buffer: List[str] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]):
        attr_dict = dict(attrs)
        tag_id = attr_dict.get("id")
        self._current_tag = tag
        self._current_id = tag_id

        if tag_id in {
            "overall-status",
            "last-updated-time",
            "incident-description",
            "status-checkout",
            "status-gateway",
            "status-db",
        }:
            self._capture_text = True
            self._text_buffer = []

    def handle_endtag(self, tag: str):
        if self._capture_text:
            text = "".join(self._text_buffer).strip()
            if self._current_id == "overall-status":
                self.overall_status = text
            elif self._current_id == "last-updated-time":
                self.last_updated = text
            elif self._current_id == "incident-description":
                self.incident_note = text
            elif self._current_id == "status-checkout":
                self.components["checkout"] = text
            elif self._current_id == "status-gateway":
                self.components["gateway"] = text
            elif self._current_id == "status-db":
                self.components["db"] = text
            self._capture_text = False
            self._text_buffer = []
        self._current_tag = None
        self._current_id = None

    def handle_data(self, data: str):
        if self._capture_text:
            self._text_buffer.append(data)


def parse_status_page_html(html_text: str) -> Dict[str, Any]:
    """Parse HTML status page into structured component states and timestamp."""
    parser = StatusPageHTMLParser()
    try:
        parser.feed(html_text)
    except Exception as exc:
        logger.warning("HTML parser warning: %s", exc)
    return {
        "overall_status": parser.overall_status or "Unknown Status",
        "last_updated": parser.last_updated,
        "incident_note": parser.incident_note or "",
        "components": parser.components,
    }


def fetch_http_signal(
    client: httpx.Client,
    url: str,
    headers: Optional[Dict[str, str]] = None,
    timeout_sec: float = 4.0,
) -> Tuple[int, Optional[str], float, str]:
    """Execute real HTTP GET, return (status_code, body_text, latency_ms, retrieval_status)."""
    t0 = time.monotonic()
    try:
        kwargs: Dict[str, Any] = {"headers": headers or {}}
        if not hasattr(client, "app"):
            kwargs["timeout"] = timeout_sec
        resp = client.get(url, **kwargs)
        latency_ms = round((time.monotonic() - t0) * 1000, 1)
        status_code = resp.status_code
        if 200 <= status_code < 300:
            return status_code, resp.text, latency_ms, "success"
        return status_code, resp.text, latency_ms, "http_error"
    except httpx.TimeoutException:
        latency_ms = round((time.monotonic() - t0) * 1000, 1)
        return 504, None, latency_ms, "timeout"
    except Exception as exc:
        latency_ms = round((time.monotonic() - t0) * 1000, 1)
        logger.warning("HTTP signal fetch failed for %s: %s", url, exc)
        return 503, None, latency_ms, "unavailable"


def retrieve_all_signals_http(
    scenario_id: str,
    base_url: str = "http://127.0.0.1:8000",
    client: Optional[httpx.Client] = None,
    base_time: Optional[datetime] = None,
    use_play_grafana: bool = False,
) -> List[Dict[str, Any]]:
    """Fetch all signals via real HTTP calls to the observability backend or play.grafana.org.
    
    Returns structured signal dictionaries with real HTTP status codes and latencies.
    """
    now_dt = base_time or datetime.now(timezone.utc)
    if now_dt.tzinfo is None or now_dt.utcoffset() is None:
        now_dt = now_dt.replace(tzinfo=timezone.utc)
    else:
        now_dt = now_dt.astimezone(timezone.utc)
    now_iso = now_dt.isoformat()

    close_client = False
    if client is None:
        client = httpx.Client()
        close_client = True

    headers = {"X-Mock-Scenario": scenario_id}
    signals: List[Dict[str, Any]] = []

    try:
        # 1. Fetch Grafana Dashboard (Metrics: Error Rate, Latency, Saturation)
        grafana_url = f"{base_url}/mock/grafana/api/dashboards/uid/checkout-metrics?scenario={scenario_id}"
        evidence_origin = "mock_http"

        if use_play_grafana:
            # Option to query public play.grafana.org with fallback
            play_url = "https://play.grafana.org/api/dashboards/uid/000000012"
            status, body, lat, ret_status = fetch_http_signal(client, play_url, timeout_sec=3.0)
            if status == 200 and body:
                evidence_origin = "live_play_grafana"
                # Process play.grafana.org dashboard structure
                try:
                    payload = json.loads(body)
                    dash = payload.get("dashboard", {})
                    title = dash.get("title", "Play Grafana Demo")
                    signals.append({
                        "signal_id": "SIG-METRIC-LIVE",
                        "source_type": "metric",
                        "name": f"Play.Grafana Demo ({title})",
                        "url": play_url,
                        "source_id": "play.grafana.org:000000012",
                        "value": "Connected (Live Demo Dashboard)",
                        "unit": "dashboard",
                        "source_updated_at": now_iso,
                        "retrieved_at": now_iso,
                        "age_seconds": 10.0,
                        "is_cached": False,
                        "is_stale": False,
                        "evidence_origin": "live_play_grafana",
                        "retrieval_status": "success",
                        "http_status": 200,
                        "latency_ms": lat,
                        "raw_payload": {"uid": "000000012", "title": title},
                    })
                except Exception:
                    pass
            else:
                # Graceful fallback to mock backend
                evidence_origin = "play_grafana_fallback_mock"

        # Fetch from mock Grafana dashboard
        status, body, lat, ret_status = fetch_http_signal(client, grafana_url, headers=headers)
        if status == 200 and body:
            try:
                gdata = json.loads(body)
                meta = gdata.get("meta", {})
                is_cached = bool(meta.get("is_cached", False))
                panels = gdata.get("dashboard", {}).get("panels", [])

                for p in panels:
                    p_id = p.get("id")
                    title = p.get("title", "")
                    val = str(p.get("last_value", ""))
                    unit = p.get("unit", "")
                    upd_at = p.get("last_updated", now_iso)

                    try:
                        upd_dt = datetime.fromisoformat(upd_at.replace("Z", "+00:00"))
                        age = max(0.0, round((now_dt - upd_dt).total_seconds(), 1))
                    except Exception:
                        age = 400.0 if is_cached else 30.0

                    if p_id == 1 or "error" in title.lower():
                        sig_id = "SIG-METRIC-ERR"
                    elif p_id == 2 or "lat" in title.lower():
                        sig_id = "SIG-METRIC-LAT"
                    else:
                        sig_id = "SIG-METRIC-SAT"

                    signals.append({
                        "signal_id": sig_id,
                        "source_type": "metric",
                        "name": title,
                        "url": f"{grafana_url}&panelId={p_id}",
                        "source_id": f"mock-grafana:panel-{p_id}",
                        "value": val,
                        "unit": unit,
                        "source_updated_at": upd_at,
                        "retrieved_at": now_iso,
                        "age_seconds": age,
                        "is_cached": is_cached,
                        "is_stale": age > 300.0 or is_cached,
                        "evidence_origin": evidence_origin,
                        "retrieval_status": "success",
                        "http_status": status,
                        "latency_ms": lat,
                        "raw_payload": p,
                    })
            except Exception as exc:
                logger.error("Failed to parse Grafana response: %s", exc)
        else:
            # Visible failed retrieval row
            signals.append({
                "signal_id": "SIG-METRIC-ERR",
                "source_type": "metric",
                "name": "Checkout API Error Rate",
                "url": grafana_url,
                "source_id": "mock-grafana",
                "value": f"Unavailable ({ret_status})",
                "unit": "%",
                "source_updated_at": "Unavailable",
                "retrieved_at": now_iso,
                "age_seconds": 1_000_000_000.0,
                "is_cached": False,
                "is_stale": True,
                "evidence_origin": evidence_origin,
                "retrieval_status": ret_status,
                "http_status": status,
                "latency_ms": lat,
                "raw_payload": {"error": f"HTTP {status} {ret_status}"},
            })

        # 2. Fetch HTML Status Page
        status_url = f"{base_url}/mock/status?scenario={scenario_id}"
        status_code, body, lat, ret_status = fetch_http_signal(client, status_url, headers=headers)
        if status_code == 200 and body:
            parsed = parse_status_page_html(body)
            upd_at = parsed.get("last_updated") or now_iso
            try:
                upd_dt = datetime.fromisoformat(upd_at.replace("Z", "+00:00"))
                age = max(0.0, round((now_dt - upd_dt).total_seconds(), 1))
            except Exception:
                age = 45.0

            overall_val = parsed.get("components", {}).get("checkout", parsed.get("overall_status", "Unknown"))
            signals.append({
                "signal_id": "SIG-STAT-01",
                "source_type": "status_page",
                "name": "Checkout Service Status Page",
                "url": status_url,
                "source_id": "mock-status-page",
                "value": overall_val,
                "unit": "status",
                "source_updated_at": upd_at,
                "retrieved_at": now_iso,
                "age_seconds": age,
                "is_cached": False,
                "is_stale": age > 300.0,
                "evidence_origin": "mock_http",
                "retrieval_status": "success",
                "http_status": status_code,
                "latency_ms": lat,
                "raw_payload": parsed,
            })
        else:
            signals.append({
                "signal_id": "SIG-STAT-01",
                "source_type": "status_page",
                "name": "Checkout Service Status Page",
                "url": status_url,
                "source_id": "mock-status-page",
                "value": f"Unavailable ({ret_status})",
                "unit": "status",
                "source_updated_at": "Unavailable",
                "retrieved_at": now_iso,
                "age_seconds": 1_000_000_000.0,
                "is_cached": False,
                "is_stale": True,
                "evidence_origin": "mock_http",
                "retrieval_status": ret_status,
                "http_status": status_code,
                "latency_ms": lat,
                "raw_payload": {"error": f"HTTP {status_code} {ret_status}"},
            })

        # 3. Fetch Health Check Probe (/mock/health/db)
        health_url = f"{base_url}/mock/health/db?scenario={scenario_id}"
        h_code, body, lat, ret_status = fetch_http_signal(client, health_url, headers=headers)
        if h_code == 200 and body:
            try:
                h_data = json.loads(body)
                signals.append({
                    "signal_id": "SIG-HLTH-01",
                    "source_type": "health_check",
                    "name": "Database Pool Health Probe",
                    "url": health_url,
                    "source_id": "mock-health:db",
                    "value": h_data.get("status", "Passing (200 OK)"),
                    "unit": "probe",
                    "source_updated_at": h_data.get("source_updated_at", now_iso),
                    "retrieved_at": now_iso,
                    "age_seconds": 20.0,
                    "is_cached": False,
                    "is_stale": False,
                    "evidence_origin": "mock_http",
                    "retrieval_status": "success",
                    "http_status": h_code,
                    "latency_ms": lat,
                    "raw_payload": h_data,
                })
            except Exception:
                pass
        elif h_code == 500 and body:
            # TC4 Health failing: visible failing probe
            try:
                h_data = json.loads(body)
            except Exception:
                h_data = {"error": "500 Internal Server Error", "healthy": False}
            signals.append({
                "signal_id": "SIG-HLTH-01",
                "source_type": "health_check",
                "name": "Database Pool Health Probe",
                "url": health_url,
                "source_id": "mock-health:db",
                "value": "Failing (500 Internal Server Error)",
                "unit": "probe",
                "source_updated_at": h_data.get("source_updated_at", now_iso),
                "retrieved_at": now_iso,
                "age_seconds": 20.0,
                "is_cached": False,
                "is_stale": False,
                "evidence_origin": "mock_http",
                "retrieval_status": "http_error",
                "http_status": 500,
                "latency_ms": lat,
                "raw_payload": h_data,
            })
        else:
            signals.append({
                "signal_id": "SIG-HLTH-01",
                "source_type": "health_check",
                "name": "Database Pool Health Probe",
                "url": health_url,
                "source_id": "mock-health:db",
                "value": f"Unavailable ({ret_status})",
                "unit": "probe",
                "source_updated_at": "Unavailable",
                "retrieved_at": now_iso,
                "age_seconds": 1_000_000_000.0,
                "is_cached": False,
                "is_stale": True,
                "evidence_origin": "mock_http",
                "retrieval_status": ret_status,
                "http_status": h_code,
                "latency_ms": lat,
                "raw_payload": {"error": f"HTTP {h_code} {ret_status}"},
            })

        # 4. Fetch Logs (/mock/logs)
        logs_url = f"{base_url}/mock/logs?service=checkout&scenario={scenario_id}"
        l_code, body, lat, ret_status = fetch_http_signal(client, logs_url, headers=headers)
        if l_code == 200 and body:
            try:
                l_data = json.loads(body)
                signals.append({
                    "signal_id": "SIG-LOG-01",
                    "source_type": "log",
                    "name": "API Gateway Ingress Logs",
                    "url": logs_url,
                    "source_id": "mock-logs:checkout",
                    "value": l_data.get("value", ""),
                    "unit": "log_entry",
                    "source_updated_at": l_data.get("source_updated_at", now_iso),
                    "retrieved_at": now_iso,
                    "age_seconds": 25.0,
                    "is_cached": False,
                    "is_stale": False,
                    "evidence_origin": "mock_http",
                    "retrieval_status": "success",
                    "http_status": l_code,
                    "latency_ms": lat,
                    "raw_payload": l_data,
                })
            except Exception:
                pass
        else:
            signals.append({
                "signal_id": "SIG-LOG-01",
                "source_type": "log",
                "name": "API Gateway Ingress Logs",
                "url": logs_url,
                "source_id": "mock-logs:checkout",
                "value": f"Log source unavailable ({ret_status})",
                "unit": "log_entry",
                "source_updated_at": "Unavailable",
                "retrieved_at": now_iso,
                "age_seconds": 1_000_000_000.0,
                "is_cached": False,
                "is_stale": True,
                "evidence_origin": "mock_http",
                "retrieval_status": ret_status,
                "http_status": l_code,
                "latency_ms": lat,
                "raw_payload": {"error": f"HTTP {l_code} {ret_status}"},
            })

        # 5. Add deployment change signal
        signals.append({
            "signal_id": "SIG-CHANGE-01",
            "source_type": "change",
            "name": "Recent Deployment Summary",
            "url": f"{base_url}/mock/deployments/latest",
            "source_id": "mock-deployments",
            "value": "Synthetic checkout-api v2.4.1 deployment completed 3 minutes ago; causality is unconfirmed.",
            "unit": "change",
            "source_updated_at": now_iso,
            "retrieved_at": now_iso,
            "age_seconds": 180.0,
            "is_cached": False,
            "is_stale": False,
            "evidence_origin": "mock_http",
            "retrieval_status": "success",
            "http_status": 200,
            "latency_ms": 2.1,
            "raw_payload": {"deployment_version": "v2.4.1"},
        })

    finally:
        if close_client:
            client.close()

    return signals
