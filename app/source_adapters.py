"""Explicitly configured external evidence adapters."""
from __future__ import annotations

import json
import logging
import math
import os
import socket
from datetime import datetime, timezone
from typing import Any, Dict, List
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


logger = logging.getLogger("incident_voice.sources")

METRIC_DEFINITIONS = {
    "error_rate": ("SIG-METRIC-ERR", "Checkout API Error Rate", "%"),
    "latency_ms": ("SIG-METRIC-LAT", "P99 API Latency", "ms"),
    "saturation": ("SIG-METRIC-SAT", "Worker Pool Saturation", "%"),
}


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _configured_queries() -> Dict[str, str]:
    raw = os.getenv("GRAFANA_METRIC_QUERIES", "").strip()
    if not raw:
        raise ValueError("GRAFANA_METRIC_QUERIES must configure at least one metric query.")
    queries = json.loads(raw)
    if not isinstance(queries, dict) or not queries:
        raise ValueError("GRAFANA_METRIC_QUERIES must be a non-empty JSON object.")
    if len(queries) > len(METRIC_DEFINITIONS):
        raise ValueError("GRAFANA_METRIC_QUERIES has too many metric entries.")
    for name, query in queries.items():
        if name not in METRIC_DEFINITIONS or not isinstance(query, str) or not query.strip():
            raise ValueError(f"Unsupported or empty Grafana metric query: {name!r}.")
    return queries


def _query_url(endpoint: str, query: str) -> str:
    parts = urlsplit(endpoint)
    if parts.scheme != "https" and not (
        parts.scheme == "http" and parts.hostname in {"localhost", "127.0.0.1", "::1"}
    ):
        raise ValueError("Grafana query endpoint must use HTTPS (HTTP is allowed only on loopback).")
    if not parts.hostname or parts.username or parts.password or parts.fragment:
        raise ValueError("Grafana query endpoint is malformed.")
    params = parse_qsl(parts.query, keep_blank_values=True)
    if params:
        raise ValueError("Grafana endpoint URL must not contain query parameters.")
    params.append(("query", query))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(params), ""))


def _failed_signal(
    name: str,
    endpoint: str,
    source_id: str,
    retrieved_at: str,
    status: str,
    message: str,
    *,
    evidence_origin: str = "live_grafana",
    endpoint_label: str | None = None,
) -> Dict[str, Any]:
    signal_id, display_name, unit = METRIC_DEFINITIONS[name]
    return {
        "signal_id": signal_id,
        "source_type": "metric",
        "name": display_name,
        "url": endpoint_label or endpoint,
        "source_id": f"{source_id}:{name}",
        "value": f"Unavailable ({status})",
        "unit": unit,
        "source_updated_at": "Unavailable",
        "retrieved_at": retrieved_at,
        "age_seconds": 1_000_000_000.0,
        "is_cached": False,
        "is_stale": True,
        "evidence_origin": evidence_origin,
        "retrieval_status": status,
        "raw_payload": {"error": message[:240]},
    }


def fetch_grafana_metrics(retrieved_at: datetime | None = None) -> List[Dict[str, Any]]:
    """Query an explicitly configured Grafana Prometheus-compatible endpoint.

    The endpoint must return the Prometheus instant-query JSON envelope. No fixture
    data is used by this adapter, including when the endpoint is unavailable.
    """
    endpoint = os.getenv("GRAFANA_PROMETHEUS_QUERY_URL", "").strip()
    source_id = os.getenv("GRAFANA_SOURCE_ID", "configured-grafana").strip()
    retrieved_dt = retrieved_at or datetime.now(timezone.utc)
    if retrieved_dt.tzinfo is None or retrieved_dt.utcoffset() is None:
        retrieved_dt = retrieved_dt.replace(tzinfo=timezone.utc)
    retrieved_dt = retrieved_dt.astimezone(timezone.utc)
    retrieved_iso = retrieved_dt.isoformat()
    if os.getenv("OFFLINE_MODE", "true").strip().lower() != "false":
        return [
            _failed_signal(
                name, "", source_id, retrieved_iso, "offline",
                "External Grafana requests are disabled in offline mode.",
                evidence_origin="unavailable_offline",
                endpoint_label="Grafana source not contacted (offline mode)",
            )
            for name in METRIC_DEFINITIONS
        ]
    if not endpoint:
        raise ValueError("GRAFANA_PROMETHEUS_QUERY_URL is not configured.")
    queries = _configured_queries()
    timeout = float(os.getenv("GRAFANA_TIMEOUT_SECONDS", "5"))
    if not 0.1 <= timeout <= 30:
        raise ValueError("GRAFANA_TIMEOUT_SECONDS must be between 0.1 and 30.")
    api_key = os.getenv("GRAFANA_API_KEY", "").strip()
    results: List[Dict[str, Any]] = []

    for name, query in queries.items():
        request_url = _query_url(endpoint, query)
        request = Request(
            request_url,
            headers={
                "Accept": "application/json",
                **({"Authorization": f"Bearer {api_key}"} if api_key else {}),
            },
        )
        try:
            with build_opener(_NoRedirectHandler).open(request, timeout=timeout) as response:
                status_code = response.getcode()
                body = response.read(1_000_001)
            if status_code != 200:
                results.append(_failed_signal(
                    name, endpoint, source_id, retrieved_iso,
                    "http_error", f"HTTP status {status_code}",
                ))
                continue
            if len(body) > 1_000_000:
                results.append(_failed_signal(
                    name, endpoint, source_id, retrieved_iso,
                    "malformed_response", "Response exceeded 1 MB.",
                ))
                continue
            payload = json.loads(body)
            if (
                not isinstance(payload, dict)
                or payload.get("status") != "success"
                or not isinstance(payload.get("data"), dict)
                or payload["data"].get("resultType") != "vector"
                or not isinstance(payload["data"].get("result"), list)
            ):
                results.append(_failed_signal(
                    name, endpoint, source_id, retrieved_iso,
                    "malformed_response", "Expected a successful Prometheus instant-query vector.",
                ))
                continue
            vector = payload["data"]["result"]
            if not vector:
                results.append(_failed_signal(
                    name, endpoint, source_id, retrieved_iso,
                    "missing_value", "Query returned no vector samples.",
                ))
                continue
            sample = vector[0]
            value_pair = sample.get("value") if isinstance(sample, dict) else None
            if not isinstance(value_pair, list) or len(value_pair) != 2:
                results.append(_failed_signal(
                    name, endpoint, source_id, retrieved_iso,
                    "malformed_response", "Vector sample has no [timestamp, value] pair.",
                ))
                continue
            if value_pair[0] is None or value_pair[0] == "":
                results.append(_failed_signal(
                    name, endpoint, source_id, retrieved_iso,
                    "missing_timestamp", "Vector sample timestamp is missing.",
                ))
                continue
            try:
                observed_dt = datetime.fromtimestamp(float(value_pair[0]), tz=timezone.utc)
                value = float(value_pair[1])
            except (TypeError, ValueError, OverflowError, OSError):
                results.append(_failed_signal(
                    name, endpoint, source_id, retrieved_iso,
                    "malformed_response", "Vector sample timestamp or value is invalid.",
                ))
                continue
            if not math.isfinite(value):
                results.append(_failed_signal(
                    name, endpoint, source_id, retrieved_iso,
                    "malformed_response", "Vector sample value is not finite.",
                ))
                continue
            signal_id, display_name, unit = METRIC_DEFINITIONS[name]
            labels = sample.get("metric", {})
            label_source = labels.get("__name__") if isinstance(labels, dict) else None
            results.append({
                "signal_id": signal_id,
                "source_type": "metric",
                "name": display_name,
                "url": endpoint,
                "source_id": f"{source_id}:{label_source or name}",
                "value": str(value),
                "unit": unit,
                "source_updated_at": observed_dt.isoformat(),
                "retrieved_at": retrieved_iso,
                "age_seconds": max(0.0, (retrieved_dt - observed_dt).total_seconds()),
                "is_cached": False,
                "is_stale": observed_dt > retrieved_dt,
                "evidence_origin": "live_grafana",
                "retrieval_status": "success",
                "raw_payload": {"labels": labels if isinstance(labels, dict) else {}},
            })
        except HTTPError as exc:
            results.append(_failed_signal(
                name, endpoint, source_id, retrieved_iso,
                "http_error", f"HTTP status {exc.code}",
            ))
        except (TimeoutError, socket.timeout) as exc:
            results.append(_failed_signal(
                name, endpoint, source_id, retrieved_iso,
                "timeout", type(exc).__name__,
            ))
        except URLError as exc:
            reason = exc.reason
            status = "timeout" if isinstance(reason, (TimeoutError, socket.timeout)) else "unavailable"
            results.append(_failed_signal(
                name, endpoint, source_id, retrieved_iso, status, type(reason).__name__,
            ))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            results.append(_failed_signal(
                name, endpoint, source_id, retrieved_iso,
                "malformed_response", type(exc).__name__,
            ))
        except OSError as exc:
            logger.warning("Configured Grafana source unavailable source_id=%s error_type=%s", source_id, type(exc).__name__)
            results.append(_failed_signal(
                name, endpoint, source_id, retrieved_iso, "unavailable", type(exc).__name__,
            ))
    return results
