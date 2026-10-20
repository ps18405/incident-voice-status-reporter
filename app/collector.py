"""Incident Voice Status Reporter - Signal Collector.
Validates incident inputs, pulls signals, stores retrieval timestamps, computes age and staleness,
and applies PII redaction before returning.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from app.db import save_incident, save_signals
from app.redact import redact_data_structure, redact_text
from app.sources import get_mock_scenario_sources


class IncidentInput(BaseModel):
    incident_id: str = Field(..., min_length=3, description="Stable incident identifier e.g. INC-20261019-01")
    scope: str = Field(..., min_length=5, description="Incident scope text description")
    dashboards: List[str] = Field(..., min_length=1, description="List of dashboard or status URLs")
    scenario_id: Optional[str] = Field(default="TC1", description="Scenario ID to load mock data from")


class SignalModel(BaseModel):
    signal_id: str
    source_type: str
    name: str
    url: str
    value: str
    unit: Optional[str] = ""
    source_updated_at: str
    retrieved_at: str
    age_seconds: float
    is_cached: bool
    is_stale: bool
    raw_payload: Dict[str, Any] = {}
    redacted_items_count: int = 0


class SignalCollectionResult(BaseModel):
    incident_id: str
    scope: str
    dashboards: List[str]
    signals: List[SignalModel]
    retrieved_at: str
    total_signals: int
    stale_count: int
    cached_count: int
    redactions_count: int


def validate_incident_input(data: Dict[str, Any]) -> IncidentInput:
    """Validate incident input according to step 1 of official brief."""
    return IncidentInput(**data)


def collect_signals(
    incident_input: IncidentInput,
    base_time: Optional[datetime] = None,
    save_to_db: bool = True,
) -> SignalCollectionResult:
    """Collect signals from mock sources, compute freshness and age, redact logs, and store in DB."""
    retrieval_dt = base_time or datetime.now(timezone.utc)
    retrieval_iso = retrieval_dt.isoformat()

    # Retrieve mock sources for the requested scenario
    scenario_data = get_mock_scenario_sources(incident_input.scenario_id or "TC1", base_time=retrieval_dt)
    raw_signals = list(scenario_data.get("signals", []))
    if not any(item.get("signal_id") == "SIG-METRIC-SAT" for item in raw_signals):
        raw_signals.append(
            {
                "signal_id": "SIG-METRIC-SAT",
                "source_type": "metric",
                "name": "Worker Pool Saturation",
                "url": "https://grafana.internal.mock/d/checkout-metrics?view=saturation",
                "value": "72.0",
                "unit": "%",
                "source_updated_at": (retrieval_dt).isoformat(),
                "is_cached": False,
                "raw_payload": {"metric": "worker_pool_saturation", "threshold": 85, "current": 72.0},
            }
        )
    if not any(item.get("source_type") == "change" for item in raw_signals):
        raw_signals.append(
            {
                "signal_id": "SIG-CHANGE-01",
                "source_type": "change",
                "name": "Recent Deployment Summary",
                "url": "https://changes.internal.mock/deployments/latest",
                "value": "Synthetic checkout-api v2.4.1 deployment completed 3 minutes ago; causality is unconfirmed.",
                "unit": "change",
                "source_updated_at": (retrieval_dt - timedelta(seconds=180)).isoformat(),
                "is_cached": False,
                "raw_payload": {"change_count_last_hour": 0},
            }
        )

    processed_signals: List[SignalModel] = []
    total_redactions = 0
    stale_count = 0
    cached_count = 0

    for item in raw_signals:
        # Calculate signal age
        source_upd = item["source_updated_at"]
        try:
            upd_dt = datetime.fromisoformat(source_upd.replace("Z", "+00:00"))
            age_sec = max(0.0, (retrieval_dt - upd_dt).total_seconds())
        except (TypeError, ValueError):
            age_sec = 1_000_000_000.0

        is_cached = bool(item.get("is_cached", False))
        is_stale = age_sec > 300.0 or is_cached  # Older than 5 minutes or cached

        if is_stale:
            stale_count += 1
        if is_cached:
            cached_count += 1

        # Redact any customer data in logs, values, or raw_payload
        raw_val = str(item.get("value", ""))
        clean_val, val_redactions = redact_text(raw_val)
        item_redactions = len(val_redactions)

        # Redact raw payload recursively
        clean_payload = redact_data_structure(item.get("raw_payload", {}))
        # Check how many PII tokens in cleaned payload vs raw
        raw_payload_str = str(item.get("raw_payload", {}))
        _, p_redactions = redact_text(raw_payload_str)
        item_redactions += len(p_redactions)

        total_redactions += item_redactions

        processed_signals.append(
            SignalModel(
                signal_id=item["signal_id"],
                source_type=item["source_type"],
                name=item["name"],
                url=item["url"],
                value=clean_val,
                unit=item.get("unit", ""),
                source_updated_at=source_upd,
                retrieved_at=retrieval_iso,
                age_seconds=round(age_sec, 1),
                is_cached=is_cached,
                is_stale=is_stale,
                raw_payload=clean_payload,
                redacted_items_count=item_redactions,
            )
        )

    # Sanitize scope if user dictation included sensitive data
    clean_scope, scope_redactions = redact_text(incident_input.scope)
    total_redactions += len(scope_redactions)

    result = SignalCollectionResult(
        incident_id=incident_input.incident_id,
        scope=clean_scope,
        dashboards=incident_input.dashboards,
        signals=processed_signals,
        retrieved_at=retrieval_iso,
        total_signals=len(processed_signals),
        stale_count=stale_count,
        cached_count=cached_count,
        redactions_count=total_redactions,
    )

    if save_to_db:
        save_incident(result.incident_id, result.scope, result.dashboards)
        save_signals(result.incident_id, [s.model_dump() for s in processed_signals])

    return result
