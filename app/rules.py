"""Incident Voice Status Reporter - Decision Rules Engine.
Implements explicit, rule-based logic without LLM dependence:
- Cached, stale (>5m), or missing signal -> UNCERTAIN ('this is not proof of recovery')
- Health check not passing -> UNCERTAIN ('recovery uncertain')
- All fresh + health check passing + error rate > 1% -> DEGRADED
- All fresh + health check passing + error rate <= 1% -> RECOVERED
- Missing required evidence -> UNCERTAIN, never guess.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel

from app.collector import SignalCollectionResult, SignalModel
from app.db import save_decision


class DecisionResult(BaseModel):
    status: str  # DEGRADED | UNCERTAIN | RECOVERED
    reason: str
    uncertainty_flag: bool
    cached_warning: bool
    recovery_uncertain_warning: bool
    evidence_summary: List[Dict[str, Any]]
    key_findings: List[str]


def evaluate_decision_rules(
    collection: SignalCollectionResult,
    save_to_db: bool = True,
) -> DecisionResult:
    """Evaluate signals against strict operational decision rules."""
    signals_by_id = {s.signal_id: s for s in collection.signals}
    signals_by_type = {}
    for s in collection.signals:
        signals_by_type.setdefault(s.source_type, []).append(s)

    evidence_summary: List[Dict[str, Any]] = []
    key_findings: List[str] = []
    for s in collection.signals:
        evidence_summary.append({
            "signal_id": s.signal_id,
            "name": s.name,
            "source_type": s.source_type,
            "url": s.url,
            "value": s.value,
            "unit": s.unit,
            "age_seconds": s.age_seconds,
            "is_cached": s.is_cached,
            "is_stale": s.is_stale,
            "source_updated_at": s.source_updated_at,
        })

    # Rule 1: Check for missing required evidence (never guess!)
    metric_signals = [s for s in collection.signals if s.source_type == "metric"]
    health_signals = [s for s in collection.signals if s.source_type == "health_check"]

    log_signals = [s for s in collection.signals if s.source_type == "log"]
    failing_health_checks = []
    for health_signal in health_signals:
        value = health_signal.value.lower()
        healthy = health_signal.raw_payload.get("healthy")
        explicitly_passing = (
            healthy is True
            or any(marker in value for marker in ("passing", "healthy", "200 ok"))
        )
        explicitly_failing = (
            healthy is False
            or any(marker in value for marker in ("failing", "unhealthy", "error", "500", "503"))
        )
        if explicitly_failing or not explicitly_passing:
            failing_health_checks.append(health_signal)
    if not metric_signals or not health_signals:
        missing = []
        if not metric_signals:
            missing.append("metric dashboard")
        if not health_signals:
            missing.append("health check")
        reason = f"Required evidence is missing ({', '.join(missing)}). Agent returns uncertain state, never guessing."
        key_findings.append("Missing required signals from monitoring sources.")
        res = DecisionResult(
            status="UNCERTAIN",
            reason=reason,
            uncertainty_flag=True,
            cached_warning=False,
            recovery_uncertain_warning=bool(failing_health_checks),
            evidence_summary=evidence_summary,
            key_findings=key_findings,
        )
        if save_to_db:
            save_decision(collection.incident_id, res.status, res.reason, res.uncertainty_flag, res.cached_warning, evidence_summary)
        return res

    # Rule 2: Check for cached dashboards (this is not proof of recovery)
    cached_signals = [s for s in collection.signals if s.is_cached]
    stale_signals = [s for s in collection.signals if (s.is_stale or s.age_seconds > 300.0) and not s.is_cached]

    # Extract primary error rate metric
    error_rate_val = None
    error_metric_signal: Optional[SignalModel] = None
    for s in metric_signals:
        if "err" in s.signal_id.lower() or "error" in s.name.lower():
            error_metric_signal = s
            try:
                error_rate_val = float(s.value.replace("%", "").strip())
            except ValueError:
                error_rate_val = None
            break

    # If error rate metric is cached or older than 5 minutes -> UNCERTAIN (TC2)
    if cached_signals:
        cached_names = ", ".join(f"{s.name} [{s.signal_id}]" for s in cached_signals)
        reason = f"Cached dashboard detected ({cached_names}). This is not proof of recovery."
        key_findings.append(f"Cached signals detected ({len(cached_signals)}). This is not proof of recovery.")
        res = DecisionResult(
            status="UNCERTAIN",
            reason=reason,
            uncertainty_flag=True,
            cached_warning=True,
            recovery_uncertain_warning=bool(failing_health_checks),
            evidence_summary=evidence_summary,
            key_findings=key_findings,
        )
        if save_to_db:
            save_decision(collection.incident_id, res.status, res.reason, res.uncertainty_flag, res.cached_warning, evidence_summary)
        return res

    if stale_signals:
        stale_names = ", ".join(f"{s.name} [{s.signal_id}] (age: {int(s.age_seconds)}s)" for s in stale_signals)
        reason = f"Monitoring signals are stale / older than 5 minutes ({stale_names}). State is uncertain."
        key_findings.append(f"Stale signals detected ({len(stale_signals)} older than 300 seconds).")
        res = DecisionResult(
            status="UNCERTAIN",
            reason=reason,
            uncertainty_flag=True,
            cached_warning=False,
            recovery_uncertain_warning=bool(failing_health_checks),
            evidence_summary=evidence_summary,
            key_findings=key_findings,
        )
        if save_to_db:
            save_decision(collection.incident_id, res.status, res.reason, res.uncertainty_flag, res.cached_warning, evidence_summary)
        return res

    # Rule 4: Health check not passing -> state UNCERTAIN ("recovery uncertain") (TC4)
    if failing_health_checks:
        failing_names = ", ".join(f"{s.name} [{s.signal_id}] => {s.value}" for s in failing_health_checks)
        # Even if metrics appear low/green (e.g. error rate <= 1%), failing health probe overrides
        reason = f"Health check probe is not passing ({failing_names}). Recovery uncertain."
        key_findings.append(f"Failing health probes detected: {failing_names}. Recovery uncertain.")
        
        # If error rate is high, also note degraded behavior
        status = "UNCERTAIN"

        res = DecisionResult(
            status=status,
            reason=reason,
            uncertainty_flag=True,
            cached_warning=False,
            recovery_uncertain_warning=True,
            evidence_summary=evidence_summary,
            key_findings=key_findings,
        )
        if save_to_db:
            save_decision(collection.incident_id, res.status, res.reason, res.uncertainty_flag, res.cached_warning, evidence_summary)
        return res

    if not log_signals:
        reason = "Required evidence is missing (log source unavailable). State is uncertain."
        key_findings.append("Log source is unavailable.")
        res = DecisionResult(
            status="UNCERTAIN",
            reason=reason,
            uncertainty_flag=True,
            cached_warning=False,
            recovery_uncertain_warning=False,
            evidence_summary=evidence_summary,
            key_findings=key_findings,
        )
        if save_to_db:
            save_decision(collection.incident_id, res.status, res.reason, res.uncertainty_flag, res.cached_warning, evidence_summary)
        return res

    # If error rate metric could not be parsed:
    if error_rate_val is None:
        reason = "Error rate metric value is missing or unparseable. Returning uncertain state."
        key_findings.append("Unparseable error rate metric.")
        res = DecisionResult(
            status="UNCERTAIN",
            reason=reason,
            uncertainty_flag=True,
            cached_warning=False,
            recovery_uncertain_warning=False,
            evidence_summary=evidence_summary,
            key_findings=key_findings,
        )
        if save_to_db:
            save_decision(collection.incident_id, res.status, res.reason, res.uncertainty_flag, res.cached_warning, evidence_summary)
        return res

    # Rule 5: Fresh signals + passing health check + error rate > 1% -> DEGRADED
    if error_rate_val > 1.0:
        sig_ref = f"[{error_metric_signal.signal_id}]" if error_metric_signal else ""
        status_conflict = any(
            signal.source_type == "status_page"
            and any(word in signal.value.lower() for word in ("resolved", "operational"))
            for signal in collection.signals
        )
        conflict_note = " Status page reports resolved/operational, which conflicts with the elevated metric." if status_conflict else ""
        reason = f"All signals fresh and health checks passing, but error rate is {error_rate_val}% {sig_ref}, exceeding the 1.0% threshold.{conflict_note}"
        key_findings.append(f"Elevated error rate: {error_rate_val}% (threshold 1.0%).")
        if status_conflict:
            key_findings.append("Status page claims recovery while error-rate telemetry remains elevated.")
        res = DecisionResult(
            status="DEGRADED",
            reason=reason,
            uncertainty_flag=False,
            cached_warning=False,
            recovery_uncertain_warning=False,
            evidence_summary=evidence_summary,
            key_findings=key_findings,
        )
        if save_to_db:
            save_decision(collection.incident_id, res.status, res.reason, res.uncertainty_flag, res.cached_warning, evidence_summary)
        return res

    # Rule 6: Fresh signals + passing health check + error rate <= 1% -> RECOVERED
    sig_ref = f"[{error_metric_signal.signal_id}]" if error_metric_signal else ""
    reason = f"All signals fresh, health checks passing (200 OK), and error rate is {error_rate_val}% {sig_ref} (below 1.0% threshold)."
    key_findings.append(f"Normal error rate: {error_rate_val}% (threshold <= 1.0%).")
    key_findings.append("All health checks responding normally.")
    res = DecisionResult(
        status="RECOVERED",
        reason=reason,
        uncertainty_flag=False,
        cached_warning=False,
        recovery_uncertain_warning=False,
        evidence_summary=evidence_summary,
        key_findings=key_findings,
    )
    if save_to_db:
        save_decision(collection.incident_id, res.status, res.reason, res.uncertainty_flag, res.cached_warning, evidence_summary)
    return res
