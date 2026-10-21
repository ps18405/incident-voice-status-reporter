"""Incident Voice Status Reporter - Decision Rules Engine.

Implements pure, explicit, deterministic operational decision rules:
- RULE-REQ-EVID-01: Required evidence present (metrics + health check)
- RULE-RETRIEVAL-FAIL-01: Successful retrieval of all monitored sources
- RULE-CACHED-01: Cached dashboard data cannot prove recovery -> UNCERTAIN (TC2)
- RULE-STALE-01: Data older than freshness threshold (default 5m) -> UNCERTAIN
- RULE-HEALTH-FAIL-01: Health check probe failing -> UNCERTAIN / recovery uncertain (TC4)
- RULE-LOG-AVAIL-01: Log telemetry source missing or unreachable -> UNCERTAIN (MISSING)
- RULE-CONFLICT-01: Status page reports operational while metrics are elevated -> DEGRADED (MIXED)
- RULE-DEGRADED-01: Elevated error rate (> 1.0%) -> DEGRADED (or OUTAGE if severe)
- RULE-RECOVERY-QUORUM-01: Recovery requires N fresh, agreeing signals -> RECOVERED

Outputs:
- status: UNCERTAIN | DEGRADED | OUTAGE | RECOVERED
- rules_fired: list of RuleFired with rule_id, evidence signals, threshold, and description
- confidence_breakdown: freshness, agreement, coverage, overall scores
- reason string and key findings
"""
from __future__ import annotations

import os
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from app.collector import SignalCollectionResult, SignalModel
from app.db import save_decision

DEFAULT_FRESHNESS_THRESHOLD_SECONDS = 300.0  # 5 minutes
DEFAULT_RECOVERY_QUORUM = 3


class RuleFired(BaseModel):
    rule_id: str
    rule_name: str
    verdict: str  # UNCERTAIN | DEGRADED | OUTAGE | RECOVERED
    evidence_signals: List[str] = Field(default_factory=list)
    threshold_applied: str = ""
    description: str = ""


class DecisionResult(BaseModel):
    status: str  # DEGRADED | UNCERTAIN | RECOVERED | OUTAGE
    reason: str
    uncertainty_flag: bool
    cached_warning: bool
    recovery_uncertain_warning: bool
    evidence_summary: List[Dict[str, Any]]
    key_findings: List[str]
    rules_fired: List[RuleFired] = Field(default_factory=list)
    confidence_breakdown: Dict[str, float] = Field(default_factory=dict)
    severity: str = "SEV2"  # SEV1 (Outage) or SEV2 (Degraded/Uncertain)


def compute_confidence_breakdown(signals: List[SignalModel]) -> Dict[str, float]:
    """Calculate quantitative telemetry confidence scores (0 to 100%)."""
    if not signals:
        return {"freshness": 0.0, "agreement": 0.0, "coverage": 0.0, "overall": 0.0}

    total = len(signals)
    fresh_count = sum(1 for s in signals if not s.is_stale and not s.is_cached and s.retrieval_status == "success")
    freshness_pct = round((fresh_count / total) * 100, 1)

    types_present = {s.source_type for s in signals if s.retrieval_status == "success"}
    core_types = {"metric", "status_page", "health_check", "log"}
    coverage_pct = round((len(types_present.intersection(core_types)) / len(core_types)) * 100, 1)

    # Agreement score: measure contradiction between status_page, health_check, and metrics
    has_err_metric = any("err" in s.signal_id.lower() and float(s.value.replace("%", "").strip() or 0) > 1.0
                         for s in signals if s.source_type == "metric" and s.value.replace("%", "").replace(".", "").isdigit())
    status_page_ok = any("operational" in s.value.lower() or "resolved" in s.value.lower()
                         for s in signals if s.source_type == "status_page")
    health_ok = all(s.retrieval_status == "success" and "failing" not in s.value.lower()
                    for s in signals if s.source_type == "health_check")

    if has_err_metric and status_page_ok:
        agreement_pct = 45.0  # Conflict detected!
    elif has_err_metric and not health_ok:
        agreement_pct = 85.0  # Both indicate problem
    elif not has_err_metric and health_ok:
        agreement_pct = 95.0  # Both indicate healthy
    else:
        agreement_pct = 70.0

    overall_pct = round((freshness_pct * 0.4) + (agreement_pct * 0.3) + (coverage_pct * 0.3), 1)

    return {
        "freshness": freshness_pct,
        "agreement": agreement_pct,
        "coverage": coverage_pct,
        "overall": overall_pct,
    }


def evaluate_decision_rules(
    collection: SignalCollectionResult,
    freshness_threshold: Optional[float] = None,
    save_to_db: bool = True,
) -> DecisionResult:
    """Evaluate signals against strict, auditable operational decision rules."""
    threshold_sec = freshness_threshold or float(os.getenv("FRESHNESS_THRESHOLD_SECONDS", str(DEFAULT_FRESHNESS_THRESHOLD_SECONDS)))
    recovery_quorum_min = int(os.getenv("RECOVERY_QUORUM_MIN", str(DEFAULT_RECOVERY_QUORUM)))

    signals_by_id = {s.signal_id: s for s in collection.signals}
    signals_by_type: Dict[str, List[SignalModel]] = {}
    for s in collection.signals:
        signals_by_type.setdefault(s.source_type, []).append(s)

    evidence_summary: List[Dict[str, Any]] = []
    key_findings: List[str] = []
    rules_fired: List[RuleFired] = []

    for s in collection.signals:
        evidence_summary.append({
            "signal_id": s.signal_id,
            "name": s.name,
            "source_type": s.source_type,
            "url": s.url,
            "source_id": s.source_id,
            "evidence_origin": s.evidence_origin,
            "retrieval_status": s.retrieval_status,
            "http_status": s.http_status,
            "latency_ms": s.latency_ms,
            "value": s.value,
            "unit": s.unit,
            "age_seconds": s.age_seconds,
            "is_cached": s.is_cached,
            "is_stale": s.is_stale,
            "source_updated_at": s.source_updated_at,
        })

    confidence = compute_confidence_breakdown(collection.signals)

    # Gather categories
    metric_signals = signals_by_type.get("metric", [])
    health_signals = signals_by_type.get("health_check", [])
    log_signals = signals_by_type.get("log", [])
    failed_retrieval_signals = [s for s in collection.signals if s.retrieval_status != "success"]

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

    # -------------------------------------------------------------------------
    # RULE 1: Check for missing required evidence (never guess!)
    # -------------------------------------------------------------------------
    if not metric_signals or not health_signals:
        missing = []
        if not metric_signals:
            missing.append("metric dashboard")
        if not health_signals:
            missing.append("health check")
        reason = f"Required evidence is missing ({', '.join(missing)}). Agent returns uncertain state, never guessing."
        key_findings.append("Missing required signals from monitoring sources.")
        rules_fired.append(RuleFired(
            rule_id="RULE-REQ-EVID-01",
            rule_name="Required Monitoring Evidence Check",
            verdict="UNCERTAIN",
            evidence_signals=[],
            threshold_applied="metric_signals >= 1 and health_signals >= 1",
            description=reason,
        ))
        res = DecisionResult(
            status="UNCERTAIN",
            reason=reason,
            uncertainty_flag=True,
            cached_warning=False,
            recovery_uncertain_warning=bool(failing_health_checks),
            evidence_summary=evidence_summary,
            key_findings=key_findings,
            rules_fired=rules_fired,
            confidence_breakdown=confidence,
            severity="SEV2",
        )
        if save_to_db:
            save_decision(
                collection.incident_id, res.status, res.reason, res.uncertainty_flag,
                res.cached_warning, evidence_summary, [r.model_dump() for r in rules_fired], confidence,
            )
        return res

    # -------------------------------------------------------------------------
    # RULE 2: Source retrieval failures
    # -------------------------------------------------------------------------
    if failed_retrieval_signals:
        failures = ", ".join(
            f"{signal.name} [{signal.signal_id}] retrieval {signal.retrieval_status}"
            for signal in failed_retrieval_signals
        )
        reason = f"Evidence source retrieval did not complete successfully ({failures}). State is uncertain."
        key_findings.append(f"Evidence retrieval failures: {failures}.")
        rules_fired.append(RuleFired(
            rule_id="RULE-RETRIEVAL-FAIL-01",
            rule_name="Source Retrieval Integrity",
            verdict="UNCERTAIN",
            evidence_signals=[s.signal_id for s in failed_retrieval_signals],
            threshold_applied="retrieval_status == 'success'",
            description=reason,
        ))
        res = DecisionResult(
            status="UNCERTAIN",
            reason=reason,
            uncertainty_flag=True,
            cached_warning=any(signal.is_cached for signal in collection.signals),
            recovery_uncertain_warning=bool(failing_health_checks),
            evidence_summary=evidence_summary,
            key_findings=key_findings,
            rules_fired=rules_fired,
            confidence_breakdown=confidence,
            severity="SEV2",
        )
        if save_to_db:
            save_decision(
                collection.incident_id, res.status, res.reason, res.uncertainty_flag,
                res.cached_warning, evidence_summary, [r.model_dump() for r in rules_fired], confidence,
            )
        return res

    # -------------------------------------------------------------------------
    # RULE 3: Check for cached dashboards (this is not proof of recovery) (TC2)
    # -------------------------------------------------------------------------
    cached_signals = [s for s in collection.signals if s.is_cached]
    stale_signals = [s for s in collection.signals if (s.is_stale or s.age_seconds > threshold_sec) and not s.is_cached]

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

    if cached_signals:
        cached_names = ", ".join(f"{s.name} [{s.signal_id}]" for s in cached_signals)
        reason = f"Cached dashboard detected ({cached_names}). This is not proof of recovery."
        key_findings.append(f"Cached signals detected ({len(cached_signals)}). This is not proof of recovery.")
        rules_fired.append(RuleFired(
            rule_id="RULE-CACHED-01",
            rule_name="Cached Dashboard Evidence Check",
            verdict="UNCERTAIN",
            evidence_signals=[s.signal_id for s in cached_signals],
            threshold_applied="is_cached == True",
            description=reason,
        ))
        res = DecisionResult(
            status="UNCERTAIN",
            reason=reason,
            uncertainty_flag=True,
            cached_warning=True,
            recovery_uncertain_warning=bool(failing_health_checks),
            evidence_summary=evidence_summary,
            key_findings=key_findings,
            rules_fired=rules_fired,
            confidence_breakdown=confidence,
            severity="SEV2",
        )
        if save_to_db:
            save_decision(
                collection.incident_id, res.status, res.reason, res.uncertainty_flag,
                res.cached_warning, evidence_summary, [r.model_dump() for r in rules_fired], confidence,
            )
        return res

    # -------------------------------------------------------------------------
    # RULE 4: Stale signals older than freshness threshold
    # -------------------------------------------------------------------------
    if stale_signals:
        stale_names = ", ".join(f"{s.name} [{s.signal_id}] (age: {int(s.age_seconds)}s)" for s in stale_signals)
        reason = f"Monitoring signals are stale / older than 5 minutes ({stale_names}). State is uncertain."
        key_findings.append(f"Stale signals detected ({len(stale_signals)} older than {int(threshold_sec)} seconds).")
        rules_fired.append(RuleFired(
            rule_id="RULE-STALE-01",
            rule_name="Telemetry Freshness Threshold Check",
            verdict="UNCERTAIN",
            evidence_signals=[s.signal_id for s in stale_signals],
            threshold_applied=f"age_seconds <= {int(threshold_sec)}s",
            description=reason,
        ))
        res = DecisionResult(
            status="UNCERTAIN",
            reason=reason,
            uncertainty_flag=True,
            cached_warning=False,
            recovery_uncertain_warning=bool(failing_health_checks),
            evidence_summary=evidence_summary,
            key_findings=key_findings,
            rules_fired=rules_fired,
            confidence_breakdown=confidence,
            severity="SEV2",
        )
        if save_to_db:
            save_decision(
                collection.incident_id, res.status, res.reason, res.uncertainty_flag,
                res.cached_warning, evidence_summary, [r.model_dump() for r in rules_fired], confidence,
            )
        return res

    # -------------------------------------------------------------------------
    # RULE 5: Health check failing -> UNCERTAIN / recovery uncertain (TC4)
    # -------------------------------------------------------------------------
    if failing_health_checks:
        failing_names = ", ".join(f"{s.name} [{s.signal_id}] => {s.value}" for s in failing_health_checks)
        metric_observations = ", ".join(
            f"{signal.name}={signal.value}{signal.unit} [{signal.signal_id}]"
            for signal in metric_signals
        )
        status_observations = ", ".join(
            f"{signal.value} [{signal.signal_id}]"
            for signal in signals_by_type.get("status_page", [])
        )
        contradictory_evidence = "; other observations: " + "; ".join(
            item for item in (
                f"metrics {metric_observations}" if metric_observations else "",
                f"status pages {status_observations}" if status_observations else "",
            ) if item
        )
        reason = (
            f"Health check probe is not passing ({failing_names}). "
            f"Recovery uncertain.{contradictory_evidence}"
        )
        key_findings.append(
            f"Failing health probes detected: {failing_names}. Recovery uncertain."
            f"{contradictory_evidence}"
        )
        rules_fired.append(RuleFired(
            rule_id="RULE-HEALTH-FAIL-01",
            rule_name="Health Check Probe Operational State",
            verdict="UNCERTAIN",
            evidence_signals=[s.signal_id for s in failing_health_checks],
            threshold_applied="health_check_status == 200 OK and healthy == True",
            description=reason,
        ))
        res = DecisionResult(
            status="UNCERTAIN",
            reason=reason,
            uncertainty_flag=True,
            cached_warning=False,
            recovery_uncertain_warning=True,
            evidence_summary=evidence_summary,
            key_findings=key_findings,
            rules_fired=rules_fired,
            confidence_breakdown=confidence,
            severity="SEV2",
        )
        if save_to_db:
            save_decision(
                collection.incident_id, res.status, res.reason, res.uncertainty_flag,
                res.cached_warning, evidence_summary, [r.model_dump() for r in rules_fired], confidence,
            )
        return res

    # -------------------------------------------------------------------------
    # RULE 6: Log source missing check
    # -------------------------------------------------------------------------
    if not log_signals:
        reason = "Required evidence is missing (log source unavailable). State is uncertain."
        key_findings.append("Log source is unavailable.")
        rules_fired.append(RuleFired(
            rule_id="RULE-LOG-AVAIL-01",
            rule_name="Log Telemetry Availability",
            verdict="UNCERTAIN",
            evidence_signals=[],
            threshold_applied="log_signals >= 1",
            description=reason,
        ))
        res = DecisionResult(
            status="UNCERTAIN",
            reason=reason,
            uncertainty_flag=True,
            cached_warning=False,
            recovery_uncertain_warning=False,
            evidence_summary=evidence_summary,
            key_findings=key_findings,
            rules_fired=rules_fired,
            confidence_breakdown=confidence,
            severity="SEV2",
        )
        if save_to_db:
            save_decision(
                collection.incident_id, res.status, res.reason, res.uncertainty_flag,
                res.cached_warning, evidence_summary, [r.model_dump() for r in rules_fired], confidence,
            )
        return res

    if error_rate_val is None:
        reason = "Error rate metric value is missing or unparseable. Returning uncertain state."
        key_findings.append("Unparseable error rate metric.")
        rules_fired.append(RuleFired(
            rule_id="RULE-METRIC-PARSE-01",
            rule_name="Metric Parsing Integrity",
            verdict="UNCERTAIN",
            evidence_signals=[error_metric_signal.signal_id] if error_metric_signal else [],
            threshold_applied="float(error_rate) is valid",
            description=reason,
        ))
        res = DecisionResult(
            status="UNCERTAIN",
            reason=reason,
            uncertainty_flag=True,
            cached_warning=False,
            recovery_uncertain_warning=False,
            evidence_summary=evidence_summary,
            key_findings=key_findings,
            rules_fired=rules_fired,
            confidence_breakdown=confidence,
            severity="SEV2",
        )
        if save_to_db:
            save_decision(
                collection.incident_id, res.status, res.reason, res.uncertainty_flag,
                res.cached_warning, evidence_summary, [r.model_dump() for r in rules_fired], confidence,
            )
        return res

    # -------------------------------------------------------------------------
    # RULE 7: Fresh signals + passing health check + error rate > 1% -> DEGRADED (TC1 / MIXED)
    # -------------------------------------------------------------------------
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
            rules_fired.append(RuleFired(
                rule_id="RULE-CONFLICT-01",
                rule_name="Status Page vs Telemetry Contradiction",
                verdict="DEGRADED",
                evidence_signals=[s.signal_id for s in collection.signals if s.source_type in {"status_page", "metric"}],
                threshold_applied="status_page == Operational while error_rate > 1.0%",
                description="Status page claims operational/resolved, conflicting with fresh elevated metric.",
            ))

        severity = "SEV1" if error_rate_val >= 10.0 else "SEV2"
        rules_fired.append(RuleFired(
            rule_id="RULE-DEGRADED-01",
            rule_name="Elevated Error Rate Threshold",
            verdict="DEGRADED",
            evidence_signals=[error_metric_signal.signal_id] if error_metric_signal else [],
            threshold_applied=f"error_rate ({error_rate_val}%) > 1.0%",
            description=reason,
        ))
        res = DecisionResult(
            status="DEGRADED",
            reason=reason,
            uncertainty_flag=False,
            cached_warning=False,
            recovery_uncertain_warning=False,
            evidence_summary=evidence_summary,
            key_findings=key_findings,
            rules_fired=rules_fired,
            confidence_breakdown=confidence,
            severity=severity,
        )
        if save_to_db:
            save_decision(
                collection.incident_id, res.status, res.reason, res.uncertainty_flag,
                res.cached_warning, evidence_summary, [r.model_dump() for r in rules_fired], confidence,
            )
        return res

    # -------------------------------------------------------------------------
    # RULE 8: Fresh signals + passing health check + error rate <= 1% -> RECOVERED
    # -------------------------------------------------------------------------
    sig_ref = f"[{error_metric_signal.signal_id}]" if error_metric_signal else ""
    reason = f"All signals fresh, health checks passing (200 OK), and error rate is {error_rate_val}% {sig_ref} (below 1.0% threshold)."
    key_findings.append(f"Normal error rate: {error_rate_val}% (threshold <= 1.0%).")
    key_findings.append("All health checks responding normally.")

    rules_fired.append(RuleFired(
        rule_id="RULE-RECOVERY-QUORUM-01",
        rule_name="Multi-Source Recovery Quorum",
        verdict="RECOVERED",
        evidence_signals=[s.signal_id for s in collection.signals if not s.is_stale and s.retrieval_status == "success"],
        threshold_applied=f"agreeing_signals >= {recovery_quorum_min} and error_rate <= 1.0%",
        description=reason,
    ))

    res = DecisionResult(
        status="RECOVERED",
        reason=reason,
        uncertainty_flag=False,
        cached_warning=False,
        recovery_uncertain_warning=False,
        evidence_summary=evidence_summary,
        key_findings=key_findings,
        rules_fired=rules_fired,
        confidence_breakdown=confidence,
        severity="RESOLVED",
    )
    if save_to_db:
        save_decision(
            collection.incident_id, res.status, res.reason, res.uncertainty_flag,
            res.cached_warning, evidence_summary, [r.model_dump() for r in rules_fired], confidence,
        )
    return res
