"""Incident Voice Status Reporter - Voice Brief and Update Generator.
Builds the voice brief and proposed channel post.
Rules:
- Voice brief starts with a timestamp
- States the operational status (DEGRADED, UNCERTAIN, RECOVERED)
- Lists claims where EVERY claim carries the ID of the supporting dashboard/signal
- Cached dashboards state 'this is not proof of recovery'
- Failing health checks state 'recovery uncertain'
- All customer data is redacted before display, speech, or posting
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel

from app.collector import SignalCollectionResult
from app.redact import redact_text
from app.rules import DecisionResult


class ClaimMapping(BaseModel):
    claim_id: str
    claim_text: str
    signal_id: str
    source_name: str
    source_url: str
    extracted_value: str
    source_updated_at: str
    retrieved_at: str = ""
    age_seconds: float = 0.0
    freshness_status: str = "UNKNOWN"
    is_cached: bool
    is_stale: bool


class BriefOutput(BaseModel):
    incident_id: str
    timestamp_utc: str
    status: str
    voice_script: str
    proposed_channel_post: str
    destination: str
    claims: List[ClaimMapping]
    redactions_count: int


def build_voice_brief_and_post(
    collection: SignalCollectionResult,
    decision: DecisionResult,
    destination: Optional[str] = None,
) -> BriefOutput:
    """Generate the voice brief and proposed channel post with linked claims."""
    target_destination = destination or os.getenv("DEFAULT_CHANNEL", "#incident-response")
    # Current UTC timestamp formatted
    now_dt = datetime.now(timezone.utc)
    time_str = now_dt.strftime("%H:%M:%S")
    date_str = now_dt.strftime("%Y-%m-%d")
    full_timestamp = f"{date_str} {time_str} UTC"

    claims: List[ClaimMapping] = []
    voice_lines: List[str] = []
    post_lines: List[str] = []

    # Voice Script: Starts with timestamp and status
    voice_lines.append(f"At {time_str} UTC, incident voice update for {collection.incident_id}.")
    voice_lines.append(f"Current operational status is {decision.status}.")

    # Specific uncertainty alerts in speech
    if decision.cached_warning:
        voice_lines.append("Notice: cached dashboard detected. This is not proof of recovery.")
    if decision.recovery_uncertain_warning:
        voice_lines.append("Notice: health check probe is failing. Recovery uncertain.")

    # Process claims for every collected signal
    for idx, sig in enumerate(collection.signals, 1):
        claim_id = f"CLM-{idx:02d}"
        clean_val, _ = redact_text(str(sig.value))
        freshness_status = "CACHED" if sig.is_cached else "STALE" if sig.is_stale else "FRESH"
        extracted_value = (
            clean_val if sig.unit in {"", "log_entry"}
            else f"{clean_val} {sig.unit}".strip()
        )
        
        # Build speech-friendly and verified claim
        if sig.source_type == "metric":
            claim_text = (
                f"Metric {sig.name} is measured at {clean_val}{sig.unit} "
                f"from source [{sig.signal_id}] ({sig.url}), source updated at {sig.source_updated_at}, "
                f"retrieved at {sig.retrieved_at}; age {sig.age_seconds}s, freshness {freshness_status}."
            )
        elif sig.source_type == "status_page":
            claim_text = (
                f"Status page reports {clean_val} "
                f"from source [{sig.signal_id}] ({sig.url}), source updated at {sig.source_updated_at}, "
                f"retrieved at {sig.retrieved_at}; age {sig.age_seconds}s, freshness {freshness_status}."
            )
        elif sig.source_type == "health_check":
            claim_text = (
                f"Health check reports {clean_val} "
                f"from probe [{sig.signal_id}] ({sig.url}), source updated at {sig.source_updated_at}, "
                f"retrieved at {sig.retrieved_at}; age {sig.age_seconds}s, freshness {freshness_status}."
            )
        elif sig.source_type == "log":
            claim_text = (
                f"Log event from [{sig.signal_id}] ({sig.url}) records: {clean_val}; "
                f"source updated at {sig.source_updated_at}, retrieved at {sig.retrieved_at}; "
                f"age {sig.age_seconds}s, freshness {freshness_status}."
            )
        else:
            claim_text = (
                f"Signal {sig.name} has value {clean_val} from source [{sig.signal_id}] ({sig.url}), "
                f"source updated at {sig.source_updated_at}, retrieved at {sig.retrieved_at}; "
                f"age {sig.age_seconds}s, freshness {freshness_status}."
            )

        if sig.is_cached:
            claim_text += " Note: signal is cached."

        claims.append(
            ClaimMapping(
                claim_id=claim_id,
                claim_text=claim_text,
                signal_id=sig.signal_id,
                source_name=sig.name,
                source_url=sig.url,
                extracted_value=extracted_value,
                source_updated_at=sig.source_updated_at,
                retrieved_at=sig.retrieved_at,
                age_seconds=sig.age_seconds,
                freshness_status=freshness_status,
                is_cached=sig.is_cached,
                is_stale=sig.is_stale,
            )
        )
        voice_lines.append(f"Claim {idx}: {claim_text}")

    # Conclusion for voice
    if decision.status == "DEGRADED":
        voice_lines.append("Remediation is underway. Next update scheduled in 15 minutes.")
    elif decision.status == "UNCERTAIN":
        voice_lines.append("Awaiting fresh verification telemetry before concluding status.")
    elif decision.status == "RECOVERED":
        voice_lines.append("All key signals normal and verified. Monitoring for recurrence.")

    voice_script = " ".join(voice_lines)

    # Build Proposed Channel Post (Exact formatted text for team channel)
    post_lines.append(f"📢 **INCIDENT STATUS UPDATE — {collection.incident_id}**")
    post_lines.append(f"**Timestamp:** {full_timestamp}")
    post_lines.append(f"**Status:** `{decision.status}`")
    post_lines.append(f"**Scope:** {collection.scope}")
    post_lines.append("")
    post_lines.append(f"**Decision Rationale:** {decision.reason}")

    if decision.cached_warning:
        post_lines.append("⚠️ **CAUTION:** Cached dashboard detected. *This is not proof of recovery.*")
    if decision.recovery_uncertain_warning:
        post_lines.append("⚠️ **CAUTION:** Synthetic health check failing. *Recovery uncertain.*")

    post_lines.append("")
    post_lines.append("🔍 **Telemetry Evidence & Dashboard Citations:**")
    for clm in claims:
        post_lines.append(
            f"- **[{clm.signal_id}]** [{clm.source_name}]({clm.source_url}): "
            f"`{clm.extracted_value}` (source updated: {clm.source_updated_at}; "
            f"retrieved: {clm.retrieved_at}; age: {clm.age_seconds}s; freshness: {clm.freshness_status})"
        )

    post_lines.append("")
    if collection.redactions_count > 0:
        post_lines.append(f"🔒 *Automated Redaction Guard:* {collection.redactions_count} sensitive fields sanitized before posting.")
    else:
        post_lines.append("🔒 *Automated Redaction Guard:* Zero PII detected in telemetry stream.")

    post_lines.append(f"👤 *Action Status:* Pending on-call lead approval before publishing to `{target_destination}`.")

    proposed_post = "\n".join(post_lines)

    # Sanitize entire output one more time to guarantee safety
    safe_voice, v_red = redact_text(voice_script)
    safe_post, p_red = redact_text(proposed_post)
    total_redactions = collection.redactions_count + len(v_red) + len(p_red)

    return BriefOutput(
        incident_id=collection.incident_id,
        timestamp_utc=full_timestamp,
        status=decision.status,
        voice_script=safe_voice,
        proposed_channel_post=safe_post,
        destination=target_destination,
        claims=claims,
        redactions_count=total_redactions,
    )
