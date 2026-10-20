"""Deterministic validation of LLM incident decisions and claims."""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List

from app.collector import SignalCollectionResult
from app.redact import scan_for_unredacted_pii
from app.rules import DecisionResult

RECOVERY_WORDING = re.compile(r"\b(recovered|resolved|fixed)\b", re.IGNORECASE)


def validate_agent_output(
    output: Dict[str, Any],
    collection: SignalCollectionResult,
    decision: DecisionResult,
) -> List[str]:
    violations: List[str] = []
    if output.get("state") != decision.status:
        violations.append(f"state must match deterministic rule state {decision.status}")
    script = output.get("voice_script")
    timestamp_pattern = r"^\s*(At \d{2}:\d{2}(?::\d{2})? UTC|20\d{2}-\d{2}-\d{2}T)"
    if not isinstance(script, str) or not re.match(timestamp_pattern, script):
        violations.append("voice_script must start with a timestamp")
    claims = output.get("claims")
    if not isinstance(claims, list) or not claims:
        violations.append("claims must be a non-empty list")
        claims = []
    valid_ids = {signal.signal_id for signal in collection.signals}
    evidence_by_id = {signal.signal_id: signal for signal in collection.signals}
    for index, claim in enumerate(claims):
        signal_id = claim.get("signal_id") if isinstance(claim, dict) else None
        if (
            not isinstance(claim, dict)
            or not isinstance(signal_id, str)
            or signal_id not in valid_ids
            or not isinstance(claim.get("text"), str)
            or not claim["text"].strip()
        ):
            violations.append(f"claim {index + 1} must cite a signal_id in this run's evidence")
        elif (
            f"[{signal_id}]" not in claim["text"]
            or evidence_by_id[signal_id].source_updated_at not in claim["text"]
        ):
            violations.append(
                f"claim {index + 1} text must include [{signal_id}] and its exact source_updated_at timestamp"
            )
        elif (
            not isinstance(script, str)
            or f"[{signal_id}]" not in script
            or evidence_by_id[signal_id].source_updated_at not in script
        ):
            violations.append(
                f"voice_script must include claim {index + 1} with [{signal_id}] and its source timestamp"
            )
    lowered = script.lower() if isinstance(script, str) else ""
    post = output.get("proposed_post")
    lowered_post = post.lower() if isinstance(post, str) else ""
    if decision.status == "UNCERTAIN" and isinstance(script, str) and RECOVERY_WORDING.search(script):
        violations.append("uncertain voice_script cannot claim recovery, resolution, or a fix")
    if (
        decision.status == "UNCERTAIN"
        and isinstance(post, str)
        and RECOVERY_WORDING.search(post)
    ):
        violations.append("uncertain proposed_post cannot claim recovery, resolution, or a fix")
    if any(signal.is_cached for signal in collection.signals) and (
        "not proof of recovery" not in lowered
        or "not proof of recovery" not in lowered_post
    ):
        violations.append("cached evidence requires the phrase 'not proof of recovery'")
    if decision.recovery_uncertain_warning and (
        "recovery uncertain" not in lowered
        or "recovery uncertain" not in lowered_post
    ):
        violations.append("a failing health check requires the phrase 'recovery uncertain'")
    combined = json.dumps(output, ensure_ascii=True)
    if scan_for_unredacted_pii(combined):
        violations.append("output contains a PII pattern")
    if not isinstance(post, str) or not post.strip():
        violations.append("proposed_post must be a non-empty string")
    elif isinstance(claims, list):
        for index, claim in enumerate(claims):
            if isinstance(claim, dict):
                signal_id = claim.get("signal_id")
                if signal_id in valid_ids and f"[{signal_id}]" not in post:
                    violations.append(f"proposed_post must cite claim {index + 1} as [{signal_id}]")
    return violations
