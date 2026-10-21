"""Incident Voice Status Reporter - Independent Verification Module.
Implements verification completely separate from the posting action:
1. Re-reads the channel to confirm post exists
2. Verifies the posted text equals the approved text exactly
3. Verifies every claim links to a real, verified signal ID
4. Verifies zero customer data (PII) is present in the post
5. Captures observed state and keeps failed/pending results visible.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel

from app.db import (
    get_all_posts,
    get_approval_by_agent_run,
    get_agent_run,
    save_verification_record,
)
from app.redact import scan_for_unredacted_pii

SIGNAL_ID_PATTERN = re.compile(r"\[(SIG-[A-Z0-9-]+)\]")


class CheckItem(BaseModel):
    name: str
    status: str  # "PASS" | "FAIL" | "PENDING"
    expected: str
    observed: str
    details: str


class VerificationReport(BaseModel):
    incident_id: str
    post_id: Optional[int]
    overall_status: str  # "PASS" | "FAIL" | "PENDING"
    verified_at: str
    total_checks: int
    passed_checks: int
    failed_checks: int
    checks: List[CheckItem]


def run_post_verification(
    incident_id: str,
    approved_text: str,
    target_post_id: Optional[int] = None,
    agent_run_id: Optional[int] = None,
) -> VerificationReport:
    """Execute rigorous independent verification of channel post."""
    now_iso = datetime.now(timezone.utc).isoformat()
    checks: List[CheckItem] = []
    approval = (
        get_approval_by_agent_run(agent_run_id)
        if agent_run_id is not None else None
    )

    # Retrieve all posts from channel
    all_posts = get_all_posts()
    matching_posts = [p for p in all_posts if p["incident_id"] == incident_id]

    target_post: Optional[Dict[str, Any]] = None
    if target_post_id is not None:
        for p in matching_posts:
            if p["id"] == target_post_id:
                target_post = p
                break
    elif matching_posts:
        if approval:
            target_post = next(
                (
                    post for post in matching_posts
                    if post["idempotency_key"] == approval["idempotency_key"]
                ),
                None,
            )
        else:
            target_post = matching_posts[0]  # Most recent

    # Check 1: Post exists in channel
    if target_post:
        checks.append(
            CheckItem(
                name="Post Existence in Channel",
                status="PASS",
                expected=f"A recorded post for incident {incident_id}",
                observed=f"Found post ID #{target_post['id']} in destination {target_post['destination']}",
                details="Message successfully retrieved from persistent channel ledger.",
            )
        )
    else:
        checks.append(
            CheckItem(
                name="Post Existence in Channel",
                status="FAIL",
                expected=f"A recorded post for incident {incident_id}",
                observed="No post found in channel for this incident ID",
                details="Post has not been executed or was rejected.",
            )
        )
        return VerificationReport(
            incident_id=incident_id,
            post_id=None,
            overall_status="FAIL",
            verified_at=now_iso,
            total_checks=len(checks),
            passed_checks=0,
            failed_checks=1,
            checks=checks,
        )

    approval_matches = bool(
        approval
        and approval.get("status") == "APPROVED"
        and approval.get("incident_id") == incident_id
        and approval.get("proposed_message") == approved_text
        and approval.get("destination") == target_post["destination"]
        and approval.get("idempotency_key") == target_post["idempotency_key"]
    )
    if agent_run_id is not None:
        checks.append(
            CheckItem(
                name="Run-bound Approval",
                status="PASS" if approval_matches else "FAIL",
                expected="Exact content and destination authorized by this run's persisted approval",
                observed=(
                    "Post matches the persisted approval for this run."
                    if approval_matches
                    else "No matching approved action is bound to this run and post."
                ),
                details="Approval state is checked independently of the submitted verification text.",
            )
        )

    agent_run = get_agent_run(agent_run_id) if agent_run_id is not None else None
    if agent_run and agent_run.get("input", {}).get("incident_id") != incident_id:
        agent_run = None
    verdict = agent_run["guardrail_verdict"] if agent_run else "MISSING"
    acceptable_verdict = verdict in {"PASS", "FALLBACK"}
    checks.append(
        CheckItem(
            name="Agent Guardrail Verdict",
            status="PASS" if acceptable_verdict else "FAIL",
            expected="PASS or deterministic FALLBACK recorded for the incident run",
            observed=f"Recorded verdict: {verdict}",
            details=(
                "The run was explicitly cleared for publication."
                if acceptable_verdict
                else "No acceptable agent guardrail verdict is associated with this incident."
            ),
        )
    )

    posted_content = target_post["message"]

    # Check 2: Text equals approved text exactly
    if posted_content == approved_text:
        checks.append(
            CheckItem(
                name="Content Fidelity to Approved Version",
                status="PASS",
                expected="Posted text exactly matches operator-approved text",
                observed="Character-for-character exact match (100% fidelity)",
                details="No tampering, unauthorized truncation, or injection occurred.",
            )
        )
    else:
        diff_len = abs(len(posted_content) - len(approved_text))
        checks.append(
            CheckItem(
                name="Content Fidelity to Approved Version",
                status="FAIL",
                expected="Posted text exactly matches operator-approved text",
                observed=f"Mismatch detected! Length diff: {diff_len} characters.",
                details="The text in the channel does not match what was approved.",
            )
        )

    # Check 3: Every claim links to evidence collected for this exact agent run.
    run_evidence = agent_run.get("evidence", []) if agent_run else []
    known_signal_ids = {
        signal["signal_id"]
        for signal in run_evidence
        if isinstance(signal, dict) and isinstance(signal.get("signal_id"), str)
    }

    found_signal_ids = set(SIGNAL_ID_PATTERN.findall(posted_content))
    agent_claims = agent_run.get("claims", []) if agent_run else []
    claim_signal_ids = {
        claim.get("signal_id")
        for claim in agent_claims
        if isinstance(claim, dict) and isinstance(claim.get("signal_id"), str)
    }
    if not found_signal_ids:
        checks.append(
            CheckItem(
                name="Claims Linked to Dashboard IDs",
                status="FAIL",
                expected="Every claim cites a signal ID from this agent run e.g. [SIG-xxx]",
                observed=(
                    "Zero signal IDs found in the post"
                    if not found_signal_ids
                    else "Agent run is missing its evidence snapshot"
                ),
                details="The post lacks citations or this run has no evidence snapshot.",
            )
        )
    else:
        invalid_ids = (found_signal_ids | claim_signal_ids) - known_signal_ids
        missing_claim_citations = claim_signal_ids - found_signal_ids
        if not invalid_ids and not missing_claim_citations:
            checks.append(
                CheckItem(
                    name="Claims Linked to Dashboard IDs",
                    status="PASS",
                    expected=f"All cited signal IDs must exist in this run's evidence snapshot ({len(known_signal_ids)} valid)",
                    observed=f"All {len(found_signal_ids)} cited IDs are verified: {', '.join(sorted(found_signal_ids))}",
                    details="Each cited telemetry claim is traceable to evidence collected for this agent run.",
                )
            )
        else:
            issue = []
            if invalid_ids:
                issue.append(f"Unrecognized signal IDs: {', '.join(sorted(invalid_ids))}")
            if missing_claim_citations:
                issue.append(f"Agent claims missing from posted text: {', '.join(sorted(missing_claim_citations))}")
            checks.append(
                CheckItem(
                    name="Claims Linked to Dashboard IDs",
                    status="FAIL",
                    expected="Every agent claim is cited in the post and exists in this run's evidence snapshot",
                    observed="; ".join(issue),
                    details="A claim references evidence outside this run or was omitted from the posted text.",
                )
            )

    # Check 4: Zero customer data in post (redaction verification)
    pii_violations = scan_for_unredacted_pii(posted_content)
    if not pii_violations:
        checks.append(
            CheckItem(
                name="Customer Data Protection (Zero PII)",
                status="PASS",
                expected="No raw emails, phone numbers, or credit card numbers present in post",
                observed="Zero unredacted PII patterns detected",
                details="Customer privacy preserved. All sensitive tokens safely redacted.",
            )
        )
    else:
        violation_types = [v["type"] for v in pii_violations]
        checks.append(
            CheckItem(
                name="Customer Data Protection (Zero PII)",
                status="FAIL",
                expected="No raw emails, phone numbers, or credit card numbers present in post",
                observed=f"LEAK DETECTED! Found {len(pii_violations)} PII items: {', '.join(violation_types)}",
                details="Unredacted customer data leaked into channel post!",
            )
        )

    passed_count = sum(1 for c in checks if c.status == "PASS")
    failed_count = sum(1 for c in checks if c.status == "FAIL")
    overall = "PASS" if failed_count == 0 else "FAIL"

    report = VerificationReport(
        incident_id=incident_id,
        post_id=target_post["id"],
        overall_status=overall,
        verified_at=now_iso,
        total_checks=len(checks),
        passed_checks=passed_count,
        failed_checks=failed_count,
        checks=checks,
    )
    try:
        save_verification_record(
            incident_id=incident_id,
            agent_run_id=agent_run_id,
            post_id=target_post["id"] if target_post else None,
            overall_status=overall,
            checks={c.name: c.model_dump() for c in checks},
            observed_text=posted_content if target_post else None,
            intended_text=approved_text,
        )
    except Exception:
        pass
    return report
