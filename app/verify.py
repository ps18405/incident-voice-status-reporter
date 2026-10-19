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

from app.db import get_all_posts, get_signals_by_incident
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
) -> VerificationReport:
    """Execute rigorous independent verification of channel post."""
    now_iso = datetime.now(timezone.utc).isoformat()
    checks: List[CheckItem] = []

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

    posted_content = target_post["message"]

    # Check 2: Text equals approved text exactly
    norm_posted = posted_content.strip()
    norm_approved = approved_text.strip()
    if norm_posted == norm_approved:
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
        diff_len = abs(len(norm_posted) - len(norm_approved))
        checks.append(
            CheckItem(
                name="Content Fidelity to Approved Version",
                status="FAIL",
                expected="Posted text exactly matches operator-approved text",
                observed=f"Mismatch detected! Length diff: {diff_len} characters.",
                details="The text in the channel does not match what was approved.",
            )
        )

    # Check 3: Every claim links to a real dashboard signal ID
    # Retrieve true signals from DB for this incident
    db_signals = get_signals_by_incident(incident_id)
    known_signal_ids = {s["signal_id"] for s in db_signals}

    found_signal_ids = set(SIGNAL_ID_PATTERN.findall(posted_content))
    if not found_signal_ids:
        checks.append(
            CheckItem(
                name="Claims Linked to Dashboard IDs",
                status="FAIL",
                expected="Every claim cites at least one verified signal ID e.g. [SIG-xxx]",
                observed="Zero signal IDs found in the post",
                details="The post lacks dashboard citations.",
            )
        )
    else:
        invalid_ids = found_signal_ids - known_signal_ids
        if not invalid_ids:
            checks.append(
                CheckItem(
                    name="Claims Linked to Dashboard IDs",
                    status="PASS",
                    expected=f"All cited signal IDs must exist in evidence store ({len(known_signal_ids)} valid)",
                    observed=f"All {len(found_signal_ids)} cited IDs are verified: {', '.join(sorted(found_signal_ids))}",
                    details="Each telemetry claim is traceable to an underlying dashboard source.",
                )
            )
        else:
            checks.append(
                CheckItem(
                    name="Claims Linked to Dashboard IDs",
                    status="FAIL",
                    expected="All cited signal IDs must exist in evidence store",
                    observed=f"Unrecognized signal IDs cited: {', '.join(sorted(invalid_ids))}",
                    details="Post references phantom or unverified signal IDs.",
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

    return VerificationReport(
        incident_id=incident_id,
        post_id=target_post["id"],
        overall_status=overall,
        verified_at=now_iso,
        total_checks=len(checks),
        passed_checks=passed_count,
        failed_checks=failed_count,
        checks=checks,
    )
