"""Incident Voice Status Reporter - Mock Team Channel.
Handles human approval gating and idempotent message posting.
Uses SHA-256 hash of (incident_id + message) as idempotency key to prevent duplicate posts on retries.
"""
from __future__ import annotations

import hashlib
import os
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from app.db import (
    clear_channel_posts,
    get_all_posts,
    get_post_by_idempotency_key,
    save_approval,
    save_post,
    update_approval_status,
)


class ChannelPostRequest(BaseModel):
    incident_id: str
    destination: str = Field(default_factory=lambda: os.getenv("DEFAULT_CHANNEL", "#incident-response"))
    message: str
    approval_decision: str  # "APPROVED" | "REJECTED"


class ChannelPostResult(BaseModel):
    success: bool
    status: str  # "POSTED" | "REJECTED" | "DUPLICATE_IGNORED"
    message: str
    destination: str
    idempotency_key: str
    post_id: Optional[int] = None
    posted_at: Optional[str] = None
    is_duplicate: bool = False


def generate_idempotency_key(incident_id: str, message: str) -> str:
    """Compute deterministic SHA-256 idempotency key from incident_id and normalized message text."""
    normalized = f"{incident_id.strip()}:{message.strip()}"
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def process_channel_approval_and_post(
    req: ChannelPostRequest,
) -> ChannelPostResult:
    """Process human approval decision.
    
    If REJECTED: Records rejection and posts nothing.
    If APPROVED: Posts to channel with strict idempotency guard against duplicates.
    """
    idem_key = generate_idempotency_key(req.incident_id, req.message)

    if req.approval_decision.upper() == "REJECTED":
        # Save rejection record in DB
        approval_id = save_approval(
            incident_id=req.incident_id,
            destination=req.destination,
            proposed_message=req.message,
            status="REJECTED",
            idempotency_key=idem_key,
        )
        return ChannelPostResult(
            success=False,
            status="REJECTED",
            message="Operator rejected the update. No post was published to the channel.",
            destination=req.destination,
            idempotency_key=idem_key,
            post_id=None,
            is_duplicate=False,
        )

    # Operator APPROVED
    approval_id = save_approval(
        incident_id=req.incident_id,
        destination=req.destination,
        proposed_message=req.message,
        status="APPROVED",
        idempotency_key=idem_key,
    )

    # Check for existing post with same idempotency key
    existing_post = get_post_by_idempotency_key(idem_key)
    if existing_post:
        # Duplicate post on retry prevented!
        return ChannelPostResult(
            success=True,
            status="DUPLICATE_IGNORED",
            message="Duplicate execution prevented: Post with this idempotency key already exists in channel.",
            destination=req.destination,
            idempotency_key=idem_key,
            post_id=existing_post["id"],
            posted_at=existing_post["posted_at"],
            is_duplicate=True,
        )

    # Fresh post publication
    post_id = save_post(
        incident_id=req.incident_id,
        destination=req.destination,
        message=req.message,
        idempotency_key=idem_key,
        is_duplicate=False,
    )

    return ChannelPostResult(
        success=True,
        status="POSTED",
        message="Update successfully approved by on-call lead and published to channel.",
        destination=req.destination,
        idempotency_key=idem_key,
        post_id=post_id,
        is_duplicate=False,
    )


def fetch_channel_feed() -> List[Dict[str, Any]]:
    """Fetch current message feed from mock channel."""
    return get_all_posts()


def reset_mock_channel() -> None:
    """Clear channel feed for clean reproducible demos."""
    clear_channel_posts()
