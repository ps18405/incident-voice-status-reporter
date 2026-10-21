"""Incident Voice Status Reporter - Mock Team Channel.
Handles human approval gating and idempotent message posting.
Uses SHA-256 hash of (incident_id + message) as idempotency key to prevent duplicate posts on retries.
"""
from __future__ import annotations

import hashlib
import logging
import os
import sqlite3
import threading
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field

from app.db import (
    clear_channel_posts,
    get_all_posts,
    get_approval_by_agent_run,
    get_post_by_idempotency_key,
    save_approval,
    save_post,
    update_approval_status,
)

logger = logging.getLogger("incident_voice.channel")
_channel_action_lock = threading.RLock()


class ChannelPostingError(RuntimeError):
    """Raised when an approved mock-channel message cannot be persisted."""


class ChannelApprovalConflict(RuntimeError):
    """Raised when a run's persisted approval does not authorize this request."""


class ChannelAdapter:
    """Abstract interface for incident status posting channels."""

    def post(self, incident_id: str, destination: str, message: str, idempotency_key: str) -> Optional[int]:
        raise NotImplementedError

    def read_feed(self) -> List[Dict[str, Any]]:
        raise NotImplementedError

    def clear(self) -> None:
        raise NotImplementedError


class MockChannelAdapter(ChannelAdapter):
    """Default high-fidelity mock team channel persisted in SQLite."""

    def post(self, incident_id: str, destination: str, message: str, idempotency_key: str) -> Optional[int]:
        return save_post(
            incident_id=incident_id,
            destination=destination,
            message=message,
            idempotency_key=idempotency_key,
            is_duplicate=False,
        )

    def read_feed(self) -> List[Dict[str, Any]]:
        return get_all_posts()

    def clear(self) -> None:
        clear_channel_posts()


class WebhookChannelAdapter(ChannelAdapter):
    """Optional Slack or Discord webhook adapter with SQLite ledger fallback."""

    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url
        self.mock_channel = MockChannelAdapter()

    def post(self, incident_id: str, destination: str, message: str, idempotency_key: str) -> Optional[int]:
        post_id = self.mock_channel.post(incident_id, destination, message, idempotency_key)
        try:
            import httpx
            payload = {"text": f"[{destination}] {message}", "content": message}
            with httpx.Client(timeout=4.0) as client:
                client.post(self.webhook_url, json=payload)
        except Exception as exc:
            logger.warning("Optional webhook dispatch failed: %s", exc)
        return post_id

    def read_feed(self) -> List[Dict[str, Any]]:
        return self.mock_channel.read_feed()

    def clear(self) -> None:
        self.mock_channel.clear()


def get_channel_adapter() -> ChannelAdapter:
    """Return active channel adapter based on environment configuration."""
    webhook = os.getenv("SLACK_WEBHOOK_URL") or os.getenv("DISCORD_WEBHOOK_URL")
    if webhook and os.getenv("ENABLE_WEBHOOK_CHANNEL", "false").strip().lower() == "true":
        return WebhookChannelAdapter(webhook.strip())
    return MockChannelAdapter()


class ChannelPostRequest(BaseModel):
    incident_id: str = Field(..., min_length=3, max_length=128)
    destination: str = Field(
        default_factory=lambda: os.getenv("DEFAULT_CHANNEL", "#incident-response"),
        min_length=1,
        max_length=128,
    )
    message: str = Field(..., min_length=1, max_length=10_000)
    approval_decision: Literal["APPROVED", "REJECTED"]
    agent_run_id: Optional[int] = None


class ChannelPostResult(BaseModel):
    success: bool
    status: str  # "POSTED" | "REJECTED" | "DUPLICATE_IGNORED"
    message: str
    destination: str
    idempotency_key: str
    post_id: Optional[int] = None
    posted_at: Optional[str] = None
    is_duplicate: bool = False


def generate_idempotency_key(incident_id: str, message: str, destination: str = "") -> str:
    """Compute a deterministic key for an incident, exact destination, and message."""
    exact_content = "\0".join((incident_id, destination, message))
    return hashlib.sha256(exact_content.encode("utf-8")).hexdigest()


def process_channel_approval_and_post(
    req: ChannelPostRequest,
    *,
    approved_by: str = "offline_test",
) -> ChannelPostResult:
    with _channel_action_lock:
        return _process_channel_approval_and_post(req, approved_by=approved_by)


def invalidate_unposted_approval_for_destination_edit(
    agent_run_id: int,
    destination: str,
) -> Optional[Dict[str, Any]]:
    with _channel_action_lock:
        approval = get_approval_by_agent_run(agent_run_id)
        if (
            approval
            and approval["status"] in {"APPROVED", "POST_FAILED"}
            and approval["destination"] != destination
            and get_post_by_idempotency_key(approval["idempotency_key"]) is None
        ):
            update_approval_status(approval["id"], "INVALIDATED")
            return get_approval_by_agent_run(agent_run_id)
        return approval


def _process_channel_approval_and_post(
    req: ChannelPostRequest,
    *,
    approved_by: str,
) -> ChannelPostResult:
    """Process human approval decision.
    
    If REJECTED: Records rejection and posts nothing.
    If APPROVED: Posts to channel with strict idempotency guard against duplicates.
    """
    idem_key = generate_idempotency_key(req.incident_id, req.message, req.destination)

    existing_approval = (
        get_approval_by_agent_run(req.agent_run_id)
        if req.agent_run_id is not None else None
    )
    if existing_approval:
        if (
            existing_approval["incident_id"] != req.incident_id
            or existing_approval["destination"] != req.destination
            or existing_approval["proposed_message"] != req.message
            or existing_approval["idempotency_key"] != idem_key
        ):
            if existing_approval["status"] in {"APPROVED", "POST_FAILED"}:
                existing_post = get_post_by_idempotency_key(
                    existing_approval["idempotency_key"]
                )
                if existing_post is None:
                    update_approval_status(existing_approval["id"], "INVALIDATED")
            raise ChannelApprovalConflict(
                "This run's approval is bound to different content or destination; create a new run to approve edits."
            )
        if existing_approval["status"] == "REJECTED":
            if req.approval_decision != "REJECTED":
                raise ChannelApprovalConflict("A rejected run cannot be approved or posted.")
            return ChannelPostResult(
                success=False,
                status="REJECTED",
                message="Operator rejected the update. No post was published to the channel.",
                destination=req.destination,
                idempotency_key=idem_key,
                post_id=None,
                is_duplicate=False,
            )
        if req.approval_decision != "APPROVED":
            raise ChannelApprovalConflict("An approved run cannot be changed to rejected.")
        if existing_approval["status"] == "INVALIDATED":
            raise ChannelApprovalConflict("This approval was invalidated; create a new run before posting.")
    else:
        try:
            approval_id = save_approval(
                incident_id=req.incident_id,
                destination=req.destination,
                proposed_message=req.message,
                status=req.approval_decision,
                idempotency_key=idem_key,
                agent_run_id=req.agent_run_id,
                approved_by=approved_by,
            )
        except sqlite3.IntegrityError:
            if req.agent_run_id is None:
                raise
            existing_approval = get_approval_by_agent_run(req.agent_run_id)
            if existing_approval is None:
                raise
            return process_channel_approval_and_post(req)

    if req.approval_decision == "REJECTED":
        return ChannelPostResult(
            success=False,
            status="REJECTED",
            message="Operator rejected the update. No post was published to the channel.",
            destination=req.destination,
            idempotency_key=idem_key,
            post_id=None,
            is_duplicate=False,
        )

    approval_id = existing_approval["id"] if existing_approval else approval_id

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
    try:
        adapter = get_channel_adapter()
        post_id = adapter.post(
            incident_id=req.incident_id,
            destination=req.destination,
            message=req.message,
            idempotency_key=idem_key,
        )
    except Exception as exc:
        update_approval_status(approval_id, "POST_FAILED")
        logger.exception(
            "Mock-channel post persistence failed incident_id=%s destination=%s",
            req.incident_id,
            req.destination,
        )
        raise ChannelPostingError("Approved message could not be persisted to the mock channel.") from exc

    if post_id is None:
        existing_post = get_post_by_idempotency_key(idem_key)
        if existing_post is None:
            update_approval_status(approval_id, "POST_FAILED")
            raise ChannelPostingError("Mock channel did not confirm the approved message.")
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
    """Fetch current message feed from active channel adapter."""
    return get_channel_adapter().read_feed()


def reset_mock_channel() -> None:
    """Clear channel feed for clean reproducible demos."""
    get_channel_adapter().clear()
