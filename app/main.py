"""Incident Voice Status Reporter - FastAPI Main Application.
Provides REST APIs and serves the single-page responsive UI.
"""
from __future__ import annotations

import os
import json
import asyncio
import logging
import copy
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app.brief import build_voice_brief_and_post
from app.channel import (
    ChannelPostRequest,
    ChannelPostResult,
    fetch_channel_feed,
    process_channel_approval_and_post,
    reset_mock_channel,
)
from app.collector import IncidentInput, collect_signals
from app.agent import run_agent
from app.db import (
    get_agent_run,
    get_approvals_by_incident,
    get_latest_test_runs,
    init_db,
    record_agent_run,
    record_test_run,
    update_agent_run_report,
)
from app.redact import redact_text, scan_for_unredacted_pii
from app.rules import evaluate_decision_rules
from app.sources import get_mock_scenario_sources, list_available_scenarios
from app.verify import run_post_verification

app = FastAPI(
    title="Incident Voice Status Reporter",
    description="Operational on-call voice briefing agent with honesty about uncertainty, PII redaction, human approval gate, and verified claims.",
    version="1.0.0",
)

allowed_origins = [
    origin.strip()
    for origin in os.getenv("CORS_ALLOW_ORIGINS", "").split(",")
    if origin.strip()
]
if allowed_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type"],
    )

logger = logging.getLogger("incident_voice")
_agent_cache: Dict[str, tuple[float, Dict[str, Any]]] = {}
_agent_requests: Dict[str, List[float]] = {}
_agent_lock = threading.Lock()
MAX_REQUEST_BYTES = 64 * 1024
AGENT_RATE_LIMIT = 30
AGENT_CACHE_SECONDS = 10 * 60

# Initialize Database
STATIC_DIR = Path(__file__).resolve().parent.parent / "static"
STATIC_DIR.mkdir(exist_ok=True)
init_db()

# Mount static folder
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.middleware("http")
async def request_size_guard(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > MAX_REQUEST_BYTES:
        return JSONResponse(status_code=413, content={"detail": "Request body exceeds the 64 KB limit."})
    return await call_next(request)


@app.get("/")
async def root():
    index_file = STATIC_DIR / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return {"message": "Incident Voice Status Reporter API is running. UI index.html not yet created."}


@app.get("/favicon.ico")
async def favicon():
    favicon_file = STATIC_DIR / "favicon.svg"
    if favicon_file.exists():
        return FileResponse(favicon_file, media_type="image/svg+xml")
    return Response(status_code=204)


@app.get("/health")
async def health_check():
    """Health check endpoint for cloud platforms and orchestrators."""
    return {"status": "ok"}




@app.get("/api/scenarios")
async def get_scenarios():
    """List available mock scenarios including TC1 to TC4."""
    scenarios = list_available_scenarios()
    # Enrich with default details
    for s in scenarios:
        src = get_mock_scenario_sources(s["id"])
        s["default_scope"] = src.get("default_scope", "")
        s["dashboards"] = src.get("dashboards", [])
    return scenarios


class AnalyzeRequest(BaseModel):
    incident_id: str = Field(..., min_length=3)
    scope: str = Field(..., min_length=3)
    dashboards: List[str] = Field(default_factory=list)
    scenario_id: str = Field(default="TC1")
    demo_trick: bool = False


def _cached_response_key(req: AnalyzeRequest) -> str:
    payload = req.model_dump()
    payload.pop("demo_trick", None)
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _allow_agent_request(client_key: str) -> bool:
    now = time.monotonic()
    with _agent_lock:
        recent = [stamp for stamp in _agent_requests.get(client_key, []) if now - stamp < 60]
        for key, (created, _) in list(_agent_cache.items()):
            if now - created > AGENT_CACHE_SECONDS:
                del _agent_cache[key]
        if len(recent) >= AGENT_RATE_LIMIT:
            _agent_requests[client_key] = recent
            return False
        recent.append(now)
        _agent_requests[client_key] = recent
    return True


@app.post("/api/collect-and-analyze")
async def collect_and_analyze(req: AnalyzeRequest, request: Request):
    """Executes Step 1 (Collect), Step 2 (Plan/Correlate), Step 3 (Find), and produces Voice Brief + Proposed Post."""
    if not _allow_agent_request(request.client.host if request.client else "unknown"):
        raise HTTPException(status_code=429, detail="Agent request limit reached. Wait one minute before trying again.")

    demo_mode_enabled = os.getenv("DEMO_MODE", "false").strip().lower() == "true"
    cache_key = _cached_response_key(req)
    if not req.demo_trick and not demo_mode_enabled:
        with _agent_lock:
            cached = _agent_cache.get(cache_key)
            if cached and time.monotonic() - cached[0] <= AGENT_CACHE_SECONDS:
                cached_result = copy.deepcopy(cached[1])
                cached_agent = cached_result.get("agent", {})
                cached_agent["cached_result"] = True
                return cached_result

    if not req.dashboards:
        # Fallback to default mock dashboards for this scenario
        src = get_mock_scenario_sources(req.scenario_id)
        req.dashboards = src.get("dashboards", ["https://grafana.internal.mock/d/checkout-metrics"])

    inp = IncidentInput(
        incident_id=req.incident_id,
        scope=req.scope,
        dashboards=req.dashboards,
        scenario_id=req.scenario_id,
    )

    try:
        # 1. Collect & Redact
        collection = collect_signals(inp)
        # 2. Decision Rules
        decision = evaluate_decision_rules(collection)
        # 3. LLM tool calls are advisory; deterministic rules and guardrails decide.
        agent_result = await asyncio.to_thread(
            run_agent,
            collection,
            decision,
            demo_trick=req.demo_trick,
            live_llm=True,
            demo_mode=demo_mode_enabled,
            scenario_id=req.scenario_id,
        )
        brief = agent_result.brief
        report = agent_result.model_dump()
        report["input"] = {
            "incident_id": inp.incident_id,
            "scope": collection.scope,
            "dashboards": collection.dashboards,
            "scenario_id": inp.scenario_id,
            "test_mode": False,
            "approval_simulated": False,
        }
        report["evidence"] = [signal.model_dump() for signal in collection.signals]
        report["decision"] = decision.model_dump()
        run_id = record_agent_run(inp.incident_id, report)

        result = {
            "success": True,
            "collection": collection.model_dump(),
            "decision": decision.model_dump(),
            "brief": brief.model_dump(),
            "agent": {
                "run_id": run_id,
                "mode": agent_result.mode,
                "model": agent_result.model,
                "provider": agent_result.provider,
                "provider_error": agent_result.provider_error,
                "cached_result": False,
                "confidence": agent_result.confidence,
                "confidence_method": agent_result.confidence_method,
                "trace": agent_result.trace,
                "guardrail_verdict": agent_result.guardrail_verdict,
                "guardrail_reasons": agent_result.guardrail_reasons,
                "latency_ms": agent_result.latency_ms,
                "token_usage": agent_result.token_usage,
                "open_questions": agent_result.open_questions,
            },
        }
        if not req.demo_trick:
            with _agent_lock:
                _agent_cache[cache_key] = (time.monotonic(), result)
        logger.info(
            "Agent run completed incident_id=%s provider=%s model=%s mode=%s state=%s verdict=%s",
            inp.incident_id, agent_result.provider, agent_result.model,
            agent_result.mode, agent_result.state, agent_result.guardrail_verdict,
        )
        return result
    except Exception as e:
        logger.exception("Incident analysis failed")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {type(e).__name__}")


@app.get("/api/config")
async def get_public_config():
    """Expose non-secret runtime mode information to the UI."""
    has_key = bool(os.getenv("LLM_API_KEY", "").strip())
    return {
        "mode": "LLM agent" if has_key else "Rules fallback",
        "provider": os.getenv("LLM_PROVIDER", "gemini"),
        "model": os.getenv("LLM_MODEL", "gemini-2.5-flash") if has_key else "rules",
        "simulated_data": True,
    }


@app.get("/api/agent-runs/{run_id}")
async def get_agent_run_endpoint(run_id: int):
    report = get_agent_run(run_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Agent run was not found.")
    return report


@app.get("/api/agent-runs/{run_id}/export")
async def export_agent_run(run_id: int):
    report = get_agent_run(run_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Agent run was not found.")
    incident_id = report.get("input", {}).get("incident_id") or report.get("brief", {}).get("incident_id")
    if "approval" not in report:
        approvals = get_approvals_by_incident(incident_id)
        report["approval"] = approvals[0] if approvals else {
            "status": "PENDING",
            "approval_simulated": False,
        }
    if "post" not in report:
        report["post"] = None
    if report["post"] is None:
        proposed_text = report.get("brief", {}).get("proposed_channel_post", "")
        report["post"] = next(
            (
                post for post in fetch_channel_feed()
                if post["incident_id"] == incident_id and post["message"] == proposed_text
            ),
            None,
        )
    if "verification" not in report:
        report["verification"] = (
            run_post_verification(
                incident_id,
                report["post"]["message"],
                report["post"]["id"],
                agent_run_id=run_id,
            ).model_dump()
            if report["post"] else None
        )
    return JSONResponse(
        content=report,
        headers={"Content-Disposition": f'attachment; filename="incident-run-{run_id}.json"'},
    )


@app.post("/api/approve", response_model=ChannelPostResult)
async def submit_approval(req: ChannelPostRequest):
    """Executes Step 4 (Act with HUMAN APPROVAL).
    
    If Approved: Posts update to channel with idempotency key guard.
    If Rejected: Stores rejection and posts nothing.
    """
    if req.agent_run_id is not None:
        run_report = get_agent_run(req.agent_run_id)
        if run_report is None or (
            run_report.get("input", {}).get("incident_id")
            != req.incident_id
        ):
            raise HTTPException(status_code=400, detail="Agent run does not match this incident.")
    result = process_channel_approval_and_post(req)
    if req.agent_run_id is not None:
        approvals = get_approvals_by_incident(req.incident_id)
        posts = [post for post in fetch_channel_feed() if post["id"] == result.post_id]
        update_agent_run_report(
            req.agent_run_id,
            {
                "approval": approvals[0] if approvals else {
                    "status": req.approval_decision,
                    "approval_simulated": False,
                },
                "post": posts[0] if posts else None,
            },
        )
    return result


class VerifyRequest(BaseModel):
    incident_id: str
    approved_text: str
    post_id: Optional[int] = None
    agent_run_id: Optional[int] = None


@app.post("/api/verify")
async def verify_post(req: VerifyRequest):
    """Executes Step 5 (Check the actual result).
    
    Independently re-reads the channel and verifies existence, content fidelity,
    signal linkage, and absence of customer PII.
    """
    if req.agent_run_id is not None:
        run_report = get_agent_run(req.agent_run_id)
        if run_report is None or run_report.get("input", {}).get("incident_id") != req.incident_id:
            raise HTTPException(status_code=400, detail="Agent run does not match this incident.")
    report = run_post_verification(
        incident_id=req.incident_id,
        approved_text=req.approved_text,
        target_post_id=req.post_id,
        agent_run_id=req.agent_run_id,
    )
    if req.agent_run_id is not None:
        update_agent_run_report(req.agent_run_id, {"verification": report.model_dump()})
    return report.model_dump()


@app.get("/api/channel")
async def get_channel_feed():
    """Retrieve all posts published to the mock team channel."""
    return fetch_channel_feed()


@app.post("/api/reset-channel")
async def reset_channel():
    """Reset the mock channel for testing."""
    reset_mock_channel()
    return {"message": "Channel and approval ledger cleared."}


class RunTestsRequest(BaseModel):
    live_llm: bool = False


@app.post("/api/run-tests")
async def run_official_tests(req: Optional[RunTestsRequest] = None):
    """Run the six synthetic scenarios through collection, agent, approval, and verification."""
    assertions = {
        "TC1": ("DEGRADED", "includes timestamps and signal citations"),
        "TC2": ("UNCERTAIN", "cached data is explicitly not proof of recovery"),
        "TC3": ("UNCERTAIN", "synthetic customer data is redacted"),
        "TC4": ("UNCERTAIN", "failing health check says recovery uncertain"),
        "MIXED": ("DEGRADED", "fresh elevated metrics override resolved status-page text"),
        "MISSING": ("UNCERTAIN", "unavailable log source is disclosed"),
    }
    results = []
    for scenario_id, (expected_state, expected_behavior) in assertions.items():
        source = get_mock_scenario_sources(scenario_id)
        incident_id = f"INC-{scenario_id}-TEST-{uuid.uuid4().hex[:8].upper()}"
        incident_input = IncidentInput(
            incident_id=incident_id,
            scope=source.get("default_scope", f"Synthetic test for {scenario_id}"),
            dashboards=source.get("dashboards", []),
            scenario_id=scenario_id,
        )
        try:
            collection = collect_signals(incident_input)
            decision = evaluate_decision_rules(collection)
            agent_result = await asyncio.to_thread(
                run_agent,
                collection,
                decision,
                live_llm=bool(req and req.live_llm),
                demo_mode=(
                    not bool(req and req.live_llm)
                    and os.getenv("DEMO_MODE", "false").strip().lower() == "true"
                ),
                scenario_id=scenario_id,
            )
            run_report = agent_result.model_dump()
            run_report["input"] = {
                "incident_id": incident_id,
                "scope": collection.scope,
                "dashboards": collection.dashboards,
                "scenario_id": scenario_id,
                "test_mode": True,
                "approval_simulated": True,
            }
            run_report["evidence"] = [signal.model_dump() for signal in collection.signals]
            run_report["decision"] = decision.model_dump()
            run_id = record_agent_run(incident_id, run_report)
            brief = agent_result.brief
            checks = {
                "state": decision.status == expected_state,
                "timestamp": brief.voice_script.startswith("At ") or brief.voice_script[:4].isdigit(),
                "citations": bool(brief.claims) and all(
                    claim.signal_id in {signal.signal_id for signal in collection.signals}
                    and f"[{claim.signal_id}]" in brief.voice_script
                    and claim.source_updated_at in brief.voice_script
                    for claim in brief.claims
                ),
            }
            if scenario_id == "TC2":
                checks["cached_warning"] = decision.cached_warning and "not proof of recovery" in brief.voice_script.lower()
            elif scenario_id == "TC3":
                safe_text = json.dumps({
                    "evidence": collection.model_dump(),
                    "trace": agent_result.trace,
                    "voice": brief.voice_script,
                    "post": brief.proposed_channel_post,
                })
                checks["redaction"] = (
                    collection.redactions_count > 0
                    and not scan_for_unredacted_pii(safe_text)
                )
            elif scenario_id == "TC4":
                checks["health_warning"] = (
                    decision.recovery_uncertain_warning
                    and "recovery uncertain" in brief.voice_script.lower()
                )
            elif scenario_id == "MIXED":
                checks["conflict_explained"] = "conflicts" in decision.reason.lower()
            elif scenario_id == "MISSING":
                checks["missing_log_disclosed"] = "log source unavailable" in decision.reason.lower()

            # This approval is simulated only inside this labelled test-run endpoint.
            post = process_channel_approval_and_post(ChannelPostRequest(
                incident_id=incident_id,
                destination=brief.destination,
                message=brief.proposed_channel_post,
                approval_decision="APPROVED",
                agent_run_id=run_id,
            ))
            verification = run_post_verification(
                incident_id, brief.proposed_channel_post, post.post_id,
                agent_run_id=run_id,
            )
            channel_post = next(
                (item for item in fetch_channel_feed() if item["id"] == post.post_id),
                None,
            )
            update_agent_run_report(run_id, {
                "approval": {
                    "status": "APPROVED",
                    "approval_simulated": True,
                    "destination": brief.destination,
                    "message": brief.proposed_channel_post,
                },
                "post": channel_post,
                "verification": verification.model_dump(),
            })
            checks["verification"] = verification.overall_status == "PASS"
            passed = all(checks.values())
            actual = (
                f"State {decision.status}; provider {agent_result.provider}; mode {agent_result.mode}; "
                f"guardrail {agent_result.guardrail_verdict}; verification {verification.overall_status}."
            )
            failed = [name for name, passed_check in checks.items() if not passed_check]
            explanation = (
                "All required assertions held; test-only approval was simulated and the independent verifier passed."
                if passed
                else f"Assertions not met: {', '.join(failed)}. No difference is reported as success."
            )
            result = {
                "test_case_id": scenario_id,
                "scenario_name": source.get("scenario_name", scenario_id),
                "input": {
                    "incident_id": incident_id,
                    "scope": incident_input.scope,
                    "scenario": scenario_id,
                    "test_mode": True,
                    "approval_simulated": True,
                },
                "expected": f"{expected_state}; {expected_behavior}",
                "actual": actual,
                "evidence": [signal.model_dump() for signal in collection.signals],
                "mode": agent_result.mode,
                "provider": agent_result.provider,
                "model": agent_result.model,
                "guardrail_verdict": agent_result.guardrail_verdict,
                "verification": verification.model_dump(),
                "run_id": run_id,
                "status": "PASS" if passed else "FAIL",
                "explanation": explanation,
            }
        except Exception as exc:
            logger.exception("Scenario test failed scenario_id=%s", scenario_id)
            result = {
                "test_case_id": scenario_id,
                "input": {"scenario": scenario_id, "test_mode": True, "approval_simulated": False},
                "expected": f"{expected_state}; {expected_behavior}",
                "actual": f"Pipeline error: {type(exc).__name__}",
                "mode": "unavailable",
                "status": "FAIL",
                "explanation": "The pipeline raised an error; this run was not reported as successful.",
            }
        record_test_run(
            result["test_case_id"],
            result.get("scenario_name", scenario_id),
            result["input"],
            result["expected"],
            result["actual"],
            result.get("evidence", []),
            result["status"],
            result["explanation"],
        )
        results.append(result)
    return {"results": results}


@app.get("/api/test-runs")
async def get_test_runs():
    """Retrieve historical/latest test runs."""
    return get_latest_test_runs()


class LLMHookRequest(BaseModel):
    enabled: bool = False
    prompt_context: Optional[str] = None


@app.post("/api/llm-summary-hook")
async def optional_llm_summary_hook(req: LLMHookRequest):
    """Retain the prior API path without pretending it invokes an LLM."""
    if not req.enabled:
        return {
            "enabled": False,
            "status": "DISABLED",
            "message": "This legacy hook is disabled. Use /api/collect-and-analyze for the guarded tool-calling agent.",
            "summary": None,
        }
    return {
        "enabled": True,
        "status": "LEGACY_NO_PROVIDER_CALL",
        "message": "This endpoint does not call a model. Use /api/collect-and-analyze to run the configured LLM agent.",
        "summary": None,
    }
