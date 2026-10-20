"""Provider adapters for tool-calling incident synthesis."""
from __future__ import annotations

import json
import logging
import os
import re
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


DEFAULT_MODEL = "gemini-2.5-flash"
logger = logging.getLogger("incident_voice")
_recordings_lock = threading.Lock()


class ProviderError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        diagnostic: str | None = None,
        retryable: bool = True,
        quota_error: bool = False,
        user_message: str | None = None,
    ):
        super().__init__(message)
        self.diagnostic = diagnostic or message
        self.retryable = retryable
        self.quota_error = quota_error
        self.user_message = user_message or self.diagnostic


def _redact_secret(value: Any, api_key: str) -> Any:
    if isinstance(value, str):
        return value.replace(api_key, "[REDACTED]") if api_key else value
    if isinstance(value, dict):
        return {
            _redact_secret(key, api_key): _redact_secret(item, api_key)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_redact_secret(item, api_key) for item in value]
    return value


def _gemini_error_details(
    exc: Exception,
    api_key: str,
) -> tuple[Any, Any, Any, str, str]:
    code = getattr(exc, "code", None)
    status = getattr(exc, "status", None)
    message = getattr(exc, "message", None) or str(exc)
    details = getattr(exc, "details", None)
    if details is None:
        details = str(exc)
    code = _redact_secret(code, api_key)
    status = _redact_secret(status, api_key)
    message = _redact_secret(message, api_key)
    details = _redact_secret(details, api_key)
    short_message = re.sub(r"\s+", " ", str(message)).strip()
    if len(short_message) > 140:
        short_message = short_message[:137] + "..."
    diagnostic = f"{code}: {short_message}" if code is not None else short_message
    serialized_details = json.dumps(details, ensure_ascii=True, default=str)
    if api_key:
        serialized_details = serialized_details.replace(api_key, "[REDACTED]")
    return code, status, message, serialized_details, diagnostic


def provider_settings() -> tuple[str, str, str, float]:
    provider = os.getenv("LLM_PROVIDER", "gemini").strip().lower()
    model = os.getenv("LLM_MODEL", DEFAULT_MODEL).strip()
    api_key = os.getenv("LLM_API_KEY", "").strip()
    timeout = float(os.getenv("LLM_TIMEOUT_SECONDS", "12"))
    if provider not in {"gemini", "openai_compat"}:
        raise ValueError("LLM_PROVIDER must be 'gemini' or 'openai_compat'.")
    if timeout <= 0:
        raise ValueError("LLM_TIMEOUT_SECONDS must be positive.")
    return provider, model, api_key, timeout


def _openai_request(
    messages: List[Dict[str, Any]],
    tools: List[Dict[str, Any]],
    *,
    model: str,
    api_key: str,
    timeout: float,
    base_url: str | None = None,
) -> tuple[str, List[Dict[str, Any]], Dict[str, int]]:
    base_url = (base_url or os.getenv("LLM_BASE_URL", "")).strip().rstrip("/")
    if not base_url:
        raise ProviderError("LLM_BASE_URL is required for openai_compat.")
    body: Dict[str, Any] = {"model": model, "messages": messages, "temperature": 0.2}
    if tools:
        body["tools"] = tools
        body["tool_choice"] = "auto"
    request = Request(
        f"{base_url}/chat/completions",
        data=json.dumps(body).encode("utf-8"),
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        try:
            payload = json.loads(exc.read().decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            payload = {}
        error = payload.get("error", {})
        message = error.get("message") or str(exc.reason)
        payload = _redact_secret(payload, api_key)
        message = _redact_secret(message, api_key)
        quota_error = exc.code == 429 or error.get("code") in {
            "rate_limit_exceeded", "insufficient_quota", "RESOURCE_EXHAUSTED",
        } or error.get("status") == "RESOURCE_EXHAUSTED"
        logger.error(
            "OpenAI-compatible request failed status_code=%s message=%s details=%s",
            exc.code, message, json.dumps(payload, ensure_ascii=True, default=str),
        )
        raise ProviderError(
            f"OpenAI-compatible request failed ({exc.code}): {message}",
            diagnostic=f"OpenAI-compatible {exc.code}: {message}",
            retryable=not quota_error,
            quota_error=quota_error,
            user_message="OpenAI-compatible quota reached" if quota_error else f"OpenAI-compatible request failed ({exc.code})",
        ) from exc
    except (URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise ProviderError(f"OpenAI-compatible provider request failed: {type(exc).__name__}") from exc
    choices = payload.get("choices", [])
    if not choices:
        raise ProviderError("OpenAI-compatible provider returned no choices.")
    message = choices[0].get("message", {})
    calls = []
    for item in message.get("tool_calls", []):
        fn = item.get("function", {})
        calls.append({
            "id": item.get("id", ""),
            "name": fn.get("name", ""),
            "arguments": json.loads(fn.get("arguments") or "{}"),
        })
    usage = payload.get("usage", {})
    return str(message.get("content") or ""), calls, {
        "prompt_tokens": int(usage.get("prompt_tokens", 0)),
        "completion_tokens": int(usage.get("completion_tokens", 0)),
    }


def _gemini_request(
    prompt: str,
    tools: List[Dict[str, Any]],
    *,
    model: str,
    api_key: str,
    timeout: float,
) -> tuple[str, List[Dict[str, Any]], Dict[str, int]]:
    try:
        from google import genai
        from google.genai import types

        declarations = [
            types.FunctionDeclaration(
                name=item["function"]["name"],
                description=item["function"]["description"],
                parameters=item["function"]["parameters"],
            )
            for item in tools
        ]
        config = types.GenerateContentConfig(
            temperature=0.2,
            tools=[types.Tool(function_declarations=declarations)] if declarations else None,
        )
        client = genai.Client(
            api_key=api_key,
            http_options=types.HttpOptions(timeout=max(10_000, int(timeout * 1000))),
        )
        response = client.models.generate_content(model=model, contents=prompt, config=config)
    except Exception as exc:
        code, status, message, details, diagnostic = _gemini_error_details(exc, api_key)
        logger.error(
            "Gemini request failed error_type=%s status_code=%s status=%s message=%s details=%s",
            type(exc).__name__, code, status, message, details,
        )
        raise ProviderError(
            f"Gemini provider request failed: {diagnostic}",
            diagnostic=f"Gemini {diagnostic}",
            retryable=code not in {400, 401, 403, 404, 429},
            quota_error=code == 429 or status == "RESOURCE_EXHAUSTED",
            user_message=(
                "Gemini quota reached; using rules fallback"
                if code == 429 or status == "RESOURCE_EXHAUSTED"
                else f"Gemini request failed ({code})"
            ),
        ) from exc
    calls = []
    for call in response.function_calls or []:
        calls.append({
            "id": call.id or call.name,
            "name": call.name,
            "arguments": dict(call.args or {}),
        })
    usage = getattr(response, "usage_metadata", None)
    return response.text or "", calls, {
        "prompt_tokens": int(getattr(usage, "prompt_token_count", 0) or 0),
        "completion_tokens": int(getattr(usage, "candidates_token_count", 0) or 0),
    }


def _request(
    prompt: str,
    messages: List[Dict[str, Any]],
    tools: List[Dict[str, Any]],
    *,
    provider: str,
    model: str,
    api_key: str,
    timeout: float,
    base_url: str | None = None,
) -> tuple[str, List[Dict[str, Any]], Dict[str, int]]:
    if provider == "openai_compat":
        return _openai_request(
            messages, tools, model=model, api_key=api_key, timeout=timeout,
            base_url=base_url,
        )
    return _gemini_request(prompt, tools, model=model, api_key=api_key, timeout=timeout)


def collect_tool_evidence(
    tools: List[Dict[str, Any]],
    execute_tool: Callable[[str, Dict[str, Any]], Any],
    incident_id: str,
) -> tuple[str, List[Dict[str, Any]]]:
    evidence_blocks = []
    trace = []
    for index, declaration in enumerate(tools, start=1):
        name = declaration["function"]["name"]
        started = time.monotonic()
        observation = execute_tool(name, {"incident_id": incident_id})
        trace.append({
            "step": index,
            "thought_summary": "Collecting synthetic evidence locally before the single model request.",
            "tool_name": name,
            "arguments": {"incident_id": incident_id},
            "observation": observation,
            "latency_ms": round((time.monotonic() - started) * 1000, 1),
        })
        evidence_blocks.append(f"{name}: {json.dumps(observation, ensure_ascii=True)}")
    return "\n\nEvidence observations:\n" + "\n".join(evidence_blocks), trace


def load_recorded_response(scenario_id: str) -> dict[str, Any] | None:
    path = Path(os.getenv("LLM_RECORDINGS_PATH", "data/llm_recordings.json"))
    try:
        with _recordings_lock:
            contents = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, json.JSONDecodeError) as exc:
        logger.exception("Unable to load LLM recordings from %s", path)
        raise ProviderError(f"Unable to load recorded LLM responses: {type(exc).__name__}") from exc
    if not isinstance(contents, dict):
        raise ProviderError("Recorded LLM response file must contain a JSON object.")
    entry = contents.get(scenario_id)
    return entry if isinstance(entry, dict) and isinstance(entry.get("response"), str) else None


def save_recorded_response(
    scenario_id: str,
    response: str,
    provider: str,
    model: str,
) -> None:
    path = Path(os.getenv("LLM_RECORDINGS_PATH", "data/llm_recordings.json"))
    with _recordings_lock:
        try:
            contents = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
            if not isinstance(contents, dict):
                raise ProviderError("Recorded LLM response file must contain a JSON object.")
            contents[scenario_id] = {
                "response": response,
                "provider": provider,
                "model": model,
                "recorded_at": datetime.now(timezone.utc).isoformat(),
            }
            path.parent.mkdir(parents=True, exist_ok=True)
            fd, temporary = tempfile.mkstemp(prefix=f"{path.name}.", suffix=".tmp", dir=path.parent)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as target:
                    json.dump(contents, target, ensure_ascii=True, indent=2)
                    target.write("\n")
                os.replace(temporary, path)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
        except (OSError, json.JSONDecodeError) as exc:
            logger.exception("Unable to save LLM recording to %s", path)
            raise ProviderError(f"Unable to save LLM recording: {type(exc).__name__}") from exc


def _request_with_failover(
    prompt: str,
    messages: List[Dict[str, Any]],
    tools: List[Dict[str, Any]],
    *,
    provider: str,
    model: str,
    api_key: str,
    timeout: float,
) -> tuple[str, str, str, Dict[str, int]]:
    try:
        response, _, usage = _request(
            prompt, messages, tools, provider=provider, model=model,
            api_key=api_key, timeout=timeout,
        )
        return response, provider, model, usage
    except ProviderError as primary_error:
        fallback_provider = os.getenv("LLM_FALLBACK_PROVIDER", "").strip().lower()
        if not primary_error.quota_error or fallback_provider != "openai_compat":
            raise
        quota_message = (
            "Gemini quota reached; using rules fallback"
            if provider == "gemini"
            else "OpenAI-compatible quota reached; using rules fallback"
        )
        fallback_key = os.getenv("LLM_FALLBACK_API_KEY", "").strip()
        fallback_model = os.getenv("LLM_FALLBACK_MODEL", "").strip()
        fallback_url = os.getenv("LLM_FALLBACK_BASE_URL", "").strip()
        if not fallback_key or not fallback_model or not fallback_url:
            raise ProviderError(
                "Primary quota exhausted and fallback is not fully configured.",
                diagnostic=primary_error.diagnostic,
                retryable=False,
                quota_error=True,
                user_message=quota_message,
            ) from primary_error
        try:
            response, _, usage = _request(
                prompt, messages, tools, provider="openai_compat",
                model=fallback_model, api_key=fallback_key, timeout=timeout,
                base_url=fallback_url,
            )
            return response, "openai_compat", fallback_model, usage
        except ProviderError as fallback_error:
            logger.error(
                "Fallback provider failed after primary quota error: %s",
                fallback_error.diagnostic,
            )
            raise ProviderError(
                "Primary quota exhausted and fallback provider failed.",
                diagnostic=f"{primary_error.diagnostic}; fallback: {fallback_error.diagnostic}",
                retryable=False,
                quota_error=True,
                user_message=quota_message,
            ) from fallback_error


def run_tool_loop(
    prompt: str,
    tools: List[Dict[str, Any]],
    execute_tool: Callable[[str, Dict[str, Any]], Any],
    *,
    incident_id: str,
) -> tuple[str, List[Dict[str, Any]], Dict[str, int], str, str]:
    provider, model, api_key, timeout = provider_settings()
    if not api_key:
        raise ProviderError("LLM_API_KEY is not configured.")
    if provider == "gemini" and timeout < 10:
        raise ProviderError(
            "Gemini requires at least a 10-second request deadline.",
            diagnostic="Gemini request skipped: timeout is below 10 seconds",
            retryable=False,
        )

    evidence, trace = collect_tool_evidence(tools, execute_tool, incident_id)
    response, actual_provider, actual_model, usage = _request_with_failover(
        prompt + evidence, [{"role": "user", "content": prompt + evidence}], [],
        provider=provider, model=model, api_key=api_key, timeout=timeout,
    )
    if not response.strip():
        raise ProviderError("Provider returned an empty response.")
    return response, trace, usage, actual_provider, actual_model


def repair_response(prompt: str) -> tuple[str, str, str, Dict[str, int]]:
    provider, model, api_key, timeout = provider_settings()
    if not api_key:
        raise ProviderError("LLM_API_KEY is not configured.")
    text, actual_provider, actual_model, usage = _request_with_failover(
        prompt, [{"role": "user", "content": prompt}], [],
        provider=provider, model=model, api_key=api_key, timeout=timeout,
    )
    if not text.strip():
        raise ProviderError("Repair response was empty.")
    return text, actual_provider, actual_model, usage
