"""Offline tests for the tool-calling agent and its deterministic guardrails."""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from google import genai

from app.agent import _deterministic_output, run_agent
from app.collector import IncidentInput, collect_signals
from app.llm import ProviderError, _gemini_request, run_tool_loop
from app.rules import evaluate_decision_rules
from app.tools import TOOL_NAMES, build_toolset


def _build_case(scenario_id: str, incident_id: str):
    source = collect_signals(
        IncidentInput(
            incident_id=incident_id,
            scope=f"Testing {scenario_id} incident evidence",
            dashboards=["https://grafana.internal.mock/d/checkout-metrics"],
            scenario_id=scenario_id,
        ),
        save_to_db=False,
    )
    return source, evaluate_decision_rules(source, save_to_db=False)


@pytest.mark.parametrize(
    ("scenario_id", "expected_state"),
    [("TC1", "DEGRADED"), ("TC2", "UNCERTAIN"), ("TC3", "UNCERTAIN"), ("TC4", "UNCERTAIN")],
)
def test_llm_mode_uses_tools_and_passes_guardrails(monkeypatch, scenario_id, expected_state):
    collection, decision = _build_case(scenario_id, f"INC-LLM-{scenario_id}")
    output, _ = _deterministic_output(collection, decision)
    captured = {}

    def fake_tool_loop(prompt, tools, execute_tool, **kwargs):
        captured["prompt"] = prompt
        observations = []
        trace = []
        for index, declaration in enumerate(tools, start=1):
            name = declaration["function"]["name"]
            observation = execute_tool(name, {"incident_id": collection.incident_id})
            observations.append(observation)
            trace.append({
                "step": index,
                "thought_summary": "Selecting synthetic evidence.",
                "tool_name": name,
                "arguments": {"incident_id": collection.incident_id},
                "observation": observation,
                "latency_ms": 0.1,
            })
        captured["observations"] = observations
        return json.dumps(output), trace, {"prompt_tokens": 12, "completion_tokens": 20}, "gemini", "mock-model"

    monkeypatch.setenv("LLM_API_KEY", "mock-key")
    monkeypatch.setenv("LLM_PROVIDER", "gemini")
    monkeypatch.setattr("app.agent.run_tool_loop", fake_tool_loop)
    monkeypatch.setattr("app.agent.repair_response", lambda *_: pytest.fail("unexpected repair"))

    result = run_agent(collection, decision)

    assert result.mode == "LLM agent"
    assert result.guardrail_verdict == "PASS"
    assert result.state == expected_state
    assert result.confidence_method.startswith("0.65 x")
    assert len(captured["observations"]) == 5
    assert all(
        set(("signal_id", "source_url", "value", "unit", "source_updated_at", "retrieved_at",
             "age_seconds", "cached", "stale")).issuperset(item)
        for group in captured["observations"]
        for item in group
    )
    if scenario_id == "TC2":
        assert "not proof of recovery" in result.voice_script.lower()
    if scenario_id == "TC4":
        assert "recovery uncertain" in result.voice_script.lower()


@pytest.mark.parametrize(
    ("scenario_id", "expected_state"),
    [("TC1", "DEGRADED"), ("TC2", "UNCERTAIN"), ("TC3", "UNCERTAIN"), ("TC4", "UNCERTAIN")],
)
def test_no_key_falls_back_to_rules(monkeypatch, scenario_id, expected_state):
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    collection, decision = _build_case(scenario_id, f"INC-FALLBACK-{scenario_id}")

    result = run_agent(collection, decision)

    assert result.mode.startswith("Rules fallback")
    assert result.guardrail_verdict == "FALLBACK"
    assert result.state == expected_state
    assert result.brief.claims


def test_cached_recovery_claim_is_rejected_and_repaired_failure_falls_back(monkeypatch):
    collection, decision = _build_case("TC2", "INC-CACHED-REJECT")
    unsafe, _ = _deterministic_output(collection, decision)
    unsafe.update({
        "state": "RECOVERED",
        "voice_script": "At 12:00 UTC the system is recovered.",
        "proposed_post": "At 12:00 UTC, the system is recovered.",
        "claims": [{"text": "Recovered", "signal_id": "SIG-NOT-REAL"}],
    })
    repair_calls = []
    monkeypatch.setenv("LLM_API_KEY", "mock-key")
    monkeypatch.setattr(
        "app.agent.run_tool_loop",
        lambda *args, **kwargs: (
            json.dumps(unsafe), [], {"prompt_tokens": 1, "completion_tokens": 1}, "gemini", "mock",
        ),
    )
    monkeypatch.setattr(
        "app.agent.repair_response",
        lambda prompt: (
            repair_calls.append(prompt)
            or (json.dumps(unsafe), "gemini", "mock", {"prompt_tokens": 1, "completion_tokens": 1})
        ),
    )

    result = run_agent(collection, decision)

    assert len(repair_calls) == 1
    assert result.guardrail_verdict == "FALLBACK"
    assert result.guardrail_reasons
    assert result.state == "UNCERTAIN"
    assert "not proof of recovery" in result.voice_script.lower()


def test_missing_timestamp_is_rejected_and_repair_is_attempted(monkeypatch):
    collection, decision = _build_case("TC1", "INC-MISSING-TIMESTAMP")
    unsafe, _ = _deterministic_output(collection, decision)
    unsafe["voice_script"] = "Incident status is degraded."
    repairs = []
    monkeypatch.setenv("LLM_API_KEY", "mock-key")
    monkeypatch.setattr(
        "app.agent.run_tool_loop",
        lambda *args, **kwargs: (json.dumps(unsafe), [], {}, "gemini", "mock"),
    )
    monkeypatch.setattr(
        "app.agent.repair_response",
        lambda prompt: repairs.append(prompt) or (
            json.dumps(unsafe), "gemini", "mock", {},
        ),
    )

    result = run_agent(collection, decision)

    assert len(repairs) == 1
    assert "timestamp" in repairs[0]
    assert result.guardrail_verdict == "FALLBACK"
    assert result.voice_script.startswith("At ")


def test_pii_in_llm_output_is_redacted_before_repair_and_rejected(monkeypatch):
    collection, decision = _build_case("TC1", "INC-PII-OUTPUT")
    unsafe, _ = _deterministic_output(collection, decision)
    unsafe["voice_script"] += " Contact user@example.com."
    repair_prompts = []
    monkeypatch.setenv("LLM_API_KEY", "mock-key")
    monkeypatch.setattr(
        "app.agent.run_tool_loop",
        lambda *args, **kwargs: (json.dumps(unsafe), [], {}, "gemini", "mock"),
    )
    monkeypatch.setattr(
        "app.agent.repair_response",
        lambda prompt: repair_prompts.append(prompt) or (
            json.dumps(unsafe), "gemini", "mock", {},
        ),
    )

    result = run_agent(collection, decision)

    assert len(repair_prompts) == 1
    assert "user@example.com" not in repair_prompts[0]
    assert "[REDACTED_EMAIL]" in repair_prompts[0]
    assert result.guardrail_verdict == "FALLBACK"
    assert "user@example.com" not in result.voice_script


def test_tc3_pii_is_redacted_before_tool_output_and_prompt(monkeypatch):
    collection, decision = _build_case("TC3", "INC-PII-PROMPT")
    output, _ = _deterministic_output(collection, decision)
    captured = {}

    def fake_tool_loop(prompt, tools, execute_tool, **kwargs):
        captured["prompt"] = prompt
        outputs = [
            execute_tool(item["function"]["name"], {"incident_id": collection.incident_id})
            for item in tools
        ]
        captured["tools"] = json.dumps(outputs)
        return json.dumps(output), [], {}, "gemini", "mock"

    monkeypatch.setenv("LLM_API_KEY", "mock-key")
    monkeypatch.setattr("app.agent.run_tool_loop", fake_tool_loop)

    result = run_agent(collection, decision)

    assert result.guardrail_verdict == "PASS"
    for private_value in ("sarah.connor@cyberdyne.io", "4532-8901-2345-6789", "555-432-8765"):
        assert private_value not in captured["prompt"]
        assert private_value not in captured["tools"]
    assert "[REDACTED_EMAIL]" in captured["tools"]


def test_provider_timeout_falls_back(monkeypatch):
    collection, decision = _build_case("TC1", "INC-PROVIDER-TIMEOUT")
    monkeypatch.setenv("LLM_API_KEY", "mock-key")
    monkeypatch.setattr(
        "app.agent.run_tool_loop",
        lambda *args, **kwargs: (_ for _ in ()).throw(ProviderError("timed out")),
    )

    result = run_agent(collection, decision)

    assert result.guardrail_verdict == "FALLBACK"
    assert "timed out" in result.provider_error


def test_gemini_minimal_call_builds_supported_schema_and_parses_response(monkeypatch):
    captured = {}

    class FakeModels:
        def generate_content(self, *, model, contents, config):
            captured.update(model=model, contents=contents, config=config)
            return SimpleNamespace(
                text="minimal response",
                function_calls=[SimpleNamespace(
                    id="call-1",
                    name=tools[0]["function"]["name"],
                    args={"incident_id": "INC-GEMINI-MINIMAL"},
                )],
                usage_metadata=SimpleNamespace(
                    prompt_token_count=2,
                    candidates_token_count=3,
                ),
            )

    class FakeClient:
        def __init__(self, **kwargs):
            captured["client_options"] = kwargs
            self.models = FakeModels()

    monkeypatch.setattr(genai, "Client", FakeClient)
    tools, _ = build_toolset(_build_case("TC1", "INC-GEMINI-MINIMAL")[0])
    response = _gemini_request(
        "minimal probe",
        tools,
        model="gemini-2.5-flash",
        api_key="test-secret",
        timeout=1,
    )

    assert response[0] == "minimal response"
    assert response[1] == [{
        "id": "call-1",
        "name": tools[0]["function"]["name"],
        "arguments": {"incident_id": "INC-GEMINI-MINIMAL"},
    }]
    assert response[2] == {"prompt_tokens": 2, "completion_tokens": 3}
    assert captured["model"] == "gemini-2.5-flash"
    assert captured["client_options"]["http_options"].timeout == 10_000
    assert captured["config"].thinking_config is None
    for declaration in captured["config"].tools[0].function_declarations:
        parameters = declaration.parameters.model_dump(exclude_none=True, by_alias=True)
        assert parameters["type"] == "OBJECT"
        assert parameters["required"] == ["incident_id"]
        assert parameters["properties"]["incident_id"]["type"] == "STRING"
        assert "additionalProperties" not in parameters


def test_gemini_full_agent_loop_calls_each_tool_then_parses_final_response(monkeypatch):
    collection, decision = _build_case("TC1", "INC-GEMINI-FULL")
    output, _ = _deterministic_output(collection, decision)
    calls = []

    def fake_gemini_request(prompt, tools, **kwargs):
        calls.append((prompt, tools, kwargs["model"]))
        return json.dumps(output), [], {}

    monkeypatch.setenv("LLM_API_KEY", "test-secret")
    monkeypatch.setenv("LLM_PROVIDER", "gemini")
    monkeypatch.setenv("LLM_MODEL", "gemini-2.5-flash")
    monkeypatch.setattr("app.llm._gemini_request", fake_gemini_request)

    result = run_agent(collection, decision)

    assert result.mode == "LLM agent"
    assert result.guardrail_verdict == "PASS"
    assert result.state == decision.status
    assert len(calls) == 1
    prompt, declarations, model = calls[0]
    assert model == "gemini-2.5-flash"
    assert declarations == []
    assert all(name in prompt for name in TOOL_NAMES)
    assert len(result.trace) >= len(TOOL_NAMES)


def test_gemini_api_error_logs_full_details_without_api_key(monkeypatch, caplog):
    from google.genai.errors import APIError

    secret = "do-not-log-this-key"
    error_details = {
        "error": {
            "code": 400,
            "status": "INVALID_ARGUMENT",
            "message": f"Invalid tool schema; credential {secret}",
            "details": [{"reason": "unsupported schema key"}],
        }
    }

    class FakeModels:
        def generate_content(self, **kwargs):
            raise APIError(400, error_details)

    class FakeClient:
        def __init__(self, **kwargs):
            self.models = FakeModels()

    monkeypatch.setattr(genai, "Client", FakeClient)
    with caplog.at_level("ERROR", logger="incident_voice"):
        with pytest.raises(ProviderError) as caught:
            _gemini_request(
                "probe",
                [],
                model="gemini-2.5-flash",
                api_key=secret,
                timeout=1,
            )

    assert "400: Invalid tool schema" in caught.value.diagnostic
    assert "status_code=400" in caplog.text
    assert "INVALID_ARGUMENT" in caplog.text
    assert "unsupported schema key" in caplog.text
    assert secret not in caplog.text
    assert secret not in caught.value.diagnostic
    assert not caught.value.retryable


def test_primary_quota_uses_configured_openai_compatible_fallback(monkeypatch):
    from app.llm import _request_with_failover

    monkeypatch.setenv("LLM_FALLBACK_PROVIDER", "openai_compat")
    monkeypatch.setenv("LLM_FALLBACK_API_KEY", "fallback-secret")
    monkeypatch.setenv("LLM_FALLBACK_MODEL", "groq/fast-model")
    monkeypatch.setenv("LLM_FALLBACK_BASE_URL", "https://api.groq.example/v1")
    calls = []

    def request(prompt, messages, tools, **kwargs):
        calls.append(kwargs)
        if len(calls) == 1:
            raise ProviderError(
                "full quota details",
                quota_error=True,
                retryable=False,
                user_message="Gemini quota reached; using rules fallback",
            )
        return '{"ok": true}', [], {"prompt_tokens": 1}

    monkeypatch.setattr("app.llm._request", request)
    response, provider, model, usage = _request_with_failover(
        "synthetic", [{"role": "user", "content": "synthetic"}], [],
        provider="gemini", model="gemini-test", api_key="primary-secret",
        timeout=12,
    )

    assert response == '{"ok": true}'
    assert provider == "openai_compat"
    assert model == "groq/fast-model"
    assert usage["prompt_tokens"] == 1
    assert calls[1]["base_url"] == "https://api.groq.example/v1"
    assert calls[1]["api_key"] == "fallback-secret"


def test_quota_failure_shows_short_status_without_leaking_diagnostic(monkeypatch):
    collection, decision = _build_case("TC1", "INC-QUOTA-BADGE")
    monkeypatch.setenv("LLM_API_KEY", "mock-key")
    monkeypatch.setenv("LLM_PROVIDER", "gemini")
    monkeypatch.delenv("LLM_FALLBACK_PROVIDER", raising=False)
    monkeypatch.setattr(
        "app.agent.run_tool_loop",
        lambda *args, **kwargs: (_ for _ in ()).throw(ProviderError(
            "full quota detail with internal identifiers",
            diagnostic="429 RESOURCE_EXHAUSTED full private diagnostic",
            quota_error=True,
            retryable=False,
            user_message="Gemini quota reached; using rules fallback",
        )),
    )

    result = run_agent(collection, decision)
    visible_content = json.dumps({
        "mode": result.mode,
        "provider_error": result.provider_error,
        "trace": result.trace,
        "reasons": result.guardrail_reasons,
    })

    assert result.provider_error == "Gemini quota reached; using rules fallback"
    assert "full private diagnostic" not in visible_content
    assert "internal identifiers" not in visible_content
    assert result.guardrail_verdict == "FALLBACK"


def test_recorded_response_replays_without_live_provider(monkeypatch, tmp_path):
    collection, decision = _build_case("TC1", "INC-RECORD-REPLAY")
    output, _ = _deterministic_output(collection, decision)
    recordings_path = tmp_path / "llm_recordings.json"
    monkeypatch.setenv("LLM_RECORDINGS_PATH", str(recordings_path))
    monkeypatch.setenv("RECORD_LLM", "true")
    monkeypatch.setenv("LLM_API_KEY", "mock-key")
    monkeypatch.setattr(
        "app.agent.run_tool_loop",
        lambda *args, **kwargs: (
            json.dumps(output), [], {"prompt_tokens": 1}, "gemini", "fixture-model",
        ),
    )

    recorded = run_agent(collection, decision, scenario_id="TC1")
    assert recorded.guardrail_verdict == "PASS"
    stored = json.loads(recordings_path.read_text(encoding="utf-8"))
    assert stored["TC1"]["provider"] == "gemini"

    monkeypatch.delenv("LLM_API_KEY", raising=False)
    monkeypatch.setattr(
        "app.agent.run_tool_loop",
        lambda *args, **kwargs: pytest.fail("replay must not call the provider"),
    )
    replay = run_agent(collection, decision, demo_mode=True, scenario_id="TC1")

    assert replay.mode == "Replay of a recorded LLM run"
    assert replay.guardrail_verdict == "PASS"
    assert replay.model == "fixture-model"
    assert len([step for step in replay.trace if step["tool_name"] in TOOL_NAMES]) == 5


def test_gemini_tool_loop_does_not_start_call_below_minimum_deadline(monkeypatch):
    monkeypatch.setenv("LLM_API_KEY", "test-secret")
    monkeypatch.setenv("LLM_PROVIDER", "gemini")
    monkeypatch.setenv("LLM_TIMEOUT_SECONDS", "8")
    monkeypatch.setattr(
        "app.llm._request",
        lambda *args, **kwargs: pytest.fail("Gemini call should not start below ten seconds remaining"),
    )

    with pytest.raises(ProviderError, match="at least a 10-second"):
        run_tool_loop("prompt", [], lambda *_: None, incident_id="INC-TIMEOUT")


def test_tool_loop_collects_five_tools_before_one_model_call(monkeypatch):
    monkeypatch.setenv("LLM_API_KEY", "mock-key")
    collection, _ = _build_case("TC1", "INC-STEP-CAP")
    tools, executor = build_toolset(collection)
    calls = []

    def single_response(prompt, messages, declarations, **kwargs):
        calls.append((prompt, declarations))
        return '{"ok": true}', [], {}

    monkeypatch.setattr("app.llm._request", single_response)
    response, trace, _, _, _ = run_tool_loop(
        "synthetic test prompt", tools, executor,
        incident_id=collection.incident_id,
    )
    assert response == '{"ok": true}'
    assert len(calls) == 1
    assert calls[0][1] == []
    assert all(tool["function"]["name"] in calls[0][0] for tool in tools)
    assert [step["tool_name"] for step in trace] == list(TOOL_NAMES)


def test_provider_request_uses_one_model_call(monkeypatch):
    monkeypatch.setenv("LLM_API_KEY", "mock-key")
    calls = []

    def respond(*args, **kwargs):
        calls.append(1)
        return '{"ok": true}', [], {}

    monkeypatch.setattr("app.llm._request", respond)

    response, trace, usage, provider, model = run_tool_loop(
        "synthetic test", [], lambda *_: None, incident_id="INC-ONE-CALL",
    )

    assert response == '{"ok": true}'
    assert len(calls) == 1
    assert trace == []
    assert provider == "gemini"


def test_demo_trick_is_blocked(monkeypatch):
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    collection, decision = _build_case("TC2", "INC-DEMO-TRICK")

    result = run_agent(collection, decision, demo_trick=True)

    assert result.guardrail_verdict == "FALLBACK"
    assert result.guardrail_reasons
    assert result.state == "UNCERTAIN"
    assert "blocked" in result.trace[0]["observation"].lower()
