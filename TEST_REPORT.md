# Test and Verification Report

## Phase 9 final hackathon demo validation

Focused command:

```powershell
pytest -q tests/test_api.py tests/test_source_adapters.py tests/test_cases.py tests/test_agent.py
```

Observed: **91 passed, 0 failed, 0 skipped, 1 warning** in 12.42 seconds.

Full command:

```powershell
pytest -q
```

Observed: **91 passed, 0 failed, 0 skipped, 1 warning** in 12.50 seconds. The sole warning is Starlette's deprecation notice for the installed `httpx` test client.

Additional observed checks: `python -m compileall -q app tests` passed; inline browser JavaScript passed `node --check` using UTF-8 input; `git diff --check` passed. A repository scan found one credential-pattern match, classified as a synthetic test value; the local `.env` file is not tracked. No credential values were printed in the scan output. No screenshots were captured for this validation.

The Phase 9 browser smoke test was performed, not inferred from pytest alone. The loopback UI run used synthetic credentials, a temporary database, fixture evidence, and offline mode. It observed zero browser requests to non-loopback addresses; the API offline test separately instrumented provider/Grafana call paths and observed zero attempts.

## Phase 8 automated suite

Focused command:

```powershell
pytest -q tests/test_api.py tests/test_source_adapters.py tests/test_cases.py tests/test_agent.py
```

Result: **91 passed, 1 warning** in 15.11 seconds; **0 skipped, 0 failed**.

Full suite:

```powershell
pytest -q
```

Result: **91 passed, 1 warning** in 15.13 seconds; **0 skipped, 0 failed**. The warning is Starlette's deprecation notice for the installed `httpx` test client; no application tests failed.

Tests use deterministic fixtures/mocks and isolated SQLite databases. No real AI provider, Grafana endpoint, status page, log source, or external channel was contacted.

## Acceptance evidence

- **Authentication:** public routes are limited to app/static resources, health, scenario metadata, and non-secret runtime config. Operator bearer authentication protects analysis, run details/exports, approval/rejection, verification, channel feed, test-run history, and legacy hook. Admin is required for run-tests and channel reset. Tests cover unauthenticated and invalid bearer requests, role restrictions, missing/identical token configuration, token absence from response/log output, and authorized approval role recording.
- **Token lifecycle:** tokens are static environment values (`OPERATOR_TOKEN`, `ADMIN_TOKEN`), with no expiry or in-app revocation. A leaked token must be revoked by changing configuration and restarting; this is demo-grade and not appropriate for production identity.
- **Grafana credentials:** mocked adapter coverage verifies the configured API key in the Authorization header and its absence from URL/result/log/error output. Missing key, malformed/credential-bearing URLs, pre-existing URL query strings, and redirect forwarding are covered. Redirects are refused; no live Grafana call was made.
- **Offline API guard:** TC1–TC4 API workflows use `OFFLINE_MODE=true` and replace Gemini, OpenAI-compatible, agent-provider-loop, and Grafana network functions with fail-immediately instrumented stubs. The four attempt counters were **0**. Status/log/change evidence is local synthetic fixture data; channel persistence uses SQLite, not a messaging service.
- **TC1:** UTC assessment/brief times, evidence IDs, source identifiers/timestamps, separate retrieval times, and claim traceability.
- **TC2:** cached/stale evidence, including synthetic HTTP-200 metadata with a 600-second-old source timestamp, cannot establish recovery.
- **TC3:** synthetic emails, phone/card-like values, API/access tokens, and authorization headers are redacted from generated data and exported reports. Redaction remains heuristic.
- **TC4:** failing health checks prevent recovery confirmation; contradictory evidence remains represented and uncertainty is stated.
- **Approval integrity:** edits to unposted approved content or destination invalidate approval. Rejection is terminal; pending is rejected by schema validation; duplicate and concurrent retries create one mock post. Failed or ambiguous persistence returns an error and cannot pass independent verification, including when a local post row exists but action status is `POST_FAILED`.
- **Provider behavior:** Gemini schema/response parsing, one-call synthesis, quota failover, fallback, recording/replay are tested at mocked provider boundaries. Recordings replay locally while offline.

## Browser verification

A loopback-only server was run at `127.0.0.1:8767` with a temporary SQLite database, synthetic operator/admin tokens, `OFFLINE_MODE=true`, `LIVE_LLM_ENABLED=false`, fixture data, and a synthetic unused LLM key.

- Browser request capture observed **0 non-loopback requests** during TC1–TC4. This statement covers browser-originated requests in the captured UI workflow; the provider/source attempt counters above independently cover application-side provider/Grafana paths.
- TC1 produced `DEGRADED`, was approved in the UI, written to the local mock ledger, independently verified (`VERIFIED`, 6/6 checks), and retried without a duplicate.
- TC2, TC3, TC4 returned `UNCERTAIN`; TC3 displayed redaction markers.
- Offline dictation was refused with a visible explanation; playback was disabled.
- This was a manual/tool-driven browser check, not an automated browser test or a live integration test.

## Other checks

| Command | Result |
|---|---|
| `python -m compileall -q app tests` | Passed |
| Extract inline `<script>` and run `node --check -` with UTF-8 input | Passed |
| `git diff --check` | Passed |

## Limitations

- **Verified with deterministic mocks:** auth roles and token error handling; Grafana header/URL/redirect handling and response parsing; offline guards; approval states; duplicate prevention; verification; TC1–TC4.
- **Verified in offline browser:** local UI authentication, TC1–TC4 analysis, TC1 mock approval/post/read-back, duplicate retry, offline speech controls.
- **Verified against a real authorized provider:** none.
- **Not implemented or not verified:** live status-page/health/log/recent-change or external-channel adapters; live Grafana reachability/credentials; production AI connectivity; identity provider or expiring user sessions; deployment/storage durability; multi-worker load behavior.
- Static bearer tokens do not expire and identify a role, not an individual. Use a production identity provider, short-lived credentials, TLS, and named audit identities before operational use.

The `/api/run-tests` endpoint runs labelled synthetic scenarios and simulated approvals in the local mock channel. Its PASS result does not demonstrate external delivery.
