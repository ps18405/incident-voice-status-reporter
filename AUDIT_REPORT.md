# Security Audit and Remediation Report

## Scope

Reviewed the existing FastAPI application, route surface, browser UI, evidence adapters, SQLite state transitions, tests, and project documentation for Phase 9 hackathon demo acceptance. Verification used synthetic credentials and deterministic mocks. No deployment, real Grafana request, external AI call, or external channel post was performed.

The implementation is FastAPI, not Flask. The user interface and service use the same-origin JSON API.

## Findings and remediation

| Severity | Finding | Remediation | Evidence |
|---|---|---|---|
| High | Protected incident reads and state-changing actions previously lacked operator authentication. | Added environment-provisioned bearer tokens with operator/admin role checks. Analysis, run reads/exports, approvals/rejections, verification, channel feed, and history require operator. Test runs and channel reset require admin. Missing token configuration fails closed. | API tests cover unauthenticated access to sensitive routes, invalid tokens, operator/admin role restrictions, no-token configuration, and an authorized approval whose role is persisted. |
| High | A configured Grafana API key could be mishandled, and endpoint query parameters could carry credentials or appear in evidence URLs. | Key is sent only in the Authorization header to the explicitly configured endpoint. Embedded URL credentials, fragments, and all pre-existing query parameters are rejected. Redirects are not followed. Error records/logging avoid response bodies and secrets. | Mocked adapter tests assert expected auth header, key absence from URL/results/logs, missing-key behavior, URL rejection, redirect refusal, timeouts, connection and HTTP errors, malformed samples, and non-finite values. No real endpoint was contacted. |
| High | The browser smoke test previously made a model request even when an empty key was intended. | `OFFLINE_MODE=true` now defaults on and takes precedence over keys. Live model calls additionally require `LIVE_LLM_ENABLED=true`. Offline Grafana returns unavailable evidence and never falls back to fixtures. Removed remote Google Fonts so UI load is offline too. | An HTTP-level TC1–TC4 test patches Gemini, OpenAI-compatible, agent-provider, and Grafana request functions to fail if called. A loopback browser run recorded zero non-loopback requests while loading and exercising the UI. |
| High | Approval and retry state needed exact binding and race-safe duplicate prevention. | Approval is run-, incident-, content-, and destination-bound; role is recorded; rejected actions are terminal; a new run invalidates pending/unposted approval. Same-process actions are serialized and SQLite atomically enforces unique idempotency keys. | API tests cover rejection, edits, invalidation, persistence failure, retries, independent verification, and concurrent duplicate attempts resulting in one stored post. |
| Medium | Failed health, stale/cached evidence, or missing evidence could otherwise be overinterpreted as recovery. | Deterministic rules keep such outcomes uncertain and preserve contradictory evidence. HTTP 200 alone is not a health/recovery assertion. | TC2 stale/cache tests, TC4 failing-health acceptance tests, and Grafana parser tests. |
| Medium | Common PII and credentials in logs/exports required stronger filtering. | Context-aware redaction handles common email, phone, card-like, API-key, access-token, and authorization-header patterns at ingestion/output boundaries. | TC3 and exported report tests check synthetic secret markers and PII. Pattern matching remains heuristic and cannot guarantee detection of every secret. |
| Medium (corrected in Phase 8) | Destination changes were rejected before reaching the channel approval integrity check, so an unposted failed approval could remain active after a changed-destination attempt. Also, verification accepted `POST_FAILED` as a valid run-bound approval when an ambiguous post row existed. | Changed destination attempts now invalidate an unposted approval. Verification requires the persisted approval status to be `APPROVED`; a post row associated with a `POST_FAILED` outcome cannot pass run-bound verification. | Regression tests simulate failed persistence followed by destination edit, and persistence followed by an ambiguous error with a post row. Both states are asserted not verified. |

## Route exposure

- Public by design: `/`, `/favicon.ico`, `/health`, `/api/scenarios`, `/api/config`.
- Operator bearer required: incident collection/analysis; run details and export; approve/reject; verify; channel feed; test-run history; legacy LLM hook.
- Admin bearer required: `/api/run-tests` and `/api/reset-channel`.
- The HTML and static assets are public; protected data/actions are not. The browser holds its token only in page memory and sends it with protected requests.
- Tokens are static environment values without expiry or in-app revocation. A leaked token is revoked only by replacing the relevant environment value and restarting the application. Treat these as demo-grade credentials, not production authentication.

## Remaining risks and deployment limits

- Bearer tokens are static environment values; they have no expiration, revocation endpoint, per-user identity, or password/session lifecycle. Rotation requires changing the environment and restarting. Use a production identity provider, short-lived credentials, TLS, and individual audit identities before operational deployment.
- No cookie session is used, so cookie-based CSRF is not applicable. Cross-origin browser access is disabled unless explicitly configured. Authentication errors do not echo supplied or configured bearer values.
- Offline mode controls application provider/source integrations; browser speech depends on local browser capabilities. No UI call to a live service was made during the offline browser check.
- Grafana coverage is mocked only. Endpoint authorization, reachability, TLS setup, provider credentials, and live response behavior are not verified. The adapter covers metrics only; health, status-page, log, and change live adapters do not exist.
- The mock channel is a local SQLite ledger, not an external messaging integration. No external posting behavior is implemented or verified.
- The in-memory cache and lock are process-local. SQLite's unique key prevents duplicate post rows, but multi-worker deployment behavior was not load-tested.
- Redaction is best-effort heuristic filtering; do not use it as the sole control for regulated data or arbitrary secrets.
- Hosting, TLS termination, persistent storage, backup/restore, and production deployment were not tested.

## Honest status

Phase 9 focused selectors and full suite both passed: **91 passed, 1 warning, 0 skipped** for each. Provider/Grafana test counters remained at zero in the guarded offline TC1–TC4 workflow; browser capture recorded zero non-loopback requests during the exercised UI workflow. The repository scan found one credential-pattern match in a synthetic test value; no production credential was identified or printed, and `.env` is not tracked. The application is ready for a hackathon demo using synthetic/mock data, with the limitations above. It is not production-ready as an incident operations service, and no real provider integration is claimed. See `TEST_REPORT.md` for commands and outcomes.
