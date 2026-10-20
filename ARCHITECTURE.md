# Architecture and Data Flow

## Components

- `app/main.py`: FastAPI routes, route dependencies, explicit offline/provider gates, ten-minute in-process analysis cache, test runner, and exports.
- `app/security.py`: constant-time comparison of environment-provisioned operator/admin bearer tokens.
- `app/sources.py`: deterministic synthetic scenarios for TC1–TC4, Mixed, and Missing.
- `app/source_adapters.py`: opt-in configured Prometheus-compatible Grafana query adapter; it does not use fixtures on source failure.
- `app/collector.py`: selects fixture or Grafana mode, redacts evidence, computes freshness, and persists provenance.
- `app/rules.py`: authoritative deterministic incident decision rules.
- `app/tools.py`, `app/llm.py`, `app/agent.py`: local evidence tool trace, guarded LLM synthesis/replay, provider failover, response parsing, and rules fallback.
- `app/brief.py`, `app/redact.py`: voice brief, proposed post, and sensitive-data protection.
- `app/channel.py`, `app/verify.py`: run-bound approval, local mock posting, and independent read-back verification.
- `app/db.py`: SQLite persistence for incidents, evidence, assessments, approvals, mock posts, and audit reports.
- `static/index.html`: same-origin browser console. Its access token remains in page memory and is sent in the Authorization header.

## Offline mode and provider gates

`OFFLINE_MODE=true` is the application default. Only the explicit value `false` disables offline mode; missing or unrecognized values remain offline. It prevents external LLM and Grafana requests even if API keys are present. Fixture sources and the mock channel operate locally. The browser UI contains no remotely loaded fonts or scripts, and browser-managed speech recognition/playback is disabled in offline mode; it can be loaded without an external request. A recorded LLM scenario may be replayed from the local recordings file when `DEMO_MODE=true`; replay does not make a provider request.

Live LLM requests require both `OFFLINE_MODE=false` and `LIVE_LLM_ENABLED=true`, plus the configured provider key. Test-runner live mode is separately requested and still requires those gates. Grafana mode requires `OFFLINE_MODE=false`, an explicitly configured authorized HTTPS endpoint, and approved metric query expressions. Request-supplied dashboard URLs are never fetched. If offline Grafana mode is selected, it returns `unavailable_offline` signals and does not substitute fixture evidence.

## API authentication

Sensitive reads and state-changing routes use `require_operator`; test execution and mock-channel reset use `require_admin`. Public routes are limited to the app shell, health, scenario metadata, and non-secret runtime mode configuration. Tokens are provisioned through `OPERATOR_TOKEN` and `ADMIN_TOKEN`. If both are empty, protected routes fail closed with HTTP 503. The application uses no password store, cookie session, or browser-persisted token, so cookie CSRF protection is not applicable. Tokens have no expiry and identify only a role; use TLS and an identity provider with per-user audit identity before deployment to an operational environment.

## Evidence and decisions

Fixture evidence is explicitly synthetic. Grafana evidence is labelled live only when it comes from a successful configured request; failures retain unavailable status. Signals record evidence ID, source ID/URL, source observation time, retrieval time, age/freshness, origin, and retrieval status. Missing, malformed, naive, future, cached, or stale timestamps cannot independently establish recovery. A failing health check or missing required evidence yields `UNCERTAIN`, including when an HTTP response is 200. Metrics-only Grafana mode cannot confirm recovery because health/status/log/change adapters are not implemented.

Five local tools (metrics, status, health, logs, recent changes) run in one code step and each observation is included in the trace. An LLM synthesis normally uses one provider request, with at most one repair request; deterministic rules remain authoritative. Offline rules and local replay do not contact providers.

## Approval, posting, verification

Analysis results are cached in-process for ten minutes by identical request inputs. Approval is tied to the exact agent run, incident, message, and destination. A changed or rejected action cannot be posted for that run; a new run invalidates pending/unposted approvals for the incident. The approval role is stored, but not an individual identity. The channel is a local SQLite ledger only.

An in-process lock serializes action attempts and SQLite's unique idempotency key prevents duplicate post records, including database-level races. A failed/ambiguous persistence is not reported as verified. Independent verification checks persisted approval, exact content/destination, run evidence citations, and the mock ledger.

## Verification status and limitations

- Automated pytest, Python compilation, inline JavaScript syntax, and `git diff --check` results are recorded in `TEST_REPORT.md`.
- Authentication, source credential handling, offline behavior, and TC1–TC4 are verified with deterministic tests; one browser run exercised the offline UI workflow against a loopback server.
- No live Grafana, AI provider, status page, log source, or external channel was contacted.
- The Grafana adapter has mocked response tests only. Do not treat an authorized endpoint as live-verified or production-ready.
- Static bearer tokens have no expiry or per-user identity. Rotate them manually and do not expose the demo publicly.
- Cache and action lock are process-local; the SQLite unique index is the duplicate-write backstop. Multi-worker operational deployment has not been tested.
- Persistence on hosted platforms depends on separately configured durable storage.
