# Offline Three-to-Five-Minute Demo

## Safe local setup

1. Install requirements and copy `.env.example` to `.env`.
2. Generate two distinct tokens locally:

   ```powershell
   python -c "import secrets; print(secrets.token_urlsafe(32))"
   ```

   Put one result in `OPERATOR_TOKEN` and a second in `ADMIN_TOKEN`. Never paste tokens into screenshots or source files.
3. Keep `OFFLINE_MODE=true`, `LIVE_LLM_ENABLED=false`, `EVIDENCE_SOURCE=fixtures`, and `DEMO_MODE=false` (or set `DEMO_MODE=true` only if local scenario recordings are available).
4. Start on loopback: `uvicorn app.main:app --host 127.0.0.1 --port 8000`.
5. Open `http://127.0.0.1:8000` and enter the admin token. The page keeps it in memory only.

The default demo uses synthetic fixtures and a local SQLite mock-channel ledger. It makes no Grafana, AI-provider, status-page, logs, or external-channel request. Dashboard-looking URLs are labels and are not fetched.

## Presentation

**0:00–0:30 — Safety and provenance**

“This local demo runs offline. Its evidence is synthetic and its channel is a SQLite mock, not a real destination. Every decision is traceable to signal IDs and source/retrieval times.”

**0:30–1:10 — TC1, status update**

1. Select TC1 and run the agent.
2. Show the `DEGRADED` decision, UTC brief time, evidence citations, and separate source and retrieval times.
3. Open the Agent Trace to show the offline rules path and guardrail step.

**1:10–1:45 — TC2, cached evidence**

1. Select TC2 and run it.
2. Show `UNCERTAIN`, cached/stale indicators, and the warning that cached data is not proof of recovery.
3. Explain that the stale HTTP-200 sample is a deterministic test fixture, not a live HTTP response.

**1:45–2:20 — TC4, failing health check**

1. Select TC4 and run.
2. Point out the healthy-looking metric beside the failed health probe.
3. Show `UNCERTAIN` and the “Recovery uncertain” message with the contradictory evidence preserved.

**2:20–2:55 — TC3, redaction**

1. Select TC3 and run.
2. Show redaction markers in evidence and the proposed brief/post. Explain that matching covers common patterns but is not a universal secret detector.

**2:55–3:45 — Approval and independent verification**

1. Review the proposed post and destination. Edit only before approval if demonstrating the run-bound approval guard.
2. Approve the update. It is written to the local mock ledger only.
3. Show the mock feed and independent read-back verification.
4. Retry the same approved action and show duplicate suppression. No external message is sent.

**3:45–4:30 — Automated acceptance**

1. Select **Run All Official Test Cases**; use admin access. Live LLM is off by default.
2. Show TC1–TC4 plus Mixed/Missing cases and the test-only approval/verification results.
3. Distinguish automated deterministic tests from manual browser interaction. No live Grafana, AI provider, or channel integration was verified.

## Optional local recordings

`DEMO_MODE=true` replays a matching recorded response from `LLM_RECORDINGS_PATH` without a network request, including when `OFFLINE_MODE=true`. Missing or invalid recordings use deterministic rules. Do not include credentials or private data in recording files.

## Not part of this demo

Do not set `OFFLINE_MODE=false` or configure live credentials for a presentation. No deployment, production identity provider, live Grafana endpoint, external AI provider, or real collaboration channel is verified.
