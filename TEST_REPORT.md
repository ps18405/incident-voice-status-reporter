# 📊 Automated Test and Verification Report

**Incident Voice Status Reporter — Agentic AI Hackathon 2026**  
**Execution Timestamp:** 2026-10-21T15:05:30Z  
**Environment:** Python 3.11.4 | FastAPI 0.146.0 | Pytest 8.4.2  

---

## 🏆 Test Suite Execution Summary

```powershell
pytest -v
```

```
============================= test session starts =============================
platform win32 -- Python 3.11.4, pytest-8.4.2, pluggy-1.7.0
rootdir: C:\Users\ps213\OneDrive\Desktop\voice
configfile: pytest.ini
testpaths: tests
plugins: anyio-4.15.1
collected 99 items

tests/test_agent.py ........................                             [ 24%]
tests/test_api.py ................................                       [ 56%]
tests/test_cases.py ..............                                       [ 70%]
tests/test_rules_engine.py ........                                      [ 78%]
tests/test_source_adapters.py .....................                      [100%]

======================= 99 passed, 1 warning in 15.99s ========================
```

- **Total Test Cases:** 99
- **Passed:** 99 (100%)
- **Failed:** 0 (0%)
- **Skipped:** 0 (0%)
- **Warnings:** 1 (Starlette deprecation notice for httpx test client)

---

## 🧪 Hackathon Official Test Cases (TC1 — TC4) Evidence Table

| Test Case | Scenario Name | Status | Expected Behavior | Actual Behavior | Verifier Result | Audit Explanation |
|:---:|:---|:---:|:---|:---|:---:|:---|
| **TC1** | **Status update** | **`PASS`** | `DEGRADED`; includes timestamps and signal citations `[SIG-xxx]` | State `DEGRADED`; brief starts with timestamp; claims cite source IDs `[SIG-METRIC-ERR]`, `[SIG-STAT-01]`, `[SIG-HLTH-01]`, `[SIG-LOG-01]` | **`PASS`** | All required assertions held; test-only approval was simulated and independent verifier confirmed content fidelity and signal linkage. |
| **TC2** | **Cached dashboard** | **`PASS`** | `UNCERTAIN`; cached data is explicitly not proof of recovery | State `UNCERTAIN`; cached warning raised; voice brief states *"cached dashboard detected: this is not proof of recovery"* | **`PASS`** | Edge-cache returns low error rate (0.1%), but deterministic `RULE-CACHED-01` rejects recovery claim and marks state `UNCERTAIN`. |
| **TC3** | **Customer data in logs** | **`PASS`** | `UNCERTAIN`; synthetic customer data is redacted everywhere | Zero customer PII leaked; emails (`alice.smith@example.com`), phones, and payment cards redacted to `[REDACTED_*]` | **`PASS`** | All sensitive patterns sanitized at boundary before reaching LLM context, voice brief, channel post, or export reports. |
| **TC4** | **Health check failing** | **`PASS`** | `UNCERTAIN`; failing health check says recovery uncertain | State `UNCERTAIN`; probe failure (500/503) overrides low error rate; brief states *"recovery uncertain"* | **`PASS`** | Deterministic `RULE-HEALTH-FAIL-01` enforces probe priority. Even with 0.2% error rate, failing probe prevents recovery declaration. |
| **MIXED** | **Mixed signals** | **`PASS`** | `DEGRADED`; fresh elevated metrics override resolved status text | State `DEGRADED`; status page claims operational but elevated metric (12.5%) triggers `RULE-CONFLICT-01` | **`PASS`** | Fresh telemetry overrides static/delayed status page claims; contradiction explained clearly in decision reason and voice brief. |
| **MISSING** | **Missing evidence** | **`PASS`** | `UNCERTAIN`; unavailable log source is disclosed | State `UNCERTAIN`; missing log telemetry discloses source unavailability via `RULE-LOG-AVAIL-01` | **`PASS`** | Agent refuses to guess when required evidence is missing or unreachable. Uncertainty declared honestly. |

---

## 🛡️ Security, Privacy & Integrity Verifications

1. **Synthetic Data Only:** All telemetry, logs, and customer records are synthetic. Zero real customer data or PII was ingested or processed.
2. **Deterministic Guardrails:** The LLM is restricted to phrasing the brief; operational state decisions are strictly calculated by pure Python rules in `app/rules.py`.
3. **Run-Bound Human Approval:** The agent cannot publish autonomously. Rejections are permanently recorded and cannot post.
4. **SHA-256 Idempotency:** Duplicate posts on network retries or double-clicks are suppressed, preventing channel spam.
5. **Separate Verification:** The independent verifier re-reads channel storage and compares character-for-character fidelity against operator-approved text.
6. **Negative Tamper Demo:** The tamper simulation modifies the database record, causing Check 2 (Content Fidelity) to visibly fail with `FAIL: Mismatch detected!`, proving the verifier is genuinely independent.
