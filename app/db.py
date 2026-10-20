"""SQLite database storage for Incident Voice Status Reporter.
Schema includes: incidents, signals, decisions, approvals, posts, test_runs.
"""
from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

def get_default_db_path() -> Path:
    env_db = os.getenv("DB_PATH")
    if env_db:
        return Path(env_db)
    if os.getenv("VERCEL"):
        return Path("/tmp/incident.db")
    return Path(__file__).resolve().parent.parent / "incident_reporter.db"


DB_PATH = get_default_db_path()

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    scope TEXT NOT NULL,
    dashboards TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS signals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL,
    signal_id TEXT NOT NULL,
    source_type TEXT NOT NULL,
    name TEXT NOT NULL,
    url TEXT NOT NULL,
    value TEXT NOT NULL,
    unit TEXT,
    source_updated_at TEXT NOT NULL,
    retrieved_at TEXT NOT NULL,
    age_seconds REAL NOT NULL,
    is_cached INTEGER NOT NULL,
    is_stale INTEGER NOT NULL,
    source_id TEXT NOT NULL DEFAULT '',
    evidence_origin TEXT NOT NULL DEFAULT 'synthetic_fixture',
    retrieval_status TEXT NOT NULL DEFAULT 'success',
    raw_payload TEXT,
    FOREIGN KEY (incident_id) REFERENCES incidents (id)
);

CREATE TABLE IF NOT EXISTS decisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL,
    status TEXT NOT NULL,
    reason TEXT NOT NULL,
    uncertainty_flag INTEGER NOT NULL,
    cached_warning INTEGER NOT NULL,
    evidence_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (incident_id) REFERENCES incidents (id)
);

CREATE TABLE IF NOT EXISTS approvals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL,
    agent_run_id INTEGER,
    action_type TEXT NOT NULL,
    destination TEXT NOT NULL,
    proposed_message TEXT NOT NULL,
    status TEXT NOT NULL,
    approved_at TEXT,
    idempotency_key TEXT NOT NULL,
    approved_by TEXT NOT NULL DEFAULT 'offline_test',
    FOREIGN KEY (incident_id) REFERENCES incidents (id)
);

CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL,
    destination TEXT NOT NULL,
    message TEXT NOT NULL,
    posted_at TEXT NOT NULL,
    idempotency_key TEXT UNIQUE NOT NULL,
    is_duplicate INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (incident_id) REFERENCES incidents (id)
);

CREATE TABLE IF NOT EXISTS test_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    test_case_id TEXT NOT NULL,
    scenario_name TEXT NOT NULL,
    input_json TEXT NOT NULL,
    expected_result TEXT NOT NULL,
    actual_result TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    status TEXT NOT NULL,
    explanation TEXT,
    run_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS agent_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL,
    mode TEXT NOT NULL,
    model TEXT NOT NULL,
    steps INTEGER NOT NULL,
    guardrail_verdict TEXT NOT NULL,
    guardrail_reasons TEXT NOT NULL,
    state TEXT NOT NULL,
    latency_ms REAL NOT NULL,
    token_usage TEXT NOT NULL,
    report_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS agent_trace (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL,
    step INTEGER NOT NULL,
    thought_summary TEXT NOT NULL,
    tool_name TEXT,
    arguments_json TEXT NOT NULL,
    observation_json TEXT NOT NULL,
    latency_ms REAL NOT NULL,
    FOREIGN KEY (run_id) REFERENCES agent_runs (id)
);
"""


def ensure_tables_exist(conn: sqlite.Connection) -> None:
    """Ensure all required tables and seeded mock data exist on every cold start."""
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='incidents'")
    has_incidents = cursor.fetchone()
    if not has_incidents:
        with conn:
            conn.executescript(SCHEMA_SQL)
            seed_mock_data_if_empty(conn)
    else:
        with conn:
            conn.executescript(SCHEMA_SQL)
    cursor.execute("PRAGMA table_info(signals)")
    signal_columns = {row["name"] for row in cursor.fetchall()}
    for column, definition in (
        ("source_id", "TEXT NOT NULL DEFAULT ''"),
        ("evidence_origin", "TEXT NOT NULL DEFAULT 'synthetic_fixture'"),
        ("retrieval_status", "TEXT NOT NULL DEFAULT 'success'"),
    ):
        if column not in signal_columns:
            conn.execute(f"ALTER TABLE signals ADD COLUMN {column} {definition}")
    cursor.execute("PRAGMA table_info(approvals)")
    approval_columns = {row["name"] for row in cursor.fetchall()}
    if "agent_run_id" not in approval_columns:
        conn.execute("ALTER TABLE approvals ADD COLUMN agent_run_id INTEGER")
    if "approved_by" not in approval_columns:
        conn.execute("ALTER TABLE approvals ADD COLUMN approved_by TEXT NOT NULL DEFAULT 'legacy'")
    conn.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS approvals_agent_run_id_unique
        ON approvals(agent_run_id) WHERE agent_run_id IS NOT NULL
        """
    )


def get_connection(db_path: Optional[Path] = None) -> sqlite3.Connection:
    target_path = Path(db_path or DB_PATH or get_default_db_path())
    target_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(target_path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    ensure_tables_exist(conn)
    return conn


def init_db(db_path: Optional[Path] = None) -> None:
    conn = get_connection(db_path)
    with conn:
        conn.executescript(SCHEMA_SQL)
        seed_mock_data_if_empty(conn)
    conn.close()


def seed_mock_data_if_empty(conn: sqlite3.Connection) -> None:
    """Pre-seed database with baseline synthetic incidents and signals if empty."""
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM incidents")
    count = cursor.fetchone()[0]
    if count == 0:
        from app.sources import get_mock_scenario_sources
        from app.redact import redact_text, redact_data_structure
        now = datetime.now(timezone.utc).isoformat()
        for sc_id in ["TC1", "TC2", "TC3", "TC4"]:
            sc = get_mock_scenario_sources(sc_id)
            inc_id = f"INC-{sc_id}-DEFAULT"
            clean_scope, _ = redact_text(sc.get("default_scope", ""))
            dashboards = json.dumps(sc.get("dashboards", []))
            conn.execute(
                "INSERT INTO incidents (id, scope, dashboards, created_at) VALUES (?, ?, ?, ?)",
                (inc_id, clean_scope, dashboards, now),
            )
            for s in sc.get("signals", []):
                c_val, _ = redact_text(str(s["value"]))
                c_name, _ = redact_text(str(s["name"]))
                c_payload = redact_data_structure(s.get("raw_payload", {}))
                conn.execute(
                    """
                    INSERT INTO signals (
                        incident_id, signal_id, source_type, name, url, value, unit,
                        source_updated_at, retrieved_at, age_seconds, is_cached, is_stale,
                        source_id, evidence_origin, retrieval_status, raw_payload
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        inc_id,
                        s["signal_id"],
                        s["source_type"],
                        c_name,
                        s["url"],
                        c_val,
                        s.get("unit", ""),
                        s["source_updated_at"],
                        now,
                        30.0,
                        1 if s.get("is_cached") else 0,
                        1 if s.get("is_cached") else 0,
                        s.get("url", ""),
                        "synthetic_fixture",
                        "success",
                        json.dumps(c_payload),
                    ),
                )



def save_incident(incident_id: str, scope: str, dashboards: List[str], db_path: Optional[Path] = None) -> None:
    conn = get_connection(db_path)
    now = datetime.now(timezone.utc).isoformat()
    with conn:
        conn.execute(
            """
            INSERT INTO incidents (id, scope, dashboards, created_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                scope = excluded.scope,
                dashboards = excluded.dashboards,
                created_at = excluded.created_at
            """,
            (incident_id, scope, json.dumps(dashboards), now),
        )
    conn.close()


def save_signals(incident_id: str, signals: List[Dict[str, Any]], db_path: Optional[Path] = None) -> None:
    conn = get_connection(db_path)
    with conn:
        conn.execute("DELETE FROM signals WHERE incident_id = ?", (incident_id,))
        for s in signals:
            conn.execute(
                """
                INSERT INTO signals (
                    incident_id, signal_id, source_type, name, url, value, unit,
                    source_updated_at, retrieved_at, age_seconds, is_cached, is_stale,
                    source_id, evidence_origin, retrieval_status, raw_payload
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    incident_id,
                    s["signal_id"],
                    s["source_type"],
                    s["name"],
                    s["url"],
                    str(s["value"]),
                    s.get("unit", ""),
                    s["source_updated_at"],
                    s["retrieved_at"],
                    float(s.get("age_seconds", 0.0)),
                    1 if s.get("is_cached") else 0,
                    1 if s.get("is_stale") else 0,
                    s.get("source_id", s.get("url", "")),
                    s.get("evidence_origin", "synthetic_fixture"),
                    s.get("retrieval_status", "success"),
                    json.dumps(s.get("raw_payload", {})),
                ),
            )
    conn.close()


def get_signals_by_incident(incident_id: str, db_path: Optional[Path] = None) -> List[Dict[str, Any]]:
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM signals WHERE incident_id = ?", (incident_id,))
    rows = cursor.fetchall()
    result = [dict(row) for row in rows]
    conn.close()
    return result


def save_decision(
    incident_id: str,
    status: str,
    reason: str,
    uncertainty_flag: bool,
    cached_warning: bool,
    evidence: List[Dict[str, Any]],
    db_path: Optional[Path] = None,
) -> int:
    conn = get_connection(db_path)
    now = datetime.now(timezone.utc).isoformat()
    with conn:
        conn.execute(
            """
            UPDATE approvals
            SET status = 'INVALIDATED'
            WHERE incident_id = ?
              AND status IN ('APPROVED', 'POST_FAILED')
              AND NOT EXISTS (
                  SELECT 1 FROM posts WHERE posts.idempotency_key = approvals.idempotency_key
              )
            """,
            (incident_id,),
        )
        cursor = conn.execute(
            """
            INSERT INTO decisions (
                incident_id, status, reason, uncertainty_flag, cached_warning, evidence_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                incident_id,
                status,
                reason,
                1 if uncertainty_flag else 0,
                1 if cached_warning else 0,
                json.dumps(evidence),
                now,
            ),
        )
        decision_id = cursor.lastrowid
    conn.close()
    return decision_id


def save_approval(
    incident_id: str,
    destination: str,
    proposed_message: str,
    status: str,
    idempotency_key: str,
    action_type: str = "CHANNEL_POST",
    agent_run_id: Optional[int] = None,
    approved_by: str = "offline_test",
    db_path: Optional[Path] = None,
) -> int:
    conn = get_connection(db_path)
    now = datetime.now(timezone.utc).isoformat() if status in ("APPROVED", "REJECTED") else None
    with conn:
        cursor = conn.execute(
            """
            INSERT INTO approvals (
                incident_id, agent_run_id, action_type, destination, proposed_message,
                status, approved_at, idempotency_key, approved_by
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                incident_id, agent_run_id, action_type, destination,
                proposed_message, status, now, idempotency_key, approved_by,
            ),
        )
        approval_id = cursor.lastrowid
    conn.close()
    return approval_id


def update_approval_status(
    approval_id: int,
    status: str,
    db_path: Optional[Path] = None,
) -> None:
    conn = get_connection(db_path)
    now = datetime.now(timezone.utc).isoformat()
    with conn:
        conn.execute(
            "UPDATE approvals SET status = ?, approved_at = ? WHERE id = ?",
            (status, now, approval_id),
        )
    conn.close()


def save_post(
    incident_id: str,
    destination: str,
    message: str,
    idempotency_key: str,
    is_duplicate: bool = False,
    db_path: Optional[Path] = None,
) -> Optional[int]:
    conn = get_connection(db_path)
    now = datetime.now(timezone.utc).isoformat()
    with conn:
        cursor = conn.execute(
            """
            INSERT OR IGNORE INTO posts (
                incident_id, destination, message, posted_at, idempotency_key, is_duplicate
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (incident_id, destination, message, now, idempotency_key, 1 if is_duplicate else 0),
        )
        post_id = cursor.lastrowid if cursor.rowcount else None
    conn.close()
    return post_id


def get_post_by_idempotency_key(idempotency_key: str, db_path: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM posts WHERE idempotency_key = ?", (idempotency_key,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def get_all_posts(db_path: Optional[Path] = None) -> List[Dict[str, Any]]:
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM posts ORDER BY id DESC")
    rows = cursor.fetchall()
    result = [dict(row) for row in rows]
    conn.close()
    return result


def clear_channel_posts(db_path: Optional[Path] = None) -> None:
    conn = get_connection(db_path)
    with conn:
        conn.execute("DELETE FROM posts")
        conn.execute("DELETE FROM approvals")
    conn.close()


def record_test_run(
    test_case_id: str,
    scenario_name: str,
    input_data: Dict[str, Any],
    expected_result: str,
    actual_result: str,
    evidence: List[Dict[str, Any]],
    status: str,
    explanation: Optional[str] = None,
    db_path: Optional[Path] = None,
) -> int:
    conn = get_connection(db_path)
    now = datetime.now(timezone.utc).isoformat()
    with conn:
        cursor = conn.execute(
            """
            INSERT INTO test_runs (
                test_case_id, scenario_name, input_json, expected_result, actual_result,
                evidence_json, status, explanation, run_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                test_case_id,
                scenario_name,
                json.dumps(input_data),
                expected_result,
                actual_result,
                json.dumps(evidence),
                status,
                explanation or "",
                now,
            ),
        )
        run_id = cursor.lastrowid
    conn.close()
    return run_id


def get_latest_test_runs(db_path: Optional[Path] = None) -> List[Dict[str, Any]]:
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT t.* FROM test_runs t
        INNER JOIN (
            SELECT test_case_id, MAX(id) as max_id
            FROM test_runs
            GROUP BY test_case_id
        ) latest ON t.id = latest.max_id
        ORDER BY t.test_case_id ASC
        """
    )
    rows = cursor.fetchall()
    result = [dict(row) for row in rows]
    conn.close()
    return result


def record_agent_run(
    incident_id: str,
    report: Dict[str, Any],
    db_path: Optional[Path] = None,
) -> int:
    conn = get_connection(db_path)
    now = datetime.now(timezone.utc).isoformat()
    trace = report.get("trace", [])
    with conn:
        cursor = conn.execute(
            """
            INSERT INTO agent_runs (
                incident_id, mode, model, steps, guardrail_verdict, guardrail_reasons,
                state, latency_ms, token_usage, report_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                incident_id,
                report["mode"],
                report["model"],
                len(trace),
                report["guardrail_verdict"],
                json.dumps(report.get("guardrail_reasons", [])),
                report["state"],
                float(report.get("latency_ms", 0)),
                json.dumps(report.get("token_usage", {})),
                json.dumps(report, ensure_ascii=True),
                now,
            ),
        )
        run_id = int(cursor.lastrowid)
        for item in trace:
            conn.execute(
                """
                INSERT INTO agent_trace (
                    run_id, step, thought_summary, tool_name, arguments_json,
                    observation_json, latency_ms
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    int(item.get("step", 0)),
                    item.get("thought_summary", ""),
                    item.get("tool_name"),
                    json.dumps(item.get("arguments", {}), ensure_ascii=True),
                    json.dumps(item.get("observation", {}), ensure_ascii=True),
                    float(item.get("latency_ms", 0)),
                ),
            )
    conn.close()
    return run_id


def get_agent_run(run_id: int, db_path: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    conn = get_connection(db_path)
    row = conn.execute("SELECT report_json FROM agent_runs WHERE id = ?", (run_id,)).fetchone()
    conn.close()
    return json.loads(row["report_json"]) if row else None


def update_agent_run_report(
    run_id: int,
    fields: Dict[str, Any],
    db_path: Optional[Path] = None,
) -> None:
    conn = get_connection(db_path)
    row = conn.execute(
        "SELECT report_json FROM agent_runs WHERE id = ?",
        (run_id,),
    ).fetchone()
    if row is None:
        conn.close()
        raise ValueError(f"Agent run {run_id} was not found.")
    report = json.loads(row["report_json"])
    report.update(fields)
    with conn:
        conn.execute(
            "UPDATE agent_runs SET report_json = ? WHERE id = ?",
            (json.dumps(report, ensure_ascii=True), run_id),
        )
    conn.close()


def get_latest_agent_run_for_incident(
    incident_id: str,
    db_path: Optional[Path] = None,
) -> Optional[Dict[str, Any]]:
    conn = get_connection(db_path)
    row = conn.execute(
        """
        SELECT report_json
        FROM agent_runs
        WHERE incident_id = ?
        ORDER BY id DESC
        LIMIT 1
        """,
        (incident_id,),
    ).fetchone()
    conn.close()
    if not row:
        return None
    report = json.loads(row["report_json"])
    return {
        "guardrail_verdict": report["guardrail_verdict"],
        "guardrail_reasons": report.get("guardrail_reasons", []),
        "claims": report.get("claims", []),
    }


def get_approvals_by_incident(
    incident_id: str,
    db_path: Optional[Path] = None,
) -> List[Dict[str, Any]]:
    conn = get_connection(db_path)
    rows = conn.execute(
        "SELECT * FROM approvals WHERE incident_id = ? ORDER BY id DESC",
        (incident_id,),
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_approval_by_agent_run(
    agent_run_id: int,
    db_path: Optional[Path] = None,
) -> Optional[Dict[str, Any]]:
    conn = get_connection(db_path)
    row = conn.execute(
        "SELECT * FROM approvals WHERE agent_run_id = ?",
        (agent_run_id,),
    ).fetchone()
    conn.close()
    return dict(row) if row else None
