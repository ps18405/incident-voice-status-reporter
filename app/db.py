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
    action_type TEXT NOT NULL,
    destination TEXT NOT NULL,
    proposed_message TEXT NOT NULL,
    status TEXT NOT NULL,
    approved_at TEXT,
    idempotency_key TEXT NOT NULL,
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
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='posts'")
        if not cursor.fetchone():
            with conn:
                conn.executescript(SCHEMA_SQL)


def get_connection(db_path: Optional[Path] = None) -> sqlite3.Connection:
    target_path = Path(db_path or DB_PATH or get_default_db_path())
    try:
        target_path.parent.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
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
                        source_updated_at, retrieved_at, age_seconds, is_cached, is_stale, raw_payload
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    source_updated_at, retrieved_at, age_seconds, is_cached, is_stale, raw_payload
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
    db_path: Optional[Path] = None,
) -> int:
    conn = get_connection(db_path)
    now = datetime.now(timezone.utc).isoformat() if status in ("APPROVED", "REJECTED") else None
    with conn:
        cursor = conn.execute(
            """
            INSERT INTO approvals (
                incident_id, action_type, destination, proposed_message, status, approved_at, idempotency_key
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (incident_id, action_type, destination, proposed_message, status, now, idempotency_key),
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
    post_id = None
    with conn:
        # Check if idempotency_key already exists
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM posts WHERE idempotency_key = ?", (idempotency_key,))
        existing = cursor.fetchone()
        if existing:
            # Duplicate post prevented
            conn.close()
            return None

        cursor = conn.execute(
            """
            INSERT INTO posts (
                incident_id, destination, message, posted_at, idempotency_key, is_duplicate
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (incident_id, destination, message, now, idempotency_key, 1 if is_duplicate else 0),
        )
        post_id = cursor.lastrowid
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
