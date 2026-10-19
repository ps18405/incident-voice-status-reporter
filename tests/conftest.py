"""Shared pytest fixtures for Incident Voice Status Reporter.
Guarantees tests use an isolated temporary SQLite database, leaving the real database untouched.
"""
from __future__ import annotations

import tempfile
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

import app.db as db_mod
from app.main import app


@pytest.fixture(autouse=True)
def isolated_temp_db(tmp_path: Path, monkeypatch):
    """Autouse fixture: Isolates every test run with a dedicated temporary SQLite DB."""
    temp_db_path = tmp_path / "test_incident_reporter.db"
    monkeypatch.setattr(db_mod, "DB_PATH", temp_db_path)
    db_mod.init_db(temp_db_path)
    yield temp_db_path


@pytest.fixture
def client():
    """TestClient for FastAPI app using isolated database."""
    return TestClient(app)
