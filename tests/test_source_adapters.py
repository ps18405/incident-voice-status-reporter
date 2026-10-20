from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlsplit

import pytest

from app import collector
from app.collector import IncidentInput, collect_signals
from app.db import get_connection, get_signals_by_incident
from app.rules import evaluate_decision_rules
from app.source_adapters import fetch_grafana_metrics


class FakeResponse:
    def __init__(self, body: bytes, status: int = 200):
        self.body = body
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def getcode(self):
        return self.status

    def read(self, size=-1):
        return self.body if size < 0 else self.body[:size]


def configure_source(monkeypatch):
    monkeypatch.setenv("GRAFANA_PROMETHEUS_QUERY_URL", "https://grafana.example/api/datasources/proxy/uid/prometheus/api/v1/query")
    monkeypatch.setenv("GRAFANA_SOURCE_ID", "incident-prometheus")
    monkeypatch.setenv("GRAFANA_API_KEY", "test-api-key")
    monkeypatch.setenv("GRAFANA_TIMEOUT_SECONDS", "3")
    monkeypatch.setenv("OFFLINE_MODE", "false")
    monkeypatch.setenv("GRAFANA_METRIC_QUERIES", json.dumps({"error_rate": "sum(rate(http_errors[5m]))"}))


def test_grafana_adapter_parses_prometheus_vector_and_records_provenance(monkeypatch):
    configure_source(monkeypatch)
    captured = {}
    body = json.dumps({
        "status": "success",
        "data": {
            "resultType": "vector",
            "result": [{
                "metric": {"__name__": "http_errors", "job": "checkout"},
                "value": [1792512000, "4.2"],
            }],
        },
    }).encode()

    class FakeOpener:
        def open(self, request, timeout):
            captured["url"] = request.full_url
            captured["authorization"] = request.get_header("Authorization")
            captured["timeout"] = timeout
            return FakeResponse(body)

    monkeypatch.setattr("app.source_adapters.build_opener", lambda *_: FakeOpener())
    fixed_now = datetime.fromtimestamp(1792512005, tz=timezone.utc)
    result = fetch_grafana_metrics(fixed_now)

    assert len(result) == 1
    signal = result[0]
    assert signal["signal_id"] == "SIG-METRIC-ERR"
    assert signal["source_id"] == "incident-prometheus:http_errors"
    assert signal["evidence_origin"] == "live_grafana"
    assert signal["retrieval_status"] == "success"
    assert signal["source_updated_at"] == datetime.fromtimestamp(1792512000, tz=timezone.utc).isoformat()
    assert signal["retrieved_at"] == fixed_now.isoformat()
    assert signal["age_seconds"] == 5
    assert parse_qs(urlsplit(captured["url"]).query)["query"] == ["sum(rate(http_errors[5m]))"]
    assert captured["authorization"] == "Bearer test-api-key"
    assert "test-api-key" not in captured["url"]
    assert captured["timeout"] == 3
    assert "test-api-key" not in json.dumps(result)


@pytest.mark.parametrize(
    ("body", "expected_status"),
    [
        (b"{bad-json", "malformed_response"),
        (b'{"status":"error","error":"bad query"}', "malformed_response"),
        (b'{"status":"success","data":{"resultType":"vector","result":[]}}', "missing_value"),
        (b'{"status":"success","data":{"resultType":"vector","result":[{"value":[null,"1"]}]}}', "missing_timestamp"),
        (b'{"status":"success","data":{"resultType":"vector","result":[{"value":["bad","1"]}]}}', "malformed_response"),
        (b'{"status":"success","data":{"resultType":"vector","result":[{"value":[1792512000,"NaN"]}]}}', "malformed_response"),
    ],
)
def test_grafana_adapter_rejects_malformed_or_missing_samples(monkeypatch, body, expected_status):
    configure_source(monkeypatch)

    class FakeOpener:
        def open(self, *_args, **_kwargs):
            return FakeResponse(body)

    monkeypatch.setattr("app.source_adapters.build_opener", lambda *_: FakeOpener())
    signal = fetch_grafana_metrics()[0]

    assert signal["retrieval_status"] == expected_status
    assert signal["source_updated_at"] == "Unavailable"
    assert signal["is_stale"]
    assert signal["evidence_origin"] == "live_grafana"


@pytest.mark.parametrize(
    ("error", "expected_status"),
    [
        (HTTPError("https://grafana.example/query", 503, "Unavailable", {}, None), "http_error"),
        (TimeoutError("timed out"), "timeout"),
        (URLError(ConnectionError("offline")), "unavailable"),
    ],
)
def test_grafana_adapter_records_http_timeout_and_unavailable_status(monkeypatch, error, expected_status):
    configure_source(monkeypatch)

    class FakeOpener:
        def open(self, *_args, **_kwargs):
            raise error

    monkeypatch.setattr("app.source_adapters.build_opener", lambda *_: FakeOpener())
    signal = fetch_grafana_metrics()[0]

    assert signal["retrieval_status"] == expected_status
    assert signal["value"].startswith("Unavailable")
    assert signal["source_updated_at"] == "Unavailable"
    assert signal["is_stale"]


def test_grafana_mode_does_not_mix_fixture_signals_and_persists_provenance(monkeypatch):
    monkeypatch.setenv("EVIDENCE_SOURCE", "grafana")
    observed = datetime(2026, 10, 20, 10, 0, tzinfo=timezone.utc).isoformat()
    monkeypatch.setattr(
        "app.collector.fetch_grafana_metrics",
        lambda _retrieved: [{
            "signal_id": "SIG-METRIC-ERR",
            "source_type": "metric",
            "name": "Configured live metric",
            "url": "https://grafana.example/api/query",
            "source_id": "authorized-source:error_rate",
            "value": "0.1",
            "unit": "%",
            "source_updated_at": observed,
            "is_cached": False,
            "evidence_origin": "live_grafana",
            "retrieval_status": "success",
            "raw_payload": {},
        }],
    )
    collected = collect_signals(
        IncidentInput(
            incident_id="INC-LIVE-METRIC-ONLY",
            scope="Explicit live source adapter path",
            dashboards=["ignored-untrusted-dashboard-id"],
            scenario_id="TC1",
        ),
        base_time=datetime(2026, 10, 20, 10, 0, 10, tzinfo=timezone.utc),
    )

    assert collected.source_mode == "grafana"
    assert {signal.signal_id for signal in collected.signals} == {"SIG-METRIC-ERR"}
    signal = collected.signals[0]
    assert signal.evidence_origin == "live_grafana"
    assert signal.source_id == "authorized-source:error_rate"
    assert signal.retrieval_status == "success"
    persisted = get_signals_by_incident(collected.incident_id)[0]
    assert persisted["source_id"] == signal.source_id
    assert persisted["evidence_origin"] == "live_grafana"
    assert persisted["retrieval_status"] == "success"
    assert evaluate_decision_rules(collected, save_to_db=False).status == "UNCERTAIN"


def test_grafana_source_requires_explicit_query_configuration(monkeypatch):
    monkeypatch.delenv("GRAFANA_PROMETHEUS_QUERY_URL", raising=False)
    monkeypatch.setenv("EVIDENCE_SOURCE", "grafana")
    monkeypatch.setenv("OFFLINE_MODE", "false")
    with pytest.raises(ValueError, match="GRAFANA_PROMETHEUS_QUERY_URL"):
        collect_signals(
            IncidentInput(
                incident_id="INC-GRAFANA-NOT-CONFIGURED",
                scope="No endpoint configured",
                dashboards=["placeholder"],
            ),
            save_to_db=False,
        )


def test_grafana_endpoint_rejects_credentials_in_url(monkeypatch):
    configure_source(monkeypatch)
    for query in (
        "sig=synthetic-secret",
        "signature=synthetic-secret",
        "X-Amz-Signature=synthetic-secret",
        "access_token=synthetic-secret",
    ):
        monkeypatch.setenv(
            "GRAFANA_PROMETHEUS_QUERY_URL",
            f"https://grafana.example/api/query?{query}",
        )
        with pytest.raises(ValueError, match="must not contain query parameters"):
            fetch_grafana_metrics()


def test_grafana_missing_key_uses_no_authorization_header(monkeypatch):
    configure_source(monkeypatch)
    monkeypatch.delenv("GRAFANA_API_KEY", raising=False)
    captured = {}

    class FakeOpener:
        def open(self, request, timeout):
            captured["authorization"] = request.get_header("Authorization")
            captured["url"] = request.full_url
            return FakeResponse(b'{"status":"success","data":{"resultType":"vector","result":[{"metric":{},"value":[1792512000,"1"]}]}}')

    monkeypatch.setattr("app.source_adapters.build_opener", lambda *_: FakeOpener())
    fetch_grafana_metrics()

    assert captured["authorization"] is None
    assert "synthetic-secret" not in captured["url"]


def test_grafana_failure_does_not_leak_key_in_logs_or_errors(monkeypatch, caplog):
    configure_source(monkeypatch)
    secret = "synthetic-grafana-secret"
    monkeypatch.setenv("GRAFANA_API_KEY", secret)
    monkeypatch.setattr(
        "app.source_adapters.build_opener",
        lambda *_: type("FakeOpener", (), {
            "open": lambda _self, *_args, **_kwargs: (_ for _ in ()).throw(
                HTTPError("https://grafana.example/query", 403, "Denied", {}, None)
            )
        })(),
    )
    with caplog.at_level("WARNING"):
        signals = fetch_grafana_metrics()

    output = caplog.text + json.dumps(signals)
    assert secret not in output
    assert signals[0]["retrieval_status"] == "http_error"


def test_grafana_rejects_malformed_endpoint_without_network(monkeypatch):
    configure_source(monkeypatch)
    for endpoint in (
        "https://user:pass@grafana.example/query",
        "ftp://grafana.example/query",
        "https://grafana.example/query#fragment",
    ):
        monkeypatch.setenv("GRAFANA_PROMETHEUS_QUERY_URL", endpoint)
        with pytest.raises(ValueError):
            fetch_grafana_metrics()


def test_grafana_redirect_is_not_followed_with_credentials(monkeypatch):
    configure_source(monkeypatch)
    redirected = HTTPError(
        "https://grafana.example/query", 302, "Redirect", {"Location": "https://evil.example/"},
        None,
    )
    calls = []

    class FakeOpener:
        def open(self, request, timeout):
            calls.append(request.full_url)
            raise redirected

    monkeypatch.setattr("app.source_adapters.build_opener", lambda *_: FakeOpener())
    signal = fetch_grafana_metrics()[0]

    assert len(calls) == 1
    assert signal["retrieval_status"] == "http_error"
    assert "test-api-key" not in calls[0]


def test_configured_grafana_http_success_never_claims_recovery_without_health(monkeypatch):
    configure_source(monkeypatch)
    monkeypatch.setenv("EVIDENCE_SOURCE", "grafana")
    response_body = json.dumps({
        "status": "success",
        "data": {
            "resultType": "vector",
            "result": [{"metric": {}, "value": [1792512000, "0.1"]}],
        },
    }).encode()

    class FakeOpener:
        def open(self, *_args, **_kwargs):
            return FakeResponse(response_body)

    monkeypatch.setattr("app.source_adapters.build_opener", lambda *_: FakeOpener())
    collection = collect_signals(
        IncidentInput(
            incident_id="INC-GRAFANA-HTTP-200",
            scope="Successful HTTP query without health evidence",
            dashboards=["http://127.0.0.1:9999/admin"],
        ),
        base_time=datetime.fromtimestamp(1792512005, tz=timezone.utc),
        save_to_db=False,
    )
    decision = evaluate_decision_rules(collection, save_to_db=False)

    assert collection.signals[0].retrieval_status == "success"
    assert collection.signals[0].url == "https://grafana.example/api/datasources/proxy/uid/prometheus/api/v1/query"
    assert collection.signals[0].evidence_origin == "live_grafana"
    assert decision.status == "UNCERTAIN"


def test_grafana_success_with_old_sample_is_stale_in_collected_evidence(monkeypatch):
    configure_source(monkeypatch)
    monkeypatch.setenv("EVIDENCE_SOURCE", "grafana")
    retrieved = datetime.fromtimestamp(1792512000, tz=timezone.utc)
    sample_time = retrieved.timestamp() - 600
    response_body = json.dumps({
        "status": "success",
        "data": {
            "resultType": "vector",
            "result": [{"metric": {"__name__": "http_errors"}, "value": [sample_time, "0.1"]}],
        },
    }).encode()

    class FakeOpener:
        def open(self, *_args, **_kwargs):
            return FakeResponse(response_body)

    monkeypatch.setattr("app.source_adapters.build_opener", lambda *_: FakeOpener())
    collection = collect_signals(
        IncidentInput(
            incident_id="INC-GRAFANA-STALE-SAMPLE",
            scope="Old sample must not establish recovery",
            dashboards=["http://127.0.0.1:9999/admin"],
        ),
        base_time=retrieved,
        save_to_db=False,
    )
    signal = collection.signals[0]

    assert signal.retrieval_status == "success"
    assert signal.age_seconds == 600
    assert signal.is_stale
    assert signal.evidence_origin == "live_grafana"
    assert evaluate_decision_rules(collection, save_to_db=False).status == "UNCERTAIN"


def test_existing_signals_table_gets_provenance_columns(tmp_path: Path):
    db_path = tmp_path / "pre-provenance.sqlite3"
    with sqlite3.connect(db_path) as connection:
        connection.execute("CREATE TABLE incidents (id TEXT PRIMARY KEY)")
        connection.execute("CREATE TABLE posts (id INTEGER PRIMARY KEY)")
        connection.execute(
            "CREATE TABLE signals (id INTEGER PRIMARY KEY, incident_id TEXT NOT NULL)"
        )

    connection = get_connection(db_path)
    columns = {row["name"] for row in connection.execute("PRAGMA table_info(signals)")}
    connection.close()

    assert {"source_id", "evidence_origin", "retrieval_status"}.issubset(columns)


def test_existing_approvals_table_gets_unique_run_binding_migration(tmp_path: Path):
    db_path = tmp_path / "pre-run-approval.sqlite3"
    with sqlite3.connect(db_path) as connection:
        connection.executescript("""
            CREATE TABLE incidents (id TEXT PRIMARY KEY);
            CREATE TABLE posts (id INTEGER PRIMARY KEY);
            CREATE TABLE approvals (
                id INTEGER PRIMARY KEY,
                incident_id TEXT NOT NULL,
                action_type TEXT NOT NULL,
                destination TEXT NOT NULL,
                proposed_message TEXT NOT NULL,
                status TEXT NOT NULL,
                approved_at TEXT,
                idempotency_key TEXT NOT NULL
            );
            CREATE TABLE signals (id INTEGER PRIMARY KEY, incident_id TEXT NOT NULL);
        """)

    connection = get_connection(db_path)
    columns = {row["name"] for row in connection.execute("PRAGMA table_info(approvals)")}
    index_names = {
        row["name"] for row in connection.execute("PRAGMA index_list(approvals)")
    }
    connection.close()

    assert "agent_run_id" in columns
    assert "approvals_agent_run_id_unique" in index_names
