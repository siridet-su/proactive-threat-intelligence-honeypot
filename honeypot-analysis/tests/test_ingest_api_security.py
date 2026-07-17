from __future__ import annotations

import http.client
import json
import socket
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, Mapping, Optional, Tuple

import pytest

from production.api.ingest_api import build_server
from production.utils import http_security
from production.utils.config import ProductionConfig
from production.utils.http_security import (
    authenticate_token,
    constant_time_token_match,
    is_loopback_host,
    parse_bearer_token,
)


class FakeStorage:
    def __init__(self) -> None:
        self.events: Dict[str, Dict[str, Any]] = {}
        self.ready = True
        self.fail_writes = False

    def health_check(self) -> Dict[str, Any]:
        return {"ok": self.ready, "backend": "fake", "secret": "do-not-expose"}

    def store_event(self, sensor_id: str, event: Dict[str, Any]) -> Tuple[str, bool]:
        if self.fail_writes:
            raise RuntimeError("database-password=top-secret")
        event_key = json.dumps(
            [sensor_id, event],
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        inserted = event_key not in self.events
        self.events[event_key] = dict(event)
        return event_key, inserted


def _config(**overrides: Any) -> ProductionConfig:
    values: Dict[str, Any] = {
        "sensor_id": "default-sensor",
        "api_token": "global-token",
        "ingest_host": "127.0.0.1",
        "ingest_port": 0,
        "ingest_max_body_bytes": 64 * 1024,
        "ingest_max_batch_events": 10,
        "ingest_max_event_bytes": 8 * 1024,
        "ingest_request_timeout_seconds": 1.0,
    }
    values.update(overrides)
    return ProductionConfig(**values)


@contextmanager
def _running_server(
    config: ProductionConfig,
    storage: Optional[FakeStorage] = None,
) -> Iterator[Tuple[Any, FakeStorage]]:
    selected_storage = storage or FakeStorage()
    server = build_server(config, storage=selected_storage)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, selected_storage
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _request(
    server: Any,
    method: str,
    path: str,
    *,
    payload: Any = None,
    raw_body: Optional[bytes] = None,
    headers: Optional[Mapping[str, str]] = None,
) -> Tuple[int, Dict[str, str], Dict[str, Any]]:
    body = raw_body
    request_headers = dict(headers or {})
    if payload is not None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    if body is not None:
        request_headers.setdefault("Content-Type", "application/json")
    connection = http.client.HTTPConnection(
        "127.0.0.1",
        server.server_address[1],
        timeout=3,
    )
    try:
        connection.request(method, path, body=body, headers=request_headers)
        response = connection.getresponse()
        response_body = response.read()
        return (
            response.status,
            {name.lower(): value for name, value in response.getheaders()},
            json.loads(response_body),
        )
    finally:
        connection.close()


def _auth_headers(
    token: str = "global-token",
    sensor_id: Optional[str] = None,
    request_id: Optional[str] = None,
) -> Dict[str, str]:
    headers = {"Authorization": f"Bearer {token}"}
    if sensor_id:
        headers["X-Sensor-ID"] = sensor_id
    if request_id:
        headers["X-Request-ID"] = request_id
    return headers


def test_shared_http_security_helpers_are_strict_and_constant_time(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert is_loopback_host("127.0.0.1") is True
    assert is_loopback_host("::1") is True
    assert is_loopback_host("localhost") is True
    assert is_loopback_host("0.0.0.0") is False
    assert parse_bearer_token("Bearer token-value") == "token-value"
    assert parse_bearer_token("bearer token-value") == "token-value"
    assert parse_bearer_token(" Bearer token-value") is None
    assert parse_bearer_token("Bearer  token-value") is None
    assert parse_bearer_token("Basic token-value") is None
    assert parse_bearer_token("Bearer token:value") is None
    assert constant_time_token_match("same", "same") is True
    assert constant_time_token_match("different", "same") is False

    comparisons = []

    def recording_compare(left: bytes, right: bytes) -> bool:
        comparisons.append((left, right))
        return left == right

    monkeypatch.setattr(http_security.hmac, "compare_digest", recording_compare)
    authentication = authenticate_token(
        "sensor-a-token",
        {
            "sensor-a": "sensor-a-token",
            "sensor-b": "sensor-b-token",
        },
        "global-token",
    )
    assert authentication.authorized is True
    assert authentication.identity == "sensor-a"
    assert len(comparisons) == 3


def test_config_parses_http_security_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "INGEST_SENSOR_TOKENS_JSON",
        '{"sensor-a":"token-a","sensor-b":"token-b"}',
    )
    monkeypatch.setenv("INGEST_MAX_BODY_BYTES", "1234")
    monkeypatch.setenv("INGEST_MAX_BATCH_EVENTS", "12")
    monkeypatch.setenv("INGEST_MAX_EVENT_BYTES", "345")
    monkeypatch.setenv("INGEST_REQUEST_TIMEOUT_SECONDS", "2.5")
    monkeypatch.setenv("DASHBOARD_READ_TOKEN", "read-token")
    monkeypatch.setenv("DASHBOARD_WRITE_TOKEN", "write-token")
    monkeypatch.setenv("MONITOR_ALLOW_FEEDBACK", "true")

    config = ProductionConfig.from_env()

    assert config.ingest_sensor_tokens == {
        "sensor-a": "token-a",
        "sensor-b": "token-b",
    }
    assert config.ingest_max_body_bytes == 1234
    assert config.ingest_max_batch_events == 12
    assert config.ingest_max_event_bytes == 345
    assert config.ingest_request_timeout_seconds == 2.5
    assert config.dashboard_read_token == "read-token"
    assert config.dashboard_write_token == "write-token"
    assert config.monitor_allow_feedback is True
    assert ProductionConfig().dashboard_host == "127.0.0.1"


@pytest.mark.parametrize(
    "mapping",
    [
        {"": "token"},
        {"sensor-a": ""},
        {"sensor-a": " padded "},
    ],
)
def test_config_rejects_unusable_sensor_token_mappings(
    monkeypatch: pytest.MonkeyPatch,
    mapping: Dict[str, str],
) -> None:
    monkeypatch.setenv("INGEST_SENSOR_TOKENS_JSON", json.dumps(mapping))
    with pytest.raises(ValueError, match="INGEST_SENSOR_TOKENS_JSON"):
        ProductionConfig.from_env()


def test_startup_rejects_unauthenticated_remote_bind_and_invalid_limits() -> None:
    with pytest.raises(ValueError, match="non-loopback"):
        build_server(
            _config(
                api_token="",
                ingest_sensor_tokens={},
                ingest_host="0.0.0.0",
            ),
            storage=FakeStorage(),
        )

    with pytest.raises(ValueError, match="ingest_max_body_bytes"):
        build_server(
            _config(ingest_max_body_bytes=0),
            storage=FakeStorage(),
        )

    with pytest.raises(ValueError, match="reuse a token"):
        build_server(
            _config(
                api_token="",
                ingest_sensor_tokens={
                    "sensor-a": "same-token",
                    "sensor-b": "same-token",
                },
            ),
            storage=FakeStorage(),
        )


def test_sensor_specific_auth_enforces_identity_and_global_token_compatibility() -> None:
    config = _config(ingest_sensor_tokens={"sensor-a": "sensor-a-token"})
    with _running_server(config) as (server, storage):
        status, _, accepted = _request(
            server,
            "POST",
            "/events",
            payload={
                "sensor_id": "sensor-a",
                "events": [{"eventid": "cowrie.session.connect", "session": "one"}],
            },
            headers=_auth_headers("sensor-a-token", "sensor-a"),
        )
        assert status == 202
        assert accepted["status"] == "accepted"
        assert accepted["sensor_id"] == "sensor-a"

        status, _, mismatch = _request(
            server,
            "POST",
            "/events",
            payload={
                "sensor_id": "sensor-b",
                "events": [{"eventid": "cowrie.session.connect", "session": "two"}],
            },
            headers=_auth_headers("sensor-a-token", "sensor-a"),
        )
        assert status == 400
        assert mismatch["error"]["code"] == "sensor_identity_mismatch"

        status, _, compatibility = _request(
            server,
            "POST",
            "/events",
            payload={
                "sensor_id": "default-sensor",
                "events": [{"eventid": "cowrie.session.connect", "session": "three"}],
            },
            headers=_auth_headers("global-token", "default-sensor"),
        )
        assert status == 202
        assert compatibility["sensor_id"] == "default-sensor"
        assert len(storage.events) == 2

        status, _, fallback_mismatch = _request(
            server,
            "POST",
            "/events",
            payload={
                "sensor_id": "sensor-b",
                "events": [{"eventid": "cowrie.session.connect", "session": "four"}],
            },
            headers=_auth_headers("global-token", "sensor-b"),
        )
        assert status == 400
        assert fallback_mismatch["error"]["code"] == "sensor_identity_mismatch"

        status, headers, unauthorized = _request(
            server,
            "POST",
            "/events",
            payload=[{"eventid": "cowrie.session.connect"}],
            headers=_auth_headers("wrong-token"),
        )
        assert status == 401
        assert headers["www-authenticate"] == "Bearer"
        assert unauthorized["error"]["code"] == "unauthorized"


def test_acknowledgements_distinguish_accepted_duplicate_partial_and_rejected() -> None:
    secret = "raw-rejected-password-must-not-echo"
    with _running_server(_config()) as (server, _):
        valid = {
            "eventid": "cowrie.command.input",
            "session": "status-test",
            "input": "whoami",
        }
        status, _, accepted = _request(
            server,
            "POST",
            "/events",
            payload=[valid],
            headers=_auth_headers(),
        )
        assert status == 202
        assert accepted["status"] == "accepted"
        assert accepted["accepted"] == 1

        status, _, duplicate = _request(
            server,
            "POST",
            "/events",
            payload=[valid],
            headers=_auth_headers(),
        )
        assert status == 200
        assert duplicate["status"] == "duplicate"
        assert duplicate["duplicates"] == 1

        status, _, partial = _request(
            server,
            "POST",
            "/events",
            payload=[
                {
                    "eventid": "cowrie.session.closed",
                    "session": "status-test",
                },
                {
                    "eventid": "",
                    "password": secret,
                },
            ],
            headers=_auth_headers(),
        )
        assert status == 202
        assert partial["status"] == "partial"
        assert partial["accepted"] == 1
        assert len(partial["rejected"]) == 1
        assert partial["rejected"][0]["index"] == 1
        assert secret not in json.dumps(partial)
        assert "event" not in partial["rejected"][0]

        status, _, rejected = _request(
            server,
            "POST",
            "/events",
            payload=[{"eventid": "", "password": secret}],
            headers=_auth_headers(),
        )
        assert status == 400
        assert rejected["status"] == "rejected"
        assert rejected["ok"] is False
        assert secret not in json.dumps(rejected)


def test_content_body_batch_and_event_limits_return_sanitized_errors() -> None:
    with _running_server(_config(ingest_max_batch_events=1)) as (server, _):
        status, _, media_error = _request(
            server,
            "POST",
            "/events",
            raw_body=b"{}",
            headers={
                **_auth_headers(),
                "Content-Type": "text/plain",
            },
        )
        assert status == 415
        assert media_error["error"]["code"] == "unsupported_media_type"

        status, _, batch_error = _request(
            server,
            "POST",
            "/events",
            payload=[
                {"eventid": "cowrie.session.connect"},
                {"eventid": "cowrie.session.closed"},
            ],
            headers=_auth_headers(),
        )
        assert status == 413
        assert batch_error["error"]["code"] == "batch_too_large"

    with _running_server(_config(ingest_max_body_bytes=20)) as (server, _):
        status, _, body_error = _request(
            server,
            "POST",
            "/events",
            payload=[{"eventid": "cowrie.session.connect"}],
            headers=_auth_headers(),
        )
        assert status == 413
        assert body_error["error"]["code"] == "body_too_large"

    secret = "event-size-secret"
    with _running_server(_config(ingest_max_event_bytes=40)) as (server, _):
        status, _, event_error = _request(
            server,
            "POST",
            "/events",
            payload=[
                {
                    "eventid": "cowrie.login.failed",
                    "password": secret * 10,
                }
            ],
            headers=_auth_headers(),
        )
        assert status == 400
        assert event_error["rejected"][0]["error_code"] == "event_too_large"
        assert secret not in json.dumps(event_error)


def test_health_routes_readiness_and_correlation_ids_are_safe() -> None:
    storage = FakeStorage()
    with _running_server(_config(), storage) as (server, _):
        status, headers, live = _request(
            server,
            "GET",
            "/health/live",
            headers={"X-Request-ID": "client-request-123"},
        )
        assert status == 200
        assert live["status"] == "live"
        assert live["request_id"] == "client-request-123"
        assert headers["x-request-id"] == "client-request-123"

        status, _, compatible = _request(server, "GET", "/health")
        assert status == 200
        assert compatible["status"] == "live"

        status, _, ready = _request(server, "GET", "/health/ready")
        assert status == 200
        assert ready["status"] == "ready"
        assert set(ready) == {
            "ok",
            "request_id",
            "service",
            "status",
            "timestamp",
        }
        assert "secret" not in ready

        storage.ready = False
        status, _, not_ready = _request(server, "GET", "/health/ready")
        assert status == 503
        assert not_ready["status"] == "not_ready"

        status, headers, generated = _request(
            server,
            "GET",
            "/health/live",
            headers={"X-Request-ID": "unsafe request id"},
        )
        assert status == 200
        assert generated["request_id"] != "unsafe request id"
        assert headers["x-request-id"] == generated["request_id"]


def test_storage_failures_return_generic_500_without_exception_details() -> None:
    storage = FakeStorage()
    storage.fail_writes = True
    with _running_server(_config(), storage) as (server, _):
        status, _, error = _request(
            server,
            "POST",
            "/events",
            payload=[{"eventid": "cowrie.session.connect"}],
            headers=_auth_headers(),
        )

    serialized = json.dumps(error)
    assert status == 500
    assert error["error"]["code"] == "storage_unavailable"
    assert "database-password" not in serialized
    assert "top-secret" not in serialized


def test_partial_request_body_times_out() -> None:
    config = _config(ingest_request_timeout_seconds=0.1)
    with _running_server(config) as (server, _):
        client = socket.create_connection(
            ("127.0.0.1", server.server_address[1]),
            timeout=2,
        )
        client.settimeout(2)
        try:
            client.sendall(
                b"POST /events HTTP/1.1\r\n"
                b"Host: 127.0.0.1\r\n"
                b"Authorization: Bearer global-token\r\n"
                b"Content-Type: application/json\r\n"
                b"Content-Length: 100\r\n"
                b"Connection: close\r\n"
                b"\r\n"
                b"{"
            )
            time.sleep(0.2)
            response = b""
            while True:
                chunk = client.recv(4096)
                if not chunk:
                    break
                response += chunk
        finally:
            client.close()

    assert b" 408 " in response
    assert b'"code":"request_timeout"' in response
