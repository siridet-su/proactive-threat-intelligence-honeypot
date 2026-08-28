from __future__ import annotations

import io
import json
from email.message import Message
from http import HTTPStatus
from types import SimpleNamespace

import pytest

import production.api.dashboard_api as dashboard_api
from production.api.security import api_row_view, public_payload


class FakeDashboardStorage:
    def __init__(self, *, ready: bool = True) -> None:
        self.ready = ready
        self.feedback: list[dict] = []
        self.health_checks = 0

    def health_check(self) -> dict:
        self.health_checks += 1
        return {
            "ok": self.ready,
            "backend": "sqlite",
            "database": "must-not-leak",
        }

    def list_rows(self, table: str, limit: int = 100) -> list[dict]:
        if table == "events":
            return [
                {
                    "event_id": "event-safe",
                    "session_id": "session-safe",
                    "sensor_id": "sensor-safe",
                    "src_ip": "203.0.113.10",
                    "eventid": "cowrie.login.success",
                    "timestamp": "2026-07-17T00:00:00Z",
                    "payload_json": json.dumps(
                        {
                            "username": "root",
                            "password": "attacker-secret",
                            "authorization": "Bearer hidden-token",
                        }
                    ),
                }
            ][:limit]
        return []

    def record_analyst_feedback(self, payload: dict) -> str:
        self.feedback.append(dict(payload))
        return "feedback-safe"


def _config(
    *,
    host: str = "127.0.0.1",
    read_token: str = "",
    write_token: str = "",
) -> SimpleNamespace:
    return SimpleNamespace(
        dashboard_host=host,
        dashboard_port=0,
        dashboard_read_token=read_token,
        dashboard_write_token=write_token,
        database_url="sqlite:///:memory:",
    )


def _handler(
    config: SimpleNamespace,
    path: str,
    *,
    method: str = "GET",
    authorization: str = "",
    body: bytes = b"",
):
    handler = object.__new__(dashboard_api.DashboardHandler)
    handler.config = config
    handler.path = path
    handler.command = method
    handler.client_address = ("127.0.0.1", 54321)
    handler.headers = {
        "Content-Length": str(len(body)),
        "X-Request-ID": "unit-request",
    }
    if body:
        handler.headers["Content-Type"] = "application/json"
    if authorization:
        handler.headers["Authorization"] = authorization
    handler.rfile = io.BytesIO(body)
    responses = []
    handler._send_json = lambda status, payload: responses.append((status, payload))
    return handler, responses


def test_dashboard_liveness_and_minimal_readiness_are_public(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    storage = FakeDashboardStorage()
    monkeypatch.setattr(dashboard_api, "open_storage", lambda _url: storage)
    config = _config(read_token="read-secret")

    live, live_responses = _handler(config, "/health")
    dashboard_api.DashboardHandler.do_GET(live)
    ready, ready_responses = _handler(config, "/health/ready")
    dashboard_api.DashboardHandler.do_GET(ready)

    assert live_responses[0][0] == HTTPStatus.OK
    assert ready_responses[0][0] == HTTPStatus.OK
    assert set(ready_responses[0][1]) == {"ok", "service", "timestamp"}
    assert "database" not in ready_responses[0][1]


def test_dashboard_readiness_reuses_initialized_storage_without_schema_open(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    storage = FakeDashboardStorage()
    monkeypatch.setattr(
        dashboard_api,
        "open_storage",
        lambda _url: pytest.fail("readiness must not reopen or initialize storage"),
    )
    handler, responses = _handler(_config(), "/health/ready")
    handler.server = SimpleNamespace(storage=storage)

    dashboard_api.DashboardHandler.do_GET(handler)

    assert responses[0][0] == HTTPStatus.OK
    assert storage.health_checks == 1


def test_dashboard_main_does_not_repeat_open_storage_initialization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = dashboard_api.ProductionConfig(
        database_url="sqlite:///:memory:",
        dashboard_host="127.0.0.1",
        dashboard_port=0,
    )
    storage = SimpleNamespace(
        initialize=lambda: pytest.fail(
            "open_storage already initializes the storage adapter"
        )
    )
    server = object()
    monkeypatch.setattr(
        dashboard_api.ProductionConfig,
        "from_env",
        classmethod(lambda _cls, _path=None: config),
    )
    monkeypatch.setattr(dashboard_api, "open_storage", lambda _url: storage)
    monkeypatch.setattr(
        dashboard_api,
        "build_server",
        lambda _config, *, storage: server,
    )
    served = []
    monkeypatch.setattr(
        dashboard_api,
        "serve_http_until_stopped",
        lambda selected: served.append(selected),
    )

    assert dashboard_api.main([]) == 0
    assert served == [server]


def test_dashboard_sensitive_reads_require_configured_bearer_and_return_views(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    storage = FakeDashboardStorage()
    monkeypatch.setattr(dashboard_api, "open_storage", lambda _url: storage)
    config = _config(read_token="read-secret")

    denied, denied_responses = _handler(config, "/events")
    dashboard_api.DashboardHandler.do_GET(denied)
    allowed, allowed_responses = _handler(
        config,
        "/events",
        authorization="Bearer read-secret",
    )
    dashboard_api.DashboardHandler.do_GET(allowed)

    assert denied_responses[0][0] == HTTPStatus.UNAUTHORIZED
    assert allowed_responses[0][0] == HTTPStatus.OK
    serialized = json.dumps(allowed_responses[0][1], sort_keys=True)
    assert "payload_json" not in serialized
    assert "attacker-secret" not in serialized
    assert "hidden-token" not in serialized
    assert allowed_responses[0][1]["items"][0]["event_id"] == "event-safe"


def test_dashboard_loopback_without_read_token_remains_local_only_compatible(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        dashboard_api,
        "open_storage",
        lambda _url: FakeDashboardStorage(),
    )
    handler, responses = _handler(_config(), "/events")

    dashboard_api.DashboardHandler.do_GET(handler)

    assert responses[0][0] == HTTPStatus.OK


def test_dashboard_feedback_never_allows_anonymous_writes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    storage = FakeDashboardStorage()
    monkeypatch.setattr(dashboard_api, "open_storage", lambda _url: storage)
    body = b'{"session_id":"session-safe","label":"useful"}'

    unavailable, unavailable_responses = _handler(
        _config(),
        "/analyst-feedback",
        method="POST",
        body=body,
    )
    dashboard_api.DashboardHandler.do_POST(unavailable)

    read_only, read_only_responses = _handler(
        _config(read_token="read-secret", write_token="write-secret"),
        "/analyst-feedback",
        method="POST",
        authorization="Bearer read-secret",
        body=body,
    )
    dashboard_api.DashboardHandler.do_POST(read_only)

    allowed, allowed_responses = _handler(
        _config(read_token="read-secret", write_token="write-secret"),
        "/analyst-feedback",
        method="POST",
        authorization="Bearer write-secret",
        body=body,
    )
    dashboard_api.DashboardHandler.do_POST(allowed)

    fallback, fallback_responses = _handler(
        _config(read_token="read-secret"),
        "/analyst-feedback",
        method="POST",
        authorization="Bearer read-secret",
        body=body,
    )
    dashboard_api.DashboardHandler.do_POST(fallback)

    assert unavailable_responses[0][0] == HTTPStatus.SERVICE_UNAVAILABLE
    assert read_only_responses[0][0] == HTTPStatus.FORBIDDEN
    assert allowed_responses[0][0] == HTTPStatus.CREATED
    assert fallback_responses[0][0] == HTTPStatus.CREATED
    assert len(storage.feedback) == 2


def test_dashboard_rejects_ambiguous_authorization_headers() -> None:
    handler, responses = _handler(
        _config(read_token="read-secret"),
        "/events",
    )
    headers = Message()
    headers.add_header("Authorization", "Bearer read-secret")
    headers.add_header("Authorization", "Bearer conflicting-secret")
    headers.add_header("X-Request-ID", "unit-request")
    handler.headers = headers

    dashboard_api.DashboardHandler.do_GET(handler)

    assert responses[0][0] == HTTPStatus.UNAUTHORIZED


def test_dashboard_feedback_allowlists_and_redacts_submitted_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    storage = FakeDashboardStorage()
    monkeypatch.setattr(dashboard_api, "open_storage", lambda _url: storage)
    secret = "submitted-feedback-secret"
    body = json.dumps(
        {
            "session_id": "session-safe",
            "label": "useful",
            "password": secret,
            "authorization": f"Bearer {secret}",
            "notes": f"password={secret}",
            "unrecognized": secret,
        }
    ).encode()
    handler, responses = _handler(
        _config(read_token="read-secret"),
        "/analyst-feedback",
        method="POST",
        authorization="Bearer read-secret",
        body=body,
    )

    dashboard_api.DashboardHandler.do_POST(handler)

    assert responses[0][0] == HTTPStatus.CREATED
    assert len(storage.feedback) == 1
    stored = storage.feedback[0]
    assert stored["source"] == "dashboard_api"
    assert "password" not in stored
    assert "authorization" not in stored
    assert "unrecognized" not in stored
    assert secret not in json.dumps(stored, sort_keys=True)


def test_dashboard_feedback_rejects_oversized_and_invalid_framing() -> None:
    config = _config(read_token="read-secret")

    oversized, oversized_responses = _handler(
        config,
        "/analyst-feedback",
        method="POST",
        authorization="Bearer read-secret",
        body=b"{}",
    )
    oversized.headers["Content-Length"] = str(
        dashboard_api.MAX_FEEDBACK_BODY_BYTES + 1
    )
    dashboard_api.DashboardHandler.do_POST(oversized)

    negative, negative_responses = _handler(
        config,
        "/analyst-feedback",
        method="POST",
        authorization="Bearer read-secret",
        body=b"{}",
    )
    negative.headers["Content-Length"] = "-1"
    dashboard_api.DashboardHandler.do_POST(negative)

    wrong_type, wrong_type_responses = _handler(
        config,
        "/analyst-feedback",
        method="POST",
        authorization="Bearer read-secret",
        body=b"{}",
    )
    wrong_type.headers["Content-Type"] = "text/plain"
    dashboard_api.DashboardHandler.do_POST(wrong_type)

    assert oversized_responses[0][0] == HTTPStatus.REQUEST_ENTITY_TOO_LARGE
    assert oversized_responses[0][1]["error_code"] == "body_too_large"
    assert negative_responses[0][0] == HTTPStatus.BAD_REQUEST
    assert negative_responses[0][1]["error_code"] == "invalid_content_length"
    assert wrong_type_responses[0][0] == HTTPStatus.UNSUPPORTED_MEDIA_TYPE


def test_dashboard_rejects_non_loopback_bind_without_read_auth(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(ValueError, match="without authentication"):
        dashboard_api.build_server(_config(host="0.0.0.0"))

    sentinel = object()
    monkeypatch.setattr(
        dashboard_api,
        "BoundedThreadingHTTPServer",
        lambda *_args, **_kwargs: sentinel,
    )
    assert (
        dashboard_api.build_server(
            _config(host="0.0.0.0", read_token="read-secret")
        )
        is sentinel
    )

    with pytest.raises(ValueError, match="valid Bearer token"):
        dashboard_api.build_server(
            _config(read_token="unusable token")
        )


def test_dashboard_unexpected_storage_error_is_generic_and_redacted(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fail_storage(_url: str):
        raise RuntimeError(
            "mongodb://user:password@example.invalid/db?token=secret-token"
        )

    monkeypatch.setattr(dashboard_api, "open_storage", fail_storage)
    handler, responses = _handler(
        _config(read_token="read-secret"),
        "/events",
        authorization="Bearer read-secret",
    )

    dashboard_api.DashboardHandler.do_GET(handler)

    assert responses == [
        (
            HTTPStatus.SERVICE_UNAVAILABLE,
            {
                "error": "service temporarily unavailable",
                "request_id": "unit-request",
            },
        )
    ]
    output = capsys.readouterr().out
    assert "password" not in output
    assert "secret-token" not in output


def test_api_view_models_and_central_redaction_remove_storage_and_url_secrets() -> None:
    row = {
        "event_id": "event-redact",
        "session_id": "session-redact",
        "payload_json": '{"password":"plaintext"}',
    }
    assert api_row_view("events", row) == {
        "event_id": "event-redact",
        "session_id": "session-redact",
    }

    redacted = public_payload(
        {
            "password_hash": "sha256:credential-digest",
            "target_url": (
                "https://user:password@example.invalid/path"
                "?token=secret-token&safe=yes"
            ),
        }
    )
    serialized = json.dumps(redacted, sort_keys=True)
    assert "credential-digest" not in serialized
    assert "secret-token" not in serialized
    assert "user:password" not in serialized
    assert "safe=yes" in serialized


def test_dashboard_request_log_sanitizes_sensitive_query_values(
    capsys: pytest.CaptureFixture[str],
) -> None:
    handler, _ = _handler(
        _config(),
        "/sessions?session_id=secret-session&token=secret-token",
    )

    dashboard_api.DashboardHandler.log_message(
        handler,
        '"%s" %s %s',
        "request",
        200,
        "-",
    )

    output = capsys.readouterr().out
    assert "secret-session" not in output
    assert "secret-token" not in output
    assert "[REDACTED]" in output
