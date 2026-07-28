from __future__ import annotations

import io
import json
from email.message import Message
from http import HTTPStatus
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlencode

import pytest

import production.api.monitor_web as monitor_web
from production.api.security import session_detail_view


class FakeMonitorHealthStorage:
    def __init__(self, ready: bool = True) -> None:
        self.ready = ready

    def health_check(self) -> dict:
        return {
            "ok": self.ready,
            "backend": "mongodb",
            "database": "must-not-leak",
        }


def _config(
    tmp_path: Path,
    *,
    host: str = "127.0.0.1",
    read_token: str = "",
    write_token: str = "",
    allow_feedback: bool = False,
) -> monitor_web.MonitorConfig:
    production_config = SimpleNamespace(
        dashboard_read_token=read_token,
        dashboard_write_token=write_token,
        monitor_allow_feedback=allow_feedback,
    )
    return monitor_web.MonitorConfig(
        db_path="",
        database_url="mongodb://database.internal/honeypot",
        reports_dir=str(tmp_path / "reports"),
        bind_host=host,
        production_config=production_config,
    )


def _handler(
    config: monitor_web.MonitorConfig,
    path: str,
    *,
    method: str = "GET",
    authorization: str = "",
    body: bytes = b"",
):
    handler = object.__new__(monitor_web.MonitorHandler)
    handler.monitor_config = config
    handler.path = path
    handler.command = method
    handler.client_address = ("127.0.0.1", 54321)
    handler.headers = {
        "Content-Length": str(len(body)),
        "X-Request-ID": "unit-monitor-request",
    }
    if body:
        handler.headers["Content-Type"] = (
            "application/x-www-form-urlencoded"
            if path == "/feedback"
            else "application/json"
        )
    if authorization:
        handler.headers["Authorization"] = authorization
    handler.rfile = io.BytesIO(body)
    responses = []
    redirects = []
    handler._send_json = lambda status, payload: responses.append((status, payload))
    handler._send = lambda status, body, content_type="text/plain": responses.append(
        (status, {"body": body, "content_type": content_type})
    )
    handler._redirect = lambda location: redirects.append(location)
    return handler, responses, redirects


def _snapshot() -> dict:
    return {
        "ok": True,
        "timestamp": "2026-07-17T00:00:00Z",
        "summary": {"total_sessions": 1},
        "sessions": [
            {
                "session_id": "session-safe",
                "src_ip": "203.0.113.10",
                "updated_at": "2026-07-17T00:00:00Z",
                "payload": {
                    "session_id": "session-safe",
                    "src_ip": "203.0.113.10",
                    "commands": ["password=attacker-secret whoami"],
                    "tactics": ["discovery"],
                    "raw_events": [{"password": "plaintext"}],
                },
            }
        ],
        "selected": {"session_id": "session-safe"},
        "events": [],
        "error": "",
    }


def test_monitor_liveness_and_minimal_readiness_are_public(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        monitor_web,
        "_open_monitor_storage",
        lambda _config: FakeMonitorHealthStorage(),
    )
    config = _config(tmp_path, read_token="read-secret")

    live, live_responses, _ = _handler(config, "/health/live")
    monitor_web.MonitorHandler.do_GET(live)
    ready, ready_responses, _ = _handler(config, "/health/ready")
    monitor_web.MonitorHandler.do_GET(ready)

    assert live_responses[0][0] == HTTPStatus.OK
    assert ready_responses[0][0] == HTTPStatus.OK
    assert set(ready_responses[0][1]) == {"ok", "service", "timestamp"}


def test_monitor_sensitive_reads_require_bearer_when_configured(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(monitor_web, "load_snapshot", lambda *_args, **_kwargs: _snapshot())
    config = _config(tmp_path, read_token="read-secret")

    denied, denied_responses, _ = _handler(config, "/api/sessions")
    monitor_web.MonitorHandler.do_GET(denied)
    allowed, allowed_responses, _ = _handler(
        config,
        "/api/sessions",
        authorization="Bearer read-secret",
    )
    monitor_web.MonitorHandler.do_GET(allowed)

    assert denied_responses[0][0] == HTTPStatus.UNAUTHORIZED
    assert allowed_responses[0][0] == HTTPStatus.OK
    session = allowed_responses[0][1]["sessions"][0]
    assert "payload" not in session
    assert session["command_count"] == 1


def test_monitor_rejects_ambiguous_authorization_headers(tmp_path: Path) -> None:
    handler, responses, _ = _handler(
        _config(tmp_path, read_token="read-secret"),
        "/api/sessions",
    )
    headers = Message()
    headers.add_header("Authorization", "Bearer read-secret")
    headers.add_header("Authorization", "Bearer conflicting-secret")
    headers.add_header("X-Request-ID", "unit-monitor-request")
    handler.headers = headers

    monitor_web.MonitorHandler.do_GET(handler)

    assert responses[0][0] == HTTPStatus.UNAUTHORIZED


def test_monitor_loopback_without_read_token_remains_local_only_compatible(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(monitor_web, "load_snapshot", lambda *_args, **_kwargs: _snapshot())
    handler, responses, _ = _handler(_config(tmp_path), "/api/sessions")

    monitor_web.MonitorHandler.do_GET(handler)

    assert responses[0][0] == HTTPStatus.OK


def test_monitor_feedback_is_disabled_by_default_and_always_write_scoped(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    writes = []
    monkeypatch.setattr(
        monitor_web,
        "record_analyst_feedback",
        lambda _config, payload: writes.append(dict(payload)) or "feedback-safe",
    )
    body = b'{"session_id":"session-safe","label":"useful"}'

    disabled, disabled_responses, _ = _handler(
        _config(
            tmp_path,
            read_token="read-secret",
            write_token="write-secret",
        ),
        "/analyst-feedback",
        method="POST",
        authorization="Bearer write-secret",
        body=body,
    )
    monitor_web.MonitorHandler.do_POST(disabled)

    unavailable, unavailable_responses, _ = _handler(
        _config(tmp_path, allow_feedback=True),
        "/analyst-feedback",
        method="POST",
        body=body,
    )
    monitor_web.MonitorHandler.do_POST(unavailable)

    read_only, read_only_responses, _ = _handler(
        _config(
            tmp_path,
            read_token="read-secret",
            write_token="write-secret",
            allow_feedback=True,
        ),
        "/analyst-feedback",
        method="POST",
        authorization="Bearer read-secret",
        body=body,
    )
    monitor_web.MonitorHandler.do_POST(read_only)

    allowed, allowed_responses, _ = _handler(
        _config(
            tmp_path,
            read_token="read-secret",
            write_token="write-secret",
            allow_feedback=True,
        ),
        "/analyst-feedback",
        method="POST",
        authorization="Bearer write-secret",
        body=body,
    )
    monitor_web.MonitorHandler.do_POST(allowed)

    assert disabled_responses[0][0] == HTTPStatus.FORBIDDEN
    assert unavailable_responses[0][0] == HTTPStatus.SERVICE_UNAVAILABLE
    assert read_only_responses[0][0] == HTTPStatus.FORBIDDEN
    assert allowed_responses[0][0] == HTTPStatus.CREATED
    assert len(writes) == 1


def test_monitor_legacy_form_feedback_uses_same_write_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    writes = []
    monkeypatch.setattr(
        monitor_web,
        "record_analyst_feedback",
        lambda _config, payload: writes.append(dict(payload)) or "feedback-safe",
    )
    config = _config(
        tmp_path,
        read_token="read-secret",
        allow_feedback=True,
    )
    body = urlencode(
        {"session_id": "session-safe", "label": "useful"}
    ).encode()
    handler, responses, redirects = _handler(
        config,
        "/feedback",
        method="POST",
        authorization="Bearer read-secret",
        body=body,
    )

    monitor_web.MonitorHandler.do_POST(handler)

    assert responses == []
    assert redirects == ["/?session_id=session-safe"]
    assert len(writes) == 1


def test_monitor_feedback_rejects_oversized_and_negative_lengths(
    tmp_path: Path,
) -> None:
    config = _config(
        tmp_path,
        read_token="read-secret",
        allow_feedback=True,
    )
    oversized, oversized_responses, _ = _handler(
        config,
        "/analyst-feedback",
        method="POST",
        authorization="Bearer read-secret",
        body=b"{}",
    )
    oversized.headers["Content-Length"] = str(
        monitor_web.MAX_FEEDBACK_JSON_BYTES + 1
    )
    monitor_web.MonitorHandler.do_POST(oversized)

    negative, negative_responses, _ = _handler(
        config,
        "/feedback",
        method="POST",
        authorization="Bearer read-secret",
        body=b"session_id=safe",
    )
    negative.headers["Content-Length"] = "-1"
    monitor_web.MonitorHandler.do_POST(negative)

    assert oversized_responses[0][0] == HTTPStatus.REQUEST_ENTITY_TOO_LARGE
    assert oversized_responses[0][1]["error_code"] == "body_too_large"
    assert negative_responses[0][0] == HTTPStatus.BAD_REQUEST
    assert negative_responses[0][1]["error_code"] == "invalid_content_length"


def test_monitor_rejects_non_loopback_bind_without_read_auth(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(ValueError, match="without authentication"):
        monitor_web.build_server(
            "0.0.0.0",
            8090,
            _config(tmp_path, host="0.0.0.0"),
        )

    sentinel = object()
    monkeypatch.setattr(
        monitor_web,
        "BoundedThreadingHTTPServer",
        lambda *_args, **_kwargs: sentinel,
    )
    assert (
        monitor_web.build_server(
            "0.0.0.0",
            8090,
            _config(
                tmp_path,
                host="0.0.0.0",
                read_token="read-secret",
            ),
        )
        is sentinel
    )

    with pytest.raises(ValueError, match="valid Bearer token"):
        monitor_web.build_server(
            "127.0.0.1",
            8090,
            _config(tmp_path, read_token="unusable token"),
        )


def test_monitor_session_api_view_omits_raw_events_and_redacts_commands() -> None:
    detail = {
        "ok": True,
        "timestamp": "2026-07-17T00:00:00Z",
        "session_id": "session-safe",
        "overview": {"session_id": "session-safe"},
        "commands": [
            "curl https://user:pass@example.invalid/a?token=secret-token",
            "password=plaintext whoami",
        ],
        "session_payload": {
            "session_id": "session-safe",
            "raw_events": [{"password": "plaintext"}],
            "commands": ["whoami"],
        },
        "events_table_rows": [
            {
                "event_id": "event-safe",
                "session_id": "session-safe",
                "payload_json": '{"password":"plaintext"}',
            }
        ],
    }

    view = session_detail_view(detail)
    serialized = json.dumps(view, sort_keys=True)

    assert "raw_events" not in serialized
    assert "payload_json" not in serialized
    assert "secret-token" not in serialized
    assert "password=plaintext" not in serialized
    assert "user:pass" not in serialized


def test_monitor_request_log_sanitizes_sensitive_query_values(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    handler, _, _ = _handler(
        _config(tmp_path),
        "/api/session?session_id=secret-session&token=secret-token",
    )

    monitor_web.MonitorHandler.log_message(
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


def test_monitor_uses_central_redaction_and_one_static_ui(
    tmp_path: Path,
) -> None:
    secret = "legacy-secret"
    redacted = monitor_web._sanitize_public(
        {
            "login_password_hash": f"sha256:{secret}",
            "target_url": f"https://user:pass@example.invalid/?token={secret}",
            "command": f"password={secret}",
        }
    )
    assert secret not in json.dumps(redacted, sort_keys=True)

    assert not hasattr(monitor_web, "render_html")

    historical_secret = "historical-database-secret"
    detail = {
        "ok": True,
        "session_id": "session-safe",
        "session_payload": {"password": historical_secret},
        "latest_prediction_snapshot": {
            "payload": {
                "local_transition_model": {
                    "source_database": (
                        "mongodb://unit-user:unit-password@example.invalid/honeypot"
                        f"?token={historical_secret}"
                    )
                },
                "weight_calibration": {
                    "status": "error",
                    "reason": f"password={historical_secret}",
                },
            }
        },
    }
    raw_panel = monitor_web._render_raw_api_panel(detail)
    prediction_panel = monitor_web._render_prediction_panel(detail)
    assert historical_secret not in raw_panel
    assert historical_secret not in prediction_panel
    assert "unit-password" not in raw_panel
    assert "unit-password" not in prediction_panel

    static_html = monitor_web.STATIC_MONITOR_HTML.read_text(encoding="utf-8")
    assert "onclick=\"openSession(" not in static_html
    assert "data-open-session=" in static_html


def test_monitor_unexpected_error_and_storage_error_do_not_echo_secrets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    secret_error = RuntimeError(
        "mongodb://user:password@example.invalid/db?token=secret-token"
    )
    assert "password" not in monitor_web._storage_error("query", secret_error)
    assert "secret-token" not in monitor_web._storage_error("query", secret_error)

    monkeypatch.setattr(
        monitor_web,
        "load_snapshot",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(secret_error),
    )
    handler, responses, _ = _handler(
        _config(tmp_path, read_token="read-secret"),
        "/api/sessions",
        authorization="Bearer read-secret",
    )

    monitor_web.MonitorHandler.do_GET(handler)

    assert responses[0][0] == HTTPStatus.SERVICE_UNAVAILABLE
    assert responses[0][1]["error"] == "service temporarily unavailable"
    output = capsys.readouterr().out
    assert "password" not in output
    assert "secret-token" not in output
