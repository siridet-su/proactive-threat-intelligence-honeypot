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
            "backend": "sqlite",
            "database": "must-not-leak",
        }


def _config(
    tmp_path: Path,
    *,
    host: str = "127.0.0.1",
    read_token: str = "",
    write_token: str = "",
    raw_commands_token: str = "",
    allow_feedback: bool = False,
) -> monitor_web.MonitorConfig:
    production_config = SimpleNamespace(
        dashboard_read_token=read_token,
        dashboard_write_token=write_token,
        monitor_raw_commands_token=raw_commands_token,
        monitor_allow_feedback=allow_feedback,
    )
    return monitor_web.MonitorConfig(
        db_path="",
        database_url="sqlite:///:memory:",
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


def test_internal_command_view_requires_private_boundary_and_separate_admin_token(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sensitive_payload = {
        "ok": True,
        "schema_version": "monitor.internal_command_view.v1",
        "sensitive": True,
        "session_id": "session-safe",
        "commands": [
            {
                "event_id": "event-command",
                "eventid": "cowrie.command.input",
                "timestamp": "2026-07-17T00:00:00Z",
                "input": "cat /tmp/admin-secret",
                "classification": [{"ttp": "T1005", "tactic": "collection"}],
            }
        ],
    }
    monkeypatch.setattr(
        monitor_web,
        "load_internal_command_detail",
        lambda *_args, **_kwargs: sensitive_payload,
    )
    config = _config(tmp_path, raw_commands_token="raw-admin-token")

    denied, denied_responses, _ = _handler(
        config,
        "/api/internal/session-commands?session_id=session-safe",
    )
    monitor_web.MonitorHandler.do_GET(denied)
    assert denied_responses[0][0] == HTTPStatus.UNAUTHORIZED

    allowed, allowed_responses, _ = _handler(
        config,
        "/api/internal/session-commands?session_id=session-safe",
        authorization="Bearer raw-admin-token",
    )
    monitor_web.MonitorHandler.do_GET(allowed)
    assert allowed_responses[0][0] == HTTPStatus.OK
    body = json.loads(allowed_responses[0][1]["body"])
    assert body["sensitive"] is True
    assert body["commands"][0]["input"] == "cat /tmp/admin-secret"

    remote, remote_responses, _ = _handler(
        _config(tmp_path, host="8.8.8.8", raw_commands_token="raw-admin-token"),
        "/api/internal/session-commands?session_id=session-safe",
        authorization="Bearer raw-admin-token",
    )
    remote.client_address = ("198.51.100.20", 4242)
    monitor_web.MonitorHandler.do_GET(remote)
    assert remote_responses[0][0] == HTTPStatus.FORBIDDEN


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


def test_public_session_projection_never_returns_benign_command_text() -> None:
    view = session_detail_view(
        {
            "ok": True,
            "timestamp": "2026-07-17T00:00:00Z",
            "session_id": "session-command-boundary",
            "overview": {
                "session_id": "session-command-boundary",
                "commands": ["printf benign_public_boundary_check"],
            },
            "commands": ["printf benign_public_boundary_check"],
            "classification_events": [
                {
                    "command": "printf benign_public_boundary_check",
                    "input": "printf benign_public_boundary_check",
                    "ttp": "T1082",
                }
            ],
            "ttp_command_map": {
                "T1082": ["printf benign_public_boundary_check"],
            },
            "session_payload": {"session_id": "session-command-boundary"},
            "events_table_rows": [
                {
                    "event_id": "event-command-boundary",
                    "eventid": "cowrie.command.input",
                    "payload_json": json.dumps(
                        {
                            "eventid": "cowrie.command.input",
                            "input": "printf benign_public_boundary_check",
                        }
                    ),
                }
            ],
        }
    )

    serialized = json.dumps(view, sort_keys=True)
    assert "benign_public_boundary_check" not in serialized
    assert view["commands"] == ["[REDACTED]"]
    assert view["overview"]["commands"] == ["[REDACTED]"]
    assert view["classification_events"][0]["command"] == "[REDACTED]"
    assert view["classification_events"][0]["input"] == "[REDACTED]"
    assert view["ttp_command_map"]["T1082"] == ["[REDACTED]"]


def test_internal_command_projection_is_bounded_and_classified_without_public_reuse() -> None:
    class RawStorage:
        def list_rows_for_session(self, table: str, session_id: str, limit: int = 100):
            if table == "sessions":
                return [
                    {
                        "session_id": session_id,
                        "payload_json": json.dumps(
                            {
                                "session_id": session_id,
                                "classification_events": [
                                    {
                                        "evidence_id": "class-1",
                                        "event_timestamp": "2026-07-17T00:00:01Z",
                                        "cowrie_eventid": "cowrie.command.input",
                                        "ttp": "T1005",
                                        "tactic": "collection",
                                        "source": "rule",
                                        "command_outcome": "outcome_unknown",
                                        "evidence_tier": "trusted_observation",
                                        "command": "cat /tmp/admin-secret",
                                    }
                                ],
                            }
                        ),
                    }
                ]
            if table == "events":
                return [
                    {
                        "event_id": "event-1",
                        "eventid": "cowrie.command.input",
                        "timestamp": "2026-07-17T00:00:01Z",
                        "received_at": "2026-07-17T00:00:02Z",
                        "payload_json": json.dumps(
                            {
                                "eventid": "cowrie.command.input",
                                "input": "cat /tmp/admin-secret",
                            }
                        ),
                    },
                    {
                        "event_id": "event-2",
                        "eventid": "cowrie.session.closed",
                        "timestamp": "2026-07-17T00:00:03Z",
                        "payload_json": json.dumps(
                            {"eventid": "cowrie.session.closed"}
                        ),
                    },
                ]
            return []

    result = monitor_web.load_internal_command_detail(
        _config(Path(".")),
        "session-safe",
        _storage=RawStorage(),
    )
    assert result["ok"] is True
    assert result["sensitive"] is True
    assert result["commands"][0]["input"] == "cat /tmp/admin-secret"
    assert result["commands"][0]["classification"] == [
        {
            "evidence_id": "class-1",
            "ttp": "T1005",
            "tactic": "collection",
            "source": "rule",
            "command_outcome": "outcome_unknown",
            "evidence_tier": "trusted_observation",
        }
    ]
    assert "command" not in result["commands"][0]["classification"][0]
    public = session_detail_view(
        {
            "ok": True,
            "session_id": "session-safe",
            "overview": {},
            "session_payload": {"session_id": "session-safe"},
            "events_table_rows": [
                {
                    "event_id": "event-1",
                    "eventid": "cowrie.command.input",
                    "payload_json": '{"input":"cat /tmp/admin-secret"}',
                }
            ],
        }
    )
    assert "admin-secret" not in json.dumps(public, sort_keys=True)


def test_monitor_session_detail_uses_canonical_events_and_event_command_count() -> None:
    rows = [
        {
            "event_id": f"event-{index}",
            "eventid": eventid,
            "session_id": "session-events",
            "timestamp": f"2026-07-17T00:00:0{index}Z",
        }
        for index, eventid in enumerate(
            [
                "cowrie.session.connect",
                "cowrie.command.input",
                "cowrie.login.success",
                "cowrie.command.input",
                "cowrie.command.input",
                "cowrie.client.kex",
                "cowrie.session.closed",
                "cowrie.login.success",
            ]
        )
    ]
    view = session_detail_view(
        {
            "ok": True,
            "session_id": "session-events",
            "overview": {"session_id": "session-events", "command_count": 0},
            "session_payload": {"session_id": "session-events", "commands": []},
            "events_table_rows": rows,
        }
    )

    assert len(view["events"]) == 8
    assert view["events_table_rows"] == view["events"]
    assert view["overview"]["command_count"] == 3
    assert view["session"]["command_count"] == 3
    assert [row["command_event"] for row in view["events"]] == [
        False,
        True,
        False,
        True,
        True,
        False,
        False,
        False,
    ]


def test_monitor_command_count_accepts_privacy_redacted_historical_input_events() -> None:
    rows = [
        {
            "event_id": f"event-redacted-{index}",
            "eventid": eventid,
            "session_id": "session-redacted-events",
            "payload_json": json.dumps(payload),
        }
        for index, (eventid, payload) in enumerate(
            [
                ("cowrie.session.connect", {"eventid": "cowrie.session.connect"}),
                (
                    "cowrie.comm[REDACTED]nd.input",
                    {
                        "eventid": "cowrie.comm[REDACTED]nd.input",
                        "input": "id",
                    },
                ),
                (
                    "cowrie.comm[REDACTED]nd.input",
                    {
                        "eventid": "cowrie.comm[REDACTED]nd.input",
                        "input": "uname -a",
                    },
                ),
                (
                    "cowrie.comm[REDACTED]nd.input",
                    {
                        "eventid": "cowrie.comm[REDACTED]nd.input",
                        "input": "pwd",
                    },
                ),
                # A different input-shaped event is not a command, even when
                # it carries an input field. The compatibility path is bound
                # to the privacy-redaction marker and the Cowrie shape.
                (
                    "cowrie.terminal.input",
                    {"eventid": "cowrie.terminal.input", "input": "terminal data"},
                ),
            ]
        )
    ]

    view = session_detail_view(
        {
            "ok": True,
            "session_id": "session-redacted-events",
            "overview": {"session_id": "session-redacted-events", "command_count": 0},
            "session_payload": {"session_id": "session-redacted-events", "commands": []},
            "events_table_rows": rows,
        }
    )

    assert len(view["events"]) == 5
    assert view["overview"]["command_count"] == 3
    assert view["session"]["command_count"] == 3
    assert [row["command_event"] for row in view["events"]] == [
        False,
        True,
        True,
        True,
        False,
    ]
    assert '"input"' not in json.dumps(view, sort_keys=True)


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


def test_monitor_detail_prefers_canonical_event_contract_with_legacy_fallback() -> None:
    static_html = monitor_web.STATIC_MONITOR_HTML.read_text(encoding="utf-8")
    assert "const canonicalEvents = arrayMaybe(detail?.events);" in static_html
    assert "const legacyEvents = arrayMaybe(detail?.events_table_rows);" in static_html
    assert "const events = canonicalEvents.length ? canonicalEvents : legacyEvents;" in static_html
    assert "const isCommandEvent = e => e?.command_event === true" in static_html
    assert "const commandCount = cmdEvents.length || Number(ov.command_count) || 0;" in static_html
    assert "command content withheld by privacy policy" in static_html
    assert "/api/internal/session-commands?session_id=" in static_html
    assert "cache: 'no-store'" in static_html
    assert "Sensitive: text is the persisted Cowrie input" in static_html


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
