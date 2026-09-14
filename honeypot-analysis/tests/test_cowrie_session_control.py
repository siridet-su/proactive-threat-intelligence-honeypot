from __future__ import annotations

import json
from types import SimpleNamespace

from production.cowrie_control.session_control import (
    SessionRegistry,
    _remove_stale_socket,
    _wrap_transport_class,
    handle_request,
    registry,
)


class FakeTransport:
    def __init__(self) -> None:
        self.aborted = False

    def abortConnection(self) -> None:
        self.aborted = True


def test_registry_terminates_exact_registered_session() -> None:
    session_registry = SessionRegistry()
    transport = FakeTransport()
    protocol = SimpleNamespace(transportId="abcdef123456", transport=transport)
    session_registry.register(protocol)

    assert session_registry.terminate("abcdef123456") == "terminating"
    assert transport.aborted is True
    session_registry.unregister(protocol)
    assert session_registry.terminate("abcdef123456") == "not_found"


def test_registry_rejects_non_cowrie_session_ids() -> None:
    assert SessionRegistry().terminate("../../service") == "invalid_session"


def test_protocol_exposes_only_terminate_session(monkeypatch) -> None:
    monkeypatch.setattr(registry, "terminate", lambda session_id: "terminating")
    response = json.loads(
        handle_request(
            b'{"action":"terminate_session","action_id":"123e4567-e89b-12d3-a456-426614174000","session_id":"abcdef123456"}'
        )
    )
    assert response == {"ok": True, "status": "terminating"}

    unsupported = json.loads(
        handle_request(b'{"action":"shell","session_id":"abcdef123456"}')
    )
    assert unsupported == {"ok": False, "status": "unsupported_action"}

    extra = json.loads(
        handle_request(
            b'{"action":"terminate_session","session_id":"abcdef123456","command":"id"}'
        )
    )
    assert extra == {"ok": False, "status": "invalid_request"}


def test_transport_hooks_register_and_unregister_exact_instance() -> None:
    transport = FakeTransport()

    class FakeProtocol:
        def connectionMade(self) -> None:
            self.transportId = "123456abcdef"
            self.transport = transport

        def connectionLost(self, reason=None) -> None:
            self.reason = reason

    _wrap_transport_class(FakeProtocol)
    protocol = FakeProtocol()
    protocol.connectionMade()
    assert registry.terminate("123456abcdef") == "terminating"
    protocol.connectionLost("test")
    assert registry.terminate("123456abcdef") == "not_found"


def test_stale_socket_cleanup_refuses_regular_file(tmp_path) -> None:
    path = tmp_path / "control.sock"
    path.write_text("not a socket", encoding="utf-8")
    try:
        _remove_stale_socket(path)
    except RuntimeError as error:
        assert "not a Unix socket" in str(error)
    else:
        raise AssertionError("regular control path was accepted")
    assert path.is_file()
