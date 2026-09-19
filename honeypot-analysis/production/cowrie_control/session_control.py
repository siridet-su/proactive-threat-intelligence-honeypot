"""Cowrie transport registry exposed through a local Unix socket only.

The protocol intentionally accepts one allow-listed operation and a Cowrie
transport id. It cannot execute shell commands, change configuration, or
address a connection by source IP.
"""

from __future__ import annotations

import json
import os
import re
import socket
import stat
from pathlib import Path
from typing import Any


SESSION_ID_PATTERN = re.compile(r"^[0-9a-f]{12}$")
ACTION_ID_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
MAX_REQUEST_BYTES = 1024


class SessionRegistry:
    def __init__(self) -> None:
        self._transports: dict[str, Any] = {}

    def register(self, protocol: Any) -> None:
        session_id = getattr(protocol, "transportId", None)
        if isinstance(session_id, str) and SESSION_ID_PATTERN.fullmatch(session_id):
            self._transports[session_id] = protocol

    def unregister(self, protocol: Any) -> None:
        session_id = getattr(protocol, "transportId", None)
        if isinstance(session_id, str) and self._transports.get(session_id) is protocol:
            del self._transports[session_id]

    def terminate(self, session_id: str) -> str:
        if SESSION_ID_PATTERN.fullmatch(session_id) is None:
            return "invalid_session"
        protocol = self._transports.get(session_id)
        if protocol is None:
            return "not_found"
        transport = getattr(protocol, "transport", None)
        if transport is None:
            self.unregister(protocol)
            return "not_found"
        abort = getattr(transport, "abortConnection", None)
        close = getattr(transport, "loseConnection", None)
        if callable(abort):
            abort()
        elif callable(close):
            close()
        else:
            return "unavailable"
        return "terminating"


registry = SessionRegistry()
_installed = False
_listener: Any = None


def _wrap_transport_class(transport_class: type[Any]) -> None:
    if getattr(transport_class, "_pti_session_control_wrapped", False):
        return
    original_connection_made = transport_class.connectionMade
    original_connection_lost = transport_class.connectionLost

    def connection_made(protocol: Any, *args: Any, **kwargs: Any) -> Any:
        result = original_connection_made(protocol, *args, **kwargs)
        registry.register(protocol)
        return result

    def connection_lost(protocol: Any, *args: Any, **kwargs: Any) -> Any:
        try:
            return original_connection_lost(protocol, *args, **kwargs)
        finally:
            registry.unregister(protocol)

    transport_class.connectionMade = connection_made
    transport_class.connectionLost = connection_lost
    transport_class._pti_session_control_wrapped = True


def _install_transport_hooks() -> None:
    from cowrie.ssh.transport import HoneyPotSSHTransport
    from cowrie.ssh_proxy.server_transport import FrontendSSHTransport
    from cowrie.telnet.transport import CowrieTelnetTransport
    from cowrie.telnet_proxy.server_transport import FrontendTelnetTransport

    for transport_class in (
        HoneyPotSSHTransport,
        FrontendSSHTransport,
        CowrieTelnetTransport,
        FrontendTelnetTransport,
    ):
        _wrap_transport_class(transport_class)


def _response(document: dict[str, Any]) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"


def handle_request(raw_request: bytes) -> bytes:
    if not raw_request or len(raw_request) > MAX_REQUEST_BYTES:
        return _response({"ok": False, "status": "invalid_request"})
    try:
        document = json.loads(raw_request)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return _response({"ok": False, "status": "invalid_request"})
    if not isinstance(document, dict) or set(document) - {"action", "action_id", "session_id"}:
        return _response({"ok": False, "status": "invalid_request"})
    if document.get("action") != "terminate_session":
        return _response({"ok": False, "status": "unsupported_action"})
    session_id = document.get("session_id")
    if not isinstance(session_id, str):
        return _response({"ok": False, "status": "invalid_session"})
    action_id = document.get("action_id")
    if not isinstance(action_id, str) or ACTION_ID_PATTERN.fullmatch(action_id) is None:
        return _response({"ok": False, "status": "invalid_request"})
    status = registry.terminate(session_id)
    return _response({"ok": status == "terminating", "status": status})


def _remove_stale_socket(path: Path) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    if path.is_symlink() or not stat.S_ISSOCK(metadata.st_mode):
        raise RuntimeError("Cowrie control path exists and is not a Unix socket")
    path.unlink()


def _start_listener(socket_path: Path) -> None:
    global _listener
    from twisted.internet import protocol, reactor
    from twisted.protocols.basic import LineReceiver
    from twisted.python import log

    _remove_stale_socket(socket_path)
    socket_path.parent.mkdir(mode=0o750, parents=True, exist_ok=True)

    class ControlProtocol(LineReceiver):
        delimiter = b"\n"
        MAX_LENGTH = MAX_REQUEST_BYTES

        def lineReceived(self, line: bytes) -> None:
            self.transport.write(handle_request(line))
            self.transport.loseConnection()

        def lineLengthExceeded(self, line: bytes) -> None:
            self.transport.write(_response({"ok": False, "status": "invalid_request"}))
            self.transport.loseConnection()

    factory = protocol.Factory.forProtocol(ControlProtocol)
    _listener = reactor.listenUNIX(str(socket_path), factory, mode=0o660, wantPID=False)
    os.chmod(socket_path, 0o660)
    log.msg("Cowrie session control socket ready")


def install_from_environment() -> bool:
    """Install hooks once; remain disabled unless an absolute socket is configured."""

    global _installed
    if _installed:
        return True
    configured = os.environ.get("HONEYPOT_COWRIE_CONTROL_SOCKET", "").strip()
    if not configured:
        return False
    socket_path = Path(configured)
    if not socket_path.is_absolute():
        raise RuntimeError("HONEYPOT_COWRIE_CONTROL_SOCKET must be absolute")
    _install_transport_hooks()
    from twisted.internet import reactor

    reactor.callWhenRunning(_start_listener, socket_path)
    _installed = True
    return True
