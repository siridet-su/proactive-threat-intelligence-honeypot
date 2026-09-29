"""Record a Cowrie command's actual outbound TCP tuple before HTTP dispatch.

Install as ``cowrie.shell.outbound_socket_receipt``.  No URL, credentials,
headers, or response outcome are included in the receipt.
"""

from __future__ import annotations

import ipaddress
from typing import Any, Callable


def socket_tuple(protocol: Any) -> dict[str, Any] | None:
    """Return a bounded IPv4 tuple from a connected Twisted protocol."""
    transport = getattr(protocol, "transport", None)
    if transport is None:
        return None
    try:
        local, remote = transport.getHost(), transport.getPeer()
        src_ip = ipaddress.ip_address(local.host)
        dst_ip = ipaddress.ip_address(remote.host)
        src_port, dst_port = int(local.port), int(remote.port)
    except (AttributeError, TypeError, ValueError):
        return None
    if src_ip.version != 4 or dst_ip.version != 4 or not (1 <= src_port <= 65535 and 1 <= dst_port <= 65535):
        return None
    return {
        "outbound_src_ip": str(src_ip), "outbound_src_port": src_port,
        "outbound_dst_ip": str(dst_ip), "outbound_dst_port": dst_port,
    }


class RecordingEndpoint:
    """Delegate the connection and emit its tuple before returning it to Agent."""

    def __init__(self, endpoint: Any, emit: Callable[[dict[str, Any]], None]) -> None:
        self._endpoint = endpoint
        self._emit = emit

    def connect(self, factory: Any) -> Any:
        deferred = self._endpoint.connect(factory)

        def record(protocol: Any) -> Any:
            value = socket_tuple(protocol)
            if value is not None:
                try:
                    self._emit(value)
                except Exception:
                    # Telemetry must never change the behavior of wget/curl.
                    pass
            return protocol

        return deferred.addCallback(record)


def make_recording_agent(cowrie_protocol: Any) -> Any:
    """Create a per-command, non-persistent treq agent with socket receipts.

    A new agent for each command prevents a pooled connection from another
    session from silently bypassing the connection hook.
    """
    from twisted.internet import reactor
    from twisted.web.client import Agent, HTTPConnectionPool

    class _RecordingAgent(Agent):
        def _getEndpoint(self, uri: Any) -> RecordingEndpoint:
            return RecordingEndpoint(super()._getEndpoint(uri), emit)

    def emit(value: dict[str, Any]) -> None:
        cowrie_protocol.logDispatch(
            eventid="cowrie.session.outbound_connection",
            format="Cowrie command opened outbound TCP connection",
            **value,
        )

    return _RecordingAgent(reactor, pool=HTTPConnectionPool(reactor, persistent=False))
