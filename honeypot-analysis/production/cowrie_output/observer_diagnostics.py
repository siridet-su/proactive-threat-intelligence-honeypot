"""Bounded observer diagnostics for isolated Cowrie output testing.

The production runtime does not configure a sink. Tests may temporarily attach
one to prove registration, invocation, write, and flush behavior without ever
capturing attacker-controlled event values or exception text.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from typing import Any


DiagnosticSink = Callable[[dict[str, Any]], None]

_ISOLATED_DIAGNOSTIC_SINK: DiagnosticSink | None = None
_OBSERVERS = frozenset({"categorical_text", "sanitized_json"})
_PHASES = frozenset({"registration", "invocation", "write", "flush", "stop"})
_EXCEPTION_CATEGORIES = frozenset(
    {"none", "initialization", "projection", "serialization", "write", "flush"}
)


def set_isolated_diagnostic_sink(sink: DiagnosticSink | None) -> DiagnosticSink | None:
    """Install a process-local test sink and return the previous sink."""

    global _ISOLATED_DIAGNOSTIC_SINK
    if sink is not None and not callable(sink):
        raise TypeError("isolated observer diagnostic sink must be callable")
    previous = _ISOLATED_DIAGNOSTIC_SINK
    _ISOLATED_DIAGNOSTIC_SINK = sink
    return previous


def _event_id_hash(event: Mapping[str, Any] | None) -> str:
    value = event.get("eventid") if event is not None else None
    if not isinstance(value, str) or not value or len(value) > 512:
        return "unavailable"
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def observer_event_category(event: Mapping[str, Any] | None) -> str:
    """Return a closed category without formatting attacker-controlled values."""

    value = event.get("eventid") if event is not None else None
    if not isinstance(value, str) or len(value) > 512:
        return "unavailable"
    normalized = value.strip().lower()
    exact = {
        "cowrie.login.success": "authentication",
        "cowrie.login.failed": "authentication",
        "cowrie.session.connect": "session",
        "cowrie.session.closed": "session",
        "cowrie.session.file_download": "transfer",
        "cowrie.session.file_upload": "transfer",
        "cowrie.command.input": "command",
        "cowrie.command.failed": "command",
        "cowrie.log.closed": "lifecycle",
    }.get(normalized)
    if exact is not None:
        return exact
    for prefix, category in (
        ("cowrie.client.", "client"),
        ("cowrie.direct-tcpip.", "network"),
        ("cowrie.session.", "session"),
        ("cowrie.command.", "command"),
        ("cowrie.login.", "authentication"),
    ):
        if normalized.startswith(prefix):
            return category
    return "diagnostic"


def emit_observer_diagnostic(
    *,
    observer: str,
    phase: str,
    sequence: int,
    event: Mapping[str, Any] | None = None,
    event_category: str = "unavailable",
    write_attempted: bool = False,
    write_succeeded: bool = False,
    flush_succeeded: bool = False,
    exception_category: str = "none",
) -> None:
    """Emit one closed diagnostic record only when an isolated sink is active."""

    sink = _ISOLATED_DIAGNOSTIC_SINK
    if sink is None:
        return
    if observer not in _OBSERVERS or phase not in _PHASES:
        raise ValueError("observer diagnostic identity is outside the closed contract")
    if exception_category not in _EXCEPTION_CATEGORIES:
        raise ValueError("observer exception category is outside the closed contract")
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 0:
        raise ValueError("observer diagnostic sequence is invalid")
    category = (
        event_category
        if event_category
        in {
            "authentication",
            "client",
            "command",
            "diagnostic",
            "lifecycle",
            "network",
            "operation",
            "session",
            "transfer",
            "unavailable",
        }
        else "unavailable"
    )
    sink(
        {
            "schema_version": "cowrie_output_observer_diagnostic.v1",
            "observer": observer,
            "phase": phase,
            "sequence": sequence,
            "event_category": category,
            "event_id_sha256": _event_id_hash(event),
            "output_path_category": (
                "sanitized_json_feed"
                if observer == "sanitized_json"
                else "categorical_text_log"
            ),
            "write_attempted": bool(write_attempted),
            "write_succeeded": bool(write_succeeded),
            "flush_succeeded": bool(flush_succeeded),
            "exception_category": exception_category,
        }
    )
