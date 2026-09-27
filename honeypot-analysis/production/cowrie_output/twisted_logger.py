"""Sanitizing Twisted logger used instead of Cowrie's plaintext logger."""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path

from production.cowrie_output.observer_diagnostics import emit_observer_diagnostic
from production.cowrie_output.runtime import boundary_from_environment
from production.utils.cowrie_privacy import sanitize_twisted_event


def _private_plain_file(path: Path):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.fchmod(descriptor, 0o600)
    return os.fdopen(descriptor, "w", encoding="utf-8")


def _isolated_text_observer(observer, output, boundary):
    """Keep categorical diagnostics isolated from authoritative JSON output."""

    sequence = 0
    emit_observer_diagnostic(
        observer="categorical_text",
        phase="registration",
        sequence=sequence,
    )

    def sanitized_observer(event):
        nonlocal sequence
        sequence += 1
        event_copy = dict(event) if isinstance(event, Mapping) else {}
        try:
            safe_event = sanitize_twisted_event(event_copy, policy=boundary.policy)
            category = str(safe_event.get("diagnostic_category", "unavailable"))
        except BaseException:
            safe_event = {
                "log_format": "sanitized diagnostic event rejected",
                "log_time": 0.0,
            }
            category = "unavailable"
            emit_observer_diagnostic(
                observer="categorical_text",
                phase="invocation",
                sequence=sequence,
                event=event_copy,
                event_category=category,
                exception_category="projection",
            )
        else:
            emit_observer_diagnostic(
                observer="categorical_text",
                phase="invocation",
                sequence=sequence,
                event=event_copy,
                event_category=category,
            )
        try:
            observer(safe_event)
            emit_observer_diagnostic(
                observer="categorical_text",
                phase="write",
                sequence=sequence,
                event=event_copy,
                event_category=category,
                write_attempted=True,
                write_succeeded=True,
            )
            output.flush()
        except BaseException:
            # The categorical sink is non-authoritative. Its failure must not
            # suppress the sanitized JSON observer that follows it.
            emit_observer_diagnostic(
                observer="categorical_text",
                phase="flush",
                sequence=sequence,
                event=event_copy,
                event_category=category,
                write_attempted=True,
                exception_category="flush",
            )
            return
        emit_observer_diagnostic(
            observer="categorical_text",
            phase="flush",
            sequence=sequence,
            event=event_copy,
            event_category=category,
            write_attempted=True,
            write_succeeded=True,
            flush_succeeded=True,
        )

    return sanitized_observer


def logger():
    """Validate the bundle, then sanitize before text formatting and writing."""

    try:
        from twisted.logger import textFileLogObserver

        import cowrie.python.logfile
        from cowrie.core.config import CowrieConfig

        boundary = boundary_from_environment()
        directory = Path(CowrieConfig.get("honeypot", "log_path", fallback="."))
        logtype = CowrieConfig.get("honeypot", "logtype", fallback="plain")
        if logtype == "rotating":
            output = cowrie.python.logfile.CowrieDailyLogFile(
                "cowrie.log", str(directory), defaultMode=0o600
            )
        elif logtype == "plain":
            output = _private_plain_file(directory / "plain.log")
        else:
            raise ValueError("unsupported Cowrie logtype")
        time_format = (
            "%Y-%m-%dT%H:%M:%S.%fZ"
            if os.environ.get("TZ") == "UTC"
            else "%Y-%m-%dT%H:%M:%S.%f%z"
        )
        observer = textFileLogObserver(output, timeFormat=time_format)
    except BaseException as exc:
        raise SystemExit(
            "sanitized Cowrie diagnostic output failed closed during initialization"
        ) from exc

    return _isolated_text_observer(observer, output, boundary)
