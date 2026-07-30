"""Sanitizing Twisted logger used instead of Cowrie's plaintext logger."""

from __future__ import annotations

import os
from pathlib import Path

from production.cowrie_output.runtime import boundary_from_environment
from production.utils.cowrie_privacy import sanitize_twisted_event


def _private_plain_file(path: Path):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.fchmod(descriptor, 0o600)
    return os.fdopen(descriptor, "w", encoding="utf-8")


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

    def sanitized_observer(event):
        try:
            safe_event = sanitize_twisted_event(event, policy=boundary.policy)
        except BaseException:
            safe_event = {
                "log_format": "sanitized diagnostic event rejected",
                "log_time": event.get("log_time", 0),
            }
        try:
            observer(safe_event)
        except BaseException as exc:
            raise SystemExit(
                "sanitized Cowrie diagnostic persistence failed closed"
            ) from exc

    return sanitized_observer
