"""Cowrie output plugin that sanitizes credentials before JSON persistence."""

from __future__ import annotations

import os
from typing import Any

from production.cowrie_output.runtime import boundary_from_environment
from production.utils.cowrie_privacy import serialize_cowrie_event_for_persistence

try:
    from twisted.python import log

    import cowrie.core.output
    import cowrie.python.logfile
    from cowrie.core.config import CowrieConfig

    _CowrieOutputBase = cowrie.core.output.Output
except ModuleNotFoundError:  # Import-safe in the non-Cowrie application environment.
    log = None
    cowrie = None
    CowrieConfig = None
    _CowrieOutputBase = object


class Output(_CowrieOutputBase):
    """Manifest-validated replacement for Cowrie's stock JSON writer."""

    def start(self) -> None:
        try:
            if CowrieConfig is None or cowrie is None:
                raise RuntimeError("Cowrie runtime dependencies are unavailable")
            boundary = boundary_from_environment()
            configured_log = CowrieConfig.get(
                "output_sanitizedjson", "logfile", fallback=""
            )
            if os.path.realpath(configured_log) != os.path.realpath(
                boundary.json_log_path
            ):
                raise RuntimeError("validated and effective JSON paths differ")
            self._boundary = boundary
            self.epoch_timestamp = CowrieConfig.getboolean(
                "output_sanitizedjson", "epoch_timestamp", fallback=False
            )
            directory = os.path.dirname(configured_log)
            basename = os.path.basename(configured_log)
            self.outfile = cowrie.python.logfile.CowrieDailyLogFile(
                basename, directory, defaultMode=0o640
            )
        except BaseException as exc:
            raise SystemExit(
                "sanitized Cowrie JSON output failed closed during initialization"
            ) from exc

    def stop(self) -> None:
        if getattr(self, "outfile", None):
            self.outfile.flush()

    def write(self, event: dict[str, Any]) -> None:
        try:
            serialized = serialize_cowrie_event_for_persistence(
                event,
                policy=self._boundary.policy,
                epoch_timestamp=self.epoch_timestamp,
            )
        except ValueError:
            if log is not None:
                log.msg("sanitizedjson: event rejected before persistence")
            return
        try:
            self.outfile.write(serialized.decode("utf-8"))
            self.outfile.flush()
        except BaseException as exc:
            raise SystemExit(
                "sanitized Cowrie JSON persistence failed closed"
            ) from exc
