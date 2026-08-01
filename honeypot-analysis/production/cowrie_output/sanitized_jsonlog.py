"""Cowrie output plugin that sanitizes credentials before JSON persistence."""

from __future__ import annotations

import os
import stat
from collections.abc import Mapping
from typing import Any

from production.cowrie_output.observer_diagnostics import (
    emit_observer_diagnostic,
    observer_event_category,
)
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
            self.outfile = _PrivateFeedDailyLogFile(
                basename, directory, defaultMode=0o640
            )
            self._observer_sequence = 0
            emit_observer_diagnostic(
                observer="sanitized_json",
                phase="registration",
                sequence=0,
            )
        except BaseException as exc:
            raise SystemExit(
                "sanitized Cowrie JSON output failed closed during initialization"
            ) from exc

    def stop(self) -> None:
        if not getattr(self, "outfile", None):
            return
        sequence = int(getattr(self, "_observer_sequence", 0))
        try:
            self.outfile.flush()
        except BaseException as exc:
            emit_observer_diagnostic(
                observer="sanitized_json",
                phase="stop",
                sequence=sequence,
                exception_category="flush",
            )
            raise SystemExit("sanitized Cowrie JSON flush failed closed") from exc
        emit_observer_diagnostic(
            observer="sanitized_json",
            phase="stop",
            sequence=sequence,
            flush_succeeded=True,
        )

    def write(self, event: dict[str, Any]) -> None:
        sequence = int(getattr(self, "_observer_sequence", 0)) + 1
        self._observer_sequence = sequence
        event_copy: Mapping[str, Any] | None = (
            dict(event) if isinstance(event, Mapping) else None
        )
        category = observer_event_category(event_copy)
        emit_observer_diagnostic(
            observer="sanitized_json",
            phase="invocation",
            sequence=sequence,
            event=event_copy,
            event_category=category,
        )
        try:
            serialized = serialize_cowrie_event_for_persistence(
                event_copy,  # type: ignore[arg-type]
                policy=self._boundary.policy,
                epoch_timestamp=self.epoch_timestamp,
            )
        except (TypeError, ValueError) as exc:
            emit_observer_diagnostic(
                observer="sanitized_json",
                phase="write",
                sequence=sequence,
                event=event_copy,
                event_category=category,
                write_attempted=True,
                exception_category="serialization",
            )
            raise SystemExit("sanitized Cowrie JSON event rejected") from exc
        try:
            self.outfile.write(serialized.decode("utf-8"))
        except BaseException as exc:
            emit_observer_diagnostic(
                observer="sanitized_json",
                phase="write",
                sequence=sequence,
                event=event_copy,
                event_category=category,
                write_attempted=True,
                exception_category="write",
            )
            raise SystemExit(
                "sanitized Cowrie JSON persistence failed closed"
            ) from exc
        emit_observer_diagnostic(
            observer="sanitized_json",
            phase="write",
            sequence=sequence,
            event=event_copy,
            event_category=category,
            write_attempted=True,
            write_succeeded=True,
        )
        try:
            self.outfile.flush()
        except BaseException as exc:
            emit_observer_diagnostic(
                observer="sanitized_json",
                phase="flush",
                sequence=sequence,
                event=event_copy,
                event_category=category,
                write_attempted=True,
                write_succeeded=True,
                exception_category="flush",
            )
            raise SystemExit(
                "sanitized Cowrie JSON persistence failed closed"
            ) from exc
        emit_observer_diagnostic(
            observer="sanitized_json",
            phase="flush",
            sequence=sequence,
            event=event_copy,
            event_category=category,
            write_attempted=True,
            write_succeeded=True,
            flush_succeeded=True,
        )


if cowrie is not None:

    class _PrivateFeedDailyLogFile(cowrie.python.logfile.CowrieDailyLogFile):
        """Rotate the group-readable feed into an owner-only historical file."""

        def rotate(self) -> None:
            if not (os.access(self.directory, os.W_OK) and os.access(self.path, os.W_OK)):
                raise OSError("sanitized Cowrie feed cannot be rotated safely")
            rotated = f"{self.path}.{self.suffix(self.lastDate)}"
            if os.path.lexists(rotated):
                raise FileExistsError("sanitized Cowrie rotation target already exists")
            metadata = os.lstat(self.path)
            if not stat.S_ISREG(metadata.st_mode):
                raise OSError("sanitized Cowrie feed is not a regular file")
            self._file.close()
            os.chmod(self.path, 0o600)
            os.rename(self.path, rotated)
            self._openFile()
            os.chmod(self.path, 0o640)
            os.chmod(rotated, 0o600)

else:  # pragma: no cover - import safety outside the Cowrie runtime
    _PrivateFeedDailyLogFile = object
