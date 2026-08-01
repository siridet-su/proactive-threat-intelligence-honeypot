"""Cowrie output plugin that sanitizes credentials before JSON persistence."""

from __future__ import annotations

import hashlib
import os
import stat
from collections.abc import Mapping
from typing import Any

from production.cowrie_output.observer_diagnostics import (
    emit_observer_diagnostic,
    observer_event_category,
)
from production.cowrie_output.lifecycle import update_lifecycle_state
from production.cowrie_output.runtime import boundary_from_environment
from production.utils.cowrie_privacy import serialize_cowrie_event_for_persistence

try:
    from twisted.python import log
    from twisted.internet import reactor

    import cowrie.core.output
    import cowrie.python.logfile
    from cowrie.core.config import CowrieConfig

    _CowrieOutputBase = cowrie.core.output.Output
except ModuleNotFoundError:  # Import-safe in the non-Cowrie application environment.
    log = None
    reactor = None
    cowrie = None
    CowrieConfig = None
    _CowrieOutputBase = object


class Output(_CowrieOutputBase):
    """Manifest-validated replacement for Cowrie's stock JSON writer."""

    def __init__(self) -> None:
        self._boundary = boundary_from_environment()
        self._observer_sequence = 0
        self._record_lifecycle(
            phase="constructor",
            result="attempted",
            flags={"class_discovered": True, "constructor_entered": True},
        )
        try:
            super().__init__()
        except BaseException:
            self._record_lifecycle(
                phase="constructor",
                result="failed",
                exception_category="constructor",
            )
            raise
        self._record_lifecycle(
            phase="constructor",
            result="succeeded",
            flags={"constructor_completed": True},
        )
        if reactor is None:
            raise SystemExit("sanitized Cowrie JSON registration cannot be verified")
        reactor.callLater(0, self._confirm_observer_registration)

    def _record_lifecycle(self, **values: Any) -> None:
        """Best-effort safe diagnostics; failure cannot suppress JSON output."""

        boundary = getattr(self, "_boundary", None)
        if boundary is None:
            return
        try:
            update_lifecycle_state(
                boundary.lifecycle_state_path,
                component_id=boundary.component_id,
                source_revision=boundary.git_revision,
                module_sha256=boundary.module_sha256,
                **values,
            )
        except BaseException:
            return

    def _confirm_observer_registration(self) -> None:
        registered = bool(
            log is not None and self.emit in log.theLogPublisher.observers
        )
        self._record_lifecycle(
            phase="registration",
            result="succeeded" if registered else "failed",
            exception_category="none" if registered else "registration",
            flags={"observer_registered": registered},
        )
        if not registered:
            self._request_fail_closed()

    @staticmethod
    def _request_fail_closed() -> None:
        if reactor is not None:
            try:
                reactor.callLater(0, reactor.stop)
            except BaseException:
                pass

    def _output_inode_category(self) -> str:
        try:
            descriptor = self.outfile._file.fileno()
            opened = os.fstat(descriptor)
            active = os.lstat(self._boundary.json_log_path)
        except (AttributeError, OSError):
            return "unavailable"
        if not stat.S_ISREG(opened.st_mode) or not stat.S_ISREG(active.st_mode):
            return "non_regular"
        return (
            "canonical_active"
            if (opened.st_dev, opened.st_ino) == (active.st_dev, active.st_ino)
            else "rotated_open"
        )

    def start(self) -> None:
        self._record_lifecycle(
            phase="start", result="attempted", flags={"start_entered": True}
        )
        try:
            if CowrieConfig is None or cowrie is None:
                raise RuntimeError("Cowrie runtime dependencies are unavailable")
            boundary = getattr(self, "_boundary", None) or boundary_from_environment()
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
        except BaseException as exc:
            self._record_lifecycle(
                phase="start",
                result="failed",
                exception_category="start",
            )
            raise SystemExit(
                "sanitized Cowrie JSON output failed closed during initialization"
            ) from exc
        self._record_lifecycle(
            phase="file_open",
            result="attempted",
            increments={"file_open_attempts": 1},
        )
        try:
            self.outfile = _PrivateFeedDailyLogFile(
                basename, directory, defaultMode=0o640
            )
        except BaseException as exc:
            self._record_lifecycle(
                phase="file_open",
                result="failed",
                exception_category="file_open",
            )
            raise SystemExit(
                "sanitized Cowrie JSON output failed closed during initialization"
            ) from exc
        self._record_lifecycle(
            phase="file_open",
            result="succeeded",
            increments={"file_open_successes": 1},
            output_inode_category=self._output_inode_category(),
        )
        try:
            self._observer_sequence = 0
            self._record_lifecycle(
                phase="start",
                result="succeeded",
                flags={"start_completed": True},
                output_inode_category=self._output_inode_category(),
            )
            self._emit_diagnostic(
                observer="sanitized_json",
                phase="registration",
                sequence=0,
            )
        except BaseException as exc:
            self._record_lifecycle(
                phase="start",
                result="failed",
                exception_category="start",
            )
            raise SystemExit(
                "sanitized Cowrie JSON output failed closed during initialization"
            ) from exc

    @staticmethod
    def _emit_diagnostic(**values: Any) -> None:
        """Keep optional diagnostic sinks outside the persistence path."""

        try:
            emit_observer_diagnostic(**values)
        except BaseException:
            return

    def stop(self) -> None:
        if not getattr(self, "outfile", None):
            return
        sequence = int(getattr(self, "_observer_sequence", 0))
        try:
            self.outfile.flush()
        except BaseException as exc:
            self._record_lifecycle(
                phase="stop",
                result="failed",
                exception_category="flush",
                increments={"flush_attempts": 1},
                output_inode_category=self._output_inode_category(),
            )
            self._request_fail_closed()
            self._emit_diagnostic(
                observer="sanitized_json",
                phase="stop",
                sequence=sequence,
                exception_category="flush",
            )
            raise SystemExit("sanitized Cowrie JSON flush failed closed") from exc
        self._emit_diagnostic(
            observer="sanitized_json",
            phase="stop",
            sequence=sequence,
            flush_succeeded=True,
        )
        self._record_lifecycle(
            phase="stop",
            result="succeeded",
            increments={"flush_attempts": 1, "flush_successes": 1},
            output_inode_category=self._output_inode_category(),
        )

    def write(self, event: dict[str, Any]) -> None:
        sequence = int(getattr(self, "_observer_sequence", 0)) + 1
        self._observer_sequence = sequence
        event_copy: Mapping[str, Any] | None = (
            dict(event) if isinstance(event, Mapping) else None
        )
        category = observer_event_category(event_copy)
        event_id = event_copy.get("eventid") if event_copy is not None else None
        event_id_sha256 = (
            hashlib.sha256(event_id.encode("utf-8", errors="replace")).hexdigest()
            if isinstance(event_id, str) and 0 < len(event_id) <= 512
            else "unavailable"
        )
        self._record_lifecycle(
            phase="invocation",
            result="succeeded",
            event_category=category,
            event_id_sha256=event_id_sha256,
            increments={"write_invocations": 1},
            output_inode_category=self._output_inode_category(),
        )
        self._emit_diagnostic(
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
            self._record_lifecycle(
                phase="serialization",
                result="failed",
                event_category=category,
                event_id_sha256=event_id_sha256,
                exception_category="serialization",
                increments={"serialization_attempts": 1},
                output_inode_category=self._output_inode_category(),
            )
            self._request_fail_closed()
            self._emit_diagnostic(
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
            payload = serialized.decode("utf-8")
            written = self.outfile.write(payload)
            if written is not None and written != len(payload):
                raise OSError("short sanitized Cowrie JSON write")
        except BaseException as exc:
            self._record_lifecycle(
                phase="write",
                result="failed",
                event_category=category,
                event_id_sha256=event_id_sha256,
                exception_category="write",
                increments={
                    "serialization_attempts": 1,
                    "serialization_successes": 1,
                    "write_attempts": 1,
                },
                output_inode_category=self._output_inode_category(),
            )
            self._request_fail_closed()
            self._emit_diagnostic(
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
        self._emit_diagnostic(
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
            self._record_lifecycle(
                phase="flush",
                result="failed",
                event_category=category,
                event_id_sha256=event_id_sha256,
                exception_category="flush",
                increments={
                    "serialization_attempts": 1,
                    "serialization_successes": 1,
                    "write_attempts": 1,
                    "write_successes": 1,
                    "flush_attempts": 1,
                },
                output_inode_category=self._output_inode_category(),
            )
            self._request_fail_closed()
            self._emit_diagnostic(
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
        self._emit_diagnostic(
            observer="sanitized_json",
            phase="flush",
            sequence=sequence,
            event=event_copy,
            event_category=category,
            write_attempted=True,
            write_succeeded=True,
            flush_succeeded=True,
        )
        self._record_lifecycle(
            phase="flush",
            result="succeeded",
            event_category=category,
            event_id_sha256=event_id_sha256,
            increments={
                "serialization_attempts": 1,
                "serialization_successes": 1,
                "write_attempts": 1,
                "write_successes": 1,
                "flush_attempts": 1,
                "flush_successes": 1,
            },
            output_inode_category=self._output_inode_category(),
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
