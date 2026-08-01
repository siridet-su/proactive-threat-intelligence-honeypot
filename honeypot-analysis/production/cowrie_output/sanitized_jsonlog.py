"""Cowrie output plugin that sanitizes credentials before JSON persistence."""

from __future__ import annotations

import os
import stat
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
            self.outfile = _PrivateFeedDailyLogFile(
                basename, directory, defaultMode=0o640
            )
        except BaseException as exc:
            raise SystemExit(
                "sanitized Cowrie JSON output failed closed during initialization"
            ) from exc


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
