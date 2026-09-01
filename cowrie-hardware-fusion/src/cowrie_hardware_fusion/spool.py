"""Fail-closed, bounded JSONL segment spool for experimental telemetry."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import shutil
import stat
from typing import Any, BinaryIO, Mapping


_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class SpoolError(RuntimeError):
    """Raised when durability or storage bounds cannot be maintained."""


@dataclass(frozen=True)
class SpoolLimits:
    max_total_bytes: int
    min_free_bytes: int
    segment_max_bytes: int
    segment_max_records: int
    fsync_every_records: int = 1

    def validate(self) -> None:
        if self.max_total_bytes <= 0:
            raise SpoolError("max_total_bytes must be positive")
        if self.min_free_bytes < 0:
            raise SpoolError("min_free_bytes cannot be negative")
        if self.segment_max_bytes <= 0:
            raise SpoolError("segment_max_bytes must be positive")
        if self.segment_max_bytes > self.max_total_bytes:
            raise SpoolError("segment_max_bytes cannot exceed max_total_bytes")
        if self.segment_max_records <= 0:
            raise SpoolError("segment_max_records must be positive")
        if self.fsync_every_records != 1:
            raise SpoolError("experimental v1 requires fsync_every_records=1")


def canonical_json_line(record: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(
            record,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


class BoundedSegmentSpool:
    """Write one run to immutable, content-addressed JSONL segments.

    A run directory must be empty at startup. Published segment filenames contain the
    SHA-256 of their exact bytes. Any exception leaves only a ``.partial`` file and no
    completed receipt, making interrupted collection explicit.
    """

    def __init__(
        self,
        root: Path,
        *,
        run_id: str,
        metric_scope: str,
        limits: SpoolLimits,
    ) -> None:
        if not _IDENTIFIER.fullmatch(run_id):
            raise SpoolError("run_id is not a safe identifier")
        if not _IDENTIFIER.fullmatch(metric_scope):
            raise SpoolError("metric_scope is not a safe identifier")
        limits.validate()
        self.root = root
        self.run_id = run_id
        self.metric_scope = metric_scope
        self.limits = limits
        self.run_dir = root / f"run={run_id}" / f"scope={metric_scope}"
        self._handle: BinaryIO | None = None
        self._partial_path: Path | None = None
        self._hasher = sha256()
        self._segment_first: int | None = None
        self._segment_last: int | None = None
        self._segment_records = 0
        self._segment_bytes = 0
        self._written_bytes = 0
        self._existing_bytes = 0
        self._last_sequence: int | None = None
        self._closed = False
        self.receipts: list[dict[str, Any]] = []

    @property
    def serialized_bytes(self) -> int:
        return self._written_bytes

    def preflight(self) -> None:
        if self.root.is_symlink():
            raise SpoolError(f"spool root cannot be a symlink: {self.root}")
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.run_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        for protected_directory in (self.root, self.run_dir):
            mode = stat.S_IMODE(protected_directory.stat().st_mode)
            if mode & 0o077:
                raise SpoolError(
                    f"spool directory must not be group/world accessible: {protected_directory}"
                )
        existing_run_entries = list(self.run_dir.iterdir())
        if existing_run_entries:
            raise SpoolError(
                f"run spool is not empty; refusing overwrite/resume: {self.run_dir}"
            )
        self._existing_bytes = sum(
            path.stat().st_size for path in self.root.rglob("*") if path.is_file()
        )
        if self._existing_bytes >= self.limits.max_total_bytes:
            raise SpoolError("spool is already at or above max_total_bytes")
        free_bytes = shutil.disk_usage(self.root).free
        if free_bytes < self.limits.min_free_bytes:
            raise SpoolError(
                f"free disk {free_bytes} is below min_free_bytes={self.limits.min_free_bytes}"
            )

    def __enter__(self) -> BoundedSegmentSpool:
        self.preflight()
        return self

    def _open_segment(self, first_sequence: int) -> None:
        partial_path = self.run_dir / f"part-{first_sequence:06d}.jsonl.partial"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        descriptor = os.open(partial_path, flags, 0o600)
        self._handle = os.fdopen(descriptor, "wb")
        self._partial_path = partial_path
        self._hasher = sha256()
        self._segment_first = first_sequence
        self._segment_last = None
        self._segment_records = 0
        self._segment_bytes = 0

    def _check_capacity(self, line_size: int) -> None:
        if line_size > self.limits.segment_max_bytes:
            raise SpoolError("one telemetry record exceeds segment_max_bytes")
        projected = self._existing_bytes + self._written_bytes + line_size
        if projected > self.limits.max_total_bytes:
            raise SpoolError("writing the next record would exceed max_total_bytes")
        free_bytes = shutil.disk_usage(self.root).free
        if free_bytes - line_size < self.limits.min_free_bytes:
            raise SpoolError("writing the next record would violate min_free_bytes")

    def append(self, record: Mapping[str, Any]) -> None:
        if self._closed:
            raise SpoolError("cannot append to a closed spool")
        sequence = record.get("time", {}).get("sequence")
        if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 0:
            raise SpoolError("record time.sequence must be a nonnegative integer")
        if self._last_sequence is not None and sequence != self._last_sequence + 1:
            raise SpoolError(
                f"sequence must be contiguous: expected {self._last_sequence + 1}, got {sequence}"
            )

        line = canonical_json_line(record)
        self._check_capacity(len(line))
        rotation_needed = self._handle is not None and (
            self._segment_records >= self.limits.segment_max_records
            or self._segment_bytes + len(line) > self.limits.segment_max_bytes
        )
        if rotation_needed:
            self._finalize_segment()
        if self._handle is None:
            self._open_segment(sequence)

        assert self._handle is not None
        self._handle.write(line)
        self._handle.flush()
        os.fsync(self._handle.fileno())
        self._hasher.update(line)
        self._segment_records += 1
        self._segment_bytes += len(line)
        self._written_bytes += len(line)
        self._segment_last = sequence
        self._last_sequence = sequence

    def _finalize_segment(self) -> None:
        if self._handle is None:
            return
        assert self._partial_path is not None
        assert self._segment_first is not None
        assert self._segment_last is not None
        self._handle.flush()
        os.fsync(self._handle.fileno())
        self._handle.close()
        self._handle = None

        digest = self._hasher.hexdigest()
        filename = (
            f"part-{self._segment_first:06d}-{self._segment_last:06d}-{digest}.jsonl"
        )
        final_path = self.run_dir / filename
        try:
            os.link(self._partial_path, final_path)
            final_path.chmod(0o400)
            self._partial_path.unlink()
        except OSError as exc:
            raise SpoolError(f"could not publish immutable segment {filename}: {exc}") from exc
        directory_fd = os.open(self.run_dir, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)

        self.receipts.append(
            {
                "filename": filename,
                "first_sequence": self._segment_first,
                "last_sequence": self._segment_last,
                "record_count": self._segment_records,
                "serialized_bytes": self._segment_bytes,
                "sha256": digest,
            }
        )
        self._partial_path = None
        self._segment_first = None
        self._segment_last = None
        self._segment_records = 0
        self._segment_bytes = 0

    def close(self) -> None:
        if self._closed:
            return
        self._finalize_segment()
        self._closed = True

    def abort(self) -> None:
        if self._handle is not None:
            self._handle.flush()
            os.fsync(self._handle.fileno())
            self._handle.close()
            self._handle = None
        self._closed = True

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        if exc_type is None:
            self.close()
        else:
            self.abort()
