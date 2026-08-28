"""Raspberry Pi Cowrie log forwarder with a durable local disk spool."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import shutil
import stat as stat_module
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

if __package__ == "production":
    # The Pi uses a minimal flat package containing only this module and its
    # config/serialization dependencies.
    from .config import ProductionConfig
    from .serialization import utc_now
    from .service_lifecycle import ServiceLifecycle
else:
    from production.utils.config import ProductionConfig
    from production.utils.sensitive_data import (
        redact_exception_for_log,
        sanitize_cowrie_event_for_persistence,
    )
    from production.utils.service_lifecycle import ServiceLifecycle
    from production.utils.serialization import utc_now


DEFAULT_MAX_SPOOL_BYTES = 64 * 1024 * 1024
DEFAULT_MIN_FREE_BYTES = 32 * 1024 * 1024
DEFAULT_MAX_LINE_BYTES = 256 * 1024
DEFAULT_MAX_QUARANTINE_BYTES = 16 * 1024 * 1024
DEFAULT_MAX_QUARANTINE_EVENTS = 1_000
OFFSET_SCHEMA = "cowrie_forwarder_offset.v2"
QUARANTINE_SCHEMA = "cowrie_forwarder_quarantine.v1"


if __package__ == "production":
    # Compatibility for the retired flat Pi package layout.  The supported
    # module layout imports the shared sanitizer above.
    def sanitize_cowrie_event_for_persistence(event: Dict[str, Any]) -> Dict[str, Any]:
        sanitized = dict(event)
        fields = []
        for field in ("username", "password", "passwd", "pwd"):
            if sanitized.get(field) not in (None, ""):
                sanitized[field] = "[REDACTED]"
                fields.append(field)
        if fields:
            sanitized["_honeypot_privacy"] = {
                "schema_version": "cowrie_credential_sanitizer.v1",
                "credential_plaintext_removed": True,
                "credential_fields_redacted": sorted(fields),
            }
        return sanitized


def _safe_exception_text(exc: BaseException) -> str:
    """Summarize failures without rendering attacker-controlled arguments."""

    if __package__ != "production":
        return redact_exception_for_log(exc)
    # The legacy Pi compatibility package has only config/serialization.  A
    # constant fallback preserves containment without maintaining a second
    # independent redaction policy there.
    return "operation_failed"


def _fsync_directory(path: Path) -> None:
    """Persist a directory-entry change on Linux filesystems."""

    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic_replace_bytes(path: Path, payload: bytes) -> None:
    """Atomically replace ``path`` with an fsynced private regular file."""

    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent)
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        descriptor = -1
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


@dataclass(frozen=True)
class TailCheckpoint:
    offset: int
    device: Optional[int] = None
    inode: Optional[int] = None


@dataclass(frozen=True)
class TailRead:
    events: List[Dict[str, Any]]
    checkpoint: TailCheckpoint
    previous_offset: int
    parse_errors: int = 0
    rotation_detected: bool = False
    truncation_detected: bool = False
    commit_required: bool = False


@dataclass
class ForwardResult:
    sent: int
    remaining: int
    duplicates: int = 0
    rejected: int = 0
    error: str = ""
    spooled: int = 0
    parse_errors: int = 0
    spool_bytes: int = 0
    source_offset: int = 0
    spool_parse_errors: int = 0
    rotation_detected: bool = False
    truncation_detected: bool = False
    disk_limited: bool = False
    lock_contended: bool = False
    quarantined: int = 0
    quarantine_evicted: int = 0
    quarantine_bytes: int = 0


class ForwarderInstanceLock:
    """Non-blocking process lock colocated with the spool state."""

    def __init__(self, spool_path: str) -> None:
        self.path = Path(f"{spool_path}.lock")
        self._descriptor: Optional[int] = None

    def __enter__(self) -> "ForwarderInstanceLock":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            os.fchmod(descriptor, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(descriptor)
            raise
        self._descriptor = descriptor
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        if self._descriptor is None:
            return
        try:
            fcntl.flock(self._descriptor, fcntl.LOCK_UN)
        finally:
            os.close(self._descriptor)
            self._descriptor = None


class SpoolCapacityError(OSError):
    """Raised before an append that would violate a disk safety bound."""


class RejectedEventQuarantine:
    """Private, bounded, durable dead-letter storage for permanent rejects."""

    def __init__(self, path: str) -> None:
        self.path = Path(path)

    def size_bytes(self) -> int:
        try:
            return self.path.stat().st_size
        except FileNotFoundError:
            return 0

    @staticmethod
    def _record(
        sensor_id: str,
        event: Dict[str, Any],
        rejection: Dict[str, Any],
    ) -> Dict[str, Any]:
        sanitized = sanitize_cowrie_event_for_persistence(event)
        event_bytes = json.dumps(
            sanitized,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        error_code = str(rejection.get("error_code") or "ingest_rejected")[:128]
        identity_material = {
            "sensor_id": str(sensor_id or ""),
            "event_sha256": hashlib.sha256(event_bytes).hexdigest(),
            "error_code": error_code,
        }
        quarantine_id = "quarantine_" + hashlib.sha256(
            json.dumps(
                identity_material,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()[:32]
        return {
            "schema_version": QUARANTINE_SCHEMA,
            "quarantine_id": quarantine_id,
            "quarantined_at": utc_now(),
            **identity_material,
            "event_bytes": len(event_bytes),
            "event": sanitized,
        }

    @staticmethod
    def _encode(record: Dict[str, Any]) -> bytes:
        return json.dumps(
            record,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8") + b"\n"

    def append_rejected(
        self,
        *,
        sensor_id: str,
        rejected: List[Tuple[Dict[str, Any], Dict[str, Any]]],
        max_bytes: int,
        max_events: int,
    ) -> Tuple[int, int]:
        """Durably add rejects, evicting oldest rows to enforce both bounds."""

        if not rejected:
            return 0, 0
        existing_lines: List[bytes] = []
        existing_ids: set[str] = set()
        if self.path.exists():
            for raw_line in self.path.read_bytes().splitlines():
                if not raw_line.strip():
                    continue
                line = raw_line + b"\n"
                existing_lines.append(line)
                try:
                    parsed = json.loads(raw_line)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    continue
                if isinstance(parsed, dict):
                    quarantine_id = parsed.get("quarantine_id")
                    if isinstance(quarantine_id, str):
                        existing_ids.add(quarantine_id)

        added_lines: List[bytes] = []
        for event, rejection in rejected:
            record = self._record(sensor_id, event, rejection)
            if record["quarantine_id"] in existing_ids:
                continue
            encoded = self._encode(record)
            if len(encoded) > max_bytes:
                record.pop("event", None)
                record["event_omitted_due_to_quarantine_bound"] = True
                encoded = self._encode(record)
            if len(encoded) > max_bytes:
                raise OSError("quarantine bound cannot hold rejection metadata")
            existing_ids.add(record["quarantine_id"])
            added_lines.append(encoded)

        lines = existing_lines + added_lines
        evicted = 0
        total_bytes = sum(len(line) for line in lines)
        while lines and (len(lines) > max_events or total_bytes > max_bytes):
            total_bytes -= len(lines.pop(0))
            evicted += 1

        _atomic_replace_bytes(self.path, b"".join(lines))
        return len(added_lines), evicted


class CowrieLogTailer:
    """Read complete Cowrie NDJSON records without prematurely committing them."""

    def __init__(self, log_path: str, offset_path: str) -> None:
        self.log_path = Path(log_path)
        self.offset_path = Path(offset_path)

    def _load_checkpoint(self) -> TailCheckpoint:
        try:
            raw = self.offset_path.read_text(encoding="utf-8").strip()
        except OSError:
            return TailCheckpoint(0)
        if not raw:
            return TailCheckpoint(0)
        # v1 stored a bare integer. It is parsed for compatibility, then
        # replayed once because it cannot identify a rotated source file.
        try:
            return TailCheckpoint(max(int(raw), 0))
        except ValueError:
            pass
        try:
            parsed = json.loads(raw)
            if not isinstance(parsed, dict) or parsed.get("schema") != OFFSET_SCHEMA:
                return TailCheckpoint(0)
            offset = parsed.get("offset")
            device = parsed.get("device")
            inode = parsed.get("inode")
            if (
                isinstance(offset, bool)
                or not isinstance(offset, int)
                or offset < 0
                or isinstance(device, bool)
                or not isinstance(device, int)
                or device < 0
                or isinstance(inode, bool)
                or not isinstance(inode, int)
                or inode < 0
            ):
                return TailCheckpoint(0)
            return TailCheckpoint(offset, device, inode)
        except (json.JSONDecodeError, TypeError, ValueError):
            return TailCheckpoint(0)

    def commit(self, checkpoint: TailCheckpoint) -> None:
        payload = json.dumps(
            {
                "device": checkpoint.device,
                "inode": checkpoint.inode,
                "offset": checkpoint.offset,
                "schema": OFFSET_SCHEMA,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        _atomic_replace_bytes(self.offset_path, payload + b"\n")

    @staticmethod
    def _parse_error_event(
        raw_line: bytes,
        reason: str,
        *,
        raw_line_bytes: Optional[int] = None,
        raw_line_sha256: Optional[str] = None,
        source_offset: Optional[int] = None,
        source_file_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        return {
            "eventid": "forwarder.parse_error",
            "error": reason,
            "raw_line_bytes": raw_line_bytes if raw_line_bytes is not None else len(raw_line),
            "raw_line_sha256": raw_line_sha256 or hashlib.sha256(raw_line).hexdigest(),
            **({"source_offset": source_offset} if source_offset is not None else {}),
            **({"source_file_id": source_file_id} if source_file_id else {}),
        }

    def _find_rotated_source(self, checkpoint: TailCheckpoint) -> Optional[Path]:
        """Find a renamed regular file matching the last committed identity."""

        if checkpoint.device is None or checkpoint.inode is None:
            return None
        try:
            with os.scandir(self.log_path.parent) as entries:
                for entry in entries:
                    if entry.name == self.log_path.name:
                        continue
                    try:
                        candidate_stat = entry.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    if not stat_module.S_ISREG(candidate_stat.st_mode):
                        continue
                    if (candidate_stat.st_dev, candidate_stat.st_ino) == (
                        checkpoint.device,
                        checkpoint.inode,
                    ):
                        return Path(entry.path)
        except OSError:
            return None
        return None

    def prepare_new_events(self, *, limit: int, max_line_bytes: int) -> TailRead:
        checkpoint = self._load_checkpoint()
        if not self.log_path.exists():
            return TailRead([], checkpoint, checkpoint.offset)

        events: List[Dict[str, Any]] = []
        parse_errors = 0
        current_stat = self.log_path.stat()
        current_identity_changed = (
            checkpoint.device is not None
            and checkpoint.inode is not None
            and (checkpoint.device, checkpoint.inode)
            != (current_stat.st_dev, current_stat.st_ino)
        )
        rotated_source = (
            self._find_rotated_source(checkpoint) if current_identity_changed else None
        )
        source_path = rotated_source or self.log_path
        recovering_rotation = rotated_source is not None

        with source_path.open("rb") as handle:
            stat = os.fstat(handle.fileno())
            source_file_id = hashlib.sha256(
                f"{stat.st_dev}:{stat.st_ino}".encode("ascii")
            ).hexdigest()[:32]
            identity_changed = (
                not recovering_rotation
                and checkpoint.device is not None
                and checkpoint.inode is not None
                and (checkpoint.device, checkpoint.inode) != (stat.st_dev, stat.st_ino)
            )
            truncated = not identity_changed and checkpoint.offset > stat.st_size
            legacy_checkpoint = (
                checkpoint.offset > 0
                and checkpoint.device is None
                and checkpoint.inode is None
            )
            # A v1 bare offset cannot prove that the current pathname still
            # refers to the same file. Resetting once may replay duplicates,
            # but cannot silently skip a rotated file.
            start_offset = (
                0 if identity_changed or truncated or legacy_checkpoint else checkpoint.offset
            )
            handle.seek(start_offset)

            while len(events) < limit:
                line_start = handle.tell()
                raw_line = handle.readline(max_line_bytes + 1)
                if not raw_line:
                    break

                if not raw_line.endswith(b"\n"):
                    if len(raw_line) <= max_line_bytes:
                        # Cowrie may still be writing this record. Re-read it
                        # after the terminating newline reaches disk.
                        if not recovering_rotation:
                            handle.seek(line_start)
                            break
                        events.append(
                            self._parse_error_event(
                                raw_line,
                                "invalid_ndjson",
                                source_offset=line_start,
                                source_file_id=source_file_id,
                            )
                        )
                        parse_errors += 1
                        continue
                    digest = hashlib.sha256()
                    digest.update(raw_line)
                    raw_line_length = len(raw_line)
                    complete = False
                    while True:
                        chunk = handle.readline(max_line_bytes + 1)
                        if not chunk:
                            break
                        digest.update(chunk)
                        raw_line_length += len(chunk)
                        if chunk.endswith(b"\n"):
                            complete = True
                            break
                    if not complete:
                        if not recovering_rotation:
                            handle.seek(line_start)
                            break
                        complete = True
                    events.append(
                        self._parse_error_event(
                            b"",
                            "line_too_large",
                            raw_line_bytes=raw_line_length,
                            raw_line_sha256=digest.hexdigest(),
                            source_offset=line_start,
                            source_file_id=source_file_id,
                        )
                    )
                    parse_errors += 1
                    continue

                stripped = raw_line.rstrip(b"\r\n")
                if not stripped:
                    continue
                if len(stripped) > max_line_bytes:
                    event = self._parse_error_event(
                        stripped,
                        "line_too_large",
                        source_offset=line_start,
                        source_file_id=source_file_id,
                    )
                    parse_errors += 1
                    events.append(event)
                    continue
                try:
                    parsed = json.loads(stripped.decode("utf-8"))
                    if not isinstance(parsed, dict):
                        raise ValueError("event_not_object")
                    events.append(parsed)
                except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
                    events.append(
                        self._parse_error_event(
                            stripped,
                            "invalid_ndjson",
                            source_offset=line_start,
                            source_file_id=source_file_id,
                        )
                    )
                    parse_errors += 1

            new_offset = handle.tell()
            recovered_to_eof = recovering_rotation and new_offset >= stat.st_size
            next_checkpoint = (
                TailCheckpoint(0, current_stat.st_dev, current_stat.st_ino)
                if recovered_to_eof
                else TailCheckpoint(new_offset, stat.st_dev, stat.st_ino)
            )

        return TailRead(
            events,
            next_checkpoint,
            checkpoint.offset,
            parse_errors=parse_errors,
            rotation_detected=current_identity_changed,
            truncation_detected=truncated,
            commit_required=(
                identity_changed
                or truncated
                or legacy_checkpoint
                or new_offset != checkpoint.offset
                or checkpoint.device is None
                or checkpoint.inode is None
                or recovered_to_eof
            ),
        )


class DiskSpool:
    """Durable bounded NDJSON queue for outbound-only sensors."""

    def __init__(self, path: str) -> None:
        self.path = Path(path)

    def size_bytes(self) -> int:
        try:
            return self.path.stat().st_size
        except FileNotFoundError:
            return 0

    def _available_bytes(self) -> int:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        return shutil.disk_usage(self.path.parent).free

    def append_many(
        self,
        events: Iterable[Dict[str, Any]],
        *,
        max_spool_bytes: int = DEFAULT_MAX_SPOOL_BYTES,
        min_free_bytes: int = DEFAULT_MIN_FREE_BYTES,
    ) -> int:
        materialized = [
            sanitize_cowrie_event_for_persistence(event) for event in events
        ]
        if not materialized:
            return 0
        payload = b"".join(
            json.dumps(event, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
            for event in materialized
        )
        current_size = self.size_bytes()
        if current_size + len(payload) > max_spool_bytes:
            raise SpoolCapacityError("forwarder spool size limit reached")
        prospective_size = current_size + len(payload)
        # A later acknowledgement rewrite temporarily needs a second file as
        # large as the queue. Reserve that space before accepting more data.
        if self._available_bytes() - len(payload) - prospective_size < min_free_bytes:
            raise SpoolCapacityError("forwarder spool free-space reserve reached")

        self.path.parent.mkdir(parents=True, exist_ok=True)
        existed = self.path.exists()
        descriptor = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            os.fchmod(descriptor, 0o600)
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("short spool append")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        if not existed:
            _fsync_directory(self.path.parent)
        return len(materialized)

    @staticmethod
    def _spool_parse_error(raw_line: str, line_index: int) -> Dict[str, Any]:
        encoded = raw_line.encode("utf-8", errors="replace")
        return {
            "eventid": "forwarder.spool_parse_error",
            "error": "invalid_spool_ndjson",
            "raw_line_bytes": len(encoded),
            "raw_line_sha256": hashlib.sha256(encoded).hexdigest(),
            "spool_line_index": line_index,
        }

    def load_batch(self, limit: int) -> Tuple[List[Dict[str, Any]], List[str]]:
        if not self.path.exists():
            return [], []
        lines = self.path.read_text(encoding="utf-8", errors="replace").splitlines()
        batch_lines = lines[:limit]
        remaining = lines[limit:]
        events: List[Dict[str, Any]] = []
        for line_index, line in enumerate(batch_lines):
            if not line.strip():
                continue
            try:
                parsed = json.loads(line)
                if not isinstance(parsed, dict):
                    raise ValueError("event_not_object")
                events.append(parsed)
            except (json.JSONDecodeError, ValueError):
                events.append(self._spool_parse_error(line, line_index))
        return events, remaining

    def replace_remaining(self, remaining_lines: List[str]) -> None:
        payload = (
            ("\n".join(remaining_lines) + "\n").encode("utf-8")
            if remaining_lines
            else b""
        )
        _atomic_replace_bytes(self.path, payload)
        if not remaining_lines:
            # The empty replacement is already durable. Removing it restores
            # the historical "no backlog means no spool file" contract.
            self.path.unlink()
            _fsync_directory(self.path.parent)

    def count(self) -> int:
        if not self.path.exists():
            return 0
        with self.path.open("r", encoding="utf-8", errors="replace") as handle:
            return sum(1 for line in handle if line.strip())


def post_events(config: ProductionConfig, events: List[Dict[str, Any]]) -> Dict[str, Any]:
    payload = {"sensor_id": config.sensor_id, "events": events}
    request = urllib.request.Request(
        config.ingest_url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {config.api_token}",
            "Content-Type": "application/json",
            "X-Sensor-ID": config.sensor_id,
        },
        method="POST",
    )
    try:
        response = urllib.request.urlopen(
            request,
            timeout=config.forwarder_timeout_seconds,
        )
    except urllib.error.HTTPError as exc:
        # A completely rejected batch is a valid indexed acknowledgement even
        # though ingest returns HTTP 400.  Other HTTP errors remain retryable.
        encoded = exc.read(1_048_577)
        if len(encoded) > 1_048_576:
            raise ValueError("ingest response exceeds size limit") from exc
        try:
            parsed = json.loads(encoded.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise exc
        if (
            exc.code != 400
            or not isinstance(parsed, dict)
            or not {"accepted", "duplicates", "rejected", "total"}.issubset(parsed)
        ):
            raise exc
        return parsed
    with response:
        encoded = response.read(1_048_577)
    if len(encoded) > 1_048_576:
        raise ValueError("ingest response exceeds size limit")
    parsed = json.loads(encoded.decode("utf-8"))
    if not isinstance(parsed, dict):
        raise ValueError("ingest response must be an object")
    return parsed


def _result(
    spool: DiskSpool,
    tail_read: TailRead,
    *,
    sent: int = 0,
    duplicates: int = 0,
    rejected: int = 0,
    error: str = "",
    spooled: int = 0,
    disk_limited: bool = False,
    checkpoint_committed: bool = True,
    spool_parse_errors: int = 0,
    quarantined: int = 0,
    quarantine_evicted: int = 0,
    quarantine_bytes: int = 0,
) -> ForwardResult:
    return ForwardResult(
        sent=sent,
        duplicates=duplicates,
        rejected=rejected,
        remaining=spool.count(),
        error=error,
        spooled=spooled,
        parse_errors=tail_read.parse_errors,
        spool_bytes=spool.size_bytes(),
        source_offset=(
            tail_read.checkpoint.offset
            if checkpoint_committed
            else tail_read.previous_offset
        ),
        spool_parse_errors=spool_parse_errors,
        rotation_detected=tail_read.rotation_detected,
        truncation_detected=tail_read.truncation_detected,
        disk_limited=disk_limited,
        quarantined=quarantined,
        quarantine_evicted=quarantine_evicted,
        quarantine_bytes=quarantine_bytes,
    )


def _forward_once_unlocked(config: ProductionConfig) -> ForwardResult:
    tailer = CowrieLogTailer(config.cowrie_log_path, f"{config.spool_path}.offset")
    spool = DiskSpool(config.spool_path)
    quarantine_path = str(
        getattr(config, "forwarder_quarantine_path", "")
        or f"{config.spool_path}.quarantine.ndjson"
    )
    quarantine = RejectedEventQuarantine(quarantine_path)
    batch_size = max(int(config.forwarder_batch_size), 1)
    max_line_bytes = int(getattr(config, "forwarder_max_line_bytes", DEFAULT_MAX_LINE_BYTES))
    tail_read = tailer.prepare_new_events(limit=batch_size, max_line_bytes=max_line_bytes)

    try:
        spooled = spool.append_many(
            tail_read.events,
            max_spool_bytes=int(
                getattr(config, "forwarder_max_spool_bytes", DEFAULT_MAX_SPOOL_BYTES)
            ),
            min_free_bytes=int(
                getattr(config, "forwarder_min_free_bytes", DEFAULT_MIN_FREE_BYTES)
            ),
        )
    except SpoolCapacityError as exc:
        # The offset deliberately remains unchanged so Cowrie remains the
        # authoritative source after operators restore capacity.
        return _result(
            spool,
            tail_read,
            error=_safe_exception_text(exc),
            disk_limited=True,
            checkpoint_committed=False,
        )
    except OSError as exc:
        return _result(
            spool,
            tail_read,
            error=_safe_exception_text(exc),
            checkpoint_committed=False,
        )

    if tail_read.commit_required:
        try:
            # This commit is strictly after the spool data fsync.
            tailer.commit(tail_read.checkpoint)
        except OSError as exc:
            return _result(
                spool,
                tail_read,
                spooled=spooled,
                error=_safe_exception_text(exc),
                checkpoint_committed=False,
            )

    events, remaining_lines = spool.load_batch(batch_size)
    spool_parse_errors = sum(
        1 for event in events if event.get("eventid") == "forwarder.spool_parse_error"
    )
    if not events:
        return _result(
            spool,
            tail_read,
            spooled=spooled,
            spool_parse_errors=spool_parse_errors,
        )

    try:
        response = post_events(config, events)
    except Exception as exc:
        return _result(
            spool,
            tail_read,
            spooled=spooled,
            error=_safe_exception_text(exc),
            spool_parse_errors=spool_parse_errors,
        )

    if not isinstance(response, dict):
        return _result(
            spool,
            tail_read,
            spooled=spooled,
            error="ingest returned an invalid response object",
            spool_parse_errors=spool_parse_errors,
        )

    try:
        accepted = max(int(response.get("accepted", len(events))), 0)
        duplicates = max(int(response.get("duplicates", 0)), 0)
    except (TypeError, ValueError):
        return _result(
            spool,
            tail_read,
            spooled=spooled,
            error="ingest returned invalid acknowledgement counts",
            spool_parse_errors=spool_parse_errors,
        )

    rejected_items = response.get("rejected", [])
    if not isinstance(rejected_items, list):
        return _result(
            spool,
            tail_read,
            sent=accepted,
            duplicates=duplicates,
            spooled=spooled,
            error="ingest returned an invalid rejected-event list",
            spool_parse_errors=spool_parse_errors,
        )

    rejected_count = len(rejected_items)
    accounted = accepted + duplicates + rejected_count
    if accounted != len(events):
        return _result(
            spool,
            tail_read,
            sent=accepted,
            duplicates=duplicates,
            rejected=rejected_count,
            spooled=spooled,
            spool_parse_errors=spool_parse_errors,
            error=(
                "ingest acknowledgement mismatch: "
                f"batch={len(events)} accepted={accepted} duplicates={duplicates} "
                f"rejected={rejected_count}"
            ),
        )

    rejected_indexes: List[int] = []
    for item in rejected_items:
        if not isinstance(item, dict) or not isinstance(item.get("index"), int):
            return _result(
                spool,
                tail_read,
                sent=accepted,
                duplicates=duplicates,
                rejected=rejected_count,
                spooled=spooled,
                error="ingest rejected events without usable batch indexes",
                spool_parse_errors=spool_parse_errors,
            )
        index = int(item["index"])
        if index < 0 or index >= len(events) or index in rejected_indexes:
            return _result(
                spool,
                tail_read,
                sent=accepted,
                duplicates=duplicates,
                rejected=rejected_count,
                spooled=spooled,
                error="ingest returned invalid or duplicate rejected-event indexes",
                spool_parse_errors=spool_parse_errors,
            )
        rejected_indexes.append(index)

    rejected_pairs = [
        (events[int(item["index"])], item)
        for item in sorted(rejected_items, key=lambda item: int(item["index"]))
    ]
    quarantine_evicted = 0
    if rejected_pairs:
        try:
            _, quarantine_evicted = quarantine.append_rejected(
                sensor_id=str(config.sensor_id),
                rejected=rejected_pairs,
                max_bytes=int(
                    getattr(
                        config,
                        "forwarder_max_quarantine_bytes",
                        DEFAULT_MAX_QUARANTINE_BYTES,
                    )
                ),
                max_events=int(
                    getattr(
                        config,
                        "forwarder_max_quarantine_events",
                        DEFAULT_MAX_QUARANTINE_EVENTS,
                    )
                ),
            )
        except OSError as exc:
            # Do not shorten the spool unless every rejected row has first
            # reached durable quarantine. Accepted rows may replay as harmless
            # duplicates after the operator restores quarantine capacity.
            return _result(
                spool,
                tail_read,
                sent=accepted,
                duplicates=duplicates,
                rejected=rejected_count,
                spooled=spooled,
                error=_safe_exception_text(exc),
                spool_parse_errors=spool_parse_errors,
            )
    rewritten = list(remaining_lines)
    try:
        # The durable spool is only shortened after a complete acknowledgement.
        spool.replace_remaining(rewritten)
    except OSError as exc:
        return _result(
            spool,
            tail_read,
            sent=accepted,
            duplicates=duplicates,
            rejected=rejected_count,
            spooled=spooled,
            error=_safe_exception_text(exc),
            spool_parse_errors=spool_parse_errors,
            quarantined=rejected_count,
            quarantine_evicted=quarantine_evicted,
            quarantine_bytes=quarantine.size_bytes(),
        )
    return _result(
        spool,
        tail_read,
        sent=accepted,
        duplicates=duplicates,
        rejected=rejected_count,
        spooled=spooled,
        spool_parse_errors=spool_parse_errors,
        quarantined=rejected_count,
        quarantine_evicted=quarantine_evicted,
        quarantine_bytes=quarantine.size_bytes(),
        error=(
            f"{rejected_count} event(s) rejected by ingest and quarantined"
            if rejected_count
            else ""
        ),
    )


def forward_once(config: ProductionConfig) -> ForwardResult:
    spool = DiskSpool(config.spool_path)
    try:
        with ForwarderInstanceLock(config.spool_path):
            return _forward_once_unlocked(config)
    except BlockingIOError:
        return ForwardResult(
            sent=0,
            remaining=spool.count(),
            error="forwarder instance lock is held",
            spool_bytes=spool.size_bytes(),
            lock_contended=True,
        )


def _log_result(result: ForwardResult) -> None:
    print(
        json.dumps(
            {"service": "sensor_forwarder", **result.__dict__, "timestamp": utc_now()},
            sort_keys=True,
        ),
        flush=True,
    )


def _forwarder_status_signature(result: ForwardResult) -> Tuple[Any, ...]:
    return (
        result.remaining,
        result.error,
        result.spool_bytes,
        result.lock_contended,
        result.disk_limited,
    )


def run_forever(
    config: ProductionConfig,
    lifecycle: Optional[ServiceLifecycle] = None,
) -> None:
    # Hold the process lock across sleeps so a second service instance fails
    # closed instead of alternating access to the same cursor and spool.
    control = lifecycle or ServiceLifecycle()
    previous_status: Optional[Tuple[Any, ...]] = None
    last_status_log = 0.0
    try:
        with control.signal_handlers():
            with ForwarderInstanceLock(config.spool_path):
                while not control.stopping:
                    result = _forward_once_unlocked(config)
                    current_status = _forwarder_status_signature(result)
                    now = time.monotonic()
                    activity = bool(
                        result.sent
                        or result.spooled
                        or result.duplicates
                        or result.rejected
                        or result.spool_parse_errors
                        or result.error
                    )
                    if (
                        activity
                        or current_status != previous_status
                        or now - last_status_log >= 60.0
                    ):
                        _log_result(result)
                        previous_status = current_status
                        last_status_log = now
                    control.wait(config.forwarder_poll_seconds)
    except BlockingIOError as exc:
        raise SystemExit("sensor forwarder instance already running") from exc


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Forward Cowrie NDJSON events to the cloud ingest API.")
    parser.add_argument("--config", help="Path to production JSON config.")
    parser.add_argument("--once", action="store_true", help="Run one poll/flush cycle and exit.")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    config = ProductionConfig.from_env(args.config)
    if not config.api_token:
        raise SystemExit("HONEYPOT_API_TOKEN or api_token is required for sensor forwarding.")
    if args.once:
        result = forward_once(config)
        print(json.dumps(result.__dict__, sort_keys=True))
        return 0 if not result.error else 1
    run_forever(config)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
