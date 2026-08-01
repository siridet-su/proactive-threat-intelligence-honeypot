"""Versioned, integrity-checked Cowrie output rollback receipts."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence


SCHEMA_VERSION = "cowrie_output_rollback_receipt.v2"
RECEIPT_NAME = "managed-paths.jsonl"
DIGEST_NAME = "managed-paths.jsonl.sha256"
LEGACY_NAME = "managed-paths.tsv"
MAX_RECEIPT_BYTES = 16 * 1024 * 1024
MAX_RECORDS = 100_000
KINDS = frozenset({"absent", "file", "metadata", "quarantine", "symlink"})
ENTRY_KEYS = frozenset(
    {
        "record_type",
        "kind",
        "target",
        "present",
        "saved",
        "saved_bytes",
        "saved_sha256",
        "mode",
        "uid",
        "gid",
    }
)


class RollbackReceiptError(RuntimeError):
    """A rollback receipt cannot be proven safe or complete."""


@dataclass(frozen=True)
class RollbackRecord:
    kind: str
    target: Path
    present: bool
    saved: str | None = None
    saved_bytes: int | None = None
    saved_sha256: str | None = None
    mode: int | None = None
    uid: int | None = None
    gid: int | None = None


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _regular_metadata(path: Path) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise RollbackReceiptError(f"rollback path is unavailable: {path}") from exc
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
        raise RollbackReceiptError(f"rollback path is not a regular file: {path}")
    return metadata


def _secure_receipt_directory(path: Path, expected_uid: int) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise RollbackReceiptError("rollback receipt directory is unavailable") from exc
    if not stat.S_ISDIR(metadata.st_mode) or path.is_symlink():
        raise RollbackReceiptError("rollback receipt path is not a directory")
    if stat.S_IMODE(metadata.st_mode) != 0o700 or metadata.st_uid != expected_uid:
        raise RollbackReceiptError("rollback receipt directory boundary is invalid")


def _secure_receipt_file(path: Path, expected_uid: int) -> os.stat_result:
    metadata = _regular_metadata(path)
    if stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_uid != expected_uid:
        raise RollbackReceiptError("rollback receipt file boundary is invalid")
    if metadata.st_size > MAX_RECEIPT_BYTES:
        raise RollbackReceiptError("rollback receipt exceeds its size limit")
    return metadata


def _validate_target(path: Path, allowed_roots: Sequence[Path]) -> Path:
    text = str(path)
    if (
        not path.is_absolute()
        or not text
        or len(text.encode("utf-8")) > 4096
        or any(ord(character) < 32 for character in text)
        or "\\" in text
        or ".." in path.parts
    ):
        raise RollbackReceiptError("rollback target path is invalid")
    normalized = Path(os.path.normpath(text))
    if normalized != path:
        raise RollbackReceiptError("rollback target path is not normalized")
    matched_root = next(
        (
            root
            for root in allowed_roots
            if normalized == root or normalized.is_relative_to(root)
        ),
        None,
    )
    if matched_root is None:
        raise RollbackReceiptError("rollback target is outside the managed boundary")
    if normalized == matched_root:
        if normalized.parent.resolve() != matched_root.parent.resolve():
            raise RollbackReceiptError("rollback target parent escapes the managed boundary")
    elif not normalized.parent.resolve().is_relative_to(matched_root.resolve()):
        raise RollbackReceiptError("rollback target parent escapes the managed boundary")
    return normalized


def _validate_saved_name(value: str) -> str:
    if (
        not value
        or len(value.encode("utf-8")) > 255
        or value != Path(value).name
        or any(ord(character) < 32 for character in value)
        or "\\" in value
    ):
        raise RollbackReceiptError("rollback saved-file name is invalid")
    return value


def _saved_receipt(path: Path) -> tuple[int, str]:
    metadata = _regular_metadata(path)
    return metadata.st_size, _sha256(path)


def _metadata_record(kind: str, target: Path, *, saved: str | None = None) -> RollbackRecord:
    try:
        metadata = target.lstat()
    except FileNotFoundError:
        return RollbackRecord(kind=kind, target=target, present=False, saved=saved)
    if not stat.S_ISREG(metadata.st_mode) or target.is_symlink():
        raise RollbackReceiptError(f"managed path is not a regular file: {target}")
    saved_bytes = None
    saved_sha256 = None
    if kind == "quarantine":
        saved_bytes, saved_sha256 = _saved_receipt(target)
    return RollbackRecord(
        kind=kind,
        target=target,
        present=True,
        saved=saved,
        saved_bytes=saved_bytes,
        saved_sha256=saved_sha256,
        mode=stat.S_IMODE(metadata.st_mode),
        uid=metadata.st_uid,
        gid=metadata.st_gid,
    )


def _copy_record(target: Path, saved: str, receipt_dir: Path) -> RollbackRecord:
    try:
        metadata = target.lstat()
    except FileNotFoundError:
        return RollbackRecord(kind="absent", target=target, present=False)
    if stat.S_ISLNK(metadata.st_mode):
        link_target = os.readlink(target)
        if len(link_target.encode("utf-8")) > 4096 or any(
            ord(character) < 32 for character in link_target
        ):
            raise RollbackReceiptError("managed symlink target is invalid")
        return RollbackRecord(
            kind="symlink",
            target=target,
            present=True,
            saved=link_target,
            mode=stat.S_IMODE(metadata.st_mode),
            uid=metadata.st_uid,
            gid=metadata.st_gid,
        )
    if not stat.S_ISREG(metadata.st_mode):
        raise RollbackReceiptError(f"managed path has an unsupported type: {target}")
    saved_name = _validate_saved_name(saved)
    destination = receipt_dir / saved_name
    if destination.exists() or destination.is_symlink():
        raise RollbackReceiptError("rollback saved-file path already exists")
    shutil.copyfile(target, destination)
    os.chown(destination, os.geteuid(), os.getegid())
    destination.chmod(0o600)
    saved_bytes, saved_sha256 = _saved_receipt(destination)
    return RollbackRecord(
        kind="file",
        target=target,
        present=True,
        saved=saved_name,
        saved_bytes=saved_bytes,
        saved_sha256=saved_sha256,
        mode=stat.S_IMODE(metadata.st_mode),
        uid=metadata.st_uid,
        gid=metadata.st_gid,
    )


def _record_document(record: RollbackRecord) -> dict[str, Any]:
    return {
        "record_type": "entry",
        "kind": record.kind,
        "target": str(record.target),
        "present": record.present,
        "saved": record.saved,
        "saved_bytes": record.saved_bytes,
        "saved_sha256": record.saved_sha256,
        "mode": record.mode,
        "uid": record.uid,
        "gid": record.gid,
    }


def write_receipt(receipt_dir: Path, records: Sequence[RollbackRecord]) -> tuple[Path, str]:
    target = receipt_dir / RECEIPT_NAME
    digest_path = receipt_dir / DIGEST_NAME
    if target.exists() or target.is_symlink() or digest_path.exists() or digest_path.is_symlink():
        raise RollbackReceiptError("rollback receipt is non-overwriting")
    header = {
        "record_type": "header",
        "schema_version": SCHEMA_VERSION,
        "record_count": len(records),
    }
    documents = [header, *(_record_document(record) for record in records)]
    payload = b"".join(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
        + b"\n"
        for document in documents
    )
    if len(payload) > MAX_RECEIPT_BYTES:
        raise RollbackReceiptError("rollback receipt exceeds its size limit")
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short rollback receipt write")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    digest = hashlib.sha256(payload).hexdigest()
    descriptor = os.open(digest_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        payload = f"{digest}  {RECEIPT_NAME}\n".encode("ascii")
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short rollback digest write")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return target, digest


def capture_receipt(
    *,
    receipt_dir: Path,
    cowrie_root: Path,
    users_file: Path,
    current: Path,
    config: Path,
    plugin: Path,
    drop_in: Path,
    logrotate: Path,
) -> tuple[list[RollbackRecord], str]:
    expected_uid = os.geteuid()
    _secure_receipt_directory(receipt_dir, expected_uid)
    log_dir = cowrie_root / "var/log/cowrie"
    records = [
        _copy_record(config, "cowrie.cfg.before", receipt_dir),
        _copy_record(plugin, "sanitizedjson.py.before", receipt_dir),
        _copy_record(drop_in, "20-sanitized-output.conf.before", receipt_dir),
        _copy_record(logrotate, "cowrie.logrotate.before", receipt_dir),
        _copy_record(current, "current.before", receipt_dir),
        _metadata_record("metadata", users_file),
        _metadata_record("metadata", log_dir / "cowrie_custom.json"),
        _metadata_record("metadata", log_dir / "cowrie.json"),
        _metadata_record(
            "quarantine", log_dir / "cowrie.log", saved="cowrie.log.protected.before"
        ),
    ]
    excluded = {
        log_dir / "cowrie_custom.json",
        log_dir / "cowrie.json",
        log_dir / "cowrie.log",
    }
    if log_dir.exists():
        for path in sorted(log_dir.rglob("*"), key=lambda item: str(item)):
            if path in excluded:
                continue
            metadata = path.lstat()
            if stat.S_ISDIR(metadata.st_mode):
                continue
            records.append(_metadata_record("metadata", path))
    allowed_roots = managed_roots(
        cowrie_root=cowrie_root,
        users_file=users_file,
        current=current,
        drop_in=drop_in,
        logrotate=logrotate,
    )
    _validate_records(records, allowed_roots=allowed_roots)
    _, digest = write_receipt(receipt_dir, records)
    return records, digest


def managed_roots(
    *,
    cowrie_root: Path,
    users_file: Path,
    current: Path,
    drop_in: Path,
    logrotate: Path,
) -> tuple[Path, ...]:
    return (
        cowrie_root / "etc",
        cowrie_root / "src/cowrie/output",
        cowrie_root / "var/log/cowrie",
        users_file,
        current,
        drop_in,
        logrotate,
    )


def _parse_int(value: Any, field: str, maximum: int) -> int | None:
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= maximum:
        raise RollbackReceiptError(f"rollback {field} is invalid")
    return value


def _record_from_document(document: Any) -> RollbackRecord:
    if not isinstance(document, dict) or set(document) != ENTRY_KEYS:
        raise RollbackReceiptError("rollback entry keys are invalid")
    if document["record_type"] != "entry" or document["kind"] not in KINDS:
        raise RollbackReceiptError("rollback entry kind is invalid")
    if not isinstance(document["target"], str) or not isinstance(document["present"], bool):
        raise RollbackReceiptError("rollback entry target or presence is invalid")
    saved = document["saved"]
    if saved is not None and not isinstance(saved, str):
        raise RollbackReceiptError("rollback saved value is invalid")
    saved_sha256 = document["saved_sha256"]
    if saved_sha256 is not None and (
        not isinstance(saved_sha256, str)
        or len(saved_sha256) != 64
        or any(character not in "0123456789abcdef" for character in saved_sha256)
    ):
        raise RollbackReceiptError("rollback saved SHA-256 is invalid")
    return RollbackRecord(
        kind=document["kind"],
        target=Path(document["target"]),
        present=document["present"],
        saved=saved,
        saved_bytes=_parse_int(document["saved_bytes"], "saved bytes", 1 << 63),
        saved_sha256=saved_sha256,
        mode=_parse_int(document["mode"], "mode", 0o7777),
        uid=_parse_int(document["uid"], "uid", 1 << 31),
        gid=_parse_int(document["gid"], "gid", 1 << 31),
    )


def _validate_records(
    records: Sequence[RollbackRecord], *, allowed_roots: Sequence[Path]
) -> None:
    if len(records) > MAX_RECORDS:
        raise RollbackReceiptError("rollback receipt has too many records")
    targets: set[Path] = set()
    saved_names: set[str] = set()
    for record in records:
        if record.kind not in KINDS:
            raise RollbackReceiptError("rollback entry kind is invalid")
        target = _validate_target(record.target, allowed_roots)
        if target in targets:
            raise RollbackReceiptError("rollback receipt contains duplicate targets")
        targets.add(target)
        if record.kind == "absent":
            if record.present or any(
                value is not None
                for value in (
                    record.saved,
                    record.saved_bytes,
                    record.saved_sha256,
                    record.mode,
                    record.uid,
                    record.gid,
                )
            ):
                raise RollbackReceiptError("absent rollback entry is inconsistent")
            continue
        if record.kind == "metadata" and not record.present:
            if any(
                value is not None
                for value in (
                    record.saved,
                    record.saved_bytes,
                    record.saved_sha256,
                    record.mode,
                    record.uid,
                    record.gid,
                )
            ):
                raise RollbackReceiptError("absent metadata entry is inconsistent")
            continue
        if record.kind == "quarantine" and not record.present:
            if record.saved is None or any(
                value is not None
                for value in (
                    record.saved_bytes,
                    record.saved_sha256,
                    record.mode,
                    record.uid,
                    record.gid,
                )
            ):
                raise RollbackReceiptError("absent quarantine entry is inconsistent")
            _validate_saved_name(record.saved)
            continue
        if not record.present:
            raise RollbackReceiptError("present rollback entry is inconsistent")
        if record.mode is None or record.uid is None or record.gid is None:
            raise RollbackReceiptError("rollback metadata is incomplete")
        if record.kind in {"file", "quarantine"}:
            if (
                record.saved is None
                or record.saved_bytes is None
                or record.saved_sha256 is None
            ):
                raise RollbackReceiptError("rollback saved-file receipt is incomplete")
            saved = _validate_saved_name(record.saved)
            if saved in saved_names:
                raise RollbackReceiptError("rollback saved-file name is duplicated")
            saved_names.add(saved)
        elif record.kind == "symlink":
            if record.saved is None or any(
                value is not None for value in (record.saved_bytes, record.saved_sha256)
            ):
                raise RollbackReceiptError("rollback symlink receipt is invalid")
            if len(record.saved.encode("utf-8")) > 4096 or any(
                ord(character) < 32 for character in record.saved
            ):
                raise RollbackReceiptError("rollback symlink value is invalid")
        elif any(
            value is not None
            for value in (record.saved, record.saved_bytes, record.saved_sha256)
        ):
            raise RollbackReceiptError("metadata rollback entry has saved-file fields")


def _parse_digest(path: Path) -> str:
    text = path.read_text(encoding="ascii")
    parts = text.rstrip("\n").split("  ")
    if (
        len(parts) != 2
        or parts[1] != RECEIPT_NAME
        or len(parts[0]) != 64
        or any(character not in "0123456789abcdef" for character in parts[0])
    ):
        raise RollbackReceiptError("rollback receipt digest is invalid")
    return parts[0]


def _load_v2(
    receipt_dir: Path, *, expected_uid: int, allowed_roots: Sequence[Path]
) -> tuple[list[RollbackRecord], str]:
    receipt_path = receipt_dir / RECEIPT_NAME
    digest_path = receipt_dir / DIGEST_NAME
    _secure_receipt_file(receipt_path, expected_uid)
    _secure_receipt_file(digest_path, expected_uid)
    raw = receipt_path.read_bytes()
    observed_digest = hashlib.sha256(raw).hexdigest()
    if _parse_digest(digest_path) != observed_digest:
        raise RollbackReceiptError("rollback receipt digest mismatch")
    lines = raw.splitlines()
    if not lines:
        raise RollbackReceiptError("rollback receipt is empty")
    try:
        documents = [json.loads(line) for line in lines]
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RollbackReceiptError("rollback receipt JSON is invalid") from exc
    header = documents[0]
    if (
        not isinstance(header, dict)
        or set(header) != {"record_type", "schema_version", "record_count"}
        or header["record_type"] != "header"
        or header["schema_version"] != SCHEMA_VERSION
        or not isinstance(header["record_count"], int)
        or isinstance(header["record_count"], bool)
        or header["record_count"] != len(documents) - 1
    ):
        raise RollbackReceiptError("rollback receipt header is invalid")
    records = [_record_from_document(document) for document in documents[1:]]
    _validate_records(records, allowed_roots=allowed_roots)
    return records, observed_digest


def _legacy_fields(raw_line: bytes) -> list[str]:
    if b"\t" in raw_line:
        fields = raw_line.split(b"\t")
    elif b"\\t" in raw_line:
        fields = raw_line.split(b"\\t")
        if any(b"\\" in field for field in fields):
            raise RollbackReceiptError("legacy literal-tab receipt is ambiguous")
    else:
        raise RollbackReceiptError("legacy rollback delimiter is missing")
    try:
        decoded = [field.decode("utf-8") for field in fields]
    except UnicodeDecodeError as exc:
        raise RollbackReceiptError("legacy rollback receipt is not UTF-8") from exc
    if any(any(ord(character) < 32 for character in field) for field in decoded):
        raise RollbackReceiptError("legacy rollback field contains control data")
    return decoded


def _legacy_metadata(kind: str, fields: list[str], receipt_dir: Path) -> RollbackRecord:
    expected = 6 if kind in {"file", "metadata", "quarantine"} else 0
    if len(fields) != expected:
        raise RollbackReceiptError("legacy rollback field count is invalid")
    target = Path(fields[1])
    saved = fields[2] if fields[2] != "-" else None
    try:
        mode = int(fields[3], 8)
        uid = int(fields[4])
        gid = int(fields[5])
    except ValueError as exc:
        raise RollbackReceiptError("legacy rollback metadata is invalid") from exc
    saved_bytes = None
    saved_sha256 = None
    if kind in {"file", "quarantine"}:
        if saved is None:
            raise RollbackReceiptError("legacy rollback saved file is missing")
        saved_path = receipt_dir / _validate_saved_name(saved)
        saved_bytes, saved_sha256 = _saved_receipt(saved_path)
    return RollbackRecord(
        kind=kind,
        target=target,
        present=True,
        saved=saved,
        saved_bytes=saved_bytes,
        saved_sha256=saved_sha256,
        mode=mode,
        uid=uid,
        gid=gid,
    )


def _load_legacy(
    receipt_dir: Path, *, expected_uid: int, allowed_roots: Sequence[Path]
) -> tuple[list[RollbackRecord], str]:
    receipt_path = receipt_dir / LEGACY_NAME
    _secure_receipt_file(receipt_path, expected_uid)
    raw = receipt_path.read_bytes()
    records: list[RollbackRecord] = []
    for raw_line in raw.splitlines():
        if not raw_line:
            raise RollbackReceiptError("legacy rollback receipt contains an empty entry")
        fields = _legacy_fields(raw_line)
        kind = fields[0] if fields else ""
        if kind in {"file", "metadata", "quarantine"}:
            records.append(_legacy_metadata(kind, fields, receipt_dir))
        elif kind == "symlink" and len(fields) == 3:
            records.append(
                RollbackRecord(
                    kind="symlink",
                    target=Path(fields[1]),
                    present=True,
                    saved=fields[2],
                    mode=0o777,
                    uid=expected_uid,
                    gid=os.getegid(),
                )
            )
        elif kind == "absent" and len(fields) == 2:
            records.append(
                RollbackRecord(kind="absent", target=Path(fields[1]), present=False)
            )
        elif kind == "absent-metadata" and len(fields) == 2:
            records.append(
                RollbackRecord(kind="metadata", target=Path(fields[1]), present=False)
            )
        else:
            raise RollbackReceiptError("legacy rollback entry is invalid")
    _validate_records(records, allowed_roots=allowed_roots)
    return records, hashlib.sha256(raw).hexdigest()


def load_receipt(
    receipt_dir: Path,
    *,
    expected_uid: int,
    allowed_roots: Sequence[Path],
) -> tuple[list[RollbackRecord], str, str]:
    _secure_receipt_directory(receipt_dir, expected_uid)
    if (receipt_dir / RECEIPT_NAME).exists():
        records, digest = _load_v2(
            receipt_dir, expected_uid=expected_uid, allowed_roots=allowed_roots
        )
        return records, digest, SCHEMA_VERSION
    if (receipt_dir / LEGACY_NAME).exists():
        records, digest = _load_legacy(
            receipt_dir, expected_uid=expected_uid, allowed_roots=allowed_roots
        )
        return records, digest, "cowrie_output_rollback_receipt.legacy_tsv"
    raise RollbackReceiptError("no supported rollback receipt is present")


def _verify_saved_files(
    records: Iterable[RollbackRecord],
    receipt_dir: Path,
    *,
    allow_pending_quarantine: bool,
    expected_uid: int,
    require_private_owner: bool,
) -> None:
    for record in records:
        if record.kind not in {"file", "quarantine"} or not record.present:
            continue
        assert record.saved is not None
        path = receipt_dir / _validate_saved_name(record.saved)
        if record.kind == "quarantine" and allow_pending_quarantine and not path.exists():
            continue
        metadata = _regular_metadata(path)
        if require_private_owner and (
            stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_uid != expected_uid
        ):
            raise RollbackReceiptError("rollback saved-file boundary is invalid")
        size, digest = metadata.st_size, _sha256(path)
        if size != record.saved_bytes or digest != record.saved_sha256:
            raise RollbackReceiptError("rollback saved-file receipt mismatch")


def verify_receipt(
    receipt_dir: Path,
    *,
    expected_uid: int,
    allowed_roots: Sequence[Path],
    allow_pending_quarantine: bool = False,
) -> tuple[list[RollbackRecord], str, str]:
    records, digest, schema = load_receipt(
        receipt_dir, expected_uid=expected_uid, allowed_roots=allowed_roots
    )
    _verify_saved_files(
        records,
        receipt_dir,
        allow_pending_quarantine=allow_pending_quarantine,
        expected_uid=expected_uid,
        require_private_owner=schema == SCHEMA_VERSION,
    )
    return records, digest, schema


def _preflight_target(record: RollbackRecord, receipt_dir: Path) -> None:
    target = record.target
    if record.kind == "metadata" and record.present:
        _regular_metadata(target)
    elif record.kind == "absent" and (target.exists() or target.is_symlink()):
        metadata = target.lstat()
        if not (stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode)):
            raise RollbackReceiptError("rollback refuses to remove an unexpected type")
    elif record.kind == "quarantine":
        if target.exists() or target.is_symlink():
            _regular_metadata(target)
        failed = receipt_dir / f"{target.name}.failed-deployment"
        if (target.exists() or target.is_symlink()) and (failed.exists() or failed.is_symlink()):
            raise RollbackReceiptError("failed-deployment preservation path exists")
    elif record.kind == "symlink" and (target.exists() or target.is_symlink()):
        metadata = target.lstat()
        if not (stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode)):
            raise RollbackReceiptError("rollback refuses to replace an unexpected type")


def _install_saved(record: RollbackRecord, receipt_dir: Path) -> None:
    assert record.saved is not None
    assert record.mode is not None and record.uid is not None and record.gid is not None
    source = receipt_dir / record.saved
    target = record.target
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{target.name}.rollback.", dir=target.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output, source.open("rb") as input_file:
            shutil.copyfileobj(input_file, output)
            output.flush()
            os.fsync(output.fileno())
        os.chown(temporary, record.uid, record.gid)
        temporary.chmod(record.mode)
        os.replace(temporary, target)
    finally:
        if temporary.exists():
            temporary.unlink()


def _apply_record(record: RollbackRecord, receipt_dir: Path) -> None:
    target = record.target
    if record.kind == "absent":
        if target.exists() or target.is_symlink():
            target.unlink()
    elif record.kind == "file":
        _install_saved(record, receipt_dir)
    elif record.kind == "metadata":
        if record.present:
            assert record.mode is not None and record.uid is not None and record.gid is not None
            os.chown(target, record.uid, record.gid)
            target.chmod(record.mode)
    elif record.kind == "quarantine":
        failed = receipt_dir / f"{target.name}.failed-deployment"
        if target.exists() or target.is_symlink():
            os.replace(target, failed)
            os.chown(failed, os.geteuid(), os.getegid())
            failed.chmod(0o600)
        if record.present:
            assert record.saved is not None
            source = receipt_dir / record.saved
            os.replace(source, target)
            assert record.mode is not None and record.uid is not None and record.gid is not None
            os.chown(target, record.uid, record.gid)
            target.chmod(record.mode)
    elif record.kind == "symlink":
        assert record.saved is not None
        temporary = target.with_name(f".{target.name}.rollback-link")
        if temporary.exists() or temporary.is_symlink():
            raise RollbackReceiptError("temporary rollback symlink already exists")
        temporary.symlink_to(record.saved)
        if record.uid is not None and record.gid is not None:
            os.lchown(temporary, record.uid, record.gid)
        os.replace(temporary, target)


def _verify_applied(record: RollbackRecord, receipt_dir: Path) -> None:
    target = record.target
    if record.kind == "absent":
        if target.exists() or target.is_symlink():
            raise RollbackReceiptError("absent rollback target was not removed")
    elif record.kind == "symlink":
        if not target.is_symlink() or os.readlink(target) != record.saved:
            raise RollbackReceiptError("rollback symlink was not restored")
    elif record.kind == "metadata" and not record.present:
        return
    elif record.kind == "quarantine" and not record.present:
        return
    else:
        metadata = _regular_metadata(target)
        if (
            (record.mode is not None and stat.S_IMODE(metadata.st_mode) != record.mode)
            or (record.uid is not None and metadata.st_uid != record.uid)
            or (record.gid is not None and metadata.st_gid != record.gid)
        ):
            raise RollbackReceiptError("rollback metadata was not restored")
        if record.kind in {"file", "quarantine"} and record.present:
            if metadata.st_size != record.saved_bytes or _sha256(target) != record.saved_sha256:
                raise RollbackReceiptError("rollback content was not restored")


def apply_receipt(
    receipt_dir: Path,
    *,
    expected_uid: int,
    allowed_roots: Sequence[Path],
) -> tuple[int, str, str]:
    records, digest, schema = verify_receipt(
        receipt_dir, expected_uid=expected_uid, allowed_roots=allowed_roots
    )
    for record in records:
        _preflight_target(record, receipt_dir)
    ordered = sorted(records, key=lambda record: record.kind == "symlink")
    for record in ordered:
        _apply_record(record, receipt_dir)
    for record in records:
        _verify_applied(record, receipt_dir)
    return len(records), digest, schema


def _paths_from_args(args: argparse.Namespace) -> tuple[Path, ...]:
    return managed_roots(
        cowrie_root=Path(args.cowrie_root),
        users_file=Path(args.users_file),
        current=Path(args.current),
        drop_in=Path(args.drop_in),
        logrotate=Path(args.logrotate),
    )


def _add_boundary_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--receipt", required=True)
    parser.add_argument("--cowrie-root", required=True)
    parser.add_argument("--users-file", required=True)
    parser.add_argument("--current", required=True)
    parser.add_argument("--drop-in", required=True)
    parser.add_argument("--logrotate", required=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Manage Cowrie rollback receipts")
    commands = parser.add_subparsers(dest="command", required=True)
    capture = commands.add_parser("capture")
    _add_boundary_arguments(capture)
    capture.add_argument("--config", required=True)
    capture.add_argument("--plugin", required=True)
    for name in ("verify", "apply"):
        _add_boundary_arguments(commands.add_parser(name))
    args = parser.parse_args()
    receipt = Path(args.receipt)
    allowed_roots = _paths_from_args(args)
    try:
        if args.command == "capture":
            records, digest = capture_receipt(
                receipt_dir=receipt,
                cowrie_root=Path(args.cowrie_root),
                users_file=Path(args.users_file),
                current=Path(args.current),
                config=Path(args.config),
                plugin=Path(args.plugin),
                drop_in=Path(args.drop_in),
                logrotate=Path(args.logrotate),
            )
            schema = SCHEMA_VERSION
        elif args.command == "verify":
            records, digest, schema = verify_receipt(
                receipt,
                expected_uid=os.geteuid(),
                allowed_roots=allowed_roots,
            )
        else:
            count, digest, schema = apply_receipt(
                receipt,
                expected_uid=os.geteuid(),
                allowed_roots=allowed_roots,
            )
            records = [None] * count  # type: ignore[list-item]
    except (OSError, RollbackReceiptError, ValueError) as exc:
        print(
            json.dumps(
                {
                    "schema_version": "cowrie_output_rollback_operation.v1",
                    "status": "invalid",
                    "operation": args.command,
                    "error_category": type(exc).__name__,
                },
                sort_keys=True,
            )
        )
        return 2
    print(
        json.dumps(
            {
                "schema_version": "cowrie_output_rollback_operation.v1",
                "status": "valid",
                "operation": args.command,
                "receipt_schema": schema,
                "receipt_sha256": digest,
                "records": len(records),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
