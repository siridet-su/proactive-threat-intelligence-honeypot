"""Copy-only MongoDB cold-archive implementation.

The module deliberately contains no MongoDB write operation.  It can read a
bounded, deterministically ordered selection, serialize the stored BSON value
as canonical Extended JSON, compress it with zstd, and verify the resulting
archive before publishing an immutable manifest and append-only catalog entry.

Deletion is represented only by a guarded purge candidate.  There is no
delete path in this module; a future deletion implementation must consume the
candidate and satisfy every guard documented by :func:`validate_purge_candidate`.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping, Sequence
from urllib.parse import urlsplit


ARCHIVE_FORMAT_VERSION = "mongo_pi_cold_archive.ejsonl.zst.v1"
MANIFEST_VERSION = "mongo_pi_archive_manifest.v1"
VERIFICATION_RECEIPT_VERSION = "mongo_pi_archive_verification_receipt.v1"
CATALOG_VERSION = "mongo_pi_archive_catalog_entry.v1"
PURGE_CANDIDATE_VERSION = "mongo_pi_archive_purge_candidate.v1"
TOOL_VERSION = "mongo-pi-cold-archive/1.0.0"
DEFAULT_ZSTD_LEVEL = 3
DEFAULT_MAX_RECORDS = 1_000_000
DEFAULT_MAX_LINE_BYTES = 32 * 1024 * 1024
DEFAULT_PI_RESERVE_BYTES = 10 * 1024 * 1024 * 1024
SENSITIVE_KEY_RE = re.compile(
    r"(?:password|passwd|passphrase|token|secret|private[_-]?key|"
    r"authorization|credential|api[_-]?key|access[_-]?key|refresh[_-]?token|"
    r"raw[_-]?(?:event|payload))",
    re.IGNORECASE,
)
SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class ArchiveError(RuntimeError):
    """Base class for fail-closed archive errors."""


class ArchiveDependencyError(ArchiveError):
    pass


class ArchiveIDConflict(ArchiveError):
    pass


class ArchiveVerificationError(ArchiveError):
    pass


class ArchivePrivacyError(ArchiveError):
    pass


class ArchiveCapacityError(ArchiveError):
    pass


class PurgeSafetyError(ArchiveError):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _stable_json(value: Any) -> str:
    """Stable JSON for already JSON-safe archive metadata."""

    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _require_bson() -> tuple[Any, Any, Any]:
    try:
        from bson.json_util import (  # type: ignore[import-not-found]
            CANONICAL_JSON_OPTIONS,
            dumps,
            loads,
        )
    except ImportError as exc:  # pragma: no cover - exercised on SQLite-only hosts.
        raise ArchiveDependencyError(
            "PyMongo bson.json_util is required for canonical BSON archive format"
        ) from exc
    return dumps, loads, CANONICAL_JSON_OPTIONS


def canonical_ejson_dumps(value: Any) -> str:
    """Serialize one BSON value in canonical Extended JSON, deterministically."""

    dumps, _, options = _require_bson()
    return dumps(
        value,
        json_options=options,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    )


def canonical_ejson_loads(value: str | bytes) -> Any:
    """Parse one canonical Extended JSON value."""

    _, loads, options = _require_bson()
    return loads(value, json_options=options)


def canonical_ejson_object(value: Any) -> Any:
    """Return a JSON-safe canonical EJSON object for manifests and receipts."""

    return json.loads(canonical_ejson_dumps(value))


def _read_json(path: str | Path) -> dict[str, Any]:
    selected = Path(path)
    try:
        metadata = selected.lstat()
    except OSError as exc:
        raise ArchiveError(f"metadata file unavailable: {selected}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ArchiveError(f"metadata file must be a regular non-symlink file: {selected}")
    try:
        value = json.loads(selected.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ArchiveError(f"metadata file is unreadable: {selected}") from exc
    if not isinstance(value, dict):
        raise ArchiveError(f"metadata file must contain an object: {selected}")
    return value


def _write_immutable_json(path: Path, value: Mapping[str, Any]) -> bool:
    """Create one restrictive JSON file without replacing an existing receipt."""

    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.parent.chmod(0o700)
    encoded = (_stable_json(dict(value)) + "\n").encode("utf-8")
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
        )
    except FileExistsError:
        try:
            existing = _read_json(path)
        except ArchiveError as exc:
            raise ArchiveIDConflict(f"immutable metadata path is not readable: {path}") from exc
        if existing != dict(value):
            raise ArchiveIDConflict(f"immutable metadata conflict: {path}")
        return False
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        if descriptor != -1:
            os.close(descriptor)
    _fsync_directory(path.parent)
    return True


def write_immutable_json(path: str | Path, value: Mapping[str, Any]) -> bool:
    """Public wrapper for restrictive, create-once JSON receipts."""

    return _write_immutable_json(Path(path), value)


def _fsync_directory(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def ensure_archive_root(root: str | Path, *, create: bool = True) -> Path:
    """Create/check one dedicated archive root and its private subdirectories."""

    selected = Path(root)
    if not selected.is_absolute():
        raise ArchiveError("archive root must be an absolute path")
    if selected.exists() and selected.is_symlink():
        raise ArchiveError("archive root must not be a symlink")
    if create:
        selected.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not selected.is_dir():
        raise ArchiveError("archive root must be a directory")
    selected.chmod(0o700)
    for name in ("archives", "manifests", "receipts", "purge_candidates", ".staging"):
        child = selected / name
        if child.exists() and child.is_symlink():
            raise ArchiveError(f"archive directory must not be a symlink: {child}")
        if create:
            child.mkdir(mode=0o700, exist_ok=True)
        if not child.is_dir():
            raise ArchiveError(f"archive path is not a directory: {child}")
        child.chmod(0o700)
    return selected


def archive_paths(root: str | Path, archive_id: str) -> dict[str, Path]:
    selected = ensure_archive_root(root)
    if not SAFE_NAME_RE.fullmatch(archive_id):
        raise ArchiveError("archive ID contains unsafe path characters")
    return {
        "archive": selected / "archives" / f"{archive_id}.ejsonl.zst",
        "manifest": selected / "manifests" / f"{archive_id}.manifest.json",
        "receipt": selected / "receipts" / f"{archive_id}.verification.json",
        "purge_candidate": selected / "purge_candidates" / f"{archive_id}.purge.json",
        "catalog": selected / "catalog.jsonl",
    }


def _validate_metadata_string(value: Any, name: str, *, max_length: int = 255) -> str:
    selected = str(value or "").strip()
    if (
        not selected
        or len(selected) > max_length
        or any(ord(character) < 0x20 for character in selected)
    ):
        raise ArchiveError(f"{name} is invalid")
    return selected


def _validate_safe_host(value: Any) -> str:
    host = _validate_metadata_string(value, "source SRV hostname").lower()
    if host != str(value).strip() or not host.endswith(".mongodb.net"):
        raise ArchiveError("source SRV hostname must be a lowercase mongodb.net hostname")
    if any(character in host for character in ("@", "/", "?", "#")):
        raise ArchiveError("source SRV hostname contains unsafe characters")
    return host


def _validate_query_metadata(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ArchiveError("query predicate must be an object")
    # Canonical EJSON conversion also rejects unsupported BSON values and
    # proves that the query is representable in the immutable manifest.
    converted = canonical_ejson_object(dict(value))
    if not isinstance(converted, dict):
        raise ArchiveError("query predicate must serialize as an object")
    return converted


@dataclass(frozen=True)
class ArchiveSpec:
    """One bounded archive selection and its non-secret source identity."""

    project_id: str
    cluster_id: str
    cluster_name: str
    srv_hostname: str
    database: str
    collection: str
    query: Mapping[str, Any]
    sort: tuple[tuple[str, int], ...]
    limit: int | None
    provenance: str
    schema_info: Mapping[str, Any] = field(default_factory=dict)
    source_epoch: str = "LEGACY_TARGET_A_NO_CANONICAL_EPOCH"
    tool_version: str = TOOL_VERSION

    def __post_init__(self) -> None:
        for name, value in (
            ("project_id", self.project_id),
            ("cluster_id", self.cluster_id),
            ("cluster_name", self.cluster_name),
            ("database", self.database),
            ("collection", self.collection),
            ("provenance", self.provenance),
        ):
            _validate_metadata_string(value, name)
        _validate_safe_host(self.srv_hostname)
        if not SAFE_NAME_RE.fullmatch(self.collection):
            raise ArchiveError("collection name contains unsafe characters")
        if not self.sort:
            raise ArchiveError("a deterministic sort is required")
        fields: set[str] = set()
        for field_name, direction in self.sort:
            _validate_metadata_string(field_name, "sort field", max_length=255)
            if direction not in (-1, 1):
                raise ArchiveError("sort direction must be -1 or 1")
            if field_name in fields:
                raise ArchiveError("sort fields must be unique")
            fields.add(field_name)
        if self.limit is not None and (
            self.limit <= 0 or self.limit > DEFAULT_MAX_RECORDS
        ):
            raise ArchiveError("archive limit is outside the bounded range")
        _validate_query_metadata(self.query)
        if not isinstance(self.schema_info, Mapping):
            raise ArchiveError("schema_info must be an object")

    @property
    def sort_list(self) -> list[list[Any]]:
        return [[field_name, direction] for field_name, direction in self.sort]

    def source_target(self) -> dict[str, str]:
        return {
            "project_id": self.project_id,
            "cluster_id": self.cluster_id,
            "cluster_name": self.cluster_name,
            "srv_hostname": self.srv_hostname,
            "database": self.database,
            "collection": self.collection,
            "storage_epoch": self.source_epoch,
        }


@dataclass(frozen=True)
class ArchivePlan:
    spec: ArchiveSpec
    source_match_count: int
    documents: tuple[Mapping[str, Any], ...]
    first_sort_key: Mapping[str, Any]
    last_sort_key: Mapping[str, Any]
    first_document_id: Any
    last_document_id: Any

    @property
    def selected_count(self) -> int:
        return len(self.documents)


def _field_value(document: Mapping[str, Any], path: str) -> Any:
    current: Any = document
    for part in path.split("."):
        if not isinstance(current, Mapping) or part not in current:
            raise ArchiveVerificationError(f"sort field is absent: {path}")
        current = current[part]
    return current


def _sort_key(document: Mapping[str, Any], spec: ArchiveSpec) -> dict[str, Any]:
    return {
        field_name: canonical_ejson_object(_field_value(document, field_name))
        for field_name, _ in spec.sort
    }


def _sort_key_text(document: Mapping[str, Any], spec: ArchiveSpec) -> tuple[str, ...]:
    return tuple(
        canonical_ejson_dumps(_field_value(document, field_name))
        for field_name, _ in spec.sort
    )


def _records_digest(documents: Iterable[Mapping[str, Any]]) -> str:
    digest = hashlib.sha256()
    for document in documents:
        digest.update((canonical_ejson_dumps(document) + "\n").encode("utf-8"))
    return digest.hexdigest()


def plan_archive(collection: Any, spec: ArchiveSpec) -> ArchivePlan:
    """Read and freeze one bounded selection without changing MongoDB."""

    source_match_count = int(collection.count_documents(dict(spec.query)))
    cursor = collection.find(dict(spec.query))
    cursor = cursor.sort(spec.sort_list)
    if spec.limit is not None:
        cursor = cursor.limit(spec.limit)
    documents = tuple(cursor)
    if not documents:
        raise ArchiveError("archive selection is empty")
    for document in documents:
        if not isinstance(document, Mapping) or "_id" not in document:
            raise ArchiveVerificationError("every archived document must contain _id")
    return ArchivePlan(
        spec=spec,
        source_match_count=source_match_count,
        documents=documents,
        first_sort_key=_sort_key(documents[0], spec),
        last_sort_key=_sort_key(documents[-1], spec),
        first_document_id=documents[0]["_id"],
        last_document_id=documents[-1]["_id"],
    )


def _archive_identity(plan: ArchivePlan) -> dict[str, Any]:
    return {
        "format": ARCHIVE_FORMAT_VERSION,
        "source": plan.spec.source_target(),
        "query_predicate": _validate_query_metadata(plan.spec.query),
        "sort": plan.spec.sort_list,
        "limit": plan.spec.limit,
        "source_match_count": plan.source_match_count,
        "selected_count": plan.selected_count,
        "first_sort_key": dict(plan.first_sort_key),
        "last_sort_key": dict(plan.last_sort_key),
        "first_document_id": canonical_ejson_object(plan.first_document_id),
        "last_document_id": canonical_ejson_object(plan.last_document_id),
        "provenance": plan.spec.provenance,
    }


def build_archive_id(plan: ArchivePlan) -> str:
    """Build a stable content/selection-bound ID; it is not timestamp-only."""

    return "mongoarc_" + _sha256_bytes(_stable_json(_archive_identity(plan)).encode())[:40]


def _scan_sensitive_value(value: Any, *, path: str = "$") -> tuple[int, int]:
    fields = 0
    nonempty = 0
    if isinstance(value, Mapping):
        for key, child in value.items():
            key_text = str(key)
            child_path = f"{path}.{key_text}"
            if SENSITIVE_KEY_RE.search(key_text):
                fields += 1
                if child not in (None, "", [], {}, b""):
                    nonempty += 1
            nested_fields, nested_nonempty = _scan_sensitive_value(child, path=child_path)
            fields += nested_fields
            nonempty += nested_nonempty
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            nested_fields, nested_nonempty = _scan_sensitive_value(
                child, path=f"{path}[{index}]"
            )
            fields += nested_fields
            nonempty += nested_nonempty
    return fields, nonempty


def privacy_scan_documents(documents: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    field_count = 0
    nonempty_count = 0
    document_count = 0
    for document in documents:
        document_count += 1
        fields, nonempty = _scan_sensitive_value(document)
        field_count += fields
        nonempty_count += nonempty
    result = {
        "documents_scanned": document_count,
        "sensitive_field_occurrences": field_count,
        "nonempty_sensitive_field_occurrences": nonempty_count,
        "status": "PASS" if nonempty_count == 0 else "REVIEW_REQUIRED",
        "stored_representation_redacted_or_reintroduced": False,
    }
    if nonempty_count:
        raise ArchivePrivacyError(
            "archive selection contains nonempty credential/secret-shaped fields"
        )
    return result


def _zstd_compress(source: Path, destination: Path, *, binary: str = "zstd") -> None:
    try:
        result = subprocess.run(
            [binary, "-q", "-T0", f"-{DEFAULT_ZSTD_LEVEL}", "-f", "-o", str(destination), str(source)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as exc:
        raise ArchiveDependencyError("zstd executable is unavailable") from exc
    if result.returncode != 0:
        raise ArchiveError("zstd compression failed")


def _zstd_lines(path: Path, *, binary: str = "zstd") -> Iterator[bytes]:
    try:
        process = subprocess.Popen(
            [binary, "-q", "-d", "-c", str(path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as exc:
        raise ArchiveDependencyError("zstd executable is unavailable") from exc
    assert process.stdout is not None
    assert process.stderr is not None
    try:
        for line in process.stdout:
            yield line
        process.stdout.close()
        process.stderr.read(4096)
        return_code = process.wait()
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
    if return_code != 0:
        raise ArchiveVerificationError("zstd decompression failed or archive is truncated")


def _copy_fsync(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        descriptor = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
        )
    except FileExistsError as exc:
        raise ArchiveIDConflict(f"archive partial path already exists: {destination}") from exc
    try:
        with source.open("rb") as source_handle, os.fdopen(descriptor, "wb") as destination_handle:
            descriptor = -1
            shutil.copyfileobj(source_handle, destination_handle, length=1024 * 1024)
            destination_handle.flush()
            os.fsync(destination_handle.fileno())
    finally:
        if descriptor != -1:
            os.close(descriptor)
    _fsync_directory(destination.parent)


def _path_is_private_regular(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ArchiveVerificationError(f"archive file is unavailable: {path}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ArchiveVerificationError("archive file must be a regular non-symlink file")
    if metadata.st_mode & 0o077:
        raise ArchiveVerificationError("archive file grants group or other permissions")


def verify_archive_file(
    path: str | Path,
    *,
    spec: ArchiveSpec,
    expected_count: int,
    expected_sha256: str | None = None,
    expected_records_sha256: str | None = None,
    expected_first_sort_key: Mapping[str, Any] | None = None,
    expected_last_sort_key: Mapping[str, Any] | None = None,
    expected_first_document_id: Any | None = None,
    expected_last_document_id: Any | None = None,
    zstd_binary: str = "zstd",
) -> dict[str, Any]:
    """Verify bytes, zstd integrity, EJSON parsing, count, order, and IDs."""

    selected = Path(path)
    _path_is_private_regular(selected)
    compressed_bytes = selected.stat().st_size
    actual_sha256 = sha256_file(selected)
    if expected_sha256 and actual_sha256 != expected_sha256:
        raise ArchiveVerificationError("compressed archive SHA-256 mismatch")
    count = 0
    uncompressed_bytes = 0
    records_digest = hashlib.sha256()
    seen_ids: set[str] = set()
    previous_sort_key: tuple[str, ...] | None = None
    first_sort_key: Mapping[str, Any] | None = None
    last_sort_key: Mapping[str, Any] | None = None
    first_id: Any = None
    last_id: Any = None
    for line in _zstd_lines(selected, binary=zstd_binary):
        if len(line) > DEFAULT_MAX_LINE_BYTES:
            raise ArchiveVerificationError("archive record line exceeds safety bound")
        if not line.endswith(b"\n"):
            raise ArchiveVerificationError("archive stream is truncated at a record boundary")
        payload = line[:-1]
        if not payload:
            raise ArchiveVerificationError("archive contains a blank record")
        try:
            document = canonical_ejson_loads(payload)
        except Exception as exc:  # BSON parser error types vary by PyMongo version.
            raise ArchiveVerificationError("archive contains invalid canonical EJSON") from exc
        if not isinstance(document, Mapping) or "_id" not in document:
            raise ArchiveVerificationError("archive record is not a BSON document with _id")
        identity = canonical_ejson_dumps(document["_id"])
        if identity in seen_ids:
            raise ArchiveVerificationError("archive contains a duplicate document ID")
        seen_ids.add(identity)
        current_sort_key = _sort_key_text(document, spec)
        if previous_sort_key is not None:
            for index, (_, direction) in enumerate(spec.sort):
                left = previous_sort_key[index]
                right = current_sort_key[index]
                if direction == 1 and left > right:
                    raise ArchiveVerificationError("archive records are not in deterministic sort order")
                if direction == -1 and left < right:
                    raise ArchiveVerificationError("archive records are not in deterministic sort order")
                if left != right:
                    break
        previous_sort_key = current_sort_key
        if count == 0:
            first_sort_key = _sort_key(document, spec)
            first_id = document["_id"]
        last_sort_key = _sort_key(document, spec)
        last_id = document["_id"]
        count += 1
        uncompressed_bytes += len(line)
        records_digest.update(line)
    if count != expected_count:
        raise ArchiveVerificationError(
            f"archive record count mismatch: expected {expected_count}, got {count}"
        )
    actual_records_sha256 = records_digest.hexdigest()
    if expected_records_sha256 and actual_records_sha256 != expected_records_sha256:
        raise ArchiveVerificationError("uncompressed record SHA-256 mismatch")
    if expected_first_sort_key is not None and dict(first_sort_key or {}) != dict(expected_first_sort_key):
        raise ArchiveVerificationError("archive first sort boundary mismatch")
    if expected_last_sort_key is not None and dict(last_sort_key or {}) != dict(expected_last_sort_key):
        raise ArchiveVerificationError("archive last sort boundary mismatch")
    if expected_first_document_id is not None and canonical_ejson_dumps(first_id) != canonical_ejson_dumps(expected_first_document_id):
        raise ArchiveVerificationError("archive first document boundary mismatch")
    if expected_last_document_id is not None and canonical_ejson_dumps(last_id) != canonical_ejson_dumps(expected_last_document_id):
        raise ArchiveVerificationError("archive last document boundary mismatch")
    return {
        "verified": True,
        "archive_status": "VERIFIED",
        "record_count": count,
        "duplicate_id_count": 0,
        "parse_error_count": 0,
        "truncated": False,
        "uncompressed_bytes": uncompressed_bytes,
        "compressed_bytes": compressed_bytes,
        "sha256": actual_sha256,
        "records_sha256": actual_records_sha256,
        "first_sort_key": dict(first_sort_key or {}),
        "last_sort_key": dict(last_sort_key or {}),
        "first_document_id": canonical_ejson_object(first_id),
        "last_document_id": canonical_ejson_object(last_id),
    }


def _self_hash(value: Mapping[str, Any], field_name: str) -> str:
    payload = {key: item for key, item in value.items() if key != field_name}
    return _sha256_bytes(_stable_json(payload).encode("utf-8"))


def _load_existing_verified(
    paths: Mapping[str, Path],
    *,
    spec: ArchiveSpec,
    archive_id: str,
) -> dict[str, Any] | None:
    if not paths["archive"].exists():
        return None
    if not paths["manifest"].exists() or not paths["receipt"].exists():
        raise ArchiveIDConflict("archive exists without immutable verified metadata")
    manifest = _read_json(paths["manifest"])
    receipt = _read_json(paths["receipt"])
    if manifest.get("archive_id") != archive_id or manifest.get("archive_status") != "VERIFIED":
        raise ArchiveIDConflict("archive ID is bound to a non-verified or different manifest")
    if receipt.get("archive_id") != archive_id or receipt.get("archive_status") != "VERIFIED":
        raise ArchiveIDConflict("archive ID is bound to a non-verified receipt")
    if manifest.get("manifest_sha256") != _self_hash(manifest, "manifest_sha256"):
        raise ArchiveVerificationError("existing manifest self-hash mismatch")
    if receipt.get("receipt_sha256") != _self_hash(receipt, "receipt_sha256"):
        raise ArchiveVerificationError("existing verification receipt self-hash mismatch")
    verify = verify_archive_file(
        paths["archive"],
        spec=spec,
        expected_count=int(manifest["selected_count"]),
        expected_sha256=str(manifest["sha256"]),
        expected_records_sha256=str(manifest["records_sha256"]),
        expected_first_sort_key=manifest["first_sort_key"],
        expected_last_sort_key=manifest["last_sort_key"],
        expected_first_document_id=canonical_ejson_loads(
            _stable_json(manifest["first_document_id"])
        ),
        expected_last_document_id=canonical_ejson_loads(
            _stable_json(manifest["last_document_id"])
        ),
    )
    catalog_found = False
    try:
        with paths["catalog"].open("r", encoding="utf-8") as catalog:
            for raw_line in catalog:
                if not raw_line.strip():
                    continue
                entry = json.loads(raw_line)
                if (
                    entry.get("archive_id") == archive_id
                    and entry.get("archive_status") == "VERIFIED"
                    and entry.get("sha256") == manifest.get("sha256")
                    and entry.get("manifest_sha256") == manifest.get("manifest_sha256")
                ):
                    catalog_found = True
                    break
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ArchiveVerificationError("verified archive catalog is unavailable") from exc
    if not catalog_found:
        raise ArchiveVerificationError("verified archive has no matching catalog entry")
    return {
        "status": "ALREADY_VERIFIED",
        "archive_id": archive_id,
        "manifest": manifest,
        "verification": verify,
        "receipt": receipt,
        "paths": {key: str(value) for key, value in paths.items()},
    }


def _append_catalog_entry(root: Path, entry: Mapping[str, Any]) -> bool:
    path = root / "catalog.jsonl"
    if path.is_symlink():
        raise ArchiveError("archive catalog must not be a symlink")
    path.touch(mode=0o600, exist_ok=True)
    path.chmod(0o600)
    encoded = (_stable_json(dict(entry)) + "\n").encode("utf-8")
    try:
        import fcntl  # Unix Pi/cloud runtime.
    except ImportError:  # pragma: no cover
        fcntl = None
    with path.open("a+b") as handle:
        if fcntl is not None:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            handle.seek(0)
            existing = []
            for raw_line in handle:
                if raw_line.strip():
                    existing.append(json.loads(raw_line))
            for item in existing:
                if item.get("archive_id") == entry.get("archive_id"):
                    if item != dict(entry):
                        raise ArchiveIDConflict("archive catalog entry conflicts with existing ID")
                    return False
            handle.seek(0, os.SEEK_END)
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        finally:
            if fcntl is not None:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    _fsync_directory(root)
    return True


def export_archive(
    collection: Any,
    spec: ArchiveSpec,
    archive_root: str | Path,
    *,
    plan: ArchivePlan | None = None,
    zstd_binary: str = "zstd",
    source_count_after: int | None = None,
) -> dict[str, Any]:
    """Export one frozen selection and publish it only after full verification."""

    root = ensure_archive_root(archive_root)
    selected_plan = plan or plan_archive(collection, spec)
    if selected_plan.spec != spec:
        raise ArchiveError("archive plan/spec mismatch")
    archive_id = build_archive_id(selected_plan)
    paths = archive_paths(root, archive_id)
    existing = _load_existing_verified(paths, spec=spec, archive_id=archive_id)
    if existing is not None:
        return existing

    privacy = privacy_scan_documents(selected_plan.documents)
    stage_directory = Path(tempfile.mkdtemp(prefix=f"{archive_id}.", dir=root / ".staging"))
    uncompressed = stage_directory / f"{archive_id}.ejsonl"
    compressed = stage_directory / f"{archive_id}.ejsonl.zst"
    try:
        records_digest = hashlib.sha256()
        with uncompressed.open("xb") as handle:
            for document in selected_plan.documents:
                line = (canonical_ejson_dumps(document) + "\n").encode("utf-8")
                handle.write(line)
                records_digest.update(line)
            handle.flush()
            os.fsync(handle.fileno())
        _zstd_compress(uncompressed, compressed, binary=zstd_binary)
        selected_source_count_after = (
            int(collection.count_documents(dict(spec.query)))
            if source_count_after is None
            else int(source_count_after)
        )
        if selected_source_count_after != selected_plan.source_match_count:
            raise ArchiveVerificationError(
                "source match count changed during copy; archive is not publishable"
            )
        stable_cursor = collection.find(dict(spec.query)).sort(spec.sort_list)
        if spec.limit is not None:
            stable_cursor = stable_cursor.limit(spec.limit)
        stable_documents = tuple(stable_cursor)
        if len(stable_documents) != selected_plan.selected_count or _records_digest(
            stable_documents
        ) != records_digest.hexdigest():
            raise ArchiveVerificationError(
                "source selection changed during copy; archive is not publishable"
            )
        partial = paths["archive"].with_suffix(paths["archive"].suffix + ".partial")
        _copy_fsync(compressed, partial)
        verification = verify_archive_file(
            partial,
            spec=spec,
            expected_count=selected_plan.selected_count,
            expected_sha256=sha256_file(compressed),
            expected_records_sha256=records_digest.hexdigest(),
            expected_first_sort_key=selected_plan.first_sort_key,
            expected_last_sort_key=selected_plan.last_sort_key,
            expected_first_document_id=selected_plan.first_document_id,
            expected_last_document_id=selected_plan.last_document_id,
            zstd_binary=zstd_binary,
        )
        if paths["archive"].exists():
            raise ArchiveIDConflict("archive final path appeared during publish")
        os.replace(partial, paths["archive"])
        os.chmod(paths["archive"], 0o600)
        _fsync_directory(paths["archive"].parent)
        manifest: dict[str, Any] = {
            "schema_version": MANIFEST_VERSION,
            "archive_format": ARCHIVE_FORMAT_VERSION,
            "archive_id": archive_id,
            "archive_status": "VERIFIED",
            "archive_path": str(paths["archive"]),
            "manifest_path": str(paths["manifest"]),
            "receipt_path": str(paths["receipt"]),
            "provenance": spec.provenance,
            "source_target": spec.source_target(),
            "query_predicate": _validate_query_metadata(spec.query),
            "sort": spec.sort_list,
            "limit": spec.limit,
            "source_match_count_before": selected_plan.source_match_count,
            "source_match_count_after": selected_source_count_after,
            "source_selection_stable": True,
            "source_selection_records_sha256": records_digest.hexdigest(),
            "selected_count": selected_plan.selected_count,
            "first_sort_key": dict(selected_plan.first_sort_key),
            "last_sort_key": dict(selected_plan.last_sort_key),
            "first_document_id": canonical_ejson_object(selected_plan.first_document_id),
            "last_document_id": canonical_ejson_object(selected_plan.last_document_id),
            "uncompressed_bytes": verification["uncompressed_bytes"],
            "compressed_bytes": verification["compressed_bytes"],
            "compression_ratio": round(
                verification["compressed_bytes"] / verification["uncompressed_bytes"], 8
            ),
            "sha256": verification["sha256"],
            "records_sha256": verification["records_sha256"],
            "serialization": "canonical_extended_json_one_document_per_line",
            "compression": "zstd",
            "created_at": utc_now(),
            "verified_at": utc_now(),
            "tool_version": spec.tool_version,
            "schema_info": dict(spec.schema_info),
            "privacy": privacy,
            "verification_gate": {
                "transfer_complete": True,
                "readable": True,
                "sha256_match": True,
                "decompressed": True,
                "every_record_parsed": True,
                "count_match": True,
                "boundaries_match": True,
                "duplicate_id_count": 0,
                "truncated": False,
                "catalog_entry_required_before_verified_use": True,
            },
            "manifest_sha256": "",
        }
        manifest["manifest_sha256"] = _self_hash(manifest, "manifest_sha256")
        _write_immutable_json(paths["manifest"], manifest)
        receipt: dict[str, Any] = {
            "schema_version": VERIFICATION_RECEIPT_VERSION,
            "archive_id": archive_id,
            "archive_status": "VERIFIED",
            "manifest_sha256": manifest["manifest_sha256"],
            "archive_sha256": verification["sha256"],
            "records_sha256": verification["records_sha256"],
            "record_count": verification["record_count"],
            "verified_at": manifest["verified_at"],
            "verification": verification,
            "catalog_entry": "append_only_after_receipt_creation",
            "credential_exposure": False,
            "mutations_performed": False,
            "source_documents_deleted": 0,
            "receipt_sha256": "",
        }
        receipt["receipt_sha256"] = _self_hash(receipt, "receipt_sha256")
        _write_immutable_json(paths["receipt"], receipt)
        catalog_entry = {
            "schema_version": CATALOG_VERSION,
            "archive_id": archive_id,
            "archive_status": "VERIFIED",
            "archive_path": str(paths["archive"]),
            "manifest_path": str(paths["manifest"]),
            "receipt_path": str(paths["receipt"]),
            "record_count": verification["record_count"],
            "sha256": verification["sha256"],
            "records_sha256": verification["records_sha256"],
            "manifest_sha256": manifest["manifest_sha256"],
            "cataloged_at": utc_now(),
        }
        catalog_added = _append_catalog_entry(root, catalog_entry)
        return {
            "status": "VERIFIED",
            "archive_id": archive_id,
            "manifest": manifest,
            "verification": verification,
            "receipt": receipt,
            "catalog_entry": catalog_entry,
            "catalog_added": catalog_added,
            "paths": {key: str(value) for key, value in paths.items()},
        }
    finally:
        shutil.rmtree(stage_directory, ignore_errors=True)


def read_archive_verified(
    archive_path: str | Path,
    *,
    manifest: Mapping[str, Any],
    zstd_binary: str = "zstd",
) -> dict[str, Any]:
    """Offline restore/read validation; it never writes to MongoDB."""

    source = manifest["source_target"]
    spec = ArchiveSpec(
        project_id=str(source["project_id"]),
        cluster_id=str(source["cluster_id"]),
        cluster_name=str(source["cluster_name"]),
        srv_hostname=str(source["srv_hostname"]),
        database=str(source["database"]),
        collection=str(source["collection"]),
        query=canonical_ejson_loads(_stable_json(manifest["query_predicate"])),
        sort=tuple((str(item[0]), int(item[1])) for item in manifest["sort"]),
        limit=manifest.get("limit"),
        provenance=str(manifest["provenance"]),
        schema_info=dict(manifest.get("schema_info") or {}),
        source_epoch=str(source.get("storage_epoch") or ""),
        tool_version=str(manifest.get("tool_version") or TOOL_VERSION),
    )
    result = verify_archive_file(
        archive_path,
        spec=spec,
        expected_count=int(manifest["selected_count"]),
        expected_sha256=str(manifest["sha256"]),
        expected_records_sha256=str(manifest["records_sha256"]),
        expected_first_sort_key=manifest["first_sort_key"],
        expected_last_sort_key=manifest["last_sort_key"],
        expected_first_document_id=canonical_ejson_loads(
            _stable_json(manifest["first_document_id"])
        ),
        expected_last_document_id=canonical_ejson_loads(
            _stable_json(manifest["last_document_id"])
        ),
        zstd_binary=zstd_binary,
    )
    return {
        "schema_version": "mongo_pi_archive_restore_read_test.v1",
        "archive_id": manifest["archive_id"],
        "restore_target": "OFFLINE_READ_ONLY_NO_MONGODB_RESTORE",
        "success": True,
        "record_count": result["record_count"],
        "sha256": result["sha256"],
        "records_sha256": result["records_sha256"],
        "first_document_id": result["first_document_id"],
        "last_document_id": result["last_document_id"],
        "source_mutations": 0,
    }


def create_purge_candidate(
    manifest: Mapping[str, Any],
    *,
    output_path: str | Path | None = None,
    lifecycle_gate: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Create a receipt that proposes, but cannot execute, source deletion."""

    if manifest.get("archive_status") != "VERIFIED":
        raise PurgeSafetyError("purge candidate requires archive_status=VERIFIED")
    gates = dict(lifecycle_gate or {})
    candidate: dict[str, Any] = {
        "schema_version": PURGE_CANDIDATE_VERSION,
        "candidate_status": "CANDIDATE_ONLY",
        "archive_id": manifest["archive_id"],
        "archive_status": manifest["archive_status"],
        "source_target": manifest["source_target"],
        "exact_deletion_predicate": manifest["query_predicate"],
        "selection_order": manifest["sort"],
        "selection_limit": manifest.get("limit"),
        "exact_selection_boundaries": {
            "first_sort_key": manifest["first_sort_key"],
            "last_sort_key": manifest["last_sort_key"],
            "first_document_id": manifest["first_document_id"],
            "last_document_id": manifest["last_document_id"],
        },
        "expected_source_count": manifest["selected_count"],
        "expected_records_sha256": manifest["records_sha256"],
        "lifecycle_gate": gates,
        "required_guards": [
            "archive_status=VERIFIED",
            "archive_id is explicitly supplied",
            "source project/cluster/host/database/collection exact match",
            "source count equals expected_source_count",
            "records_sha256 equals immutable manifest",
            "exact immutable predicate and boundaries",
            "explicit operator confirmation",
            "post-delete source count and archive verification",
        ],
        "purge_executed": False,
        "documents_deleted": 0,
        "force_or_skip_verify": False,
        "credential_exposure": False,
        "mutations_performed": False,
        "created_at": utc_now(),
        "candidate_sha256": "",
    }
    candidate["candidate_sha256"] = _self_hash(candidate, "candidate_sha256")
    if output_path is not None:
        _write_immutable_json(Path(output_path), candidate)
    return candidate


def validate_purge_candidate(
    candidate: Mapping[str, Any],
    manifest: Mapping[str, Any],
    *,
    target: Mapping[str, Any],
    current_source_count: int,
    explicit_confirmation: bool = False,
) -> None:
    """Validate every future purge guard without performing the deletion."""

    if candidate.get("candidate_status") != "CANDIDATE_ONLY":
        raise PurgeSafetyError("only candidate-only receipts may enter the purge guard")
    if manifest.get("archive_status") != "VERIFIED":
        raise PurgeSafetyError("source deletion is impossible before VERIFIED")
    if candidate.get("archive_id") != manifest.get("archive_id"):
        raise PurgeSafetyError("archive ID mismatch")
    if candidate.get("source_target") != manifest.get("source_target"):
        raise PurgeSafetyError("source target mismatch")
    if dict(target) != dict(manifest["source_target"]):
        raise PurgeSafetyError("current target does not exactly match archive target")
    if int(current_source_count) != int(candidate["expected_source_count"]):
        raise PurgeSafetyError("source count mismatch")
    if candidate.get("force_or_skip_verify"):
        raise PurgeSafetyError("force/skip-verify is prohibited")
    if not explicit_confirmation:
        raise PurgeSafetyError("explicit purge confirmation is required")
    if candidate.get("mutations_performed") is not False:
        raise PurgeSafetyError("candidate receipt is not immutable copy-only state")


def redacted_uri_metadata(uri: str) -> dict[str, Any]:
    """Return safe URI metadata without user, password, or query options."""

    try:
        parsed = urlsplit(uri)
    except ValueError as exc:
        raise ArchiveError("Mongo URI is malformed") from exc
    if parsed.scheme not in {"mongodb", "mongodb+srv"}:
        raise ArchiveError("Mongo URI scheme is unsupported")
    host = parsed.hostname or ""
    if not host:
        raise ArchiveError("Mongo URI host is unavailable")
    database = parsed.path.lstrip("/").split("/", 1)[0]
    return {
        "scheme": parsed.scheme,
        "host": host.lower(),
        "database": database or None,
        "credential_exposed": False,
    }


def _parse_env_text(raw: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            continue
        try:
            parsed = shlex.split(value, comments=False, posix=True)
            values[key] = parsed[0] if parsed else ""
        except ValueError:
            values[key] = value.strip("\"'")
    return values


def read_protected_env_value(path: str | Path, key: str) -> str:
    """Read one existing protected env file through sudo into process memory."""

    selected = str(path)
    try:
        result = subprocess.run(
            ["sudo", "-n", "cat", selected],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
        )
    except OSError as exc:
        raise ArchiveError("protected env reader is unavailable") from exc
    if result.returncode != 0:
        raise ArchiveError("protected env file cannot be read")
    value = _parse_env_text(result.stdout).get(key, "").strip()
    if not value:
        raise ArchiveError(f"protected env key is unavailable: {key}")
    return value


def read_private_uri_file(path: str | Path) -> str:
    selected = Path(path)
    try:
        metadata = selected.lstat()
    except OSError as exc:
        raise ArchiveError("Mongo URI file is unavailable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ArchiveError("Mongo URI file must be a regular non-symlink file")
    if metadata.st_mode & 0o077 or metadata.st_size > 64 * 1024:
        raise ArchiveError("Mongo URI file has unsafe permissions or size")
    value = selected.read_text(encoding="utf-8").strip()
    if not value:
        raise ArchiveError("Mongo URI file is empty")
    return value


def load_uri_and_database(
    *,
    uri_file: str | Path | None = None,
    protected_env_files: Sequence[str | Path] = (),
    database: str | None = None,
) -> tuple[str, str]:
    """Load credentials without exposing them in argv, output, or artifacts."""

    uri = read_private_uri_file(uri_file) if uri_file else ""
    selected_database = str(database or "").strip()
    for env_file in protected_env_files:
        values: dict[str, str] = {}
        for key in ("MONGO_URI", "MONGO_DATABASE"):
            try:
                values[key] = read_protected_env_value(env_file, key)
            except ArchiveError:
                continue
        uri = uri or values.get("MONGO_URI", "")
        selected_database = selected_database or values.get("MONGO_DATABASE", "")
    if not uri:
        raise ArchiveError("no protected Mongo URI source was supplied")
    if not selected_database:
        uri_database = redacted_uri_metadata(uri).get("database")
        selected_database = str(uri_database or "")
    if not selected_database:
        raise ArchiveError("Mongo database is not configured")
    # Validate only safe metadata; never include URI in the returned error.
    redacted_uri_metadata(uri)
    return uri, selected_database


def connect_readonly(uri: str, *, timeout_ms: int = 10_000) -> Any:
    try:
        from pymongo import MongoClient  # type: ignore[import-not-found]
    except ImportError as exc:  # pragma: no cover
        raise ArchiveDependencyError("PyMongo is required for live archive reads") from exc
    client = MongoClient(uri, serverSelectionTimeoutMS=timeout_ms, connectTimeoutMS=timeout_ms)
    client.admin.command("ping")
    return client


def filesystem_capacity(path: str | Path) -> dict[str, Any]:
    selected = Path(path)
    usage = shutil.disk_usage(selected)
    filesystem = None
    try:
        probe = subprocess.run(
            ["findmnt", "-T", str(selected), "-no", "FSTYPE"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
        )
        if probe.returncode == 0:
            filesystem = probe.stdout.strip() or None
    except OSError:
        filesystem = None
    return {
        "path": str(selected),
        "total_bytes": usage.total,
        "used_bytes": usage.used,
        "free_bytes": usage.free,
        "used_ratio": round(usage.used / usage.total, 8) if usage.total else None,
        "filesystem": filesystem,
    }


def pi_capacity_gate(
    capacity: Mapping[str, Any],
    archive_bytes: int,
    *,
    reserve_bytes: int = DEFAULT_PI_RESERVE_BYTES,
    max_used_ratio: float = 0.90,
) -> dict[str, Any]:
    free = int(capacity["free_bytes"])
    total = int(capacity["total_bytes"])
    used = int(capacity["used_bytes"])
    projected_used = used + int(archive_bytes)
    projected_ratio = projected_used / total if total else 1.0
    passed = free - archive_bytes >= reserve_bytes and projected_ratio <= max_used_ratio
    result = {
        "passed": passed,
        "free_before_bytes": free,
        "archive_bytes_required": int(archive_bytes),
        "reserve_bytes": int(reserve_bytes),
        "free_after_bytes": free - int(archive_bytes),
        "projected_used_bytes": projected_used,
        "projected_used_ratio": round(projected_ratio, 8),
        "max_used_ratio": max_used_ratio,
        "reason": "PASS" if passed else "PI_CAPACITY_INSUFFICIENT",
    }
    if not passed:
        raise ArchiveCapacityError("Pi capacity gate failed")
    return result


def mongo_capacity_status(
    database: Any,
    *,
    tier_limit_bytes: int | None = None,
    recent_growth: Mapping[str, Any] | None = None,
    policy_thresholds: Mapping[str, float] | None = None,
) -> dict[str, Any]:
    """Read-only logical/index/storage capacity summary."""

    thresholds = {
        "warning": 0.70,
        "critical": 0.80,
        "emergency": 0.90,
    }
    if policy_thresholds:
        thresholds.update({key: float(value) for key, value in policy_thresholds.items()})
    stats = database.command("dbStats")
    names = sorted(database.list_collection_names())
    collections: list[dict[str, Any]] = []
    for name in names:
        item = database.command("collStats", name)
        collections.append(
            {
                "collection": name,
                "count": int(item.get("count", 0)),
                "data_bytes": int(item.get("size", item.get("dataSize", 0))),
                "storage_bytes": int(item.get("storageSize", 0)),
                "index_bytes": int(item.get("totalIndexSize", item.get("indexSize", 0))),
            }
        )
    data_bytes = int(stats.get("dataSize", 0))
    index_bytes = int(stats.get("indexSize", 0))
    logical = data_bytes + index_bytes
    used_ratio = logical / tier_limit_bytes if tier_limit_bytes else None
    largest = max(collections, key=lambda item: item["data_bytes"] + item["index_bytes"], default=None)
    return {
        "schema_version": "mongo_capacity_status.v1",
        "observed_at": utc_now(),
        "database": database.name,
        "collections": len(names),
        "document_count": int(stats.get("objects", 0)),
        "data_bytes": data_bytes,
        "index_bytes": index_bytes,
        "storage_bytes": int(stats.get("storageSize", 0)),
        "logical_data_plus_index_bytes": logical,
        "tier_limit_bytes": tier_limit_bytes,
        "used_ratio": round(used_ratio, 8) if used_ratio is not None else None,
        "headroom_bytes": tier_limit_bytes - logical if tier_limit_bytes else None,
        "largest_collection": largest,
        "recent_growth": dict(recent_growth or {}),
        "policy_thresholds": thresholds,
        "threshold_policy_note": "Local configurable operating policy; not an industry standard.",
        "status": (
            "UNKNOWN_TIER_LIMIT"
            if used_ratio is None
            else "EMERGENCY"
            if used_ratio >= thresholds["emergency"]
            else "CRITICAL"
            if used_ratio >= thresholds["critical"]
            else "WARNING"
            if used_ratio >= thresholds["warning"]
            else "NORMAL"
        ),
        "read_only": True,
        "mutations_performed": False,
    }


def safe_index_summary(database: Any, collection_names: Sequence[str]) -> dict[str, Any]:
    """Inspect index metadata without creating or changing an index."""

    result: dict[str, Any] = {}
    for name in collection_names:
        indexes = []
        for index in database[name].list_indexes():
            item = {
                "name": str(index.get("name", "")),
                "key": [[str(key), int(direction)] for key, direction in index.get("key", {}).items()],
            }
            if "expireAfterSeconds" in index:
                item["expireAfterSeconds"] = index["expireAfterSeconds"]
            indexes.append(item)
        result[name] = indexes
    return result


def compare_index_policy(
    actual: Mapping[str, Sequence[Mapping[str, Any]]],
    *,
    expected: Mapping[str, Sequence[Mapping[str, Any]]] | None = None,
    ttl_allowed: bool = False,
) -> dict[str, Any]:
    """Compare read-only index metadata and fail visibly on unexpected TTL."""

    unexpected_ttl = [
        {"collection": collection, "index": dict(index)}
        for collection, indexes in actual.items()
        for index in indexes
        if "expireAfterSeconds" in index and not ttl_allowed
    ]
    missing: list[dict[str, Any]] = []
    unexpected: list[dict[str, Any]] = []
    if expected is not None:
        for collection, expected_indexes in expected.items():
            actual_names = {str(item.get("name")) for item in actual.get(collection, [])}
            expected_names = {str(item.get("name")) for item in expected_indexes}
            missing.extend(
                {"collection": collection, "index": name}
                for name in sorted(expected_names - actual_names)
            )
            unexpected.extend(
                {"collection": collection, "index": name}
                for name in sorted(actual_names - expected_names)
            )
    status = "PASS" if not unexpected_ttl and not missing and not unexpected else "DISCREPANCY"
    return {
        "status": status,
        "ttl_allowed": ttl_allowed,
        "unexpected_ttl_indexes": unexpected_ttl,
        "missing_indexes": missing,
        "unexpected_indexes": unexpected,
        "mutations_performed": False,
    }
