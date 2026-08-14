#!/usr/bin/env python3
"""Range-stage the development members of the reviewed successor cohort.

The module deliberately separates archive-directory verification from content
access.  It verifies that all 31 declared archive entries exist and records
their central-directory size/compressed-size/CRC metadata, but opens and stages
only the 24 unsealed development members.  The seven final-test members remain
sealed; their content hashes therefore remain absent from this staging receipt.

This is preparation tooling, not corpus ingestion.  It does not parse event
rows, create a selected store, classify commands, or complete the pending
``next_behavior_source_selection.v2`` declaration.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import sqlite3
import time
import uuid
import zipfile
import zlib
from pathlib import Path
from typing import Any, BinaryIO, Callable, Dict, Mapping, Sequence

from production.reproduction.next_behavior.selected_store import (
    SelectedCorpusBuildError,
    final_member_receipts_sha256,
)
from production.reproduction.next_behavior.source_selection_v2 import (
    COMPLETE_STATUS,
    NextBehaviorSourceSelectionV2Error,
    PENDING_STATUS,
    build_successor_member_inventory,
    canonical_contract_sha256,
    load_source_selection_v2,
    require_valid_source_selection_v2,
)
from production.reproduction.next_behavior.zenodo_members import (
    HttpRangeReader,
    extract_members,
    verify_archive_entries,
)
from production.utils.serialization import stable_json


SCHEMA_VERSION = "next_behavior_successor_member_staging.v1"
STATUS = "development_members_staged_test_members_sealed"
PRESERVED_TEST_RECEIPT_SCHEMA_VERSION = (
    "next_behavior_preserved_test_member_receipts.v1"
)
PRESERVED_SOURCE_SELECTION_SHA256 = (
    "078a0d2185f95a13c4642b15a5f8da69bc80df6093dc4d8435f181ff93702487"
)
PRESERVED_PREPARATION_RECEIPT_ID = (
    "nextbehaviorfinalpreparation_a826f2278ec882bbbe6c9a18837446b6"
)
PRESERVED_PREPARATION_ARTIFACT_SHA256 = (
    "f5ec258e5e03a13ec6266efb6a26440cf4d5e8920f392c901a3a91ce31948664"
)
PRESERVED_FINAL_INGEST_ARTIFACT_SHA256 = (
    "97ca205c3225306b763b2ad226cd2c06fa6b96c4d4205cb40ed85efad44dc055"
)
PRESERVED_FINAL_MEMBER_RECEIPTS_SHA256 = (
    "318ac6d0028ba1773a90c1005875efe338315bb7a4fb98249279b40abdd1d627"
)
_READ_BLOCK_BYTES = 8 * 1024 * 1024
SUCCESSOR_STORAGE_MOUNT = Path("/mnt/honeypot-data")
SUCCESSOR_MEMBER_ROOT = (
    SUCCESSOR_STORAGE_MOUNT / "next-behavior-successor" / "member-inventory"
)
MINIMUM_STAGING_AVAILABLE_BYTES = 60 * 1024 * 1024 * 1024
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "status",
        "source_selection_id",
        "source_selection_sha256",
        "source_selection_verification_status",
        "archive",
        "storage_preflight",
        "member_count",
        "development_member_count",
        "sealed_test_member_count",
        "archive_entries_verified",
        "test_member_contents_accessed",
        "ordered_member_metadata_sha256",
        "ordered_development_content_sha256",
        "members",
        "receipt_sha256",
    }
)
_PRESERVED_TEST_RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "status",
        "source_selection_sha256",
        "preparation_receipt_id",
        "preparation_artifact_sha256",
        "final_ingest_artifact_sha256",
        "final_member_receipts_sha256",
        "store_evidence",
        "sealed_test_member_count",
        "test_member_contents_accessed",
        "test_metrics_used",
        "members",
        "receipt_sha256",
    }
)


class SuccessorMemberStagingError(ValueError):
    """Raised when successor members cannot be staged without ambiguity."""


def _decode_mount_field(value: str) -> str:
    return (
        value.replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
    )


def _default_mount_probe(mountpoint: Path) -> Dict[str, Any]:
    """Read the exact mount identity without mutating or probing by writing."""

    try:
        lines = Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise SuccessorMemberStagingError("cannot inspect mount table") from exc
    expected = str(mountpoint)
    observed: Dict[str, Any] | None = None
    for line in lines:
        fields = line.split()
        try:
            separator = fields.index("-")
        except ValueError:
            continue
        if _decode_mount_field(fields[4]) != expected:
            continue
        statvfs = os.statvfs(mountpoint)
        observed = {
            "mount_target": expected,
            "source": _decode_mount_field(fields[separator + 2]),
            "fstype": fields[separator + 1],
            "mount_options": sorted(set(fields[5].split(","))),
            "super_options": sorted(set(fields[separator + 3].split(","))),
            "available_bytes": statvfs.f_bavail * statvfs.f_frsize,
            "writable": os.access(mountpoint, os.W_OK),
        }
        break
    if observed is None:
        raise SuccessorMemberStagingError(
            "reviewed successor storage is not a distinct mounted filesystem"
        )
    return observed


def _require_safe_staging_storage(
    destination: Path,
    *,
    mount_probe: Callable[[Path], Mapping[str, Any]] | None,
) -> Dict[str, Any]:
    """Fail before network/archive access unless the reviewed ext4 root is safe."""

    mountpoint = SUCCESSOR_STORAGE_MOUNT
    member_root = SUCCESSOR_MEMBER_ROOT
    if mountpoint.is_symlink() or not mountpoint.is_dir():
        raise SuccessorMemberStagingError("reviewed successor mountpoint is unsafe")
    resolved_mount = mountpoint.resolve(strict=True)
    resolved_root = member_root.resolve(strict=False)
    resolved_destination = destination.resolve(strict=False)
    if resolved_root.parent.parent != resolved_mount:
        raise SuccessorMemberStagingError("reviewed member root escapes its mount")
    if resolved_destination != resolved_root:
        raise SuccessorMemberStagingError(
            "staging destination must be the exact reviewed member-inventory root"
        )
    current = mountpoint
    relative_parts = member_root.relative_to(mountpoint).parts
    for part in relative_parts:
        current = current / part
        if current.exists() or current.is_symlink():
            if current.is_symlink() or not current.is_dir():
                raise SuccessorMemberStagingError(
                    "staging destination contains an unsafe path component"
                )
    probe = dict((mount_probe or _default_mount_probe)(mountpoint))
    required_fields = {
        "mount_target",
        "source",
        "fstype",
        "mount_options",
        "super_options",
        "available_bytes",
        "writable",
    }
    if set(probe) != required_fields:
        raise SuccessorMemberStagingError("staging mount probe fields are invalid")
    mount_options = probe["mount_options"]
    if not isinstance(mount_options, list) or not all(
        isinstance(value, str) for value in mount_options
    ):
        raise SuccessorMemberStagingError("staging mount options are invalid")
    available = probe["available_bytes"]
    if (
        probe["mount_target"] != str(mountpoint)
        or not str(probe["source"]).startswith("/dev/")
        or probe["fstype"] != "ext4"
        or "rw" not in mount_options
        or "ro" in mount_options
        or probe["writable"] is not True
        or isinstance(available, bool)
        or not isinstance(available, int)
        or available < MINIMUM_STAGING_AVAILABLE_BYTES
    ):
        raise SuccessorMemberStagingError(
            "reviewed ext4 staging mount is not writable or has insufficient capacity"
        )
    return {
        "schema_version": "next_behavior_successor_staging_storage.v1",
        "status": "verified_before_archive_access",
        "required_mount": str(mountpoint),
        "required_member_root": str(member_root),
        "destination": str(resolved_destination),
        "mount_target": probe["mount_target"],
        "source": probe["source"],
        "fstype": probe["fstype"],
        "mount_options": mount_options,
        "super_options": probe["super_options"],
        "available_bytes": available,
        "required_minimum_available_bytes": MINIMUM_STAGING_AVAILABLE_BYTES,
        "writable": True,
    }


def _sha256(value: Any) -> str:
    return hashlib.sha256(stable_json(value).encode("utf-8")).hexdigest()


def require_valid_staging_receipt(
    value: Any,
    *,
    source_selection: Mapping[str, Any] | None = None,
) -> Dict[str, Any]:
    """Validate a staging receipt without opening any staged member."""

    if not isinstance(value, Mapping) or set(value) != _RECEIPT_FIELDS:
        raise SuccessorMemberStagingError("staging receipt fields are invalid")
    receipt = dict(value)
    if receipt.get("schema_version") != SCHEMA_VERSION or receipt.get("status") != STATUS:
        raise SuccessorMemberStagingError("staging receipt schema/status is invalid")
    if (
        receipt.get("member_count") != 31
        or receipt.get("development_member_count") != 24
        or receipt.get("sealed_test_member_count") != 7
        or receipt.get("archive_entries_verified") is not True
        or receipt.get("test_member_contents_accessed") is not False
    ):
        raise SuccessorMemberStagingError("staging receipt safety counts are invalid")
    storage = receipt.get("storage_preflight")
    if not isinstance(storage, Mapping):
        raise SuccessorMemberStagingError("staging storage preflight is missing")
    expected_storage_fields = {
        "schema_version",
        "status",
        "required_mount",
        "required_member_root",
        "destination",
        "mount_target",
        "source",
        "fstype",
        "mount_options",
        "super_options",
        "available_bytes",
        "required_minimum_available_bytes",
        "writable",
    }
    if (
        set(storage) != expected_storage_fields
        or storage.get("schema_version")
        != "next_behavior_successor_staging_storage.v1"
        or storage.get("status") != "verified_before_archive_access"
        or storage.get("required_mount") != str(SUCCESSOR_STORAGE_MOUNT)
        or storage.get("required_member_root") != str(SUCCESSOR_MEMBER_ROOT)
        or storage.get("destination")
        != str(SUCCESSOR_MEMBER_ROOT.resolve(strict=False))
        or storage.get("mount_target") != str(SUCCESSOR_STORAGE_MOUNT)
        or not str(storage.get("source", "")).startswith("/dev/")
        or storage.get("fstype") != "ext4"
        or "rw" not in storage.get("mount_options", [])
        or "ro" in storage.get("mount_options", [])
        or storage.get("required_minimum_available_bytes")
        != MINIMUM_STAGING_AVAILABLE_BYTES
        or storage.get("writable") is not True
        or isinstance(storage.get("available_bytes"), bool)
        or not isinstance(storage.get("available_bytes"), int)
        or storage["available_bytes"] < MINIMUM_STAGING_AVAILABLE_BYTES
    ):
        raise SuccessorMemberStagingError(
            "staging storage preflight binding is invalid"
        )
    members = receipt.get("members")
    if not isinstance(members, list) or len(members) != 31:
        raise SuccessorMemberStagingError("staging receipt must contain 31 members")
    orders = [
        member.get("chronological_order")
        for member in members
        if isinstance(member, Mapping)
    ]
    if len(orders) != 31 or orders != list(range(1, 32)):
        raise SuccessorMemberStagingError("staging receipt member order is invalid")
    for member in members:
        sealed = member.get("role") == "test" and member.get("sealed") is True
        digest = member.get("content_sha256")
        status = member.get("content_status")
        if sealed:
            if digest is not None or status != "sealed_metadata_only":
                raise SuccessorMemberStagingError(
                    "sealed test receipt must not claim content access"
                )
        elif (
            not _SHA256.fullmatch(str(digest or ""))
            or status not in {"downloaded_and_verified", "verified_existing"}
        ):
            raise SuccessorMemberStagingError(
                "development member content receipt is invalid"
            )
    metadata_hash = _sha256(
        [
            {
                key: member[key]
                for key in (
                    "filename",
                    "archive_path",
                    "size_bytes",
                    "archive_compressed_bytes",
                    "archive_crc32",
                )
            }
            for member in members
        ]
    )
    development_hash = _sha256(
        [
            {"filename": member["filename"], "sha256": member["content_sha256"]}
            for member in members
            if member["role"] != "test"
        ]
    )
    if receipt.get("ordered_member_metadata_sha256") != metadata_hash:
        raise SuccessorMemberStagingError("staging member metadata hash mismatch")
    if receipt.get("ordered_development_content_sha256") != development_hash:
        raise SuccessorMemberStagingError("staging development content hash mismatch")
    receipt_basis = {key: receipt[key] for key in receipt if key != "receipt_sha256"}
    if receipt.get("receipt_sha256") != _sha256(receipt_basis):
        raise SuccessorMemberStagingError("staging receipt hash mismatch")
    if source_selection is not None:
        selection = require_valid_source_selection_v2(dict(source_selection))
        if receipt.get("source_selection_id") != selection["selection_id"]:
            raise SuccessorMemberStagingError("staging source-selection ID mismatch")
        if receipt.get("source_selection_sha256") != canonical_contract_sha256(selection):
            raise SuccessorMemberStagingError("staging source-selection hash mismatch")
        declarations = selection["members"]
        for actual, expected in zip(members, declarations):
            if any(actual.get(key) != expected[key] for key in expected):
                raise SuccessorMemberStagingError(
                    "staging member differs from frozen source selection"
                )
    return receipt


def _legacy_manifest(
    selection: Mapping[str, Any],
    members: Sequence[Mapping[str, Any]],
) -> Dict[str, Any]:
    """Adapt exactly seven v2 receipts to the reviewed v1 ZIP primitives.

    The old ZIP helpers intentionally validate seven entries at a time.  The
    successor cohort uses overlapping final windows so every declaration can
    still be checked by those reviewed helpers without changing their v1
    contract.  Callers must pass exactly seven unique members.
    """

    if len(members) != 7 or len({item["filename"] for item in members}) != 7:
        raise SuccessorMemberStagingError(
            "legacy archive verification windows require seven unique members"
        )
    archive = selection["archive"]
    return {
        "schema_version": "next_behavior_zenodo_source.v1",
        "source": {
            "zenodo_record_id": selection["source"]["zenodo_record_id"],
            "doi": selection["source"]["doi"],
            "title": "Cowrie Honeypot Dataset",
            "license": "source-record-declared",
            "record_url": "https://zenodo.org/records/21260400",
        },
        "archive": dict(archive),
        "selection": {
            "selection_id": "successor_archive_metadata_window.v1",
            "method": "exact reviewed successor declarations",
            "member_count": 7,
            "excluded_previously_used_members": [],
            "transferred_file_archive_used": False,
        },
        "members": [
            {
                "filename": item["filename"],
                "archive_path": item["archive_path"],
                "collection_date": item["collection_date"],
                "chronological_order": index + 1,
                "size_bytes": item["size_bytes"],
                "archive_compressed_bytes": item["archive_compressed_bytes"],
                "archive_crc32": item["archive_crc32"],
                "sha256": item["sha256"],
            }
            for index, item in enumerate(members)
        ],
    }


def _windows_of_seven(members: Sequence[Mapping[str, Any]]) -> list[list[Mapping[str, Any]]]:
    """Cover an arbitrary declaration with deterministic seven-member windows."""

    if len(members) < 7:
        raise SuccessorMemberStagingError("at least seven archive members are required")
    windows = [list(members[start : start + 7]) for start in range(0, len(members) - 6, 7)]
    covered = {member["filename"] for window in windows for member in window}
    if len(covered) != len(members):
        windows.append(list(members[-7:]))
    return windows


def _central_directory_receipts(
    archive: zipfile.ZipFile,
    selection: Mapping[str, Any],
) -> list[Dict[str, Any]]:
    """Verify all declarations before any destination path is created."""

    declared = selection["members"]
    occurrences: Dict[str, list[zipfile.ZipInfo]] = {}
    for entry in archive.infolist():
        occurrences.setdefault(entry.filename, []).append(entry)

    completed_by_name = {
        item["filename"]: item
        for item in selection["verification"]["member_receipts"]
    }
    receipts: list[Dict[str, Any]] = []
    for declaration in declared:
        matches = occurrences.get(declaration["archive_path"], [])
        if len(matches) != 1:
            raise SuccessorMemberStagingError(
                "declared archive entry must occur exactly once: "
                f"{declaration['filename']}"
            )
        entry = matches[0]
        expected = completed_by_name.get(declaration["filename"])
        if expected is not None:
            observed_metadata = (
                entry.file_size,
                entry.compress_size,
                f"{entry.CRC:08x}",
            )
            expected_metadata = (
                expected["size_bytes"],
                expected["archive_compressed_bytes"],
                expected["archive_crc32"],
            )
            if observed_metadata != expected_metadata:
                raise SuccessorMemberStagingError(
                    f"archive metadata mismatch: {declaration['filename']}"
                )
        receipts.append(
            {
                **dict(declaration),
                "size_bytes": entry.file_size,
                "archive_compressed_bytes": entry.compress_size,
                "archive_crc32": f"{entry.CRC:08x}",
                # The v1 primitive validates shape before checking ZIP metadata.
                # Pending declarations have no content hash yet, so this value is
                # internal to metadata validation and is never emitted as content
                # evidence.
                "sha256": (
                    expected["sha256"] if expected is not None else "0" * 64
                ),
            }
        )

    # Keep the reviewed v1 central-directory verifier in the trust path.
    for window in _windows_of_seven(receipts):
        verify_archive_entries(archive, _legacy_manifest(selection, window))
    return receipts


def _hash_existing(path: Path, expected_size: int, expected_crc32: str) -> str:
    if path.is_symlink() or not path.is_file():
        raise SuccessorMemberStagingError(
            f"refusing non-regular existing member: {path.name}"
        )
    if path.stat().st_size != expected_size:
        raise SuccessorMemberStagingError(
            f"refusing mismatched existing member size: {path.name}"
        )
    digest = hashlib.sha256()
    crc = 0
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(_READ_BLOCK_BYTES), b""):
            digest.update(block)
            crc = zlib.crc32(block, crc)
    if f"{crc & 0xFFFFFFFF:08x}" != expected_crc32:
        raise SuccessorMemberStagingError(
            f"refusing mismatched existing member CRC: {path.name}"
        )
    return digest.hexdigest()


def _stage_one(
    archive: zipfile.ZipFile,
    entry: zipfile.ZipInfo,
    target: Path,
    *,
    expected_sha256: str | None,
) -> tuple[str, str]:
    """Stream one entry to a unique partial and publish without overwrite."""

    partial = target.parent / (
        f".{target.name}.part.{os.getpid()}.{time.time_ns()}.{uuid.uuid4().hex}"
    )
    digest = hashlib.sha256()
    crc = 0
    written = 0
    try:
        with archive.open(entry, "r") as source, partial.open("xb") as output:
            for block in iter(lambda: source.read(_READ_BLOCK_BYTES), b""):
                output.write(block)
                digest.update(block)
                crc = zlib.crc32(block, crc)
                written += len(block)
            output.flush()
            os.fsync(output.fileno())
        observed_sha256 = digest.hexdigest()
        if written != entry.file_size or (crc & 0xFFFFFFFF) != entry.CRC:
            raise SuccessorMemberStagingError(
                f"staged member failed size/CRC verification: {target.name}"
            )
        if expected_sha256 is not None and observed_sha256 != expected_sha256:
            raise SuccessorMemberStagingError(
                f"staged member failed SHA-256 verification: {target.name}"
            )
        # Hard-link publication is atomic and, unlike rename/replace, refuses
        # to overwrite a member that appeared during extraction.
        os.link(partial, target)
        partial.unlink()
        directory_fd = os.open(target.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        # Preserve a completed/partial uniquely named file for audit evidence.
        raise
    return observed_sha256, "downloaded_and_verified"


def _write_receipt_exclusive(path: Path, receipt: Mapping[str, Any]) -> None:
    if path.exists():
        raise SuccessorMemberStagingError(
            f"refusing to overwrite existing staging receipt: {path}"
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    partial = path.parent / f".{path.name}.part.{os.getpid()}.{uuid.uuid4().hex}"
    payload = (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode("utf-8")
    try:
        with partial.open("xb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(partial, path)
        partial.unlink()
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        raise


def _write_json_pair_exclusive(
    first_path: Path,
    first_value: Mapping[str, Any],
    second_path: Path,
    second_value: Mapping[str, Any],
) -> None:
    """Publish two immutable JSON outputs, rolling back a publication race."""

    _write_json_outputs_exclusive(
        ((first_path, first_value), (second_path, second_value))
    )


def _write_json_outputs_exclusive(
    values: Sequence[tuple[Path, Mapping[str, Any]]],
) -> None:
    """Publish immutable JSON outputs, rolling back an exclusive-link race."""

    paths = [path for path, _value in values]
    if len(paths) != len(set(paths)):
        raise SuccessorMemberStagingError("finalization output paths must differ")
    for path in paths:
        if path.exists():
            raise SuccessorMemberStagingError(
                f"refusing to overwrite existing finalization output: {path}"
            )
    for path in paths:
        path.parent.mkdir(parents=True, exist_ok=True)
    partials: list[Path] = []
    published: list[Path] = []
    try:
        for path, value in values:
            partial = path.parent / (
                f".{path.name}.part.{os.getpid()}.{uuid.uuid4().hex}"
            )
            payload = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode(
                "utf-8"
            )
            with partial.open("xb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            partials.append(partial)
        for (path, _), partial in zip(values, partials):
            os.link(partial, path)
            published.append(path)
        for partial in partials:
            partial.unlink()
        for directory in {path.parent for path in paths}:
            directory_fd = os.open(directory, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    except BaseException:
        # These are outputs created by this call, never pre-existing evidence.
        # Removing them restores the all-or-none state if an exclusive link
        # loses a race.  Unique partials remain for forensic inspection.
        for path in published:
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        raise


def _require_pinned_artifact_hash(actual: str, expected: str, label: str) -> None:
    if not _SHA256.fullmatch(str(actual).lower()) or not _SHA256.fullmatch(
        str(expected).lower()
    ):
        raise SuccessorMemberStagingError(f"{label} SHA-256 is invalid")
    if actual.lower() != expected.lower():
        raise SuccessorMemberStagingError(f"{label} artifact identity mismatch")


def _safe_immutable_store_side_files(path: Path) -> Dict[str, Any]:
    """Apply the reviewed zero-WAL immutable-main-database rule."""

    if path.is_symlink() or not path.is_file() or path.stat().st_size < 1:
        raise SuccessorMemberStagingError("preserved SQLite store is missing or unsafe")
    wal = Path(str(path) + "-wal")
    shm = Path(str(path) + "-shm")
    journal = Path(str(path) + "-journal")
    for side in (wal, shm, journal):
        if side.is_symlink():
            raise SuccessorMemberStagingError("preserved SQLite side file is unsafe")
    wal_exists = wal.exists()
    wal_size = wal.stat().st_size if wal_exists else 0
    shm_exists = shm.exists()
    shm_size = shm.stat().st_size if shm_exists else 0
    if wal_exists and wal_size != 0:
        raise SuccessorMemberStagingError(
            "preserved SQLite store has a non-empty WAL"
        )
    if journal.exists():
        raise SuccessorMemberStagingError(
            "preserved SQLite store has a rollback journal"
        )
    if shm_exists and (not wal_exists or wal_size != 0):
        raise SuccessorMemberStagingError(
            "preserved SQLite SHM is not paired with an empty WAL"
        )
    return {
        "main_database_size_bytes": path.stat().st_size,
        "wal_exists": wal_exists,
        "wal_size_bytes": wal_size,
        "shm_exists": shm_exists,
        "shm_size_bytes": shm_size,
        "rollback_journal_exists": False,
        "sqlite_quick_check": "pending",
    }


def _metadata_only_authorizer(
    action: int,
    arg1: str | None,
    arg2: str | None,
    _database: str | None,
    _trigger: str | None,
) -> int:
    allowed_columns = {
        "metadata": {"key", "value"},
        "source_members": {
            "filename",
            "source_sha256",
            "source_size_bytes",
            "archive_crc32",
            "chronological_order",
            "source_cohort",
            "experiment_role",
        },
    }
    if action == sqlite3.SQLITE_SELECT:
        return sqlite3.SQLITE_OK
    if action == sqlite3.SQLITE_READ and arg1 in allowed_columns:
        return (
            sqlite3.SQLITE_OK
            if arg2 in allowed_columns[arg1]
            else sqlite3.SQLITE_DENY
        )
    return sqlite3.SQLITE_DENY


def _resolve_preserved_test_member_receipt_values(
    store_path: Path,
    pending_selection_value: Mapping[str, Any],
    preparation_receipt_value: Mapping[str, Any],
    final_ingest_receipt_value: Mapping[str, Any],
    *,
    preparation_artifact_sha256: str,
    expected_preparation_artifact_sha256: str,
    final_ingest_artifact_sha256: str,
    expected_final_ingest_artifact_sha256: str,
) -> Dict[str, Any]:
    """Resolve seven hashes from the immutable store without reading test data."""

    pending = require_valid_source_selection_v2(dict(pending_selection_value))
    if pending["verification"]["status"] != PENDING_STATUS:
        raise SuccessorMemberStagingError(
            "preserved receipt resolution requires the pending v2 declaration"
        )
    _require_pinned_artifact_hash(
        preparation_artifact_sha256,
        expected_preparation_artifact_sha256,
        "final-preparation receipt",
    )
    _require_pinned_artifact_hash(
        final_ingest_artifact_sha256,
        expected_final_ingest_artifact_sha256,
        "final-ingest receipt",
    )
    if (
        expected_preparation_artifact_sha256.lower()
        != PRESERVED_PREPARATION_ARTIFACT_SHA256
        or expected_final_ingest_artifact_sha256.lower()
        != PRESERVED_FINAL_INGEST_ARTIFACT_SHA256
    ):
        raise SuccessorMemberStagingError(
            "preserved receipt pins do not match the reviewed gate lineage"
        )
    preparation = dict(preparation_receipt_value)
    final_ingest = dict(final_ingest_receipt_value)
    if (
        preparation.get("schema_version")
        != "next_behavior_final_corpus_preparation.v1"
        or preparation.get("status") != "frozen_for_blinded_preparation"
        or preparation.get("purpose") != "prepare_final_corpus"
        or preparation.get("evaluation_opened") is not False
        or preparation.get("receipt_id") != PRESERVED_PREPARATION_RECEIPT_ID
        or preparation.get("source_selection_sha256")
        != PRESERVED_SOURCE_SELECTION_SHA256
        or preparation.get("final_source_member_count") != 7
        or preparation.get("final_source_member_receipts_sha256")
        != PRESERVED_FINAL_MEMBER_RECEIPTS_SHA256
        or not _SHA256.fullmatch(
            str(preparation.get("final_source_member_receipts_sha256", ""))
        )
    ):
        raise SuccessorMemberStagingError(
            "final-preparation receipt lineage is invalid"
        )
    expected_test_names = [
        item["filename"] for item in pending["members"] if item["role"] == "test"
    ]
    ingest_members = final_ingest.get("member_receipts")
    if (
        final_ingest.get("schema_version")
        != "next_behavior_selected_ingest_receipt.v1"
        or final_ingest.get("status") != "cohort_ingested"
        or final_ingest.get("cohort") != "final"
        or final_ingest.get("evaluation_opened") is not False
        or final_ingest.get("final_corpus_prepared") is not True
        or final_ingest.get("raw_content_emitted") is not False
        or final_ingest.get("requested_member_count") != 7
        or final_ingest.get("source_selection_sha256")
        != PRESERVED_SOURCE_SELECTION_SHA256
        or final_ingest.get("final_preparation_gate") != preparation
        or not isinstance(ingest_members, list)
        or [item.get("filename") for item in ingest_members]
        != expected_test_names
        or any(item.get("status") != "ingested" for item in ingest_members)
    ):
        raise SuccessorMemberStagingError("final-ingest receipt lineage is invalid")

    side_files = _safe_immutable_store_side_files(store_path)
    uri = f"file:{store_path.resolve().as_posix()}?mode=ro&immutable=1"
    try:
        database = sqlite3.connect(uri, uri=True)
        database.execute("PRAGMA query_only=ON")
        quick = str(database.execute("PRAGMA quick_check").fetchone()[0]).strip()
        if quick != "ok":
            raise SuccessorMemberStagingError(
                "preserved SQLite store quick_check failed"
            )
        side_files["sqlite_quick_check"] = "ok"
        database.set_authorizer(_metadata_only_authorizer)
        metadata = dict(
            database.execute(
                "SELECT key, value FROM metadata WHERE key IN "
                "('store_schema_version', 'source_selection_sha256', "
                "'final_corpus_preparation_receipt_id', "
                "'final_corpus_preparation_receipt_json', "
                "'final_corpus_prepared_at', 'final_test_opened_at')"
            )
        )
        rows = database.execute(
            "SELECT filename, source_sha256, source_size_bytes, archive_crc32, "
            "chronological_order, source_cohort, experiment_role "
            "FROM source_members WHERE experiment_role = 'test' "
            "ORDER BY chronological_order"
        ).fetchall()
    except sqlite3.Error as exc:
        raise SuccessorMemberStagingError(
            f"cannot verify preserved SQLite store read-only: {exc}"
        ) from exc
    finally:
        if "database" in locals():
            database.close()
    try:
        embedded_preparation = json.loads(
            metadata["final_corpus_preparation_receipt_json"]
        )
    except (KeyError, json.JSONDecodeError) as exc:
        raise SuccessorMemberStagingError(
            "preserved store preparation metadata is invalid"
        ) from exc
    if (
        metadata.get("store_schema_version")
        != "next_behavior_selected_private_store.v1"
        or metadata.get("source_selection_sha256")
        != PRESERVED_SOURCE_SELECTION_SHA256
        or metadata.get("final_corpus_preparation_receipt_id")
        != PRESERVED_PREPARATION_RECEIPT_ID
        or embedded_preparation != preparation
        or not metadata.get("final_corpus_prepared_at")
        or "final_test_opened_at" in metadata
    ):
        raise SuccessorMemberStagingError(
            "preserved SQLite metadata lineage is invalid"
        )
    member_keys = (
        "filename",
        "source_sha256",
        "source_size_bytes",
        "archive_crc32",
        "chronological_order",
        "source_cohort",
        "experiment_role",
    )
    members = [dict(zip(member_keys, row)) for row in rows]
    if [member["filename"] for member in members] != expected_test_names:
        raise SuccessorMemberStagingError(
            "preserved store sealed-test membership mismatch"
        )
    try:
        member_receipts_sha256 = final_member_receipts_sha256(members)
    except SelectedCorpusBuildError as exc:
        raise SuccessorMemberStagingError(str(exc)) from exc
    if member_receipts_sha256 != preparation["final_source_member_receipts_sha256"]:
        raise SuccessorMemberStagingError(
            "preserved store final-member receipt hash mismatch"
        )
    basis: Dict[str, Any] = {
        "schema_version": PRESERVED_TEST_RECEIPT_SCHEMA_VERSION,
        "status": "sealed_test_metadata_resolved",
        "source_selection_sha256": PRESERVED_SOURCE_SELECTION_SHA256,
        "preparation_receipt_id": PRESERVED_PREPARATION_RECEIPT_ID,
        "preparation_artifact_sha256": preparation_artifact_sha256,
        "final_ingest_artifact_sha256": final_ingest_artifact_sha256,
        "final_member_receipts_sha256": member_receipts_sha256,
        "store_evidence": side_files,
        "sealed_test_member_count": 7,
        "test_member_contents_accessed": False,
        "test_metrics_used": False,
        "members": members,
    }
    basis["receipt_sha256"] = _sha256(basis)
    return basis


def resolve_preserved_test_member_receipts(
    store_path: Path,
    pending_selection_value: Mapping[str, Any],
    preparation_receipt_path: Path,
    final_ingest_receipt_path: Path,
    *,
    expected_preparation_artifact_sha256: str,
    expected_final_ingest_artifact_sha256: str,
) -> Dict[str, Any]:
    """Resolve preserved identities from caller-pinned receipt file bytes.

    Receipt mappings and their alleged byte hashes are intentionally not part
    of this public boundary.  This function reads each immutable receipt once,
    computes its actual byte identity locally, and passes both parsed content
    and computed identity to the private value-level validator.
    """

    preparation, preparation_sha256 = _load_json_with_artifact_sha256(
        preparation_receipt_path
    )
    final_ingest, final_ingest_sha256 = _load_json_with_artifact_sha256(
        final_ingest_receipt_path
    )
    return _resolve_preserved_test_member_receipt_values(
        store_path,
        pending_selection_value,
        preparation,
        final_ingest,
        preparation_artifact_sha256=preparation_sha256,
        expected_preparation_artifact_sha256=(
            expected_preparation_artifact_sha256
        ),
        final_ingest_artifact_sha256=final_ingest_sha256,
        expected_final_ingest_artifact_sha256=(
            expected_final_ingest_artifact_sha256
        ),
    )


def require_valid_preserved_test_receipt(
    value: Any,
    *,
    pending_selection: Mapping[str, Any],
) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        raise SuccessorMemberStagingError("preserved test receipt is invalid")
    receipt = dict(value)
    if set(receipt) != _PRESERVED_TEST_RECEIPT_FIELDS:
        raise SuccessorMemberStagingError(
            "preserved test receipt fields are invalid"
        )
    pending = require_valid_source_selection_v2(dict(pending_selection))
    expected_names = [
        item["filename"] for item in pending["members"] if item["role"] == "test"
    ]
    members = receipt.get("members")
    if (
        receipt.get("schema_version") != PRESERVED_TEST_RECEIPT_SCHEMA_VERSION
        or receipt.get("status") != "sealed_test_metadata_resolved"
        or receipt.get("source_selection_sha256")
        != PRESERVED_SOURCE_SELECTION_SHA256
        or receipt.get("preparation_receipt_id")
        != PRESERVED_PREPARATION_RECEIPT_ID
        or receipt.get("preparation_artifact_sha256")
        != PRESERVED_PREPARATION_ARTIFACT_SHA256
        or receipt.get("final_ingest_artifact_sha256")
        != PRESERVED_FINAL_INGEST_ARTIFACT_SHA256
        or receipt.get("final_member_receipts_sha256")
        != PRESERVED_FINAL_MEMBER_RECEIPTS_SHA256
        or receipt.get("sealed_test_member_count") != 7
        or receipt.get("test_member_contents_accessed") is not False
        or receipt.get("test_metrics_used") is not False
        or not isinstance(members, list)
        or [member.get("filename") for member in members] != expected_names
    ):
        raise SuccessorMemberStagingError("preserved test receipt lineage is invalid")
    store_evidence = receipt.get("store_evidence")
    if (
        not isinstance(store_evidence, Mapping)
        or store_evidence.get("sqlite_quick_check") != "ok"
        or store_evidence.get("wal_size_bytes") != 0
        or store_evidence.get("rollback_journal_exists") is not False
        or (
            store_evidence.get("shm_exists") is True
            and store_evidence.get("wal_exists") is not True
        )
    ):
        raise SuccessorMemberStagingError(
            "preserved test receipt store evidence is invalid"
        )
    try:
        observed_members_sha256 = final_member_receipts_sha256(members)
    except SelectedCorpusBuildError as exc:
        raise SuccessorMemberStagingError(str(exc)) from exc
    if receipt.get("final_member_receipts_sha256") != observed_members_sha256:
        raise SuccessorMemberStagingError(
            "preserved test member receipt hash mismatch"
        )
    basis = {key: receipt[key] for key in receipt if key != "receipt_sha256"}
    if receipt.get("receipt_sha256") != _sha256(basis):
        raise SuccessorMemberStagingError("preserved test receipt hash mismatch")
    return receipt


def finalize_successor_inventory(
    pending_selection_value: Mapping[str, Any],
    staging_receipt_value: Mapping[str, Any],
    preserved_test_receipt_value: Mapping[str, Any],
) -> Dict[str, Any]:
    """Combine staged development evidence with metadata-only test receipts."""

    pending = require_valid_source_selection_v2(dict(pending_selection_value))
    if pending["verification"]["status"] != PENDING_STATUS:
        raise SuccessorMemberStagingError(
            "finalization requires the immutable pending source-selection v2"
        )
    staging = require_valid_staging_receipt(
        staging_receipt_value,
        source_selection=pending,
    )
    preserved = require_valid_preserved_test_receipt(
        preserved_test_receipt_value,
        pending_selection=pending,
    )
    historical_test_receipts = {
        item["filename"]: item for item in preserved["members"]
    }
    staged = {item["filename"]: item for item in staging["members"]}
    completed_receipts: list[Dict[str, Any]] = []
    for declaration in pending["members"]:
        name = declaration["filename"]
        staged_member = staged[name]
        if declaration["role"] == "test":
            historical = historical_test_receipts[name]
            if (
                historical["source_size_bytes"] != staged_member["size_bytes"]
                or historical["archive_crc32"] != staged_member["archive_crc32"]
            ):
                raise SuccessorMemberStagingError(
                    f"historical sealed-test metadata mismatch: {name}"
                )
            digest = historical["source_sha256"]
        else:
            digest = staged_member["content_sha256"]
        completed_receipts.append(
            {
                **dict(declaration),
                "size_bytes": staged_member["size_bytes"],
                "archive_compressed_bytes": staged_member[
                    "archive_compressed_bytes"
                ],
                "archive_crc32": staged_member["archive_crc32"],
                "sha256": digest,
            }
        )
    completed = copy.deepcopy(pending)
    completed["verification"] = {
        "status": COMPLETE_STATUS,
        "member_receipts": completed_receipts,
    }
    try:
        completed = require_valid_source_selection_v2(completed)
        inventory = build_successor_member_inventory(completed)
    except NextBehaviorSourceSelectionV2Error as exc:
        raise SuccessorMemberStagingError(str(exc)) from exc
    return {
        "completed_source_selection": completed,
        "member_inventory": inventory,
        "lineage": {
            "pending_source_selection_sha256": canonical_contract_sha256(pending),
            "development_staging_receipt_sha256": staging["receipt_sha256"],
            "preserved_test_receipt_sha256": preserved["receipt_sha256"],
            "preparation_artifact_sha256": preserved[
                "preparation_artifact_sha256"
            ],
            "final_ingest_artifact_sha256": preserved[
                "final_ingest_artifact_sha256"
            ],
            "completed_source_selection_sha256": canonical_contract_sha256(
                completed
            ),
            "successor_member_inventory_sha256": canonical_contract_sha256(
                inventory
            ),
            "sealed_test_receipt_count": 7,
            "test_member_contents_accessed": False,
            "test_metrics_used": False,
        },
    }


def stage_development_members(
    selection_value: Mapping[str, Any],
    destination: Path,
    *,
    reader_factory: Callable[..., BinaryIO] = HttpRangeReader,
    mount_probe: Callable[[Path], Mapping[str, Any]] | None = None,
    read_ahead_bytes: int = 32 * 1024 * 1024,
    verify_only: bool = False,
) -> Dict[str, Any]:
    """Stage development members while keeping all final-test content sealed."""

    try:
        selection = require_valid_source_selection_v2(dict(selection_value))
    except NextBehaviorSourceSelectionV2Error as exc:
        raise SuccessorMemberStagingError(str(exc)) from exc
    if read_ahead_bytes < 1:
        raise SuccessorMemberStagingError("read-ahead must be positive")
    storage_preflight = _require_safe_staging_storage(
        destination,
        mount_probe=mount_probe,
    )

    reader = reader_factory(
        selection["archive"]["download_url"],
        expected_size=selection["archive"]["size_bytes"],
        read_ahead_bytes=read_ahead_bytes,
    )
    with zipfile.ZipFile(reader) as archive:
        metadata = _central_directory_receipts(archive, selection)
        entries = {entry.filename: entry for entry in archive.infolist()}
        development = [item for item in metadata if not item["sealed"]]

        # Reject every mismatched pre-existing development target before any
        # directory creation or archive-content access.
        existing_hashes: Dict[str, str] = {}
        if destination.exists() and not destination.is_dir():
            raise SuccessorMemberStagingError("destination is not a directory")
        for item in development:
            target = destination / item["filename"]
            if target.exists() or target.is_symlink():
                digest = _hash_existing(
                    target, item["size_bytes"], item["archive_crc32"]
                )
                declared = next(
                    (
                        receipt
                        for receipt in selection["verification"]["member_receipts"]
                        if receipt["filename"] == item["filename"]
                    ),
                    None,
                )
                if declared is not None and digest != declared["sha256"]:
                    raise SuccessorMemberStagingError(
                        f"refusing mismatched existing member SHA-256: {item['filename']}"
                    )
                existing_hashes[item["filename"]] = digest
        missing = [
            item for item in development if item["filename"] not in existing_hashes
        ]
        if verify_only and missing:
            raise SuccessorMemberStagingError(
                "verify-only mode found missing development members: "
                + ", ".join(item["filename"] for item in missing)
            )

        destination.mkdir(parents=True, exist_ok=True)
        statuses: Dict[str, str] = {
            filename: "verified_existing" for filename in existing_hashes
        }
        content_hashes = dict(existing_hashes)
        for item in missing:
            declared = next(
                (
                    receipt
                    for receipt in selection["verification"]["member_receipts"]
                    if receipt["filename"] == item["filename"]
                ),
                None,
            )
            digest, status = _stage_one(
                archive,
                entries[item["archive_path"]],
                destination / item["filename"],
                expected_sha256=(declared["sha256"] if declared is not None else None),
            )
            content_hashes[item["filename"]] = digest
            statuses[item["filename"]] = status

        # Reuse the reviewed v1 extractor as an independent local-byte and
        # archive-metadata verification after publication.  Overlapping windows
        # only re-verify existing local files; no archive member is reopened.
        actual_development = [
            {**item, "sha256": content_hashes[item["filename"]]}
            for item in development
        ]
        for window in _windows_of_seven(actual_development):
            extract_members(
                archive,
                _legacy_manifest(selection, window),
                destination,
            )

    emitted_members: list[Dict[str, Any]] = []
    for item in metadata:
        common = {key: value for key, value in item.items() if key != "sha256"}
        if item["sealed"]:
            emitted_members.append(
                {
                    **common,
                    "content_sha256": None,
                    "content_status": "sealed_metadata_only",
                }
            )
        else:
            emitted_members.append(
                {
                    **common,
                    "content_sha256": content_hashes[item["filename"]],
                    "content_status": statuses[item["filename"]],
                }
            )
    basis: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "status": STATUS,
        "source_selection_id": selection["selection_id"],
        "source_selection_sha256": canonical_contract_sha256(selection),
        "source_selection_verification_status": selection["verification"]["status"],
        "archive": dict(selection["archive"]),
        "storage_preflight": storage_preflight,
        "member_count": 31,
        "development_member_count": 24,
        "sealed_test_member_count": 7,
        "archive_entries_verified": True,
        "test_member_contents_accessed": False,
        "ordered_member_metadata_sha256": _sha256(
            [
                {
                    key: member[key]
                    for key in (
                        "filename",
                        "archive_path",
                        "size_bytes",
                        "archive_compressed_bytes",
                        "archive_crc32",
                    )
                }
                for member in emitted_members
            ]
        ),
        "ordered_development_content_sha256": _sha256(
            [
                {
                    "filename": member["filename"],
                    "sha256": member["content_sha256"],
                }
                for member in emitted_members
                if member["role"] != "test"
            ]
        ),
        "members": emitted_members,
    }
    basis["receipt_sha256"] = _sha256(basis)
    return require_valid_staging_receipt(basis, source_selection=selection)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source-selection",
        type=Path,
        default=Path("configs/next_behavior_source_selection.v2.json"),
    )
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--verify-only", action="store_true")
    parser.add_argument("--read-ahead-mib", type=int, default=32)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    selection = load_source_selection_v2(args.source_selection)
    receipt = stage_development_members(
        selection,
        args.destination,
        read_ahead_bytes=args.read_ahead_mib * 1024 * 1024,
        verify_only=args.verify_only,
    )
    _write_receipt_exclusive(args.receipt, receipt)
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


def _load_json_with_artifact_sha256(path: Path) -> tuple[Dict[str, Any], str]:
    try:
        payload = path.read_bytes()
        value = json.loads(payload)
    except (OSError, json.JSONDecodeError) as exc:
        raise SuccessorMemberStagingError(f"cannot read JSON artifact {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise SuccessorMemberStagingError(f"JSON artifact is not an object: {path}")
    return value, hashlib.sha256(payload).hexdigest()


def build_finalize_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Finalize successor inventory without opening sealed test content."
    )
    parser.add_argument(
        "--pending-source-selection",
        type=Path,
        default=Path("configs/next_behavior_source_selection.v2.json"),
    )
    parser.add_argument("--development-staging-receipt", type=Path, required=True)
    parser.add_argument("--preserved-store", type=Path, required=True)
    parser.add_argument("--final-preparation-receipt", type=Path, required=True)
    parser.add_argument(
        "--expected-final-preparation-sha256",
        required=True,
        help="Reviewed byte SHA-256 of the preserved final-preparation receipt",
    )
    parser.add_argument("--final-ingest-receipt", type=Path, required=True)
    parser.add_argument("--expected-final-ingest-sha256", required=True)
    parser.add_argument("--preserved-test-receipt-output", type=Path, required=True)
    parser.add_argument("--completed-source-selection-output", type=Path, required=True)
    parser.add_argument("--member-inventory-output", type=Path, required=True)
    return parser


def finalize_main(argv: Sequence[str] | None = None) -> int:
    args = build_finalize_parser().parse_args(argv)
    pending, _ = _load_json_with_artifact_sha256(args.pending_source_selection)
    staging, _ = _load_json_with_artifact_sha256(
        args.development_staging_receipt
    )
    preserved = resolve_preserved_test_member_receipts(
        args.preserved_store,
        pending,
        args.final_preparation_receipt,
        args.final_ingest_receipt,
        expected_preparation_artifact_sha256=(
            args.expected_final_preparation_sha256.strip().lower()
        ),
        expected_final_ingest_artifact_sha256=(
            args.expected_final_ingest_sha256.strip().lower()
        ),
    )
    finalized = finalize_successor_inventory(
        pending,
        staging,
        preserved,
    )
    _write_json_outputs_exclusive(
        (
            (args.preserved_test_receipt_output, preserved),
            (
                args.completed_source_selection_output,
                finalized["completed_source_selection"],
            ),
            (args.member_inventory_output, finalized["member_inventory"]),
        )
    )
    print(json.dumps(finalized["lineage"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
