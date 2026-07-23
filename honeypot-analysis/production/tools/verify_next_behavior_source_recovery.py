#!/usr/bin/env python3
"""Publish compact, privacy-safe evidence for recovered source members.

This verifier is deliberately offline.  It validates a completed corrected-
target source-selection receipt, recomputes the exact identity of every local
member, streams each gzip member to EOF without interpreting event content,
and proves that ``data_all.zip`` is absent from declared local roots.

Filesystem paths are inputs only.  The published evidence contains stable
logical root identifiers, never machine-specific cache paths.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import re
import tempfile
import zlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Mapping, Sequence

from production.prediction.next_behavior_source_selection import (
    require_completed_source_selection,
)


SCHEMA_VERSION = "next_behavior_source_recovery_evidence.v1"
FULL_ARCHIVE_FILENAME = "data_all.zip"
_BLOCK_SIZE = 8 * 1024 * 1024
_ROOT_ID = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")


class SourceRecoveryEvidenceError(ValueError):
    """Raised when source-recovery evidence cannot be proven."""


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(_BLOCK_SIZE), b""):
            digest.update(block)
    return digest.hexdigest()


def _member_identity(path: Path) -> tuple[int, str, str]:
    digest = hashlib.sha256()
    crc32 = 0
    size = 0
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(_BLOCK_SIZE), b""):
            size += len(block)
            crc32 = zlib.crc32(block, crc32)
            digest.update(block)
    return size, f"{crc32 & 0xFFFFFFFF:08x}", digest.hexdigest()


def _require_gzip_integrity(path: Path, filename: str) -> None:
    try:
        with gzip.open(path, "rb") as handle:
            for _block in iter(lambda: handle.read(_BLOCK_SIZE), b""):
                pass
    except (EOFError, OSError, zlib.error) as exc:
        raise SourceRecoveryEvidenceError(
            f"gzip integrity check failed: {filename}"
        ) from exc


def _load_completed_selection(path: Path) -> tuple[Dict[str, Any], str]:
    try:
        raw = path.read_bytes()
        value = json.loads(raw)
        completed = require_completed_source_selection(value)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        raise SourceRecoveryEvidenceError(
            f"completed selection is invalid: {exc}"
        ) from exc
    return completed, hashlib.sha256(raw).hexdigest()


def _require_logical_roots(
    roots: Mapping[str, Path],
) -> Dict[str, Path]:
    if not roots:
        raise SourceRecoveryEvidenceError(
            "at least one archive-absence root is required"
        )
    normalized: Dict[str, Path] = {}
    for root_id, path in roots.items():
        if not _ROOT_ID.fullmatch(str(root_id)):
            raise SourceRecoveryEvidenceError(
                f"invalid archive-absence root identifier: {root_id}"
            )
        if root_id in normalized:
            raise SourceRecoveryEvidenceError(
                f"duplicate archive-absence root identifier: {root_id}"
            )
        if not path.is_dir():
            raise SourceRecoveryEvidenceError(
                f"archive-absence root is not a directory: {root_id}"
            )
        normalized[root_id] = path
    return normalized


def _find_full_archive(root: Path) -> bool:
    """Return whether an exact full-archive filename exists below ``root``.

    Directory symlinks are not followed.  A symlink named ``data_all.zip`` is
    still treated as present and therefore fails closed.
    """

    for directory, subdirectories, filenames in os.walk(
        root,
        followlinks=False,
    ):
        subdirectories[:] = [
            name
            for name in subdirectories
            if not (Path(directory) / name).is_symlink()
        ]
        if FULL_ARCHIVE_FILENAME in filenames:
            return True
        candidate = Path(directory) / FULL_ARCHIVE_FILENAME
        if candidate.is_symlink():
            return True
    return False


def build_source_recovery_evidence(
    completed_selection_path: Path,
    source_root: Path,
    archive_absence_roots: Mapping[str, Path],
    *,
    observed_at: str | None = None,
) -> Dict[str, Any]:
    """Verify recovered members and return a compact evidence object."""

    completed, completed_sha256 = _load_completed_selection(
        completed_selection_path
    )
    if not source_root.is_dir():
        raise SourceRecoveryEvidenceError(
            "source root is not a directory"
        )
    roots = _require_logical_roots(archive_absence_roots)

    receipts_by_filename = {
        receipt["filename"]: receipt
        for receipt in completed["verification"]["member_receipts"]
    }
    evidence_members: list[Dict[str, Any]] = []
    counts = {
        "reused_verified_local": 0,
        "selectively_downloaded_archive_member": 0,
    }
    total_bytes = 0
    for member in completed["members"]:
        filename = member["filename"]
        expected = receipts_by_filename[filename]
        target = source_root / filename
        if (
            not target.is_file()
            or target.is_symlink()
            or target.parent.resolve() != source_root.resolve()
        ):
            raise SourceRecoveryEvidenceError(
                f"missing or unsafe recovered member: {filename}"
            )
        size_bytes, crc32, sha256 = _member_identity(target)
        if size_bytes != expected["size_bytes"]:
            raise SourceRecoveryEvidenceError(
                f"size mismatch: {filename}"
            )
        if crc32 != expected["archive_crc32"]:
            raise SourceRecoveryEvidenceError(
                f"CRC32 mismatch: {filename}"
            )
        if sha256 != expected["sha256"]:
            raise SourceRecoveryEvidenceError(
                f"SHA-256 mismatch: {filename}"
            )
        _require_gzip_integrity(target, filename)

        if member["role"] == "development":
            acquisition_method = "reused_verified_local"
        elif member["role"] == "final":
            acquisition_method = "selectively_downloaded_archive_member"
        else:  # The frozen selection validator should make this unreachable.
            raise SourceRecoveryEvidenceError(
                f"unsupported member role: {member['role']}"
            )
        counts[acquisition_method] += 1
        total_bytes += size_bytes
        evidence_members.append(
            {
                "filename": filename,
                "archive_path": member["archive_path"],
                "collection_date": member["collection_date"],
                "chronological_order": member["chronological_order"],
                "role": member["role"],
                "acquisition_method": acquisition_method,
                "size_bytes": size_bytes,
                "archive_compressed_bytes": expected[
                    "archive_compressed_bytes"
                ],
                "archive_crc32": crc32,
                "sha256": sha256,
                "gzip_integrity": "verified",
            }
        )

    if counts != {
        "reused_verified_local": 6,
        "selectively_downloaded_archive_member": 7,
    }:
        raise SourceRecoveryEvidenceError(
            "source recovery must contain six reused and seven downloaded members"
        )

    absence_evidence = []
    for root_id, path in sorted(roots.items()):
        if _find_full_archive(path):
            raise SourceRecoveryEvidenceError(
                f"{FULL_ARCHIVE_FILENAME} is present in root: {root_id}"
            )
        absence_evidence.append(
            {
                "root_id": root_id,
                "filename": FULL_ARCHIVE_FILENAME,
                "present": False,
                "recursive": True,
                "directory_symlinks_followed": False,
            }
        )

    timestamp = observed_at or datetime.now(timezone.utc).isoformat(
        timespec="seconds"
    ).replace("+00:00", "Z")
    return {
        "schema_version": SCHEMA_VERSION,
        "selection_id": completed["selection_id"],
        "observed_at": timestamp,
        "source": completed["source"],
        "selection_policy": completed["policy"],
        "completed_selection_sha256": completed_sha256,
        "archive_identity": {
            "filename": completed["archive"]["filename"],
            "size_bytes": completed["archive"]["size_bytes"],
            "checksum": completed["archive"]["checksum"],
            "full_archive_downloaded": False,
        },
        "acquisition_summary": {
            "member_count": len(evidence_members),
            **counts,
            "selective_member_retrieval": True,
        },
        "verification": {
            "member_count": len(evidence_members),
            "total_member_bytes": total_bytes,
            "exact_filename_verified": True,
            "exact_size_verified": True,
            "exact_crc32_verified": True,
            "exact_sha256_verified": True,
            "gzip_integrity_verified": True,
            "event_content_parsed": False,
        },
        "archive_absence": absence_evidence,
        "members": evidence_members,
    }


def _atomic_create_json(path: Path, value: Mapping[str, Any]) -> None:
    if path.exists():
        raise SourceRecoveryEvidenceError(
            f"refusing to overwrite evidence: {path}"
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True, allow_nan=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError as exc:
            raise SourceRecoveryEvidenceError(
                f"refusing to overwrite evidence: {path}"
            ) from exc
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _parse_absence_root(value: str) -> tuple[str, Path]:
    root_id, separator, path = value.partition("=")
    if not separator or not root_id or not path:
        raise argparse.ArgumentTypeError(
            "archive-absence roots must use ROOT_ID=PATH"
        )
    return root_id, Path(path)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--completed-selection", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument(
        "--archive-absence-root",
        action="append",
        type=_parse_absence_root,
        required=True,
        metavar="ROOT_ID=PATH",
    )
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    roots = dict(args.archive_absence_root)
    if len(roots) != len(args.archive_absence_root):
        raise SourceRecoveryEvidenceError(
            "archive-absence root identifiers must be unique"
        )
    evidence = build_source_recovery_evidence(
        args.completed_selection,
        args.source_root,
        roots,
    )
    _atomic_create_json(args.output, evidence)
    print(
        json.dumps(
            {
                "schema_version": evidence["schema_version"],
                "selection_id": evidence["selection_id"],
                "member_count": evidence["verification"]["member_count"],
                "output": str(args.output),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
