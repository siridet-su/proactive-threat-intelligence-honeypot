#!/usr/bin/env python3
"""Selectively retrieve the corrected-target source members.

The six development members must already exist and match the preserved v1
manifest. Only missing final members are opened from the exact ``data_all.zip``
archive through HTTP range reads. The pending selection is never modified; a
separate completed selection is created only after every member is verified.
"""

from __future__ import annotations

import argparse
import copy
import gzip
import hashlib
import json
import os
import tempfile
import uuid
import zipfile
import zlib
from contextlib import closing
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, Callable, Dict, Mapping, Sequence

from production.prediction.next_behavior_source_selection import (
    COMPLETE_STATUS,
    PENDING_STATUS,
    require_completed_source_selection,
    require_valid_source_selection,
)
from production.tools.fetch_next_behavior_zenodo_members import (
    HttpRangeReader,
    file_sha256,
    load_source_manifest,
    validate_source_manifest,
)


_BLOCK_SIZE = 8 * 1024 * 1024
_RECEIPT_FIELDS = (
    "filename",
    "archive_path",
    "collection_date",
    "role",
    "size_bytes",
    "archive_compressed_bytes",
    "archive_crc32",
    "sha256",
)


class SelectedMemberFetchError(ValueError):
    """Raised when selective retrieval cannot preserve source identity."""


def _file_identity(path: Path) -> tuple[int, str, str]:
    digest = hashlib.sha256()
    crc32 = 0
    size = 0
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(_BLOCK_SIZE), b""):
            digest.update(block)
            crc32 = zlib.crc32(block, crc32)
            size += len(block)
    return size, f"{crc32 & 0xFFFFFFFF:08x}", digest.hexdigest()


def _require_gzip_integrity(path: Path, *, filename: str) -> None:
    try:
        with gzip.open(path, "rb") as handle:
            for _block in iter(lambda: handle.read(_BLOCK_SIZE), b""):
                pass
    except (OSError, EOFError, zlib.error) as exc:
        raise SelectedMemberFetchError(
            f"gzip integrity check failed: {filename}"
        ) from exc


def _receipt(
    member: Mapping[str, Any],
    *,
    size_bytes: int,
    archive_compressed_bytes: int,
    archive_crc32: str,
    sha256: str,
) -> Dict[str, Any]:
    return {
        "filename": member["filename"],
        "archive_path": member["archive_path"],
        "collection_date": member["collection_date"],
        "role": member["role"],
        "size_bytes": size_bytes,
        "archive_compressed_bytes": archive_compressed_bytes,
        "archive_crc32": archive_crc32,
        "sha256": sha256,
    }


def _require_compatible_preserved_manifest(
    selection: Mapping[str, Any],
    preserved_manifest: Mapping[str, Any],
) -> Dict[str, Mapping[str, Any]]:
    errors = validate_source_manifest(preserved_manifest)
    if errors:
        raise SelectedMemberFetchError("; ".join(errors))
    if preserved_manifest.get("archive") != selection.get("archive"):
        raise SelectedMemberFetchError(
            "preserved manifest archive does not match the pending selection"
        )
    preserved_source = preserved_manifest.get("source") or {}
    if any(
        preserved_source.get(field) != expected
        for field, expected in selection["source"].items()
    ):
        raise SelectedMemberFetchError(
            "preserved manifest source does not match the pending selection"
        )
    preserved_selection = preserved_manifest.get("selection") or {}
    if preserved_selection.get("transferred_file_archive_used") is not False:
        raise SelectedMemberFetchError(
            "transferred file archive is forbidden"
        )

    by_filename = {
        member["filename"]: member for member in preserved_manifest["members"]
    }
    development = [
        member for member in selection["members"]
        if member["role"] == "development"
    ]
    for member in development:
        preserved = by_filename.get(member["filename"])
        if preserved is None:
            raise SelectedMemberFetchError(
                f"development member is absent from preserved v1: "
                f"{member['filename']}"
            )
        for field in ("filename", "archive_path", "collection_date"):
            if preserved.get(field) != member.get(field):
                raise SelectedMemberFetchError(
                    f"development member changed from preserved v1: "
                    f"{member['filename']}"
                )
    return by_filename


def load_pending_inputs(
    selection_path: Path,
    preserved_manifest_path: Path | None = None,
) -> tuple[Dict[str, Any], Dict[str, Any]]:
    """Load the pending declaration and its exact preserved v1 manifest."""

    try:
        selection_value = json.loads(selection_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SelectedMemberFetchError(
            f"cannot read source selection: {exc}"
        ) from exc
    try:
        selection = require_valid_source_selection(selection_value)
    except ValueError as exc:
        raise SelectedMemberFetchError(str(exc)) from exc
    if selection["verification"]["status"] != PENDING_STATUS:
        raise SelectedMemberFetchError(
            "input source selection must be pending archive verification"
        )

    if preserved_manifest_path is None:
        reference = Path(selection["preserved_source_manifest"]["path"])
        preserved_manifest_path = selection_path.resolve().parent.parent / reference
    expected_sha256 = selection["preserved_source_manifest"]["sha256"]
    try:
        observed_sha256 = file_sha256(preserved_manifest_path)
    except OSError as exc:
        raise SelectedMemberFetchError(
            f"cannot read preserved source manifest: {exc}"
        ) from exc
    if observed_sha256 != expected_sha256:
        raise SelectedMemberFetchError(
            "preserved source manifest SHA-256 does not match selection"
        )
    try:
        preserved = load_source_manifest(preserved_manifest_path)
    except ValueError as exc:
        raise SelectedMemberFetchError(str(exc)) from exc
    _require_compatible_preserved_manifest(selection, preserved)
    return selection, preserved


def verify_development_members(
    selection: Mapping[str, Any],
    preserved_manifest: Mapping[str, Any],
    destination: Path,
) -> list[Dict[str, Any]]:
    """Verify the six existing development members without archive access."""

    preserved_by_filename = _require_compatible_preserved_manifest(
        selection,
        preserved_manifest,
    )
    receipts: list[Dict[str, Any]] = []
    for member in selection["members"]:
        if member["role"] != "development":
            continue
        filename = member["filename"]
        expected = preserved_by_filename[filename]
        target = destination / filename
        if (
            not target.exists()
            or not target.is_file()
            or target.is_symlink()
        ):
            raise SelectedMemberFetchError(
                f"missing or unsafe development member: {filename}"
            )
        size, crc32, sha256 = _file_identity(target)
        if (
            size != expected["size_bytes"]
            or crc32 != expected["archive_crc32"]
            or sha256 != expected["sha256"]
        ):
            raise SelectedMemberFetchError(
                f"development member identity mismatch: {filename}"
            )
        _require_gzip_integrity(target, filename=filename)
        receipts.append(
            _receipt(
                member,
                size_bytes=size,
                archive_compressed_bytes=expected[
                    "archive_compressed_bytes"
                ],
                archive_crc32=crc32,
                sha256=sha256,
            )
        )
    if len(receipts) != 6:
        raise SelectedMemberFetchError(
            "exactly six development members must be reused"
        )
    return receipts


def inspect_final_archive_entries(
    selection: Mapping[str, Any],
    archive: zipfile.ZipFile,
) -> Dict[str, zipfile.ZipInfo]:
    """Resolve the seven exact final paths without accepting aliases."""

    final_members = [
        member for member in selection["members"] if member["role"] == "final"
    ]
    entries = archive.infolist()
    selected: Dict[str, zipfile.ZipInfo] = {}
    for member in final_members:
        filename = member["filename"]
        candidates = [
            entry for entry in entries
            if PurePosixPath(entry.filename).name == filename
        ]
        if (
            len(candidates) != 1
            or candidates[0].filename != member["archive_path"]
        ):
            raise SelectedMemberFetchError(
                f"exact final archive member is missing or ambiguous: {filename}"
            )
        entry = candidates[0]
        if (
            entry.is_dir()
            or entry.flag_bits & 0x1
            or entry.file_size < 1
            or entry.compress_size < 1
            or not 0 <= entry.CRC <= 0xFFFFFFFF
        ):
            raise SelectedMemberFetchError(
                f"final archive metadata is unsafe: {filename}"
            )
        selected[filename] = entry
    if len(selected) != 7:
        raise SelectedMemberFetchError(
            "exactly seven final archive members are required"
        )
    return selected


def _verify_existing_final(
    member: Mapping[str, Any],
    entry: zipfile.ZipInfo,
    target: Path,
) -> Dict[str, Any]:
    filename = member["filename"]
    if not target.is_file() or target.is_symlink():
        raise SelectedMemberFetchError(
            f"refusing to overwrite unsafe final member: {filename}"
        )
    size, crc32, sha256 = _file_identity(target)
    if size != entry.file_size or crc32 != f"{entry.CRC:08x}":
        raise SelectedMemberFetchError(
            f"refusing to overwrite mismatched final member: {filename}"
        )
    _require_gzip_integrity(target, filename=filename)
    return _receipt(
        member,
        size_bytes=size,
        archive_compressed_bytes=entry.compress_size,
        archive_crc32=crc32,
        sha256=sha256,
    )


def _stage_final_member(
    member: Mapping[str, Any],
    entry: zipfile.ZipInfo,
    archive: zipfile.ZipFile,
    destination: Path,
) -> tuple[Path, Dict[str, Any]]:
    filename = member["filename"]
    partial = destination / (
        f".{filename}.part.{os.getpid()}.{uuid.uuid4().hex}"
    )
    digest = hashlib.sha256()
    crc32 = 0
    size = 0
    try:
        with archive.open(entry, "r") as source, partial.open("xb") as output:
            for block in iter(lambda: source.read(_BLOCK_SIZE), b""):
                output.write(block)
                digest.update(block)
                crc32 = zlib.crc32(block, crc32)
                size += len(block)
            output.flush()
            os.fsync(output.fileno())
    except (OSError, EOFError, RuntimeError, zipfile.BadZipFile, zlib.error) as exc:
        raise SelectedMemberFetchError(
            f"failed to retrieve final member: {filename}"
        ) from exc
    observed_crc32 = f"{crc32 & 0xFFFFFFFF:08x}"
    if size != entry.file_size or observed_crc32 != f"{entry.CRC:08x}":
        raise SelectedMemberFetchError(
            f"downloaded final member identity mismatch: {filename}"
        )
    _require_gzip_integrity(partial, filename=filename)
    return partial, _receipt(
        member,
        size_bytes=size,
        archive_compressed_bytes=entry.compress_size,
        archive_crc32=observed_crc32,
        sha256=digest.hexdigest(),
    )


def _install_without_overwrite(partial: Path, target: Path) -> None:
    try:
        os.link(partial, target)
    except FileExistsError as exc:
        raise SelectedMemberFetchError(
            f"refusing to overwrite source member: {target.name}"
        ) from exc
    except OSError as exc:
        raise SelectedMemberFetchError(
            f"cannot install source member: {target.name}: {exc}"
        ) from exc
    partial.unlink()


def retrieve_selected_members(
    selection: Mapping[str, Any],
    preserved_manifest: Mapping[str, Any],
    destination: Path,
    output_path: Path,
    *,
    reader_factory: Callable[..., BinaryIO] = HttpRangeReader,
    archive_factory: Callable[[BinaryIO], zipfile.ZipFile] = zipfile.ZipFile,
    read_ahead_bytes: int = 32 * 1024 * 1024,
) -> Dict[str, Any]:
    """Verify/retrieve exact members and atomically create a completed receipt."""

    if output_path.exists():
        raise SelectedMemberFetchError(
            f"refusing to overwrite completed selection: {output_path}"
        )
    if read_ahead_bytes < 1:
        raise SelectedMemberFetchError("read-ahead must be positive")
    try:
        pending = require_valid_source_selection(selection)
    except ValueError as exc:
        raise SelectedMemberFetchError(str(exc)) from exc
    if pending["verification"]["status"] != PENDING_STATUS:
        raise SelectedMemberFetchError(
            "input source selection must be pending archive verification"
        )

    development_receipts = verify_development_members(
        pending,
        preserved_manifest,
        destination,
    )
    reader = reader_factory(
        pending["archive"]["download_url"],
        expected_size=pending["archive"]["size_bytes"],
        read_ahead_bytes=read_ahead_bytes,
    )
    with closing(reader):
        with archive_factory(reader) as archive:
            final_entries = inspect_final_archive_entries(pending, archive)
            final_members = [
                member for member in pending["members"]
                if member["role"] == "final"
            ]

            final_receipts: Dict[str, Dict[str, Any]] = {}
            missing: list[Mapping[str, Any]] = []
            for member in final_members:
                target = destination / member["filename"]
                if target.exists():
                    final_receipts[member["filename"]] = _verify_existing_final(
                        member,
                        final_entries[member["filename"]],
                        target,
                    )
                else:
                    missing.append(member)

            staged: list[tuple[Path, Path]] = []
            for member in missing:
                partial, receipt = _stage_final_member(
                    member,
                    final_entries[member["filename"]],
                    archive,
                    destination,
                )
                staged.append((partial, destination / member["filename"]))
                final_receipts[member["filename"]] = receipt

    for partial, target in staged:
        _install_without_overwrite(partial, target)

    receipt_by_filename = {
        receipt["filename"]: receipt
        for receipt in development_receipts
    }
    receipt_by_filename.update(final_receipts)
    completed = copy.deepcopy(pending)
    completed["verification"] = {
        "status": COMPLETE_STATUS,
        "member_receipts": [
            {
                field: receipt_by_filename[member["filename"]][field]
                for field in _RECEIPT_FIELDS
            }
            for member in completed["members"]
        ],
    }
    try:
        require_completed_source_selection(completed)
    except ValueError as exc:
        raise SelectedMemberFetchError(str(exc)) from exc
    _atomic_create_json(output_path, completed)
    return completed


def _atomic_create_json(path: Path, value: Mapping[str, Any]) -> None:
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
            raise SelectedMemberFetchError(
                f"refusing to overwrite completed selection: {path}"
            ) from exc
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--selection",
        type=Path,
        default=Path("configs/next_behavior_source_selection.v1.json"),
    )
    parser.add_argument("--preserved-manifest", type=Path)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--read-ahead-mib", type=int, default=32)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.read_ahead_mib < 1:
        raise SelectedMemberFetchError("read-ahead must be positive")
    selection, preserved = load_pending_inputs(
        args.selection,
        args.preserved_manifest,
    )
    completed = retrieve_selected_members(
        selection,
        preserved,
        args.destination,
        args.output,
        read_ahead_bytes=args.read_ahead_mib * 1024 * 1024,
    )
    print(
        json.dumps(
            {
                "selection_id": completed["selection_id"],
                "status": completed["verification"]["status"],
                "member_count": len(
                    completed["verification"]["member_receipts"]
                ),
                "output": str(args.output),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
