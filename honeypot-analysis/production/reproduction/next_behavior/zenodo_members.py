#!/usr/bin/env python3
"""Fetch or verify the frozen Zenodo members for the next-behavior corpus.

Only the seven declared JSON/GZip event-log members are read from the public
``data_all.zip`` archive. The transferred-file archive is never accessed.
Extraction sanitizes the archive paths, refuses to overwrite any mismatched
local file, and verifies archive metadata, ZIP CRC, byte size, and SHA-256.
Raw members must be stored outside Git.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import time
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, Dict, Mapping, Sequence

import requests


SCHEMA_VERSION = "next_behavior_zenodo_source.v1"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MD5_RECEIPT = re.compile(r"^md5:[0-9a-f]{32}$")
_CRC32 = re.compile(r"^[0-9a-f]{8}$")
_SOURCE_FIELDS = frozenset(
    {"zenodo_record_id", "doi", "title", "license", "record_url"}
)
_ARCHIVE_FIELDS = frozenset(
    {"filename", "size_bytes", "checksum", "download_url"}
)
_SELECTION_FIELDS = frozenset(
    {
        "selection_id",
        "method",
        "member_count",
        "excluded_previously_used_members",
        "transferred_file_archive_used",
    }
)
_MEMBER_FIELDS = frozenset(
    {
        "filename",
        "archive_path",
        "collection_date",
        "chronological_order",
        "size_bytes",
        "archive_compressed_bytes",
        "archive_crc32",
        "sha256",
    }
)


class ZenodoSourceError(ValueError):
    """Raised when a source receipt or local member cannot be trusted."""


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _positive_integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(8 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def validate_source_manifest(value: Any) -> list[str]:
    if not isinstance(value, dict):
        return ["source manifest must be an object"]
    errors: list[str] = []
    if set(value) != {"schema_version", "source", "archive", "selection", "members"}:
        errors.append("source manifest fields are invalid")
    if value.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"schema_version must be {SCHEMA_VERSION}")

    source = value.get("source")
    if not isinstance(source, dict) or set(source) != _SOURCE_FIELDS:
        errors.append("source fields are invalid")
    else:
        if source.get("zenodo_record_id") != 21260400:
            errors.append("Zenodo record ID is not the frozen record")
        if source.get("doi") != "10.5281/zenodo.21260400":
            errors.append("Zenodo DOI is not the frozen DOI")
        for field in ("title", "license", "record_url"):
            if not _clean(source.get(field)):
                errors.append(f"source.{field} is required")

    archive = value.get("archive")
    if not isinstance(archive, dict) or set(archive) != _ARCHIVE_FIELDS:
        errors.append("archive fields are invalid")
    else:
        if archive.get("filename") != "data_all.zip":
            errors.append("only data_all.zip is permitted")
        if not _positive_integer(archive.get("size_bytes")):
            errors.append("archive.size_bytes must be positive")
        if not _MD5_RECEIPT.fullmatch(_clean(archive.get("checksum")).lower()):
            errors.append("archive.checksum must be an MD5 receipt")
        if not _clean(archive.get("download_url")).startswith(
            "https://zenodo.org/api/records/21260400/files/data_all.zip/"
        ):
            errors.append("archive.download_url is outside the frozen record")

    selection = value.get("selection")
    if not isinstance(selection, dict) or set(selection) != _SELECTION_FIELDS:
        errors.append("selection fields are invalid")
    else:
        if selection.get("member_count") != 7:
            errors.append("selection.member_count must be seven")
        if selection.get("transferred_file_archive_used") is not False:
            errors.append("transferred file artifacts must not be used")
        excluded = selection.get("excluded_previously_used_members")
        if not isinstance(excluded, list) or not all(
            isinstance(item, str) and item for item in excluded
        ):
            errors.append("excluded member names are invalid")

    members = value.get("members")
    if not isinstance(members, list) or len(members) != 7:
        errors.append("members must contain exactly seven entries")
        return errors
    filenames: set[str] = set()
    orders: list[int] = []
    dates: list[str] = []
    for index, member in enumerate(members):
        path = f"members[{index}]"
        if not isinstance(member, dict) or set(member) != _MEMBER_FIELDS:
            errors.append(f"{path} fields are invalid")
            continue
        filename = _clean(member.get("filename"))
        archive_path = _clean(member.get("archive_path"))
        if (
            not filename.endswith(".json.gz")
            or "/" in filename
            or PurePosixPath(archive_path).name != filename
        ):
            errors.append(f"{path} filename/path is unsafe or inconsistent")
        if filename in filenames:
            errors.append(f"{path} filename is duplicated")
        filenames.add(filename)
        for field in ("size_bytes", "archive_compressed_bytes"):
            if not _positive_integer(member.get(field)):
                errors.append(f"{path}.{field} must be positive")
        order = member.get("chronological_order")
        if not _positive_integer(order):
            errors.append(f"{path}.chronological_order must be positive")
        else:
            orders.append(order)
        collection_date = _clean(member.get("collection_date"))
        if not re.fullmatch(r"20[0-9]{2}-[01][0-9]-[0-3][0-9]", collection_date):
            errors.append(f"{path}.collection_date is invalid")
        dates.append(collection_date)
        if not _CRC32.fullmatch(_clean(member.get("archive_crc32")).lower()):
            errors.append(f"{path}.archive_crc32 is invalid")
        if not _SHA256.fullmatch(_clean(member.get("sha256")).lower()):
            errors.append(f"{path}.sha256 is invalid")
    if orders != list(range(1, 8)):
        errors.append("member chronological order must be exactly 1 through 7")
    if dates != sorted(dates):
        errors.append("members are not in chronological date order")
    return errors


def load_source_manifest(path: Path) -> Dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ZenodoSourceError(f"cannot read source manifest: {exc}") from exc
    errors = validate_source_manifest(value)
    if errors:
        raise ZenodoSourceError("; ".join(errors))
    return dict(value)


def verify_local_members(
    manifest: Mapping[str, Any],
    destination: Path,
) -> list[Dict[str, Any]]:
    errors = validate_source_manifest(manifest)
    if errors:
        raise ZenodoSourceError("; ".join(errors))
    receipts: list[Dict[str, Any]] = []
    for member in manifest["members"]:
        path = destination / member["filename"]
        if not path.is_file():
            raise ZenodoSourceError(f"missing source member: {member['filename']}")
        actual_size = path.stat().st_size
        if actual_size != member["size_bytes"]:
            raise ZenodoSourceError(
                f"source member size mismatch: {member['filename']}"
            )
        actual_sha256 = file_sha256(path)
        if actual_sha256 != member["sha256"]:
            raise ZenodoSourceError(
                f"source member SHA-256 mismatch: {member['filename']}"
            )
        receipts.append(
            {
                "filename": member["filename"],
                "size_bytes": actual_size,
                "sha256": actual_sha256,
                "status": "verified",
            }
        )
    return receipts


def verify_archive_entries(
    archive: zipfile.ZipFile,
    manifest: Mapping[str, Any],
) -> Dict[str, zipfile.ZipInfo]:
    errors = validate_source_manifest(manifest)
    if errors:
        raise ZenodoSourceError("; ".join(errors))
    entries = {entry.filename: entry for entry in archive.infolist()}
    selected: Dict[str, zipfile.ZipInfo] = {}
    for member in manifest["members"]:
        entry = entries.get(member["archive_path"])
        if entry is None:
            raise ZenodoSourceError(
                f"archive member is missing: {member['filename']}"
            )
        observed = (
            entry.file_size,
            entry.compress_size,
            f"{entry.CRC:08x}",
        )
        expected = (
            member["size_bytes"],
            member["archive_compressed_bytes"],
            member["archive_crc32"],
        )
        if observed != expected:
            raise ZenodoSourceError(
                f"archive metadata mismatch: {member['filename']}"
            )
        selected[member["filename"]] = entry
    return selected


def extract_members(
    archive: zipfile.ZipFile,
    manifest: Mapping[str, Any],
    destination: Path,
) -> list[Dict[str, Any]]:
    """Extract selected entries without trusting their archive paths."""

    selected = verify_archive_entries(archive, manifest)
    destination.mkdir(parents=True, exist_ok=True)
    receipts: list[Dict[str, Any]] = []
    members = {member["filename"]: member for member in manifest["members"]}
    for filename, member in members.items():
        target = destination / filename
        if target.exists():
            actual_size = target.stat().st_size
            actual_hash = (
                file_sha256(target)
                if target.is_file() and actual_size == member["size_bytes"]
                else ""
            )
            if (
                not target.is_file()
                or actual_size != member["size_bytes"]
                or actual_hash != member["sha256"]
            ):
                raise ZenodoSourceError(
                    f"refusing to overwrite mismatched source member: {filename}"
                )
            receipts.append(
                {
                    "filename": filename,
                    "size_bytes": actual_size,
                    "sha256": actual_hash,
                    "status": "verified_existing",
                }
            )
            continue

        partial = destination / (
            f".{filename}.part.{os.getpid()}.{int(time.time())}"
        )
        digest = hashlib.sha256()
        written = 0
        try:
            with archive.open(selected[filename], "r") as source, partial.open(
                "xb"
            ) as output:
                for block in iter(lambda: source.read(8 * 1024 * 1024), b""):
                    output.write(block)
                    digest.update(block)
                    written += len(block)
                output.flush()
                os.fsync(output.fileno())
            if (
                written != member["size_bytes"]
                or digest.hexdigest() != member["sha256"]
            ):
                raise ZenodoSourceError(
                    f"downloaded source member failed verification: {filename}"
                )
            if target.exists():
                raise ZenodoSourceError(
                    f"source member appeared during extraction: {filename}"
                )
            partial.replace(target)
        except BaseException:
            # Preserve the uniquely named partial for forensic inspection.
            raise
        receipts.append(
            {
                "filename": filename,
                "size_bytes": written,
                "sha256": digest.hexdigest(),
                "status": "downloaded_and_verified",
            }
        )
    return receipts


class HttpRangeReader(io.RawIOBase):
    """Seekable HTTP byte-range reader used by ``zipfile.ZipFile``."""

    def __init__(
        self,
        url: str,
        *,
        expected_size: int,
        read_ahead_bytes: int = 32 * 1024 * 1024,
    ) -> None:
        self.url = url
        self.expected_size = expected_size
        self.read_ahead_bytes = read_ahead_bytes
        self.session = requests.Session()
        response = self.session.head(url, allow_redirects=True, timeout=60)
        response.raise_for_status()
        observed_size = int(response.headers.get("Content-Length") or 0)
        if observed_size != expected_size:
            raise ZenodoSourceError("remote archive size does not match manifest")
        self.position = 0
        self.cache_start = 0
        self.cache = b""

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        return self.position

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        if whence == io.SEEK_SET:
            position = offset
        elif whence == io.SEEK_CUR:
            position = self.position + offset
        elif whence == io.SEEK_END:
            position = self.expected_size + offset
        else:
            raise ValueError(f"unsupported seek mode: {whence}")
        if position < 0:
            raise ValueError("negative seek")
        self.position = min(position, self.expected_size)
        return self.position

    def read(self, size: int = -1) -> bytes:
        if self.position >= self.expected_size:
            return b""
        if size is None or size < 0:
            size = self.expected_size - self.position
        remaining = min(size, self.expected_size - self.position)
        output: list[bytes] = []
        while remaining:
            cache_end = self.cache_start + len(self.cache)
            if not (self.cache_start <= self.position < cache_end):
                fetch_size = max(remaining, self.read_ahead_bytes)
                end = min(self.position + fetch_size, self.expected_size) - 1
                response = self.session.get(
                    self.url,
                    headers={"Range": f"bytes={self.position}-{end}"},
                    timeout=300,
                )
                response.raise_for_status()
                if response.status_code != 206:
                    raise ZenodoSourceError("server ignored the required byte range")
                self.cache_start = self.position
                self.cache = response.content
                cache_end = self.cache_start + len(self.cache)
            offset = self.position - self.cache_start
            take = min(remaining, cache_end - self.position)
            output.append(self.cache[offset : offset + take])
            self.position += take
            remaining -= take
        return b"".join(output)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path("configs/next_behavior_zenodo_source.v1.json"),
    )
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--verify-only", action="store_true")
    parser.add_argument("--read-ahead-mib", type=int, default=32)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    manifest = load_source_manifest(args.manifest)
    if args.verify_only:
        receipts = verify_local_members(manifest, args.destination)
        mode = "verify_only"
    else:
        if args.read_ahead_mib < 1:
            raise ZenodoSourceError("read-ahead must be positive")
        reader: BinaryIO = HttpRangeReader(
            manifest["archive"]["download_url"],
            expected_size=manifest["archive"]["size_bytes"],
            read_ahead_bytes=args.read_ahead_mib * 1024 * 1024,
        )
        with zipfile.ZipFile(reader) as archive:
            receipts = extract_members(archive, manifest, args.destination)
        mode = "fetch_and_verify"
    print(
        json.dumps(
            {
                "schema_version": SCHEMA_VERSION,
                "status": "verified",
                "mode": mode,
                "member_count": len(receipts),
                "members": receipts,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0
