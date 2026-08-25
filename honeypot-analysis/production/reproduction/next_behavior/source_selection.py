"""Fail-closed source selection for the corrected-target experiment.

The original seven-member source manifest remains a historical v1 artifact.
This additive contract freezes a date-only development/final selection and
allows archive-entry receipts to be populated later. A pending contract is
valid as a declaration, but it cannot be used as a completed selection.
"""

from __future__ import annotations

import json
import re
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List, Mapping


SCHEMA_VERSION = "next_behavior_source_selection.v1"
SELECTION_ID = "corrected_target_calendar_selection.v1"
PENDING_STATUS = "pending_archive_verification"
COMPLETE_STATUS = "archive_members_verified"

_TOP_FIELDS = frozenset(
    {
        "schema_version",
        "selection_id",
        "preserved_source_manifest",
        "source",
        "archive",
        "policy",
        "forbidden_final_members",
        "members",
        "verification",
    }
)
_PRESERVED_MANIFEST = {
    "path": "configs/next_behavior_zenodo_source.v1.json",
    "schema_version": "next_behavior_zenodo_source.v1",
    "sha256": "a82f2c71251a241eac7294ced9dc41d6ca22e72e1358babc902c4eabcdc59e6f",
}
_SOURCE = {
    "zenodo_record_id": 21260400,
    "doi": "10.5281/zenodo.21260400",
}
_ARCHIVE = {
    "filename": "data_all.zip",
    "size_bytes": 19372965772,
    "checksum": "md5:5b6d6e77e5f7247ac400d2318cef7adb",
    "download_url": (
        "https://zenodo.org/api/records/21260400/files/data_all.zip/content"
    ),
}
_POLICY = {
    "selection_basis": "collection_date_only",
    "development_cutoff_date": "2025-08-07",
    "embargo_dates": ["2025-08-08"],
    "final_window_start_date": "2025-08-09",
    "final_window_end_date": "2025-08-16",
    "development_rule": (
        "fixed_weekly_members_from_preserved_v1_through_cutoff"
    ),
    "final_rule": (
        "all_daily_members_in_final_window_except_forbidden_dates"
    ),
    "labels_used": False,
    "member_sizes_used": False,
    "substitution_allowed": False,
}
_DEVELOPMENT_DATES = (
    "2025-07-03",
    "2025-07-10",
    "2025-07-17",
    "2025-07-24",
    "2025-07-31",
    "2025-08-07",
)
_FINAL_DATES = (
    "2025-08-09",
    "2025-08-10",
    "2025-08-11",
    "2025-08-12",
    "2025-08-13",
    "2025-08-15",
    "2025-08-16",
)
_EXPECTED_MEMBERS = tuple(
    (f"{date}.json.gz", date, "development")
    for date in _DEVELOPMENT_DATES
) + tuple((f"{date}.json.gz", date, "final") for date in _FINAL_DATES)
_FORBIDDEN_FINAL_MEMBERS = (
    "2025-06-27.json.gz",
    "2025-06-29.json.gz",
    "2025-07-03.json.gz",
    "2025-07-10.json.gz",
    "2025-07-17.json.gz",
    "2025-07-24.json.gz",
    "2025-07-31.json.gz",
    "2025-08-07.json.gz",
    "2025-08-14.json.gz",
    "2025-08-17.json.gz",
)
_MEMBER_FIELDS = frozenset(
    {
        "filename",
        "archive_path",
        "collection_date",
        "chronological_order",
        "role",
    }
)
_VERIFICATION_FIELDS = frozenset({"status", "member_receipts"})
_RECEIPT_FIELDS = frozenset(
    {
        "filename",
        "archive_path",
        "collection_date",
        "role",
        "size_bytes",
        "archive_compressed_bytes",
        "archive_crc32",
        "sha256",
    }
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_CRC32 = re.compile(r"^[0-9a-f]{8}$")


class NextBehaviorSourceSelectionError(ValueError):
    """Raised when the corrected-target source selection is unsafe."""


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _positive_integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _expected_archive_path(filename: str) -> str:
    return f"../logs_by_day/{filename}"


def _validate_fixed_identity(
    value: Any,
    expected: Mapping[str, Any],
    path: str,
    errors: List[str],
) -> None:
    if not isinstance(value, dict) or value != expected:
        errors.append(f"{path} does not match the frozen identity")


def _validate_members(value: Any, errors: List[str]) -> List[Mapping[str, Any]]:
    if not isinstance(value, list):
        errors.append("members must be an array")
        return []
    if len(value) != len(_EXPECTED_MEMBERS):
        errors.append("members must contain the exact 13-member selection")

    members: List[Mapping[str, Any]] = []
    filenames: List[str] = []
    archive_paths: List[str] = []
    dates: List[str] = []
    for index, member in enumerate(value):
        path = f"members[{index}]"
        if not isinstance(member, dict) or set(member) != _MEMBER_FIELDS:
            errors.append(f"{path} fields are invalid")
            continue
        members.append(member)
        filename = _clean(member.get("filename"))
        archive_path = _clean(member.get("archive_path"))
        collection_date = _clean(member.get("collection_date"))
        role = _clean(member.get("role"))
        filenames.append(filename)
        archive_paths.append(archive_path)
        dates.append(collection_date)
        if PurePosixPath(archive_path).name != filename:
            errors.append(f"{path} archive path does not identify its filename")
        if index < len(_EXPECTED_MEMBERS):
            expected_filename, expected_date, expected_role = _EXPECTED_MEMBERS[index]
            expected = {
                "filename": expected_filename,
                "archive_path": _expected_archive_path(expected_filename),
                "collection_date": expected_date,
                "chronological_order": index + 1,
                "role": expected_role,
            }
            if member != expected:
                errors.append(f"{path} does not match the frozen member and role")

    if len(filenames) != len(set(filenames)):
        errors.append("member filenames must be unique")
    if len(archive_paths) != len(set(archive_paths)):
        errors.append("member archive paths must be unique")
    if len(dates) != len(set(dates)):
        errors.append("member collection dates must be unique")
    final_names = {
        _clean(member.get("filename"))
        for member in members
        if member.get("role") == "final"
    }
    forbidden_overlap = sorted(final_names.intersection(_FORBIDDEN_FINAL_MEMBERS))
    if forbidden_overlap:
        errors.append(
            "final selection contains forbidden members: "
            + ", ".join(forbidden_overlap)
        )
    return members


def _validate_verification(
    value: Any,
    members: List[Mapping[str, Any]],
    errors: List[str],
) -> None:
    if not isinstance(value, dict) or set(value) != _VERIFICATION_FIELDS:
        errors.append("verification fields are invalid")
        return
    status = value.get("status")
    receipts = value.get("member_receipts")
    if status not in {PENDING_STATUS, COMPLETE_STATUS}:
        errors.append("verification.status is invalid")
    if not isinstance(receipts, list):
        errors.append("verification.member_receipts must be an array")
        return
    if status == PENDING_STATUS:
        if receipts:
            errors.append("pending verification must not contain partial receipts")
        return
    if status != COMPLETE_STATUS:
        return
    if len(receipts) != len(_EXPECTED_MEMBERS):
        errors.append("completed selection requires one receipt per member")

    expected_by_filename = {
        _clean(member.get("filename")): member for member in members
    }
    receipt_names: List[str] = []
    receipt_hashes: List[str] = []
    for index, receipt in enumerate(receipts):
        path = f"verification.member_receipts[{index}]"
        if not isinstance(receipt, dict) or set(receipt) != _RECEIPT_FIELDS:
            errors.append(f"{path} fields are invalid")
            continue
        filename = _clean(receipt.get("filename"))
        receipt_names.append(filename)
        expected = expected_by_filename.get(filename)
        if expected is None:
            errors.append(f"{path} names an unselected or forbidden member")
        else:
            for field in ("archive_path", "collection_date", "role"):
                if receipt.get(field) != expected.get(field):
                    errors.append(f"{path}.{field} does not match selection")
        for field in ("size_bytes", "archive_compressed_bytes"):
            if not _positive_integer(receipt.get(field)):
                errors.append(f"{path}.{field} must be a positive integer")
        crc32 = _clean(receipt.get("archive_crc32")).lower()
        if not _CRC32.fullmatch(crc32):
            errors.append(f"{path}.archive_crc32 must be an 8-digit hex receipt")
        sha256 = _clean(receipt.get("sha256")).lower()
        if not _SHA256.fullmatch(sha256):
            errors.append(f"{path}.sha256 must be a SHA-256 receipt")
        else:
            receipt_hashes.append(sha256)
    if len(receipt_names) != len(set(receipt_names)):
        errors.append("receipt member filenames must be unique")
    if set(receipt_names) != set(expected_by_filename):
        errors.append("receipt membership does not match the frozen selection")
    if len(receipt_hashes) != len(set(receipt_hashes)):
        errors.append("receipt SHA-256 identities must be unique")


def validate_source_selection(value: Any) -> List[str]:
    """Return stable errors for a pending or fully receipted selection."""

    if not isinstance(value, dict):
        return ["source selection must be an object"]
    errors: List[str] = []
    if set(value) != _TOP_FIELDS:
        errors.append("source selection fields are invalid")
    if value.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"schema_version must be {SCHEMA_VERSION}")
    if value.get("selection_id") != SELECTION_ID:
        errors.append(f"selection_id must be {SELECTION_ID}")
    _validate_fixed_identity(
        value.get("preserved_source_manifest"),
        _PRESERVED_MANIFEST,
        "preserved_source_manifest",
        errors,
    )
    _validate_fixed_identity(value.get("source"), _SOURCE, "source", errors)
    _validate_fixed_identity(value.get("archive"), _ARCHIVE, "archive", errors)
    _validate_fixed_identity(value.get("policy"), _POLICY, "policy", errors)
    if value.get("forbidden_final_members") != list(_FORBIDDEN_FINAL_MEMBERS):
        errors.append("forbidden_final_members does not match the frozen list")
    members = _validate_members(value.get("members"), errors)
    _validate_verification(value.get("verification"), members, errors)
    return errors


def require_valid_source_selection(value: Any) -> Dict[str, Any]:
    """Return a valid declaration, including an explicitly pending one."""

    errors = validate_source_selection(value)
    if errors:
        raise NextBehaviorSourceSelectionError("; ".join(errors))
    return dict(value)


def require_completed_source_selection(value: Any) -> Dict[str, Any]:
    """Require exact membership plus complete archive SHA/CRC receipts."""

    selection = require_valid_source_selection(value)
    if selection["verification"]["status"] != COMPLETE_STATUS:
        raise NextBehaviorSourceSelectionError(
            "source selection is pending archive verification"
        )
    return selection


def load_source_selection(path: Path) -> Dict[str, Any]:
    """Load and validate a source-selection declaration without downloading."""

    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise NextBehaviorSourceSelectionError(
            f"cannot read source selection: {exc}"
        ) from exc
    return require_valid_source_selection(value)
