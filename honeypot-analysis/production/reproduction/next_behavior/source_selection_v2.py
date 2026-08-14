"""Fail-closed 31-member successor source-selection contracts.

This module is additive.  The historical ``next_behavior_source_selection.v1``
reader remains unchanged and is never used to reinterpret a v1 declaration.
The v2 declaration freezes a label-blind calendar protocol; archive member
hashes are deliberately populated only after the declaration has been
reviewed and the member bytes have been verified.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import date, timedelta
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Mapping, Sequence

from production.utils.serialization import stable_id, stable_json


SCHEMA_VERSION = "next_behavior_source_selection.v2"
INVENTORY_SCHEMA_VERSION = "next_behavior_successor_member_inventory.v1"
SELECTION_ID = "successor_calendar_blocks_10_7_7_7.v1"
PENDING_STATUS = "pending_archive_verification"
COMPLETE_STATUS = "archive_members_verified"

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_CRC32 = re.compile(r"^[0-9a-f]{8}$")
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
_PRESERVED_V1 = {
    "path": "configs/next_behavior_source_selection.v1.json",
    "schema_version": "next_behavior_source_selection.v1",
    "sha256": "f453502df46a79c5e934eb3377287d47815605f240d51a305ec89645b2f8f514",
}
_POLICY = {
    "selection_basis": "collection_date_only_complete_calendar_blocks",
    "labels_used": False,
    "member_sizes_used": False,
    "test_metrics_used": False,
    "substitution_allowed": False,
    "train_rule": (
        "fixed_anchors_2025-07-03_2025-07-10_2025-07-17_plus_"
        "all_daily_members_2025-07-18_through_2025-07-24"
    ),
    "selection_window_start_date": "2025-07-25",
    "selection_window_end_date": "2025-07-31",
    "calibration_window_start_date": "2025-08-01",
    "development_cutoff_date": "2025-08-07",
    "embargo_dates": ["2025-08-08"],
    "final_window_start_date": "2025-08-09",
    "final_window_end_date": "2025-08-16",
    "excluded_dates": ["2025-08-14"],
    "test_access": "sealed_until_one_final_evaluation",
}
ROLE_COUNTS = {"train": 10, "selection": 7, "calibration": 7, "test": 7}

_TOP_FIELDS = frozenset(
    {
        "schema_version",
        "selection_id",
        "preserved_source_selection",
        "source",
        "archive",
        "policy",
        "members",
        "verification",
    }
)
_MEMBER_FIELDS = frozenset(
    {
        "filename",
        "archive_path",
        "collection_date",
        "chronological_order",
        "cohort",
        "role",
        "sealed",
    }
)
_RECEIPT_FIELDS = frozenset(
    {
        "filename",
        "archive_path",
        "collection_date",
        "chronological_order",
        "cohort",
        "role",
        "sealed",
        "size_bytes",
        "archive_compressed_bytes",
        "archive_crc32",
        "sha256",
    }
)
_INVENTORY_FIELDS = frozenset(
    {
        "schema_version",
        "inventory_id",
        "status",
        "source_selection_id",
        "source_selection_sha256",
        "member_count",
        "role_counts",
        "test_members_sealed",
        "ordered_member_receipts_sha256",
        "members",
    }
)


class NextBehaviorSourceSelectionV2Error(ValueError):
    """Raised when the successor selection or inventory is unsafe."""


def _dates(start: str, end: str) -> tuple[str, ...]:
    current = date.fromisoformat(start)
    final = date.fromisoformat(end)
    values: list[str] = []
    while current <= final:
        values.append(current.isoformat())
        current += timedelta(days=1)
    return tuple(values)


TRAIN_DATES = (
    "2025-07-03",
    "2025-07-10",
    "2025-07-17",
    *_dates("2025-07-18", "2025-07-24"),
)
SELECTION_DATES = _dates("2025-07-25", "2025-07-31")
CALIBRATION_DATES = _dates("2025-08-01", "2025-08-07")
TEST_DATES = (
    "2025-08-09",
    "2025-08-10",
    "2025-08-11",
    "2025-08-12",
    "2025-08-13",
    "2025-08-15",
    "2025-08-16",
)
_EXPECTED_DATES_BY_ROLE = {
    "train": TRAIN_DATES,
    "selection": SELECTION_DATES,
    "calibration": CALIBRATION_DATES,
    "test": TEST_DATES,
}


def expected_successor_members() -> list[Dict[str, Any]]:
    """Return the exact reviewed date-only 10/7/7/7 declaration."""

    output: list[Dict[str, Any]] = []
    for role in ("train", "selection", "calibration", "test"):
        for collection_date in _EXPECTED_DATES_BY_ROLE[role]:
            filename = f"{collection_date}.json.gz"
            output.append(
                {
                    "filename": filename,
                    "archive_path": f"../logs_by_day/{filename}",
                    "collection_date": collection_date,
                    "chronological_order": len(output) + 1,
                    "cohort": "final" if role == "test" else "development",
                    "role": role,
                    "sealed": role == "test",
                }
            )
    return output


def _is_positive_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(stable_json(value).encode("utf-8")).hexdigest()


def validate_source_selection_v2(value: Any) -> list[str]:
    """Return stable errors for a pending or completed v2 declaration."""

    if not isinstance(value, dict):
        return ["source selection v2 must be an object"]
    errors: list[str] = []
    if set(value) != _TOP_FIELDS:
        errors.append("source selection v2 fields are invalid")
    if value.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"schema_version must be {SCHEMA_VERSION}")
    if value.get("selection_id") != SELECTION_ID:
        errors.append(f"selection_id must be {SELECTION_ID}")
    if value.get("preserved_source_selection") != _PRESERVED_V1:
        errors.append("preserved source selection identity changed")
    if value.get("source") != _SOURCE:
        errors.append("source identity changed")
    if value.get("archive") != _ARCHIVE:
        errors.append("archive identity changed")
    if value.get("policy") != _POLICY:
        errors.append("date-only selection policy changed")

    expected = expected_successor_members()
    members = value.get("members")
    if not isinstance(members, list) or len(members) != 31:
        errors.append("members must contain the exact reviewed 31-member selection")
        members = []
    elif members != expected:
        errors.append("members do not match the reviewed 10/7/7/7 calendar protocol")
    for index, member in enumerate(members):
        if not isinstance(member, dict) or set(member) != _MEMBER_FIELDS:
            errors.append(f"members[{index}] fields are invalid")
            continue
        if PurePosixPath(str(member.get("archive_path", ""))).name != member.get(
            "filename"
        ):
            errors.append(f"members[{index}] archive path does not match filename")

    verification = value.get("verification")
    if not isinstance(verification, dict) or set(verification) != {
        "status",
        "member_receipts",
    }:
        errors.append("verification fields are invalid")
        return errors
    status = verification.get("status")
    receipts = verification.get("member_receipts")
    if status not in {PENDING_STATUS, COMPLETE_STATUS}:
        errors.append("verification.status is invalid")
    if not isinstance(receipts, list):
        errors.append("verification.member_receipts must be an array")
        return errors
    if status == PENDING_STATUS:
        if receipts:
            errors.append("pending verification must not contain receipts")
        return errors
    if status != COMPLETE_STATUS:
        return errors
    if len(receipts) != 31:
        errors.append("completed selection requires exactly 31 member receipts")
    expected_by_name = {member["filename"]: member for member in expected}
    seen_names: list[str] = []
    seen_hashes: list[str] = []
    for index, receipt in enumerate(receipts):
        path = f"verification.member_receipts[{index}]"
        if not isinstance(receipt, dict) or set(receipt) != _RECEIPT_FIELDS:
            errors.append(f"{path} fields are invalid")
            continue
        filename = str(receipt.get("filename", "")).strip()
        seen_names.append(filename)
        declaration = expected_by_name.get(filename)
        if declaration is None:
            errors.append(f"{path} names an undeclared member")
        elif any(receipt.get(field) != declaration[field] for field in _MEMBER_FIELDS):
            errors.append(f"{path} does not match its frozen declaration")
        if not _is_positive_int(receipt.get("size_bytes")):
            errors.append(f"{path}.size_bytes must be a positive integer")
        if not _is_positive_int(receipt.get("archive_compressed_bytes")):
            errors.append(
                f"{path}.archive_compressed_bytes must be a positive integer"
            )
        crc32 = str(receipt.get("archive_crc32", "")).strip().lower()
        if not _CRC32.fullmatch(crc32):
            errors.append(f"{path}.archive_crc32 must be an 8-digit hex receipt")
        digest = str(receipt.get("sha256", "")).strip().lower()
        if not _SHA256.fullmatch(digest):
            errors.append(f"{path}.sha256 must be a SHA-256 receipt")
        else:
            seen_hashes.append(digest)
    if len(seen_names) != len(set(seen_names)):
        errors.append("receipt member filenames must be unique")
    if set(seen_names) != set(expected_by_name):
        errors.append("receipt membership does not match the frozen selection")
    if len(seen_hashes) != len(set(seen_hashes)):
        errors.append("receipt SHA-256 identities must be unique")
    return errors


def require_valid_source_selection_v2(value: Any) -> Dict[str, Any]:
    errors = validate_source_selection_v2(value)
    if errors:
        raise NextBehaviorSourceSelectionV2Error("; ".join(errors))
    return dict(value)


def require_completed_source_selection_v2(value: Any) -> Dict[str, Any]:
    selection = require_valid_source_selection_v2(value)
    if selection["verification"]["status"] != COMPLETE_STATUS:
        raise NextBehaviorSourceSelectionV2Error(
            "source selection v2 is pending archive verification"
        )
    return selection


def load_source_selection_v2(path: Path) -> Dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise NextBehaviorSourceSelectionV2Error(
            f"cannot read source selection v2: {exc}"
        ) from exc
    return require_valid_source_selection_v2(value)


def build_successor_member_inventory(
    completed_selection: Mapping[str, Any],
) -> Dict[str, Any]:
    """Freeze the verified member receipts without opening test contents."""

    selection = require_completed_source_selection_v2(dict(completed_selection))
    receipts = sorted(
        (dict(receipt) for receipt in selection["verification"]["member_receipts"]),
        key=lambda item: item["chronological_order"],
    )
    role_counts = {
        role: sum(receipt["role"] == role for receipt in receipts)
        for role in ROLE_COUNTS
    }
    basis: Dict[str, Any] = {
        "schema_version": INVENTORY_SCHEMA_VERSION,
        "status": "member_inventory_frozen",
        "source_selection_id": selection["selection_id"],
        "source_selection_sha256": _canonical_sha256(selection),
        "member_count": len(receipts),
        "role_counts": role_counts,
        "test_members_sealed": all(
            receipt["sealed"] for receipt in receipts if receipt["role"] == "test"
        ),
        "ordered_member_receipts_sha256": _canonical_sha256(receipts),
        "members": receipts,
    }
    basis["inventory_id"] = stable_id("nextbehaviorsuccessorinventory", basis)
    return require_valid_successor_member_inventory(
        basis,
        source_selection=selection,
    )


def require_valid_successor_member_inventory(
    value: Any,
    *,
    source_selection: Mapping[str, Any] | None = None,
) -> Dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _INVENTORY_FIELDS:
        raise NextBehaviorSourceSelectionV2Error(
            "successor member inventory fields are invalid"
        )
    document = dict(value)
    if document.get("schema_version") != INVENTORY_SCHEMA_VERSION:
        raise NextBehaviorSourceSelectionV2Error(
            "successor member inventory schema is invalid"
        )
    if document.get("status") != "member_inventory_frozen":
        raise NextBehaviorSourceSelectionV2Error(
            "successor member inventory is incomplete"
        )
    members = document.get("members")
    if not isinstance(members, list) or len(members) != 31:
        raise NextBehaviorSourceSelectionV2Error(
            "successor member inventory requires exactly 31 members"
        )
    if any(not isinstance(member, dict) or set(member) != _RECEIPT_FIELDS for member in members):
        raise NextBehaviorSourceSelectionV2Error(
            "successor member inventory member fields are invalid"
        )
    declarations = expected_successor_members()
    for index, member in enumerate(members):
        if any(member.get(field) != declarations[index][field] for field in _MEMBER_FIELDS):
            raise NextBehaviorSourceSelectionV2Error(
                "successor member inventory differs from the reviewed calendar protocol"
            )
        if not _is_positive_int(member.get("size_bytes")) or not _is_positive_int(
            member.get("archive_compressed_bytes")
        ):
            raise NextBehaviorSourceSelectionV2Error(
                "successor member inventory sizes are invalid"
            )
        if not _CRC32.fullmatch(str(member.get("archive_crc32", "")).lower()):
            raise NextBehaviorSourceSelectionV2Error(
                "successor member inventory CRC receipt is invalid"
            )
    orders = [member.get("chronological_order") for member in members]
    if orders != list(range(1, 32)):
        raise NextBehaviorSourceSelectionV2Error(
            "successor member inventory order is not canonical"
        )
    if document.get("member_count") != 31 or document.get("role_counts") != ROLE_COUNTS:
        raise NextBehaviorSourceSelectionV2Error(
            "successor member inventory role counts are invalid"
        )
    if document.get("test_members_sealed") is not True or any(
        member["sealed"] is not (member["role"] == "test") for member in members
    ):
        raise NextBehaviorSourceSelectionV2Error(
            "successor test members are not sealed"
        )
    for member in members:
        if not _SHA256.fullmatch(str(member.get("sha256", "")).lower()):
            raise NextBehaviorSourceSelectionV2Error(
                "successor member inventory contains an invalid SHA-256"
            )
    if len({member["sha256"] for member in members}) != 31:
        raise NextBehaviorSourceSelectionV2Error(
            "successor member inventory SHA-256 identities must be unique"
        )
    if document.get("ordered_member_receipts_sha256") != _canonical_sha256(members):
        raise NextBehaviorSourceSelectionV2Error(
            "successor member inventory receipt hash mismatch"
        )
    id_basis = {key: document[key] for key in document if key != "inventory_id"}
    if document.get("inventory_id") != stable_id(
        "nextbehaviorsuccessorinventory", id_basis
    ):
        raise NextBehaviorSourceSelectionV2Error(
            "successor member inventory identity mismatch"
        )
    if source_selection is not None:
        selection = require_completed_source_selection_v2(dict(source_selection))
        if document.get("source_selection_id") != selection["selection_id"]:
            raise NextBehaviorSourceSelectionV2Error(
                "successor inventory selection identity mismatch"
            )
        if document.get("source_selection_sha256") != _canonical_sha256(selection):
            raise NextBehaviorSourceSelectionV2Error(
                "successor inventory selection hash mismatch"
            )
        expected = sorted(
            selection["verification"]["member_receipts"],
            key=lambda item: item["chronological_order"],
        )
        if members != expected:
            raise NextBehaviorSourceSelectionV2Error(
                "successor inventory does not match completed selection receipts"
            )
    return document


def require_source_selection_v2_repository_binding(
    value: Any,
    *,
    repository_root: Path,
) -> Dict[str, Any]:
    """Verify the declared preserved v1 bytes against the repository.

    This is deliberately separate from structural loading so frozen fixtures
    can be inspected without being silently rebound to a caller's checkout.
    Preparation code must call this boundary before issuing a receipt.
    """

    selection = require_valid_source_selection_v2(value)
    reference = selection["preserved_source_selection"]
    relative = PurePosixPath(reference["path"])
    if relative.is_absolute() or ".." in relative.parts:
        raise NextBehaviorSourceSelectionV2Error(
            "preserved source selection path is unsafe"
        )
    path = repository_root.joinpath(*relative.parts)
    if not path.is_file() or path.is_symlink():
        raise NextBehaviorSourceSelectionV2Error(
            "preserved source selection file is missing or unsafe"
        )
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != reference["sha256"]:
        raise NextBehaviorSourceSelectionV2Error(
            "preserved source selection file hash mismatch"
        )
    return selection


def canonical_contract_sha256(value: Mapping[str, Any]) -> str:
    """Return the canonical content hash used by successor cross-bindings."""

    return _canonical_sha256(dict(value))
