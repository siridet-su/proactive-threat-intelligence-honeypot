from __future__ import annotations

import copy
import hashlib
from pathlib import Path

import pytest

from production.reproduction.next_behavior.source_selection import (
    COMPLETE_STATUS,
    NextBehaviorSourceSelectionError,
    load_source_selection,
    require_completed_source_selection,
    validate_source_selection,
)


ROOT = Path(__file__).resolve().parents[1]
SELECTION_PATH = ROOT / "configs" / "next_behavior_source_selection.v1.json"
V1_SOURCE_PATH = ROOT / "configs" / "next_behavior_zenodo_source.v1.json"
EXPECTED_V1_SHA256 = (
    "a82f2c71251a241eac7294ced9dc41d6ca22e72e1358babc902c4eabcdc59e6f"
)
DEV_DATES = [
    "2025-07-03",
    "2025-07-10",
    "2025-07-17",
    "2025-07-24",
    "2025-07-31",
    "2025-08-07",
]
FINAL_DATES = [
    "2025-08-09",
    "2025-08-10",
    "2025-08-11",
    "2025-08-12",
    "2025-08-13",
    "2025-08-15",
    "2025-08-16",
]
FORBIDDEN_FINAL = [
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
]


def _selection() -> dict:
    return load_source_selection(SELECTION_PATH)


def _complete(value: dict) -> dict:
    completed = copy.deepcopy(value)
    completed["verification"] = {
        "status": COMPLETE_STATUS,
        "member_receipts": [
            {
                "filename": member["filename"],
                "archive_path": member["archive_path"],
                "collection_date": member["collection_date"],
                "role": member["role"],
                "size_bytes": 1000 + index,
                "archive_compressed_bytes": 900 + index,
                "archive_crc32": f"{index:08x}",
                "sha256": hashlib.sha256(
                    member["filename"].encode("utf-8")
                ).hexdigest(),
            }
            for index, member in enumerate(completed["members"], start=1)
        ],
    }
    return completed


def test_contract_preserves_v1_and_freezes_date_only_selection() -> None:
    selection = _selection()

    assert hashlib.sha256(V1_SOURCE_PATH.read_bytes()).hexdigest() == (
        EXPECTED_V1_SHA256
    )
    assert selection["preserved_source_manifest"]["sha256"] == EXPECTED_V1_SHA256
    assert selection["archive"] == {
        "filename": "data_all.zip",
        "size_bytes": 19372965772,
        "checksum": "md5:5b6d6e77e5f7247ac400d2318cef7adb",
        "download_url": (
            "https://zenodo.org/api/records/21260400/"
            "files/data_all.zip/content"
        ),
    }
    assert selection["policy"]["development_cutoff_date"] == "2025-08-07"
    assert selection["policy"]["embargo_dates"] == ["2025-08-08"]
    assert selection["policy"]["labels_used"] is False
    assert selection["policy"]["member_sizes_used"] is False
    assert selection["policy"]["substitution_allowed"] is False
    assert [
        member["collection_date"]
        for member in selection["members"]
        if member["role"] == "development"
    ] == DEV_DATES
    assert [
        member["collection_date"]
        for member in selection["members"]
        if member["role"] == "final"
    ] == FINAL_DATES
    assert selection["forbidden_final_members"] == FORBIDDEN_FINAL


def test_pending_contract_has_no_fabricated_receipts_and_cannot_complete() -> None:
    selection = _selection()

    assert selection["verification"] == {
        "status": "pending_archive_verification",
        "member_receipts": [],
    }
    with pytest.raises(
        NextBehaviorSourceSelectionError,
        match="pending archive verification",
    ):
        require_completed_source_selection(selection)


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        (
            lambda value: value["archive"].__setitem__("size_bytes", 1),
            "archive does not match the frozen identity",
        ),
        (
            lambda value: value["policy"].__setitem__("labels_used", True),
            "policy does not match the frozen identity",
        ),
        (
            lambda value: value["members"].pop(),
            "exact 13-member selection",
        ),
        (
            lambda value: value["members"][6].__setitem__(
                "filename", "2025-08-14.json.gz"
            ),
            "frozen member and role",
        ),
        (
            lambda value: value["members"][6].__setitem__(
                "role", "development"
            ),
            "frozen member and role",
        ),
        (
            lambda value: value["forbidden_final_members"].remove(
                "2025-08-17.json.gz"
            ),
            "frozen list",
        ),
    ],
)
def test_changed_missing_or_forbidden_selection_fails_closed(
    mutation,
    expected: str,
) -> None:
    selection = _selection()
    mutation(selection)

    assert expected in "; ".join(validate_source_selection(selection))


def test_completed_selection_requires_exact_unique_sha_crc_receipts() -> None:
    completed = _complete(_selection())

    assert require_completed_source_selection(completed) == completed

    missing = copy.deepcopy(completed)
    missing["verification"]["member_receipts"].pop()
    with pytest.raises(
        NextBehaviorSourceSelectionError,
        match="one receipt per member",
    ):
        require_completed_source_selection(missing)

    changed = copy.deepcopy(completed)
    changed["verification"]["member_receipts"][0]["collection_date"] = (
        "2025-07-04"
    )
    with pytest.raises(
        NextBehaviorSourceSelectionError,
        match="collection_date does not match selection",
    ):
        require_completed_source_selection(changed)

    invalid_sha = copy.deepcopy(completed)
    invalid_sha["verification"]["member_receipts"][0]["sha256"] = "pending"
    with pytest.raises(
        NextBehaviorSourceSelectionError,
        match="SHA-256 receipt",
    ):
        require_completed_source_selection(invalid_sha)

    invalid_crc = copy.deepcopy(completed)
    invalid_crc["verification"]["member_receipts"][0]["archive_crc32"] = ""
    with pytest.raises(
        NextBehaviorSourceSelectionError,
        match="8-digit hex receipt",
    ):
        require_completed_source_selection(invalid_crc)


def test_partial_or_duplicate_receipts_are_never_accepted() -> None:
    pending = _selection()
    pending["verification"]["member_receipts"] = [
        _complete(pending)["verification"]["member_receipts"][0]
    ]
    with pytest.raises(
        NextBehaviorSourceSelectionError,
        match="must not contain partial receipts",
    ):
        require_completed_source_selection(pending)

    duplicate = _complete(_selection())
    duplicate["verification"]["member_receipts"][-1] = copy.deepcopy(
        duplicate["verification"]["member_receipts"][0]
    )
    with pytest.raises(
        NextBehaviorSourceSelectionError,
        match="filenames must be unique",
    ):
        require_completed_source_selection(duplicate)
