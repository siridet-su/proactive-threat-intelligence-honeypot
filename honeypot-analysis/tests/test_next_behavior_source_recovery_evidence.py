from __future__ import annotations

import copy
import gzip
import hashlib
import io
import json
import zlib
from pathlib import Path

import pytest

from production.prediction.next_behavior_source_selection import COMPLETE_STATUS
from production.tools.verify_next_behavior_source_recovery import (
    SourceRecoveryEvidenceError,
    _atomic_create_json,
    build_source_recovery_evidence,
)


ROOT = Path(__file__).resolve().parents[1]
SELECTION_PATH = ROOT / "configs" / "next_behavior_source_selection.v1.json"
FIXED_TIME = "2026-07-23T12:00:00Z"


def _gzip_payload(label: str) -> bytes:
    output = io.BytesIO()
    with gzip.GzipFile(fileobj=output, mode="wb", mtime=0) as handle:
        # Deliberately not JSON: integrity verification must not parse events.
        handle.write(f"opaque fixture: {label}\n".encode())
    return output.getvalue()


def _completed_fixture(tmp_path: Path) -> tuple[Path, Path, dict]:
    completed = json.loads(SELECTION_PATH.read_text(encoding="utf-8"))
    source_root = tmp_path / "source"
    source_root.mkdir()
    receipts = []
    for index, member in enumerate(completed["members"], start=1):
        payload = _gzip_payload(member["filename"])
        (source_root / member["filename"]).write_bytes(payload)
        receipts.append(
            {
                "filename": member["filename"],
                "archive_path": member["archive_path"],
                "collection_date": member["collection_date"],
                "role": member["role"],
                "size_bytes": len(payload),
                "archive_compressed_bytes": max(1, len(payload) - index),
                "archive_crc32": f"{zlib.crc32(payload) & 0xFFFFFFFF:08x}",
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
    completed["verification"] = {
        "status": COMPLETE_STATUS,
        "member_receipts": receipts,
    }
    completed_path = tmp_path / "completed.json"
    completed_path.write_text(
        json.dumps(completed, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return completed_path, source_root, completed


def test_publishes_compact_privacy_safe_evidence_for_exact_members(
    tmp_path: Path,
) -> None:
    completed_path, source_root, completed = _completed_fixture(tmp_path)
    cache_root = tmp_path / "cache"
    cache_root.mkdir()

    evidence = build_source_recovery_evidence(
        completed_path,
        source_root,
        {"source_cache": cache_root, "member_directory": source_root},
        observed_at=FIXED_TIME,
    )

    assert evidence["schema_version"] == (
        "next_behavior_source_recovery_evidence.v1"
    )
    assert evidence["observed_at"] == FIXED_TIME
    assert evidence["completed_selection_sha256"] == hashlib.sha256(
        completed_path.read_bytes()
    ).hexdigest()
    assert evidence["selection_policy"] == completed["policy"]
    assert evidence["acquisition_summary"] == {
        "member_count": 13,
        "reused_verified_local": 6,
        "selectively_downloaded_archive_member": 7,
        "selective_member_retrieval": True,
    }
    assert evidence["verification"]["event_content_parsed"] is False
    assert all(
        member["gzip_integrity"] == "verified"
        for member in evidence["members"]
    )
    assert [
        member["acquisition_method"] for member in evidence["members"][:6]
    ] == ["reused_verified_local"] * 6
    assert [
        member["acquisition_method"] for member in evidence["members"][6:]
    ] == ["selectively_downloaded_archive_member"] * 7
    assert evidence["archive_absence"] == [
        {
            "root_id": "member_directory",
            "filename": "data_all.zip",
            "present": False,
            "recursive": True,
            "directory_symlinks_followed": False,
        },
        {
            "root_id": "source_cache",
            "filename": "data_all.zip",
            "present": False,
            "recursive": True,
            "directory_symlinks_followed": False,
        },
    ]
    serialized = json.dumps(evidence)
    assert str(tmp_path) not in serialized
    assert "opaque fixture" not in serialized


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        ("size", "size mismatch"),
        ("crc", "CRC32 mismatch"),
        ("sha", "SHA-256 mismatch"),
        ("gzip", "gzip integrity check failed"),
    ],
)
def test_changed_or_invalid_member_fails_closed(
    tmp_path: Path,
    mutation: str,
    expected: str,
) -> None:
    completed_path, source_root, completed = _completed_fixture(tmp_path)
    member = completed["members"][0]
    target = source_root / member["filename"]
    if mutation == "size":
        target.write_bytes(target.read_bytes() + b"x")
    elif mutation == "gzip":
        payload = b"x" * completed["verification"]["member_receipts"][0][
            "size_bytes"
        ]
        target.write_bytes(payload)
        receipt = completed["verification"]["member_receipts"][0]
        receipt["archive_crc32"] = f"{zlib.crc32(payload) & 0xFFFFFFFF:08x}"
        receipt["sha256"] = hashlib.sha256(payload).hexdigest()
        completed_path.write_text(
            json.dumps(completed, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    else:
        receipt = completed["verification"]["member_receipts"][0]
        if mutation == "crc":
            receipt["archive_crc32"] = "00000000"
        else:
            receipt["sha256"] = "0" * 64
        completed_path.write_text(
            json.dumps(completed, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    with pytest.raises(SourceRecoveryEvidenceError, match=expected):
        build_source_recovery_evidence(
            completed_path,
            source_root,
            {"cache": tmp_path},
            observed_at=FIXED_TIME,
        )


def test_mutated_selection_policy_is_rejected_before_member_use(
    tmp_path: Path,
) -> None:
    completed_path, source_root, completed = _completed_fixture(tmp_path)
    completed["policy"]["labels_used"] = True
    completed_path.write_text(json.dumps(completed), encoding="utf-8")

    with pytest.raises(
        SourceRecoveryEvidenceError,
        match="policy does not match the frozen identity",
    ):
        build_source_recovery_evidence(
            completed_path,
            source_root,
            {"cache": tmp_path},
            observed_at=FIXED_TIME,
        )


def test_full_archive_anywhere_in_declared_root_fails_closed(
    tmp_path: Path,
) -> None:
    completed_path, source_root, _ = _completed_fixture(tmp_path)
    nested = tmp_path / "cache" / "nested"
    nested.mkdir(parents=True)
    (nested / "data_all.zip").write_bytes(b"not-used")

    with pytest.raises(
        SourceRecoveryEvidenceError,
        match="data_all.zip is present in root: cache",
    ):
        build_source_recovery_evidence(
            completed_path,
            source_root,
            {"cache": tmp_path / "cache"},
            observed_at=FIXED_TIME,
        )


def test_unsafe_member_symlink_is_rejected(tmp_path: Path) -> None:
    completed_path, source_root, completed = _completed_fixture(tmp_path)
    filename = completed["members"][0]["filename"]
    target = source_root / filename
    elsewhere = tmp_path / "elsewhere.gz"
    target.replace(elsewhere)
    target.symlink_to(elsewhere)

    with pytest.raises(
        SourceRecoveryEvidenceError,
        match="missing or unsafe recovered member",
    ):
        build_source_recovery_evidence(
            completed_path,
            source_root,
            {"cache": tmp_path},
            observed_at=FIXED_TIME,
        )


def test_atomic_publication_refuses_to_overwrite(tmp_path: Path) -> None:
    output = tmp_path / "evidence.json"
    value = {"schema_version": "fixture.v1"}
    _atomic_create_json(output, value)

    assert json.loads(output.read_text(encoding="utf-8")) == value
    with pytest.raises(
        SourceRecoveryEvidenceError,
        match="refusing to overwrite evidence",
    ):
        _atomic_create_json(output, value)
