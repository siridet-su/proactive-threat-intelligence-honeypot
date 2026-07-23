from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import zipfile

import pytest

from production.tools.fetch_next_behavior_zenodo_members import (
    SCHEMA_VERSION,
    ZenodoSourceError,
    extract_members,
    load_source_manifest,
    validate_source_manifest,
    verify_archive_entries,
    verify_local_members,
)


def _manifest(payloads: list[tuple[str, bytes]]) -> dict:
    members = []
    for index, (filename, payload) in enumerate(payloads, start=1):
        members.append(
            {
                "filename": filename,
                "archive_path": f"../logs_by_day/{filename}",
                "collection_date": f"2025-07-{index:02d}",
                "chronological_order": index,
                "size_bytes": len(payload),
                "archive_compressed_bytes": 1,
                "archive_crc32": "00000000",
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
    while len(members) < 7:
        index = len(members) + 1
        payload = f"member-{index}".encode()
        members.append(
            {
                "filename": f"2025-07-{index:02d}.json.gz",
                "archive_path": f"../logs_by_day/2025-07-{index:02d}.json.gz",
                "collection_date": f"2025-07-{index:02d}",
                "chronological_order": index,
                "size_bytes": len(payload),
                "archive_compressed_bytes": 1,
                "archive_crc32": "00000000",
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "source": {
            "zenodo_record_id": 21260400,
            "doi": "10.5281/zenodo.21260400",
            "title": "fixture",
            "license": "CC-BY-4.0",
            "record_url": "https://zenodo.org/records/21260400",
        },
        "archive": {
            "filename": "data_all.zip",
            "size_bytes": 123,
            "checksum": "md5:" + "a" * 32,
            "download_url": (
                "https://zenodo.org/api/records/21260400/"
                "files/data_all.zip/content"
            ),
        },
        "selection": {
            "selection_id": "fixture",
            "method": "fixture",
            "member_count": 7,
            "excluded_previously_used_members": [],
            "transferred_file_archive_used": False,
        },
        "members": members,
    }


def _write_archive(
    path: Path,
    manifest: dict,
    payloads: dict[str, bytes],
) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for member in manifest["members"]:
            payload = payloads[member["filename"]]
            archive.writestr(member["archive_path"], payload)
    with zipfile.ZipFile(path) as archive:
        entries = {entry.filename: entry for entry in archive.infolist()}
    for member in manifest["members"]:
        entry = entries[member["archive_path"]]
        member["archive_compressed_bytes"] = entry.compress_size
        member["archive_crc32"] = f"{entry.CRC:08x}"


def _seven_payloads() -> dict[str, bytes]:
    return {
        f"2025-07-{index:02d}.json.gz": f"payload-{index}".encode()
        for index in range(1, 8)
    }


def test_versioned_manifest_loads_and_real_receipts_are_strict() -> None:
    manifest = load_source_manifest(
        Path("configs/next_behavior_zenodo_source.v1.json")
    )
    assert manifest["source"]["zenodo_record_id"] == 21260400
    assert len(manifest["members"]) == 7
    assert validate_source_manifest(manifest) == []
    assert all(len(member["sha256"]) == 64 for member in manifest["members"])


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        (
            lambda value: value["selection"].__setitem__(
                "transferred_file_archive_used", True
            ),
            "transferred file artifacts",
        ),
        (
            lambda value: value["archive"].__setitem__(
                "download_url", "https://example.invalid/data_all.zip"
            ),
            "outside the frozen record",
        ),
        (
            lambda value: value["members"][0].__setitem__(
                "archive_path", "../../transferred_files.zip"
            ),
            "unsafe or inconsistent",
        ),
        (
            lambda value: value["members"][0].__setitem__("sha256", "copied"),
            "sha256 is invalid",
        ),
    ],
)
def test_manifest_rejects_unsafe_or_unverifiable_sources(
    mutation,
    expected: str,
) -> None:
    value = _manifest([])
    mutation(value)
    assert expected in "; ".join(validate_source_manifest(value))


def test_archive_metadata_and_extraction_are_verified(tmp_path: Path) -> None:
    payloads = _seven_payloads()
    manifest = _manifest(list(payloads.items()))
    archive_path = tmp_path / "source.zip"
    _write_archive(archive_path, manifest, payloads)
    destination = tmp_path / "raw"

    with zipfile.ZipFile(archive_path) as archive:
        assert len(verify_archive_entries(archive, manifest)) == 7
        receipts = extract_members(archive, manifest, destination)

    assert len(receipts) == 7
    assert all(receipt["status"] == "downloaded_and_verified" for receipt in receipts)
    assert verify_local_members(manifest, destination) == [
        {
            "filename": filename,
            "size_bytes": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
            "status": "verified",
        }
        for filename, payload in payloads.items()
    ]
    assert not (tmp_path / "logs_by_day").exists()


def test_existing_mismatch_is_never_overwritten(tmp_path: Path) -> None:
    payloads = _seven_payloads()
    manifest = _manifest(list(payloads.items()))
    archive_path = tmp_path / "source.zip"
    _write_archive(archive_path, manifest, payloads)
    destination = tmp_path / "raw"
    destination.mkdir()
    target = destination / manifest["members"][0]["filename"]
    target.write_bytes(b"unrelated-existing-data")

    with zipfile.ZipFile(archive_path) as archive:
        with pytest.raises(ZenodoSourceError, match="refusing to overwrite"):
            extract_members(archive, manifest, destination)

    assert target.read_bytes() == b"unrelated-existing-data"


def test_archive_metadata_mismatch_fails_before_writes(tmp_path: Path) -> None:
    payloads = _seven_payloads()
    manifest = _manifest(list(payloads.items()))
    archive_path = tmp_path / "source.zip"
    _write_archive(archive_path, manifest, payloads)
    forged = copy.deepcopy(manifest)
    forged["members"][0]["archive_crc32"] = "deadbeef"
    destination = tmp_path / "raw"

    with zipfile.ZipFile(archive_path) as archive:
        with pytest.raises(ZenodoSourceError, match="archive metadata mismatch"):
            extract_members(archive, forged, destination)

    assert not destination.exists()


def test_local_hash_mismatch_fails_closed(tmp_path: Path) -> None:
    payloads = _seven_payloads()
    manifest = _manifest(list(payloads.items()))
    destination = tmp_path / "raw"
    destination.mkdir()
    for filename, payload in payloads.items():
        (destination / filename).write_bytes(payload)
    manifest["members"][3]["sha256"] = hashlib.sha256(b"other").hexdigest()

    with pytest.raises(ZenodoSourceError, match="SHA-256 mismatch"):
        verify_local_members(manifest, destination)


def test_manifest_loader_rejects_extra_fields(tmp_path: Path) -> None:
    value = _manifest([])
    value["secret_path"] = "/private/raw"
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ZenodoSourceError, match="fields are invalid"):
        load_source_manifest(path)
