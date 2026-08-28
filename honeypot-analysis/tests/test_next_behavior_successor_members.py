from __future__ import annotations

import copy
import hashlib
import io
import json
import sqlite3
import zipfile
from pathlib import Path

import pytest

import production.reproduction.next_behavior.successor_members as successor_members
from production.reproduction.next_behavior.selected_store import (
    final_member_receipts_sha256,
)
from production.reproduction.next_behavior.source_selection_v2 import (
    NextBehaviorSourceSelectionV2Error,
    require_valid_source_selection_v2,
)
from production.reproduction.next_behavior.successor_members import (
    SuccessorMemberStagingError,
    _sha256,
    _write_json_pair_exclusive,
    _write_receipt_exclusive,
    finalize_successor_inventory,
    require_valid_staging_receipt,
    resolve_preserved_test_member_receipts,
    stage_development_members,
)


ROOT = Path(__file__).resolve().parents[1]
SELECTION_PATH = ROOT / "configs" / "next_behavior_source_selection.v2.json"


@pytest.fixture(autouse=True)
def _reviewed_test_mount(tmp_path, monkeypatch):
    mountpoint = tmp_path
    member_root = mountpoint / "next-behavior-successor" / "member-inventory"
    monkeypatch.setattr(successor_members, "SUCCESSOR_STORAGE_MOUNT", mountpoint)
    monkeypatch.setattr(successor_members, "SUCCESSOR_MEMBER_ROOT", member_root)

    def probe(path: Path) -> dict:
        assert path == mountpoint
        return {
            "mount_target": str(mountpoint),
            "source": "/dev/test-successor",
            "fstype": "ext4",
            "mount_options": ["rw", "nosuid", "nodev"],
            "super_options": ["rw"],
            "available_bytes": 80 * 1024 * 1024 * 1024,
            "writable": True,
        }

    monkeypatch.setattr(successor_members, "_default_mount_probe", probe)


def _destination(tmp_path: Path) -> Path:
    return tmp_path / "next-behavior-successor" / "member-inventory"


def _pending_selection() -> dict:
    return json.loads(SELECTION_PATH.read_text(encoding="utf-8"))


def _archive(selection: dict, *, omit: str | None = None) -> tuple[bytes, dict[str, bytes]]:
    output = io.BytesIO()
    payloads: dict[str, bytes] = {}
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for member in selection["members"]:
            if member["filename"] == omit:
                continue
            payload = (
                f"synthetic-successor-member:{member['collection_date']}\n".encode()
                * (member["chronological_order"] + 1)
            )
            payloads[member["filename"]] = payload
            archive.writestr(member["archive_path"], payload)
    return output.getvalue(), payloads


class _RangeOnlyFactory:
    def __init__(self, archive_bytes: bytes) -> None:
        self.archive_bytes = archive_bytes
        self.calls: list[dict] = []

    def __call__(self, url: str, *, expected_size: int, read_ahead_bytes: int):
        self.calls.append(
            {
                "url": url,
                "expected_size": expected_size,
                "read_ahead_bytes": read_ahead_bytes,
            }
        )
        return io.BytesIO(self.archive_bytes)


def _completed_selection(selection: dict, archive_bytes: bytes, payloads: dict[str, bytes]) -> dict:
    completed = copy.deepcopy(selection)
    receipts = []
    with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
        entries = {entry.filename: entry for entry in archive.infolist()}
        for member in completed["members"]:
            entry = entries[member["archive_path"]]
            receipts.append(
                {
                    **member,
                    "size_bytes": entry.file_size,
                    "archive_compressed_bytes": entry.compress_size,
                    "archive_crc32": f"{entry.CRC:08x}",
                    "sha256": hashlib.sha256(payloads[member["filename"]]).hexdigest(),
                }
            )
    completed["verification"] = {
        "status": "archive_members_verified",
        "member_receipts": receipts,
    }
    require_valid_source_selection_v2(completed)
    return completed


def _artifact_identity(value: dict) -> str:
    return hashlib.sha256(
        (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    ).hexdigest()


def _restamp_staging_receipt(receipt: dict) -> None:
    receipt["ordered_member_metadata_sha256"] = _sha256(
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
            for member in receipt["members"]
        ]
    )
    receipt["ordered_development_content_sha256"] = _sha256(
        [
            {"filename": member["filename"], "sha256": member["content_sha256"]}
            for member in receipt["members"]
            if member["role"] != "test"
        ]
    )
    basis = {key: receipt[key] for key in receipt if key != "receipt_sha256"}
    receipt["receipt_sha256"] = _sha256(basis)


def _preserved_store_state(
    tmp_path: Path,
    selection: dict,
    archive_bytes: bytes,
    payloads: dict[str, bytes],
    monkeypatch,
) -> tuple[Path, Path, str, Path, str, list[dict]]:
    with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
        entries = {entry.filename: entry for entry in archive.infolist()}
        members = []
        test_declarations = [
            item for item in selection["members"] if item["role"] == "test"
        ]
        for order, declaration in enumerate(test_declarations, start=7):
            entry = entries[declaration["archive_path"]]
            members.append(
                {
                    "filename": declaration["filename"],
                    "source_sha256": hashlib.sha256(
                        payloads[declaration["filename"]]
                    ).hexdigest(),
                    "source_size_bytes": entry.file_size,
                    "archive_crc32": f"{entry.CRC:08x}",
                    "chronological_order": order,
                    "source_cohort": "final",
                    "experiment_role": "test",
                }
            )
    member_hash = final_member_receipts_sha256(members)
    monkeypatch.setattr(
        successor_members,
        "PRESERVED_FINAL_MEMBER_RECEIPTS_SHA256",
        member_hash,
    )
    preparation = {
        "schema_version": "next_behavior_final_corpus_preparation.v1",
        "status": "frozen_for_blinded_preparation",
        "purpose": "prepare_final_corpus",
        "evaluation_opened": False,
        "receipt_id": successor_members.PRESERVED_PREPARATION_RECEIPT_ID,
        "source_selection_sha256": (
            successor_members.PRESERVED_SOURCE_SELECTION_SHA256
        ),
        "final_source_member_count": 7,
        "final_source_member_receipts_sha256": member_hash,
    }
    preparation_sha = _artifact_identity(preparation)
    preparation_path = tmp_path / "final_preparation_receipt.json"
    preparation_path.write_text(
        json.dumps(preparation, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        successor_members,
        "PRESERVED_PREPARATION_ARTIFACT_SHA256",
        preparation_sha,
    )
    final_ingest = {
        "schema_version": "next_behavior_selected_ingest_receipt.v1",
        "status": "cohort_ingested",
        "cohort": "final",
        "evaluation_opened": False,
        "final_corpus_prepared": True,
        "raw_content_emitted": False,
        "requested_member_count": 7,
        "source_selection_sha256": (
            successor_members.PRESERVED_SOURCE_SELECTION_SHA256
        ),
        "final_preparation_gate": preparation,
        "counts": {"test_metric_that_must_not_be_used": 999},
        "member_receipts": [
            {"filename": item["filename"], "status": "ingested", "stats": {}}
            for item in members
        ],
    }
    final_ingest_sha = _artifact_identity(final_ingest)
    final_ingest_path = tmp_path / "final_ingest_receipt.json"
    final_ingest_path.write_text(
        json.dumps(final_ingest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        successor_members,
        "PRESERVED_FINAL_INGEST_ARTIFACT_SHA256",
        final_ingest_sha,
    )

    store = tmp_path / "preserved.sqlite"
    with sqlite3.connect(store) as database:
        database.executescript(
            """
            CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE source_members (
                filename TEXT PRIMARY KEY,
                source_sha256 TEXT NOT NULL,
                source_size_bytes INTEGER NOT NULL,
                archive_crc32 TEXT NOT NULL,
                chronological_order INTEGER NOT NULL UNIQUE,
                source_cohort TEXT NOT NULL,
                experiment_role TEXT NOT NULL,
                collection_start TEXT NOT NULL,
                collection_end TEXT NOT NULL,
                stats_json TEXT NOT NULL
            );
            """
        )
        database.executemany(
            "INSERT INTO metadata(key, value) VALUES (?, ?)",
            [
                ("store_schema_version", "next_behavior_selected_private_store.v1"),
                (
                    "source_selection_sha256",
                    successor_members.PRESERVED_SOURCE_SELECTION_SHA256,
                ),
                (
                    "final_corpus_preparation_receipt_id",
                    successor_members.PRESERVED_PREPARATION_RECEIPT_ID,
                ),
                (
                    "final_corpus_preparation_receipt_json",
                    json.dumps(preparation, sort_keys=True),
                ),
                ("final_corpus_prepared_at", "2026-08-13T00:00:00Z"),
            ],
        )
        database.executemany(
            "INSERT INTO source_members VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    item["filename"],
                    item["source_sha256"],
                    item["source_size_bytes"],
                    item["archive_crc32"],
                    item["chronological_order"],
                    item["source_cohort"],
                    item["experiment_role"],
                    "2025-08-09T00:00:00Z",
                    "2025-08-09T23:59:59Z",
                    '{"must_not_be_read":true}',
                )
                for item in members
            ],
        )
    Path(str(store) + "-wal").write_bytes(b"")
    Path(str(store) + "-shm").write_bytes(b"stale-shm-is-permitted")
    return (
        store,
        preparation_path,
        preparation_sha,
        final_ingest_path,
        final_ingest_sha,
        members,
    )


def test_pending_declaration_range_stages_only_development_members(tmp_path, monkeypatch):
    selection = _pending_selection()
    archive_bytes, payloads = _archive(selection)
    factory = _RangeOnlyFactory(archive_bytes)
    opened: list[str] = []
    real_open = zipfile.ZipFile.open

    def recording_open(self, name, *args, **kwargs):
        filename = name.filename if isinstance(name, zipfile.ZipInfo) else str(name)
        opened.append(filename)
        return real_open(self, name, *args, **kwargs)

    monkeypatch.setattr(zipfile.ZipFile, "open", recording_open)
    destination = _destination(tmp_path)
    receipt = stage_development_members(
        selection,
        destination,
        reader_factory=factory,
        read_ahead_bytes=4096,
    )

    assert len(factory.calls) == 1
    assert factory.calls[0]["url"] == selection["archive"]["download_url"]
    assert factory.calls[0]["read_ahead_bytes"] == 4096
    assert receipt["member_count"] == 31
    assert receipt["development_member_count"] == 24
    assert receipt["sealed_test_member_count"] == 7
    assert receipt["test_member_contents_accessed"] is False
    assert receipt["storage_preflight"] == {
        "schema_version": "next_behavior_successor_staging_storage.v1",
        "status": "verified_before_archive_access",
        "required_mount": str(tmp_path),
        "required_member_root": str(_destination(tmp_path)),
        "destination": str(_destination(tmp_path)),
        "mount_target": str(tmp_path),
        "source": "/dev/test-successor",
        "fstype": "ext4",
        "mount_options": ["rw", "nosuid", "nodev"],
        "super_options": ["rw"],
        "available_bytes": 80 * 1024 * 1024 * 1024,
        "required_minimum_available_bytes": 60 * 1024 * 1024 * 1024,
        "writable": True,
    }
    assert len(list(destination.glob("*.json.gz"))) == 24
    assert all(
        (destination / name).read_bytes() == payloads[name]
        for name in payloads
        if name <= "2025-08-07.json.gz"
    )
    assert not any("2025-08-09" <= Path(name).name[:10] for name in opened)
    sealed = [member for member in receipt["members"] if member["role"] == "test"]
    assert all(member["content_status"] == "sealed_metadata_only" for member in sealed)
    assert all(member["content_sha256"] is None for member in sealed)
    assert all(not (destination / member["filename"]).exists() for member in sealed)
    assert require_valid_staging_receipt(receipt, source_selection=selection) == receipt


@pytest.mark.parametrize(
    ("probe_change", "expected"),
    [
        ({"mount_options": ["ro"]}, "not writable"),
        ({"fstype": "xfs"}, "not writable"),
        ({"writable": False}, "not writable"),
        ({"available_bytes": 60 * 1024 * 1024 * 1024 - 1}, "insufficient"),
        ({"source": "overlay"}, "not writable"),
    ],
)
def test_storage_preflight_fails_before_http_reader(
    tmp_path, probe_change, expected
):
    selection = _pending_selection()
    reader_calls: list[bool] = []
    base = {
        "mount_target": str(tmp_path),
        "source": "/dev/test-successor",
        "fstype": "ext4",
        "mount_options": ["rw"],
        "super_options": ["rw"],
        "available_bytes": 80 * 1024 * 1024 * 1024,
        "writable": True,
    }
    base.update(probe_change)

    def reader(*_args, **_kwargs):
        reader_calls.append(True)
        raise AssertionError("HTTP reader must not be constructed")

    with pytest.raises(SuccessorMemberStagingError, match=expected):
        stage_development_members(
            selection,
            _destination(tmp_path),
            reader_factory=reader,
            mount_probe=lambda _path: base,
        )
    assert reader_calls == []
    assert not _destination(tmp_path).exists()


def test_storage_preflight_rejects_path_escape_and_symlink_before_http(tmp_path):
    selection = _pending_selection()
    calls: list[bool] = []

    def reader(*_args, **_kwargs):
        calls.append(True)
        raise AssertionError("HTTP reader must not be constructed")

    with pytest.raises(SuccessorMemberStagingError, match="exact reviewed"):
        stage_development_members(
            selection,
            tmp_path / "outside",
            reader_factory=reader,
        )
    parent = _destination(tmp_path).parent
    parent.mkdir(parents=True)
    _destination(tmp_path).symlink_to(tmp_path / "outside", target_is_directory=True)
    with pytest.raises(SuccessorMemberStagingError, match="escape|unsafe"):
        stage_development_members(
            selection,
            _destination(tmp_path),
            reader_factory=reader,
        )
    assert calls == []


def test_completed_declaration_binds_content_hashes_and_existing_files(tmp_path):
    pending = _pending_selection()
    archive_bytes, payloads = _archive(pending)
    completed = _completed_selection(pending, archive_bytes, payloads)
    destination = _destination(tmp_path)
    first = stage_development_members(
        completed,
        destination,
        reader_factory=_RangeOnlyFactory(archive_bytes),
    )
    second = stage_development_members(
        completed,
        destination,
        reader_factory=_RangeOnlyFactory(archive_bytes),
        verify_only=True,
    )
    assert all(
        member["content_status"] == "downloaded_and_verified"
        for member in first["members"]
        if member["role"] != "test"
    )
    assert all(
        member["content_status"] == "verified_existing"
        for member in second["members"]
        if member["role"] != "test"
    )
    assert (
        first["ordered_development_content_sha256"]
        == second["ordered_development_content_sha256"]
    )


def test_archive_declaration_failure_happens_before_any_write(tmp_path):
    selection = _pending_selection()
    missing = selection["members"][-1]["filename"]
    archive_bytes, _ = _archive(selection, omit=missing)
    destination = _destination(tmp_path)
    with pytest.raises(SuccessorMemberStagingError, match="exactly once"):
        stage_development_members(
            selection,
            destination,
            reader_factory=_RangeOnlyFactory(archive_bytes),
        )
    assert not destination.exists()


def test_completed_hash_mismatch_never_publishes_target(tmp_path):
    pending = _pending_selection()
    archive_bytes, payloads = _archive(pending)
    completed = _completed_selection(pending, archive_bytes, payloads)
    completed["verification"]["member_receipts"][0]["sha256"] = "f" * 64
    # The declaration validator checks receipt form/membership; archive bytes
    # remain the independent authority checked during staging.
    require_valid_source_selection_v2(completed)
    destination = _destination(tmp_path)
    with pytest.raises(SuccessorMemberStagingError, match="SHA-256"):
        stage_development_members(
            completed,
            destination,
            reader_factory=_RangeOnlyFactory(archive_bytes),
        )
    assert not (destination / pending["members"][0]["filename"]).exists()


def test_mismatched_existing_member_is_rejected_before_missing_members_are_written(tmp_path):
    selection = _pending_selection()
    archive_bytes, _ = _archive(selection)
    destination = _destination(tmp_path)
    destination.mkdir(parents=True)
    (destination / selection["members"][0]["filename"]).write_bytes(b"wrong")
    with pytest.raises(SuccessorMemberStagingError, match="mismatched existing member"):
        stage_development_members(
            selection,
            destination,
            reader_factory=_RangeOnlyFactory(archive_bytes),
        )
    assert len(list(destination.iterdir())) == 1


def test_receipt_write_is_exclusive_and_tampering_fails(tmp_path):
    selection = _pending_selection()
    archive_bytes, _ = _archive(selection)
    receipt = stage_development_members(
        selection,
        _destination(tmp_path),
        reader_factory=_RangeOnlyFactory(archive_bytes),
    )
    output = tmp_path / "receipt.json"
    _write_receipt_exclusive(output, receipt)
    original = output.read_bytes()
    with pytest.raises(SuccessorMemberStagingError, match="overwrite"):
        _write_receipt_exclusive(output, receipt)
    assert output.read_bytes() == original

    tampered = copy.deepcopy(receipt)
    tampered["members"][0]["content_sha256"] = "f" * 64
    with pytest.raises(SuccessorMemberStagingError, match="hash mismatch"):
        require_valid_staging_receipt(tampered, source_selection=selection)

    lowered = copy.deepcopy(receipt)
    lowered["storage_preflight"]["required_minimum_available_bytes"] = 1
    basis = {key: lowered[key] for key in lowered if key != "receipt_sha256"}
    lowered["receipt_sha256"] = _sha256(basis)
    with pytest.raises(SuccessorMemberStagingError, match="storage preflight"):
        require_valid_staging_receipt(lowered, source_selection=selection)


@pytest.mark.parametrize("prohibited_date", ["2025-08-08", "2025-08-14"])
def test_prohibited_dates_cannot_enter_the_frozen_selection(prohibited_date):
    selection = _pending_selection()
    selection["members"][0]["collection_date"] = prohibited_date
    selection["members"][0]["filename"] = f"{prohibited_date}.json.gz"
    selection["members"][0]["archive_path"] = f"../logs_by_day/{prohibited_date}.json.gz"
    with pytest.raises(NextBehaviorSourceSelectionV2Error, match="calendar protocol"):
        require_valid_source_selection_v2(selection)


def test_resolve_store_metadata_then_finalize_without_test_content_or_metrics(
    tmp_path, monkeypatch
):
    pending = _pending_selection()
    archive_bytes, payloads = _archive(pending)
    staging = stage_development_members(
        pending,
        _destination(tmp_path),
        reader_factory=_RangeOnlyFactory(archive_bytes),
    )
    store, preparation, prep_sha, ingest, ingest_sha, historical = (
        _preserved_store_state(
            tmp_path, pending, archive_bytes, payloads, monkeypatch
        )
    )
    preserved = resolve_preserved_test_member_receipts(
        store,
        pending,
        preparation,
        ingest,
        expected_preparation_artifact_sha256=prep_sha,
        expected_final_ingest_artifact_sha256=ingest_sha,
    )
    result = finalize_successor_inventory(pending, staging, preserved)

    completed = result["completed_source_selection"]
    inventory = result["member_inventory"]
    assert completed["verification"]["status"] == "archive_members_verified"
    assert len(completed["verification"]["member_receipts"]) == 31
    assert inventory["schema_version"] == "next_behavior_successor_member_inventory.v1"
    assert inventory["member_count"] == 31
    assert inventory["test_members_sealed"] is True
    assert result["lineage"]["sealed_test_receipt_count"] == 7
    assert result["lineage"]["test_member_contents_accessed"] is False
    assert result["lineage"]["test_metrics_used"] is False
    assert preserved["store_evidence"]["wal_size_bytes"] == 0
    assert preserved["store_evidence"]["shm_exists"] is True
    assert preserved["store_evidence"]["sqlite_quick_check"] == "ok"
    old_test = {
        item["filename"]: item["source_sha256"] for item in historical
    }
    new_test = {
        item["filename"]: item["sha256"]
        for item in completed["verification"]["member_receipts"]
        if item["role"] == "test"
    }
    assert new_test == old_test
    assert all(
        member["content_sha256"] is None
        for member in staging["members"]
        if member["role"] == "test"
    )


def test_resolver_rejects_wrong_caller_pinned_receipt_hash(tmp_path, monkeypatch):
    pending = _pending_selection()
    archive_bytes, payloads = _archive(pending)
    store, preparation, prep_sha, ingest, ingest_sha, _ = _preserved_store_state(
        tmp_path, pending, archive_bytes, payloads, monkeypatch
    )
    # Parsed JSON remains identical, but the immutable artifact byte identity
    # changes.  The public resolver must compute and reject that change itself.
    preparation.write_bytes(preparation.read_bytes() + b" \n")
    with pytest.raises(SuccessorMemberStagingError, match="artifact identity"):
        resolve_preserved_test_member_receipts(
            store,
            pending,
            preparation,
            ingest,
            expected_preparation_artifact_sha256=prep_sha,
            expected_final_ingest_artifact_sha256=ingest_sha,
        )


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "wrong_name"])
def test_resolver_rejects_bad_final_ingest_membership(
    tmp_path, monkeypatch, mutation
):
    pending = _pending_selection()
    archive_bytes, payloads = _archive(pending)
    store, preparation, prep_sha, ingest, _ingest_sha, _ = _preserved_store_state(
        tmp_path, pending, archive_bytes, payloads, monkeypatch
    )
    ingest_value = json.loads(ingest.read_text(encoding="utf-8"))
    receipts = ingest_value["member_receipts"]
    if mutation == "missing":
        receipts.pop()
    elif mutation == "duplicate":
        receipts[-1] = copy.deepcopy(receipts[-2])
    else:
        receipts[-1]["filename"] = "2025-08-14.json.gz"
    ingest.write_text(
        json.dumps(ingest_value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    ingest_sha = hashlib.sha256(ingest.read_bytes()).hexdigest()
    monkeypatch.setattr(
        successor_members,
        "PRESERVED_FINAL_INGEST_ARTIFACT_SHA256",
        ingest_sha,
    )
    with pytest.raises(SuccessorMemberStagingError, match="final-ingest"):
        resolve_preserved_test_member_receipts(
            store,
            pending,
            preparation,
            ingest,
            expected_preparation_artifact_sha256=prep_sha,
            expected_final_ingest_artifact_sha256=ingest_sha,
        )


def test_resolver_rejects_store_member_hash_mismatch(tmp_path, monkeypatch):
    pending = _pending_selection()
    archive_bytes, payloads = _archive(pending)
    store, preparation, prep_sha, ingest, ingest_sha, _ = _preserved_store_state(
        tmp_path, pending, archive_bytes, payloads, monkeypatch
    )
    with sqlite3.connect(store) as database:
        database.execute(
            "UPDATE source_members SET source_sha256 = ? WHERE filename = ?",
            ("f" * 64, "2025-08-16.json.gz"),
        )
    with pytest.raises(SuccessorMemberStagingError, match="receipt hash mismatch"):
        resolve_preserved_test_member_receipts(
            store,
            pending,
            preparation,
            ingest,
            expected_preparation_artifact_sha256=prep_sha,
            expected_final_ingest_artifact_sha256=ingest_sha,
        )


def test_finalize_rejects_tampered_staging_test_metadata(tmp_path, monkeypatch):
    pending = _pending_selection()
    archive_bytes, payloads = _archive(pending)
    staging = stage_development_members(
        pending,
        _destination(tmp_path),
        reader_factory=_RangeOnlyFactory(archive_bytes),
    )
    test_member = next(item for item in staging["members"] if item["role"] == "test")
    test_member["archive_crc32"] = "00000000"
    _restamp_staging_receipt(staging)
    store, preparation, prep_sha, ingest, ingest_sha, _ = _preserved_store_state(
        tmp_path, pending, archive_bytes, payloads, monkeypatch
    )
    preserved = resolve_preserved_test_member_receipts(
        store,
        pending,
        preparation,
        ingest,
        expected_preparation_artifact_sha256=prep_sha,
        expected_final_ingest_artifact_sha256=ingest_sha,
    )
    with pytest.raises(SuccessorMemberStagingError, match="metadata mismatch"):
        finalize_successor_inventory(pending, staging, preserved)


def test_finalize_rejects_restamped_preserved_lineage_tampering(
    tmp_path, monkeypatch
):
    pending = _pending_selection()
    archive_bytes, payloads = _archive(pending)
    staging = stage_development_members(
        pending,
        _destination(tmp_path),
        reader_factory=_RangeOnlyFactory(archive_bytes),
    )
    store, preparation, prep_sha, ingest, ingest_sha, _ = _preserved_store_state(
        tmp_path, pending, archive_bytes, payloads, monkeypatch
    )
    preserved = resolve_preserved_test_member_receipts(
        store,
        pending,
        preparation,
        ingest,
        expected_preparation_artifact_sha256=prep_sha,
        expected_final_ingest_artifact_sha256=ingest_sha,
    )
    preserved["preparation_artifact_sha256"] = "f" * 64
    basis = {
        key: preserved[key] for key in preserved if key != "receipt_sha256"
    }
    preserved["receipt_sha256"] = _sha256(basis)
    with pytest.raises(SuccessorMemberStagingError, match="lineage"):
        finalize_successor_inventory(pending, staging, preserved)


@pytest.mark.parametrize("side_suffix", ["-wal", "-journal"])
def test_resolver_rejects_nonzero_wal_or_any_journal(
    tmp_path, monkeypatch, side_suffix
):
    pending = _pending_selection()
    archive_bytes, payloads = _archive(pending)
    store, preparation, prep_sha, ingest, ingest_sha, _ = _preserved_store_state(
        tmp_path, pending, archive_bytes, payloads, monkeypatch
    )
    Path(str(store) + side_suffix).write_bytes(b"unsafe")
    expected = "non-empty WAL" if side_suffix == "-wal" else "rollback journal"
    with pytest.raises(SuccessorMemberStagingError, match=expected):
        resolve_preserved_test_member_receipts(
            store,
            pending,
            preparation,
            ingest,
            expected_preparation_artifact_sha256=prep_sha,
            expected_final_ingest_artifact_sha256=ingest_sha,
        )


def test_finalization_pair_is_exclusive(tmp_path):
    first = tmp_path / "completed.json"
    second = tmp_path / "inventory.json"
    _write_json_pair_exclusive(first, {"kind": "completed"}, second, {"kind": "inventory"})
    before = (first.read_bytes(), second.read_bytes())
    with pytest.raises(SuccessorMemberStagingError, match="overwrite"):
        _write_json_pair_exclusive(first, {"changed": True}, second, {"changed": True})
    assert (first.read_bytes(), second.read_bytes()) == before
