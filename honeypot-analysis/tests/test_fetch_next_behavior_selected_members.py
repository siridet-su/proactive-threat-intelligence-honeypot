from __future__ import annotations

import gzip
import hashlib
import io
import json
import random
import zipfile
import zlib
from pathlib import Path

import pytest

from production.prediction.next_behavior_source_selection import (
    require_completed_source_selection,
)
from production.tools.fetch_next_behavior_selected_members import (
    SelectedMemberFetchError,
    load_pending_inputs,
    retrieve_selected_members,
)
from production.tools.fetch_next_behavior_zenodo_members import (
    file_sha256,
    load_source_manifest,
)


ROOT = Path(__file__).resolve().parents[1]
SELECTION_PATH = ROOT / "configs" / "next_behavior_source_selection.v1.json"
PRESERVED_PATH = ROOT / "configs" / "next_behavior_zenodo_source.v1.json"


def _gzip_payload(label: str) -> bytes:
    output = io.BytesIO()
    with gzip.GzipFile(fileobj=output, mode="wb", mtime=0) as handle:
        handle.write((json.dumps({"fixture": label}) + "\n").encode())
    return output.getvalue()


def _selection() -> dict:
    return json.loads(SELECTION_PATH.read_text(encoding="utf-8"))


def _fixture_preserved(dev_payloads: dict[str, bytes]) -> dict:
    preserved = load_source_manifest(PRESERVED_PATH)
    for member in preserved["members"]:
        payload = dev_payloads.get(member["filename"])
        if payload is None:
            payload = _gzip_payload(member["filename"])
        member["size_bytes"] = len(payload)
        member["archive_compressed_bytes"] = max(1, len(payload) - 1)
        member["archive_crc32"] = f"{zlib.crc32(payload) & 0xFFFFFFFF:08x}"
        member["sha256"] = hashlib.sha256(payload).hexdigest()
    return preserved


def _fixture(
    tmp_path: Path,
    *,
    omit_final: str | None = None,
    invalid_gzip: str | None = None,
) -> tuple[
    dict,
    dict,
    Path,
    bytes,
    dict[str, bytes],
    dict[str, bytes],
]:
    selection = _selection()
    dev_payloads = {
        member["filename"]: _gzip_payload(member["filename"])
        for member in selection["members"]
        if member["role"] == "development"
    }
    final_payloads = {
        member["filename"]: (
            b"not-a-gzip-stream"
            if member["filename"] == invalid_gzip
            else _gzip_payload(member["filename"])
        )
        for member in selection["members"]
        if member["role"] == "final" and member["filename"] != omit_final
    }
    preserved = _fixture_preserved(dev_payloads)
    destination = tmp_path / "raw"
    destination.mkdir()
    for filename, payload in dev_payloads.items():
        (destination / filename).write_bytes(payload)

    archive_buffer = io.BytesIO()
    noise = random.Random(7).randbytes(2 * 1024 * 1024)
    with zipfile.ZipFile(
        archive_buffer,
        "w",
        compression=zipfile.ZIP_DEFLATED,
    ) as archive:
        for member in selection["members"]:
            if member["role"] != "final":
                continue
            payload = final_payloads.get(member["filename"])
            if payload is not None:
                archive.writestr(member["archive_path"], payload)
        archive.writestr(
            "../logs_by_day/2025-08-14.json.gz",
            _gzip_payload("forbidden"),
        )
        archive.writestr(
            "../transferred_files/capture.bin",
            b"must-not-be-opened",
        )
        archive.writestr("../unselected/noise.bin", noise)
    return (
        selection,
        preserved,
        destination,
        archive_buffer.getvalue(),
        dev_payloads,
        final_payloads,
    )


class _TrackingReader(io.BytesIO):
    def __init__(self, payload: bytes) -> None:
        super().__init__(payload)
        self.requests: list[int] = []

    def read(self, size: int = -1) -> bytes:
        self.requests.append(size)
        if size is None or size < 0:
            raise AssertionError("full archive reads are forbidden")
        return super().read(size)


class _RecordingArchive:
    def __init__(self, reader: _TrackingReader) -> None:
        self.archive = zipfile.ZipFile(reader)
        self.opened: list[str] = []

    def __enter__(self) -> "_RecordingArchive":
        return self

    def __exit__(self, *_args) -> None:
        self.archive.close()

    def infolist(self):
        return self.archive.infolist()

    def open(self, entry, mode="r"):
        self.opened.append(entry.filename)
        return self.archive.open(entry, mode)


class _InjectedFactories:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload
        self.reader: _TrackingReader | None = None
        self.archive: _RecordingArchive | None = None
        self.reader_calls: list[tuple[str, int, int]] = []

    def reader_factory(
        self,
        url: str,
        *,
        expected_size: int,
        read_ahead_bytes: int,
    ) -> _TrackingReader:
        self.reader_calls.append((url, expected_size, read_ahead_bytes))
        self.reader = _TrackingReader(self.payload)
        return self.reader

    def archive_factory(self, reader: _TrackingReader) -> _RecordingArchive:
        self.archive = _RecordingArchive(reader)
        return self.archive


def _retrieve(fixture, tmp_path: Path):
    selection, preserved, destination, archive_bytes, _, _ = fixture
    factories = _InjectedFactories(archive_bytes)
    output = tmp_path / "completed.json"
    completed = retrieve_selected_members(
        selection,
        preserved,
        destination,
        output,
        reader_factory=factories.reader_factory,
        archive_factory=factories.archive_factory,
        read_ahead_bytes=4096,
    )
    return completed, output, factories


def test_reuses_dev_and_selectively_downloads_only_seven_final_members(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    selection, _, destination, archive_bytes, dev_payloads, final_payloads = fixture
    pending_before = SELECTION_PATH.read_bytes()

    completed, output, factories = _retrieve(fixture, tmp_path)

    assert SELECTION_PATH.read_bytes() == pending_before
    assert require_completed_source_selection(completed) == completed
    assert json.loads(output.read_text(encoding="utf-8")) == completed
    assert len(completed["verification"]["member_receipts"]) == 13
    assert factories.archive is not None
    assert factories.archive.opened == [
        member["archive_path"]
        for member in selection["members"]
        if member["role"] == "final"
    ]
    assert not any(
        filename in factories.archive.opened for filename in dev_payloads
    )
    assert all(
        (destination / filename).read_bytes() == payload
        for filename, payload in {**dev_payloads, **final_payloads}.items()
    )
    assert factories.reader_calls == [
        (
            selection["archive"]["download_url"],
            selection["archive"]["size_bytes"],
            4096,
        )
    ]
    assert factories.reader is not None
    assert -1 not in factories.reader.requests
    assert sum(factories.reader.requests) < len(archive_bytes) // 4


def test_existing_verified_final_is_not_downloaded_again(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    selection, _, destination, _, _, final_payloads = fixture
    filename = "2025-08-09.json.gz"
    target = destination / filename
    target.write_bytes(final_payloads[filename])

    completed, _, factories = _retrieve(fixture, tmp_path)

    assert target.read_bytes() == final_payloads[filename]
    assert factories.archive is not None
    assert selection["members"][6]["archive_path"] not in (
        factories.archive.opened
    )
    assert len(factories.archive.opened) == 6
    receipt = next(
        item
        for item in completed["verification"]["member_receipts"]
        if item["filename"] == filename
    )
    assert receipt["sha256"] == hashlib.sha256(final_payloads[filename]).hexdigest()


@pytest.mark.parametrize("mode", ["missing", "mismatched"])
def test_development_failure_occurs_before_reader_or_writes(
    tmp_path: Path,
    mode: str,
) -> None:
    fixture = _fixture(tmp_path)
    selection, preserved, destination, archive_bytes, _, final_payloads = fixture
    target = destination / selection["members"][0]["filename"]
    if mode == "missing":
        target.unlink()
    else:
        target.write_bytes(b"mismatch")
    factories = _InjectedFactories(archive_bytes)
    output = tmp_path / "completed.json"

    with pytest.raises(SelectedMemberFetchError, match="development member"):
        retrieve_selected_members(
            selection,
            preserved,
            destination,
            output,
            reader_factory=factories.reader_factory,
            archive_factory=factories.archive_factory,
        )

    assert factories.reader_calls == []
    assert not output.exists()
    assert not any((destination / filename).exists() for filename in final_payloads)


def test_missing_exact_archive_entry_fails_before_final_writes(
    tmp_path: Path,
) -> None:
    omitted = "2025-08-12.json.gz"
    fixture = _fixture(tmp_path, omit_final=omitted)
    selection, preserved, destination, archive_bytes, _, final_payloads = fixture
    factories = _InjectedFactories(archive_bytes)
    output = tmp_path / "completed.json"

    with pytest.raises(
        SelectedMemberFetchError,
        match="missing or ambiguous",
    ):
        retrieve_selected_members(
            selection,
            preserved,
            destination,
            output,
            reader_factory=factories.reader_factory,
            archive_factory=factories.archive_factory,
        )

    assert not output.exists()
    assert not any((destination / filename).exists() for filename in final_payloads)
    assert factories.archive is not None
    assert factories.archive.opened == []


def test_mismatched_existing_final_is_never_overwritten(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    selection, preserved, destination, archive_bytes, _, _ = fixture
    filename = "2025-08-09.json.gz"
    target = destination / filename
    original = b"unrelated-existing-bytes"
    target.write_bytes(original)
    factories = _InjectedFactories(archive_bytes)
    output = tmp_path / "completed.json"

    with pytest.raises(
        SelectedMemberFetchError,
        match="refusing to overwrite mismatched final member",
    ):
        retrieve_selected_members(
            selection,
            preserved,
            destination,
            output,
            reader_factory=factories.reader_factory,
            archive_factory=factories.archive_factory,
        )

    assert target.read_bytes() == original
    assert not output.exists()
    assert factories.archive is not None
    assert factories.archive.opened == []
    assert not (destination / "2025-08-10.json.gz").exists()


def test_gzip_failure_keeps_final_targets_and_receipt_unpublished(
    tmp_path: Path,
) -> None:
    bad = "2025-08-11.json.gz"
    fixture = _fixture(tmp_path, invalid_gzip=bad)
    selection, preserved, destination, archive_bytes, _, final_payloads = fixture
    factories = _InjectedFactories(archive_bytes)
    output = tmp_path / "completed.json"

    with pytest.raises(SelectedMemberFetchError, match="gzip integrity"):
        retrieve_selected_members(
            selection,
            preserved,
            destination,
            output,
            reader_factory=factories.reader_factory,
            archive_factory=factories.archive_factory,
        )

    assert not output.exists()
    assert not any((destination / filename).exists() for filename in final_payloads)
    assert list(destination.glob(f".{bad}.part.*"))


def test_existing_completed_output_blocks_reader_and_member_changes(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    selection, preserved, destination, archive_bytes, _, final_payloads = fixture
    output = tmp_path / "completed.json"
    output.write_text("keep", encoding="utf-8")
    factories = _InjectedFactories(archive_bytes)

    with pytest.raises(SelectedMemberFetchError, match="refusing to overwrite"):
        retrieve_selected_members(
            selection,
            preserved,
            destination,
            output,
            reader_factory=factories.reader_factory,
            archive_factory=factories.archive_factory,
        )

    assert output.read_text(encoding="utf-8") == "keep"
    assert factories.reader_calls == []
    assert not any((destination / filename).exists() for filename in final_payloads)


def test_loads_exact_pending_and_rejects_changed_preserved_manifest(
    tmp_path: Path,
) -> None:
    selection, preserved = load_pending_inputs(SELECTION_PATH, PRESERVED_PATH)
    assert selection["verification"]["member_receipts"] == []
    assert preserved["schema_version"] == "next_behavior_zenodo_source.v1"

    changed = tmp_path / "changed-v1.json"
    changed.write_bytes(PRESERVED_PATH.read_bytes() + b"\n")
    with pytest.raises(SelectedMemberFetchError, match="SHA-256"):
        load_pending_inputs(SELECTION_PATH, changed)

    assert file_sha256(PRESERVED_PATH) == (
        selection["preserved_source_manifest"]["sha256"]
    )
