from __future__ import annotations

import gzip
import hashlib
import io
import json
import sqlite3
from pathlib import Path

import pytest

from production.tools.build_next_behavior_zenodo_corpus import (
    NextBehaviorCorpusBuildError,
    ingest_members,
    open_private_database,
)


def _gzip_member(path: Path, events: list[object]) -> None:
    with path.open("wb") as raw_handle:
        with gzip.GzipFile(
            fileobj=raw_handle,
            mode="wb",
            filename="",
            mtime=0,
        ) as compressed:
            with io.TextIOWrapper(compressed, encoding="utf-8") as handle:
                for event in events:
                    if isinstance(event, str):
                        handle.write(event + "\n")
                    else:
                        handle.write(json.dumps(event, sort_keys=True) + "\n")


def _manifest(raw_directory: Path, member_events: list[list[object]]) -> dict:
    members = []
    for index in range(7):
        filename = f"2025-07-{index + 1:02d}.json.gz"
        path = raw_directory / filename
        events = member_events[index] if index < len(member_events) else [
            {
                "eventid": "cowrie.session.connect",
                "session": f"fixture-{index}",
                "ts": f"2025-07-{index + 1:02d}T00:00:00Z",
                "protocol": "ssh",
                "group": 1,
            }
        ]
        _gzip_member(path, events)
        payload = path.read_bytes()
        members.append(
            {
                "filename": filename,
                "archive_path": f"../logs_by_day/{filename}",
                "collection_date": f"2025-07-{index + 1:02d}",
                "chronological_order": index + 1,
                "size_bytes": len(payload),
                "archive_compressed_bytes": 1,
                "archive_crc32": "00000000",
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
    return {
        "schema_version": "next_behavior_zenodo_source.v1",
        "source": {
            "zenodo_record_id": 21260400,
            "doi": "10.5281/zenodo.21260400",
            "title": "fixture",
            "license": "CC-BY-4.0",
            "record_url": "https://zenodo.org/records/21260400",
        },
        "archive": {
            "filename": "data_all.zip",
            "size_bytes": 1,
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


def _write_manifest(path: Path, manifest: dict) -> None:
    path.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")


def _event(
    eventid: str,
    *,
    session: str = "session-a",
    timestamp: str = "2025-07-01T00:00:00Z",
    command: str | None = None,
) -> dict:
    value = {
        "eventid": eventid,
        "session": session,
        "ts": timestamp,
        "protocol": "ssh" if eventid == "cowrie.session.connect" else None,
        "group": 2,
    }
    if command is not None:
        value["input"] = command
    return value


def test_ingest_builds_private_causal_mapping_and_is_resumable(
    tmp_path: Path,
) -> None:
    raw_directory = tmp_path / "raw"
    raw_directory.mkdir()
    events = [
        _event("cowrie.session.connect"),
        _event("cowrie.login.failed", timestamp="2025-07-01T00:00:01Z"),
        _event("cowrie.login.success", timestamp="2025-07-01T00:00:02Z"),
        _event(
            "cowrie.command.input",
            timestamp="2025-07-01T00:00:03Z",
            command="PRIVATE FIXTURE COMMAND",
        ),
        _event(
            "cowrie.session.file_download",
            timestamp="2025-07-01T00:00:04Z",
        ),
        _event("cowrie.session.closed", timestamp="2025-07-01T00:00:05Z"),
        "{malformed",
        ["not", "an", "object"],
    ]
    manifest = _manifest(raw_directory, [events])
    manifest_path = tmp_path / "source.json"
    _write_manifest(manifest_path, manifest)
    database_path = tmp_path / "private/sessions.sqlite"

    first = ingest_members(
        source_manifest_path=manifest_path,
        raw_directory=raw_directory,
        private_database_path=database_path,
        selected_members=[manifest["members"][0]["filename"]],
    )
    second = ingest_members(
        source_manifest_path=manifest_path,
        raw_directory=raw_directory,
        private_database_path=database_path,
        selected_members=[manifest["members"][0]["filename"]],
    )

    assert first["counts"] == {
        "processed_members": 1,
        "sessions": 1,
        "command_events": 1,
        "context_events": 3,
        "cross_member_sessions": 0,
    }
    assert second["counts"] == first["counts"]
    assert second["member_receipts"][0]["status"] == "already_ingested"
    assert "PRIVATE FIXTURE COMMAND" not in json.dumps(first)
    database = sqlite3.connect(database_path)
    try:
        assert database.execute(
            "SELECT command FROM command_events"
        ).fetchone()[0] == "PRIVATE FIXTURE COMMAND"
        stats = json.loads(
            database.execute(
                "SELECT stats_json FROM processed_members"
            ).fetchone()[0]
        )
        assert stats["malformed_records"] == 1
        assert stats["non_object_records"] == 1
    finally:
        database.close()


def test_hash_mismatch_fails_before_private_database_creation(
    tmp_path: Path,
) -> None:
    raw_directory = tmp_path / "raw"
    raw_directory.mkdir()
    manifest = _manifest(raw_directory, [[]])
    manifest["members"][0]["sha256"] = "f" * 64
    manifest_path = tmp_path / "source.json"
    _write_manifest(manifest_path, manifest)
    database_path = tmp_path / "private.sqlite"

    with pytest.raises(NextBehaviorCorpusBuildError, match="SHA-256 mismatch"):
        ingest_members(
            source_manifest_path=manifest_path,
            raw_directory=raw_directory,
            private_database_path=database_path,
            selected_members=[manifest["members"][0]["filename"]],
        )

    database = sqlite3.connect(database_path)
    try:
        assert database.execute(
            "SELECT COUNT(*) FROM command_events"
        ).fetchone()[0] == 0
    finally:
        database.close()


def test_cross_member_session_is_rejected_without_reassignment(
    tmp_path: Path,
) -> None:
    raw_directory = tmp_path / "raw"
    raw_directory.mkdir()
    manifest = _manifest(
        raw_directory,
        [
            [_event("cowrie.session.connect", session="shared-session")],
            [
                _event(
                    "cowrie.command.input",
                    session="shared-session",
                    timestamp="2025-07-02T00:00:00Z",
                    command="fixture",
                )
            ],
        ],
    )
    manifest_path = tmp_path / "source.json"
    _write_manifest(manifest_path, manifest)
    database_path = tmp_path / "private.sqlite"

    with pytest.raises(
        NextBehaviorCorpusBuildError,
        match="more than one source member",
    ):
        ingest_members(
            source_manifest_path=manifest_path,
            raw_directory=raw_directory,
            private_database_path=database_path,
            selected_members=[
                manifest["members"][0]["filename"],
                manifest["members"][1]["filename"],
            ],
        )

    database = sqlite3.connect(database_path)
    try:
        row = database.execute(
            "SELECT source_member, cross_member FROM sessions"
        ).fetchone()
        assert row == (manifest["members"][0]["filename"], 1)
    finally:
        database.close()


def test_private_database_rejects_foreign_schema(tmp_path: Path) -> None:
    path = tmp_path / "foreign.sqlite"
    database = sqlite3.connect(path)
    database.execute(
        "CREATE TABLE build_metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
    )
    database.execute(
        "INSERT INTO build_metadata VALUES ('private_store_id', 'other.v1')"
    )
    database.commit()
    database.close()

    with pytest.raises(NextBehaviorCorpusBuildError, match="another schema"):
        open_private_database(path)
