from __future__ import annotations

import gzip
import hashlib
import io
import json
import sqlite3
from pathlib import Path

import pytest

from production.tools import build_next_behavior_zenodo_corpus as builder
from production.tools.build_next_behavior_zenodo_corpus import (
    NextBehaviorCorpusBuildError,
    build_safe_corpus,
    classify_private_commands,
    ingest_members,
    load_or_create_pseudonymization_key,
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
        assert stats["timestamp_normalization"].startswith(
            "source naive timestamps"
        )
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


def test_naive_zenodo_timestamp_is_explicitly_normalized_to_utc(
    tmp_path: Path,
) -> None:
    raw_directory = tmp_path / "raw"
    raw_directory.mkdir()
    event = _event(
        "cowrie.session.connect",
        timestamp="2025-07-01 12:34:56.123456",
    )
    manifest = _manifest(raw_directory, [[event]])
    manifest_path = tmp_path / "source.json"
    _write_manifest(manifest_path, manifest)
    database_path = tmp_path / "private.sqlite"

    ingest_members(
        source_manifest_path=manifest_path,
        raw_directory=raw_directory,
        private_database_path=database_path,
        selected_members=[manifest["members"][0]["filename"]],
    )

    database = sqlite3.connect(database_path)
    try:
        first_seen, collection_start = database.execute(
            """
            SELECT sessions.first_seen, processed_members.collection_start
            FROM sessions JOIN processed_members
              ON sessions.source_member = processed_members.source_member
            """
        ).fetchone()
    finally:
        database.close()
    assert first_seen == "2025-07-01T12:34:56.123456Z"
    assert collection_start == "2025-07-01T12:34:56.123456Z"


def _frozen_classifier_manifest() -> dict:
    return {
        "classifier": {
            "device": "cpu",
            "max_length": 128,
            "checkpoint_sha256": "c" * 64,
        },
        "classification_policy": {
            "securebert_candidate_threshold": 0.55,
            "trusted_model_only_threshold": 0.90,
            "rule_policy_path": "rules.json",
            "rule_policy_sha256": "a" * 64,
            "trust_policy_sha256": "b" * 64,
            "mitre_cache_path": "mitre.json",
            "mitre_cache_sha256": hashlib.sha256(b"mitre\n").hexdigest(),
            "drop_rule_securebert_disagreements": True,
        },
    }


def _ingest_complete_fixture(
    tmp_path: Path,
) -> tuple[Path, Path, Path, dict]:
    raw_directory = tmp_path / "raw"
    raw_directory.mkdir()
    events = [
        _event("cowrie.session.connect"),
        _event("cowrie.login.failed", timestamp="2025-07-01T00:00:01Z"),
        _event("cowrie.login.success", timestamp="2025-07-01T00:00:02Z"),
        _event(
            "cowrie.command.input",
            timestamp="2025-07-01T00:00:03Z",
            command="synthetic fixture command",
        ),
        _event(
            "cowrie.session.file_download",
            timestamp="2025-07-01T00:00:04Z",
        ),
        _event("cowrie.session.closed", timestamp="2025-07-01T00:00:05Z"),
    ]
    manifest = _manifest(raw_directory, [events])
    manifest_path = tmp_path / "source.json"
    _write_manifest(manifest_path, manifest)
    database_path = tmp_path / "private/sessions.sqlite"
    ingest_members(
        source_manifest_path=manifest_path,
        raw_directory=raw_directory,
        private_database_path=database_path,
    )
    classifier_manifest_path = tmp_path / "classifier.json"
    classifier_manifest_path.write_text("{}\n", encoding="utf-8")
    label_adapter = (
        tmp_path / "production/prediction/next_behavior_label_policy.py"
    )
    label_adapter.parent.mkdir(parents=True)
    label_adapter.write_text("# fixture\n", encoding="utf-8")
    (tmp_path / "mitre.json").write_bytes(b"mitre\n")
    return (
        raw_directory,
        manifest_path,
        classifier_manifest_path,
        manifest,
    )


class _FakeSecureBert:
    def __init__(self, **_kwargs) -> None:
        pass

    def classify_batch(self, commands: list[str]):
        return [("T1059", 0.95) for _command in commands]


class _FakeMitre:
    def get_tactics(self, technique: str):
        return ["execution"] if technique == "T1059" else ["discovery"]


class _FakeHybridClassifier:
    def __init__(self, **_kwargs) -> None:
        pass

    def classify(self, command: str):
        return [
            {
                "command": command,
                "ttp": "T1059",
                "tactic": "execution",
                "source": "securebert",
                "confidence": 0.95,
                "high_confidence": True,
                "agreement_status": "model_only",
            }
        ]


def _patch_classifier_dependencies(monkeypatch) -> None:
    manifest = _frozen_classifier_manifest()
    monkeypatch.setattr(
        builder,
        "load_classifier_manifest",
        lambda _path: manifest,
    )
    monkeypatch.setattr(
        builder,
        "verify_classifier_assets",
        lambda *_args, **_kwargs: {"status": "assets_verified"},
    )
    monkeypatch.setattr(builder, "SecureBertCommandClassifier", _FakeSecureBert)
    monkeypatch.setattr(builder, "NotebookParityClassifier", _FakeHybridClassifier)
    monkeypatch.setattr(
        builder,
        "load_mitre_attack_db",
        lambda **_kwargs: _FakeMitre(),
    )
    monkeypatch.setattr(
        builder,
        "_require_repository_commit",
        lambda _root, commit: commit,
    )


def test_classification_and_safe_build_preserve_causal_context_and_privacy(
    tmp_path: Path,
    monkeypatch,
) -> None:
    (
        _raw_directory,
        source_manifest_path,
        classifier_manifest_path,
        _manifest_value,
    ) = _ingest_complete_fixture(tmp_path)
    database_path = tmp_path / "private/sessions.sqlite"
    _patch_classifier_dependencies(monkeypatch)
    database = open_private_database(database_path)
    database.execute(
        """
        INSERT INTO command_labels(command, labels_json, unrepresented_json)
        VALUES ('interrupted partial row', '[]', '{}')
        """
    )
    database.commit()
    database.close()

    classification = classify_private_commands(
        source_manifest_path=source_manifest_path,
        classifier_manifest_path=classifier_manifest_path,
        repository_root=tmp_path,
        model_root=tmp_path / "model",
        private_database_path=database_path,
        code_commit="e" * 40,
        batch_size=4,
    )
    repeated = classify_private_commands(
        source_manifest_path=source_manifest_path,
        classifier_manifest_path=classifier_manifest_path,
        repository_root=tmp_path,
        model_root=tmp_path / "model",
        private_database_path=database_path,
        code_commit="e" * 40,
        batch_size=4,
    )

    assert classification["unique_command_count"] == 1
    assert classification["label_counts"] == {
        "trusted_observation:securebert": 1
    }
    assert repeated["status"] == "already_classified"

    historical_path = tmp_path / "historical.jsonl"
    historical_path.write_text(
        json.dumps(
            {
                "session_id": builder._legacy_historical_id("session-a"),
                "split": "test",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    preprocessing_path = tmp_path / "preprocessing.json"
    preprocessing_path.write_text('{"fixture":true}\n', encoding="utf-8")
    key_path = tmp_path / "private/pseudonymization.key"
    safe_path = tmp_path / "safe/corpus.jsonl"
    source_receipts_path = tmp_path / "safe/source_receipts.json"
    corpus_receipt_path = tmp_path / "safe/corpus_receipt.json"
    build_receipt_path = tmp_path / "safe/build_receipt.json"

    receipt = build_safe_corpus(
        source_manifest_path=source_manifest_path,
        classifier_manifest_path=classifier_manifest_path,
        preprocessing_manifest_path=preprocessing_path,
        historical_payload_path=historical_path,
        private_database_path=database_path,
        pseudonymization_key_path=key_path,
        safe_payload_path=safe_path,
        source_receipts_path=source_receipts_path,
        corpus_receipt_path=corpus_receipt_path,
        build_receipt_path=build_receipt_path,
        repository_root=tmp_path,
        code_commit="e" * 40,
        create_key=True,
    )

    safe_record = json.loads(safe_path.read_text(encoding="utf-8"))
    context = safe_record["observation_groups"][0]["session_context"]
    assert context == {
        "login_outcome": "success",
        "command_count_bucket": "1",
        "session_age_bucket": "under_10s",
        "confirmed_transfer_observed": False,
    }
    serialized = (
        safe_path.read_text(encoding="utf-8")
        + source_receipts_path.read_text(encoding="utf-8")
        + corpus_receipt_path.read_text(encoding="utf-8")
        + build_receipt_path.read_text(encoding="utf-8")
    )
    assert "synthetic fixture command" not in serialized
    assert "session-a" not in serialized
    assert "2025-07-01.json.gz" not in serialized
    assert receipt["historical_membership"]["overlap_by_historical_split"] == {
        "test": 1
    }
    assert receipt["safe_payload"]["line_count"] == 1
    assert receipt["pipeline_reconciliation"] == {
        "raw_event_records": 12,
        "raw_command_input_events": 1,
        "empty_command_input_events": 0,
        "nonempty_command_events": 1,
        "private_store_command_events": 1,
        "unique_classified_commands": 1,
        "groups_with_trusted_label": 1,
        "unrepresented_output_occurrences_by_reason": {},
        "private_sessions_entering_safe_adapter": 1,
        "privacy_safe_sessions_emitted": 1,
        "sessions_dropped_without_trusted_behavior": 0,
    }
    assert key_path.stat().st_mode & 0o777 == 0o600

    with pytest.raises(NextBehaviorCorpusBuildError, match="refusing to overwrite"):
        build_safe_corpus(
            source_manifest_path=source_manifest_path,
            classifier_manifest_path=classifier_manifest_path,
            preprocessing_manifest_path=preprocessing_path,
            historical_payload_path=historical_path,
            private_database_path=database_path,
            pseudonymization_key_path=key_path,
            safe_payload_path=safe_path,
            source_receipts_path=source_receipts_path,
            corpus_receipt_path=corpus_receipt_path,
            build_receipt_path=build_receipt_path,
            repository_root=tmp_path,
            code_commit="e" * 40,
        )


def test_key_loading_rejects_broad_permissions_or_wrong_size(
    tmp_path: Path,
) -> None:
    broad = tmp_path / "broad.key"
    broad.write_bytes(b"x" * 32)
    broad.chmod(0o644)
    with pytest.raises(NextBehaviorCorpusBuildError, match="too broad"):
        load_or_create_pseudonymization_key(broad, create=False)

    short = tmp_path / "short.key"
    short.write_bytes(b"x")
    short.chmod(0o600)
    with pytest.raises(NextBehaviorCorpusBuildError, match="exactly 32"):
        load_or_create_pseudonymization_key(short, create=False)


def test_artifact_generation_requires_exact_clean_repository_head(
    tmp_path: Path,
    monkeypatch,
) -> None:
    class _Result:
        def __init__(self, output: str) -> None:
            self.stdout = output

    outputs = iter([_Result("a" * 40 + "\n"), _Result("")])
    monkeypatch.setattr(
        builder.subprocess,
        "run",
        lambda *_args, **_kwargs: next(outputs),
    )
    assert builder._require_repository_commit(tmp_path, "a" * 40) == "a" * 40

    outputs = iter([_Result("a" * 40 + "\n"), _Result("")])
    monkeypatch.setattr(
        builder.subprocess,
        "run",
        lambda *_args, **_kwargs: next(outputs),
    )
    with pytest.raises(NextBehaviorCorpusBuildError, match="does not match"):
        builder._require_repository_commit(tmp_path, "b" * 40)

    outputs = iter(
        [
            _Result("a" * 40 + "\n"),
            _Result(" M production/example.py\n"),
        ]
    )
    monkeypatch.setattr(
        builder.subprocess,
        "run",
        lambda *_args, **_kwargs: next(outputs),
    )
    with pytest.raises(NextBehaviorCorpusBuildError, match="must be clean"):
        builder._require_repository_commit(tmp_path, "a" * 40)
