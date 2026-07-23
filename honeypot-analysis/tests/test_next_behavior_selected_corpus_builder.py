from __future__ import annotations

import gzip
import hashlib
import io
import json
import sqlite3
import zlib
from pathlib import Path
from types import SimpleNamespace

import pytest

import production.tools.build_next_behavior_selected_corpus as selected_corpus
from production.prediction.next_behavior_source_selection import (
    COMPLETE_STATUS,
)
from production.tools.build_next_behavior_selected_corpus import (
    SelectedCorpusBuildError,
    build_final_corpus_preparation_receipt,
    build_role_inventory,
    import_verified_classification_cache,
    ingest_selected_members,
    iter_missing_classification_commands,
    iter_role_private_sessions,
    normalized_selected_members,
)
from production.utils.serialization import stable_json


ROOT = Path(__file__).resolve().parents[1]
DECLARATION = (
    ROOT / "configs" / "next_behavior_source_selection.v1.json"
)
CLASSIFIER_MANIFEST = (
    ROOT / "configs" / "next_behavior_classifier_environment.v1.json"
)
PREPROCESSING_MANIFEST = ROOT / "configs/next_behavior_preprocessing.v1.json"


def _event(
    eventid: str,
    *,
    session: str,
    timestamp: str,
    command: str | None = None,
) -> dict:
    value = {
        "eventid": eventid,
        "session": session,
        "ts": timestamp,
        "group": 1,
    }
    if eventid == "cowrie.session.connect":
        value["protocol"] = "ssh"
    if command is not None:
        value["input"] = command
    return value


def _gzip_bytes(events: list[object]) -> bytes:
    output = io.BytesIO()
    with gzip.GzipFile(fileobj=output, mode="wb", mtime=0) as compressed:
        for event in events:
            line = event if isinstance(event, str) else json.dumps(event)
            compressed.write((line + "\n").encode())
    return output.getvalue()


def _fixture(
    tmp_path: Path,
    events_by_name: dict[str, list[object]] | None = None,
) -> tuple[Path, Path, dict[str, bytes]]:
    selection = json.loads(DECLARATION.read_text(encoding="utf-8"))
    raw_directory = tmp_path / "raw"
    raw_directory.mkdir()
    payloads: dict[str, bytes] = {}
    receipts: list[dict] = []
    events_by_name = events_by_name or {}
    for member in selection["members"]:
        date = member["collection_date"]
        default_session = f"session-{date}"
        default_events = [
            _event(
                "cowrie.session.connect",
                session=default_session,
                timestamp=f"{date}T00:00:00Z",
            ),
            _event(
                "cowrie.command.input",
                session=default_session,
                timestamp=f"{date}T00:00:01Z",
                command=f"private fixture {date}",
            ),
            _event(
                "cowrie.session.closed",
                session=default_session,
                timestamp=f"{date}T00:00:02Z",
            ),
        ]
        payload = _gzip_bytes(events_by_name.get(member["filename"], default_events))
        payloads[member["filename"]] = payload
        (raw_directory / member["filename"]).write_bytes(payload)
        receipts.append(
            {
                "filename": member["filename"],
                "archive_path": member["archive_path"],
                "collection_date": member["collection_date"],
                "role": member["role"],
                "size_bytes": len(payload),
                "archive_compressed_bytes": max(1, len(payload) - 1),
                "archive_crc32": f"{zlib.crc32(payload) & 0xFFFFFFFF:08x}",
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
    selection["verification"] = {
        "status": COMPLETE_STATUS,
        "member_receipts": receipts,
    }
    completed_path = tmp_path / "completed.json"
    completed_path.write_text(
        json.dumps(selection, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return completed_path, raw_directory, payloads


def _ingest_development(
    tmp_path: Path,
    events_by_name: dict[str, list[object]] | None = None,
) -> tuple[Path, Path, Path]:
    completed, raw_directory, _payloads = _fixture(
        tmp_path, events_by_name
    )
    database = tmp_path / "private/selected.sqlite"
    ingest_selected_members(
        completed_selection_path=completed,
        raw_directory=raw_directory,
        private_database_path=database,
        cohort="development",
        flush_size=2,
    )
    return completed, raw_directory, database


def test_completed_selection_binds_source_cohorts_to_frozen_roles(
    tmp_path: Path,
) -> None:
    completed, _raw, _payloads = _fixture(tmp_path)
    selection = json.loads(completed.read_text(encoding="utf-8"))
    members = normalized_selected_members(selection)

    assert [member["experiment_role"] for member in members] == [
        "train",
        "train",
        "train",
        "train",
        "selection",
        "calibration",
        "test",
        "test",
        "test",
        "test",
        "test",
        "test",
        "test",
    ]
    assert [member["source_cohort"] for member in members].count(
        "development"
    ) == 6
    assert [member["source_cohort"] for member in members].count("final") == 7


def test_pending_or_partially_receipted_selection_is_rejected(
    tmp_path: Path,
) -> None:
    pending = tmp_path / "pending.json"
    pending.write_bytes(DECLARATION.read_bytes())
    with pytest.raises(SelectedCorpusBuildError, match="pending"):
        ingest_selected_members(
            completed_selection_path=pending,
            raw_directory=tmp_path,
            private_database_path=tmp_path / "must-not-exist.sqlite",
            cohort="development",
        )
    assert not (tmp_path / "must-not-exist.sqlite").exists()


def test_all_requested_hashes_are_verified_before_database_creation(
    tmp_path: Path,
) -> None:
    completed, raw_directory, _payloads = _fixture(tmp_path)
    target = raw_directory / "2025-07-24.json.gz"
    target.write_bytes(target.read_bytes() + b"tampered")
    database = tmp_path / "must-not-exist.sqlite"

    with pytest.raises(SelectedCorpusBuildError, match="identity mismatch"):
        ingest_selected_members(
            completed_selection_path=completed,
            raw_directory=raw_directory,
            private_database_path=database,
            cohort="development",
        )
    assert not database.exists()


def test_ingest_tracks_connect_close_roles_and_resumes_without_duplication(
    tmp_path: Path,
) -> None:
    completed, raw_directory, database = _ingest_development(tmp_path)
    repeated = ingest_selected_members(
        completed_selection_path=completed,
        raw_directory=raw_directory,
        private_database_path=database,
        cohort="development",
        flush_size=2,
    )

    assert repeated["counts"]["processed_members"] == 6
    assert repeated["counts"]["sessions"] == 6
    assert repeated["counts"]["by_role"]["train"][
        "eligible_complete_sessions"
    ] == 4
    assert repeated["counts"]["by_role"]["selection"][
        "eligible_complete_sessions"
    ] == 1
    assert repeated["counts"]["by_role"]["calibration"][
        "eligible_complete_sessions"
    ] == 1
    assert {
        item["status"] for item in repeated["member_receipts"]
    } == {"already_ingested"}
    connection = sqlite3.connect(database)
    try:
        rows = connection.execute(
            """
            SELECT connected, closed, source_cohort, experiment_role
            FROM sessions ORDER BY first_seen
            """
        ).fetchall()
    finally:
        connection.close()
    assert rows[0] == (1, 1, "development", "train")
    assert rows[-1] == (1, 1, "development", "calibration")
    assert "private fixture" not in json.dumps(repeated)


def test_ingest_receipt_is_atomic_privacy_safe_and_never_overwritten(
    tmp_path: Path,
) -> None:
    completed, raw_directory, _payloads = _fixture(tmp_path)
    database = tmp_path / "private.sqlite"
    output = tmp_path / "receipts/development.json"
    receipt = ingest_selected_members(
        completed_selection_path=completed,
        raw_directory=raw_directory,
        private_database_path=database,
        cohort="development",
        receipt_output_path=output,
    )
    assert json.loads(output.read_text(encoding="utf-8")) == receipt
    assert "private fixture" not in output.read_text(encoding="utf-8")
    with pytest.raises(SelectedCorpusBuildError, match="overwrite"):
        ingest_selected_members(
            completed_selection_path=completed,
            raw_directory=raw_directory,
            private_database_path=database,
            cohort="development",
            receipt_output_path=output,
        )


def test_partial_sessions_are_quarantined_and_never_yielded(
    tmp_path: Path,
) -> None:
    filename = "2025-07-03.json.gz"
    events = {
        filename: [
            _event(
                "cowrie.command.input",
                session="closed-without-connect",
                timestamp="2025-07-03T00:00:01Z",
                command="private",
            ),
            _event(
                "cowrie.session.closed",
                session="closed-without-connect",
                timestamp="2025-07-03T00:00:02Z",
            ),
            _event(
                "cowrie.session.connect",
                session="connect-without-close",
                timestamp="2025-07-03T01:00:00Z",
            ),
        ]
    }
    _completed, _raw, database = _ingest_development(tmp_path, events)
    sessions = list(
        iter_role_private_sessions(
            private_database_path=database,
            purpose="fit_model",
        )
    )
    assert all(
        item["session_id"]
        not in {"closed-without-connect", "connect-without-close"}
        for item in sessions
    )
    connection = sqlite3.connect(database)
    try:
        quarantined = connection.execute(
            """
            SELECT raw_session_id, reason FROM quarantined_sessions
            WHERE raw_session_id IN (
                'closed-without-connect', 'connect-without-close'
            ) ORDER BY raw_session_id
            """
        ).fetchall()
    finally:
        connection.close()
    assert quarantined == [
        ("closed-without-connect", "incomplete_connection_or_close"),
        ("connect-without-close", "incomplete_connection_or_close"),
    ]


def test_cross_member_and_cross_role_sessions_are_quarantined(
    tmp_path: Path,
) -> None:
    shared = "shared-session"
    events = {
        "2025-07-24.json.gz": [
            _event(
                "cowrie.session.connect",
                session=shared,
                timestamp="2025-07-24T23:59:59Z",
            )
        ],
        "2025-07-31.json.gz": [
            _event(
                "cowrie.session.closed",
                session=shared,
                timestamp="2025-07-31T00:00:00Z",
            )
        ],
    }
    _completed, _raw, database = _ingest_development(tmp_path, events)
    connection = sqlite3.connect(database)
    try:
        row = connection.execute(
            """
            SELECT reason, source_members_json, experiment_roles_json
            FROM quarantined_sessions WHERE raw_session_id = ?
            """,
            (shared,),
        ).fetchone()
    finally:
        connection.close()
    assert row is not None
    assert row[0] == "cross_role"
    assert json.loads(row[1]) == [
        "2025-07-24.json.gz",
        "2025-07-31.json.gz",
    ]
    assert json.loads(row[2]) == ["selection", "train"]
    assert shared not in {
        item["session_id"]
        for item in iter_role_private_sessions(
            private_database_path=database,
            purpose="fit_model",
        )
    }


def test_same_role_cross_member_session_is_quarantined(
    tmp_path: Path,
) -> None:
    shared = "same-role-shared"
    events = {
        "2025-07-03.json.gz": [
            _event(
                "cowrie.session.connect",
                session=shared,
                timestamp="2025-07-03T23:59:59Z",
            )
        ],
        "2025-07-10.json.gz": [
            _event(
                "cowrie.session.closed",
                session=shared,
                timestamp="2025-07-10T00:00:00Z",
            )
        ],
    }
    _completed, _raw, database = _ingest_development(tmp_path, events)
    connection = sqlite3.connect(database)
    try:
        reason = connection.execute(
            "SELECT reason FROM quarantined_sessions "
            "WHERE raw_session_id = ?",
            (shared,),
        ).fetchone()[0]
    finally:
        connection.close()
    assert reason == "cross_member"


def _final_preparation(
    completed: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    commit: str = "a" * 40,
    key_id: str = "fixture-key",
) -> Path:
    calls = iter(
        (
            SimpleNamespace(stdout=commit + "\n"),
            SimpleNamespace(stdout=""),
        )
    )
    monkeypatch.setattr(
        selected_corpus.subprocess,
        "run",
        lambda *_args, **_kwargs: next(calls),
    )
    output = tmp_path / "final-preparation.json"
    build_final_corpus_preparation_receipt(
        completed_selection_path=completed,
        classifier_manifest_path=CLASSIFIER_MANIFEST,
        preprocessing_manifest_path=PREPROCESSING_MANIFEST,
        repository_root=ROOT,
        code_commit=commit,
        pseudonymization_key_id=key_id,
        output_path=output,
    )
    return output


def test_final_ingest_is_sealed_until_blinded_preparation_freezes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    completed, raw_directory, _payloads = _fixture(tmp_path)
    database = tmp_path / "private.sqlite"
    with pytest.raises(SelectedCorpusBuildError, match="remains sealed"):
        ingest_selected_members(
            completed_selection_path=completed,
            raw_directory=raw_directory,
            private_database_path=database,
            cohort="final",
        )
    assert not database.exists()

    with pytest.raises(SelectedCorpusBuildError, match="blinded-preparation"):
        ingest_selected_members(
            completed_selection_path=completed,
            raw_directory=raw_directory,
            private_database_path=database,
            cohort="final",
            prepare_final_corpus=True,
        )
    assert not database.exists()

    commit = "a" * 40
    preparation = _final_preparation(
        completed, tmp_path, monkeypatch, commit=commit
    )
    calls = iter(
        (
            SimpleNamespace(stdout=commit + "\n"),
            SimpleNamespace(stdout=""),
        )
    )
    def fake_run(command: list[str], **_kwargs: object) -> SimpleNamespace:
        return next(calls)

    monkeypatch.setattr(selected_corpus.subprocess, "run", fake_run)
    receipt = ingest_selected_members(
        completed_selection_path=completed,
        raw_directory=raw_directory,
        private_database_path=database,
        cohort="final",
        prepare_final_corpus=True,
        final_preparation_receipt_path=preparation,
        classifier_manifest_path=CLASSIFIER_MANIFEST,
        preprocessing_manifest_path=PREPROCESSING_MANIFEST,
        pseudonymization_key_id="fixture-key",
        repository_root=ROOT,
        code_commit=commit,
    )
    assert receipt["final_corpus_prepared"] is True
    assert receipt["evaluation_opened"] is False
    assert receipt["final_preparation_gate"]["status"] == (
        "frozen_for_blinded_preparation"
    )
    assert receipt["counts"]["by_role"]["test"][
        "eligible_complete_sessions"
    ] == 7
    connection = sqlite3.connect(database)
    try:
        metadata = dict(connection.execute("SELECT key, value FROM metadata"))
    finally:
        connection.close()
    assert "final_corpus_prepared_at" in metadata
    assert "final_test_opened_at" not in metadata


def test_final_preparation_rejects_mutated_provenance_before_database_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    completed, raw_directory, _payloads = _fixture(tmp_path)
    database = tmp_path / "private.sqlite"
    commit = "b" * 40
    receipt = _final_preparation(
        completed, tmp_path, monkeypatch, commit=commit
    )
    value = json.loads(receipt.read_text())
    value["evaluation_opened"] = True
    receipt.write_text(stable_json(value) + "\n", encoding="utf-8")
    calls = iter(
        (
            SimpleNamespace(stdout=commit + "\n"),
            SimpleNamespace(stdout=""),
        )
    )
    monkeypatch.setattr(
        selected_corpus.subprocess,
        "run",
        lambda *_args, **_kwargs: next(calls),
    )
    with pytest.raises(SelectedCorpusBuildError, match="does not match"):
        ingest_selected_members(
            completed_selection_path=completed,
            raw_directory=raw_directory,
            private_database_path=database,
            cohort="final",
            prepare_final_corpus=True,
            final_preparation_receipt_path=receipt,
            classifier_manifest_path=CLASSIFIER_MANIFEST,
            preprocessing_manifest_path=PREPROCESSING_MANIFEST,
            pseudonymization_key_id="fixture-key",
            repository_root=ROOT,
            code_commit=commit,
        )
    assert not database.exists()


def test_final_preparation_receipt_is_deterministic_complete_and_secret_free(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    completed, _raw_directory, _payloads = _fixture(tmp_path)
    receipt_path = _final_preparation(completed, tmp_path, monkeypatch)
    receipt = json.loads(receipt_path.read_text())

    assert receipt["status"] == "frozen_for_blinded_preparation"
    assert receipt["purpose"] == "prepare_final_corpus"
    assert receipt["evaluation_opened"] is False
    assert receipt["final_source_member_count"] == 7
    assert receipt["pseudonymization_key_id"] == "fixture-key"
    assert all(
        len(receipt[field]) == 64
        for field in (
            "source_selection_sha256",
            "final_source_member_receipts_sha256",
            "classifier_manifest_sha256",
            "classifier_adapter_sha256",
            "classification_pipeline_sha256",
            "preprocessing_sha256",
            "environment_lock_sha256",
            "label_policy_sha256",
            "trust_policy_sha256",
            "mitre_cache_sha256",
            "classification_checkpoint_sha256",
        )
    )
    serialized = stable_json(receipt)
    assert "training_bundle" not in serialized
    assert "test_opened" not in serialized
    assert "private fixture" not in serialized


def test_final_preparation_requires_exact_clean_code_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    completed, _raw_directory, _payloads = _fixture(tmp_path)
    commit = "e" * 40
    calls = iter(
        (
            SimpleNamespace(stdout="f" * 40 + "\n"),
            SimpleNamespace(stdout=""),
        )
    )
    monkeypatch.setattr(
        selected_corpus.subprocess,
        "run",
        lambda *_args, **_kwargs: next(calls),
    )
    with pytest.raises(SelectedCorpusBuildError, match="does not match"):
        build_final_corpus_preparation_receipt(
            completed_selection_path=completed,
            classifier_manifest_path=CLASSIFIER_MANIFEST,
            preprocessing_manifest_path=PREPROCESSING_MANIFEST,
            repository_root=ROOT,
            code_commit=commit,
            pseudonymization_key_id="fixture-key",
        )

    calls = iter(
        (
            SimpleNamespace(stdout=commit + "\n"),
            SimpleNamespace(stdout=" M tracked.py\n"),
        )
    )
    monkeypatch.setattr(
        selected_corpus.subprocess,
        "run",
        lambda *_args, **_kwargs: next(calls),
    )
    with pytest.raises(SelectedCorpusBuildError, match="must be clean"):
        build_final_corpus_preparation_receipt(
            completed_selection_path=completed,
            classifier_manifest_path=CLASSIFIER_MANIFEST,
            preprocessing_manifest_path=PREPROCESSING_MANIFEST,
            repository_root=ROOT,
            code_commit=commit,
            pseudonymization_key_id="fixture-key",
        )


def test_final_ingest_rejects_wrong_hmac_identity_before_database_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    completed, raw_directory, _payloads = _fixture(tmp_path)
    commit = "c" * 40
    preparation = _final_preparation(
        completed, tmp_path, monkeypatch, commit=commit
    )
    calls = iter(
        (
            SimpleNamespace(stdout=commit + "\n"),
            SimpleNamespace(stdout=""),
        )
    )
    monkeypatch.setattr(
        selected_corpus.subprocess,
        "run",
        lambda *_args, **_kwargs: next(calls),
    )
    database = tmp_path / "must-not-exist.sqlite"
    with pytest.raises(SelectedCorpusBuildError, match="does not match"):
        ingest_selected_members(
            completed_selection_path=completed,
            raw_directory=raw_directory,
            private_database_path=database,
            cohort="final",
            prepare_final_corpus=True,
            final_preparation_receipt_path=preparation,
            classifier_manifest_path=CLASSIFIER_MANIFEST,
            preprocessing_manifest_path=PREPROCESSING_MANIFEST,
            pseudonymization_key_id="another-key",
            repository_root=ROOT,
            code_commit=commit,
        )
    assert not database.exists()


def test_legacy_open_state_cannot_be_reclassified_as_blinded_preparation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    completed, raw_directory, _payloads = _fixture(tmp_path)
    commit = "d" * 40
    preparation = _final_preparation(
        completed, tmp_path, monkeypatch, commit=commit
    )
    database = tmp_path / "private.sqlite"
    connection = selected_corpus.open_selected_database(database)
    connection.execute(
        "INSERT INTO metadata(key, value) VALUES "
        "('final_test_opened_at', 'legacy')"
    )
    connection.commit()
    connection.close()
    calls = iter(
        (
            SimpleNamespace(stdout=commit + "\n"),
            SimpleNamespace(stdout=""),
        )
    )
    monkeypatch.setattr(
        selected_corpus.subprocess,
        "run",
        lambda *_args, **_kwargs: next(calls),
    )
    with pytest.raises(SelectedCorpusBuildError, match="legacy"):
        ingest_selected_members(
            completed_selection_path=completed,
            raw_directory=raw_directory,
            private_database_path=database,
            cohort="final",
            prepare_final_corpus=True,
            final_preparation_receipt_path=preparation,
            classifier_manifest_path=CLASSIFIER_MANIFEST,
            preprocessing_manifest_path=PREPROCESSING_MANIFEST,
            pseudonymization_key_id="fixture-key",
            repository_root=ROOT,
            code_commit=commit,
        )


def test_role_inventory_is_pseudonymous_purpose_scoped_and_no_overwrite(
    tmp_path: Path,
) -> None:
    _completed, _raw, database = _ingest_development(tmp_path)
    output = tmp_path / "train-inventory.json"
    inventory = build_role_inventory(
        private_database_path=database,
        purpose="fit_model",
        pseudonymization_key=b"k" * 32,
        pseudonymization_key_id="fixture-key",
        output_path=output,
    )
    serialized = output.read_text(encoding="utf-8")

    assert inventory["role"] == "train"
    assert inventory["source_cohort"] == "development"
    assert inventory["source_member_count"] == 4
    assert inventory["eligible_complete_session_count"] == 4
    assert inventory["partial_sessions_can_emit_terminal_target"] is False
    assert "session-2025" not in serialized
    assert "private fixture" not in serialized
    with pytest.raises(SelectedCorpusBuildError, match="overwrite"):
        build_role_inventory(
            private_database_path=database,
            purpose="fit_model",
            pseudonymization_key=b"k" * 32,
            pseudonymization_key_id="fixture-key",
            output_path=output,
        )


def test_role_inventory_requires_every_member_and_preparation_marker(
    tmp_path: Path,
) -> None:
    completed, raw_directory, _payloads = _fixture(tmp_path)
    database = tmp_path / "private.sqlite"
    ingest_selected_members(
        completed_selection_path=completed,
        raw_directory=raw_directory,
        private_database_path=database,
        cohort="development",
        selected_members=["2025-07-03.json.gz"],
    )
    with pytest.raises(SelectedCorpusBuildError, match="all frozen train"):
        build_role_inventory(
            private_database_path=database,
            purpose="fit_model",
            pseudonymization_key=b"k" * 32,
            pseudonymization_key_id="fixture-key",
        )
    with pytest.raises(
        SelectedCorpusBuildError, match="blinded preparation"
    ):
        build_role_inventory(
            private_database_path=database,
            purpose="final_evaluation",
            pseudonymization_key=b"k" * 32,
            pseudonymization_key_id="fixture-key",
        )


def test_private_iterator_is_role_scoped_and_preserves_event_order(
    tmp_path: Path,
) -> None:
    _completed, _raw, database = _ingest_development(tmp_path)
    training = list(
        iter_role_private_sessions(
            private_database_path=database,
            purpose="fit_model",
        )
    )
    selection = list(
        iter_role_private_sessions(
            private_database_path=database,
            purpose="select_model",
        )
    )
    calibration = list(
        iter_role_private_sessions(
            private_database_path=database,
            purpose="fit_calibration",
        )
    )

    assert len(training) == 4
    assert len(selection) == 1
    assert len(calibration) == 1
    assert {item["experiment_role"] for item in training} == {"train"}
    assert training[0]["commands"][0]["source_line"] == 2
    assert training[0]["connected"] is True
    assert training[0]["closed"] is True


def test_source_selection_hash_drift_is_rejected_on_resume(
    tmp_path: Path,
) -> None:
    completed, raw_directory, database = _ingest_development(tmp_path)
    changed = json.loads(completed.read_text(encoding="utf-8"))
    changed["verification"]["member_receipts"][0][
        "archive_compressed_bytes"
    ] += 1
    changed_path = tmp_path / "changed-completed.json"
    changed_path.write_text(json.dumps(changed), encoding="utf-8")

    with pytest.raises(
        SelectedCorpusBuildError,
        match="source-selection hash mismatch",
    ):
        ingest_selected_members(
            completed_selection_path=changed_path,
            raw_directory=raw_directory,
            private_database_path=database,
            cohort="development",
        )


def _cache_label() -> list[dict]:
    classifier = json.loads(CLASSIFIER_MANIFEST.read_text(encoding="utf-8"))
    policy = classifier["classification_policy"]
    return [
        {
            "agreement_status": "rule_only",
            "checkpoint_sha256": "",
            "confidence": None,
            "confidence_bucket": "not_applicable",
            "evidence_ref": "fixture:output-0",
            "policy_sha256": policy["rule_policy_sha256"],
            "source": "reviewed_rule",
            "tactic": "execution",
            "technique": "T1059",
            "trust_policy_sha256": policy["trust_policy_sha256"],
            "trust_tier": "trusted_observation",
        }
    ]


def _classification_donor(
    path: Path,
    *,
    selection_path: Path,
    cached_commands: list[str],
    canonical_rows: bool = True,
    mutate_receipt: tuple[str, object] | None = None,
) -> None:
    selection = json.loads(selection_path.read_text(encoding="utf-8"))
    members = normalized_selected_members(selection)
    classifier = json.loads(CLASSIFIER_MANIFEST.read_text(encoding="utf-8"))
    policy = classifier["classification_policy"]
    receipt = {
        "schema_version": "next_behavior_zenodo_classification.v1",
        "status": "classified",
        "source_manifest_sha256": selection["preserved_source_manifest"][
            "sha256"
        ],
        "classifier_manifest_sha256": hashlib.sha256(
            CLASSIFIER_MANIFEST.read_bytes()
        ).hexdigest(),
        "checkpoint_sha256": classifier["classifier"]["checkpoint_sha256"],
        "rule_policy_sha256": policy["rule_policy_sha256"],
        "trust_policy_sha256": policy["trust_policy_sha256"],
        "trusted_model_only_threshold": policy[
            "trusted_model_only_threshold"
        ],
        "drop_rule_securebert_disagreements": policy[
            "drop_rule_securebert_disagreements"
        ],
        "label_adapter_sha256": hashlib.sha256(
            (
                ROOT
                / "production/prediction/next_behavior_label_policy.py"
            ).read_bytes()
        ).hexdigest(),
        "corpus_builder_sha256": hashlib.sha256(
            (
                ROOT / "production/tools/build_next_behavior_zenodo_corpus.py"
            ).read_bytes()
        ).hexdigest(),
    }
    if mutate_receipt is not None:
        receipt[mutate_receipt[0]] = mutate_receipt[1]
    database = sqlite3.connect(path)
    database.executescript(
        """
        CREATE TABLE processed_members(
            source_member TEXT PRIMARY KEY,
            source_sha256 TEXT NOT NULL,
            source_size_bytes INTEGER NOT NULL,
            chronological_order INTEGER NOT NULL
        );
        CREATE TABLE build_stage_receipts(
            stage_id TEXT PRIMARY KEY,
            receipt_json TEXT NOT NULL
        );
        CREATE TABLE command_labels(
            command TEXT PRIMARY KEY,
            labels_json TEXT NOT NULL,
            unrepresented_json TEXT NOT NULL
        );
        """
    )
    database.executemany(
        "INSERT INTO processed_members VALUES (?, ?, ?, ?)",
        [
            (
                member["filename"],
                member["sha256"],
                member["size_bytes"],
                member["chronological_order"],
            )
            for member in members
        ],
    )
    database.execute(
        "INSERT INTO build_stage_receipts VALUES (?, ?)",
        (
            "next_behavior_zenodo_classification.v1",
            stable_json(receipt),
        ),
    )
    labels_json = stable_json(_cache_label())
    if not canonical_rows:
        labels_json = json.dumps(_cache_label(), indent=2)
    database.executemany(
        "INSERT INTO command_labels VALUES (?, ?, ?)",
        [
            (command, labels_json, "{}")
            for command in cached_commands
        ],
    )
    database.commit()
    database.close()


def test_verified_cache_import_reuses_only_exact_commands_and_reports_missing(
    tmp_path: Path,
) -> None:
    completed, _raw, database = _ingest_development(tmp_path)
    commands = [
        row[0]
        for row in sqlite3.connect(database).execute(
            "SELECT DISTINCT command FROM command_events ORDER BY command"
        )
    ]
    donor = tmp_path / "donor.sqlite"
    _classification_donor(
        donor,
        selection_path=completed,
        cached_commands=[commands[0], commands[2], "not-in-target"],
    )

    receipt = import_verified_classification_cache(
        completed_selection_path=completed,
        classifier_manifest_path=CLASSIFIER_MANIFEST,
        repository_root=ROOT,
        donor_database_path=donor,
        private_database_path=database,
    )
    missing = list(iter_missing_classification_commands(database))

    assert receipt["imported_exact_command_count"] == 2
    assert receipt["target_unique_command_count"] == 6
    assert receipt["missing_unique_command_count"] == 4
    assert receipt["only_missing_commands_require_classification"] is True
    assert missing == sorted(set(commands) - {commands[0], commands[2]})
    connection = sqlite3.connect(database)
    try:
        stored = connection.execute(
            "SELECT command, labels_json, unrepresented_json "
            "FROM command_labels ORDER BY command"
        ).fetchall()
    finally:
        connection.close()
    assert [row[0] for row in stored] == sorted([commands[0], commands[2]])
    assert all(row[1] == stable_json(_cache_label()) for row in stored)
    assert all(row[2] == "{}" for row in stored)


def test_cache_import_is_resumable_by_exact_receipt_identity(
    tmp_path: Path,
) -> None:
    completed, _raw, database = _ingest_development(tmp_path)
    command = next(iter_missing_classification_commands(database))
    donor = tmp_path / "donor.sqlite"
    _classification_donor(
        donor,
        selection_path=completed,
        cached_commands=[command],
    )
    first = import_verified_classification_cache(
        completed_selection_path=completed,
        classifier_manifest_path=CLASSIFIER_MANIFEST,
        repository_root=ROOT,
        donor_database_path=donor,
        private_database_path=database,
    )
    second = import_verified_classification_cache(
        completed_selection_path=completed,
        classifier_manifest_path=CLASSIFIER_MANIFEST,
        repository_root=ROOT,
        donor_database_path=donor,
        private_database_path=database,
    )
    assert first["status"] == "verified_exact_command_cache_imported"
    assert second["status"] == "already_imported"
    assert second["cache_receipt_id"] == first["cache_receipt_id"]


@pytest.mark.parametrize(
    ("canonical_rows", "mutate_receipt", "message"),
    [
        (False, None, "canonically serialized"),
        (
            True,
            ("trust_policy_sha256", "f" * 64),
            "trust_policy_sha256 receipt mismatch",
        ),
    ],
)
def test_cache_import_fails_closed_before_any_destination_labels(
    tmp_path: Path,
    canonical_rows: bool,
    mutate_receipt: tuple[str, object] | None,
    message: str,
) -> None:
    completed, _raw, database = _ingest_development(tmp_path)
    command = next(iter_missing_classification_commands(database))
    donor = tmp_path / "donor.sqlite"
    _classification_donor(
        donor,
        selection_path=completed,
        cached_commands=[command],
        canonical_rows=canonical_rows,
        mutate_receipt=mutate_receipt,
    )

    with pytest.raises(SelectedCorpusBuildError, match=message):
        import_verified_classification_cache(
            completed_selection_path=completed,
            classifier_manifest_path=CLASSIFIER_MANIFEST,
            repository_root=ROOT,
            donor_database_path=donor,
            private_database_path=database,
        )
    connection = sqlite3.connect(database)
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM command_labels"
        ).fetchone()[0] == 0
        assert connection.execute(
            "SELECT COUNT(*) FROM classification_cache_receipts"
        ).fetchone()[0] == 0
    finally:
        connection.close()
