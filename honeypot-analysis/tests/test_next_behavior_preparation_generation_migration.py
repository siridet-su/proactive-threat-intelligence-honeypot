from __future__ import annotations

import json
import hashlib
import hmac
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from production.tools.build_next_behavior_selected_corpus import (
    FINAL_PREPARATION_GENERATION_SCHEMA_VERSION,
    SelectedCorpusBuildError,
    open_selected_database,
    require_final_preparation_generation_marker,
    require_final_preparation_generation_receipt,
)
from production.tools.build_next_behavior_selected_safe_corpus import (
    SAFE_BUILD_RECEIPT_SCHEMA_VERSION,
    SelectedSafeCorpusError,
    build_selected_safe_corpus,
    migrate_final_preparation_generation,
    _store_snapshot_hmac_sha256,
    verify_selected_role_artifacts,
)
from production.utils.serialization import stable_id, stable_json
from tests.test_next_behavior_selected_safe_corpus import (
    CLASSIFIER_MANIFEST,
    CODE_COMMIT,
    PREPROCESSING_MANIFEST,
    _preparation_receipt,
    _safe_store,
)


KEY = b"k" * 32
KEY_ID = "fixture-key"


def _reference_snapshot(database: sqlite3.Connection) -> str:
    """The pre-optimization snapshot queries, retained only for equivalence."""

    digest = hmac.new(
        KEY,
        b"next-behavior-final-store-snapshot.v1\0",
        hashlib.sha256,
    )
    queries = (
        (
            "metadata",
            """
            SELECT key, value FROM metadata
            WHERE key IN (
                'store_schema_version', 'source_selection_sha256',
                'final_corpus_prepared_at',
                'final_corpus_preparation_receipt_id',
                'final_corpus_preparation_receipt_json'
            ) ORDER BY key
            """,
        ),
        (
            "source_members",
            """
            SELECT filename, source_sha256, source_size_bytes, archive_crc32,
                   chronological_order, source_cohort, experiment_role,
                   collection_start, collection_end, stats_json
            FROM source_members WHERE experiment_role = 'test'
            ORDER BY chronological_order
            """,
        ),
        (
            "sessions",
            """
            SELECT raw_session_id, source_member, source_cohort,
                   experiment_role, first_seen, last_seen, protocol,
                   configuration, connected, closed, cross_member, cross_role
            FROM sessions WHERE experiment_role = 'test'
            ORDER BY raw_session_id
            """,
        ),
        (
            "session_sources",
            """
            SELECT raw_session_id, source_member, source_cohort,
                   experiment_role, chronological_order, first_seen,
                   last_seen, protocol, configuration, connected, closed
            FROM session_sources WHERE experiment_role = 'test'
            ORDER BY raw_session_id, source_member
            """,
        ),
        (
            "command_events",
            """
            SELECT events.source_member, events.source_line,
                   events.raw_session_id, events.event_time, events.command
            FROM command_events AS events
            JOIN source_members AS members
              ON members.filename = events.source_member
            WHERE members.experiment_role = 'test'
            ORDER BY events.source_member, events.source_line
            """,
        ),
        (
            "context_events",
            """
            SELECT events.source_member, events.source_line,
                   events.raw_session_id, events.event_time, events.event_type
            FROM context_events AS events
            JOIN source_members AS members
              ON members.filename = events.source_member
            WHERE members.experiment_role = 'test'
            ORDER BY events.source_member, events.source_line
            """,
        ),
        (
            "quarantine",
            """
            SELECT q.raw_session_id, q.reason, q.source_members_json,
                   q.experiment_roles_json
            FROM quarantined_sessions AS q
            WHERE EXISTS (
                SELECT 1 FROM session_sources AS sources
                WHERE sources.raw_session_id = q.raw_session_id
                  AND sources.experiment_role = 'test'
            ) ORDER BY q.raw_session_id
            """,
        ),
        (
            "command_labels",
            """
            SELECT labels.command, labels.labels_json,
                   labels.unrepresented_json, labels.cache_receipt_id
            FROM command_labels AS labels
            WHERE EXISTS (
                SELECT 1 FROM command_events AS events
                JOIN source_members AS members
                  ON members.filename = events.source_member
                WHERE events.command = labels.command
                  AND members.experiment_role = 'test'
            ) ORDER BY labels.command
            """,
        ),
    )
    for table, query in queries:
        digest.update(table.encode())
        digest.update(b"\0")
        count = 0
        for row in database.execute(query):
            digest.update(stable_json(list(row)).encode())
            digest.update(b"\n")
            count += 1
        digest.update(str(count).encode())
        digest.update(b"\0")
    return digest.hexdigest()


@pytest.fixture(autouse=True)
def _verified_repository_commit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "production.tools.build_next_behavior_selected_safe_corpus."
        "_require_repository_commit",
        lambda _root, commit: commit,
    )


def _legacy_paths(root: Path) -> dict[str, Path]:
    return {
        "safe_sessions_path": root / "safe_sessions.jsonl",
        "examples_path": root / "examples.jsonl",
        "source_receipts_path": root / "source_receipts.json",
        "corpus_receipt_path": root / "corpus_receipt.json",
        "build_receipt_path": root / "build_receipt.json",
    }


def _generation_paths(root: Path) -> dict[str, Path]:
    return {
        **_legacy_paths(root),
        "historical_split_evidence_path": (
            root / "historical_split_evidence.json"
        ),
    }


@dataclass
class MigrationCase:
    database_path: Path
    historical_path: Path
    preparation: dict[str, Any]
    predecessor_paths: dict[str, Path]
    predecessor_bytes: dict[str, bytes]
    root: Path

    def migration_arguments(
        self,
        *,
        generation: str = "generation-1",
        outputs: str = "v3-generation-1",
    ) -> dict[str, Any]:
        return {
            "private_database_path": self.database_path,
            "preparation_receipt": self.preparation,
            "predecessor_build_receipt_path": self.predecessor_paths[
                "build_receipt_path"
            ],
            "predecessor_safe_sessions_path": self.predecessor_paths[
                "safe_sessions_path"
            ],
            "predecessor_examples_path": self.predecessor_paths[
                "examples_path"
            ],
            "predecessor_source_receipts_path": self.predecessor_paths[
                "source_receipts_path"
            ],
            "predecessor_corpus_receipt_path": self.predecessor_paths[
                "corpus_receipt_path"
            ],
            "classifier_manifest_path": CLASSIFIER_MANIFEST,
            "preprocessing_manifest_path": PREPROCESSING_MANIFEST,
            "pseudonymization_key": KEY,
            "pseudonymization_key_id": KEY_ID,
            **_generation_paths(self.root / outputs),
            "generation_receipt_path": self.root / f"{generation}.json",
            "code_commit": CODE_COMMIT,
        }


@pytest.fixture
def migration_case(tmp_path: Path) -> MigrationCase:
    state_root = tmp_path / "state"
    state_root.mkdir()
    database_path, historical_path = _safe_store(
        state_root, role="test"
    )
    preparation = _preparation_receipt(database_path)
    predecessor_paths = _legacy_paths(tmp_path / "legacy-v2")
    receipt = build_selected_safe_corpus(
        purpose="final_evaluation",
        private_database_path=database_path,
        classifier_manifest_path=CLASSIFIER_MANIFEST,
        preprocessing_manifest_path=PREPROCESSING_MANIFEST,
        historical_payload_path=historical_path,
        pseudonymization_key=KEY,
        pseudonymization_key_id=KEY_ID,
        code_commit=CODE_COMMIT,
        final_preparation_receipt=preparation,
        **predecessor_paths,
    )
    assert receipt["schema_version"] == (
        "next_behavior_selected_safe_build.v2"
    )
    return MigrationCase(
        database_path=database_path,
        historical_path=historical_path,
        preparation=preparation,
        predecessor_paths=predecessor_paths,
        predecessor_bytes={
            name: path.read_bytes()
            for name, path in predecessor_paths.items()
        },
        root=tmp_path,
    )


def _load_generation(arguments: dict[str, Any]) -> dict[str, Any]:
    return json.loads(arguments["generation_receipt_path"].read_text())


def _assert_predecessor_unchanged(case: MigrationCase) -> None:
    assert {
        name: path.read_bytes()
        for name, path in case.predecessor_paths.items()
    } == case.predecessor_bytes


def test_migration_is_additive_and_authorizes_verified_v3_output(
    migration_case: MigrationCase,
) -> None:
    arguments = migration_case.migration_arguments()
    migrated = migrate_final_preparation_generation(**arguments)
    generation = _load_generation(arguments)

    assert migrated["migration_status"] == "generation_recorded"
    assert generation["schema_version"] == (
        FINAL_PREPARATION_GENERATION_SCHEMA_VERSION
    )
    assert generation["generation_number"] == 1
    assert generation["predecessor_generation_id"] is None
    assert not any(
        path.exists()
        for path in _generation_paths(
            migration_case.root / "v3-generation-1"
        ).values()
    )
    _assert_predecessor_unchanged(migration_case)

    v3_paths = _generation_paths(
        migration_case.root / "v3-generation-1"
    )
    built = build_selected_safe_corpus(
        purpose="final_evaluation",
        private_database_path=migration_case.database_path,
        classifier_manifest_path=CLASSIFIER_MANIFEST,
        preprocessing_manifest_path=PREPROCESSING_MANIFEST,
        historical_payload_path=migration_case.historical_path,
        pseudonymization_key=KEY,
        pseudonymization_key_id=KEY_ID,
        code_commit=CODE_COMMIT,
        final_preparation_generation=generation,
        **v3_paths,
    )

    assert built["schema_version"] == SAFE_BUILD_RECEIPT_SCHEMA_VERSION
    assert built["final_preparation_gate"] == generation
    assert verify_selected_role_artifacts(
        build_receipt_path=v3_paths["build_receipt_path"],
        safe_sessions_path=v3_paths["safe_sessions_path"],
        examples_path=v3_paths["examples_path"],
        source_receipts_path=v3_paths["source_receipts_path"],
        corpus_receipt_path=v3_paths["corpus_receipt_path"],
        historical_split_evidence_path=v3_paths[
            "historical_split_evidence_path"
        ],
        expected_purpose="final_evaluation",
        allow_final=True,
    )["status"] == "selected_role_artifacts_verified"
    _assert_predecessor_unchanged(migration_case)


def test_migration_is_idempotent_and_recovers_only_a_missing_head(
    migration_case: MigrationCase,
) -> None:
    arguments = migration_case.migration_arguments()
    first = migrate_final_preparation_generation(**arguments)
    second = migrate_final_preparation_generation(**arguments)
    assert first["generation_id"] == second["generation_id"]
    assert second["migration_status"] == "generation_already_recorded"

    database = sqlite3.connect(migration_case.database_path)
    database.execute(
        "DELETE FROM metadata "
        "WHERE key = 'final_corpus_preparation_generation_id'"
    )
    database.commit()
    database.close()

    recovered = migrate_final_preparation_generation(**arguments)
    assert recovered["generation_id"] == first["generation_id"]
    assert recovered["migration_status"] == "generation_head_recovered"
    database = sqlite3.connect(migration_case.database_path)
    assert database.execute(
        "SELECT COUNT(*) FROM final_preparation_generations"
    ).fetchone() == (1,)
    assert database.execute(
        "SELECT value FROM metadata "
        "WHERE key = 'final_corpus_preparation_generation_id'"
    ).fetchone() == (first["generation_id"],)
    database.close()


def test_migration_refuses_silent_preparation_or_head_rebinding(
    migration_case: MigrationCase,
) -> None:
    changed_preparation = dict(migration_case.preparation)
    changed_preparation["source_selection_id"] = "silently-rebound"
    changed_preparation.pop("receipt_id")
    changed_preparation["receipt_id"] = stable_id(
        "nextbehaviorfinalpreparation", changed_preparation
    )
    rebound_arguments = migration_case.migration_arguments()
    rebound_arguments["preparation_receipt"] = changed_preparation
    with pytest.raises(
        SelectedSafeCorpusError,
        match="current preparation source_selection_id is incompatible",
    ):
        migrate_final_preparation_generation(**rebound_arguments)
    assert not rebound_arguments["generation_receipt_path"].exists()

    arguments = migration_case.migration_arguments()
    migrate_final_preparation_generation(**arguments)
    database = sqlite3.connect(migration_case.database_path)
    database.execute(
        "UPDATE metadata SET value = ? "
        "WHERE key = 'final_corpus_preparation_generation_id'",
        ("forged-other-generation",),
    )
    database.commit()
    database.close()
    with pytest.raises(
        SelectedSafeCorpusError, match="head cannot be rebound"
    ):
        migrate_final_preparation_generation(**arguments)


@pytest.mark.parametrize("failure", ["missing", "incompatible"])
def test_migration_rejects_missing_or_incompatible_predecessor(
    migration_case: MigrationCase,
    failure: str,
) -> None:
    build_path = migration_case.predecessor_paths["build_receipt_path"]
    if failure == "missing":
        build_path.unlink()
        expected = "predecessor v2 artifact is missing"
    else:
        receipt = json.loads(build_path.read_text())
        receipt["classifier_manifest_sha256"] = "f" * 64
        receipt.pop("build_receipt_id")
        receipt["build_receipt_id"] = stable_id(
            "nextbehaviorselectedsafebuild", receipt
        )
        build_path.write_text(
            json.dumps(receipt, indent=2, sort_keys=True) + "\n"
        )
        expected = "predecessor v2 classifier_manifest_sha256 is incompatible"

    arguments = migration_case.migration_arguments()
    with pytest.raises(SelectedSafeCorpusError, match=expected):
        migrate_final_preparation_generation(**arguments)
    assert not arguments["generation_receipt_path"].exists()


def test_migration_rejects_a_store_changed_since_the_v2_predecessor(
    migration_case: MigrationCase,
) -> None:
    database = sqlite3.connect(migration_case.database_path)
    database.execute(
        "UPDATE context_events SET event_type = 'cowrie.login.failed' "
        "WHERE source_line = 1"
    )
    database.commit()
    database.close()

    arguments = migration_case.migration_arguments()
    with pytest.raises(
        SelectedSafeCorpusError,
        match="predecessor .*incompatible with store|store .*changed",
    ):
        migrate_final_preparation_generation(**arguments)
    assert not arguments["generation_receipt_path"].exists()


def test_migration_never_overwrites_v2_or_preexisting_v3_artifacts(
    migration_case: MigrationCase,
) -> None:
    arguments = migration_case.migration_arguments()
    arguments["safe_sessions_path"] = migration_case.predecessor_paths[
        "safe_sessions_path"
    ]
    with pytest.raises(
        SelectedSafeCorpusError, match="cannot overwrite predecessor"
    ):
        migrate_final_preparation_generation(**arguments)
    _assert_predecessor_unchanged(migration_case)

    arguments = migration_case.migration_arguments()
    arguments["safe_sessions_path"].parent.mkdir(parents=True)
    arguments["safe_sessions_path"].write_bytes(b"do-not-overwrite\n")
    with pytest.raises(
        SelectedSafeCorpusError, match="authorized v3 output must be fresh"
    ):
        migrate_final_preparation_generation(**arguments)
    assert arguments["safe_sessions_path"].read_bytes() == b"do-not-overwrite\n"
    _assert_predecessor_unchanged(migration_case)


def test_generation_cannot_be_used_for_unauthorized_output_paths(
    migration_case: MigrationCase,
) -> None:
    arguments = migration_case.migration_arguments()
    migrate_final_preparation_generation(**arguments)
    generation = _load_generation(arguments)
    unauthorized = _generation_paths(
        migration_case.root / "not-authorized-by-generation"
    )

    with pytest.raises(
        SelectedSafeCorpusError,
        match="authorized_output_paths is inconsistent",
    ):
        build_selected_safe_corpus(
            purpose="final_evaluation",
            private_database_path=migration_case.database_path,
            classifier_manifest_path=CLASSIFIER_MANIFEST,
            preprocessing_manifest_path=PREPROCESSING_MANIFEST,
            historical_payload_path=migration_case.historical_path,
            pseudonymization_key=KEY,
            pseudonymization_key_id=KEY_ID,
            code_commit=CODE_COMMIT,
            final_preparation_generation=generation,
            **unauthorized,
        )
    assert not any(path.exists() for path in unauthorized.values())


def test_generation_receipt_and_entire_ledger_history_are_validated(
    migration_case: MigrationCase,
) -> None:
    arguments = migration_case.migration_arguments()
    migrate_final_preparation_generation(**arguments)
    generation = _load_generation(arguments)

    malformed = dict(generation)
    malformed["authorized_output_paths"] = {
        **malformed["authorized_output_paths"],
        "safe_sessions": "/tmp/unauthorized.jsonl",
    }
    with pytest.raises(
        SelectedCorpusBuildError, match="output authorization is invalid"
    ):
        require_final_preparation_generation_receipt(malformed)

    database = sqlite3.connect(migration_case.database_path)
    database.execute(
        "UPDATE final_preparation_generations "
        "SET receipt_sha256 = ? WHERE generation_number = 1",
        ("0" * 64,),
    )
    database.commit()
    with pytest.raises(
        SelectedCorpusBuildError, match="ledger history is inconsistent"
    ):
        require_final_preparation_generation_marker(database, generation)
    database.close()


def test_new_compatible_generation_appends_to_history(
    migration_case: MigrationCase,
) -> None:
    first_arguments = migration_case.migration_arguments()
    first = migrate_final_preparation_generation(**first_arguments)
    second_arguments = migration_case.migration_arguments(
        generation="generation-2",
        outputs="v3-generation-2",
    )
    second = migrate_final_preparation_generation(**second_arguments)

    assert second["generation_number"] == 2
    assert second["predecessor_generation_id"] == first["generation_id"]
    database = open_selected_database(migration_case.database_path)
    assert database.execute(
        "SELECT generation_id FROM final_preparation_generations "
        "ORDER BY generation_number"
    ).fetchall() == [
        (first["generation_id"],),
        (second["generation_id"],),
    ]
    database.close()


def test_optimized_snapshot_matches_reference_and_reports_aggregate_progress(
    migration_case: MigrationCase,
) -> None:
    database = sqlite3.connect(migration_case.database_path)
    progress: list[tuple[str, int]] = []
    try:
        reference = _reference_snapshot(database)
        optimized = _store_snapshot_hmac_sha256(
            database,
            pseudonymization_key=KEY,
            progress=lambda table, count: progress.append((table, count)),
        )
    finally:
        database.close()

    assert optimized == reference
    assert [table for table, _count in progress] == [
        "metadata",
        "source_members",
        "sessions",
        "session_sources",
        "command_events",
        "context_events",
        "quarantine",
        "command_labels",
    ]
    assert all(isinstance(count, int) and count >= 0 for _, count in progress)


def test_snapshot_uses_single_pass_membership_filters_on_large_label_fixture(
    migration_case: MigrationCase,
) -> None:
    database = sqlite3.connect(migration_case.database_path)
    traced: list[str] = []
    try:
        database.executemany(
            """
            INSERT INTO command_labels(
                command, labels_json, unrepresented_json, cache_receipt_id
            ) VALUES (?, '[]', '[]', 'synthetic-cache')
            """,
            [(f"synthetic-unmatched-{index:04d}",) for index in range(600)],
        )
        database.commit()
        database.set_trace_callback(traced.append)
        _store_snapshot_hmac_sha256(database, pseudonymization_key=KEY)
    finally:
        database.set_trace_callback(None)
        database.close()

    normalized = [statement.upper() for statement in traced]
    label_statements = [
        statement for statement in normalized if "FROM COMMAND_LABELS" in statement
    ]
    quarantine_statements = [
        statement
        for statement in normalized
        if "FROM QUARANTINED_SESSIONS" in statement
    ]
    assert len(label_statements) == 1
    assert len(quarantine_statements) == 1
    assert not any("WHERE EXISTS" in statement for statement in normalized)
