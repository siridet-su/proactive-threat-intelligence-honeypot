from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import production.tools.build_next_behavior_selected_safe_corpus as safe_corpus
from production.prediction.next_behavior_label_policy import (
    normalize_classifier_outputs,
)
from production.tools.build_next_behavior_selected_corpus import (
    FINAL_PREPARATION_SCHEMA_VERSION,
    final_member_receipts_sha256,
    open_selected_database,
)
from production.tools.build_next_behavior_selected_safe_corpus import (
    HISTORICAL_DATASET_SOURCE,
    SelectedSafeCorpusError,
    _require_repository_commit,
    _scan_public_value,
    build_selected_safe_corpus,
    classify_missing_selected_commands,
    verify_selected_role_artifacts,
)
from production.utils.serialization import stable_id, stable_json


ROOT = Path(__file__).resolve().parents[1]
CLASSIFIER_MANIFEST = (
    ROOT / "configs/next_behavior_classifier_environment.v1.json"
)
PREPROCESSING_MANIFEST = ROOT / "configs/next_behavior_preprocessing.v1.json"
CODE_COMMIT = "a" * 40
SELECTION_SHA = "b" * 64


@pytest.fixture(autouse=True)
def _verified_repository_commit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "production.tools.build_next_behavior_selected_safe_corpus."
        "_require_repository_commit",
        lambda _root, commit: commit,
    )


class _Classifier:
    def __init__(self, *, fail_command: str = "") -> None:
        self.commands: list[str] = []
        self.fail_command = fail_command

    def classify(self, command: str) -> list[dict]:
        self.commands.append(command)
        if command == self.fail_command:
            raise RuntimeError("synthetic classifier interruption")
        return [
            {
                "ttp": "T1082",
                "tactic": "discovery",
                "source": "rule",
                "high_confidence": True,
                "agreement_status": "rule_only",
            }
        ]


def _asset_verification(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "production.tools.build_next_behavior_selected_safe_corpus."
        "verify_classifier_assets",
        lambda *args, **kwargs: {"status": "assets_verified"},
    )


def _database(tmp_path: Path) -> Path:
    path = tmp_path / "private.sqlite"
    database = open_selected_database(path)
    database.execute(
        "INSERT INTO metadata(key, value) VALUES (?, ?)",
        ("source_selection_sha256", SELECTION_SHA),
    )
    database.commit()
    database.close()
    return path


def test_repository_commit_gate_rejects_mismatch_and_dirty_tree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Result:
        def __init__(self, stdout: str) -> None:
            self.stdout = stdout

    outputs = iter((Result("c" * 40 + "\n"), Result("")))
    monkeypatch.setattr(
        "production.tools.build_next_behavior_selected_safe_corpus."
        "subprocess.run",
        lambda *args, **kwargs: next(outputs),
    )
    with pytest.raises(SelectedSafeCorpusError, match="does not match"):
        _require_repository_commit(tmp_path, CODE_COMMIT)

    outputs = iter((Result(CODE_COMMIT + "\n"), Result(" M tracked.py\n")))
    monkeypatch.setattr(
        "production.tools.build_next_behavior_selected_safe_corpus."
        "subprocess.run",
        lambda *args, **kwargs: next(outputs),
    )
    with pytest.raises(SelectedSafeCorpusError, match="tracked repository"):
        _require_repository_commit(tmp_path, CODE_COMMIT)


def _insert_commands(path: Path, commands: list[str]) -> None:
    database = open_selected_database(path)
    next_line = int(
        database.execute(
            "SELECT COALESCE(MAX(source_line), 0) FROM command_events "
            "WHERE source_member = 'member.json.gz'"
        ).fetchone()[0]
    )
    for offset, command in enumerate(commands, start=1):
        source_line = next_line + offset
        database.execute(
            """
            INSERT INTO command_events(
                source_member, source_line, raw_session_id,
                event_time, command
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                "member.json.gz",
                source_line,
                "private-session",
                f"2025-07-03T00:00:{source_line:02d}Z",
                command,
            ),
        )
    database.commit()
    database.close()


def _canonical_label(tactic: str, technique: str) -> str:
    manifest = json.loads(CLASSIFIER_MANIFEST.read_text())
    policy = manifest["classification_policy"]
    normalized = normalize_classifier_outputs(
        [
            {
                "ttp": technique,
                "tactic": tactic,
                "source": "rule",
                "high_confidence": True,
                "agreement_status": "rule_only",
            }
        ],
        private_evidence_prefix="private",
        policy_sha256=policy["rule_policy_sha256"],
        trust_policy_sha256=policy["trust_policy_sha256"],
        checkpoint_sha256=manifest["classifier"]["checkpoint_sha256"],
        tactic_lookup=lambda _technique: tactic,
        trusted_model_only_threshold=policy["trusted_model_only_threshold"],
    )
    return stable_json(normalized["labels"])


def _insert_label(
    path: Path,
    command: str,
    *,
    tactic: str = "discovery",
    technique: str = "T1082",
    receipt_id: str = "verified-cache",
) -> None:
    database = open_selected_database(path)
    database.execute(
        """
        INSERT INTO command_labels(
            command, labels_json, unrepresented_json, cache_receipt_id
        ) VALUES (?, ?, '{}', ?)
        """,
        (command, _canonical_label(tactic, technique), receipt_id),
    )
    database.commit()
    database.close()


def test_classification_passes_only_missing_exact_commands(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _asset_verification(monkeypatch)
    path = _database(tmp_path)
    _insert_commands(path, ["cached", "new command"])
    _insert_label(path, "cached")
    classifier = _Classifier()
    received_fragments: list[list[str]] = []

    def factory(fragments: list[str]):
        received_fragments.append(list(fragments))
        return classifier, lambda _technique: "discovery"

    receipt = classify_missing_selected_commands(
        classifier_manifest_path=CLASSIFIER_MANIFEST,
        repository_root=ROOT,
        model_root=tmp_path / "model",
        private_database_path=path,
        code_commit=CODE_COMMIT,
        command_batch_size=10,
        classifier_factory=factory,
    )

    assert receipt["verified_cached_command_count_before_run"] == 1
    assert receipt["missing_command_count_before_run"] == 1
    assert receipt["newly_classified_command_count"] == 1
    assert classifier.commands == ["new command"]
    assert received_fragments == [["new command"]]
    database = open_selected_database(path)
    assert database.execute("SELECT COUNT(*) FROM command_labels").fetchone()[0] == 2
    database.close()


def test_classification_resumes_after_a_committed_batch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _asset_verification(monkeypatch)
    path = _database(tmp_path)
    _insert_commands(path, ["first", "second"])
    interrupted = _Classifier(fail_command="second")

    with pytest.raises(RuntimeError, match="synthetic classifier interruption"):
        classify_missing_selected_commands(
            classifier_manifest_path=CLASSIFIER_MANIFEST,
            repository_root=ROOT,
            model_root=tmp_path / "model",
            private_database_path=path,
            code_commit=CODE_COMMIT,
            command_batch_size=1,
            classifier_factory=lambda _fragments: (
                interrupted,
                lambda _technique: "discovery",
            ),
        )

    database = open_selected_database(path)
    assert database.execute(
        "SELECT command FROM command_labels ORDER BY command"
    ).fetchall() == [("first",)]
    database.close()

    resumed = _Classifier()
    receipt = classify_missing_selected_commands(
        classifier_manifest_path=CLASSIFIER_MANIFEST,
        repository_root=ROOT,
        model_root=tmp_path / "model",
        private_database_path=path,
        code_commit=CODE_COMMIT,
        command_batch_size=1,
        classifier_factory=lambda _fragments: (
            resumed,
            lambda _technique: "discovery",
        ),
    )
    assert resumed.commands == ["second"]
    assert receipt["verified_cached_command_count_before_run"] == 1
    assert receipt["newly_classified_command_count"] == 1


def test_completed_development_classification_can_extend_after_final_ingest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _asset_verification(monkeypatch)
    path = _database(tmp_path)
    _insert_commands(path, ["development"])
    first = _Classifier()
    first_receipt = classify_missing_selected_commands(
        classifier_manifest_path=CLASSIFIER_MANIFEST,
        repository_root=ROOT,
        model_root=tmp_path / "model",
        private_database_path=path,
        code_commit=CODE_COMMIT,
        classifier_factory=lambda _fragments: (
            first,
            lambda _technique: "discovery",
        ),
    )
    _insert_commands(path, ["final-only"])
    second = _Classifier()
    second_receipt = classify_missing_selected_commands(
        classifier_manifest_path=CLASSIFIER_MANIFEST,
        repository_root=ROOT,
        model_root=tmp_path / "model",
        private_database_path=path,
        code_commit=CODE_COMMIT,
        classifier_factory=lambda _fragments: (
            second,
            lambda _technique: "discovery",
        ),
    )

    assert first_receipt["cache_receipt_id"] != second_receipt[
        "cache_receipt_id"
    ]
    assert second.commands == ["final-only"]
    assert second_receipt["verified_cached_command_count_before_run"] == 1
    assert second_receipt["unique_command_count"] == 2


def _historical_id(raw_session_id: str) -> str:
    digest = hashlib.sha256(
        f"{HISTORICAL_DATASET_SOURCE}\0{raw_session_id}".encode()
    ).hexdigest()
    return f"external-{digest[:24]}"


def _safe_store(
    tmp_path: Path,
    *,
    role: str = "train",
    historical_split: str = "not_present",
) -> tuple[Path, Path]:
    path = _database(tmp_path)
    database = open_selected_database(path)
    cohort = "final" if role == "test" else "development"
    orders = range(7, 14) if role == "test" else (
        range(1, 5) if role == "train" else [5 if role == "selection" else 6]
    )
    filenames = []
    for member_index, order in enumerate(orders):
        filename = f"2025-07-{order:02d}.json.gz"
        filenames.append(filename)
        stats = {
            "raw_event_records": 4,
            "raw_command_input_events": 2,
            "nonempty_command_events": 2,
        }
        database.execute(
            """
            INSERT INTO source_members(
                filename, source_sha256, source_size_bytes, archive_crc32,
                chronological_order, source_cohort, experiment_role,
                collection_start, collection_end, stats_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                filename,
                hashlib.sha256(filename.encode()).hexdigest(),
                100 + order,
                f"{order:08x}",
                order,
                cohort,
                role,
                f"2025-07-{order:02d}T00:00:00Z",
                f"2025-07-{order:02d}T23:59:59Z",
                stable_json(stats),
            ),
        )
    commands = [
        ("uname -a", "discovery", "T1082"),
        ("sh payload", "execution", "T1059"),
    ]
    raw_session_ids = []
    for member_index, source_member in enumerate(filenames, start=1):
        raw_session_id = f"raw-private-session-{member_index}"
        raw_session_ids.append(raw_session_id)
        database.execute(
            """
            INSERT INTO sessions(
                raw_session_id, source_member, source_cohort, experiment_role,
                first_seen, last_seen, protocol, configuration,
                connected, closed, cross_member, cross_role
            ) VALUES (?, ?, ?, ?, ?, ?, 'ssh', 'fixture', 1, 1, 0, 0)
            """,
            (
                raw_session_id,
                source_member,
                cohort,
                role,
                "2025-07-03T00:00:00Z",
                "2025-07-03T00:00:03Z",
            ),
        )
        database.execute(
            """
            INSERT INTO context_events(
                source_member, source_line, raw_session_id,
                event_time, event_type
            ) VALUES (?, 1, ?, ?, 'cowrie.login.success')
            """,
            (
                source_member,
                raw_session_id,
                "2025-07-03T00:00:00Z",
            ),
        )
        for index, (command, tactic, technique) in enumerate(
            commands, start=1
        ):
            database.execute(
                """
                INSERT INTO command_events(
                    source_member, source_line, raw_session_id,
                    event_time, command
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    source_member,
                    10 + index,
                    raw_session_id,
                    f"2025-07-03T00:00:0{index}Z",
                    command,
                ),
            )
            database.execute(
                """
                INSERT OR IGNORE INTO command_labels(
                    command, labels_json, unrepresented_json,
                    cache_receipt_id
                ) VALUES (?, ?, '{}', 'verified-cache')
                """,
                (command, _canonical_label(tactic, technique)),
            )
    database.commit()
    database.close()

    historical_path = tmp_path / "historical.jsonl"
    if historical_split != "not_present":
        historical_rows = [
            {
                "session_id": _historical_id(raw_session_id),
                "split": historical_split,
            }
            for raw_session_id in raw_session_ids
        ]
    else:
        historical_rows = [
            {"session_id": "external-unrelated", "split": "train"}
        ]
    historical_path.write_text(
        "".join(stable_json(row) + "\n" for row in historical_rows)
    )
    return path, historical_path


def _safe_outputs(tmp_path: Path) -> dict:
    return {
        "safe_sessions_path": tmp_path / "safe_sessions.jsonl",
        "examples_path": tmp_path / "examples.jsonl",
        "source_receipts_path": tmp_path / "source_receipts.json",
        "corpus_receipt_path": tmp_path / "corpus_receipt.json",
        "build_receipt_path": tmp_path / "build_receipt.json",
        "historical_split_evidence_path": (
            tmp_path / "historical_split_evidence.json"
        ),
    }


def _preparation_receipt(path: Path) -> dict:
    manifest = json.loads(CLASSIFIER_MANIFEST.read_text())
    database = open_selected_database(path)
    members = [
        {
            "filename": str(row[0]),
            "source_sha256": str(row[1]),
            "source_size_bytes": int(row[2]),
            "archive_crc32": str(row[3]),
            "chronological_order": int(row[4]),
            "source_cohort": str(row[5]),
            "experiment_role": str(row[6]),
        }
        for row in database.execute(
            """
            SELECT filename, source_sha256, source_size_bytes, archive_crc32,
                   chronological_order, source_cohort, experiment_role
            FROM source_members WHERE experiment_role = 'test'
            ORDER BY chronological_order
            """
        )
    ]
    receipt = {
        "schema_version": FINAL_PREPARATION_SCHEMA_VERSION,
        "status": "frozen_for_blinded_preparation",
        "purpose": "prepare_final_corpus",
        "evaluation_opened": False,
        "code_commit": CODE_COMMIT,
        "source_selection_id": "fixture-selection",
        "source_selection_sha256": SELECTION_SHA,
        "final_source_member_count": 7,
        "final_source_member_receipts_sha256": (
            final_member_receipts_sha256(members)
        ),
        "classifier_manifest_sha256": hashlib.sha256(
            CLASSIFIER_MANIFEST.read_bytes()
        ).hexdigest(),
        "classifier_adapter_sha256": manifest["classifier"][
            "adapter_sha256"
        ],
        "classification_pipeline_sha256": manifest["classifier"][
            "pipeline_sha256"
        ],
        "preprocessing_sha256": hashlib.sha256(
            PREPROCESSING_MANIFEST.read_bytes()
        ).hexdigest(),
        "environment_lock_sha256": manifest["dependency_lock"]["sha256"],
        "label_policy_sha256": manifest["classification_policy"][
            "rule_policy_sha256"
        ],
        "trust_policy_sha256": manifest["classification_policy"][
            "trust_policy_sha256"
        ],
        "mitre_cache_sha256": manifest["classification_policy"][
            "mitre_cache_sha256"
        ],
        "classification_checkpoint_sha256": manifest["classifier"][
            "checkpoint_sha256"
        ],
        "pseudonymization_key_id": "fixture-key",
    }
    receipt["receipt_id"] = stable_id(
        "nextbehaviorfinalpreparation", receipt
    )
    database.execute(
        "INSERT INTO metadata(key, value) VALUES "
        "('final_corpus_prepared_at', '2025-08-17T00:00:00Z')"
    )
    database.execute(
        "INSERT INTO metadata(key, value) VALUES (?, ?)",
        ("final_corpus_preparation_receipt_id", receipt["receipt_id"]),
    )
    database.execute(
        "INSERT INTO metadata(key, value) VALUES (?, ?)",
        ("final_corpus_preparation_receipt_json", stable_json(receipt)),
    )
    database.commit()
    database.close()
    return receipt


def test_development_safe_export_is_causal_private_and_discloses_reuse(
    tmp_path: Path,
) -> None:
    path, historical = _safe_store(
        tmp_path, historical_split="train"
    )
    outputs = _safe_outputs(tmp_path)
    receipt = build_selected_safe_corpus(
        purpose="fit_model",
        private_database_path=path,
        classifier_manifest_path=CLASSIFIER_MANIFEST,
        preprocessing_manifest_path=PREPROCESSING_MANIFEST,
        historical_payload_path=historical,
        pseudonymization_key=b"k" * 32,
        pseudonymization_key_id="fixture-key",
        code_commit=CODE_COMMIT,
        **outputs,
    )

    assert receipt["safe_sessions"]["line_count"] == 4
    assert receipt["examples"]["line_count"] == 8
    assert receipt["historical_membership"]["overlap_by_split"] == {"train": 4}
    evidence = json.loads(
        outputs["historical_split_evidence_path"].read_text()
    )
    assert evidence["schema_version"] == (
        "next_behavior_historical_split_evidence.v1"
    )
    assert evidence["selected_safe_corpus_receipt_id"] == receipt[
        "corpus_receipt_id"
    ]
    assert [record["session_id"] for record in evidence["records"]] == sorted(
        record["session_id"] for record in evidence["records"]
    )
    assert all(record["historical_split"] == "train" for record in evidence["records"])
    assert receipt["historical_split_evidence"]["record_count"] == 4
    sessions_text = outputs["safe_sessions_path"].read_text()
    examples_text = outputs["examples_path"].read_text()
    assert "raw-private-session" not in sessions_text + examples_text
    assert "uname -a" not in sessions_text + examples_text
    assert "sh payload" not in sessions_text + examples_text
    safe = json.loads(sessions_text.splitlines()[0])
    assert [group["event_order"] for group in safe["observation_groups"]] == [1, 2]
    assert safe["observation_groups"][0]["session_context"][
        "login_outcome"
    ] == "success"
    assert all(path.is_file() for path in outputs.values())


def test_development_rejects_historical_test_overlap(tmp_path: Path) -> None:
    path, historical = _safe_store(
        tmp_path, historical_split="test"
    )
    with pytest.raises(
        SelectedSafeCorpusError, match="historical test"
    ):
        build_selected_safe_corpus(
            purpose="fit_model",
            private_database_path=path,
            classifier_manifest_path=CLASSIFIER_MANIFEST,
            preprocessing_manifest_path=PREPROCESSING_MANIFEST,
            historical_payload_path=historical,
            pseudonymization_key=b"k" * 32,
            pseudonymization_key_id="fixture-key",
            code_commit=CODE_COMMIT,
            **_safe_outputs(tmp_path),
        )


def test_safe_build_is_deterministic_and_excludes_incomplete_sessions(
    tmp_path: Path,
) -> None:
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first_path, first_historical = _safe_store(first_root)
    second_path, second_historical = _safe_store(second_root)
    second_database = open_selected_database(second_path)
    second_database.execute(
        "UPDATE sessions SET connected = 0 "
        "WHERE raw_session_id LIKE 'raw-private-session-%'"
    )
    second_database.commit()
    second_database.close()

    first_outputs = _safe_outputs(first_root)
    first_receipt = build_selected_safe_corpus(
        purpose="fit_model",
        private_database_path=first_path,
        classifier_manifest_path=CLASSIFIER_MANIFEST,
        preprocessing_manifest_path=PREPROCESSING_MANIFEST,
        historical_payload_path=first_historical,
        pseudonymization_key=b"k" * 32,
        pseudonymization_key_id="fixture-key",
        code_commit=CODE_COMMIT,
        **first_outputs,
    )
    second_outputs = _safe_outputs(second_root)
    with pytest.raises(
        SelectedSafeCorpusError, match="must contribute a safe session"
    ):
        build_selected_safe_corpus(
            purpose="fit_model",
            private_database_path=second_path,
            classifier_manifest_path=CLASSIFIER_MANIFEST,
            preprocessing_manifest_path=PREPROCESSING_MANIFEST,
            historical_payload_path=second_historical,
            pseudonymization_key=b"k" * 32,
            pseudonymization_key_id="fixture-key",
            code_commit=CODE_COMMIT,
            **second_outputs,
        )

    assert first_receipt["safe_sessions"]["line_count"] == 4
    assert not any(path.exists() for path in second_outputs.values())


def test_identical_safe_builds_are_byte_deterministic(tmp_path: Path) -> None:
    roots = [tmp_path / "one", tmp_path / "two"]
    output_sets = []
    for root in roots:
        path, historical = _safe_store(root)
        outputs = _safe_outputs(root)
        build_selected_safe_corpus(
            purpose="fit_model",
            private_database_path=path,
            classifier_manifest_path=CLASSIFIER_MANIFEST,
            preprocessing_manifest_path=PREPROCESSING_MANIFEST,
            historical_payload_path=historical,
            pseudonymization_key=b"k" * 32,
            pseudonymization_key_id="fixture-key",
            code_commit=CODE_COMMIT,
            **outputs,
        )
        output_sets.append(outputs)
    for name in output_sets[0]:
        assert output_sets[0][name].read_bytes() == output_sets[1][
            name
        ].read_bytes()


def test_role_artifact_verifier_reconstructs_and_binds_exact_payloads(
    tmp_path: Path,
) -> None:
    path, historical = _safe_store(tmp_path)
    outputs = _safe_outputs(tmp_path)
    build_selected_safe_corpus(
        purpose="fit_model",
        private_database_path=path,
        classifier_manifest_path=CLASSIFIER_MANIFEST,
        preprocessing_manifest_path=PREPROCESSING_MANIFEST,
        historical_payload_path=historical,
        pseudonymization_key=b"k" * 32,
        pseudonymization_key_id="fixture-key",
        code_commit=CODE_COMMIT,
        **outputs,
    )
    verified = verify_selected_role_artifacts(
        build_receipt_path=outputs["build_receipt_path"],
        safe_sessions_path=outputs["safe_sessions_path"],
        examples_path=outputs["examples_path"],
        source_receipts_path=outputs["source_receipts_path"],
        corpus_receipt_path=outputs["corpus_receipt_path"],
        historical_split_evidence_path=outputs[
            "historical_split_evidence_path"
        ],
        expected_purpose="fit_model",
    )
    assert verified["status"] == "selected_role_artifacts_verified"
    assert verified["role"] == "train"
    assert verified["membership"]["source_member_count"] == 4
    assert verified["membership"]["session_count"] == 4
    assert verified["membership"]["example_count"] == 8

    outputs["examples_path"].write_bytes(
        outputs["examples_path"].read_bytes() + b"\n"
    )
    with pytest.raises(SelectedSafeCorpusError, match="identity mismatch"):
        verify_selected_role_artifacts(
            build_receipt_path=outputs["build_receipt_path"],
            safe_sessions_path=outputs["safe_sessions_path"],
            examples_path=outputs["examples_path"],
            source_receipts_path=outputs["source_receipts_path"],
            corpus_receipt_path=outputs["corpus_receipt_path"],
            historical_split_evidence_path=outputs[
                "historical_split_evidence_path"
            ],
            expected_purpose="fit_model",
        )


def test_historical_split_evidence_is_required_and_hash_bound(
    tmp_path: Path,
) -> None:
    path, historical = _safe_store(tmp_path)
    outputs = _safe_outputs(tmp_path)
    build_selected_safe_corpus(
        purpose="fit_model",
        private_database_path=path,
        classifier_manifest_path=CLASSIFIER_MANIFEST,
        preprocessing_manifest_path=PREPROCESSING_MANIFEST,
        historical_payload_path=historical,
        pseudonymization_key=b"k" * 32,
        pseudonymization_key_id="fixture-key",
        code_commit=CODE_COMMIT,
        **outputs,
    )
    common = {
        "build_receipt_path": outputs["build_receipt_path"],
        "safe_sessions_path": outputs["safe_sessions_path"],
        "examples_path": outputs["examples_path"],
        "source_receipts_path": outputs["source_receipts_path"],
        "corpus_receipt_path": outputs["corpus_receipt_path"],
        "expected_purpose": "fit_model",
    }
    with pytest.raises(SelectedSafeCorpusError, match="evidence is missing"):
        verify_selected_role_artifacts(**common)

    evidence_path = outputs["historical_split_evidence_path"]
    evidence = json.loads(evidence_path.read_text())
    evidence["records"][0]["historical_split"] = "calibration"
    evidence_path.write_text(stable_json(evidence) + "\n")
    with pytest.raises(SelectedSafeCorpusError, match="evidence identity mismatch"):
        verify_selected_role_artifacts(
            **common,
            historical_split_evidence_path=evidence_path,
        )


def test_legacy_v2_safe_build_remains_verifiable_without_sidecar(
    tmp_path: Path,
) -> None:
    path, historical = _safe_store(tmp_path)
    outputs = _safe_outputs(tmp_path)
    evidence_path = outputs.pop("historical_split_evidence_path")
    receipt = build_selected_safe_corpus(
        purpose="fit_model",
        private_database_path=path,
        classifier_manifest_path=CLASSIFIER_MANIFEST,
        preprocessing_manifest_path=PREPROCESSING_MANIFEST,
        historical_payload_path=historical,
        pseudonymization_key=b"k" * 32,
        pseudonymization_key_id="fixture-key",
        code_commit=CODE_COMMIT,
        **outputs,
    )
    assert receipt["schema_version"] == "next_behavior_selected_safe_build.v2"
    assert not evidence_path.exists()
    assert verify_selected_role_artifacts(
        build_receipt_path=outputs["build_receipt_path"],
        safe_sessions_path=outputs["safe_sessions_path"],
        examples_path=outputs["examples_path"],
        source_receipts_path=outputs["source_receipts_path"],
        corpus_receipt_path=outputs["corpus_receipt_path"],
        expected_purpose="fit_model",
    )["status"] == "selected_role_artifacts_verified"


def test_training_role_verifier_rejects_final_bundle(tmp_path: Path) -> None:
    path, historical = _safe_store(tmp_path, role="test")
    preparation = _preparation_receipt(path)
    outputs = _safe_outputs(tmp_path)
    receipt = build_selected_safe_corpus(
        purpose="final_evaluation",
        private_database_path=path,
        classifier_manifest_path=CLASSIFIER_MANIFEST,
        preprocessing_manifest_path=PREPROCESSING_MANIFEST,
        historical_payload_path=historical,
        pseudonymization_key=b"k" * 32,
        pseudonymization_key_id="fixture-key",
        code_commit=CODE_COMMIT,
        final_preparation_receipt=preparation,
        **outputs,
    )
    assert receipt["final_preparation_gate"]["evaluation_opened"] is False
    with pytest.raises(
        SelectedSafeCorpusError, match="cannot accept final-test"
    ):
        verify_selected_role_artifacts(
            build_receipt_path=outputs["build_receipt_path"],
            safe_sessions_path=outputs["safe_sessions_path"],
            examples_path=outputs["examples_path"],
            source_receipts_path=outputs["source_receipts_path"],
            corpus_receipt_path=outputs["corpus_receipt_path"],
            expected_purpose="final_evaluation",
        )


def test_final_gate_is_checked_before_private_store_access(tmp_path: Path) -> None:
    with pytest.raises(
        SelectedSafeCorpusError, match="preparation receipt fields"
    ):
        build_selected_safe_corpus(
            purpose="final_evaluation",
            private_database_path=tmp_path / "does-not-exist.sqlite",
            classifier_manifest_path=CLASSIFIER_MANIFEST,
            preprocessing_manifest_path=PREPROCESSING_MANIFEST,
            historical_payload_path=tmp_path / "does-not-exist.jsonl",
            pseudonymization_key=b"k" * 32,
            pseudonymization_key_id="fixture-key",
            code_commit=CODE_COMMIT,
            final_preparation_receipt={"forged": True},
            **_safe_outputs(tmp_path),
        )
    assert not (tmp_path / "does-not-exist.sqlite").exists()


@pytest.mark.parametrize(
    "receipt",
    [
        {
            "status": "frozen_for_blinded_preparation",
            "evaluation_opened": False,
            "code_commit": CODE_COMMIT,
        },
    ],
)
def test_final_gate_rejects_incomplete_or_inconsistent_receipts(
    tmp_path: Path, receipt: dict
) -> None:
    with pytest.raises(
        SelectedSafeCorpusError, match="final corpus preparation"
    ):
        build_selected_safe_corpus(
            purpose="final_evaluation",
            private_database_path=tmp_path / "does-not-exist.sqlite",
            classifier_manifest_path=CLASSIFIER_MANIFEST,
            preprocessing_manifest_path=PREPROCESSING_MANIFEST,
            historical_payload_path=tmp_path / "does-not-exist.jsonl",
            pseudonymization_key=b"k" * 32,
            pseudonymization_key_id="fixture-key",
            code_commit=CODE_COMMIT,
            final_preparation_receipt=receipt,
            **_safe_outputs(tmp_path),
        )
    assert not (tmp_path / "does-not-exist.sqlite").exists()


@pytest.mark.parametrize(
    ("field", "replacement", "error"),
    [
        ("evaluation_opened", True, "cannot follow evaluation access"),
        (
            "pseudonymization_key_id",
            "copied-other-key",
            "pseudonymization_key_id is inconsistent",
        ),
        (
            "final_source_member_receipts_sha256",
            "f" * 64,
            "source receipts differ",
        ),
    ],
)
def test_final_preparation_rejects_mutated_valid_shaped_receipt(
    tmp_path: Path,
    field: str,
    replacement: object,
    error: str,
) -> None:
    path, historical = _safe_store(tmp_path, role="test")
    receipt = _preparation_receipt(path)
    receipt[field] = replacement
    identity = dict(receipt)
    identity.pop("receipt_id")
    receipt["receipt_id"] = stable_id(
        "nextbehaviorfinalpreparation", identity
    )
    database = open_selected_database(path)
    database.execute(
        "UPDATE metadata SET value = ? "
        "WHERE key = 'final_corpus_preparation_receipt_id'",
        (receipt["receipt_id"],),
    )
    database.execute(
        "UPDATE metadata SET value = ? "
        "WHERE key = 'final_corpus_preparation_receipt_json'",
        (stable_json(receipt),),
    )
    database.commit()
    database.close()
    with pytest.raises(SelectedSafeCorpusError, match=error):
        build_selected_safe_corpus(
            purpose="final_evaluation",
            private_database_path=path,
            classifier_manifest_path=CLASSIFIER_MANIFEST,
            preprocessing_manifest_path=PREPROCESSING_MANIFEST,
            historical_payload_path=historical,
            pseudonymization_key=b"k" * 32,
            pseudonymization_key_id="fixture-key",
            code_commit=CODE_COMMIT,
            final_preparation_receipt=receipt,
            **_safe_outputs(tmp_path),
        )


def test_legacy_final_open_marker_does_not_authorize_safe_export(
    tmp_path: Path,
) -> None:
    path, historical = _safe_store(tmp_path, role="test")
    receipt = _preparation_receipt(path)
    database = open_selected_database(path)
    database.execute(
        "DELETE FROM metadata WHERE key IN "
        "('final_corpus_prepared_at', "
        "'final_corpus_preparation_receipt_id', "
        "'final_corpus_preparation_receipt_json')"
    )
    database.execute(
        "INSERT INTO metadata(key, value) VALUES "
        "('final_test_opened_at', 'legacy')"
    )
    database.commit()
    database.close()
    with pytest.raises(
        SelectedSafeCorpusError, match="preparation marker"
    ):
        build_selected_safe_corpus(
            purpose="final_evaluation",
            private_database_path=path,
            classifier_manifest_path=CLASSIFIER_MANIFEST,
            preprocessing_manifest_path=PREPROCESSING_MANIFEST,
            historical_payload_path=historical,
            pseudonymization_key=b"k" * 32,
            pseudonymization_key_id="fixture-key",
            code_commit=CODE_COMMIT,
            final_preparation_receipt=receipt,
            **_safe_outputs(tmp_path),
        )


def test_final_classification_requires_completed_preparation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path, _historical = _safe_store(tmp_path, role="test")
    _asset_verification(monkeypatch)
    with pytest.raises(
        SelectedSafeCorpusError, match="completed blinded preparation"
    ):
        classify_missing_selected_commands(
            classifier_manifest_path=CLASSIFIER_MANIFEST,
            repository_root=ROOT,
            model_root=tmp_path / "model",
            private_database_path=path,
            code_commit=CODE_COMMIT,
        )

    _preparation_receipt(path)
    result = classify_missing_selected_commands(
        classifier_manifest_path=CLASSIFIER_MANIFEST,
        repository_root=ROOT,
        model_root=tmp_path / "model",
        private_database_path=path,
        code_commit=CODE_COMMIT,
    )
    assert result["status"] == "classification_complete"
    assert result["missing_command_count_before_run"] == 0


def test_final_export_rejects_any_historical_overlap(tmp_path: Path) -> None:
    path, historical = _safe_store(
        tmp_path, role="test", historical_split="calibration"
    )
    preparation = _preparation_receipt(path)
    with pytest.raises(SelectedSafeCorpusError, match="final role overlaps"):
        build_selected_safe_corpus(
            purpose="final_evaluation",
            private_database_path=path,
            classifier_manifest_path=CLASSIFIER_MANIFEST,
            preprocessing_manifest_path=PREPROCESSING_MANIFEST,
            historical_payload_path=historical,
            pseudonymization_key=b"k" * 32,
            pseudonymization_key_id="fixture-key",
            code_commit=CODE_COMMIT,
            final_preparation_receipt=preparation,
            **_safe_outputs(tmp_path),
        )


def test_no_overwrite_and_secret_field_scan(tmp_path: Path) -> None:
    path, historical = _safe_store(tmp_path)
    outputs = _safe_outputs(tmp_path)
    outputs["safe_sessions_path"].write_text("existing\n")
    with pytest.raises(SelectedSafeCorpusError, match="refusing to overwrite"):
        build_selected_safe_corpus(
            purpose="fit_model",
            private_database_path=path,
            classifier_manifest_path=CLASSIFIER_MANIFEST,
            preprocessing_manifest_path=PREPROCESSING_MANIFEST,
            historical_payload_path=historical,
            pseudonymization_key=b"k" * 32,
            pseudonymization_key_id="fixture-key",
            code_commit=CODE_COMMIT,
            **outputs,
        )
    with pytest.raises(SelectedSafeCorpusError, match="forbidden field"):
        _scan_public_value({"nested": {"raw_command": "secret"}})


def test_verify_role_cli_reports_only_aggregate_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    captured: dict[str, object] = {}

    def fake_verify(**kwargs: object) -> dict[str, object]:
        captured.update(kwargs)
        return {
            "status": "selected_role_artifacts_verified",
            "purpose": "final_evaluation",
            "role": "test",
            "build_receipt_id": "nextbehaviorselectedsafebuild_fixture",
            "membership": {
                "source_member_count": 7,
                "session_count": 11,
                "example_count": 19,
            },
        }

    monkeypatch.setattr(
        safe_corpus, "verify_selected_role_artifacts", fake_verify
    )
    paths = {
        option: tmp_path / filename
        for option, filename in {
            "safe-sessions": "safe_sessions.jsonl",
            "examples": "examples.jsonl",
            "source-receipts": "source_receipts.json",
            "corpus-receipt": "corpus_receipt.json",
            "build-receipt": "build_receipt.json",
            "historical-split-evidence": "historical.json",
        }.items()
    }
    argv = ["verify-role", "--purpose", "final_evaluation"]
    for option, path in paths.items():
        argv.extend((f"--{option}", str(path)))
    assert safe_corpus.main(argv) == 0
    assert captured["allow_final"] is True
    assert captured["expected_purpose"] == "final_evaluation"
    assert captured["historical_split_evidence_path"] == paths[
        "historical-split-evidence"
    ]
    assert json.loads(capsys.readouterr().out) == {
        "build_receipt_id": "nextbehaviorselectedsafebuild_fixture",
        "membership": {
            "example_count": 19,
            "session_count": 11,
            "source_member_count": 7,
        },
        "purpose": "final_evaluation",
        "role": "test",
        "status": "selected_role_artifacts_verified",
    }
