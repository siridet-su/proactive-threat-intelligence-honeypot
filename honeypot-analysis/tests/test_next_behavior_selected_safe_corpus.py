from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from production.prediction.next_behavior_label_policy import (
    normalize_classifier_outputs,
)
from production.tools.build_next_behavior_selected_corpus import (
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
from production.utils.serialization import stable_json


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
    if role == "test":
        database.execute(
            "INSERT INTO metadata(key, value) VALUES "
            "('final_test_opened_at', '2025-08-17T00:00:00Z')"
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
    }


def _pretest_receipt() -> dict:
    return {
        "status": "frozen_pre_test",
        "test_opened": False,
        "code_commit": CODE_COMMIT,
        "training_bundle_sha256": "c" * 64,
    }


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
            expected_purpose="fit_model",
        )


def test_training_role_verifier_rejects_final_bundle(tmp_path: Path) -> None:
    path, historical = _safe_store(tmp_path, role="test")
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
        final_access_gate=lambda _purpose: _pretest_receipt(),
        **outputs,
    )
    assert receipt["final_pretest_gate"]["training_bundle_sha256"] == "c" * 64
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
        SelectedSafeCorpusError, match="pre-test receipt fields"
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
            final_access_gate=lambda _purpose: True,
            **_safe_outputs(tmp_path),
        )
    assert not (tmp_path / "does-not-exist.sqlite").exists()


@pytest.mark.parametrize(
    "receipt",
    [
        {
            "status": "frozen_pre_test",
            "test_opened": False,
            "code_commit": CODE_COMMIT,
        },
        {
            **_pretest_receipt(),
            "test_opened": True,
        },
        {
            **_pretest_receipt(),
            "code_commit": "d" * 40,
        },
        {
            **_pretest_receipt(),
            "unexpected": "copied-but-mutated",
        },
    ],
)
def test_final_gate_rejects_incomplete_or_inconsistent_receipts(
    tmp_path: Path, receipt: dict
) -> None:
    with pytest.raises(SelectedSafeCorpusError, match="final pre-test"):
        build_selected_safe_corpus(
            purpose="final_evaluation",
            private_database_path=tmp_path / "does-not-exist.sqlite",
            classifier_manifest_path=CLASSIFIER_MANIFEST,
            preprocessing_manifest_path=PREPROCESSING_MANIFEST,
            historical_payload_path=tmp_path / "does-not-exist.jsonl",
            pseudonymization_key=b"k" * 32,
            pseudonymization_key_id="fixture-key",
            code_commit=CODE_COMMIT,
            final_access_gate=lambda _purpose: receipt,
            **_safe_outputs(tmp_path),
        )
    assert not (tmp_path / "does-not-exist.sqlite").exists()


def test_final_export_rejects_any_historical_overlap(tmp_path: Path) -> None:
    path, historical = _safe_store(
        tmp_path, role="test", historical_split="calibration"
    )
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
            final_access_gate=lambda _purpose: _pretest_receipt(),
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
