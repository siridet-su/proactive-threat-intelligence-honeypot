from __future__ import annotations

import hashlib
import inspect
import json
from pathlib import Path

import pytest

from production.prediction.next_behavior_contract import SESSION_SCHEMA_VERSION
from production.prediction.next_behavior_partitions import (
    V2_DEVELOPMENT_CUTOFF,
    V2_FINAL_WINDOW_START,
    build_partition_manifest_v2,
)
from production.prediction.next_behavior_preprocessing import (
    build_next_behavior_examples,
)
from production.tools.reproduce_next_behavior_experiment import (
    DECLARED_SEEDS,
    NextBehaviorTrainingError,
    _calibration_rows,
    _prediction_from_raw,
    assess_selection_candidate,
    build_parser,
    build_training_vocabulary,
    load_pre_final_examples,
    publish_selection_blocked_bundle,
    require_all_declared_seeds,
    require_consistent_role_provenance,
    require_selection_support,
    run_training_experiment,
    select_completed_seed,
)


HASH_A = "a" * 64
HASH_B = "b" * 64
ROOT = Path(__file__).resolve().parents[1]
PREPROCESSING_PATH = ROOT / "configs" / "next_behavior_preprocessing.v1.json"


def _opaque(kind: str, value: str) -> str:
    return f"nb{kind}_{hashlib.sha256(value.encode()).hexdigest()}"


def _members() -> list[dict]:
    dates = (
        "2025-07-03",
        "2025-07-10",
        "2025-07-17",
        "2025-07-24",
        "2025-07-31",
        "2025-08-07",
        "2025-08-09",
        "2025-08-10",
        "2025-08-11",
        "2025-08-12",
        "2025-08-13",
        "2025-08-15",
        "2025-08-16",
    )
    return [
        {
            "member_id": _opaque("member", date),
            "sha256": hashlib.sha256(date.encode()).hexdigest(),
            "chronological_order": index,
            "collection_start": f"{date}T00:00:00Z",
            "collection_end": f"{date}T23:59:59Z",
        }
        for index, date in enumerate(dates, 1)
    ]


def _session(member: dict, index: int, *, technique: str = "T1082") -> dict:
    session_id = _opaque("session", f"session-{index}")

    def group(order: int, tactic: str) -> dict:
        evidence = _opaque("evidence", f"{index}-{order}")
        return {
            "group_id": _opaque("group", f"{index}-{order}"),
            "event_order": order,
            "relative_time_ms": (order - 1) * 1000,
            "tactics": [tactic],
            "techniques": [technique],
            "evidence_refs": [evidence],
            "label_provenance": [
                {
                    "tactic": tactic,
                    "technique": technique,
                    "source": "reviewed_rule",
                    "trust_tier": "trusted_observation",
                    "policy_sha256": HASH_A,
                    "trust_policy_sha256": HASH_B,
                    "checkpoint_sha256": "",
                    "confidence": 1.0,
                    "confidence_bucket": "high",
                    "agreement_status": "rule_only",
                    "evidence_ref": evidence,
                }
            ],
            "session_context": {
                "login_outcome": "success",
                "command_count_bucket": "1" if order == 1 else "2-5",
                "session_age_bucket": "under_10s",
                "confirmed_transfer_observed": False,
            },
        }

    return {
        "schema_version": SESSION_SCHEMA_VERSION,
        "session_id": session_id,
        "source_member_id": member["member_id"],
        "source_member_sha256": member["sha256"],
        "protocol": "ssh",
        "status": "closed",
        "observation_groups": [
            group(1, "discovery"),
            group(2, "execution"),
        ],
    }


def _partition_fixture(tmp_path: Path) -> tuple[dict[str, Path], Path, dict]:
    members = _members()
    records = [_session(member, index) for index, member in enumerate(members)]
    historical = {
        record["session_id"]: (
            "train"
            if index < 5
            else "calibration"
            if index == 5
            else "not_present"
        )
        for index, record in enumerate(records)
    }
    manifest = build_partition_manifest_v2(
        records,
        members,
        preprocessing_sha256=hashlib.sha256(
            PREPROCESSING_PATH.read_bytes()
        ).hexdigest(),
        label_policy_sha256=HASH_A,
        trust_policy_sha256=HASH_B,
        code_commit="fixture-commit",
        historical_split_by_session=historical,
        development_cutoff=V2_DEVELOPMENT_CUTOFF,
        final_window_start=V2_FINAL_WINDOW_START,
    )
    role_members = {
        role: set(details["source_member_ids"])
        for role, details in manifest["roles"].items()
    }
    paths = {}
    for role in ("train", "selection", "calibration", "test"):
        path = tmp_path / f"{role}.json"
        role_records = [
            record
            for record in records
            if record["source_member_id"] in role_members[role]
        ]
        path.write_text(
            json.dumps(
                [
                    example
                    for record in role_records
                    for example in build_next_behavior_examples(record)
                ],
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        paths[role] = path
    manifest_path = tmp_path / "partition_manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, sort_keys=True),
        encoding="utf-8",
    )
    return paths, manifest_path, manifest


def _payload_hashes(paths: dict[str, Path]) -> dict[str, str]:
    return {
        role: hashlib.sha256(paths[role].read_bytes()).hexdigest()
        for role in ("train", "selection", "calibration")
    }


def _class_metrics(
    *,
    execution_recall: float,
    macro_f1: float,
    balanced_accuracy: float,
    terminal_f1: float,
) -> dict:
    tactics = sorted(
        {
            "collection",
            "command_and_control",
            "credential_access",
            "defense_evasion",
            "discovery",
            "execution",
            "exfiltration",
            "impact",
            "initial_access",
            "lateral_movement",
            "persistence",
            "privilege_escalation",
            "reconnaissance",
            "resource_development",
        }
    )
    return {
        "multilabel_tactics": {
            "reportable_classes": ["execution"],
            "per_class": {
                tactic: {
                    "recall": execution_recall if tactic == "execution" else 0.0
                }
                for tactic in tactics
            },
        },
        "session_cluster_bootstrap": {
            "metrics": {
                "macro_f1": {"estimate": macro_f1},
                "balanced_accuracy": {"estimate": balanced_accuracy},
                "terminal_f1": {"estimate": terminal_f1},
            }
        },
    }


def _selection_policy() -> dict:
    return {
        "high_consequence_tactics": ["execution"],
        "maximum_high_consequence_recall_regression": 0.1,
    }


def test_cli_and_python_api_have_no_final_test_path() -> None:
    parser = build_parser()
    option_strings = {
        option
        for action in parser._actions
        for option in action.option_strings
    }
    parameters = set(inspect.signature(run_training_experiment).parameters)

    assert "--test" not in option_strings
    assert "--final-test" not in option_strings
    assert "test_path" not in parameters
    assert "final_test_path" not in parameters
    assert "--experiment-policy" in option_strings
    assert "--environment-lock" in option_strings
    assert "--train-historical-split-evidence" in option_strings
    assert "--selection-historical-split-evidence" in option_strings
    assert "--calibration-historical-split-evidence" in option_strings
    assert "train_historical_split_evidence_path" in parameters
    assert "selection_historical_split_evidence_path" in parameters
    assert "calibration_historical_split_evidence_path" in parameters


def test_role_export_and_training_commits_are_independently_bound() -> None:
    export_commit = "1" * 40
    common = {
        "code_commit": export_commit,
        "source_selection_sha256": "2" * 64,
        "classifier_manifest_sha256": "3" * 64,
        "preprocessing_sha256": "4" * 64,
        "label_policy_sha256": "5" * 64,
        "trust_policy_sha256": "6" * 64,
        "classification_checkpoint_sha256": "7" * 64,
    }
    verifications = {
        role: dict(common) for role in ("train", "selection", "calibration")
    }

    assert require_consistent_role_provenance(
        verifications,
        preprocessing_sha256="4" * 64,
    ) == export_commit

    verifications["selection"]["code_commit"] = "8" * 40
    with pytest.raises(
        NextBehaviorTrainingError,
        match="selection role provenance differs",
    ):
        require_consistent_role_provenance(
            verifications,
            preprocessing_sha256="4" * 64,
        )


def test_role_scoped_loading_never_opens_test(tmp_path: Path) -> None:
    paths, manifest_path, manifest = _partition_fixture(tmp_path)
    test_before = paths["test"].stat().st_atime_ns

    examples, loaded_manifest = load_pre_final_examples(
        train_path=paths["train"],
        selection_path=paths["selection"],
        calibration_path=paths["calibration"],
        partition_manifest_path=manifest_path,
        expected_payload_sha256=_payload_hashes(paths),
    )

    assert loaded_manifest == manifest
    assert set(examples) == {"train", "selection", "calibration"}
    assert {len(examples[role]) for role in examples} == {2, 8}
    assert paths["test"].stat().st_atime_ns == test_before


def test_role_scoped_jsonl_is_supported_without_a_combined_corpus(
    tmp_path: Path,
) -> None:
    paths, manifest_path, _manifest = _partition_fixture(tmp_path)
    train_records = json.loads(paths["train"].read_text(encoding="utf-8"))
    train_jsonl = tmp_path / "train.jsonl"
    train_jsonl.write_text(
        "".join(
            json.dumps(record, sort_keys=True) + "\n"
            for record in train_records
        ),
        encoding="utf-8",
    )

    examples, _ = load_pre_final_examples(
        train_path=train_jsonl,
        selection_path=paths["selection"],
        calibration_path=paths["calibration"],
        partition_manifest_path=manifest_path,
        expected_payload_sha256={
            **_payload_hashes(paths),
            "train": hashlib.sha256(train_jsonl.read_bytes()).hexdigest(),
        },
    )

    assert len(examples["train"]) == 8


def test_wrong_role_content_is_rejected_before_training(tmp_path: Path) -> None:
    paths, manifest_path, _manifest = _partition_fixture(tmp_path)

    with pytest.raises(
        NextBehaviorTrainingError,
        match="another role",
    ):
        load_pre_final_examples(
            train_path=paths["train"],
            selection_path=paths["test"],
            calibration_path=paths["calibration"],
            partition_manifest_path=manifest_path,
            expected_payload_sha256={
                **_payload_hashes(paths),
                "selection": hashlib.sha256(
                    paths["test"].read_bytes()
                ).hexdigest(),
            },
        )


def test_role_payload_mutation_after_verification_is_rejected(
    tmp_path: Path,
) -> None:
    paths, manifest_path, _manifest = _partition_fixture(tmp_path)
    expected = _payload_hashes(paths)
    selection = json.loads(paths["selection"].read_text(encoding="utf-8"))
    selection[0]["target"]["techniques"] = ["T1098"]
    paths["selection"].write_text(json.dumps(selection), encoding="utf-8")

    with pytest.raises(NextBehaviorTrainingError, match="changed"):
        load_pre_final_examples(
            train_path=paths["train"],
            selection_path=paths["selection"],
            calibration_path=paths["calibration"],
            partition_manifest_path=manifest_path,
            expected_payload_sha256=expected,
        )


def test_vocabulary_is_derived_from_training_inputs_only() -> None:
    member = _members()[0]
    train_examples = build_next_behavior_examples(
        _session(member, 1, technique="T1082")
    )
    vocabulary = build_training_vocabulary(
        train_examples,
        preprocessing_sha256=HASH_A,
        training_membership_sha256=HASH_B,
    )

    assert "T1082" in vocabulary["techniques"]


def test_high_consequence_recall_regression_blocks_candidate() -> None:
    baseline = _class_metrics(
        execution_recall=0.8,
        macro_f1=0.5,
        balanced_accuracy=0.5,
        terminal_f1=0.5,
    )
    candidate = _class_metrics(
        execution_recall=0.69,
        macro_f1=0.9,
        balanced_accuracy=0.9,
        terminal_f1=0.9,
    )

    result = assess_selection_candidate(
        seed=DECLARED_SEEDS[0],
        metrics=candidate,
        baseline_metrics=baseline,
        p95_latency_ms=1.0,
        selection_policy=_selection_policy(),
    )

    assert result["eligible"] is False
    assert result["blockers"] == [
        "high_consequence_recall_regression:execution"
    ]


def test_selection_requires_independent_high_consequence_support() -> None:
    unsupported = _class_metrics(
        execution_recall=0.0,
        macro_f1=0.0,
        balanced_accuracy=0.5,
        terminal_f1=0.5,
    )
    unsupported["multilabel_tactics"]["reportable_classes"] = []

    with pytest.raises(NextBehaviorTrainingError, match="support gate"):
        require_selection_support(unsupported, _selection_policy())

    assert require_selection_support(
        _class_metrics(
            execution_recall=0.5,
            macro_f1=0.5,
            balanced_accuracy=0.5,
            terminal_f1=0.5,
        ),
        _selection_policy(),
    ) == ["execution"]


def test_selection_uses_frozen_order_and_excludes_incomplete_seed() -> None:
    records = [
        {
            "seed": DECLARED_SEEDS[0],
            "status": "complete",
            "completion_marker_verified": True,
            "candidate": {
                "eligible": True,
                "selection_values": {
                    "macro_f1": 0.8,
                    "balanced_accuracy": 0.7,
                    "worst_reportable_tactic_recall_regression": 0.0,
                    "terminal_f1": 0.8,
                    "p95_single_case_cpu_latency_ms": 2.0,
                },
            },
        },
        {
            "seed": DECLARED_SEEDS[1],
            "status": "incomplete",
            "completion_marker_verified": False,
            "candidate": {
                "eligible": True,
                "selection_values": {
                    "macro_f1": 1.0,
                    "balanced_accuracy": 1.0,
                    "worst_reportable_tactic_recall_regression": 0.0,
                    "terminal_f1": 1.0,
                    "p95_single_case_cpu_latency_ms": 0.1,
                },
            },
        },
        {
            "seed": DECLARED_SEEDS[2],
            "status": "complete",
            "completion_marker_verified": True,
            "candidate": {
                "eligible": True,
                "selection_values": {
                    "macro_f1": 0.8,
                    "balanced_accuracy": 0.71,
                    "worst_reportable_tactic_recall_regression": 0.0,
                    "terminal_f1": 0.7,
                    "p95_single_case_cpu_latency_ms": 1.0,
                },
            },
        },
    ]

    selected = select_completed_seed(records)

    assert selected["seed"] == DECLARED_SEEDS[2]


def test_publication_requires_every_declared_seed_to_complete() -> None:
    complete = [
        {
            "seed": seed,
            "status": "complete",
            "completion_marker_verified": True,
        }
        for seed in DECLARED_SEEDS
    ]

    require_all_declared_seeds(complete)

    incomplete = [dict(record) for record in complete]
    incomplete[-1] = {
        "seed": DECLARED_SEEDS[-1],
        "status": "incomplete",
        "completion_marker_verified": False,
        "error_type": "RuntimeError",
    }
    with pytest.raises(
        NextBehaviorTrainingError,
        match="every declared seed must complete",
    ):
        require_all_declared_seeds(incomplete)

    with pytest.raises(
        NextBehaviorTrainingError,
        match="declared seed order",
    ):
        require_all_declared_seeds(complete[:-1])


def test_no_complete_eligible_seed_cannot_be_frozen() -> None:
    with pytest.raises(NextBehaviorTrainingError, match="no complete seed"):
        select_completed_seed(
            [
                {
                    "seed": seed,
                    "status": "incomplete",
                    "completion_marker_verified": False,
                    "candidate": {"eligible": True},
                }
                for seed in DECLARED_SEEDS
            ]
        )


def test_selection_blocker_evidence_is_atomic_and_idempotent(
    tmp_path: Path,
) -> None:
    staging = tmp_path / ".training.staging"
    staging.mkdir()
    checkpoint = staging / "seed_runs" / "seed" / "checkpoint.pt"
    checkpoint.parent.mkdir(parents=True)
    checkpoint.write_bytes(b"checkpoint")
    output = tmp_path / "training"
    records = [
        {
            "seed": seed,
            "status": "complete",
            "completion_marker_verified": True,
            "candidate": {
                "eligible": False,
                "blockers": [
                    "high_consequence_recall_regression:execution"
                ],
            },
            "checkpoint": {
                "path": str(checkpoint.relative_to(staging)),
                "sha256": hashlib.sha256(b"checkpoint").hexdigest(),
            },
            "selection_metrics": {
                "path": f"seed_runs/{seed}/selection_metrics.json",
                "sha256": HASH_A,
            },
            "completion": {
                "path": f"seed_runs/{seed}/completion.json",
                "sha256": HASH_B,
            },
        }
        for seed in DECLARED_SEEDS
    ]

    blocked = publish_selection_blocked_bundle(
        staging,
        output,
        seed_records=records,
        code_commit="1" * 40,
    )
    receipt = json.loads(
        (blocked / "SELECTION_BLOCKED.json").read_text(encoding="utf-8")
    )

    assert not staging.exists()
    assert not output.exists()
    assert receipt["status"] == "selection_blocked_pre_test"
    assert receipt["test_opened"] is False
    assert receipt["final_test_path_accepted_by_command"] is False
    assert receipt["declared_seeds"] == list(DECLARED_SEEDS)
    assert receipt["pre_test_artifact_hashes"] == {
        "seed_runs/seed/checkpoint.pt": hashlib.sha256(
            b"checkpoint"
        ).hexdigest()
    }
    identity = dict(receipt)
    receipt_sha256 = identity.pop("receipt_sha256")
    assert receipt_sha256 == hashlib.sha256(
        json.dumps(
            identity,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()

    second_staging = tmp_path / ".training.second"
    second_staging.mkdir()
    sentinel = blocked / "SELECTION_BLOCKED.json"
    before = sentinel.read_bytes()
    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        publish_selection_blocked_bundle(
            second_staging,
            output,
            seed_records=records,
            code_commit="1" * 40,
        )
    assert sentinel.read_bytes() == before
    assert second_staging.exists()


def test_existing_output_is_refused_before_any_input_is_opened(
    tmp_path: Path,
) -> None:
    output = tmp_path / "accepted"
    output.mkdir()
    sentinel = output / "sentinel"
    sentinel.write_text("unchanged", encoding="utf-8")

    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        run_training_experiment(
            train_path=tmp_path / "missing-train.jsonl",
            train_safe_sessions_path=tmp_path / "missing-train-sessions.jsonl",
            train_build_receipt_path=tmp_path / "missing-train-build.json",
            train_source_receipts_path=tmp_path / "missing-train-sources.json",
            train_corpus_receipt_path=tmp_path / "missing-train-corpus.json",
            train_historical_split_evidence_path=(
                tmp_path / "missing-train-historical.json"
            ),
            selection_path=tmp_path / "missing-selection.jsonl",
            selection_safe_sessions_path=(
                tmp_path / "missing-selection-sessions.jsonl"
            ),
            selection_build_receipt_path=(
                tmp_path / "missing-selection-build.json"
            ),
            selection_source_receipts_path=(
                tmp_path / "missing-selection-sources.json"
            ),
            selection_corpus_receipt_path=(
                tmp_path / "missing-selection-corpus.json"
            ),
            selection_historical_split_evidence_path=(
                tmp_path / "missing-selection-historical.json"
            ),
            calibration_path=tmp_path / "missing-calibration.jsonl",
            calibration_safe_sessions_path=(
                tmp_path / "missing-calibration-sessions.jsonl"
            ),
            calibration_build_receipt_path=(
                tmp_path / "missing-calibration-build.json"
            ),
            calibration_source_receipts_path=(
                tmp_path / "missing-calibration-sources.json"
            ),
            calibration_corpus_receipt_path=(
                tmp_path / "missing-calibration-corpus.json"
            ),
            calibration_historical_split_evidence_path=(
                tmp_path / "missing-calibration-historical.json"
            ),
            partition_manifest_path=tmp_path / "missing-manifest.json",
            preprocessing_config_path=tmp_path / "missing-preprocessing.json",
            experiment_policy_path=tmp_path / "missing-policy.json",
            environment_lock_path=tmp_path / "missing-environment.lock",
            output_dir=output,
            code_commit="fixture",
        )

    assert sentinel.read_text(encoding="utf-8") == "unchanged"


def test_calibration_adapter_declares_raw_scores_not_probabilities() -> None:
    example = {
        "example_id": _opaque("example", "calibration"),
        "target": {
            "outcome_type": "next_behavior_phase",
            "tactics": ["execution"],
        },
    }
    raw = {
        "example_id": example["example_id"],
        "session_id": _opaque("session", "calibration"),
        "model_output": {
            "score_semantics": "raw_uncalibrated_logits",
            "tactic_logits": {
                tactic: float(index)
                for index, tactic in enumerate(
                    sorted(_class_metrics(
                        execution_recall=1.0,
                        macro_f1=1.0,
                        balanced_accuracy=1.0,
                        terminal_f1=1.0,
                    )["multilabel_tactics"]["per_class"])
                )
            },
            "terminal_logit": -1.0,
        },
    }
    example["session_id"] = raw["session_id"]

    rows = _calibration_rows(
        [example],
        [raw],
        checkpoint_sha256=HASH_A,
        vocabulary_sha256_value=HASH_A,
        preprocessing_sha256=HASH_B,
    )

    assert rows[0]["score_semantics"] == "raw_model_scores_not_probabilities"


def test_selection_decoder_uses_the_frozen_terminal_and_tactic_rules() -> None:
    example = {
        "example_id": _opaque("example", "decision"),
        "session_id": _opaque("session", "decision"),
    }
    scores = {
        tactic: -10.0
        for tactic in _class_metrics(
            execution_recall=1.0,
            macro_f1=1.0,
            balanced_accuracy=1.0,
            terminal_f1=1.0,
        )["multilabel_tactics"]["per_class"]
    }
    scores["execution"] = 2.0
    scores["persistence"] = 1.0

    terminal = _prediction_from_raw(
        example,
        {"tactic_logits": scores, "terminal_logit": 0.0},
    )
    nonterminal = _prediction_from_raw(
        example,
        {"tactic_logits": scores, "terminal_logit": -0.01},
    )
    no_positive = _prediction_from_raw(
        example,
        {
            "tactic_logits": {
                tactic: score - 3.0 for tactic, score in scores.items()
            },
            "terminal_logit": -0.01,
        },
    )

    assert terminal["predicted_terminal"] is True
    assert terminal["predicted_tactics"] == []
    assert nonterminal["predicted_tactics"] == ["execution", "persistence"]
    assert nonterminal["ranked_tactics"][:2] == ["execution", "persistence"]
    assert no_positive["predicted_tactics"] == ["execution"]
