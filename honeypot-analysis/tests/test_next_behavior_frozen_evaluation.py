from __future__ import annotations

import hashlib
import importlib.util
import json
import copy
from pathlib import Path

import pytest

from production.prediction.next_behavior_baseline import (
    fit_corrected_target_baselines,
)
from production.prediction.next_behavior_calibration import (
    CALIBRATION_MAPPING_SCHEMA_VERSION,
    CALIBRATION_METHOD,
    RAW_SCORE_SEMANTICS,
    require_valid_calibration_mapping,
)
from production.prediction.next_behavior_contract import (
    EXAMPLE_SCHEMA_VERSION,
    MODEL_INPUT_SCHEMA_VERSION,
    TARGET_CONTRACT_ID,
    TERMINAL_OUTCOME,
)
from production.prediction.next_behavior_model import (
    build_model,
    build_model_spec,
    save_checkpoint,
    load_checkpoint,
)
from production.prediction.next_behavior_experiment_policy import (
    experiment_policy_sha256,
    load_experiment_policy,
)
from production.prediction.next_behavior_tensor import (
    VOCABULARY_SCHEMA_VERSION,
    require_valid_vocabulary,
)
from production.prediction.next_behavior_preprocessing import (
    build_next_behavior_examples,
)
from production.tools import evaluate_next_behavior_frozen as frozen
from production.utils.serialization import stable_id, stable_json


TORCH_AVAILABLE = importlib.util.find_spec("torch") is not None
HASH_A = "a" * 64
HASH_B = "b" * 64


def _example(
    name: str,
    session: str,
    history: list[list[str]],
    target: list[str] | None,
) -> dict:
    return {
        "schema_version": EXAMPLE_SCHEMA_VERSION,
        "target_contract_id": TARGET_CONTRACT_ID,
        "example_id": f"example-{name}",
        "session_id": f"session-{session}",
        "source_member_id": "member-fixture",
        "prediction_phase_id": f"phase-{name}",
        "prediction_event_order": len(history),
        "model_input": {
            "schema_version": MODEL_INPUT_SCHEMA_VERSION,
            "target_contract_id": TARGET_CONTRACT_ID,
            "phase_sequence": [
                {
                    "tactics": sorted(tactics),
                    "techniques": [],
                    "repetition_bucket": "1",
                    "elapsed_time_bucket": "unknown",
                    "label_provenance_sources": [],
                    "label_confidence_buckets": [],
                    "label_agreement_statuses": [],
                    "audit_only_label_count": 0,
                    "evidence_refs": [],
                }
                for tactics in history
            ],
        },
        "target": (
            {
                "outcome_type": "session_end",
                "tactics": [],
                "techniques": [],
                "terminal_outcome": TERMINAL_OUTCOME,
                "target_evidence_refs": [],
            }
            if target is None
            else {
                "outcome_type": "next_behavior_phase",
                "tactics": sorted(target),
                "techniques": [],
                "terminal_outcome": "",
                "target_evidence_refs": [],
            }
        ),
    }


def _examples() -> list[dict]:
    return [
        _example("a1", "a", [["discovery"]], ["execution"]),
        _example("a2", "a", [["discovery"], ["execution"]], None),
        _example("b1", "b", [["reconnaissance"]], ["discovery"]),
    ]


def _vocabulary() -> dict:
    value = {
        "schema_version": VOCABULARY_SCHEMA_VERSION,
        "target_contract_id": TARGET_CONTRACT_ID,
        "input_schema_version": MODEL_INPUT_SCHEMA_VERSION,
        "tactics": [
            "collection",
            "command-and-control",
            "credential-access",
            "defense-evasion",
            "discovery",
            "execution",
            "exfiltration",
            "impact",
            "initial-access",
            "lateral-movement",
            "persistence",
            "privilege-escalation",
            "reconnaissance",
            "resource-development",
        ],
        "techniques": ["<UNK>"],
        "label_sources": ["reviewed_rule", "rule_model_agreement", "securebert"],
        "confidence_buckets": ["high", "low", "medium", "not_applicable"],
        "agreement_statuses": [
            "agreed",
            "disagreed",
            "emergency",
            "model_only",
            "rule_only",
            "unreviewed",
        ],
        "repetition_buckets": ["1", "2", "3-5", "6+"],
        "elapsed_time_buckets": [
            "10_to_60s",
            "1_to_10s",
            "over_60s",
            "under_1s",
            "unknown",
        ],
        "audit_count_buckets": ["0", "1", "2-5", "6+"],
        "login_outcomes": ["failed", "success", "unknown"],
        "command_count_buckets": ["0", "1", "2-5", "6-20", "21+"],
        "session_age_buckets": [
            "under_10s",
            "10_to_60s",
            "1_to_5m",
            "over_5m",
            "unknown",
        ],
        "maximum_sequence_length": 8,
        "terminal_outcome": TERMINAL_OUTCOME,
        "preprocessing_sha256": HASH_A,
        "training_membership_sha256": HASH_B,
    }
    value["vocabulary_id"] = stable_id("nextbehaviorvocabulary", value)
    return require_valid_vocabulary(value)


def _write_json(path: Path, value: object) -> None:
    path.write_text(stable_json(value) + "\n", encoding="utf-8")


def _valid_calibration(
    *,
    checkpoint_sha256: str,
    vocabulary_sha256: str,
    preprocessing_sha256: str,
) -> dict:
    value = {
        "schema_version": CALIBRATION_MAPPING_SCHEMA_VERSION,
        "status": "valid",
        "target_contract_id": TARGET_CONTRACT_ID,
        "score_semantics": RAW_SCORE_SEMANTICS,
        "method": CALIBRATION_METHOD,
        "tactic_temperature": 1.25,
        "terminal_temperature": 0.9,
        "fit_example_count": 2,
        "fit_partition_membership_sha256": "c" * 64,
        "checkpoint_sha256": checkpoint_sha256,
        "vocabulary_sha256": vocabulary_sha256,
        "preprocessing_sha256": preprocessing_sha256,
        "mapping_sha256": "",
    }
    identity = copy.deepcopy(value)
    identity.pop("mapping_sha256")
    value["mapping_sha256"] = hashlib.sha256(
        stable_json(identity).encode("utf-8")
    ).hexdigest()
    return require_valid_calibration_mapping(value)


@pytest.mark.skipif(not TORCH_AVAILABLE, reason="PyTorch unavailable")
def _bundle(
    tmp_path: Path,
) -> tuple[dict, dict[str, Path], list[dict], dict]:
    from tests.test_next_behavior_tensor import _closed

    first = _closed()
    second = copy.deepcopy(first)
    second["session_id"] = "nbsession_" + hashlib.sha256(b"second").hexdigest()
    examples = [
        *build_next_behavior_examples(first),
        *build_next_behavior_examples(second),
    ]
    vocabulary = _vocabulary()
    spec = build_model_spec(vocabulary)
    paths: dict[str, Path] = {
        role: tmp_path / f"{role}.artifact"
        for role in frozen.REQUIRED_ARTIFACT_ROLES
    }
    _write_json(paths["vocabulary"], vocabulary)
    _write_json(paths["model_spec"], spec)
    policy_path = Path("configs/next_behavior_experiment_policy.v1.json")
    paths["experiment_policy"].write_bytes(policy_path.read_bytes())
    _write_json(paths["test_safe_payload"], [first, second])
    for family, artifact in fit_corrected_target_baselines(
        examples, maximum_order=2
    ).items():
        _write_json(paths[frozen.BASELINE_ROLES[family]], artifact)
    checkpoint_receipt = save_checkpoint(
        paths["checkpoint"], build_model(spec, seed=4), spec=spec
    )
    _write_json(
        paths["calibration"],
        _valid_calibration(
            checkpoint_sha256=checkpoint_receipt["checkpoint_sha256"],
            vocabulary_sha256=spec["vocabulary_sha256"],
            preprocessing_sha256=spec["preprocessing_sha256"],
        ),
    )
    loaded, checkpoint_metadata = load_checkpoint(
        paths["checkpoint"],
        expected_spec=spec,
        expected_checkpoint_sha256=checkpoint_receipt["checkpoint_sha256"],
    )
    policy = load_experiment_policy(paths["experiment_policy"])
    membership = hashlib.sha256(
        stable_json(sorted(item["example_id"] for item in examples)).encode(
            "utf-8"
        )
    ).hexdigest()
    manifest = {
        "schema_version": "next_behavior_experiment_manifest.v2",
        "code_commit": "fixture-commit",
        "artifact_hashes": {
            role: (
                frozen.sha256_file(path) if path.is_file() else "0" * 64
            )
            for role, path in paths.items()
        },
        "corpora": {"test": {"safe_session_count": 2}},
        "partitions": {
            "membership_sha256": {
                "calibration": "c" * 64,
                "test": membership,
            }
        },
    }
    preflight = {
        "manifest": manifest,
        "manifest_sha256": hashlib.sha256(
            stable_json(manifest).encode("utf-8")
        ).hexdigest(),
        "verified_artifacts": {
            "test_safe_payload": {
                "path": str(paths["test_safe_payload"]),
                "sha256": frozen.sha256_file(paths["test_safe_payload"]),
            }
        },
        "vocabulary": vocabulary,
        "model_spec": spec,
        "calibration": _valid_calibration(
            checkpoint_sha256=checkpoint_receipt["checkpoint_sha256"],
            vocabulary_sha256=spec["vocabulary_sha256"],
            preprocessing_sha256=spec["preprocessing_sha256"],
        ),
        "experiment_policy": policy,
        "baselines": fit_corrected_target_baselines(
            examples, maximum_order=2
        ),
        "model": loaded,
        "checkpoint_metadata": checkpoint_metadata,
    }
    return manifest, paths, examples, preflight


def _ledger_preflight(
    tmp_path: Path,
    *,
    manifest_sha256: str = "1" * 64,
    payload_bytes: bytes = b"sealed test fixture\n",
) -> dict:
    """Construct a byte-sealed payload receipt without parsing its content."""

    payload = tmp_path / "sealed-test-payload.jsonl"
    payload.write_bytes(payload_bytes)
    return {
        "manifest_sha256": manifest_sha256,
        "verified_artifacts": {
            "test_safe_payload": {
                "path": str(payload),
                "sha256": frozen.sha256_file(payload),
            }
        },
    }


def test_manifest_requires_v2_and_pre_test_freeze(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    value = {
        "schema_version": "next_behavior_experiment_manifest.v2",
        "status": "frozen_pre_test",
        "partitions": {"test_opened": False},
        "decision_freeze": {"frozen_before_test": True},
    }
    monkeypatch.setattr(
        frozen, "require_valid_experiment_manifest", lambda item: item
    )
    assert frozen.require_valid_frozen_evaluation_manifest(value) == value

    value["partitions"]["test_opened"] = True
    with pytest.raises(frozen.FrozenEvaluationError, match="frozen"):
        frozen.require_valid_frozen_evaluation_manifest(value)


def test_wrong_purpose_is_rejected_before_any_artifact_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        frozen,
        "require_valid_frozen_evaluation_manifest",
        lambda *_args: (_ for _ in ()).throw(
            AssertionError("manifest/artifacts must not be accessed")
        ),
    )
    with pytest.raises(frozen.FrozenEvaluationError, match="final_evaluation"):
        frozen.verify_pre_test_artifacts(
            {}, {}, purpose="select_model"
        )


def test_v2_preflight_verifies_all_semantics_and_checkpoint_before_test_read(
    tmp_path: Path,
) -> None:
    from tests.test_next_behavior_experiment import _write_complete_v2_bundle

    manifest, paths = _write_complete_v2_bundle(tmp_path)
    sealed_test_bytes = paths["test_safe_payload"].read_bytes()
    # Reaching the evaluator's stricter valid-calibration requirement proves
    # the complete v2 artifact gate passed, while the test payload remained
    # semantically unopened.
    with pytest.raises(frozen.FrozenEvaluationError, match="valid calibration"):
        frozen.verify_pre_test_artifacts(
            manifest, paths, purpose="final_evaluation"
        )
    assert paths["test_safe_payload"].read_bytes() == sealed_test_bytes


def test_final_sessions_support_canonical_jsonl_and_verify_membership(
    tmp_path: Path,
) -> None:
    from tests.test_next_behavior_tensor import _closed

    session = _closed()
    examples = build_next_behavior_examples(session)
    path = tmp_path / "test_safe_payload.jsonl"
    path.write_text(
        stable_json(session) + "\n",
        encoding="utf-8",
    )
    ids = sorted(item["example_id"] for item in examples)
    preflight = {
        "manifest": {
            "corpora": {"test": {"safe_session_count": 1}},
            "partitions": {
                "membership_sha256": {
                    "test": hashlib.sha256(
                        stable_json(ids).encode("utf-8")
                    ).hexdigest()
                }
            },
        },
        "verified_artifacts": {
            "test_safe_payload": {"path": str(path)}
        },
    }

    assert frozen._load_final_examples(preflight) == examples
    path.write_text(path.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    with pytest.raises(frozen.FrozenEvaluationError, match="blank"):
        frozen._load_final_examples(preflight)


def test_malformed_calibration_fails_before_final_payload_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vocabulary = _vocabulary()
    spec = build_model_spec(vocabulary)
    vocabulary_path = tmp_path / "vocabulary.json"
    spec_path = tmp_path / "model_spec.json"
    calibration_path = tmp_path / "calibration.json"
    policy_path = tmp_path / "policy.json"
    _write_json(vocabulary_path, vocabulary)
    _write_json(spec_path, spec)
    _write_json(calibration_path, {"status": "valid", "temperature": -1})
    policy_path.write_bytes(
        Path("configs/next_behavior_experiment_policy.v1.json").read_bytes()
    )
    verified = {
        "vocabulary": {"path": str(vocabulary_path)},
        "model_spec": {"path": str(spec_path)},
        "calibration": {"path": str(calibration_path)},
        "experiment_policy": {"path": str(policy_path)},
        # Deliberately omit test_safe_payload. Reaching it would violate the
        # required failure ordering.
    }
    manifest = {
        "policies": {
            "experiment_policy_sha256": experiment_policy_sha256(
                load_experiment_policy(policy_path)
            )
        }
    }
    monkeypatch.setattr(
        frozen,
        "require_valid_frozen_evaluation_manifest",
        lambda _value: manifest,
    )
    monkeypatch.setattr(
        frozen,
        "verify_experiment_artifacts_v2_pretest",
        lambda *_args, **_kwargs: {
            "status": "verified_pre_test",
            "test_opened": False,
            "artifacts": verified,
        },
    )

    with pytest.raises(frozen.FrozenEvaluationError, match="mapping is invalid"):
        frozen.verify_pre_test_artifacts(
            manifest, {}, purpose="final_evaluation"
        )


def test_member_sensitivity_uses_preserved_member_identity_or_blocks() -> None:
    examples = _examples()
    examples[0]["source_member_id"] = "member-a"
    examples[1]["source_member_id"] = "member-a"
    examples[2]["source_member_id"] = "member-b"
    predictions = [
        {
            "example_id": example["example_id"],
            "session_id": example["session_id"],
            "status": "predicted",
            "predicted_terminal": (
                example["target"]["outcome_type"] == "session_end"
            ),
            "predicted_tactics": list(example["target"]["tactics"]),
            "ranked_tactics": (
                list(example["target"]["tactics"]) or ["execution"]
            ),
        }
        for example in examples
    ]
    available = frozen._member_sensitivity(
        examples,
        {
            "small_causal_transformer": predictions,
            "hard_backoff_vomm": copy.deepcopy(predictions),
        },
        member_order=["member-a", "member-b"],
        minimum_target_sessions=1,
        minimum_targets=1,
        bootstrap_seed=3,
    )
    assert available["status"] == "evaluated"
    assert len(available["per_member"]) == 2
    assert len(available["leave_one_member_out"]) == 2

    examples[0].pop("source_member_id")
    blocked = frozen._member_sensitivity(
        examples,
        {"small_causal_transformer": predictions},
        member_order=["member-a", "member-b"],
        minimum_target_sessions=1,
        minimum_targets=1,
        bootstrap_seed=3,
    )
    assert blocked == {
        "status": "blocked",
        "reason": "source_member_identity_unavailable_or_unbound",
        "fabricated_membership": False,
    }


def test_calibration_diagnostics_use_probability_not_raw_logit_semantics() -> None:
    result = frozen._binary_calibration_diagnostics(
        [0.9, 0.2],
        [True, False],
        reliability_bin_count=2,
    )

    assert result["brier_score"] == pytest.approx((0.1**2 + 0.2**2) / 2)
    assert result["log_loss"] > 0.0
    assert result["ece"] == pytest.approx(0.15)
    assert sum(item["count"] for item in result["reliability_bins"]) == 2
    with pytest.raises(frozen.FrozenEvaluationError, match="probability"):
        frozen._binary_calibration_diagnostics([1.2], [True])


def test_final_access_ledger_is_exclusive_and_binds_manifest_and_payload(
    tmp_path: Path,
) -> None:
    preflight = _ledger_preflight(tmp_path)
    claim = frozen._claim_final_evaluation_access(
        preflight, output_directory=tmp_path / "first-output"
    )
    ledger_path = frozen.evaluation_access_ledger_path(preflight)
    ledger = json.loads(ledger_path.read_text(encoding="utf-8"))

    assert claim["ledger_path"] == ledger_path
    assert ledger["schema_version"] == (
        frozen.EVALUATION_ACCESS_LEDGER_SCHEMA_VERSION
    )
    assert ledger["state"] == "opened"
    assert ledger["experiment_manifest_sha256"] == "1" * 64
    assert ledger["test_payload_sha256"] == frozen.sha256_file(
        tmp_path / "sealed-test-payload.jsonl"
    )
    assert ledger["automatic_retry_permitted"] is False

    with pytest.raises(frozen.FrozenEvaluationError, match="already claimed"):
        frozen._claim_final_evaluation_access(
            preflight, output_directory=tmp_path / "different-output"
        )
    conflicting_manifest = _ledger_preflight(
        tmp_path,
        manifest_sha256="2" * 64,
        payload_bytes=(tmp_path / "sealed-test-payload.jsonl").read_bytes(),
    )
    # Reuse the exact same payload path/receipt while changing only the
    # manifest binding.  A different frozen manifest cannot reopen it.
    conflicting_manifest["verified_artifacts"]["test_safe_payload"] = (
        preflight["verified_artifacts"]["test_safe_payload"]
    )
    with pytest.raises(
        frozen.FrozenEvaluationError, match="different frozen manifest"
    ):
        frozen._claim_final_evaluation_access(
            conflicting_manifest,
            output_directory=tmp_path / "conflicting-output",
        )


def test_evaluator_claims_before_final_load_and_records_completion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    preflight = _ledger_preflight(tmp_path)
    destination = tmp_path / "accepted"
    monkeypatch.setattr(
        frozen, "verify_pre_test_artifacts", lambda *_args, **_kwargs: preflight
    )

    def after_claim(
        observed_preflight: dict,
        observed_destination: Path,
        **_kwargs: object,
    ) -> dict:
        assert observed_preflight is preflight
        assert observed_destination == destination
        ledger = json.loads(
            frozen.evaluation_access_ledger_path(preflight).read_text(
                encoding="utf-8"
            )
        )
        assert ledger["state"] == "opened"
        return {"status": "complete"}

    monkeypatch.setattr(frozen, "_evaluate_after_access_claim", after_claim)
    assert frozen.evaluate_frozen_experiment(
        {}, {}, destination, purpose="final_evaluation", bootstrap_samples=1
    ) == {"status": "complete"}
    ledger = json.loads(
        frozen.evaluation_access_ledger_path(preflight).read_text(encoding="utf-8")
    )
    assert ledger["state"] == "completed"
    assert ledger["completed_output_directory"] == str(destination.resolve())
    with pytest.raises(frozen.FrozenEvaluationError, match="already claimed"):
        frozen.evaluate_frozen_experiment(
            {}, {}, tmp_path / "retry", purpose="final_evaluation", bootstrap_samples=1
        )


def test_post_open_failure_is_durable_and_blocks_different_output_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    preflight = _ledger_preflight(tmp_path)
    monkeypatch.setattr(
        frozen, "verify_pre_test_artifacts", lambda *_args, **_kwargs: preflight
    )
    monkeypatch.setattr(
        frozen,
        "_evaluate_after_access_claim",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("boom")),
    )
    with pytest.raises(RuntimeError, match="boom"):
        frozen.evaluate_frozen_experiment(
            {}, {}, tmp_path / "failed-output", purpose="final_evaluation", bootstrap_samples=1
        )
    ledger = json.loads(
        frozen.evaluation_access_ledger_path(preflight).read_text(encoding="utf-8")
    )
    assert ledger["state"] == "failed"
    assert ledger["failure_type"] == "RuntimeError"
    assert "boom" not in stable_json(ledger)
    with pytest.raises(frozen.FrozenEvaluationError, match="already claimed"):
        frozen.evaluate_frozen_experiment(
            {}, {}, tmp_path / "hidden-retry", purpose="final_evaluation", bootstrap_samples=1
        )


def test_post_preflight_payload_mutation_fails_closed_after_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    preflight = _ledger_preflight(tmp_path)
    payload = Path(preflight["verified_artifacts"]["test_safe_payload"]["path"])

    def preflight_then_mutate(*_args: object, **_kwargs: object) -> dict:
        payload.write_bytes(b"mutated after preflight\n")
        return preflight

    monkeypatch.setattr(
        frozen, "verify_pre_test_artifacts", preflight_then_mutate
    )
    with pytest.raises(frozen.FrozenEvaluationError, match="changed after"):
        frozen.evaluate_frozen_experiment(
            {}, {}, tmp_path / "mutated", purpose="final_evaluation", bootstrap_samples=1
        )
    ledger = json.loads(
        frozen.evaluation_access_ledger_path(preflight).read_text(encoding="utf-8")
    )
    assert ledger["state"] == "failed"


@pytest.mark.skipif(not TORCH_AVAILABLE, reason="PyTorch unavailable")
def test_evaluator_aligns_every_model_and_publishes_atomically(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest, paths, examples, preflight = _bundle(tmp_path)
    monkeypatch.setattr(
        frozen, "verify_pre_test_artifacts", lambda *_args, **_kwargs: preflight
    )
    destination = tmp_path / "accepted"
    result = frozen.evaluate_frozen_experiment(
        manifest,
        paths,
        destination,
        purpose="final_evaluation",
        bootstrap_samples=5,
        bootstrap_seed=7,
    )

    assert result["example_count"] == len(examples)
    assert set(result["metrics"]) == {
        "small_causal_transformer",
        *frozen.BASELINE_ROLES,
    }
    assert (destination / "COMPLETED.json").is_file()
    transformer_rows = json.loads(
        (
            destination
            / "predictions"
            / "small_causal_transformer.json"
        ).read_text(encoding="utf-8")
    )
    for row in transformer_rows:
        raw_ranking = sorted(
            row["raw_scores"]["tactic_logits"],
            key=lambda tactic: (
                -row["raw_scores"]["tactic_logits"][tactic],
                tactic,
            ),
        )
        assert row["ranked_tactics"] == raw_ranking
        calibrated_ranking = sorted(
            row["calibrated_probabilities"]["tactics"],
            key=lambda tactic: (
                -row["calibrated_probabilities"]["tactics"][tactic],
                tactic,
            ),
        )
        assert calibrated_ranking == raw_ranking
        if row["raw_scores"]["terminal_logit"] >= 0.0:
            assert row["predicted_terminal"] is True
            assert row["predicted_tactics"] == []
        else:
            expected_set = sorted(
                tactic
                for tactic, score in row["raw_scores"][
                    "tactic_logits"
                ].items()
                if score >= 0.0
            )
            assert row["predicted_terminal"] is False
            assert row["predicted_tactics"] == (
                expected_set or [raw_ranking[0]]
            )
        assert row["calibrated_probabilities"]["mapping_sha256"] == (
            preflight["calibration"]["mapping_sha256"]
        )
        assert row["calibrated_probabilities"][
            "fit_partition_membership_sha256"
        ] == "c" * 64
    diagnostics = result["calibration_diagnostics"]
    assert diagnostics["mapping_sha256"] == preflight["calibration"][
        "mapping_sha256"
    ]
    assert diagnostics["terminal"]["count"] == len(examples)
    assert diagnostics["terminal"]["reliability_bin_count"] == 10
    assert result["chronological_member_sensitivity"]["status"] == "blocked"
    for metrics in result["metrics"].values():
        assert metrics["example_ids"] == [
            item["example_id"] for item in examples
        ]
    with pytest.raises(frozen.FrozenEvaluationError, match="already exists"):
        frozen.evaluate_frozen_experiment(
            manifest, paths, destination, purpose="final_evaluation"
        )


@pytest.mark.skipif(not TORCH_AVAILABLE, reason="PyTorch unavailable")
def test_failure_leaves_no_partial_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest, paths, _examples_value, preflight = _bundle(tmp_path)
    monkeypatch.setattr(
        frozen, "verify_pre_test_artifacts", lambda *_args, **_kwargs: preflight
    )
    monkeypatch.setattr(
        frozen,
        "_transformer_prediction",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("boom")),
    )
    destination = tmp_path / "never-published"
    with pytest.raises(RuntimeError, match="boom"):
        frozen.evaluate_frozen_experiment(
            manifest,
            paths,
            destination,
            purpose="final_evaluation",
            bootstrap_samples=5,
        )
    assert not destination.exists()
