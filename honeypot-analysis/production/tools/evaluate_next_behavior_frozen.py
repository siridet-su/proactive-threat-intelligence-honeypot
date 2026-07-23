"""One-time, fail-closed evaluation of the frozen corrected-target experiment.

The evaluator deliberately separates pre-test verification from final-partition
access.  Every non-test artifact, including the deserialized neural checkpoint,
is verified before the sealed final-role safe-session payload is opened.
Results are written to a new directory through an atomic rename; an existing
or partial result is never overwritten.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import shutil
import tempfile
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, Mapping, Sequence

from production.prediction.next_behavior_baseline import (
    BASELINE_FAMILIES,
    predict_many,
    require_valid_baseline,
)
from production.prediction.next_behavior_contract import TARGET_CONTRACT_ID
from production.prediction.next_behavior_calibration import (
    apply_temperature_mapping,
    require_valid_calibration_mapping,
)
from production.prediction.next_behavior_metrics import (
    DEFAULT_BOOTSTRAP_SEED,
    evaluate_next_behavior_predictions,
    paired_model_comparison,
)
from production.prediction.next_behavior_experiment import (
    EXPERIMENT_MANIFEST_SCHEMA_VERSION_V2,
    REQUIRED_ARTIFACT_ROLES_V2,
    require_valid_experiment_manifest,
    verify_experiment_artifacts_v2_pretest,
)
from production.prediction.next_behavior_experiment_policy import (
    experiment_policy_sha256,
    load_experiment_policy,
)
from production.prediction.next_behavior_model import (
    load_checkpoint,
    predict_next_behavior,
    require_valid_model_spec,
)
from production.prediction.next_behavior_tensor import (
    require_valid_vocabulary,
    tensorize_model_input,
    vocabulary_sha256,
)
from production.prediction.next_behavior_preprocessing import (
    build_next_behavior_examples,
)
from production.utils.serialization import stable_json


FROZEN_EVALUATION_RESULT_SCHEMA_VERSION = "next_behavior_frozen_result.v1"
COMPLETION_SCHEMA_VERSION = "next_behavior_frozen_completion.v1"
BASELINE_ROLES = {
    family: f"baseline_{family}" for family in sorted(BASELINE_FAMILIES)
}
REQUIRED_ARTIFACT_ROLES = REQUIRED_ARTIFACT_ROLES_V2


class FrozenEvaluationError(ValueError):
    """Raised before a result is accepted or a partial result can escape."""


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _json_sha256(value: Any) -> str:
    return hashlib.sha256(stable_json(value).encode("utf-8")).hexdigest()


def _read_json(path: Path, *, role: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise FrozenEvaluationError(f"{role} is not valid JSON") from exc


def require_valid_frozen_evaluation_manifest(value: Any) -> Dict[str, Any]:
    """Require the additive 13-member experiment freeze, not a local alias."""

    try:
        validated = require_valid_experiment_manifest(value)
    except Exception as exc:
        raise FrozenEvaluationError("experiment manifest is invalid") from exc
    if validated.get("schema_version") != EXPERIMENT_MANIFEST_SCHEMA_VERSION_V2:
        raise FrozenEvaluationError("final evaluator requires experiment manifest v2")
    if (
        validated.get("status") != "frozen_pre_test"
        or validated["partitions"].get("test_opened") is not False
        or validated["decision_freeze"].get("frozen_before_test") is not True
    ):
        raise FrozenEvaluationError("experiment is not frozen before test")
    return validated


def verify_pre_test_artifacts(
    manifest: Mapping[str, Any],
    artifact_paths: Mapping[str, str | Path],
    *,
    purpose: str,
) -> Dict[str, Any]:
    """Verify every non-test artifact without touching the final partition."""

    if purpose != "final_evaluation":
        raise FrozenEvaluationError("purpose must be final_evaluation")
    frozen = require_valid_frozen_evaluation_manifest(dict(manifest))
    try:
        receipt = verify_experiment_artifacts_v2_pretest(
            frozen, artifact_paths
        )
    except Exception as exc:
        raise FrozenEvaluationError("pre-test artifact verification failed") from exc
    if receipt.get("status") != "verified_pre_test" or receipt.get(
        "test_opened"
    ) is not False:
        raise FrozenEvaluationError("pre-test artifact verifier did not fail closed")
    verified = receipt["artifacts"]

    vocabulary = require_valid_vocabulary(
        _read_json(Path(verified["vocabulary"]["path"]), role="vocabulary")
    )
    experiment_policy = load_experiment_policy(
        verified["experiment_policy"]["path"]
    )
    if (
        experiment_policy_sha256(experiment_policy)
        != frozen["policies"]["experiment_policy_sha256"]
    ):
        raise FrozenEvaluationError("experiment policy semantic hash mismatch")
    spec = require_valid_model_spec(
        _read_json(Path(verified["model_spec"]["path"]), role="model_spec")
    )
    if spec["vocabulary_sha256"] != vocabulary_sha256(vocabulary):
        raise FrozenEvaluationError("model spec and vocabulary disagree")
    try:
        calibration = require_valid_calibration_mapping(
            _read_json(
                Path(verified["calibration"]["path"]),
                role="calibration",
            )
        )
    except Exception as exc:
        raise FrozenEvaluationError("calibration mapping is invalid") from exc
    if calibration["status"] != "valid":
        raise FrozenEvaluationError(
            "frozen final evaluation requires a valid calibration mapping"
        )

    baselines: Dict[str, Any] = {}
    for family, role in BASELINE_ROLES.items():
        baseline = require_valid_baseline(
            _read_json(Path(verified[role]["path"]), role=role)
        )
        if baseline["family"] != family:
            raise FrozenEvaluationError(f"{role} has the wrong family")
        baselines[family] = baseline
    training_memberships = {
        tuple(artifact["training_example_ids"]) for artifact in baselines.values()
    }
    if len(training_memberships) != 1:
        raise FrozenEvaluationError("baseline training memberships differ")
    baseline_training_hash = hashlib.sha256(
        stable_json(sorted(next(iter(training_memberships)))).encode("utf-8")
    ).hexdigest()
    if baseline_training_hash != frozen["partitions"]["membership_sha256"][
        "train"
    ]:
        raise FrozenEvaluationError(
            "baseline training membership does not match the frozen partition"
        )

    try:
        model, checkpoint_metadata = load_checkpoint(
            verified["checkpoint"]["path"],
            expected_spec=spec,
            expected_checkpoint_sha256=verified["checkpoint"]["sha256"],
        )
    except Exception as exc:
        raise FrozenEvaluationError("checkpoint verification failed") from exc
    if (
        checkpoint_metadata["parameter_count"]
        != frozen["model"]["parameter_count"]
        or checkpoint_metadata["state_dictionary_sha256"]
        != frozen["model"]["state_dictionary_sha256"]
        or checkpoint_metadata["checkpoint_sha256"]
        != frozen["model"]["checkpoint_sha256"]
    ):
        raise FrozenEvaluationError("checkpoint metadata binding mismatch")
    calibration_bindings = {
        "checkpoint_sha256": verified["checkpoint"]["sha256"],
        "vocabulary_sha256": spec["vocabulary_sha256"],
        "preprocessing_sha256": spec["preprocessing_sha256"],
    }
    for field, expected in calibration_bindings.items():
        if calibration[field] != expected:
            raise FrozenEvaluationError(f"calibration {field} mismatch")
    partition = _read_json(
        Path(verified["partition_manifest"]["path"]),
        role="partition_manifest",
    )
    test_role = (partition.get("roles") or {}).get("test")
    test_member_order = (
        list(test_role.get("source_member_ids") or [])
        if isinstance(test_role, Mapping)
        else []
    )
    return {
        "manifest": frozen,
        "manifest_sha256": _json_sha256(frozen),
        "verified_artifacts": verified,
        "vocabulary": vocabulary,
        "model_spec": spec,
        "calibration": calibration,
        "experiment_policy": experiment_policy,
        "baselines": baselines,
        "model": model,
        "checkpoint_metadata": checkpoint_metadata,
        "test_member_order": test_member_order,
    }


def _read_json_or_jsonl(path: Path, *, role: str) -> list[Any]:
    if path.suffix == ".jsonl":
        value: list[Any] = []
        try:
            with path.open("r", encoding="utf-8") as handle:
                for line_number, line in enumerate(handle, start=1):
                    if not line.strip():
                        raise FrozenEvaluationError(
                            f"{role} JSONL line {line_number} is blank"
                        )
                    try:
                        item = json.loads(line)
                    except json.JSONDecodeError as exc:
                        raise FrozenEvaluationError(
                            f"{role} JSONL line {line_number} is invalid"
                        ) from exc
                    value.append(item)
        except (OSError, UnicodeError) as exc:
            raise FrozenEvaluationError(f"{role} JSONL cannot be read") from exc
    else:
        value = _read_json(path, role=role)
    if not isinstance(value, list):
        raise FrozenEvaluationError(f"{role} must be an array or JSONL sequence")
    return value


def _load_final_examples(preflight: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Purpose-scoped first semantic access to the sealed final-role payload."""

    final_path = Path(
        preflight["verified_artifacts"]["test_safe_payload"]["path"]
    )
    sessions = _read_json_or_jsonl(final_path, role="test_safe_payload")
    expected_sessions = preflight["manifest"]["corpora"]["test"][
        "safe_session_count"
    ]
    if len(sessions) != expected_sessions:
        raise FrozenEvaluationError("test safe-session count mismatch")
    value: list[dict[str, Any]] = []
    for index, session in enumerate(sessions):
        try:
            value.extend(build_next_behavior_examples(session))
        except Exception as exc:
            raise FrozenEvaluationError(
                f"test safe session {index} is invalid"
            ) from exc
    if not isinstance(value, list) or not value:
        raise FrozenEvaluationError("final_examples must be a non-empty list")
    example_ids: list[str] = []
    for index, example in enumerate(value):
        if not isinstance(example, dict):
            raise FrozenEvaluationError(f"final_examples[{index}] is invalid")
        example_id = example.get("example_id")
        if not isinstance(example_id, str) or not example_id.strip():
            raise FrozenEvaluationError(f"final_examples[{index}].example_id is invalid")
        if example_id in example_ids:
            raise FrozenEvaluationError("final example identifiers are duplicated")
        example_ids.append(example_id)
    membership = hashlib.sha256(
        stable_json(sorted(example_ids)).encode("utf-8")
    ).hexdigest()
    if membership != preflight["manifest"]["partitions"]["membership_sha256"][
        "test"
    ]:
        raise FrozenEvaluationError("final test membership hash mismatch")
    return value


def _transformer_prediction(
    example: Mapping[str, Any],
    *,
    model: Any,
    spec: Mapping[str, Any],
    vocabulary: Mapping[str, Any],
    experiment_policy: Mapping[str, Any],
    calibration_mapping: Mapping[str, Any],
    checkpoint_sha256: str,
    calibration_membership_sha256: str,
) -> Dict[str, Any]:
    tensor = tensorize_model_input(example["model_input"], vocabulary)
    raw = predict_next_behavior(model, tensor, spec=spec)
    ranking = sorted(
        raw["tactic_logits"],
        key=lambda tactic: (-raw["tactic_logits"][tactic], tactic),
    )
    decision = experiment_policy["prediction_decision"]
    if decision["terminal_rule"] != "terminal_logit_greater_than_or_equal_to_zero":
        raise FrozenEvaluationError("frozen terminal decision rule changed")
    if decision["tactic_rule"] != "each_tactic_logit_greater_than_or_equal_to_zero":
        raise FrozenEvaluationError("frozen tactic decision rule changed")
    terminal = raw["terminal_logit"] >= 0.0
    selected = (
        []
        if terminal
        else sorted(
            tactic
            for tactic, score in raw["tactic_logits"].items()
            if score >= 0.0
        )
    )
    if not terminal and not selected:
        selected = [ranking[0]]
    calibration_input = {
        "score_semantics": "raw_model_scores_not_probabilities",
        "ranked_tactics": [
            {
                "tactic": tactic,
                "raw_score": float(raw["tactic_logits"][tactic]),
                "rank": index,
                "calibrated_probability": None,
            }
            for index, tactic in enumerate(ranking, start=1)
        ],
        "terminal_outcome": {
            "label": raw["terminal_label"],
            "raw_score": float(raw["terminal_logit"]),
            "calibrated_probability": None,
        },
        "calibration": {
            "status": "not_implemented",
            "method": "",
            "mapping_sha256": "",
            "fit_partition_membership_sha256": "",
        },
    }
    calibration = apply_temperature_mapping(
        calibration_input,
        calibration_mapping,
        fit_partition_membership_sha256=calibration_membership_sha256,
        checkpoint_sha256=checkpoint_sha256,
        vocabulary_sha256=spec["vocabulary_sha256"],
        preprocessing_sha256=spec["preprocessing_sha256"],
    )
    calibrated_ranking = [
        item["tactic"] for item in calibration["ranked_tactics"]
    ]
    if calibrated_ranking != ranking:
        raise FrozenEvaluationError("calibration changed tactic ranking")
    return {
        "example_id": example["example_id"],
        "session_id": example["session_id"],
        "status": "predicted",
        "predicted_terminal": terminal,
        "predicted_tactics": selected,
        "ranked_tactics": ranking,
        "raw_scores": {
            "score_semantics": "raw_uncalibrated_logits",
            "tactic_logits": deepcopy(raw["tactic_logits"]),
            "terminal_logit": raw["terminal_logit"],
        },
        "calibrated_probabilities": {
            "score_semantics": "calibrated_sigmoid_probabilities",
            "tactics": {
                item["tactic"]: item["calibrated_probability"]
                for item in calibration["ranked_tactics"]
            },
            "terminal": calibration["terminal_outcome"][
                "calibrated_probability"
            ],
            "mapping_sha256": calibration["calibration"][
                "mapping_sha256"
            ],
            "fit_partition_membership_sha256": calibration["calibration"][
                "fit_partition_membership_sha256"
            ],
        },
    }


def _binary_calibration_diagnostics(
    probabilities: Sequence[float],
    targets: Sequence[bool],
    *,
    reliability_bin_count: int = 10,
) -> Dict[str, Any]:
    if len(probabilities) != len(targets) or not probabilities:
        raise FrozenEvaluationError("calibration diagnostic rows are misaligned")
    bins: list[dict[str, Any]] = []
    brier_total = 0.0
    log_loss_total = 0.0
    ece_total = 0.0
    count = len(probabilities)
    for probability, target in zip(probabilities, targets):
        if not math.isfinite(probability) or not 0.0 <= probability <= 1.0:
            raise FrozenEvaluationError("calibrated probability is invalid")
        numeric_target = 1.0 if target else 0.0
        brier_total += (probability - numeric_target) ** 2
        bounded = min(max(probability, 1e-15), 1.0 - 1e-15)
        log_loss_total -= (
            numeric_target * math.log(bounded)
            + (1.0 - numeric_target) * math.log(1.0 - bounded)
        )
    for index in range(reliability_bin_count):
        lower = index / reliability_bin_count
        upper = (index + 1) / reliability_bin_count
        selected = [
            (probability, target)
            for probability, target in zip(probabilities, targets)
            if lower <= probability < upper
            or (index == reliability_bin_count - 1 and probability == 1.0)
        ]
        if selected:
            mean_probability = sum(item[0] for item in selected) / len(selected)
            observed_frequency = sum(bool(item[1]) for item in selected) / len(
                selected
            )
            gap = abs(mean_probability - observed_frequency)
            ece_total += len(selected) / count * gap
        else:
            mean_probability = None
            observed_frequency = None
            gap = None
        bins.append(
            {
                "index": index,
                "lower_inclusive": lower,
                "upper_inclusive": (
                    index == reliability_bin_count - 1
                ),
                "upper": upper,
                "count": len(selected),
                "mean_probability": mean_probability,
                "observed_frequency": observed_frequency,
                "absolute_gap": gap,
            }
        )
    return {
        "count": count,
        "positive_count": sum(bool(item) for item in targets),
        "brier_score": brier_total / count,
        "log_loss": log_loss_total / count,
        "ece": ece_total,
        "reliability_bin_count": reliability_bin_count,
        "reliability_bins": bins,
    }


def _calibration_diagnostics(
    examples: Sequence[Mapping[str, Any]],
    predictions: Sequence[Mapping[str, Any]],
    *,
    reportable_tactics: Sequence[str],
    mapping: Mapping[str, Any],
) -> Dict[str, Any]:
    by_id = {item["example_id"]: item for item in predictions}
    tactic_results: Dict[str, Any] = {}
    for tactic in reportable_tactics:
        probabilities = [
            float(
                by_id[example["example_id"]]["calibrated_probabilities"][
                    "tactics"
                ][tactic]
            )
            for example in examples
        ]
        targets = [
            tactic in example["target"]["tactics"] for example in examples
        ]
        tactic_results[tactic] = _binary_calibration_diagnostics(
            probabilities, targets
        )
    terminal_probabilities = [
        float(
            by_id[example["example_id"]]["calibrated_probabilities"][
                "terminal"
            ]
        )
        for example in examples
    ]
    terminal_targets = [
        example["target"]["outcome_type"] == "session_end"
        for example in examples
    ]
    return {
        "status": "evaluated",
        "semantics": (
            "global_temperature_sigmoid_probabilities_separate_from_raw_logits"
        ),
        "raw_logits_preserved": True,
        "calibration_changes_ranking": False,
        "calibration_changes_prediction_set": False,
        "mapping_sha256": mapping["mapping_sha256"],
        "fit_partition_membership_sha256": mapping[
            "fit_partition_membership_sha256"
        ],
        "reportable_tactics": list(reportable_tactics),
        "per_reportable_tactic": tactic_results,
        "terminal": _binary_calibration_diagnostics(
            terminal_probabilities, terminal_targets
        ),
    }


def _point_summary(result: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        key: value["estimate"]
        for key, value in result["session_cluster_bootstrap"]["metrics"].items()
    }


def _member_sensitivity(
    examples: Sequence[Mapping[str, Any]],
    predictions: Mapping[str, Sequence[Mapping[str, Any]]],
    *,
    member_order: Sequence[str],
    minimum_target_sessions: int,
    minimum_targets: int,
    bootstrap_seed: int,
) -> Dict[str, Any]:
    example_members = {
        str(example.get("source_member_id") or "").strip()
        for example in examples
    }
    if (
        not member_order
        or "" in example_members
        or not example_members.issubset(set(member_order))
    ):
        return {
            "status": "blocked",
            "reason": "source_member_identity_unavailable_or_unbound",
            "fabricated_membership": False,
        }
    model_names = [
        name
        for name in ("small_causal_transformer", "hard_backoff_vomm")
        if name in predictions
    ]
    prediction_maps = {
        name: {row["example_id"]: row for row in predictions[name]}
        for name in model_names
    }

    def evaluate_slice(
        selected_examples: Sequence[Mapping[str, Any]],
        model_name: str,
    ) -> Dict[str, Any]:
        selected_predictions = [
            prediction_maps[model_name][example["example_id"]]
            for example in selected_examples
        ]
        result = evaluate_next_behavior_predictions(
            selected_examples,
            selected_predictions,
            minimum_target_sessions=minimum_target_sessions,
            minimum_targets=minimum_targets,
            bootstrap_samples=1,
            bootstrap_seed=bootstrap_seed,
        )
        return {
            "example_count": result["example_count"],
            "session_count": result["session_count"],
            "point_metrics": _point_summary(result),
            "reportable_tactics": result["multilabel_tactics"][
                "reportable_classes"
            ],
        }

    per_member: list[dict[str, Any]] = []
    leave_one_out: list[dict[str, Any]] = []
    for member_id in member_order:
        included = [
            example
            for example in examples
            if example["source_member_id"] == member_id
        ]
        if not included:
            per_member.append(
                {
                    "source_member_id": member_id,
                    "status": "no_eligible_examples",
                    "models": {},
                }
            )
        else:
            per_member.append(
                {
                    "source_member_id": member_id,
                    "status": "evaluated",
                    "models": {
                        name: evaluate_slice(included, name)
                        for name in model_names
                    },
                }
            )
        retained = [
            example
            for example in examples
            if example["source_member_id"] != member_id
        ]
        if retained:
            leave_one_out.append(
                {
                    "excluded_source_member_id": member_id,
                    "status": "evaluated",
                    "models": {
                        name: evaluate_slice(retained, name)
                        for name in model_names
                    },
                }
            )
    return {
        "status": "evaluated",
        "member_order": list(member_order),
        "models": model_names,
        "point_semantics": "descriptive_slice_specific_reportability",
        "uncertainty": (
            "full_result_uses_session_cluster_bootstrap_slices_are_point_only"
        ),
        "per_member": per_member,
        "leave_one_member_out": leave_one_out,
    }


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(stable_json(value) + "\n", encoding="utf-8")


def evaluate_frozen_experiment(
    manifest: Mapping[str, Any],
    artifact_paths: Mapping[str, str | Path],
    output_directory: str | Path,
    *,
    purpose: str,
    bootstrap_samples: int = 1000,
    bootstrap_seed: int = DEFAULT_BOOTSTRAP_SEED,
) -> Dict[str, Any]:
    """Run one immutable final evaluation and publish it atomically."""

    destination = Path(output_directory)
    if destination.exists():
        raise FrozenEvaluationError("output directory already exists")
    # This call loads and validates the checkpoint before the test path is used.
    if (
        isinstance(bootstrap_samples, bool)
        or not isinstance(bootstrap_samples, int)
        or bootstrap_samples < 1
    ):
        raise FrozenEvaluationError("bootstrap_samples must be positive")
    if isinstance(bootstrap_seed, bool) or not isinstance(bootstrap_seed, int):
        raise FrozenEvaluationError("bootstrap_seed must be an integer")
    preflight = verify_pre_test_artifacts(
        manifest, artifact_paths, purpose=purpose
    )
    examples = _load_final_examples(preflight)
    transformer_predictions = [
        _transformer_prediction(
            example,
            model=preflight["model"],
            spec=preflight["model_spec"],
            vocabulary=preflight["vocabulary"],
            experiment_policy=preflight["experiment_policy"],
            calibration_mapping=preflight["calibration"],
            checkpoint_sha256=preflight["checkpoint_metadata"][
                "checkpoint_sha256"
            ],
            calibration_membership_sha256=preflight["manifest"][
                "partitions"
            ]["membership_sha256"]["calibration"],
        )
        for example in examples
    ]
    predictions: Dict[str, list[dict[str, Any]]] = {
        "small_causal_transformer": transformer_predictions
    }
    for family, artifact in preflight["baselines"].items():
        predictions[family] = predict_many(artifact, examples)
    expected_ids = [item["example_id"] for item in examples]
    for model_id, rows in predictions.items():
        if [item["example_id"] for item in rows] != expected_ids:
            raise FrozenEvaluationError(f"{model_id} prediction alignment changed")

    selection = preflight["experiment_policy"]["selection"]
    metric_kwargs = {
        "minimum_target_sessions": selection[
            "minimum_independent_target_sessions"
        ],
        "minimum_targets": selection["minimum_targets"],
        "bootstrap_samples": bootstrap_samples,
        "bootstrap_seed": bootstrap_seed,
    }
    metrics = {
        name: evaluate_next_behavior_predictions(examples, rows, **metric_kwargs)
        for name, rows in predictions.items()
    }
    paired = {
        family: paired_model_comparison(
            examples,
            transformer_predictions,
            predictions[family],
            model_a="small_causal_transformer",
            model_b=family,
            **metric_kwargs,
        )
        for family in sorted(preflight["baselines"])
    }
    reportable_tactics = metrics["small_causal_transformer"][
        "multilabel_tactics"
    ]["reportable_classes"]
    calibration_diagnostics = _calibration_diagnostics(
        examples,
        transformer_predictions,
        reportable_tactics=reportable_tactics,
        mapping=preflight["calibration"],
    )
    member_sensitivity = _member_sensitivity(
        examples,
        predictions,
        member_order=preflight.get("test_member_order") or [],
        minimum_target_sessions=selection[
            "minimum_independent_target_sessions"
        ],
        minimum_targets=selection["minimum_targets"],
        bootstrap_seed=bootstrap_seed,
    )
    result = {
        "schema_version": FROZEN_EVALUATION_RESULT_SCHEMA_VERSION,
        "status": "complete",
        "purpose": "final_evaluation",
        "target_contract_id": TARGET_CONTRACT_ID,
        "frozen_manifest_sha256": preflight["manifest_sha256"],
        "artifact_hashes": deepcopy(preflight["manifest"]["artifact_hashes"]),
        "test_membership_sha256": preflight["manifest"]["partitions"][
            "membership_sha256"
        ]["test"],
        "example_count": len(examples),
        "session_count": len({item["session_id"] for item in examples}),
        "methodology": {
            "primary_point_estimate": (
                "all_rows_reportable_tactics_plus_terminal_macro_f1"
            ),
            "uncertainty_unit": "whole_session_cluster_bootstrap",
            "equal_weight_per_session_aggregate": "diagnostic_only",
            "bootstrap_samples": bootstrap_samples,
            "bootstrap_seed": bootstrap_seed,
        },
        "model_ids": sorted(predictions),
        "metrics": metrics,
        "paired_comparisons": paired,
        "calibration_diagnostics": calibration_diagnostics,
        "chronological_member_sensitivity": member_sensitivity,
    }

    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(
        tempfile.mkdtemp(prefix=f".{destination.name}.", dir=destination.parent)
    )
    try:
        _write_json(temporary / "frozen_manifest.json", preflight["manifest"])
        _write_json(temporary / "final_evaluation.json", result)
        for name, rows in predictions.items():
            _write_json(temporary / "predictions" / f"{name}.json", rows)
            _write_json(temporary / "metrics" / f"{name}.json", metrics[name])
        for name, comparison in paired.items():
            _write_json(temporary / "paired" / f"transformer_vs_{name}.json", comparison)
        _write_json(
            temporary / "calibration_diagnostics.json",
            calibration_diagnostics,
        )
        _write_json(
            temporary / "chronological_member_sensitivity.json",
            member_sensitivity,
        )
        file_hashes = {
            str(path.relative_to(temporary)): sha256_file(path)
            for path in sorted(temporary.rglob("*"))
            if path.is_file()
        }
        completion = {
            "schema_version": COMPLETION_SCHEMA_VERSION,
            "status": "complete",
            "frozen_manifest_sha256": preflight["manifest_sha256"],
            "file_hashes": file_hashes,
        }
        _write_json(temporary / "COMPLETED.json", completion)
        os.replace(temporary, destination)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return result


def _artifact_arguments(values: Sequence[str]) -> Dict[str, Path]:
    output: Dict[str, Path] = {}
    for value in values:
        if "=" not in value:
            raise FrozenEvaluationError("artifact must use ROLE=PATH")
        role, raw_path = value.split("=", 1)
        if role in output or role not in REQUIRED_ARTIFACT_ROLES:
            raise FrozenEvaluationError("artifact role is invalid or duplicated")
        output[role] = Path(raw_path)
    if set(output) != set(REQUIRED_ARTIFACT_ROLES):
        raise FrozenEvaluationError("every required artifact role must be supplied")
    return output


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--artifact", action="append", default=[])
    parser.add_argument("--output", required=True)
    parser.add_argument("--purpose", required=True)
    parser.add_argument("--bootstrap-samples", type=int, default=1000)
    parser.add_argument("--bootstrap-seed", type=int, default=DEFAULT_BOOTSTRAP_SEED)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    manifest = _read_json(Path(args.manifest), role="evaluation manifest")
    paths = _artifact_arguments(args.artifact)
    evaluate_frozen_experiment(
        manifest,
        paths,
        args.output,
        purpose=args.purpose,
        bootstrap_samples=args.bootstrap_samples,
        bootstrap_seed=args.bootstrap_seed,
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
