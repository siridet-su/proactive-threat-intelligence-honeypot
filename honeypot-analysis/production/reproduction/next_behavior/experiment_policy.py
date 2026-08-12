"""Strict loader for the pre-test corrected-target experiment policy."""

from __future__ import annotations

import hashlib
import json
import re
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict

from production.prediction.next_behavior_contract import (
    LEGACY_TARGET_CONTRACT_ID as TARGET_CONTRACT_ID,
)
from production.prediction.next_behavior_model import ARCHITECTURE, MODEL_FAMILY
from production.utils.serialization import stable_json

EXPERIMENT_POLICY_SCHEMA_VERSION = "next_behavior_experiment_policy.v1"
CALIBRATION_METHOD = "global_scalar_temperature_sigmoid.v1"
DECLARED_SEEDS = (20260721, 20260722, 20260723, 20260724, 20260725)
DECLARED_BASELINES = (
    "majority_terminal_prevalence",
    "first_order_phase_state_markov",
    "hard_backoff_vomm",
    "interpolated_vomm",
)
DECLARED_TIE_BREAKERS = (
    "session_clustered_balanced_accuracy",
    "lower_worst_reportable_class_recall_regression_vs_hard_backoff_vomm",
    "terminal_f1",
    "lower_p95_cpu_single_case_latency",
    "lower_seed",
)

_POLICY_ID = re.compile(r"^[a-z0-9_.-]{1,120}$")


class NextBehaviorExperimentPolicyError(ValueError):
    """Raised when the frozen training/evaluation policy is incomplete."""


def experiment_policy_sha256(value: Dict[str, Any]) -> str:
    """Hash the exact validated semantic policy."""

    return hashlib.sha256(stable_json(value).encode("utf-8")).hexdigest()


def _require_exact_keys(
    value: Any,
    keys: set[str],
    path: str,
) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise NextBehaviorExperimentPolicyError(f"{path} must be an object")
    if set(value) != keys:
        raise NextBehaviorExperimentPolicyError(
            f"{path} fields do not match the frozen contract"
        )
    return value


def _positive_number(value: Any, path: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or float(value) <= 0.0
    ):
        raise NextBehaviorExperimentPolicyError(f"{path} must be positive")
    return float(value)


def _exact_list(value: Any, expected: tuple[Any, ...], path: str) -> bool:
    return isinstance(value, list) and tuple(value) == expected


def require_valid_experiment_policy(value: Any) -> Dict[str, Any]:
    """Validate every choice that must be fixed before final-test access."""

    root = _require_exact_keys(
        value,
        {
            "schema_version",
            "policy_id",
            "target_contract_id",
            "model_family",
            "architecture",
            "training",
            "prediction_decision",
            "selection",
            "calibration",
            "abstention",
            "baselines",
            "runtime_budgets",
            "authority",
        },
        "$",
    )
    if root["schema_version"] != EXPERIMENT_POLICY_SCHEMA_VERSION:
        raise NextBehaviorExperimentPolicyError("policy schema_version is invalid")
    if not isinstance(root["policy_id"], str) or not _POLICY_ID.fullmatch(
        root["policy_id"]
    ):
        raise NextBehaviorExperimentPolicyError("policy_id is invalid")
    if root["target_contract_id"] != TARGET_CONTRACT_ID:
        raise NextBehaviorExperimentPolicyError("target contract is invalid")
    if root["model_family"] != MODEL_FAMILY:
        raise NextBehaviorExperimentPolicyError("model family is invalid")
    if root["architecture"] != ARCHITECTURE:
        raise NextBehaviorExperimentPolicyError(
            "architecture does not match the frozen model"
        )

    training = _require_exact_keys(
        root["training"],
        {
            "seeds",
            "epochs",
            "batch_size",
            "optimizer",
            "learning_rate",
            "weight_decay",
            "shuffle_each_epoch",
            "deterministic_algorithms",
            "device",
            "tactic_loss",
            "terminal_loss",
            "combined_loss",
            "early_stopping",
            "feature_ablation_search",
        },
        "$.training",
    )
    if not _exact_list(training["seeds"], DECLARED_SEEDS, "$.training.seeds"):
        raise NextBehaviorExperimentPolicyError("training seeds are not frozen")
    if training["epochs"] != 6 or training["batch_size"] != 2048:
        raise NextBehaviorExperimentPolicyError(
            "training epochs or batch size changed"
        )
    if (
        training["optimizer"] != "adam"
        or training["learning_rate"] != 0.003
        or training["weight_decay"] != 0.0
        or training["device"] != "cpu"
    ):
        raise NextBehaviorExperimentPolicyError("optimizer contract changed")
    expected_training = {
        "shuffle_each_epoch": True,
        "deterministic_algorithms": True,
        "tactic_loss": "binary_cross_entropy_with_logits_mean",
        "terminal_loss": "binary_cross_entropy_with_logits_mean",
        "combined_loss": "tactic_loss_plus_terminal_loss",
        "early_stopping": False,
        "feature_ablation_search": False,
    }
    if any(training[key] != expected for key, expected in expected_training.items()):
        raise NextBehaviorExperimentPolicyError(
            "training objective or determinism contract changed"
        )

    decision = _require_exact_keys(
        root["prediction_decision"],
        {
            "score_semantics",
            "terminal_rule",
            "tactic_rule",
            "empty_nonterminal_rule",
            "ranking_rule",
            "prediction_set_threshold_source",
        },
        "$.prediction_decision",
    )
    expected_decision = {
        "score_semantics": "raw_model_scores_not_probabilities",
        "terminal_rule": "terminal_logit_greater_than_or_equal_to_zero",
        "tactic_rule": "each_tactic_logit_greater_than_or_equal_to_zero",
        "empty_nonterminal_rule": "select_highest_ranked_tactic",
        "ranking_rule": "descending_raw_logit_then_lexical_tactic",
        "prediction_set_threshold_source": "fixed_before_model_fitting",
    }
    if decision != expected_decision:
        raise NextBehaviorExperimentPolicyError("prediction decision rule changed")

    selection = _require_exact_keys(
        root["selection"],
        {
            "partition_role",
            "minimum_targets",
            "minimum_independent_target_sessions",
            "primary_metric",
            "tie_breakers",
            "high_consequence_tactics",
            "maximum_high_consequence_recall_regression",
            "reject_reportable_class_zero_recall_collapse",
            "test_metrics_used",
        },
        "$.selection",
    )
    if (
        selection["partition_role"] != "selection"
        or selection["minimum_targets"] != 30
        or selection["minimum_independent_target_sessions"] != 30
        or selection["primary_metric"]
        != (
            "macro_f1_reportable_tactics_plus_terminal_with_"
            "whole_session_cluster_bootstrap"
        )
        or not _exact_list(
            selection["tie_breakers"],
            DECLARED_TIE_BREAKERS,
            "$.selection.tie_breakers",
        )
        or selection["high_consequence_tactics"] != ["execution"]
        or selection["maximum_high_consequence_recall_regression"] != 0.1
        or selection["reject_reportable_class_zero_recall_collapse"] is not True
        or selection["test_metrics_used"] is not False
    ):
        raise NextBehaviorExperimentPolicyError("selection policy changed")

    calibration = _require_exact_keys(
        root["calibration"],
        {
            "partition_role",
            "method",
            "tactic_mapping",
            "terminal_mapping",
            "class_specific_mapping_allowed",
            "changes_ranking",
            "changes_prediction_set",
        },
        "$.calibration",
    )
    if calibration != {
        "partition_role": "calibration",
        "method": CALIBRATION_METHOD,
        "tactic_mapping": "one_positive_global_temperature",
        "terminal_mapping": "one_positive_global_temperature",
        "class_specific_mapping_allowed": False,
        "changes_ranking": False,
        "changes_prediction_set": False,
    }:
        raise NextBehaviorExperimentPolicyError("calibration policy changed")

    abstention = _require_exact_keys(
        root["abstention"],
        {
            "model_unavailable",
            "schema_or_hash_mismatch",
            "missing_required_features",
            "uncertainty_threshold",
            "fallback_model",
        },
        "$.abstention",
    )
    if abstention != {
        "model_unavailable": True,
        "schema_or_hash_mismatch": True,
        "missing_required_features": True,
        "uncertainty_threshold": None,
        "fallback_model": None,
    }:
        raise NextBehaviorExperimentPolicyError("abstention policy changed")

    baselines = _require_exact_keys(
        root["baselines"],
        {
            "families",
            "maximum_order",
            "include_zero_order",
            "interpolation_decay",
            "same_training_membership_required",
        },
        "$.baselines",
    )
    if (
        not _exact_list(
            baselines["families"],
            DECLARED_BASELINES,
            "$.baselines.families",
        )
        or baselines["maximum_order"] != 8
        or baselines["include_zero_order"] is not False
        or baselines["interpolation_decay"] != 0.5
        or baselines["same_training_membership_required"] is not True
    ):
        raise NextBehaviorExperimentPolicyError("baseline policy changed")

    budgets = _require_exact_keys(
        root["runtime_budgets"],
        {
            "device",
            "maximum_checkpoint_bytes",
            "maximum_checkpoint_load_seconds",
            "maximum_p95_single_case_latency_ms",
            "maximum_process_rss_delta_bytes",
        },
        "$.runtime_budgets",
    )
    if budgets["device"] != "cpu":
        raise NextBehaviorExperimentPolicyError("runtime device must be cpu")
    for field in (
        "maximum_checkpoint_bytes",
        "maximum_checkpoint_load_seconds",
        "maximum_p95_single_case_latency_ms",
        "maximum_process_rss_delta_bytes",
    ):
        _positive_number(budgets[field], f"$.runtime_budgets.{field}")

    authority = _require_exact_keys(
        root["authority"],
        {
            "offline_experiment_only",
            "production_change_allowed",
            "prediction_can_authorize_alerts_guidance_recommendations_or_actions",
        },
        "$.authority",
    )
    if authority != {
        "offline_experiment_only": True,
        "production_change_allowed": False,
        "prediction_can_authorize_alerts_guidance_recommendations_or_actions": False,
    }:
        raise NextBehaviorExperimentPolicyError("authority boundary changed")
    return deepcopy(root)


def load_experiment_policy(path: str | Path) -> Dict[str, Any]:
    """Load one policy without accepting duplicate keys or trailing content."""

    source = Path(path)
    if not source.is_file():
        raise NextBehaviorExperimentPolicyError("experiment policy is missing")

    def no_duplicates(pairs: list[tuple[str, Any]]) -> Dict[str, Any]:
        output: Dict[str, Any] = {}
        for key, item in pairs:
            if key in output:
                raise NextBehaviorExperimentPolicyError(
                    f"experiment policy contains duplicate key: {key}"
                )
            output[key] = item
        return output

    try:
        value = json.loads(
            source.read_text(encoding="utf-8"),
            object_pairs_hook=no_duplicates,
        )
    except NextBehaviorExperimentPolicyError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise NextBehaviorExperimentPolicyError(
            "experiment policy cannot be parsed"
        ) from exc
    return require_valid_experiment_policy(value)
