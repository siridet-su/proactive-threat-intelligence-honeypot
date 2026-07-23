from __future__ import annotations

import copy
from pathlib import Path

import pytest

from production.prediction.next_behavior_experiment_policy import (
    DECLARED_SEEDS,
    NextBehaviorExperimentPolicyError,
    experiment_policy_sha256,
    load_experiment_policy,
    require_valid_experiment_policy,
)


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "configs" / "next_behavior_experiment_policy.v1.json"


def _policy() -> dict:
    return load_experiment_policy(POLICY_PATH)


def test_repository_policy_freezes_all_pre_test_choices() -> None:
    policy = _policy()

    assert tuple(policy["training"]["seeds"]) == DECLARED_SEEDS
    assert policy["training"]["epochs"] == 6
    assert policy["training"]["device"] == "cpu"
    assert policy["prediction_decision"]["score_semantics"] == (
        "raw_model_scores_not_probabilities"
    )
    assert policy["selection"]["test_metrics_used"] is False
    assert policy["selection"]["primary_metric"].endswith(
        "with_whole_session_cluster_bootstrap"
    )
    assert policy["calibration"]["class_specific_mapping_allowed"] is False
    assert policy["abstention"]["fallback_model"] is None
    assert policy["authority"]["production_change_allowed"] is False
    assert len(experiment_policy_sha256(policy)) == 64


@pytest.mark.parametrize(
    ("path", "value", "message"),
    [
        (("training", "seeds"), [20260723], "seeds"),
        (("training", "epochs"), 7, "epochs"),
        (("training", "device"), "cuda", "optimizer"),
        (
            ("prediction_decision", "tactic_rule"),
            "chosen_after_test",
            "decision",
        ),
        (("selection", "test_metrics_used"), True, "selection"),
        (
            ("selection", "maximum_high_consequence_recall_regression"),
            0.5,
            "selection",
        ),
        (
            ("calibration", "class_specific_mapping_allowed"),
            True,
            "calibration",
        ),
        (("abstention", "fallback_model"), "vomm", "abstention"),
        (("authority", "production_change_allowed"), True, "authority"),
    ],
)
def test_policy_rejects_post_freeze_mutations(
    path: tuple[str, str],
    value,
    message: str,
) -> None:
    policy = _policy()
    policy[path[0]][path[1]] = value

    with pytest.raises(NextBehaviorExperimentPolicyError, match=message):
        require_valid_experiment_policy(policy)


def test_policy_rejects_unknown_fields_and_architecture_changes() -> None:
    policy = _policy()
    policy["new_post_test_rule"] = True
    with pytest.raises(NextBehaviorExperimentPolicyError, match="fields"):
        require_valid_experiment_policy(policy)

    policy = _policy()
    policy["architecture"]["attention_heads"] = 2
    with pytest.raises(NextBehaviorExperimentPolicyError, match="architecture"):
        require_valid_experiment_policy(policy)


def test_hash_is_deterministic_and_semantic() -> None:
    policy = _policy()
    assert experiment_policy_sha256(policy) == experiment_policy_sha256(
        copy.deepcopy(policy)
    )
