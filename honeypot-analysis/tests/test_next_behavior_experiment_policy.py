from __future__ import annotations

import copy
from pathlib import Path

import pytest

from production.prediction.next_behavior_contract import (
    LEGACY_TARGET_CONTRACT_ID,
    TARGET_CONTRACT_ID,
)
from production.reproduction.next_behavior.experiment_policy import (
    DECLARED_SEEDS,
    EXPERIMENT_POLICY_SCHEMA_VERSION,
    LEGACY_EXPERIMENT_POLICY_SCHEMA_VERSION,
    NextBehaviorExperimentPolicyError,
    experiment_policy_sha256,
    load_experiment_policy,
    require_current_experiment_policy,
    require_valid_experiment_policy,
)


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "configs" / "next_behavior_experiment_policy.v1.json"
POLICY_V2_PATH = ROOT / "configs" / "next_behavior_experiment_policy.v2.json"


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


def test_repository_policies_preserve_v1_and_bind_v2_target() -> None:
    legacy = load_experiment_policy(POLICY_PATH)
    current = load_experiment_policy(POLICY_V2_PATH)

    assert legacy["schema_version"] == LEGACY_EXPERIMENT_POLICY_SCHEMA_VERSION
    assert legacy["target_contract_id"] == LEGACY_TARGET_CONTRACT_ID
    assert current["schema_version"] == EXPERIMENT_POLICY_SCHEMA_VERSION
    assert current["target_contract_id"] == TARGET_CONTRACT_ID
    assert current["architecture"] == legacy["architecture"]
    assert current["training"] == legacy["training"]
    assert experiment_policy_sha256(current) != experiment_policy_sha256(legacy)

    with pytest.raises(NextBehaviorExperimentPolicyError, match="requires the v2"):
        require_current_experiment_policy(legacy)
    assert require_current_experiment_policy(current) == current


@pytest.mark.parametrize(
    ("path", "schema_version", "target_contract_id"),
    [
        (POLICY_PATH, LEGACY_EXPERIMENT_POLICY_SCHEMA_VERSION, TARGET_CONTRACT_ID),
        (POLICY_V2_PATH, EXPERIMENT_POLICY_SCHEMA_VERSION, LEGACY_TARGET_CONTRACT_ID),
    ],
)
def test_policy_schema_cannot_claim_the_other_target_contract(
    path: Path,
    schema_version: str,
    target_contract_id: str,
) -> None:
    policy = load_experiment_policy(path)
    policy["schema_version"] = schema_version
    policy["target_contract_id"] = target_contract_id

    with pytest.raises(NextBehaviorExperimentPolicyError, match="schema version"):
        require_valid_experiment_policy(policy)


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
