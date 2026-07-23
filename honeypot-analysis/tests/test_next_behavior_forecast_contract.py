from __future__ import annotations

import copy
import hashlib

import pytest

from production.prediction.next_behavior_contract import SESSION_SCHEMA_VERSION
from production.prediction.next_behavior_forecast_contract import (
    FIXED_AUTHORITY,
    FORECAST_SCHEMA_VERSION,
    NextBehaviorForecastContractError,
    bind_forecast_input,
    forecast_id_for,
    require_valid_next_behavior_forecast,
    validate_next_behavior_forecast,
)
from production.prediction.next_behavior_preprocessing import (
    build_live_model_input,
)


HASH_A = "a" * 64
HASH_B = "b" * 64


def _opaque(kind: str, value: str) -> str:
    return f"nb{kind}_{hashlib.sha256(value.encode()).hexdigest()}"


def _model_input() -> dict:
    evidence_ref = _opaque("evidence", "one")
    session = {
        "schema_version": SESSION_SCHEMA_VERSION,
        "session_id": _opaque("session", "one"),
        "source_member_id": _opaque("member", "one"),
        "source_member_sha256": HASH_A,
        "protocol": "ssh",
        "status": "active",
        "observation_groups": [
            {
                "group_id": _opaque("group", "one"),
                "event_order": 1,
                "relative_time_ms": 0,
                "tactics": ["discovery"],
                "techniques": ["T1082"],
                "evidence_refs": [evidence_ref],
                "label_provenance": [
                    {
                        "tactic": "discovery",
                        "technique": "T1082",
                        "source": "reviewed_rule",
                        "trust_tier": "trusted_observation",
                        "policy_sha256": HASH_A,
                        "trust_policy_sha256": HASH_B,
                        "checkpoint_sha256": "",
                        "confidence": 1.0,
                        "confidence_bucket": "high",
                        "agreement_status": "rule_only",
                        "evidence_ref": evidence_ref,
                    }
                ],
                "session_context": {
                    "login_outcome": "success",
                    "command_count_bucket": "1",
                    "session_age_bucket": "under_10s",
                    "confirmed_transfer_observed": False,
                },
            }
        ],
    }
    return bind_forecast_input(
        build_live_model_input(session),
        preprocessing_sha256=HASH_A,
        vocabulary_sha256=HASH_B,
    )


def _forecast() -> dict:
    model_input = _model_input()
    observed_at = "2026-07-23T10:00:00Z"
    model_id = "small-causal-transformer-v3-fixture"
    return {
        "schema_version": FORECAST_SCHEMA_VERSION,
        "forecast_id": forecast_id_for(
            session_id=_opaque("session", "one"),
            observation_timestamp=observed_at,
            model_id=model_id,
            input_hash=model_input["input_hash"],
        ),
        "session_id": _opaque("session", "one"),
        "observation_timestamp": observed_at,
        "generated_at": "2026-07-23T10:00:01Z",
        "status": "predicted",
        "status_reason": {
            "code": "prediction_available",
            "text": "A frozen experimental model produced raw rank scores.",
        },
        "model": {
            "role": "experimental_primary",
            "model_id": model_id,
            "model_family": "small_causal_transformer",
            "checkpoint_sha256": HASH_A,
            "artifact_sha256": "",
            "manifest_id": "next-behavior-experiment-fixture",
            "code_commit": "test-commit",
            "device": "cpu",
            "dtype": "float32",
        },
        "input": model_input,
        "output": {
            "ranked_tactics": [
                {
                    "tactic": "execution",
                    "raw_score": 1.25,
                    "rank": 1,
                    "calibrated_probability": None,
                },
                {
                    "tactic": "persistence",
                    "raw_score": -0.4,
                    "rank": 2,
                    "calibrated_probability": None,
                },
            ],
            "terminal_outcome": {
                "label": "session_end_no_further_trusted_behavior",
                "raw_score": 0.1,
                "calibrated_probability": None,
            },
            "prediction_set": [],
            "score_semantics": "raw_model_scores_not_probabilities",
            "calibration": {
                "status": "not_implemented",
                "method": "",
                "mapping_sha256": "",
                "fit_partition_membership_sha256": "",
            },
            "abstention": {
                "abstained": False,
                "reason_code": "",
                "coverage_policy_id": "",
            },
        },
        "baseline": {
            "status": "available",
            "model_id": "same-target-hard-backoff-vomm",
            "artifact_sha256": HASH_B,
            "ranked_tactics": [
                {
                    "tactic": "execution",
                    "raw_score": 0.7,
                    "rank": 1,
                    "calibrated_probability": None,
                }
            ],
            "terminal_outcome": {
                "label": "session_end_no_further_trusted_behavior",
                "raw_score": 0.3,
                "calibrated_probability": None,
            },
            "authority": "interpretable_disagreement_reference_only",
        },
        "disagreement": {
            "status": "agree",
            "top_tactic_differs": False,
            "terminal_decision_differs": False,
            "semantics": "diagnostic_only_no_score_blending_no_routing",
        },
        "authority": copy.deepcopy(FIXED_AUTHORITY),
        "audit": {
            "historical_snapshot": False,
            "recomputed": False,
            "supersedes_forecast_id": "",
            "retention_policy_id": "experimental-v3-retention",
            "redaction_policy_version": "next-behavior-safe-v1",
            "failure_codes": [],
        },
    }


def test_complete_raw_score_forecast_is_valid() -> None:
    value = _forecast()

    assert validate_next_behavior_forecast(value) == []
    assert require_valid_next_behavior_forecast(value) == value


def test_forged_authority_and_unknown_nested_fields_are_rejected() -> None:
    value = _forecast()
    value["authority"]["may_create_alert_alone"] = True
    value["output"]["ranked_tactics"][0]["action"] = "block-source"

    errors = validate_next_behavior_forecast(value)

    assert any("fixed non-authoritative" in error for error in errors)
    assert any("action is not defined" in error for error in errors)


def test_raw_scores_cannot_be_labeled_probabilities_without_mapping() -> None:
    value = _forecast()
    value["output"]["ranked_tactics"][0]["calibrated_probability"] = 0.9
    value["output"]["prediction_set"] = ["execution"]

    errors = validate_next_behavior_forecast(value)

    assert any("must be null when uncalibrated" in error for error in errors)
    assert any("requires valid calibration" in error for error in errors)


@pytest.mark.parametrize("bad_score", [float("nan"), float("inf"), True, "0.9"])
def test_nonfinite_or_coerced_scores_fail_closed(bad_score) -> None:
    value = _forecast()
    value["output"]["ranked_tactics"][0]["raw_score"] = bad_score

    assert any(
        "finite number" in error
        for error in validate_next_behavior_forecast(value)
    )


def test_prediction_status_and_abstention_cannot_contradict() -> None:
    value = _forecast()
    value["status"] = "model_unavailable"
    value["status_reason"] = {
        "code": "artifact_missing",
        "text": "A required frozen model artifact is unavailable.",
    }

    errors = validate_next_behavior_forecast(value)

    assert any("cannot contain ranked_tactics" in error for error in errors)
    assert any("must be abstained" in error for error in errors)


def test_forged_or_malformed_input_is_rejected_at_forecast_boundary() -> None:
    value = _forecast()
    value["input"]["phase_sequence"][0]["evidence_refs"] = []
    value["input"]["session_context"]["source_ip"] = "192.0.2.1"

    errors = validate_next_behavior_forecast(value)

    assert any("does not match phase evidence" in error for error in errors)
    assert any("source_ip is not defined" in error for error in errors)


def test_copied_input_hash_cannot_cover_mutated_causal_features() -> None:
    value = _forecast()
    value["input"]["phase_sequence"][0]["tactics"] = ["execution"]

    errors = validate_next_behavior_forecast(value)

    assert any("input_hash does not match" in error for error in errors)


def test_baseline_nested_predictions_are_strictly_validated() -> None:
    value = _forecast()
    value["baseline"]["terminal_outcome"]["action"] = "block-source"
    value["baseline"]["ranked_tactics"][0]["raw_score"] = float("nan")

    errors = validate_next_behavior_forecast(value)

    assert any("action is not defined" in error for error in errors)
    assert any("finite number" in error for error in errors)


def test_model_unavailable_payload_has_no_scores_and_is_valid() -> None:
    value = _forecast()
    value["status"] = "model_unavailable"
    value["status_reason"] = {
        "code": "artifact_missing",
        "text": "A required frozen model artifact is unavailable.",
    }
    value["output"]["ranked_tactics"] = []
    value["output"]["terminal_outcome"]["raw_score"] = None
    value["output"]["abstention"] = {
        "abstained": True,
        "reason_code": "artifact_missing",
        "coverage_policy_id": "",
    }

    assert validate_next_behavior_forecast(value) == []


def test_binding_requires_exact_preprocessing_and_vocabulary_hashes() -> None:
    unbound = _model_input()
    unbound.pop("preprocessing_sha256")
    unbound.pop("vocabulary_sha256")

    with pytest.raises(
        NextBehaviorForecastContractError,
        match="hashes are required",
    ):
        bind_forecast_input(
            unbound,
            preprocessing_sha256="not-a-hash",
            vocabulary_sha256=HASH_B,
        )


def test_validator_raises_on_invalid_payload() -> None:
    value = _forecast()
    value["model"]["checkpoint_sha256"] = "wrong"

    with pytest.raises(
        NextBehaviorForecastContractError,
        match="checkpoint_sha256",
    ):
        require_valid_next_behavior_forecast(value)
