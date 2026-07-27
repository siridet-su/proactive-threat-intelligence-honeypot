from __future__ import annotations

import copy
import math

import pytest

from production.reproduction.next_behavior.calibration import (
    CALIBRATION_METHOD,
    MAX_TEMPERATURE,
    MIN_TEMPERATURE,
    RAW_SCORE_SEMANTICS,
    NextBehaviorCalibrationError,
    apply_temperature_mapping,
    build_not_implemented_mapping,
    fit_temperature_mapping,
    require_valid_calibration_mapping,
    validate_calibration_mapping,
)
from production.prediction.next_behavior_contract import (
    TACTIC_VOCABULARY,
    TARGET_CONTRACT_ID,
    TERMINAL_OUTCOME,
)
from production.reproduction.next_behavior.partitions import membership_sha256


HASH_A = "a" * 64
HASH_B = "b" * 64
HASH_C = "c" * 64
HASH_D = "d" * 64
EXAMPLE_A = "nextbehaviorexample_" + "1" * 32
EXAMPLE_B = "nextbehaviorexample_" + "2" * 32


def _row(
    example_id: str,
    *,
    terminal_target: bool,
    target_tactics: list[str],
) -> dict:
    logits = {
        tactic: (index - 6.0) / 3.0
        for index, tactic in enumerate(sorted(TACTIC_VOCABULARY))
    }
    if target_tactics:
        logits[target_tactics[0]] = 2.5
    return {
        "example_id": example_id,
        "partition_role": "calibration",
        "target_contract_id": TARGET_CONTRACT_ID,
        "score_semantics": RAW_SCORE_SEMANTICS,
        "checkpoint_sha256": HASH_A,
        "vocabulary_sha256": HASH_B,
        "preprocessing_sha256": HASH_C,
        "tactic_logits": logits,
        "target_tactics": target_tactics,
        "terminal_logit": 2.0 if terminal_target else -1.5,
        "terminal_target": terminal_target,
    }


def _rows() -> list[dict]:
    return [
        _row(
            EXAMPLE_A,
            terminal_target=False,
            target_tactics=["execution"],
        ),
        _row(
            EXAMPLE_B,
            terminal_target=True,
            target_tactics=[],
        ),
    ]


def _fit(rows: list[dict] | None = None) -> dict:
    return fit_temperature_mapping(
        rows or _rows(),
        calibration_example_ids=[EXAMPLE_A, EXAMPLE_B],
        fit_partition_membership_sha256=membership_sha256(
            [EXAMPLE_A, EXAMPLE_B]
        ),
        checkpoint_sha256=HASH_A,
        vocabulary_sha256=HASH_B,
        preprocessing_sha256=HASH_C,
    )


def _raw_output() -> dict:
    return {
        "ranked_tactics": [
            {
                "tactic": "execution",
                "raw_score": 2.0,
                "rank": 1,
                "calibrated_probability": None,
            },
            {
                "tactic": "discovery",
                "raw_score": 0.25,
                "rank": 2,
                "calibrated_probability": None,
            },
            {
                "tactic": "persistence",
                "raw_score": -1.0,
                "rank": 3,
                "calibrated_probability": None,
            },
        ],
        "terminal_outcome": {
            "label": TERMINAL_OUTCOME,
            "raw_score": -0.4,
            "calibrated_probability": None,
        },
        "prediction_set": [],
        "score_semantics": RAW_SCORE_SEMANTICS,
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
    }


def _apply(raw_output: dict, mapping: dict | None = None) -> dict:
    return apply_temperature_mapping(
        raw_output,
        mapping or _fit(),
        fit_partition_membership_sha256=membership_sha256(
            [EXAMPLE_A, EXAMPLE_B]
        ),
        checkpoint_sha256=HASH_A,
        vocabulary_sha256=HASH_B,
        preprocessing_sha256=HASH_C,
    )


def test_fit_is_deterministic_and_contains_only_two_global_temperatures() -> None:
    first = _fit()
    second = _fit()
    reversed_rows = list(reversed(_rows()))
    third = _fit(reversed_rows)

    assert first == second == third
    assert first["status"] == "valid"
    assert first["method"] == CALIBRATION_METHOD
    assert MIN_TEMPERATURE <= first["tactic_temperature"] <= MAX_TEMPERATURE
    assert MIN_TEMPERATURE <= first["terminal_temperature"] <= MAX_TEMPERATURE
    assert "class_temperatures" not in first
    assert require_valid_calibration_mapping(first) == first


def test_not_implemented_is_explicit_and_cannot_be_applied() -> None:
    mapping = build_not_implemented_mapping(
        fit_partition_membership_sha256=membership_sha256(
            [EXAMPLE_A, EXAMPLE_B]
        ),
        checkpoint_sha256=HASH_A,
        vocabulary_sha256=HASH_B,
        preprocessing_sha256=HASH_C,
    )

    assert mapping["status"] == "not_implemented"
    assert mapping["tactic_temperature"] is None
    assert mapping["terminal_temperature"] is None
    assert mapping["mapping_sha256"] == ""
    with pytest.raises(
        NextBehaviorCalibrationError,
        match="not implemented",
    ):
        _apply(_raw_output(), mapping)


def test_membership_hash_and_exact_fit_rows_are_both_required() -> None:
    with pytest.raises(
        NextBehaviorCalibrationError,
        match="supplied calibration membership",
    ):
        fit_temperature_mapping(
            _rows(),
            calibration_example_ids=[EXAMPLE_A, EXAMPLE_B],
            fit_partition_membership_sha256=HASH_D,
            checkpoint_sha256=HASH_A,
            vocabulary_sha256=HASH_B,
            preprocessing_sha256=HASH_C,
        )

    rows = _rows()
    rows.pop()
    with pytest.raises(
        NextBehaviorCalibrationError,
        match="exactly match",
    ):
        _fit(rows)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (
            lambda row: row.__setitem__("partition_role", "selection"),
            "partition_role must be calibration",
        ),
        (
            lambda row: row.__setitem__("target_contract_id", "old-target.v2"),
            "corrected target",
        ),
        (
            lambda row: row.__setitem__("checkpoint_sha256", HASH_D),
            "checkpoint_sha256 does not match",
        ),
        (
            lambda row: row.__setitem__("vocabulary_sha256", HASH_D),
            "vocabulary_sha256 does not match",
        ),
        (
            lambda row: row.__setitem__("preprocessing_sha256", HASH_D),
            "preprocessing_sha256 does not match",
        ),
    ],
)
def test_fit_provenance_mismatch_fails_closed(mutation, message: str) -> None:
    rows = _rows()
    mutation(rows[0])

    with pytest.raises(NextBehaviorCalibrationError, match=message):
        _fit(rows)


def test_fit_refuses_scores_described_as_probabilities() -> None:
    rows = _rows()
    rows[0]["score_semantics"] = "probabilities"

    with pytest.raises(
        NextBehaviorCalibrationError,
        match="raw_model_scores_not_probabilities",
    ):
        _fit(rows)


def test_mapping_hash_detects_mutation_and_class_specific_extensions() -> None:
    mapping = _fit()
    mapping["tactic_temperature"] *= 1.1

    assert any(
        "mapping_sha256 does not match" in error
        for error in validate_calibration_mapping(mapping)
    )

    mapping = _fit()
    mapping["class_temperatures"] = {"execution": 0.5}
    assert any(
        "class_temperatures is not defined" in error
        for error in validate_calibration_mapping(mapping)
    )


@pytest.mark.parametrize(
    ("binding", "message"),
    [
        ("fit_partition_membership_sha256", "membership_sha256 mismatch"),
        ("checkpoint_sha256", "checkpoint_sha256 mismatch"),
        ("vocabulary_sha256", "vocabulary_sha256 mismatch"),
        ("preprocessing_sha256", "preprocessing_sha256 mismatch"),
    ],
)
def test_apply_rejects_every_provenance_mismatch(
    binding: str,
    message: str,
) -> None:
    kwargs = {
        "fit_partition_membership_sha256": membership_sha256(
            [EXAMPLE_A, EXAMPLE_B]
        ),
        "checkpoint_sha256": HASH_A,
        "vocabulary_sha256": HASH_B,
        "preprocessing_sha256": HASH_C,
    }
    kwargs[binding] = HASH_D

    with pytest.raises(NextBehaviorCalibrationError, match=message):
        apply_temperature_mapping(_raw_output(), _fit(), **kwargs)


def test_apply_requires_mapping_and_raw_score_semantics() -> None:
    with pytest.raises(NextBehaviorCalibrationError, match="mapping is missing"):
        apply_temperature_mapping(
            _raw_output(),
            None,
            fit_partition_membership_sha256=membership_sha256(
                [EXAMPLE_A, EXAMPLE_B]
            ),
            checkpoint_sha256=HASH_A,
            vocabulary_sha256=HASH_B,
            preprocessing_sha256=HASH_C,
        )

    output = _raw_output()
    output["score_semantics"] = "already_probabilities"
    with pytest.raises(
        NextBehaviorCalibrationError,
        match="raw_model_scores_not_probabilities",
    ):
        _apply(output)


def test_apply_uses_sigmoid_but_preserves_raw_scores_and_tactic_ranks() -> None:
    raw = _raw_output()
    before = copy.deepcopy(raw)
    mapping = _fit()

    calibrated = _apply(raw, mapping)

    assert raw == before
    assert calibrated["score_semantics"] == RAW_SCORE_SEMANTICS
    assert [
        (item["tactic"], item["raw_score"], item["rank"])
        for item in calibrated["ranked_tactics"]
    ] == [
        (item["tactic"], item["raw_score"], item["rank"])
        for item in before["ranked_tactics"]
    ]
    expected = 1.0 / (
        1.0 + math.exp(-2.0 / mapping["tactic_temperature"])
    )
    assert calibrated["ranked_tactics"][0]["calibrated_probability"] == (
        pytest.approx(expected)
    )
    probabilities = [
        item["calibrated_probability"]
        for item in calibrated["ranked_tactics"]
    ]
    assert probabilities == sorted(probabilities, reverse=True)
    assert all(0.0 <= value <= 1.0 for value in probabilities)
    assert calibrated["calibration"] == {
        "status": "valid",
        "method": CALIBRATION_METHOD,
        "mapping_sha256": mapping["mapping_sha256"],
        "fit_partition_membership_sha256": mapping[
            "fit_partition_membership_sha256"
        ],
    }
