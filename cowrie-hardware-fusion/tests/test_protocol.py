from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from cowrie_hardware_fusion.batch import canonical_sha256
from cowrie_hardware_fusion.dataset import DatasetContractError
from cowrie_hardware_fusion.protocol import validate_hardware_impact_protocol


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _protocol() -> dict:
    return json.loads(
        (
            PROJECT_ROOT
            / "configs"
            / "hardware_impact_experiment_protocol.v2.json"
        ).read_text(encoding="utf-8")
    )


def _rehash(document: dict) -> None:
    without_hash = dict(document)
    without_hash.pop("protocol_sha256", None)
    document["protocol_sha256"] = canonical_sha256(without_hash)


def test_frozen_protocol_validates_and_plans_independent_waves() -> None:
    protocol = _protocol()
    schema = json.loads(
        (
            PROJECT_ROOT
            / "schemas"
            / "hardware_impact_experiment_protocol.v2.schema.json"
        ).read_text(encoding="utf-8")
    )
    Draft202012Validator(schema).validate(protocol)

    summary = validate_hardware_impact_protocol(protocol)

    assert summary["scenario_count"] == 7
    assert summary["repetitions_per_scenario"] == 20
    assert summary["planned_run_count"] == 140
    assert summary["planned_sample_count"] == 12_600
    assert summary["partition_run_counts"] == {
        "development_train": 70,
        "calibration": 35,
        "final_test": 35,
    }
    assert summary["impact_scenario_counts"] == {
        "COMPUTE_SATURATION": 2,
        "NO_MATERIAL_IMPACT": 3,
        "SERVICE_PRESSURE": 2,
    }
    assert summary["feature_profile_counts"] == {
        "go_agent_overlap_v1": 25,
        "host_extended_v2": 48,
        "target_augmented_v2": 54,
    }
    assert summary["final_test_opened"] is False


def test_protocol_rejects_content_tampering() -> None:
    protocol = _protocol()
    protocol["acquisition"]["repetitions_per_scenario"] = 19

    with pytest.raises(DatasetContractError, match="protocol_sha256"):
        validate_hardware_impact_protocol(protocol)


def test_protocol_requires_benign_counterexample_for_every_material_impact() -> None:
    protocol = deepcopy(_protocol())
    protocol["scenario_design"]["scenarios"] = [
        scenario
        for scenario in protocol["scenario_design"]["scenarios"]
        if scenario["scenario_id"] != "v2_benign_service_high"
    ]
    _rehash(protocol)

    with pytest.raises(DatasetContractError, match="requires benign and malicious"):
        validate_hardware_impact_protocol(protocol)


def test_protocol_forbids_using_ttp_as_hardware_target() -> None:
    protocol = deepcopy(_protocol())
    protocol["labels_and_authority"]["hardware_primary_target"] = "ground_truth_ttps"
    _rehash(protocol)

    with pytest.raises(DatasetContractError, match="primary_impact"):
        validate_hardware_impact_protocol(protocol)


def test_protocol_requires_matched_benign_and_malicious_treatment() -> None:
    protocol = deepcopy(_protocol())
    for scenario in protocol["scenario_design"]["scenarios"]:
        if scenario["scenario_id"] == "v2_benign_compute_high":
            scenario["intensity"] = 50
    _rehash(protocol)

    with pytest.raises(DatasetContractError, match="matched benign/malicious treatment"):
        validate_hardware_impact_protocol(protocol)
