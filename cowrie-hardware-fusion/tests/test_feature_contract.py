from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from cowrie_hardware_fusion.batch import canonical_sha256
from cowrie_hardware_fusion.cli import main as cli_main
from cowrie_hardware_fusion.dataset import DatasetContractError, build_training_window
from cowrie_hardware_fusion.feature_contract import validate_model_feature_contract


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _contract() -> dict:
    return _load(PROJECT_ROOT / "configs" / "model_feature_contract.v1.json")


def _representative_window() -> dict:
    examples = PROJECT_ROOT / "schemas" / "examples"
    manifest = _load(examples / "experiment_run_manifest.v1.example.json")
    manifest["state"] = "completed"
    template = _load(examples / "hardware_telemetry_sample.v1.example.json")
    samples: list[dict] = []
    for sequence in range(60):
        sample = deepcopy(template)
        sample["sample_id"] = f"sample-contract-{sequence:06d}"
        sample["phase"] = "baseline" if sequence < 30 else "workload"
        sample["time"]["sequence"] = sequence
        sample["time"]["monotonic_ns"] = (sequence + 1) * 1_000_000_000
        sample["time"]["observed_at"] = f"2026-09-01T08:00:{sequence:02d}Z"
        samples.append(sample)
    return build_training_window(
        manifest,
        samples,
        metric_scope="pi_sensor",
        phase="workload",
        horizon_seconds=30,
        minimum_coverage=0.99,
    )


def _rehash(contract: dict) -> None:
    payload = dict(contract)
    payload.pop("contract_sha256", None)
    contract["contract_sha256"] = canonical_sha256(payload)


def test_frozen_contract_validates_schema_and_builder_v2_identity() -> None:
    contract = _contract()
    schema = _load(PROJECT_ROOT / "schemas" / "model_feature_contract.v1.schema.json")
    Draft202012Validator(schema).validate(contract)

    summary = validate_model_feature_contract(contract, _representative_window())

    assert summary["xgboost_profile_counts"] == {
        "go_agent_overlap_v1": 25,
        "host_extended_v3": 51,
        "target_augmented_v3": 66,
    }
    assert summary["tcn_profile_counts"] == {
        "host_extended_v3": 14,
        "target_augmented_v3": 22,
    }
    assert summary["deployment_authority"] == "audit_only"
    assert summary["final_test_opened"] is False


def test_contract_hash_tampering_is_rejected() -> None:
    contract = _contract()
    contract["contract_id"] = "tampered-contract"

    with pytest.raises(DatasetContractError, match="contract hash"):
        validate_model_feature_contract(contract, _representative_window())


def test_rehashed_contract_cannot_add_simulator_presence_artifact() -> None:
    contract = _contract()
    target = next(
        profile
        for profile in contract["xgboost_profiles"]
        if profile["profile_id"] == "target_augmented_v3"
    )
    target["input_names"].append("target_process_present_fraction")
    target["input_names"].sort()
    contract["forbidden_model_inputs"].remove("target_process_present_fraction")
    _rehash(contract)

    with pytest.raises(DatasetContractError, match="simulator artifact"):
        validate_model_feature_contract(contract, _representative_window())


def test_rehashed_contract_cannot_add_label() -> None:
    contract = _contract()
    profile = next(
        item
        for item in contract["xgboost_profiles"]
        if item["profile_id"] == "host_extended_v3"
    )
    profile["input_names"].append("ground_truth_ttps")
    profile["input_names"].sort()
    _rehash(contract)

    with pytest.raises(DatasetContractError, match="unavailable inputs"):
        validate_model_feature_contract(contract, _representative_window())


def test_cli_validates_contract_against_window(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    window_path = tmp_path / "window.json"
    window_path.write_text(
        json.dumps(_representative_window(), sort_keys=True), encoding="utf-8"
    )

    exit_code = cli_main(
        [
            "validate-model-feature-contract",
            "--contract",
            str(PROJECT_ROOT / "configs" / "model_feature_contract.v1.json"),
            "--window",
            str(window_path),
        ]
    )

    assert exit_code == 0
    output = json.loads(capsys.readouterr().out)
    assert output["feature_count"] == 67
    assert output["channel_count"] == 22
