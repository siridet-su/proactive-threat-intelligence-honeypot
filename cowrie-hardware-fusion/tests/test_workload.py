from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from cowrie_hardware_fusion.dataset import DatasetContractError
from cowrie_hardware_fusion.workload import validate_bounded_workload


PROJECT_ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = PROJECT_ROOT / "configs" / "scenario_catalog.v1.json"


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _specification() -> dict:
    return _load_json(
        PROJECT_ROOT / "configs" / "bounded_workload.benign_compute.example.json"
    )


def _manifest() -> dict:
    manifest = _load_json(
        PROJECT_ROOT
        / "schemas"
        / "examples"
        / "experiment_run_manifest.benign_compute.v1.example.json"
    )
    manifest["run_id"] = "run-benign-compute-test-001"
    manifest["execution_boundary"]["backend_id"] = "backend-test-001"
    return manifest


def _validate(manifest: dict, specification: dict) -> dict:
    return validate_bounded_workload(
        manifest,
        specification,
        catalog_path=CATALOG_PATH,
        schema_dir=PROJECT_ROOT / "schemas",
    )


def test_bounded_workload_preflight_is_deterministic_and_does_not_execute() -> None:
    specification = _specification()
    manifest = _manifest()

    first = _validate(manifest, specification)
    second = _validate(deepcopy(manifest), deepcopy(specification))

    assert first == second
    assert first["contract_valid"] is True
    assert first["execution_authorized"] is False
    assert first["scenario_id"] == "benign_compute_control"
    assert first["runner"]["kind"] == "oci_container_in_disposable_vm"
    assert first["limits"]["cpu_quota_millicores"] == 250
    schema = _load_json(
        PROJECT_ROOT / "schemas" / "bounded_workload_preflight_receipt.v1.schema.json"
    )
    Draft202012Validator(schema).validate(first)


def test_bounded_workload_rejects_pi_or_no_execution_boundary() -> None:
    specification = _specification()
    manifest = _manifest()
    manifest["execution_boundary"] = {
        "kind": "none",
        "metric_scopes": ["pi_sensor"],
        "execution_observed": False,
        "backend_id": None,
        "backend_image_sha256": None,
        "network_policy_sha256": None,
    }

    with pytest.raises(DatasetContractError, match="disposable_vm"):
        _validate(manifest, specification)


def test_bounded_workload_rejects_intensity_that_differs_from_hard_cpu_quota() -> None:
    specification = _specification()
    manifest = _manifest()
    specification["limits"]["cpu_quota_millicores"] = 500

    with pytest.raises(DatasetContractError, match="CPU quota"):
        _validate(manifest, specification)


def test_bounded_workload_rejects_raw_cowrie_command_input() -> None:
    specification = _specification()
    manifest = _manifest()
    specification["input_policy"]["raw_cowrie_command_allowed"] = True

    with pytest.raises(DatasetContractError, match="False was expected"):
        _validate(manifest, specification)
