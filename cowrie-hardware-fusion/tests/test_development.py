from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path

from jsonschema import Draft202012Validator
import pytest

from cowrie_hardware_fusion.batch import canonical_sha256
from cowrie_hardware_fusion.cli import main as cli_main
from cowrie_hardware_fusion.dataset import DatasetContractError
from cowrie_hardware_fusion.development import (
    build_hardware_impact_development_matrix,
    validate_development_matrix,
    validate_development_workload_contract,
)
from cowrie_hardware_fusion.poc import DockerWorkloadLifecycle


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PROTOCOL_PATH = PROJECT_ROOT / "configs" / "hardware_impact_experiment_protocol.v2.json"
FEATURE_CONTRACT_PATH = PROJECT_ROOT / "configs" / "model_feature_contract.v1.json"
CATALOG_PATH = PROJECT_ROOT / "configs" / "scenario_catalog.v1.json"
SCHEMA_DIR = PROJECT_ROOT / "schemas"


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _build() -> tuple[dict, list[tuple[dict, dict | None]]]:
    return build_hardware_impact_development_matrix(
        experiment_id="hardware-impact-development-v2",
        image_id="sha256:" + "1" * 64,
        implementation_sha256="2" * 64,
        repo_commit="3" * 40,
        environment_signature_sha256="4" * 64,
        sensor_id="sensor-redacted",
        host_id="pi-host-pseudonymous-01",
        collector_id="experimental-telemetry-collector",
        protocol_path=PROTOCOL_PATH,
        feature_contract_path=FEATURE_CONTRACT_PATH,
        catalog_path=CATALOG_PATH,
        schema_dir=SCHEMA_DIR,
    )


def _validator(filename: str) -> Draft202012Validator:
    return Draft202012Validator(_load(SCHEMA_DIR / filename))


def _semantic_arguments() -> dict:
    return {
        "protocol": _load(PROTOCOL_PATH),
        "feature_contract": _load(FEATURE_CONTRACT_PATH),
        "catalog": _load(CATALOG_PATH),
        "catalog_sha256": sha256(CATALOG_PATH.read_bytes()).hexdigest(),
        "schema_dir": SCHEMA_DIR,
    }


def _write_controls(root: Path) -> tuple[dict, list[tuple[dict, dict | None]]]:
    matrix, documents = _build()
    root.mkdir()
    (root / "matrix.json").write_text(json.dumps(matrix), encoding="utf-8")
    control_root = root / "control"
    for manifest, specification in documents:
        run_root = control_root / f"run={manifest['run_id']}"
        run_root.mkdir(parents=True)
        (run_root / "planned-manifest.json").write_text(
            json.dumps(manifest), encoding="utf-8"
        )
        if specification is not None:
            (run_root / "workload-spec.json").write_text(
                json.dumps(specification), encoding="utf-8"
            )
    return matrix, documents


def _runtime_cli_arguments(root: Path, run_id: str, config: Path) -> list[str]:
    return [
        "--matrix",
        str(root / "matrix.json"),
        "--control-dir",
        str(root / "control"),
        "--protocol",
        str(PROTOCOL_PATH),
        "--feature-contract",
        str(FEATURE_CONTRACT_PATH),
        "--scenario-catalog",
        str(CATALOG_PATH),
        "--run-id",
        run_id,
        "--config",
        str(config),
    ]


def test_development_matrix_has_exact_70_run_coverage_and_valid_schemas() -> None:
    matrix, documents = _build()
    _validator("hardware_impact_development_matrix.v1.schema.json").validate(matrix)
    manifest_validator = _validator("experiment_run_manifest.v1.schema.json")
    spec_validator = _validator(
        "hardware_impact_development_workload_spec.v1.schema.json"
    )

    assert matrix["run_count"] == len(documents) == 70
    assert matrix["estimated_total_seconds"] == 6300
    assert matrix["partition"] == "development_train"
    assert matrix["training_eligible"] is True
    assert matrix["pilot_only"] is False
    assert matrix["final_test_opened"] is False
    assert {entry["planned_day_slot"] for entry in matrix["runs"]} == {1, 2}
    assert sum(specification is None for _, specification in documents) == 10
    for manifest, specification in documents:
        manifest_validator.validate(manifest)
        assert manifest["provenance"]["pilot_only"] is False
        if specification is not None:
            spec_validator.validate(specification)
            assert specification["claim_control"]["training_eligible"] is True
            assert specification["claim_control"]["final_test_opened"] is False


def test_development_matrix_is_deterministic_and_semantically_valid() -> None:
    first_matrix, first_documents = _build()
    second_matrix, second_documents = _build()

    assert first_matrix == second_matrix
    assert first_documents == second_documents
    summary = validate_development_matrix(
        first_matrix, first_documents, **_semantic_arguments()
    )
    assert summary["run_count"] == 70
    assert summary["planned_day_slot_counts"] == {1: 35, 2: 35}
    assert set(summary["scenario_counts"].values()) == {10}
    assert summary["final_test_opened"] is False


def test_each_repetition_preserves_matched_benign_malicious_treatments() -> None:
    _, documents = _build()
    by_key = {
        (
            specification["acquisition"]["repetition"],
            manifest["workload"]["scenario_id"],
        ): specification
        for manifest, specification in documents
        if specification is not None
    }
    for repetition in range(1, 11):
        for benign_id, malicious_id in (
            ("v2_benign_compute_high", "v2_t1496_001_compute_high"),
            ("v2_benign_service_high", "v2_t1499_002_service_high"),
        ):
            benign = by_key[(repetition, benign_id)]
            malicious = by_key[(repetition, malicious_id)]
            assert benign["treatment"] == malicious["treatment"]
            assert benign["limits"] == malicious["limits"]
            benign_parameters = dict(benign["parameters"])
            malicious_parameters = dict(malicious["parameters"])
            benign_parameters.pop("deterministic_seed")
            malicious_parameters.pop("deterministic_seed")
            assert benign_parameters == malicious_parameters


def test_rehashed_matrix_cannot_open_final_test_or_change_schedule() -> None:
    matrix, documents = _build()
    matrix["final_test_opened"] = True
    payload = dict(matrix)
    payload.pop("matrix_sha256")
    matrix["matrix_sha256"] = canonical_sha256(payload)
    with pytest.raises(DatasetContractError, match="final_test_opened"):
        validate_development_matrix(matrix, documents, **_semantic_arguments())

    matrix, documents = _build()
    matrix["runs"][0], matrix["runs"][1] = matrix["runs"][1], matrix["runs"][0]
    for order, entry in enumerate(matrix["runs"], start=1):
        entry["order"] = order
    payload = dict(matrix)
    payload.pop("matrix_sha256")
    matrix["matrix_sha256"] = canonical_sha256(payload)
    with pytest.raises(DatasetContractError, match="not deterministic"):
        validate_development_matrix(matrix, documents, **_semantic_arguments())


def test_development_spec_cannot_revert_to_pilot_claim() -> None:
    _, documents = _build()
    manifest, specification = next(
        (manifest, specification)
        for manifest, specification in documents
        if specification is not None
    )
    tampered = deepcopy(specification)
    tampered["claim_control"]["pilot_only"] = True
    with pytest.raises(DatasetContractError, match="claim control"):
        validate_development_workload_contract(
            manifest, tampered, **_semantic_arguments()
        )


def test_development_service_spec_passes_v2_connection_arguments() -> None:
    _, documents = _build()
    manifest, specification = next(
        (manifest, specification)
        for manifest, specification in documents
        if specification is not None
        and specification["parameters"]["mode"] == "service"
    )

    arguments = DockerWorkloadLifecycle(
        manifest, specification
    )._fixed_workload_arguments()

    assert "--connection-mode=close" in arguments
    assert "--service-capacity=2" in arguments
    assert "--handler-delay=40ms" in arguments


def test_cli_writes_only_development_controls(tmp_path: Path) -> None:
    output = tmp_path / "development-controls"
    exit_code = cli_main(
        [
            "prepare-hardware-impact-development",
            "--experiment-id",
            "hardware-impact-development-v2",
            "--image-id",
            "sha256:" + "1" * 64,
            "--implementation-sha256",
            "2" * 64,
            "--repo-commit",
            "3" * 40,
            "--environment-signature-sha256",
            "4" * 64,
            "--config",
            str(
                PROJECT_ROOT
                / "configs"
                / "experimental_collector.pi_sensor.pilot.example.json"
            ),
            "--protocol",
            str(PROTOCOL_PATH),
            "--feature-contract",
            str(FEATURE_CONTRACT_PATH),
            "--scenario-catalog",
            str(CATALOG_PATH),
            "--output-dir",
            str(output),
        ]
    )

    assert exit_code == 0
    matrix = _load(output / "matrix.json")
    control_dirs = list((output / "control").glob("run=*"))
    assert matrix["run_count"] == len(control_dirs) == 70
    assert matrix["partition"] == "development_train"
    documents = []
    for entry in matrix["runs"]:
        control_dir = output / "control" / f"run={entry['run_id']}"
        manifest = _load(control_dir / "planned-manifest.json")
        specification_path = control_dir / "workload-spec.json"
        specification = _load(specification_path) if specification_path.exists() else None
        documents.append((manifest, specification))
    summary = validate_development_matrix(
        matrix, documents, **_semantic_arguments()
    )
    assert summary["run_count"] == 70
    validation_exit = cli_main(
        [
            "validate-hardware-impact-development-controls",
            "--matrix",
            str(output / "matrix.json"),
            "--control-dir",
            str(output / "control"),
            "--protocol",
            str(PROTOCOL_PATH),
            "--feature-contract",
            str(FEATURE_CONTRACT_PATH),
            "--scenario-catalog",
            str(CATALOG_PATH),
        ]
    )
    assert validation_exit == 0


def test_development_preflight_dispatches_controlled_and_idle_without_collection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import cowrie_hardware_fusion.collector as collector
    import cowrie_hardware_fusion.poc as poc

    root = tmp_path / "controls"
    matrix, _ = _write_controls(root)
    config = _load(
        PROJECT_ROOT
        / "configs"
        / "experimental_collector.pi_sensor.pilot.example.json"
    )
    config["spool"]["directory"] = str(tmp_path / "spool")
    config_path = tmp_path / "collector.json"
    config_path.write_text(json.dumps(config), encoding="utf-8")
    calls = {"controlled": 0, "idle": 0, "runtime": 0}

    def controlled_preflight(*args: object, **kwargs: object) -> dict:
        calls["controlled"] += 1
        return {"ntp_synchronized": True}

    def idle_preflight(*args: object, **kwargs: object) -> dict:
        calls["idle"] += 1
        return {"ntp_synchronized": True}

    def runtime_preflight(*args: object, **kwargs: object) -> dict:
        calls["runtime"] += 1
        return {"execution_authorized": True, "execution_started": False}

    monkeypatch.setattr(collector, "controlled_collector_preflight", controlled_preflight)
    monkeypatch.setattr(collector, "collector_preflight", idle_preflight)
    monkeypatch.setattr(poc, "safe_container_runtime_preflight", runtime_preflight)

    controlled_run = next(
        entry["run_id"] for entry in matrix["runs"] if entry["controlled_workload"]
    )
    idle_run = next(
        entry["run_id"] for entry in matrix["runs"] if not entry["controlled_workload"]
    )
    assert (
        cli_main(
            [
                "hardware-impact-development-preflight",
                *_runtime_cli_arguments(root, controlled_run, config_path),
            ]
        )
        == 0
    )
    assert (
        cli_main(
            [
                "hardware-impact-development-preflight",
                *_runtime_cli_arguments(root, idle_run, config_path),
            ]
        )
        == 0
    )
    assert calls == {"controlled": 1, "idle": 1, "runtime": 1}
