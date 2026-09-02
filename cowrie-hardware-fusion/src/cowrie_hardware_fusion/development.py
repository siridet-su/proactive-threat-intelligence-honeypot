"""Fail-closed planning for the 70-run hardware-impact development wave."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
from typing import Any

from .batch import canonical_sha256
from .dataset import DatasetContractError
from .instrumentation import (
    PROFILES,
    SCENARIO_SLUGS,
    build_service_pressure_instrumentation_matrix,
    validate_service_pressure_contract,
)
from .protocol import validate_hardware_impact_protocol


MATRIX_SCHEMA_VERSION = "hardware_impact_development_matrix.v1"
SPEC_SCHEMA_VERSION = "hardware_impact_development_workload_spec.v1"
DEFAULT_SCHEDULE_SEED = 20260903
PARTITION = "development_train"


def _load_mapping(path: Path, label: str) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise DatasetContractError(f"{label} must contain one JSON object")
    return value


def _sha256_bytes(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _validate_hex(value: str, label: str, lengths: set[int]) -> None:
    if len(value) not in lengths or any(ch not in "0123456789abcdef" for ch in value):
        raise DatasetContractError(f"development {label} is invalid")


def _feature_contract_binding(
    feature_contract: Mapping[str, Any], protocol: Mapping[str, Any]
) -> dict[str, str]:
    if feature_contract.get("schema_version") != "model_feature_contract.v1":
        raise DatasetContractError("unsupported model feature contract")
    claimed_hash = feature_contract.get("contract_sha256")
    payload = dict(feature_contract)
    payload.pop("contract_sha256", None)
    if not isinstance(claimed_hash, str) or canonical_sha256(payload) != claimed_hash:
        raise DatasetContractError("model feature contract hash does not match")
    expected_protocol = {
        "schema_version": protocol["schema_version"],
        "protocol_id": protocol["protocol_id"],
        "protocol_sha256": protocol["protocol_sha256"],
    }
    if feature_contract.get("experiment_protocol") != expected_protocol:
        raise DatasetContractError(
            "model feature contract does not bind the experiment protocol"
        )
    claims = feature_contract.get("claim_control")
    if not isinstance(claims, Mapping) or claims.get("final_test_opened") is not False:
        raise DatasetContractError("model feature contract does not keep final test closed")
    return {
        "schema_version": str(feature_contract["schema_version"]),
        "contract_id": str(feature_contract["contract_id"]),
        "contract_sha256": claimed_hash,
    }


def _planned_day_slot(repetition: int) -> int:
    return 1 if repetition % 2 == 1 else 2


def _scheduled_rows(
    scenario_ids: Sequence[str],
    repetitions: int,
    schedule_seed: int,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    order = 0
    for day_slot in (1, 2):
        for repetition in range(1, repetitions + 1):
            if _planned_day_slot(repetition) != day_slot:
                continue
            scenario_order = sorted(
                scenario_ids,
                key=lambda scenario_id: canonical_sha256(
                    {
                        "schedule_seed": schedule_seed,
                        "planned_day_slot": day_slot,
                        "repetition": repetition,
                        "scenario_id": scenario_id,
                    }
                ),
            )
            for scenario_id in scenario_order:
                order += 1
                rows.append(
                    {
                        "order": order,
                        "repetition": repetition,
                        "planned_day_slot": day_slot,
                        "scenario_id": scenario_id,
                    }
                )
    return rows


def _deterministic_workload_seed(
    schedule_seed: int, repetition: int, scenario_id: str
) -> int:
    digest = canonical_sha256(
        {
            "schedule_seed": schedule_seed,
            "repetition": repetition,
            "scenario_id": scenario_id,
            "purpose": "bounded-workload-seed",
        }
    )
    return int(digest[:8], 16) % 2_147_483_648


def validate_development_workload_contract(
    manifest: Mapping[str, Any],
    specification: Mapping[str, Any],
    *,
    protocol: Mapping[str, Any],
    feature_contract: Mapping[str, Any],
    catalog: Mapping[str, Any],
    catalog_sha256: str,
    schema_dir: Path,
) -> None:
    """Validate development-only claims, then reuse the reviewed treatment validator."""

    if specification.get("schema_version") != SPEC_SCHEMA_VERSION:
        raise DatasetContractError("unsupported development workload specification")
    feature_binding = _feature_contract_binding(feature_contract, protocol)
    if specification.get("model_feature_contract") != feature_binding:
        raise DatasetContractError("development spec feature-contract binding does not match")
    acquisition = specification.get("acquisition")
    if not isinstance(acquisition, Mapping):
        raise DatasetContractError("development acquisition binding is missing")
    repetition = acquisition.get("repetition")
    day_slot = acquisition.get("planned_day_slot")
    if (
        acquisition.get("partition") != PARTITION
        or not isinstance(repetition, int)
        or not 1 <= repetition <= 10
        or day_slot != _planned_day_slot(repetition)
    ):
        raise DatasetContractError("development acquisition binding is invalid")
    if specification.get("claim_control") != {
        "pilot_only": False,
        "training_eligible": True,
        "changes_frozen_feature_set": False,
        "simulator_receipt_is_model_feature": False,
        "final_test_opened": False,
    }:
        raise DatasetContractError("development claim control is not fail closed")
    if manifest.get("provenance") != {
        "source": "controlled_experiment",
        "controlled": True,
        "pilot_only": False,
        "production_analytics_eligible": False,
    }:
        raise DatasetContractError("development manifest provenance is invalid")
    scenario_id = str(specification["scenario_id"])
    slug = SCENARIO_SLUGS[scenario_id]
    expected_run_id = f"run-hardware-v2-development-{slug}-r{repetition:02d}"
    if manifest.get("run_id") != expected_run_id:
        raise DatasetContractError("development run identity does not match acquisition")
    expected_batch = (
        f"hardware-v2-development-day{day_slot:02d}-r{repetition:02d}"
    )
    if manifest.get("split_groups", {}).get("collection_batch") != expected_batch:
        raise DatasetContractError("development collection batch does not match schedule")
    if manifest.get("execution_boundary", {}).get("backend_id") != (
        "hardware-impact-development-pi-v2"
    ):
        raise DatasetContractError("development execution boundary is invalid")

    pilot_manifest = deepcopy(dict(manifest))
    pilot_manifest["provenance"] = {
        "source": "controlled_experiment",
        "controlled": True,
        "pilot_only": True,
        "production_analytics_eligible": False,
    }
    pilot_manifest["execution_boundary"]["backend_id"] = (
        "service-pressure-instrumentation-pi-v2"
    )
    pilot_specification = deepcopy(dict(specification))
    pilot_specification["schema_version"] = "service_pressure_workload_spec.v2"
    pilot_specification.pop("acquisition", None)
    pilot_specification.pop("model_feature_contract", None)
    pilot_specification["claim_control"] = {
        "pilot_only": True,
        "training_eligible": False,
        "changes_frozen_feature_set": False,
        "simulator_receipt_is_model_feature": False,
    }
    validate_service_pressure_contract(
        pilot_manifest,
        pilot_specification,
        protocol=protocol,
        catalog=catalog,
        catalog_sha256=catalog_sha256,
        schema_dir=schema_dir,
    )


def validate_development_matrix(
    matrix: Mapping[str, Any],
    documents: Sequence[tuple[Mapping[str, Any], Mapping[str, Any] | None]],
    *,
    protocol: Mapping[str, Any],
    feature_contract: Mapping[str, Any],
    catalog: Mapping[str, Any],
    catalog_sha256: str,
    schema_dir: Path,
) -> dict[str, Any]:
    """Verify schedule coverage, claims, identities and every manifest/spec hash."""

    validate_hardware_impact_protocol(protocol)
    feature_binding = _feature_contract_binding(feature_contract, protocol)
    claimed_hash = matrix.get("matrix_sha256")
    payload = dict(matrix)
    payload.pop("matrix_sha256", None)
    if not isinstance(claimed_hash, str) or canonical_sha256(payload) != claimed_hash:
        raise DatasetContractError("development matrix hash does not match")
    expected_top = {
        "schema_version": MATRIX_SCHEMA_VERSION,
        "status": "planned",
        "partition": PARTITION,
        "purpose": "controlled_hardware_impact_model_development",
        "pilot_only": False,
        "training_eligible": True,
        "final_test_opened": False,
        "stop_after_wave": True,
        "repetitions_per_scenario": 10,
        "minimum_distinct_days": 2,
        "scenario_count": 7,
        "run_count": 70,
        "sample_interval_seconds": 1,
        "seconds_per_run": 90,
        "estimated_total_seconds": 6300,
    }
    for field, expected in expected_top.items():
        if matrix.get(field) != expected:
            raise DatasetContractError(f"development matrix {field} is invalid")
    if matrix.get("matrix_id") != f"matrix-{matrix.get('experiment_id')}":
        raise DatasetContractError("development matrix identity is invalid")
    if matrix.get("model_feature_contract") != feature_binding:
        raise DatasetContractError("development matrix feature binding does not match")
    expected_protocol = {
        "schema_version": protocol["schema_version"],
        "protocol_id": protocol["protocol_id"],
        "protocol_sha256": protocol["protocol_sha256"],
    }
    if matrix.get("experiment_protocol") != expected_protocol:
        raise DatasetContractError("development matrix protocol binding does not match")

    schedule_block = matrix.get("schedule")
    if not isinstance(schedule_block, Mapping):
        raise DatasetContractError("development schedule is missing")
    schedule_seed = schedule_block.get("seed")
    if not isinstance(schedule_seed, int):
        raise DatasetContractError("development schedule seed is invalid")
    expected_day_slots = [
        {"planned_day_slot": 1, "repetitions": [1, 3, 5, 7, 9]},
        {"planned_day_slot": 2, "repetitions": [2, 4, 6, 8, 10]},
    ]
    if schedule_block != {
        "seed": schedule_seed,
        "strategy": "two-day-slots_repetition-blocked_hash-order",
        "day_slots": expected_day_slots,
    }:
        raise DatasetContractError("development day-slot plan is invalid")
    expected_schedule = _scheduled_rows(
        list(PROFILES), expected_top["repetitions_per_scenario"], schedule_seed
    )
    observed_schedule = [
        {
            "order": entry.get("order"),
            "repetition": entry.get("repetition"),
            "planned_day_slot": entry.get("planned_day_slot"),
            "scenario_id": entry.get("scenario_id"),
        }
        for entry in matrix["runs"]
    ]
    if observed_schedule != expected_schedule:
        raise DatasetContractError("development run order is not deterministic")
    counts = Counter(entry["scenario_id"] for entry in matrix["runs"])
    if counts != Counter({scenario_id: 10 for scenario_id in PROFILES}):
        raise DatasetContractError("development matrix scenario coverage is incomplete")

    documents_by_run = {
        str(manifest["run_id"]): (manifest, spec)
        for manifest, spec in documents
    }
    if len(documents_by_run) != 70 or set(documents_by_run) != {
        str(entry["run_id"]) for entry in matrix["runs"]
    }:
        raise DatasetContractError("development control-document membership does not match")
    artifacts = matrix.get("artifact_bindings")
    if not isinstance(artifacts, Mapping):
        raise DatasetContractError("development artifact bindings are missing")
    if artifacts.get("scenario_catalog_sha256") != catalog_sha256:
        raise DatasetContractError("development catalog binding does not match")
    for entry in matrix["runs"]:
        manifest, specification = documents_by_run[str(entry["run_id"])]
        scenario_id = str(entry["scenario_id"])
        repetition = int(entry["repetition"])
        day_slot = int(entry["planned_day_slot"])
        slug = SCENARIO_SLUGS[scenario_id]
        expected_run_id = f"run-hardware-v2-development-{slug}-r{repetition:02d}"
        if entry["run_id"] != expected_run_id:
            raise DatasetContractError("development matrix run identity is invalid")
        profile = PROFILES[scenario_id]
        if (
            entry["controlled_workload"] is not (profile.mode is not None)
            or entry["treatment_id"] != profile.treatment_id
            or entry["primary_impact"] != profile.primary_impact
        ):
            raise DatasetContractError("development matrix treatment metadata is invalid")
        if canonical_sha256(manifest) != entry["planned_manifest_sha256"]:
            raise DatasetContractError("development planned manifest hash does not match")
        if (
            manifest["experiment_id"] != matrix["experiment_id"]
            or manifest["workload"]["scenario_id"] != scenario_id
            or manifest["sensor"]["repo_commit"] != artifacts.get("repo_commit")
            or manifest["sensor"]["environment_signature_sha256"]
            != artifacts.get("environment_signature_sha256")
            or manifest["collection"]["collector_sha256"]
            != artifacts.get("collector_source_sha256")
        ):
            raise DatasetContractError("development manifest artifact binding does not match")
        expected_batch = f"hardware-v2-development-day{day_slot:02d}-r{repetition:02d}"
        if manifest["split_groups"]["collection_batch"] != expected_batch:
            raise DatasetContractError("development manifest schedule binding does not match")
        if profile.mode is None:
            if specification is not None or entry["workload_spec_id"] is not None:
                raise DatasetContractError("development idle run cannot have a workload spec")
            if manifest["provenance"]["pilot_only"] is not False:
                raise DatasetContractError("development idle run cannot remain pilot-only")
            if manifest["execution_boundary"]["kind"] != "none":
                raise DatasetContractError("development idle boundary must be none")
        else:
            if specification is None:
                raise DatasetContractError("development controlled run requires a workload spec")
            if specification["spec_id"] != entry["workload_spec_id"]:
                raise DatasetContractError("development workload spec identity does not match")
            if canonical_sha256(specification) != entry["workload_spec_sha256"]:
                raise DatasetContractError("development workload spec hash does not match")
            if (
                specification["runner"]["image_id"] != artifacts.get("image_id")
                or specification["runner"]["implementation_sha256"]
                != artifacts.get("implementation_sha256")
                or specification["telemetry_contract"]["collector_source_sha256"]
                != artifacts.get("collector_source_sha256")
                or specification["telemetry_contract"]["schema_sha256"]
                != artifacts.get("telemetry_schema_sha256")
            ):
                raise DatasetContractError(
                    "development workload artifact binding does not match"
                )
            validate_development_workload_contract(
                manifest,
                specification,
                protocol=protocol,
                feature_contract=feature_contract,
                catalog=catalog,
                catalog_sha256=catalog_sha256,
                schema_dir=schema_dir,
            )
    return {
        "matrix_sha256": claimed_hash,
        "run_count": 70,
        "scenario_counts": dict(sorted(counts.items())),
        "planned_day_slot_counts": dict(
            sorted(Counter(entry["planned_day_slot"] for entry in matrix["runs"]).items())
        ),
        "final_test_opened": False,
        "training_eligible": True,
    }


def build_hardware_impact_development_matrix(
    *,
    experiment_id: str,
    image_id: str,
    implementation_sha256: str,
    repo_commit: str,
    environment_signature_sha256: str,
    sensor_id: str,
    host_id: str,
    collector_id: str,
    protocol_path: Path,
    feature_contract_path: Path,
    catalog_path: Path,
    schema_dir: Path,
    schedule_seed: int = DEFAULT_SCHEDULE_SEED,
) -> tuple[dict[str, Any], list[tuple[dict[str, Any], dict[str, Any] | None]]]:
    """Build exactly the unlocked development wave; calibration/final remain absent."""

    if not image_id.startswith("sha256:") or len(image_id) != 71:
        raise DatasetContractError("development image_id is invalid")
    _validate_hex(implementation_sha256, "implementation hash", {64})
    _validate_hex(repo_commit, "repository commit", {40, 64})
    _validate_hex(environment_signature_sha256, "environment signature", {64})
    if not 0 <= schedule_seed <= 2_147_483_647:
        raise DatasetContractError("development schedule seed is invalid")

    protocol = _load_mapping(protocol_path, "hardware-impact protocol")
    protocol_summary = validate_hardware_impact_protocol(protocol)
    development_waves = [
        wave
        for wave in protocol["acquisition"]["waves"]
        if wave["partition"] == PARTITION
    ]
    if development_waves != [
        {
            "partition": PARTITION,
            "repetitions_per_scenario": 10,
            "minimum_distinct_days": 2,
            "locked_until_model_freeze": False,
        }
    ]:
        raise DatasetContractError("protocol development wave is not the expected unlocked wave")
    if protocol["acquisition"]["stop_after_development_for_signal_review"] is not True:
        raise DatasetContractError("protocol must stop after development for signal review")

    feature_contract = _load_mapping(feature_contract_path, "model feature contract")
    feature_binding = _feature_contract_binding(feature_contract, protocol)
    catalog = _load_mapping(catalog_path, "scenario catalog")
    catalog_hash = _sha256_bytes(catalog_path)
    base_matrix, base_documents = build_service_pressure_instrumentation_matrix(
        generation="v2",
        experiment_id=experiment_id,
        image_id=image_id,
        implementation_sha256=implementation_sha256,
        repo_commit=repo_commit,
        environment_signature_sha256=environment_signature_sha256,
        sensor_id=sensor_id,
        host_id=host_id,
        collector_id=collector_id,
        protocol_path=protocol_path,
        catalog_path=catalog_path,
        schema_dir=schema_dir,
    )
    base_by_scenario = {
        manifest["workload"]["scenario_id"]: (manifest, specification)
        for manifest, specification in base_documents
    }
    schedule = _scheduled_rows(list(PROFILES), 10, schedule_seed)
    documents: list[tuple[dict[str, Any], dict[str, Any] | None]] = []
    matrix_runs: list[dict[str, Any]] = []

    for row in schedule:
        scenario_id = row["scenario_id"]
        repetition = row["repetition"]
        day_slot = row["planned_day_slot"]
        slug = SCENARIO_SLUGS[scenario_id]
        run_id = f"run-hardware-v2-development-{slug}-r{repetition:02d}"
        base_manifest, base_specification = base_by_scenario[scenario_id]
        manifest = deepcopy(base_manifest)
        manifest["run_id"] = run_id
        manifest["experiment_id"] = experiment_id
        manifest["provenance"]["pilot_only"] = False
        manifest["split_groups"]["collection_batch"] = (
            f"hardware-v2-development-day{day_slot:02d}-r{repetition:02d}"
        )
        if manifest["execution_boundary"]["kind"] == "safe_container":
            manifest["execution_boundary"]["backend_id"] = (
                "hardware-impact-development-pi-v2"
            )

        specification: dict[str, Any] | None = None
        if base_specification is not None:
            specification = deepcopy(base_specification)
            specification["schema_version"] = SPEC_SCHEMA_VERSION
            specification["spec_id"] = (
                f"spec-hardware-v2-development-{slug}-r{repetition:02d}"
            )
            specification["parameters"]["deterministic_seed"] = (
                _deterministic_workload_seed(schedule_seed, repetition, scenario_id)
            )
            specification["acquisition"] = {
                "partition": PARTITION,
                "repetition": repetition,
                "planned_day_slot": day_slot,
            }
            specification["model_feature_contract"] = dict(feature_binding)
            specification["claim_control"] = {
                "pilot_only": False,
                "training_eligible": True,
                "changes_frozen_feature_set": False,
                "simulator_receipt_is_model_feature": False,
                "final_test_opened": False,
            }

        documents.append((manifest, specification))
        profile = PROFILES[scenario_id]
        matrix_runs.append(
            {
                **row,
                "run_id": run_id,
                "controlled_workload": specification is not None,
                "workload_spec_id": (
                    specification["spec_id"] if specification is not None else None
                ),
                "treatment_id": profile.treatment_id,
                "primary_impact": profile.primary_impact,
                "planned_manifest_sha256": canonical_sha256(manifest),
                "workload_spec_sha256": (
                    canonical_sha256(specification) if specification is not None else None
                ),
            }
        )

    matrix: dict[str, Any] = {
        "schema_version": MATRIX_SCHEMA_VERSION,
        "matrix_id": f"matrix-{experiment_id}",
        "experiment_id": experiment_id,
        "status": "planned",
        "partition": PARTITION,
        "purpose": "controlled_hardware_impact_model_development",
        "pilot_only": False,
        "training_eligible": True,
        "final_test_opened": False,
        "stop_after_wave": True,
        "repetitions_per_scenario": 10,
        "minimum_distinct_days": 2,
        "scenario_count": 7,
        "run_count": 70,
        "sample_interval_seconds": 1,
        "seconds_per_run": 90,
        "estimated_total_seconds": 6300,
        "schedule": {
            "seed": schedule_seed,
            "strategy": "two-day-slots_repetition-blocked_hash-order",
            "day_slots": [
                {"planned_day_slot": 1, "repetitions": [1, 3, 5, 7, 9]},
                {"planned_day_slot": 2, "repetitions": [2, 4, 6, 8, 10]},
            ],
        },
        "experiment_protocol": {
            "schema_version": protocol["schema_version"],
            "protocol_id": protocol_summary["protocol_id"],
            "protocol_sha256": protocol_summary["protocol_sha256"],
        },
        "model_feature_contract": feature_binding,
        "artifact_bindings": {
            "scenario_catalog_sha256": catalog_hash,
            "collector_source_sha256": base_matrix["artifact_bindings"][
                "collector_source_sha256"
            ],
            "telemetry_schema_sha256": base_matrix["artifact_bindings"][
                "telemetry_schema_sha256"
            ],
            "image_id": image_id,
            "implementation_sha256": implementation_sha256,
            "repo_commit": repo_commit,
            "environment_signature_sha256": environment_signature_sha256,
        },
        "runs": matrix_runs,
    }
    matrix["matrix_sha256"] = canonical_sha256(matrix)
    validate_development_matrix(
        matrix,
        documents,
        protocol=protocol,
        feature_contract=feature_contract,
        catalog=catalog,
        catalog_sha256=catalog_hash,
        schema_dir=schema_dir,
    )
    return matrix, documents
