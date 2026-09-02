"""Hash-bound seven-scenario instrumentation pilot and signal summaries.

The pilot in this module is deliberately excluded from model training.  Its only job is
to determine which production-observable service-pressure fields are sufficiently
available and responsive to justify a later, explicitly frozen feature revision.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from hashlib import sha256
import json
import math
from pathlib import Path
from statistics import fmean
from typing import Any

from .batch import canonical_sha256
from .collector import collector_source_sha256, telemetry_schema_sha256
from .dataset import DatasetContractError
from .protocol import validate_hardware_impact_protocol


SPEC_SCHEMA_VERSION = "service_pressure_workload_spec.v2"
MATRIX_SCHEMA_VERSION = "service_pressure_instrumentation_matrix.v2"
REPORT_SCHEMA_VERSION = "service_pressure_signal_report.v1"


@dataclass(frozen=True)
class InstrumentationProfile:
    disposition: str
    workload_family: str
    primary_impact: str
    ground_truth_ttps: tuple[str, ...]
    protocol_intensity: int
    protocol_intensity_unit: str
    treatment_id: str
    mode: str | None
    manifest_intensity_percent: int
    intensity_basis: str
    cpu_limit_cores: float | None
    workers: int | None
    duty_percent: int | None
    requests_per_second: int | None
    work_iterations: int | None
    connection_mode: str | None
    service_capacity: int | None
    handler_delay_ms: int | None
    evidence_gate_type: str | None
    minimum_attempts: int | None
    minimum_error_fraction: float | None
    maximum_error_fraction: float | None
    minimum_rejected: int | None
    maximum_rejected: int | None
    minimum_latency_p95_ms: float | None


PROFILES: dict[str, InstrumentationProfile] = {
    "v2_neutral_idle": InstrumentationProfile(
        "neutral_baseline",
        "none",
        "NO_MATERIAL_IMPACT",
        (),
        0,
        "none",
        "idle",
        None,
        0,
        "none",
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    ),
    "v2_benign_compute_low": InstrumentationProfile(
        "benign_control",
        "bounded_compute",
        "NO_MATERIAL_IMPACT",
        (),
        25,
        "assigned_cpu_percent",
        "compute-low-25",
        "compute",
        25,
        "assigned_cpu_capacity",
        1.0,
        1,
        25,
        1,
        1,
        "reuse",
        2,
        0,
        "bounded_execution",
        1,
        0.0,
        0.0,
        0,
        0,
        0.0,
    ),
    "v2_benign_compute_high": InstrumentationProfile(
        "benign_control",
        "bounded_compute",
        "COMPUTE_SATURATION",
        (),
        75,
        "assigned_cpu_percent",
        "compute-high-75",
        "compute",
        75,
        "assigned_cpu_capacity",
        1.0,
        1,
        75,
        1,
        1,
        "reuse",
        2,
        0,
        "bounded_execution",
        1,
        0.0,
        0.0,
        0,
        0,
        0.0,
    ),
    "v2_t1496_001_compute_high": InstrumentationProfile(
        "malicious_simulation",
        "bounded_compute",
        "COMPUTE_SATURATION",
        ("T1496.001",),
        75,
        "assigned_cpu_percent",
        "compute-high-75",
        "compute",
        75,
        "assigned_cpu_capacity",
        1.0,
        1,
        75,
        1,
        1,
        "reuse",
        2,
        0,
        "bounded_execution",
        1,
        0.0,
        0.0,
        0,
        0,
        0.0,
    ),
    "v2_benign_service_low": InstrumentationProfile(
        "benign_control",
        "bounded_service",
        "NO_MATERIAL_IMPACT",
        (),
        10,
        "requests_per_second",
        "service-low-10rps",
        "service",
        25,
        "assigned_service_capacity",
        1.0,
        8,
        100,
        10,
        500,
        "close",
        2,
        40,
        "healthy_service",
        200,
        0.0,
        0.05,
        0,
        0,
        20.0,
    ),
    "v2_benign_service_high": InstrumentationProfile(
        "benign_control",
        "bounded_service",
        "SERVICE_PRESSURE",
        (),
        150,
        "requests_per_second",
        "service-high-150rps",
        "service",
        75,
        "assigned_service_capacity",
        1.0,
        8,
        100,
        150,
        500,
        "close",
        2,
        40,
        "service_degradation",
        3000,
        0.20,
        1.0,
        1,
        None,
        20.0,
    ),
    "v2_t1499_002_service_high": InstrumentationProfile(
        "malicious_simulation",
        "bounded_service",
        "SERVICE_PRESSURE",
        ("T1499.002",),
        150,
        "requests_per_second",
        "service-high-150rps",
        "service",
        75,
        "assigned_service_capacity",
        1.0,
        8,
        100,
        150,
        500,
        "close",
        2,
        40,
        "service_degradation",
        3000,
        0.20,
        1.0,
        1,
        None,
        20.0,
    ),
}

SCENARIO_SLUGS = {
    "v2_neutral_idle": "idle",
    "v2_benign_compute_low": "benign-compute-low",
    "v2_benign_compute_high": "benign-compute-high",
    "v2_t1496_001_compute_high": "t1496-001-compute-high",
    "v2_benign_service_low": "benign-service-low",
    "v2_benign_service_high": "benign-service-high",
    "v2_t1499_002_service_high": "t1499-002-service-high",
}


def _sha256_bytes(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _load_mapping(path: Path, label: str) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise DatasetContractError(f"{label} must contain one JSON object")
    return value


def _one_scenario(document: Mapping[str, Any], scenario_id: str) -> Mapping[str, Any]:
    scenarios = document.get("scenarios")
    if not isinstance(scenarios, list):
        raise DatasetContractError("scenario catalog scenarios must be an array")
    matches = [
        scenario
        for scenario in scenarios
        if isinstance(scenario, Mapping) and scenario.get("scenario_id") == scenario_id
    ]
    if len(matches) != 1:
        raise DatasetContractError(
            f"scenario catalog must contain exactly one scenario_id={scenario_id}"
        )
    return matches[0]


def _protocol_scenarios(protocol: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    return {
        str(scenario["scenario_id"]): scenario
        for scenario in protocol["scenario_design"]["scenarios"]
    }


def _fixed_security() -> dict[str, Any]:
    return {
        "network_mode": "none",
        "read_only_rootfs": True,
        "cap_drop_all": True,
        "no_new_privileges": True,
        "run_as_uid": 65532,
        "run_as_gid": 65532,
    }


def validate_service_pressure_contract(
    manifest: Mapping[str, Any],
    specification: Mapping[str, Any],
    *,
    protocol: Mapping[str, Any],
    catalog: Mapping[str, Any],
    catalog_sha256: str,
    schema_dir: Path,
) -> InstrumentationProfile:
    """Validate one controlled instrumentation run against all frozen identities."""

    if specification.get("schema_version") != SPEC_SCHEMA_VERSION:
        raise DatasetContractError("unsupported service-pressure workload specification")
    validate_hardware_impact_protocol(protocol)
    protocol_binding = specification["experiment_protocol"]
    if protocol_binding != {
        "schema_version": protocol["schema_version"],
        "protocol_id": protocol["protocol_id"],
        "protocol_sha256": protocol["protocol_sha256"],
    }:
        raise DatasetContractError("workload specification protocol binding does not match")
    if specification["scenario_catalog_sha256"] != catalog_sha256:
        raise DatasetContractError("workload specification scenario catalog hash does not match")
    telemetry_binding = specification["telemetry_contract"]
    if telemetry_binding != {
        "schema_version": "hardware_telemetry_sample.v1",
        "schema_sha256": telemetry_schema_sha256(schema_dir),
        "collector_source_sha256": collector_source_sha256(),
    }:
        raise DatasetContractError("workload specification telemetry binding does not match")

    scenario_id = specification["scenario_id"]
    profile = PROFILES.get(scenario_id)
    if profile is None or profile.mode is None:
        raise DatasetContractError("controlled instrumentation scenario is not allowlisted")
    protocol_scenario = _protocol_scenarios(protocol).get(scenario_id)
    if protocol_scenario is None:
        raise DatasetContractError("scenario is absent from the frozen protocol")
    expected_protocol = {
        "scenario_disposition": profile.disposition,
        "workload_family": profile.workload_family,
        "intensity": profile.protocol_intensity,
        "primary_impact": profile.primary_impact,
        "ground_truth_ttps": list(profile.ground_truth_ttps),
        "hardware_label_source": "scenario_manifest_plus_observed_impact_evidence",
    }
    for field, expected in expected_protocol.items():
        if protocol_scenario.get(field) != expected:
            raise DatasetContractError(f"protocol scenario {field} does not match profile")

    catalog_scenario = _one_scenario(catalog, scenario_id)
    expected_catalog = {
        "disposition": profile.disposition,
        "safe_workload_family": profile.workload_family,
        "execution_boundary": "safe_container",
        "target_metric_scopes": ["pi_sensor"],
        "primary_impact": profile.primary_impact,
        "ground_truth_ttps": list(profile.ground_truth_ttps),
    }
    for field, expected in expected_catalog.items():
        if catalog_scenario.get(field) != expected:
            raise DatasetContractError(f"scenario catalog {field} does not match profile")

    treatment = specification["treatment"]
    if treatment != {
        "treatment_id": profile.treatment_id,
        "workload_family": profile.workload_family,
        "protocol_intensity": profile.protocol_intensity,
        "protocol_intensity_unit": profile.protocol_intensity_unit,
    }:
        raise DatasetContractError("workload treatment does not match the fixed profile")
    parameters = specification["parameters"]
    expected_parameters = {
        "mode": profile.mode,
        "workers": profile.workers,
        "duty_percent": profile.duty_percent,
        "duty_period_ms": 100,
        "requests_per_second": profile.requests_per_second,
        "work_iterations": profile.work_iterations,
        "connection_mode": profile.connection_mode,
        "service_capacity": profile.service_capacity,
        "handler_delay_ms": profile.handler_delay_ms,
    }
    for field, expected in expected_parameters.items():
        if parameters.get(field) != expected:
            raise DatasetContractError(f"workload parameters.{field} is not allowlisted")
    if specification["limits"]["cpu_limit_cores"] != profile.cpu_limit_cores:
        raise DatasetContractError("CPU limit does not match the fixed profile")
    expected_gate = {
        "gate_type": profile.evidence_gate_type,
        "minimum_attempts": profile.minimum_attempts,
        "minimum_error_fraction": profile.minimum_error_fraction,
        "maximum_error_fraction": profile.maximum_error_fraction,
        "minimum_rejected": profile.minimum_rejected,
        "maximum_rejected": profile.maximum_rejected,
        "minimum_latency_p95_ms": profile.minimum_latency_p95_ms,
    }
    if specification["observed_impact_gate"] != expected_gate:
        raise DatasetContractError("observed-impact evidence gate is not allowlisted")

    workload = manifest["workload"]
    expected_workload = {
        "scenario_id": scenario_id,
        "family": profile.workload_family,
        "implementation_sha256": specification["runner"]["implementation_sha256"],
        "intensity_percent": profile.manifest_intensity_percent,
        "intensity_basis": profile.intensity_basis,
    }
    for field, expected in expected_workload.items():
        if workload.get(field) != expected:
            raise DatasetContractError(f"manifest workload.{field} does not match profile")
    labels = manifest["labels"]
    for field, expected in {
        "scenario_disposition": profile.disposition,
        "primary_impact": profile.primary_impact,
        "ground_truth_ttps": list(profile.ground_truth_ttps),
    }.items():
        if labels.get(field) != expected:
            raise DatasetContractError(f"manifest labels.{field} does not match profile")
    if labels["observed_impacts"] != [profile.primary_impact]:
        raise DatasetContractError("manifest observed impact does not match profile")
    if manifest["provenance"] != {
        "source": "controlled_experiment",
        "controlled": True,
        "pilot_only": True,
        "production_analytics_eligible": False,
    }:
        raise DatasetContractError("instrumentation run must remain pilot-only")
    if manifest["collection"]["collector_sha256"] != collector_source_sha256():
        raise DatasetContractError("manifest collector hash does not match")

    security = _fixed_security()
    if specification["security"] != security:
        raise DatasetContractError("instrumentation security policy is not allowlisted")
    if specification["claim_control"] != {
        "pilot_only": True,
        "training_eligible": False,
        "changes_frozen_feature_set": False,
        "simulator_receipt_is_model_feature": False,
    }:
        raise DatasetContractError("instrumentation claim control is invalid")
    if specification["input_policy"] != {
        "attacker_controlled_input": False,
        "fixed_entrypoint_only": True,
        "raw_cowrie_command_allowed": False,
    }:
        raise DatasetContractError("instrumentation input policy is not fail closed")
    if manifest["execution_boundary"] != {
        "kind": "safe_container",
        "metric_scopes": ["pi_sensor"],
        "execution_observed": True,
        "backend_id": "service-pressure-instrumentation-pi-v2",
        "backend_image_sha256": specification["runner"]["image_id"].removeprefix(
            "sha256:"
        ),
        "network_policy_sha256": canonical_sha256(security),
    }:
        raise DatasetContractError("manifest execution boundary does not match specification")
    if manifest["safety"] != {
        "bounded_benign_workload": True,
        "actual_malware_used": False,
        "public_or_third_party_target_used": False,
        "default_deny_egress": True,
        "egress_enforcement_scope": "execution_boundary",
        "hard_resource_limits": True,
        "watchdog_timeout_seconds": 40,
    }:
        raise DatasetContractError("manifest safety block is not allowlisted")
    if manifest["timing"] != {
        "timezone": "UTC",
        "sample_interval_seconds": 1,
        "baseline_seconds": 30,
        "workload_seconds": 30,
        "recovery_seconds": 30,
    }:
        raise DatasetContractError("instrumentation timing must remain 30/30/30 at 1 Hz")
    return profile


def validate_observed_impact_evidence(
    manifest: Mapping[str, Any],
    specification: Mapping[str, Any],
    execution_receipt: Mapping[str, Any],
) -> dict[str, Any]:
    """Fail closed unless the workload receipt proves its assigned treatment occurred."""

    summary = execution_receipt.get("workload_summary")
    if not isinstance(summary, Mapping):
        raise DatasetContractError("execution receipt lacks a workload summary")
    if summary.get("schema_version") != "poc_workload_summary.v2":
        raise DatasetContractError("instrumentation requires workload summary v2 evidence")
    if summary.get("mode") != specification["parameters"]["mode"]:
        raise DatasetContractError("workload evidence mode does not match specification")

    integer_fields = ("operations", "errors", "attempts", "rejected")
    if any(
        not isinstance(summary.get(field), int) or summary[field] < 0
        for field in integer_fields
    ):
        raise DatasetContractError("workload evidence counters are invalid")
    attempts = summary["attempts"]
    errors = summary["errors"]
    rejected = summary["rejected"]
    if attempts <= 0 or attempts != summary["operations"] + errors:
        raise DatasetContractError("workload evidence attempts do not reconcile")
    if rejected > errors:
        raise DatasetContractError("workload rejected count exceeds errors")
    latency_p95_ms = summary.get("latency_p95_ms")
    if (
        not isinstance(latency_p95_ms, (int, float))
        or isinstance(latency_p95_ms, bool)
        or not math.isfinite(float(latency_p95_ms))
        or latency_p95_ms < 0
    ):
        raise DatasetContractError("workload latency evidence is invalid")

    gate = specification["observed_impact_gate"]
    error_fraction = errors / attempts
    if attempts < gate["minimum_attempts"]:
        raise DatasetContractError("observed-impact gate failed: insufficient attempts")
    if error_fraction < gate["minimum_error_fraction"]:
        raise DatasetContractError("observed-impact gate failed: error fraction too low")
    if error_fraction > gate["maximum_error_fraction"]:
        raise DatasetContractError("observed-impact gate failed: error fraction too high")
    if rejected < gate["minimum_rejected"]:
        raise DatasetContractError("observed-impact gate failed: insufficient rejections")
    maximum_rejected = gate["maximum_rejected"]
    if maximum_rejected is not None and rejected > maximum_rejected:
        raise DatasetContractError("observed-impact gate failed: too many rejections")
    if latency_p95_ms < gate["minimum_latency_p95_ms"]:
        raise DatasetContractError("observed-impact gate failed: p95 latency too low")

    return {
        "gate_type": gate["gate_type"],
        "attempts": attempts,
        "operations": summary["operations"],
        "errors": errors,
        "error_fraction": error_fraction,
        "rejected": rejected,
        "latency_p95_ms": float(latency_p95_ms),
        "passed": True,
        "simulator_receipt_is_model_feature": False,
        "scenario_id": manifest["workload"]["scenario_id"],
    }


def build_service_pressure_instrumentation_matrix(
    *,
    generation: str,
    experiment_id: str,
    image_id: str,
    implementation_sha256: str,
    repo_commit: str,
    environment_signature_sha256: str,
    sensor_id: str,
    host_id: str,
    collector_id: str,
    protocol_path: Path,
    catalog_path: Path,
    schema_dir: Path,
) -> tuple[dict[str, Any], list[tuple[dict[str, Any], dict[str, Any] | None]]]:
    """Build one excluded instrumentation run for each frozen protocol scenario."""

    if generation != "v2":
        raise DatasetContractError("service-pressure instrumentation requires generation v2")
    if not image_id.startswith("sha256:") or len(image_id) != 71:
        raise DatasetContractError("instrumentation image_id is invalid")
    for label, value, valid_lengths in (
        ("implementation hash", implementation_sha256, {64}),
        ("repository commit", repo_commit, {40, 64}),
        ("environment signature", environment_signature_sha256, {64}),
    ):
        if len(value) not in valid_lengths or any(ch not in "0123456789abcdef" for ch in value):
            raise DatasetContractError(f"instrumentation {label} is invalid")

    protocol = _load_mapping(protocol_path, "hardware-impact protocol")
    summary = validate_hardware_impact_protocol(protocol)
    protocol_scenario_ids = list(_protocol_scenarios(protocol))
    if protocol_scenario_ids != list(PROFILES):
        raise DatasetContractError("instrumentation profiles do not exactly cover protocol order")
    catalog = _load_mapping(catalog_path, "scenario catalog")
    catalog_hash = _sha256_bytes(catalog_path)
    collector_hash = collector_source_sha256()
    telemetry_hash = telemetry_schema_sha256(schema_dir)
    security = _fixed_security()
    documents: list[tuple[dict[str, Any], dict[str, Any] | None]] = []
    matrix_runs: list[dict[str, Any]] = []

    for order, scenario_id in enumerate(protocol_scenario_ids, start=1):
        profile = PROFILES[scenario_id]
        slug = SCENARIO_SLUGS[scenario_id]
        run_id = f"run-service-pressure-{generation}-{slug}-r01"
        controlled = profile.mode is not None
        specification: dict[str, Any] | None = None
        if controlled:
            specification = {
                "schema_version": SPEC_SCHEMA_VERSION,
                "spec_id": f"spec-service-pressure-{generation}-{slug}-r01",
                "experiment_protocol": {
                    "schema_version": protocol["schema_version"],
                    "protocol_id": protocol["protocol_id"],
                    "protocol_sha256": protocol["protocol_sha256"],
                },
                "scenario_catalog_sha256": catalog_hash,
                "telemetry_contract": {
                    "schema_version": "hardware_telemetry_sample.v1",
                    "schema_sha256": telemetry_hash,
                    "collector_source_sha256": collector_hash,
                },
                "scenario_id": scenario_id,
                "treatment": {
                    "treatment_id": profile.treatment_id,
                    "workload_family": profile.workload_family,
                    "protocol_intensity": profile.protocol_intensity,
                    "protocol_intensity_unit": profile.protocol_intensity_unit,
                },
                "runner": {
                    "kind": "oci_container_on_pi",
                    "runtime": "docker",
                    "image_id": image_id,
                    "entrypoint_id": "poc_workload_v2",
                    "implementation_sha256": implementation_sha256,
                },
                "security": dict(security),
                "limits": {
                    "cpu_limit_cores": profile.cpu_limit_cores,
                    "memory_max_bytes": 134217728,
                    "pids_max": 16,
                    "output_max_bytes": 4096,
                },
                "timing": {
                    "workload_seconds": 30,
                    "binary_extra_seconds": 2,
                    "watchdog_timeout_seconds": 40,
                    "termination_grace_seconds": 2,
                },
                "parameters": {
                    "mode": profile.mode,
                    "workers": profile.workers,
                    "duty_percent": profile.duty_percent,
                    "duty_period_ms": 100,
                    "requests_per_second": profile.requests_per_second,
                    "work_iterations": profile.work_iterations,
                    "connection_mode": profile.connection_mode,
                    "service_capacity": profile.service_capacity,
                    "handler_delay_ms": profile.handler_delay_ms,
                    "deterministic_seed": 2026090200 + order,
                },
                "observed_impact_gate": {
                    "gate_type": profile.evidence_gate_type,
                    "minimum_attempts": profile.minimum_attempts,
                    "minimum_error_fraction": profile.minimum_error_fraction,
                    "maximum_error_fraction": profile.maximum_error_fraction,
                    "minimum_rejected": profile.minimum_rejected,
                    "maximum_rejected": profile.maximum_rejected,
                    "minimum_latency_p95_ms": profile.minimum_latency_p95_ms,
                },
                "host_gates": {
                    "minimum_available_memory_bytes": 2147483648,
                    "minimum_free_disk_bytes": 5368709120,
                    "maximum_temperature_c": 75,
                    "maximum_load_1m": 3,
                },
                "input_policy": {
                    "attacker_controlled_input": False,
                    "fixed_entrypoint_only": True,
                    "raw_cowrie_command_allowed": False,
                },
                "claim_control": {
                    "pilot_only": True,
                    "training_eligible": False,
                    "changes_frozen_feature_set": False,
                    "simulator_receipt_is_model_feature": False,
                },
            }

        if controlled:
            workload = {
                "scenario_catalog_version": catalog["schema_version"],
                "scenario_id": scenario_id,
                "family": profile.workload_family,
                "variant_id": f"service-pressure-{slug}-v2",
                "implementation_id": "poc-workload-v2",
                "implementation_sha256": implementation_sha256,
                "intensity_percent": profile.manifest_intensity_percent,
                "intensity_basis": profile.intensity_basis,
                "background_load_profile": "ordinary-decoy-stack",
            }
            boundary = {
                "kind": "safe_container",
                "metric_scopes": ["pi_sensor"],
                "execution_observed": True,
                "backend_id": "service-pressure-instrumentation-pi-v2",
                "backend_image_sha256": image_id.removeprefix("sha256:"),
                "network_policy_sha256": canonical_sha256(security),
            }
            safety = {
                "bounded_benign_workload": True,
                "actual_malware_used": False,
                "public_or_third_party_target_used": False,
                "default_deny_egress": True,
                "egress_enforcement_scope": "execution_boundary",
                "hard_resource_limits": True,
                "watchdog_timeout_seconds": 40,
            }
        else:
            workload = {
                "scenario_catalog_version": catalog["schema_version"],
                "scenario_id": scenario_id,
                "family": "none",
                "variant_id": "service-pressure-idle-v2",
                "implementation_id": "none-v1",
                "implementation_sha256": "0" * 64,
                "intensity_percent": 0,
                "intensity_basis": "none",
                "background_load_profile": "ordinary-decoy-stack",
            }
            boundary = {
                "kind": "none",
                "metric_scopes": ["pi_sensor"],
                "execution_observed": False,
                "backend_id": None,
                "backend_image_sha256": None,
                "network_policy_sha256": None,
            }
            safety = {
                "bounded_benign_workload": True,
                "actual_malware_used": False,
                "public_or_third_party_target_used": False,
                "default_deny_egress": False,
                "egress_enforcement_scope": "not_applicable_no_execution",
                "hard_resource_limits": True,
                "watchdog_timeout_seconds": 120,
            }

        manifest = {
            "schema_version": "experiment_run_manifest.v1",
            "run_id": run_id,
            "experiment_id": experiment_id,
            "state": "planned",
            "provenance": {
                "source": "controlled_experiment",
                "controlled": True,
                "pilot_only": True,
                "production_analytics_eligible": False,
            },
            "sensor": {
                "sensor_id": sensor_id,
                "host_id": host_id,
                "repo_commit": repo_commit,
                "cowrie_backend": "shell",
                "environment_signature_sha256": environment_signature_sha256,
            },
            "execution_boundary": boundary,
            "timing": {
                "timezone": "UTC",
                "sample_interval_seconds": 1,
                "baseline_seconds": 30,
                "workload_seconds": 30,
                "recovery_seconds": 30,
            },
            "workload": workload,
            "labels": {
                "scenario_disposition": profile.disposition,
                "primary_impact": profile.primary_impact,
                "observed_impacts": [profile.primary_impact],
                "ground_truth_ttps": list(profile.ground_truth_ttps),
                "label_source": "scenario_manifest_plus_observed_evidence",
                "evidence_receipt_ids": [],
            },
            "collection": {
                "telemetry_schema_version": "hardware_telemetry_sample.v1",
                "collector_id": collector_id,
                "collector_sha256": collector_hash,
                "command_events_required": False,
                "raw_data_immutable": True,
            },
            "split_groups": {
                "scenario_variant_group": f"service-pressure-{slug}-v2",
                "workload_family_group": profile.workload_family,
                "command_template_group": "no-command",
                "collection_batch": f"service-pressure-{generation}-instrumentation-r01",
                "environment_group": "pi5-safe-container-v2",
            },
            "safety": safety,
        }
        if specification is not None:
            validate_service_pressure_contract(
                manifest,
                specification,
                protocol=protocol,
                catalog=catalog,
                catalog_sha256=catalog_hash,
                schema_dir=schema_dir,
            )
        documents.append((manifest, specification))
        matrix_runs.append(
            {
                "order": order,
                "run_id": run_id,
                "scenario_id": scenario_id,
                "controlled_workload": controlled,
                "workload_spec_id": specification["spec_id"] if specification else None,
                "treatment_id": profile.treatment_id,
                "protocol_intensity": profile.protocol_intensity,
                "protocol_intensity_unit": profile.protocol_intensity_unit,
                "primary_impact": profile.primary_impact,
                "planned_manifest_sha256": canonical_sha256(manifest),
                "workload_spec_sha256": (
                    canonical_sha256(specification) if specification is not None else None
                ),
            }
        )

    matrix: dict[str, Any] = {
        "schema_version": MATRIX_SCHEMA_VERSION,
        "generation": generation,
        "experiment_id": experiment_id,
        "status": "planned",
        "purpose": "candidate_instrumentation_only",
        "pilot_only": True,
        "training_eligible": False,
        "changes_frozen_feature_set": False,
        "repetitions": 1,
        "scenario_count": len(PROFILES),
        "run_count": len(PROFILES),
        "sample_interval_seconds": 1,
        "seconds_per_run": 90,
        "estimated_total_seconds": len(PROFILES) * 90,
        "experiment_protocol": {
            "schema_version": protocol["schema_version"],
            "protocol_id": summary["protocol_id"],
            "protocol_sha256": summary["protocol_sha256"],
        },
        "artifact_bindings": {
            "scenario_catalog_sha256": catalog_hash,
            "collector_source_sha256": collector_hash,
            "telemetry_schema_sha256": telemetry_hash,
            "image_id": image_id,
            "implementation_sha256": implementation_sha256,
            "repo_commit": repo_commit,
            "environment_signature_sha256": environment_signature_sha256,
        },
        "runs": matrix_runs,
    }
    matrix["matrix_sha256"] = canonical_sha256(matrix)
    return matrix, documents


@dataclass(frozen=True)
class CandidateSignal:
    signal_id: str
    path: str
    scope: str
    unit: str


def _candidate_signals() -> tuple[CandidateSignal, ...]:
    host = (
        ("host_cpu_psi_some", "cpu.pressure.some.stall_usec_per_second", "usec_per_second"),
        ("host_memory_psi_some", "memory.pressure.some.stall_usec_per_second", "usec_per_second"),
        ("host_memory_psi_full", "memory.pressure.full.stall_usec_per_second", "usec_per_second"),
        ("host_io_psi_some", "disk.pressure.some.stall_usec_per_second", "usec_per_second"),
        ("host_io_psi_full", "disk.pressure.full.stall_usec_per_second", "usec_per_second"),
        ("host_tcp_established", "network.tcp_states.established", "count"),
        ("host_tcp_syn_received", "network.tcp_states.syn_received", "count"),
        ("host_tcp_time_wait", "network.tcp_states.time_wait", "count"),
        ("host_tcp_total", "network.tcp_states.total", "count"),
        ("host_sockets_used", "network.socket_summary.sockets_used", "count"),
        ("host_tcp_allocated", "network.socket_summary.tcp_allocated", "count"),
        ("host_tcp_memory_pages", "network.socket_summary.tcp_memory_pages", "pages"),
        ("host_listen_overflows_rate", "network.tcp_pressure.listen_overflows_per_second", "events_per_second"),
        ("host_listen_drops_rate", "network.tcp_pressure.listen_drops_per_second", "events_per_second"),
        ("host_request_queue_drops_rate", "network.tcp_pressure.request_queue_full_drops_per_second", "events_per_second"),
        ("host_backlog_drops_rate", "network.tcp_pressure.backlog_drops_per_second", "events_per_second"),
        ("host_tcp_memory_pressure_rate", "network.tcp_pressure.memory_pressure_events_per_second", "events_per_second"),
        ("host_receive_queue_drops_rate", "network.tcp_pressure.receive_queue_drops_per_second", "events_per_second"),
    )
    target = (
        ("target_tcp_established", "process.target.tcp_states.established", "count"),
        ("target_tcp_time_wait", "process.target.tcp_states.time_wait", "count"),
        ("target_tcp_total", "process.target.tcp_states.total", "count"),
        ("target_sockets_used", "process.target.socket_summary.sockets_used", "count"),
        ("target_tcp_allocated", "process.target.socket_summary.tcp_allocated", "count"),
        ("target_listen_drops_rate", "process.target.tcp_pressure.listen_drops_per_second", "events_per_second"),
        ("target_backlog_drops_rate", "process.target.tcp_pressure.backlog_drops_per_second", "events_per_second"),
        ("cgroup_cpu_usage_rate", "process.target.cgroup.cpu.usage_usec_per_second", "usec_per_second"),
        ("cgroup_cpu_throttled_rate", "process.target.cgroup.cpu.throttled_usec_per_second", "usec_per_second"),
        ("cgroup_cpu_throttled_periods_rate", "process.target.cgroup.cpu.throttled_periods_per_second", "periods_per_second"),
        ("cgroup_memory_current", "process.target.cgroup.memory.current_bytes", "bytes"),
        ("cgroup_memory_high_events_rate", "process.target.cgroup.memory.high_events_per_second", "events_per_second"),
        ("cgroup_pids_current", "process.target.cgroup.pids.current", "count"),
        ("cgroup_pids_max_events_rate", "process.target.cgroup.pids.max_events_per_second", "events_per_second"),
        ("cgroup_io_read_rate", "process.target.cgroup.io.read_bytes_per_second", "bytes_per_second"),
        ("cgroup_io_write_rate", "process.target.cgroup.io.write_bytes_per_second", "bytes_per_second"),
        ("cgroup_cpu_psi_some", "process.target.cgroup.pressure.cpu.some.stall_usec_per_second", "usec_per_second"),
        ("cgroup_memory_psi_some", "process.target.cgroup.pressure.memory.some.stall_usec_per_second", "usec_per_second"),
        ("cgroup_io_psi_some", "process.target.cgroup.pressure.io.some.stall_usec_per_second", "usec_per_second"),
    )
    return tuple(
        CandidateSignal(signal_id, path, "host", unit)
        for signal_id, path, unit in host
    ) + tuple(
        CandidateSignal(signal_id, path, "target", unit)
        for signal_id, path, unit in target
    )


def _lookup_number(document: Mapping[str, Any], path: str) -> float | None:
    current: Any = document
    for component in path.split("."):
        if not isinstance(current, Mapping) or component not in current:
            return None
        current = current[component]
    if isinstance(current, bool) or not isinstance(current, (int, float)):
        return None
    value = float(current)
    return value if math.isfinite(value) else None


def _percentile(values: Sequence[float], percentile: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * percentile / 100.0
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return float(ordered[lower])
    weight = position - lower
    return float(ordered[lower] * (1.0 - weight) + ordered[upper] * weight)


def _phase_stats(
    samples: Sequence[Mapping[str, Any]], path: str, expected_samples: int
) -> dict[str, Any]:
    values = [value for sample in samples if (value := _lookup_number(sample, path)) is not None]
    return {
        "expected_samples": expected_samples,
        "observed_samples": len(values),
        "coverage": len(values) / expected_samples,
        "mean": float(fmean(values)) if values else None,
        "p95": _percentile(values, 95.0) if values else None,
        "max": float(max(values)) if values else None,
    }


def summarize_service_pressure_signals(
    manifest: Mapping[str, Any],
    samples: Sequence[Mapping[str, Any]],
    *,
    collection_receipt_sha256: str,
    source_segments: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Summarize availability and baseline-to-workload deltas without selecting features."""

    if manifest.get("schema_version") != "experiment_run_manifest.v1":
        raise DatasetContractError("unsupported manifest schema")
    if manifest.get("state") != "completed":
        raise DatasetContractError("signal report requires a completed manifest")
    if manifest.get("provenance", {}).get("pilot_only") is not True:
        raise DatasetContractError("signal report accepts only pilot-only runs")
    if not samples:
        raise DatasetContractError("signal report telemetry is empty")
    seen_sequences: set[int] = set()
    by_phase: dict[str, list[Mapping[str, Any]]] = {
        "baseline": [],
        "workload": [],
        "recovery": [],
    }
    for index, sample in enumerate(samples):
        if sample.get("run_id") != manifest["run_id"]:
            raise DatasetContractError(f"sample[{index}] run_id does not match manifest")
        if sample.get("experiment_id") != manifest["experiment_id"]:
            raise DatasetContractError(f"sample[{index}] experiment_id does not match manifest")
        sequence = sample.get("time", {}).get("sequence")
        if not isinstance(sequence, int) or isinstance(sequence, bool):
            raise DatasetContractError(f"sample[{index}] sequence is invalid")
        if sequence in seen_sequences:
            raise DatasetContractError(f"duplicate telemetry sequence {sequence}")
        seen_sequences.add(sequence)
        phase = sample.get("phase")
        if phase not in by_phase:
            raise DatasetContractError(f"sample[{index}] phase is unsupported")
        if sample.get("quality", {}).get("valid") is True:
            by_phase[phase].append(sample)

    interval = float(manifest["timing"]["sample_interval_seconds"])
    expected = {
        phase: round(float(manifest["timing"][f"{phase}_seconds"]) / interval)
        for phase in by_phase
    }
    signals: list[dict[str, Any]] = []
    for candidate in _candidate_signals():
        baseline = _phase_stats(by_phase["baseline"], candidate.path, expected["baseline"])
        workload = _phase_stats(by_phase["workload"], candidate.path, expected["workload"])
        recovery = _phase_stats(by_phase["recovery"], candidate.path, expected["recovery"])
        baseline_applicable = candidate.scope == "host"
        delta_mean = (
            workload["mean"] - baseline["mean"]
            if baseline_applicable
            and workload["mean"] is not None
            and baseline["mean"] is not None
            else None
        )
        delta_p95 = (
            workload["p95"] - baseline["p95"]
            if baseline_applicable
            and workload["p95"] is not None
            and baseline["p95"] is not None
            else None
        )
        review_eligible = workload["coverage"] >= 0.9 and (
            not baseline_applicable or baseline["coverage"] >= 0.9
        )
        signals.append(
            {
                "signal_id": candidate.signal_id,
                "path": candidate.path,
                "scope": candidate.scope,
                "unit": candidate.unit,
                "baseline_applicable": baseline_applicable,
                "baseline": baseline,
                "workload": workload,
                "recovery": recovery,
                "workload_delta_from_baseline_mean": delta_mean,
                "workload_delta_from_baseline_p95": delta_p95,
                "eligible_for_feature_freeze_review": review_eligible,
            }
        )

    phase_quality = {
        phase: {
            "expected_samples": expected[phase],
            "valid_samples": len(by_phase[phase]),
            "valid_sample_coverage": len(by_phase[phase]) / expected[phase],
        }
        for phase in by_phase
    }
    report: dict[str, Any] = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "report_id": "service-pressure-signal-v1-"
        + sha256(manifest["run_id"].encode("utf-8")).hexdigest()[:40],
        "run_id": manifest["run_id"],
        "experiment_id": manifest["experiment_id"],
        "purpose": "candidate_availability_and_delta_review",
        "model_feature_eligible": False,
        "changes_frozen_feature_set": False,
        "source_binding": {
            "manifest_content_sha256": canonical_sha256(manifest),
            "collection_receipt_sha256": collection_receipt_sha256,
            "segments": [dict(segment) for segment in source_segments],
        },
        "evaluation_context": {
            "scenario_id": manifest["workload"]["scenario_id"],
            "primary_impact": manifest["labels"]["primary_impact"],
            "scenario_disposition": manifest["labels"]["scenario_disposition"],
            "excluded_from_candidate_values": True,
        },
        "quality": {
            "phase_coverage": phase_quality,
            "candidate_signal_count": len(signals),
            "feature_freeze_review_eligible_count": sum(
                signal["eligible_for_feature_freeze_review"] for signal in signals
            ),
        },
        "signals": signals,
    }
    report["report_sha256"] = canonical_sha256(report)
    return report
