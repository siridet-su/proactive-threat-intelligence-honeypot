"""Fail-closed Docker lifecycle for the bounded Raspberry Pi hardware PoC."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import subprocess
from typing import Any, Mapping

import psutil

from .batch import canonical_sha256
from .collector import Probe, collector_source_sha256
from .dataset import DatasetContractError


SPEC_SCHEMA_VERSION = "pi_poc_workload_spec.v1"
EXECUTION_RECEIPT_SCHEMA_VERSION = "pi_poc_execution_receipt.v1"


@dataclass(frozen=True)
class ScenarioProfile:
    disposition: str
    family: str
    primary_impact: str
    ground_truth_ttps: tuple[str, ...]
    mode: str
    intensity_percent: int
    intensity_basis: str
    cpu_limit_cores: float
    workers: int
    duty_percent: int
    requests_per_second: int
    work_iterations: int


PROFILES: dict[str, ScenarioProfile] = {
    "poc_pi_benign_compute_control": ScenarioProfile(
        disposition="benign_control",
        family="poc_bounded_compute_control",
        primary_impact="COMPUTE_SATURATION",
        ground_truth_ttps=(),
        mode="compute",
        intensity_percent=25,
        intensity_basis="assigned_cpu_capacity",
        cpu_limit_cores=0.25,
        workers=1,
        duty_percent=100,
        requests_per_second=1,
        work_iterations=1,
    ),
    "poc_pi_compute_hijacking_simulation": ScenarioProfile(
        disposition="malicious_simulation",
        family="poc_bounded_compute_simulation",
        primary_impact="COMPUTE_SATURATION",
        ground_truth_ttps=("T1496.001",),
        mode="compute",
        intensity_percent=75,
        intensity_basis="assigned_cpu_capacity",
        cpu_limit_cores=0.75,
        workers=1,
        duty_percent=100,
        requests_per_second=1,
        work_iterations=1,
    ),
    "poc_pi_benign_service_load_control": ScenarioProfile(
        disposition="benign_control",
        family="poc_bounded_local_service_control",
        primary_impact="SERVICE_PRESSURE",
        ground_truth_ttps=(),
        mode="service",
        intensity_percent=25,
        intensity_basis="assigned_service_capacity",
        cpu_limit_cores=0.25,
        workers=2,
        duty_percent=100,
        requests_per_second=10,
        work_iterations=500,
    ),
    "poc_pi_service_exhaustion_simulation": ScenarioProfile(
        disposition="malicious_simulation",
        family="poc_bounded_local_service_simulation",
        primary_impact="SERVICE_PRESSURE",
        ground_truth_ttps=("T1499.002",),
        mode="service",
        intensity_percent=75,
        intensity_basis="assigned_service_capacity",
        cpu_limit_cores=0.75,
        workers=4,
        duty_percent=100,
        requests_per_second=150,
        work_iterations=5000,
    ),
}

SCENARIO_SLUGS = {
    "neutral_idle": "idle",
    "poc_pi_benign_compute_control": "benign-compute",
    "poc_pi_compute_hijacking_simulation": "t1496-001",
    "poc_pi_benign_service_load_control": "benign-service",
    "poc_pi_service_exhaustion_simulation": "t1499-002",
}


def _iso_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def _catalog_scenario(catalog: Mapping[str, Any], scenario_id: str) -> Mapping[str, Any]:
    matches = [
        item
        for item in catalog.get("scenarios", [])
        if isinstance(item, Mapping) and item.get("scenario_id") == scenario_id
    ]
    if len(matches) != 1:
        raise DatasetContractError(
            f"scenario catalog must contain exactly one scenario_id={scenario_id}"
        )
    return matches[0]


def validate_pi_poc_contract(
    manifest: Mapping[str, Any],
    specification: Mapping[str, Any],
    *,
    catalog_path: Path,
) -> ScenarioProfile:
    """Prove that labels, a fixed profile, and the safe boundary agree."""

    if specification.get("schema_version") != SPEC_SCHEMA_VERSION:
        raise DatasetContractError("unsupported Pi PoC workload specification")
    scenario_id = specification.get("scenario_id")
    if scenario_id not in PROFILES:
        raise DatasetContractError("Pi PoC scenario is not allowlisted")
    profile = PROFILES[scenario_id]

    catalog_bytes = catalog_path.read_bytes()
    catalog = json.loads(catalog_bytes)
    if not isinstance(catalog, Mapping):
        raise DatasetContractError("scenario catalog must contain one object")
    if specification["scenario_catalog_sha256"] != sha256(catalog_bytes).hexdigest():
        raise DatasetContractError("scenario catalog hash does not match specification")
    scenario = _catalog_scenario(catalog, scenario_id)
    catalog_expected = {
        "disposition": profile.disposition,
        "safe_workload_family": profile.family,
        "execution_boundary": "safe_container",
        "target_metric_scopes": ["pi_sensor"],
        "primary_impact": profile.primary_impact,
        "ground_truth_ttps": list(profile.ground_truth_ttps),
    }
    for field, expected in catalog_expected.items():
        if scenario.get(field) != expected:
            raise DatasetContractError(f"scenario catalog {field} does not match profile")

    workload = manifest["workload"]
    labels = manifest["labels"]
    boundary = manifest["execution_boundary"]
    safety = manifest["safety"]
    parameters = specification["parameters"]
    limits = specification["limits"]
    timing = specification["timing"]
    runner = specification["runner"]
    security = specification["security"]

    manifest_expected = {
        "scenario_id": scenario_id,
        "family": profile.family,
        "intensity_percent": profile.intensity_percent,
        "intensity_basis": profile.intensity_basis,
        "implementation_sha256": runner["implementation_sha256"],
    }
    for field, expected in manifest_expected.items():
        if workload.get(field) != expected:
            raise DatasetContractError(f"manifest workload.{field} does not match profile")
    label_expected = {
        "scenario_disposition": profile.disposition,
        "primary_impact": profile.primary_impact,
        "ground_truth_ttps": list(profile.ground_truth_ttps),
    }
    for field, expected in label_expected.items():
        if labels.get(field) != expected:
            raise DatasetContractError(f"manifest labels.{field} does not match profile")
    if profile.primary_impact not in labels["observed_impacts"]:
        raise DatasetContractError("primary impact is absent from observed impacts")

    parameter_expected = {
        "mode": profile.mode,
        "workers": profile.workers,
        "duty_percent": profile.duty_percent,
        "duty_period_ms": 100,
        "requests_per_second": profile.requests_per_second,
        "work_iterations": profile.work_iterations,
    }
    for field, expected in parameter_expected.items():
        if parameters.get(field) != expected:
            raise DatasetContractError(f"workload parameters.{field} is not allowlisted")
    if limits["cpu_limit_cores"] != profile.cpu_limit_cores:
        raise DatasetContractError("CPU limit does not match the fixed scenario profile")

    if manifest["timing"]["workload_seconds"] != timing["workload_seconds"]:
        raise DatasetContractError("manifest and specification duration do not match")
    if timing["watchdog_timeout_seconds"] < (
        timing["workload_seconds"]
        + timing["binary_extra_seconds"]
        + timing["termination_grace_seconds"]
    ):
        raise DatasetContractError("watchdog cannot cover workload and termination grace")
    if safety["watchdog_timeout_seconds"] != timing["watchdog_timeout_seconds"]:
        raise DatasetContractError("manifest and specification watchdog do not match")

    if boundary != {
        "kind": "safe_container",
        "metric_scopes": ["pi_sensor"],
        "execution_observed": True,
        "backend_id": "poc-pi-safe-container-v1",
        "backend_image_sha256": runner["image_id"].removeprefix("sha256:"),
        "network_policy_sha256": canonical_sha256(security),
    }:
        raise DatasetContractError("manifest execution boundary does not match specification")
    if safety != {
        "bounded_benign_workload": True,
        "actual_malware_used": False,
        "public_or_third_party_target_used": False,
        "default_deny_egress": True,
        "egress_enforcement_scope": "execution_boundary",
        "hard_resource_limits": True,
        "watchdog_timeout_seconds": timing["watchdog_timeout_seconds"],
    }:
        raise DatasetContractError("manifest safety block is not the fixed Pi PoC policy")
    if specification["input_policy"] != {
        "attacker_controlled_input": False,
        "fixed_entrypoint_only": True,
        "raw_cowrie_command_allowed": False,
    }:
        raise DatasetContractError("Pi PoC input policy is not fail closed")
    if security != {
        "network_mode": "none",
        "read_only_rootfs": True,
        "cap_drop_all": True,
        "no_new_privileges": True,
        "run_as_uid": 65532,
        "run_as_gid": 65532,
    }:
        raise DatasetContractError("Pi PoC security policy is not allowlisted")
    return profile


def build_pi_poc_matrix(
    *,
    experiment_id: str,
    repetitions: int,
    image_id: str,
    implementation_sha256: str,
    repo_commit: str,
    environment_signature_sha256: str,
    sensor_id: str,
    host_id: str,
    collector_id: str,
    catalog_path: Path,
) -> tuple[dict[str, Any], list[tuple[dict[str, Any], dict[str, Any] | None]]]:
    """Create an interleaved 3-repetition smoke-test matrix without writing it."""

    if repetitions != 3:
        raise DatasetContractError("Pi PoC v1 requires exactly three repetitions")
    if not image_id.startswith("sha256:") or len(image_id) != 71:
        raise DatasetContractError("Pi PoC image_id is invalid")
    if len(implementation_sha256) != 64:
        raise DatasetContractError("Pi PoC implementation hash is invalid")
    if len(repo_commit) not in {40, 64}:
        raise DatasetContractError("Pi PoC repository commit is invalid")
    if len(environment_signature_sha256) != 64:
        raise DatasetContractError("Pi PoC environment signature is invalid")

    catalog_hash = sha256(catalog_path.read_bytes()).hexdigest()
    security = {
        "network_mode": "none",
        "read_only_rootfs": True,
        "cap_drop_all": True,
        "no_new_privileges": True,
        "run_as_uid": 65532,
        "run_as_gid": 65532,
    }
    ordered_scenarios = ["neutral_idle", *PROFILES]
    documents: list[tuple[dict[str, Any], dict[str, Any] | None]] = []
    matrix_runs: list[dict[str, Any]] = []
    for repetition in range(1, repetitions + 1):
        for scenario_index, scenario_id in enumerate(ordered_scenarios):
            slug = SCENARIO_SLUGS[scenario_id]
            run_id = f"run-poc-pi-v1-{slug}-r{repetition:02d}"
            controlled = scenario_id != "neutral_idle"
            profile = PROFILES.get(scenario_id)
            specification: dict[str, Any] | None = None
            if profile is not None:
                specification = {
                    "schema_version": SPEC_SCHEMA_VERSION,
                    "spec_id": f"spec-poc-pi-v1-{slug}-r{repetition:02d}",
                    "scenario_catalog_sha256": catalog_hash,
                    "scenario_id": scenario_id,
                    "runner": {
                        "kind": "oci_container_on_pi",
                        "runtime": "docker",
                        "image_id": image_id,
                        "entrypoint_id": "poc_workload_v1",
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
                        "deterministic_seed": 2026090200
                        + scenario_index * 10
                        + repetition,
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
                }

            if profile is None:
                workload = {
                    "scenario_catalog_version": "cowrie_hardware_scenario_catalog.v1",
                    "scenario_id": "neutral_idle",
                    "family": "none",
                    "variant_id": "poc-pi-neutral-idle-v1",
                    "implementation_id": "none-v1",
                    "implementation_sha256": "0" * 64,
                    "intensity_percent": 0,
                    "intensity_basis": "none",
                    "background_load_profile": "ordinary-decoy-stack",
                }
                labels = {
                    "scenario_disposition": "neutral_baseline",
                    "primary_impact": "NO_MATERIAL_IMPACT",
                    "observed_impacts": ["NO_MATERIAL_IMPACT"],
                    "ground_truth_ttps": [],
                    "label_source": "scenario_manifest_plus_observed_evidence",
                    "evidence_receipt_ids": [],
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
            else:
                workload = {
                    "scenario_catalog_version": "cowrie_hardware_scenario_catalog.v1",
                    "scenario_id": scenario_id,
                    "family": profile.family,
                    "variant_id": f"poc-pi-{slug}-v1",
                    "implementation_id": "poc-workload-v1",
                    "implementation_sha256": implementation_sha256,
                    "intensity_percent": profile.intensity_percent,
                    "intensity_basis": profile.intensity_basis,
                    "background_load_profile": "ordinary-decoy-stack",
                }
                labels = {
                    "scenario_disposition": profile.disposition,
                    "primary_impact": profile.primary_impact,
                    "observed_impacts": [profile.primary_impact],
                    "ground_truth_ttps": list(profile.ground_truth_ttps),
                    "label_source": "scenario_manifest_plus_observed_evidence",
                    "evidence_receipt_ids": [],
                }
                boundary = {
                    "kind": "safe_container",
                    "metric_scopes": ["pi_sensor"],
                    "execution_observed": True,
                    "backend_id": "poc-pi-safe-container-v1",
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
                "labels": labels,
                "collection": {
                    "telemetry_schema_version": "hardware_telemetry_sample.v1",
                    "collector_id": collector_id,
                    "collector_sha256": "pending-generated-after-source-freeze",
                    "command_events_required": False,
                    "raw_data_immutable": True,
                },
                "split_groups": {
                    "scenario_variant_group": f"poc-pi-{slug}-v1",
                    "workload_family_group": (
                        profile.family if profile is not None else "none"
                    ),
                    "command_template_group": "no-command",
                    "collection_batch": f"poc-pi-v1-r{repetition:02d}",
                    "environment_group": "pi5-safe-container-v1",
                },
                "safety": safety,
            }
            matrix_runs.append(
                {
                    "order": len(matrix_runs) + 1,
                    "run_id": run_id,
                    "scenario_id": scenario_id,
                    "repetition": repetition,
                    "controlled_workload": controlled,
                }
            )
            documents.append((manifest, specification))

    source_hash = collector_source_sha256()
    for manifest, _ in documents:
        manifest["collection"]["collector_sha256"] = source_hash
    matrix = {
        "schema_version": "pi_poc_matrix.v1",
        "experiment_id": experiment_id,
        "status": "planned",
        "repetitions": repetitions,
        "scenario_count": len(ordered_scenarios),
        "run_count": len(documents),
        "sample_interval_seconds": 1,
        "seconds_per_run": 90,
        "estimated_total_seconds": len(documents) * 90,
        "collector_source_sha256": source_hash,
        "image_id": image_id,
        "implementation_sha256": implementation_sha256,
        "runs": matrix_runs,
    }
    matrix["matrix_sha256"] = canonical_sha256(matrix)
    return matrix, documents


def _run_docker(
    arguments: list[str],
    *,
    check: bool = True,
    timeout: float = 15,
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            ["docker", *arguments],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DatasetContractError(f"Docker command failed: {type(exc).__name__}") from exc
    if check and result.returncode != 0:
        detail = result.stderr.strip().splitlines()
        message = detail[-1][:300] if detail else "no diagnostic"
        raise DatasetContractError(f"Docker command rejected: {message}")
    return result


def pi_poc_preflight(
    manifest: Mapping[str, Any],
    specification: Mapping[str, Any],
    *,
    catalog_path: Path,
) -> dict[str, Any]:
    """Check image identity, Docker defenses, cgroup v2, and Pi headroom."""

    validate_pi_poc_contract(manifest, specification, catalog_path=catalog_path)
    if shutil.which("docker") is None:
        raise DatasetContractError("Docker CLI is unavailable")
    if not Path("/sys/fs/cgroup/cgroup.controllers").is_file():
        raise DatasetContractError("cgroup v2 is unavailable")

    image_id = specification["runner"]["image_id"]
    image_result = _run_docker(["image", "inspect", image_id])
    image_documents = json.loads(image_result.stdout)
    if not isinstance(image_documents, list) or len(image_documents) != 1:
        raise DatasetContractError("Docker image identity is ambiguous")
    image = image_documents[0]
    if image.get("Id") != image_id or image.get("Architecture") != "arm64":
        raise DatasetContractError("Docker image ID or architecture does not match")
    image_config = image.get("Config", {})
    if image_config.get("Entrypoint") != ["/poc-workload"]:
        raise DatasetContractError("Docker image has an unexpected entrypoint")
    if image_config.get("User") != "65532:65532":
        raise DatasetContractError("Docker image does not enforce the unprivileged user")
    revision = (image_config.get("Labels") or {}).get(
        "org.opencontainers.image.revision"
    )
    if revision != specification["runner"]["implementation_sha256"]:
        raise DatasetContractError("Docker image revision label does not match binary")

    security_result = _run_docker(["info", "--format", "{{json .SecurityOptions}}"])
    security_options = json.loads(security_result.stdout)
    rendered_security = " ".join(str(item) for item in security_options)
    if "seccomp" not in rendered_security:
        raise DatasetContractError("Docker default seccomp support is unavailable")

    container_name = DockerWorkloadLifecycle.container_name_for(manifest["run_id"])
    existing = _run_docker(["container", "inspect", container_name], check=False)
    if existing.returncode == 0:
        raise DatasetContractError("PoC container name already exists; cleanup is required")

    gates = specification["host_gates"]
    memory_available = int(psutil.virtual_memory().available)
    free_disk = int(shutil.disk_usage("/").free)
    load_1m = float(os.getloadavg()[0])
    temperature_path = Path("/sys/class/thermal/thermal_zone0/temp")
    try:
        temperature_c = float(temperature_path.read_text(encoding="ascii").strip()) / 1000
    except (OSError, ValueError) as exc:
        raise DatasetContractError("Pi temperature is unavailable") from exc
    if memory_available < gates["minimum_available_memory_bytes"]:
        raise DatasetContractError("Pi available memory is below the safety gate")
    if free_disk < gates["minimum_free_disk_bytes"]:
        raise DatasetContractError("Pi free disk is below the safety gate")
    if load_1m > gates["maximum_load_1m"]:
        raise DatasetContractError("Pi load is above the safety gate")
    if temperature_c > gates["maximum_temperature_c"]:
        raise DatasetContractError("Pi temperature is above the safety gate")

    return {
        "contract_valid": True,
        "execution_authorized": True,
        "execution_started": False,
        "container_name": container_name,
        "image_id": image_id,
        "architecture": image["Architecture"],
        "cgroup_version": 2,
        "docker_seccomp_available": True,
        "available_memory_bytes": memory_available,
        "free_disk_bytes": free_disk,
        "load_1m": load_1m,
        "temperature_c": temperature_c,
    }


class DockerWorkloadLifecycle:
    """Start exactly one fixed container during the workload phase and remove it."""

    def __init__(
        self,
        manifest: Mapping[str, Any],
        specification: Mapping[str, Any],
    ) -> None:
        self.manifest = manifest
        self.specification = specification
        self.container_name = self.container_name_for(manifest["run_id"])
        self._container_id: str | None = None
        self._container_id_sha256: str | None = None
        self._target_process_id: int | None = None
        self._started_at: datetime | None = None
        self._ended_at: datetime | None = None
        self._summary: dict[str, Any] | None = None
        self._cleanup_verified = False

    @staticmethod
    def container_name_for(run_id: str) -> str:
        return "chf-poc-" + sha256(run_id.encode("utf-8")).hexdigest()[:20]

    def _fixed_workload_arguments(self) -> list[str]:
        parameters = self.specification["parameters"]
        timing = self.specification["timing"]
        duration = timing["workload_seconds"] + timing["binary_extra_seconds"]
        return [
            f"--mode={parameters['mode']}",
            f"--duration={duration}s",
            f"--workers={parameters['workers']}",
            f"--duty-percent={parameters['duty_percent']}",
            f"--duty-period={parameters['duty_period_ms']}ms",
            f"--requests-per-second={parameters['requests_per_second']}",
            f"--work-iterations={parameters['work_iterations']}",
            f"--seed={parameters['deterministic_seed']}",
        ]

    def before_phase(self, phase: str, probe: Probe) -> None:
        if phase != "workload":
            return
        if self._container_id is not None:
            raise DatasetContractError("PoC workload container was already created")
        limits = self.specification["limits"]
        security = self.specification["security"]
        image_id = self.specification["runner"]["image_id"]
        create_arguments = [
            "create",
            "--name",
            self.container_name,
            "--pull=never",
            "--network=none",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true",
            f"--user={security['run_as_uid']}:{security['run_as_gid']}",
            f"--pids-limit={limits['pids_max']}",
            f"--memory={limits['memory_max_bytes']}",
            f"--memory-swap={limits['memory_max_bytes']}",
            f"--cpus={limits['cpu_limit_cores']}",
            f"--stop-timeout={self.specification['timing']['termination_grace_seconds']}",
            "--restart=no",
            "--log-driver=local",
            "--log-opt=max-size=64k",
            "--log-opt=max-file=1",
            "--label=org.proactive-threat-intelligence.purpose=bounded-hardware-poc",
            image_id,
            *self._fixed_workload_arguments(),
        ]
        created = _run_docker(create_arguments)
        container_id = created.stdout.strip()
        if len(container_id) != 64:
            raise DatasetContractError("Docker returned an invalid container identity")
        self._container_id = container_id
        self._container_id_sha256 = sha256(container_id.encode("ascii")).hexdigest()
        self._verify_created_container()
        _run_docker(["start", container_id])
        self._started_at = datetime.now(timezone.utc)
        inspected = self._inspect_container()
        process_id = int(inspected["State"]["Pid"])
        if not inspected["State"]["Running"] or process_id <= 0:
            raise DatasetContractError("PoC workload did not enter the running state")
        setter = getattr(probe, "set_target_process", None)
        if not callable(setter):
            raise DatasetContractError("collector probe cannot observe the target process")
        setter(process_id)
        self._target_process_id = process_id

    def _inspect_container(self) -> Mapping[str, Any]:
        if self._container_id is None:
            raise DatasetContractError("PoC workload container is unavailable")
        result = _run_docker(["container", "inspect", self._container_id])
        documents = json.loads(result.stdout)
        if not isinstance(documents, list) or len(documents) != 1:
            raise DatasetContractError("Docker container inspection is ambiguous")
        return documents[0]

    def _verify_created_container(self) -> None:
        inspected = self._inspect_container()
        limits = self.specification["limits"]
        security = self.specification["security"]
        host_config = inspected.get("HostConfig", {})
        config = inspected.get("Config", {})
        security_options = host_config.get("SecurityOpt") or []
        expected = {
            "Image": self.specification["runner"]["image_id"],
            "User": f"{security['run_as_uid']}:{security['run_as_gid']}",
            "NetworkMode": "none",
            "ReadonlyRootfs": True,
            "PidsLimit": limits["pids_max"],
            "Memory": limits["memory_max_bytes"],
            "MemorySwap": limits["memory_max_bytes"],
            "NanoCpus": int(limits["cpu_limit_cores"] * 1_000_000_000),
        }
        observed = {
            "Image": inspected.get("Image"),
            "User": config.get("User"),
            "NetworkMode": host_config.get("NetworkMode"),
            "ReadonlyRootfs": host_config.get("ReadonlyRootfs"),
            "PidsLimit": host_config.get("PidsLimit"),
            "Memory": host_config.get("Memory"),
            "MemorySwap": host_config.get("MemorySwap"),
            "NanoCpus": host_config.get("NanoCpus"),
        }
        if observed != expected:
            raise DatasetContractError("created container does not match fixed limits")
        if "ALL" not in (host_config.get("CapDrop") or []):
            raise DatasetContractError("created container did not drop all capabilities")
        if "no-new-privileges:true" not in security_options:
            raise DatasetContractError("created container lacks no-new-privileges")
        if inspected.get("Mounts"):
            raise DatasetContractError("created container unexpectedly has host mounts")

    def after_phase(self, phase: str, probe: Probe) -> None:
        if phase != "workload":
            return
        clearer = getattr(probe, "clear_target_process", None)
        if callable(clearer):
            clearer()
        if self._container_id is None:
            raise DatasetContractError("PoC workload container disappeared")
        _run_docker(
            [
                "stop",
                "--time",
                str(self.specification["timing"]["termination_grace_seconds"]),
                self._container_id,
            ],
            timeout=self.specification["timing"]["watchdog_timeout_seconds"],
        )
        self._ended_at = datetime.now(timezone.utc)
        inspected = self._inspect_container()
        if inspected["State"].get("ExitCode") != 0:
            raise DatasetContractError("PoC workload exited unsuccessfully")
        logs = _run_docker(["logs", self._container_id]).stdout.encode("utf-8")
        if len(logs) > self.specification["limits"]["output_max_bytes"]:
            raise DatasetContractError("PoC workload output exceeded its fixed limit")
        nonempty = [line for line in logs.decode("utf-8").splitlines() if line.strip()]
        if len(nonempty) != 1:
            raise DatasetContractError("PoC workload did not emit exactly one summary")
        summary = json.loads(nonempty[0])
        if summary.get("mode") != self.specification["parameters"]["mode"]:
            raise DatasetContractError("PoC workload summary mode does not match")
        if not isinstance(summary.get("operations"), int) or summary["operations"] <= 0:
            raise DatasetContractError("PoC workload reported no completed operations")
        self._summary = summary
        _run_docker(["rm", self._container_id])
        self._container_id = None
        missing = _run_docker(
            ["container", "inspect", self.container_name], check=False
        )
        self._cleanup_verified = missing.returncode != 0
        if not self._cleanup_verified:
            raise DatasetContractError("PoC workload cleanup could not be verified")

    def close(self, probe: Probe) -> None:
        clearer = getattr(probe, "clear_target_process", None)
        if callable(clearer):
            clearer()
        if self._container_id is not None:
            _run_docker(["rm", "--force", self._container_id], check=False)
            self._container_id = None

    def execution_receipt(self) -> dict[str, Any]:
        if (
            self._started_at is None
            or self._ended_at is None
            or self._summary is None
            or self._target_process_id is None
            or self._container_id_sha256 is None
            or not self._cleanup_verified
        ):
            raise DatasetContractError("PoC execution is incomplete")
        receipt: dict[str, Any] = {
            "schema_version": EXECUTION_RECEIPT_SCHEMA_VERSION,
            "receipt_id": "pi-poc-execution-v1-"
            + sha256(self.manifest["run_id"].encode("utf-8")).hexdigest()[:40],
            "run_id": self.manifest["run_id"],
            "spec_id": self.specification["spec_id"],
            "scenario_id": self.specification["scenario_id"],
            "state": "completed",
            "started_at": _iso_utc(self._started_at),
            "ended_at": _iso_utc(self._ended_at),
            "manifest_content_sha256": canonical_sha256(self.manifest),
            "specification_content_sha256": canonical_sha256(self.specification),
            "container_id_sha256": self._container_id_sha256,
            "image_id": self.specification["runner"]["image_id"],
            "target_process_id_sha256": sha256(
                f"{self.container_name}\0{self._target_process_id}".encode("utf-8")
            ).hexdigest(),
            "security": dict(self.specification["security"]),
            "limits": dict(self.specification["limits"]),
            "workload_summary": self._summary,
            "cleanup_verified": True,
        }
        receipt["receipt_sha256"] = canonical_sha256(receipt)
        return receipt
