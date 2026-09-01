from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from cowrie_hardware_fusion.batch import canonical_sha256
from cowrie_hardware_fusion.collector import (
    CollectorConfig,
    ProbeResult,
    collect_controlled_run,
    collector_source_sha256,
)
from cowrie_hardware_fusion.dataset import DatasetContractError
from cowrie_hardware_fusion.poc import build_pi_poc_matrix, validate_pi_poc_contract
from cowrie_hardware_fusion.spool import SpoolLimits


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _security() -> dict:
    return {
        "network_mode": "none",
        "read_only_rootfs": True,
        "cap_drop_all": True,
        "no_new_privileges": True,
        "run_as_uid": 65532,
        "run_as_gid": 65532,
    }


def _specification() -> dict:
    catalog_path = PROJECT_ROOT / "configs" / "scenario_catalog.v1.json"
    return {
        "schema_version": "pi_poc_workload_spec.v1",
        "spec_id": "poc-pi-benign-compute-r01",
        "scenario_catalog_sha256": sha256(catalog_path.read_bytes()).hexdigest(),
        "scenario_id": "poc_pi_benign_compute_control",
        "runner": {
            "kind": "oci_container_on_pi",
            "runtime": "docker",
            "image_id": "sha256:" + "1" * 64,
            "entrypoint_id": "poc_workload_v1",
            "implementation_sha256": "2" * 64,
        },
        "security": _security(),
        "limits": {
            "cpu_limit_cores": 0.25,
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
            "mode": "compute",
            "workers": 1,
            "duty_percent": 100,
            "duty_period_ms": 100,
            "requests_per_second": 1,
            "work_iterations": 1,
            "deterministic_seed": 20260902,
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


def _manifest() -> dict:
    specification = _specification()
    manifest = _load_json(
        PROJECT_ROOT / "schemas" / "examples" / "experiment_run_manifest.v1.example.json"
    )
    manifest["run_id"] = "run-poc-pi-benign-compute-r01"
    manifest["experiment_id"] = "poc-pi-two-ttp-v1"
    manifest["execution_boundary"] = {
        "kind": "safe_container",
        "metric_scopes": ["pi_sensor"],
        "execution_observed": True,
        "backend_id": "poc-pi-safe-container-v1",
        "backend_image_sha256": "1" * 64,
        "network_policy_sha256": canonical_sha256(_security()),
    }
    manifest["workload"] = {
        "scenario_catalog_version": "cowrie_hardware_scenario_catalog.v1",
        "scenario_id": "poc_pi_benign_compute_control",
        "family": "poc_bounded_compute_control",
        "variant_id": "poc-pi-benign-compute-v1",
        "implementation_id": "poc-workload-v1",
        "implementation_sha256": "2" * 64,
        "intensity_percent": 25,
        "intensity_basis": "assigned_cpu_capacity",
        "background_load_profile": "ordinary-decoy-stack",
    }
    manifest["labels"] = {
        "scenario_disposition": "benign_control",
        "primary_impact": "COMPUTE_SATURATION",
        "observed_impacts": ["COMPUTE_SATURATION"],
        "ground_truth_ttps": [],
        "label_source": "scenario_manifest_plus_observed_evidence",
        "evidence_receipt_ids": [],
    }
    manifest["collection"]["collector_sha256"] = collector_source_sha256()
    manifest["split_groups"] = {
        "scenario_variant_group": "poc-pi-benign-compute-v1",
        "workload_family_group": "poc-bounded-compute-control-v1",
        "command_template_group": "no-command",
        "collection_batch": "poc-pi-batch-v1",
        "environment_group": "pi5-safe-container-v1",
    }
    manifest["safety"] = {
        "bounded_benign_workload": True,
        "actual_malware_used": False,
        "public_or_third_party_target_used": False,
        "default_deny_egress": True,
        "egress_enforcement_scope": "execution_boundary",
        "hard_resource_limits": True,
        "watchdog_timeout_seconds": 40,
    }
    assert specification["runner"]["implementation_sha256"] == manifest["workload"][
        "implementation_sha256"
    ]
    return manifest


def test_pi_poc_contract_and_examples_are_schema_valid() -> None:
    specification = _specification()
    manifest = _manifest()
    Draft202012Validator(
        _load_json(PROJECT_ROOT / "schemas" / "pi_poc_workload_spec.v1.schema.json")
    ).validate(specification)
    Draft202012Validator(
        _load_json(PROJECT_ROOT / "schemas" / "experiment_run_manifest.v1.schema.json")
    ).validate(manifest)

    profile = validate_pi_poc_contract(
        manifest,
        specification,
        catalog_path=PROJECT_ROOT / "configs" / "scenario_catalog.v1.json",
    )

    assert profile.mode == "compute"
    assert profile.cpu_limit_cores == 0.25


def test_pi_poc_contract_rejects_parameter_drift() -> None:
    specification = _specification()
    specification["parameters"]["workers"] = 2

    with pytest.raises(DatasetContractError, match="not allowlisted"):
        validate_pi_poc_contract(
            _manifest(),
            specification,
            catalog_path=PROJECT_ROOT / "configs" / "scenario_catalog.v1.json",
        )


def test_pi_poc_matrix_is_interleaved_and_all_documents_validate() -> None:
    matrix, documents = build_pi_poc_matrix(
        experiment_id="poc-pi-two-ttp-v1",
        repetitions=3,
        image_id="sha256:" + "1" * 64,
        implementation_sha256="2" * 64,
        repo_commit="3" * 40,
        environment_signature_sha256="4" * 64,
        sensor_id="sensor-redacted",
        host_id="pi-host-pseudonymous-01",
        collector_id="experimental-telemetry-collector",
        catalog_path=PROJECT_ROOT / "configs" / "scenario_catalog.v1.json",
    )
    manifest_validator = Draft202012Validator(
        _load_json(PROJECT_ROOT / "schemas" / "experiment_run_manifest.v1.schema.json")
    )
    spec_validator = Draft202012Validator(
        _load_json(PROJECT_ROOT / "schemas" / "pi_poc_workload_spec.v1.schema.json")
    )
    matrix_validator = Draft202012Validator(
        _load_json(PROJECT_ROOT / "schemas" / "pi_poc_matrix.v1.schema.json")
    )

    matrix_validator.validate(matrix)
    assert matrix["run_count"] == 15
    assert [item["repetition"] for item in matrix["runs"][:5]] == [1] * 5
    assert sum(item["controlled_workload"] for item in matrix["runs"]) == 12
    for manifest, specification in documents:
        manifest_validator.validate(manifest)
        if specification is not None:
            spec_validator.validate(specification)
            validate_pi_poc_contract(
                manifest,
                specification,
                catalog_path=PROJECT_ROOT / "configs" / "scenario_catalog.v1.json",
            )


class FakeClock:
    def __init__(self) -> None:
        self._origin_ns = 1_000_000_000
        self._current_ns = self._origin_ns
        self._origin_wall = datetime(2026, 9, 2, 8, 0, 0, tzinfo=timezone.utc)

    def monotonic_ns(self) -> int:
        return self._current_ns

    def now_utc(self) -> datetime:
        elapsed = (self._current_ns - self._origin_ns) / 1_000_000_000
        return self._origin_wall + timedelta(seconds=elapsed)

    def sleep_until_ns(self, deadline_ns: int) -> None:
        self._current_ns = max(self._current_ns, deadline_ns)


class FakeProbe:
    boot_id_sha256 = "3" * 64

    def __init__(self) -> None:
        self.template = _load_json(
            PROJECT_ROOT / "schemas" / "examples" / "hardware_telemetry_sample.v1.example.json"
        )
        self.target_active = False

    def set_target_process(self, process_id: int) -> None:
        assert process_id == 123
        self.target_active = True

    def clear_target_process(self) -> None:
        self.target_active = False

    def sample(self) -> ProbeResult:
        sample = deepcopy(self.template)
        if not self.target_active:
            sample["process"]["target"] = None
        return ProbeResult(
            cpu=sample["cpu"],
            memory=sample["memory"],
            disk=sample["disk"],
            network=sample["network"],
            thermal=sample["thermal"],
            process=sample["process"],
        )


class FakeLifecycle:
    def __init__(self) -> None:
        self.events: list[str] = []

    def before_phase(self, phase: str, probe: FakeProbe) -> None:
        self.events.append(f"before:{phase}")
        if phase == "workload":
            probe.set_target_process(123)

    def after_phase(self, phase: str, probe: FakeProbe) -> None:
        self.events.append(f"after:{phase}")
        if phase == "workload":
            probe.clear_target_process()

    def close(self, probe: FakeProbe) -> None:
        self.events.append("close")
        probe.clear_target_process()


def test_controlled_collection_starts_target_only_in_workload_phase(
    tmp_path: Path,
) -> None:
    config_document = _load_json(
        PROJECT_ROOT / "configs" / "experimental_collector.pi_sensor.pilot.example.json"
    )
    config = replace(
        CollectorConfig.from_document(config_document),
        spool_directory=tmp_path,
        spool_limits=SpoolLimits(
            max_total_bytes=20_000_000,
            min_free_bytes=0,
            segment_max_bytes=1_000_000,
            segment_max_records=30,
        ),
    )
    lifecycle = FakeLifecycle()

    receipt = collect_controlled_run(
        _manifest(),
        config,
        schema_dir=PROJECT_ROOT / "schemas",
        lifecycle=lifecycle,
        probe=FakeProbe(),
        clock=FakeClock(),
    )

    assert receipt["record_count"] == 90
    assert lifecycle.events == [
        "before:baseline",
        "after:baseline",
        "before:workload",
        "after:workload",
        "before:recovery",
        "after:recovery",
        "close",
    ]
