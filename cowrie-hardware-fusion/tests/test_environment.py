from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator
import pytest

from cowrie_hardware_fusion.cli import main as cli_main
from cowrie_hardware_fusion.dataset import DatasetContractError
from cowrie_hardware_fusion.environment import (
    build_environment_receipt,
    validate_environment_receipt,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _receipt(
    *,
    observed_at: str = "2026-09-03T00:00:00Z",
    hardware_state: str = "inactive",
    available_memory_bytes: int = 6_000_000_000,
) -> dict:
    services = {
        "cowrie": "active",
        "honeypot_collector": "active",
        "honeypot_processor": "active",
        "honeypot_sensor_forwarder": "active",
        "zeek": "active",
        "honeypot_hardware": hardware_state,
        "hardware_metrics": "inactive",
        "hardware_metrics_processor": "inactive",
    }
    return build_environment_receipt(
        observed_at=observed_at,
        sensor_id="sensor-redacted",
        subject_id="pi-host-pseudonymous-01",
        boot_id_sha256="1" * 64,
        host={
            "architecture": "aarch64",
            "kernel_release": "6.8.0-1063-raspi",
            "cpu_model": "Cortex-A76",
            "logical_cpu_count": 4,
            "memory_total_bytes": 8_322_752_512,
            "swap_total_bytes": 0,
            "root_device": "mmcblk0p2",
        },
        network={
            "observed_interfaces": ["lo", "tailscale0", "wlan0"],
            "ntp_synchronized": True,
        },
        collector_runtime={
            "python_version": "3.12.3",
            "psutil_version": "7.2.2",
            "collector_repo_commit": "2" * 40,
            "source_archive_sha256": "9" * 64,
            "collector_source_sha256": "3" * 64,
            "telemetry_schema_sha256": "4" * 64,
        },
        production_context={
            "repo_commit": "5" * 40,
            "working_tree_clean": True,
            "services": services,
            "containers": [
                {
                    "name": "decoy-one",
                    "image_reference": "decoy:latest",
                    "image_id": "sha256:" + "6" * 64,
                }
            ],
        },
        reviewed_runner={
            "image_id": "sha256:" + "7" * 64,
            "architecture": "arm64",
            "user": "65532:65532",
            "entrypoint": ["/poc-workload"],
            "implementation_sha256": "8" * 64,
        },
        headroom={
            "available_memory_bytes": available_memory_bytes,
            "root_free_bytes": 60_000_000_000,
            "load_1m": 0.1,
            "temperature_c": 55.0,
        },
    )


def test_environment_receipt_is_schema_valid_and_passes_safety_gates() -> None:
    receipt = _receipt()
    schema = json.loads(
        (
            PROJECT_ROOT
            / "schemas"
            / "experiment_environment_receipt.v2.schema.json"
        ).read_text(encoding="utf-8")
    )
    Draft202012Validator(
        schema, format_checker=Draft202012Validator.FORMAT_CHECKER
    ).validate(receipt)

    summary = validate_environment_receipt(receipt)

    assert summary["safety_gates_passed"] is True
    assert summary["production_container_count"] == 1


def test_capture_time_and_headroom_are_not_part_of_environment_signature() -> None:
    first = _receipt(observed_at="2026-09-03T00:00:00Z")
    second = _receipt(
        observed_at="2026-09-03T00:05:00Z",
        available_memory_bytes=5_500_000_000,
    )

    assert (
        first["environment_signature_sha256"]
        == second["environment_signature_sha256"]
    )
    assert first["receipt_sha256"] != second["receipt_sha256"]


def test_environment_receipt_rejects_tampering_and_active_sink() -> None:
    tampered = _receipt()
    tampered["headroom"]["load_1m"] = 2.0
    with pytest.raises(DatasetContractError, match="receipt hash"):
        validate_environment_receipt(tampered)

    active_sink = _receipt(hardware_state="active")
    with pytest.raises(DatasetContractError, match="honeypot_hardware"):
        validate_environment_receipt(active_sink)


def test_environment_receipt_rejects_low_headroom_and_experiment_container() -> None:
    low_memory = _receipt(available_memory_bytes=1_000_000_000)
    with pytest.raises(DatasetContractError, match="memory"):
        validate_environment_receipt(low_memory)

    running_experiment = _receipt()
    running_experiment["production_context"]["containers"][0]["name"] = "chf-poc-test"
    rebuilt = build_environment_receipt(
        observed_at=running_experiment["observed_at"],
        sensor_id=running_experiment["sensor_id"],
        subject_id=running_experiment["subject_id"],
        boot_id_sha256=running_experiment["boot_id_sha256"],
        host=running_experiment["host"],
        network=running_experiment["network"],
        collector_runtime=running_experiment["collector_runtime"],
        production_context=running_experiment["production_context"],
        reviewed_runner=running_experiment["reviewed_runner"],
        headroom=running_experiment["headroom"],
    )
    with pytest.raises(DatasetContractError, match="experiment container"):
        validate_environment_receipt(rebuilt)


def test_environment_receipt_rejects_dirty_production_tree() -> None:
    receipt = _receipt()
    context = dict(receipt["production_context"])
    context["working_tree_clean"] = False
    rebuilt = build_environment_receipt(
        observed_at=receipt["observed_at"],
        sensor_id=receipt["sensor_id"],
        subject_id=receipt["subject_id"],
        boot_id_sha256=receipt["boot_id_sha256"],
        host=receipt["host"],
        network=receipt["network"],
        collector_runtime=receipt["collector_runtime"],
        production_context=context,
        reviewed_runner=receipt["reviewed_runner"],
        headroom=receipt["headroom"],
    )

    with pytest.raises(DatasetContractError, match="working tree"):
        validate_environment_receipt(rebuilt)


def test_environment_receipt_cli_validates_round_trip(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "environment-receipt.json"
    path.write_text(json.dumps(_receipt(), sort_keys=True), encoding="utf-8")

    exit_code = cli_main(
        ["validate-pi-environment-receipt", "--receipt", str(path)]
    )

    assert exit_code == 0
    output = json.loads(capsys.readouterr().out)
    assert output["safety_gates_passed"] is True
