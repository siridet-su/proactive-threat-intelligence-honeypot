"""Versioned, privacy-bounded Raspberry Pi environment receipts."""

from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import subprocess
from typing import Any

from .batch import canonical_sha256
from .collector import collector_source_sha256, telemetry_schema_sha256
from .dataset import DatasetContractError


RECEIPT_SCHEMA_VERSION = "experiment_environment_receipt.v2"
SIGNATURE_SCHEMA_VERSION = "experiment_environment_signature.v1"
OBSERVED_SERVICES = (
    "cowrie.service",
    "honeypot-collector.service",
    "honeypot-processor.service",
    "honeypot-sensor-forwarder.service",
    "zeek.service",
    "honeypot-hardware.service",
    "hardware-metrics.service",
    "hardware-metrics-processor.service",
)


def _run(arguments: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            arguments,
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DatasetContractError(
            f"environment command failed: {arguments[0]} ({type(exc).__name__})"
        ) from exc
    if check and result.returncode != 0:
        raise DatasetContractError(f"environment command rejected: {arguments[0]}")
    return result


def _iso_now() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def _cpu_model() -> str:
    try:
        lines = Path("/proc/cpuinfo").read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise DatasetContractError("cannot read CPU model") from exc
    for line in lines:
        if line.lower().startswith("model name") and ":" in line:
            return line.split(":", 1)[1].strip()
    for line in lines:
        if line.lower().startswith("model") and ":" in line:
            return line.split(":", 1)[1].strip()
    raise DatasetContractError("CPU model is unavailable")


def _service_states() -> dict[str, str]:
    states: dict[str, str] = {}
    for unit in OBSERVED_SERVICES:
        result = _run(["systemctl", "is-active", unit], check=False)
        state = result.stdout.strip() or "unknown"
        if state not in {
            "active",
            "inactive",
            "failed",
            "activating",
            "deactivating",
            "reloading",
            "unknown",
        }:
            state = "unknown"
        states[unit.removesuffix(".service").replace("-", "_")] = state
    return states


def _production_containers() -> list[dict[str, str]]:
    listing = _run(
        ["docker", "ps", "--no-trunc", "--format", "{{.Names}}\t{{.Image}}\t{{.ID}}"]
    )
    containers: list[dict[str, str]] = []
    for line in listing.stdout.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) != 3:
            raise DatasetContractError("Docker container listing is malformed")
        name, image_reference, container_id = parts
        inspected = _run(
            ["docker", "container", "inspect", "--format", "{{.Image}}", container_id]
        )
        image_id = inspected.stdout.strip()
        if not image_id.startswith("sha256:") or len(image_id) != 71:
            raise DatasetContractError("Docker container image identity is invalid")
        containers.append(
            {
                "name": name,
                "image_reference": image_reference,
                "image_id": image_id,
            }
        )
    return sorted(containers, key=lambda item: item["name"])


def _reviewed_runner(image_id: str) -> dict[str, Any]:
    inspected = _run(["docker", "image", "inspect", image_id])
    values = json.loads(inspected.stdout)
    if not isinstance(values, list) or len(values) != 1:
        raise DatasetContractError("reviewed runner image inspection is ambiguous")
    image = values[0]
    config = image.get("Config", {})
    entrypoint = config.get("Entrypoint")
    revision = (config.get("Labels") or {}).get("org.opencontainers.image.revision")
    result = {
        "image_id": image.get("Id"),
        "architecture": image.get("Architecture"),
        "user": config.get("User"),
        "entrypoint": entrypoint,
        "implementation_sha256": revision,
    }
    if (
        result["image_id"] != image_id
        or result["architecture"] != "arm64"
        or result["user"] != "65532:65532"
        or result["entrypoint"] != ["/poc-workload"]
        or not isinstance(revision, str)
        or len(revision) != 64
    ):
        raise DatasetContractError("reviewed runner image contract does not match")
    return result


def _git_context(repo: Path) -> dict[str, Any]:
    result = _run(["git", "-C", str(repo), "rev-parse", "HEAD"])
    commit = result.stdout.strip()
    if len(commit) not in {40, 64} or any(
        character not in "0123456789abcdef" for character in commit
    ):
        raise DatasetContractError("production repository commit is invalid")
    status = _run(["git", "-C", str(repo), "status", "--porcelain"])
    return {"repo_commit": commit, "working_tree_clean": not bool(status.stdout.strip())}


def validate_environment_receipt(receipt: dict[str, Any]) -> dict[str, Any]:
    """Verify content identities and minimum pre-collection safety state."""

    if receipt.get("schema_version") != RECEIPT_SCHEMA_VERSION:
        raise DatasetContractError("unsupported environment receipt")
    payload = dict(receipt)
    claimed_receipt_hash = payload.pop("receipt_sha256", None)
    if (
        not isinstance(claimed_receipt_hash, str)
        or canonical_sha256(payload) != claimed_receipt_hash
    ):
        raise DatasetContractError("environment receipt hash does not match")
    signature_payload = {
        "schema_version": receipt["signature_schema_version"],
        "sensor_id": receipt["sensor_id"],
        "subject_id": receipt["subject_id"],
        "boot_id_sha256": receipt["boot_id_sha256"],
        "host": receipt["host"],
        "network": receipt["network"],
        "collector_runtime": receipt["collector_runtime"],
        "production_context": receipt["production_context"],
        "reviewed_runner": receipt["reviewed_runner"],
    }
    if (
        receipt["signature_schema_version"] != SIGNATURE_SCHEMA_VERSION
        or canonical_sha256(signature_payload)
        != receipt["environment_signature_sha256"]
    ):
        raise DatasetContractError("environment signature does not match")
    if receipt["network"]["ntp_synchronized"] is not True:
        raise DatasetContractError("environment receipt requires synchronized NTP")
    runner = receipt["reviewed_runner"]
    if (
        runner["architecture"] != "arm64"
        or runner["user"] != "65532:65532"
        or runner["entrypoint"] != ["/poc-workload"]
        or not runner["image_id"].startswith("sha256:")
        or len(runner["image_id"]) != 71
        or len(runner["implementation_sha256"]) != 64
    ):
        raise DatasetContractError("environment reviewed runner is invalid")
    services = receipt["production_context"]["services"]
    if receipt["production_context"]["working_tree_clean"] is not True:
        raise DatasetContractError("production repository working tree must be clean")
    if services.get("cowrie") != "active":
        raise DatasetContractError("Cowrie must be active in the environment receipt")
    for service in (
        "honeypot_hardware",
        "hardware_metrics",
        "hardware_metrics_processor",
    ):
        if services.get(service) != "inactive":
            raise DatasetContractError(f"{service} must remain inactive during collection")
    if any(
        container["name"].startswith("chf-poc-")
        for container in receipt["production_context"]["containers"]
    ):
        raise DatasetContractError("an experiment container is already running")
    headroom = receipt["headroom"]
    if headroom["available_memory_bytes"] < 2_147_483_648:
        raise DatasetContractError("environment memory is below the safety gate")
    if headroom["root_free_bytes"] < 5_368_709_120:
        raise DatasetContractError("environment disk is below the safety gate")
    if headroom["load_1m"] > 3:
        raise DatasetContractError("environment load is above the safety gate")
    if headroom["temperature_c"] > 75:
        raise DatasetContractError("environment temperature is above the safety gate")
    return {
        "environment_signature_sha256": receipt["environment_signature_sha256"],
        "receipt_sha256": claimed_receipt_hash,
        "production_container_count": len(
            receipt["production_context"]["containers"]
        ),
        "ntp_synchronized": True,
        "safety_gates_passed": True,
    }


def build_environment_receipt(
    *,
    observed_at: str,
    sensor_id: str,
    subject_id: str,
    boot_id_sha256: str,
    host: dict[str, Any],
    network: dict[str, Any],
    collector_runtime: dict[str, Any],
    production_context: dict[str, Any],
    reviewed_runner: dict[str, Any],
    headroom: dict[str, Any],
) -> dict[str, Any]:
    """Build receipt and a stable-within-state signature independent of capture time."""

    signature_payload = {
        "schema_version": SIGNATURE_SCHEMA_VERSION,
        "sensor_id": sensor_id,
        "subject_id": subject_id,
        "boot_id_sha256": boot_id_sha256,
        "host": host,
        "network": network,
        "collector_runtime": collector_runtime,
        "production_context": production_context,
        "reviewed_runner": reviewed_runner,
    }
    receipt: dict[str, Any] = {
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "observed_at": observed_at,
        "sensor_id": sensor_id,
        "subject_id": subject_id,
        "signature_schema_version": SIGNATURE_SCHEMA_VERSION,
        "environment_signature_sha256": canonical_sha256(signature_payload),
        "boot_id_sha256": boot_id_sha256,
        "host": host,
        "network": network,
        "collector_runtime": collector_runtime,
        "production_context": production_context,
        "reviewed_runner": reviewed_runner,
        "headroom": headroom,
        "privacy": {
            "contains_credentials": False,
            "contains_raw_ip": False,
            "contains_hostname": False,
        },
    }
    receipt["receipt_sha256"] = canonical_sha256(receipt)
    return receipt


def capture_pi_environment_receipt(
    *,
    sensor_id: str,
    subject_id: str,
    collector_repo_commit: str,
    collector_source_archive: Path,
    production_repo: Path,
    runner_image_id: str,
    schema_dir: Path,
) -> dict[str, Any]:
    """Capture only allowlisted local state; never read addresses, credentials or commands."""

    try:
        import psutil
    except ImportError as exc:
        raise DatasetContractError("psutil is required for environment capture") from exc
    if len(collector_repo_commit) not in {40, 64} or any(
        character not in "0123456789abcdef"
        for character in collector_repo_commit
    ):
        raise DatasetContractError("collector repository commit is invalid")
    boot_id = Path("/proc/sys/kernel/random/boot_id").read_text(
        encoding="ascii"
    ).strip()
    boot_hash = sha256(boot_id.encode("ascii")).hexdigest()
    memory = psutil.virtual_memory()
    swap = psutil.swap_memory()
    disk = psutil.disk_usage("/")
    root_source = _run(["findmnt", "-n", "-o", "SOURCE", "/"]).stdout.strip()
    if not root_source:
        raise DatasetContractError("root filesystem source is unavailable")
    interfaces = sorted(path.name for path in Path("/sys/class/net").iterdir())
    ntp = _run(
        ["timedatectl", "show", "-p", "NTPSynchronized", "--value"]
    ).stdout.strip()
    if ntp not in {"yes", "no"}:
        raise DatasetContractError("NTP synchronization state is unavailable")
    load_1m = float(os.getloadavg()[0])
    temperature_path = Path("/sys/class/thermal/thermal_zone0/temp")
    try:
        temperature_c = (
            float(temperature_path.read_text(encoding="ascii").strip()) / 1000
        )
    except (OSError, ValueError) as exc:
        raise DatasetContractError("Pi temperature is unavailable") from exc

    host = {
        "architecture": platform.machine(),
        "kernel_release": platform.release(),
        "cpu_model": _cpu_model(),
        "logical_cpu_count": int(psutil.cpu_count(logical=True) or 0),
        "memory_total_bytes": int(memory.total),
        "swap_total_bytes": int(swap.total),
        "root_device": Path(root_source).name,
    }
    network = {
        "observed_interfaces": interfaces,
        "ntp_synchronized": ntp == "yes",
    }
    collector_runtime = {
        "python_version": platform.python_version(),
        "psutil_version": str(psutil.__version__),
        "collector_repo_commit": collector_repo_commit,
        "source_archive_sha256": sha256(
            collector_source_archive.read_bytes()
        ).hexdigest(),
        "collector_source_sha256": collector_source_sha256(),
        "telemetry_schema_sha256": telemetry_schema_sha256(schema_dir),
    }
    production_context = {
        **_git_context(production_repo),
        "services": _service_states(),
        "containers": _production_containers(),
    }
    reviewed_runner = _reviewed_runner(runner_image_id)
    headroom = {
        "available_memory_bytes": int(memory.available),
        "root_free_bytes": int(disk.free),
        "load_1m": load_1m,
        "temperature_c": temperature_c,
    }
    receipt = build_environment_receipt(
        observed_at=_iso_now(),
        sensor_id=sensor_id,
        subject_id=subject_id,
        boot_id_sha256=boot_hash,
        host=host,
        network=network,
        collector_runtime=collector_runtime,
        production_context=production_context,
        reviewed_runner=reviewed_runner,
        headroom=headroom,
    )
    validate_environment_receipt(receipt)
    return receipt
