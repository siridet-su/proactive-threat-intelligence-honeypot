"""Isolated 1 Hz telemetry collector for Stage A neutral-idle pilot runs.

The collector writes only to a bounded local spool. It has no Redis, MongoDB, cloud,
command execution, or canonical-authority integration.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
import json
import math
import os
from pathlib import Path
import subprocess
import time
from typing import Any, Mapping, Protocol

import psutil
from jsonschema import Draft202012Validator

from .dataset import DatasetContractError
from .spool import BoundedSegmentSpool, SpoolLimits


COLLECTOR_VERSION = "0.2.0"
COLLECTOR_SCHEMA_VERSION = "experimental_collector_config.v1"
RECEIPT_SCHEMA_VERSION = "experiment_collection_receipt.v1"


@dataclass(frozen=True)
class InterfaceConfig:
    name: str
    accounting_role: str
    include_in_aggregate: bool


@dataclass(frozen=True)
class CollectorConfig:
    collector_id: str
    collector_version: str
    sensor_id: str
    subject_id: str
    metric_scope: str
    interfaces: tuple[InterfaceConfig, ...]
    disk_devices: tuple[str, ...]
    spool_directory: Path
    spool_limits: SpoolLimits
    late_tolerance_ms: float
    require_ntp_synchronized: bool

    @classmethod
    def from_document(cls, document: Mapping[str, Any]) -> CollectorConfig:
        if document.get("schema_version") != COLLECTOR_SCHEMA_VERSION:
            raise DatasetContractError("unsupported experimental collector config")
        spool = document["spool"]
        timing = document["timing"]
        interfaces = tuple(
            InterfaceConfig(
                name=item["name"],
                accounting_role=item["accounting_role"],
                include_in_aggregate=item["include_in_aggregate"],
            )
            for item in document["interfaces"]
        )
        return cls(
            collector_id=document["collector_id"],
            collector_version=document["collector_version"],
            sensor_id=document["sensor_id"],
            subject_id=document["subject_id"],
            metric_scope=document["metric_scope"],
            interfaces=interfaces,
            disk_devices=tuple(document["disk_devices"]),
            spool_directory=Path(spool["directory"]),
            spool_limits=SpoolLimits(
                max_total_bytes=spool["max_total_bytes"],
                min_free_bytes=spool["min_free_bytes"],
                segment_max_bytes=spool["segment_max_bytes"],
                segment_max_records=spool["segment_max_records"],
                fsync_every_records=spool["fsync_every_records"],
            ),
            late_tolerance_ms=float(timing["late_tolerance_ms"]),
            require_ntp_synchronized=timing["require_ntp_synchronized"],
        )


@dataclass(frozen=True)
class ProbeResult:
    cpu: dict[str, Any]
    memory: dict[str, Any]
    disk: dict[str, Any]
    network: dict[str, Any]
    thermal: dict[str, Any]
    process: dict[str, Any]
    missing_fields: tuple[str, ...] = ()
    counter_resets: tuple[str, ...] = ()
    collector_errors: tuple[str, ...] = ()
    valid: bool = True


class Probe(Protocol):
    boot_id_sha256: str

    def sample(self) -> ProbeResult: ...


class Clock(Protocol):
    def monotonic_ns(self) -> int: ...

    def now_utc(self) -> datetime: ...

    def sleep_until_ns(self, deadline_ns: int) -> None: ...


class SystemClock:
    def monotonic_ns(self) -> int:
        return time.monotonic_ns()

    def now_utc(self) -> datetime:
        return datetime.now(timezone.utc)

    def sleep_until_ns(self, deadline_ns: int) -> None:
        remaining = (deadline_ns - time.monotonic_ns()) / 1_000_000_000
        if remaining > 0:
            time.sleep(remaining)


def _iso_utc(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def _file_sha256(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_sha256(value: Any) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return sha256(payload).hexdigest()


def _schema_validator(schema_dir: Path, filename: str) -> Draft202012Validator:
    schema = json.loads((schema_dir / filename).read_text(encoding="utf-8"))
    return Draft202012Validator(
        schema,
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    )


def _validate_document(
    document: Mapping[str, Any],
    validator: Draft202012Validator,
    label: str,
) -> None:
    errors = sorted(
        validator.iter_errors(document),
        key=lambda error: list(error.absolute_path),
    )
    if errors:
        error = errors[0]
        location = ".".join(str(component) for component in error.absolute_path) or "$"
        raise DatasetContractError(f"{label}:{location}: {error.message}")


def collector_source_sha256() -> str:
    """Hash the exact modules that perform collection and durable spooling."""

    digest = sha256()
    package_dir = Path(__file__).resolve().parent
    for name in ("collector.py", "spool.py"):
        payload = (package_dir / name).read_bytes()
        digest.update(name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
    return digest.hexdigest()


def telemetry_schema_sha256(schema_dir: Path) -> str:
    return _file_sha256(schema_dir / "hardware_telemetry_sample.v1.schema.json")


def _boot_id_sha256() -> str:
    boot_id = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
    if not boot_id:
        raise DatasetContractError("Linux boot ID is unavailable")
    return sha256(boot_id.encode("ascii")).hexdigest()


def ntp_is_synchronized() -> bool:
    """Read systemd's NTP synchronization state without changing host state."""

    try:
        result = subprocess.run(
            ["timedatectl", "show", "--property=NTPSynchronized", "--value"],
            check=False,
            capture_output=True,
            text=True,
            timeout=3,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0 and result.stdout.strip().lower() == "yes"


def _safe_delta(current: int, previous: int, name: str, resets: list[str]) -> int:
    if current < previous:
        resets.append(name)
        return 0
    return current - previous


def _read_vmstat() -> dict[str, int]:
    wanted = {"pgfault", "pgmajfault", "oom_kill"}
    values: dict[str, int] = {}
    with Path("/proc/vmstat").open("r", encoding="ascii") as handle:
        for line in handle:
            name, raw_value = line.split(maxsplit=1)
            if name in wanted:
                values[name] = int(raw_value)
    return values


def _socket_counts() -> tuple[int, int]:
    connection_count = 0
    socket_count = 0
    for name in ("tcp", "tcp6", "udp", "udp6"):
        path = Path("/proc/net") / name
        try:
            with path.open("r", encoding="ascii") as handle:
                count = max(sum(1 for _ in handle) - 1, 0)
        except OSError:
            continue
        socket_count += count
        if name.startswith("tcp"):
            connection_count += count
    unix_path = Path("/proc/net/unix")
    try:
        with unix_path.open("r", encoding="ascii") as handle:
            socket_count += max(sum(1 for _ in handle) - 1, 0)
    except OSError:
        pass
    return connection_count, socket_count


def _temperature_c() -> float | None:
    path = Path("/sys/class/thermal/thermal_zone0/temp")
    try:
        return float(path.read_text(encoding="ascii").strip()) / 1000.0
    except (OSError, ValueError):
        return None


class LinuxSystemProbe:
    """Collect Linux host telemetry using psutil plus read-only proc/sys files."""

    def __init__(self, config: CollectorConfig) -> None:
        self.config = config
        self.boot_id_sha256 = _boot_id_sha256()
        psutil.cpu_percent(interval=None, percpu=False)
        psutil.cpu_percent(interval=None, percpu=True)
        psutil.cpu_times_percent(interval=None, percpu=False)
        self._previous_at_ns = time.monotonic_ns()
        self._previous_disk = psutil.disk_io_counters(perdisk=True) or {}
        self._previous_network = psutil.net_io_counters(pernic=True)

    def sample(self) -> ProbeResult:
        missing: list[str] = []
        resets: list[str] = []
        errors: list[str] = []
        valid = True
        observed_ns = time.monotonic_ns()
        elapsed = max((observed_ns - self._previous_at_ns) / 1_000_000_000, 1e-9)

        total_cpu = float(psutil.cpu_percent(interval=None, percpu=False))
        per_core = [float(value) for value in psutil.cpu_percent(interval=None, percpu=True)]
        times = psutil.cpu_times_percent(interval=None, percpu=False)
        load_1m, load_5m, load_15m = os.getloadavg()
        frequency = psutil.cpu_freq()
        cpu_stats = psutil.cpu_stats()
        cpu_block: dict[str, Any] = {
            "utilization_semantics": "aggregate_busy_percent_0_100",
            "core_count": len(per_core),
            "total_percent": total_cpu,
            "per_core_percent": per_core,
            "user_percent": float(times.user),
            "system_percent": float(times.system),
            "iowait_percent": float(getattr(times, "iowait", 0.0)),
            "irq_percent": float(getattr(times, "irq", 0.0) + getattr(times, "softirq", 0.0)),
            "steal_percent": float(getattr(times, "steal", 0.0)),
            "load_1m": float(load_1m),
            "load_5m": float(load_5m),
            "load_15m": float(load_15m),
            "frequency_mhz": float(frequency.current) if frequency else None,
            "context_switches_total": int(cpu_stats.ctx_switches),
        }
        if not per_core:
            valid = False
            missing.append("cpu.per_core_percent")

        virtual = psutil.virtual_memory()
        swap = psutil.swap_memory()
        memory_block: dict[str, Any] = {
            "total_bytes": int(virtual.total),
            "available_bytes": int(virtual.available),
            "used_bytes": int(virtual.used),
            "used_percent": float(virtual.percent),
            "cache_bytes": int(getattr(virtual, "cached", 0)),
            "swap_total_bytes": int(swap.total),
            "swap_used_bytes": int(swap.used),
        }
        try:
            vmstat = _read_vmstat()
            if "pgfault" in vmstat:
                memory_block["page_faults_total"] = vmstat["pgfault"]
            if "pgmajfault" in vmstat:
                memory_block["major_page_faults_total"] = vmstat["pgmajfault"]
            if "oom_kill" in vmstat:
                memory_block["oom_kills_total"] = vmstat["oom_kill"]
        except (OSError, ValueError) as exc:
            errors.append(f"vmstat:{type(exc).__name__}")

        root = psutil.disk_usage("/")
        current_disk = psutil.disk_io_counters(perdisk=True) or {}
        disk_devices: list[dict[str, Any]] = []
        for device_name in self.config.disk_devices:
            current = current_disk.get(device_name)
            previous = self._previous_disk.get(device_name)
            if current is None or previous is None:
                missing.append(f"disk.devices.{device_name}")
                valid = False
                continue
            read_bytes_delta = _safe_delta(
                int(current.read_bytes), int(previous.read_bytes), f"disk.{device_name}.read_bytes", resets
            )
            write_bytes_delta = _safe_delta(
                int(current.write_bytes), int(previous.write_bytes), f"disk.{device_name}.write_bytes", resets
            )
            read_count_delta = _safe_delta(
                int(current.read_count), int(previous.read_count), f"disk.{device_name}.read_count", resets
            )
            write_count_delta = _safe_delta(
                int(current.write_count), int(previous.write_count), f"disk.{device_name}.write_count", resets
            )
            busy_delta = _safe_delta(
                int(current.busy_time), int(previous.busy_time), f"disk.{device_name}.busy_time", resets
            )
            disk_devices.append(
                {
                    "device_id": device_name,
                    "read_bytes_total": int(current.read_bytes),
                    "write_bytes_total": int(current.write_bytes),
                    "read_bytes_per_second": read_bytes_delta / elapsed,
                    "write_bytes_per_second": write_bytes_delta / elapsed,
                    "reads_per_second": read_count_delta / elapsed,
                    "writes_per_second": write_count_delta / elapsed,
                    "io_time_percent": min(max(busy_delta / (elapsed * 10.0), 0.0), 100.0),
                }
            )
        disk_block = {
            "root_used_bytes": int(root.used),
            "root_used_percent": float(root.percent),
            "devices": disk_devices,
        }

        current_network = psutil.net_io_counters(pernic=True)
        try:
            interface_stats = psutil.net_if_stats()
        except (OSError, psutil.Error) as exc:
            interface_stats = {}
            errors.append(f"network.interface_stats:{type(exc).__name__}")
        interfaces: list[dict[str, Any]] = []
        for configured in self.config.interfaces:
            current = current_network.get(configured.name)
            previous = self._previous_network.get(configured.name)
            if current is None or previous is None:
                missing.append(f"network.interfaces.{configured.name}")
                if configured.include_in_aggregate:
                    valid = False
                interfaces.append(
                    {
                        "name": configured.name,
                        "accounting_role": configured.accounting_role,
                        "include_in_aggregate": configured.include_in_aggregate,
                        "up": False,
                        "rx_bytes_total": 0,
                        "tx_bytes_total": 0,
                        "rx_bytes_per_second": 0.0,
                        "tx_bytes_per_second": 0.0,
                        "rx_packets_total": 0,
                        "tx_packets_total": 0,
                        "rx_packets_per_second": 0.0,
                        "tx_packets_per_second": 0.0,
                        "rx_errors_total": 0,
                        "tx_errors_total": 0,
                        "rx_drops_total": 0,
                        "tx_drops_total": 0,
                    }
                )
                continue
            rx_bytes_delta = _safe_delta(
                int(current.bytes_recv), int(previous.bytes_recv), f"network.{configured.name}.rx_bytes", resets
            )
            tx_bytes_delta = _safe_delta(
                int(current.bytes_sent), int(previous.bytes_sent), f"network.{configured.name}.tx_bytes", resets
            )
            rx_packets_delta = _safe_delta(
                int(current.packets_recv), int(previous.packets_recv), f"network.{configured.name}.rx_packets", resets
            )
            tx_packets_delta = _safe_delta(
                int(current.packets_sent), int(previous.packets_sent), f"network.{configured.name}.tx_packets", resets
            )
            stats = interface_stats.get(configured.name)
            if stats is None:
                missing.append(f"network.interfaces.{configured.name}.up")
                if configured.include_in_aggregate:
                    valid = False
            interfaces.append(
                {
                    "name": configured.name,
                    "accounting_role": configured.accounting_role,
                    "include_in_aggregate": configured.include_in_aggregate,
                    "up": bool(stats and stats.isup),
                    "rx_bytes_total": int(current.bytes_recv),
                    "tx_bytes_total": int(current.bytes_sent),
                    "rx_bytes_per_second": rx_bytes_delta / elapsed,
                    "tx_bytes_per_second": tx_bytes_delta / elapsed,
                    "rx_packets_total": int(current.packets_recv),
                    "tx_packets_total": int(current.packets_sent),
                    "rx_packets_per_second": rx_packets_delta / elapsed,
                    "tx_packets_per_second": tx_packets_delta / elapsed,
                    "rx_errors_total": int(current.errin),
                    "tx_errors_total": int(current.errout),
                    "rx_drops_total": int(current.dropin),
                    "tx_drops_total": int(current.dropout),
                }
            )
        connection_count, socket_count = _socket_counts()
        network_block = {
            "interfaces": interfaces,
            "connection_count": connection_count,
            "socket_count": socket_count,
        }

        temperature = _temperature_c()
        if temperature is None:
            missing.append("thermal.temperature_c")
        thermal_block = {
            "temperature_c": temperature,
            "throttled": None,
            "undervoltage": None,
        }

        process_count = 0
        thread_count = 0
        for process in psutil.process_iter(attrs=("num_threads",), ad_value=None):
            process_count += 1
            threads = process.info.get("num_threads")
            if isinstance(threads, int):
                thread_count += threads
        process_block = {
            "process_count": process_count,
            "thread_count": thread_count,
            "target": None,
        }

        self._previous_at_ns = observed_ns
        self._previous_disk = current_disk
        self._previous_network = current_network
        return ProbeResult(
            cpu=cpu_block,
            memory=memory_block,
            disk=disk_block,
            network=network_block,
            thermal=thermal_block,
            process=process_block,
            missing_fields=tuple(sorted(set(missing))),
            counter_resets=tuple(sorted(set(resets))),
            collector_errors=tuple(sorted(set(errors))),
            valid=valid,
        )


def _validate_idle_contract(
    manifest: Mapping[str, Any], config: CollectorConfig, source_sha256: str
) -> None:
    if manifest.get("state") not in {"planned", "running"}:
        raise DatasetContractError("collector accepts only planned or running manifests")
    if config.collector_version != COLLECTOR_VERSION:
        raise DatasetContractError("collector config version does not match runtime")
    if config.metric_scope != "pi_sensor":
        raise DatasetContractError("collector v0.2.0 supports only pi_sensor")
    if config.sensor_id != manifest["sensor"]["sensor_id"]:
        raise DatasetContractError("config sensor_id does not match manifest")
    if config.subject_id != manifest["sensor"]["host_id"]:
        raise DatasetContractError("config subject_id does not match manifest host_id")
    if config.collector_id != manifest["collection"]["collector_id"]:
        raise DatasetContractError("config collector_id does not match manifest")
    if manifest["collection"]["collector_sha256"] != source_sha256:
        raise DatasetContractError(
            "manifest collector_sha256 does not match this collector source"
        )
    if manifest["timing"]["sample_interval_seconds"] != 1:
        raise DatasetContractError("collector v0.2.0 requires a 1-second manifest interval")
    if manifest["workload"]["scenario_id"] != "neutral_idle":
        raise DatasetContractError("collector v0.2.0 is restricted to neutral_idle")
    if manifest["workload"]["family"] != "none":
        raise DatasetContractError("idle collector cannot run a workload family")
    if manifest["workload"]["intensity_percent"] != 0:
        raise DatasetContractError("idle collector requires intensity_percent=0")
    if manifest["execution_boundary"]["kind"] != "none":
        raise DatasetContractError("idle collector requires execution_boundary.kind=none")
    if manifest["execution_boundary"]["execution_observed"] is not False:
        raise DatasetContractError("idle collector cannot claim execution evidence")
    if "pi_sensor" not in manifest["execution_boundary"]["metric_scopes"]:
        raise DatasetContractError("manifest does not authorize pi_sensor telemetry")
    if manifest["collection"]["command_events_required"] is not False:
        raise DatasetContractError("Stage A idle run cannot require command events")
    if manifest["labels"]["scenario_disposition"] != "neutral_baseline":
        raise DatasetContractError("idle run must use neutral_baseline disposition")
    if manifest["labels"]["primary_impact"] != "NO_MATERIAL_IMPACT":
        raise DatasetContractError("idle run must use NO_MATERIAL_IMPACT")
    if manifest["labels"]["ground_truth_ttps"]:
        raise DatasetContractError("idle run cannot declare ground-truth TTPs")
    safety = manifest["safety"]
    if safety["actual_malware_used"] or safety["public_or_third_party_target_used"]:
        raise DatasetContractError("idle collector safety boundary was violated")
    if safety["egress_enforcement_scope"] != "not_applicable_no_execution":
        raise DatasetContractError(
            "idle collector requires egress_enforcement_scope=not_applicable_no_execution"
        )

    names = [interface.name for interface in config.interfaces]
    if len(names) != len(set(names)):
        raise DatasetContractError("collector interface names must be unique")
    aggregate = [interface for interface in config.interfaces if interface.include_in_aggregate]
    if len(aggregate) != 1 or aggregate[0].accounting_role != "primary_physical":
        raise DatasetContractError(
            "pi_sensor pilot requires exactly one aggregate primary_physical interface"
        )
    for interface in config.interfaces:
        if interface.accounting_role in {"overlay_observability", "loopback_observability"}:
            if interface.include_in_aggregate:
                raise DatasetContractError(
                    f"{interface.name} observability traffic cannot be aggregate-eligible"
                )
    config.spool_limits.validate()


def collector_preflight(
    manifest: Mapping[str, Any],
    config: CollectorConfig,
    *,
    schema_dir: Path,
    ntp_synchronized: bool | None = None,
) -> dict[str, Any]:
    source_hash = collector_source_sha256()
    feature_hash = telemetry_schema_sha256(schema_dir)
    _validate_idle_contract(manifest, config, source_hash)
    synchronized = ntp_is_synchronized() if ntp_synchronized is None else ntp_synchronized
    if config.require_ntp_synchronized and not synchronized:
        raise DatasetContractError("NTP is not synchronized or could not be verified")

    available_interfaces = psutil.net_io_counters(pernic=True)
    missing_interfaces = [
        interface.name
        for interface in config.interfaces
        if interface.name not in available_interfaces
    ]
    aggregate_missing = [
        interface.name
        for interface in config.interfaces
        if interface.include_in_aggregate and interface.name in missing_interfaces
    ]
    if aggregate_missing:
        raise DatasetContractError(
            f"aggregate interface is unavailable: {','.join(aggregate_missing)}"
        )
    disk_counters = psutil.disk_io_counters(perdisk=True) or {}
    missing_disks = [name for name in config.disk_devices if name not in disk_counters]
    if missing_disks:
        raise DatasetContractError(f"configured disk devices unavailable: {','.join(missing_disks)}")

    phase_counts = _phase_counts(manifest)
    spool = BoundedSegmentSpool(
        config.spool_directory,
        run_id=manifest["run_id"],
        metric_scope=config.metric_scope,
        limits=config.spool_limits,
    )
    spool.preflight()
    return {
        "collector_source_sha256": source_hash,
        "feature_schema_sha256": feature_hash,
        "ntp_synchronized": synchronized,
        "available_configured_interfaces": sorted(set(available_interfaces) & set(interface.name for interface in config.interfaces)),
        "optional_missing_interfaces": sorted(set(missing_interfaces) - set(aggregate_missing)),
        "available_disk_devices": list(config.disk_devices),
        "expected_records": sum(phase_counts.values()),
        "phase_record_counts": phase_counts,
        "spool_directory": str(config.spool_directory),
    }


def _phase_counts(manifest: Mapping[str, Any]) -> dict[str, int]:
    interval = float(manifest["timing"]["sample_interval_seconds"])
    counts: dict[str, int] = {}
    for phase, field in (
        ("baseline", "baseline_seconds"),
        ("workload", "workload_seconds"),
        ("recovery", "recovery_seconds"),
    ):
        raw_count = float(manifest["timing"][field]) / interval
        count = round(raw_count)
        if not math.isclose(raw_count, count, abs_tol=1e-9) or count <= 0:
            raise DatasetContractError(f"{field} must contain a whole positive sample count")
        counts[phase] = count
    return counts


def _sample_id(run_id: str, metric_scope: str, boot_hash: str, sequence: int) -> str:
    identity = f"hardware_telemetry_sample.v1\0{run_id}\0{metric_scope}\0{boot_hash}\0{sequence}"
    return f"sample-v1-{sha256(identity.encode('utf-8')).hexdigest()[:40]}"


def write_json_exclusive(path: Path, document: Mapping[str, Any]) -> None:
    encoded = (
        json.dumps(document, ensure_ascii=False, allow_nan=False, sort_keys=True, indent=2)
        + "\n"
    ).encode("utf-8")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(encoded)
        handle.flush()
        os.fsync(handle.fileno())
    directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def collect_idle_run(
    manifest: Mapping[str, Any],
    config: CollectorConfig,
    *,
    schema_dir: Path,
    probe: Probe | None = None,
    clock: Clock | None = None,
    ntp_synchronized: bool = True,
) -> dict[str, Any]:
    """Collect one neutral-idle run and return its durable collection receipt."""

    source_hash = collector_source_sha256()
    feature_hash = telemetry_schema_sha256(schema_dir)
    _validate_idle_contract(manifest, config, source_hash)
    if config.require_ntp_synchronized and not ntp_synchronized:
        raise DatasetContractError("NTP synchronization is required")
    phase_counts = _phase_counts(manifest)
    telemetry_validator = _schema_validator(
        schema_dir,
        "hardware_telemetry_sample.v1.schema.json",
    )
    runtime_clock = clock or SystemClock()
    runtime_probe = probe or LinuxSystemProbe(config)
    interval_ns = int(float(manifest["timing"]["sample_interval_seconds"]) * 1_000_000_000)
    started_at = runtime_clock.now_utc()
    deadline_ns = runtime_clock.monotonic_ns() + interval_ns
    sequence = 0

    spool = BoundedSegmentSpool(
        config.spool_directory,
        run_id=manifest["run_id"],
        metric_scope=config.metric_scope,
        limits=config.spool_limits,
    )
    with spool:
        for phase in ("baseline", "workload", "recovery"):
            for _ in range(phase_counts[phase]):
                runtime_clock.sleep_until_ns(deadline_ns)
                observed_monotonic_ns = runtime_clock.monotonic_ns()
                late_by_ms = max(
                    (observed_monotonic_ns - deadline_ns) / 1_000_000,
                    0.0,
                )
                result = runtime_probe.sample()
                sample = {
                    "schema_version": "hardware_telemetry_sample.v1",
                    "sample_id": _sample_id(
                        manifest["run_id"],
                        config.metric_scope,
                        runtime_probe.boot_id_sha256,
                        sequence,
                    ),
                    "run_id": manifest["run_id"],
                    "experiment_id": manifest["experiment_id"],
                    "phase": phase,
                    "metric_scope": config.metric_scope,
                    "subject_id": config.subject_id,
                    "time": {
                        "observed_at": _iso_utc(runtime_clock.now_utc()),
                        "monotonic_ns": observed_monotonic_ns,
                        "boot_id_sha256": runtime_probe.boot_id_sha256,
                        "sequence": sequence,
                        "sample_interval_seconds": float(
                            manifest["timing"]["sample_interval_seconds"]
                        ),
                        "ntp_synchronized": ntp_synchronized,
                        "clock_error_bound_ms": None,
                    },
                    "collector": {
                        "collector_id": config.collector_id,
                        "version": config.collector_version,
                        "source_sha256": source_hash,
                        "feature_schema_sha256": feature_hash,
                    },
                    "correlation": {
                        "sensor_id": config.sensor_id,
                        "state": "no_active_session",
                        "canonical_session_ids": [],
                        "command_event_ids": [],
                    },
                    "cpu": result.cpu,
                    "memory": result.memory,
                    "disk": result.disk,
                    "network": result.network,
                    "thermal": result.thermal,
                    "process": result.process,
                    "privacy": {
                        "contains_raw_command": False,
                        "contains_credentials": False,
                        "contains_raw_ip": False,
                    },
                    "quality": {
                        "valid": result.valid,
                        "missing_fields": list(result.missing_fields),
                        "counter_resets": list(result.counter_resets),
                        "sample_late": late_by_ms > config.late_tolerance_ms,
                        "late_by_ms": late_by_ms,
                        "collector_errors": list(result.collector_errors),
                    },
                }
                _validate_document(
                    sample,
                    telemetry_validator,
                    f"telemetry sequence {sequence}",
                )
                spool.append(sample)
                sequence += 1
                deadline_ns += interval_ns

    ended_at = runtime_clock.now_utc()
    receipt = {
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "receipt_id": "collection-receipt-v1-"
        + sha256(
            f"{manifest['run_id']}\0{config.metric_scope}".encode("utf-8")
        ).hexdigest()[:40],
        "run_id": manifest["run_id"],
        "experiment_id": manifest["experiment_id"],
        "metric_scope": config.metric_scope,
        "state": "completed",
        "started_at": _iso_utc(started_at),
        "ended_at": _iso_utc(ended_at),
        "collector": {
            "collector_id": config.collector_id,
            "version": config.collector_version,
            "source_sha256": source_hash,
            "feature_schema_sha256": feature_hash,
        },
        "record_count": sequence,
        "phase_record_counts": phase_counts,
        "serialized_bytes": spool.serialized_bytes,
        "segments": spool.receipts,
    }
    receipt["receipt_sha256"] = _canonical_sha256(receipt)
    write_json_exclusive(spool.run_dir / "collection-receipt.json", receipt)
    return receipt


def verify_collection_receipt(
    receipt: Mapping[str, Any],
    *,
    run_dir: Path,
    telemetry_validator: Draft202012Validator | None = None,
) -> None:
    """Verify receipt identity plus exact segment bytes, counts, and sequences."""

    if receipt.get("schema_version") != RECEIPT_SCHEMA_VERSION:
        raise DatasetContractError("unsupported collection receipt schema")
    claimed_receipt_hash = receipt.get("receipt_sha256")
    if not isinstance(claimed_receipt_hash, str):
        raise DatasetContractError("collection receipt hash is missing")
    without_hash = dict(receipt)
    without_hash.pop("receipt_sha256", None)
    if _canonical_sha256(without_hash) != claimed_receipt_hash:
        raise DatasetContractError("collection receipt content hash does not match")
    expected_receipt_id = "collection-receipt-v1-" + sha256(
        f"{receipt.get('run_id')}\0{receipt.get('metric_scope')}".encode("utf-8")
    ).hexdigest()[:40]
    if receipt.get("receipt_id") != expected_receipt_id:
        raise DatasetContractError("collection receipt identity does not match run/scope")

    expected_next = 0
    total_records = 0
    total_bytes = 0
    phase_counts = {"baseline": 0, "workload": 0, "recovery": 0}
    segments = receipt.get("segments")
    if not isinstance(segments, list) or not segments:
        raise DatasetContractError("collection receipt has no segments")
    for segment in segments:
        filename = segment.get("filename")
        if not isinstance(filename, str) or Path(filename).name != filename:
            raise DatasetContractError("segment filename is unsafe")
        path = run_dir / filename
        digest = sha256()
        record_count = 0
        first_sequence: int | None = None
        last_sequence: int | None = None
        serialized_bytes = 0
        try:
            handle = path.open("rb")
        except OSError as exc:
            raise DatasetContractError(f"segment is unavailable: {filename}") from exc
        with handle:
            for line_number, line in enumerate(handle, start=1):
                digest.update(line)
                serialized_bytes += len(line)
                try:
                    document = json.loads(line)
                    sequence = document["time"]["sequence"]
                except (json.JSONDecodeError, KeyError, TypeError) as exc:
                    raise DatasetContractError(
                        f"invalid segment record {filename}:{line_number}"
                    ) from exc
                if not isinstance(sequence, int) or isinstance(sequence, bool):
                    raise DatasetContractError(
                        f"invalid segment sequence {filename}:{line_number}"
                    )
                if document.get("schema_version") != "hardware_telemetry_sample.v1":
                    raise DatasetContractError(
                        f"unexpected telemetry schema {filename}:{line_number}"
                    )
                if telemetry_validator is not None:
                    _validate_document(
                        document,
                        telemetry_validator,
                        f"{filename}:{line_number}",
                    )
                for identity_field in ("run_id", "experiment_id", "metric_scope"):
                    if document.get(identity_field) != receipt.get(identity_field):
                        raise DatasetContractError(
                            f"segment {identity_field} mismatch {filename}:{line_number}"
                        )
                phase = document.get("phase")
                if phase not in phase_counts:
                    raise DatasetContractError(
                        f"unexpected phase {filename}:{line_number}"
                    )
                phase_counts[phase] += 1
                if sequence != expected_next:
                    raise DatasetContractError(
                        f"noncontiguous segment sequence: expected {expected_next}, got {sequence}"
                    )
                expected_next += 1
                record_count += 1
                if first_sequence is None:
                    first_sequence = sequence
                last_sequence = sequence
        if first_sequence is None or last_sequence is None:
            raise DatasetContractError(f"segment is empty: {filename}")
        observed = {
            "first_sequence": first_sequence,
            "last_sequence": last_sequence,
            "record_count": record_count,
            "serialized_bytes": serialized_bytes,
            "sha256": digest.hexdigest(),
        }
        for field, value in observed.items():
            if segment.get(field) != value:
                raise DatasetContractError(
                    f"segment {filename} {field} does not match receipt"
                )
        expected_filename = (
            f"part-{first_sequence:06d}-{last_sequence:06d}-{digest.hexdigest()}.jsonl"
        )
        if filename != expected_filename:
            raise DatasetContractError("segment filename is not content-addressed correctly")
        total_records += record_count
        total_bytes += serialized_bytes
    if receipt.get("record_count") != total_records:
        raise DatasetContractError("receipt record_count does not match segments")
    if receipt.get("serialized_bytes") != total_bytes:
        raise DatasetContractError("receipt serialized_bytes does not match segments")
    if receipt.get("phase_record_counts") != phase_counts:
        raise DatasetContractError("receipt phase_record_counts does not match segments")


def finalize_idle_manifest(
    manifest: Mapping[str, Any],
    receipt: Mapping[str, Any],
    *,
    run_dir: Path,
    schema_dir: Path,
) -> dict[str, Any]:
    """Create a completed manifest copy only after receipt/segment verification."""

    if manifest.get("state") not in {"planned", "running"}:
        raise DatasetContractError("only a planned/running manifest can be finalized")
    if receipt.get("state") != "completed":
        raise DatasetContractError("collection receipt is not completed")
    for field in ("run_id", "experiment_id"):
        if receipt.get(field) != manifest.get(field):
            raise DatasetContractError(f"receipt {field} does not match manifest")
    if receipt.get("metric_scope") not in manifest["execution_boundary"]["metric_scopes"]:
        raise DatasetContractError("receipt metric_scope is not authorized by manifest")
    receipt_collector = receipt.get("collector", {})
    if receipt_collector.get("collector_id") != manifest["collection"]["collector_id"]:
        raise DatasetContractError("receipt collector_id does not match manifest")
    if receipt_collector.get("source_sha256") != manifest["collection"]["collector_sha256"]:
        raise DatasetContractError("receipt collector source does not match manifest")
    if receipt.get("phase_record_counts") != _phase_counts(manifest):
        raise DatasetContractError("receipt phase counts do not match manifest timing")
    _validate_document(
        manifest,
        _schema_validator(schema_dir, "experiment_run_manifest.v1.schema.json"),
        "source manifest",
    )
    _validate_document(
        receipt,
        _schema_validator(schema_dir, "experiment_collection_receipt.v1.schema.json"),
        "collection receipt",
    )
    telemetry_validator = _schema_validator(
        schema_dir,
        "hardware_telemetry_sample.v1.schema.json",
    )
    verify_collection_receipt(
        receipt,
        run_dir=run_dir,
        telemetry_validator=telemetry_validator,
    )

    completed = deepcopy(manifest)
    completed["state"] = "completed"
    completed["timing"]["started_at"] = receipt["started_at"]
    completed["timing"]["ended_at"] = receipt["ended_at"]
    receipt_ids = completed["labels"]["evidence_receipt_ids"]
    if receipt["receipt_id"] not in receipt_ids:
        receipt_ids.append(receipt["receipt_id"])
    _validate_document(
        completed,
        _schema_validator(schema_dir, "experiment_run_manifest.v1.schema.json"),
        "completed manifest",
    )
    return completed
