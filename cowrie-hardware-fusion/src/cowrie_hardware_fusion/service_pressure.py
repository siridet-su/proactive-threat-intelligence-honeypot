"""Read-only Linux service-pressure telemetry parsers.

The module deliberately reads counters and scheduler/kernel observations only. It
does not read socket addresses, request payloads, commands, credentials, or simulator
receipts.
"""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any, Mapping, Sequence


TCP_STATE_NAMES = {
    "01": "established",
    "02": "syn_sent",
    "03": "syn_received",
    "04": "fin_wait_1",
    "05": "fin_wait_2",
    "06": "time_wait",
    "07": "closed",
    "08": "close_wait",
    "09": "last_ack",
    "0A": "listen",
    "0B": "closing",
    "0C": "new_syn_received",
}

TCP_PRESSURE_FIELDS = {
    "ListenOverflows": "listen_overflows_total",
    "ListenDrops": "listen_drops_total",
    "TCPReqQFullDoCookies": "request_queue_full_cookies_total",
    "TCPReqQFullDrop": "request_queue_full_drops_total",
    "TCPBacklogDrop": "backlog_drops_total",
    "TCPMemoryPressures": "memory_pressure_events_total",
    "TCPAbortOnMemory": "aborts_on_memory_total",
    "TCPRcvQDrop": "receive_queue_drops_total",
}


def parse_pressure_text(text: str) -> dict[str, dict[str, float | int]]:
    """Parse one Linux PSI file without accepting unknown numeric semantics."""

    result: dict[str, dict[str, float | int]] = {}
    for raw_line in text.splitlines():
        parts = raw_line.split()
        if not parts or parts[0] not in {"some", "full"}:
            continue
        values: dict[str, str] = {}
        for part in parts[1:]:
            if "=" not in part:
                continue
            key, value = part.split("=", 1)
            values[key] = value
        required = {"avg10", "avg60", "avg300", "total"}
        if not required.issubset(values):
            raise ValueError(f"incomplete PSI line for {parts[0]}")
        averages = [float(values[name]) for name in ("avg10", "avg60", "avg300")]
        total = int(values["total"])
        if any(value < 0.0 or value > 100.0 for value in averages) or total < 0:
            raise ValueError(f"invalid PSI values for {parts[0]}")
        result[parts[0]] = {
            "avg10_percent": averages[0],
            "avg60_percent": averages[1],
            "avg300_percent": averages[2],
            "total_stall_usec": total,
        }
    if "some" not in result:
        raise ValueError("PSI file has no some line")
    return result


def read_pressure(path: Path) -> dict[str, dict[str, float | int]]:
    return parse_pressure_text(path.read_text(encoding="ascii"))


def pressure_with_rates(
    current: Mapping[str, Mapping[str, float | int]],
    previous: Mapping[str, Mapping[str, float | int]] | None,
    elapsed_seconds: float,
    *,
    reset_prefix: str,
    resets: list[str],
) -> dict[str, dict[str, float | int]]:
    result = deepcopy(dict(current))
    for kind, values in result.items():
        current_total = int(values["total_stall_usec"])
        previous_values = previous.get(kind) if previous is not None else None
        previous_total = (
            int(previous_values["total_stall_usec"])
            if previous_values is not None
            else current_total
        )
        if current_total < previous_total:
            resets.append(f"{reset_prefix}.{kind}.total_stall_usec")
            delta = 0
        else:
            delta = current_total - previous_total
        values["stall_usec_per_second"] = delta / max(elapsed_seconds, 1e-9)
    return result


def _parse_integer_sections(text: str) -> dict[str, dict[str, int]]:
    result: dict[str, dict[str, int]] = {}
    for raw_line in text.splitlines():
        parts = raw_line.split()
        if len(parts) < 3 or not parts[0].endswith(":"):
            continue
        section = parts[0][:-1]
        values: dict[str, int] = {}
        for index in range(1, len(parts) - 1, 2):
            try:
                values[parts[index]] = int(parts[index + 1])
            except ValueError as exc:
                raise ValueError(f"invalid integer in {section}") from exc
        result[section] = values
    return result


def parse_socket_summary_text(
    ipv4_text: str,
    ipv6_text: str = "",
) -> dict[str, int]:
    ipv4 = _parse_integer_sections(ipv4_text)
    ipv6 = _parse_integer_sections(ipv6_text)
    return {
        "sockets_used": ipv4.get("sockets", {}).get("used", 0),
        "tcp_inuse": ipv4.get("TCP", {}).get("inuse", 0),
        "tcp_orphan": ipv4.get("TCP", {}).get("orphan", 0),
        "tcp_time_wait": ipv4.get("TCP", {}).get("tw", 0),
        "tcp_allocated": ipv4.get("TCP", {}).get("alloc", 0),
        "tcp_memory_pages": ipv4.get("TCP", {}).get("mem", 0),
        "udp_inuse": ipv4.get("UDP", {}).get("inuse", 0),
        "udp_memory_pages": ipv4.get("UDP", {}).get("mem", 0),
        "tcp6_inuse": ipv6.get("TCP6", {}).get("inuse", 0),
        "udp6_inuse": ipv6.get("UDP6", {}).get("inuse", 0),
    }


def read_socket_summary(network_root: Path) -> dict[str, int]:
    ipv4 = (network_root / "sockstat").read_text(encoding="ascii")
    ipv6_path = network_root / "sockstat6"
    try:
        ipv6 = ipv6_path.read_text(encoding="ascii")
    except OSError:
        ipv6 = ""
    return parse_socket_summary_text(ipv4, ipv6)


def parse_tcp_states_texts(texts: Sequence[str]) -> dict[str, int]:
    counts = {name: 0 for name in TCP_STATE_NAMES.values()}
    for text in texts:
        for raw_line in text.splitlines()[1:]:
            fields = raw_line.split()
            if len(fields) < 4:
                continue
            name = TCP_STATE_NAMES.get(fields[3].upper())
            if name is not None:
                counts[name] += 1
    counts["total"] = sum(counts.values())
    return counts


def read_tcp_states(network_root: Path) -> dict[str, int]:
    texts: list[str] = []
    for name in ("tcp", "tcp6"):
        try:
            texts.append((network_root / name).read_text(encoding="ascii"))
        except OSError:
            continue
    if not texts:
        raise OSError("TCP state tables are unavailable")
    return parse_tcp_states_texts(texts)


def parse_tcp_pressure_text(text: str) -> dict[str, int]:
    lines = [line.split() for line in text.splitlines() if line.startswith("TcpExt:")]
    if len(lines) < 2:
        raise ValueError("netstat has no TcpExt key/value pair")
    keys = lines[0][1:]
    raw_values = lines[1][1:]
    if len(keys) != len(raw_values):
        raise ValueError("TcpExt key/value lengths differ")
    values = {key: int(value) for key, value in zip(keys, raw_values)}
    return {
        output_name: values[kernel_name]
        for kernel_name, output_name in TCP_PRESSURE_FIELDS.items()
        if kernel_name in values
    }


def read_tcp_pressure(path: Path) -> dict[str, int]:
    return parse_tcp_pressure_text(path.read_text(encoding="ascii"))


def counters_with_rates(
    current: Mapping[str, int],
    previous: Mapping[str, int] | None,
    elapsed_seconds: float,
    *,
    reset_prefix: str,
    resets: list[str],
) -> dict[str, int | float]:
    result: dict[str, int | float] = dict(current)
    for name, current_value in current.items():
        if not name.endswith("_total"):
            continue
        previous_value = previous.get(name, current_value) if previous is not None else current_value
        if current_value < previous_value:
            resets.append(f"{reset_prefix}.{name}")
            delta = 0
        else:
            delta = current_value - previous_value
        result[name.removesuffix("_total") + "_per_second"] = delta / max(
            elapsed_seconds,
            1e-9,
        )
    return result


def _read_key_values(path: Path) -> dict[str, int]:
    values: dict[str, int] = {}
    for raw_line in path.read_text(encoding="ascii").splitlines():
        parts = raw_line.split()
        if len(parts) == 2:
            values[parts[0]] = int(parts[1])
    return values


def _read_io_stat(path: Path) -> dict[str, int]:
    totals = {
        "read_bytes_total": 0,
        "write_bytes_total": 0,
        "read_operations_total": 0,
        "write_operations_total": 0,
        "discard_bytes_total": 0,
        "discard_operations_total": 0,
    }
    field_names = {
        "rbytes": "read_bytes_total",
        "wbytes": "write_bytes_total",
        "rios": "read_operations_total",
        "wios": "write_operations_total",
        "dbytes": "discard_bytes_total",
        "dios": "discard_operations_total",
    }
    for raw_line in path.read_text(encoding="ascii").splitlines():
        parts = raw_line.split()
        if not parts or ":" not in parts[0]:
            continue
        for part in parts[1:]:
            if "=" not in part:
                continue
            name, raw_value = part.split("=", 1)
            output_name = field_names.get(name)
            if output_name is not None:
                totals[output_name] += int(raw_value)
    return totals


def resolve_unified_cgroup(
    process_id: int,
    cgroup_root: Path = Path("/sys/fs/cgroup"),
    proc_root: Path = Path("/proc"),
) -> Path:
    lines = (proc_root / str(process_id) / "cgroup").read_text(
        encoding="ascii"
    ).splitlines()
    relative = next(line.split(":", 2)[2] for line in lines if line.startswith("0::"))
    root = cgroup_root.resolve()
    target = (root / relative.lstrip("/")).resolve()
    if not target.is_relative_to(root):
        raise ValueError("cgroup path escapes the cgroup root")
    return target


def read_cgroup_snapshot(path: Path) -> dict[str, Any]:
    """Read a cgroup-v2 observation; unavailable controllers remain absent."""

    result: dict[str, Any] = {}
    try:
        cpu = _read_key_values(path / "cpu.stat")
        result["cpu"] = {
            "usage_usec_total": cpu.get("usage_usec", 0),
            "user_usec_total": cpu.get("user_usec", 0),
            "system_usec_total": cpu.get("system_usec", 0),
            "periods_total": cpu.get("nr_periods", 0),
            "throttled_periods_total": cpu.get("nr_throttled", 0),
            "throttled_usec_total": cpu.get("throttled_usec", 0),
        }
    except OSError:
        pass

    memory: dict[str, int] = {}
    for filename, field in (
        ("memory.current", "current_bytes"),
        ("memory.peak", "peak_bytes"),
    ):
        try:
            memory[field] = int((path / filename).read_text(encoding="ascii").strip())
        except (OSError, ValueError):
            continue
    try:
        events = _read_key_values(path / "memory.events")
        for source, field in (
            ("low", "low_events_total"),
            ("high", "high_events_total"),
            ("max", "max_events_total"),
            ("oom", "oom_events_total"),
            ("oom_kill", "oom_kill_events_total"),
            ("oom_group_kill", "oom_group_kill_events_total"),
        ):
            if source in events:
                memory[field] = events[source]
    except OSError:
        pass
    if memory:
        result["memory"] = memory

    pids: dict[str, int] = {}
    try:
        pids["current"] = int((path / "pids.current").read_text(encoding="ascii").strip())
    except (OSError, ValueError):
        pass
    try:
        events = _read_key_values(path / "pids.events")
        if "max" in events:
            pids["max_events_total"] = events["max"]
    except OSError:
        pass
    if pids:
        result["pids"] = pids

    try:
        result["io"] = _read_io_stat(path / "io.stat")
    except (OSError, ValueError):
        pass

    pressure: dict[str, Any] = {}
    for resource in ("cpu", "memory", "io"):
        try:
            pressure[resource] = read_pressure(path / f"{resource}.pressure")
        except (OSError, ValueError):
            continue
    if pressure:
        result["pressure"] = pressure
    return result


def cgroup_with_rates(
    current: Mapping[str, Any],
    previous: Mapping[str, Any] | None,
    elapsed_seconds: float,
    *,
    reset_prefix: str,
    resets: list[str],
) -> dict[str, Any]:
    result = deepcopy(dict(current))
    previous = previous or {}
    for block_name in ("cpu", "memory", "pids", "io"):
        block = current.get(block_name)
        if isinstance(block, Mapping):
            previous_block = previous.get(block_name)
            result[block_name] = counters_with_rates(
                block,
                previous_block if isinstance(previous_block, Mapping) else None,
                elapsed_seconds,
                reset_prefix=f"{reset_prefix}.{block_name}",
                resets=resets,
            )
    pressure = current.get("pressure")
    if isinstance(pressure, Mapping):
        result_pressure: dict[str, Any] = {}
        previous_pressure = previous.get("pressure")
        for resource, block in pressure.items():
            if not isinstance(block, Mapping):
                continue
            old = (
                previous_pressure.get(resource)
                if isinstance(previous_pressure, Mapping)
                else None
            )
            result_pressure[resource] = pressure_with_rates(
                block,
                old if isinstance(old, Mapping) else None,
                elapsed_seconds,
                reset_prefix=f"{reset_prefix}.pressure.{resource}",
                resets=resets,
            )
        result["pressure"] = result_pressure
    return result
