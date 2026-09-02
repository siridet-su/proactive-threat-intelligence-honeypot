from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from cowrie_hardware_fusion.service_pressure import (
    cgroup_with_rates,
    counters_with_rates,
    parse_pressure_text,
    parse_socket_summary_text,
    parse_tcp_pressure_text,
    parse_tcp_states_texts,
    pressure_with_rates,
    read_cgroup_snapshot,
    resolve_unified_cgroup,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_pressure_parser_and_rate_use_cumulative_stall_without_spikes() -> None:
    previous = parse_pressure_text(
        "some avg10=1.00 avg60=2.00 avg300=3.00 total=1000\n"
        "full avg10=0.50 avg60=1.00 avg300=1.50 total=200\n"
    )
    current = parse_pressure_text(
        "some avg10=4.00 avg60=5.00 avg300=6.00 total=1400\n"
        "full avg10=1.00 avg60=2.00 avg300=3.00 total=260\n"
    )
    resets: list[str] = []

    observed = pressure_with_rates(
        current,
        previous,
        2.0,
        reset_prefix="host.pressure.cpu",
        resets=resets,
    )

    assert observed["some"]["stall_usec_per_second"] == 200.0
    assert observed["full"]["stall_usec_per_second"] == 30.0
    assert resets == []

    reset_current = deepcopy(current)
    reset_current["some"]["total_stall_usec"] = 10
    observed = pressure_with_rates(
        reset_current,
        current,
        1.0,
        reset_prefix="host.pressure.cpu",
        resets=resets,
    )
    assert observed["some"]["stall_usec_per_second"] == 0.0
    assert resets == ["host.pressure.cpu.some.total_stall_usec"]


def test_socket_and_tcp_state_parsers_do_not_retain_addresses() -> None:
    summary = parse_socket_summary_text(
        "sockets: used 12\nTCP: inuse 4 orphan 1 tw 2 alloc 7 mem 3\n"
        "UDP: inuse 2 mem 1\n",
        "TCP6: inuse 5\nUDP6: inuse 6\n",
    )
    states = parse_tcp_states_texts(
        [
            "  sl  local_address rem_address   st\n"
            "   0: 0100007F:1234 00000000:0000 0A\n"
            "   1: 0100007F:1235 0100007F:9999 01\n",
            "  sl  local_address rem_address   st\n"
            "   0: 00000000000000000000000000000000:1234 0:0 06\n",
        ]
    )

    assert summary["sockets_used"] == 12
    assert summary["tcp_inuse"] == 4
    assert summary["tcp6_inuse"] == 5
    assert states["listen"] == 1
    assert states["established"] == 1
    assert states["time_wait"] == 1
    assert states["total"] == 3
    assert "0100007F" not in json.dumps(states)


def test_tcp_pressure_selects_production_observable_counters_and_rates() -> None:
    counters = parse_tcp_pressure_text(
        "TcpExt: ListenOverflows ListenDrops TCPReqQFullDrop TCPBacklogDrop "
        "TCPMemoryPressures TCPAbortOnMemory TCPRcvQDrop Ignored\n"
        "TcpExt: 4 5 6 7 8 9 10 999\n"
    )
    previous = {name: value - 1 for name, value in counters.items()}
    observed = counters_with_rates(
        counters,
        previous,
        0.5,
        reset_prefix="network.tcp_pressure",
        resets=[],
    )

    assert observed["listen_overflows_total"] == 4
    assert observed["listen_overflows_per_second"] == 2.0
    assert observed["request_queue_full_drops_total"] == 6
    assert "Ignored" not in observed


def test_cgroup_snapshot_and_rates_cover_throttling_memory_pids_and_psi(
    tmp_path: Path,
) -> None:
    (tmp_path / "cpu.stat").write_text(
        "usage_usec 1200\nuser_usec 900\nsystem_usec 300\n"
        "nr_periods 10\nnr_throttled 2\nthrottled_usec 100\n",
        encoding="ascii",
    )
    (tmp_path / "memory.current").write_text("4096\n", encoding="ascii")
    (tmp_path / "memory.peak").write_text("8192\n", encoding="ascii")
    (tmp_path / "memory.events").write_text(
        "low 0\nhigh 1\nmax 2\noom 0\noom_kill 0\noom_group_kill 0\n",
        encoding="ascii",
    )
    (tmp_path / "pids.current").write_text("9\n", encoding="ascii")
    (tmp_path / "pids.events").write_text("max 1\n", encoding="ascii")
    (tmp_path / "io.stat").write_text(
        "8:0 rbytes=100 wbytes=200 rios=3 wios=4 dbytes=5 dios=6\n"
        "8:1 rbytes=10 wbytes=20 rios=1 wios=2 dbytes=0 dios=0\n",
        encoding="ascii",
    )
    for resource in ("cpu", "memory", "io"):
        (tmp_path / f"{resource}.pressure").write_text(
            "some avg10=1.00 avg60=0.50 avg300=0.10 total=500\n"
            "full avg10=0.25 avg60=0.10 avg300=0.05 total=100\n",
            encoding="ascii",
        )

    current = read_cgroup_snapshot(tmp_path)
    previous = deepcopy(current)
    previous["cpu"]["usage_usec_total"] = 1000
    previous["cpu"]["throttled_usec_total"] = 50
    previous["memory"]["high_events_total"] = 0
    previous["io"]["write_bytes_total"] = 180
    previous["pressure"]["cpu"]["some"]["total_stall_usec"] = 400
    observed = cgroup_with_rates(
        current,
        previous,
        2.0,
        reset_prefix="process.target.cgroup",
        resets=[],
    )

    assert observed["cpu"]["usage_usec_per_second"] == 100.0
    assert observed["cpu"]["throttled_usec_per_second"] == 25.0
    assert observed["memory"]["current_bytes"] == 4096
    assert observed["memory"]["high_events_per_second"] == 0.5
    assert observed["pids"]["current"] == 9
    assert observed["io"]["read_bytes_total"] == 110
    assert observed["io"]["write_bytes_per_second"] == 20.0
    assert observed["pressure"]["cpu"]["some"]["stall_usec_per_second"] == 50.0


def test_cgroup_path_resolution_rejects_escape(tmp_path: Path) -> None:
    proc_root = tmp_path / "proc"
    cgroup_root = tmp_path / "cgroup"
    (proc_root / "123").mkdir(parents=True)
    cgroup_root.mkdir()
    (proc_root / "123" / "cgroup").write_text(
        "0::/system.slice/test.scope\n",
        encoding="ascii",
    )

    assert resolve_unified_cgroup(123, cgroup_root, proc_root) == (
        cgroup_root / "system.slice" / "test.scope"
    )

    (proc_root / "123" / "cgroup").write_text("0::/../../escape\n", encoding="ascii")
    with pytest.raises(ValueError, match="escapes"):
        resolve_unified_cgroup(123, cgroup_root, proc_root)


def test_readable_empty_cgroup_io_stat_means_zero_io(tmp_path: Path) -> None:
    (tmp_path / "io.stat").write_text("", encoding="ascii")

    observed = read_cgroup_snapshot(tmp_path)

    assert observed["io"] == {
        "read_bytes_total": 0,
        "write_bytes_total": 0,
        "read_operations_total": 0,
        "write_operations_total": 0,
        "discard_bytes_total": 0,
        "discard_operations_total": 0,
    }


def test_extended_service_pressure_sample_validates_against_schema() -> None:
    sample = json.loads(
        (
            PROJECT_ROOT
            / "schemas"
            / "examples"
            / "hardware_telemetry_sample.v1.example.json"
        ).read_text(encoding="utf-8")
    )
    pressure = pressure_with_rates(
        parse_pressure_text(
            "some avg10=1.00 avg60=0.50 avg300=0.10 total=500\n"
            "full avg10=0.25 avg60=0.10 avg300=0.05 total=100\n"
        ),
        None,
        1.0,
        reset_prefix="test",
        resets=[],
    )
    sample["cpu"]["pressure"] = pressure
    sample["memory"]["pressure"] = pressure
    sample["disk"]["pressure"] = pressure
    sample["network"]["tcp_states"] = parse_tcp_states_texts(
        ["  sl local rem st\n   0: local remote 0A\n"]
    )
    sample["network"]["socket_summary"] = parse_socket_summary_text(
        "sockets: used 1\nTCP: inuse 1 orphan 0 tw 0 alloc 1 mem 0\n"
    )
    sample["network"]["tcp_pressure"] = counters_with_rates(
        {"listen_drops_total": 0},
        None,
        1.0,
        reset_prefix="test",
        resets=[],
    )

    schema = json.loads(
        (
            PROJECT_ROOT / "schemas" / "hardware_telemetry_sample.v1.schema.json"
        ).read_text(encoding="utf-8")
    )
    Draft202012Validator(schema).validate(sample)
