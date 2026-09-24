"""Exact-session decoy receipt selection; same-IP/time is never sufficient."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


SOURCE = Path(__file__).resolve().parents[1] / "production" / "model2_v7_transfer_runtime" / "v7_sensor_binding.py"
SPEC = importlib.util.spec_from_file_location("v7_sensor_binding", SOURCE)
assert SPEC and SPEC.loader
binding = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(binding)


IDS = {
    "session_id": "session-a",
    "run_id": "run-a",
    "measurement_id": "measurement-a",
    "episode_id": "episode-a",
}


def receipt(port: int = 80, source_port: int = 50000, **changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        "schema_version": "model2_v7_t1046_sensor_receipt.v1",
        "binding_mode": "EXACT_MEASUREMENT_IDENTITY",
        **IDS,
        "source_ip": "198.51.100.9",
        "source_port": source_port,
        "target_ip": "10.148.0.2",
        "target_port": port,
        "started_epoch": 100.0,
        "response_bytes": 19,
        "orig_payload_bytes": 0,
    }
    value.update(changes)
    return value


def select(receipts: list[dict[str, object]]) -> list[dict[str, object]]:
    return binding.select_bound_sensor_tuples(
        receipts,
        source_ip="198.51.100.9",
        target_ip="10.148.0.2",
        allowed_ports=frozenset({80, 443, 445, 3306}),
        low=99.0,
        high=101.0,
        **IDS,
    )


def flow(value: dict[str, object], uid: str) -> dict[str, object]:
    return {
        "id.orig_h": value["src_ip"],
        "id.orig_p": value["src_port"],
        "id.resp_h": value["dst_ip"],
        "id.resp_p": value["dst_port"],
        "uid": uid,
    }


def test_current_source_time_only_receipts_are_not_session_features() -> None:
    unbound = [receipt(80, 50000), receipt(443, 50001)]
    for item in unbound:
        for field in IDS:
            item.pop(field)
        item.pop("binding_mode")
    assert select(unbound) == []


def test_same_ip_other_session_and_mismatched_measurement_are_rejected() -> None:
    assert select([receipt(session_id="session-b"), receipt(measurement_id="measurement-b")]) == []


def test_exact_receipts_require_matching_offline_flows_and_two_ports() -> None:
    tuples = select([receipt(80, 50000), receipt(443, 50001)])
    marker = binding.bound_scan_observation(tuples, [flow(tuples[0], "flow-a"), flow(tuples[1], "flow-b")], **IDS)
    assert marker["observed"] is True
    assert marker["binding_mode"] == "EXACT_MEASUREMENT_IDENTITY"
    assert marker["destination_ports"] == [80, 443]
    assert {key: marker[key] for key in IDS} == IDS


def test_single_port_is_not_a_multiservice_scan() -> None:
    tuples = select([receipt()])
    marker = binding.bound_scan_observation(tuples, [flow(tuples[0], "flow-a")], **IDS)
    assert marker["observed"] is False
    assert marker["reason"] == "t1046_not_observed"


def test_flow_mismatch_and_duplicate_receipts_fail_closed() -> None:
    tuples = select([receipt(80, 50000), receipt(443, 50001)])
    with pytest.raises(binding.SensorBindingError, match="sensor_flow_tuple_or_uid_mismatch"):
        binding.bound_scan_observation(tuples, [flow(tuples[1], "flow-a"), flow(tuples[0], "flow-b")], **IDS)
    with pytest.raises(binding.SensorBindingError, match="sensor_receipt_tuple_duplicate"):
        select([receipt(), receipt()])
