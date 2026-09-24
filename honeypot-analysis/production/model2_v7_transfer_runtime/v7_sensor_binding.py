"""Select only decoy-sensor receipts bound to one exact Model2 measurement.

Source IP plus time is insufficient: two Cowrie sessions may share both. The
current sensor emits no measurement identities, so its receipts remain context
and do not enter a session's model features.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


class SensorBindingError(ValueError):
    """A receipt cannot be bound to one measurement without ambiguity."""


def _tuple(item: Mapping[str, Any]) -> dict[str, Any]:
    value = {
        "src_ip": str(item["source_ip"]),
        "src_port": int(item["source_port"]),
        "dst_ip": str(item["target_ip"]),
        "dst_port": int(item["target_port"]),
    }
    if not value["src_ip"] or not value["dst_ip"] or not 1 <= value["src_port"] <= 65535 or not 1 <= value["dst_port"] <= 65535:
        raise SensorBindingError("sensor_tuple_invalid")
    return value


def select_bound_sensor_tuples(
    receipts: list[Mapping[str, Any]],
    *,
    source_ip: str,
    target_ip: str,
    allowed_ports: frozenset[int],
    low: float,
    high: float,
    session_id: str,
    run_id: str,
    measurement_id: str,
    episode_id: str,
) -> list[dict[str, Any]]:
    expected_identity = {
        "session_id": session_id,
        "run_id": run_id,
        "measurement_id": measurement_id,
        "episode_id": episode_id,
    }
    if any(not value for value in expected_identity.values()):
        raise SensorBindingError("sensor_measurement_identity_missing")
    result: list[dict[str, Any]] = []
    for item in receipts:
        if item.get("schema_version") != "model2_v7_t1046_sensor_receipt.v1":
            continue
        if item.get("binding_mode") != "EXACT_MEASUREMENT_IDENTITY":
            continue
        if any(str(item.get(field) or "") != value for field, value in expected_identity.items()):
            continue
        try:
            started = float(item["started_epoch"])
            value = _tuple(item)
            response_bytes = int(item["response_bytes"])
            orig_payload_bytes = int(item["orig_payload_bytes"])
        except (KeyError, TypeError, ValueError):
            continue
        if (
            value["src_ip"] != source_ip
            or value["dst_ip"] != target_ip
            or value["dst_port"] not in allowed_ports
            or not low <= started <= high
            or response_bytes != 19
            or not 0 <= orig_payload_bytes <= 4096
        ):
            continue
        result.append(value)
    identities = {(item["src_ip"], item["src_port"], item["dst_ip"], item["dst_port"]) for item in result}
    if len(result) != len(identities):
        raise SensorBindingError("sensor_receipt_tuple_duplicate")
    return result


def bound_scan_observation(
    sensor_tuples: list[Mapping[str, Any]],
    sensor_flows: list[Mapping[str, Any]],
    *,
    session_id: str,
    run_id: str,
    measurement_id: str,
    episode_id: str,
) -> dict[str, Any]:
    """Create a scan marker only after exact receipt and offline-flow selection."""
    expected_identity = {
        "session_id": session_id,
        "run_id": run_id,
        "measurement_id": measurement_id,
        "episode_id": episode_id,
    }
    if any(not value for value in expected_identity.values()):
        raise SensorBindingError("sensor_measurement_identity_missing")
    if len(sensor_tuples) != len(sensor_flows):
        raise SensorBindingError("sensor_flow_count_mismatch")
    uids: list[str] = []
    ports: set[int] = set()
    for expected, flow in zip(sensor_tuples, sensor_flows):
        expected_tuple = (str(expected["src_ip"]), int(expected["src_port"]), str(expected["dst_ip"]), int(expected["dst_port"]))
        actual_tuple = (str(flow["id.orig_h"]), int(flow["id.orig_p"]), str(flow["id.resp_h"]), int(flow["id.resp_p"]))
        reverse_tuple = (actual_tuple[2], actual_tuple[3], actual_tuple[0], actual_tuple[1])
        uid = str(flow.get("uid") or "")
        if expected_tuple not in (actual_tuple, reverse_tuple) or not uid:
            raise SensorBindingError("sensor_flow_tuple_or_uid_mismatch")
        uids.append(uid)
        ports.add(int(expected["dst_port"]))
    if len(set(uids)) != len(uids):
        raise SensorBindingError("sensor_flow_uid_duplicate")
    observed = len(ports) >= 2
    return {
        **expected_identity,
        "observed": observed,
        "scope": "MULTISERVICE_SCAN" if observed else "NONE",
        "binding_mode": "EXACT_MEASUREMENT_IDENTITY" if observed else "NO_EXACT_MULTISERVICE_BINDING",
        "pcap_binding": "PASS",
        "zeek_binding": "PASS",
        "source_ip_only_binding": False,
        "cross_session_contamination": "NO",
        "flow_uids": uids if observed else [],
        "destination_ports": sorted(ports) if observed else [],
        "reason": "exact_bound_multiservice_scan" if observed else "t1046_not_observed",
    }
