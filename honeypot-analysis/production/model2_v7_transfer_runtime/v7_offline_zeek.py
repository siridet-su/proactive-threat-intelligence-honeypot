#!/usr/bin/env python3
"""Merge exact capstone and Pi packet sets, retain them, then run offline Zeek."""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import tempfile
from typing import Any, Mapping

from v7_common import (
    MAX_FLOW_ROWS,
    Packet,
    V7BoundaryError,
    canonical,
    exact_tuple,
    packets_for_tuples,
    read_pcap,
    read_rings,
    sanitize_flow,
    sha256_bytes,
    sha256_file,
    tuple_equal,
    write_raw_pcap,
)
from v7_transfer_binding import packet_set_matches_events, transfer_tuple_allowed


SCHEMA = "model2_v7_production_offline_zeek.v1"
TRANSFER_SOURCE = "192.168.89.112"


def _flow_tuple(flow: Mapping[str, Any]) -> dict[str, Any]:
    return {"src_ip": flow["id.orig_h"], "src_port": flow["id.orig_p"], "dst_ip": flow["id.resp_h"], "dst_port": flow["id.resp_p"]}


def run(
    *, request: Mapping[str, Any], capstone_pcap: bytes, transfer_ring_bases: list[pathlib.Path],
    retain_dir: pathlib.Path, work_dir: pathlib.Path, zeek_bin: str = "/usr/local/bin/zeek",
) -> dict[str, Any]:
    request_id = str(request.get("request_id") or "")
    if len(request_id) != 64 or sha256_bytes(capstone_pcap) != str(request.get("capstone_pcap_sha256") or ""):
        raise V7BoundaryError("offline_request_identity_invalid")
    low, high = float(request["window_start_epoch"]), float(request["window_end_epoch"])
    if high <= low or high - low > 3600:
        raise V7BoundaryError("offline_window_invalid")
    transfer_tuples = [exact_tuple(value, "transfer_tuple") for value in request.get("transfer_tuples", [])]
    if any(not transfer_tuple_allowed(value) for value in transfer_tuples):
        raise V7BoundaryError("transfer_boundary_invalid")
    download_events = request.get("download_events")
    if not isinstance(download_events, list) or len(download_events) != len(transfer_tuples):
        raise V7BoundaryError("transfer_download_binding_missing")
    with tempfile.TemporaryDirectory(prefix=request_id[:16] + "-", dir=work_dir) as temp_name:
        temp = pathlib.Path(temp_name)
        capstone_path = temp / "capstone.pcap"
        capstone_path.write_bytes(capstone_pcap)
        capstone_packets = read_pcap(capstone_path)
        transfer_packets: list[Packet] = []
        if transfer_tuples:
            transfer_packets = packets_for_tuples(read_rings(transfer_ring_bases, low, high), transfer_tuples)
            for expected in transfer_tuples:
                syns = [packet for packet in transfer_packets if tuple_equal(packet.tuple, expected) and packet.flags & 0x02 and not packet.flags & 0x10]
                if len(syns) != 1:
                    raise V7BoundaryError("transfer_pcap_tuple_ambiguous")
            if not packet_set_matches_events(download_events, transfer_packets, transfer_tuples):
                raise V7BoundaryError("transfer_pcap_http_request_mismatch")
        retain_dir.mkdir(parents=True, exist_ok=True)
        exact_path = retain_dir / f"{request_id}.pcap"
        exact_meta = write_raw_pcap(exact_path, [*capstone_packets, *transfer_packets])
        os.chmod(exact_path, 0o640)
        completed = subprocess.run(
            [zeek_bin, "-C", "-e", "redef LogAscii::use_json = T;", "-r", str(exact_path)],
            cwd=temp, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=20, check=False,
        )
        if completed.returncode != 0:
            raise V7BoundaryError("offline_zeek_nonzero_exit")
        conn_path = temp / "conn.log"
        all_flows: list[dict[str, Any]] = []
        with conn_path.open("rb") as handle:
            for line in handle:
                if len(line) > 256 * 1024 or not line.startswith(b"{"):
                    continue
                try:
                    raw = json.loads(line)
                    all_flows.append(sanitize_flow(raw))
                except (json.JSONDecodeError, TypeError, ValueError, V7BoundaryError):
                    continue
        expected = [exact_tuple(request["backend_tuple"], "backend_tuple"), *[exact_tuple(value, "sensor_tuple") for value in request.get("sensor_tuples", [])], *transfer_tuples]
        selected: list[dict[str, Any]] = []
        for item in expected:
            matches = [flow for flow in all_flows if tuple_equal(_flow_tuple(flow), item, bidirectional=True)]
            if len(matches) != 1:
                raise V7BoundaryError(f"offline_zeek_exact_flow_count:{len(matches)}")
            selected.append(matches[0])
        if not selected or len(selected) > MAX_FLOW_ROWS or len({item["uid"] for item in selected}) != len(selected):
            raise V7BoundaryError("offline_zeek_flow_set_invalid")
        projection = canonical(selected) + b"\n"
        projection_path = retain_dir / f"{request_id}.flows.json"
        projection_path.write_bytes(projection)
        os.chmod(projection_path, 0o640)
        return {
            "schema_version": SCHEMA,
            "status": "PASS",
            "request_id": request_id,
            "pcap": {**exact_meta, "finalized": True},
            "zeek": {
                "sha256": sha256_file(conn_path), "projection_sha256": sha256_bytes(projection),
                "pcap_sha256": exact_meta["sha256"], "finalized": True,
                "materialization": "offline_zeek_from_exact_pcap",
                "selected_flow_uids": [item["uid"] for item in selected],
                "projection_path": str(projection_path),
            },
            "flows": selected,
            "transfer_packet_count": len(transfer_packets),
        }
