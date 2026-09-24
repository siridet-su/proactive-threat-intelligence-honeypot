#!/usr/bin/env python3
"""Fail-closed V7 production coordinator built on the proven V6 transport."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import pathlib
import re
import socket
import sys
from typing import Any, Mapping

HERE = pathlib.Path(__file__).resolve().parent
for candidate in (
    HERE,
    HERE.parents[1] / "model2_v6_production_native_20260911_v1",
    pathlib.Path("/opt/model2-v6"),
    HERE.parents[2],
    HERE.parents[2] / "research",
):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

import v6_capstone_runtime as v6  # noqa: E402
from research.model2_v7_32_shadow.materialize import materialize_episode  # noqa: E402
from research.model2_v7_32_shadow.targeted_runtime import infer_shadow, load_model  # noqa: E402
from research.model2_v5_style_unified_production_native.runtime import (  # noqa: E402
    infer_shadow as infer_v5_unified_shadow,
    load_model as load_v5_unified_model,
)
from v7_common import (  # noqa: E402
    V7BoundaryError, canonical, exact_tuple, iso, packets_for_tuples, read_pcap,
    read_rings, sanitize_flow, sha256_bytes, sha256_file, tuple_equal, utc,
    write_raw_pcap,
)
from v7_offline_zeek import SCHEMA as OFFLINE_SCHEMA  # noqa: E402
from v7_transfer_binding import transfer_tuple_allowed  # noqa: E402
from v7_sensor_binding import bound_scan_observation, select_bound_sensor_tuples, unbound_sensor_context_present  # noqa: E402


_v6_sanitized_event = v6.sanitized_event


def sanitized_v7_event(raw: Mapping[str, Any]) -> dict[str, Any]:
    """Include only the bounded download fingerprint in the event digest."""
    event = _v6_sanitized_event(raw)
    if event["eventid"] == "cowrie.session.file_download":
        fingerprint = raw.get("download_request_sha256")
        if isinstance(fingerprint, str) and re.fullmatch(r"[0-9a-f]{64}", fingerprint):
            event["download_request_sha256"] = fingerprint
    return event


v6.sanitized_event = sanitized_v7_event


MODEL_VERSION = "MODEL2_V7_PRODUCTION_NATIVE_MULTILABEL_20260913_32F_V1"
ARTIFACT_SHA256 = "622f50709ed621e0dfcf6088392c0eb19adda53484636ba4208ae82c20ce7aee"
CANDIDATE_SHA256 = "51526097888e55d670832ea4cf9eca24c7c0036c05453e580280c504e5ce51b7"
V5_UNIFIED_ARTIFACT_SHA256 = "104d4c77a3e1536b847561abb19fc7c0d6d7dc0111cd98d1ff2d9c9d74a2ed1a"
V5_UNIFIED_CANDIDATE_SHA256 = "ce1b2d7bd25423226ed675d83493d5f69e5a7061deb96d955a03de94587552ac"
BINDING_SHA256 = "2aa0cfebe1298943517610c3e62e0c9a38651ea93b65747dc69250d814b26c7b"
CAPSTONE_PUBLIC_IP = "10.148.0.2"
BACKEND_SOURCE_HOST = "10.58.33.6"
BACKEND_HOST = "10.58.33.42"
BACKEND_PORT = 2298
SENSOR_PORTS = frozenset({80, 443, 445, 3306})
TRANSFER_SOURCE = "192.168.89.112"
MAX_OFFLINE_RESPONSE = 512 * 1024


def flow_tuple(flow: Mapping[str, Any]) -> dict[str, Any]:
    return {"src_ip": flow["id.orig_h"], "src_port": flow["id.orig_p"], "dst_ip": flow["id.resp_h"], "dst_port": flow["id.resp_p"]}


def _read_line(connection: socket.socket, limit: int) -> bytes:
    data = bytearray()
    while len(data) <= limit:
        chunk = connection.recv(1)
        if not chunk:
            break
        data.extend(chunk)
        if chunk == b"\n":
            return bytes(data)
    raise V7BoundaryError("offline_response_bound_exceeded")


class Coordinator(v6.Coordinator):
    def __init__(self, config: Mapping[str, Any]) -> None:
        self.collection_enabled = bool(config.get("collection_enabled", False))
        self.model_adapter = str(config.get("model_adapter", "v7"))
        if self.model_adapter not in {"v7", "v5_unified"}:
            raise V7BoundaryError("model_adapter_invalid")
        self.feature_schema_path = pathlib.Path(str(config["feature_schema_path"]))
        self.runtime_contract_path = pathlib.Path(str(config["runtime_contract_path"]))
        self.binding_contract_path = pathlib.Path(str(config["binding_contract_path"]))
        self.sensor_receipt_path = pathlib.Path(str(config["sensor_receipt_path"]))
        super().__init__(config)
        self.collection_rows = self.root / "collection"
        self.collection_rows.mkdir(parents=True, exist_ok=True)
        self.model = None
        if self.shadow_enabled:
            if self.model_adapter == "v5_unified":
                self.model = load_v5_unified_model(
                    self.artifact_path,
                    feature_schema_path=self.feature_schema_path,
                    expected_model_sha256=V5_UNIFIED_ARTIFACT_SHA256,
                )
            else:
                self.model = load_model(
                    self.artifact_path,
                    feature_schema_path=self.feature_schema_path,
                    runtime_contract_path=self.runtime_contract_path,
                    expected_model_sha256=ARTIFACT_SHA256,
                )

    def _validate_installation(self) -> None:
        if sha256_file(self.binding_contract_path) != BINDING_SHA256:
            raise V7BoundaryError("binding_contract_sha256_mismatch")
        if self.shadow_enabled:
            expected_artifact = V5_UNIFIED_ARTIFACT_SHA256 if self.model_adapter == "v5_unified" else ARTIFACT_SHA256
            if sha256_file(self.artifact_path) != expected_artifact:
                raise V7BoundaryError("artifact_sha256_mismatch")
            artifact = json.loads(self.artifact_path.read_text(encoding="utf-8"))
            expected_candidate = V5_UNIFIED_CANDIDATE_SHA256 if self.model_adapter == "v5_unified" else CANDIDATE_SHA256
            if artifact.get("candidate_sha256") != expected_candidate:
                raise V7BoundaryError("candidate_sha256_mismatch")

    def _write_collection_row(self, run_id: str, row: Mapping[str, Any]) -> None:
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", run_id):
            raise V7BoundaryError("collection_run_id_invalid")
        final = self.collection_rows / f"{run_id}.row.json"
        temp = final.with_suffix(".tmp")
        with temp.open("wb") as handle:
            handle.write(canonical(dict(row)) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, final)

    def unavailable(self, *, message_id: str, reason: str, session_id: str = "", run_id: str = "") -> dict[str, Any]:
        if self.model_adapter == "v5_unified":
            result = {
                "schema_version": "model2_v5_style_unified_production_native_shadow_result.v1",
                "status": "MODEL2_UNAVAILABLE", "availability": "UNAVAILABLE",
                "failure_closed_state": "MODEL2_UNAVAILABLE",
                "authority": "NON_AUTHORITATIVE_SHADOW_ONLY",
                "message_id": message_id, "session_id": session_id, "run_id": run_id,
                "reason": reason[:240], "pcap_binding": "FAIL", "zeek_binding": "FAIL",
                "feature_materialization": "FAIL", "canonical_write_authority": False,
                "one_model": True, "independent_binary_heads": False,
            }
        else:
            result = {
                "schema_version": "model2_v7_production_shadow_result.v1",
                "status": "MODEL2_V7_UNAVAILABLE", "availability": "UNAVAILABLE",
                "authority": "NON_AUTHORITATIVE_SHADOW_ONLY",
                "message_id": message_id, "session_id": session_id, "run_id": run_id,
                "reason": reason[:240], "pcap_binding": "FAIL", "zeek_binding": "FAIL",
                "feature_materialization": "FAIL", "canonical_write_authority": False,
            }
        try:
            self._write_result(run_id or f"unavailable-{message_id[:24]}", result)
            self._record(result)
        except (OSError, Exception):
            pass
        return result

    def _sensor_tuples(
        self, source_ip: str, low: float, high: float, *,
        session_id: str, run_id: str, measurement_id: str, episode_id: str,
    ) -> tuple[list[dict[str, Any]], bool]:
        try:
            size = self.sensor_receipt_path.stat().st_size
            with self.sensor_receipt_path.open("rb") as handle:
                handle.seek(max(0, size - 16 * 1024 * 1024))
                data = handle.read(16 * 1024 * 1024)
        except OSError:
            return [], False
        if size > 16 * 1024 * 1024:
            _, _, data = data.partition(b"\n")
        receipts: list[Mapping[str, Any]] = []
        for line in data.splitlines():
            try:
                item = json.loads(line)
                if isinstance(item, Mapping):
                    receipts.append(item)
            except (ValueError, json.JSONDecodeError):
                continue
        selected = select_bound_sensor_tuples(
            receipts, source_ip=source_ip, target_ip=CAPSTONE_PUBLIC_IP,
            allowed_ports=SENSOR_PORTS, low=low, high=high,
            session_id=session_id, run_id=run_id,
            measurement_id=measurement_id, episode_id=episode_id,
        )
        return selected, unbound_sensor_context_present(
            receipts, source_ip=source_ip, target_ip=CAPSTONE_PUBLIC_IP,
            allowed_ports=SENSOR_PORTS, low=low, high=high,
        )

    def _transfer_tuples(self, raw_candidates: Any, events: list[Any]) -> list[dict[str, Any]]:
        if not isinstance(raw_candidates, list):
            raise V7BoundaryError("transfer_packet_candidates_invalid")
        candidates = [exact_tuple(value, "transfer_packet_tuple") for value in raw_candidates]
        if any(not transfer_tuple_allowed(value) for value in candidates):
            raise V7BoundaryError("transfer_packet_boundary_invalid")
        downloads = [item for item in events if item.eventid == "cowrie.session.file_download"]
        if len(candidates) != len(downloads):
            raise V7BoundaryError(f"transfer_event_flow_count_mismatch:{len(downloads)}:{len(candidates)}")
        if len({(value["src_ip"], value["src_port"], value["dst_ip"], value["dst_port"]) for value in candidates}) != len(candidates):
            raise V7BoundaryError("transfer_tuple_reuse")
        return candidates

    def _capstone_exact(
        self, *, output: pathlib.Path, original: Mapping[str, Any], connect_ts: float,
        close_ts: float, sensor_tuples: list[dict[str, Any]], run_id: str,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        all_packets = read_rings(self.ring_bases, connect_ts - 5.0, close_ts + 5.0)
        front_syns = [packet for packet in all_packets if tuple_equal(packet.tuple, original) and packet.flags & 0x02 and not packet.flags & 0x10]
        if not front_syns:
            raise V7BoundaryError("pcap_front_syn_missing")
        expected_proxy = f"PROXY TCP4 {original['src_ip']} {original['dst_ip']} {original['src_port']} {original['dst_port']}".encode()
        backend_syns = [packet for packet in all_packets if packet.src_ip == BACKEND_SOURCE_HOST and packet.dst_ip == BACKEND_HOST and packet.dst_port == BACKEND_PORT and packet.flags & 0x02 and not packet.flags & 0x10]
        matches: list[tuple[dict[str, Any], float]] = []
        for syn in backend_syns:
            value = syn.tuple
            chunks = [packet for packet in all_packets if tuple_equal(packet.tuple, value) and packet.payload]
            stream = b"".join(packet.payload for packet in sorted(chunks, key=lambda packet: (packet.sequence, packet.timestamp)))[:4096]
            if expected_proxy + b"\r\n" in stream:
                matches.append((value, syn.timestamp))
        unique: dict[tuple[str, int, str, int], tuple[dict[str, Any], float]] = {}
        for value, started in sorted(matches, key=lambda item: item[1]):
            key = (value["src_ip"], value["src_port"], value["dst_ip"], value["dst_port"])
            unique.setdefault(key, (value, started))
        if len(unique) != 1:
            raise V7BoundaryError(f"proxy_exact_backend_count:{len(unique)}")
        backend, backend_start = next(iter(unique.values()))
        base_packets = packets_for_tuples(all_packets, [original, backend])
        sensor_packets = packets_for_tuples(all_packets, sensor_tuples)
        for expected in sensor_tuples:
            syns = [packet for packet in sensor_packets if tuple_equal(packet.tuple, expected) and packet.flags & 0x02 and not packet.flags & 0x10]
            if len(syns) != 1:
                raise V7BoundaryError("sensor_pcap_tuple_ambiguous")
        metadata = write_raw_pcap(output, [*base_packets, *sensor_packets])
        base = {"backend": backend, "backend_start_ts": backend_start, "proxy_v1_line": expected_proxy.decode(), "front_start_ts": min(item.timestamp for item in front_syns)}
        metadata.update({"backend": backend, "backend_start_ts": backend_start, "proxy_v1_line": expected_proxy.decode(), "sensor_tuple_count": len(sensor_tuples), "run_id": run_id})
        return metadata, base

    def _offline(
        self, connection: socket.socket, pcap_path: pathlib.Path, *, backend: Mapping[str, Any],
        sensor_tuples: list[dict[str, Any]], transfer_tuples: list[dict[str, Any]],
        download_events: list[dict[str, Any]], low: float, high: float,
    ) -> dict[str, Any]:
        pcap = pcap_path.read_bytes()
        request_id = sha256_bytes(canonical({"pcap": sha256_bytes(pcap), "backend": dict(backend), "sensor": sensor_tuples, "transfer": transfer_tuples, "downloads": download_events, "low": low, "high": high}))
        request = {
            "schema_version": OFFLINE_SCHEMA, "request_id": request_id,
            "capstone_pcap_sha256": sha256_bytes(pcap), "capstone_pcap_bytes": len(pcap),
            "backend_tuple": dict(backend), "sensor_tuples": sensor_tuples,
            "transfer_tuples": transfer_tuples, "download_events": download_events,
            "window_start_epoch": low, "window_end_epoch": high,
        }
        connection.settimeout(40.0)
        connection.sendall(b"OFFLINE_ZEEK_V7\n" + canonical(request) + b"\n" + pcap)
        try:
            response = json.loads(_read_line(connection, MAX_OFFLINE_RESPONSE))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise V7BoundaryError("offline_response_invalid") from exc
        if not isinstance(response, Mapping) or response.get("schema_version") != OFFLINE_SCHEMA or response.get("status") != "PASS" or response.get("request_id") != request_id:
            detail = str(response.get("reason") or "invalid_response")[:120] if isinstance(response, Mapping) else "non_object_response"
            raise V7BoundaryError("offline_zeek_unavailable:" + detail)
        flows = [sanitize_flow(item) for item in response.get("flows", [])]
        expected = [exact_tuple(backend), *sensor_tuples, *transfer_tuples]
        if len(flows) != len(expected) or any(not tuple_equal(flow_tuple(flow), value, bidirectional=True) for flow, value in zip(flows, expected)):
            raise V7BoundaryError("offline_flow_order_or_tuple_mismatch")
        return dict(response)

    def _complete(self, message_id: str, body: Mapping[str, Any], connection: socket.socket | None) -> dict[str, Any]:
        session_id = str(body.get("session_id") or "")
        run_id = ""
        pcap_path: pathlib.Path | None = None
        try:
            if connection is None:
                raise V7BoundaryError("offline_session_missing")
            events_raw = body.get("events")
            if not session_id or not isinstance(events_raw, list) or not events_raw or len(events_raw) > v6.MAX_EVENTS:
                raise V7BoundaryError("session_event_stream_invalid")
            events = [v6.as_cowrie_event(item) for item in events_raw]
            if any(item.session != session_id for item in events):
                raise V7BoundaryError("cross_session_event_contamination")
            connects = [item for item in events if item.eventid == "cowrie.session.connect"]
            closes = [item for item in events if item.eventid == "cowrie.session.closed"]
            if len(connects) != 1 or len(closes) != 1 or closes[0].timestamp <= connects[0].timestamp:
                raise V7BoundaryError("session_lifecycle_invalid")
            original = exact_tuple(body.get("original_tuple"), "original_tuple")
            connect_tuple = exact_tuple({"src_ip": connects[0].src_ip, "src_port": connects[0].src_port, "dst_ip": connects[0].dst_ip, "dst_port": connects[0].dst_port}, "connect_tuple")
            if not tuple_equal(original, connect_tuple) or original["dst_ip"] != CAPSTONE_PUBLIC_IP or original["dst_port"] != 2222:
                raise V7BoundaryError("original_frontend_binding_invalid")
            seed = {"contract": BINDING_SHA256, "session_id": session_id, "original_tuple": original, "connect_timestamp": connects[0].timestamp.isoformat()}
            digest = sha256_bytes(canonical(seed))
            run_id, measurement_id, episode_id = "v7-" + digest[:32], "measurement-" + digest[:32], "episode-" + digest[:32]
            connect_epoch, close_epoch = connects[0].timestamp.timestamp(), closes[0].timestamp.timestamp()
            capture_low, capture_high = connect_epoch - 5.0, close_epoch + 12.0
            raw_flows = body.get("zeek_flows")
            if not isinstance(raw_flows, list) or len(raw_flows) > v6.MAX_FLOW_ROWS:
                raise V7BoundaryError("live_flow_candidates_invalid")
            live_flows = [sanitize_flow(item) for item in raw_flows]
            transfer_tuples = self._transfer_tuples(body.get("transfer_packet_tuples"), events)
            sensor_tuples, unbound_sensor_context = self._sensor_tuples(
                original["src_ip"], connect_epoch - 1.0, close_epoch + 1.0,
                session_id=session_id, run_id=run_id,
                measurement_id=measurement_id, episode_id=episode_id,
            )
            pcap_path = self.root / "pcap" / f"{run_id}.capstone.pcap"
            pcap_meta, base = self._capstone_exact(output=pcap_path, original=original, connect_ts=connects[0].timestamp.timestamp(), close_ts=closes[0].timestamp.timestamp(), sensor_tuples=sensor_tuples, run_id=run_id)
            download_events = [{"eventid": item.get("eventid"), "download_request_sha256": item.get("download_request_sha256")} for item in events_raw if item.get("eventid") == "cowrie.session.file_download"]
            offline = self._offline(connection, pcap_path, backend=base["backend"], sensor_tuples=sensor_tuples, transfer_tuples=transfer_tuples, download_events=download_events, low=capture_low, high=capture_high)
            pcap_evidence, zeek_evidence = dict(offline["pcap"]), dict(offline["zeek"])
            flows = [sanitize_flow(item) for item in offline["flows"]]
            t1046_observation = bound_scan_observation(
                sensor_tuples, flows[1:1 + len(sensor_tuples)],
                session_id=session_id, run_id=run_id,
                measurement_id=measurement_id, episode_id=episode_id,
                unbound_sensor_context=unbound_sensor_context,
            )
            event_epochs = [item.timestamp.timestamp() for item in events]
            flow_starts = [float(item["ts"]) for item in flows]
            flow_ends = [float(item["ts"]) + float(item["duration"]) for item in flows]
            window_start, window_end = min([*event_epochs, *flow_starts]), max([*event_epochs, *flow_ends])
            if window_end <= window_start or window_end - window_start > 60.0:
                raise V7BoundaryError("episode_window_invalid")
            pcap_evidence.update({"source": "capstone_frontend_backend_sensor_plus_pi_transfer_exact_packet_set", "capture_interface": "ens4+ztxoocdlsi+wlan0", "capstone_component_sha256": pcap_meta["sha256"]})
            zeek_evidence.update({"source": "pi_offline_zeek_exact_retained_pcap"})
            cowrie_binding = {
                "session_id": session_id, "original_tuple": original, "frontend_tuple": original,
                "backend_tuple": base["backend"], "proxy_v1_line": base["proxy_v1_line"],
            }
            flow_uids = [item["uid"] for item in flows]
            episode = {
                "model_version": MODEL_VERSION, "measurement_unit": "PRODUCTION_ATTACK_EPISODE",
                "measurement_boundary": "PUBLIC_COWRIE_CAPSTONE_SENSOR_PLUS_BOUND_PI_TRANSFER",
                "episode_id": episode_id, "measurement_id": measurement_id, "run_id": run_id,
                "window_start_utc": utc(window_start), "window_end_utc": utc(window_end),
                "cowrie_observation_complete": True, "cowrie_events": events_raw,
                "cowrie_binding": cowrie_binding, "network_observation_complete": True,
                "source_ip_only_binding": False, "cross_session_contamination": "NO",
                "measurement_evidence": {"pcap": pcap_evidence, "zeek": zeek_evidence},
                "t1046_observation": t1046_observation,
                "network_flows": flows, "network_flow_binding": {"flow_uids": flow_uids},
            }
            row = materialize_episode(episode)
            for key in ("measurement_boundary", "measurement_evidence", "t1046_observation", "cowrie_binding", "network_flows", "network_flow_binding"):
                row[key] = episode[key]
            row["session_id"] = session_id
            if row.get("measurement_validity") != "VALID" or row.get("feature_count") != 32:
                raise V7BoundaryError("feature_materialization_unavailable:" + str(row.get("adapter_invalid_reason") or row.get("evidence", {}).get("invalid_reason")))
            row.update({
                "source_id": run_id,
                "ground_truth_events": events_raw,
                "prediction_invoked": False,
                "model_predictions_invoked": False,
                "collection_only": True,
                "measurement_contract_sha256": BINDING_SHA256,
            })
            if self.collection_enabled:
                self._write_collection_row(run_id, row)
            if self.shadow_enabled:
                if self.model is None:
                    raise V7BoundaryError("shadow_model_not_loaded")
                if self.model_adapter == "v5_unified":
                    result = infer_v5_unified_shadow(row, self.model)
                else:
                    result = infer_shadow(row, self.model)
            elif self.collection_enabled:
                result = {
                    "status": "VALID_COLLECTION_ROW",
                    "availability": "COLLECTION_ONLY",
                    "reason": "prediction_blind_collection_mode",
                    "authority": "NON_AUTHORITATIVE_SHADOW_ONLY",
                }
            else:
                result = {"status": "MODEL2_V7_UNAVAILABLE", "availability": "UNAVAILABLE", "reason": "shadow_gate_disabled", "authority": "NON_AUTHORITATIVE_SHADOW_ONLY"}
            result.update({
                "session_id": session_id, "run_id": run_id, "measurement_id": measurement_id, "episode_id": episode_id,
                "pcap_binding": "PASS", "zeek_binding": "PASS", "feature_materialization": "PASS",
                "source_binding": "PASS", "session_binding": "PASS", "run_id_binding": "PASS",
                "feature_count": 32 if self.collection_enabled or self.model_adapter == "v5_unified" else 27,
                "source_feature_count": 32, "zero_fill": False,
                "source_ip_only_binding": False, "cross_session_contamination": "NO",
                "proxy_v1_delivery": "PASS", "capture_sha256": pcap_evidence["sha256"],
                "selected_flow_uids": flow_uids, "sensor_flow_count": len(sensor_tuples),
                "t1046_observation": t1046_observation,
                "transfer_flow_count": len(transfer_tuples), "binding_contract_sha256": BINDING_SHA256,
                "canonical_write_authority": False,
            })
            if self.shadow_enabled and result.get("status") != "VALID_SHADOW":
                raise V7BoundaryError("shadow_inference_unavailable:" + str(result.get("reason")))
            self._write_result(run_id, result)
            self._record(result)
            return result
        except Exception as exc:
            return self.unavailable(message_id=message_id, reason=str(exc), session_id=session_id, run_id=run_id)
        finally:
            if pcap_path is not None:
                pcap_path.unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=pathlib.Path, required=True)
    args = parser.parse_args()
    config = json.loads(args.config.read_text(encoding="utf-8"))
    Coordinator(config).serve()


if __name__ == "__main__":
    main()
