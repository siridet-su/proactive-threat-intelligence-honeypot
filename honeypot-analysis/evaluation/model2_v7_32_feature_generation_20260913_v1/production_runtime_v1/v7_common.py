#!/usr/bin/env python3
"""Shared bounded PCAP and evidence helpers for the Model2 V7 runtime."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import math
import os
import pathlib
import struct
from dataclasses import dataclass
from typing import Any, Iterable, Mapping


MAX_PCAP_BYTES = 96 * 1024 * 1024
MAX_FLOW_ROWS = 64
TERMINAL_STATES = frozenset({"SF", "SH", "S1", "S2", "S3", "SHR", "S0", "REJ", "RSTO", "RSTR", "OTH", "ERR"})


class V7BoundaryError(RuntimeError):
    pass


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def iso(value: Any) -> dt.datetime:
    if not isinstance(value, str):
        raise V7BoundaryError("timestamp_missing")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise V7BoundaryError("timestamp_invalid") from exc
    return parsed.astimezone(dt.timezone.utc) if parsed.tzinfo else parsed.replace(tzinfo=dt.timezone.utc)


def utc(epoch: float) -> str:
    return dt.datetime.fromtimestamp(epoch, dt.timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def exact_tuple(value: Any, name: str = "tuple") -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise V7BoundaryError(f"{name}_missing")
    try:
        result = {"src_ip": str(value["src_ip"]), "src_port": int(value["src_port"]), "dst_ip": str(value["dst_ip"]), "dst_port": int(value["dst_port"])}
    except (KeyError, TypeError, ValueError) as exc:
        raise V7BoundaryError(f"{name}_invalid") from exc
    if not result["src_ip"] or not result["dst_ip"] or not 1 <= result["src_port"] <= 65535 or not 1 <= result["dst_port"] <= 65535:
        raise V7BoundaryError(f"{name}_invalid")
    return result


def tuple_equal(left: Mapping[str, Any], right: Mapping[str, Any], *, bidirectional: bool = False) -> bool:
    forward = all((str(left[k]) == str(right[k]) if k.endswith("_ip") else int(left[k]) == int(right[k])) for k in ("src_ip", "src_port", "dst_ip", "dst_port"))
    if forward or not bidirectional:
        return forward
    return str(left["src_ip"]) == str(right["dst_ip"]) and int(left["src_port"]) == int(right["dst_port"]) and str(left["dst_ip"]) == str(right["src_ip"]) and int(left["dst_port"]) == int(right["src_port"])


@dataclass(frozen=True)
class Packet:
    timestamp: float
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    flags: int
    sequence: int
    payload: bytes
    ip_payload: bytes

    @property
    def tuple(self) -> dict[str, Any]:
        return {"src_ip": self.src_ip, "src_port": self.src_port, "dst_ip": self.dst_ip, "dst_port": self.dst_port}


def _ipv4(frame: bytes, linktype: int) -> bytes | None:
    if linktype == 1:
        if len(frame) < 14:
            return None
        offset, protocol = 14, int.from_bytes(frame[12:14], "big")
        if protocol in {0x8100, 0x88A8}:
            if len(frame) < 18:
                return None
            offset, protocol = 18, int.from_bytes(frame[16:18], "big")
        return frame[offset:] if protocol == 0x0800 else None
    if linktype == 113:
        return frame[16:] if len(frame) >= 16 and int.from_bytes(frame[14:16], "big") == 0x0800 else None
    if linktype == 276:
        return frame[20:] if len(frame) >= 20 and int.from_bytes(frame[0:2], "big") == 0x0800 else None
    if linktype == 101:
        return frame
    return None


def _packet(frame: bytes, timestamp: float, linktype: int) -> Packet | None:
    ip = _ipv4(frame, linktype)
    if ip is None or len(ip) < 40 or ip[0] >> 4 != 4:
        return None
    ihl = (ip[0] & 0x0F) * 4
    total = int.from_bytes(ip[2:4], "big")
    if ihl < 20 or total < ihl + 20 or len(ip) < total or ip[9] != 6:
        return None
    tcp = ip[ihl:total]
    data_offset = ((tcp[12] >> 4) & 0x0F) * 4
    if data_offset < 20 or len(tcp) < data_offset:
        return None
    return Packet(
        timestamp=timestamp,
        src_ip=".".join(str(value) for value in ip[12:16]),
        src_port=int.from_bytes(tcp[0:2], "big"),
        dst_ip=".".join(str(value) for value in ip[16:20]),
        dst_port=int.from_bytes(tcp[2:4], "big"),
        flags=tcp[13],
        sequence=int.from_bytes(tcp[4:8], "big"),
        payload=tcp[data_offset:],
        ip_payload=ip[:total],
    )


def read_pcap(path: pathlib.Path) -> list[Packet]:
    packets: list[Packet] = []
    with path.open("rb") as handle:
        header = handle.read(24)
        if len(header) != 24:
            raise V7BoundaryError("pcap_header_missing")
        magic = header[:4]
        if magic in {b"\xd4\xc3\xb2\xa1", b"M<\xb2\xa1"}:
            endian = "<"
        elif magic in {b"\xa1\xb2\xc3\xd4", b"\xa1\xb2<M"}:
            endian = ">"
        else:
            raise V7BoundaryError("pcap_format_not_classic")
        linktype = struct.unpack(endian + "I", header[20:24])[0]
        nanos = magic in {b"M<\xb2\xa1", b"\xa1\xb2<M"}
        while True:
            record = handle.read(16)
            if not record:
                break
            if len(record) != 16:
                raise V7BoundaryError("pcap_record_incomplete")
            sec, fraction, included, original = struct.unpack(endian + "IIII", record)
            if included > MAX_PCAP_BYTES or original < included:
                raise V7BoundaryError("pcap_record_bound_invalid")
            frame = handle.read(included)
            if len(frame) != included:
                raise V7BoundaryError("pcap_frame_incomplete")
            parsed = _packet(frame, sec + fraction / (1_000_000_000.0 if nanos else 1_000_000.0), linktype)
            if parsed is not None:
                packets.append(parsed)
    return packets


def ring_paths(base: pathlib.Path) -> list[pathlib.Path]:
    return sorted({path for path in (base, *base.parent.glob(base.name + "[0-9]*")) if path.is_file()})


def read_rings(bases: Iterable[pathlib.Path], low: float, high: float) -> list[Packet]:
    packets: list[Packet] = []
    for base in bases:
        for path in ring_paths(base):
            packets.extend(packet for packet in read_pcap(path) if low <= packet.timestamp <= high)
    return packets


def packets_for_tuples(packets: Iterable[Packet], tuples: Iterable[Mapping[str, Any]]) -> list[Packet]:
    expected = [exact_tuple(value) for value in tuples]
    selected = [packet for packet in packets if any(tuple_equal(packet.tuple, value, bidirectional=True) for value in expected)]
    selected.sort(key=lambda item: item.timestamp)
    return selected


def write_raw_pcap(path: pathlib.Path, packets: Iterable[Packet]) -> dict[str, Any]:
    selected = sorted(packets, key=lambda item: item.timestamp)
    if not selected:
        raise V7BoundaryError("exact_packet_set_empty")
    path.parent.mkdir(parents=True, exist_ok=True)
    total = 24
    with path.open("wb") as handle:
        handle.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 101))
        for packet in selected:
            seconds = int(packet.timestamp)
            micros = int(round((packet.timestamp - seconds) * 1_000_000))
            payload = packet.ip_payload
            handle.write(struct.pack("<IIII", seconds, micros, len(payload), len(payload)))
            handle.write(payload)
            total += 16 + len(payload)
            if total > MAX_PCAP_BYTES:
                raise V7BoundaryError("exact_pcap_bound_exceeded")
        handle.flush()
        os.fsync(handle.fileno())
    return {"path": str(path), "sha256": sha256_file(path), "bytes": total, "packet_count": len(selected)}


def sanitize_flow(raw: Mapping[str, Any]) -> dict[str, Any]:
    required = ("ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts")
    if any(key not in raw for key in required):
        raise V7BoundaryError("zeek_required_field_missing")
    row: dict[str, Any] = {
        "ts": float(raw["ts"]), "uid": str(raw["uid"]),
        "id.orig_h": str(raw["id.orig_h"]), "id.orig_p": int(raw["id.orig_p"]),
        "id.resp_h": str(raw["id.resp_h"]), "id.resp_p": int(raw["id.resp_p"]),
        "proto": str(raw["proto"]), "duration": float(raw["duration"]),
        "orig_bytes": float(raw["orig_bytes"]), "resp_bytes": float(raw["resp_bytes"]),
        "orig_pkts": float(raw["orig_pkts"]), "resp_pkts": float(raw["resp_pkts"]),
        "conn_state": str(raw.get("conn_state") or ""),
    }
    numerics = (row["ts"], row["duration"], row["orig_bytes"], row["resp_bytes"], row["orig_pkts"], row["resp_pkts"])
    if not row["uid"] or row["proto"] != "tcp" or row["conn_state"] not in TERMINAL_STATES or any(not math.isfinite(v) or v < 0 for v in numerics[1:]):
        raise V7BoundaryError("zeek_flow_semantics_invalid")
    row["ts_utc"] = utc(row["ts"])
    return row
