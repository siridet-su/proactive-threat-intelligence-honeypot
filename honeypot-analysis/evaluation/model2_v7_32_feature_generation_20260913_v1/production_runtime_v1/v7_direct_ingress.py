"""Fail-closed helpers for the direct Raspberry Pi SSH ingress profile."""

from __future__ import annotations

import hashlib
from typing import Any, Iterable, Mapping

from v7_common import Packet, V7BoundaryError, exact_tuple, tuple_equal


PROXY_INGRESS = "CAPSTONE_PROXY_V1"
DIRECT_PI_INGRESS = "DIRECT_PI_22_POC_V1"
DIRECT_PI_HOST = "10.58.33.42"
DIRECT_PI_PORT = 22
MAX_DIRECT_PCAP_BYTES = 8 * 1024 * 1024


def ingress_profile(value: Mapping[str, Any]) -> str:
    """Classify only the two explicitly supported ingress endpoints."""
    original = exact_tuple(value, "original_tuple")
    if original["dst_ip"] == "10.148.0.2" and original["dst_port"] == 2222:
        return PROXY_INGRESS
    if original["dst_ip"] == DIRECT_PI_HOST and original["dst_port"] == DIRECT_PI_PORT:
        return DIRECT_PI_INGRESS
    raise V7BoundaryError("session_destination_not_supported_ingress")


def select_direct_packets(
    packets: Iterable[Packet], original: Mapping[str, Any], low: float, high: float,
) -> list[Packet]:
    """Select one exact direct-SSH flow and reject ambiguous/missing SYNs."""
    expected = exact_tuple(original, "original_tuple")
    if ingress_profile(expected) != DIRECT_PI_INGRESS:
        raise V7BoundaryError("direct_ingress_profile_required")
    if high <= low or high - low > 3600:
        raise V7BoundaryError("direct_ingress_window_invalid")
    selected = sorted(
        (
            packet for packet in packets
            if low <= packet.timestamp <= high
            and tuple_equal(packet.tuple, expected, bidirectional=True)
        ),
        key=lambda packet: packet.timestamp,
    )
    syns = [
        packet for packet in selected
        if tuple_equal(packet.tuple, expected)
        and packet.flags & 0x02 and not packet.flags & 0x10
    ]
    if len(syns) != 1:
        raise V7BoundaryError(f"direct_ingress_syn_count:{len(syns)}")
    return selected


def validate_direct_metadata(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise V7BoundaryError("direct_ingress_pcap_metadata_missing")
    identifier = str(value.get("id") or "")
    digest = str(value.get("sha256") or "")
    try:
        size = int(value.get("bytes"))
    except (TypeError, ValueError) as exc:
        raise V7BoundaryError("direct_ingress_pcap_size_invalid") from exc
    if (
        len(identifier) != 64
        or any(character not in "0123456789abcdef" for character in identifier)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
        or not 1 <= size <= MAX_DIRECT_PCAP_BYTES
    ):
        raise V7BoundaryError("direct_ingress_pcap_metadata_invalid")
    return {"id": identifier, "sha256": digest, "bytes": size}


def direct_pcap_id(session_id: str, original: Mapping[str, Any], event_hashes: Iterable[str]) -> str:
    material = "\n".join(
        [session_id, repr(exact_tuple(original, "original_tuple")), *[str(value) for value in event_hashes]]
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()
