from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest


RUNTIME = (
    Path(__file__).resolve().parents[1]
    / "evaluation"
    / "model2_v7_32_feature_generation_20260913_v1"
    / "production_runtime_v1"
)
sys.path.insert(0, str(RUNTIME))

common = importlib.import_module("v7_common")
direct = importlib.import_module("v7_direct_ingress")


def packet(
    *, timestamp: float = 100.0, src_ip: str = "203.0.113.7",
    src_port: int = 41000, dst_ip: str = "10.58.33.42",
    dst_port: int = 22, flags: int = 0x02,
) -> object:
    return common.Packet(
        timestamp=timestamp,
        src_ip=src_ip,
        src_port=src_port,
        dst_ip=dst_ip,
        dst_port=dst_port,
        flags=flags,
        sequence=1,
        payload=b"",
        ip_payload=b"x" * 40,
    )


def original() -> dict[str, object]:
    return {
        "src_ip": "203.0.113.7",
        "src_port": 41000,
        "dst_ip": "10.58.33.42",
        "dst_port": 22,
    }


def test_ingress_profiles_preserve_proxy_and_add_only_exact_direct_endpoint() -> None:
    assert direct.ingress_profile(original()) == direct.DIRECT_PI_INGRESS
    assert direct.ingress_profile({**original(), "dst_ip": "10.148.0.2", "dst_port": 2222}) == direct.PROXY_INGRESS
    with pytest.raises(common.V7BoundaryError, match="session_destination_not_supported_ingress"):
        direct.ingress_profile({**original(), "dst_port": 23})


def test_direct_packet_selection_requires_one_exact_client_syn() -> None:
    values = [
        packet(),
        packet(timestamp=100.1, src_ip="10.58.33.42", src_port=22, dst_ip="203.0.113.7", dst_port=41000, flags=0x12),
        packet(timestamp=100.2, flags=0x10),
        packet(timestamp=100.3, src_ip="198.51.100.8", src_port=42000),
    ]
    selected = direct.select_direct_packets(values, original(), 95.0, 105.0)
    assert len(selected) == 3
    assert all(
        common.tuple_equal(value.tuple, original(), bidirectional=True)
        for value in selected
    )


def test_direct_packet_selection_fails_closed_on_missing_or_duplicate_syn() -> None:
    with pytest.raises(common.V7BoundaryError, match="direct_ingress_syn_count:0"):
        direct.select_direct_packets([packet(flags=0x10)], original(), 95.0, 105.0)
    with pytest.raises(common.V7BoundaryError, match="direct_ingress_syn_count:2"):
        direct.select_direct_packets([packet(), packet(timestamp=100.1)], original(), 95.0, 105.0)


def test_direct_packet_selection_rejects_unbounded_window() -> None:
    with pytest.raises(common.V7BoundaryError, match="direct_ingress_window_invalid"):
        direct.select_direct_packets([packet()], original(), 100.0, 100.0)


def test_direct_metadata_is_bounded_and_exact() -> None:
    value = {"id": "a" * 64, "sha256": "b" * 64, "bytes": 4096}
    assert direct.validate_direct_metadata(value) == value
    with pytest.raises(common.V7BoundaryError, match="direct_ingress_pcap_metadata_invalid"):
        direct.validate_direct_metadata({**value, "bytes": direct.MAX_DIRECT_PCAP_BYTES + 1})


def test_direct_pcap_identifier_is_deterministic_and_event_bound() -> None:
    first = direct.direct_pcap_id("session-a", original(), ["a" * 64, "b" * 64])
    assert first == direct.direct_pcap_id("session-a", original(), ["a" * 64, "b" * 64])
    assert first != direct.direct_pcap_id("session-a", original(), ["b" * 64, "a" * 64])
