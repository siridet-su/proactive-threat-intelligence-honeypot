"""The Model2 transfer flow must be bound to a real Cowrie HTTP download."""

from __future__ import annotations

import datetime as dt
import importlib.util
from pathlib import Path
from types import SimpleNamespace


SOURCE = Path(__file__).resolve().parents[1] / "production" / "model2_v7_transfer_runtime" / "v7_transfer_binding.py"
SPEC = importlib.util.spec_from_file_location("v7_transfer_binding", SOURCE)
assert SPEC and SPEC.loader
binding = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(binding)


def timestamp(value: str) -> dt.datetime:
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


def download(url: str = "http://example.com/a?x=1") -> dict[str, str]:
    return {"eventid": "cowrie.session.file_download", "url": url, "timestamp": "2026-09-24T00:00:10Z"}


def packet(*, host: str = "example.com", path: str = "/a?x=1", destination: str = "93.184.215.14", port: int = 49152, when: float | None = None) -> SimpleNamespace:
    return SimpleNamespace(
        timestamp=when if when is not None else timestamp("2026-09-24T00:00:09Z").timestamp(),
        tuple={"src_ip": "192.168.89.112", "src_port": port, "dst_ip": destination, "dst_port": 80},
        payload=f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode(),
    )


def test_unique_http_request_matches_download_and_offline_verification() -> None:
    event = download()
    fingerprinted = {"eventid": event["eventid"], "timestamp": event["timestamp"], "download_request_sha256": binding.request_digest(event)}
    observed = packet()
    tuples = binding.select_transfer_tuples([fingerprinted], [observed], timestamp)
    assert tuples == [observed.tuple]
    assert binding.packet_set_matches_events([fingerprinted], [observed], tuples)
    assert "url" not in fingerprinted


def test_wrong_host_path_private_destination_and_late_request_fail_closed() -> None:
    event = download()
    for observed in (
        packet(host="other.example"),
        packet(path="/other"),
        packet(destination="10.0.0.1"),
        packet(when=timestamp("2026-09-24T00:00:11Z").timestamp()),
    ):
        assert binding.select_transfer_tuples([event], [observed], timestamp) == []


def test_ambiguous_requests_and_reused_tuple_fail_closed() -> None:
    event = download()
    assert binding.select_transfer_tuples([event], [packet(), packet(port=49153)], timestamp) == []
    assert binding.select_transfer_tuples([event, event], [packet()], timestamp) == []


def test_https_and_invalid_event_url_are_not_claimed() -> None:
    for url in ("https://example.com/a?x=1", "http://user@example.com/a?x=1", "http://example.com:8080/a?x=1"):
        assert binding.select_transfer_tuples([download(url)], [packet()], timestamp) == []


def test_offline_verification_rejects_swapped_packet_or_event() -> None:
    observed = packet()
    assert not binding.packet_set_matches_events([download("http://example.com/other")], [observed], [observed.tuple])
    assert not binding.packet_set_matches_events([download()], [packet(port=49153)], [observed.tuple])
