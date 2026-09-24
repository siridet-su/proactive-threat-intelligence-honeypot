"""Fail-closed HTTP request binding for Cowrie file_download packet evidence.

The URL in a Cowrie event identifies the requested resource, not a TCP flow.
Only a unique, observed HTTP request for that resource may supply a flow tuple.
"""

from __future__ import annotations

import ipaddress
import hashlib
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit


TRANSFER_SOURCE = "192.168.89.112"
MAX_HTTP_HEADER = 8192


def transfer_tuple_allowed(value: Mapping[str, Any]) -> bool:
    try:
        source = ipaddress.ip_address(str(value["src_ip"]))
        destination = ipaddress.ip_address(str(value["dst_ip"]))
        source_port = int(value["src_port"])
        destination_port = int(value["dst_port"])
    except (KeyError, TypeError, ValueError):
        return False
    return (
        source.version == destination.version == 4
        and str(source) == TRANSFER_SOURCE
        and destination.is_global
        and 1 <= source_port <= 65535
        and destination_port == 80
    )


def request_identity(event: Mapping[str, Any]) -> tuple[str, str] | None:
    if event.get("eventid") != "cowrie.session.file_download":
        return None
    url = event.get("url")
    if not isinstance(url, str) or len(url) > 4096:
        return None
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError:
        return None
    if (
        parsed.scheme.lower() != "http"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or port not in (None, 80)
    ):
        return None
    host = parsed.hostname.lower().rstrip(".")
    if not host or any(ord(character) > 127 for character in host):
        return None
    return host, (parsed.path or "/") + ("?" + parsed.query if parsed.query else "")


def packet_request_identity(packet: Any) -> tuple[str, str] | None:
    payload = packet.payload
    if not isinstance(payload, bytes) or not 1 <= len(payload) <= MAX_HTTP_HEADER:
        return None
    header, separator, _ = payload.partition(b"\r\n\r\n")
    if not separator:
        return None
    lines = header.split(b"\r\n")
    if not lines or not lines[0].startswith(b"GET "):
        return None
    parts = lines[0].split(b" ")
    if len(parts) != 3 or parts[2] not in (b"HTTP/1.0", b"HTTP/1.1"):
        return None
    try:
        path = parts[1].decode("ascii")
        hosts = [line[5:].strip().decode("ascii").lower() for line in lines[1:] if line.lower().startswith(b"host:")]
    except UnicodeDecodeError:
        return None
    if not path.startswith("/") or len(hosts) != 1:
        return None
    host = hosts[0].removesuffix(":80").rstrip(".")
    return host, path


def request_digest(event: Mapping[str, Any]) -> str | None:
    if event.get("eventid") != "cowrie.session.file_download":
        return None
    existing = event.get("download_request_sha256")
    if isinstance(existing, str) and len(existing) == 64 and all(c in "0123456789abcdef" for c in existing):
        return existing
    identity = request_identity(event)
    if identity is None:
        return None
    return hashlib.sha256((identity[0] + "\n" + identity[1]).encode("utf-8")).hexdigest()


def packet_request_digest(packet: Any) -> str | None:
    identity = packet_request_identity(packet)
    if identity is None:
        return None
    return hashlib.sha256((identity[0] + "\n" + identity[1]).encode("utf-8")).hexdigest()


def select_transfer_tuples(events: Iterable[Mapping[str, Any]], packets: Iterable[Any], parse_timestamp: Any) -> list[dict[str, Any]]:
    downloads = [event for event in events if event.get("eventid") == "cowrie.session.file_download"]
    packet_list = list(packets)
    selected: list[dict[str, Any]] = []
    used: set[tuple[str, int, str, int]] = set()
    for event in downloads:
        expected = request_digest(event)
        if expected is None:
            return []
        event_epoch = parse_timestamp(event["timestamp"]).timestamp()
        matches: dict[tuple[str, int, str, int], float] = {}
        for packet in packet_list:
            candidate = packet.tuple
            if not transfer_tuple_allowed(candidate):
                continue
            if not event_epoch - 60.0 <= packet.timestamp <= event_epoch:
                continue
            if packet_request_digest(packet) != expected:
                continue
            key = (candidate["src_ip"], candidate["src_port"], candidate["dst_ip"], candidate["dst_port"])
            matches[key] = packet.timestamp
        # Two eligible HTTP requests for one event cannot be bound reliably.
        if len(matches) != 1:
            return []
        key = next(iter(matches))
        if key in used:
            return []
        used.add(key)
        selected.append({"src_ip": key[0], "src_port": key[1], "dst_ip": key[2], "dst_port": key[3]})
    return selected


def packet_set_matches_events(events: Iterable[Mapping[str, Any]], packets: Iterable[Any], tuples: Iterable[Mapping[str, Any]]) -> bool:
    downloads = [event for event in events if event.get("eventid") == "cowrie.session.file_download"]
    bound = list(tuples)
    packet_list = list(packets)
    if len(downloads) != len(bound):
        return False
    for event, expected_tuple in zip(downloads, bound):
        expected_request = request_digest(event)
        if expected_request is None or not transfer_tuple_allowed(expected_tuple):
            return False
        matches = [packet for packet in packet_list if packet.tuple == expected_tuple and packet_request_digest(packet) == expected_request]
        if len(matches) != 1:
            return False
    return True
