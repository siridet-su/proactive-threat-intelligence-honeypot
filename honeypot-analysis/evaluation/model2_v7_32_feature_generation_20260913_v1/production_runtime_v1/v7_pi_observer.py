#!/usr/bin/env python3
"""V7 extension of the proven privacy-preserving V6 Cowrie observer."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import shlex
import socket
import sys
import threading
import time
from typing import Any, Mapping
from urllib.parse import urlsplit

HERE = pathlib.Path(__file__).resolve().parent
for candidate in (
    HERE,
    HERE.parents[1] / "model2_v6_production_native_20260911_v1",
    pathlib.Path("/opt/model2-v6"),
):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

import v6_pi_observer as v6  # noqa: E402
from v7_common import (  # noqa: E402
    V7BoundaryError, canonical, exact_tuple, read_rings, sanitize_flow, write_raw_pcap,
)
from v7_direct_ingress import (  # noqa: E402
    DIRECT_PI_INGRESS, PROXY_INGRESS, direct_pcap_id, ingress_profile,
    select_direct_packets, validate_direct_metadata,
)
from v7_offline_zeek import SCHEMA as OFFLINE_SCHEMA, run as run_offline  # noqa: E402
from v7_transfer_binding import (  # noqa: E402
    request_digest,
    select_session_bound_tuples,
    select_transfer_tuples,
    transfer_tuple_allowed,
)


TRANSFER_SOURCE = "192.168.89.112"
BACKEND_SOURCE = "10.58.33.6"
BACKEND_HOST = "10.58.33.42"
BACKEND_PORT = 2298
MAX_RESPONSE = 256 * 1024
SESSION_SOCKET_CAPTURE_CONTRACT = "OUTCOME_INDEPENDENT_SESSION_SOCKET_V2"


_v6_sanitize_event = v6.sanitize_event

COMMAND_INPUT = "cowrie.command.input"
AUTH_EVENTS = {"cowrie.login.failed", "cowrie.login.success"}
TRANSFER_TOOLS = {"wget": "wget", "curl": "curl", "fetch": "other", "ftp": "other", "tftp": "other"}
WRAPPERS = {"sudo", "doas", "command", "env"}
SHELL_NAMES = {"sh", "bash", "dash", "zsh"}
BEHAVIOR_FAMILIES = {
    "wget": "transfer", "curl": "transfer", "fetch": "transfer", "ftp": "transfer", "tftp": "transfer",
    "nmap": "discovery", "nc": "discovery", "netcat": "discovery", "telnet": "discovery",
    "ss": "discovery", "netstat": "discovery", "ping": "discovery", "traceroute": "discovery",
    "whoami": "identity", "id": "identity", "uname": "identity", "hostname": "identity", "groups": "identity",
    "ls": "filesystem", "find": "filesystem", "pwd": "filesystem", "cat": "filesystem", "head": "filesystem", "tail": "filesystem", "stat": "filesystem",
    "sh": "execution", "bash": "execution", "dash": "execution", "zsh": "execution", "python": "execution", "python3": "execution", "perl": "execution", "php": "execution",
    "chmod": "permission", "chown": "permission", "tar": "archive", "gzip": "archive", "bzip2": "archive", "xz": "archive", "unzip": "archive", "zip": "archive",
    "rm": "cleanup", "shred": "cleanup", "unlink": "cleanup",
}


def _tokens(raw: Any) -> list[str]:
    try:
        return shlex.split(raw, posix=True) if isinstance(raw, str) and raw.strip() else []
    except ValueError:
        return []


def _executable(tokens: list[str]) -> tuple[str, int]:
    index = 0
    while index < len(tokens):
        name = tokens[index].rsplit("/", 1)[-1].lower()
        if name in WRAPPERS:
            index += 1
            if name == "env":
                while index < len(tokens) and "=" in tokens[index] and not tokens[index].startswith("-"):
                    index += 1
            continue
        if name == "busybox" and index + 1 < len(tokens):
            return tokens[index + 1].rsplit("/", 1)[-1].lower(), index + 1
        return name, index
    return "", 0


def _port_class(port: int | None, scheme: str) -> str:
    selected = port if port is not None else {"http": 80, "https": 443}.get(scheme)
    if selected is None:
        return "unknown"
    if selected in {80, 443}:
        return "default_web"
    if 0 < selected < 1024:
        return "other_well_known"
    return "nonstandard" if selected <= 65535 else "unknown"


def _pipe_to_shell(raw: Any) -> bool:
    if not isinstance(raw, str):
        return False
    try:
        lexer = shlex.shlex(raw, posix=True, punctuation_chars="|")
        lexer.whitespace_split = True
        lexer.commenters = ""
        values = list(lexer)
    except ValueError:
        return False
    return any(value == "|" and values[index + 1].rsplit("/", 1)[-1].lower() in SHELL_NAMES for index, value in enumerate(values[:-1]))


def _command_projection(raw: Any) -> dict[str, Any]:
    tokens = _tokens(raw)
    executable, executable_index = _executable(tokens)
    projection: dict[str, Any] = {"family": BEHAVIOR_FAMILIES.get(executable, "other")}
    tool = TRANSFER_TOOLS.get(executable)
    if tool is None:
        return projection
    args = tokens[executable_index + 1:]
    if any(token in {"--help", "-h", "--version", "-V"} for token in args):
        return projection
    urls = []
    for token in args:
        candidate = token[6:] if token.startswith("--url=") else token
        if not candidate.startswith("-") and "://" in candidate:
            urls.append(candidate.strip("\"'"))
    if tool in {"wget", "curl"} and not urls:
        return projection
    schemes: list[str] = []
    ports: list[str] = []
    destinations: set[str] = set()
    for url in urls:
        try:
            parsed = urlsplit(url)
            scheme = parsed.scheme.lower()
            host = (parsed.hostname or "").lower().rstrip(".")
            port = parsed.port
        except ValueError:
            scheme, host, port = "", "", None
        schemes.append(scheme if scheme in {"http", "https"} else (scheme or "unknown"))
        ports.append(_port_class(port, scheme))
        if host:
            destinations.add(hashlib.sha256(host.encode()).hexdigest())
    if not urls:
        schemes, ports = ["unknown"], ["unknown"]
    if executable == "wget":
        output = any(token == "-O" or token == "--output-document" or token.startswith("--output-document=") for token in args)
        redirect = bool(urls) and "--max-redirect=0" not in args
    elif executable == "curl":
        output = any(token in {"-o", "-O", "--output", "--remote-name"} or token.startswith("--output=") for token in args)
        redirect = bool(urls) and any(token in {"-L", "--location", "--location-trusted"} for token in args)
    else:
        output, redirect = False, False
    projection["transfer"] = {
        "tool": tool, "schemes": schemes, "ports": ports,
        "output": output, "redirect": redirect, "pipe_shell": _pipe_to_shell(raw),
        "destination_digests": sorted(destinations),
    }
    return projection


def sanitize_v7_event(raw: Mapping[str, Any]) -> dict[str, Any]:
    """Preserve only an opaque HTTP request fingerprint, never the raw URL."""
    event = _v6_sanitize_event(raw)
    if event["eventid"] == "cowrie.session.file_download":
        digest = request_digest(raw)
        if digest is not None:
            event["download_request_sha256"] = digest
    elif event["eventid"] == "cowrie.session.outbound_connection":
        candidate = exact_tuple({
            "src_ip": raw.get("outbound_src_ip"),
            "src_port": raw.get("outbound_src_port"),
            "dst_ip": raw.get("outbound_dst_ip"),
            "dst_port": raw.get("outbound_dst_port"),
        }, "outbound_socket")
        if transfer_tuple_allowed(candidate):
            event.update({
                "outbound_src_ip": candidate["src_ip"],
                "outbound_src_port": candidate["src_port"],
                "outbound_dst_ip": candidate["dst_ip"],
                "outbound_dst_port": candidate["dst_port"],
            })
    elif event["eventid"] == COMMAND_INPUT:
        event["command_projection"] = _command_projection(raw.get("input"))
    elif event["eventid"] in AUTH_EVENTS:
        username = raw.get("username")
        if isinstance(username, str) and username:
            event["username_sha256"] = hashlib.sha256(username.casefold().encode()).hexdigest()
    return event


v6.sanitize_event = sanitize_v7_event


def read_candidates(path: pathlib.Path, low: float, high: float) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        size = path.stat().st_size
        with path.open("rb") as handle:
            handle.seek(max(0, size - v6.ZEEK_TAIL_BYTES))
            data = handle.read(v6.ZEEK_TAIL_BYTES)
    except OSError:
        return []
    if size > v6.ZEEK_TAIL_BYTES:
        _, _, data = data.partition(b"\n")
    for line in data.splitlines():
        if len(line) > v6.MAX_LINE_BYTES or not line.startswith(b"{"):
            continue
        try:
            raw = json.loads(line)
            row = sanitize_flow(raw)
        except (json.JSONDecodeError, TypeError, ValueError, V7BoundaryError):
            continue
        is_backend = row["id.orig_h"] == BACKEND_SOURCE and row["id.resp_h"] == BACKEND_HOST and row["id.resp_p"] == BACKEND_PORT
        if is_backend and low <= float(row["ts"]) <= high:
            rows.append(row)
    return rows[:v6.MAX_FLOW_ROWS]


class Observer(v6.Observer):
    def __init__(self, config: Mapping[str, Any]) -> None:
        super().__init__(config)
        self.transfer_rings = [pathlib.Path(str(value)) for value in config.get("transfer_ring_bases", [])]
        self.retain_dir = pathlib.Path(str(config.get("exact_evidence_dir", self.state_dir / "exact")))
        self.work_dir = self.state_dir / "offline"
        self.zeek_bin = str(config.get("zeek_bin", "/usr/local/bin/zeek"))

    def _ingest_line(self, line: bytes) -> None:
        """Undo the base observer's in-memory append if durable enqueue fails."""
        try:
            super()._ingest_line(line)
        except (v6.ObserverError, OSError) as exc:
            if isinstance(exc, OSError) or str(exc) == "observer_queue_pressure":
                try:
                    event = v6.sanitize_event(json.loads(line))
                    entries = self.state["sessions"][event["session"]]["events"]
                    if entries and entries[-1].get("event_key") == v6.digest(event):
                        entries.pop()
                except (KeyError, TypeError, ValueError, json.JSONDecodeError, v6.ObserverError):
                    pass
            raise

    def _tail_once(self, handle):
        """Keep the log cursor on an event until it is durably queued."""
        if handle is None or handle.closed:
            handle = self._open_current_log()
        descriptor_stat = os.fstat(handle.fileno())
        descriptor_inode = int(descriptor_stat.st_ino)
        offset = int(self.state.get("offset", 0))
        if int(self.state.get("inode", 0)) != descriptor_inode or offset > descriptor_stat.st_size:
            offset = 0
            with self.lock:
                self.state["offset"] = 0
                self.state["inode"] = descriptor_inode
                self._persist_state()
        handle.seek(offset)
        progressed = False
        while True:
            line_start = handle.tell()
            line = handle.readline(v6.MAX_LINE_BYTES + 2)
            if not line:
                break
            if not line.endswith(b"\n"):
                handle.seek(line_start)
                break
            with self.lock:
                try:
                    self._ingest_line(line)
                except v6.ObserverError as exc:
                    if str(exc) == "observer_queue_pressure":
                        self.state["offset"] = line_start
                        handle.seek(line_start)
                        self._persist_state()
                        return handle
                    # Invalid complete records cannot be used as evidence.
                except OSError:
                    self.state["offset"] = line_start
                    handle.seek(line_start)
                    self._persist_state()
                    return handle
                self.state["offset"] = handle.tell()
                progressed = True
                if int(self.state["sequence"]) % v6.EVENT_PERSIST_INTERVAL == 0:
                    self._persist_state()
        if progressed:
            with self.lock:
                self._persist_state()
        # Do not switch to a rotated pathname while the old descriptor has
        # an unqueued event. That case returns above with its cursor intact.
        path_stat = self.log_path.stat()
        if int(path_stat.st_ino) != descriptor_inode:
            handle.close()
            handle = self.log_path.open("rb")
            new_stat = os.fstat(handle.fileno())
            with self.lock:
                self.state["inode"] = int(new_stat.st_ino)
                self.state["offset"] = 0
                self._persist_state()
        return handle

    def _enqueue_completion(self, body: Mapping[str, Any]) -> bool:
        """Wait for queue capacity, retaining the closed session on shutdown."""
        while not self.stop.is_set():
            try:
                self._enqueue("session_complete", body)
                return True
            except v6.ObserverError as exc:
                if str(exc) != "observer_queue_pressure":
                    raise
                self.stop.wait(1.0)
        return False

    def run(self) -> None:
        # Rehydrate closed sessions after a restart during queue pressure.
        with self.lock:
            pending = [
                (session_id, [item["event"] for item in value.get("events", [])])
                for session_id, value in self.state["sessions"].items()
                if isinstance(value, dict) and value.get("closed")
            ]
        for session_id, events in pending:
            threading.Thread(
                target=self._complete_session, args=(session_id, events), daemon=True
            ).start()
        super().run()

    def _flow_candidates(self, connect: Mapping[str, Any], close: Mapping[str, Any]) -> list[dict[str, Any]]:
        low = v6.parse_timestamp(connect["timestamp"]).timestamp() - 5.0
        high = v6.parse_timestamp(close["timestamp"]).timestamp() + 12.0
        deadline = time.monotonic() + v6.FLOW_WAIT_SECONDS
        earliest = time.monotonic() + v6.FLOW_MIN_FINALIZATION_WAIT_SECONDS
        while True:
            rows = read_candidates(self.zeek_path, low, high)
            now = time.monotonic()
            if (rows and now >= earliest) or now >= deadline:
                return rows
            time.sleep(0.25)

    def _transfer_packet_tuples(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        downloads = [item for item in events if item.get("eventid") == "cowrie.session.file_download"]
        packets = read_rings(self.transfer_rings, min(v6.parse_timestamp(item["timestamp"]).timestamp() for item in events) - 5.0, max(v6.parse_timestamp(item["timestamp"]).timestamp() for item in events) + 5.0)
        return select_transfer_tuples(downloads, packets, v6.parse_timestamp)

    def _episode_packet_tuples(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        low = min(v6.parse_timestamp(item["timestamp"]).timestamp() for item in events) - 5.0
        high = max(v6.parse_timestamp(item["timestamp"]).timestamp() for item in events) + 5.0
        packets = read_rings(self.transfer_rings, low, high)
        return select_session_bound_tuples(events, packets, v6.parse_timestamp, low, high)

    def _direct_ingress_pcap(
        self, session_id: str, original: Mapping[str, Any], events: list[dict[str, Any]],
    ) -> dict[str, Any]:
        low = min(v6.parse_timestamp(item["timestamp"]).timestamp() for item in events) - 5.0
        high = max(v6.parse_timestamp(item["timestamp"]).timestamp() for item in events) + 5.0
        packets = read_rings(self.transfer_rings, low, high)
        selected = select_direct_packets(packets, original, low, high)
        event_hashes = [v6.digest(item) for item in events]
        identifier = direct_pcap_id(session_id, original, event_hashes)
        path = self.retain_dir / f"direct-{identifier}.pcap"
        metadata = write_raw_pcap(path, selected)
        result = {"id": identifier, "sha256": metadata["sha256"], "bytes": metadata["bytes"]}
        return validate_direct_metadata(result)

    def _complete_session(self, session_id: str, events: list[dict[str, Any]]) -> None:
        try:
            connects = [item for item in events if item.get("eventid") == "cowrie.session.connect"]
            closes = [item for item in events if item.get("eventid") == "cowrie.session.closed"]
            body: dict[str, Any] = {
                "session_id": session_id,
                "events": events,
                "event_hashes": [v6.digest(item) for item in events],
                "zeek_flows": [],
                "transfer_packet_tuples": [],
                "episode_packet_tuples": [],
                "episode_capture_contract": SESSION_SOCKET_CAPTURE_CONTRACT,
                "completion_status": "INCOMPLETE",
            }
            if len(connects) != 1 or len(closes) != 1:
                body["failure_reason"] = "session_lifecycle_not_unique"
            else:
                original = v6.event_tuple(connects[0])
                profile = ""
                if original is None:
                    body["failure_reason"] = "session_connect_tuple_missing"
                else:
                    try:
                        profile = ingress_profile(original)
                    except V7BoundaryError as exc:
                        body["failure_reason"] = str(exc)
                if original is not None and profile:
                    body["original_tuple"] = original
                    body["ingress_profile"] = profile
                    body["zeek_flows"] = (
                        self._flow_candidates(connects[0], closes[0])
                        if profile == PROXY_INGRESS else []
                    )
                    body["transfer_packet_tuples"] = self._transfer_packet_tuples(events)
                    try:
                        body["episode_packet_tuples"] = self._episode_packet_tuples(events)
                    except V7BoundaryError as exc:
                        # Keep an explicit unavailable envelope rather than
                        # dropping this session when a socket cannot be bound.
                        body["failure_reason"] = str(exc)
                    if profile == DIRECT_PI_INGRESS:
                        body["direct_ingress_pcap"] = self._direct_ingress_pcap(
                            session_id, original, events
                        )
                    body["completion_status"] = "READY" if (
                        not body.get("failure_reason")
                        and (body["zeek_flows"] or profile == DIRECT_PI_INGRESS)
                    ) else "INCOMPLETE"
                    if profile == PROXY_INGRESS and not body["zeek_flows"] and not body.get("failure_reason"):
                        body["failure_reason"] = "exact_backend_zeek_flow_not_observed"
            if not self._enqueue_completion(body):
                return
            with self.lock:
                self.state["sessions"].pop(session_id, None)
                self._persist_state()
        except Exception:
            with self.lock:
                self.state["sessions"].pop(session_id, None)
                try:
                    self._persist_state()
                except OSError:
                    pass

    @staticmethod
    def _readline(reader: Any, limit: int) -> bytes:
        line = reader.readline(limit + 1)
        if not line or len(line) > limit:
            raise v6.ObserverError("receiver_response_invalid")
        return line

    def _send_one(self) -> None:
        paths = sorted(self.queue_dir.glob("*.json"))
        if not paths:
            return
        path = paths[0]
        try:
            payload = path.read_bytes()
            envelope = json.loads(payload)
            message_id = str(envelope.get("message_id") or "")
            with socket.create_connection((self.capstone_host, self.capstone_port), timeout=3.0) as connection:
                connection.settimeout(30.0)
                connection.sendall(payload)
                reader = connection.makefile("rb")
                try:
                    response = self._readline(reader, 256)
                    while response in {b"DIRECT_PCAP_V7\n", b"OFFLINE_ZEEK_V7\n"}:
                        request = json.loads(self._readline(reader, 64 * 1024))
                        if response == b"DIRECT_PCAP_V7\n":
                            metadata = validate_direct_metadata(request)
                            body = envelope.get("body") if isinstance(envelope, dict) else None
                            expected = validate_direct_metadata(
                                body.get("direct_ingress_pcap") if isinstance(body, dict) else None
                            )
                            if metadata != expected:
                                raise v6.ObserverError("direct_ingress_pcap_request_mismatch")
                            direct_path = self.retain_dir / f"direct-{metadata['id']}.pcap"
                            direct_payload = direct_path.read_bytes()
                            if len(direct_payload) != metadata["bytes"]:
                                raise v6.ObserverError("direct_ingress_pcap_size_mismatch")
                            connection.sendall(direct_payload)
                            response = self._readline(reader, 256)
                            continue
                        if not isinstance(request, dict) or request.get("schema_version") != OFFLINE_SCHEMA:
                            raise v6.ObserverError("offline_request_invalid")
                        size = int(request.get("capstone_pcap_bytes", 0))
                        if not 1 <= size <= 96 * 1024 * 1024:
                            raise v6.ObserverError("offline_pcap_size_invalid")
                        pcap = reader.read(size)
                        if len(pcap) != size:
                            raise v6.ObserverError("offline_pcap_incomplete")
                        try:
                            result = run_offline(
                                request=request, capstone_pcap=pcap,
                                transfer_ring_bases=self.transfer_rings,
                                retain_dir=self.retain_dir, work_dir=self.work_dir,
                                zeek_bin=self.zeek_bin,
                            )
                        except Exception as exc:
                            result = {"schema_version": OFFLINE_SCHEMA, "status": "FAIL", "reason": str(exc)[:200]}
                        connection.sendall(canonical(result) + b"\n")
                        response = self._readline(reader, 256)
                finally:
                    reader.close()
            if response.decode("ascii", "replace").strip() == f"ACK {message_id}":
                body = envelope.get("body") if isinstance(envelope, dict) else None
                if isinstance(body, dict) and body.get("ingress_profile") == DIRECT_PI_INGRESS:
                    metadata = validate_direct_metadata(body.get("direct_ingress_pcap"))
                    (self.retain_dir / f"direct-{metadata['id']}.pcap").unlink(missing_ok=True)
                path.unlink(missing_ok=True)
        except (OSError, ValueError, TypeError, json.JSONDecodeError, v6.ObserverError):
            return


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=pathlib.Path, required=True)
    args = parser.parse_args()
    config = json.loads(args.config.read_text(encoding="utf-8"))
    Observer(config).run()


if __name__ == "__main__":
    main()
