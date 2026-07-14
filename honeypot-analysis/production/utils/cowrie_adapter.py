"""Notebook cell 1A Cowrie adapter as reusable production code."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple


SUSPICIOUS_PORTS = {3333, 4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337}
COWRIE_COMMAND_EVENTS = {
    "cowrie.command.input",
    "cowrie.command.failed",
    "cowrie.command.success",
    "cowrie.session.file_download",
}
_RE_IPV4_EXTRACT = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")


def extract_dst_port(command: str) -> int:
    match = re.search(r":(\d{1,5})\b", command or "")
    if not match:
        return 0
    try:
        port = int(match.group(1))
        return port if 0 < port <= 65535 else 0
    except ValueError:
        return 0


def extract_dst_ip(command: str) -> str:
    match = _RE_IPV4_EXTRACT.search(command or "")
    return match.group(0) if match else ""


def load_cowrie_events(log_source: Any) -> List[Dict[str, Any]]:
    if isinstance(log_source, (str, Path)):
        path = Path(log_source)
        if not path.exists():
            raise FileNotFoundError(f"Cowrie log file not found: {path}")
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
            return loaded if isinstance(loaded, list) else [loaded]
        except json.JSONDecodeError:
            events: List[Dict[str, Any]] = []
            for line in path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
            return events
    return [dict(event) for event in (log_source or [])]


def cowrie_to_events(log_source: Any, honeypot_mode: bool = True) -> Tuple[List[Dict[str, Any]], Dict[str, Any], List[Dict[str, Any]]]:
    raw_events = load_cowrie_events(log_source)
    if not raw_events:
        return [], {}, []

    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for event in raw_events:
        grouped.setdefault(event.get("session", "unknown"), []).append(event)
    for events in grouped.values():
        events.sort(key=lambda item: item.get("timestamp", ""))

    session_meta: Dict[str, Any] = {}
    for session_id, events in grouped.items():
        session_meta[session_id] = {
            "src_ip": next((event.get("src_ip", "") for event in events), ""),
            "timestamp": next((event.get("timestamp", "") for event in events), ""),
            "login_success": any(event.get("eventid") == "cowrie.login.success" for event in events),
            "has_command": any(event.get("eventid") in COWRIE_COMMAND_EVENTS for event in events),
            "failed_logins": sum(1 for event in events if event.get("eventid") == "cowrie.login.failed"),
        }

    process_events: List[Dict[str, Any]] = []
    for session_id, events in grouped.items():
        src_ip = session_meta[session_id]["src_ip"]
        timestamp = session_meta[session_id]["timestamp"]
        commands: List[Dict[str, Any]] = []
        for event in events:
            eventid = event.get("eventid", "")
            if eventid in {"cowrie.command.input", "cowrie.command.success"}:
                command = (event.get("input") or "").strip()
                success = event.get("success", 1) != 0 or eventid == "cowrie.command.success"
                if command:
                    commands.append({"cmd": command, "success": success, "file_hash": ""})
            elif eventid == "cowrie.command.failed":
                command = (event.get("input") or "").strip()
                if command:
                    commands.append({"cmd": command, "success": False, "file_hash": ""})
            elif eventid == "cowrie.session.file_download":
                url = event.get("url", "")
                if url:
                    commands.append({"cmd": f"wget {url}", "success": True, "file_hash": event.get("shasum", "")})
        if not commands:
            continue

        session_hash = int(hashlib.md5(session_id.encode("utf-8")).hexdigest()[:7], 16)
        shell_pid = session_hash * 100000
        process_events.append(
            {
                "ProcessId": shell_pid,
                "ParentProcessId": shell_pid - 1,
                "CommandLine": "bash",
                "Image": "cowrie_session",
                "UtcTime": timestamp,
                "User": "root",
                "_src_ip": src_ip,
                "_session_id": session_id,
                "_honeypot": True,
                "_ioc_force_high": honeypot_mode,
                "_file_hash": "",
                "_success": True,
                "_dst_ip": "",
                "_dst_port": 0,
                "_suspicious": False,
                "_is_shell_node": True,
            }
        )
        for index, item in enumerate(commands):
            command = item["cmd"]
            dst_port = extract_dst_port(command)
            process_events.append(
                {
                    "ProcessId": shell_pid + index + 1,
                    "ParentProcessId": shell_pid,
                    "CommandLine": command,
                    "Image": "bash",
                    "UtcTime": timestamp,
                    "User": "root",
                    "_src_ip": src_ip,
                    "_session_id": session_id,
                    "_honeypot": True,
                    "_ioc_force_high": honeypot_mode,
                    "_file_hash": item["file_hash"],
                    "_success": item["success"],
                    "_dst_ip": extract_dst_ip(command),
                    "_dst_port": dst_port,
                    "_suspicious": dst_port in SUSPICIOUS_PORTS,
                    "_is_shell_node": False,
                }
            )

    return process_events, session_meta, list(raw_events)
