#!/usr/bin/env python3
"""Bounded local recovery watchdog for allowlisted systemd and Docker targets."""

from __future__ import annotations

import argparse
import fcntl
import ipaddress
import json
import os
import re
import socket
import subprocess
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping


SCHEMA = "honeypot.service_watchdog.v1"
STATE_SCHEMA = "honeypot.service_watchdog_state.v1"
NAME = re.compile(r"^[A-Za-z0-9_.@-]{1,128}$")
MAX_TARGETS = 64
MAX_OUTPUT_BYTES = 4096


class WatchdogError(RuntimeError):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _clean_name(value: Any, field: str) -> str:
    selected = str(value or "").strip()
    if not NAME.fullmatch(selected):
        raise WatchdogError(f"invalid {field}")
    if "watchdog" in selected.lower():
        raise WatchdogError(f"watchdog cannot manage itself via {field}")
    return selected


def _bounded_int(value: Any, field: str, low: int, high: int) -> int:
    try:
        selected = int(value)
    except (TypeError, ValueError) as exc:
        raise WatchdogError(f"invalid {field}") from exc
    if not low <= selected <= high:
        raise WatchdogError(f"invalid {field}")
    return selected


def load_config(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise WatchdogError("configuration unavailable") from exc
    if not isinstance(value, Mapping) or value.get("schema_version") != SCHEMA:
        raise WatchdogError("configuration schema invalid")
    node_id = _clean_name(value.get("node_id"), "node_id")
    defaults = value.get("defaults")
    if not isinstance(defaults, Mapping):
        raise WatchdogError("defaults missing")
    normalized_defaults = {
        "failure_threshold": _bounded_int(defaults.get("failure_threshold", 3), "failure_threshold", 1, 10),
        "max_restarts": _bounded_int(defaults.get("max_restarts", 3), "max_restarts", 1, 10),
        "restart_window_seconds": _bounded_int(defaults.get("restart_window_seconds", 900), "restart_window_seconds", 60, 86400),
        "probe_timeout_seconds": _bounded_int(defaults.get("probe_timeout_seconds", 3), "probe_timeout_seconds", 1, 15),
        "recovery_wait_seconds": _bounded_int(defaults.get("recovery_wait_seconds", 2), "recovery_wait_seconds", 0, 15),
    }
    targets = value.get("targets")
    if not isinstance(targets, list) or not 1 <= len(targets) <= MAX_TARGETS:
        raise WatchdogError("targets invalid")
    normalized_targets: list[dict[str, Any]] = []
    identities: set[str] = set()
    for raw in targets:
        if not isinstance(raw, Mapping):
            raise WatchdogError("target invalid")
        kind = str(raw.get("kind") or "").strip()
        if kind not in {"systemd", "docker"}:
            raise WatchdogError("target kind invalid")
        name = _clean_name(raw.get("name"), "target name")
        identity = f"{kind}:{name}"
        if identity in identities:
            raise WatchdogError("duplicate target")
        identities.add(identity)
        probe = normalize_probe(raw.get("probe"), normalized_defaults)
        normalized_targets.append({
            "kind": kind,
            "name": name,
            "identity": identity,
            "probe": probe,
            "failure_threshold": _bounded_int(
                raw.get("failure_threshold", normalized_defaults["failure_threshold"]),
                "target failure_threshold", 1, 10,
            ),
        })
    maintenance_file = str(value.get("maintenance_file") or "/run/honeypot-maintenance.lock")
    if not maintenance_file.startswith("/run/") or ".." in Path(maintenance_file).parts:
        raise WatchdogError("maintenance_file invalid")
    return {
        "schema_version": SCHEMA,
        "node_id": node_id,
        "defaults": normalized_defaults,
        "targets": normalized_targets,
        "maintenance_file": maintenance_file,
    }


def normalize_probe(value: Any, defaults: Mapping[str, int]) -> dict[str, Any] | None:
    if value in (None, {}):
        return None
    if not isinstance(value, Mapping):
        raise WatchdogError("probe invalid")
    kind = str(value.get("type") or "").strip()
    timeout = _bounded_int(
        value.get("timeout_seconds", defaults["probe_timeout_seconds"]),
        "probe timeout", 1, 15,
    )
    if kind == "http":
        url = str(value.get("url") or "").strip()
        if not (url.startswith("http://127.0.0.1:") or url.startswith("http://[::1]:")):
            raise WatchdogError("HTTP probes must use loopback")
        return {"type": kind, "url": url, "timeout_seconds": timeout}
    if kind == "tcp":
        host = str(value.get("host") or "").strip()
        try:
            ipaddress.ip_address(host)
        except ValueError as exc:
            raise WatchdogError("TCP probe host must be an IP address") from exc
        port = _bounded_int(value.get("port"), "TCP probe port", 1, 65535)
        return {"type": kind, "host": host, "port": port, "timeout_seconds": timeout}
    raise WatchdogError("probe type invalid")


def run(command: list[str], *, timeout: int = 15) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise WatchdogError("local command failed") from exc


def systemd_state(name: str) -> tuple[bool, str]:
    result = run([
        "/usr/bin/systemctl", "show", f"{name}.service",
        "--property=LoadState", "--property=ActiveState",
        "--property=SubState", "--property=Result", "--no-pager",
    ])
    fields: dict[str, str] = {}
    for line in result.stdout.splitlines():
        key, separator, value = line.partition("=")
        if separator:
            fields[key] = value
    healthy = (
        result.returncode == 0
        and fields.get("LoadState") == "loaded"
        and fields.get("ActiveState") == "active"
        and fields.get("SubState") in {"running", "listening", "exited"}
    )
    reason = ":".join([
        fields.get("LoadState", "unknown"),
        fields.get("ActiveState", "unknown"),
        fields.get("SubState", "unknown"),
        fields.get("Result", "unknown"),
    ])
    return healthy, reason


def docker_state(name: str) -> tuple[bool, str]:
    result = run([
        "/usr/bin/docker", "inspect", "--format",
        "{{.State.Running}} {{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}",
        name,
    ])
    value = result.stdout.strip().split()
    running = result.returncode == 0 and len(value) == 2 and value[0] == "true"
    health = value[1] if len(value) == 2 else "unknown"
    return running and health not in {"unhealthy"}, f"running={running}:health={health}"


def probe_state(probe: Mapping[str, Any] | None) -> tuple[bool, str]:
    if probe is None:
        return True, "not_configured"
    timeout = int(probe["timeout_seconds"])
    if probe["type"] == "tcp":
        try:
            with socket.create_connection((str(probe["host"]), int(probe["port"])), timeout=timeout):
                return True, "tcp_ok"
        except OSError:
            return False, "tcp_failed"
    request = urllib.request.Request(str(probe["url"]), method="GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status == 200, f"http_{response.status}"
    except (OSError, urllib.error.URLError):
        return False, "http_failed"


def restart_target(target: Mapping[str, Any]) -> tuple[bool, str]:
    if target["kind"] == "systemd":
        run(["/usr/bin/systemctl", "reset-failed", f"{target['name']}.service"])
        result = run(["/usr/bin/systemctl", "restart", f"{target['name']}.service"], timeout=30)
    else:
        result = run(["/usr/bin/docker", "restart", str(target["name"])], timeout=30)
    return result.returncode == 0, "restart_command_ok" if result.returncode == 0 else "restart_command_failed"


def load_state(path: Path, node_id: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        value = {}
    if not isinstance(value, dict) or value.get("schema_version") != STATE_SCHEMA or value.get("node_id") != node_id:
        return {"schema_version": STATE_SCHEMA, "node_id": node_id, "targets": {}}
    if not isinstance(value.get("targets"), dict):
        value["targets"] = {}
    return value


def save_state(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    os.chmod(temporary, 0o640)
    os.replace(temporary, path)


def inspect_target(target: Mapping[str, Any]) -> tuple[bool, str]:
    process_ok, process_reason = (
        systemd_state(str(target["name"]))
        if target["kind"] == "systemd"
        else docker_state(str(target["name"]))
    )
    if not process_ok:
        return False, process_reason
    probe_ok, probe_reason = probe_state(target.get("probe"))
    return probe_ok, probe_reason if not probe_ok else f"{process_reason}:{probe_reason}"


def check(config: Mapping[str, Any], state: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    now = time.time()
    defaults = config["defaults"]
    maintenance = Path(str(config["maintenance_file"])).exists()
    output_targets: dict[str, Any] = state.setdefault("targets", {})
    configured = {str(target["identity"]) for target in config["targets"]}
    for stale in set(output_targets).difference(configured):
        output_targets.pop(stale, None)

    summary = {"healthy": 0, "degraded": 0, "recovered": 0, "crash_loop": 0}
    for target in config["targets"]:
        identity = str(target["identity"])
        previous = output_targets.get(identity)
        previous = previous if isinstance(previous, dict) else {}
        history = [
            float(item) for item in previous.get("restart_history", [])
            if isinstance(item, (int, float)) and now - float(item) <= defaults["restart_window_seconds"]
        ]
        healthy, reason = inspect_target(target)
        failures = 0 if healthy else int(previous.get("consecutive_failures") or 0) + 1
        status = "HEALTHY" if healthy else "DEGRADED"
        action = "none"
        if not healthy and failures >= int(target["failure_threshold"]):
            if maintenance:
                status, action = "MAINTENANCE", "restart_suppressed"
            elif len(history) >= defaults["max_restarts"]:
                status, action = "CRASH_LOOP", "restart_rate_limited"
            elif dry_run:
                status, action = "RESTART_REQUIRED", "dry_run"
            else:
                restart_ok, restart_reason = restart_target(target)
                history.append(now)
                action = restart_reason
                if restart_ok:
                    time.sleep(defaults["recovery_wait_seconds"])
                    healthy, reason = inspect_target(target)
                status = "RECOVERED" if healthy else "RESTART_FAILED"
                failures = 0 if healthy else failures
        key = (
            "healthy" if status == "HEALTHY" else
            "recovered" if status == "RECOVERED" else
            "crash_loop" if status in {"CRASH_LOOP", "RESTART_FAILED"} else
            "degraded"
        )
        summary[key] += 1
        output_targets[identity] = {
            "kind": target["kind"],
            "name": target["name"],
            "status": status,
            "reason": reason[:160],
            "action": action,
            "consecutive_failures": failures,
            "restart_count_in_window": len(history),
            "restart_history": history,
            "checked_at": utc_now(),
        }
        print(json.dumps({
            "service": "honeypot_service_watchdog",
            "node_id": config["node_id"],
            "target": identity,
            "status": status,
            "reason": reason[:160],
            "action": action,
            "timestamp": utc_now(),
        }, sort_keys=True), flush=True)
    state.update({
        "schema_version": STATE_SCHEMA,
        "node_id": config["node_id"],
        "summary": summary,
        "maintenance": maintenance,
        "checked_at": utc_now(),
    })
    return state


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    config = load_config(args.config)
    args.lock.parent.mkdir(parents=True, exist_ok=True)
    with args.lock.open("a+", encoding="utf-8") as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return 0
        state = check(config, load_state(args.state, config["node_id"]), dry_run=args.dry_run)
        save_state(args.state, state)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
