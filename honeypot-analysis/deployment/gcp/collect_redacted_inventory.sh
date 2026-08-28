#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 2 || "$1" != "--output" || -z "$2" ]]; then
  echo "usage: $0 --output OWNER_ONLY_JSON" >&2
  exit 2
fi

output=$2
case "$output" in
  */honeypot-analysis/*|*/teammate-repo/*)
    echo "refusing to write an inventory inside a source checkout" >&2
    exit 2
    ;;
esac

umask 077
parent=${output%/*}
[[ "$parent" == "$output" ]] && parent=.
install -d -m 0700 "$parent"
if [[ -e "$output" ]]; then
  echo "refusing to overwrite existing inventory: $output" >&2
  exit 2
fi

tmp=$(mktemp "$parent/.redacted-inventory.XXXXXX")
trap 'rm -f -- "$tmp"' EXIT
python3 - "$tmp" "$output" <<'PY'
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


temporary = Path(sys.argv[1])
destination = Path(sys.argv[2])


def command(*args: str) -> str:
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError):
        return "unavailable"
    return result.stdout.strip() or "unavailable"


def os_identity() -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            key, separator, value = line.partition("=")
            if separator and key in {"ID", "VERSION_ID"}:
                values[key.lower()] = value.strip().strip('"')
    except OSError:
        values = {"id": "unavailable", "version_id": "unavailable"}
    return values


def listening_ports() -> list[int]:
    ports: set[int] = set()
    for filename in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            lines = Path(filename).read_text(encoding="ascii").splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            fields = line.split()
            if len(fields) < 4 or fields[3] != "0A":  # TCP_LISTEN
                continue
            try:
                ports.add(int(fields[1].rsplit(":", 1)[1], 16))
            except (IndexError, ValueError):
                continue
    return sorted(ports)


def managed_units() -> list[str]:
    output = command("systemctl", "list-unit-files", "honeypot-*.service", "honeypot-*.timer", "--no-legend", "--plain")
    units: list[str] = []
    for line in output.splitlines():
        match = re.match(r"^(honeypot-[A-Za-z0-9_.@-]+\.(?:service|timer))\s", line)
        if match:
            units.append(match.group(1))
    return sorted(set(units))


def marker() -> dict[str, str]:
    result: dict[str, str] = {"revision": "unavailable", "manifest_sha256": "unavailable"}
    marker_path = Path("/opt/honeypot/DEPLOYED_COMMIT")
    try:
        revision = marker_path.read_text(encoding="ascii").strip()
        if re.fullmatch(r"[0-9a-f]{40}", revision):
            result["revision"] = revision
    except OSError:
        pass
    manifest_path = Path("/opt/honeypot/DEPLOYMENT_MANIFEST.json")
    try:
        digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
        result["manifest_sha256"] = digest
    except OSError:
        pass
    return result


document = {
    "schema_version": "gcp_vm_redacted_inventory.v1",
    "captured_at": datetime.now(timezone.utc).isoformat(),
    "host": "<REDACTED>",
    "os": os_identity(),
    "kernel": command("uname", "-r"),
    "runtime_versions": {
        "python": command("python3", "--version"),
        "sqlite": command("sqlite3", "--version").split()[0],
        "haproxy": command("haproxy", "-v").splitlines()[0],
        "systemd": command("systemctl", "--version").splitlines()[0],
    },
    "listening_tcp_ports": listening_ports(),
    "managed_units": managed_units(),
    "release_marker": marker(),
    "network": {
        "addresses": "<REDACTED>",
        "firewall_rules": "<PRIVATE_INVENTORY_ONLY>",
        "tailscale_peers": "<PRIVATE_INVENTORY_ONLY>",
    },
    "layout": [
        {"path": "/opt/honeypot", "purpose": "active release pointer"},
        {"path": "/opt/honeypot-releases", "purpose": "immutable releases"},
        {"path": "/opt/honeypot-model-bundles", "purpose": "frozen model bundles"},
        {"path": "/var/lib/honeypot", "purpose": "mutable SQLite and runtime state"},
        {"path": "/var/backups/honeypot", "purpose": "owner-only backups and receipts"},
        {"path": "/etc/honeypot", "purpose": "configuration and separately provisioned secrets"},
    ],
    "secrets": "not collected; provision separately",
}

temporary.write_text(json.dumps(document, sort_keys=True, indent=2) + "\n", encoding="utf-8")
os.chmod(temporary, 0o600)
os.replace(temporary, destination)
os.chmod(destination, 0o600)
PY
chmod 0600 "$output"
trap - EXIT
echo "$output"
