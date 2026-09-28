#!/usr/bin/env python3
"""Fill only blank, host-derived settings in fresh private env skeletons."""

import argparse
import ipaddress
import json
import os
import re
import socket
import stat
import subprocess
import tempfile
from pathlib import Path


def interface_ip(interface: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,32}", interface):
        raise ValueError("invalid interface")
    result = subprocess.run(["ip", "-j", "-4", "addr", "show", "dev", interface], check=True, capture_output=True, text=True)
    addresses = [entry["local"] for item in json.loads(result.stdout) for entry in item.get("addr_info", []) if entry.get("family") == "inet" and entry.get("scope") in {"global", "host"}]
    if len(addresses) != 1:
        raise ValueError("fresh interface must have one IPv4 address")
    return str(ipaddress.IPv4Address(addresses[0]))


def fill(path: Path, values: dict[str, str], *, verify: tuple[str, ...] = ()) -> bool:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600:
        raise ValueError(f"unsafe private env file: {path.name}")
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    seen = set()
    changed = False
    for index, line in enumerate(lines):
        if line.lstrip().startswith("#") or not line.strip():
            continue
        match = re.fullmatch(r"([A-Z][A-Z0-9_]*)=(.*)\n?", line)
        if not match:
            raise ValueError(f"invalid assignment in {path.name}")
        key, current = match.groups()
        if key in seen:
            raise ValueError(f"duplicate assignment in {path.name}")
        seen.add(key)
        current = current.rstrip("\n")
        if key in verify and current and current != values[key]:
            raise ValueError(f"{key} differs from current fresh-host network state")
        if key in values and not current:
            lines[index] = f"{key}={values[key]}\n"
            changed = True
    missing = set(values) - seen
    if missing:
        lines.extend(f"{key}={values[key]}\n" for key in sorted(missing))
        changed = True
    if not changed:
        return False
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.writelines(lines)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, path)
    finally:
        Path(temporary_name).unlink(missing_ok=True)
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interface", required=True)
    parser.add_argument("--ssh-port", type=int, required=True)
    parser.add_argument("--telnet-port", type=int, required=True)
    args = parser.parse_args()
    host_ip = interface_ip(args.interface)
    sensor = socket.gethostname()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,62}", sensor):
        raise ValueError("invalid host name for sensor ID")
    shared = {
        "SENSOR_NAME": sensor,
        "SENSOR_LAN_IP": host_ip,
        "SENSOR_LAN_IFACE": args.interface,
        "WEB_CORP_SENSOR_IP": "127.0.0.1",
        "WEB_CORP_SENSOR_IFACE": "lo",
        "ALLOW_RESP_PORTS": f"{args.ssh_port},{args.telnet_port}",
        "READ_FROM_START": "true",
        "COWRIE_LOG_FILE": "/home/cowrie/cowrie/var/log/cowrie/cowrie.json",
        **{f"ZEEK_{kind}_LOG": f"/opt/zeek/logs/current/{kind.lower()}.log" for kind in ("CONN", "SSH", "SSL", "DNS", "HTTP", "FILES", "NOTICE")},
    }
    changed = fill(Path("/etc/honeypot-agent.env"), shared, verify=("SENSOR_LAN_IP", "SENSOR_LAN_IFACE", "ALLOW_RESP_PORTS"))
    changed |= fill(Path("/etc/honeypot/hardware.env"), {"NETWORK_INTERFACES": args.interface, "NETWORK_PRIMARY_INTERFACE": args.interface, "NETWORK_SAMPLE_SECONDS": "1", "HARDWARE_SENSOR_ID": sensor}, verify=("NETWORK_PRIMARY_INTERFACE",))
    changed |= fill(Path("/etc/honeypot/decoy.env"), {"WEB_CORP_BIND_IP": "127.0.0.1", "ZEEK_LOG_DIR": "/opt/zeek/logs/current"}, verify=("WEB_CORP_BIND_IP", "ZEEK_LOG_DIR"))
    print("FRESH_ENV_CHANGED" if changed else "FRESH_ENV_UNCHANGED")


if __name__ == "__main__":
    main()
