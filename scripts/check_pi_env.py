#!/usr/bin/env python3
"""Read-only, value-redacting checks for operator-uploaded Pi env files.

This checks file shape and key presence. It does not establish service health,
credential validity, connectivity, or readiness to expose a listener.
"""

from __future__ import annotations

import argparse
import os
import re
import stat
import sys
from pathlib import Path


SHARED = "honeypot-agent.env"
FILES = {
    "collector": (SHARED,),
    "processor": (SHARED, "honeypot/processor.env"),
    "ti-worker": (SHARED, "honeypot/ti-worker.env"),
    "hardware": (SHARED, "honeypot/hardware.env"),
    "hardware-backup": (SHARED, "honeypot/processor.env", "honeypot/backup.env"),
}
REQUIRED = {
    SHARED: {"REDIS_ADDR", "REDIS_DB"},
    "honeypot/processor.env": set(),
    "honeypot/ti-worker.env": set(),
    "honeypot/hardware.env": {"NETWORK_INTERFACES", "NETWORK_PRIMARY_INTERFACE"},
    "honeypot/backup.env": {
        "BACKUP_MODE", "BACKUP_TARGETS", "B2_BUCKET", "B2_KEY_ID", "B2_APPLICATION_KEY"
    },
}
SERVICE_SHARED_KEYS = {
    "collector": {
        "SENSOR_NAME", "SENSOR_LAN_IP", "SENSOR_LAN_IFACE",
        "SENSOR_ZT_IP", "SENSOR_ZT_IFACE", "COWRIE_LOG_FILE",
        "ZEEK_CONN_LOG", "ZEEK_SSH_LOG", "ZEEK_SSL_LOG", "ZEEK_DNS_LOG",
        "ZEEK_HTTP_LOG", "ZEEK_FILES_LOG", "ZEEK_NOTICE_LOG",
    },
    "processor": {"MONGO_URI"},
    "ti-worker": {"MONGO_URI"},
    "hardware": set(),
    "hardware-backup": {"MONGO_URI"},
}
KEY_LINE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$")


def check_file(path: Path, *, require_owner: bool = True) -> tuple[set[str], list[str]]:
    errors: list[str] = []
    try:
        info = path.lstat()
    except FileNotFoundError:
        return set(), ["missing file"]
    if not stat.S_ISREG(info.st_mode):
        return set(), ["must be a regular file, not a symlink or directory"]
    if stat.S_IMODE(info.st_mode) != 0o600:
        errors.append("mode must be 0600")
    if require_owner and (info.st_uid, info.st_gid) != (0, 0):
        errors.append("owner must be root:root")
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return set(), errors + ["cannot read UTF-8 env file"]
    values: dict[str, str] = {}
    for number, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = KEY_LINE.fullmatch(stripped)
        if not match:
            errors.append(f"invalid assignment on line {number}")
            continue
        key, value = match.groups()
        if key in values:
            errors.append(f"duplicate key: {key}")
        values[key] = value.strip().strip('"\'')
    present = {key for key, value in values.items() if value and not value.startswith("<")}
    return present, errors


def check_services(root: Path, services: list[str], *, require_owner: bool = True) -> list[str]:
    needed_files = dict.fromkeys(file for service in services for file in FILES[service])
    errors: list[str] = []
    present_by_file: dict[str, set[str]] = {}
    for name in needed_files:
        present, file_errors = check_file(root / name, require_owner=require_owner)
        present_by_file[name] = present
        errors.extend(f"{name}: {error}" for error in file_errors)
        missing = REQUIRED[name] - present
        errors.extend(f"{name}: missing value for {key}" for key in sorted(missing))
    shared_present = present_by_file.get(SHARED, set())
    for service in services:
        missing = SERVICE_SHARED_KEYS[service] - shared_present
        errors.extend(f"{SHARED}: {service} needs {key}" for key in sorted(missing))
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--service", choices=[*FILES, "all"], default="all")
    parser.add_argument("--etc-root", type=Path, default=Path("/etc"))
    args = parser.parse_args()
    services = list(FILES) if args.service == "all" else [args.service]
    errors = check_services(args.etc_root, services)
    if errors:
        for error in errors:
            print(f"FAIL {error}", file=sys.stderr)
        print("Private env check failed; no values were printed.", file=sys.stderr)
        return 1
    print("Private env file shape and required keys passed; service readiness is not established.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
