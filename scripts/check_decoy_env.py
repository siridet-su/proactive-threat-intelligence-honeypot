#!/usr/bin/env python3
"""Check a private decoy env file without printing or returning any values."""

import argparse
import os
import re
import stat
from pathlib import Path


def check(path: Path) -> None:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600:
        raise ValueError("decoy env must be a root-owned regular file with mode 0600")
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line or line.lstrip().startswith("#"):
            continue
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*=.*", line):
            raise ValueError("decoy env has invalid assignment syntax")
        name, value = line.split("=", 1)
        if name in values:
            raise ValueError("decoy env has a duplicate key")
        values[name] = value
    if not values.get("POSTGRES_PASSWORD", "").strip():
        raise ValueError("POSTGRES_PASSWORD is missing")
    if values.get("WEB_CORP_BIND_IP", "") not in ("", "127.0.0.1"):
        raise ValueError("fresh Web-corp must bind to 127.0.0.1")
    if any(values.get(name, "") for name in ("WEB_CORP_WG_BIND_IP", "WEB_CORP_PROXY_PEER_IP")):
        raise ValueError("fresh localhost deployment cannot use public Web-corp override")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path)
    args = parser.parse_args()
    try:
        check(args.path)
    except (OSError, UnicodeError, ValueError) as exc:
        parser.exit(2, f"decoy env not ready: {exc}\n")


if __name__ == "__main__":
    main()
