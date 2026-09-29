#!/usr/bin/env python3
"""Check local Redis binding policy without reading or printing secrets."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def check_redis_config(path: Path) -> list[str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return ["Redis config is missing or unreadable"]
    directives: dict[str, list[str]] = {}
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split()
        if parts:
            directives[parts[0].lower()] = parts[1:]
    errors = []
    if "include" in directives:
        errors.append("Redis config uses an include; binding needs separate review")
    bind = directives.get("bind", [])
    if not bind or any(item.lstrip("-") not in {"127.0.0.1", "::1"} for item in bind):
        errors.append("Redis must bind only to loopback")
    if directives.get("protected-mode") != ["yes"]:
        errors.append("Redis protected-mode must be yes")
    if directives.get("port") not in (None, ["6379"]):
        errors.append("Redis TCP port must be 6379")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--redis-config", type=Path, default=Path("/etc/redis/redis.conf"))
    args = parser.parse_args()
    errors = check_redis_config(args.redis_config)
    for error in errors:
        print(f"FAIL {error}", file=sys.stderr)
    if errors:
        return 1
    print("Redis loopback binding policy passed; no connection was attempted.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
