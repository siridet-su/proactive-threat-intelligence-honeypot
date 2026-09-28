#!/usr/bin/env python3
"""Validate the current Dashboard staging env contract without printing values."""

from __future__ import annotations

import stat
import sys
from pathlib import Path


REQUIRED = ("MONGODB_URI", "PTI_ADMIN_PASSWORD", "AUTH_SESSION_SECRET")


def check(path: Path, *, expected_uid: int = 0) -> list[str]:
    problems: list[str] = []
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != expected_uid or stat.S_IMODE(metadata.st_mode) != 0o600:
            return ["staging environment ownership, type, or mode is unsafe"]
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return ["staging environment is missing or unreadable"]
    values: dict[str, str] = {}
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            problems.append("staging environment contains an invalid assignment")
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key in values:
            problems.append(f"staging environment repeats {key}")
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key] = value
    for key in REQUIRED:
        if not values.get(key):
            problems.append(f"staging environment needs {key}")
    if values.get("AUTH_SESSION_SECRET") and len(values["AUTH_SESSION_SECRET"]) < 32:
        problems.append("AUTH_SESSION_SECRET must be at least 32 characters")
    if values.get("PTI_ADMIN_PASSWORD") and len(values["PTI_ADMIN_PASSWORD"]) < 12:
        problems.append("PTI_ADMIN_PASSWORD must be at least 12 characters")
    uri = values.get("MONGODB_URI", "")
    if uri and not uri.startswith(("mongodb://", "mongodb+srv://")):
        problems.append("MONGODB_URI must use a MongoDB URI scheme")
    return problems


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: check-runtime-env.py /path/to/staging.env", file=sys.stderr)
        return 2
    problems = check(Path(sys.argv[1]))
    for problem in problems:
        print(problem, file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
