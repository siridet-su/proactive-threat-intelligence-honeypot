#!/usr/bin/env python3
"""Fail if another process already listens on a proposed Cowrie port."""

import argparse
from pathlib import Path


def listening_ports(path: Path) -> set[int]:
    with path.open(encoding="ascii") as stream:
        next(stream)
        return {
            int(fields[1].split(":")[1], 16)
            for line in stream
            if (fields := line.split())[3] == "0A"
        }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, action="append", required=True)
    args = parser.parse_args()
    occupied = listening_ports(Path("/proc/net/tcp")) | listening_ports(Path("/proc/net/tcp6"))
    conflict = sorted(occupied.intersection(args.port))
    if conflict:
        parser.exit(2, f"Cowrie listener port already occupied: {','.join(map(str, conflict))}\n")


if __name__ == "__main__":
    main()
