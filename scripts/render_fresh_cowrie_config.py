#!/usr/bin/env python3
"""Create a private Cowrie config for an approved fresh sensor listener."""

import argparse
import ipaddress
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path

from production.tools.cowrie_output_integration import render_config


def interface_address(name: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,32}", name):
        raise ValueError("invalid interface")
    result = subprocess.run(
        ["ip", "-j", "-4", "addr", "show", "dev", name],
        check=True, capture_output=True, text=True,
    )
    addresses = [
        value["local"]
        for device in json.loads(result.stdout)
        for value in device.get("addr_info", [])
        if value.get("family") == "inet" and value.get("scope") in {"global", "host"}
    ]
    if len(addresses) != 1:
        raise ValueError("listener interface must have exactly one IPv4 address")
    return str(ipaddress.IPv4Address(addresses[0]))


def replace_section_option(lines: list[str], section: str, option: str, value: str) -> None:
    header = f"[{section}]"
    start = next((i for i, line in enumerate(lines) if line.strip().lower() == header), None)
    if start is None:
        raise ValueError(f"missing Cowrie section: {section}")
    end = next((i for i in range(start + 1, len(lines)) if lines[i].lstrip().startswith("[")), len(lines))
    pattern = re.compile(rf"^\s*{re.escape(option)}\s*=", re.I)
    matches = [i for i in range(start + 1, end) if pattern.match(lines[i])]
    if len(matches) != 1:
        raise ValueError(f"expected one active {section}.{option}")
    lines[matches[0]] = f"{option} = {value}\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--bundle-root", type=Path, required=True)
    parser.add_argument("--interface", required=True)
    parser.add_argument("--ssh-port", type=int, required=True)
    parser.add_argument("--telnet-port", type=int, required=True)
    args = parser.parse_args()
    if args.destination.exists() or args.destination.is_symlink():
        raise FileExistsError("existing Cowrie config is never replaced by fresh install")
    if any(not 1 <= port <= 65535 for port in (args.ssh_port, args.telnet_port)) or args.ssh_port == args.telnet_port:
        raise ValueError("invalid Cowrie listener ports")
    ip = interface_address(args.interface)
    with tempfile.TemporaryDirectory(dir=args.destination.parent) as temporary:
        staged = Path(temporary) / "cowrie.cfg"
        render_config(args.source, staged, args.bundle_root)
        lines = staged.read_text(encoding="utf-8").splitlines(keepends=True)
        replace_section_option(lines, "ssh", "listen_endpoints", f"tcp:{args.ssh_port}:interface={ip}")
        replace_section_option(lines, "telnet", "listen_endpoints", f"tcp:{args.telnet_port}:interface={ip}")
        replace_section_option(lines, "telnet", "enabled", "true")
        staged.write_text("".join(lines), encoding="utf-8")
        staged.chmod(0o600)
        os.replace(staged, args.destination)


if __name__ == "__main__":
    main()
