#!/usr/bin/env python3
"""Write a narrow Zeek packet filter for one fresh sensor interface.

The address is resolved at every service start so DHCP renewal does not leave
the next restart bound to a stale address. A missing or ambiguous IPv4 address
fails closed instead of starting broad capture.
"""

import argparse
import ipaddress
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path


def address_for(interface: str) -> str:
    result = subprocess.run(
        ["ip", "-j", "-4", "addr", "show", "dev", interface],
        check=True, capture_output=True, text=True,
    )
    addresses = [
        entry["local"]
        for device in json.loads(result.stdout)
        for entry in device.get("addr_info", [])
        if entry.get("family") == "inet"
        and entry.get("scope") in {"global", "host"}
    ]
    if len(addresses) != 1:
        raise ValueError("capture interface must have exactly one IPv4 address")
    return str(ipaddress.IPv4Address(addresses[0]))


def render(interface: str, ports: list[int], output: Path) -> None:
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,32}", interface):
        raise ValueError("invalid capture interface")
    if not ports or len(ports) != len(set(ports)) or any(not 1 <= p <= 65535 for p in ports):
        raise ValueError("invalid decoy port set")
    host = address_for(interface)
    destination = " or ".join(f"dst port {p}" for p in ports)
    source = " or ".join(f"src port {p}" for p in ports)
    expression = (
        f"tcp and ((dst host {host} and ({destination}))"
        f" or (src host {host} and ({source})))"
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="ascii", dir=output.parent,
        prefix=".pti-fresh-capture-", delete=False,
    ) as temporary:
        temporary.write("# Generated at service start; do not edit.\n")
        temporary.write(f'redef PacketFilter::restricted_filter = "{expression}";\n')
        staged = Path(temporary.name)
    try:
        os.chmod(staged, 0o644)
        os.replace(staged, output)
    finally:
        staged.unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interface", required=True)
    parser.add_argument("--ports", required=True, help="comma-separated reviewed TCP ports")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        ports = [int(port) for port in args.ports.split(",")]
    except ValueError as exc:
        parser.error(f"invalid port list: {exc}")
    render(args.interface, ports, args.output)


if __name__ == "__main__":
    main()
