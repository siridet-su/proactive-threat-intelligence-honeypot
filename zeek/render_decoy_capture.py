#!/usr/bin/env python3
"""Render the existing Pi's Zeek capture policy from current interface IPs."""

import ipaddress
import json
import os
import subprocess
import tempfile
import time
from pathlib import Path


SITE_DIR = Path("/usr/local/zeek/share/zeek/site")
OUTPUT = SITE_DIR / "pti-decoy-capture.zeek"
INTERFACES = ("wlan0", "ztxoocdlsi", "wg0")


def interface_ipv4(name: str) -> str:
    result = subprocess.run(
        ["ip", "-j", "-4", "addr", "show", "dev", name],
        check=True,
        capture_output=True,
        text=True,
    )
    addresses = [
        item["local"]
        for iface in json.loads(result.stdout)
        for item in iface.get("addr_info", [])
        if item.get("family") == "inet" and item.get("scope") == "global"
    ]
    if len(addresses) != 1:
        raise ValueError(f"{name}: expected one global IPv4 address")
    return str(ipaddress.IPv4Address(addresses[0]))


def capture_filter(wlan_ip: str, zerotier_ip: str, wireguard_ip: str) -> str:
    wlan_dst_ports = "(dst port 22 or dst port 23)"
    wlan_src_ports = "(src port 22 or src port 23)"
    zerotier_dst_ports = "(dst port 22 or dst port 23 or dst port 80)"
    zerotier_src_ports = "(src port 22 or src port 23 or src port 80)"
    return (
        "tcp and ("
        f"(dst host {wlan_ip} and {wlan_dst_ports}) or "
        f"(src host {wlan_ip} and {wlan_src_ports}) or "
        f"(dst host {zerotier_ip} and {zerotier_dst_ports}) or "
        f"(src host {zerotier_ip} and {zerotier_src_ports}) or "
        f"(dst host {wireguard_ip} and dst port 80) or "
        f"(src host {wireguard_ip} and src port 80)"
        ")"
    )


def main() -> None:
    deadline = time.monotonic() + 40
    while True:
        try:
            wlan_ip, zerotier_ip, wireguard_ip = (interface_ipv4(name) for name in INTERFACES)
            break
        except (subprocess.CalledProcessError, ValueError, json.JSONDecodeError):
            if time.monotonic() >= deadline:
                raise SystemExit("Zeek decoy capture: interface IPv4 unavailable")
            time.sleep(2)

    content = (
        "# Generated at Zeek startup from active interface addresses. Do not edit.\n"
        f'redef PacketFilter::restricted_filter = "{capture_filter(wlan_ip, zerotier_ip, wireguard_ip)}";\n'
    )
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="ascii", dir=SITE_DIR, prefix=".pti-decoy-capture-", delete=False
    ) as temporary:
        temporary.write(content)
        temporary_path = Path(temporary.name)
    try:
        os.chmod(temporary_path, 0o644)
        os.replace(temporary_path, OUTPUT)
    finally:
        temporary_path.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
