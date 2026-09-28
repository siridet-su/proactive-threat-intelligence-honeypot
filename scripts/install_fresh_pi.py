#!/usr/bin/env python3
"""Resume the reviewed fresh Ubuntu ARM64 Pi stack from one command.

Builds a missing approved Go release, stages every dependency, pauses for the
operator's private env files, then activates Cowrie, Zeek, localhost decoys,
and the Go services. The legacy GCP sensor forwarder is deliberately omitted.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

from install_pi_sensor import (
    ANSIBLE, InstallError, ensure_release, load_vars, validate_one_host,
)


SHA256 = re.compile(r"^[0-9a-f]{64}$")
REVISION = re.compile(r"^[0-9a-f]{40}$")
VERSION = re.compile(r"^[0-9][A-Za-z0-9.+:~_-]*$")


def reviewed_full_vars(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise InstallError("cannot read reviewed non-secret full-stack vars") from exc
    artifacts = {
        "pti_cowrie_archive": "pti_cowrie_sha256",
        "pti_cowrie_bundle": "pti_cowrie_bundle_sha256",
        "pti_decoy_archive": "pti_decoy_sha256",
    }
    for artifact, digest in artifacts.items():
        raw_path, expected = data.get(artifact), data.get(digest)
        if not isinstance(raw_path, str) or not Path(raw_path).is_absolute():
            raise InstallError(f"{artifact} needs an absolute local path")
        if not isinstance(expected, str) or not SHA256.fullmatch(expected):
            raise InstallError(f"{digest} needs an approved SHA-256")
        try:
            actual = hashlib.sha256(Path(raw_path).read_bytes()).hexdigest()
        except OSError as exc:
            raise InstallError(f"cannot read {artifact}") from exc
        if actual != expected:
            raise InstallError(f"{artifact} differs from its approved SHA-256")
    for name in ("pti_cowrie_bundle_revision", "pti_decoy_commit"):
        value = data.get(name)
        if not isinstance(value, str) or not REVISION.fullmatch(value):
            raise InstallError(f"{name} needs a reviewed full Git revision")
    for name in ("pti_docker_version", "pti_compose_version"):
        value = data.get(name)
        if not isinstance(value, str) or not VERSION.fullmatch(value):
            raise InstallError(f"{name} needs an exact reviewed package version")
    if data.get("pti_zeek_interface") not in ("wlan0", "lo"):
        raise InstallError("capture interface must be wlan0, or lo for isolated VM validation")
    if data.get("pti_cowrie_interface") != data["pti_zeek_interface"]:
        raise InstallError("Cowrie and Zeek must use the same reviewed interface")
    ports = (data.get("pti_cowrie_ssh_port"), data.get("pti_cowrie_telnet_port"))
    if any(type(port) is not int or not 1 <= port <= 65535 for port in ports) or ports[0] == ports[1]:
        raise InstallError("Cowrie needs two distinct valid TCP ports")
    if data.get("pti_zeek_ports") != list(ports):
        raise InstallError("Zeek capture ports must exactly match Cowrie listeners")
    if data["pti_zeek_interface"] == "wlan0" and ports != (22, 23):
        raise InstallError("fresh Wi-Fi Pi contract uses Cowrie TCP 22/23")
    if data["pti_zeek_interface"] == "lo" and 22 in ports:
        raise InstallError("VM loopback test must leave administrator SSH port 22 alone")
    return data


def play(base: list[str], *names: str) -> None:
    command = [*base, *(str(ANSIBLE / name) for name in names)]
    try:
        subprocess.run(command, check=True)
    except (OSError, subprocess.CalledProcessError) as exc:
        raise InstallError(f"Ansible step failed: {', '.join(names)}") from exc


def service_property(inventory: Path, unit: str, property_name: str) -> str:
    result = subprocess.run(
        ["ansible", "-i", str(inventory), "pi_sensors", "-m", "command",
         "-a", f"systemctl show --property={property_name} --value {unit}", "-o"],
        capture_output=True, text=True, check=False,
    )
    if result.returncode:
        raise InstallError(f"cannot check target service state: {unit}")
    match = re.search(r"\(stdout\)\s*([A-Za-z-]+)\s*$", result.stdout)
    if match is None:
        raise InstallError(f"unexpected target service state: {unit}")
    return match.group(1)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--vars", type=Path, required=True)
    parser.add_argument("--passwordless-sudo", action="store_true")
    parser.add_argument("--enable-backup", action="store_true", help="activate B2 backup only after the operator supplies their own write-capable destination key")
    args = parser.parse_args()
    try:
        release_id, release_path, digest = load_vars(args.vars)
        reviewed_full_vars(args.vars)
        validate_one_host(args.inventory)
        if not ensure_release(release_id, release_path, digest):
            return 2
        base = ["ansible-playbook", "-i", str(args.inventory), "-e", f"@{args.vars}",
                "-e", "pti_require_inactive=false", "-e", "pti_env_profile=fresh-wifi",
                "-e", f"pti_enable_backup={'true' if args.enable_backup else 'false'}"]
        if not args.passwordless_sudo:
            base.append("--ask-become-pass")
        play(base, "prepare-pi.yml", "audit-prepared-pi.yml", "stage-pi-env-examples.yml")
        if service_property(args.inventory, "cowrie.service", "LoadState") == "not-found":
            play(base, "prepare-cowrie.yml")
        if service_property(args.inventory, "zeek.service", "LoadState") == "not-found":
            play(base, "prepare-zeek.yml")
        if service_property(args.inventory, "docker.service", "ActiveState") != "active":
            play(base, "prepare-decoy.yml")
        play(base, "fill-fresh-nonsecret-env.yml")
        try:
            play(base, "check-fresh-env.yml")
        except InstallError:
            print("PAUSED: fill the staged private /etc/honeypot-agent.env and /etc/honeypot/*.env files, then rerun this same command. No credential value was read by the controller.", file=sys.stderr)
            return 2
        play(base, "activate-zeek.yml", "activate-cowrie.yml", "activate-decoy.yml", "activate-pi-go.yml")
        backup_state = "enabled by operator request" if args.enable_backup else "disabled pending the operator's own B2 key"
        print(f"ACTIVE: fresh Pi core passed immediate service and localhost checks; B2 backup {backup_state}. Verify telemetry end to end.")
        return 0
    except InstallError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
