#!/usr/bin/env python3
"""One resumable build/prepare/configuration/activation entry point for a fresh Pi.

The reviewed vars file contains release identity and package versions, never
credentials. Blank private skeletons are staged only when absent; the operator
fills the actual files before retrying activation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ANSIBLE = ROOT / "deploy/ansible"
RELEASE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")


class InstallError(RuntimeError):
    pass


def run(*argv: str, capture: bool = False) -> str:
    try:
        result = subprocess.run(
            argv, check=True, text=True, capture_output=capture
        )
    except FileNotFoundError as exc:
        raise InstallError(f"required command missing: {argv[0]}") from exc
    except subprocess.CalledProcessError as exc:
        raise InstallError(f"step failed: {Path(argv[0]).name}") from exc
    return result.stdout if capture else ""


def load_vars(path: Path) -> tuple[str, Path, str | None]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise InstallError("cannot read reviewed non-secret vars JSON") from exc
    if not isinstance(data, dict):
        raise InstallError("reviewed vars must be a JSON object")
    release_id = data.get("pti_release_id")
    release_source = data.get("pti_release_source")
    digest = data.get("pti_manifest_sha256")
    if not isinstance(release_id, str) or not RELEASE_ID.fullmatch(release_id):
        raise InstallError("reviewed vars need a valid pti_release_id")
    if not isinstance(release_source, str) or "\n" in release_source:
        raise InstallError("reviewed vars need an absolute pti_release_source")
    release_path = Path(release_source)
    if not release_path.is_absolute() or release_path.name != release_id:
        raise InstallError("pti_release_source must be an absolute path ending in the release ID")
    if digest in (None, "", "REPLACE_WITH_APPROVED_64_HEX_DIGEST"):
        digest = None
    elif not isinstance(digest, str) or not SHA256.fullmatch(digest):
        raise InstallError("pti_manifest_sha256 must be a reviewed 64-character SHA-256")
    packages = data.get("pti_package_versions")
    if not isinstance(packages, dict) or set(packages) != {
        "ca-certificates", "python3", "python3-venv", "redis-server"
    }:
        raise InstallError("reviewed vars need exact versions for all four Pi packages")
    for name, version in packages.items():
        if not isinstance(version, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+:~_-]*", version) or version.startswith("REPLACE_"):
            raise InstallError(f"reviewed vars need an approved version for {name}")
    return release_id, release_path, digest


def validate_one_host(inventory: Path) -> None:
    raw = run("ansible-inventory", "-i", str(inventory), "--list", capture=True)
    try:
        data = json.loads(raw)
        hosts = data["pi_sensors"]["hosts"]
    except (ValueError, KeyError, TypeError) as exc:
        raise InstallError("inventory must have one direct pi_sensors host") from exc
    if len(hosts) != 1:
        raise InstallError("inventory must have exactly one pi_sensors host")


def ensure_release(release_id: str, release_path: Path, digest: str | None) -> bool:
    if not release_path.exists():
        print(f"Building missing ARM64 release {release_id} on this controller.", flush=True)
        run(
            "bash", str(ROOT / "scripts/bootstrap_sensor_build.sh"),
            "--release-id", release_id, "--output-root", str(release_path.parent),
        )
    manifest = release_path / "manifest.json"
    try:
        actual = hashlib.sha256(manifest.read_bytes()).hexdigest()
    except OSError as exc:
        raise InstallError("release manifest is missing or unreadable") from exc
    if digest is None:
        print(f"PAUSED: review the built release, then set pti_manifest_sha256={actual} in the reviewed non-secret vars file and rerun.")
        return False
    if actual != digest:
        raise InstallError("release manifest differs from the approved SHA-256")
    run(
        "python3", str(ROOT / "scripts/verify_sensor_release.py"),
        "--release-dir", str(release_path), "--release-id", release_id,
        "--manifest-sha256", digest,
    )
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--vars", type=Path, required=True)
    parser.add_argument(
        "--passwordless-sudo", action="store_true",
        help="skip the sudo password prompt when the target account already has approved passwordless sudo",
    )
    args = parser.parse_args()
    try:
        release_id, release_path, digest = load_vars(args.vars)
        validate_one_host(args.inventory)
        if not ensure_release(release_id, release_path, digest):
            return 2
        base = [
            "ansible-playbook", "-i", str(args.inventory),
            "-e", f"@{args.vars}", "-e", "pti_require_inactive=false",
        ]
        if not args.passwordless_sudo:
            base.append("--ask-become-pass")
        print("Preparing, auditing, staging blank env files, and checking activation gates with one sudo session.", flush=True)
        try:
            run(
                *base,
                str(ANSIBLE / "prepare-pi.yml"),
                str(ANSIBLE / "audit-prepared-pi.yml"),
                str(ANSIBLE / "stage-pi-env-examples.yml"),
                str(ANSIBLE / "activate-pi-go.yml"),
            )
        except InstallError:
            print("PAUSED: review the failed Ansible task and rerun this command after correction. Once preparation and audit pass, blank .env files are placed at /etc/honeypot-agent.env and /etc/honeypot/*.env only when absent. Fill those actual files; existing values are never replaced.", file=sys.stderr)
            return 2
        print(f"ACTIVE: approved Pi Go release {release_id}; verify telemetry and service logs on the target.")
        return 0
    except InstallError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
