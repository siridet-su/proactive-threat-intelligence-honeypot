#!/usr/bin/env python3
"""Verify a local, non-secret ARM64 agent bundle before host preparation."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

EXPECTED = {
    "collector": "pti-collector",
    "processor": "pti-processor",
    "ti-worker": "pti-ti-worker",
    "hardware-agent": "pti-hardware-agent",
    "hardware-backup": "pti-hardware-backup",
}
RELEASE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def verify_release(directory: Path, expected_id: str) -> None:
    if not RELEASE_ID.fullmatch(expected_id) or expected_id in {".", ".."}:
        raise ValueError("invalid release ID")
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("release directory must be a real directory")
    try:
        manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("cannot read release manifest") from exc
    if manifest.get("schema_version") != "pti.sensor-release.v1":
        raise ValueError("unsupported release manifest")
    if manifest.get("release_id") != expected_id or directory.name != expected_id:
        raise ValueError("release ID mismatch")
    if manifest.get("target") != {"goos": "linux", "goarch": "arm64", "cgo_enabled": False}:
        raise ValueError("release target is not static Linux ARM64")
    if manifest.get("runtime_configuration_included") is not False:
        raise ValueError("release must exclude runtime configuration")
    modules = manifest.get("modules")
    if not isinstance(modules, list) or len(modules) != len(EXPECTED):
        raise ValueError("release module set is incomplete")
    seen: set[str] = set()
    checksum_lines = []
    for module in modules:
        if not isinstance(module, dict):
            raise ValueError("invalid module record")
        module_id = module.get("id")
        if module_id not in EXPECTED or module_id in seen:
            raise ValueError("unexpected or duplicate module")
        seen.add(module_id)
        relative = f"bin/{EXPECTED[module_id]}"
        checksum = module.get("sha256")
        if module.get("binary") != relative or not isinstance(checksum, str) or not SHA256.fullmatch(checksum):
            raise ValueError("invalid binary path or checksum")
        binary = directory / relative
        if binary.is_symlink() or not binary.is_file():
            raise ValueError(f"missing regular binary: {relative}")
        if binary.stat().st_mode & 0o111 == 0:
            raise ValueError(f"binary is not executable: {relative}")
        actual = hashlib.sha256(binary.read_bytes()).hexdigest()
        if actual != checksum:
            raise ValueError(f"binary checksum mismatch: {relative}")
        checksum_lines.append(f"{checksum}  {relative}")
    try:
        recorded = (directory / "SHA256SUMS").read_text(encoding="ascii").splitlines()
    except OSError as exc:
        raise ValueError("missing SHA256SUMS") from exc
    if recorded != checksum_lines:
        raise ValueError("SHA256SUMS disagrees with manifest")
    allowed = {"manifest.json", "SHA256SUMS", "bin"}
    allowed.update(f"bin/{name}" for name in EXPECTED.values())
    for entry in directory.rglob("*"):
        relative = entry.relative_to(directory).as_posix()
        if relative not in allowed or entry.is_symlink():
            raise ValueError(f"unexpected release content: {relative}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-dir", required=True, type=Path)
    parser.add_argument("--release-id", required=True)
    args = parser.parse_args()
    try:
        verify_release(args.release_dir, args.release_id)
    except ValueError as exc:
        print(f"release verification failed: {exc}", file=sys.stderr)
        return 2
    print(f"Verified ARM64 agent release: {args.release_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
