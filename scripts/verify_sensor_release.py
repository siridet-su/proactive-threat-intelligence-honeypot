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
    "collector": ("agents/collector-agent", "pti-collector"),
    "processor": ("agents/processor-agent", "pti-processor"),
    "ti-worker": ("agents/ti-worker", "pti-ti-worker"),
    "hardware-agent": ("agents/hardware-agent", "pti-hardware-agent"),
    "hardware-backup": ("agents/hardware-backup", "pti-hardware-backup"),
}
RELEASE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
MAX_MANIFEST_BYTES = 64 * 1024
MAX_BINARY_BYTES = 256 * 1024 * 1024


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_release(directory: Path, expected_id: str, manifest_sha256: str) -> None:
    if not RELEASE_ID.fullmatch(expected_id) or expected_id in {".", ".."}:
        raise ValueError("invalid release ID")
    if not SHA256.fullmatch(manifest_sha256):
        raise ValueError("invalid pinned manifest SHA-256")
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("release directory must be a real directory")
    manifest_path = directory / "manifest.json"
    if manifest_path.is_symlink():
        raise ValueError("release manifest must be a regular file")
    try:
        if manifest_path.stat().st_size > MAX_MANIFEST_BYTES:
            raise ValueError("release manifest is too large")
        manifest_bytes = manifest_path.read_bytes()
        if hashlib.sha256(manifest_bytes).hexdigest() != manifest_sha256:
            raise ValueError("manifest SHA-256 differs from approved digest")
        manifest = json.loads(manifest_bytes)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("cannot read release manifest") from exc
    if not isinstance(manifest, dict):
        raise ValueError("release manifest must be an object")
    if manifest.get("schema_version") != "pti.sensor-release.v1":
        raise ValueError("unsupported release manifest")
    if set(manifest) != {
        "schema_version", "release_id", "source_commit", "built_at_utc",
        "go_version", "target", "module_downloads",
        "runtime_configuration_included", "modules",
    }:
        raise ValueError("unexpected release manifest fields")
    if manifest.get("release_id") != expected_id or directory.name != expected_id:
        raise ValueError("release ID mismatch")
    if manifest.get("target") != {"goos": "linux", "goarch": "arm64", "cgo_enabled": False}:
        raise ValueError("release target is not static Linux ARM64")
    if manifest.get("runtime_configuration_included") is not False:
        raise ValueError("release must exclude runtime configuration")
    if manifest.get("module_downloads") != "disabled; dependencies must already be cached":
        raise ValueError("release network policy mismatch")
    if not isinstance(manifest.get("source_commit"), str) or not re.fullmatch(
        r"[0-9a-f]{40}|[0-9a-f]{64}", manifest["source_commit"]
    ):
        raise ValueError("invalid source revision")
    if not isinstance(manifest.get("built_at_utc"), str) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+00:00", manifest["built_at_utc"]
    ):
        raise ValueError("invalid build timestamp")
    if not isinstance(manifest.get("go_version"), str) or not manifest["go_version"].startswith("go version ") or len(manifest["go_version"]) > 200:
        raise ValueError("invalid Go version")
    modules = manifest.get("modules")
    if not isinstance(modules, list) or len(modules) != len(EXPECTED):
        raise ValueError("release module set is incomplete")
    seen: set[str] = set()
    checksum_lines = []
    for module in modules:
        if not isinstance(module, dict):
            raise ValueError("invalid module record")
        module_id = module.get("id")
        if not isinstance(module_id, str) or module_id not in EXPECTED or module_id in seen:
            raise ValueError("unexpected or duplicate module")
        if set(module) != {
            "id", "module", "binary", "sha256", "size_bytes",
            "test_command", "test_result",
        }:
            raise ValueError("unexpected module fields")
        seen.add(module_id)
        module_path, binary_name = EXPECTED[module_id]
        relative = f"bin/{binary_name}"
        checksum = module.get("sha256")
        if (module.get("module") != module_path or module.get("binary") != relative
            or not isinstance(checksum, str) or not SHA256.fullmatch(checksum)):
            raise ValueError("invalid binary path or checksum")
        if (not isinstance(module.get("size_bytes"), int) or module["size_bytes"] <= 0
            or module.get("test_command") != "go test ./..."
            or module.get("test_result") != "passed"):
            raise ValueError("invalid module test or size record")
        binary = directory / relative
        if binary.is_symlink() or not binary.is_file():
            raise ValueError(f"missing regular binary: {relative}")
        if binary.stat().st_mode & 0o111 == 0:
            raise ValueError(f"binary is not executable: {relative}")
        binary_size = binary.stat().st_size
        if binary_size > MAX_BINARY_BYTES:
            raise ValueError(f"binary is too large: {relative}")
        if binary_size != module["size_bytes"]:
            raise ValueError(f"binary size mismatch: {relative}")
        actual = sha256_file(binary)
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
    allowed.update(f"bin/{name}" for _, name in EXPECTED.values())
    for entry in directory.rglob("*"):
        relative = entry.relative_to(directory).as_posix()
        if relative not in allowed or entry.is_symlink():
            raise ValueError(f"unexpected release content: {relative}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-dir", required=True, type=Path)
    parser.add_argument("--release-id", required=True)
    parser.add_argument("--manifest-sha256", required=True)
    args = parser.parse_args()
    try:
        verify_release(args.release_dir, args.release_id, args.manifest_sha256)
    except ValueError as exc:
        print(f"release verification failed: {exc}", file=sys.stderr)
        return 2
    print(f"Verified ARM64 agent release: {args.release_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
