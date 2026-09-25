#!/usr/bin/env python3
"""Build a clean, checksummed Linux ARM64 release of the Go sensor agents.

This tool only builds artifacts into a new, explicitly selected output path. It
does not install them, change service state, or copy runtime configuration.
Go module downloads and automatic toolchain downloads are disabled.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence


REPO_ROOT = Path(__file__).resolve().parents[1]
RELEASE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
GO_VERSION_PATTERN = re.compile(r"go(\d+)\.(\d+)(?:\.(\d+))?")
GO_DIRECTIVE_PATTERN = re.compile(r"^go\s+(\d+)\.(\d+)(?:\.(\d+))?\s*$", re.MULTILINE)

AGENTS = (
    ("collector", "agents/collector-agent", "pti-collector"),
    ("processor", "agents/processor-agent", "pti-processor"),
    ("ti-worker", "agents/ti-worker", "pti-ti-worker"),
    ("hardware-agent", "agents/hardware-agent", "pti-hardware-agent"),
    ("hardware-backup", "agents/hardware-backup", "pti-hardware-backup"),
    ("response-agent", "agents/response-agent", "pti-response-agent"),
)


class ReleaseBuildError(RuntimeError):
    """Raised when the source tree or build environment is not release-ready."""


def validate_release_id(release_id: str) -> None:
    if not RELEASE_ID_PATTERN.fullmatch(release_id) or release_id in {".", ".."}:
        raise ReleaseBuildError(
            "release ID must be 1-64 safe letters, numbers, dots, underscores, or hyphens"
        )


def parse_go_version(version_text: str) -> tuple[int, int, int]:
    match = GO_VERSION_PATTERN.search(version_text)
    if not match:
        raise ReleaseBuildError(f"cannot parse Go version: {version_text!r}")
    major, minor, patch = match.groups()
    return int(major), int(minor), int(patch or 0)


def module_go_requirement(module_path: str) -> tuple[int, int, int]:
    go_mod = REPO_ROOT / module_path / "go.mod"
    try:
        contents = go_mod.read_text(encoding="utf-8")
    except OSError as exc:
        raise ReleaseBuildError(f"cannot read {go_mod}: {exc}") from exc
    match = GO_DIRECTIVE_PATTERN.search(contents)
    if not match:
        raise ReleaseBuildError(f"no supported Go version directive in {go_mod}")
    major, minor, patch = match.groups()
    return int(major), int(minor), int(patch or 0)


def release_plan(release_id: str) -> dict[str, object]:
    validate_release_id(release_id)
    return {
        "release_id": release_id,
        "target": {"goos": "linux", "goarch": "arm64", "cgo_enabled": False},
        "source_root": str(REPO_ROOT),
        "agents": [
            {"id": agent_id, "module": module_path, "binary": binary_name}
            for agent_id, module_path, binary_name in AGENTS
        ],
        "actions": [
            "verify selected Go module source is clean",
            "run each module's Go tests with a sanitized environment",
            "cross-build each binary for Linux ARM64",
            "write a manifest and SHA-256 checksums",
        ],
        "network_policy": "Go module and toolchain downloads disabled",
        "install_or_service_changes": False,
    }


def _run(
    command: Sequence[str],
    *,
    cwd: Path,
    env: dict[str, str],
    capture_output: bool = False,
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command,
            cwd=cwd,
            env=env,
            text=True,
            check=True,
            capture_output=capture_output,
        )
    except FileNotFoundError as exc:
        raise ReleaseBuildError(f"required command not found: {command[0]}") from exc
    except subprocess.CalledProcessError as exc:
        if capture_output:
            detail = (exc.stderr or exc.stdout or "").strip()
            raise ReleaseBuildError(f"command failed ({' '.join(command)}): {detail}") from exc
        raise ReleaseBuildError(f"command failed ({' '.join(command)})") from exc


def _source_commit() -> str:
    result = _run(
        ["git", "rev-parse", "--verify", "HEAD^{commit}"],
        cwd=REPO_ROOT,
        env=_safe_go_env(),
        capture_output=True,
    )
    return result.stdout.strip()


def _require_clean_agent_sources() -> None:
    module_paths = [module_path for _, module_path, _ in AGENTS]
    result = _run(
        ["git", "status", "--porcelain=v1", "--untracked-files=all", "--", *module_paths],
        cwd=REPO_ROOT,
        env=_safe_go_env(),
        capture_output=True,
    )
    if result.stdout.strip():
        raise ReleaseBuildError(
            "Go agent source tree is dirty; review/commit module changes before release build"
        )


def _safe_go_env() -> dict[str, str]:
    """Drop inherited app/secret variables so tests cannot reach configured services."""
    path = os.environ.get("PATH", "/usr/bin:/bin")
    home = str(Path.home())
    return {
        "PATH": path,
        "HOME": home,
        "GOTOOLCHAIN": "local",
        "GOPROXY": "off",
        "GOFLAGS": "-mod=readonly",
    }


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_release(release_id: str, output_root: Path) -> Path:
    validate_release_id(release_id)
    _require_clean_agent_sources()

    go_result = _run(
        ["go", "version"], cwd=REPO_ROOT, env=_safe_go_env(), capture_output=True
    )
    go_version_text = go_result.stdout.strip()
    actual_go_version = parse_go_version(go_version_text)
    required_go_version = max(module_go_requirement(module_path) for _, module_path, _ in AGENTS)
    if actual_go_version < required_go_version:
        raise ReleaseBuildError(
            f"Go {actual_go_version} is older than module minimum {required_go_version}"
        )

    output_root = output_root.expanduser().resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    destination = output_root / release_id
    if destination.exists() or destination.is_symlink():
        raise ReleaseBuildError(f"output already exists; refusing to overwrite: {destination}")

    base_env = _safe_go_env()
    source_commit = _source_commit()
    built_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()

    try:
        with tempfile.TemporaryDirectory(prefix=f".{release_id}.tmp-", dir=output_root) as temp_dir:
            staging = Path(temp_dir)
            bin_dir = staging / "bin"
            bin_dir.mkdir()
            module_results = []

            for agent_id, module_path, binary_name in AGENTS:
                module_root = REPO_ROOT / module_path
                print(f"[test] {agent_id}", flush=True)
                _run(["go", "test", "./..."], cwd=module_root, env=base_env)

                print(f"[build] {agent_id} -> linux/arm64", flush=True)
                build_env = {
                    **base_env,
                    "GOOS": "linux",
                    "GOARCH": "arm64",
                    "CGO_ENABLED": "0",
                }
                binary_path = bin_dir / binary_name
                _run(
                    [
                        "go",
                        "build",
                        "-trimpath",
                        "-buildvcs=false",
                        "-o",
                        str(binary_path),
                        ".",
                    ],
                    cwd=module_root,
                    env=build_env,
                )
                module_results.append(
                    {
                        "id": agent_id,
                        "module": module_path,
                        "binary": f"bin/{binary_name}",
                        "sha256": _sha256(binary_path),
                        "size_bytes": binary_path.stat().st_size,
                        "test_command": "go test ./...",
                        "test_result": "passed",
                    }
                )

            manifest = {
                "schema_version": "pti.sensor-release.v1",
                "release_id": release_id,
                "source_commit": source_commit,
                "built_at_utc": built_at,
                "go_version": go_version_text,
                "target": {"goos": "linux", "goarch": "arm64", "cgo_enabled": False},
                "module_downloads": "disabled; dependencies must already be cached",
                "runtime_configuration_included": False,
                "modules": module_results,
            }
            (staging / "manifest.json").write_text(
                json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            checksum_lines = [
                f"{entry['sha256']}  {entry['binary']}"
                for entry in module_results
            ]
            (staging / "SHA256SUMS").write_text(
                "\n".join(checksum_lines) + "\n", encoding="utf-8"
            )
            os.replace(staging, destination)
    except OSError as exc:
        raise ReleaseBuildError(f"cannot publish release under {output_root}: {exc}") from exc

    return destination


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build tested, checksummed Linux ARM64 Go sensor-agent artifacts."
    )
    parser.add_argument("--release-id", required=True, help="immutable version/build label")
    parser.add_argument(
        "--output-root", type=Path, help="explicit directory where a new release folder is created"
    )
    parser.add_argument(
        "--plan", action="store_true", help="print the build plan without invoking Go or writing files"
    )
    args = parser.parse_args(argv)

    try:
        plan = release_plan(args.release_id)
        if args.plan:
            print(json.dumps(plan, indent=2, sort_keys=True))
            return 0
        if args.output_root is None:
            parser.error("--output-root is required unless --plan is selected")
        release_dir = build_release(args.release_id, args.output_root)
    except ReleaseBuildError as exc:
        print(f"release build error: {exc}", file=sys.stderr)
        return 2

    print(f"Release artifacts created: {release_dir}")
    print("No host installation or service changes were performed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
