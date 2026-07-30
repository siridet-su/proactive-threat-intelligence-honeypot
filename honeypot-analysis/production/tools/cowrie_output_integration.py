"""Build, configure, and validate the managed Cowrie output boundary."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
from pathlib import Path
from typing import Any

from production.cowrie_output.runtime import (
    MANIFEST_NAME,
    MANIFEST_SCHEMA_VERSION,
    REQUIRED_BUNDLE_FILES,
    CowrieOutputBoundaryError,
    verify_boundary,
)
from production.utils.cowrie_privacy import load_policy


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _write_exclusive(path: Path, payload: bytes, mode: int = 0o600) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _expected_mode(relative: str) -> int:
    return 0o700 if relative.endswith(".sh") else 0o600


def build_bundle(source_root: Path, bundle_root: Path, revision: str) -> dict[str, Any]:
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("revision must be a full lowercase Git SHA-1")
    if bundle_root.exists():
        raise FileExistsError("bundle destination already exists")
    bundle_root.mkdir(parents=True, mode=0o700)
    try:
        inventory: dict[str, dict[str, Any]] = {}
        for relative in sorted(REQUIRED_BUNDLE_FILES):
            source = source_root / relative
            if not source.is_file() or source.is_symlink():
                raise ValueError(f"required source file is absent or unsafe: {relative}")
            destination = bundle_root / relative
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            shutil.copyfile(source, destination)
            mode = _expected_mode(relative)
            destination.chmod(mode)
            inventory[relative] = {
                "bytes": destination.stat().st_size,
                "sha256": _sha256_file(destination),
                "mode": f"{mode:04o}",
            }
        for directory in [bundle_root, *bundle_root.rglob("*")]:
            if directory.is_dir():
                directory.chmod(0o700)
        policy_relative = "configs/cowrie_output_privacy.v1.json"
        policy = load_policy(bundle_root / policy_relative)
        identity_payload = json.dumps(
            {
                "git_revision": revision,
                "files": inventory,
                "policy_sha256": policy.sha256,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        manifest = {
            "schema_version": MANIFEST_SCHEMA_VERSION,
            "git_revision": revision,
            "component_id": "cowrie_output_" + hashlib.sha256(identity_payload).hexdigest()[:32],
            "files": inventory,
            "policy": {
                "relative_path": policy_relative,
                "policy_id": policy.policy_id,
                "version": policy.version,
                "sha256": policy.sha256,
            },
        }
        _write_exclusive(
            bundle_root / MANIFEST_NAME,
            (
                json.dumps(manifest, sort_keys=True, separators=(",", ":"))
                + "\n"
            ).encode("utf-8"),
        )
        return manifest
    except BaseException:
        shutil.rmtree(bundle_root, ignore_errors=True)
        raise


def _replace_enabled(section_lines: list[str], enabled: bool) -> list[str]:
    replacement = f"enabled = {'true' if enabled else 'false'}\n"
    result: list[str] = []
    replaced = False
    for line in section_lines:
        if re.match(r"^\s*enabled\s*=", line, flags=re.IGNORECASE):
            if replaced:
                raise ValueError("configuration section has duplicate enabled options")
            result.append(replacement)
            replaced = True
        else:
            result.append(line)
    if not replaced:
        result.append(replacement)
    return result


def render_config(source: Path, destination: Path, bundle_root: Path) -> None:
    try:
        lines = source.read_text(encoding="utf-8").splitlines(keepends=True)
    except (OSError, UnicodeDecodeError) as exc:
        raise ValueError("source Cowrie configuration is unreadable") from exc
    sections: list[tuple[str, int, int]] = []
    starts: list[tuple[str, int]] = []
    for index, line in enumerate(lines):
        match = re.match(r"^\s*\[([^\]]+)\]\s*(?:[#;].*)?$", line)
        if match:
            starts.append((match.group(1).strip().lower(), index))
    for position, (name, start) in enumerate(starts):
        end = starts[position + 1][1] if position + 1 < len(starts) else len(lines)
        sections.append((name, start, end))
    if sum(name == "output_jsonlog" for name, _, _ in sections) != 1:
        raise ValueError("configuration must contain exactly one output_jsonlog section")
    if sum(name == "output_sanitizedjson" for name, _, _ in sections) > 1:
        raise ValueError("configuration contains duplicate output_sanitizedjson sections")
    rendered: list[str] = []
    cursor = 0
    for name, start, end in sections:
        rendered.extend(lines[cursor:start])
        if name == "output_sanitizedjson":
            cursor = end
            continue
        block = lines[start:end]
        if name == "output_jsonlog":
            block = [block[0], *_replace_enabled(block[1:], False)]
        rendered.extend(block)
        cursor = end
    rendered.extend(lines[cursor:])
    if rendered and not rendered[-1].endswith("\n"):
        rendered[-1] += "\n"
    root = str(bundle_root)
    rendered.extend(
        [
            "\n[output_sanitizedjson]\n",
            "enabled = true\n",
            "epoch_timestamp = false\n",
            "logfile = ${honeypot:log_path}/cowrie.json\n",
            f"bundle_root = {root}\n",
            f"manifest = {root}/{MANIFEST_NAME}\n",
            f"policy = {root}/configs/cowrie_output_privacy.v1.json\n",
        ]
    )
    _write_exclusive(destination, "".join(rendered).encode("utf-8"))


def validate_live_permissions(boundary) -> None:
    expected_modes = {
        boundary.json_log_path: 0o640,
        boundary.json_log_path.with_name("cowrie.log"): 0o600,
        Path("/home/cowrie/users.txt"): 0o600,
        Path("/home/cowrie/cowrie/var/log/cowrie/cowrie_custom.json"): 0o600,
    }
    for path, expected_mode in expected_modes.items():
        if path.exists() and stat.S_IMODE(path.stat().st_mode) != expected_mode:
            raise CowrieOutputBoundaryError(f"unsafe persistent-file mode: {path}")
    for path in boundary.json_log_path.parent.rglob("*"):
        if (
            path.is_file()
            and path != boundary.json_log_path
            and stat.S_IMODE(path.stat().st_mode) != 0o600
        ):
            raise CowrieOutputBoundaryError(
                f"unsafe historical Cowrie log mode: {path}"
            )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Manage the manifest-bound Cowrie credential output boundary"
    )
    commands = parser.add_subparsers(dest="command", required=True)

    build = commands.add_parser("build")
    build.add_argument("--source-root", required=True)
    build.add_argument("--bundle-root", required=True)
    build.add_argument("--revision", required=True)

    render = commands.add_parser("render-config")
    render.add_argument("--source", required=True)
    render.add_argument("--destination", required=True)
    render.add_argument("--bundle-root", required=True)

    validate = commands.add_parser("validate")
    validate.add_argument("--config", required=True)
    validate.add_argument("--bundle-root", required=True)
    validate.add_argument("--plugin-link")
    validate.add_argument("--drop-in")
    validate.add_argument("--live-permissions", action="store_true")

    args = parser.parse_args()
    if args.command == "build":
        manifest = build_bundle(
            Path(args.source_root), Path(args.bundle_root), args.revision
        )
        print(json.dumps(manifest, sort_keys=True))
        return 0
    if args.command == "render-config":
        render_config(Path(args.source), Path(args.destination), Path(args.bundle_root))
        return 0
    try:
        result = verify_boundary(
            config_path=args.config,
            bundle_root=args.bundle_root,
            plugin_link=args.plugin_link,
            drop_in=args.drop_in,
        )
        if args.live_permissions:
            validate_live_permissions(result)
    except (CowrieOutputBoundaryError, ValueError, OSError) as exc:
        print(
            json.dumps(
                {
                    "schema_version": "cowrie_output_boundary_validation.v1",
                    "status": "invalid",
                    "error": str(exc),
                },
                sort_keys=True,
            )
        )
        return 2
    print(
        json.dumps(
            {
                "schema_version": "cowrie_output_boundary_validation.v1",
                "status": "valid",
                "git_revision": result.git_revision,
                "manifest_sha256": result.manifest_sha256,
                "policy_sha256": result.policy.sha256,
                "json_log_path": str(result.json_log_path),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
