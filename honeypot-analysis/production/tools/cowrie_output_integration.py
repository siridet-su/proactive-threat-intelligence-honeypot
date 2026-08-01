"""Build, configure, and validate the managed Cowrie output boundary."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import inspect
import json
import os
import re
import shutil
import stat
from pathlib import Path
from typing import Any

from production.cowrie_output.runtime import (
    DEPLOYMENT_CONTRACT,
    EXPECTED_STARTING_SANITIZER_REVISION,
    MANIFEST_NAME,
    MANIFEST_SCHEMA_VERSION,
    REQUIRED_BUNDLE_FILES,
    CowrieOutputBoundaryError,
    verify_boundary,
    verify_bundle,
)
from production.cowrie_output.lifecycle import (
    LifecycleStateError,
    load_lifecycle_state,
    update_lifecycle_state,
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
                "deployment": DEPLOYMENT_CONTRACT,
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
            "deployment": json.loads(json.dumps(DEPLOYMENT_CONTRACT)),
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


def verify_starting_sanitizer(
    current: Path,
    *,
    releases_root: Path = Path("/opt/honeypot-cowrie-output/releases"),
    expected_revision: str = EXPECTED_STARTING_SANITIZER_REVISION,
) -> str:
    """Verify the exact inactive-to-candidate starting link without loading it."""

    try:
        metadata = current.lstat()
    except OSError as exc:
        raise CowrieOutputBoundaryError("starting sanitizer link is unavailable") from exc
    if not stat.S_ISLNK(metadata.st_mode):
        raise CowrieOutputBoundaryError("starting sanitizer path is not a symlink")
    target = current.resolve(strict=True)
    expected = expected_revision
    if target.name != expected or target.parent != releases_root:
        raise CowrieOutputBoundaryError("starting sanitizer revision is unexpected")
    manifest_path = target / MANIFEST_NAME
    try:
        manifest_metadata = manifest_path.lstat()
        document = json.loads(manifest_path.read_bytes())
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise CowrieOutputBoundaryError("starting sanitizer manifest is invalid") from exc
    if (
        not stat.S_ISREG(manifest_metadata.st_mode)
        or manifest_path.is_symlink()
        or stat.S_IMODE(manifest_metadata.st_mode) != 0o600
        or not isinstance(document, dict)
        or document.get("git_revision") != expected
    ):
        raise CowrieOutputBoundaryError("starting sanitizer identity is invalid")
    return expected


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
            "lifecycle_state = var/lib/cowrie/cowrie-output-lifecycle.json\n",
            f"bundle_root = {root}\n",
            f"manifest = {root}/{MANIFEST_NAME}\n",
            f"policy = {root}/configs/cowrie_output_privacy.v1.json\n",
        ]
    )
    _write_exclusive(destination, "".join(rendered).encode("utf-8"))


def inspect_plugin_readiness(boundary, *, write_state: bool = False) -> dict[str, Any]:
    """Inspect Cowrie's effective plugin contract without creating an event."""

    try:
        import cowrie.core.output as output_base
        from cowrie.core.config import CowrieConfig

        enabled = sorted(
            section
            for section in CowrieConfig.sections()
            if section.startswith("output_")
            and CowrieConfig.getboolean(section, "enabled", fallback=False)
        )
        if enabled != ["output_sanitizedjson"]:
            raise CowrieOutputBoundaryError(
                "effective Cowrie output enablement differs from the validated config"
            )
        module = importlib.import_module("cowrie.output.sanitizedjson")
        module_path = Path(module.__file__).resolve(strict=True)
        expected_module = (
            boundary.bundle_root
            / "production/cowrie_output/sanitized_jsonlog.py"
        )
        if module_path != expected_module or _sha256_file(module_path) != boundary.module_sha256:
            raise CowrieOutputBoundaryError("effective Cowrie output module is not manifest-bound")
        output_class = getattr(module, "Output", None)
        if (
            not inspect.isclass(output_class)
            or output_class.__name__ != "Output"
            or output_class.__module__ != "cowrie.output.sanitizedjson"
            or inspect.isabstract(output_class)
            or not issubclass(output_class, output_base.Output)
        ):
            raise CowrieOutputBoundaryError("effective Cowrie output class is invalid")
        output_base_path = Path(output_base.__file__).resolve(strict=True)
        loader_path = output_base_path.parents[2] / "twisted/plugins/cowrie_plugin.py"
        compatibility = DEPLOYMENT_CONTRACT["compatibility"]
        if _sha256_file(output_base_path) != compatibility["cowrie_output_base_sha256"]:
            raise CowrieOutputBoundaryError("Cowrie output base compatibility hash differs")
        if _sha256_file(loader_path) != compatibility["cowrie_output_loader_sha256"]:
            raise CowrieOutputBoundaryError("Cowrie output loader compatibility hash differs")
        cowrie_root = Path(os.environ.get("HONEYPOT_COWRIE_ROOT", ".")).resolve()
        configured_log = CowrieConfig.get(
            "output_sanitizedjson", "logfile", fallback=""
        )
        configured_log_path = Path(configured_log)
        if not configured_log_path.is_absolute():
            configured_log_path = cowrie_root / configured_log_path
        if configured_log_path.resolve() != boundary.json_log_path:
            raise CowrieOutputBoundaryError("effective Cowrie JSON destination differs")
        configured_state = CowrieConfig.get(
            "output_sanitizedjson", "lifecycle_state", fallback=""
        )
        configured_state_path = Path(configured_state)
        if not configured_state_path.is_absolute():
            configured_state_path = cowrie_root / configured_state_path
        if configured_state_path.resolve() != boundary.lifecycle_state_path:
            raise CowrieOutputBoundaryError("effective lifecycle destination differs")
        for directory in (
            boundary.json_log_path.parent,
            boundary.lifecycle_state_path.parent,
        ):
            metadata = directory.lstat()
            if not stat.S_ISDIR(metadata.st_mode) or directory.is_symlink():
                raise CowrieOutputBoundaryError("Cowrie output directory is unsafe")
            if not os.access(directory, os.W_OK | os.X_OK):
                raise CowrieOutputBoundaryError("Cowrie output directory is not writable")
        if write_state:
            update_lifecycle_state(
                boundary.lifecycle_state_path,
                component_id=boundary.component_id,
                source_revision=boundary.git_revision,
                module_sha256=boundary.module_sha256,
                phase="class_discovery",
                result="succeeded",
                flags={"class_discovered": True},
            )
    except (ImportError, AttributeError, OSError, LifecycleStateError) as exc:
        raise CowrieOutputBoundaryError("Cowrie output plugin discovery failed") from exc
    return {
        "schema_version": "cowrie_output_plugin_readiness.v1",
        "status": "ready",
        "component_id": boundary.component_id,
        "source_revision": boundary.git_revision,
        "module_path_category": "manifest_bound_release",
        "module_sha256": boundary.module_sha256,
        "class_name": "Output",
        "class_discovered": True,
        "class_abstract": False,
        "output_section": "output_sanitizedjson",
        "output_directory_writable": True,
        "lifecycle_directory_writable": True,
        "fake_event_created": False,
    }


def validate_live_readiness(boundary, *, expected_pid: int) -> dict[str, Any]:
    state = load_lifecycle_state(boundary.lifecycle_state_path)
    if (
        state["component_id"] != boundary.component_id
        or state["source_revision"] != boundary.git_revision
        or state["module_sha256"] != boundary.module_sha256
        or state["process_pid"] != expected_pid
        or not state["class_discovered"]
        or not state["constructor_entered"]
        or not state["constructor_completed"]
        or not state["start_entered"]
        or not state["start_completed"]
        or not state["observer_registered"]
    ):
        raise CowrieOutputBoundaryError("live Cowrie output lifecycle is not ready")
    return {
        "schema_version": "cowrie_output_live_readiness.v1",
        "status": "ready",
        "component_id": boundary.component_id,
        "source_revision": boundary.git_revision,
        "module_sha256": boundary.module_sha256,
        "process_pid": expected_pid,
        "observer_registered": True,
        "write_invocations": state["write_invocations"],
        "state_sha256": state["state_sha256"],
    }


def validate_live_permissions(boundary) -> None:
    expected_modes = {
        boundary.json_log_path: 0o640,
        boundary.json_log_path.with_name("cowrie.log"): 0o600,
        Path("/home/cowrie/users.txt"): 0o600,
        Path("/home/cowrie/cowrie/var/log/cowrie/cowrie_custom.json"): 0o600,
    }
    expected_owner = boundary.json_log_path.parent.stat()
    for path, expected_mode in expected_modes.items():
        if path.exists() or path.is_symlink():
            metadata = path.lstat()
            if not stat.S_ISREG(metadata.st_mode):
                raise CowrieOutputBoundaryError(
                    f"unsafe persistent-file type: {path}"
                )
            if stat.S_IMODE(metadata.st_mode) != expected_mode:
                raise CowrieOutputBoundaryError(f"unsafe persistent-file mode: {path}")
            if (
                metadata.st_uid != expected_owner.st_uid
                or metadata.st_gid != expected_owner.st_gid
            ):
                raise CowrieOutputBoundaryError(
                    f"unsafe persistent-file ownership: {path}"
                )
    for path in boundary.json_log_path.parent.rglob("*"):
        metadata = path.lstat()
        if stat.S_ISDIR(metadata.st_mode):
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise CowrieOutputBoundaryError(
                f"unsafe historical Cowrie log type: {path}"
            )
        if path != boundary.json_log_path and stat.S_IMODE(metadata.st_mode) != 0o600:
            raise CowrieOutputBoundaryError(f"unsafe historical Cowrie log mode: {path}")
        if metadata.st_uid != expected_owner.st_uid or metadata.st_gid != expected_owner.st_gid:
            raise CowrieOutputBoundaryError(
                f"unsafe historical Cowrie log ownership: {path}"
            )


def _rotation_paths(boundary) -> tuple[Path, Path]:
    return boundary.json_log_path, boundary.json_log_path.with_name("cowrie.log")


def _require_private_regular(path: Path) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise CowrieOutputBoundaryError(f"rotation path is unavailable: {path}") from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise CowrieOutputBoundaryError(f"rotation path is not a regular file: {path}")
    return metadata


def prepare_live_rotation(boundary) -> None:
    """Make active logs owner-only before logrotate creates any copy."""

    expected_owner = boundary.json_log_path.parent.stat()
    for path in _rotation_paths(boundary):
        if not path.exists() and not path.is_symlink():
            continue
        metadata = _require_private_regular(path)
        if metadata.st_uid != expected_owner.st_uid or metadata.st_gid != expected_owner.st_gid:
            raise CowrieOutputBoundaryError(f"rotation path ownership is invalid: {path}")
        path.chmod(0o600)


def finish_live_rotation(boundary) -> None:
    """Restore the active feed mode and close all historical file modes."""

    json_log, text_log = _rotation_paths(boundary)
    expected_owner = json_log.parent.stat()
    for path in json_log.parent.rglob("*"):
        metadata = path.lstat()
        if stat.S_ISDIR(metadata.st_mode):
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise CowrieOutputBoundaryError(f"rotation produced an unsafe file type: {path}")
        if metadata.st_uid != expected_owner.st_uid or metadata.st_gid != expected_owner.st_gid:
            raise CowrieOutputBoundaryError(f"rotation produced unsafe ownership: {path}")
        path.chmod(0o640 if path == json_log else 0o600)
    if text_log.exists() or text_log.is_symlink():
        _require_private_regular(text_log)
        text_log.chmod(0o600)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Manage the manifest-bound Cowrie credential output boundary"
    )
    commands = parser.add_subparsers(dest="command", required=True)

    build = commands.add_parser("build")
    build.add_argument("--source-root", required=True)
    build.add_argument("--bundle-root", required=True)
    build.add_argument("--revision", required=True)

    verify_bundle_command = commands.add_parser("verify-bundle")
    verify_bundle_command.add_argument("--bundle-root", required=True)
    verify_bundle_command.add_argument("--expected-revision", required=True)

    verify_start = commands.add_parser("verify-start")
    verify_start.add_argument("--current", required=True)

    render = commands.add_parser("render-config")
    render.add_argument("--source", required=True)
    render.add_argument("--destination", required=True)
    render.add_argument("--bundle-root", required=True)

    validate = commands.add_parser("validate")
    validate.add_argument("--config", required=True)
    validate.add_argument("--bundle-root", required=True)
    validate.add_argument("--plugin-link")
    validate.add_argument("--drop-in")
    validate.add_argument("--logrotate")
    validate.add_argument("--live-permissions", action="store_true")

    plugin_readiness = commands.add_parser("plugin-readiness")
    plugin_readiness.add_argument("--config", required=True)
    plugin_readiness.add_argument("--bundle-root", required=True)
    plugin_readiness.add_argument("--plugin-link", required=True)
    plugin_readiness.add_argument("--write-state", action="store_true")

    live_readiness = commands.add_parser("live-readiness")
    live_readiness.add_argument("--config", required=True)
    live_readiness.add_argument("--bundle-root", required=True)
    live_readiness.add_argument("--expected-pid", required=True, type=int)

    for name in ("prepare-rotation", "finish-rotation"):
        rotation = commands.add_parser(name)
        rotation.add_argument("--config", required=True)
        rotation.add_argument("--bundle-root", required=True)

    args = parser.parse_args()
    if args.command == "build":
        manifest = build_bundle(
            Path(args.source_root), Path(args.bundle_root), args.revision
        )
        print(json.dumps(manifest, sort_keys=True))
        return 0
    if args.command == "verify-bundle":
        try:
            manifest, _path, digest = verify_bundle(Path(args.bundle_root))
            if manifest["git_revision"] != args.expected_revision:
                raise CowrieOutputBoundaryError("bundle revision does not match installation")
        except (CowrieOutputBoundaryError, OSError, ValueError) as exc:
            print(
                json.dumps(
                    {
                        "schema_version": "cowrie_output_package_verification.v1",
                        "status": "invalid",
                        "error_category": type(exc).__name__,
                    },
                    sort_keys=True,
                )
            )
            return 2
        print(
            json.dumps(
                {
                    "schema_version": "cowrie_output_package_verification.v1",
                    "status": "valid",
                    "git_revision": manifest["git_revision"],
                    "manifest_sha256": digest,
                    "component_id": manifest["component_id"],
                },
                sort_keys=True,
            )
        )
        return 0
    if args.command == "verify-start":
        try:
            revision = verify_starting_sanitizer(Path(args.current))
        except (CowrieOutputBoundaryError, OSError, ValueError) as exc:
            print(
                json.dumps(
                    {
                        "schema_version": "cowrie_output_starting_boundary.v1",
                        "status": "invalid",
                        "error_category": type(exc).__name__,
                    },
                    sort_keys=True,
                )
            )
            return 2
        print(
            json.dumps(
                {
                    "schema_version": "cowrie_output_starting_boundary.v1",
                    "status": "valid",
                    "sanitizer_revision": revision,
                },
                sort_keys=True,
            )
        )
        return 0
    if args.command == "render-config":
        render_config(Path(args.source), Path(args.destination), Path(args.bundle_root))
        return 0
    if args.command in {"prepare-rotation", "finish-rotation"}:
        try:
            result = verify_boundary(
                config_path=args.config,
                bundle_root=args.bundle_root,
            )
            if args.command == "prepare-rotation":
                prepare_live_rotation(result)
            else:
                finish_live_rotation(result)
        except (CowrieOutputBoundaryError, ValueError, OSError) as exc:
            print(
                json.dumps(
                    {
                        "schema_version": "cowrie_output_rotation.v1",
                        "status": "invalid",
                        "operation": args.command,
                        "error": str(exc),
                    },
                    sort_keys=True,
                )
            )
            return 2
        print(
            json.dumps(
                {
                    "schema_version": "cowrie_output_rotation.v1",
                    "status": "valid",
                    "operation": args.command,
                },
                sort_keys=True,
            )
        )
        return 0
    if args.command in {"plugin-readiness", "live-readiness"}:
        try:
            result = verify_boundary(
                config_path=args.config,
                bundle_root=args.bundle_root,
                plugin_link=(
                    args.plugin_link if args.command == "plugin-readiness" else None
                ),
            )
            if args.command == "plugin-readiness":
                receipt = inspect_plugin_readiness(
                    result, write_state=args.write_state
                )
            else:
                receipt = validate_live_readiness(
                    result, expected_pid=args.expected_pid
                )
        except (
            CowrieOutputBoundaryError,
            LifecycleStateError,
            OSError,
            ValueError,
        ) as exc:
            print(
                json.dumps(
                    {
                        "schema_version": (
                            "cowrie_output_plugin_readiness.v1"
                            if args.command == "plugin-readiness"
                            else "cowrie_output_live_readiness.v1"
                        ),
                        "status": "not_ready",
                        "error_category": type(exc).__name__,
                    },
                    sort_keys=True,
                )
            )
            return 2
        print(json.dumps(receipt, sort_keys=True))
        return 0
    try:
        result = verify_boundary(
            config_path=args.config,
            bundle_root=args.bundle_root,
            plugin_link=args.plugin_link,
            drop_in=args.drop_in,
            logrotate=args.logrotate,
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
