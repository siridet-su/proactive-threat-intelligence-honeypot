"""Build, configure, and validate the managed Cowrie output boundary."""

from __future__ import annotations

import argparse
import grp
import hashlib
import importlib
import inspect
import json
import os
import pwd
import re
import shutil
import stat
import tarfile
from pathlib import Path
from typing import Any, Callable

from production.cowrie_output.runtime import (
    DEPLOYMENT_CONTRACT,
    EXPECTED_STARTING_SANITIZER_REVISION,
    MANIFEST_NAME,
    MANIFEST_SCHEMA_VERSION,
    REQUIRED_BUNDLE_FILES,
    CowrieOutputBoundaryError,
    expected_bundle_mode,
    expected_file_installation,
    load_manifest_bytes,
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
            mode = expected_bundle_mode(relative)
            destination.chmod(mode)
            inventory[relative] = {
                **expected_file_installation(relative, revision),
                "bytes": destination.stat().st_size,
                "sha256": _sha256_file(destination),
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
        "component_id": (
            "cowrie_output_" + hashlib.sha256(identity_payload).hexdigest()[:32]
        ),
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


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _safe_archive_name(value: str) -> str:
    while value.startswith("./"):
        value = value[2:]
    path = Path(value)
    if (
        not value
        or value == "."
        or path.is_absolute()
        or ".." in path.parts
        or "\\" in value
        or any(ord(character) < 32 for character in value)
    ):
        raise CowrieOutputBoundaryError("package contains an unsafe archive path")
    return str(path)


def extract_verified_package(
    package: Path,
    staging_root: Path,
    expected_revision: str,
    *,
    fault: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Safely extract and verify a closed package before runtime mutation."""

    if staging_root.exists() or staging_root.is_symlink():
        raise CowrieOutputBoundaryError("package staging destination already exists")
    try:
        package_metadata = package.lstat()
    except OSError as exc:
        raise CowrieOutputBoundaryError("package archive is unavailable") from exc
    if not stat.S_ISREG(package_metadata.st_mode) or package.is_symlink():
        raise CowrieOutputBoundaryError("package archive is not a regular file")
    fault = fault or (lambda _step: None)
    staging_root.mkdir(parents=False, mode=0o700)
    try:
        fault("staging_created")
        with tarfile.open(package, mode="r:") as archive:
            members: dict[str, tarfile.TarInfo] = {}
            for member in archive.getmembers():
                if member.name in {".", "./"}:
                    if not member.isdir():
                        raise CowrieOutputBoundaryError(
                            "package root entry is not a directory"
                        )
                    continue
                name = _safe_archive_name(member.name)
                if name in members:
                    raise CowrieOutputBoundaryError(
                        "package contains duplicate archive paths"
                    )
                if not (member.isfile() or member.isdir()):
                    raise CowrieOutputBoundaryError(
                        "package contains a link or special file"
                    )
                members[name] = member
            manifest_member = members.get(MANIFEST_NAME)
            if manifest_member is None or not manifest_member.isfile():
                raise CowrieOutputBoundaryError("package manifest is absent")
            if manifest_member.size > 4 * 1024 * 1024:
                raise CowrieOutputBoundaryError("package manifest exceeds its size limit")
            manifest_handle = archive.extractfile(manifest_member)
            if manifest_handle is None:
                raise CowrieOutputBoundaryError("package manifest is unreadable")
            manifest_raw = manifest_handle.read()
            manifest = load_manifest_bytes(manifest_raw)
            if manifest["git_revision"] != expected_revision:
                raise CowrieOutputBoundaryError("package revision does not match installation")
            expected_files = set(REQUIRED_BUNDLE_FILES) | {MANIFEST_NAME}
            expected_directories: set[str] = set()
            for name in expected_files:
                expected_directories.update(
                    str(parent)
                    for parent in Path(name).parents
                    if str(parent) != "."
                )
            observed_files = {
                name for name, member in members.items() if member.isfile()
            }
            observed_directories = {
                name for name, member in members.items() if member.isdir()
            }
            if (
                observed_files != expected_files
                or observed_directories != expected_directories
            ):
                raise CowrieOutputBoundaryError("package archive inventory is not closed")
            for directory in sorted(
                expected_directories, key=lambda item: len(Path(item).parts)
            ):
                member = members[directory]
                if stat.S_IMODE(member.mode) != 0o700:
                    raise CowrieOutputBoundaryError("package directory mode is invalid")
                destination = staging_root / directory
                destination.mkdir(mode=0o700)
            for name in sorted(expected_files):
                member = members[name]
                expected_mode = (
                    0o600
                    if name == MANIFEST_NAME
                    else int(manifest["files"][name]["mode"], 8)
                )
                if stat.S_IMODE(member.mode) != expected_mode:
                    raise CowrieOutputBoundaryError(f"package archive mode mismatch: {name}")
                if (
                    name != MANIFEST_NAME
                    and member.size != manifest["files"][name]["bytes"]
                ):
                    raise CowrieOutputBoundaryError(f"package archive size mismatch: {name}")
                source = archive.extractfile(member)
                if source is None:
                    raise CowrieOutputBoundaryError(f"package file is unreadable: {name}")
                destination = staging_root / name
                descriptor = os.open(
                    destination,
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_NOFOLLOW", 0),
                    expected_mode,
                )
                try:
                    with os.fdopen(descriptor, "wb") as output:
                        shutil.copyfileobj(source, output)
                        output.flush()
                        os.fsync(output.fileno())
                finally:
                    source.close()
                destination.chmod(expected_mode)
                fault(f"staged_file:{name}")
            for directory in sorted(
                [
                    staging_root,
                    *(path for path in staging_root.rglob("*") if path.is_dir()),
                ],
                key=lambda item: len(item.parts),
                reverse=True,
            ):
                directory.chmod(0o700)
                _fsync_directory(directory)
        verify_bundle(staging_root)
        fault("staged_inventory_verified")
        return manifest
    except BaseException:
        shutil.rmtree(staging_root, ignore_errors=True)
        raise


def create_deterministic_package(bundle_root: Path, package: Path) -> str:
    """Create a byte-reproducible closed tar archive from a verified bundle."""

    _manifest, _manifest_path, manifest_sha256 = verify_bundle(bundle_root)
    if package.exists() or package.is_symlink():
        raise CowrieOutputBoundaryError("package destination already exists")
    expected_files = sorted({*REQUIRED_BUNDLE_FILES, MANIFEST_NAME})
    directories = sorted(
        {
            str(parent)
            for name in expected_files
            for parent in Path(name).parents
            if str(parent) != "."
        }
    )

    def metadata(name: str, *, mode: int, directory: bool) -> tarfile.TarInfo:
        member = tarfile.TarInfo(name)
        member.type = tarfile.DIRTYPE if directory else tarfile.REGTYPE
        member.mode = mode
        member.uid = 0
        member.gid = 0
        member.uname = "root"
        member.gname = "root"
        member.mtime = 0
        return member

    try:
        with tarfile.open(package, mode="x:", format=tarfile.GNU_FORMAT) as archive:
            archive.addfile(metadata(".", mode=0o700, directory=True))
            for directory in directories:
                archive.addfile(
                    metadata(f"./{directory}", mode=0o700, directory=True)
                )
            for name in expected_files:
                source = bundle_root / name
                mode = stat.S_IMODE(source.stat().st_mode)
                member = metadata(f"./{name}", mode=mode, directory=False)
                member.size = source.stat().st_size
                with source.open("rb") as handle:
                    archive.addfile(member, handle)
        descriptor = os.open(package, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        _fsync_directory(package.parent)
        return manifest_sha256
    except BaseException:
        package.unlink(missing_ok=True)
        raise


def install_verified_bundle(
    staging_root: Path,
    release_root: Path,
    expected_revision: str,
    *,
    enforce_canonical_destination: bool = True,
    owner_uid: int | None = None,
    group_gid: int | None = None,
    fault: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Install each immutable file with manifest-declared metadata and verify it."""

    manifest, manifest_path, _digest = verify_bundle(staging_root)
    if manifest["git_revision"] != expected_revision:
        raise CowrieOutputBoundaryError("staged bundle revision does not match")
    canonical = Path(f"/opt/honeypot-cowrie-output/releases/{expected_revision}")
    if enforce_canonical_destination and release_root != canonical:
        raise CowrieOutputBoundaryError("release destination is not canonical")
    if release_root.exists() or release_root.is_symlink():
        raise CowrieOutputBoundaryError("release destination already exists")
    uid = pwd.getpwnam("cowrie").pw_uid if owner_uid is None else owner_uid
    gid = grp.getgrnam("cowrie").gr_gid if group_gid is None else group_gid
    fault = fault or (lambda _step: None)
    release_root.mkdir(mode=0o700)
    os.chown(release_root, uid, gid)
    release_root.chmod(0o700)
    try:
        fault("release_created")
        for relative in sorted(REQUIRED_BUNDLE_FILES):
            receipt = manifest["files"][relative]
            expected_destination = canonical / relative
            if Path(receipt["destination"]) != expected_destination:
                raise CowrieOutputBoundaryError(
                    f"manifest destination mismatch: {relative}"
                )
            source = staging_root / relative
            destination = release_root / relative
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            parent = destination.parent
            while parent != release_root.parent:
                os.chown(parent, uid, gid)
                parent.chmod(0o700)
                if parent == release_root:
                    break
                parent = parent.parent
            mode = int(receipt["mode"], 8)
            descriptor = os.open(
                destination,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_NOFOLLOW", 0),
                mode,
            )
            with os.fdopen(descriptor, "wb") as output, source.open(
                "rb"
            ) as input_file:
                shutil.copyfileobj(input_file, output)
                output.flush()
                os.fsync(output.fileno())
            os.chown(destination, uid, gid)
            destination.chmod(mode)
            if (
                destination.stat().st_size != receipt["bytes"]
                or _sha256_file(destination) != receipt["sha256"]
                or stat.S_IMODE(destination.stat().st_mode) != mode
                or bool(mode & 0o111) != receipt["executable"]
            ):
                raise CowrieOutputBoundaryError(
                    f"installed bundle metadata mismatch: {relative}"
                )
            _fsync_directory(destination.parent)
            fault(f"installed_file:{relative}")
        installed_manifest = release_root / MANIFEST_NAME
        descriptor = os.open(
            installed_manifest,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        with os.fdopen(descriptor, "wb") as output, manifest_path.open(
            "rb"
        ) as input_file:
            shutil.copyfileobj(input_file, output)
            output.flush()
            os.fsync(output.fileno())
        os.chown(installed_manifest, uid, gid)
        installed_manifest.chmod(0o600)
        _fsync_directory(release_root)
        fault("manifest_installed")
        verify_bundle(release_root)
        for path in [
            release_root,
            *(item for item in release_root.rglob("*") if item.is_dir()),
        ]:
            metadata = path.stat()
            if (
                stat.S_IMODE(metadata.st_mode) != 0o700
                or metadata.st_uid != uid
                or metadata.st_gid != gid
            ):
                raise CowrieOutputBoundaryError("installed bundle directory metadata mismatch")
        for relative in [*sorted(REQUIRED_BUNDLE_FILES), MANIFEST_NAME]:
            metadata = (release_root / relative).lstat()
            if metadata.st_uid != uid or metadata.st_gid != gid:
                raise CowrieOutputBoundaryError("installed bundle ownership mismatch")
        fault("installed_inventory_verified")
        return manifest
    except BaseException:
        shutil.rmtree(release_root, ignore_errors=True)
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


def _replace_option(
    section_lines: list[str], option: str, value: str
) -> list[str]:
    replacement = f"{option} = {value}\n"
    result: list[str] = []
    replaced = False
    pattern = re.compile(rf"^\s*{re.escape(option)}\s*=", re.IGNORECASE)
    for line in section_lines:
        if pattern.match(line):
            if replaced:
                raise ValueError(
                    f"configuration section has duplicate {option} options"
                )
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
    if sum(name == "honeypot" for name, _, _ in sections) != 1:
        raise ValueError("configuration must contain exactly one honeypot section")
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
        if name == "honeypot":
            block = [block[0], *_replace_option(block[1:], "ttylog", "false")]
        elif name == "output_jsonlog":
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

    extract_package_command = commands.add_parser("extract-package")
    extract_package_command.add_argument("--package", required=True)
    extract_package_command.add_argument("--staging-root", required=True)
    extract_package_command.add_argument("--expected-revision", required=True)

    package_command = commands.add_parser("package")
    package_command.add_argument("--bundle-root", required=True)
    package_command.add_argument("--package", required=True)

    install_bundle_command = commands.add_parser("install-bundle")
    install_bundle_command.add_argument("--staging-root", required=True)
    install_bundle_command.add_argument("--release-root", required=True)
    install_bundle_command.add_argument("--expected-revision", required=True)

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
    if args.command in {"extract-package", "install-bundle", "package"}:
        try:
            if args.command == "extract-package":
                manifest = extract_verified_package(
                    Path(args.package),
                    Path(args.staging_root),
                    args.expected_revision,
                )
                operation = "package_extracted"
            elif args.command == "install-bundle":
                manifest = install_verified_bundle(
                    Path(args.staging_root),
                    Path(args.release_root),
                    args.expected_revision,
                )
                operation = "bundle_installed"
            else:
                manifest, _path, _digest = verify_bundle(Path(args.bundle_root))
                create_deterministic_package(
                    Path(args.bundle_root), Path(args.package)
                )
                operation = "package_created"
        except (CowrieOutputBoundaryError, OSError, ValueError, tarfile.TarError) as exc:
            print(
                json.dumps(
                    {
                        "schema_version": "cowrie_output_package_installation.v1",
                        "status": "invalid",
                        "operation": args.command,
                        "error_category": type(exc).__name__,
                    },
                    sort_keys=True,
                )
            )
            return 2
        print(
            json.dumps(
                {
                    "schema_version": "cowrie_output_package_installation.v1",
                    "status": "valid",
                    "operation": operation,
                    "git_revision": manifest["git_revision"],
                    "component_id": manifest["component_id"],
                },
                sort_keys=True,
            )
        )
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
