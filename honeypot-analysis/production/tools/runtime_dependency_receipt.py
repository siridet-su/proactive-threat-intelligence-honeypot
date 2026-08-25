"""Build and verify immutable Python runtime and dependency receipts.

The application release, frozen model bundle, Python runtime, and offline wheel
bundle have different ownership and lifecycle boundaries.  This module binds
the runtime and dependency artifacts without representing either as a model
artifact or embedding host-specific paths in the application release manifest.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import stat
import tarfile
import zipfile
from datetime import datetime, timezone
from email.parser import Parser
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping, Sequence

from production.utils.serialization import stable_json


RUNTIME_MANIFEST_SCHEMA = "python_runtime_bundle.v1"
WHEEL_MANIFEST_SCHEMA = "python_wheel_bundle.v1"
RECEIPT_SCHEMA = "runtime_dependency_receipt.v1"
BUILD_ENVIRONMENT_SCHEMA = "python_runtime_build_environment.v1"
FROZEN_PYTHON_VERSION = "3.12.13"
FROZEN_LOCK_FILENAME = "requirements-runtime.lock.txt"
FROZEN_LOCK_SHA256 = (
    "8d5cf671c79e7c6127d7573fe291d36c189cdfa62da74cd12005e52c82b25bd6"
)
FROZEN_REQUIREMENT_COUNT = 54
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
REQUIREMENT_RE = re.compile(r"^([A-Za-z0-9_.-]+)==([^\s]+)$")
ID_RE = re.compile(r"^[a-z][a-z0-9_]*_[0-9a-f]{64}$")
RUNTIME_PREFIX = "/opt/honeypot-python-runtimes/"
PYTHON_SOURCE_URL = (
    "https://www.python.org/ftp/python/3.12.13/Python-3.12.13.tar.xz"
)


class RuntimeDependencyReceiptError(ValueError):
    """A runtime/dependency manifest or artifact failed closed validation."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_stream(stream: Any) -> str:
    digest = hashlib.sha256()
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
        digest.update(chunk)
    return digest.hexdigest()


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(stable_json(value).encode("utf-8")).hexdigest()


def _require_exact_keys(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise RuntimeDependencyReceiptError(f"{label} fields are invalid")


def _require_sha256(value: Any, label: str) -> str:
    text = str(value or "")
    if not SHA256_RE.fullmatch(text):
        raise RuntimeDependencyReceiptError(f"{label} is not a SHA-256")
    return text


def _require_text(value: Any, label: str) -> str:
    text = str(value or "").strip()
    if not text or any(ord(character) < 32 for character in text):
        raise RuntimeDependencyReceiptError(f"{label} is invalid")
    return text


def _safe_relative_path(value: Any, label: str) -> str:
    text = _require_text(value, label)
    path = PurePosixPath(text)
    if path.is_absolute() or ".." in path.parts or "." in path.parts:
        raise RuntimeDependencyReceiptError(f"{label} is unsafe")
    return path.as_posix()


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeDependencyReceiptError(f"cannot read JSON: {path}") from exc
    if not isinstance(value, dict):
        raise RuntimeDependencyReceiptError(f"JSON root must be an object: {path}")
    return value


def _write_owner_only_json(path: Path, value: Mapping[str, Any]) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(stable_json(dict(value)) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise


def _regular_file(path: Path, label: str) -> Path:
    if path.is_symlink():
        raise RuntimeDependencyReceiptError(f"{label} must not be a symlink")
    path = path.resolve()
    if not path.is_file():
        raise RuntimeDependencyReceiptError(f"{label} must be a regular file")
    return path


def _file_reference(path: Path, artifact_root: Path) -> dict[str, Any]:
    path = _regular_file(path, "artifact")
    artifact_root = artifact_root.resolve()
    try:
        relative = path.relative_to(artifact_root).as_posix()
    except ValueError as exc:
        raise RuntimeDependencyReceiptError("artifact escapes artifact root") from exc
    return {
        "path": _safe_relative_path(relative, "artifact path"),
        "bytes": path.stat().st_size,
        "sha256": sha256_file(path),
    }


def _validate_file_reference(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RuntimeDependencyReceiptError(f"{label} must be an object")
    _require_exact_keys(value, {"path", "bytes", "sha256"}, label)
    path = _safe_relative_path(value["path"], f"{label}.path")
    size = value["bytes"]
    if isinstance(size, bool) or not isinstance(size, int) or size < 1:
        raise RuntimeDependencyReceiptError(f"{label}.bytes is invalid")
    return {
        "path": path,
        "bytes": size,
        "sha256": _require_sha256(value["sha256"], f"{label}.sha256"),
    }


def _verify_file_reference(value: Mapping[str, Any], root: Path, label: str) -> Path:
    reference = _validate_file_reference(value, label)
    root = root.resolve()
    candidate = root / reference["path"]
    if candidate.is_symlink():
        raise RuntimeDependencyReceiptError(f"{label} artifact must not be a symlink")
    path = candidate.resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise RuntimeDependencyReceiptError(f"{label} escapes artifact root") from exc
    if not path.is_file() or path.is_symlink():
        raise RuntimeDependencyReceiptError(f"{label} artifact is unavailable")
    if path.stat().st_size != reference["bytes"] or sha256_file(path) != reference["sha256"]:
        raise RuntimeDependencyReceiptError(f"{label} artifact identity mismatch")
    return path


def _inventory(root: Path) -> dict[str, dict[str, Any]]:
    root = root.resolve()
    if not root.is_dir() or root.is_symlink():
        raise RuntimeDependencyReceiptError("inventory root must be a directory")
    inventory: dict[str, dict[str, Any]] = {}
    for directory, dirnames, filenames in os.walk(root, followlinks=False):
        directory_path = Path(directory)
        entries = sorted([*(directory_path / item for item in dirnames), *(directory_path / item for item in filenames)])
        for path in entries:
            relative = path.relative_to(root).as_posix()
            mode = stat.S_IMODE(path.lstat().st_mode)
            if path.is_symlink():
                target = os.readlink(path)
                target_path = PurePosixPath(target)
                if target_path.is_absolute() or ".." in target_path.parts:
                    raise RuntimeDependencyReceiptError(f"runtime symlink is unsafe: {relative}")
                inventory[relative] = {
                    "type": "symlink",
                    "mode": mode,
                    "target": target,
                    "sha256": hashlib.sha256(target.encode("utf-8")).hexdigest(),
                }
            elif path.is_file():
                inventory[relative] = {
                    "type": "file",
                    "mode": mode,
                    "bytes": path.stat().st_size,
                    "sha256": sha256_file(path),
                }
            elif path.is_dir():
                continue
            else:
                raise RuntimeDependencyReceiptError(f"unsupported runtime entry: {relative}")
    if not inventory:
        raise RuntimeDependencyReceiptError("runtime inventory is empty")
    return dict(sorted(inventory.items()))


def _validate_inventory(value: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(value, dict) or not value:
        raise RuntimeDependencyReceiptError("runtime inventory is invalid")
    result: dict[str, dict[str, Any]] = {}
    for relative, entry in sorted(value.items()):
        safe = _safe_relative_path(relative, "runtime inventory path")
        if not isinstance(entry, dict):
            raise RuntimeDependencyReceiptError("runtime inventory entry is invalid")
        kind = entry.get("type")
        expected = {"type", "mode", "sha256", "bytes"} if kind == "file" else {"type", "mode", "sha256", "target"}
        _require_exact_keys(entry, expected, "runtime inventory entry")
        mode = entry["mode"]
        if isinstance(mode, bool) or not isinstance(mode, int) or not 0 <= mode <= 0o7777:
            raise RuntimeDependencyReceiptError("runtime inventory mode is invalid")
        normalized: dict[str, Any] = {
            "type": kind,
            "mode": mode,
            "sha256": _require_sha256(entry["sha256"], "runtime inventory sha256"),
        }
        if kind == "file":
            size = entry["bytes"]
            if isinstance(size, bool) or not isinstance(size, int) or size < 0:
                raise RuntimeDependencyReceiptError("runtime inventory size is invalid")
            normalized["bytes"] = size
        elif kind == "symlink":
            target = _require_text(entry["target"], "runtime symlink target")
            target_path = PurePosixPath(target)
            if target_path.is_absolute() or ".." in target_path.parts:
                raise RuntimeDependencyReceiptError("runtime symlink target is unsafe")
            if hashlib.sha256(target.encode("utf-8")).hexdigest() != normalized["sha256"]:
                raise RuntimeDependencyReceiptError("runtime symlink hash mismatch")
            normalized["target"] = target
        else:
            raise RuntimeDependencyReceiptError("runtime inventory type is invalid")
        result[safe] = normalized
    return result


def validate_build_environment(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RuntimeDependencyReceiptError("build environment must be an object")
    expected = {
        "schema_version", "base_os", "base_image", "architecture", "compiler",
        "configure_flags", "build_packages", "libc", "openssl_version",
        "sqlite_version", "python", "installation_prefix",
    }
    _require_exact_keys(value, expected, "build environment")
    if value["schema_version"] != BUILD_ENVIRONMENT_SCHEMA:
        raise RuntimeDependencyReceiptError("build environment schema is invalid")
    for label in ("base_os", "base_image", "compiler", "libc", "python"):
        if not isinstance(value[label], dict):
            raise RuntimeDependencyReceiptError(f"build environment {label} is invalid")
    _require_exact_keys(value["base_os"], {"id", "version_id"}, "base_os")
    _require_exact_keys(value["base_image"], {"reference", "digest"}, "base_image")
    _require_exact_keys(value["compiler"], {"name", "version"}, "compiler")
    _require_exact_keys(value["libc"], {"implementation", "version"}, "libc")
    _require_exact_keys(
        value["python"],
        {"implementation", "version", "abi", "platform", "executable_relative_path"},
        "python",
    )
    if value["python"]["implementation"] != "CPython" or value["python"]["version"] != FROZEN_PYTHON_VERSION:
        raise RuntimeDependencyReceiptError("build environment does not describe frozen CPython")
    prefix = _require_text(value["installation_prefix"], "installation_prefix")
    if not prefix.startswith(RUNTIME_PREFIX) or ".." in Path(prefix).parts:
        raise RuntimeDependencyReceiptError("installation_prefix is outside the managed runtime boundary")
    executable = _safe_relative_path(value["python"]["executable_relative_path"], "python executable")
    flags = value["configure_flags"]
    if not isinstance(flags, list) or not flags or any(not isinstance(item, str) or not item for item in flags):
        raise RuntimeDependencyReceiptError("configure_flags are invalid")
    packages = value["build_packages"]
    if not isinstance(packages, list) or not packages:
        raise RuntimeDependencyReceiptError("build_packages are invalid")
    normalized_packages: list[dict[str, str]] = []
    package_names: set[str] = set()
    for package in packages:
        if not isinstance(package, dict):
            raise RuntimeDependencyReceiptError("build package is invalid")
        _require_exact_keys(package, {"name", "version"}, "build package")
        package_name = _require_text(package["name"], "build package name")
        if package_name in package_names:
            raise RuntimeDependencyReceiptError("build_packages contain a duplicate")
        package_names.add(package_name)
        normalized_packages.append({
            "name": package_name,
            "version": _require_text(package["version"], "build package version"),
        })
    if normalized_packages != sorted(normalized_packages, key=lambda item: item["name"]):
        raise RuntimeDependencyReceiptError("build_packages must be sorted")
    result = json.loads(stable_json(value))
    result["installation_prefix"] = prefix
    result["python"]["executable_relative_path"] = executable
    for label in ("architecture", "openssl_version", "sqlite_version"):
        _require_text(result[label], label)
    for container, fields in {
        "base_os": ("id", "version_id"), "base_image": ("reference", "digest"),
        "compiler": ("name", "version"), "libc": ("implementation", "version"),
        "python": ("abi", "platform"),
    }.items():
        for field in fields:
            _require_text(result[container][field], f"{container}.{field}")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", result["base_image"]["digest"]):
        raise RuntimeDependencyReceiptError("base_image.digest is invalid")
    if f"--prefix={prefix}" not in result["configure_flags"]:
        raise RuntimeDependencyReceiptError("configure_flags do not bind installation_prefix")
    return result


def create_runtime_manifest(
    *, runtime_root: Path, source_archive: Path, source_url: str,
    build_environment_path: Path,
) -> dict[str, Any]:
    source_archive = _regular_file(source_archive, "Python source archive")
    build_environment = validate_build_environment(_load_json(build_environment_path))
    inventory = _inventory(runtime_root)
    executable = build_environment["python"]["executable_relative_path"]
    if executable not in inventory or inventory[executable]["type"] != "file":
        raise RuntimeDependencyReceiptError("frozen Python executable is absent from runtime inventory")
    source = {
        "filename": source_archive.name,
        "url": _require_text(source_url, "source URL"),
        "bytes": source_archive.stat().st_size,
        "sha256": sha256_file(source_archive),
    }
    if source["sha256"] != "c08bc65a81971c1dd5783182826503369466c7e67374d1646519adf05207b684":
        raise RuntimeDependencyReceiptError("Python source archive is not the reviewed 3.12.13 source")
    if source["url"] != PYTHON_SOURCE_URL:
        raise RuntimeDependencyReceiptError("Python source URL is not the reviewed source")
    archive_root = build_environment["installation_prefix"].lstrip("/")
    basis = {
        "source": source,
        "build_environment": build_environment,
        "archive_root": archive_root,
        "inventory_sha256": _sha256_json(inventory),
    }
    return {
        "schema_version": RUNTIME_MANIFEST_SCHEMA,
        "runtime_id": f"python_runtime_{_sha256_json(basis)}",
        **basis,
        "inventory": inventory,
    }


def validate_runtime_manifest(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RuntimeDependencyReceiptError("runtime manifest must be an object")
    _require_exact_keys(
        value,
        {"schema_version", "runtime_id", "source", "build_environment", "archive_root", "inventory_sha256", "inventory"},
        "runtime manifest",
    )
    if value["schema_version"] != RUNTIME_MANIFEST_SCHEMA or not ID_RE.fullmatch(str(value["runtime_id"])):
        raise RuntimeDependencyReceiptError("runtime manifest identity is invalid")
    source = value["source"]
    if not isinstance(source, dict):
        raise RuntimeDependencyReceiptError("runtime source is invalid")
    _require_exact_keys(source, {"filename", "url", "bytes", "sha256"}, "runtime source")
    filename = _safe_relative_path(source["filename"], "runtime source filename")
    if "/" in filename:
        raise RuntimeDependencyReceiptError("runtime source filename must be a basename")
    source_size = source["bytes"]
    if isinstance(source_size, bool) or not isinstance(source_size, int) or source_size < 1:
        raise RuntimeDependencyReceiptError("runtime source size is invalid")
    source_normalized = {
        "filename": filename,
        "url": _require_text(source["url"], "runtime source URL"),
        "bytes": source_size,
        "sha256": _require_sha256(source["sha256"], "runtime source sha256"),
    }
    if source_normalized["sha256"] != "c08bc65a81971c1dd5783182826503369466c7e67374d1646519adf05207b684":
        raise RuntimeDependencyReceiptError("runtime source is not frozen Python 3.12.13")
    if source_normalized["url"] != PYTHON_SOURCE_URL:
        raise RuntimeDependencyReceiptError("runtime source URL is not frozen")
    environment = validate_build_environment(value["build_environment"])
    archive_root = _safe_relative_path(value["archive_root"], "runtime archive_root")
    if archive_root != environment["installation_prefix"].lstrip("/"):
        raise RuntimeDependencyReceiptError("runtime archive root does not match installation prefix")
    inventory = _validate_inventory(value["inventory"])
    inventory_sha256 = _require_sha256(value["inventory_sha256"], "runtime inventory_sha256")
    if _sha256_json(inventory) != inventory_sha256:
        raise RuntimeDependencyReceiptError("runtime inventory hash mismatch")
    executable = environment["python"]["executable_relative_path"]
    if executable not in inventory or inventory[executable]["type"] != "file":
        raise RuntimeDependencyReceiptError("runtime manifest omits frozen Python executable")
    basis = {
        "source": source_normalized,
        "build_environment": environment,
        "archive_root": archive_root,
        "inventory_sha256": inventory_sha256,
    }
    if value["runtime_id"] != f"python_runtime_{_sha256_json(basis)}":
        raise RuntimeDependencyReceiptError("runtime ID mismatch")
    return {"schema_version": RUNTIME_MANIFEST_SCHEMA, "runtime_id": value["runtime_id"], **basis, "inventory": inventory}


def _normalized_project(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _parse_locked_requirements(text: str) -> dict[str, dict[str, str]]:
    requirements: dict[str, dict[str, str]] = {}
    for line_number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line:
            continue
        match = REQUIREMENT_RE.fullmatch(line)
        if not match:
            raise RuntimeDependencyReceiptError(f"lock line {line_number} is not an exact requirement")
        project, version = match.groups()
        normalized = _normalized_project(project)
        if normalized in requirements:
            raise RuntimeDependencyReceiptError("dependency lock contains a duplicate project")
        requirements[normalized] = {"project": project, "version": version}
    if len(requirements) != FROZEN_REQUIREMENT_COUNT:
        raise RuntimeDependencyReceiptError("dependency lock requirement count is not frozen")
    return requirements


def _locked_requirements(lock_path: Path) -> dict[str, dict[str, str]]:
    lock_path = _regular_file(lock_path, "dependency lock")
    if lock_path.name != FROZEN_LOCK_FILENAME:
        raise RuntimeDependencyReceiptError("dependency lock filename is not frozen")
    if sha256_file(lock_path) != FROZEN_LOCK_SHA256:
        raise RuntimeDependencyReceiptError("dependency lock hash is not frozen")
    return _parse_locked_requirements(lock_path.read_text(encoding="utf-8"))


def _wheel_metadata(path: Path) -> dict[str, Any]:
    try:
        with zipfile.ZipFile(path) as archive:
            candidates = [
                name for name in archive.namelist()
                if name.endswith(".dist-info/METADATA") and name.count("/") == 1
            ]
            if len(candidates) != 1:
                raise RuntimeDependencyReceiptError(f"wheel metadata is ambiguous: {path.name}")
            metadata = Parser().parsestr(archive.read(candidates[0]).decode("utf-8"))
    except (OSError, UnicodeDecodeError, zipfile.BadZipFile, KeyError) as exc:
        raise RuntimeDependencyReceiptError(f"wheel is unreadable: {path.name}") from exc
    project = _require_text(metadata.get("Name"), "wheel project")
    version = _require_text(metadata.get("Version"), "wheel version")
    filename = path.name
    python_tag, abi_tag, platform_tag = _wheel_filename_tags(filename)
    return {
        "filename": filename,
        "project": project,
        "version": version,
        "python_tag": _require_text(python_tag, "wheel python tag"),
        "abi_tag": _require_text(abi_tag, "wheel ABI tag"),
        "platform_tag": _require_text(platform_tag, "wheel platform tag"),
        "bytes": path.stat().st_size,
        "sha256": sha256_file(path),
    }


def _wheel_filename_tags(filename: str) -> tuple[str, str, str]:
    """Parse the compressed compatibility tags from a wheel filename."""

    if not filename.endswith(".whl"):
        raise RuntimeDependencyReceiptError("wheel filename is invalid")
    try:
        prefix, python_tag, abi_tag, platform_tag = filename[:-4].rsplit("-", 3)
    except ValueError as exc:
        raise RuntimeDependencyReceiptError(f"wheel tags are invalid: {filename}") from exc
    tag_pattern = re.compile(r"^[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)*$")
    if not prefix or any(
        tag_pattern.fullmatch(value) is None
        for value in (python_tag, abi_tag, platform_tag)
    ):
        raise RuntimeDependencyReceiptError(f"wheel tags are invalid: {filename}")
    return python_tag, abi_tag, platform_tag


def _frozen_platform_compatible(platform_tag: str) -> bool:
    if platform_tag == "any":
        return True
    if platform_tag in {
        "manylinux1_x86_64",
        "manylinux2010_x86_64",
        "manylinux2014_x86_64",
    }:
        return True
    match = re.fullmatch(r"manylinux_(\d+)_(\d+)_x86_64", platform_tag)
    return bool(match and int(match.group(1)) == 2 and int(match.group(2)) <= 34)


def _frozen_python_abi_compatible(
    python_tag: str,
    abi_tag: str,
    platform_tag: str,
) -> bool:
    if platform_tag == "any":
        return abi_tag == "none" and python_tag in {"py3", "py312", "cp312"}
    if not _frozen_platform_compatible(platform_tag):
        return False
    if abi_tag == "none":
        return python_tag in {"py3", "py312", "cp312"}
    if python_tag == "cp312" and abi_tag in {"cp312", "abi3"}:
        return True
    abi3_match = re.fullmatch(r"cp3(\d{1,2})", python_tag)
    return bool(
        abi_tag == "abi3"
        and abi3_match
        and 2 <= int(abi3_match.group(1)) <= 12
    )


def _require_frozen_wheel_compatibility(
    python_tag: str,
    abi_tag: str,
    platform_tag: str,
    filename: str,
) -> None:
    """Require at least one tag triple compatible with CPython 3.12/x86_64."""

    compatible = any(
        _frozen_python_abi_compatible(python_value, abi_value, platform_value)
        for python_value in python_tag.split(".")
        for abi_value in abi_tag.split(".")
        for platform_value in platform_tag.split(".")
    )
    if not compatible:
        raise RuntimeDependencyReceiptError(
            f"wheel is incompatible with the frozen CPython target: {filename}"
        )


def _wheel_metadata_bytes(filename: str, value: bytes) -> dict[str, str]:
    try:
        with zipfile.ZipFile(io.BytesIO(value)) as archive:
            candidates = [
                name for name in archive.namelist()
                if name.endswith(".dist-info/METADATA") and name.count("/") == 1
            ]
            if len(candidates) != 1:
                raise RuntimeDependencyReceiptError(f"wheel metadata is ambiguous: {filename}")
            metadata = Parser().parsestr(archive.read(candidates[0]).decode("utf-8"))
    except (UnicodeDecodeError, zipfile.BadZipFile, KeyError) as exc:
        raise RuntimeDependencyReceiptError(f"wheel is unreadable: {filename}") from exc
    return {
        "project": _require_text(metadata.get("Name"), "wheel project"),
        "version": _require_text(metadata.get("Version"), "wheel version"),
    }


def create_wheel_manifest(
    *, wheel_root: Path, lock_path: Path, indexes: Sequence[str],
    resolver_version: str, download_arguments: Sequence[str],
) -> dict[str, Any]:
    requirements = _locked_requirements(lock_path)
    wheel_root = wheel_root.resolve()
    if not wheel_root.is_dir() or wheel_root.is_symlink():
        raise RuntimeDependencyReceiptError("wheel root must be a directory")
    wheels = [_wheel_metadata(path) for path in sorted(wheel_root.glob("*.whl"))]
    if len(wheels) != len(requirements):
        raise RuntimeDependencyReceiptError("wheel count does not match frozen lock")
    matched: set[str] = set()
    for wheel in wheels:
        _require_frozen_wheel_compatibility(
            wheel["python_tag"],
            wheel["abi_tag"],
            wheel["platform_tag"],
            wheel["filename"],
        )
        project = _normalized_project(wheel["project"])
        requirement = requirements.get(project)
        if requirement is None or requirement["version"] != wheel["version"]:
            raise RuntimeDependencyReceiptError(f"wheel does not match frozen lock: {wheel['filename']}")
        if project in matched:
            raise RuntimeDependencyReceiptError("multiple wheels satisfy one locked project")
        wheel["source_index"] = (
            "https://download.pytorch.org/whl/cpu"
            if project == "torch"
            else "https://pypi.org/simple"
        )
        matched.add(project)
    if matched != set(requirements):
        raise RuntimeDependencyReceiptError("frozen lock is not fully represented by wheels")
    normalized_indexes = sorted({_require_text(value, "package index") for value in indexes})
    if normalized_indexes != sorted(["https://download.pytorch.org/whl/cpu", "https://pypi.org/simple"]):
        raise RuntimeDependencyReceiptError("wheel sources differ from the reviewed indexes")
    lock = {
        "filename": lock_path.name,
        "bytes": lock_path.stat().st_size,
        "sha256": sha256_file(lock_path),
        "requirement_count": len(requirements),
    }
    target = {
        "implementation": "CPython",
        "python_version": "3.12",
        "abi": "cp312",
        "architecture": "x86_64",
        "platforms": [
            "manylinux_2_17_x86_64",
            "manylinux_2_28_x86_64",
            "manylinux_2_34_x86_64",
        ],
    }
    resolver = {
        "name": "pip",
        "version": _require_text(resolver_version, "resolver version"),
        "download_arguments": list(download_arguments),
    }
    if not resolver["download_arguments"] or any(
        not isinstance(item, str) or not item for item in resolver["download_arguments"]
    ):
        raise RuntimeDependencyReceiptError("resolver download arguments are invalid")
    basis = {
        "target": target, "indexes": normalized_indexes, "resolver": resolver,
        "dependency_lock": lock, "wheels": wheels,
    }
    return {
        "schema_version": WHEEL_MANIFEST_SCHEMA,
        "bundle_id": f"python_wheels_{_sha256_json(basis)}",
        **basis,
    }


def validate_wheel_manifest(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RuntimeDependencyReceiptError("wheel manifest must be an object")
    _require_exact_keys(value, {"schema_version", "bundle_id", "target", "indexes", "resolver", "dependency_lock", "wheels"}, "wheel manifest")
    if value["schema_version"] != WHEEL_MANIFEST_SCHEMA or not ID_RE.fullmatch(str(value["bundle_id"])):
        raise RuntimeDependencyReceiptError("wheel manifest identity is invalid")
    target = value["target"]
    expected_targets = (
        {
            "implementation": "CPython", "python_version": "3.12", "abi": "cp312",
            "architecture": "x86_64",
            "platforms": ["manylinux_2_17_x86_64", "manylinux_2_28_x86_64"],
        },
        {
            "implementation": "CPython", "python_version": "3.12", "abi": "cp312",
            "architecture": "x86_64",
            "platforms": [
                "manylinux_2_17_x86_64",
                "manylinux_2_28_x86_64",
                "manylinux_2_34_x86_64",
            ],
        },
    )
    if target not in expected_targets:
        raise RuntimeDependencyReceiptError("wheel target is not the frozen target")
    indexes = value["indexes"]
    expected_indexes = sorted(["https://download.pytorch.org/whl/cpu", "https://pypi.org/simple"])
    if indexes != expected_indexes:
        raise RuntimeDependencyReceiptError("wheel indexes are invalid")
    resolver = value["resolver"]
    if not isinstance(resolver, dict):
        raise RuntimeDependencyReceiptError("wheel resolver is invalid")
    _require_exact_keys(resolver, {"name", "version", "download_arguments"}, "wheel resolver")
    if resolver["name"] != "pip":
        raise RuntimeDependencyReceiptError("wheel resolver name is invalid")
    normalized_resolver = {
        "name": "pip", "version": _require_text(resolver["version"], "wheel resolver version"),
        "download_arguments": resolver["download_arguments"],
    }
    if not isinstance(normalized_resolver["download_arguments"], list) or not normalized_resolver["download_arguments"] or any(
        not isinstance(item, str) or not item for item in normalized_resolver["download_arguments"]
    ):
        raise RuntimeDependencyReceiptError("wheel resolver arguments are invalid")
    lock = value["dependency_lock"]
    if not isinstance(lock, dict):
        raise RuntimeDependencyReceiptError("wheel lock receipt is invalid")
    _require_exact_keys(lock, {"filename", "bytes", "sha256", "requirement_count"}, "wheel lock receipt")
    normalized_lock = {
        "filename": _safe_relative_path(lock["filename"], "wheel lock filename"),
        "bytes": lock["bytes"], "sha256": _require_sha256(lock["sha256"], "wheel lock sha256"),
        "requirement_count": lock["requirement_count"],
    }
    if (
        normalized_lock["filename"] != FROZEN_LOCK_FILENAME
        or normalized_lock["sha256"] != FROZEN_LOCK_SHA256
    ):
        raise RuntimeDependencyReceiptError("wheel lock identity is invalid")
    if normalized_lock["requirement_count"] != FROZEN_REQUIREMENT_COUNT or not isinstance(normalized_lock["bytes"], int) or normalized_lock["bytes"] < 1:
        raise RuntimeDependencyReceiptError("wheel lock metadata is invalid")
    wheels = value["wheels"]
    if not isinstance(wheels, list) or len(wheels) != FROZEN_REQUIREMENT_COUNT:
        raise RuntimeDependencyReceiptError("wheel inventory count is invalid")
    normalized_wheels: list[dict[str, Any]] = []
    filenames: set[str] = set()
    projects: set[str] = set()
    fields = {"filename", "project", "version", "python_tag", "abi_tag", "platform_tag", "source_index", "bytes", "sha256"}
    for wheel in wheels:
        if not isinstance(wheel, dict):
            raise RuntimeDependencyReceiptError("wheel inventory entry is invalid")
        _require_exact_keys(wheel, fields, "wheel inventory entry")
        filename = _safe_relative_path(wheel["filename"], "wheel filename")
        project = _require_text(wheel["project"], "wheel project")
        if "/" in filename or not filename.endswith(".whl") or filename in filenames or _normalized_project(project) in projects:
            raise RuntimeDependencyReceiptError("wheel inventory identity is invalid")
        size = wheel["bytes"]
        if isinstance(size, bool) or not isinstance(size, int) or size < 1:
            raise RuntimeDependencyReceiptError("wheel size is invalid")
        filenames.add(filename)
        projects.add(_normalized_project(project))
        expected_source = (
            "https://download.pytorch.org/whl/cpu"
            if _normalized_project(project) == "torch"
            else "https://pypi.org/simple"
        )
        if wheel["source_index"] != expected_source:
            raise RuntimeDependencyReceiptError("wheel source index is invalid")
        parsed_tags = _wheel_filename_tags(filename)
        declared_tags = (
            _require_text(wheel["python_tag"], "wheel python tag"),
            _require_text(wheel["abi_tag"], "wheel ABI tag"),
            _require_text(wheel["platform_tag"], "wheel platform tag"),
        )
        if declared_tags != parsed_tags:
            raise RuntimeDependencyReceiptError(
                "wheel compatibility tags do not match its filename"
            )
        _require_frozen_wheel_compatibility(*declared_tags, filename)
        normalized_wheels.append({
            "filename": filename, "project": project,
            "version": _require_text(wheel["version"], "wheel version"),
            "python_tag": declared_tags[0],
            "abi_tag": declared_tags[1],
            "platform_tag": declared_tags[2],
            "source_index": expected_source,
            "bytes": size, "sha256": _require_sha256(wheel["sha256"], "wheel sha256"),
        })
    if normalized_wheels != sorted(normalized_wheels, key=lambda item: item["filename"]):
        raise RuntimeDependencyReceiptError("wheel inventory must be sorted")
    basis = {
        "target": target, "indexes": indexes, "resolver": normalized_resolver,
        "dependency_lock": normalized_lock, "wheels": normalized_wheels,
    }
    if value["bundle_id"] != f"python_wheels_{_sha256_json(basis)}":
        raise RuntimeDependencyReceiptError("wheel bundle ID mismatch")
    return {"schema_version": WHEEL_MANIFEST_SCHEMA, "bundle_id": value["bundle_id"], **basis}


def _tar_members(path: Path) -> dict[str, dict[str, Any]]:
    members: dict[str, dict[str, Any]] = {}
    try:
        with tarfile.open(path, "r:*") as archive:
            for member in archive:
                raw = member.name.rstrip("/")
                if not raw:
                    continue
                name = _safe_relative_path(raw, "archive member")
                if name in members:
                    raise RuntimeDependencyReceiptError("archive contains duplicate members")
                if member.isdir():
                    continue
                mode = member.mode
                if member.isfile():
                    stream = archive.extractfile(member)
                    if stream is None:
                        raise RuntimeDependencyReceiptError("archive file cannot be read")
                    members[name] = {"type": "file", "mode": mode, "bytes": member.size, "sha256": _sha256_stream(stream)}
                elif member.issym():
                    target_path = PurePosixPath(member.linkname)
                    if target_path.is_absolute() or ".." in target_path.parts:
                        raise RuntimeDependencyReceiptError("archive symlink is unsafe")
                    members[name] = {
                        "type": "symlink", "mode": mode, "target": member.linkname,
                        "sha256": hashlib.sha256(member.linkname.encode("utf-8")).hexdigest(),
                    }
                else:
                    raise RuntimeDependencyReceiptError("archive contains an unsupported entry")
    except (OSError, tarfile.TarError) as exc:
        raise RuntimeDependencyReceiptError(f"archive is unreadable: {path}") from exc
    return dict(sorted(members.items()))


def verify_runtime_archive(path: Path, manifest: Mapping[str, Any]) -> None:
    validated = validate_runtime_manifest(manifest)
    prefix = validated["archive_root"] + "/"
    expected = {prefix + relative: entry for relative, entry in validated["inventory"].items()}
    if _tar_members(path) != expected:
        raise RuntimeDependencyReceiptError("runtime archive does not match closed inventory")


def verify_wheel_archive(path: Path, manifest: Mapping[str, Any]) -> None:
    validated = validate_wheel_manifest(manifest)
    expected: dict[str, dict[str, Any]] = {
        validated["dependency_lock"]["filename"]: {
            "type": "file", "mode": 0o600, "bytes": validated["dependency_lock"]["bytes"],
            "sha256": validated["dependency_lock"]["sha256"],
        }
    }
    for wheel in validated["wheels"]:
        expected["wheels/" + wheel["filename"]] = {
            "type": "file", "mode": 0o600, "bytes": wheel["bytes"], "sha256": wheel["sha256"],
        }
    if _tar_members(path) != dict(sorted(expected.items())):
        raise RuntimeDependencyReceiptError("wheel archive does not match closed inventory")
    try:
        with tarfile.open(path, "r:*") as archive:
            lock_member = archive.getmember(validated["dependency_lock"]["filename"])
            lock_stream = archive.extractfile(lock_member)
            if lock_stream is None:
                raise RuntimeDependencyReceiptError("wheel archive lock is unreadable")
            locked = _parse_locked_requirements(lock_stream.read().decode("utf-8"))
            represented: set[str] = set()
            for wheel in validated["wheels"]:
                member = archive.getmember("wheels/" + wheel["filename"])
                stream = archive.extractfile(member)
                if stream is None:
                    raise RuntimeDependencyReceiptError("wheel archive member is unreadable")
                metadata = _wheel_metadata_bytes(wheel["filename"], stream.read())
                project = _normalized_project(metadata["project"])
                requirement = locked.get(project)
                if requirement is None or requirement["version"] != metadata["version"]:
                    raise RuntimeDependencyReceiptError("wheel archive content differs from frozen lock")
                if metadata["project"] != wheel["project"] or metadata["version"] != wheel["version"]:
                    raise RuntimeDependencyReceiptError("wheel archive metadata differs from manifest")
                represented.add(project)
            if represented != set(locked):
                raise RuntimeDependencyReceiptError("wheel archive does not cover frozen lock")
    except (OSError, UnicodeDecodeError, KeyError, tarfile.TarError) as exc:
        if isinstance(exc, RuntimeDependencyReceiptError):
            raise
        raise RuntimeDependencyReceiptError("wheel archive semantics are unreadable") from exc


def create_receipt(
    *, artifact_root: Path, application_revision: str, application_archive: Path,
    runtime_manifest_path: Path, runtime_archive: Path,
    wheel_manifest_path: Path, wheel_archive: Path,
) -> dict[str, Any]:
    artifact_root = artifact_root.resolve()
    if not REVISION_RE.fullmatch(application_revision):
        raise RuntimeDependencyReceiptError("application revision is invalid")
    runtime_manifest = validate_runtime_manifest(_load_json(runtime_manifest_path))
    wheel_manifest = validate_wheel_manifest(_load_json(wheel_manifest_path))
    verify_runtime_archive(runtime_archive, runtime_manifest)
    verify_wheel_archive(wheel_archive, wheel_manifest)
    source_path = artifact_root / runtime_manifest["source"]["filename"]
    source_ref = _file_reference(source_path, artifact_root)
    if source_ref["sha256"] != runtime_manifest["source"]["sha256"] or source_ref["bytes"] != runtime_manifest["source"]["bytes"]:
        raise RuntimeDependencyReceiptError("retained Python source differs from runtime manifest")
    basis = {
        "application": {"revision": application_revision, "archive": _file_reference(application_archive, artifact_root)},
        "python_source": source_ref,
        "runtime": {
            "runtime_id": runtime_manifest["runtime_id"],
            "manifest": _file_reference(runtime_manifest_path, artifact_root),
            "archive": _file_reference(runtime_archive, artifact_root),
        },
        "dependencies": {
            "bundle_id": wheel_manifest["bundle_id"],
            "lock_sha256": wheel_manifest["dependency_lock"]["sha256"],
            "manifest": _file_reference(wheel_manifest_path, artifact_root),
            "archive": _file_reference(wheel_archive, artifact_root),
        },
    }
    return {
        "schema_version": RECEIPT_SCHEMA,
        "receipt_id": f"runtime_dependency_{_sha256_json(basis)}",
        "created_at": datetime.now(timezone.utc).isoformat(),
        **basis,
    }


def validate_receipt(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RuntimeDependencyReceiptError("receipt must be an object")
    _require_exact_keys(value, {"schema_version", "receipt_id", "created_at", "application", "python_source", "runtime", "dependencies"}, "receipt")
    if value["schema_version"] != RECEIPT_SCHEMA or not ID_RE.fullmatch(str(value["receipt_id"])):
        raise RuntimeDependencyReceiptError("receipt identity is invalid")
    application = value["application"]
    runtime = value["runtime"]
    dependencies = value["dependencies"]
    for item, label, fields in (
        (application, "application", {"revision", "archive"}),
        (runtime, "runtime", {"runtime_id", "manifest", "archive"}),
        (dependencies, "dependencies", {"bundle_id", "lock_sha256", "manifest", "archive"}),
    ):
        if not isinstance(item, dict):
            raise RuntimeDependencyReceiptError(f"{label} receipt is invalid")
        _require_exact_keys(item, fields, label)
    if not REVISION_RE.fullmatch(str(application["revision"])):
        raise RuntimeDependencyReceiptError("application revision is invalid")
    if not ID_RE.fullmatch(str(runtime["runtime_id"])) or not ID_RE.fullmatch(str(dependencies["bundle_id"])):
        raise RuntimeDependencyReceiptError("component identity is invalid")
    normalized = {
        "schema_version": RECEIPT_SCHEMA,
        "receipt_id": value["receipt_id"],
        "created_at": _require_text(value["created_at"], "created_at"),
        "application": {"revision": application["revision"], "archive": _validate_file_reference(application["archive"], "application.archive")},
        "python_source": _validate_file_reference(value["python_source"], "python_source"),
        "runtime": {
            "runtime_id": runtime["runtime_id"], "manifest": _validate_file_reference(runtime["manifest"], "runtime.manifest"),
            "archive": _validate_file_reference(runtime["archive"], "runtime.archive"),
        },
        "dependencies": {
            "bundle_id": dependencies["bundle_id"],
            "lock_sha256": _require_sha256(dependencies["lock_sha256"], "dependencies.lock_sha256"),
            "manifest": _validate_file_reference(dependencies["manifest"], "dependencies.manifest"),
            "archive": _validate_file_reference(dependencies["archive"], "dependencies.archive"),
        },
    }
    basis = {key: normalized[key] for key in ("application", "python_source", "runtime", "dependencies")}
    if normalized["receipt_id"] != f"runtime_dependency_{_sha256_json(basis)}":
        raise RuntimeDependencyReceiptError("receipt ID mismatch")
    return normalized


def verify_receipt(path: Path, artifact_root: Path) -> dict[str, Any]:
    receipt = validate_receipt(_load_json(path))
    _verify_file_reference(receipt["application"]["archive"], artifact_root, "application.archive")
    source_path = _verify_file_reference(receipt["python_source"], artifact_root, "python_source")
    runtime_manifest_path = _verify_file_reference(receipt["runtime"]["manifest"], artifact_root, "runtime.manifest")
    runtime_archive_path = _verify_file_reference(receipt["runtime"]["archive"], artifact_root, "runtime.archive")
    wheel_manifest_path = _verify_file_reference(receipt["dependencies"]["manifest"], artifact_root, "dependencies.manifest")
    wheel_archive_path = _verify_file_reference(receipt["dependencies"]["archive"], artifact_root, "dependencies.archive")
    runtime_manifest = validate_runtime_manifest(_load_json(runtime_manifest_path))
    wheel_manifest = validate_wheel_manifest(_load_json(wheel_manifest_path))
    if runtime_manifest["runtime_id"] != receipt["runtime"]["runtime_id"]:
        raise RuntimeDependencyReceiptError("runtime identity differs from receipt")
    if wheel_manifest["bundle_id"] != receipt["dependencies"]["bundle_id"] or wheel_manifest["dependency_lock"]["sha256"] != receipt["dependencies"]["lock_sha256"]:
        raise RuntimeDependencyReceiptError("dependency identity differs from receipt")
    if sha256_file(source_path) != runtime_manifest["source"]["sha256"]:
        raise RuntimeDependencyReceiptError("Python source differs from runtime manifest")
    verify_runtime_archive(runtime_archive_path, runtime_manifest)
    verify_wheel_archive(wheel_archive_path, wheel_manifest)
    return {
        "verified": True,
        "receipt_id": receipt["receipt_id"],
        "application_revision": receipt["application"]["revision"],
        "runtime_id": runtime_manifest["runtime_id"],
        "dependency_bundle_id": wheel_manifest["bundle_id"],
        "runtime_file_count": len(runtime_manifest["inventory"]),
        "wheel_count": len(wheel_manifest["wheels"]),
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    runtime = commands.add_parser("create-runtime-manifest")
    runtime.add_argument("--runtime-root", required=True, type=Path)
    runtime.add_argument("--source-archive", required=True, type=Path)
    runtime.add_argument("--source-url", required=True)
    runtime.add_argument("--build-environment", required=True, type=Path)
    runtime.add_argument("--output", required=True, type=Path)
    wheels = commands.add_parser("create-wheel-manifest")
    wheels.add_argument("--wheel-root", required=True, type=Path)
    wheels.add_argument("--lock", required=True, type=Path)
    wheels.add_argument("--index", action="append", required=True)
    wheels.add_argument("--resolver-version", required=True)
    wheels.add_argument("--download-argument", action="append", required=True)
    wheels.add_argument("--output", required=True, type=Path)
    receipt = commands.add_parser("create-receipt")
    receipt.add_argument("--artifact-root", required=True, type=Path)
    receipt.add_argument("--application-revision", required=True)
    receipt.add_argument("--application-archive", required=True, type=Path)
    receipt.add_argument("--runtime-manifest", required=True, type=Path)
    receipt.add_argument("--runtime-archive", required=True, type=Path)
    receipt.add_argument("--wheel-manifest", required=True, type=Path)
    receipt.add_argument("--wheel-archive", required=True, type=Path)
    receipt.add_argument("--output", required=True, type=Path)
    verify = commands.add_parser("verify")
    verify.add_argument("--receipt", required=True, type=Path)
    verify.add_argument("--artifact-root", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "create-runtime-manifest":
        value = create_runtime_manifest(
            runtime_root=args.runtime_root, source_archive=args.source_archive,
            source_url=args.source_url, build_environment_path=args.build_environment,
        )
        _write_owner_only_json(args.output, value)
        print(stable_json({"runtime_id": value["runtime_id"], "output": str(args.output)}))
    elif args.command == "create-wheel-manifest":
        value = create_wheel_manifest(
            wheel_root=args.wheel_root, lock_path=args.lock, indexes=args.index,
            resolver_version=args.resolver_version,
            download_arguments=args.download_argument,
        )
        _write_owner_only_json(args.output, value)
        print(stable_json({"bundle_id": value["bundle_id"], "output": str(args.output)}))
    elif args.command == "create-receipt":
        value = create_receipt(
            artifact_root=args.artifact_root, application_revision=args.application_revision,
            application_archive=args.application_archive, runtime_manifest_path=args.runtime_manifest,
            runtime_archive=args.runtime_archive, wheel_manifest_path=args.wheel_manifest,
            wheel_archive=args.wheel_archive,
        )
        _write_owner_only_json(args.output, value)
        print(stable_json({"receipt_id": value["receipt_id"], "output": str(args.output)}))
    else:
        print(stable_json(verify_receipt(args.receipt, args.artifact_root)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
