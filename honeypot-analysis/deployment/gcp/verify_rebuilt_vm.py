#!/usr/bin/env python3
"""Verify a concrete, manifest-bound replacement-VM inventory.

The verifier is deliberately stdlib-only and read-only.  It checks the
content-addressed release files, policy files, frozen-model files, database
backup, and the canonical release-tree digest declared by a concrete rebuild
manifest.  Service checks are opt-in so the same verifier can be used in an
isolated restore or in a live replacement host.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sqlite3
import subprocess
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence


SCHEMA_VERSION = "gcp_vm_rebuild_manifest.v1"
_REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_PLACEHOLDER_RE = re.compile(r"<[^>]+>")


class ManifestError(ValueError):
    """Raised when a rebuild manifest or a referenced file is unsafe."""


def _exact_keys(value: Mapping[str, Any], expected: set[str], context: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise ManifestError(f"{context} keys invalid; missing={missing}, extra={extra}")


def _mapping(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ManifestError(f"{context} must be an object")
    return value


def _nonempty_string(value: Any, context: str, *, allow_placeholder: bool = False) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ManifestError(f"{context} must be a non-empty string")
    if not allow_placeholder and _PLACEHOLDER_RE.search(value):
        raise ManifestError(f"{context} still contains a placeholder")
    return value


def _revision(value: Any, context: str) -> str:
    value = _nonempty_string(value, context)
    if not _REVISION_RE.fullmatch(value):
        raise ManifestError(f"{context} must be a 40-character lowercase Git revision")
    return value


def _sha256(value: Any, context: str) -> str:
    value = _nonempty_string(value, context)
    if not _SHA256_RE.fullmatch(value):
        raise ManifestError(f"{context} must be a lowercase SHA-256")
    return value


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise ManifestError(f"cannot read {path}: {exc}") from exc
    return digest.hexdigest()


def _resolve_path(root: Path, declared: Any, context: str) -> Path:
    value = _nonempty_string(declared, context)
    root = root.resolve()
    raw = Path(value)
    if raw.is_absolute() and root != Path("/") and raw.is_relative_to(root):
        candidate = raw.resolve()
    elif raw.is_absolute():
        candidate = (root / raw.relative_to("/")).resolve()
    else:
        candidate = (root / raw).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ManifestError(f"{context} escapes verifier root") from exc
    return candidate


def _file_entry(value: Any, context: str) -> dict[str, Any]:
    entry = _mapping(value, context)
    _exact_keys(entry, {"path", "sha256", "bytes"}, context)
    path = _nonempty_string(entry["path"], f"{context}.path")
    digest = _sha256(entry["sha256"], f"{context}.sha256")
    size = entry["bytes"]
    if not isinstance(size, int) or isinstance(size, bool) or size < 0:
        raise ManifestError(f"{context}.bytes must be a non-negative integer")
    return {"path": path, "sha256": digest, "bytes": size}


def _sorted_file_entries(value: Any, context: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise ManifestError(f"{context} must be a non-empty list")
    entries = [_file_entry(item, f"{context}[{index}]") for index, item in enumerate(value)]
    paths = [str(item["path"]) for item in entries]
    if len(paths) != len(set(paths)) or paths != sorted(paths):
        raise ManifestError(f"{context} paths must be sorted and unique")
    return entries


def _named_file_entries(value: Any, context: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise ManifestError(f"{context} must be a non-empty list")
    entries: list[dict[str, Any]] = []
    names: list[str] = []
    for index, raw in enumerate(value):
        item = _mapping(raw, f"{context}[{index}]")
        _exact_keys(item, {"name", "path", "sha256", "bytes"}, f"{context}[{index}]")
        name = _nonempty_string(item["name"], f"{context}[{index}].name")
        entry = _file_entry(
            {"path": item["path"], "sha256": item["sha256"], "bytes": item["bytes"]},
            f"{context}[{index}]",
        )
        entry["name"] = name
        entries.append(entry)
        names.append(name)
    if names != sorted(names) or len(names) != len(set(names)):
        raise ManifestError(f"{context} names must be sorted and unique")
    return entries


def release_tree_sha256(entries: Sequence[Mapping[str, Any]]) -> str:
    """Return the canonical digest for the sorted release-file inventory."""

    encoded = json.dumps(
        list(entries), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _named_hashes(value: Any, context: str) -> list[dict[str, str]]:
    if not isinstance(value, list) or not value:
        raise ManifestError(f"{context} must be a non-empty list")
    result: list[dict[str, str]] = []
    names: list[str] = []
    for index, raw in enumerate(value):
        item = _mapping(raw, f"{context}[{index}]")
        _exact_keys(item, {"name", "path", "sha256"}, f"{context}[{index}]")
        name = _nonempty_string(item["name"], f"{context}[{index}].name")
        path = _nonempty_string(item["path"], f"{context}[{index}].path")
        digest = _sha256(item["sha256"], f"{context}[{index}].sha256")
        names.append(name)
        result.append({"name": name, "path": path, "sha256": digest})
    if len(names) != len(set(names)) or names != sorted(names):
        raise ManifestError(f"{context} names must be sorted and unique")
    return result


def _service_names(value: Any, context: str) -> list[str]:
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not re.fullmatch(r"[A-Za-z0-9_.@-]+\.(?:service|timer)", item)
        for item in value
    ):
        raise ManifestError(f"{context} contains an invalid unit")
    result = list(value)
    if result != sorted(result) or len(result) != len(set(result)):
        raise ManifestError(f"{context} must be sorted and unique")
    return result


def validate_manifest_document(document: Any) -> Mapping[str, Any]:
    manifest = _mapping(document, "manifest")
    _exact_keys(
        manifest,
        {"schema_version", "source_commit", "release", "policies", "model_bundle", "database", "services", "network"},
        "manifest",
    )
    if manifest["schema_version"] != SCHEMA_VERSION:
        raise ManifestError(f"schema_version must be {SCHEMA_VERSION}")
    _revision(manifest["source_commit"], "source_commit")

    release = _mapping(manifest["release"], "release")
    _exact_keys(release, {"root", "manifest_path", "release_tree_sha256", "files"}, "release")
    _nonempty_string(release["root"], "release.root")
    _nonempty_string(release["manifest_path"], "release.manifest_path")
    _sha256(release["release_tree_sha256"], "release.release_tree_sha256")
    _sorted_file_entries(release["files"], "release.files")

    policies = _named_hashes(manifest["policies"], "policies")
    if any(name == "" for name in (item["name"] for item in policies)):
        raise ManifestError("policy names must not be empty")

    bundle = _mapping(manifest["model_bundle"], "model_bundle")
    _exact_keys(bundle, {"bundle_id", "manifest_path", "manifest_sha256", "artifacts"}, "model_bundle")
    _nonempty_string(bundle["bundle_id"], "model_bundle.bundle_id")
    _nonempty_string(bundle["manifest_path"], "model_bundle.manifest_path")
    _sha256(bundle["manifest_sha256"], "model_bundle.manifest_sha256")
    _named_file_entries(bundle["artifacts"], "model_bundle.artifacts")

    database = _mapping(manifest["database"], "database")
    _exact_keys(
        database,
        {"backup_path", "backup_sha256", "backup_manifest_path", "backup_manifest_sha256", "schema_version"},
        "database",
    )
    _nonempty_string(database["backup_path"], "database.backup_path")
    _sha256(database["backup_sha256"], "database.backup_sha256")
    _nonempty_string(database["backup_manifest_path"], "database.backup_manifest_path")
    _sha256(database["backup_manifest_sha256"], "database.backup_manifest_sha256")
    if not isinstance(database["schema_version"], int) or isinstance(database["schema_version"], bool):
        raise ManifestError("database.schema_version must be an integer")

    services = _mapping(manifest["services"], "services")
    _exact_keys(services, {"required_active", "required_timers"}, "services")
    _service_names(services["required_active"], "services.required_active")
    _service_names(services["required_timers"], "services.required_timers")

    network = _mapping(manifest["network"], "network")
    _exact_keys(network, {"frontend_port", "backend_role"}, "network")
    port = network["frontend_port"]
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise ManifestError("network.frontend_port must be a valid TCP port")
    _nonempty_string(network["backend_role"], "network.backend_role")
    return manifest


def _verify_file(root: Path, entry: Mapping[str, Any], context: str, *, within: Path | None = None) -> dict[str, Any]:
    path = _resolve_path(root, entry["path"], f"{context}.path")
    if within is not None:
        try:
            path.relative_to(within)
        except ValueError as exc:
            raise ManifestError(f"{context}.path escapes its declared boundary") from exc
    if not path.is_file():
        raise ManifestError(f"{context}.path is not a regular file: {path}")
    actual_size = path.stat().st_size
    if actual_size != entry["bytes"]:
        raise ManifestError(f"{context}.bytes mismatch for {path}: {actual_size} != {entry['bytes']}")
    actual_hash = sha256_file(path)
    if actual_hash != entry["sha256"]:
        raise ManifestError(f"{context}.sha256 mismatch for {path}: {actual_hash} != {entry['sha256']}")
    return {"path": str(path), "bytes": actual_size, "sha256": actual_hash}


def _verify_named_hash(root: Path, item: Mapping[str, str], context: str, *, within: Path | None = None) -> dict[str, Any]:
    path = _resolve_path(root, item["path"], f"{context}.path")
    if within is not None:
        try:
            path.relative_to(within)
        except ValueError as exc:
            raise ManifestError(f"{context}.path escapes its declared boundary") from exc
    if not path.is_file():
        raise ManifestError(f"{context}.path is not a regular file: {path}")
    actual_hash = sha256_file(path)
    if actual_hash != item["sha256"]:
        raise ManifestError(f"{context}.sha256 mismatch for {path}: {actual_hash} != {item['sha256']}")
    return {"name": item["name"], "path": str(path), "sha256": actual_hash}


def _verify_sqlite(path: Path, expected_user_version: int) -> dict[str, Any]:
    if not path.is_file():
        raise ManifestError(f"database backup is not a regular file: {path}")
    uri = f"file:{path}?mode=ro"
    try:
        with sqlite3.connect(uri, uri=True, timeout=5) as database:
            quick = str(database.execute("PRAGMA quick_check").fetchone()[0])
            integrity = str(database.execute("PRAGMA integrity_check").fetchone()[0])
            user_version = int(database.execute("PRAGMA user_version").fetchone()[0])
    except sqlite3.Error as exc:
        raise ManifestError(f"SQLite restore validation failed for {path}: {exc}") from exc
    if quick != "ok" or integrity != "ok" or user_version != expected_user_version:
        raise ManifestError(
            f"SQLite checks failed for {path}: quick={quick!r}, integrity={integrity!r}, user_version={user_version}"
        )
    return {"quick_check": quick, "integrity_check": integrity, "user_version": user_version}


def _verify_services(services: Mapping[str, Any]) -> dict[str, str]:
    observed: dict[str, str] = {}
    for unit in [*services["required_active"], *services["required_timers"]]:
        completed = subprocess.run(
            ["systemctl", "is-active", unit],
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
        )
        state = completed.stdout.strip() or "inactive"
        observed[unit] = state
        if unit in services["required_active"] and state != "active":
            raise ManifestError(f"required service is not active: {unit}={state}")
        if unit in services["required_timers"] and state != "active":
            raise ManifestError(f"required timer is not active: {unit}={state}")
    return observed


def verify_manifest(
    document: Any,
    *,
    root: Path = Path("/"),
    manifest_path: Path | None = None,
    check_services: bool = False,
) -> dict[str, Any]:
    manifest = validate_manifest_document(document)
    root = root.resolve()
    release = manifest["release"]
    release_root = _resolve_path(root, release["root"], "release.root")
    if not release_root.is_dir():
        raise ManifestError(f"release.root is not a directory: {release_root}")
    declared_manifest = _resolve_path(root, release["manifest_path"], "release.manifest_path")
    if not declared_manifest.is_file():
        raise ManifestError(f"release.manifest_path is not a regular file: {declared_manifest}")
    try:
        declared_manifest.relative_to(release_root)
    except ValueError as exc:
        raise ManifestError("release.manifest_path escapes release.root") from exc
    if manifest_path is not None:
        supplied_manifest = manifest_path.resolve()
        if supplied_manifest != declared_manifest:
            raise ManifestError("--manifest does not match release.manifest_path")
        try:
            if json.loads(supplied_manifest.read_text(encoding="utf-8")) != manifest:
                raise ManifestError("manifest document does not match the declared manifest file")
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ManifestError(f"cannot parse declared manifest file: {supplied_manifest}") from exc

    verified_files: list[dict[str, Any]] = []
    for index, entry in enumerate(release["files"]):
        verified_files.append(_verify_file(root, entry, f"release.files[{index}]", within=release_root))
    if release_tree_sha256(release["files"]) != release["release_tree_sha256"]:
        raise ManifestError("release.release_tree_sha256 does not match its declared file inventory")

    verified_policies = [
        _verify_named_hash(root, item, f"policies[{index}]", within=release_root)
        for index, item in enumerate(manifest["policies"])
    ]

    bundle = manifest["model_bundle"]
    bundle_manifest = _resolve_path(root, bundle["manifest_path"], "model_bundle.manifest_path")
    if not bundle_manifest.is_file():
        raise ManifestError(f"model bundle manifest is not a regular file: {bundle_manifest}")
    actual_bundle_hash = sha256_file(bundle_manifest)
    if actual_bundle_hash != bundle["manifest_sha256"]:
        raise ManifestError("model_bundle.manifest_sha256 mismatch")
    verified_artifacts = [
        _verify_file(root, item, f"model_bundle.artifacts[{index}]")
        | {"name": item["name"]}
        for index, item in enumerate(_named_file_entries(bundle["artifacts"], "model_bundle.artifacts"))
    ]

    database = manifest["database"]
    database_path = _resolve_path(root, database["backup_path"], "database.backup_path")
    backup_manifest = _resolve_path(root, database["backup_manifest_path"], "database.backup_manifest_path")
    if sha256_file(database_path) != database["backup_sha256"]:
        raise ManifestError("database.backup_sha256 mismatch")
    if not backup_manifest.is_file() or sha256_file(backup_manifest) != database["backup_manifest_sha256"]:
        raise ManifestError("database.backup_manifest_sha256 mismatch")
    sqlite_report = _verify_sqlite(database_path, int(database["schema_version"]))

    report: dict[str, Any] = {
        "schema_version": "gcp_vm_rebuild_verification.v1",
        "status": "valid",
        "source_commit": manifest["source_commit"],
        "release_tree_sha256": release["release_tree_sha256"],
        "verified_files": verified_files,
        "verified_policies": verified_policies,
        "model_bundle_manifest_sha256": actual_bundle_hash,
        "verified_model_artifacts": verified_artifacts,
        "database": {"sha256": database["backup_sha256"], **sqlite_report},
        "manifest_sha256": sha256_file(declared_manifest),
    }
    if check_services:
        report["services"] = _verify_services(manifest["services"])
    return report


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path, help="concrete rebuild manifest JSON")
    parser.add_argument("--root", type=Path, default=Path("/"), help="filesystem root for verification (default: /)")
    parser.add_argument("--check-services", action="store_true", help="also require declared systemd units to be active")
    parser.add_argument("--json", action="store_true", help="emit a machine-readable verification receipt")
    args = parser.parse_args(argv)
    try:
        document = json.loads(args.manifest.read_text(encoding="utf-8"))
        report = verify_manifest(
            document,
            root=args.root,
            manifest_path=args.manifest,
            check_services=args.check_services,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ManifestError) as exc:
        payload = {"schema_version": "gcp_vm_rebuild_verification.v1", "status": "invalid", "error": str(exc)}
        print(json.dumps(payload, sort_keys=True) if args.json else f"INVALID: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(report, sort_keys=True, indent=2) if args.json else "VALID")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
