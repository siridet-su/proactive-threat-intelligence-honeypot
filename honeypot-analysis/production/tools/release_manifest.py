from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


SCHEMA_VERSION = "honeypot_release_manifest.v4"
LEGACY_SCHEMA_VERSIONS = frozenset(
    {"honeypot_release_manifest.v2", "honeypot_release_manifest.v3"}
)
REVISION_PATTERN = re.compile(r"^[0-9a-f]{40}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
EXCLUDED_RELEASE_FILES = frozenset({"DEPLOYED_COMMIT", "DEPLOYMENT_MANIFEST.json"})
RUNTIME_BYTECODE_SUFFIXES = frozenset({".pyc", ".pyo"})
MUTABLE_RUNTIME_FEED_CONFIGURATION_NAMES = frozenset(
    {"cisa_cache", "sigma_cache", "mitre_cache"}
)
MUTABLE_RUNTIME_FEED_BASENAMES = frozenset(
    {"cisa_kev_cache.json", "sigma_rules_cache.json", "mitre_attack_cache.json"}
)
RUNTIME_FEED_PROVENANCE_SCHEMA = "runtime_feed_provenance.v1"


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def release_file_inventory(root: Path) -> dict[str, dict[str, Any]]:
    root = root.resolve()
    if not root.is_dir():
        raise ValueError("release root must be a directory")
    inventory: dict[str, dict[str, Any]] = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if relative in EXCLUDED_RELEASE_FILES:
            continue
        # Python may compile imported modules in-place after a release has been
        # verified.  Those bytecode caches are reproducible runtime byproducts,
        # not deployed source or an undocumented overlay; retaining them in the
        # immutable inventory would make a valid release unverifiable at runtime.
        if (
            "__pycache__" in Path(relative).parts
            or path.suffix in RUNTIME_BYTECODE_SUFFIXES
        ):
            continue
        if path.is_symlink():
            target = os.readlink(path)
            inventory[relative] = {
                "type": "symlink",
                "target": target,
                "sha256": _sha256_bytes(target.encode("utf-8")),
            }
        elif path.is_dir():
            continue
        elif path.is_file():
            inventory[relative] = {
                "type": "file",
                "bytes": path.stat().st_size,
                "sha256": _sha256_file(path),
            }
        else:
            raise ValueError(f"unsupported release entry: {relative}")
    if not inventory:
        raise ValueError("release inventory must not be empty")
    return inventory


def inventory_sha256(inventory: dict[str, dict[str, Any]]) -> str:
    encoded = json.dumps(
        inventory, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return _sha256_bytes(encoded)


def _named_paths(values: Iterable[str], field: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for value in values:
        name, separator, path = value.partition("=")
        name = name.strip()
        path = path.strip()
        if not separator or not name or not path or name in parsed:
            raise ValueError(f"{field} values must be unique NAME=PATH pairs")
        parsed[name] = str(Path(path).resolve())
    return dict(sorted(parsed.items()))


def _artifact_hashes(paths: dict[str, str]) -> dict[str, dict[str, Any]]:
    artifacts: dict[str, dict[str, Any]] = {}
    for name, path_text in paths.items():
        path = Path(path_text)
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"artifact {name} must be a regular file")
        artifacts[name] = {
            "path": str(path.resolve()),
            "bytes": path.stat().st_size,
            "sha256": _sha256_file(path),
        }
    return artifacts


def _validate_immutable_configuration_paths(paths: dict[str, str]) -> None:
    """Reject mutable feed caches from the immutable release boundary."""
    for name, path_text in paths.items():
        if (
            name in MUTABLE_RUNTIME_FEED_CONFIGURATION_NAMES
            or Path(path_text).name in MUTABLE_RUNTIME_FEED_BASENAMES
        ):
            raise ValueError(
                "mutable runtime feed caches must not be immutable release "
                "configuration inputs; record them through runtime feed provenance"
            )


def _runtime_feed_provenance_contract(path_text: str) -> dict[str, Any]:
    return {
        "schema_version": RUNTIME_FEED_PROVENANCE_SCHEMA,
        "path": str(Path(path_text).resolve()),
        "integrity": {
            "cache_file_sha256_required": True,
            "cache_content_checksum_required": True,
        },
        "required_fields": [
            "feed_version",
            "retrieved_at",
            "importer",
            "evaluator_git_revision",
        ],
        "authority": "non_authoritative_context_only",
    }


def _frozen_model_bundle_receipt(
    manifest_path_text: str,
    package_path_text: str = "",
) -> dict[str, Any]:
    """Bind a separately managed immutable model bundle to this release."""

    manifest_path = Path(manifest_path_text).resolve()
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise ValueError("frozen model bundle manifest must be a regular file")
    try:
        bundle = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("frozen model bundle manifest is unreadable") from exc
    if (
        not isinstance(bundle, dict)
        or bundle.get("schema_version") != "frozen_model_bundle.v1"
        or not str(bundle.get("bundle_id") or "").strip()
        or not SHA256_PATTERN.fullmatch(
            str(bundle.get("artifact_inventory_sha256") or "")
        )
    ):
        raise ValueError("frozen model bundle manifest is invalid")
    receipt: dict[str, Any] = {
        "manifest_path": str(manifest_path),
        "manifest_sha256": _sha256_file(manifest_path),
        "bundle_id": str(bundle["bundle_id"]),
        "artifact_inventory_sha256": str(bundle["artifact_inventory_sha256"]),
    }
    if package_path_text.strip():
        package_path = Path(package_path_text).resolve()
        if not package_path.is_file() or package_path.is_symlink():
            raise ValueError("frozen model bundle package must be a regular file")
        receipt["package"] = {
            "path": str(package_path),
            "bytes": package_path.stat().st_size,
            "sha256": _sha256_file(package_path),
        }
    return receipt


def build_manifest(
    *,
    revision: str,
    release_root: Path,
    package_path: Path,
    rollback_location: Path,
    configuration_paths: dict[str, str],
    artifact_paths: dict[str, str],
    runtime_feed_provenance_path: str = "",
    frozen_model_bundle_manifest_path: str = "",
    frozen_model_bundle_package_path: str = "",
    deployed_at: str | None = None,
) -> dict[str, Any]:
    if not REVISION_PATTERN.fullmatch(revision):
        raise ValueError("revision must be a full lowercase Git SHA-1")
    package_path = package_path.resolve()
    rollback_location = rollback_location.resolve()
    if not package_path.is_file():
        raise ValueError("release package does not exist")
    if not rollback_location.exists():
        raise ValueError("rollback location does not exist")
    _validate_immutable_configuration_paths(configuration_paths)
    inventory = release_file_inventory(release_root)
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "git_revision": revision,
        "deployed_at": deployed_at or datetime.now(timezone.utc).isoformat(),
        "release_path": str(release_root.resolve()),
        "release_files": inventory,
        "release_tree_sha256": inventory_sha256(inventory),
        "package": {
            "path": str(package_path),
            "bytes": package_path.stat().st_size,
            "sha256": _sha256_file(package_path),
        },
        "effective_configurations": _artifact_hashes(configuration_paths),
        "model_artifacts": _artifact_hashes(artifact_paths),
        "rollback_location": str(rollback_location),
    }
    if runtime_feed_provenance_path.strip():
        manifest["runtime_feed_provenance"] = _runtime_feed_provenance_contract(
            runtime_feed_provenance_path
        )
    if frozen_model_bundle_package_path.strip() and not frozen_model_bundle_manifest_path.strip():
        raise ValueError("frozen model bundle package requires its manifest")
    if frozen_model_bundle_manifest_path.strip():
        manifest["frozen_model_bundle"] = _frozen_model_bundle_receipt(
            frozen_model_bundle_manifest_path,
            frozen_model_bundle_package_path,
        )
    return manifest


def write_manifest(path: Path, manifest: dict[str, Any]) -> None:
    path = path.resolve()
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(manifest, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise


def verify_manifest(path: Path, release_root: Path) -> dict[str, Any]:
    manifest = json.loads(path.read_text(encoding="utf-8"))
    schema_version = manifest.get("schema_version")
    if schema_version not in {SCHEMA_VERSION, *LEGACY_SCHEMA_VERSIONS}:
        raise ValueError("unsupported release manifest schema")
    if not REVISION_PATTERN.fullmatch(str(manifest.get("git_revision", ""))):
        raise ValueError("manifest Git revision is invalid")
    if Path(str(manifest.get("release_path", ""))).resolve() != release_root.resolve():
        raise ValueError("manifest release path mismatch")
    actual_inventory = release_file_inventory(release_root)
    if actual_inventory != manifest.get("release_files"):
        raise ValueError("deployed release files do not match manifest")
    if inventory_sha256(actual_inventory) != manifest.get("release_tree_sha256"):
        raise ValueError("deployed release tree hash does not match manifest")
    package = manifest.get("package")
    if not isinstance(package, dict):
        raise ValueError("manifest package metadata is invalid")
    package_path = Path(str(package.get("path", "")))
    if (
        not package_path.is_file()
        or package_path.stat().st_size != package.get("bytes")
        or _sha256_file(package_path) != package.get("sha256")
    ):
        raise ValueError("release package does not match manifest")
    for name, artifact in (manifest.get("model_artifacts") or {}).items():
        if not isinstance(artifact, dict):
            raise ValueError(f"artifact metadata invalid: {name}")
        artifact_path = Path(str(artifact.get("path", "")))
        if (
            not artifact_path.is_file()
            or artifact_path.stat().st_size != artifact.get("bytes")
            or _sha256_file(artifact_path) != artifact.get("sha256")
        ):
            raise ValueError(f"artifact does not match manifest: {name}")
    for name, config in (manifest.get("effective_configurations") or {}).items():
        if not isinstance(config, dict):
            raise ValueError(f"effective configuration metadata invalid: {name}")
        config_path = Path(str(config.get("path", "")))
        if (
            not config_path.is_file()
            or config_path.stat().st_size != config.get("bytes")
            or _sha256_file(config_path) != config.get("sha256")
        ):
            raise ValueError(f"effective configuration does not match: {name}")
    if schema_version in {SCHEMA_VERSION, "honeypot_release_manifest.v3"}:
        contract = manifest.get("runtime_feed_provenance")
        if contract is not None:
            if not isinstance(contract, dict):
                raise ValueError("runtime feed provenance contract is invalid")
            if contract.get("schema_version") != RUNTIME_FEED_PROVENANCE_SCHEMA:
                raise ValueError("runtime feed provenance contract schema is invalid")
            if not Path(str(contract.get("path", ""))).is_absolute():
                raise ValueError("runtime feed provenance path must be absolute")
            if contract.get("authority") != "non_authoritative_context_only":
                raise ValueError("runtime feed provenance authority is invalid")
            integrity = contract.get("integrity")
            if not isinstance(integrity, dict) or (
                integrity.get("cache_file_sha256_required") is not True
                or integrity.get("cache_content_checksum_required") is not True
            ):
                raise ValueError("runtime feed provenance integrity contract is invalid")
    frozen_model_bundle = manifest.get("frozen_model_bundle")
    if frozen_model_bundle is not None:
        if not isinstance(frozen_model_bundle, dict):
            raise ValueError("frozen model bundle receipt is invalid")
        actual = _frozen_model_bundle_receipt(
            str(frozen_model_bundle.get("manifest_path") or ""),
            str((frozen_model_bundle.get("package") or {}).get("path") or ""),
        )
        if actual != frozen_model_bundle:
            raise ValueError("frozen model bundle does not match manifest receipt")
    if not Path(str(manifest.get("rollback_location", ""))).exists():
        raise ValueError("rollback location is missing")
    return {
        "verified": True,
        "git_revision": manifest["git_revision"],
        "release_tree_sha256": manifest["release_tree_sha256"],
        "release_file_count": len(actual_inventory),
        "manifest_sha256": _sha256_file(path),
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Create or verify a hash-bound honeypot release manifest"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    create = subparsers.add_parser("create")
    create.add_argument("--revision", required=True)
    create.add_argument("--release-root", required=True, type=Path)
    create.add_argument("--package", required=True, type=Path)
    create.add_argument("--rollback-location", required=True, type=Path)
    create.add_argument("--configuration", action="append", default=[])
    create.add_argument("--artifact", action="append", default=[])
    create.add_argument(
        "--runtime-feed-provenance",
        default="",
        help="Mutable runtime feed-provenance file, excluded from release hashes.",
    )
    create.add_argument(
        "--frozen-model-bundle-manifest",
        default="",
        help="Immutable separately managed frozen-model bundle manifest.",
    )
    create.add_argument(
        "--frozen-model-bundle-package",
        default="",
        help="Optional verified recovery archive for the frozen model bundle.",
    )
    create.add_argument("--output", required=True, type=Path)
    verify = subparsers.add_parser("verify")
    verify.add_argument("--manifest", required=True, type=Path)
    verify.add_argument("--release-root", required=True, type=Path)
    return parser


def main() -> int:
    args = _parser().parse_args()
    if args.command == "create":
        manifest = build_manifest(
            revision=args.revision,
            release_root=args.release_root,
            package_path=args.package,
            rollback_location=args.rollback_location,
            configuration_paths=_named_paths(args.configuration, "configuration"),
            artifact_paths=_named_paths(args.artifact, "artifact"),
            runtime_feed_provenance_path=args.runtime_feed_provenance,
            frozen_model_bundle_manifest_path=args.frozen_model_bundle_manifest,
            frozen_model_bundle_package_path=args.frozen_model_bundle_package,
        )
        write_manifest(args.output, manifest)
        result = verify_manifest(args.output, args.release_root)
    else:
        result = verify_manifest(args.manifest, args.release_root)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
