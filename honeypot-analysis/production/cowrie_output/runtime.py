"""Runtime integrity and configuration checks for the Cowrie output bundle."""

from __future__ import annotations

import configparser
import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from production.utils.cowrie_privacy import CowriePrivacyPolicy, load_policy


MANIFEST_SCHEMA_VERSION = "cowrie_output_bundle_manifest.v4"
VALIDATION_SCHEMA_VERSION = "cowrie_output_boundary_validation.v1"
EXPECTED_STARTING_SANITIZER_REVISION = "7f764ab471e8dac555d06277b4613237299aee69"
DEPLOYMENT_CONTRACT = {
    "expected_starting_sanitizer_revision": EXPECTED_STARTING_SANITIZER_REVISION,
    "compatibility": {
        "cowrie_git_revision": "575146bc6b24d70082527d66cd805d9bae0e0db4",
        "cowrie_describe": "v2.6.1-202-g575146bc-dirty",
        "python": "3.12.3",
        "twisted": "25.5.0",
        "cowrie_output_loader_sha256": "b6fc9e6c90a519404724b1a0d6cbd40281858fdfcd61af9a5fe7411c8d241b37",
        "cowrie_output_base_sha256": "0ccf8afde9797efc2a9a94569e37ab68f6727b563f09d09d96449b102868b0e3",
    },
    "receipt_schemas": {
        "writer": "cowrie_output_rollback_receipt.v2",
        "read_compatibility": [
            "cowrie_output_rollback_receipt.v2",
            "cowrie_output_rollback_receipt.legacy_tsv_actual_tab",
            "cowrie_output_rollback_receipt.legacy_tsv_literal_tab",
        ],
    },
    "installation": {
        "release_root_template": "/opt/honeypot-cowrie-output/releases/{git_revision}",
        "current_symlink": "/opt/honeypot-cowrie-output/current",
        "managed_destinations": [
            {
                "source": "generated:cowrie.cfg",
                "destination": "/home/cowrie/cowrie/etc/cowrie.cfg",
                "type": "regular",
                "owner": "cowrie",
                "group": "cowrie",
                "mode": "0600",
            },
            {
                "source": "production/cowrie_output/sanitized_jsonlog.py",
                "destination": "/home/cowrie/cowrie/src/cowrie/output/sanitizedjson.py",
                "type": "symlink",
                "owner": "cowrie",
                "group": "cowrie",
                "mode": "0777",
            },
            {
                "source": "deployment/cowrie_output/20-sanitized-output.conf",
                "destination": "/etc/systemd/system/cowrie.service.d/20-sanitized-output.conf",
                "type": "regular",
                "owner": "root",
                "group": "root",
                "mode": "0644",
            },
            {
                "source": "deployment/cowrie_output/cowrie.logrotate",
                "destination": "/etc/logrotate.d/cowrie",
                "type": "regular",
                "owner": "root",
                "group": "root",
                "mode": "0644",
            },
        ],
    },
    "service_impact": {
        "stop_then_start": ["cowrie.service"],
        "must_remain_active": ["honeypot-sensor-forwarder.service"],
    },
    "runtime_state": {
        "lifecycle_state": "/home/cowrie/cowrie/var/lib/cowrie/cowrie-output-lifecycle.json",
        "owner": "cowrie",
        "group": "cowrie",
        "directory_mode": "0700",
        "file_mode": "0600",
        "authority": "diagnostic_only",
    },
}
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
REQUIRED_BUNDLE_FILES = frozenset(
    {
        "configs/cowrie_output_privacy.v1.json",
        "deployment/cowrie_output/20-sanitized-output.conf",
        "deployment/cowrie_output/cowrie.logrotate",
        "deployment/cowrie_output/check-live-readiness.sh",
        "deployment/cowrie_output/README.md",
        "deployment/cowrie_output/install-sanitized-output.sh",
        "deployment/cowrie_output/rollback-sanitized-output.sh",
        "deployment/cowrie_output/run-sanitized-cowrie.sh",
        "production/__init__.py",
        "production/cowrie_output/__init__.py",
        "production/cowrie_output/lifecycle.py",
        "production/cowrie_output/observer_diagnostics.py",
        "production/cowrie_output/runtime.py",
        "production/cowrie_output/sanitized_jsonlog.py",
        "production/cowrie_output/twisted_logger.py",
        "production/tools/__init__.py",
        "production/tools/cowrie_rollback_receipt.py",
        "production/tools/cowrie_output_integration.py",
        "production/utils/__init__.py",
        "production/utils/cowrie_privacy.py",
    }
)
MANIFEST_NAME = "COWRIE_OUTPUT_MANIFEST.json"
MAX_BUNDLE_FILE_BYTES = 16 * 1024 * 1024
MAX_BUNDLE_BYTES = 64 * 1024 * 1024
FILE_RECEIPT_KEYS = frozenset(
    {
        "source",
        "destination",
        "file_type",
        "bytes",
        "sha256",
        "owner",
        "group",
        "mode",
        "executable",
        "classification",
    }
)


def expected_bundle_mode(relative: str) -> int:
    """Return the reviewed immutable mode for one closed-inventory file."""

    return 0o700 if relative.endswith(".sh") else 0o600


def expected_file_installation(relative: str, revision: str) -> dict[str, Any]:
    """Return the closed installation metadata that a manifest must bind."""

    mode = expected_bundle_mode(relative)
    return {
        "source": relative,
        "destination": (
            f"/opt/honeypot-cowrie-output/releases/{revision}/{relative}"
        ),
        "file_type": "regular",
        "owner": "cowrie",
        "group": "cowrie",
        "mode": f"{mode:04o}",
        "executable": bool(mode & 0o111),
        "classification": "immutable",
    }


class CowrieOutputBoundaryError(RuntimeError):
    """The output boundary cannot be proven safe."""


@dataclass(frozen=True)
class VerifiedBoundary:
    bundle_root: Path
    manifest_path: Path
    manifest_sha256: str
    git_revision: str
    component_id: str
    policy_path: Path
    policy: CowriePrivacyPolicy
    json_log_path: Path
    lifecycle_state_path: Path
    module_sha256: str


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _safe_relative(value: str) -> Path:
    path = Path(value)
    if path.is_absolute() or not path.parts or ".." in path.parts:
        raise CowrieOutputBoundaryError("manifest contains an unsafe relative path")
    return path


def _validate_manifest_document(document: Any) -> dict[str, Any]:
    """Validate the complete manifest contract independently of a filesystem."""

    if not isinstance(document, dict):
        raise CowrieOutputBoundaryError("bundle manifest must be an object")
    expected_keys = {
        "schema_version",
        "git_revision",
        "component_id",
        "deployment",
        "files",
        "policy",
    }
    if set(document) != expected_keys:
        raise CowrieOutputBoundaryError("bundle manifest keys are invalid")
    if document["schema_version"] != MANIFEST_SCHEMA_VERSION:
        raise CowrieOutputBoundaryError("bundle manifest schema is invalid")
    revision = str(document["git_revision"])
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise CowrieOutputBoundaryError("bundle Git revision is invalid")
    if (
        not isinstance(document["component_id"], str)
        or re.fullmatch(r"cowrie_output_[0-9a-f]{32}", document["component_id"])
        is None
    ):
        raise CowrieOutputBoundaryError("bundle component identity is invalid")
    if document["deployment"] != DEPLOYMENT_CONTRACT:
        raise CowrieOutputBoundaryError("bundle deployment contract is invalid")
    files = document.get("files")
    if not isinstance(files, Mapping) or set(files) != REQUIRED_BUNDLE_FILES:
        raise CowrieOutputBoundaryError("bundle file inventory is incomplete or unexpected")
    total_bytes = 0
    for relative_text, raw_receipt in files.items():
        relative = str(_safe_relative(str(relative_text)))
        receipt = raw_receipt if isinstance(raw_receipt, Mapping) else {}
        if set(receipt) != FILE_RECEIPT_KEYS:
            raise CowrieOutputBoundaryError(f"invalid file receipt: {relative_text}")
        expected = expected_file_installation(relative, revision)
        for key, value in expected.items():
            if receipt.get(key) != value:
                raise CowrieOutputBoundaryError(
                    f"bundle installation metadata mismatch: {relative_text}"
                )
        if (
            not isinstance(receipt.get("bytes"), int)
            or isinstance(receipt.get("bytes"), bool)
            or not 0 <= receipt["bytes"] <= MAX_BUNDLE_FILE_BYTES
        ):
            raise CowrieOutputBoundaryError(f"bundle size is invalid: {relative_text}")
        total_bytes += receipt["bytes"]
        if not SHA256_PATTERN.fullmatch(str(receipt.get("sha256"))):
            raise CowrieOutputBoundaryError(
                f"bundle SHA-256 is invalid: {relative_text}"
            )
    if total_bytes > MAX_BUNDLE_BYTES:
        raise CowrieOutputBoundaryError("bundle total size exceeds its limit")
    policy_receipt = document.get("policy")
    if not isinstance(policy_receipt, Mapping) or set(policy_receipt) != {
        "relative_path",
        "policy_id",
        "version",
        "sha256",
    }:
        raise CowrieOutputBoundaryError("policy receipt is invalid")
    if not SHA256_PATTERN.fullmatch(str(policy_receipt.get("sha256"))):
        raise CowrieOutputBoundaryError("policy receipt SHA-256 is invalid")
    _safe_relative(str(policy_receipt.get("relative_path")))
    identity_payload = json.dumps(
        {
            "deployment": document["deployment"],
            "git_revision": revision,
            "files": document["files"],
            "policy_sha256": policy_receipt["sha256"],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    expected_component = (
        "cowrie_output_" + hashlib.sha256(identity_payload).hexdigest()[:32]
    )
    if document["component_id"] != expected_component:
        raise CowrieOutputBoundaryError("bundle component identity does not match content")
    return document


def load_manifest_bytes(raw: bytes) -> dict[str, Any]:
    """Load and validate manifest bytes for archive preflight."""

    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CowrieOutputBoundaryError("bundle manifest is unavailable or invalid") from exc
    return _validate_manifest_document(document)


def _load_manifest(bundle_root: Path) -> tuple[dict[str, Any], Path, str]:
    manifest_path = bundle_root / MANIFEST_NAME
    try:
        raw = manifest_path.read_bytes()
    except OSError as exc:
        raise CowrieOutputBoundaryError("bundle manifest is unavailable or invalid") from exc
    return load_manifest_bytes(raw), manifest_path, hashlib.sha256(raw).hexdigest()


def verify_bundle(bundle_root: str | Path) -> tuple[dict[str, Any], Path, str]:
    root = Path(bundle_root).resolve()
    manifest, manifest_path, manifest_sha256 = _load_manifest(root)
    if stat.S_IMODE(root.stat().st_mode) != 0o700:
        raise CowrieOutputBoundaryError("bundle root permissions are not owner-only")
    if stat.S_IMODE(manifest_path.stat().st_mode) != 0o600:
        raise CowrieOutputBoundaryError("bundle manifest permissions are not owner-only")
    files = manifest["files"]
    observed_files = {
        str(path.relative_to(root))
        for path in root.rglob("*")
        if path.is_file() or path.is_symlink()
    }
    expected_files = set(REQUIRED_BUNDLE_FILES) | {MANIFEST_NAME}
    if observed_files != expected_files:
        raise CowrieOutputBoundaryError(
            "bundle contains unmanifested or missing filesystem entries"
        )
    for relative_text, raw_receipt in files.items():
        relative = _safe_relative(str(relative_text))
        receipt = raw_receipt if isinstance(raw_receipt, Mapping) else {}
        path = root / relative
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise CowrieOutputBoundaryError(f"missing bundle file: {relative_text}") from exc
        if not stat.S_ISREG(metadata.st_mode):
            raise CowrieOutputBoundaryError(f"bundle file is not regular: {relative_text}")
        if metadata.st_size != receipt["bytes"]:
            raise CowrieOutputBoundaryError(f"bundle file size mismatch: {relative_text}")
        if _sha256_file(path) != receipt["sha256"]:
            raise CowrieOutputBoundaryError(f"bundle SHA-256 mismatch: {relative_text}")
        expected_mode = int(str(receipt["mode"]), 8)
        if stat.S_IMODE(metadata.st_mode) != expected_mode:
            raise CowrieOutputBoundaryError(f"bundle mode mismatch: {relative_text}")
        parent = path.parent
        while parent != root.parent:
            if stat.S_IMODE(parent.stat().st_mode) != 0o700:
                raise CowrieOutputBoundaryError(
                    f"bundle directory permissions are not owner-only: {parent}"
                )
            if parent == root:
                break
            parent = parent.parent
    policy_receipt = manifest["policy"]
    policy_path = root / _safe_relative(str(policy_receipt["relative_path"]))
    policy = load_policy(policy_path)
    if (
        policy.policy_id != policy_receipt["policy_id"]
        or policy.version != policy_receipt["version"]
        or policy.sha256 != policy_receipt["sha256"]
    ):
        raise CowrieOutputBoundaryError("policy receipt does not match the effective policy")
    return manifest, manifest_path, manifest_sha256


def _read_config(config_path: Path) -> configparser.ConfigParser:
    parser = configparser.ConfigParser(interpolation=configparser.ExtendedInterpolation())
    cowrie_root = config_path.parent.parent
    candidates = [
        cowrie_root / "etc/cowrie.cfg.dist",
        Path("/etc/cowrie/cowrie.cfg"),
        config_path,
        cowrie_root / "cowrie.cfg",
    ]
    readable = []
    for candidate in candidates:
        resolved = candidate.resolve()
        if resolved not in readable and candidate.is_file():
            readable.append(resolved)
    if not parser.read(readable):
        raise CowrieOutputBoundaryError("Cowrie configuration is unavailable")
    return parser


def _enabled_output_sections(parser: configparser.ConfigParser) -> set[str]:
    enabled: set[str] = set()
    for section in parser.sections():
        if section.startswith("output_") and parser.getboolean(
            section, "enabled", fallback=False
        ):
            enabled.add(section)
    for key, raw_value in os.environ.items():
        match = re.fullmatch(r"COWRIE_(OUTPUT_.+)_ENABLED", key)
        if not match:
            continue
        section = match.group(1).lower()
        normalized = raw_value.strip().lower()
        if normalized in {"1", "yes", "true", "on"}:
            enabled.add(section)
        elif normalized in {"0", "no", "false", "off"}:
            enabled.discard(section)
        else:
            raise CowrieOutputBoundaryError(
                f"invalid output enablement environment override: {key}"
            )
    return enabled


def verify_config(
    config_path: str | Path,
    bundle_root: str | Path,
) -> tuple[Path, Path, Path]:
    resolved_config_path = Path(config_path).resolve()
    config = _read_config(resolved_config_path)
    enabled = _enabled_output_sections(config)
    if enabled != {"output_sanitizedjson"}:
        raise CowrieOutputBoundaryError(
            "exactly output_sanitizedjson must be enabled; unsafe or unknown writers are active"
        )
    if config.getboolean("output_jsonlog", "enabled", fallback=False):
        raise CowrieOutputBoundaryError("unsafe output_jsonlog remains enabled")
    if config.getboolean("honeypot", "ttylog", fallback=True):
        raise CowrieOutputBoundaryError(
            "credential-bearing Cowrie TTY replay remains enabled"
        )
    root = Path(bundle_root).resolve()
    configured_root = Path(
        config.get("output_sanitizedjson", "bundle_root", fallback="")
    ).resolve()
    if configured_root != root:
        raise CowrieOutputBoundaryError("configured bundle root does not match")
    manifest = Path(
        config.get("output_sanitizedjson", "manifest", fallback="")
    ).resolve()
    policy = Path(config.get("output_sanitizedjson", "policy", fallback="")).resolve()
    if manifest != root / MANIFEST_NAME:
        raise CowrieOutputBoundaryError("configured manifest path is not bundle-bound")
    if policy != root / "configs/cowrie_output_privacy.v1.json":
        raise CowrieOutputBoundaryError("configured policy path is not bundle-bound")
    logfile = config.get("output_sanitizedjson", "logfile", fallback="").strip()
    if not logfile or Path(logfile).name != "cowrie.json":
        raise CowrieOutputBoundaryError("sanitized JSON logfile path is invalid")
    log_path = Path(logfile)
    if not log_path.is_absolute():
        configured_cowrie_root = os.environ.get("HONEYPOT_COWRIE_ROOT", "").strip()
        cowrie_root = (
            Path(configured_cowrie_root).resolve()
            if configured_cowrie_root
            else resolved_config_path.parent.parent
        )
        log_path = cowrie_root / log_path
    lifecycle = config.get(
        "output_sanitizedjson", "lifecycle_state", fallback=""
    ).strip()
    if not lifecycle or Path(lifecycle).name != "cowrie-output-lifecycle.json":
        raise CowrieOutputBoundaryError("lifecycle state path is invalid")
    lifecycle_path = Path(lifecycle)
    if not lifecycle_path.is_absolute():
        configured_cowrie_root = os.environ.get("HONEYPOT_COWRIE_ROOT", "").strip()
        cowrie_root = (
            Path(configured_cowrie_root).resolve()
            if configured_cowrie_root
            else resolved_config_path.parent.parent
        )
        lifecycle_path = cowrie_root / lifecycle_path
    expected_lifecycle = Path(
        DEPLOYMENT_CONTRACT["runtime_state"]["lifecycle_state"]
    )
    if str(resolved_config_path).startswith("/home/cowrie/cowrie/"):
        if lifecycle_path.resolve() != expected_lifecycle:
            raise CowrieOutputBoundaryError("lifecycle state path is not canonical")
    elif lifecycle_path.name != expected_lifecycle.name:
        raise CowrieOutputBoundaryError("lifecycle state filename is not canonical")
    return policy, log_path.resolve(), lifecycle_path.resolve()


def verify_boundary(
    *,
    config_path: str | Path,
    bundle_root: str | Path,
    plugin_link: str | Path | None = None,
    drop_in: str | Path | None = None,
    logrotate: str | Path | None = None,
) -> VerifiedBoundary:
    root = Path(bundle_root).resolve()
    manifest, manifest_path, manifest_sha256 = verify_bundle(root)
    policy_path, logfile, lifecycle_state = verify_config(config_path, root)
    policy = load_policy(policy_path)
    if plugin_link is not None:
        link = Path(plugin_link)
        if not link.is_symlink():
            raise CowrieOutputBoundaryError("sanitized output plugin link is absent")
        if link.resolve() != root / "production/cowrie_output/sanitized_jsonlog.py":
            raise CowrieOutputBoundaryError("sanitized output plugin link target is invalid")
    if drop_in is not None:
        try:
            unit_text = Path(drop_in).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise CowrieOutputBoundaryError("Cowrie systemd drop-in is unavailable") from exc
        required_fragments = (
            "UMask=0077",
            "ExecStartPre=",
            "production.tools.cowrie_output_integration validate",
            "production.tools.cowrie_output_integration plugin-readiness",
            "--write-state",
            "run-sanitized-cowrie.sh",
            "check-live-readiness.sh",
            "StandardOutput=null",
            "StandardError=null",
            "--live-permissions",
            "--logrotate /etc/logrotate.d/cowrie",
            "Environment=PYTHONPATH=/opt/honeypot-cowrie-output/current:/home/cowrie/cowrie/src",
            "Environment=PYTHONDONTWRITEBYTECODE=1",
            "ReadOnlyPaths=/home/cowrie/users.txt",
            "ReadOnlyPaths=/home/cowrie/cowrie/var/log/cowrie/cowrie_custom.json",
        )
        if any(fragment not in unit_text for fragment in required_fragments):
            raise CowrieOutputBoundaryError("Cowrie systemd drop-in is incomplete")
    if logrotate is not None:
        installed_logrotate = Path(logrotate)
        expected_logrotate = root / "deployment/cowrie_output/cowrie.logrotate"
        try:
            metadata = installed_logrotate.lstat()
        except OSError as exc:
            raise CowrieOutputBoundaryError("Cowrie logrotate policy is unavailable") from exc
        if not stat.S_ISREG(metadata.st_mode) or installed_logrotate.is_symlink():
            raise CowrieOutputBoundaryError("Cowrie logrotate policy is not a regular file")
        if stat.S_IMODE(metadata.st_mode) != 0o644:
            raise CowrieOutputBoundaryError("Cowrie logrotate policy mode is invalid")
        if str(installed_logrotate).startswith("/etc/") and (
            metadata.st_uid != 0 or metadata.st_gid != 0
        ):
            raise CowrieOutputBoundaryError("Cowrie logrotate policy ownership is invalid")
        if _sha256_file(installed_logrotate) != _sha256_file(expected_logrotate):
            raise CowrieOutputBoundaryError("Cowrie logrotate policy differs from the bundle")
    return VerifiedBoundary(
        bundle_root=root,
        manifest_path=manifest_path,
        manifest_sha256=manifest_sha256,
        git_revision=str(manifest["git_revision"]),
        component_id=str(manifest["component_id"]),
        policy_path=policy_path,
        policy=policy,
        json_log_path=logfile,
        lifecycle_state_path=lifecycle_state,
        module_sha256=str(
            manifest["files"]["production/cowrie_output/sanitized_jsonlog.py"][
                "sha256"
            ]
        ),
    )


def boundary_from_environment() -> VerifiedBoundary:
    config_path = os.environ.get(
        "HONEYPOT_COWRIE_CONFIG", "/home/cowrie/cowrie/etc/cowrie.cfg"
    )
    bundle_root = os.environ.get(
        "HONEYPOT_COWRIE_OUTPUT_ROOT", "/opt/honeypot-cowrie-output/current"
    )
    return verify_boundary(config_path=config_path, bundle_root=bundle_root)
