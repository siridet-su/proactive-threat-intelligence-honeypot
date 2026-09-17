"""Shared, offline validation for reviewed external-reference provenance.

The policy files are allowed to cite public material, but a URL alone is not
evidence that the title or semantics behind the URL were checked.  This module
keeps that check deterministic and offline: policy validators bind references
to the reviewed manifest, and the manifest records the public snapshot hash.

No runtime network access is performed here.  A source refresh is an explicit
reviewer operation which creates a new manifest and a new policy version.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional


MANIFEST_SCHEMA_VERSION = "trusted_reference_manifest.v1"
DEFAULT_MANIFEST_PATH = "configs/trusted_reference_manifest.v1.json"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)
TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)


def project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def clean(value: Any) -> str:
    return str(value or "").strip()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def normalize_url(value: Any) -> str:
    text = clean(value)
    return f"{text.rstrip('/')}/" if text else ""


def _nonempty_text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _string_list(value: Any) -> bool:
    return isinstance(value, list) and bool(value) and all(_nonempty_text(item) for item in value)


def load_reference_manifest(path_text: str = "") -> Dict[str, Any]:
    path = Path(path_text) if path_text else project_root() / DEFAULT_MANIFEST_PATH
    loaded = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise ValueError("reference manifest root must be an object")
    return loaded


def _resolve_project_path(path_text: Any, root: Optional[Path] = None) -> Optional[Path]:
    text = clean(path_text)
    if not text or Path(text).is_absolute():
        return None
    candidate = (root or project_root()) / text
    try:
        candidate.resolve().relative_to((root or project_root()).resolve())
    except ValueError:
        return None
    return candidate


def validate_reference_manifest(manifest: Any) -> List[str]:
    errors: List[str] = []
    if not isinstance(manifest, dict):
        return ["reference manifest: root must be an object"]
    if manifest.get("schema_version") != MANIFEST_SCHEMA_VERSION:
        errors.append(
            f"reference manifest: schema_version must be {MANIFEST_SCHEMA_VERSION}"
        )
    for key in ("manifest_id", "generated_at", "runtime_fetch"):
        if not _nonempty_text(manifest.get(key)):
            errors.append(f"reference manifest: {key} is required")
    if manifest.get("runtime_fetch") != "disabled":
        errors.append("reference manifest: runtime_fetch must be disabled")

    sources = manifest.get("source_artifacts")
    if not isinstance(sources, dict) or not sources:
        errors.append("reference manifest: source_artifacts must be a non-empty object")
        sources = {}
    for source_id, source in sources.items():
        path = f"reference manifest.source_artifacts.{source_id}"
        if not isinstance(source, dict):
            errors.append(f"{path}: must be an object")
            continue
        for key in ("type", "name", "url", "retrieved_at"):
            if not _nonempty_text(source.get(key)):
                errors.append(f"{path}: {key} is required")
        digest = clean(source.get("sha256")).lower()
        if not SHA256_RE.fullmatch(digest):
            errors.append(f"{path}.sha256: must be a SHA-256 digest")
        if not _string_list(source.get("supports")):
            errors.append(f"{path}.supports: must be a non-empty string list")
        if not _string_list(source.get("does_not_support")):
            errors.append(f"{path}.does_not_support: must be a non-empty string list")

    runtime_cache = manifest.get("runtime_cache")
    if not isinstance(runtime_cache, dict):
        errors.append("reference manifest: runtime_cache is required")
    else:
        for key in ("path", "version", "role"):
            if not _nonempty_text(runtime_cache.get(key)):
                errors.append(f"reference manifest.runtime_cache: {key} is required")
        if not SHA256_RE.fullmatch(clean(runtime_cache.get("sha256")).lower()):
            errors.append("reference manifest.runtime_cache.sha256: must be a SHA-256 digest")

    default_scope = manifest.get("default_scope")
    if not isinstance(default_scope, dict):
        errors.append("reference manifest: default_scope is required")
    else:
        for key in ("supports", "does_not_support"):
            if not _string_list(default_scope.get(key)):
                errors.append(f"reference manifest.default_scope.{key}: must be a non-empty string list")

    techniques = manifest.get("techniques")
    if not isinstance(techniques, dict) or not techniques:
        errors.append("reference manifest: techniques must be a non-empty object")
        techniques = {}
    for technique_id, technique in techniques.items():
        path = f"reference manifest.techniques.{technique_id}"
        if not TECHNIQUE_RE.fullmatch(str(technique_id)):
            errors.append(f"{path}: invalid technique ID")
        if not isinstance(technique, dict):
            errors.append(f"{path}: must be an object")
            continue
        for key in ("name", "canonical_url", "source_artifact_id", "object_id", "modified", "version"):
            if not _nonempty_text(technique.get(key)):
                errors.append(f"{path}: {key} is required")
        if not SHA256_RE.fullmatch(clean(technique.get("object_sha256")).lower()):
            errors.append(f"{path}.object_sha256: must be a SHA-256 digest")
        if not isinstance(technique.get("revoked"), bool):
            errors.append(f"{path}.revoked: must be boolean")
        if technique.get("source_artifact_id") not in sources:
            errors.append(f"{path}: unknown source_artifact_id")
        if technique.get("revoked") and not TECHNIQUE_RE.fullmatch(
            clean(technique.get("superseded_by"))
        ):
            errors.append(f"{path}: revoked technique must declare superseded_by")
        if not technique.get("revoked") and technique.get("superseded_by"):
            errors.append(f"{path}: active technique must not declare superseded_by")
    return errors


def validate_manifest_binding(
    document: Dict[str, Any],
    errors: List[str],
    *,
    path_prefix: str = "reference_manifest",
    root: Optional[Path] = None,
) -> Optional[Dict[str, Any]]:
    binding = document.get("reference_manifest")
    if not isinstance(binding, dict):
        errors.append(f"{path_prefix}: binding is required")
        return None
    path_text = clean(binding.get("path"))
    expected = clean(binding.get("sha256")).lower()
    if not path_text:
        errors.append(f"{path_prefix}.path: is required")
        return None
    if not SHA256_RE.fullmatch(expected):
        errors.append(f"{path_prefix}.sha256: must be a SHA-256 digest")
    manifest_path = _resolve_project_path(path_text, root)
    if manifest_path is None:
        errors.append(f"{path_prefix}.path: must resolve inside the project")
        return None
    try:
        actual = sha256_file(manifest_path)
        if SHA256_RE.fullmatch(expected) and actual != expected:
            errors.append(f"{path_prefix}: SHA-256 mismatch")
        manifest = load_reference_manifest(str(manifest_path))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        errors.append(f"{path_prefix}: cannot load bound manifest ({type(exc).__name__})")
        return None
    errors.extend(validate_reference_manifest(manifest))
    return manifest


def validate_runtime_cache_binding(
    binding: Any,
    errors: List[str],
    *,
    root: Optional[Path] = None,
    path_prefix: str = "mitre_cache_binding",
) -> None:
    if not isinstance(binding, dict):
        errors.append(f"{path_prefix}: binding is required")
        return
    path_text = clean(binding.get("path"))
    expected = clean(binding.get("sha256")).lower()
    version = clean(binding.get("version"))
    if not path_text or not version:
        errors.append(f"{path_prefix}: path and version are required")
    if not SHA256_RE.fullmatch(expected):
        errors.append(f"{path_prefix}.sha256: must be a SHA-256 digest")
    cache_path = _resolve_project_path(path_text, root)
    if cache_path is None:
        errors.append(f"{path_prefix}.path: must resolve inside the project")
        return
    try:
        actual = sha256_file(cache_path)
    except OSError as exc:
        errors.append(f"{path_prefix}: cannot read cache ({type(exc).__name__})")
        return
    if SHA256_RE.fullmatch(expected) and actual != expected:
        errors.append(f"{path_prefix}: SHA-256 mismatch")


def _technique_from_url(url: Any) -> str:
    match = re.search(r"/techniques/(T\d{4})(?:/(\d{3}))?/?$", clean(url), re.IGNORECASE)
    if not match:
        return ""
    return match.group(1).upper() + (f".{match.group(2)}" if match.group(2) else "")


def validate_attack_reference(
    reference: Any,
    ttp: str,
    manifest: Dict[str, Any],
    errors: List[str],
    path: str,
    *,
    retired: bool = False,
    historical_pinned: bool = False,
) -> None:
    if not isinstance(reference, dict):
        return
    url = normalize_url(reference.get("url"))
    reference_ttp = _technique_from_url(url)
    expected_ttp = clean(ttp).upper()
    if reference_ttp != expected_ttp:
        errors.append(f"{path}: URL technique {reference_ttp or '<missing>'} does not match TTP {expected_ttp}")
        return
    technique = (manifest.get("techniques") or {}).get(expected_ttp)
    if not isinstance(technique, dict):
        errors.append(f"{path}: TTP {expected_ttp} is absent from the reference manifest")
        return
    if url != normalize_url(technique.get("canonical_url")):
        errors.append(f"{path}: URL is not the manifest canonical URL for {expected_ttp}")
    expected_name = clean(technique.get("name")).lower()
    actual_name = clean(reference.get("name")).lower()
    if expected_name and expected_name not in actual_name:
        errors.append(f"{path}: reference title does not match manifest title for {expected_ttp}")
    if technique.get("revoked"):
        if not retired and not historical_pinned:
            errors.append(f"{path}: revoked TTP {expected_ttp} cannot be used by an active rule")
        if clean(technique.get("superseded_by")) != "T1685":
            errors.append(f"{path}: revoked TTP {expected_ttp} has no approved replacement")


def validate_source_artifacts(
    artifacts: Any,
    errors: List[str],
    *,
    root: Optional[Path] = None,
    path_prefix: str = "source_artifacts",
) -> None:
    if not isinstance(artifacts, list) or not artifacts:
        errors.append(f"{path_prefix}: must be a non-empty list")
        return
    for index, artifact in enumerate(artifacts):
        path = f"{path_prefix}[{index}]"
        if not isinstance(artifact, dict):
            errors.append(f"{path}: must be an object")
            continue
        for key in ("artifact_id", "path", "purpose"):
            if not _nonempty_text(artifact.get(key)):
                errors.append(f"{path}: {key} is required")
        digest = clean(artifact.get("sha256")).lower()
        if not SHA256_RE.fullmatch(digest):
            errors.append(f"{path}.sha256: must be a SHA-256 digest")
        for key in ("supports", "does_not_support"):
            if not _string_list(artifact.get(key)):
                errors.append(f"{path}.{key}: must be a non-empty string list")
        artifact_path = _resolve_project_path(artifact.get("path"), root)
        if artifact_path is None:
            errors.append(f"{path}.path: must resolve inside the project")
            continue
        try:
            actual = sha256_file(artifact_path)
        except OSError as exc:
            errors.append(f"{path}: cannot read artifact ({type(exc).__name__})")
            continue
        if SHA256_RE.fullmatch(digest) and actual != digest:
            errors.append(f"{path}: SHA-256 mismatch")


def validate_source_scope(scope: Any, errors: List[str], path: str) -> None:
    if not isinstance(scope, dict):
        errors.append(f"{path}: reference scope is required")
        return
    for key in ("supports", "does_not_support"):
        if not _string_list(scope.get(key)):
            errors.append(f"{path}.{key}: must be a non-empty string list")


def validate_external_source_binding(
    source_id: str,
    source: Any,
    manifest: Dict[str, Any],
    errors: List[str],
    path: str,
) -> None:
    """Verify a response-policy source against a manifest artifact."""

    if not isinstance(source, dict):
        return
    manifest_source_id = clean(source.get("manifest_source_id"))
    if not manifest_source_id:
        errors.append(f"{path}: manifest_source_id is required")
        return
    artifacts = manifest.get("source_artifacts") or {}
    artifact = artifacts.get(manifest_source_id)
    if not isinstance(artifact, dict):
        errors.append(f"{path}: unknown manifest_source_id {manifest_source_id!r}")
        return
    technique_id = clean(source.get("manifest_technique_id")).upper()
    if technique_id:
        technique = (manifest.get("techniques") or {}).get(technique_id)
        if not isinstance(technique, dict):
            errors.append(f"{path}: unknown manifest_technique_id {technique_id!r}")
            return
        if manifest_source_id != clean(technique.get("source_artifact_id")):
            errors.append(f"{path}: manifest source does not own {technique_id}")
        expected_url = normalize_url(technique.get("canonical_url"))
        if normalize_url(source.get("url")) != expected_url:
            errors.append(f"{path}: URL does not match manifest technique {technique_id}")
        if clean(source.get("snapshot_sha256")).lower() != clean(technique.get("object_sha256")).lower():
            errors.append(f"{path}: snapshot SHA-256 does not match manifest technique {technique_id}")
        if technique.get("revoked"):
            errors.append(f"{path}: response source must not cite revoked technique {technique_id}")
        return

    aliases = [normalize_url(value) for value in (artifact.get("aliases") or [])]
    expected_url = normalize_url(artifact.get("url"))
    if normalize_url(source.get("url")) not in {expected_url, *aliases}:
        errors.append(f"{path}: URL does not match manifest source artifact")
    if clean(source.get("snapshot_sha256")).lower() != clean(artifact.get("sha256")).lower():
        errors.append(f"{path}: snapshot SHA-256 does not match manifest source artifact")
