#!/usr/bin/env python3
"""Create and verify an immutable, separately managed frozen-model bundle.

The bundle contains only the exact Transformer and SecureBERT runtime files
already pinned by reviewed policy receipts.  It is intentionally outside Git
and a release archive; releases link to it only before their manifest is
created, then record both the bundle manifest and individual artifact hashes.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import pwd
import grp
import shutil
import stat
import tarfile
from pathlib import Path
from typing import Any, Mapping, Sequence

from production.prediction.next_behavior_model import load_checkpoint
from production.prediction.next_behavior_runtime import (
    FrozenTransformerPocPredictor,
    _apply_frozen_calibration,
    _load_json,
)
from production.prediction.next_behavior_tensor import (
    require_valid_vocabulary,
    vocabulary_sha256,
)
from production.policies.validate_prediction_policy import (
    TRANSFORMER_POC_MODE,
    load_policy_file,
    validate_policy_document,
)
from production.reproduction.next_behavior.classifier_assets import (
    load_classifier_manifest,
    verify_classifier_assets,
)
from production.utils.serialization import stable_json


SCHEMA_VERSION = "frozen_model_bundle.v1"
MANIFEST_NAME = "FROZEN_MODEL_BUNDLE_MANIFEST.json"
TRANSFORMER_SPECS = (
    ("transformer_checkpoint", "transformer_checkpoint_path", "transformer_checkpoint_sha256"),
    ("transformer_model_spec", "transformer_model_spec_path", "transformer_model_spec_file_sha256"),
    ("transformer_vocabulary", "transformer_vocabulary_path", "transformer_vocabulary_file_sha256"),
    ("transformer_calibration", "transformer_calibration_path", "transformer_calibration_file_sha256"),
)
SECUREBERT_RELATIVE_FILES = (
    "config.json",
    "label_mapping.json",
    "tokenizer.json",
    "tokenizer_config.json",
    "checkpoint-6765/config.json",
    "checkpoint-6765/model.safetensors",
    "checkpoint-6765/tokenizer.json",
    "checkpoint-6765/tokenizer_config.json",
)


class FrozenModelBundleError(ValueError):
    """Raised when an artifact bundle cannot be safely trusted."""


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(stable_json(value).encode("utf-8")).hexdigest()


def _safe_relative(value: str | Path) -> Path:
    path = Path(value)
    if path.is_absolute() or not path.parts or ".." in path.parts:
        raise FrozenModelBundleError("artifact path must be a safe relative path")
    return path


def _regular_file(path: Path, label: str) -> None:
    try:
        mode = path.lstat().st_mode
    except OSError as exc:
        raise FrozenModelBundleError(f"missing {label}") from exc
    if not stat.S_ISREG(mode):
        raise FrozenModelBundleError(f"{label} must be a regular file")


def _receipt(path: Path, expected: str, label: str) -> dict[str, Any]:
    _regular_file(path, label)
    actual = _sha256_file(path)
    if actual != expected:
        raise FrozenModelBundleError(f"{label} SHA-256 mismatch")
    return {
        "relative_path": "",
        "bytes": path.stat().st_size,
        "sha256": actual,
    }


def _transformer_policy(policy_path: Path) -> tuple[dict[str, Any], str]:
    document = load_policy_file(policy_path)
    errors = validate_policy_document(
        document,
        repository_root=policy_path.resolve().parent.parent,
    )
    if errors:
        raise FrozenModelBundleError("invalid prediction policy: " + "; ".join(errors))
    policy = document.get("policy")
    if not isinstance(policy, dict) or policy.get("prediction_mode") != TRANSFORMER_POC_MODE:
        raise FrozenModelBundleError("prediction policy must select the frozen Transformer")
    return copy.deepcopy(policy), _sha256_file(policy_path)


def _mapped_transformer_policy(
    policy: Mapping[str, Any],
    paths: Mapping[str, Path],
) -> dict[str, Any]:
    mapped = copy.deepcopy(dict(policy))
    for role, path_key, _hash_key in TRANSFORMER_SPECS:
        mapped[path_key] = str(paths[role])
    return mapped


def _validate_transformer_runtime(policy: Mapping[str, Any]) -> dict[str, Any]:
    spec = _load_json(
        policy["transformer_model_spec_path"],
        policy["transformer_model_spec_file_sha256"],
        "model_spec",
    )
    vocabulary = require_valid_vocabulary(
        _load_json(
            policy["transformer_vocabulary_path"],
            policy["transformer_vocabulary_file_sha256"],
            "vocabulary",
        )
    )
    semantic_vocabulary_sha256 = vocabulary_sha256(vocabulary)
    if semantic_vocabulary_sha256 != policy["transformer_vocabulary_sha256"]:
        raise FrozenModelBundleError("vocabulary semantic SHA-256 mismatch")
    calibration = _load_json(
        policy["transformer_calibration_path"],
        policy["transformer_calibration_file_sha256"],
        "calibration",
    )
    _apply_frozen_calibration(
        {
            "tactic_logits": {
                tactic: 0.0 for tactic in spec["output"]["tactics"]
            },
            "terminal_logit": 0.0,
        },
        calibration,
        policy,
        semantic_vocabulary_sha256,
    )
    model, metadata = load_checkpoint(
        policy["transformer_checkpoint_path"],
        expected_spec=spec,
        expected_checkpoint_sha256=policy["transformer_checkpoint_sha256"],
    )
    del model
    if metadata["parameter_count"] != int(policy["transformer_parameter_count"]):
        raise FrozenModelBundleError("Transformer parameter count mismatch")
    if metadata["initialization_seed"] != int(policy["transformer_seed"]):
        raise FrozenModelBundleError("Transformer seed mismatch")
    return {
        "model_spec_schema_version": spec.get("schema_version", ""),
        "model_architecture_sha256": _sha256_json(spec.get("architecture") or {}),
        "vocabulary_schema_version": vocabulary.get("schema_version", ""),
        "vocabulary_semantic_sha256": semantic_vocabulary_sha256,
        "calibration_schema_version": calibration.get("schema_version", ""),
        "calibration_mapping_sha256": calibration.get("mapping_sha256", ""),
        "calibration_membership_sha256": calibration.get(
            "fit_partition_membership_sha256", ""
        ),
        "checkpoint_parameter_count": metadata["parameter_count"],
        "checkpoint_initialization_seed": metadata["initialization_seed"],
    }


def _copy_readonly(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with source.open("rb") as original, os.fdopen(descriptor, "wb") as copied:
            shutil.copyfileobj(original, copied, length=1024 * 1024)
            copied.flush()
            os.fsync(copied.fileno())
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    os.chmod(destination, 0o600)


def _write_manifest(path: Path, value: Mapping[str, Any]) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(value, handle, sort_keys=True, separators=(",", ":"))
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())


def _chown_tree(root: Path, uid: int | None, gid: int | None) -> None:
    if uid is None or gid is None:
        return
    for path in [root, *sorted(root.rglob("*"))]:
        os.chown(path, uid, gid, follow_symlinks=False)


def _bundle_manifest(
    *,
    transformer: Mapping[str, Mapping[str, Any]],
    classifier_files: Mapping[str, Mapping[str, Any]],
    policy: Mapping[str, Any],
    policy_sha256: str,
    classifier_manifest_sha256: str,
    classifier_receipt: Mapping[str, Any],
    runtime_identity: Mapping[str, Any],
    source_receipt: Mapping[str, str],
) -> dict[str, Any]:
    inventory = {
        **{name: dict(value) for name, value in transformer.items()},
        **{
            f"securebert:{name}": dict(value)
            for name, value in classifier_files.items()
        },
    }
    inventory_sha256 = _sha256_json(inventory)
    bundle_identity_sha256 = _sha256_json(
        {
            "artifact_inventory_sha256": inventory_sha256,
            "prediction_policy_sha256": policy_sha256,
            "classifier_environment_manifest_sha256": classifier_manifest_sha256,
            "runtime_identity": dict(runtime_identity),
            "immutable_final_result_sha256": policy["immutable_final_result_sha256"],
        }
    )
    bundle_id = f"frozen_model_bundle_{bundle_identity_sha256[:32]}"
    return {
        "schema_version": SCHEMA_VERSION,
        "bundle_id": bundle_id,
        "artifact_inventory_sha256": inventory_sha256,
        "bundle_identity_sha256": bundle_identity_sha256,
        "source_receipt": dict(source_receipt),
        "transformer": {
            "prediction_mode": policy["prediction_mode"],
            "prediction_policy_sha256": policy_sha256,
            "immutable_final_result_sha256": policy["immutable_final_result_sha256"],
            "artifacts": {name: dict(value) for name, value in transformer.items()},
            "runtime_identity": dict(runtime_identity),
        },
        "classifier": {
            "environment_manifest_sha256": classifier_manifest_sha256,
            "checkpoint_id": classifier_receipt["classifier"]["checkpoint_id"],
            "checkpoint_sha256": classifier_receipt["classifier"]["checkpoint_sha256"],
            "files": {name: dict(value) for name, value in classifier_files.items()},
        },
    }


def load_bundle_manifest(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FrozenModelBundleError("bundle manifest is unreadable") from exc
    if not isinstance(value, dict) or value.get("schema_version") != SCHEMA_VERSION:
        raise FrozenModelBundleError("bundle manifest schema is invalid")
    return value


def _bundle_paths(bundle_root: Path, manifest: Mapping[str, Any]) -> dict[str, Path]:
    transformer = manifest.get("transformer") or {}
    artifacts = transformer.get("artifacts") if isinstance(transformer, dict) else None
    if not isinstance(artifacts, dict):
        raise FrozenModelBundleError("bundle transformer artifacts are invalid")
    paths: dict[str, Path] = {}
    for role, _path_key, _hash_key in TRANSFORMER_SPECS:
        item = artifacts.get(role)
        if not isinstance(item, dict):
            raise FrozenModelBundleError(f"bundle missing {role}")
        paths[role] = bundle_root / _safe_relative(str(item.get("relative_path") or ""))
    return paths


def verify_bundle(
    *,
    bundle_root: Path,
    prediction_policy_path: Path,
    classifier_environment_path: Path,
    repository_root: Path,
    runtime_check: bool = False,
    smoke_test: bool = False,
) -> dict[str, Any]:
    if bundle_root.is_symlink() or not bundle_root.is_dir():
        raise FrozenModelBundleError("bundle root must be a real directory")
    if bundle_root.stat().st_mode & 0o077:
        raise FrozenModelBundleError("bundle root must be owner-only")
    manifest_path = bundle_root / MANIFEST_NAME
    manifest = load_bundle_manifest(manifest_path)
    transformer_manifest = manifest.get("transformer") or {}
    expected_bundle_identity = _sha256_json(
        {
            "artifact_inventory_sha256": manifest.get("artifact_inventory_sha256", ""),
            "prediction_policy_sha256": transformer_manifest.get(
                "prediction_policy_sha256", ""
            ),
            "classifier_environment_manifest_sha256": (manifest.get("classifier") or {}).get(
                "environment_manifest_sha256", ""
            ),
            "runtime_identity": transformer_manifest.get("runtime_identity") or {},
            "immutable_final_result_sha256": transformer_manifest.get(
                "immutable_final_result_sha256", ""
            ),
        }
    )
    if (
        manifest.get("bundle_identity_sha256") != expected_bundle_identity
        or manifest.get("bundle_id")
        != f"frozen_model_bundle_{expected_bundle_identity[:32]}"
    ):
        raise FrozenModelBundleError("bundle identity receipt is invalid")
    policy, policy_sha256 = _transformer_policy(prediction_policy_path)
    transformer = transformer_manifest
    if transformer.get("prediction_policy_sha256") != policy_sha256:
        raise FrozenModelBundleError("bundle prediction policy receipt mismatch")
    if transformer.get("prediction_mode") != policy["prediction_mode"]:
        raise FrozenModelBundleError("bundle prediction mode receipt mismatch")
    if transformer.get("immutable_final_result_sha256") != policy["immutable_final_result_sha256"]:
        raise FrozenModelBundleError("bundle final-result receipt mismatch")
    transformer_paths = _bundle_paths(bundle_root, manifest)
    verified: dict[str, Any] = {}
    for role, _path_key, hash_key in TRANSFORMER_SPECS:
        item = transformer["artifacts"][role]
        path = transformer_paths[role]
        if path.lstat().st_mode & 0o077:
            raise FrozenModelBundleError(f"{role} must be owner-only")
        receipt = _receipt(path, policy[hash_key], role)
        if item.get("sha256") != receipt["sha256"] or item.get("bytes") != receipt["bytes"]:
            raise FrozenModelBundleError(f"bundle receipt mismatch for {role}")
        receipt["relative_path"] = item["relative_path"]
        verified[role] = receipt
    classifier_manifest = load_classifier_manifest(classifier_environment_path)
    classifier_manifest_sha256 = _sha256_file(classifier_environment_path)
    classifier = manifest.get("classifier") or {}
    if classifier.get("environment_manifest_sha256") != classifier_manifest_sha256:
        raise FrozenModelBundleError("bundle classifier environment receipt mismatch")
    model_root = bundle_root / "securebert_ttp"
    classifier_receipt = verify_classifier_assets(
        classifier_manifest,
        repository_root=repository_root,
        model_root=model_root,
    )
    classifier_files = classifier.get("files")
    if not isinstance(classifier_files, dict):
        raise FrozenModelBundleError("bundle classifier files are invalid")
    for relative, expected in classifier_files.items():
        if not isinstance(expected, dict):
            raise FrozenModelBundleError("bundle classifier receipt is invalid")
        path = bundle_root / _safe_relative(str(expected.get("relative_path") or ""))
        if path.lstat().st_mode & 0o077:
            raise FrozenModelBundleError("classifier artifact must be owner-only")
        actual = _receipt(path, str(expected.get("sha256") or ""), relative)
        if actual["bytes"] != expected.get("bytes"):
            raise FrozenModelBundleError("bundle classifier size receipt mismatch")
    if classifier.get("checkpoint_sha256") != classifier_receipt["classifier"]["checkpoint_sha256"]:
        raise FrozenModelBundleError("bundle classifier checkpoint receipt mismatch")
    runtime_identity: dict[str, Any] = {}
    mapped_policy = _mapped_transformer_policy(policy, transformer_paths)
    mapped_policy["transformer_preprocessing_path"] = str(
        repository_root / _safe_relative(mapped_policy["transformer_preprocessing_path"])
    )
    mapped_policy["runtime_rule_policy_path"] = str(
        repository_root / _safe_relative(mapped_policy["runtime_rule_policy_path"])
    )
    mapped_policy["runtime_trust_policy_path"] = str(
        repository_root / _safe_relative(mapped_policy["runtime_trust_policy_path"])
    )
    mapped_policy["runtime_classifier_checkpoint_path"] = str(
        model_root / "checkpoint-6765/model.safetensors"
    )
    if runtime_check:
        runtime_identity = _validate_transformer_runtime(mapped_policy)
        expected_identity = transformer.get("runtime_identity")
        if runtime_identity != expected_identity:
            raise FrozenModelBundleError("bundle Transformer runtime identity mismatch")
    smoke: dict[str, Any] = {}
    if smoke_test:
        predictor = FrozenTransformerPocPredictor(mapped_policy)
        if predictor.load_error:
            raise FrozenModelBundleError("bundle Transformer predictor failed to load")
        snapshot = predictor.predict_session(
            {
                "session_id": "bundle-nonpersistent-smoke",
                "start_time": "2026-07-29T00:00:00Z",
                "protocol": "ssh",
                "status": "active",
                "is_ended": False,
                "login_success": True,
                "login_attempts": 1,
                "commands": [],
                "classification_events": [
                    {
                        "cowrie_eventid": "cowrie.command.input",
                        "event_timestamp": "2026-07-29T00:00:01Z",
                        "compound_command_index": 0,
                        "ttp": "T1059",
                        "tactic": "execution",
                        "source": "rule",
                        "confidence": 1.0,
                        "high_confidence": True,
                        "agreement_status": "rule_only",
                    }
                ],
                "raw_events": [],
            },
            event_id="bundle-nonpersistent-smoke-event",
        )
        if snapshot.get("prediction_status") != "predicted":
            raise FrozenModelBundleError("bundle Transformer smoke inference failed")
        smoke = {
            "prediction_status": snapshot["prediction_status"],
            "snapshot_id": snapshot["snapshot_id"],
            "snapshot_sha256": snapshot["snapshot_sha256"],
            "predictive_alert_status": snapshot["predictive_alert"]["status"],
        }
    return {
        "verified": True,
        "bundle_id": manifest["bundle_id"],
        "bundle_manifest_sha256": _sha256_file(manifest_path),
        "artifact_inventory_sha256": manifest["artifact_inventory_sha256"],
        "transformer": verified,
        "classifier_checkpoint_sha256": classifier_receipt["classifier"]["checkpoint_sha256"],
        "runtime_identity": runtime_identity,
        "smoke": smoke,
    }


def create_bundle(
    *,
    bundle_parent: Path,
    transformer_source_root: Path,
    classifier_source_root: Path,
    prediction_policy_path: Path,
    classifier_environment_path: Path,
    repository_root: Path,
    owner_uid: int | None = None,
    owner_gid: int | None = None,
) -> dict[str, Any]:
    policy, policy_sha256 = _transformer_policy(prediction_policy_path)
    transformer_sources: dict[str, Path] = {}
    transformer_receipts: dict[str, dict[str, Any]] = {}
    for role, path_key, hash_key in TRANSFORMER_SPECS:
        source = transformer_source_root / _safe_relative(policy[path_key])
        transformer_sources[role] = source
        receipt = _receipt(source, policy[hash_key], role)
        receipt["relative_path"] = f"transformer/{source.name}"
        transformer_receipts[role] = receipt
    source_policy = _mapped_transformer_policy(policy, transformer_sources)
    source_policy["transformer_preprocessing_path"] = str(
        repository_root / _safe_relative(source_policy["transformer_preprocessing_path"])
    )
    source_policy["runtime_rule_policy_path"] = str(
        repository_root / _safe_relative(source_policy["runtime_rule_policy_path"])
    )
    source_policy["runtime_trust_policy_path"] = str(
        repository_root / _safe_relative(source_policy["runtime_trust_policy_path"])
    )
    source_policy["runtime_classifier_checkpoint_path"] = str(
        classifier_source_root / "checkpoint-6765/model.safetensors"
    )
    runtime_identity = _validate_transformer_runtime(source_policy)
    classifier_manifest = load_classifier_manifest(classifier_environment_path)
    classifier_receipt = verify_classifier_assets(
        classifier_manifest,
        repository_root=repository_root,
        model_root=classifier_source_root,
    )
    classifier_files: dict[str, dict[str, Any]] = {}
    for relative in SECUREBERT_RELATIVE_FILES:
        source = classifier_source_root / relative
        expected = classifier_manifest["classifier"]["files"][relative]
        receipt = _receipt(source, expected, f"classifier {relative}")
        receipt["relative_path"] = f"securebert_ttp/{relative}"
        classifier_files[relative] = receipt
    manifest = _bundle_manifest(
        transformer=transformer_receipts,
        classifier_files=classifier_files,
        policy=policy,
        policy_sha256=policy_sha256,
        classifier_manifest_sha256=_sha256_file(classifier_environment_path),
        classifier_receipt=classifier_receipt,
        runtime_identity=runtime_identity,
        source_receipt={
            "transformer_source_root": str(transformer_source_root.resolve()),
            "classifier_source_root": str(classifier_source_root.resolve()),
        },
    )
    bundle_parent.mkdir(parents=True, exist_ok=True)
    os.chmod(bundle_parent, 0o700)
    if owner_uid is not None and owner_gid is not None:
        os.chown(bundle_parent, owner_uid, owner_gid)
    destination = bundle_parent / manifest["bundle_id"]
    if destination.exists():
        return verify_bundle(
            bundle_root=destination,
            prediction_policy_path=prediction_policy_path,
            classifier_environment_path=classifier_environment_path,
            repository_root=repository_root,
            runtime_check=True,
        )
    staging = bundle_parent / f".{manifest['bundle_id']}.staging"
    if staging.exists():
        raise FrozenModelBundleError("refusing to reuse an incomplete bundle staging directory")
    staging.mkdir(mode=0o700)
    try:
        for role, source in transformer_sources.items():
            _copy_readonly(source, staging / transformer_receipts[role]["relative_path"])
        for relative, receipt in classifier_files.items():
            _copy_readonly(classifier_source_root / relative, staging / receipt["relative_path"])
        _write_manifest(staging / MANIFEST_NAME, manifest)
        _chown_tree(staging, owner_uid, owner_gid)
        os.replace(staging, destination)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return verify_bundle(
        bundle_root=destination,
        prediction_policy_path=prediction_policy_path,
        classifier_environment_path=classifier_environment_path,
        repository_root=repository_root,
        runtime_check=True,
    )


def install_release_links(*, release_root: Path, bundle_root: Path) -> dict[str, Any]:
    manifest = load_bundle_manifest(bundle_root / MANIFEST_NAME)
    release_root = release_root.resolve()
    bundle_root = bundle_root.resolve()
    data_root = release_root / "data"
    if data_root.is_symlink() or (data_root.exists() and not data_root.is_dir()):
        raise FrozenModelBundleError("release data path must be a real directory")
    data_root.mkdir(exist_ok=True)
    model_path_root = data_root / "models"
    if model_path_root.is_symlink() or (
        model_path_root.exists() and not model_path_root.is_dir()
    ):
        raise FrozenModelBundleError(
            "release data/models path must be a real directory"
        )
    model_path_root.mkdir(exist_ok=True)
    links: dict[str, str] = {}
    for role, _path_key, _hash_key in TRANSFORMER_SPECS:
        item = manifest["transformer"]["artifacts"][role]
        source = bundle_root / _safe_relative(item["relative_path"])
        target = release_root / "data/models" / Path(item["relative_path"]).name
        if target.exists() or target.is_symlink():
            raise FrozenModelBundleError(f"release artifact link already exists: {target}")
        os.symlink(source, target)
        links[str(target.relative_to(release_root))] = str(source)
    models = release_root / "models"
    if models.exists() or models.is_symlink():
        raise FrozenModelBundleError("release models link already exists")
    os.symlink(bundle_root, models)
    links["models"] = str(bundle_root)
    verified = verify_release_links(
        release_root=release_root,
        bundle_root=bundle_root,
    )
    return {**verified, "release_links": links}


def verify_release_links(
    *,
    release_root: Path,
    bundle_root: Path,
) -> dict[str, Any]:
    """Require every policy-relative runtime model path to bind to one bundle."""

    release_root = release_root.resolve()
    bundle_root = bundle_root.resolve()
    manifest = load_bundle_manifest(bundle_root / MANIFEST_NAME)
    verified: dict[str, dict[str, Any]] = {}
    for role, _path_key, _hash_key in TRANSFORMER_SPECS:
        item = (manifest.get("transformer") or {}).get("artifacts", {}).get(role)
        if not isinstance(item, Mapping):
            raise FrozenModelBundleError(f"bundle missing {role}")
        source = bundle_root / _safe_relative(str(item.get("relative_path") or ""))
        receipt = _receipt(source, str(item.get("sha256") or ""), role)
        if receipt["bytes"] != item.get("bytes"):
            raise FrozenModelBundleError(f"bundle receipt mismatch for {role}")
        target = release_root / "data/models" / source.name
        if not target.is_symlink():
            raise FrozenModelBundleError(
                f"release prediction artifact link is missing: {target}"
            )
        try:
            resolved = target.resolve(strict=True)
        except OSError as exc:
            raise FrozenModelBundleError(
                f"release prediction artifact link is invalid: {target}"
            ) from exc
        if resolved != source.resolve():
            raise FrozenModelBundleError(
                f"release prediction artifact link targets the wrong bundle: {target}"
            )
        verified[role] = {
            "release_path": str(target),
            "bundle_path": str(source),
            "bytes": receipt["bytes"],
            "sha256": receipt["sha256"],
        }
    models = release_root / "models"
    try:
        models_target = models.resolve(strict=True) if models.is_symlink() else None
    except OSError as exc:
        raise FrozenModelBundleError(
            "release classifier-model link is invalid"
        ) from exc
    if models_target != bundle_root:
        raise FrozenModelBundleError(
            "release classifier-model link does not target the frozen bundle"
        )
    return {
        "bundle_id": manifest["bundle_id"],
        "prediction_ready": True,
        "transformer_artifacts": verified,
        "classifier_model_path": str(models),
    }


def archive_bundle(*, bundle_root: Path, archive_path: Path) -> dict[str, Any]:
    if archive_path.exists():
        raise FrozenModelBundleError("refusing to overwrite model-bundle archive")
    load_bundle_manifest(bundle_root / MANIFEST_NAME)
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive_path, "x") as archive:
        archive.add(bundle_root, arcname=bundle_root.name, recursive=True)
    os.chmod(archive_path, 0o600)
    return {
        "archive_path": str(archive_path),
        "bytes": archive_path.stat().st_size,
        "sha256": _sha256_file(archive_path),
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("create", "verify"):
        item = commands.add_parser(name)
        item.add_argument("--bundle-root" if name == "verify" else "--bundle-parent", type=Path, required=True)
        item.add_argument("--prediction-policy", type=Path, required=True)
        item.add_argument("--classifier-environment", type=Path, required=True)
        item.add_argument("--repository-root", type=Path, required=True)
        item.add_argument("--runtime-check", action="store_true")
        item.add_argument("--smoke-test", action="store_true")
        if name == "create":
            item.add_argument("--transformer-source-root", type=Path, required=True)
            item.add_argument("--classifier-source-root", type=Path, required=True)
            item.add_argument("--owner", required=True)
            item.add_argument("--group", required=True)
    links = commands.add_parser("install-release-links")
    links.add_argument("--release-root", type=Path, required=True)
    links.add_argument("--bundle-root", type=Path, required=True)
    verify_links = commands.add_parser("verify-release-links")
    verify_links.add_argument("--release-root", type=Path, required=True)
    verify_links.add_argument("--bundle-root", type=Path, required=True)
    archive = commands.add_parser("archive")
    archive.add_argument("--bundle-root", type=Path, required=True)
    archive.add_argument("--archive", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "create":
        receipt = create_bundle(
            bundle_parent=args.bundle_parent,
            transformer_source_root=args.transformer_source_root,
            classifier_source_root=args.classifier_source_root,
            prediction_policy_path=args.prediction_policy,
            classifier_environment_path=args.classifier_environment,
            repository_root=args.repository_root,
            owner_uid=pwd.getpwnam(args.owner).pw_uid,
            owner_gid=grp.getgrnam(args.group).gr_gid,
        )
    elif args.command == "verify":
        receipt = verify_bundle(
            bundle_root=args.bundle_root,
            prediction_policy_path=args.prediction_policy,
            classifier_environment_path=args.classifier_environment,
            repository_root=args.repository_root,
            runtime_check=args.runtime_check,
            smoke_test=args.smoke_test,
        )
    elif args.command == "install-release-links":
        receipt = install_release_links(
            release_root=args.release_root,
            bundle_root=args.bundle_root,
        )
    elif args.command == "verify-release-links":
        receipt = verify_release_links(
            release_root=args.release_root,
            bundle_root=args.bundle_root,
        )
    else:
        receipt = archive_bundle(bundle_root=args.bundle_root, archive_path=args.archive)
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
