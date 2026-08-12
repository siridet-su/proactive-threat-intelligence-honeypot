#!/usr/bin/env python3
"""Verify the frozen classifier environment and private model assets.

The versioned manifest contains hashes and configuration but never a local
model path. Operators supply the private model root explicitly. Verification
is read-only; the optional smoke test uses a fixed synthetic command and emits
no raw-corpus content.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from math import isfinite
from pathlib import Path
from typing import Any, Dict, Mapping, Sequence


SCHEMA_VERSION = "next_behavior_classifier_environment.v4"
COMPATIBILITY_SCHEMA_VERSION = "next_behavior_classifier_environment.v3"
LEGACY_SCHEMA_VERSION = "next_behavior_classifier_environment.v2"
VERY_LEGACY_SCHEMA_VERSION = "next_behavior_classifier_environment.v1"
SOURCE_IDENTITY_SCHEMA_VERSION = "classifier_source_identity.v1"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_LEGACY_TOP_LEVEL_FIELDS = frozenset(
    {
        "schema_version",
        "python",
        "dependency_lock",
        "classifier",
        "classification_policy",
        "freeze",
    }
)
_TOP_LEVEL_FIELDS = _LEGACY_TOP_LEVEL_FIELDS | {"source_identity"}
_PYTHON_FIELDS = frozenset({"implementation", "version"})
_LOCK_FIELDS = frozenset({"path", "sha256"})
_CLASSIFIER_FIELDS = frozenset(
    {
        "adapter",
        "adapter_sha256",
        "pipeline_sha256",
        "operation_parser_sha256",
        "splitter_sha256",
        "checkpoint_id",
        "checkpoint_sha256",
        "parameter_count",
        "label_count",
        "device",
        "max_length",
        "files",
    }
)
_POLICY_FIELDS = frozenset(
    {
        "rule_policy_id",
        "rule_policy_version",
        "rule_policy_path",
        "rule_policy_sha256",
        "mitre_cache_path",
        "mitre_cache_sha256",
        "trust_policy_path",
        "trust_policy_sha256",
        "securebert_candidate_threshold",
        "trusted_model_only_threshold",
        "drop_rule_securebert_disagreements",
        "compound_command_splitter",
        "authority_decision_contract_version",
        "authority_decision_sha256",
        "trusted_history_schema_version",
        "trusted_history_builder_path",
        "trusted_history_builder_sha256",
        "trusted_history_runtime_path",
        "trusted_history_runtime_sha256",
        "trusted_history_maximum_phases",
    }
)
_V4_POLICY_FIELDS = _POLICY_FIELDS | frozenset({
    "target_contract_id",
    "model_input_schema_version",
    "prediction_snapshot_schema_version",
    "feedback_contract_version",
    "checkpoint_compatibility_status",
    "preprocessing_contract_path",
    "preprocessing_contract_sha256",
})
_LEGACY_FREEZE_FIELDS = frozenset(
    {
        "basis_commit",
        "release_revision",
        "historical_runtime_threshold_distinction_preserved",
        "raw_scores_are_probabilities",
    }
)
_V3_FREEZE_FIELDS = frozenset(
    {
        "basis_commit",
        "historical_runtime_threshold_distinction_preserved",
        "raw_scores_are_probabilities",
    }
)
_SOURCE_IDENTITY_FIELDS = frozenset({"schema_version", "files", "sha256"})
SOURCE_IDENTITY_PATHS = (
    "production/classification/securebert_classifier.py",
    "production/classification/classification_pipeline.py",
    "production/classification/authority.py",
    "production/classification/environment.py",
    "production/reproduction/next_behavior/classifier_assets.py",
    "production/semantics/command_operations.py",
    "production/prediction/trusted_history.py",
    "production/prediction/next_behavior_runtime.py",
    "production/prediction/next_behavior_contract.py",
    "production/prediction/next_behavior_preprocessing.py",
    "production/prediction/next_behavior_tensor.py",
    "production/prediction/next_behavior_forecast_contract.py",
    "production/prediction/prediction_snapshot_contract.py",
    "configs/classification_rules.trusted.json",
    "configs/next_behavior_preprocessing.v2.json",
    "production/classification/trust.py",
    "production/utils/feedback.py",
    "production/workers/session_monitor.py",
    "production/workers/session_worker.py",
    "data/feeds/mitre_attack_cache.json",
)
V3_SOURCE_IDENTITY_PATHS = tuple(
    path for path in SOURCE_IDENTITY_PATHS
    if path not in {
        "production/prediction/next_behavior_contract.py",
        "production/prediction/next_behavior_preprocessing.py",
        "production/prediction/next_behavior_tensor.py",
        "production/prediction/next_behavior_forecast_contract.py",
        "production/prediction/prediction_snapshot_contract.py",
        "configs/next_behavior_preprocessing.v2.json",
        "production/utils/feedback.py",
        "production/workers/session_monitor.py",
        "production/workers/session_worker.py",
    }
)
_MODEL_FILE_PATHS = frozenset(
    {
        "config.json",
        "label_mapping.json",
        "tokenizer.json",
        "tokenizer_config.json",
        "checkpoint-6765/config.json",
        "checkpoint-6765/model.safetensors",
        "checkpoint-6765/tokenizer.json",
        "checkpoint-6765/tokenizer_config.json",
    }
)
_CLASSIFIER_ADAPTER = (
    "production.classification.securebert_classifier."
    "SecureBertCommandClassifier"
)
_COMPOUND_SPLITTER = (
    "production.classification.classification_pipeline.split_compound_command"
)


class ClassifierAssetError(ValueError):
    """Raised when a frozen classifier receipt cannot be verified."""


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _is_sha256(value: Any) -> bool:
    return bool(_SHA256.fullmatch(_clean(value).lower()))


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(8 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def source_identity_sha256(files: Mapping[str, str]) -> str:
    encoded = json.dumps(
        dict(sorted((str(path), str(digest)) for path, digest in files.items())),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def build_source_identity(repository_root: Path) -> Dict[str, Any]:
    files: Dict[str, str] = {}
    for relative in SOURCE_IDENTITY_PATHS:
        path = repository_root / relative
        if not path.is_file() or path.is_symlink():
            raise ClassifierAssetError(f"missing classifier source identity asset: {relative}")
        files[relative] = file_sha256(path)
    return {
        "schema_version": SOURCE_IDENTITY_SCHEMA_VERSION,
        "files": files,
        "sha256": source_identity_sha256(files),
    }


def verify_classifier_source_identity(
    manifest: Mapping[str, Any],
    *,
    repository_root: Path,
) -> Dict[str, Any] | None:
    if manifest.get("schema_version") != SCHEMA_VERSION:
        return None
    source = manifest.get("source_identity")
    if not isinstance(source, Mapping):
        raise ClassifierAssetError("classifier source identity is missing")
    files = source.get("files")
    if not isinstance(files, Mapping):
        raise ClassifierAssetError("classifier source identity files are invalid")
    expected = {str(path): str(digest) for path, digest in files.items()}
    actual: Dict[str, str] = {}
    for relative, digest in expected.items():
        if relative not in SOURCE_IDENTITY_PATHS:
            raise ClassifierAssetError("classifier source identity contains an unexpected path")
        if not _is_sha256(digest):
            raise ClassifierAssetError("classifier source identity contains an invalid hash")
        path = repository_root / relative
        if not path.is_file() or path.is_symlink():
            raise ClassifierAssetError(f"missing classifier source identity asset: {relative}")
        actual[relative] = file_sha256(path)
        if actual[relative] != digest:
            raise ClassifierAssetError(f"classifier source identity mismatch: {relative}")
    if set(actual) != set(SOURCE_IDENTITY_PATHS):
        raise ClassifierAssetError("classifier source identity file set is incomplete")
    identity_hash = source_identity_sha256(actual)
    if source.get("sha256") != identity_hash:
        raise ClassifierAssetError("classifier source identity hash mismatch")
    return {
        "schema_version": SOURCE_IDENTITY_SCHEMA_VERSION,
        "files": actual,
        "sha256": identity_hash,
    }


def validate_classifier_manifest(value: Any) -> list[str]:
    if not isinstance(value, dict):
        return ["classifier environment manifest must be an object"]
    errors: list[str] = []
    schema = value.get("schema_version")
    expected_top_level = (
        _TOP_LEVEL_FIELDS
        if schema in {SCHEMA_VERSION, COMPATIBILITY_SCHEMA_VERSION}
        else _LEGACY_TOP_LEVEL_FIELDS
    )
    if set(value) != expected_top_level:
        errors.append("classifier environment fields are invalid")
    if schema not in {
        SCHEMA_VERSION,
        COMPATIBILITY_SCHEMA_VERSION,
        LEGACY_SCHEMA_VERSION,
        VERY_LEGACY_SCHEMA_VERSION,
    }:
        errors.append("classifier environment schema is unsupported")

    python = value.get("python")
    if not isinstance(python, dict) or set(python) != _PYTHON_FIELDS:
        errors.append("python fields are invalid")
    elif python.get("implementation") != "CPython" or not re.fullmatch(
        r"3\.12\.[0-9]+", _clean(python.get("version"))
    ):
        errors.append("python runtime is not the frozen CPython 3.12 runtime")

    lock = value.get("dependency_lock")
    if not isinstance(lock, dict) or set(lock) != _LOCK_FIELDS:
        errors.append("dependency_lock fields are invalid")
    else:
        if Path(_clean(lock.get("path"))).is_absolute():
            errors.append("dependency lock path must be repository-relative")
        if not _is_sha256(lock.get("sha256")):
            errors.append("dependency lock SHA-256 is invalid")

    classifier = value.get("classifier")
    classifier_fields = _CLASSIFIER_FIELDS
    if schema == VERY_LEGACY_SCHEMA_VERSION:
        classifier_fields = _CLASSIFIER_FIELDS - {"splitter_sha256"}
    if not isinstance(classifier, dict) or set(classifier) != classifier_fields:
        errors.append("classifier fields are invalid")
    else:
        if classifier.get("adapter") != _CLASSIFIER_ADAPTER:
            errors.append("classifier.adapter is not the frozen adapter")
        if classifier.get("checkpoint_id") != (
            "securebert_ttp_model_v2/checkpoint-6765"
        ):
            errors.append("classifier.checkpoint_id is not frozen")
        for field in (
            "adapter_sha256",
            "pipeline_sha256",
            "operation_parser_sha256",
            "checkpoint_sha256",
        ):
            if not _is_sha256(classifier.get(field)):
                errors.append(f"classifier.{field} is invalid")
        if value.get("schema_version") == SCHEMA_VERSION and not _is_sha256(
            classifier.get("splitter_sha256")
        ):
            errors.append("classifier.splitter_sha256 is invalid")
        for field in ("parameter_count", "label_count", "max_length"):
            number = classifier.get(field)
            if isinstance(number, bool) or not isinstance(number, int) or number < 1:
                errors.append(f"classifier.{field} must be positive")
        if classifier.get("device") != "cpu":
            errors.append("classifier.device must be cpu")
        files = classifier.get("files")
        if not isinstance(files, dict) or set(files) != _MODEL_FILE_PATHS:
            errors.append("classifier.files must contain the exact frozen asset set")
        else:
            for filename, digest in files.items():
                path = Path(_clean(filename))
                if (
                    not _clean(filename)
                    or path.is_absolute()
                    or ".." in path.parts
                    or not _is_sha256(digest)
                ):
                    errors.append("classifier.files contains an unsafe receipt")

    policy = value.get("classification_policy")
    policy_fields = _V4_POLICY_FIELDS if schema == SCHEMA_VERSION else _POLICY_FIELDS
    if schema == VERY_LEGACY_SCHEMA_VERSION:
        policy_fields = _POLICY_FIELDS - {
            "rule_policy_id",
            "rule_policy_version",
            "authority_decision_contract_version",
            "authority_decision_sha256",
            "trusted_history_schema_version",
            "trusted_history_builder_path",
            "trusted_history_builder_sha256",
            "trusted_history_runtime_path",
            "trusted_history_runtime_sha256",
            "trusted_history_maximum_phases",
        }
    if not isinstance(policy, dict) or set(policy) != policy_fields:
        errors.append("classification_policy fields are invalid")
    else:
        for path_field in (
            "rule_policy_path",
            "mitre_cache_path",
            "trust_policy_path",
        ):
            path = Path(_clean(policy.get(path_field)))
            if path.is_absolute() or ".." in path.parts:
                errors.append(f"classification_policy.{path_field} is unsafe")
        for hash_field in (
            "rule_policy_sha256",
            "mitre_cache_sha256",
            "trust_policy_sha256",
        ):
            if not _is_sha256(policy.get(hash_field)):
                errors.append(f"classification_policy.{hash_field} is invalid")
        if schema in {SCHEMA_VERSION, COMPATIBILITY_SCHEMA_VERSION, LEGACY_SCHEMA_VERSION}:
            if policy.get("authority_decision_contract_version") != "command_authority_decision.v2":
                errors.append("authority decision contract version is invalid")
            if not _is_sha256(policy.get("authority_decision_sha256")):
                errors.append("authority decision contract hash is invalid")
            expected_history = (
                "prediction_trusted_history_manifest.v3"
                if schema == SCHEMA_VERSION
                else "prediction_trusted_history_manifest.v2"
            )
            if policy.get("trusted_history_schema_version") != expected_history:
                errors.append("trusted-history manifest schema is invalid")
            for field in (
                "trusted_history_builder_path",
                "trusted_history_runtime_path",
            ):
                path = Path(_clean(policy.get(field)))
                if (
                    not _clean(policy.get(field))
                    or path.is_absolute()
                    or ".." in path.parts
                ):
                    errors.append(f"{field} is unsafe")
            for field in (
                "trusted_history_builder_sha256",
                "trusted_history_runtime_sha256",
            ):
                if not _is_sha256(policy.get(field)):
                    errors.append(f"{field} is invalid")
            if (
                type(policy.get("trusted_history_maximum_phases")) is not int
                or policy.get("trusted_history_maximum_phases") != 8
            ):
                errors.append("trusted-history maximum phases are not frozen")
            if schema == SCHEMA_VERSION:
                expected_v4 = {
                    "target_contract_id": "next_distinct_trusted_behavior_phase_or_session_end.v2",
                    "model_input_schema_version": "next_behavior_input.v2",
                    "prediction_snapshot_schema_version": "prediction_snapshot.v4",
                    "feedback_contract_version": "prediction_feedback.v2",
                    "checkpoint_compatibility_status": "pending_phase7_deterministic_semantics_freeze",
                    "preprocessing_contract_path": "configs/next_behavior_preprocessing.v2.json",
                }
                for field, expected in expected_v4.items():
                    if policy.get(field) != expected:
                        errors.append(f"classification_policy.{field} is invalid")
                if not _is_sha256(policy.get("preprocessing_contract_sha256")):
                    errors.append("classification_policy.preprocessing_contract_sha256 is invalid")
        candidate = policy.get("securebert_candidate_threshold")
        trusted = policy.get("trusted_model_only_threshold")
        if not isinstance(candidate, (int, float)) or isinstance(candidate, bool):
            errors.append("SecureBERT candidate threshold is invalid")
        if not isinstance(trusted, (int, float)) or isinstance(trusted, bool):
            errors.append("trusted model-only threshold is invalid")
        if (
            isinstance(candidate, (int, float))
            and not isinstance(candidate, bool)
            and isinstance(trusted, (int, float))
            and not isinstance(trusted, bool)
            and (
                not isfinite(float(candidate))
                or not isfinite(float(trusted))
                or not (0.0 <= float(candidate) <= float(trusted) <= 1.0)
            )
        ):
            errors.append("classification thresholds are inconsistent")
        if policy.get("drop_rule_securebert_disagreements") is not True:
            errors.append("classifier disagreements must remain audit-only")
        if policy.get("compound_command_splitter") != _COMPOUND_SPLITTER:
            errors.append("compound command splitter is not frozen")

    source_identity = value.get("source_identity")
    if schema in {SCHEMA_VERSION, COMPATIBILITY_SCHEMA_VERSION}:
        if not isinstance(source_identity, dict) or set(source_identity) != _SOURCE_IDENTITY_FIELDS:
            errors.append("classifier source identity fields are invalid")
        else:
            if source_identity.get("schema_version") != SOURCE_IDENTITY_SCHEMA_VERSION:
                errors.append("classifier source identity schema is invalid")
            files = source_identity.get("files")
            expected_source_paths = (
                SOURCE_IDENTITY_PATHS
                if schema == SCHEMA_VERSION else V3_SOURCE_IDENTITY_PATHS
            )
            if not isinstance(files, dict) or set(files) != set(expected_source_paths):
                errors.append("classifier source identity file set is invalid")
            else:
                for relative, digest in files.items():
                    path = Path(_clean(relative))
                    if (
                        path.is_absolute()
                        or ".." in path.parts
                        or relative not in expected_source_paths
                        or not _is_sha256(digest)
                    ):
                        errors.append("classifier source identity contains an unsafe file")
            if not _is_sha256(source_identity.get("sha256")):
                errors.append("classifier source identity hash is invalid")

    freeze = value.get("freeze")
    if schema in {SCHEMA_VERSION, COMPATIBILITY_SCHEMA_VERSION}:
        freeze_fields = _V3_FREEZE_FIELDS
    elif schema == LEGACY_SCHEMA_VERSION:
        freeze_fields = _LEGACY_FREEZE_FIELDS
    else:
        freeze_fields = _LEGACY_FREEZE_FIELDS - {"release_revision"}
    if not isinstance(freeze, dict) or set(freeze) != freeze_fields:
        errors.append("freeze fields are invalid")
    else:
        if not re.fullmatch(r"[0-9a-f]{40}", _clean(freeze.get("basis_commit"))):
            errors.append("freeze.basis_commit is invalid")
        if schema == LEGACY_SCHEMA_VERSION and not re.fullmatch(
            r"[0-9a-f]{40}", _clean(freeze.get("release_revision"))
        ):
            errors.append("freeze.release_revision is invalid")
        if freeze.get("historical_runtime_threshold_distinction_preserved") is not True:
            errors.append("historical/runtime threshold distinction is not preserved")
        if freeze.get("raw_scores_are_probabilities") is not False:
            errors.append("raw classifier scores must not be called probabilities")
    return errors


def load_classifier_manifest(path: Path) -> Dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ClassifierAssetError(f"cannot read classifier manifest: {exc}") from exc
    errors = validate_classifier_manifest(value)
    if errors:
        raise ClassifierAssetError("; ".join(errors))
    return dict(value)


def _verify_file(path: Path, expected_sha256: str, label: str) -> Dict[str, Any]:
    if not path.is_file():
        raise ClassifierAssetError(f"missing {label}")
    actual = file_sha256(path)
    if actual != expected_sha256:
        raise ClassifierAssetError(f"{label} SHA-256 mismatch")
    return {"sha256": actual, "size_bytes": path.stat().st_size}


def verify_classifier_assets(
    manifest: Mapping[str, Any],
    *,
    repository_root: Path,
    model_root: Path,
) -> Dict[str, Any]:
    errors = validate_classifier_manifest(manifest)
    if errors:
        raise ClassifierAssetError("; ".join(errors))
    verify_classifier_source_identity(manifest, repository_root=repository_root)
    classifier = manifest["classifier"]
    policy = manifest["classification_policy"]
    verified: Dict[str, Any] = {}
    verified["dependency_lock"] = _verify_file(
        repository_root / manifest["dependency_lock"]["path"],
        manifest["dependency_lock"]["sha256"],
        "dependency lock",
    )
    verified["classifier_adapter"] = _verify_file(
        repository_root / "production/classification/securebert_classifier.py",
        classifier["adapter_sha256"],
        "SecureBERT adapter",
    )
    verified["classification_pipeline"] = _verify_file(
        repository_root / "production/classification/classification_pipeline.py",
        classifier["pipeline_sha256"],
        "classification pipeline",
    )
    verified["command_operation_parser"] = _verify_file(
        repository_root / "production/semantics/command_operations.py",
        classifier["operation_parser_sha256"],
        "command operation parser",
    )
    for path_field, hash_field in (
        ("rule_policy_path", "rule_policy_sha256"),
        ("mitre_cache_path", "mitre_cache_sha256"),
        ("trust_policy_path", "trust_policy_sha256"),
    ):
        verified[path_field] = _verify_file(
            repository_root / policy[path_field],
            policy[hash_field],
            path_field,
        )
    verified_model_files: Dict[str, Any] = {}
    for relative_path, expected_hash in classifier["files"].items():
        verified_model_files[relative_path] = _verify_file(
            model_root / relative_path,
            expected_hash,
            f"classifier asset {relative_path}",
        )
    verified["model_files"] = verified_model_files
    checkpoint_receipt = verified_model_files["checkpoint-6765/model.safetensors"]
    if checkpoint_receipt["sha256"] != classifier["checkpoint_sha256"]:
        raise ClassifierAssetError("checkpoint receipt is inconsistent")
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "assets_verified",
        "classifier": {
            "checkpoint_id": classifier["checkpoint_id"],
            "checkpoint_sha256": checkpoint_receipt["sha256"],
            "parameter_count": classifier["parameter_count"],
            "label_count": classifier["label_count"],
            "max_length": classifier["max_length"],
            "device": classifier["device"],
        },
        "verified": verified,
    }


def run_smoke_test(
    manifest: Mapping[str, Any],
    *,
    model_root: Path,
) -> Dict[str, Any]:
    from production.classification.securebert_classifier import (
        SecureBertCommandClassifier,
    )

    classifier_config = manifest["classifier"]
    classifier = SecureBertCommandClassifier(
        model_path=str(model_root),
        checkpoint_path=str(model_root / "checkpoint-6765"),
        device=classifier_config["device"],
        max_length=classifier_config["max_length"],
    )
    first = classifier.classify("uname -a")
    second = classifier.classify("uname -a")
    parameter_count = sum(
        parameter.numel() for parameter in classifier.model.parameters()
    )
    label_count = len(classifier.model.config.id2label)
    if parameter_count != classifier_config["parameter_count"]:
        raise ClassifierAssetError("loaded classifier parameter count mismatch")
    if label_count != classifier_config["label_count"]:
        raise ClassifierAssetError("loaded classifier label count mismatch")
    if first != second:
        raise ClassifierAssetError("loaded classifier inference is not deterministic")
    return {
        "status": "loaded_and_deterministic",
        "parameter_count": parameter_count,
        "label_count": label_count,
        "synthetic_replay_equal": True,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path("configs/next_behavior_classifier_environment.v1.json"),
    )
    parser.add_argument("--repository-root", type=Path, default=Path("."))
    parser.add_argument("--model-root", type=Path, required=True)
    parser.add_argument("--smoke-test", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    manifest = load_classifier_manifest(args.manifest)
    receipt = verify_classifier_assets(
        manifest,
        repository_root=args.repository_root,
        model_root=args.model_root,
    )
    if args.smoke_test:
        receipt["smoke_test"] = run_smoke_test(
            manifest,
            model_root=args.model_root,
        )
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
