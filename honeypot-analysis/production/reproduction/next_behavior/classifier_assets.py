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


SCHEMA_VERSION = "next_behavior_classifier_environment.v3"
COMPATIBILITY_SCHEMA_VERSION = "next_behavior_classifier_environment.v2"
LEGACY_SCHEMA_VERSION = "next_behavior_classifier_environment.v1"
SOURCE_IDENTITY_SCHEMA_VERSION = "classifier_source_identity.v1"
RUNTIME_ASSET_CONTRACT_SCHEMA_VERSION = "securebert_runtime_asset_contract.v1"
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
_RUNTIME_CONTRACT_CLASSIFIER_FIELDS = frozenset(
    {"runtime_asset_contract_path", "runtime_asset_contract_sha256"}
)
_CLASSIFIER_FIELDS_WITH_RUNTIME_CONTRACT = (
    _CLASSIFIER_FIELDS | _RUNTIME_CONTRACT_CLASSIFIER_FIELDS
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
    "configs/classification_rules.trusted.json",
    "production/classification/trust.py",
    "data/feeds/mitre_attack_cache.json",
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

MODEL_ARCHITECTURE = "ModernBertForSequenceClassification"
MODEL_TYPE = "modernbert"
MODEL_TASK = "SINGLE_LABEL_MULTICLASS"
MODEL_LABEL_COUNT = 196
MODEL_PARAMETER_COUNT = 149755588
MODEL_MAX_TOKENS = 128


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
    expected_top_level = _TOP_LEVEL_FIELDS if schema == SCHEMA_VERSION else _LEGACY_TOP_LEVEL_FIELDS
    if set(value) != expected_top_level:
        errors.append("classifier environment fields are invalid")
    if schema not in {
        SCHEMA_VERSION,
        COMPATIBILITY_SCHEMA_VERSION,
        LEGACY_SCHEMA_VERSION,
    }:
        errors.append(f"schema_version must be one of {SCHEMA_VERSION}, {COMPATIBILITY_SCHEMA_VERSION}, {LEGACY_SCHEMA_VERSION}")

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
    if schema == LEGACY_SCHEMA_VERSION:
        classifier_fields = _CLASSIFIER_FIELDS - {"splitter_sha256"}
    valid_classifier_field_sets = {classifier_fields}
    # A historical v3 receipt may predate the explicit runtime asset contract.
    # The current runtime receipt uses the extended set; retaining the old set
    # here keeps archived evidence parseable without weakening current loading.
    if schema in {SCHEMA_VERSION, COMPATIBILITY_SCHEMA_VERSION}:
        valid_classifier_field_sets.add(
            classifier_fields | _RUNTIME_CONTRACT_CLASSIFIER_FIELDS
        )
    if not isinstance(classifier, dict) or set(classifier) not in valid_classifier_field_sets:
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
        if _RUNTIME_CONTRACT_CLASSIFIER_FIELDS.issubset(classifier):
            contract_path = Path(_clean(classifier.get("runtime_asset_contract_path")))
            if not _safe_relative_path(contract_path):
                errors.append("classifier.runtime_asset_contract_path is unsafe")
            if not _is_sha256(classifier.get("runtime_asset_contract_sha256")):
                errors.append("classifier.runtime_asset_contract_sha256 is invalid")

    policy = value.get("classification_policy")
    policy_fields = _POLICY_FIELDS
    if schema == LEGACY_SCHEMA_VERSION:
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
        if schema in {SCHEMA_VERSION, COMPATIBILITY_SCHEMA_VERSION}:
            if policy.get("authority_decision_contract_version") != "command_authority_decision.v1":
                errors.append("authority decision contract version is invalid")
            if not _is_sha256(policy.get("authority_decision_sha256")):
                errors.append("authority decision contract hash is invalid")
            if policy.get("trusted_history_schema_version") not in {
                "prediction_trusted_history_manifest.v2",
                "prediction_trusted_history_manifest.v3",
            }:
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
    if schema == SCHEMA_VERSION:
        if not isinstance(source_identity, dict) or set(source_identity) != _SOURCE_IDENTITY_FIELDS:
            errors.append("classifier source identity fields are invalid")
        else:
            if source_identity.get("schema_version") != SOURCE_IDENTITY_SCHEMA_VERSION:
                errors.append("classifier source identity schema is invalid")
            files = source_identity.get("files")
            if not isinstance(files, dict) or set(files) != set(SOURCE_IDENTITY_PATHS):
                errors.append("classifier source identity file set is invalid")
            else:
                for relative, digest in files.items():
                    path = Path(_clean(relative))
                    if (
                        path.is_absolute()
                        or ".." in path.parts
                        or relative not in SOURCE_IDENTITY_PATHS
                        or not _is_sha256(digest)
                    ):
                        errors.append("classifier source identity contains an unsafe file")
            if not _is_sha256(source_identity.get("sha256")):
                errors.append("classifier source identity hash is invalid")

    freeze = value.get("freeze")
    if schema == SCHEMA_VERSION:
        freeze_fields = _V3_FREEZE_FIELDS
    elif schema == COMPATIBILITY_SCHEMA_VERSION:
        freeze_fields = _LEGACY_FREEZE_FIELDS
    else:
        freeze_fields = _LEGACY_FREEZE_FIELDS - {"release_revision"}
    if not isinstance(freeze, dict) or set(freeze) != freeze_fields:
        errors.append("freeze fields are invalid")
    else:
        if not re.fullmatch(r"[0-9a-f]{40}", _clean(freeze.get("basis_commit"))):
            errors.append("freeze.basis_commit is invalid")
        if schema == COMPATIBILITY_SCHEMA_VERSION and not re.fullmatch(
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


def ordered_label_sha256(labels: Sequence[str]) -> str:
    """Return the stable identity of an ordered classifier label list."""

    encoded = json.dumps(
        [str(label) for label in labels],
        ensure_ascii=True,
        sort_keys=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _safe_relative_path(value: Any) -> bool:
    path = Path(_clean(value))
    return bool(_clean(value)) and not path.is_absolute() and ".." not in path.parts


def validate_securebert_runtime_contract(value: Any) -> list[str]:
    """Validate the model/tokenizer/label contract without touching model bytes."""

    if not isinstance(value, Mapping):
        return ["SecureBERT runtime asset contract must be an object"]
    errors: list[str] = []
    if value.get("schema_version") != RUNTIME_ASSET_CONTRACT_SCHEMA_VERSION:
        errors.append("SecureBERT runtime asset contract schema is invalid")
    if _clean(value.get("legacy_project_identifier")) != "securebert":
        errors.append("legacy SecureBERT identifier is invalid")
    if _clean(value.get("verified_model_architecture")) != MODEL_ARCHITECTURE:
        errors.append("verified model architecture is invalid")
    if _clean(value.get("model_type")) != MODEL_TYPE:
        errors.append("verified model type is invalid")
    if _clean(value.get("task")) != MODEL_TASK:
        errors.append("SecureBERT task contract is invalid")
    if _clean(value.get("published_securebert_lineage")) not in {
        "UNPROVEN",
        "UNKNOWN",
        "MISSING",
    }:
        errors.append("published SecureBERT lineage must remain unproven")
    for field, expected in (
        ("num_labels", MODEL_LABEL_COUNT),
        ("parameter_count", MODEL_PARAMETER_COUNT),
        ("max_model_tokens", MODEL_MAX_TOKENS),
    ):
        if value.get(field) != expected:
            errors.append(f"{field} does not match the reviewed model contract")
    if _clean(value.get("confidence_semantics")) != "uncalibrated_top_softmax_score":
        errors.append("confidence semantics must be uncalibrated_top_softmax_score")
    if value.get("temperature_applied") is not False:
        errors.append("command classifier temperature must be disabled")

    checkpoint = value.get("checkpoint")
    if not isinstance(checkpoint, Mapping):
        errors.append("checkpoint contract is invalid")
    else:
        if not _safe_relative_path(checkpoint.get("path")):
            errors.append("checkpoint path is unsafe")
        if not _is_sha256(checkpoint.get("sha256")):
            errors.append("checkpoint SHA-256 is invalid")

    model_config = value.get("model_config")
    if not isinstance(model_config, Mapping):
        errors.append("model config contract is invalid")
    else:
        files = model_config.get("files")
        if not isinstance(files, Mapping) or set(files) != {
            "config.json",
            "checkpoint-6765/config.json",
        }:
            errors.append("model config contract must bind both config files")
        else:
            for relative, digest in files.items():
                if not _safe_relative_path(relative) or not _is_sha256(digest):
                    errors.append("model config contract contains an unsafe file")

    tokenizer = value.get("tokenizer")
    if not isinstance(tokenizer, Mapping):
        errors.append("tokenizer contract is invalid")
    else:
        files = tokenizer.get("files")
        expected_files = {
            "tokenizer.json",
            "tokenizer_config.json",
            "checkpoint-6765/tokenizer.json",
            "checkpoint-6765/tokenizer_config.json",
        }
        if not isinstance(files, Mapping) or set(files) != expected_files:
            errors.append("tokenizer contract must bind the reviewed tokenizer files")
        else:
            for relative, digest in files.items():
                if not _safe_relative_path(relative) or not _is_sha256(digest):
                    errors.append("tokenizer contract contains an unsafe file")
        if tokenizer.get("normalizer") != "NFC":
            errors.append("tokenizer normalizer is not the reviewed NFC contract")
        if tokenizer.get("lowercase") is not False:
            errors.append("tokenizer lowercase contract is invalid")
        if tokenizer.get("truncation_side") != "right":
            errors.append("tokenizer truncation side is invalid")
        if tokenizer.get("padding_side") != "right":
            errors.append("tokenizer padding side is invalid")

    label_space = value.get("label_space")
    if not isinstance(label_space, Mapping):
        errors.append("label-space contract is invalid")
    else:
        if not _safe_relative_path(label_space.get("path")):
            errors.append("label-space path is unsafe")
        if not _is_sha256(label_space.get("sha256")):
            errors.append("label-space SHA-256 is invalid")
        if label_space.get("label_count") != MODEL_LABEL_COUNT:
            errors.append("label-space count is invalid")
        if not _is_sha256(label_space.get("ordered_labels_sha256")):
            errors.append("ordered label SHA-256 is invalid")
    preprocessing = value.get("preprocessing")
    if not isinstance(preprocessing, Mapping):
        errors.append("preprocessing contract is invalid")
    else:
        if preprocessing.get("strip") is not True:
            errors.append("preprocessing strip contract is invalid")
        if preprocessing.get("split_operators") != ["\\n", ";", "&&", "||"]:
            errors.append("preprocessing split contract is invalid")
        if preprocessing.get("split_pipes") is not False:
            errors.append("preprocessing pipe contract is invalid")
    return errors


def load_securebert_runtime_contract(path: Path) -> Dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ClassifierAssetError("SecureBERT runtime asset contract unavailable") from exc
    errors = validate_securebert_runtime_contract(value)
    if errors:
        raise ClassifierAssetError("; ".join(errors))
    return dict(value)


def _mapping_from_config(value: Mapping[str, Any]) -> Dict[str, str]:
    raw = value.get("id2label")
    if not isinstance(raw, Mapping):
        raise ClassifierAssetError("classifier config id2label is invalid")
    normalized: Dict[str, str] = {}
    for index in range(MODEL_LABEL_COUNT):
        key = str(index)
        label = raw.get(key, raw.get(index))
        if not isinstance(label, str) or not label.strip():
            raise ClassifierAssetError("classifier config label order is incomplete")
        normalized[key] = label.strip()
    return normalized


def _verify_json_file(path: Path, expected_sha256: str, label: str) -> Dict[str, Any]:
    verified = _verify_file(path, expected_sha256, label)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ClassifierAssetError(f"{label} is not valid JSON") from exc
    if not isinstance(value, Mapping):
        raise ClassifierAssetError(f"{label} must contain an object")
    verified["json"] = True
    return verified


def verify_securebert_runtime_assets(
    contract: Mapping[str, Any],
    *,
    model_root: Path,
) -> Dict[str, Any]:
    """Verify all model-side bytes and their architecture/label identity."""

    errors = validate_securebert_runtime_contract(contract)
    if errors:
        raise ClassifierAssetError("; ".join(errors))
    root = Path(model_root)
    checkpoint = contract["checkpoint"]
    model_config = contract["model_config"]
    tokenizer = contract["tokenizer"]
    label_space = contract["label_space"]
    verified: Dict[str, Any] = {}
    verified["checkpoint"] = _verify_file(
        root / checkpoint["path"], checkpoint["sha256"], "SecureBERT checkpoint"
    )
    configs: Dict[str, Any] = {}
    for relative, digest in model_config["files"].items():
        configs[relative] = _verify_json_file(
            root / relative, digest, f"SecureBERT model config {relative}"
        )
    tokenizers: Dict[str, Any] = {}
    for relative, digest in tokenizer["files"].items():
        tokenizers[relative] = _verify_json_file(
            root / relative, digest, f"SecureBERT tokenizer asset {relative}"
        )
    label_path = root / label_space["path"]
    label_receipt = _verify_json_file(
        label_path, label_space["sha256"], "SecureBERT label mapping"
    )
    try:
        config_values = [
            json.loads((root / relative).read_text(encoding="utf-8"))
            for relative in model_config["files"]
        ]
        label_mapping = json.loads(label_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ClassifierAssetError("SecureBERT model identity JSON is unreadable") from exc
    if not isinstance(label_mapping, Mapping):
        raise ClassifierAssetError("SecureBERT label mapping is invalid")
    if set(str(key) for key in label_mapping) != {str(i) for i in range(MODEL_LABEL_COUNT)}:
        raise ClassifierAssetError("SecureBERT label mapping count is invalid")
    ordered = [str(label_mapping[str(index)]).strip() for index in range(MODEL_LABEL_COUNT)]
    if any(not label for label in ordered) or len(set(ordered)) != MODEL_LABEL_COUNT:
        raise ClassifierAssetError("SecureBERT labels are missing or duplicated")
    if ordered_label_sha256(ordered) != label_space["ordered_labels_sha256"]:
        raise ClassifierAssetError("SecureBERT ordered label identity mismatch")
    for config_value in config_values:
        if not isinstance(config_value, Mapping):
            raise ClassifierAssetError("SecureBERT model config is invalid")
        architectures = config_value.get("architectures") or []
        if MODEL_ARCHITECTURE not in architectures:
            raise ClassifierAssetError("SecureBERT model architecture mismatch")
        if config_value.get("model_type") != MODEL_TYPE:
            raise ClassifierAssetError("SecureBERT model type mismatch")
        config_labels = _mapping_from_config(config_value)
        if [config_labels[str(index)] for index in range(MODEL_LABEL_COUNT)] != ordered:
            raise ClassifierAssetError("SecureBERT config label order mismatch")
        label2id = config_value.get("label2id")
        normalized_label2id = {}
        if isinstance(label2id, Mapping):
            for label, value in label2id.items():
                try:
                    normalized_label2id[str(label)] = int(value)
                except (TypeError, ValueError):
                    normalized_label2id[str(label)] = -1
        if normalized_label2id != {
            str(label): int(index) for index, label in enumerate(ordered)
        }:
            raise ClassifierAssetError("SecureBERT config inverse label mapping mismatch")
    if label_mapping != {str(index): label for index, label in enumerate(ordered)}:
        raise ClassifierAssetError("SecureBERT external label mapping is not canonical")
    verified["model_configs"] = configs
    verified["tokenizer_files"] = tokenizers
    verified["label_mapping"] = label_receipt
    return {
        "schema_version": RUNTIME_ASSET_CONTRACT_SCHEMA_VERSION,
        "status": "runtime_model_assets_verified",
        "model_root": str(root.resolve()),
        "checkpoint_sha256": checkpoint["sha256"],
        "architecture": MODEL_ARCHITECTURE,
        "model_type": MODEL_TYPE,
        "num_labels": MODEL_LABEL_COUNT,
        "parameter_count": MODEL_PARAMETER_COUNT,
        "max_model_tokens": MODEL_MAX_TOKENS,
        "ordered_labels_sha256": label_space["ordered_labels_sha256"],
        "verified": verified,
    }


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
    runtime_contract = None
    if _RUNTIME_CONTRACT_CLASSIFIER_FIELDS.issubset(classifier):
        contract_path = repository_root / classifier["runtime_asset_contract_path"]
        contract_receipt = _verify_json_file(
            contract_path,
            classifier["runtime_asset_contract_sha256"],
            "SecureBERT runtime asset contract",
        )
        runtime_contract = load_securebert_runtime_contract(contract_path)
        verified["runtime_asset_contract"] = contract_receipt
        verified["runtime_model_identity"] = verify_securebert_runtime_assets(
            runtime_contract,
            model_root=model_root,
        )
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
            **(
                {
                    "runtime_asset_contract_path": classifier[
                        "runtime_asset_contract_path"
                    ],
                    "runtime_asset_contract_sha256": classifier[
                        "runtime_asset_contract_sha256"
                    ],
                }
                if runtime_contract is not None
                else {}
            ),
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
    contract = None
    contract_path_text = classifier_config.get("runtime_asset_contract_path")
    if contract_path_text:
        contract = load_securebert_runtime_contract(
            Path(__file__).resolve().parents[3] / contract_path_text
        )
    classifier = SecureBertCommandClassifier(
        model_path=str(model_root),
        checkpoint_path=str(model_root / "checkpoint-6765"),
        device=classifier_config["device"],
        max_length=classifier_config["max_length"],
        runtime_asset_contract=contract,
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
