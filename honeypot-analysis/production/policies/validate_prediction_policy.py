"""Validate the two supported prediction policies."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import stat
from pathlib import Path
from typing import Any, Dict, List


TRANSFORMER_POC_MODE = "professor_approved_corrected_target_transformer_poc"
VOMM_ROLLBACK_MODE = "external_hard_backoff_vomm"
SUPPORTED_MODES = {TRANSFORMER_POC_MODE, VOMM_ROLLBACK_MODE}


def load_policy_file(path: str | Path) -> Dict[str, Any]:
    with Path(path).open("r", encoding="utf-8") as handle:
        loaded = json.load(handle)
    if not isinstance(loaded, dict):
        raise ValueError("policy file must contain a JSON object")
    return loaded


def _policy_body(document: Dict[str, Any]) -> Dict[str, Any]:
    body = document.get("policy", document)
    return body if isinstance(body, dict) else {}


def _sha256(value: Any) -> bool:
    text = str(value or "").strip().lower()
    return len(text) == 64 and all(character in "0123456789abcdef" for character in text)


def _probability(value: Any) -> bool:
    return (
        not isinstance(value, bool)
        and isinstance(value, (int, float))
        and math.isfinite(float(value))
        and 0.0 <= float(value) <= 1.0
    )


def _repository_root(repository_root: str | Path | None) -> Path:
    return (
        Path(repository_root).resolve()
        if repository_root is not None
        else Path(__file__).resolve().parents[2]
    )


def _resolve_referenced_path(
    value: Any,
    *,
    repository_root: Path,
) -> Path:
    path = Path(str(value or "").strip())
    return path if path.is_absolute() else repository_root / path


def _validate_environment_binding(
    policy: Dict[str, Any],
    errors: List[str],
    *,
    repository_root: Path,
) -> None:
    path_text = str(policy.get("runtime_classifier_environment_path") or "").strip()
    expected = str(policy.get("runtime_classifier_environment_sha256") or "").strip().lower()
    if not path_text or not expected:
        return
    path = _resolve_referenced_path(path_text, repository_root=repository_root)
    try:
        metadata = path.lstat()
    except OSError:
        errors.append(
            "policy.runtime_classifier_environment_path must reference a readable regular file"
        )
        return
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        errors.append(
            "policy.runtime_classifier_environment_path must reference a readable regular non-symlink file"
        )
        return
    try:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        errors.append(
            "policy.runtime_classifier_environment_path must reference a readable regular file"
        )
        return
    if digest != expected:
        errors.append(
            "policy.runtime_classifier_environment_sha256 does not match the referenced file bytes"
        )


def _validate_transformer(
    policy: Dict[str, Any],
    errors: List[str],
    *,
    repository_root: Path,
) -> None:
    if policy.get("compute_weighted_ensemble_baseline") is not False:
        errors.append(f"{TRANSFORMER_POC_MODE} requires compute_weighted_ensemble_baseline=false")
    if policy.get("weight_influence_scope") != "not_applicable_external_authority":
        errors.append(
            f"{TRANSFORMER_POC_MODE} requires weight_influence_scope=not_applicable_external_authority"
        )
    if policy.get("predictive_alerts") != {"enabled": False}:
        errors.append(f"{TRANSFORMER_POC_MODE} requires predictive_alerts.enabled=false")
    required_paths = (
        "transformer_checkpoint_path",
        "transformer_model_spec_path",
        "transformer_vocabulary_path",
        "transformer_preprocessing_path",
        "transformer_calibration_path",
        "runtime_rule_policy_path",
        "runtime_trust_policy_path",
        "runtime_classifier_environment_path",
        "runtime_classifier_checkpoint_path",
    )
    for field in required_paths:
        if not str(policy.get(field) or "").strip():
            errors.append(f"{TRANSFORMER_POC_MODE} requires policy.{field}")
    required_hashes = (
        "transformer_checkpoint_sha256",
        "transformer_model_spec_file_sha256",
        "transformer_vocabulary_file_sha256",
        "transformer_vocabulary_sha256",
        "transformer_preprocessing_sha256",
        "transformer_calibration_file_sha256",
        "calibration_mapping_sha256",
        "calibration_membership_sha256",
        "runtime_rule_policy_sha256",
        "runtime_trust_policy_sha256",
        "runtime_classifier_environment_sha256",
        "runtime_classifier_checkpoint_sha256",
        "immutable_final_result_sha256",
    )
    for field in required_hashes:
        if not _sha256(policy.get(field)):
            errors.append(f"policy.{field} must be a SHA-256 digest")
    for field in ("transformer_seed", "transformer_parameter_count"):
        value = policy.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            errors.append(f"policy.{field} must be a positive integer")
    for field in ("tactic_probability_threshold", "terminal_probability_threshold"):
        if not _probability(policy.get(field)):
            errors.append(f"policy.{field} must be in [0, 1]")
    _validate_environment_binding(
        policy,
        errors,
        repository_root=repository_root,
    )


def _validate_vomm(policy: Dict[str, Any], errors: List[str]) -> None:
    if policy.get("compute_weighted_ensemble_baseline") is not False:
        errors.append(f"{VOMM_ROLLBACK_MODE} requires compute_weighted_ensemble_baseline=false")
    if policy.get("weight_influence_scope") != "not_applicable_external_authority":
        errors.append(
            f"{VOMM_ROLLBACK_MODE} requires weight_influence_scope=not_applicable_external_authority"
        )
    primary = policy.get("primary_transition")
    if not isinstance(primary, dict):
        errors.append("policy.primary_transition must be an object")
        primary = {}
    if primary.get("source_order") != ["external_seed_transition"]:
        errors.append(
            f"{VOMM_ROLLBACK_MODE} requires primary_transition.source_order to be [external_seed_transition]"
        )
    if str(primary.get("fallback_scorer") or "").strip():
        errors.append(f"{VOMM_ROLLBACK_MODE} must not configure a primary fallback scorer")
    for field in (
        "external_transition_model_path",
        "external_transition_manifest_path",
        "external_transition_expected_model_id",
        "external_transition_expected_manifest_id",
    ):
        if not str(policy.get(field) or "").strip():
            errors.append(f"{VOMM_ROLLBACK_MODE} requires policy.{field}")
    if not _sha256(policy.get("external_transition_expected_artifact_sha256")):
        errors.append(
            "policy.external_transition_expected_artifact_sha256 must be a SHA-256 digest"
        )


def validate_policy_document(
    document: Dict[str, Any],
    *,
    repository_root: str | Path | None = None,
) -> List[str]:
    if not isinstance(document, dict):
        return ["policy document must be an object"]
    policy = _policy_body(document)
    if not policy:
        return ["policy must be an object"]
    errors: List[str] = []
    if "enabled" in policy and not isinstance(policy.get("enabled"), bool):
        errors.append("policy.enabled must be boolean")
    mode = str(policy.get("prediction_mode") or "").strip()
    if mode not in SUPPORTED_MODES:
        errors.append(
            "policy.prediction_mode must select the frozen Transformer or explicit VOMM rollback"
        )
        return errors
    root = _repository_root(repository_root)
    if mode == TRANSFORMER_POC_MODE:
        _validate_transformer(policy, errors, repository_root=root)
    else:
        _validate_vomm(policy, errors)
    return errors


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--policy",
        default="configs/prediction_policy.transformer_poc.trusted.json",
    )
    args = parser.parse_args(argv)
    policy_path = Path(args.policy)
    errors = validate_policy_document(
        load_policy_file(policy_path),
        repository_root=policy_path.resolve().parent.parent,
    )
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1
    print("prediction policy validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
