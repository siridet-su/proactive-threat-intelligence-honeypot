"""Experimental-only successor policy for the prediction ATT&CK PoC.

The v2 prediction contract and its implementation remain immutable.  This
module only authorizes an offline proof-of-concept training run after binding
the already-completed support evidence, frozen role membership, and the exact
v2 target/preprocessing identities.  It never enables production prediction,
canonical trust, sealed-test access, or a change to target semantics.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any, Mapping

from production.prediction.prediction_attck_label_v2 import (
    load_prediction_attck_label_policy_v2,
)
from production.utils.serialization import stable_json


POLICY_SCHEMA_VERSION = "prediction_attck_label_policy.poc.v3"
DATASET_SCHEMA_VERSION = "prediction_attck_poc_dataset_manifest.v1"
POLICY_PATH = "configs/prediction_attck_label_policy.poc.v3.json"
DATASET_PATH = "configs/prediction_attck_label_poc_dataset_manifest.v1.json"
TARGET_CONTRACT_ID = "next_prediction_attck_label_group_or_session_end.v1"
V2_POLICY_ID = "prediction-only-reviewed-rule-labels-legacy-parity-20260816.v2"
V2_POLICY_SHA256 = "03160fd9fad7cbf9e3db652112c47e1b88242ecbe91c8884a6ddc7324d735a61"
V2_ENVIRONMENT_SHA256 = "4b60e27fecf4f5f1ef3614418b52987fad1444b6dabc23423ba9f9cd83236ac1"
V2_IMPLEMENTATION_SHA256 = "45c456ac7c5834129a11d3559acee4371a3bac6f48883876be3dd1035bdcf11c"
V1_IMPLEMENTATION_SHA256 = "28885527e05bd1711f39a798452435646c311054eef794186b8965ef938cdea9"
RULE_BINDINGS_SHA256 = "14db69d7650276f374852aee21b5dcfa90918cf8e49a4b4e9c80317e3862f967"
RUNTIME_ID = "CPython-3.12.13"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_EXTERNAL_ROOTS = (
    Path("/mnt/honeypot-data/prediction-attck-internal-40"),
    Path("/mnt/honeypot-data/prediction-attck-final-support-v4"),
)


class PredictionAttckLabelPocV3Error(ValueError):
    """Raised when the experimental policy or its evidence is invalid."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_hash_without(document: Mapping[str, Any], field: str) -> str:
    body = dict(document)
    body.pop(field, None)
    return _sha256_bytes(stable_json(body).encode("utf-8"))


def _text(value: Any) -> str:
    return str(value or "").strip()


def _errors_for_exact_keys(value: Mapping[str, Any], expected: set[str], path: str) -> list[str]:
    return [
        f"{path}.{key} is not defined by the contract"
        for key in sorted(value)
        if key not in expected
    ]


def _resolve_repo_file(root: Path, relative: str) -> Path | None:
    candidate = Path(relative)
    if candidate.is_absolute() or ".." in candidate.parts:
        return None
    return root / candidate


def _resolve_external_file(value: str) -> Path | None:
    candidate = Path(value)
    if not candidate.is_absolute():
        return None
    try:
        resolved = candidate.resolve(strict=False)
    except OSError:
        return None
    if not any(
        resolved == root or root in resolved.parents for root in _EXTERNAL_ROOTS
    ):
        return None
    return resolved


def _check_file(path: Path | None, expected_sha: str, label: str) -> list[str]:
    if path is None:
        return [f"{label} path is unsafe"]
    if path.is_symlink() or not path.is_file():
        return [f"{label} is not a regular non-symlink file"]
    if not _SHA256.fullmatch(expected_sha or ""):
        return [f"{label} hash is not a SHA-256 digest"]
    try:
        actual = _sha256(path)
    except OSError as exc:
        return [f"{label} cannot be hashed: {exc}"]
    return [] if actual == expected_sha else [f"{label} bytes do not match its binding"]


def _load_json(path: Path, label: str) -> tuple[dict[str, Any] | None, list[str]]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return None, [f"{label} cannot be loaded: {exc}"]
    if not isinstance(value, dict):
        return None, [f"{label} must be an object"]
    return value, []


def _validate_target_identity(document: Mapping[str, Any]) -> list[str]:
    expected = {
        "label_schema_version": "prediction_attck_label.v1",
        "group_schema_version": "prediction_attck_label_group.v1",
        "history_schema_version": "prediction_attck_label_history_manifest.v1",
        "maximum_history_groups": 8,
        "session_end_representation": "explicit_close_only",
        "barrier_policy": "prediction_attck_causal_barrier.v1",
        "no_transition_across_barrier": True,
    }
    return [] if document == expected else ["target_policy_identity is not the frozen v2 identity"]


def _validate_support_receipt(
    name: str, reference: Mapping[str, Any], *, expected_status: str
) -> list[str]:
    errors: list[str] = []
    expected_keys = {
        "path",
        "file_sha256",
        "receipt_id",
        "receipt_sha256",
        "status",
        "sealed_test_accessed",
        "training_performed",
    }
    if name == "pooled":
        expected_keys |= {
            "support_gate_passed",
            "gate_summary_sha256",
            "failed_gate_families",
            "training_started",
            "training_performed",
        }
    errors.extend(_errors_for_exact_keys(reference, expected_keys, f"support_evidence.{name}"))
    if reference.get("status") != expected_status:
        errors.append(f"support_evidence.{name}.status is invalid")
    if reference.get("sealed_test_accessed") is not False:
        errors.append(f"support_evidence.{name} sealed boundary is invalid")
    if reference.get("training_performed") is not False:
        errors.append(f"support_evidence.{name} training state is invalid")
    if name == "pooled":
        if reference.get("support_gate_passed") is not False:
            errors.append("support_evidence.pooled must preserve failed support gates")
        if reference.get("training_started") is not False:
            errors.append("support_evidence.pooled training must not have started")
        if reference.get("training_performed") is not False:
            errors.append("support_evidence.pooled training must not have been performed")
        if reference.get("failed_gate_families") != [
            "conditional_tactic_support",
            "execution_required_support",
            "changed_from_current_support",
        ]:
            errors.append("support_evidence.pooled failed gate families are invalid")
        if not _SHA256.fullmatch(_text(reference.get("gate_summary_sha256"))):
            errors.append("support_evidence.pooled gate summary hash is invalid")
    for field in ("file_sha256", "receipt_sha256"):
        if not _SHA256.fullmatch(_text(reference.get(field))):
            errors.append(f"support_evidence.{name}.{field} is not a SHA-256 digest")
    if not _text(reference.get("receipt_id")):
        errors.append(f"support_evidence.{name}.receipt_id is required")
    return errors


def _verify_support_receipt_file(
    name: str, reference: Mapping[str, Any], *, expected_status: str
) -> list[str]:
    path = _resolve_external_file(_text(reference.get("path")))
    errors = _check_file(path, _text(reference.get("file_sha256")), f"support receipt {name}")
    if errors or path is None:
        return errors
    value, load_errors = _load_json(path, f"support receipt {name}")
    errors.extend(load_errors)
    if value is None:
        return errors
    if value.get("status") != expected_status:
        errors.append(f"support receipt {name} status differs from the policy")
    if value.get("receipt_sha256") != reference.get("receipt_sha256"):
        errors.append(f"support receipt {name} receipt identity differs")
    if name == "pooled":
        boundary = value.get("sealed_boundary")
        if not isinstance(boundary, Mapping) or any(
            boundary.get(field) is not False
            for field in (
                "sealed_internal_accessed",
                "sealed_cyberlab_accessed",
                "embargoed_or_excluded_accessed",
            )
        ):
            errors.append("support receipt pooled accessed sealed or excluded data")
    elif value.get("sealed_test_accessed") is not False:
        errors.append(f"support receipt {name} accessed sealed data")
    if value.get("training_performed") is True:
        errors.append(f"support receipt {name} reports training already performed")
    execution = value.get("execution")
    if isinstance(execution, Mapping) and execution.get("training_started") is True:
        errors.append(f"support receipt {name} reports training already started")
    identities = value.get("identities")
    if isinstance(identities, Mapping):
        if identities.get("policy_id") != V2_POLICY_ID:
            errors.append(f"support receipt {name} policy identity differs")
        if identities.get("policy_sha256") != V2_POLICY_SHA256:
            errors.append(f"support receipt {name} policy hash differs")
        if identities.get("environment_sha256") != "fe9aa9e439033ffbb6dac5ee2fc09683a009a496e7534720aa9fabf593f1429f":
            errors.append(f"support receipt {name} environment identity differs")
    return errors


def validate_prediction_attck_label_poc_policy(
    document: Any,
    *,
    repository_root: str | Path,
    verify_external_receipts: bool = False,
) -> list[str]:
    """Return fail-closed validation errors for the v3 PoC policy."""

    root = Path(repository_root).resolve()
    if not isinstance(document, Mapping):
        return ["prediction ATT&CK PoC policy must be an object"]
    allowed = {
        "schema_version",
        "policy_id",
        "authority",
        "predecessor_policy_path",
        "predecessor_policy_sha256",
        "target_contract_id",
        "target_policy_identity",
        "preprocessing_identity",
        "dataset_manifest",
        "support_evidence",
        "poc_training_authorization",
        "training_authorization",
        "model_protocol",
        "runtime_boundary",
        "claims",
        "policy_sha256",
    }
    errors = _errors_for_exact_keys(document, allowed, "policy")
    if document.get("schema_version") != POLICY_SCHEMA_VERSION:
        errors.append("policy.schema_version is invalid")
    if document.get("authority") != "prediction_weak_rule_label":
        errors.append("policy.authority is invalid")
    if not _text(document.get("policy_id")):
        errors.append("policy.policy_id is required")
    predecessor_path = _resolve_repo_file(root, _text(document.get("predecessor_policy_path")))
    errors.extend(_check_file(predecessor_path, V2_POLICY_SHA256, "predecessor policy"))
    if document.get("predecessor_policy_sha256") != V2_POLICY_SHA256:
        errors.append("policy.predecessor_policy_sha256 is not the frozen v2 policy hash")
    if document.get("target_contract_id") != TARGET_CONTRACT_ID:
        errors.append("policy.target_contract_id is invalid")
    errors.extend(_validate_target_identity(document.get("target_policy_identity")))

    preprocessing = document.get("preprocessing_identity")
    if not isinstance(preprocessing, Mapping):
        errors.append("preprocessing_identity is required")
    else:
        errors.extend(
            _errors_for_exact_keys(
                preprocessing,
                {
                    "environment_path",
                    "environment_sha256",
                    "implementation_path",
                    "implementation_sha256",
                    "base_contract_path",
                    "base_contract_sha256",
                    "rule_bindings_sha256",
                    "runtime",
                },
                "preprocessing_identity",
            )
        )
        if preprocessing.get("environment_path") != "configs/prediction_attck_label_environment.v2.json":
            errors.append("preprocessing environment path is invalid")
        if preprocessing.get("environment_sha256") != V2_ENVIRONMENT_SHA256:
            errors.append("preprocessing environment hash differs")
        if preprocessing.get("implementation_path") != "production/prediction/prediction_attck_label_v2.py":
            errors.append("preprocessing implementation path is invalid")
        if preprocessing.get("implementation_sha256") != V2_IMPLEMENTATION_SHA256:
            errors.append("preprocessing implementation hash differs")
        if preprocessing.get("base_contract_path") != "production/prediction/prediction_attck_label.py":
            errors.append("preprocessing base contract path is invalid")
        if preprocessing.get("base_contract_sha256") != V1_IMPLEMENTATION_SHA256:
            errors.append("preprocessing base contract hash differs")
        if preprocessing.get("rule_bindings_sha256") != RULE_BINDINGS_SHA256:
            errors.append("preprocessing rule binding hash differs")
        if preprocessing.get("runtime") != RUNTIME_ID:
            errors.append("preprocessing runtime differs")
        for rel, digest, label in (
            (preprocessing.get("environment_path"), V2_ENVIRONMENT_SHA256, "preprocessing environment"),
            (preprocessing.get("implementation_path"), V2_IMPLEMENTATION_SHA256, "preprocessing implementation"),
            (preprocessing.get("base_contract_path"), V1_IMPLEMENTATION_SHA256, "preprocessing base contract"),
        ):
            errors.extend(_check_file(_resolve_repo_file(root, _text(rel)), digest, label))

    dataset = document.get("dataset_manifest")
    if not isinstance(dataset, Mapping):
        errors.append("dataset_manifest is required")
    else:
        errors.extend(
            _errors_for_exact_keys(
                dataset,
                {"path", "schema_version", "membership_id", "membership_sha256", "status"},
                "dataset_manifest",
            )
        )
        if dataset.get("path") != DATASET_PATH:
            errors.append("dataset manifest path is invalid")
        if dataset.get("schema_version") != DATASET_SCHEMA_VERSION:
            errors.append("dataset manifest schema is invalid")
        if dataset.get("status") != "membership_frozen_examples_not_materialized":
            errors.append("dataset manifest status is invalid")
        dataset_path = _resolve_repo_file(root, _text(dataset.get("path")))
        errors.extend(_check_file(dataset_path, _text(dataset.get("membership_sha256")), "dataset manifest"))
        if dataset_path is not None and dataset_path.is_file() and not dataset_path.is_symlink():
            value, load_errors = _load_json(dataset_path, "dataset manifest")
            errors.extend(load_errors)
            if value is not None:
                if value.get("schema_version") != DATASET_SCHEMA_VERSION:
                    errors.append("dataset manifest schema differs")
                if value.get("manifest_id") != dataset.get("membership_id"):
                    errors.append("dataset manifest identity differs")
                if value.get("status") != dataset.get("status"):
                    errors.append("dataset manifest status differs")
                if value.get("sealed_boundary") != {
                    "sealed_internal_accessed": False,
                    "sealed_cyberlab_accessed": False,
                    "embargoed_or_excluded_accessed": False,
                    "controlled_synthetic_test_accessed": False,
                }:
                    errors.append("dataset manifest sealed boundary is invalid")

    support = document.get("support_evidence")
    if not isinstance(support, Mapping) or set(support) != {"internal", "cyberlab", "pooled"}:
        errors.append("support_evidence must contain internal, cyberlab, and pooled")
    else:
        errors.extend(_validate_support_receipt("internal", support["internal"], expected_status="COMPLETE_VALID"))
        errors.extend(_validate_support_receipt("cyberlab", support["cyberlab"], expected_status="COMPLETE_VALID"))
        errors.extend(_validate_support_receipt("pooled", support["pooled"], expected_status="SUPPORT_GATE_FAILED"))
        if verify_external_receipts:
            errors.extend(_verify_support_receipt_file("internal", support["internal"], expected_status="COMPLETE_VALID"))
            errors.extend(_verify_support_receipt_file("cyberlab", support["cyberlab"], expected_status="COMPLETE_VALID"))
            errors.extend(_verify_support_receipt_file("pooled", support["pooled"], expected_status="SUPPORT_GATE_FAILED"))

    poc_auth = document.get("poc_training_authorization")
    expected_poc_auth = {
        "empirical_support_qualified": False,
        "production_model_qualified": False,
        "experimental_poc_training_authorized": True,
        "scope": "offline_non_authoritative_experiment_only",
        "does_not_override_failed_support_gates": True,
        "does_not_authorize_sealed_test_access": True,
        "does_not_authorize_production_deployment": True,
    }
    if poc_auth != expected_poc_auth:
        errors.append("poc_training_authorization is invalid")
    training_auth = document.get("training_authorization")
    if training_auth != {
        "support_analysis_only": False,
        "model_training_authorized": False,
        "production_prediction_authorized": False,
        "sealed_test_access_authorized": False,
    }:
        errors.append("production training_authorization must remain disabled")

    model = document.get("model_protocol")
    if not isinstance(model, Mapping):
        errors.append("model_protocol is required")
    else:
        architecture = model.get("architecture")
        if architecture != {
            "causal_layers": 1,
            "d_model": 16,
            "feedforward_dimension": 32,
            "attention_heads": 4,
            "dropout": 0.1,
            "maximum_sequence_length": 8,
            "activation": "gelu",
            "batch_first": True,
            "norm_first": False,
            "device": "cpu",
        }:
            errors.append("model_protocol architecture is not the reviewed Transformer architecture")
        if model.get("training", {}).get("deterministic_algorithms") is not True:
            errors.append("model training must require deterministic algorithms")
        if model.get("training", {}).get("seed") != 20260820:
            errors.append("model training seed is invalid")
        candidates = model.get("candidates")
        if not isinstance(candidates, Mapping) or set(candidates) != {"candidate_a", "candidate_b", "candidate_c"}:
            errors.append("model candidates are incomplete")
        elif candidates.get("candidate_a", {}).get("augmentation") is not False or candidates.get("candidate_b", {}).get("augmentation") is not False:
            errors.append("model augmentation must remain disabled")

    runtime = document.get("runtime_boundary")
    if not isinstance(runtime, Mapping):
        errors.append("runtime_boundary is required")
    else:
        for field in (
            "authoritative",
            "canonical_findings_affected",
            "canonical_attck_truth_assigned",
            "automatic_response_triggered",
            "final_f_ai_advisory_input",
            "controlled_synthetic_training_input",
            "production_enabled",
        ):
            if runtime.get(field) is not False:
                errors.append(f"runtime_boundary.{field} must be false")
        if runtime.get("low_confidence_behavior") != "unavailable":
            errors.append("runtime low-confidence behavior must abstain")

    claims = document.get("claims")
    if not isinstance(claims, Mapping) or not isinstance(claims.get("supported"), list) or not isinstance(claims.get("not_supported"), list):
        errors.append("claims must contain supported and not_supported lists")

    policy_sha = _text(document.get("policy_sha256"))
    if not _SHA256.fullmatch(policy_sha):
        errors.append("policy_sha256 must be a SHA-256 digest")
    elif _canonical_hash_without(document, "policy_sha256") != policy_sha:
        errors.append("policy_sha256 does not match canonical policy body")
    return sorted(set(errors))


def load_prediction_attck_label_poc_policy(
    path: str | Path, *, verify_external_receipts: bool = True
) -> dict[str, Any]:
    """Load and validate the v3 policy, including immutable v2 lineage."""

    policy_path = Path(path)
    root = policy_path.resolve().parents[1]
    try:
        raw = policy_path.read_bytes()
        document = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PredictionAttckLabelPocV3Error(f"cannot load PoC policy: {exc}") from exc
    errors = validate_prediction_attck_label_poc_policy(
        document,
        repository_root=root,
        verify_external_receipts=verify_external_receipts,
    )
    if errors:
        raise PredictionAttckLabelPocV3Error("; ".join(errors))
    predecessor_path = root / _text(document["predecessor_policy_path"])
    try:
        predecessor = load_prediction_attck_label_policy_v2(predecessor_path)
    except Exception as exc:  # noqa: BLE001 - fail-closed contract boundary.
        raise PredictionAttckLabelPocV3Error(f"v2 predecessor cannot be loaded: {exc}") from exc
    if predecessor.get("policy_id") != V2_POLICY_ID:
        raise PredictionAttckLabelPocV3Error("v2 predecessor policy identity differs")
    result = dict(document)
    result["predecessor_policy"] = predecessor
    result["policy_file_sha256"] = _sha256_bytes(raw)
    return result


def require_materialized_poc_examples(
    policy: Mapping[str, Any], *, examples_path: str | Path | None = None
) -> Path:
    """Refuse training until a separately reviewed example corpus exists.

    Support receipts intentionally freeze membership and aggregate support, not
    model examples.  This guard prevents a caller from treating authorization
    alone as proof that training inputs exist.
    """

    dataset = policy.get("dataset_manifest") if isinstance(policy, Mapping) else None
    if not isinstance(dataset, Mapping) or dataset.get("status") != "materialized":
        raise PredictionAttckLabelPocV3Error(
            "PoC training blocked: current-semantics example corpus is not materialized"
        )
    if examples_path is None:
        raise PredictionAttckLabelPocV3Error(
            "PoC training blocked: a reviewed examples path is required"
        )
    path = Path(examples_path).resolve()
    if path.is_symlink() or not path.is_file():
        raise PredictionAttckLabelPocV3Error(
            "PoC training blocked: examples path is not a regular non-symlink file"
        )
    return path


def _git_tree_for_commit(root: Path, commit: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), "rev-parse", f"{commit}^{{tree}}"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def validate_prediction_attck_label_poc_freeze_receipt(
    receipt: Any, *, repository_root: str | Path
) -> list[str]:
    """Validate the immutable policy/membership freeze receipt."""

    root = Path(repository_root).resolve()
    if not isinstance(receipt, Mapping):
        return ["PoC freeze receipt must be an object"]
    allowed = {
        "schema_version",
        "freeze_id",
        "status",
        "repository",
        "lineage",
        "contracts",
        "support_evidence",
        "dataset",
        "poc_training_authorization",
        "training_state",
        "boundaries",
        "validation",
        "receipt_sha256",
    }
    errors = _errors_for_exact_keys(receipt, allowed, "freeze_receipt")
    if receipt.get("schema_version") != "prediction_attck_label_poc_freeze_receipt.v1":
        errors.append("freeze receipt schema is invalid")
    if receipt.get("status") != "frozen_poc_policy_membership_training_not_started":
        errors.append("freeze receipt status is invalid")
    repository = receipt.get("repository")
    if not isinstance(repository, Mapping) or set(repository) != {
        "implementation_commit",
        "implementation_tree",
    }:
        errors.append("freeze receipt repository identity is incomplete")
    else:
        commit = _text(repository.get("implementation_commit"))
        tree = _text(repository.get("implementation_tree"))
        try:
            if _git_tree_for_commit(root, commit) != tree:
                errors.append("freeze receipt repository tree differs")
        except (OSError, subprocess.CalledProcessError):
            errors.append("freeze receipt repository commit is unavailable")
    if receipt.get("lineage") != {
        "predecessor_policy_path": "configs/prediction_attck_label_policy.v2.json",
        "predecessor_policy_sha256": V2_POLICY_SHA256,
        "predecessor_immutable": True,
    }:
        errors.append("freeze receipt v2 lineage is invalid")
    contracts = receipt.get("contracts")
    if not isinstance(contracts, Mapping):
        errors.append("freeze receipt contracts are required")
    else:
        required = {
            "policy",
            "dataset_manifest",
            "poc_implementation",
            "validator",
            "v2_policy",
            "v2_implementation",
            "v2_environment",
        }
        if set(contracts) != required:
            errors.append("freeze receipt contracts are incomplete")
        for name, reference in contracts.items():
            if not isinstance(reference, Mapping) or set(reference) != {"path", "sha256"}:
                errors.append(f"freeze receipt contract reference is invalid: {name}")
                continue
            errors.extend(
                _check_file(
                    _resolve_repo_file(root, _text(reference.get("path"))),
                    _text(reference.get("sha256")),
                    f"freeze receipt contract {name}",
                )
            )
    support = receipt.get("support_evidence")
    if not isinstance(support, Mapping) or set(support) != {"internal", "cyberlab", "pooled"}:
        errors.append("freeze receipt support evidence is incomplete")
    else:
        for name, reference in support.items():
            if not isinstance(reference, Mapping) or set(reference) != {
                "path",
                "file_sha256",
                "receipt_sha256",
                "status",
            }:
                errors.append(f"freeze receipt support reference is invalid: {name}")
                continue
            expected = "SUPPORT_GATE_FAILED" if name == "pooled" else "COMPLETE_VALID"
            if reference.get("status") != expected:
                errors.append(f"freeze receipt support status is invalid: {name}")
            errors.extend(_verify_support_receipt_file(name, reference, expected_status=expected))
    dataset = receipt.get("dataset")
    if dataset != {
        "manifest_path": DATASET_PATH,
        "manifest_sha256": "3ec5f0cc9b44e7993d3724278cb964391b1995d2ff1284aa560f0ba2d25d3451",
        "status": "membership_frozen_examples_not_materialized",
        "examples_present": False,
    }:
        errors.append("freeze receipt dataset state is invalid")
    auth = receipt.get("poc_training_authorization")
    if auth != {
        "empirical_support_qualified": False,
        "production_model_qualified": False,
        "experimental_poc_training_authorized": True,
    }:
        errors.append("freeze receipt PoC authorization is invalid")
    training = receipt.get("training_state")
    if training != {
        "status": "BLOCKED_EXAMPLE_CORPUS_NOT_MATERIALIZED",
        "training_started": False,
        "candidate_a": "not_started",
        "candidate_b": "not_started",
        "candidate_c": "not_authorized",
        "checkpoint": "not_created",
        "calibration": "not_created",
    }:
        errors.append("freeze receipt training state is invalid")
    boundaries = receipt.get("boundaries")
    if not isinstance(boundaries, Mapping):
        errors.append("freeze receipt boundaries are required")
    else:
        for field in (
            "support_reprocessed",
            "pooled_recomputed",
            "sealed_data_accessed",
            "synthetic_data_accessed",
            "training_started",
            "production_changed",
            "prediction_semantics_changed",
        ):
            if boundaries.get(field) is not False:
                errors.append(f"freeze receipt boundary {field} must be false")
    validation = receipt.get("validation")
    if not isinstance(validation, Mapping) or validation.get("policy_validator_passed") is not True:
        errors.append("freeze receipt validation is incomplete")
    receipt_sha = _text(receipt.get("receipt_sha256"))
    if not _SHA256.fullmatch(receipt_sha):
        errors.append("freeze receipt self-hash is invalid")
    elif _canonical_hash_without(receipt, "receipt_sha256") != receipt_sha:
        errors.append("freeze receipt self-hash differs")
    return sorted(set(errors))
