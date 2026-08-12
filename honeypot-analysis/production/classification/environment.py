"""Pinned classifier-environment provenance used by durable replay.

The JSON receipt is a release input.  Runtime code verifies the receipt and
the byte hashes of the executable classifier/policy assets before it is bound
to a session.  A caller can explicitly select an archived receipt for
historical reanalysis; the default path is the active release receipt.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict

from production.reproduction.next_behavior.classifier_assets import (
    ClassifierAssetError,
    validate_classifier_manifest,
)
from production.utils.serialization import stable_json


SCHEMA_VERSION = "classification_environment.v2"
DEFAULT_RECEIPT_PATH = "configs/next_behavior_classifier_environment.v1.json"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _environment_hash(receipt: Dict[str, Any]) -> str:
    # The receipt hash is content addressed and never includes the derived
    # hash itself.  This is also the exact value included in classification
    # and trusted-history manifests.
    return hashlib.sha256(stable_json(receipt).encode("utf-8")).hexdigest()


def load_classifier_environment(
    path_text: str = "",
    *,
    repository_root: Path | None = None,
    verify_assets: bool = True,
) -> Dict[str, Any]:
    root = repository_root or Path(__file__).resolve().parents[2]
    path = Path(path_text) if _clean(path_text) else root / DEFAULT_RECEIPT_PATH
    if not path.is_absolute():
        path = root / path
    try:
        raw = path.read_bytes()
        receipt = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ClassifierAssetError("classifier environment receipt unavailable") from exc
    if not isinstance(receipt, dict):
        raise ClassifierAssetError("classifier environment receipt must be an object")
    errors = validate_classifier_manifest(receipt)
    if errors:
        raise ClassifierAssetError("; ".join(errors))
    if receipt.get("schema_version") != "next_behavior_classifier_environment.v2":
        raise ClassifierAssetError("runtime classifier environment must be v2")
    classifier = receipt.get("classifier") or {}
    policy = receipt.get("classification_policy") or {}
    freeze = receipt.get("freeze") or {}
    required = {
        "release_revision": freeze.get("release_revision"),
        "parser_hash": classifier.get("operation_parser_sha256"),
        "splitter_hash": classifier.get("splitter_sha256"),
        "pipeline_hash": classifier.get("pipeline_sha256"),
        "rule_policy_id": policy.get("rule_policy_id"),
        "rule_policy_hash": policy.get("rule_policy_sha256"),
        "rule_policy_version": policy.get("rule_policy_version"),
        "trust_policy_hash": policy.get("trust_policy_sha256"),
        "authority_contract": policy.get("authority_decision_contract_version"),
        "authority_hash": policy.get("authority_decision_sha256"),
        "trusted_history_schema": policy.get("trusted_history_schema_version"),
        "trusted_history_builder_hash": policy.get("trusted_history_builder_sha256"),
        "trusted_history_runtime_hash": policy.get("trusted_history_runtime_sha256"),
        "securebert_checkpoint": classifier.get("checkpoint_sha256"),
    }
    if any(not _clean(value) for value in required.values()):
        raise ClassifierAssetError("classifier environment provenance is incomplete")
    configured_revision = _clean(os.getenv("DEPLOYED_COMMIT"))
    receipt_revision = _clean(freeze.get("release_revision"))
    if configured_revision and configured_revision.lower() != receipt_revision.lower():
        raise ClassifierAssetError("classifier environment release revision mismatch")
    deployment_manifest = root / "DEPLOYMENT_MANIFEST.json"
    if deployment_manifest.is_file() and not deployment_manifest.is_symlink():
        try:
            deployed = json.loads(deployment_manifest.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ClassifierAssetError("deployment manifest is unreadable") from exc
        deployed_revision = _clean(deployed.get("git_revision"))
        if deployed_revision and deployed_revision.lower() != receipt_revision.lower():
            raise ClassifierAssetError("classifier environment deployment revision mismatch")

    if verify_assets:
        checks = {
            "production/classification/securebert_classifier.py": classifier.get("adapter_sha256"),
            "production/classification/classification_pipeline.py": classifier.get("pipeline_sha256"),
            "production/semantics/command_operations.py": classifier.get("operation_parser_sha256"),
            "production/classification/authority.py": policy.get("authority_decision_sha256"),
            policy.get("trusted_history_builder_path", ""): policy.get(
                "trusted_history_builder_sha256"
            ),
            policy.get("trusted_history_runtime_path", ""): policy.get(
                "trusted_history_runtime_sha256"
            ),
            policy.get("rule_policy_path", ""): policy.get("rule_policy_sha256"),
            policy.get("trust_policy_path", ""): policy.get("trust_policy_sha256"),
            policy.get("mitre_cache_path", ""): policy.get("mitre_cache_sha256"),
        }
        for relative, expected in checks.items():
            asset = root / str(relative)
            if not relative or not asset.is_file() or _sha256(asset) != str(expected):
                raise ClassifierAssetError(f"classifier environment asset mismatch: {relative}")
        policy_path = root / _clean(policy.get("rule_policy_path"))
        try:
            policy_document = json.loads(policy_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ClassifierAssetError("bound classification policy is unreadable") from exc
        if (
            not isinstance(policy_document, dict)
            or _clean(policy_document.get("policy_id")) != _clean(policy.get("rule_policy_id"))
            or _clean(policy_document.get("version")) != _clean(policy.get("rule_policy_version"))
        ):
            raise ClassifierAssetError("bound classification policy identity mismatch")

    bound = dict(receipt)
    bound["environment_schema_version"] = SCHEMA_VERSION
    bound["environment_sha256"] = _environment_hash(receipt)
    bound["receipt_path"] = str(path.resolve())
    return bound


def environment_identity(environment: Dict[str, Any]) -> Dict[str, Any]:
    """Return only stable, non-secret binding fields for manifests."""

    classifier = environment.get("classifier") or {}
    policy = environment.get("classification_policy") or {}
    freeze = environment.get("freeze") or {}
    return {
        "schema_version": SCHEMA_VERSION,
        "environment_sha256": _clean(environment.get("environment_sha256")),
        "release_revision": _clean(freeze.get("release_revision") or freeze.get("basis_commit")),
        "parser_sha256": _clean(classifier.get("operation_parser_sha256")),
        "splitter_sha256": _clean(classifier.get("splitter_sha256")),
        "pipeline_sha256": _clean(classifier.get("pipeline_sha256")),
        "rule_policy_path": _clean(policy.get("rule_policy_path")),
        "rule_policy_sha256": _clean(policy.get("rule_policy_sha256")),
        "trust_policy_sha256": _clean(policy.get("trust_policy_sha256")),
        "mitre_cache_sha256": _clean(policy.get("mitre_cache_sha256")),
        "securebert_checkpoint_sha256": _clean(classifier.get("checkpoint_sha256")),
        "authority_decision_contract_version": _clean(
            policy.get("authority_decision_contract_version")
        ),
        "authority_decision_sha256": _clean(policy.get("authority_decision_sha256")),
        "trusted_history_schema_version": _clean(
            policy.get("trusted_history_schema_version")
        ),
        "trusted_history_builder_sha256": _clean(
            policy.get("trusted_history_builder_sha256")
        ),
        "trusted_history_runtime_sha256": _clean(
            policy.get("trusted_history_runtime_sha256")
        ),
        "trusted_history_maximum_phases": policy.get(
            "trusted_history_maximum_phases"
        ),
    }
