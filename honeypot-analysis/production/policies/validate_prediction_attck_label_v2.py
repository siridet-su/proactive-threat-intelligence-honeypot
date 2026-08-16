"""Validate the separately versioned prediction-only ATT&CK label v2 freeze."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any, Mapping

from production.prediction.prediction_attck_label_v2 import (
    ENVIRONMENT_SCHEMA_VERSION,
    FREEZE_RECEIPT_SCHEMA_VERSION,
    LEGACY_REVIEW_COMMIT,
    LEGACY_REVIEW_PATH,
    LEGACY_REVIEW_SHA256,
    load_prediction_attck_label_policy_v2,
    validate_prediction_attck_environment_v2,
    validate_prediction_attck_label_policy_v2,
)
from production.utils.serialization import stable_json


V1_FROZEN_HASHES = {
    "configs/prediction_attck_label_policy.v1.json": "2f7669d7aacfb4ffa59cc2d9c0b89be88e2b16dfd80b551944ee07db6e8b1cc6",
    "configs/prediction_attck_rule_bindings.v1.json": "9eec0ed41f27f98c3530887b7326063fbc6dd4012b4630ebb8e30d7c4bbe90df",
    "configs/prediction_attck_label_environment.v1.json": "200f209ce1385d10cd38fa8bf78c37773d163d43a9efcd8422a8a71738f3b815",
    "configs/prediction_attck_label_known_answers.v1.json": "00ef47ca1aa2eaef5d3031698d6fdc48ba5b0cf2000a6756a5488f79af91e42a",
    "configs/prediction_attck_label_freeze_receipt.v1.json": "8ba835b6a7bc5b5ab342de23b60e417a3455476b03901f7f3dcd6123ab05e2f4",
    "production/prediction/prediction_attck_label.py": "28885527e05bd1711f39a798452435646c311054eef794186b8965ef938cdea9",
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def _git_tree_for_commit(root: Path, commit: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), "rev-parse", f"{commit}^{{tree}}"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _git_file_bytes(root: Path, commit: str, path: str) -> bytes:
    return subprocess.run(
        ["git", "-C", str(root), "show", f"{commit}:{path}"],
        check=True,
        capture_output=True,
    ).stdout


def _regular_bound_file(root: Path, relative: str, expected_sha: str) -> bool:
    path = Path(relative)
    if path.is_absolute() or ".." in path.parts:
        return False
    candidate = root / path
    return (
        not candidate.is_symlink()
        and candidate.is_file()
        and _sha256(candidate) == expected_sha
    )


def _verify_legacy_review_source(root: Path, policy: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    try:
        raw = _git_file_bytes(root, LEGACY_REVIEW_COMMIT, LEGACY_REVIEW_PATH)
        legacy = json.loads(raw.decode("utf-8"))
    except (subprocess.CalledProcessError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return [f"legacy review source cannot be loaded: {exc}"]
    if hashlib.sha256(raw).hexdigest() != LEGACY_REVIEW_SHA256:
        errors.append("legacy review source bytes do not match the frozen identity")
    rules = (legacy.get("policy") or {}).get("rules")
    if not isinstance(rules, list):
        return errors + ["legacy review source rules are unavailable"]
    reviewed = {
        str(rule.get("rule_id") or "")
        for rule in rules
        if isinstance(rule, Mapping)
        and rule.get("enabled") is not False
        and (rule.get("provenance") or {}).get("reviewed") is True
    }
    unreviewed = {
        str(rule.get("rule_id") or "")
        for rule in rules
        if isinstance(rule, Mapping)
        and rule.get("enabled") is not False
        and (rule.get("provenance") or {}).get("reviewed") is not True
    }
    admitted = set((policy.get("admission_class") or {}).get("rule_ids") or [])
    if len(reviewed) != 84 or len(unreviewed) != 27:
        errors.append("legacy reviewed/unreviewed rule counts do not match the frozen review")
    if not admitted or not admitted <= reviewed:
        errors.append("v2 admission includes a rule not historically reviewed")
    if admitted & unreviewed:
        errors.append("v2 admission restores a historically unreviewed rule")
    return errors


def validate_prediction_attck_label_environment_v2(
    *,
    repository_root: str | Path,
    policy_path: str | Path,
    environment_path: str | Path,
    classification_policy_path: str | Path | None = None,
) -> list[str]:
    root = Path(repository_root).resolve()
    policy_file = Path(policy_path)
    if not policy_file.is_absolute():
        policy_file = root / policy_file
    environment_file = Path(environment_path)
    if not environment_file.is_absolute():
        environment_file = root / environment_file
    errors: list[str] = []
    try:
        policy = load_prediction_attck_label_policy_v2(policy_file)
    except Exception as exc:  # noqa: BLE001 - aggregate validator boundary.
        return [f"prediction label v2 policy failed to load: {exc}"]
    classification_file = Path(
        classification_policy_path
        or policy.get("classification_rule_policy_path")
        or ""
    )
    if not classification_file.is_absolute():
        classification_file = root / classification_file
    try:
        classification = _load_json(classification_file)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        errors.append(f"classification policy cannot be loaded: {exc}")
        classification = None
    if classification is not None:
        errors.extend(
            validate_prediction_attck_label_policy_v2(
                policy, classification_policy=classification
            )
        )
        if _sha256(classification_file) != policy.get("classification_rule_policy_sha256"):
            errors.append("classification policy bytes do not match the v2 binding")
    errors.extend(_verify_legacy_review_source(root, policy))
    for relative, expected in V1_FROZEN_HASHES.items():
        if not _regular_bound_file(root, relative, expected):
            errors.append(f"frozen v1 bytes changed: {relative}")
    try:
        environment = _load_json(environment_file)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        return sorted(set(errors + [f"prediction label v2 environment cannot be loaded: {exc}"]))
    errors.extend(validate_prediction_attck_environment_v2(environment))
    if environment.get("schema_version") != ENVIRONMENT_SCHEMA_VERSION:
        errors.append("environment schema is not v2")
    if environment.get("policy_id") != policy.get("policy_id"):
        errors.append("environment policy identity does not match v2 policy")
    if environment.get("policy_sha256") != policy.get("policy_sha256"):
        errors.append("environment policy hash does not match v2 policy bytes")
    v1_module = root / "production/prediction/prediction_attck_label.py"
    v2_module = root / "production/prediction/prediction_attck_label_v2.py"
    v1_sha = _sha256(v1_module) if v1_module.is_file() else ""
    v2_sha = _sha256(v2_module) if v2_module.is_file() else ""
    for field in (
        "group_builder_sha256",
        "history_builder_sha256",
        "target_builder_sha256",
        "barrier_policy_sha256",
        "base_contract_implementation_sha256",
    ):
        if environment.get(field) != v1_sha:
            errors.append(f"environment.{field} does not bind the immutable v1 contract code")
    for field in (
        "v2_policy_implementation_sha256",
        "v2_admission_predicate_sha256",
    ):
        if environment.get(field) != v2_sha:
            errors.append(f"environment.{field} does not bind the current v2 implementation")
    source_selection = root / "configs/next_behavior_source_selection.v1.json"
    if (
        not source_selection.is_file()
        or _sha256(source_selection) != environment.get("source_corpus_membership_sha256")
    ):
        errors.append("environment frozen Phase-2 source binding does not match")
    try:
        commit = str(environment.get("repository_commit") or "")
        if _git_tree_for_commit(root, commit) != environment.get("repository_tree"):
            errors.append("environment repository tree does not match its implementation commit")
    except (OSError, subprocess.CalledProcessError) as exc:
        errors.append(f"environment repository identity is unavailable: {exc}")
    return sorted(set(errors))


def validate_prediction_attck_freeze_receipt_v2(
    receipt: Mapping[str, Any], *, repository_root: str | Path
) -> list[str]:
    root = Path(repository_root).resolve()
    if not isinstance(receipt, Mapping):
        return ["freeze receipt v2 must be an object"]
    allowed = {
        "schema_version",
        "freeze_id",
        "status",
        "authority",
        "repository",
        "lineage",
        "semantic_change",
        "contracts",
        "support_policy",
        "validation",
        "boundaries",
        "receipt_sha256",
    }
    errors = [
        f"freeze receipt.{key} is not defined by the contract"
        for key in sorted(receipt)
        if key not in allowed
    ]
    if receipt.get("schema_version") != FREEZE_RECEIPT_SCHEMA_VERSION:
        errors.append("freeze receipt schema is invalid")
    if receipt.get("status") != "frozen_contract_only":
        errors.append("freeze receipt status is invalid")
    if receipt.get("authority") != "prediction_weak_rule_label":
        errors.append("freeze receipt authority is invalid")
    repository = receipt.get("repository")
    if not isinstance(repository, Mapping):
        errors.append("freeze receipt repository identity is required")
    else:
        commit = str(repository.get("implementation_commit") or "")
        tree = str(repository.get("implementation_tree") or "")
        try:
            if _git_tree_for_commit(root, commit) != tree:
                errors.append("freeze receipt implementation tree differs")
        except (OSError, subprocess.CalledProcessError):
            errors.append("freeze receipt implementation commit is unavailable")
    lineage = receipt.get("lineage")
    if not isinstance(lineage, Mapping) or lineage != {
        "predecessor_freeze_receipt_path": "configs/prediction_attck_label_freeze_receipt.v1.json",
        "predecessor_freeze_receipt_sha256": V1_FROZEN_HASHES["configs/prediction_attck_label_freeze_receipt.v1.json"],
        "predecessor_evidence_immutable": True,
    }:
        errors.append("freeze receipt predecessor lineage is invalid")
    change = receipt.get("semantic_change")
    if not isinstance(change, Mapping):
        errors.append("freeze receipt semantic change is required")
    else:
        if change.get("only_change") != "parser_context_over_restriction":
            errors.append("freeze receipt semantic change scope is invalid")
        for field in (
            "canonical_trust_changed",
            "attck_bindings_changed",
            "target_contract_changed",
            "support_thresholds_changed",
            "model_authority_added",
        ):
            if change.get(field) is not False:
                errors.append(f"freeze receipt semantic_change.{field} must be false")
    required_contracts = {
        "policy",
        "legacy_literal_bindings",
        "implementation_v2",
        "base_implementation_v1",
        "environment",
        "known_answers",
        "validator",
        "canonical_trust",
    }
    contracts = receipt.get("contracts")
    if not isinstance(contracts, Mapping) or set(contracts) != required_contracts:
        errors.append("freeze receipt contracts are incomplete")
    else:
        for name, reference in contracts.items():
            if not isinstance(reference, Mapping) or set(reference) != {"path", "sha256"}:
                errors.append(f"freeze receipt contract reference is invalid: {name}")
                continue
            if not _regular_bound_file(
                root, str(reference.get("path") or ""), str(reference.get("sha256") or "")
            ):
                errors.append(f"freeze receipt contract bytes differ: {name}")
    support = receipt.get("support_policy")
    if not isinstance(support, Mapping) or support.get("analysis_status") != "not_run":
        errors.append("freeze receipt must record that large-data support was not run")
    validation = receipt.get("validation")
    if not isinstance(validation, Mapping) or validation.get("focused_tests_passed") is not True:
        errors.append("freeze receipt focused validation is incomplete")
    boundaries = receipt.get("boundaries")
    if not isinstance(boundaries, Mapping):
        errors.append("freeze receipt boundaries are required")
    else:
        for field in (
            "large_corpus_support_inspected",
            "model_training",
            "sealed_test_accessed",
            "canonical_trust_modified",
            "production_changed",
        ):
            if boundaries.get(field) is not False:
                errors.append(f"freeze receipt boundary {field} must be false")
        if boundaries.get("canonical_noninterference_proven") is not True:
            errors.append("freeze receipt canonical noninterference proof is missing")
    if isinstance(receipt.get("receipt_sha256"), str):
        body = dict(receipt)
        body.pop("receipt_sha256", None)
        digest = hashlib.sha256(stable_json(body).encode("utf-8")).hexdigest()
        if receipt.get("receipt_sha256") != digest:
            errors.append("freeze receipt self-hash differs")
    else:
        errors.append("freeze receipt self-hash is required")
    return sorted(set(errors))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", default=None)
    parser.add_argument(
        "--policy", default="configs/prediction_attck_label_policy.v2.json"
    )
    parser.add_argument(
        "--environment", default="configs/prediction_attck_label_environment.v2.json"
    )
    parser.add_argument("--classification-policy", default=None)
    parser.add_argument("--freeze-receipt", default=None)
    args = parser.parse_args(argv)
    root = Path(args.repository_root or Path(__file__).resolve().parents[2])
    errors = validate_prediction_attck_label_environment_v2(
        repository_root=root,
        policy_path=args.policy,
        environment_path=args.environment,
        classification_policy_path=args.classification_policy,
    )
    if args.freeze_receipt:
        receipt_path = Path(args.freeze_receipt)
        if not receipt_path.is_absolute():
            receipt_path = root / receipt_path
        try:
            errors.extend(
                validate_prediction_attck_freeze_receipt_v2(
                    _load_json(receipt_path), repository_root=root
                )
            )
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            errors.append(f"freeze receipt cannot be loaded: {exc}")
    if errors:
        for error in sorted(set(errors)):
            print(f"ERROR: {error}")
        return 1
    print("prediction-only ATT&CK label v2 environment validation passed")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

