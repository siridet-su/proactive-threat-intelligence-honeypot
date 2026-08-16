"""Validate the frozen prediction-only ATT&CK label environment.

This validator is intentionally separate from ``validate_prediction_policy``.
The latter validates the currently supported runtime predictors; this module
validates the offline, non-authoritative label-domain freeze and its source
byte bindings.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any, Mapping

from production.prediction.prediction_attck_label import (
    load_prediction_attck_label_policy,
    validate_prediction_attck_environment,
    validate_prediction_attck_label_policy,
)


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


def _git_identity(root: Path) -> tuple[str, str]:
    commit = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    tree = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD^{tree}"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    return commit, tree


def validate_prediction_attck_label_environment(
    *,
    repository_root: str | Path,
    policy_path: str | Path,
    environment_path: str | Path,
    classification_policy_path: str | Path | None = None,
) -> list[str]:
    """Validate content, policy, source, and repository bindings fail-closed."""

    root = Path(repository_root).resolve()
    policy_file = Path(policy_path)
    if not policy_file.is_absolute():
        policy_file = root / policy_file
    environment_file = Path(environment_path)
    if not environment_file.is_absolute():
        environment_file = root / environment_file
    errors: list[str] = []
    try:
        policy = load_prediction_attck_label_policy(policy_file)
    except Exception as exc:  # noqa: BLE001 - CLI must report a single failure list.
        return [f"prediction label policy failed to load: {exc}"]
    actual_policy_sha = _sha256(policy_file)
    if policy.get("policy_sha256") != actual_policy_sha:
        errors.append("prediction label policy byte hash mismatch")
    classification_file = Path(
        classification_policy_path
        or policy.get("classification_rule_policy_path")
        or ""
    )
    if not classification_file.is_absolute():
        classification_file = root / classification_file
    try:
        classification_policy = _load_json(classification_file)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        errors.append(f"classification policy cannot be loaded: {exc}")
        classification_policy = None
    if classification_policy is not None:
        errors.extend(
            validate_prediction_attck_label_policy(
                policy,
                classification_policy=classification_policy,
            )
        )
        if _sha256(classification_file) != policy.get("classification_rule_policy_sha256"):
            errors.append("classification policy bytes do not match prediction policy binding")
    try:
        environment = _load_json(environment_file)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        return errors + [f"prediction label environment cannot be loaded: {exc}"]
    errors.extend(validate_prediction_attck_environment(environment))
    if environment.get("policy_sha256") != actual_policy_sha:
        errors.append("environment policy hash does not match policy bytes")
    if environment.get("policy_id") != policy.get("policy_id"):
        errors.append("environment policy identity does not match policy")
    if environment.get("target_contract_id") != policy.get("target_contract_id"):
        errors.append("environment target contract does not match policy")
    binding_file = policy_file.parent / str(policy.get("rule_bindings_path") or "")
    if not binding_file.is_file() or _sha256(binding_file) != policy.get("rule_bindings_sha256"):
        errors.append("prediction rule-binding bytes do not match policy")
    module_file = root / "production" / "prediction" / "prediction_attck_label.py"
    module_sha = _sha256(module_file) if module_file.is_file() else ""
    for field in ("group_builder_sha256", "history_builder_sha256", "target_builder_sha256", "barrier_policy_sha256"):
        if environment.get(field) != module_sha:
            errors.append(f"environment.{field} does not bind current prediction label implementation")
    source_selection = root / "configs" / "next_behavior_source_selection.v1.json"
    if not source_selection.is_file() or _sha256(source_selection) != environment.get("source_corpus_membership_sha256"):
        errors.append("environment source membership bytes do not match the frozen selection binding")
    try:
        commit, tree = _git_identity(root)
    except (OSError, subprocess.CalledProcessError) as exc:
        errors.append(f"repository identity unavailable: {exc}")
    else:
        if environment.get("repository_commit") != commit:
            errors.append("environment.repository_commit does not match HEAD")
        if environment.get("repository_tree") != tree:
            errors.append("environment.repository_tree does not match HEAD tree")
    return sorted(set(errors))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", default=None)
    parser.add_argument("--policy", default="configs/prediction_attck_label_policy.v1.json")
    parser.add_argument("--environment", default="configs/prediction_attck_label_environment.v1.json")
    parser.add_argument("--classification-policy", default=None)
    args = parser.parse_args(argv)
    root = Path(args.repository_root or Path(__file__).resolve().parents[2])
    errors = validate_prediction_attck_label_environment(
        repository_root=root,
        policy_path=args.policy,
        environment_path=args.environment,
        classification_policy_path=args.classification_policy,
    )
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1
    print("prediction-only ATT&CK label environment validation passed")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
