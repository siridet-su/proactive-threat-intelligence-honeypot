#!/usr/bin/env python3
"""Merge verified pre-test artifacts into a v2 experiment manifest.

This command is intentionally a manifest assembler, not an evaluator.  It
never reads a role safe-payload file; it seals its bytes and records the path
for the purpose-scoped final evaluator.  All digests are calculated from the
files supplied to the command, never accepted from a caller-provided JSON
document.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, Mapping, Sequence

from production.prediction.next_behavior_contract import (
    MODEL_INPUT_SCHEMA_VERSION,
    TARGET_CONTRACT_ID,
)
from production.prediction.next_behavior_experiment import (
    REQUIRED_ARTIFACT_ROLES_V2,
    require_valid_experiment_manifest,
    with_experiment_manifest_id,
)
from production.prediction.next_behavior_partitions import MEMBER_ROLES
from production.tools.train_next_behavior_experiment import (
    NextBehaviorTrainingError,
    require_valid_experiment_manifest_bindings,
)
from production.utils.serialization import stable_json


MERGE_RECEIPT_SCHEMA_VERSION = "next_behavior_experiment_manifest_merge.v1"
ARTIFACT_PATHS_SCHEMA_VERSION = "next_behavior_experiment_artifact_paths.v1"
ROLE_FILENAMES = {
    "role_inventory": "role_inventory.json",
    "corpus_receipt": "corpus_receipt.json",
    "safe_payload": "safe_sessions.json",
}


class NextBehaviorManifestMergeError(ValueError):
    """Raised when independently produced pre-test artifacts cannot merge."""


def _sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(stable_json(value).encode("utf-8")).hexdigest()


def _read_json(path: Path, *, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise NextBehaviorManifestMergeError(f"{label} is not valid JSON") from exc


def _require_file(path: Path, *, label: str) -> Path:
    if not path.is_file() or path.is_symlink():
        raise NextBehaviorManifestMergeError(f"{label} is missing or unsafe")
    return path.resolve()


def _atomic_write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(stable_json(value))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def _bundle_artifact_path(
    bundle_dir: Path,
    entry: Any,
    *,
    label: str,
) -> Path:
    if not isinstance(entry, Mapping) or set(entry) != {
        "path", "sha256", "byte_size"
    }:
        raise NextBehaviorManifestMergeError(f"{label} bundle entry is invalid")
    relative = Path(str(entry["path"]))
    if relative.is_absolute() or ".." in relative.parts or not relative.parts:
        raise NextBehaviorManifestMergeError(f"{label} bundle path escapes bundle")
    path = _require_file(bundle_dir / relative, label=label)
    if path.stat().st_size != entry["byte_size"] or _sha256_path(path) != entry["sha256"]:
        raise NextBehaviorManifestMergeError(f"{label} bundle artifact changed")
    return path


def _load_training_bindings(
    training_bundle_dir: Path,
    *,
    policy: Mapping[str, Any],
) -> tuple[Dict[str, Any], Dict[str, Any], Dict[str, Path]]:
    root = _require_file(
        training_bundle_dir / "training_bundle.json", label="training bundle"
    ).parent
    bundle = _read_json(root / "training_bundle.json", label="training bundle")
    if not isinstance(bundle, dict) or bundle.get("status") != "frozen_pre_test":
        raise NextBehaviorManifestMergeError("training bundle is not frozen pre-test")
    identity = deepcopy(bundle)
    if identity.pop("bundle_sha256", None) != _sha256_json(identity):
        raise NextBehaviorManifestMergeError("training bundle identity is invalid")
    bindings_path = _bundle_artifact_path(
        root, bundle.get("experiment_manifest_bindings"), label="manifest bindings"
    )
    bindings = _read_json(bindings_path, label="manifest bindings")
    try:
        bindings = require_valid_experiment_manifest_bindings(bindings, policy=policy)
    except NextBehaviorTrainingError as exc:
        raise NextBehaviorManifestMergeError("training bindings are invalid") from exc
    if bundle.get("code_commit") != bindings["code_commit"]:
        raise NextBehaviorManifestMergeError("training bundle code commit disagrees")
    artifact_paths = {
        role: _bundle_artifact_path(root, bundle.get(key), label=role)
        for role, key in {
            "vocabulary": "vocabulary",
            "model_spec": "model_spec",
            "calibration": "calibration",
            "baseline_manifest": "baselines_manifest",
        }.items()
    }
    selected = bindings["artifact_paths_relative_to_bundle"]
    for role in ("checkpoint", "baseline_majority_terminal_prevalence", "baseline_first_order_phase_state_markov", "baseline_hard_backoff_vomm", "baseline_interpolated_vomm"):
        relative = Path(str(selected.get(role) or ""))
        if relative.is_absolute() or ".." in relative.parts or not relative.parts:
            raise NextBehaviorManifestMergeError(f"{role} binding path is invalid")
        artifact_paths[role] = _require_file(root / relative, label=role)
    for role, path in artifact_paths.items():
        expected = bindings["artifact_hashes"].get(role)
        if _sha256_path(path) != expected:
            raise NextBehaviorManifestMergeError(f"{role} disagrees with training binding")
    return bundle, bindings, artifact_paths


def _role_artifacts(role_dirs: Mapping[str, Path]) -> tuple[Dict[str, Path], Dict[str, Any]]:
    if set(role_dirs) != set(MEMBER_ROLES):
        raise NextBehaviorManifestMergeError("exactly train, selection, calibration, and test role directories are required")
    paths: Dict[str, Path] = {}
    corpora: Dict[str, Any] = {}
    for role in MEMBER_ROLES:
        directory = Path(role_dirs[role])
        role_paths = {
            suffix: _require_file(directory / filename, label=f"{role} {suffix}")
            for suffix, filename in ROLE_FILENAMES.items()
        }
        inventory = _read_json(role_paths["role_inventory"], label=f"{role} role inventory")
        receipt = _read_json(role_paths["corpus_receipt"], label=f"{role} corpus receipt")
        if not isinstance(inventory, dict) or not isinstance(receipt, dict):
            raise NextBehaviorManifestMergeError(f"{role} role metadata is invalid")
        payload_sha256 = _sha256_path(role_paths["safe_payload"])
        if (
            inventory.get("role") != role
            or receipt.get("safe_payload_sha256") != payload_sha256
            or inventory.get("source_member_count")
            != receipt.get("source_member_count")
            or inventory.get("eligible_complete_session_count")
            != receipt.get("safe_session_count")
        ):
            raise NextBehaviorManifestMergeError(f"{role} role inventory has the wrong role")
        corpora[role] = {
            "receipt_id": receipt.get("receipt_id"),
            "receipt_sha256": _sha256_path(role_paths["corpus_receipt"]),
            "safe_payload_sha256": payload_sha256,
            "role_inventory_sha256": _sha256_path(role_paths["role_inventory"]),
            "source_member_count": receipt.get("source_member_count"),
            "safe_session_count": receipt.get("safe_session_count"),
        }
        for suffix, path in role_paths.items():
            paths[f"{role}_{suffix}"] = path
    return paths, corpora


def merge_experiment_manifest(
    *,
    training_bundle_dir: Path,
    partition_dir: Path,
    role_dirs: Mapping[str, Path],
    source_selection_receipt_path: Path,
    source_member_receipts_path: Path,
    experiment_policy_path: Path,
    preprocessing_path: Path,
    label_policy_path: Path,
    trust_policy_path: Path,
    classification_checkpoint_path: Path,
    environment_lock_path: Path,
) -> tuple[Dict[str, Any], Dict[str, str], Dict[str, Any]]:
    """Create an in-memory v2 manifest and evaluator artifact path map.

    This function is side-effect free.  Call :func:`write_merged_manifest`
    to publish the verified result atomically.
    """

    from production.prediction.next_behavior_experiment_policy import load_experiment_policy

    source_selection_receipt_path = _require_file(source_selection_receipt_path, label="source selection receipt")
    source_member_receipts_path = _require_file(source_member_receipts_path, label="source member receipts")
    experiment_policy_path = _require_file(experiment_policy_path, label="experiment policy")
    policy = load_experiment_policy(experiment_policy_path)
    bundle, bindings, training_paths = _load_training_bindings(
        Path(training_bundle_dir), policy=policy
    )
    partition_path = _require_file(Path(partition_dir) / "partition_manifest.json", label="partition manifest")
    partition = _read_json(partition_path, label="partition manifest")
    if not isinstance(partition, dict) or (
        partition.get("manifest_id") != bindings["partition_manifest_id"]
        or _sha256_path(partition_path) != bindings["partition_manifest_sha256"]
        or partition.get("roles") is None
    ):
        raise NextBehaviorManifestMergeError("partition manifest disagrees with training binding")
    memberships = {
        role: partition["roles"].get(role, {}).get("example_membership_sha256")
        for role in MEMBER_ROLES
    }
    if memberships != bindings["partition_membership_sha256"]:
        raise NextBehaviorManifestMergeError("partition memberships disagree with training binding")
    role_paths, corpora = _role_artifacts(role_dirs)
    source_selection = _read_json(source_selection_receipt_path, label="source selection receipt")
    if not isinstance(source_selection, dict):
        raise NextBehaviorManifestMergeError("source selection receipt is invalid")

    external_paths = {
        "source_selection_receipt": source_selection_receipt_path,
        "source_member_receipts": source_member_receipts_path,
        "experiment_policy": experiment_policy_path,
        "preprocessing": _require_file(preprocessing_path, label="preprocessing"),
        "partition_manifest": partition_path,
        "environment_lock": _require_file(environment_lock_path, label="environment lock"),
        "label_policy": _require_file(label_policy_path, label="label policy"),
        "trust_policy": _require_file(trust_policy_path, label="trust policy"),
        "classification_checkpoint": _require_file(classification_checkpoint_path, label="classification checkpoint"),
    }
    paths = {**external_paths, **training_paths, **role_paths}
    if set(paths) != set(REQUIRED_ARTIFACT_ROLES_V2):
        raise NextBehaviorManifestMergeError("merged artifact roles are incomplete")
    artifact_hashes = {role: _sha256_path(path) for role, path in paths.items()}
    policies = {
        **bindings["policies"],
        "label_policy_sha256": artifact_hashes["label_policy"],
        "trust_policy_sha256": artifact_hashes["trust_policy"],
        "classification_checkpoint_sha256": artifact_hashes["classification_checkpoint"],
    }
    for role, field in {
        "experiment_policy": "experiment_policy_artifact_sha256",
        "preprocessing": "preprocessing_sha256",
        "vocabulary": "vocabulary_artifact_sha256",
        "partition_manifest": "partition_manifest_sha256",
        "environment_lock": "environment_lock_sha256",
    }.items():
        expected = bindings["artifact_hashes"].get(role, bindings.get(field))
        if artifact_hashes[role] != expected:
            raise NextBehaviorManifestMergeError(f"{role} changed since training")
    manifest = {
        "schema_version": "next_behavior_experiment_manifest.v2",
        "status": "frozen_pre_test",
        "target_contract_id": TARGET_CONTRACT_ID,
        "input_schema_version": MODEL_INPUT_SCHEMA_VERSION,
        "code_commit": bindings["code_commit"],
        "source_selection": {
            "selection_id": source_selection.get("selection_id"),
            "completed_receipt_sha256": artifact_hashes["source_selection_receipt"],
            "source_member_count": 13,
            "source_member_receipts_sha256": artifact_hashes["source_member_receipts"],
        },
        "corpora": corpora,
        "partitions": {
            "manifest_id": partition["manifest_id"],
            "manifest_sha256": artifact_hashes["partition_manifest"],
            "membership_sha256": memberships,
            "test_opened": False,
        },
        "policies": policies,
        "model": bindings["model"],
        "baselines": bindings["baselines"],
        "calibration": bindings["calibration"],
        "decision_freeze": {
            key: value
            for key, value in bindings["decision_freeze"].items()
            if key not in {"schema_version", "bindings_sha256"}
        },
        "artifact_hashes": artifact_hashes,
    }
    manifest = with_experiment_manifest_id(manifest)
    try:
        manifest = require_valid_experiment_manifest(manifest)
    except Exception as exc:
        raise NextBehaviorManifestMergeError("merged experiment manifest is invalid") from exc
    path_map = {role: str(path) for role, path in sorted(paths.items())}
    receipt = {
        "schema_version": MERGE_RECEIPT_SCHEMA_VERSION,
        "status": "frozen_pre_test_manifest_merged",
        "training_bundle_sha256": _sha256_path(Path(training_bundle_dir) / "training_bundle.json"),
        "training_bindings_sha256": bindings["bindings_sha256"],
        "experiment_manifest_sha256": _sha256_json(manifest),
        "test_opened": False,
    }
    return manifest, path_map, receipt


def write_merged_manifest(
    output_dir: Path,
    **kwargs: Any,
) -> Dict[str, Any]:
    """Merge and atomically publish a new manifest directory without overwrite."""

    if output_dir.exists():
        raise FileExistsError(f"refusing to overwrite existing output: {output_dir}")
    manifest, path_map, receipt = merge_experiment_manifest(**kwargs)
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{output_dir.name}.", dir=output_dir.parent))
    try:
        _atomic_write_json(staging / "experiment_manifest.json", manifest)
        _atomic_write_json(
            staging / "artifact_paths.json",
            {"schema_version": ARTIFACT_PATHS_SCHEMA_VERSION, "artifacts": path_map},
        )
        _atomic_write_json(staging / "merge_receipt.json", receipt)
        os.replace(staging, output_dir)
    except BaseException:
        import shutil
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return receipt


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--training-bundle-dir", type=Path, required=True)
    parser.add_argument("--partition-dir", type=Path, required=True)
    for role in MEMBER_ROLES:
        parser.add_argument(f"--{role}-role-dir", type=Path, required=True)
    parser.add_argument("--source-selection-receipt", type=Path, required=True)
    parser.add_argument("--source-member-receipts", type=Path, required=True)
    parser.add_argument("--experiment-policy", type=Path, required=True)
    parser.add_argument("--preprocessing", type=Path, required=True)
    parser.add_argument("--label-policy", type=Path, required=True)
    parser.add_argument("--trust-policy", type=Path, required=True)
    parser.add_argument("--classification-checkpoint", type=Path, required=True)
    parser.add_argument("--environment-lock", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    receipt = write_merged_manifest(
        args.output_dir,
        training_bundle_dir=args.training_bundle_dir,
        partition_dir=args.partition_dir,
        role_dirs={role: getattr(args, f"{role}_role_dir") for role in MEMBER_ROLES},
        source_selection_receipt_path=args.source_selection_receipt,
        source_member_receipts_path=args.source_member_receipts,
        experiment_policy_path=args.experiment_policy,
        preprocessing_path=args.preprocessing,
        label_policy_path=args.label_policy,
        trust_policy_path=args.trust_policy,
        classification_checkpoint_path=args.classification_checkpoint,
        environment_lock_path=args.environment_lock,
    )
    print(json.dumps({"output": str(args.output_dir), **receipt}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
