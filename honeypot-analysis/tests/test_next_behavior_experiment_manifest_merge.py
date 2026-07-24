from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from production.prediction.next_behavior_experiment import (
    require_valid_experiment_manifest,
)
from production.prediction.next_behavior_experiment_policy import (
    load_experiment_policy,
)
from production.prediction.next_behavior_partitions import MEMBER_ROLES
from production.prediction.next_behavior_tensor import vocabulary_sha256
from production.tools.merge_next_behavior_experiment_manifest import (
    NextBehaviorManifestMergeError,
    merge_experiment_manifest,
    write_merged_manifest,
)
from production.tools.train_next_behavior_experiment import (
    build_decision_freeze_bindings,
)
from production.utils.serialization import stable_json


ROOT = Path(__file__).resolve().parents[1]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _entry(path: Path, root: Path) -> dict:
    return {
        "path": str(path.relative_to(root)),
        "sha256": _sha256(path),
        "byte_size": path.stat().st_size,
    }


def _inputs(tmp_path: Path) -> dict:
    from tests.test_next_behavior_experiment import _write_complete_v2_bundle

    source_dir = tmp_path / "source"
    source_dir.mkdir()
    _legacy_manifest, paths = _write_complete_v2_bundle(source_dir)
    policy_path = ROOT / "configs" / "next_behavior_experiment_policy.v1.json"
    policy = load_experiment_policy(policy_path)
    bundle_dir = tmp_path / "training-bundle"
    bundle_dir.mkdir()
    copied = {}
    for role in (
        "vocabulary",
        "model_spec",
        "calibration",
        "baseline_manifest",
        "checkpoint",
        "baseline_majority_terminal_prevalence",
        "baseline_first_order_phase_state_markov",
        "baseline_hard_backoff_vomm",
        "baseline_interpolated_vomm",
    ):
        target = bundle_dir / f"{role}.artifact"
        target.write_bytes(paths[role].read_bytes())
        copied[role] = target
    partition_dir = tmp_path / "partition"
    partition_dir.mkdir()
    partition_path = partition_dir / "partition_manifest.json"
    partition_path.write_bytes(paths["partition_manifest"].read_bytes())
    payload_dir = partition_dir / "safe_payloads"
    payload_dir.mkdir()
    for role in MEMBER_ROLES:
        (payload_dir / f"{role}.json").write_bytes(
            paths[f"{role}_safe_payload"].read_bytes()
        )
    partition = json.loads(partition_path.read_text())
    memberships = {
        role: partition["roles"][role]["example_membership_sha256"]
        for role in MEMBER_ROLES
    }
    bindings = {
        "schema_version": "next_behavior_experiment_bindings.v2",
        "status": "ready_for_v2_experiment_manifest_merge",
        "target_contract_id": policy["target_contract_id"],
        "code_commit": "a" * 40,
        "test_opened": False,
        "partition_manifest_id": partition["manifest_id"],
        "partition_manifest_sha256": _sha256(partition_path),
        "partition_membership_sha256": memberships,
        "pre_final_role_artifacts": {},
        "policies": {
            "experiment_policy_artifact_sha256": _sha256(policy_path),
            "experiment_policy_sha256": hashlib.sha256(
                stable_json(policy).encode("utf-8")
            ).hexdigest(),
            "preprocessing_sha256": _sha256(paths["preprocessing"]),
            "vocabulary_artifact_sha256": _sha256(copied["vocabulary"]),
            "vocabulary_sha256": vocabulary_sha256(
                json.loads(copied["vocabulary"].read_text())
            ),
            "environment_lock_sha256": _sha256(paths["environment_lock"]),
        },
        "model": {
            "family": "small_causal_transformer",
            "model_id": json.loads(copied["model_spec"].read_text())["spec_id"],
            "architecture_sha256": json.loads(copied["model_spec"].read_text())["architecture_sha256"],
            "parameter_count": 2632,
            "checkpoint_sha256": _sha256(copied["checkpoint"]),
            "model_spec_artifact_sha256": _sha256(copied["model_spec"]),
            "model_spec_sha256": json.loads(copied["model_spec"].read_text())["spec_sha256"],
            "state_dictionary_sha256": "b" * 64,
            "training_seed": 20260723,
            "training_membership_sha256": memberships["train"],
            "selection_membership_sha256": memberships["selection"],
            "selected_on_partition": "selection",
            "deterministic_replay_verified": True,
        },
        "baselines": {
            "manifest_sha256": _sha256(copied["baseline_manifest"]),
            "training_membership_sha256": memberships["train"],
            "families": {
                family: {
                    "model_id": json.loads(copied[f"baseline_{family}"].read_text())["model_id"],
                    "artifact_sha256": _sha256(copied[f"baseline_{family}"]),
                    "training_membership_sha256": memberships["train"],
                    "selection_membership_sha256": memberships["selection"],
                }
                for family in (
                    "majority_terminal_prevalence",
                    "first_order_phase_state_markov",
                    "hard_backoff_vomm",
                    "interpolated_vomm",
                )
            },
        },
        "calibration": {
            "artifact_sha256": _sha256(copied["calibration"]),
            **{
                key: json.loads(copied["calibration"].read_text())[key]
                for key in (
                    "status",
                    "method",
                    "mapping_sha256",
                    "fit_partition_membership_sha256",
                )
            },
        },
        "decision_freeze": build_decision_freeze_bindings(policy),
        "artifact_hashes": {
            "experiment_policy": _sha256(policy_path),
            "preprocessing": _sha256(paths["preprocessing"]),
            "vocabulary": _sha256(copied["vocabulary"]),
            "partition_manifest": _sha256(partition_path),
            "environment_lock": _sha256(paths["environment_lock"]),
            **{role: _sha256(path) for role, path in copied.items() if role not in {"vocabulary", "model_spec", "calibration", "baseline_manifest"}},
            "model_spec": _sha256(copied["model_spec"]),
            "calibration": _sha256(copied["calibration"]),
            "baseline_manifest": _sha256(copied["baseline_manifest"]),
        },
        "artifact_paths_relative_to_bundle": {
            role: path.name for role, path in copied.items()
        },
    }
    bindings["bindings_sha256"] = hashlib.sha256(
        stable_json(bindings).encode("utf-8")
    ).hexdigest()
    bindings_path = bundle_dir / "experiment_manifest_bindings.json"
    bindings_path.write_text(stable_json(bindings), encoding="utf-8")
    bundle = {
        "status": "frozen_pre_test",
        "code_commit": "a" * 40,
        "experiment_manifest_bindings": _entry(bindings_path, bundle_dir),
        "vocabulary": _entry(copied["vocabulary"], bundle_dir),
        "model_spec": _entry(copied["model_spec"], bundle_dir),
        "calibration": _entry(copied["calibration"], bundle_dir),
        "baselines_manifest": _entry(copied["baseline_manifest"], bundle_dir),
    }
    bundle["bundle_sha256"] = hashlib.sha256(stable_json(bundle).encode("utf-8")).hexdigest()
    (bundle_dir / "training_bundle.json").write_text(stable_json(bundle), encoding="utf-8")
    role_dirs = {}
    for role in MEMBER_ROLES:
        directory = tmp_path / f"{role}-role"
        directory.mkdir()
        for source, name in (
            (paths[f"{role}_role_inventory"], "role_inventory.json"),
            (paths[f"{role}_corpus_receipt"], "corpus_receipt.json"),
        ):
            (directory / name).write_bytes(source.read_bytes())
        role_dirs[role] = directory
    return {
        "training_bundle_dir": bundle_dir,
        "partition_dir": partition_dir,
        "role_dirs": role_dirs,
        "source_selection_receipt_path": paths["source_selection_receipt"],
        "source_member_receipts_path": paths["source_member_receipts"],
        "experiment_policy_path": policy_path,
        "preprocessing_path": paths["preprocessing"],
        "label_policy_path": paths["label_policy"],
        "trust_policy_path": paths["trust_policy"],
        "classification_checkpoint_path": paths["classification_checkpoint"],
        "environment_lock_path": paths["environment_lock"],
    }


def test_merger_derives_every_hash_and_preserves_the_test_payload_seal(tmp_path: Path) -> None:
    inputs = _inputs(tmp_path)
    manifest, paths, receipt = merge_experiment_manifest(**inputs)

    assert require_valid_experiment_manifest(manifest) == manifest
    assert receipt["test_opened"] is False
    assert Path(paths["test_safe_payload"]).read_bytes() == (
        inputs["partition_dir"] / "safe_payloads" / "test.json"
    ).read_bytes()
    output = tmp_path / "merged"
    write_merged_manifest(output, **inputs)
    assert json.loads((output / "experiment_manifest.json").read_text()) == manifest


def test_merger_rejects_changed_pre_final_binding(tmp_path: Path) -> None:
    inputs = _inputs(tmp_path)
    (inputs["preprocessing_path"]).write_text("changed\n", encoding="utf-8")
    with pytest.raises(NextBehaviorManifestMergeError, match="changed since training"):
        merge_experiment_manifest(**inputs)
