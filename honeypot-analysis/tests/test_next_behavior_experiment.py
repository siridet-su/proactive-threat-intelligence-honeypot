from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from production.prediction.next_behavior_contract import (
    MODEL_INPUT_SCHEMA_VERSION,
    TARGET_CONTRACT_ID,
)
from production.reproduction.next_behavior.experiment import (
    EXPERIMENT_MANIFEST_SCHEMA_VERSION,
    EXPERIMENT_MANIFEST_SCHEMA_VERSION_V2,
    REQUIRED_ARTIFACT_ROLES,
    REQUIRED_ARTIFACT_ROLES_V2,
    NextBehaviorExperimentError,
    require_valid_experiment_manifest,
    validate_experiment_manifest,
    verify_experiment_artifacts,
    verify_experiment_artifacts_v2_pretest,
    with_experiment_manifest_id,
)
from production.reproduction.next_behavior.experiment_policy import (
    experiment_policy_sha256,
)
from production.prediction.next_behavior_preprocessing import (
    build_next_behavior_examples,
    build_live_model_input,
)
from production.prediction.next_behavior_tensor import (
    build_vocabulary,
    vocabulary_sha256,
)
from production.prediction.next_behavior_model import build_model_spec
from production.reproduction.next_behavior.baseline import (
    fit_corrected_target_baselines,
)
from production.reproduction.next_behavior.calibration import (
    build_not_implemented_mapping,
)
from production.utils.serialization import stable_id, stable_json

ROOT = Path(__file__).resolve().parents[1]


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _manifest(
    hashes: dict[str, str] | None = None,
    *,
    corpus_receipt_id: str = "nextbehaviorcorpus_fixture",
) -> dict:
    artifact_hashes = hashes or {
        role: _digest(role) for role in REQUIRED_ARTIFACT_ROLES
    }
    memberships = {
        "train": _digest("train-membership"),
        "selection": _digest("selection-membership"),
        "calibration": _digest("calibration-membership"),
        "test": _digest("test-membership"),
    }
    value = {
        "schema_version": EXPERIMENT_MANIFEST_SCHEMA_VERSION,
        "status": "frozen_pre_test",
        "target_contract_id": TARGET_CONTRACT_ID,
        "input_schema_version": MODEL_INPUT_SCHEMA_VERSION,
        "code_commit": "fixture-commit",
        "corpus": {
            "receipt_id": corpus_receipt_id,
            "receipt_sha256": artifact_hashes["corpus_receipt"],
            "safe_payload_sha256": artifact_hashes["safe_payload"],
            "accepted_historical_exclusion_sha256": _digest(
                "historical-exclusion"
            ),
            "safe_session_count": 1,
            "trusted_group_count": 1,
            "source_member_count": 7,
            "source_member_receipts_artifact_sha256": artifact_hashes[
                "source_member_receipts"
            ],
        },
        "partitions": {
            "manifest_id": "nextbehaviorpartition_fixture",
            "manifest_sha256": artifact_hashes["partition_manifest"],
            "membership_sha256": memberships,
            "test_opened": False,
        },
        "policies": {
            "preprocessing_sha256": artifact_hashes["preprocessing"],
            "vocabulary_sha256": artifact_hashes["vocabulary"],
            "label_policy_sha256": artifact_hashes["label_policy"],
            "trust_policy_sha256": artifact_hashes["trust_policy"],
            "environment_lock_sha256": artifact_hashes["environment_lock"],
            "classification_checkpoint_sha256": artifact_hashes[
                "classification_checkpoint"
            ],
        },
        "model": {
            "family": "small_causal_transformer",
            "model_id": "next-behavior-transformer-fixture",
            "architecture_sha256": _digest("architecture"),
            "parameter_count": 2632,
            "checkpoint_sha256": artifact_hashes["checkpoint"],
            "state_dictionary_sha256": _digest("state-dictionary"),
            "training_seed": 20260723,
            "training_membership_sha256": memberships["train"],
            "selection_membership_sha256": memberships["selection"],
            "selected_on_partition": "selection",
            "deterministic_replay_verified": True,
        },
        "baseline": {
            "family": "hard_backoff_vomm",
            "model_id": "same-target-vomm-fixture",
            "target_contract_id": TARGET_CONTRACT_ID,
            "artifact_sha256": artifact_hashes["baseline_artifact"],
            "manifest_sha256": artifact_hashes["baseline_manifest"],
            "training_membership_sha256": memberships["train"],
            "selection_membership_sha256": memberships["selection"],
            "role": "interpretable_disagreement_reference_only",
        },
        "calibration": {
            "status": "not_implemented",
            "method": "",
            "mapping_sha256": "",
            "fit_partition_membership_sha256": memberships["calibration"],
        },
        "decision_freeze": {
            "selection_rule_sha256": _digest("selection-rule"),
            "promotion_rule_sha256": _digest("promotion-rule"),
            "feature_rule_sha256": _digest("feature-rule"),
            "seed_rule_sha256": _digest("seed-rule"),
            "calibration_rule_sha256": _digest("calibration-rule"),
            "frozen_before_test": True,
        },
        "artifact_hashes": artifact_hashes,
    }
    return with_experiment_manifest_id(value)


def _memberships() -> dict[str, str]:
    return {
        "train": _digest("train-membership"),
        "selection": _digest("selection-membership"),
        "calibration": _digest("calibration-membership"),
        "test": _digest("test-membership"),
    }


def _write_bundle(tmp_path: Path) -> tuple[dict[str, Path], dict[str, str]]:
    paths = {role: tmp_path / f"{role}.artifact" for role in REQUIRED_ARTIFACT_ROLES}
    paths["checkpoint"].write_bytes(b"checkpoint bytes\n")
    paths["label_policy"].write_text('{"policy": "label"}\n', encoding="utf-8")
    paths["trust_policy"].write_text('{"policy": "trust"}\n', encoding="utf-8")
    paths["environment_lock"].write_text("fixture==1.0\n", encoding="utf-8")
    paths["classification_checkpoint"].write_bytes(
        b"classification checkpoint bytes\n"
    )
    source_receipts = [
        {
            "schema_version": "next_behavior_source_member_receipt.v1",
            "member_id": (
                "nbmember_"
                + (_digest("member") if index == 0 else _digest(f"member-{index}"))
            ),
            "sha256": _digest(f"source-member-{index}"),
            "byte_size": 1000 + index,
            "chronological_order": index + 1,
            "collection_start": f"2026-01-{index + 1:02d}T00:00:00Z",
            "collection_end": f"2026-01-{index + 1:02d}T23:59:59Z",
            "pseudonymization_scheme": "hmac-sha256-v1",
            "pseudonymization_key_id": "fixture-key-v1",
        }
        for index in range(7)
    ]
    source_receipts.sort(key=lambda receipt: receipt["member_id"])
    chronological_member_ids = [
        receipt["member_id"]
        for receipt in sorted(
            source_receipts,
            key=lambda receipt: receipt["chronological_order"],
        )
    ]
    paths["source_member_receipts"].write_text(
        stable_json(source_receipts),
        encoding="utf-8",
    )
    paths["baseline_artifact"].write_bytes(b"same-target baseline bytes\n")
    label_policy_sha = hashlib.sha256(paths["label_policy"].read_bytes()).hexdigest()
    trust_policy_sha = hashlib.sha256(paths["trust_policy"].read_bytes()).hexdigest()
    evidence_ref = "nbevidence_" + _digest("evidence")
    paths["safe_payload"].write_text(
        json.dumps(
            [
                {
                    "schema_version": "next_behavior_session.v1",
                    "session_id": "nbsession_" + _digest("session"),
                    "source_member_id": "nbmember_" + _digest("member"),
                    "source_member_sha256": _digest("source-member"),
                    "protocol": "ssh",
                    "status": "closed",
                    "observation_groups": [
                        {
                            "group_id": "nbgroup_" + _digest("group"),
                            "event_order": 1,
                            "relative_time_ms": 0,
                            "tactics": ["discovery"],
                            "techniques": ["T1082"],
                            "evidence_refs": [evidence_ref],
                            "label_provenance": [
                                {
                                    "tactic": "discovery",
                                    "technique": "T1082",
                                    "source": "reviewed_rule",
                                    "trust_tier": "trusted_observation",
                                    "policy_sha256": label_policy_sha,
                                    "trust_policy_sha256": trust_policy_sha,
                                    "checkpoint_sha256": "",
                                    "confidence": 1.0,
                                    "confidence_bucket": "high",
                                    "agreement_status": "rule_only",
                                    "evidence_ref": evidence_ref,
                                }
                            ],
                            "session_context": {
                                "login_outcome": "success",
                                "command_count_bucket": "1",
                                "session_age_bucket": "under_10s",
                                "confirmed_transfer_observed": False,
                            },
                        }
                    ],
                }
            ],
            sort_keys=True,
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    paths["preprocessing"].write_text(
        json.dumps(
            {
                "schema_version": "next_behavior_preprocessing.v1",
                "target_contract_id": TARGET_CONTRACT_ID,
                "input_schema_version": MODEL_INPUT_SCHEMA_VERSION,
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    safe_payload_value = json.loads(paths["safe_payload"].read_text())
    vocabulary = build_vocabulary(
        [build_live_model_input(safe_payload_value[0])],
        preprocessing_sha256=hashlib.sha256(
            paths["preprocessing"].read_bytes()
        ).hexdigest(),
        training_membership_sha256=_memberships()["train"],
    )
    paths["vocabulary"].write_text(
        stable_json(vocabulary),
        encoding="utf-8",
    )
    hashes = {
        role: hashlib.sha256(path.read_bytes()).hexdigest()
        for role, path in paths.items()
        if path.exists()
    }
    paths["baseline_manifest"].write_text(
        json.dumps(
            {
                "target_contract_id": TARGET_CONTRACT_ID,
                "artifact_sha256": hashes["baseline_artifact"],
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    paths["partition_manifest"].write_text(
        json.dumps(
            {
                "manifest_id": "nextbehaviorpartition_fixture",
                "target_contract_id": TARGET_CONTRACT_ID,
                "roles": {
                    role: {
                        "example_membership_sha256": membership,
                        "source_member_ids": (
                            chronological_member_ids[:4]
                            if role == "train"
                            else [
                                chronological_member_ids[
                                    {
                                        "selection": 4,
                                        "calibration": 5,
                                        "test": 6,
                                    }[role]
                                ]
                            ]
                        ),
                    }
                    for role, membership in _memberships().items()
                },
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    hashes.update(
        {
            role: hashlib.sha256(paths[role].read_bytes()).hexdigest()
            for role in ("baseline_manifest", "partition_manifest")
        }
    )
    corpus_receipt = {
        "schema_version": "next_behavior_corpus_receipt.v1",
        "status": "safe_payload_reconciled",
        "code_commit": "fixture-commit",
        "preprocessing_sha256": hashes["preprocessing"],
        "label_policy_sha256": hashes["label_policy"],
        "trust_policy_sha256": hashes["trust_policy"],
        "classification_checkpoint_sha256": hashes[
            "classification_checkpoint"
        ],
        "source_member_count": 7,
        "source_member_receipts_sha256": hashlib.sha256(
            stable_json(
                sorted(
                    hashlib.sha256(
                        stable_json(receipt).encode("utf-8")
                    ).hexdigest()
                    for receipt in source_receipts
                )
            ).encode("utf-8")
        ).hexdigest(),
        "source_member_receipts_artifact_sha256": hashes[
            "source_member_receipts"
        ],
        "private_session_count": 1,
        "safe_session_count": 1,
        "dropped_session_count": 0,
        "safe_session_membership_sha256": _digest("session-membership"),
        "safe_payload_sha256": hashes["safe_payload"],
        "counts": {
            "private_group_count": 1,
            "safe_trusted_group_count": 1,
            "audit_only_group_count": 0,
            "private_label_count": 1,
            "trusted_label_count": 1,
            "audit_only_label_count": 0,
        },
    }
    corpus_receipt["receipt_id"] = stable_id(
        "nextbehaviorcorpus",
        corpus_receipt,
    )
    paths["corpus_receipt"].write_text(
        json.dumps(corpus_receipt, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    hashes["corpus_receipt"] = hashlib.sha256(
        paths["corpus_receipt"].read_bytes()
    ).hexdigest()
    assert set(paths) == set(hashes) == set(REQUIRED_ARTIFACT_ROLES)
    return paths, hashes


def test_complete_corrected_target_freeze_manifest_is_valid() -> None:
    value = _manifest()

    assert validate_experiment_manifest(value) == []
    assert require_valid_experiment_manifest(value) == value


def test_old_target_or_current_production_baseline_cannot_be_reused() -> None:
    value = _manifest()
    value["target_contract_id"] = "next_distinct_tactic.v2"
    value["baseline"]["target_contract_id"] = "next_distinct_tactic.v2"
    value = with_experiment_manifest_id(value)

    errors = validate_experiment_manifest(value)

    assert any("corrected phase-or-end target" in error for error in errors)
    assert any("baseline must be rebuilt" in error for error in errors)


def test_selection_calibration_and_test_membership_must_be_independent() -> None:
    value = _manifest()
    value["partitions"]["membership_sha256"]["calibration"] = (
        value["partitions"]["membership_sha256"]["selection"]
    )
    value["calibration"]["fit_partition_membership_sha256"] = (
        value["partitions"]["membership_sha256"]["selection"]
    )
    value = with_experiment_manifest_id(value)

    assert any(
        "must be distinct" in error for error in validate_experiment_manifest(value)
    )


def test_model_and_baseline_must_use_exact_role_memberships() -> None:
    value = _manifest()
    value["model"]["training_membership_sha256"] = _digest("wrong")
    value["baseline"]["selection_membership_sha256"] = _digest("wrong")
    value = with_experiment_manifest_id(value)

    errors = validate_experiment_manifest(value)

    assert any("model training membership" in error for error in errors)
    assert any("baseline selection membership" in error for error in errors)


def test_pre_test_manifest_cannot_open_test_or_change_rules_afterward() -> None:
    value = _manifest()
    value["partitions"]["test_opened"] = True
    value["decision_freeze"]["frozen_before_test"] = False
    value = with_experiment_manifest_id(value)

    errors = validate_experiment_manifest(value)

    assert any("cannot have an opened test" in error for error in errors)
    assert any("frozen before test" in error for error in errors)


def test_manifest_identity_detects_copied_hash_with_mutated_content() -> None:
    value = _manifest()
    value["model"]["training_seed"] += 1

    assert any(
        "manifest_id does not match" in error
        for error in validate_experiment_manifest(value)
    )


def test_every_artifact_field_is_bound_to_the_same_hash() -> None:
    value = _manifest()
    value["artifact_hashes"]["checkpoint"] = _digest("different")
    value = with_experiment_manifest_id(value)

    assert any(
        "checkpoint contradicts" in error
        for error in validate_experiment_manifest(value)
    )


def test_exact_artifact_bytes_verify_before_inference(tmp_path: Path) -> None:
    paths, hashes = _write_bundle(tmp_path)
    corpus_receipt = json.loads(paths["corpus_receipt"].read_text())
    value = _manifest(
        hashes,
        corpus_receipt_id=corpus_receipt["receipt_id"],
    )

    result = verify_experiment_artifacts(value, paths)

    assert result["status"] == "verified"
    assert result["target_contract_id"] == TARGET_CONTRACT_ID
    assert set(result["artifacts"]) == set(REQUIRED_ARTIFACT_ROLES)


def test_missing_or_hash_mismatched_artifacts_fail_closed(tmp_path: Path) -> None:
    paths, hashes = _write_bundle(tmp_path)
    corpus_receipt = json.loads(paths["corpus_receipt"].read_text())
    value = _manifest(
        hashes,
        corpus_receipt_id=corpus_receipt["receipt_id"],
    )

    paths["checkpoint"].unlink()
    with pytest.raises(NextBehaviorExperimentError, match="checkpoint.*missing"):
        verify_experiment_artifacts(value, paths)

    paths["checkpoint"].write_text("corrupted", encoding="utf-8")
    with pytest.raises(
        NextBehaviorExperimentError,
        match="checkpoint.*hash mismatch",
    ):
        verify_experiment_artifacts(value, paths)


def test_hash_valid_but_semantically_old_baseline_fails_closed(
    tmp_path: Path,
) -> None:
    paths, hashes = _write_bundle(tmp_path)
    paths["baseline_manifest"].write_text(
        json.dumps(
            {
                "target_contract_id": "next_distinct_tactic.v2",
                "artifact_sha256": hashes["baseline_artifact"],
            }
        ),
        encoding="utf-8",
    )
    hashes["baseline_manifest"] = hashlib.sha256(
        paths["baseline_manifest"].read_bytes()
    ).hexdigest()
    corpus_receipt = json.loads(paths["corpus_receipt"].read_text())
    value = _manifest(
        hashes,
        corpus_receipt_id=corpus_receipt["receipt_id"],
    )

    with pytest.raises(
        NextBehaviorExperimentError,
        match="baseline manifest semantic binding mismatch",
    ):
        verify_experiment_artifacts(value, paths)


def test_hash_valid_payload_with_wrong_label_policy_fails_closed(
    tmp_path: Path,
) -> None:
    paths, hashes = _write_bundle(tmp_path)
    safe_payload = json.loads(paths["safe_payload"].read_text())
    safe_payload[0]["observation_groups"][0]["label_provenance"][0][
        "policy_sha256"
    ] = _digest("different-label-policy")
    paths["safe_payload"].write_text(
        json.dumps(safe_payload, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    hashes["safe_payload"] = hashlib.sha256(
        paths["safe_payload"].read_bytes()
    ).hexdigest()
    receipt = json.loads(paths["corpus_receipt"].read_text())
    receipt["safe_payload_sha256"] = hashes["safe_payload"]
    receipt.pop("receipt_id")
    receipt["receipt_id"] = stable_id("nextbehaviorcorpus", receipt)
    paths["corpus_receipt"].write_text(
        json.dumps(receipt, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    hashes["corpus_receipt"] = hashlib.sha256(
        paths["corpus_receipt"].read_bytes()
    ).hexdigest()
    value = _manifest(
        hashes,
        corpus_receipt_id=receipt["receipt_id"],
    )

    with pytest.raises(
        NextBehaviorExperimentError,
        match="label policy binding mismatch",
    ):
        verify_experiment_artifacts(value, paths)


def test_unknown_manifest_fields_are_rejected() -> None:
    value = _manifest()
    value["automatic_promotion"] = True
    value = with_experiment_manifest_id(value)

    assert any(
        "automatic_promotion is not defined" in error
        for error in validate_experiment_manifest(value)
    )


def _v2_manifest(
    hashes: dict[str, str],
    *,
    policy_semantic_sha256: str,
) -> dict:
    memberships = _memberships()
    corpora = {
        role: {
            "receipt_id": f"nextbehaviorcorpus_{role}",
            "receipt_sha256": hashes[f"{role}_corpus_receipt"],
            "safe_payload_sha256": hashes[f"{role}_safe_payload"],
            "role_inventory_sha256": hashes[f"{role}_role_inventory"],
            "source_member_count": {
                "train": 4,
                "selection": 1,
                "calibration": 1,
                "test": 7,
            }[role],
            "safe_session_count": 1,
        }
        for role in memberships
    }
    baseline_families = (
        "majority_terminal_prevalence",
        "first_order_phase_state_markov",
        "hard_backoff_vomm",
        "interpolated_vomm",
    )
    value = {
        "schema_version": EXPERIMENT_MANIFEST_SCHEMA_VERSION_V2,
        "status": "frozen_pre_test",
        "target_contract_id": TARGET_CONTRACT_ID,
        "input_schema_version": MODEL_INPUT_SCHEMA_VERSION,
        "code_commit": "fixture-v2-commit",
        "source_selection": {
            "selection_id": "corrected_target_calendar_selection.v1",
            "completed_receipt_sha256": hashes[
                "source_selection_receipt"
            ],
            "source_member_count": 13,
            "source_member_receipts_sha256": hashes[
                "source_member_receipts"
            ],
        },
        "corpora": corpora,
        "partitions": {
            "manifest_id": "nextbehaviorpartition_fixture_v2",
            "manifest_sha256": hashes["partition_manifest"],
            "membership_sha256": memberships,
            "test_opened": False,
        },
        "policies": {
            "experiment_policy_artifact_sha256": hashes[
                "experiment_policy"
            ],
            "experiment_policy_sha256": policy_semantic_sha256,
            "preprocessing_sha256": hashes["preprocessing"],
            "vocabulary_artifact_sha256": hashes["vocabulary"],
            "vocabulary_sha256": _digest("semantic-vocabulary"),
            "label_policy_sha256": hashes["label_policy"],
            "trust_policy_sha256": hashes["trust_policy"],
            "environment_lock_sha256": hashes["environment_lock"],
            "classification_checkpoint_sha256": hashes[
                "classification_checkpoint"
            ],
        },
        "model": {
            "family": "small_causal_transformer",
            "model_id": "nextbehaviormodelspec_fixture",
            "architecture_sha256": _digest("architecture-v2"),
            "parameter_count": 2632,
            "checkpoint_sha256": hashes["checkpoint"],
            "model_spec_artifact_sha256": hashes["model_spec"],
            "model_spec_sha256": _digest("semantic-model-spec"),
            "state_dictionary_sha256": _digest("state-v2"),
            "training_seed": 20260723,
            "training_membership_sha256": memberships["train"],
            "selection_membership_sha256": memberships["selection"],
            "selected_on_partition": "selection",
            "deterministic_replay_verified": True,
        },
        "baselines": {
            "manifest_sha256": hashes["baseline_manifest"],
            "training_membership_sha256": memberships["train"],
            "families": {
                family: {
                    "model_id": f"nextbehaviorbaseline_{family}",
                    "artifact_sha256": hashes[f"baseline_{family}"],
                    "training_membership_sha256": memberships["train"],
                    "selection_membership_sha256": memberships["selection"],
                }
                for family in baseline_families
            },
        },
        "calibration": {
            "artifact_sha256": hashes["calibration"],
            "status": "not_implemented",
            "method": "",
            "mapping_sha256": "",
            "fit_partition_membership_sha256": memberships["calibration"],
        },
        "decision_freeze": {
            "selection_rule_sha256": _digest("selection-rule-v2"),
            "promotion_rule_sha256": _digest("promotion-rule-v2"),
            "feature_rule_sha256": _digest("feature-rule-v2"),
            "seed_rule_sha256": _digest("seed-rule-v2"),
            "calibration_rule_sha256": _digest("calibration-rule-v2"),
            "frozen_before_test": True,
        },
        "artifact_hashes": hashes,
    }
    return with_experiment_manifest_id(value)


def _write_v2_policy_preflight_bundle(
    tmp_path: Path,
    *,
    invalid_policy: bool,
) -> tuple[dict, dict[str, Path]]:
    paths = {
        role: tmp_path / f"{role}.artifact"
        for role in REQUIRED_ARTIFACT_ROLES_V2
    }
    for role, path in paths.items():
        path.write_text(f"{role} fixture\n", encoding="utf-8")

    selection = json.loads(
        (
            ROOT / "configs" / "next_behavior_source_selection.v1.json"
        ).read_text(encoding="utf-8")
    )
    completed_receipts = []
    source_receipts = []
    for member in selection["members"]:
        order = member["chronological_order"]
        sha256 = _digest(f"selected-member-{order}")
        completed_receipts.append(
            {
                "filename": member["filename"],
                "archive_path": member["archive_path"],
                "collection_date": member["collection_date"],
                "role": member["role"],
                "size_bytes": 1000 + order,
                "archive_compressed_bytes": 500 + order,
                "archive_crc32": f"{order:08x}",
                "sha256": sha256,
            }
        )
        source_receipts.append(
            {
                "schema_version": "next_behavior_source_member_receipt.v1",
                "member_id": "nbmember_" + _digest(member["filename"]),
                "sha256": sha256,
                "byte_size": 1000 + order,
                "chronological_order": order,
                "collection_start": member["collection_date"] + "T00:00:00Z",
                "collection_end": member["collection_date"] + "T23:59:59Z",
                "pseudonymization_scheme": "hmac-sha256-v1",
                "pseudonymization_key_id": "fixture-key-v2",
            }
        )
    selection["verification"] = {
        "status": "archive_members_verified",
        "member_receipts": completed_receipts,
    }
    paths["source_selection_receipt"].write_text(
        stable_json(selection), encoding="utf-8"
    )
    paths["source_member_receipts"].write_text(
        stable_json(source_receipts), encoding="utf-8"
    )

    policy = json.loads(
        (
            ROOT / "configs" / "next_behavior_experiment_policy.v1.json"
        ).read_text(encoding="utf-8")
    )
    if invalid_policy:
        policy["authority"]["production_change_allowed"] = True
    paths["experiment_policy"].write_text(
        stable_json(policy), encoding="utf-8"
    )
    hashes = {
        role: hashlib.sha256(path.read_bytes()).hexdigest()
        for role, path in paths.items()
    }
    manifest = _v2_manifest(
        hashes,
        policy_semantic_sha256=experiment_policy_sha256(policy),
    )
    return manifest, paths


def _write_complete_v2_bundle(
    tmp_path: Path,
) -> tuple[dict, dict[str, Path]]:
    legacy = tmp_path / "legacy"
    legacy.mkdir()
    legacy_paths, _legacy_hashes = _write_bundle(legacy)
    manifest, paths = _write_v2_policy_preflight_bundle(
        tmp_path,
        invalid_policy=False,
    )
    source_receipts = json.loads(paths["source_member_receipts"].read_text())
    policy = json.loads(paths["experiment_policy"].read_text())
    memberships = _memberships()

    for role in (
        "preprocessing",
        "label_policy",
        "trust_policy",
        "classification_checkpoint",
    ):
        paths[role].write_bytes(legacy_paths[role].read_bytes())
    paths["environment_lock"].write_text("fixture==1.0\n", encoding="utf-8")
    preprocessing_sha = hashlib.sha256(paths["preprocessing"].read_bytes()).hexdigest()
    label_sha = hashlib.sha256(paths["label_policy"].read_bytes()).hexdigest()
    trust_sha = hashlib.sha256(paths["trust_policy"].read_bytes()).hexdigest()
    classification_sha = hashlib.sha256(
        paths["classification_checkpoint"].read_bytes()
    ).hexdigest()

    safe_session = json.loads(legacy_paths["safe_payload"].read_text())[0]
    safe_session["source_member_id"] = source_receipts[0]["member_id"]
    safe_session["source_member_sha256"] = source_receipts[0]["sha256"]
    vocabulary = build_vocabulary(
        [build_live_model_input(safe_session)],
        preprocessing_sha256=preprocessing_sha,
        training_membership_sha256=memberships["train"],
    )
    paths["vocabulary"].write_text(stable_json(vocabulary), encoding="utf-8")
    model_spec = build_model_spec(vocabulary)
    paths["model_spec"].write_text(stable_json(model_spec), encoding="utf-8")
    paths["checkpoint"].write_bytes(b"fixture checkpoint bytes\n")
    checkpoint_sha = hashlib.sha256(paths["checkpoint"].read_bytes()).hexdigest()

    calibration = build_not_implemented_mapping(
        fit_partition_membership_sha256=memberships["calibration"],
        checkpoint_sha256=checkpoint_sha,
        vocabulary_sha256=vocabulary_sha256(vocabulary),
        preprocessing_sha256=preprocessing_sha,
    )
    paths["calibration"].write_text(
        stable_json(calibration), encoding="utf-8"
    )

    examples = build_next_behavior_examples(safe_session)
    baseline_artifacts = fit_corrected_target_baselines(examples)
    baseline_entries = {}
    for family, artifact in baseline_artifacts.items():
        path = paths[f"baseline_{family}"]
        path.write_text(stable_json(artifact), encoding="utf-8")
        baseline_entries[family] = {
            "model_id": artifact["model_id"],
            "artifact_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "selection_metrics_sha256": _digest(f"{family}-metrics"),
        }
    baseline_manifest = {
        "schema_version": "next_behavior_baseline_bundle.v1",
        "target_contract_id": TARGET_CONTRACT_ID,
        "experiment_policy_sha256": experiment_policy_sha256(policy),
        "training_membership_sha256": memberships["train"],
        "selection_membership_sha256": memberships["selection"],
        "configuration": policy["baselines"],
        "artifacts": baseline_entries,
    }
    baseline_manifest["manifest_sha256"] = hashlib.sha256(
        stable_json(baseline_manifest).encode()
    ).hexdigest()
    paths["baseline_manifest"].write_text(
        stable_json(baseline_manifest), encoding="utf-8"
    )

    role_members = {
        "train": [item["member_id"] for item in source_receipts[:4]],
        "selection": [source_receipts[4]["member_id"]],
        "calibration": [source_receipts[5]["member_id"]],
        "test": [item["member_id"] for item in source_receipts[6:]],
    }
    for role, member_ids in role_members.items():
        role_session = copy.deepcopy(safe_session)
        role_session["session_id"] = "nbsession_" + _digest(f"{role}-session")
        selected_receipt = next(
            item for item in source_receipts if item["member_id"] == member_ids[0]
        )
        role_session["source_member_id"] = selected_receipt["member_id"]
        role_session["source_member_sha256"] = selected_receipt["sha256"]
        payload = [role_session]
        paths[f"{role}_safe_payload"].write_text(
            stable_json(payload), encoding="utf-8"
        )
        payload_sha = hashlib.sha256(
            paths[f"{role}_safe_payload"].read_bytes()
        ).hexdigest()
        receipt = {
            "schema_version": "next_behavior_corpus_receipt.v1",
            "status": "safe_payload_reconciled",
            "code_commit": "fixture-v2-commit",
            "preprocessing_sha256": preprocessing_sha,
            "label_policy_sha256": label_sha,
            "trust_policy_sha256": trust_sha,
            "classification_checkpoint_sha256": classification_sha,
            "source_member_count": len(member_ids),
            "source_member_receipts_sha256": _digest(f"{role}-receipts"),
            "source_member_receipts_artifact_sha256": hashlib.sha256(
                paths["source_member_receipts"].read_bytes()
            ).hexdigest(),
            "private_session_count": 1,
            "safe_session_count": 1,
            "dropped_session_count": 0,
            "safe_session_membership_sha256": _digest(f"{role}-membership"),
            "safe_payload_sha256": payload_sha,
            "counts": {
                "private_group_count": 1,
                "safe_trusted_group_count": 1,
                "audit_only_group_count": 0,
                "private_label_count": 1,
                "trusted_label_count": 1,
                "audit_only_label_count": 0,
            },
        }
        receipt["receipt_id"] = stable_id("nextbehaviorcorpus", receipt)
        paths[f"{role}_corpus_receipt"].write_text(
            stable_json(receipt), encoding="utf-8"
        )
        inventory = {
            "schema_version": "next_behavior_role_inventory.v1",
            "status": "role_membership_frozen",
            "target_contract_id": TARGET_CONTRACT_ID,
            "purpose": {
                "train": "fit_model",
                "selection": "select_model",
                "calibration": "fit_calibration",
                "test": "final_evaluation",
            }[role],
            "role": role,
            "source_cohort": "final" if role == "test" else "development",
            "source_selection_sha256": hashlib.sha256(
                paths["source_selection_receipt"].read_bytes()
            ).hexdigest(),
            "pseudonymization_scheme": "hmac-sha256-v1",
            "pseudonymization_key_id": "fixture-key-v2",
            "source_member_count": len(member_ids),
            "source_members_sha256": _digest(f"{role}-members"),
            "eligible_complete_session_count": 1,
            "session_membership_sha256": _digest(f"{role}-sessions"),
            "quarantined_session_count": 0,
            "partial_sessions_can_emit_terminal_target": False,
            "raw_content_emitted": False,
            "inventory_id": f"nextbehaviorroleinventory_{_digest(role)[:32]}",
        }
        paths[f"{role}_role_inventory"].write_text(
            stable_json(inventory), encoding="utf-8"
        )

    partition = {
        "schema_version": "next_behavior_partition_manifest.v2",
        "target_contract_id": TARGET_CONTRACT_ID,
        "status": "membership_frozen",
        "code_commit": "fixture-v2-commit",
        "manifest_id": "nextbehaviorpartition_fixture_v2",
        "roles": {
            role: {
                "cohort": "final" if role == "test" else "development",
                "source_member_count": len(member_ids),
                "source_member_ids": member_ids,
                "example_membership_sha256": memberships[role],
            }
            for role, member_ids in role_members.items()
        },
        "intersection_proofs": {
            "roles": {
                "source_members": {"all_empty": True},
                "sessions": {"all_empty": True},
                "examples": {"all_empty": True},
            },
            "cohorts": {
                "source_members": {"all_empty": True},
                "sessions": {"all_empty": True},
                "examples": {"all_empty": True},
            },
        },
    }
    paths["partition_manifest"].write_text(
        stable_json(partition), encoding="utf-8"
    )

    hashes = {
        role: hashlib.sha256(path.read_bytes()).hexdigest()
        for role, path in paths.items()
    }
    value = _v2_manifest(
        hashes,
        policy_semantic_sha256=experiment_policy_sha256(policy),
    )
    value["policies"]["preprocessing_sha256"] = preprocessing_sha
    value["policies"]["vocabulary_sha256"] = vocabulary_sha256(vocabulary)
    value["policies"]["label_policy_sha256"] = label_sha
    value["policies"]["trust_policy_sha256"] = trust_sha
    value["policies"]["classification_checkpoint_sha256"] = classification_sha
    value["model"]["model_id"] = model_spec["spec_id"]
    value["model"]["architecture_sha256"] = model_spec["architecture_sha256"]
    value["model"]["model_spec_sha256"] = model_spec["spec_sha256"]
    value["model"]["checkpoint_sha256"] = checkpoint_sha
    value["calibration"]["artifact_sha256"] = hashes["calibration"]
    for role in memberships:
        receipt = json.loads(paths[f"{role}_corpus_receipt"].read_text())
        value["corpora"][role]["receipt_id"] = receipt["receipt_id"]
    for family in baseline_artifacts:
        value["baselines"]["families"][family]["model_id"] = (
            baseline_artifacts[family]["model_id"]
        )
    value = with_experiment_manifest_id(value)
    assert validate_experiment_manifest(value) == []
    return value, paths


def test_v2_manifest_binds_thirteen_members_four_roles_and_four_baselines() -> None:
    hashes = {
        role: _digest(f"v2-{role}") for role in REQUIRED_ARTIFACT_ROLES_V2
    }
    manifest = _v2_manifest(
        hashes,
        policy_semantic_sha256=_digest("policy-semantic"),
    )

    assert validate_experiment_manifest(manifest) == []
    assert require_valid_experiment_manifest(manifest) == manifest

    changed = copy.deepcopy(manifest)
    changed["corpora"]["test"]["source_member_count"] = 1
    changed["partitions"]["test_opened"] = True
    changed["baselines"]["families"].pop("interpolated_vomm")
    changed = with_experiment_manifest_id(changed)
    errors = validate_experiment_manifest(changed)
    assert any("corpora.test.source_member_count must be 7" in item for item in errors)
    assert any("test_opened=false" in item for item in errors)
    assert any("all four frozen baselines" in item for item in errors)


def test_v2_semantically_invalid_policy_fails_before_test_payload_parse(
    tmp_path: Path,
) -> None:
    manifest, paths = _write_v2_policy_preflight_bundle(
        tmp_path,
        invalid_policy=True,
    )
    # This is deliberately not JSON.  A pre-test gate may hash and seal it,
    # but must not parse/open it before every prerequisite has verified.
    assert paths["test_safe_payload"].read_text() == "test_safe_payload fixture\n"

    with pytest.raises(
        NextBehaviorExperimentError,
        match="experiment policy is semantically invalid",
    ):
        verify_experiment_artifacts_v2_pretest(manifest, paths)


def test_v2_hash_mismatch_fails_before_any_semantic_artifact_is_trusted(
    tmp_path: Path,
) -> None:
    manifest, paths = _write_v2_policy_preflight_bundle(
        tmp_path,
        invalid_policy=True,
    )
    paths["test_safe_payload"].write_text("changed sealed payload\n")

    with pytest.raises(
        NextBehaviorExperimentError,
        match="test_safe_payload artifact hash mismatch",
    ):
        verify_experiment_artifacts(manifest, paths)


def test_complete_v2_bundle_verifies_without_opening_final_payload(
    tmp_path: Path,
) -> None:
    manifest, paths = _write_complete_v2_bundle(tmp_path)

    result = verify_experiment_artifacts_v2_pretest(manifest, paths)

    assert result["status"] == "verified_pre_test"
    assert result["test_opened"] is False
    assert result["artifacts"]["test_safe_payload"]["sha256"] == (
        manifest["artifact_hashes"]["test_safe_payload"]
    )
