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
from production.prediction.next_behavior_experiment import (
    EXPERIMENT_MANIFEST_SCHEMA_VERSION,
    REQUIRED_ARTIFACT_ROLES,
    NextBehaviorExperimentError,
    require_valid_experiment_manifest,
    validate_experiment_manifest,
    verify_experiment_artifacts,
    with_experiment_manifest_id,
)
from production.prediction.next_behavior_preprocessing import (
    build_live_model_input,
)
from production.prediction.next_behavior_tensor import build_vocabulary
from production.utils.serialization import stable_id, stable_json


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
