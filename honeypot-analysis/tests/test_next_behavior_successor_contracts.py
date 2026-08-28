from __future__ import annotations

import copy
import hashlib
from pathlib import Path

import pytest

from production.prediction.trusted_history import SCHEMA_VERSION as HISTORY_SCHEMA
from production.reproduction.next_behavior.source_selection import (
    SCHEMA_VERSION as HISTORICAL_SELECTION_SCHEMA,
)
from production.reproduction.next_behavior.source_selection_v2 import (
    COMPLETE_STATUS,
    ROLE_COUNTS,
    NextBehaviorSourceSelectionV2Error,
    build_successor_member_inventory,
    canonical_contract_sha256,
    load_source_selection_v2,
    require_completed_source_selection_v2,
    require_source_selection_v2_repository_binding,
    require_valid_source_selection_v2,
    require_valid_successor_member_inventory,
)
from production.reproduction.next_behavior.successor_contracts import (
    EXPERIMENT_BINDINGS_SCHEMA_VERSION,
    EXPERIMENT_MANIFEST_SCHEMA_VERSION,
    INGEST_SCHEMA_VERSION,
    PARTITION_PROTOCOL,
    PARTITION_SCHEMA_VERSION,
    PREPARATION_SCHEMA_VERSION,
    ROLE_INVENTORY_SCHEMA_VERSION,
    SAFE_BUILD_SCHEMA_VERSION,
    SEMANTICS_FREEZE_SCHEMA_VERSION,
    STORE_SCHEMA_VERSION,
    SUPPORT_GATE_SCHEMA_VERSION,
    SUPPORT_PREFLIGHT_SCHEMA_VERSION,
    TARGET_CONTRACT_ID,
    NextBehaviorSuccessorContractError,
    build_deterministic_semantics_freeze_evidence_v2,
    build_experiment_bindings_v3,
    build_experiment_manifest_v3,
    build_final_corpus_preparation_v2,
    build_partition_manifest_v3,
    build_role_inventory_v2,
    build_selected_ingest_receipt_v2,
    build_selected_private_store_metadata_v2,
    build_selected_safe_build_v4,
    build_selection_support_gate_v1,
    contract_sha256,
    require_valid_partition_manifest_v3,
    require_valid_role_inventory_v2,
    require_valid_selected_safe_build_v4,
    require_valid_experiment_manifest_v3,
    require_valid_deterministic_semantics_freeze_evidence_v2,
    require_valid_selection_support_gate_v1,
    require_valid_successor_contract,
)


ROOT = Path(__file__).resolve().parents[1]
SELECTION_PATH = ROOT / "configs" / "next_behavior_source_selection.v2.json"
HASH = "a" * 64
COMMIT = "b" * 40


def _hash(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _completed_selection() -> dict:
    value = copy.deepcopy(load_source_selection_v2(SELECTION_PATH))
    value["verification"] = {
        "status": COMPLETE_STATUS,
        "member_receipts": [
            {
                **member,
                "size_bytes": 1000 + index,
                "archive_compressed_bytes": 900 + index,
                "archive_crc32": f"{index:08x}",
                "sha256": _hash(member["filename"]),
            }
            for index, member in enumerate(value["members"], start=1)
        ],
    }
    return require_completed_source_selection_v2(value)


def _bindings(keys: set[str]) -> dict[str, str]:
    return {
        key: COMMIT if key == "code_commit" else _hash(key)
        for key in keys
    }


def _partition_and_roles() -> tuple[dict, dict]:
    inventory = build_successor_member_inventory(_completed_selection())
    partition = build_partition_manifest_v3(inventory)
    role_bindings = {
        "selected_ingest_receipt_sha256": _hash("selected-ingest"),
        "partition_manifest_sha256": contract_sha256(partition),
        "final_preparation_receipt_sha256": _hash("final-preparation"),
    }
    empty = {role: [] for role in ("train", "selection", "calibration")}
    roles = build_role_inventory_v2(
        bindings=role_bindings,
        partition_manifest=partition,
        development_session_ids=empty,
        development_example_ids=empty,
    )
    return partition, roles


def _semantic_tuple() -> dict:
    return {
        "classification_policy_sha256": _hash("classification-policy"),
        "classifier_source_identity_sha256": _hash("classifier-source"),
        "maximum_trusted_phases": 8,
        "mitre_cache_sha256": _hash("mitre-cache"),
        "preprocessing_contract_sha256": _hash("preprocessing"),
        "sequence_length": 8,
        "target_contract_id": TARGET_CONTRACT_ID,
        "trust_policy_sha256": _hash("trust-policy"),
        "trusted_history_schema_version": HISTORY_SCHEMA,
    }


def _prior_freeze() -> dict:
    return {
        "schema_version": "next_behavior_deterministic_semantics_freeze_evidence.v1",
        "status": "deterministic_semantics_frozen",
        "frozen_semantics": _semantic_tuple(),
    }


def _support(targets: int = 60) -> dict:
    return {
        "sessions": targets,
        "trusted_groups": targets * 3,
        "trusted_labels": targets * 3,
        "trusted_history_manifests": targets,
        "trusted_history_membership_sha256": _hash(
            f"trusted-history-membership-{targets}"
        ),
        "distinct_behavior_phases": targets * 3,
        "examples": targets * 3,
        "nonterminal_targets": targets * 2,
        "terminal_targets": targets,
        "target_tactics": {"discovery": targets, "execution": targets},
        "target_techniques": {"T1059": targets, "T1082": targets},
        "target_tactic_technique_pairs": {
            "discovery|T1082": targets,
            "execution|T1059": targets,
        },
        "phase_tactics": {"discovery": targets * 2, "execution": targets},
        "phase_techniques": {"T1059": targets, "T1082": targets * 2},
        "distinct_session_support": {
            "terminal": targets,
            "nonterminal": targets,
            "by_tactic": {"discovery": targets, "execution": targets},
            "by_technique": {"T1059": targets, "T1082": targets},
        },
        "terminal_to_nonterminal_ratio": "0.500000",
    }


def _support_preflight(targets: int = 60) -> dict:
    from production.reproduction.next_behavior.support_preflight import _gate_result
    from production.utils.serialization import stable_id, stable_json

    roles = {
        role: _support(targets)
        for role in ("train", "selection", "calibration")
    }
    gate = _gate_result(roles, require_selection_discovery=True)
    key_fingerprint = _hash("fixture-key")
    receipt = {
        "schema_version": SUPPORT_PREFLIGHT_SCHEMA_VERSION,
        "status": "support_gate_passed" if gate["passed"] else "support_gate_failed",
        "purpose": "development_only_support_preflight",
        "target_contract_id": TARGET_CONTRACT_ID,
        "trusted_history_schema_version": HISTORY_SCHEMA,
        "max_trusted_phases": 8,
        "successor_inventory_id": "fixture-inventory",
        "successor_inventory_sha256": _hash("inventory"),
        "source_selection_sha256": _hash("selection"),
        "classification_receipt_sha256": _hash("classification"),
        "donor_import_receipt_sha256": None,
        "pseudonymization_key_id": "next-behavior-hmac-" + key_fingerprint[:16],
        "pseudonymization_key_fingerprint_sha256": key_fingerprint,
        "frozen_semantics": {
            "classifier_manifest_sha256": _hash("classifier-manifest"),
            "classifier_source_identity_sha256": _hash("classifier-source"),
            "classifier_environment_sha256": _hash("classifier-environment"),
            "environment_lock_sha256": _hash("environment-lock"),
            "classifier_adapter_sha256": _hash("classifier-adapter"),
            "classification_pipeline_sha256": _hash("classification-pipeline"),
            "rule_policy_sha256": _hash("rule-policy"),
            "trust_policy_sha256": _hash("trust-policy"),
            "mitre_cache_sha256": _hash("mitre-cache"),
            "checkpoint_sha256": _hash("checkpoint"),
            "preprocessing_sha256": _hash("preprocessing"),
            "label_adapter_sha256": _hash("label-adapter"),
            "source_member_inventory_sha256": _hash("source-member-inventory"),
            "target_contract_id": TARGET_CONTRACT_ID,
            "trusted_history_schema_version": HISTORY_SCHEMA,
            "max_trusted_phases": 8,
        },
        "roles": roles,
        "aggregate_support_sha256": hashlib.sha256(
            stable_json(roles).encode("utf-8")
        ).hexdigest(),
        "gate": gate,
        "protections": {
            "test_members_accessed": False,
            "test_metrics_used": False,
            "raw_content_emitted": False,
            "unknown_or_unresolved_labels": 0,
            "role_membership_intersections": {
                "train_selection": 0,
                "train_calibration": 0,
                "selection_calibration": 0,
            },
            "source_member_partition_isolation": {
                "status": "verified_disjoint_from_validated_inventory",
                "identity_basis": "filename_and_source_sha256",
                "development_member_count": 24,
                "test_member_count": 7,
                "development_membership_sha256": _hash("development-members"),
                "test_membership_sha256": _hash("test-members"),
                "filename_intersection_count": 0,
                "content_sha256_intersection_count": 0,
            },
            "historical_test_session_membership": {
                "status": "verified_zero_intersection",
                "receipt_id": "historical-test-membership-fixture",
                "receipt_sha256": _hash("historical-membership-receipt"),
                "artifact_sha256": _hash("historical-membership-artifact"),
                "session_count": 1,
                "intersection_count": 0,
            },
        },
    }
    receipt["receipt_id"] = stable_id("nextbehaviorsupportpreflight", receipt)
    return receipt


def _baseline_requirements() -> list[dict]:
    return [
        {
            "role": role,
            "support_kind": kind,
            "label": label,
            "minimum_targets": 30,
            "minimum_distinct_sessions": 30,
        }
        for role, kind, label in (
            ("train", "tactic", "execution"),
            ("train", "tactic", "discovery"),
            ("selection", "tactic", "execution"),
            ("selection", "terminal", "session_end"),
            ("calibration", "terminal", "session_end"),
            ("calibration", "nonterminal", "any"),
        )
    ]


def test_v2_selection_is_exact_pending_and_does_not_redefine_v1() -> None:
    value = load_source_selection_v2(SELECTION_PATH)

    assert HISTORICAL_SELECTION_SCHEMA == "next_behavior_source_selection.v1"
    assert value["schema_version"] == "next_behavior_source_selection.v2"
    assert value["verification"] == {
        "status": "pending_archive_verification",
        "member_receipts": [],
    }
    assert [
        sum(member["role"] == role for member in value["members"])
        for role in ("train", "selection", "calibration", "test")
    ] == [10, 7, 7, 7]
    assert [
        member["collection_date"]
        for member in value["members"]
        if member["role"] == "test"
    ] == [
        "2025-08-09",
        "2025-08-10",
        "2025-08-11",
        "2025-08-12",
        "2025-08-13",
        "2025-08-15",
        "2025-08-16",
    ]
    assert all(
        member["sealed"] is (member["role"] == "test")
        for member in value["members"]
    )
    with pytest.raises(NextBehaviorSourceSelectionV2Error, match="pending"):
        require_completed_source_selection_v2(value)
    assert require_source_selection_v2_repository_binding(
        value, repository_root=ROOT
    ) == value


def test_v2_preserved_source_bytes_are_verified(tmp_path: Path) -> None:
    value = load_source_selection_v2(SELECTION_PATH)
    target = tmp_path / "configs" / "next_behavior_source_selection.v1.json"
    target.parent.mkdir(parents=True)
    target.write_text("changed", encoding="utf-8")

    with pytest.raises(NextBehaviorSourceSelectionV2Error, match="hash mismatch"):
        require_source_selection_v2_repository_binding(
            value, repository_root=tmp_path
        )


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value["policy"].__setitem__("labels_used", True),
        lambda value: value["members"].pop(),
        lambda value: value["members"][24].__setitem__("sealed", False),
        lambda value: value["members"][17].__setitem__("role", "train"),
    ],
)
def test_v2_selection_changes_fail_closed(mutation) -> None:
    value = copy.deepcopy(load_source_selection_v2(SELECTION_PATH))
    mutation(value)
    with pytest.raises(NextBehaviorSourceSelectionV2Error):
        require_valid_source_selection_v2(value)


def test_successor_inventory_is_deterministic_and_cross_bound() -> None:
    selection = _completed_selection()
    first = build_successor_member_inventory(selection)
    second = build_successor_member_inventory(copy.deepcopy(selection))

    assert first == second
    assert first["member_count"] == 31
    assert first["role_counts"] == ROLE_COUNTS
    assert first["source_selection_sha256"] == canonical_contract_sha256(selection)
    assert first["test_members_sealed"] is True

    tampered = copy.deepcopy(first)
    tampered["members"][0]["sha256"] = HASH
    with pytest.raises(NextBehaviorSourceSelectionV2Error):
        require_valid_successor_member_inventory(tampered, source_selection=selection)


def test_partition_v3_has_explicit_10_7_7_7_roles_and_sealed_test() -> None:
    inventory = build_successor_member_inventory(_completed_selection())
    manifest = build_partition_manifest_v3(inventory)

    assert manifest["schema_version"] == PARTITION_SCHEMA_VERSION
    assert manifest["evidence"]["protocol"] == PARTITION_PROTOCOL
    assert manifest["evidence"]["target_contract_id"] == TARGET_CONTRACT_ID
    assert manifest["evidence"]["max_sequence_length"] == 8
    assert {
        role: manifest["evidence"]["roles"][role]["source_member_count"]
        for role in ROLE_COUNTS
    } == ROLE_COUNTS
    assert manifest["evidence"]["roles"]["test"]["sealed"] is True
    assert manifest["evidence"]["labels_used_for_partitioning"] is False

    changed = copy.deepcopy(manifest)
    changed["evidence"]["roles"]["test"]["ordered_source_members"][0] = (
        changed["evidence"]["roles"]["train"]["ordered_source_members"][0]
    )
    changed["manifest_id"] = "nextbehaviorpartition_" + "0" * 32
    with pytest.raises(NextBehaviorSuccessorContractError):
        require_valid_partition_manifest_v3(changed, inventory=inventory)


def test_store_ingest_preparation_and_role_contracts_validate() -> None:
    partition, roles = _partition_and_roles()
    store = build_selected_private_store_metadata_v2(
        bindings=_bindings(
            {
                "source_selection_sha256",
                "successor_member_inventory_sha256",
                "partition_manifest_sha256",
                "implementation_sha256",
                "code_commit",
            }
        ),
        database_schema_revision=2,
    )
    ingest = build_selected_ingest_receipt_v2(
        bindings=_bindings(
            {
                "selected_private_store_sha256",
                "successor_member_inventory_sha256",
                "partition_manifest_sha256",
            }
        ),
        processed_member_names=[f"member-{index}" for index in range(31)],
        ordered_member_content_sha256=_hash("ordered-content"),
        row_counts={"sessions": 10, "command_events": 20},
    )
    preparation = build_final_corpus_preparation_v2(
        bindings=_bindings(
            {
                "source_selection_sha256",
                "successor_member_inventory_sha256",
                "partition_manifest_sha256",
                "selected_store_implementation_sha256",
                "classifier_environment_sha256",
                "preprocessing_sha256",
                "rule_policy_sha256",
                "trust_policy_sha256",
                "label_adapter_sha256",
                "code_commit",
            }
        ),
        pseudonymization_key_id="successor-hmac-fixture",
    )
    assert store["schema_version"] == STORE_SCHEMA_VERSION
    assert ingest["schema_version"] == INGEST_SCHEMA_VERSION
    assert ingest["evidence"]["test_members_classified"] is False
    assert preparation["schema_version"] == PREPARATION_SCHEMA_VERSION
    assert preparation["evidence"]["test_members_accessed"] is False
    assert roles["schema_version"] == ROLE_INVENTORY_SCHEMA_VERSION
    assert roles["evidence"]["test_access"] == "sealed_not_opened"
    for artifact in (store, ingest, preparation):
        assert require_valid_successor_contract(artifact) == artifact
    assert require_valid_role_inventory_v2(
        roles, partition_manifest=partition
    ) == roles
    with pytest.raises(NextBehaviorSuccessorContractError, match="upstream"):
        require_valid_successor_contract(roles)


def test_support_preflight_never_contains_test_metrics_and_gate_recomputes() -> None:
    preflight = _support_preflight()
    requirements = _baseline_requirements()
    gate = build_selection_support_gate_v1(
        preflight=preflight,
        requirements=requirements,
        requirements_policy_sha256=_hash("requirements-policy"),
        requirements_frozen_before_content_inspection=True,
    )

    assert preflight["schema_version"] == SUPPORT_PREFLIGHT_SCHEMA_VERSION
    assert set(preflight["roles"]) == {
        "train",
        "selection",
        "calibration",
    }
    assert preflight["protections"]["test_members_accessed"] is False
    assert gate["schema_version"] == SUPPORT_GATE_SCHEMA_VERSION
    assert gate["evidence"]["decision"] == "GO"

    tampered = copy.deepcopy(gate)
    tampered["evidence"]["checks"][0]["observed_targets"] = 0
    tampered_without_id = {
        key: value for key, value in tampered.items() if key != "gate_id"
    }
    from production.utils.serialization import stable_id, stable_json

    tampered["gate_id"] = stable_id(
        "nextbehaviorselectionsupportgate", tampered_without_id
    )
    with pytest.raises(
        NextBehaviorSuccessorContractError, match="observations mismatch"
    ):
        require_valid_selection_support_gate_v1(tampered, preflight=preflight)


def test_support_gate_records_no_go_without_weakening_thresholds() -> None:
    preflight = _support_preflight(targets=3)
    gate = build_selection_support_gate_v1(
        preflight=preflight,
        requirements=_baseline_requirements(),
        requirements_policy_sha256=_hash("requirements-policy"),
        requirements_frozen_before_content_inspection=True,
    )
    assert gate["evidence"]["decision"] == "NO_GO"
    assert "selection:tactic:execution" in gate["evidence"]["failed_checks"]


def test_support_gate_rejects_missing_or_weakened_reviewed_baseline() -> None:
    preflight = _support_preflight()
    missing = _baseline_requirements()[:-1]
    with pytest.raises(NextBehaviorSuccessorContractError, match="omit"):
        build_selection_support_gate_v1(
            preflight=preflight,
            requirements=missing,
            requirements_policy_sha256=_hash("requirements-policy"),
            requirements_frozen_before_content_inspection=True,
        )

    weakened = _baseline_requirements()
    weakened[0]["minimum_targets"] = 1
    with pytest.raises(NextBehaviorSuccessorContractError, match="cannot be weakened"):
        build_selection_support_gate_v1(
            preflight=preflight,
            requirements=weakened,
            requirements_policy_sha256=_hash("requirements-policy"),
            requirements_frozen_before_content_inspection=True,
        )


def test_safe_build_experiment_and_freeze_contracts_preserve_sealed_test() -> None:
    from production.utils.serialization import stable_id, stable_json

    partition, role_inventory = _partition_and_roles()
    empty_artifact = {"line_count": 0, "size_bytes": 0, "sha256": _hash("")}
    empty_membership_sha256 = hashlib.sha256(
        stable_json([]).encode("utf-8")
    ).hexdigest()
    reviewed_basis = {
        "schema_version": "next_behavior_selected_safe_build.v3",
        "status": "role_safe_corpus_built",
        "purpose": "fit_model",
        "role": "train",
        "source_cohort": "development",
        "max_sequence_length": 8,
        "raw_content_emitted": False,
        "membership": {
            "source_member_count": 0,
            "source_member_membership_sha256": empty_membership_sha256,
            "session_count": 0,
            "session_membership_sha256": empty_membership_sha256,
            "example_count": 0,
            "example_membership_sha256": empty_membership_sha256,
            "input_count": 0,
            "input_membership_sha256": empty_membership_sha256,
        },
        "safe_sessions": empty_artifact,
        "examples": empty_artifact,
    }
    reviewed_receipt = {
        **reviewed_basis,
        "build_receipt_id": stable_id(
            "nextbehaviorselectedsafebuild", reviewed_basis
        ),
    }
    safe_bindings = {
        "selected_store_sha256": _hash("selected-store"),
        "selected_ingest_receipt_sha256": _hash("selected-ingest"),
        "final_preparation_receipt_sha256": _hash("final-preparation"),
        "role_inventory_sha256": contract_sha256(role_inventory),
        "partition_manifest_sha256": contract_sha256(partition),
        "reviewed_safe_build_receipt_sha256": contract_sha256(reviewed_receipt),
    }
    safe = build_selected_safe_build_v4(
        bindings=safe_bindings,
        purpose="fit_model",
        reviewed_safe_build_receipt=reviewed_receipt,
        safe_sessions=[],
        examples=[],
        role_inventory=role_inventory,
        partition_manifest=partition,
    )
    freeze_base = {
        "source_selection_sha256": _hash("source-selection"),
        "successor_member_inventory_sha256": _hash("member-inventory"),
        "partition_manifest_sha256": contract_sha256(partition),
        "final_preparation_receipt_sha256": _hash("final-preparation"),
        "code_commit": COMMIT,
    }
    prior_freeze = _prior_freeze()
    freeze = build_deterministic_semantics_freeze_evidence_v2(
        bindings=freeze_base,
        prior_freeze=prior_freeze,
        current_semantic_tuple=_semantic_tuple(),
    )
    support = _support_preflight()
    gate = build_selection_support_gate_v1(
        preflight=support,
        requirements=_baseline_requirements(),
        requirements_policy_sha256=_hash("requirements-policy"),
        requirements_frozen_before_content_inspection=True,
    )
    experiment_binding_values = _bindings(
        {
            "source_selection_sha256",
            "successor_member_inventory_sha256",
            "partition_manifest_sha256",
            "final_preparation_receipt_sha256",
            "role_inventory_sha256",
            "selection_support_gate_sha256",
            "experiment_policy_sha256",
            "preprocessing_sha256",
            "classifier_environment_sha256",
            "deterministic_semantics_freeze_sha256",
            "code_commit",
        }
    )
    experiment_binding_values["selection_support_gate_sha256"] = contract_sha256(gate)
    bindings = build_experiment_bindings_v3(bindings=experiment_binding_values)
    manifest_bindings = _bindings(
        {
            "experiment_bindings_sha256",
            "selection_support_gate_sha256",
            "train_safe_build_sha256",
            "selection_safe_build_sha256",
            "calibration_safe_build_sha256",
        }
    )
    manifest_bindings["experiment_bindings_sha256"] = contract_sha256(bindings)
    manifest_bindings["selection_support_gate_sha256"] = contract_sha256(gate)
    manifest = build_experiment_manifest_v3(
        bindings=manifest_bindings,
        experiment_bindings=bindings,
        support_preflight=support,
        selection_gate=gate,
    )

    assert safe["schema_version"] == SAFE_BUILD_SCHEMA_VERSION
    assert safe["evidence"]["authorized_role"] == "train"
    assert freeze["schema_version"] == SEMANTICS_FREEZE_SCHEMA_VERSION
    assert freeze["evidence"]["reference_tuple_redefined"] is False
    assert bindings["schema_version"] == EXPERIMENT_BINDINGS_SCHEMA_VERSION
    assert bindings["evidence"]["model_checkpoint_decision_made"] is False
    assert manifest["schema_version"] == EXPERIMENT_MANIFEST_SCHEMA_VERSION
    assert manifest["evidence"]["test_safe_build_present"] is False
    assert require_valid_successor_contract(bindings) == bindings
    assert require_valid_selected_safe_build_v4(
        safe,
        reviewed_safe_build_receipt=reviewed_receipt,
        safe_sessions=[],
        examples=[],
        role_inventory=role_inventory,
        partition_manifest=partition,
    ) == safe
    assert require_valid_deterministic_semantics_freeze_evidence_v2(
        freeze,
        prior_freeze=prior_freeze,
        current_semantic_tuple=_semantic_tuple(),
    ) == freeze
    assert require_valid_experiment_manifest_v3(
        manifest,
        experiment_bindings=bindings,
        support_preflight=support,
        selection_gate=gate,
    ) == manifest
    for artifact in (safe, freeze, manifest):
        with pytest.raises(NextBehaviorSuccessorContractError, match="upstream"):
            require_valid_successor_contract(artifact)


def test_deterministic_identity_and_binding_tampering_fail_closed() -> None:
    store_bindings = _bindings(
        {
            "source_selection_sha256",
            "successor_member_inventory_sha256",
            "partition_manifest_sha256",
            "implementation_sha256",
            "code_commit",
        }
    )
    store = build_selected_private_store_metadata_v2(
        bindings=store_bindings, database_schema_revision=2
    )
    assert contract_sha256(store) == contract_sha256(copy.deepcopy(store))

    changed = copy.deepcopy(store)
    changed["bindings"]["implementation_sha256"] = _hash("changed")
    with pytest.raises(NextBehaviorSuccessorContractError, match="identity mismatch"):
        require_valid_successor_contract(changed)

    with pytest.raises(NextBehaviorSuccessorContractError, match="required upstream"):
        from production.reproduction.next_behavior.successor_contracts import (
            require_valid_selected_private_store_metadata_v2,
        )

        require_valid_selected_private_store_metadata_v2(
            store,
            expected_bindings={**store_bindings, "implementation_sha256": HASH},
        )
