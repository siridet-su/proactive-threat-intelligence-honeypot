"""Successor-corpus contract and validator layer.

The contracts in this module describe a future 31-member preparation.  They
do not create a database, open sealed test data, manufacture receipts, or
reinterpret historical v1/v2 artifacts.  Builders accept already-observed
hashes/counts and immediately validate the resulting artifact; consumers can
revalidate the same object and optionally require exact upstream bindings.
"""

from __future__ import annotations

import hashlib
import re
from itertools import combinations
from typing import Any, Callable, Dict, Mapping, Sequence

from production.prediction.next_behavior_contract import (
    NextBehaviorContractError,
    require_valid_next_behavior_session,
)
from production.prediction.next_behavior_preprocessing import (
    build_next_behavior_examples,
)
from production.reproduction.next_behavior.safe_export import (
    SAFE_BUILD_RECEIPT_SCHEMA_VERSION as REVIEWED_SAFE_BUILD_SCHEMA_VERSION,
    SelectedSafeCorpusError,
    _scan_public_value,
)
from production.reproduction.next_behavior.source_selection_v2 import (
    ROLE_COUNTS,
    canonical_contract_sha256,
    require_valid_successor_member_inventory,
)
from production.reproduction.next_behavior.support_preflight import (
    SupportPreflightError,
    build_support_preflight_receipt,
    require_valid_support_preflight_receipt,
)
from production.utils.serialization import stable_id, stable_json


PARTITION_SCHEMA_VERSION = "next_behavior_partition_manifest.v3"
STORE_SCHEMA_VERSION = "next_behavior_selected_private_store.v2"
INGEST_SCHEMA_VERSION = "next_behavior_selected_ingest_receipt.v2"
PREPARATION_SCHEMA_VERSION = "next_behavior_final_corpus_preparation.v2"
ROLE_INVENTORY_SCHEMA_VERSION = "next_behavior_role_inventory.v2"
SUPPORT_PREFLIGHT_SCHEMA_VERSION = "next_behavior_support_preflight.v1"
SUPPORT_GATE_SCHEMA_VERSION = "next_behavior_selection_support_gate.v1"
SAFE_BUILD_SCHEMA_VERSION = "next_behavior_selected_safe_build.v4"
EXPERIMENT_BINDINGS_SCHEMA_VERSION = "next_behavior_experiment_bindings.v3"
EXPERIMENT_MANIFEST_SCHEMA_VERSION = "next_behavior_experiment_manifest.v3"
SEMANTICS_FREEZE_SCHEMA_VERSION = (
    "next_behavior_deterministic_semantics_freeze_evidence.v2"
)

TARGET_CONTRACT_ID = (
    "next_distinct_trusted_behavior_phase_or_session_end.v2"
)
PARTITION_PROTOCOL = "successor_chronological_10_7_7_7_with_embargo.v1"
ROLE_ORDER = ("train", "selection", "calibration", "test")
DEVELOPMENT_ROLES = ("train", "selection", "calibration")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_KEY_ID = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")


class NextBehaviorSuccessorContractError(ValueError):
    """Raised when a successor artifact is incomplete or inconsistent."""


def contract_sha256(value: Mapping[str, Any]) -> str:
    """Return a deterministic content identity for a validated contract."""

    return hashlib.sha256(stable_json(dict(value)).encode("utf-8")).hexdigest()


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _is_sha256(value: Any) -> bool:
    return bool(_SHA256.fullmatch(_clean(value).lower()))


def _require_sha256(value: Any, path: str) -> str:
    digest = _clean(value).lower()
    if not _SHA256.fullmatch(digest):
        raise NextBehaviorSuccessorContractError(f"{path} must be a SHA-256 digest")
    return digest


def _require_nonnegative_int(value: Any, path: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise NextBehaviorSuccessorContractError(
            f"{path} must be a non-negative integer"
        )
    return value


def _require_positive_int(value: Any, path: str) -> int:
    result = _require_nonnegative_int(value, path)
    if result < 1:
        raise NextBehaviorSuccessorContractError(f"{path} must be positive")
    return result


def _require_exact_keys(value: Any, keys: set[str], path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise NextBehaviorSuccessorContractError(f"{path} fields are invalid")
    return value


def _require_bindings(
    value: Any,
    keys: set[str],
    *,
    path: str = "bindings",
) -> Dict[str, str]:
    bindings = _require_exact_keys(value, keys, path)
    result: Dict[str, str] = {}
    for key in sorted(keys):
        text = _clean(bindings[key]).lower()
        if key.endswith("_sha256"):
            _require_sha256(text, f"{path}.{key}")
        elif key == "code_commit":
            if not _COMMIT.fullmatch(text):
                raise NextBehaviorSuccessorContractError(
                    f"{path}.code_commit must be a full Git SHA"
                )
        elif not text:
            raise NextBehaviorSuccessorContractError(f"{path}.{key} is required")
        result[key] = text
    return result


def _require_expected_bindings(
    actual: Mapping[str, Any], expected: Mapping[str, Any] | None
) -> None:
    if expected is None:
        return
    if dict(actual) != dict(expected):
        raise NextBehaviorSuccessorContractError(
            "successor contract bindings do not match required upstream identities"
        )


def _build_document(
    *,
    schema_version: str,
    id_field: str,
    id_prefix: str,
    status: str,
    bindings: Mapping[str, Any],
    evidence: Mapping[str, Any],
) -> Dict[str, Any]:
    document: Dict[str, Any] = {
        "schema_version": schema_version,
        "status": status,
        "bindings": dict(bindings),
        "evidence": dict(evidence),
    }
    document[id_field] = stable_id(id_prefix, document)
    return document


def _require_document(
    value: Any,
    *,
    schema_version: str,
    id_field: str,
    id_prefix: str,
    status: str,
    binding_keys: set[str],
    evidence_keys: set[str],
    expected_bindings: Mapping[str, Any] | None = None,
) -> tuple[Dict[str, Any], Dict[str, str], Mapping[str, Any]]:
    fields = {"schema_version", id_field, "status", "bindings", "evidence"}
    root = _require_exact_keys(value, fields, schema_version)
    if root["schema_version"] != schema_version:
        raise NextBehaviorSuccessorContractError(
            f"unsupported schema: {root['schema_version']}"
        )
    if root["status"] != status:
        raise NextBehaviorSuccessorContractError(
            f"{schema_version} status must be {status}"
        )
    bindings = _require_bindings(root["bindings"], binding_keys)
    _require_expected_bindings(bindings, expected_bindings)
    evidence = _require_exact_keys(root["evidence"], evidence_keys, "evidence")
    basis = {
        "schema_version": root["schema_version"],
        "status": root["status"],
        "bindings": dict(root["bindings"]),
        "evidence": dict(root["evidence"]),
    }
    if root[id_field] != stable_id(id_prefix, basis):
        raise NextBehaviorSuccessorContractError(
            f"{schema_version} deterministic identity mismatch"
        )
    return dict(root), bindings, evidence


def _membership_sha256(values: Sequence[str]) -> str:
    if any(not _clean(value) for value in values):
        raise NextBehaviorSuccessorContractError("membership contains an empty identity")
    if len(values) != len(set(values)):
        raise NextBehaviorSuccessorContractError("membership identities must be unique")
    return hashlib.sha256(stable_json(sorted(values)).encode("utf-8")).hexdigest()


def build_partition_manifest_v3(
    inventory: Mapping[str, Any],
) -> Dict[str, Any]:
    """Bind the exact verified members to explicit variable role membership."""

    checked = require_valid_successor_member_inventory(inventory)
    roles: Dict[str, Dict[str, Any]] = {}
    all_names: Dict[str, set[str]] = {}
    for role in ROLE_ORDER:
        members = [item for item in checked["members"] if item["role"] == role]
        names = [item["filename"] for item in members]
        all_names[role] = set(names)
        roles[role] = {
            "source_member_count": len(members),
            "ordered_source_members": names,
            "source_member_membership_sha256": _membership_sha256(names),
            "source_member_receipts_sha256": _membership_sha256(
                [f"{item['filename']}:{item['sha256']}" for item in members]
            ),
            "cohort": "final" if role == "test" else "development",
            "sealed": role == "test",
        }
    intersections = {
        f"{left}__{right}": sorted(all_names[left].intersection(all_names[right]))
        for left, right in combinations(ROLE_ORDER, 2)
    }
    bindings = {
        "source_selection_sha256": checked["source_selection_sha256"],
        "successor_member_inventory_sha256": contract_sha256(checked),
    }
    evidence = {
        "protocol": PARTITION_PROTOCOL,
        "target_contract_id": TARGET_CONTRACT_ID,
        "max_sequence_length": 8,
        "role_counts": dict(ROLE_COUNTS),
        "roles": roles,
        "embargo_dates": ["2025-08-08"],
        "excluded_dates": ["2025-08-14"],
        "role_intersections": intersections,
        "test_access": "sealed_until_one_final_evaluation",
        "labels_used_for_partitioning": False,
    }
    document = _build_document(
        schema_version=PARTITION_SCHEMA_VERSION,
        id_field="manifest_id",
        id_prefix="nextbehaviorpartition",
        status="membership_frozen",
        bindings=bindings,
        evidence=evidence,
    )
    return require_valid_partition_manifest_v3(document, inventory=checked)


def require_valid_partition_manifest_v3(
    value: Any,
    *,
    inventory: Mapping[str, Any] | None = None,
) -> Dict[str, Any]:
    expected = None
    checked_inventory = None
    if inventory is not None:
        checked_inventory = require_valid_successor_member_inventory(inventory)
        expected = {
            "source_selection_sha256": checked_inventory["source_selection_sha256"],
            "successor_member_inventory_sha256": contract_sha256(checked_inventory),
        }
    document, _, evidence = _require_document(
        value,
        schema_version=PARTITION_SCHEMA_VERSION,
        id_field="manifest_id",
        id_prefix="nextbehaviorpartition",
        status="membership_frozen",
        binding_keys={
            "source_selection_sha256",
            "successor_member_inventory_sha256",
        },
        evidence_keys={
            "protocol",
            "target_contract_id",
            "max_sequence_length",
            "role_counts",
            "roles",
            "embargo_dates",
            "excluded_dates",
            "role_intersections",
            "test_access",
            "labels_used_for_partitioning",
        },
        expected_bindings=expected,
    )
    if evidence["protocol"] != PARTITION_PROTOCOL:
        raise NextBehaviorSuccessorContractError("partition protocol changed")
    if evidence["target_contract_id"] != TARGET_CONTRACT_ID:
        raise NextBehaviorSuccessorContractError("partition target contract changed")
    if evidence["max_sequence_length"] != 8:
        raise NextBehaviorSuccessorContractError("partition sequence length changed")
    if evidence["role_counts"] != ROLE_COUNTS:
        raise NextBehaviorSuccessorContractError("partition role counts changed")
    if evidence["embargo_dates"] != ["2025-08-08"] or evidence[
        "excluded_dates"
    ] != ["2025-08-14"]:
        raise NextBehaviorSuccessorContractError("partition temporal exclusions changed")
    if evidence["test_access"] != "sealed_until_one_final_evaluation":
        raise NextBehaviorSuccessorContractError("partition test access is not sealed")
    if evidence["labels_used_for_partitioning"] is not False:
        raise NextBehaviorSuccessorContractError("partitioning must remain label-blind")
    roles = _require_exact_keys(evidence["roles"], set(ROLE_ORDER), "evidence.roles")
    seen: set[str] = set()
    for role in ROLE_ORDER:
        item = _require_exact_keys(
            roles[role],
            {
                "source_member_count",
                "ordered_source_members",
                "source_member_membership_sha256",
                "source_member_receipts_sha256",
                "cohort",
                "sealed",
            },
            f"evidence.roles.{role}",
        )
        names = item["ordered_source_members"]
        if not isinstance(names, list) or len(names) != ROLE_COUNTS[role]:
            raise NextBehaviorSuccessorContractError(
                f"partition {role} membership count is invalid"
            )
        if item["source_member_count"] != len(names):
            raise NextBehaviorSuccessorContractError(
                f"partition {role} declared count does not reconcile"
            )
        if item["source_member_membership_sha256"] != _membership_sha256(names):
            raise NextBehaviorSuccessorContractError(
                f"partition {role} membership hash mismatch"
            )
        if seen.intersection(names):
            raise NextBehaviorSuccessorContractError("partition memberships overlap")
        seen.update(names)
        if item["cohort"] != ("final" if role == "test" else "development"):
            raise NextBehaviorSuccessorContractError("partition cohort assignment changed")
        if item["sealed"] is not (role == "test"):
            raise NextBehaviorSuccessorContractError("partition sealed state changed")
        _require_sha256(
            item["source_member_receipts_sha256"],
            f"evidence.roles.{role}.source_member_receipts_sha256",
        )
    intersections = _require_exact_keys(
        evidence["role_intersections"],
        {f"{a}__{b}" for a, b in combinations(ROLE_ORDER, 2)},
        "evidence.role_intersections",
    )
    if any(value != [] for value in intersections.values()):
        raise NextBehaviorSuccessorContractError("partition intersection proof failed")
    if checked_inventory is not None:
        expected_by_role = {
            role: [
                item["filename"]
                for item in checked_inventory["members"]
                if item["role"] == role
            ]
            for role in ROLE_ORDER
        }
        for role in ROLE_ORDER:
            if roles[role]["ordered_source_members"] != expected_by_role[role]:
                raise NextBehaviorSuccessorContractError(
                    f"partition {role} membership differs from verified inventory"
                )
            receipt_membership = _membership_sha256(
                [
                    f"{item['filename']}:{item['sha256']}"
                    for item in checked_inventory["members"]
                    if item["role"] == role
                ]
            )
            if roles[role]["source_member_receipts_sha256"] != receipt_membership:
                raise NextBehaviorSuccessorContractError(
                    f"partition {role} receipt hash mismatch"
                )
    return document


_STORE_BINDINGS = {
    "source_selection_sha256",
    "successor_member_inventory_sha256",
    "partition_manifest_sha256",
    "implementation_sha256",
    "code_commit",
}
_STORE_EVIDENCE = {
    "database_schema_revision",
    "journal_mode",
    "synchronous",
    "fresh_store_only",
    "canonical_tables",
    "test_members_sealed",
}
_CANONICAL_TABLES = [
    "metadata",
    "source_members",
    "command_events",
    "context_events",
    "session_sources",
    "sessions",
    "quarantined_sessions",
    "command_labels",
    "build_stage_receipts",
]


def build_selected_private_store_metadata_v2(
    *, bindings: Mapping[str, Any], database_schema_revision: int
) -> Dict[str, Any]:
    checked_bindings = _require_bindings(bindings, _STORE_BINDINGS)
    evidence = {
        "database_schema_revision": _require_positive_int(
            database_schema_revision, "database_schema_revision"
        ),
        "journal_mode": "WAL",
        "synchronous": "NORMAL",
        "fresh_store_only": True,
        "canonical_tables": list(_CANONICAL_TABLES),
        "test_members_sealed": True,
    }
    return require_valid_selected_private_store_metadata_v2(
        _build_document(
            schema_version=STORE_SCHEMA_VERSION,
            id_field="metadata_id",
            id_prefix="nextbehaviorselectedstore",
            status="initialized_for_successor_preparation",
            bindings=checked_bindings,
            evidence=evidence,
        )
    )


def require_valid_selected_private_store_metadata_v2(
    value: Any, *, expected_bindings: Mapping[str, Any] | None = None
) -> Dict[str, Any]:
    document, _, evidence = _require_document(
        value,
        schema_version=STORE_SCHEMA_VERSION,
        id_field="metadata_id",
        id_prefix="nextbehaviorselectedstore",
        status="initialized_for_successor_preparation",
        binding_keys=_STORE_BINDINGS,
        evidence_keys=_STORE_EVIDENCE,
        expected_bindings=expected_bindings,
    )
    _require_positive_int(evidence["database_schema_revision"], "database_schema_revision")
    if evidence["journal_mode"] != "WAL" or evidence["synchronous"] not in {
        "NORMAL",
        "FULL",
    }:
        raise NextBehaviorSuccessorContractError("unsafe SQLite durability mode")
    if evidence["fresh_store_only"] is not True:
        raise NextBehaviorSuccessorContractError("v2 store must be created fresh")
    if evidence["canonical_tables"] != _CANONICAL_TABLES:
        raise NextBehaviorSuccessorContractError("v2 store canonical tables changed")
    if evidence["test_members_sealed"] is not True:
        raise NextBehaviorSuccessorContractError("v2 store test members are not sealed")
    return document


_INGEST_BINDINGS = {
    "selected_private_store_sha256",
    "successor_member_inventory_sha256",
    "partition_manifest_sha256",
}
_INGEST_EVIDENCE = {
    "processed_member_count",
    "processed_member_membership_sha256",
    "ordered_member_content_sha256",
    "row_counts",
    "sqlite_quick_check",
    "foreign_key_violation_count",
    "source_receipts_reconciled",
    "test_members_classified",
}


def build_selected_ingest_receipt_v2(
    *,
    bindings: Mapping[str, Any],
    processed_member_names: Sequence[str],
    ordered_member_content_sha256: str,
    row_counts: Mapping[str, int],
) -> Dict[str, Any]:
    checked = _require_bindings(bindings, _INGEST_BINDINGS)
    if len(processed_member_names) != 31:
        raise NextBehaviorSuccessorContractError("ingest must reconcile exactly 31 members")
    counts = {
        str(key): _require_nonnegative_int(value, f"row_counts.{key}")
        for key, value in row_counts.items()
    }
    if not counts:
        raise NextBehaviorSuccessorContractError("ingest row counts are required")
    evidence = {
        "processed_member_count": 31,
        "processed_member_membership_sha256": _membership_sha256(
            list(processed_member_names)
        ),
        "ordered_member_content_sha256": _require_sha256(
            ordered_member_content_sha256, "ordered_member_content_sha256"
        ),
        "row_counts": counts,
        "sqlite_quick_check": "ok",
        "foreign_key_violation_count": 0,
        "source_receipts_reconciled": True,
        "test_members_classified": False,
    }
    return require_valid_selected_ingest_receipt_v2(
        _build_document(
            schema_version=INGEST_SCHEMA_VERSION,
            id_field="receipt_id",
            id_prefix="nextbehaviorselectedingest",
            status="ingest_reconciled",
            bindings=checked,
            evidence=evidence,
        )
    )


def require_valid_selected_ingest_receipt_v2(
    value: Any, *, expected_bindings: Mapping[str, Any] | None = None
) -> Dict[str, Any]:
    document, _, evidence = _require_document(
        value,
        schema_version=INGEST_SCHEMA_VERSION,
        id_field="receipt_id",
        id_prefix="nextbehaviorselectedingest",
        status="ingest_reconciled",
        binding_keys=_INGEST_BINDINGS,
        evidence_keys=_INGEST_EVIDENCE,
        expected_bindings=expected_bindings,
    )
    if evidence["processed_member_count"] != 31:
        raise NextBehaviorSuccessorContractError("ingest member count changed")
    _require_sha256(
        evidence["processed_member_membership_sha256"],
        "processed_member_membership_sha256",
    )
    _require_sha256(evidence["ordered_member_content_sha256"], "ordered_member_content_sha256")
    counts = evidence["row_counts"]
    if not isinstance(counts, Mapping) or not counts:
        raise NextBehaviorSuccessorContractError("ingest row counts are invalid")
    for key, count in counts.items():
        if not _clean(key):
            raise NextBehaviorSuccessorContractError("ingest row count key is empty")
        _require_nonnegative_int(count, f"row_counts.{key}")
    if evidence["sqlite_quick_check"] != "ok":
        raise NextBehaviorSuccessorContractError("SQLite integrity check failed")
    if evidence["foreign_key_violation_count"] != 0:
        raise NextBehaviorSuccessorContractError("SQLite foreign-key check failed")
    if evidence["source_receipts_reconciled"] is not True:
        raise NextBehaviorSuccessorContractError("source receipts did not reconcile")
    if evidence["test_members_classified"] is not False:
        raise NextBehaviorSuccessorContractError("test members were opened before evaluation")
    return document


_PREPARATION_BINDINGS = {
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
_PREPARATION_EVIDENCE = {
    "purpose",
    "evaluation_opened",
    "test_members_accessed",
    "pseudonymization_key_id",
    "target_contract_id",
    "max_sequence_length",
    "role_counts",
}


def build_final_corpus_preparation_v2(
    *, bindings: Mapping[str, Any], pseudonymization_key_id: str
) -> Dict[str, Any]:
    checked = _require_bindings(bindings, _PREPARATION_BINDINGS)
    key_id = _clean(pseudonymization_key_id)
    if not _KEY_ID.fullmatch(key_id):
        raise NextBehaviorSuccessorContractError("pseudonymization key ID is invalid")
    evidence = {
        "purpose": "prepare_successor_corpus",
        "evaluation_opened": False,
        "test_members_accessed": False,
        "pseudonymization_key_id": key_id,
        "target_contract_id": TARGET_CONTRACT_ID,
        "max_sequence_length": 8,
        "role_counts": dict(ROLE_COUNTS),
    }
    return require_valid_final_corpus_preparation_v2(
        _build_document(
            schema_version=PREPARATION_SCHEMA_VERSION,
            id_field="receipt_id",
            id_prefix="nextbehaviorfinalpreparation",
            status="frozen_for_blinded_preparation",
            bindings=checked,
            evidence=evidence,
        )
    )


def require_valid_final_corpus_preparation_v2(
    value: Any, *, expected_bindings: Mapping[str, Any] | None = None
) -> Dict[str, Any]:
    document, _, evidence = _require_document(
        value,
        schema_version=PREPARATION_SCHEMA_VERSION,
        id_field="receipt_id",
        id_prefix="nextbehaviorfinalpreparation",
        status="frozen_for_blinded_preparation",
        binding_keys=_PREPARATION_BINDINGS,
        evidence_keys=_PREPARATION_EVIDENCE,
        expected_bindings=expected_bindings,
    )
    if evidence["purpose"] != "prepare_successor_corpus":
        raise NextBehaviorSuccessorContractError("preparation purpose changed")
    if evidence["evaluation_opened"] is not False or evidence[
        "test_members_accessed"
    ] is not False:
        raise NextBehaviorSuccessorContractError("preparation opened sealed evaluation data")
    if not _KEY_ID.fullmatch(_clean(evidence["pseudonymization_key_id"])):
        raise NextBehaviorSuccessorContractError("preparation key identity is invalid")
    if evidence["target_contract_id"] != TARGET_CONTRACT_ID:
        raise NextBehaviorSuccessorContractError("preparation target contract changed")
    if evidence["max_sequence_length"] != 8 or evidence["role_counts"] != ROLE_COUNTS:
        raise NextBehaviorSuccessorContractError("preparation model/role contract changed")
    return document


_ROLE_INVENTORY_BINDINGS = {
    "selected_ingest_receipt_sha256",
    "partition_manifest_sha256",
    "final_preparation_receipt_sha256",
}
_ROLE_INVENTORY_EVIDENCE = {"roles", "intersection_proofs", "test_access"}
_ROLE_ITEM_FIELDS = {
    "source_members",
    "source_member_count",
    "source_member_membership_sha256",
    "session_membership",
    "example_membership",
}
_AVAILABLE_MEMBERSHIP_FIELDS = {"state", "ids", "count", "sha256"}
_SEALED_MEMBERSHIP = {"state": "unavailable_sealed"}


def _available_membership(values: Sequence[Any], path: str) -> Dict[str, Any]:
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        raise NextBehaviorSuccessorContractError(f"{path} must be an ID array")
    ids = [_clean(value) for value in values]
    digest = _membership_sha256(ids)
    return {
        "state": "available",
        "ids": sorted(ids),
        "count": len(ids),
        "sha256": digest,
    }


def _intersection_proof(
    memberships: Mapping[str, Sequence[str]],
    roles: Sequence[str],
) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for left, right in combinations(roles, 2):
        intersection = sorted(set(memberships[left]).intersection(memberships[right]))
        result[f"{left}__{right}"] = {
            "intersection_ids": intersection,
            "intersection_count": len(intersection),
        }
    return result


def build_role_inventory_v2(
    *,
    bindings: Mapping[str, Any],
    partition_manifest: Mapping[str, Any],
    development_session_ids: Mapping[str, Sequence[Any]],
    development_example_ids: Mapping[str, Sequence[Any]],
) -> Dict[str, Any]:
    checked = _require_bindings(bindings, _ROLE_INVENTORY_BINDINGS)
    partition = require_valid_partition_manifest_v3(partition_manifest)
    if checked["partition_manifest_sha256"] != contract_sha256(partition):
        raise NextBehaviorSuccessorContractError(
            "role inventory partition binding mismatch"
        )
    if set(development_session_ids) != set(DEVELOPMENT_ROLES) or set(
        development_example_ids
    ) != set(DEVELOPMENT_ROLES):
        raise NextBehaviorSuccessorContractError(
            "role inventory requires exact development role memberships"
        )
    roles: Dict[str, Dict[str, Any]] = {}
    source_memberships: Dict[str, Sequence[str]] = {}
    session_memberships: Dict[str, Sequence[str]] = {}
    example_memberships: Dict[str, Sequence[str]] = {}
    for role in ROLE_ORDER:
        source_members = list(
            partition["evidence"]["roles"][role]["ordered_source_members"]
        )
        source_memberships[role] = source_members
        if role == "test":
            sessions = dict(_SEALED_MEMBERSHIP)
            examples = dict(_SEALED_MEMBERSHIP)
        else:
            sessions = _available_membership(
                development_session_ids[role], f"development_session_ids.{role}"
            )
            examples = _available_membership(
                development_example_ids[role], f"development_example_ids.{role}"
            )
            session_memberships[role] = sessions["ids"]
            example_memberships[role] = examples["ids"]
        roles[role] = {
            "source_members": source_members,
            "source_member_count": len(source_members),
            "source_member_membership_sha256": _membership_sha256(source_members),
            "session_membership": sessions,
            "example_membership": examples,
        }
    intersection_proofs = {
        "source_members": _intersection_proof(source_memberships, ROLE_ORDER),
        "development_sessions": _intersection_proof(
            session_memberships, DEVELOPMENT_ROLES
        ),
        "development_examples": _intersection_proof(
            example_memberships, DEVELOPMENT_ROLES
        ),
    }
    if any(
        proof["intersection_count"]
        for dimension in intersection_proofs.values()
        for proof in dimension.values()
    ):
        raise NextBehaviorSuccessorContractError(
            "role inventory membership intersects"
        )
    evidence = {
        "roles": roles,
        "intersection_proofs": intersection_proofs,
        "test_access": "sealed_not_opened",
    }
    return require_valid_role_inventory_v2(
        _build_document(
            schema_version=ROLE_INVENTORY_SCHEMA_VERSION,
            id_field="inventory_id",
            id_prefix="nextbehaviorroleinventory",
            status="role_inventory_frozen",
            bindings=checked,
            evidence=evidence,
        ),
        partition_manifest=partition,
        expected_bindings=checked,
    )


def require_valid_role_inventory_v2(
    value: Any,
    *,
    partition_manifest: Mapping[str, Any],
    expected_bindings: Mapping[str, Any] | None = None,
) -> Dict[str, Any]:
    partition = require_valid_partition_manifest_v3(partition_manifest)
    document, bindings, evidence = _require_document(
        value,
        schema_version=ROLE_INVENTORY_SCHEMA_VERSION,
        id_field="inventory_id",
        id_prefix="nextbehaviorroleinventory",
        status="role_inventory_frozen",
        binding_keys=_ROLE_INVENTORY_BINDINGS,
        evidence_keys=_ROLE_INVENTORY_EVIDENCE,
        expected_bindings=expected_bindings,
    )
    if bindings["partition_manifest_sha256"] != contract_sha256(partition):
        raise NextBehaviorSuccessorContractError(
            "role inventory partition binding mismatch"
        )
    roles = _require_exact_keys(evidence["roles"], set(ROLE_ORDER), "evidence.roles")
    source_memberships: Dict[str, Sequence[str]] = {}
    development_sessions: Dict[str, Sequence[str]] = {}
    development_examples: Dict[str, Sequence[str]] = {}
    for role in ROLE_ORDER:
        item = _require_exact_keys(roles[role], _ROLE_ITEM_FIELDS, f"roles.{role}")
        members = item["source_members"]
        if not isinstance(members, list):
            raise NextBehaviorSuccessorContractError(
                f"{role} source members must be an array"
            )
        expected_members = partition["evidence"]["roles"][role][
            "ordered_source_members"
        ]
        if members != expected_members:
            raise NextBehaviorSuccessorContractError(
                f"{role} source membership differs from the frozen partition"
            )
        if item["source_member_count"] != ROLE_COUNTS[role] or item[
            "source_member_count"
        ] != len(members):
            raise NextBehaviorSuccessorContractError(f"{role} source member count changed")
        if item["source_member_membership_sha256"] != _membership_sha256(members):
            raise NextBehaviorSuccessorContractError(
                f"{role} source membership hash mismatch"
            )
        source_memberships[role] = members
        for field, target in (
            ("session_membership", development_sessions),
            ("example_membership", development_examples),
        ):
            membership = item[field]
            if role == "test":
                if membership != _SEALED_MEMBERSHIP:
                    raise NextBehaviorSuccessorContractError(
                        "test session/example membership must remain unavailable_sealed"
                    )
                continue
            record = _require_exact_keys(
                membership,
                _AVAILABLE_MEMBERSHIP_FIELDS,
                f"roles.{role}.{field}",
            )
            if record["state"] != "available" or not isinstance(record["ids"], list):
                raise NextBehaviorSuccessorContractError(
                    f"roles.{role}.{field} state is invalid"
                )
            expected_record = _available_membership(
                record["ids"], f"roles.{role}.{field}.ids"
            )
            if dict(record) != expected_record:
                raise NextBehaviorSuccessorContractError(
                    f"roles.{role}.{field} count/hash mismatch"
                )
            target[role] = record["ids"]
    expected_proofs = {
        "source_members": _intersection_proof(source_memberships, ROLE_ORDER),
        "development_sessions": _intersection_proof(
            development_sessions, DEVELOPMENT_ROLES
        ),
        "development_examples": _intersection_proof(
            development_examples, DEVELOPMENT_ROLES
        ),
    }
    if evidence["intersection_proofs"] != expected_proofs:
        raise NextBehaviorSuccessorContractError(
            "role inventory intersection proofs do not match exact memberships"
        )
    if any(
        proof["intersection_count"]
        for dimension in expected_proofs.values()
        for proof in dimension.values()
    ):
        raise NextBehaviorSuccessorContractError("role inventory membership intersects")
    if evidence["test_access"] != "sealed_not_opened":
        raise NextBehaviorSuccessorContractError("role inventory opened test data")
    return document


build_support_preflight_v1 = build_support_preflight_receipt


def require_valid_support_preflight_v1(value: Any) -> Dict[str, Any]:
    """Delegate to the single canonical support-preflight implementation."""

    try:
        return require_valid_support_preflight_receipt(value)
    except SupportPreflightError as exc:
        raise NextBehaviorSuccessorContractError(str(exc)) from exc


_GATE_BINDINGS = {
    "support_preflight_sha256",
    "requirements_sha256",
    "requirements_policy_sha256",
}
_GATE_EVIDENCE = {
    "requirements",
    "requirements_frozen_before_content_inspection",
    "checks",
    "failed_checks",
    "decision",
    "test_metrics_used",
}
_REQUIREMENT_FIELDS = {
    "role",
    "support_kind",
    "label",
    "minimum_targets",
    "minimum_distinct_sessions",
}
_BASELINE_REQUIREMENTS = {
    ("train", "tactic", "execution"),
    ("train", "tactic", "discovery"),
    ("selection", "tactic", "execution"),
    ("selection", "terminal", "session_end"),
    ("calibration", "terminal", "session_end"),
    ("calibration", "nonterminal", "any"),
}


def _measure_requirement(preflight: Mapping[str, Any], requirement: Mapping[str, Any]) -> tuple[int, int]:
    role = requirement["role"]
    support = preflight["roles"][role]
    kind = requirement["support_kind"]
    label = requirement["label"]
    if kind == "tactic":
        return (
            support["target_tactics"].get(label, 0),
            support["distinct_session_support"]["by_tactic"].get(label, 0),
        )
    if kind == "technique":
        return (
            support["target_techniques"].get(label, 0),
            support["distinct_session_support"]["by_technique"].get(label, 0),
        )
    if kind == "terminal" and label == "session_end":
        return support["terminal_targets"], support["distinct_session_support"]["terminal"]
    if kind == "nonterminal" and label == "any":
        return (
            support["nonterminal_targets"],
            support["distinct_session_support"]["nonterminal"],
        )
    raise NextBehaviorSuccessorContractError("support-gate requirement kind/label is invalid")


def _normalize_requirements(requirements: Sequence[Mapping[str, Any]]) -> list[Dict[str, Any]]:
    if not isinstance(requirements, Sequence) or isinstance(requirements, (str, bytes)):
        raise NextBehaviorSuccessorContractError("support requirements must be an array")
    output: list[Dict[str, Any]] = []
    identities: set[tuple[str, str, str]] = set()
    for index, value in enumerate(requirements):
        item = _require_exact_keys(value, _REQUIREMENT_FIELDS, f"requirements[{index}]")
        role = _clean(item["role"])
        kind = _clean(item["support_kind"])
        label = _clean(item["label"])
        if role not in DEVELOPMENT_ROLES or not label:
            raise NextBehaviorSuccessorContractError("support requirement role/label is invalid")
        if kind not in {"tactic", "technique", "terminal", "nonterminal"}:
            raise NextBehaviorSuccessorContractError("support requirement kind is invalid")
        identity = (role, kind, label)
        if identity in identities:
            raise NextBehaviorSuccessorContractError("support requirements must be unique")
        identities.add(identity)
        output.append(
            {
                "role": role,
                "support_kind": kind,
                "label": label,
                "minimum_targets": _require_positive_int(
                    item["minimum_targets"], f"requirements[{index}].minimum_targets"
                ),
                "minimum_distinct_sessions": _require_positive_int(
                    item["minimum_distinct_sessions"],
                    f"requirements[{index}].minimum_distinct_sessions",
                ),
            }
        )
    if not output:
        raise NextBehaviorSuccessorContractError("at least one support requirement is required")
    by_identity = {
        (item["role"], item["support_kind"], item["label"]): item
        for item in output
    }
    missing = sorted(_BASELINE_REQUIREMENTS - set(by_identity))
    if missing:
        raise NextBehaviorSuccessorContractError(
            "support requirements omit reviewed baseline gates: "
            + ", ".join(":".join(item) for item in missing)
        )
    for identity in _BASELINE_REQUIREMENTS:
        item = by_identity[identity]
        if item["minimum_targets"] < 30 or item["minimum_distinct_sessions"] < 30:
            raise NextBehaviorSuccessorContractError(
                "reviewed baseline support gates cannot be weakened below 30/30"
            )
    return output


def build_selection_support_gate_v1(
    *,
    preflight: Mapping[str, Any],
    requirements: Sequence[Mapping[str, Any]],
    requirements_policy_sha256: str,
    requirements_frozen_before_content_inspection: bool,
) -> Dict[str, Any]:
    checked_preflight = require_valid_support_preflight_v1(preflight)
    if requirements_frozen_before_content_inspection is not True:
        raise NextBehaviorSuccessorContractError(
            "support requirements must be frozen before content inspection"
        )
    normalized = _normalize_requirements(requirements)
    checks: list[Dict[str, Any]] = []
    for item in normalized:
        targets, sessions = _measure_requirement(checked_preflight, item)
        checks.append(
            {
                **item,
                "observed_targets": targets,
                "observed_distinct_sessions": sessions,
                "passed": (
                    targets >= item["minimum_targets"]
                    and sessions >= item["minimum_distinct_sessions"]
                ),
            }
        )
    failed = [
        f"{item['role']}:{item['support_kind']}:{item['label']}"
        for item in checks
        if not item["passed"]
    ]
    bindings = {
        "support_preflight_sha256": contract_sha256(checked_preflight),
        "requirements_sha256": hashlib.sha256(
            stable_json(normalized).encode("utf-8")
        ).hexdigest(),
        "requirements_policy_sha256": _require_sha256(
            requirements_policy_sha256, "requirements_policy_sha256"
        ),
    }
    evidence = {
        "requirements": normalized,
        "requirements_frozen_before_content_inspection": True,
        "checks": checks,
        "failed_checks": failed,
        "decision": "GO" if not failed else "NO_GO",
        "test_metrics_used": False,
    }
    return require_valid_selection_support_gate_v1(
        _build_document(
            schema_version=SUPPORT_GATE_SCHEMA_VERSION,
            id_field="gate_id",
            id_prefix="nextbehaviorselectionsupportgate",
            status="support_gate_evaluated",
            bindings=bindings,
            evidence=evidence,
        ),
        preflight=checked_preflight,
    )


def require_valid_selection_support_gate_v1(
    value: Any,
    *,
    preflight: Mapping[str, Any] | None = None,
) -> Dict[str, Any]:
    expected = None
    checked_preflight = None
    if preflight is not None:
        checked_preflight = require_valid_support_preflight_v1(preflight)
    document, bindings, evidence = _require_document(
        value,
        schema_version=SUPPORT_GATE_SCHEMA_VERSION,
        id_field="gate_id",
        id_prefix="nextbehaviorselectionsupportgate",
        status="support_gate_evaluated",
        binding_keys=_GATE_BINDINGS,
        evidence_keys=_GATE_EVIDENCE,
        expected_bindings=expected,
    )
    requirements = _normalize_requirements(evidence["requirements"])
    requirements_hash = hashlib.sha256(stable_json(requirements).encode("utf-8")).hexdigest()
    if bindings["requirements_sha256"] != requirements_hash:
        raise NextBehaviorSuccessorContractError("support requirements hash mismatch")
    if evidence["requirements_frozen_before_content_inspection"] is not True:
        raise NextBehaviorSuccessorContractError("support requirements were not pre-frozen")
    if evidence["test_metrics_used"] is not False:
        raise NextBehaviorSuccessorContractError("test metrics influenced the support gate")
    checks = evidence["checks"]
    if not isinstance(checks, list) or len(checks) != len(requirements):
        raise NextBehaviorSuccessorContractError("support gate check count is invalid")
    if checked_preflight is not None:
        if bindings["support_preflight_sha256"] != contract_sha256(checked_preflight):
            raise NextBehaviorSuccessorContractError("support preflight binding mismatch")
        expected_checks: list[Dict[str, Any]] = []
        for item in requirements:
            targets, sessions = _measure_requirement(checked_preflight, item)
            expected_checks.append(
                {
                    **item,
                    "observed_targets": targets,
                    "observed_distinct_sessions": sessions,
                    "passed": targets >= item["minimum_targets"]
                    and sessions >= item["minimum_distinct_sessions"],
                }
            )
        if checks != expected_checks:
            raise NextBehaviorSuccessorContractError("support gate observations mismatch")
    else:
        expected_checks = []
        for index, check in enumerate(checks):
            expected_fields = _REQUIREMENT_FIELDS | {
                "observed_targets",
                "observed_distinct_sessions",
                "passed",
            }
            item = _require_exact_keys(check, expected_fields, f"checks[{index}]")
            req = {key: item[key] for key in _REQUIREMENT_FIELDS}
            if req != requirements[index]:
                raise NextBehaviorSuccessorContractError("support gate requirement/check mismatch")
            targets = _require_nonnegative_int(item["observed_targets"], "observed_targets")
            sessions = _require_nonnegative_int(item["observed_distinct_sessions"], "observed_distinct_sessions")
            passed = targets >= req["minimum_targets"] and sessions >= req["minimum_distinct_sessions"]
            if item["passed"] is not passed:
                raise NextBehaviorSuccessorContractError("support gate pass result mismatch")
            expected_checks.append(dict(item))
    failed = [
        f"{item['role']}:{item['support_kind']}:{item['label']}"
        for item in expected_checks
        if not item["passed"]
    ]
    if evidence["failed_checks"] != failed:
        raise NextBehaviorSuccessorContractError("support gate failures mismatch")
    if evidence["decision"] != ("GO" if not failed else "NO_GO"):
        raise NextBehaviorSuccessorContractError("support gate decision mismatch")
    return document


_SAFE_BUILD_BINDINGS = {
    "selected_store_sha256",
    "selected_ingest_receipt_sha256",
    "final_preparation_receipt_sha256",
    "role_inventory_sha256",
    "partition_manifest_sha256",
    "reviewed_safe_build_receipt_sha256",
}
_SAFE_BUILD_EVIDENCE = {
    "purpose",
    "authorized_role",
    "reviewed_safe_build_receipt_id",
    "safe_sessions_artifact",
    "examples_artifact",
    "membership",
    "privacy_validation",
}
_PURPOSE_ROLE = {
    "fit_model": "train",
    "select_model": "selection",
    "fit_calibration": "calibration",
    "final_evaluation": "test",
}


def _artifact_receipt(records: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    payload = b"".join(
        (stable_json(dict(record)) + "\n").encode("utf-8") for record in records
    )
    return {
        "line_count": len(records),
        "size_bytes": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }


def _validate_reviewed_safe_artifacts(
    reviewed_receipt: Mapping[str, Any],
    *,
    purpose: str,
    safe_sessions: Sequence[Mapping[str, Any]],
    examples: Sequence[Mapping[str, Any]],
) -> Dict[str, Any]:
    if not isinstance(reviewed_receipt, Mapping):
        raise NextBehaviorSuccessorContractError(
            "reviewed safe-build receipt must be an object"
        )
    receipt = dict(reviewed_receipt)
    role = _PURPOSE_ROLE[purpose]
    if (
        receipt.get("schema_version") != REVIEWED_SAFE_BUILD_SCHEMA_VERSION
        or receipt.get("status") != "role_safe_corpus_built"
        or receipt.get("purpose") != purpose
        or receipt.get("role") != role
        or receipt.get("source_cohort")
        != ("final" if role == "test" else "development")
        or receipt.get("max_sequence_length") != 8
        or receipt.get("raw_content_emitted") is not False
    ):
        raise NextBehaviorSuccessorContractError(
            "reviewed safe-build receipt purpose or safety state is invalid"
        )
    receipt_basis = dict(receipt)
    receipt_id = receipt_basis.pop("build_receipt_id", None)
    if receipt_id != stable_id("nextbehaviorselectedsafebuild", receipt_basis):
        raise NextBehaviorSuccessorContractError(
            "reviewed safe-build receipt identity mismatch"
        )
    if isinstance(safe_sessions, (str, bytes)) or not isinstance(
        safe_sessions, Sequence
    ):
        raise NextBehaviorSuccessorContractError("safe sessions must be an array")
    if isinstance(examples, (str, bytes)) or not isinstance(examples, Sequence):
        raise NextBehaviorSuccessorContractError("examples must be an array")
    checked_sessions: list[Dict[str, Any]] = []
    expected_examples: list[Dict[str, Any]] = []
    try:
        for raw in safe_sessions:
            session = require_valid_next_behavior_session(raw)
            _scan_public_value(session)
            checked_sessions.append(session)
            expected_examples.extend(
                build_next_behavior_examples(session, max_sequence_length=8)
            )
        checked_examples = [dict(value) for value in examples]
        for value in checked_examples:
            _scan_public_value(value)
    except (NextBehaviorContractError, SelectedSafeCorpusError, ValueError) as exc:
        raise NextBehaviorSuccessorContractError(
            "actual safe artifact failed reviewed privacy/schema validation"
        ) from exc
    if checked_examples != expected_examples:
        raise NextBehaviorSuccessorContractError(
            "actual examples differ from deterministic session reconstruction"
        )
    session_ids = [_clean(item["session_id"]) for item in checked_sessions]
    example_ids = [_clean(item["example_id"]) for item in checked_examples]
    source_member_ids = sorted(
        {_clean(item["source_member_id"]) for item in checked_sessions}
    )
    input_hashes = [
        _clean(item["model_input"]["input_hash"]) for item in checked_examples
    ]
    for values, label in (
        (session_ids, "safe session"),
        (example_ids, "safe example"),
    ):
        if len(values) != len(set(values)):
            raise NextBehaviorSuccessorContractError(
                f"actual {label} membership is duplicated"
            )
    actual_membership = {
        "source_member_count": len(source_member_ids),
        "source_member_membership_sha256": _membership_sha256(source_member_ids),
        "session_count": len(session_ids),
        "session_membership_sha256": _membership_sha256(session_ids),
        "example_count": len(example_ids),
        "example_membership_sha256": _membership_sha256(example_ids),
        "input_count": len(input_hashes),
        "input_membership_sha256": _membership_sha256(input_hashes),
    }
    if receipt.get("membership") != actual_membership:
        raise NextBehaviorSuccessorContractError(
            "reviewed safe-build membership differs from actual artifacts"
        )
    if receipt.get("safe_sessions") != _artifact_receipt(checked_sessions):
        raise NextBehaviorSuccessorContractError(
            "reviewed safe-build session artifact hash mismatch"
        )
    if receipt.get("examples") != _artifact_receipt(checked_examples):
        raise NextBehaviorSuccessorContractError(
            "reviewed safe-build example artifact hash mismatch"
        )
    return receipt


def build_selected_safe_build_v4(
    *,
    bindings: Mapping[str, Any],
    purpose: str,
    reviewed_safe_build_receipt: Mapping[str, Any],
    safe_sessions: Sequence[Mapping[str, Any]],
    examples: Sequence[Mapping[str, Any]],
    role_inventory: Mapping[str, Any],
    partition_manifest: Mapping[str, Any],
) -> Dict[str, Any]:
    checked = _require_bindings(bindings, _SAFE_BUILD_BINDINGS)
    clean_purpose = _clean(purpose)
    if clean_purpose not in _PURPOSE_ROLE:
        raise NextBehaviorSuccessorContractError("safe-build purpose is invalid")
    role = _PURPOSE_ROLE[clean_purpose]
    if role == "test":
        raise NextBehaviorSuccessorContractError(
            "test safe-build evidence requires a later final-evaluation contract"
        )
    partition = require_valid_partition_manifest_v3(partition_manifest)
    inventory = require_valid_role_inventory_v2(
        role_inventory,
        partition_manifest=partition,
    )
    if checked["partition_manifest_sha256"] != contract_sha256(partition):
        raise NextBehaviorSuccessorContractError("safe-build partition binding mismatch")
    if checked["role_inventory_sha256"] != contract_sha256(inventory):
        raise NextBehaviorSuccessorContractError("safe-build role inventory binding mismatch")
    receipt = _validate_reviewed_safe_artifacts(
        reviewed_safe_build_receipt,
        purpose=clean_purpose,
        safe_sessions=safe_sessions,
        examples=examples,
    )
    if checked["reviewed_safe_build_receipt_sha256"] != contract_sha256(receipt):
        raise NextBehaviorSuccessorContractError(
            "safe-build reviewed receipt binding mismatch"
        )
    expected_sessions = inventory["evidence"]["roles"][role]["session_membership"]
    expected_examples = inventory["evidence"]["roles"][role]["example_membership"]
    if (
        receipt["membership"]["session_count"] != expected_sessions["count"]
        or receipt["membership"]["session_membership_sha256"]
        != expected_sessions["sha256"]
        or receipt["membership"]["example_count"] != expected_examples["count"]
        or receipt["membership"]["example_membership_sha256"]
        != expected_examples["sha256"]
    ):
        raise NextBehaviorSuccessorContractError(
            "safe-build payload differs from its authorized role membership"
        )
    evidence = {
        "purpose": clean_purpose,
        "authorized_role": role,
        "reviewed_safe_build_receipt_id": receipt["build_receipt_id"],
        "safe_sessions_artifact": dict(receipt["safe_sessions"]),
        "examples_artifact": dict(receipt["examples"]),
        "membership": dict(receipt["membership"]),
        "privacy_validation": "recomputed_from_actual_artifacts",
    }
    return require_valid_selected_safe_build_v4(
        _build_document(
            schema_version=SAFE_BUILD_SCHEMA_VERSION,
            id_field="receipt_id",
            id_prefix="nextbehaviorselectedsafebuild",
            status="safe_role_artifact_built",
            bindings=checked,
            evidence=evidence,
        ),
        reviewed_safe_build_receipt=receipt,
        safe_sessions=safe_sessions,
        examples=examples,
        role_inventory=inventory,
        partition_manifest=partition,
        expected_bindings=checked,
    )


def require_valid_selected_safe_build_v4(
    value: Any,
    *,
    reviewed_safe_build_receipt: Mapping[str, Any],
    safe_sessions: Sequence[Mapping[str, Any]],
    examples: Sequence[Mapping[str, Any]],
    role_inventory: Mapping[str, Any],
    partition_manifest: Mapping[str, Any],
    expected_bindings: Mapping[str, Any] | None = None,
) -> Dict[str, Any]:
    partition = require_valid_partition_manifest_v3(partition_manifest)
    inventory = require_valid_role_inventory_v2(
        role_inventory,
        partition_manifest=partition,
    )
    document, bindings, evidence = _require_document(
        value,
        schema_version=SAFE_BUILD_SCHEMA_VERSION,
        id_field="receipt_id",
        id_prefix="nextbehaviorselectedsafebuild",
        status="safe_role_artifact_built",
        binding_keys=_SAFE_BUILD_BINDINGS,
        evidence_keys=_SAFE_BUILD_EVIDENCE,
        expected_bindings=expected_bindings,
    )
    purpose = evidence["purpose"]
    if purpose not in _PURPOSE_ROLE or evidence["authorized_role"] != _PURPOSE_ROLE[purpose]:
        raise NextBehaviorSuccessorContractError("safe-build purpose/role mismatch")
    if purpose == "final_evaluation":
        raise NextBehaviorSuccessorContractError(
            "test safe-build evidence requires a later final-evaluation contract"
        )
    if bindings["partition_manifest_sha256"] != contract_sha256(partition):
        raise NextBehaviorSuccessorContractError("safe-build partition binding mismatch")
    if bindings["role_inventory_sha256"] != contract_sha256(inventory):
        raise NextBehaviorSuccessorContractError("safe-build role inventory binding mismatch")
    receipt = _validate_reviewed_safe_artifacts(
        reviewed_safe_build_receipt,
        purpose=purpose,
        safe_sessions=safe_sessions,
        examples=examples,
    )
    if bindings["reviewed_safe_build_receipt_sha256"] != contract_sha256(receipt):
        raise NextBehaviorSuccessorContractError("safe-build reviewed receipt binding mismatch")
    role = evidence["authorized_role"]
    expected_sessions = inventory["evidence"]["roles"][role]["session_membership"]
    expected_examples = inventory["evidence"]["roles"][role]["example_membership"]
    if evidence != {
        "purpose": purpose,
        "authorized_role": role,
        "reviewed_safe_build_receipt_id": receipt["build_receipt_id"],
        "safe_sessions_artifact": dict(receipt["safe_sessions"]),
        "examples_artifact": dict(receipt["examples"]),
        "membership": dict(receipt["membership"]),
        "privacy_validation": "recomputed_from_actual_artifacts",
    }:
        raise NextBehaviorSuccessorContractError("safe-build evidence mismatch")
    if (
        receipt["membership"]["session_count"] != expected_sessions["count"]
        or receipt["membership"]["session_membership_sha256"]
        != expected_sessions["sha256"]
        or receipt["membership"]["example_count"] != expected_examples["count"]
        or receipt["membership"]["example_membership_sha256"]
        != expected_examples["sha256"]
    ):
        raise NextBehaviorSuccessorContractError(
            "safe-build payload differs from its authorized role membership"
        )
    return document


_EXPERIMENT_BINDING_KEYS = {
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
_EXPERIMENT_BINDINGS_EVIDENCE = {
    "target_contract_id",
    "max_sequence_length",
    "partition_protocol",
    "test_access",
    "model_checkpoint_decision_made",
}


def build_experiment_bindings_v3(*, bindings: Mapping[str, Any]) -> Dict[str, Any]:
    checked = _require_bindings(bindings, _EXPERIMENT_BINDING_KEYS)
    evidence = {
        "target_contract_id": TARGET_CONTRACT_ID,
        "max_sequence_length": 8,
        "partition_protocol": PARTITION_PROTOCOL,
        "test_access": "sealed_until_one_final_evaluation",
        "model_checkpoint_decision_made": False,
    }
    return require_valid_experiment_bindings_v3(
        _build_document(
            schema_version=EXPERIMENT_BINDINGS_SCHEMA_VERSION,
            id_field="bindings_id",
            id_prefix="nextbehaviorexperimentbindings",
            status="successor_inputs_bound",
            bindings=checked,
            evidence=evidence,
        )
    )


def require_valid_experiment_bindings_v3(
    value: Any, *, expected_bindings: Mapping[str, Any] | None = None
) -> Dict[str, Any]:
    document, _, evidence = _require_document(
        value,
        schema_version=EXPERIMENT_BINDINGS_SCHEMA_VERSION,
        id_field="bindings_id",
        id_prefix="nextbehaviorexperimentbindings",
        status="successor_inputs_bound",
        binding_keys=_EXPERIMENT_BINDING_KEYS,
        evidence_keys=_EXPERIMENT_BINDINGS_EVIDENCE,
        expected_bindings=expected_bindings,
    )
    if evidence != {
        "target_contract_id": TARGET_CONTRACT_ID,
        "max_sequence_length": 8,
        "partition_protocol": PARTITION_PROTOCOL,
        "test_access": "sealed_until_one_final_evaluation",
        "model_checkpoint_decision_made": False,
    }:
        raise NextBehaviorSuccessorContractError("experiment binding semantics changed")
    return document


_EXPERIMENT_MANIFEST_BINDINGS = {
    "experiment_bindings_sha256",
    "selection_support_gate_sha256",
    "train_safe_build_sha256",
    "selection_safe_build_sha256",
    "calibration_safe_build_sha256",
}
_EXPERIMENT_MANIFEST_EVIDENCE = {
    "role_counts",
    "support_preflight_status",
    "selection_gate_decision",
    "test_safe_build_present",
    "test_metrics_used",
    "ready_for_model_gate",
}


def build_experiment_manifest_v3(
    *,
    bindings: Mapping[str, Any],
    experiment_bindings: Mapping[str, Any],
    support_preflight: Mapping[str, Any],
    selection_gate: Mapping[str, Any],
) -> Dict[str, Any]:
    checked = _require_bindings(bindings, _EXPERIMENT_MANIFEST_BINDINGS)
    checked_experiment_bindings = require_valid_experiment_bindings_v3(
        experiment_bindings
    )
    checked_preflight = require_valid_support_preflight_v1(support_preflight)
    checked_gate = require_valid_selection_support_gate_v1(
        selection_gate,
        preflight=checked_preflight,
    )
    if checked["experiment_bindings_sha256"] != contract_sha256(
        checked_experiment_bindings
    ):
        raise NextBehaviorSuccessorContractError(
            "experiment manifest bindings artifact mismatch"
        )
    if checked["selection_support_gate_sha256"] != contract_sha256(checked_gate):
        raise NextBehaviorSuccessorContractError(
            "experiment manifest support-gate binding mismatch"
        )
    preflight_passed = (
        checked_preflight["status"] == "support_gate_passed"
        and checked_preflight["gate"]["passed"] is True
    )
    decision = (
        "GO"
        if preflight_passed and checked_gate["evidence"]["decision"] == "GO"
        else "NO_GO"
    )
    evidence = {
        "role_counts": dict(ROLE_COUNTS),
        "support_preflight_status": checked_preflight["status"],
        "selection_gate_decision": decision,
        "test_safe_build_present": False,
        "test_metrics_used": False,
        "ready_for_model_gate": decision == "GO",
    }
    return require_valid_experiment_manifest_v3(
        _build_document(
            schema_version=EXPERIMENT_MANIFEST_SCHEMA_VERSION,
            id_field="manifest_id",
            id_prefix="nextbehaviorexperimentmanifest",
            status="successor_experiment_declared",
            bindings=checked,
            evidence=evidence,
        ),
        experiment_bindings=checked_experiment_bindings,
        support_preflight=checked_preflight,
        selection_gate=checked_gate,
        expected_bindings=checked,
    )


def require_valid_experiment_manifest_v3(
    value: Any,
    *,
    experiment_bindings: Mapping[str, Any],
    support_preflight: Mapping[str, Any],
    selection_gate: Mapping[str, Any],
    expected_bindings: Mapping[str, Any] | None = None,
) -> Dict[str, Any]:
    checked_experiment_bindings = require_valid_experiment_bindings_v3(
        experiment_bindings
    )
    checked_preflight = require_valid_support_preflight_v1(support_preflight)
    checked_gate = require_valid_selection_support_gate_v1(
        selection_gate,
        preflight=checked_preflight,
    )
    document, bindings, evidence = _require_document(
        value,
        schema_version=EXPERIMENT_MANIFEST_SCHEMA_VERSION,
        id_field="manifest_id",
        id_prefix="nextbehaviorexperimentmanifest",
        status="successor_experiment_declared",
        binding_keys=_EXPERIMENT_MANIFEST_BINDINGS,
        evidence_keys=_EXPERIMENT_MANIFEST_EVIDENCE,
        expected_bindings=expected_bindings,
    )
    if bindings["experiment_bindings_sha256"] != contract_sha256(
        checked_experiment_bindings
    ):
        raise NextBehaviorSuccessorContractError(
            "experiment manifest bindings artifact mismatch"
        )
    if bindings["selection_support_gate_sha256"] != contract_sha256(checked_gate):
        raise NextBehaviorSuccessorContractError(
            "experiment manifest support-gate binding mismatch"
        )
    preflight_passed = (
        checked_preflight["status"] == "support_gate_passed"
        and checked_preflight["gate"]["passed"] is True
    )
    decision = (
        "GO"
        if preflight_passed and checked_gate["evidence"]["decision"] == "GO"
        else "NO_GO"
    )
    if (
        evidence["support_preflight_status"] != checked_preflight["status"]
        or evidence["selection_gate_decision"] != decision
        or evidence["ready_for_model_gate"] is not (decision == "GO")
    ):
        raise NextBehaviorSuccessorContractError("experiment gate readiness mismatch")
    if evidence["role_counts"] != ROLE_COUNTS:
        raise NextBehaviorSuccessorContractError("experiment role counts changed")
    if evidence["test_safe_build_present"] is not False or evidence[
        "test_metrics_used"
    ] is not False:
        raise NextBehaviorSuccessorContractError("experiment opened sealed test evidence")
    return document


_FREEZE_BASE_BINDINGS = {
    "source_selection_sha256",
    "successor_member_inventory_sha256",
    "partition_manifest_sha256",
    "final_preparation_receipt_sha256",
    "code_commit",
}
_FREEZE_BINDINGS = _FREEZE_BASE_BINDINGS | {
    "reference_freeze_sha256",
    "reference_tuple_sha256",
    "current_tuple_sha256",
}
_REFERENCE_TUPLE_FIELDS = {
    "classification_policy_sha256",
    "classifier_source_identity_sha256",
    "maximum_trusted_phases",
    "mitre_cache_sha256",
    "preprocessing_contract_sha256",
    "sequence_length",
    "target_contract_id",
    "trust_policy_sha256",
    "trusted_history_schema_version",
}
_FREEZE_EVIDENCE = {
    "reference_freeze_schema_version",
    "reference_tuple",
    "current_tuple",
    "tuples_equal",
    "reference_tuple_redefined",
    "all_semantic_inputs_verified",
    "test_members_accessed",
}


def _require_semantic_tuple(value: Any, path: str) -> Dict[str, Any]:
    item = _require_exact_keys(value, _REFERENCE_TUPLE_FIELDS, path)
    for field in (
        "classification_policy_sha256",
        "classifier_source_identity_sha256",
        "mitre_cache_sha256",
        "preprocessing_contract_sha256",
        "trust_policy_sha256",
    ):
        _require_sha256(item[field], f"{path}.{field}")
    if (
        item["maximum_trusted_phases"] != 8
        or item["sequence_length"] != 8
        or item["target_contract_id"] != TARGET_CONTRACT_ID
        or item["trusted_history_schema_version"]
        != "prediction_trusted_history_manifest.v3"
    ):
        raise NextBehaviorSuccessorContractError(
            f"{path} target/history semantics are incompatible"
        )
    return dict(item)


def _reference_tuple(prior_freeze: Any) -> tuple[str, Dict[str, Any]]:
    if not isinstance(prior_freeze, Mapping):
        raise NextBehaviorSuccessorContractError(
            "prior deterministic freeze must be an object"
        )
    if (
        prior_freeze.get("schema_version")
        != "next_behavior_deterministic_semantics_freeze_evidence.v1"
        or prior_freeze.get("status") != "deterministic_semantics_frozen"
    ):
        raise NextBehaviorSuccessorContractError(
            "prior deterministic freeze schema/status is invalid"
        )
    return (
        str(prior_freeze["schema_version"]),
        _require_semantic_tuple(prior_freeze.get("frozen_semantics"), "prior_freeze.frozen_semantics"),
    )


def build_deterministic_semantics_freeze_evidence_v2(
    *,
    bindings: Mapping[str, Any],
    prior_freeze: Mapping[str, Any],
    current_semantic_tuple: Mapping[str, Any],
) -> Dict[str, Any]:
    checked_base = _require_bindings(bindings, _FREEZE_BASE_BINDINGS)
    reference_schema, reference_tuple = _reference_tuple(prior_freeze)
    current_tuple = _require_semantic_tuple(
        current_semantic_tuple, "current_semantic_tuple"
    )
    if reference_tuple != current_tuple:
        raise NextBehaviorSuccessorContractError(
            "current deterministic semantic tuple differs from the frozen reference"
        )
    checked = {
        **checked_base,
        "reference_freeze_sha256": contract_sha256(dict(prior_freeze)),
        "reference_tuple_sha256": contract_sha256(reference_tuple),
        "current_tuple_sha256": contract_sha256(current_tuple),
    }
    evidence = {
        "reference_freeze_schema_version": reference_schema,
        "reference_tuple": reference_tuple,
        "current_tuple": current_tuple,
        "tuples_equal": True,
        "reference_tuple_redefined": False,
        "all_semantic_inputs_verified": True,
        "test_members_accessed": False,
    }
    return require_valid_deterministic_semantics_freeze_evidence_v2(
        _build_document(
            schema_version=SEMANTICS_FREEZE_SCHEMA_VERSION,
            id_field="evidence_id",
            id_prefix="nextbehaviorsemanticsfreeze",
            status="deterministic_semantics_frozen",
            bindings=checked,
            evidence=evidence,
        ),
        prior_freeze=prior_freeze,
        current_semantic_tuple=current_tuple,
        expected_bindings=checked,
    )


def require_valid_deterministic_semantics_freeze_evidence_v2(
    value: Any,
    *,
    prior_freeze: Mapping[str, Any],
    current_semantic_tuple: Mapping[str, Any],
    expected_bindings: Mapping[str, Any] | None = None,
) -> Dict[str, Any]:
    reference_schema, reference_tuple = _reference_tuple(prior_freeze)
    current_tuple = _require_semantic_tuple(
        current_semantic_tuple, "current_semantic_tuple"
    )
    document, bindings, evidence = _require_document(
        value,
        schema_version=SEMANTICS_FREEZE_SCHEMA_VERSION,
        id_field="evidence_id",
        id_prefix="nextbehaviorsemanticsfreeze",
        status="deterministic_semantics_frozen",
        binding_keys=_FREEZE_BINDINGS,
        evidence_keys=_FREEZE_EVIDENCE,
        expected_bindings=expected_bindings,
    )
    expected_hashes = {
        "reference_freeze_sha256": contract_sha256(dict(prior_freeze)),
        "reference_tuple_sha256": contract_sha256(reference_tuple),
        "current_tuple_sha256": contract_sha256(current_tuple),
    }
    if any(bindings[field] != digest for field, digest in expected_hashes.items()):
        raise NextBehaviorSuccessorContractError(
            "successor freeze reference/current binding mismatch"
        )
    if evidence != {
        "reference_freeze_schema_version": reference_schema,
        "reference_tuple": reference_tuple,
        "current_tuple": current_tuple,
        "tuples_equal": reference_tuple == current_tuple,
        "reference_tuple_redefined": reference_tuple != current_tuple,
        "all_semantic_inputs_verified": reference_tuple == current_tuple,
        "test_members_accessed": False,
    }:
        raise NextBehaviorSuccessorContractError(
            "successor freeze equality evidence mismatch"
        )
    if reference_tuple != current_tuple:
        raise NextBehaviorSuccessorContractError(
            "successor freeze redefined deterministic semantics"
        )
    return document


def require_valid_successor_contract(value: Any) -> Dict[str, Any]:
    """Dispatch to the strict validator for any supported successor artifact."""

    if not isinstance(value, Mapping):
        raise NextBehaviorSuccessorContractError("successor contract must be an object")
    contextual_schemas = {
        ROLE_INVENTORY_SCHEMA_VERSION,
        SAFE_BUILD_SCHEMA_VERSION,
        EXPERIMENT_MANIFEST_SCHEMA_VERSION,
        SEMANTICS_FREEZE_SCHEMA_VERSION,
    }
    schema = _clean(value.get("schema_version"))
    if schema in contextual_schemas:
        raise NextBehaviorSuccessorContractError(
            f"{schema} requires its exact upstream artifacts for validation"
        )
    validators: Dict[str, Callable[[Any], Dict[str, Any]]] = {
        PARTITION_SCHEMA_VERSION: require_valid_partition_manifest_v3,
        STORE_SCHEMA_VERSION: require_valid_selected_private_store_metadata_v2,
        INGEST_SCHEMA_VERSION: require_valid_selected_ingest_receipt_v2,
        PREPARATION_SCHEMA_VERSION: require_valid_final_corpus_preparation_v2,
        SUPPORT_PREFLIGHT_SCHEMA_VERSION: require_valid_support_preflight_v1,
        SUPPORT_GATE_SCHEMA_VERSION: require_valid_selection_support_gate_v1,
        EXPERIMENT_BINDINGS_SCHEMA_VERSION: require_valid_experiment_bindings_v3,
    }
    validator = validators.get(schema)
    if validator is None:
        raise NextBehaviorSuccessorContractError(
            f"unsupported successor contract schema: {schema or '<missing>'}"
        )
    return validator(value)
