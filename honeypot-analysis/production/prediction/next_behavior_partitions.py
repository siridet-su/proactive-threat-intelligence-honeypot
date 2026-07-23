"""Partition and membership controls for the final next-behavior experiment.

This module does not create a real split without provenance-complete source
members. It supplies deterministic, fail-closed controls for a future private
corpus build while keeping every accepted historical benchmark unchanged.
"""

from __future__ import annotations

import hashlib
from copy import deepcopy
from typing import Any, Dict, Iterable, List, Mapping, Sequence

from production.prediction.next_behavior_contract import (
    TARGET_CONTRACT_ID,
    NextBehaviorContractError,
    require_valid_next_behavior_session,
)
from production.prediction.next_behavior_preprocessing import (
    build_next_behavior_examples,
)
from production.utils.serialization import stable_id, stable_json

PARTITION_SCHEMA_VERSION = "next_behavior_partition_manifest.v1"
MEMBER_ROLES = ("train", "selection", "calibration", "test")
PURPOSE_TO_ROLE = {
    "fit_model": "train",
    "select_model": "selection",
    "fit_calibration": "calibration",
    "final_evaluation": "test",
}
_SHA_FIELDS = (
    "preprocessing_sha256",
    "label_policy_sha256",
    "trust_policy_sha256",
)


class NextBehaviorPartitionError(ValueError):
    """Raised when experimental membership or role access is unsafe."""


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _is_sha256(value: Any) -> bool:
    text = _clean(value).lower()
    return len(text) == 64 and all(character in "0123456789abcdef" for character in text)


def membership_sha256(values: Iterable[Any]) -> str:
    """Hash a sorted, duplicate-free safe membership list."""

    normalized = sorted({_clean(value) for value in values if _clean(value)})
    return hashlib.sha256(stable_json(normalized).encode("utf-8")).hexdigest()


def assign_seven_member_roles(
    source_members: Sequence[Mapping[str, Any]],
) -> Dict[str, str]:
    """Assign the frozen four/one/one/one chronological seven-member split."""

    if len(source_members) != 7:
        raise NextBehaviorPartitionError(
            "the frozen seven-member protocol requires exactly seven source members"
        )
    member_ids: List[str] = []
    previous_order: int | None = None
    for index, member in enumerate(source_members):
        if not isinstance(member, Mapping):
            raise NextBehaviorPartitionError(
                f"source_members[{index}] must be an object"
            )
        unknown = set(member) - {
            "schema_version",
            "member_id",
            "sha256",
            "byte_size",
            "chronological_order",
            "collection_start",
            "collection_end",
            "pseudonymization_scheme",
            "pseudonymization_key_id",
        }
        if unknown:
            raise NextBehaviorPartitionError(
                f"source_members[{index}] contains undefined fields: "
                f"{', '.join(sorted(unknown))}"
            )
        member_id = _clean(member.get("member_id"))
        if not member_id or member_id in member_ids:
            raise NextBehaviorPartitionError(
                "source member identities must be non-empty and unique"
            )
        if not _is_sha256(member.get("sha256")):
            raise NextBehaviorPartitionError(
                f"source member {member_id} has no valid SHA-256 receipt"
            )
        order = member.get("chronological_order")
        if isinstance(order, bool) or not isinstance(order, int):
            raise NextBehaviorPartitionError(
                f"source member {member_id} chronological_order must be an integer"
            )
        if previous_order is not None and order <= previous_order:
            raise NextBehaviorPartitionError(
                "source members must be supplied in strictly chronological order"
            )
        previous_order = order
        member_ids.append(member_id)
    return {
        **{member_id: "train" for member_id in member_ids[:4]},
        member_ids[4]: "selection",
        member_ids[5]: "calibration",
        member_ids[6]: "test",
    }


def _role_intersections(role_values: Mapping[str, Sequence[str]]) -> Dict[str, Any]:
    pairs: Dict[str, List[str]] = {}
    all_empty = True
    for left_index, left in enumerate(MEMBER_ROLES):
        left_values = set(role_values.get(left) or [])
        for right in MEMBER_ROLES[left_index + 1 :]:
            values = sorted(left_values.intersection(role_values.get(right) or []))
            pairs[f"{left}__{right}"] = values
            if values:
                all_empty = False
    return {"all_empty": all_empty, "pairs": pairs}


def build_partition_manifest(
    session_records: Sequence[Mapping[str, Any]],
    source_members: Sequence[Mapping[str, Any]],
    *,
    preprocessing_sha256: str,
    label_policy_sha256: str,
    trust_policy_sha256: str,
    code_commit: str,
    forbidden_historical_session_ids: Iterable[str] = (),
    max_sequence_length: int = 8,
) -> Dict[str, Any]:
    """Build an auditable manifest without writing or opening any partition."""

    hashes = {
        "preprocessing_sha256": preprocessing_sha256,
        "label_policy_sha256": label_policy_sha256,
        "trust_policy_sha256": trust_policy_sha256,
    }
    for field in _SHA_FIELDS:
        if not _is_sha256(hashes[field]):
            raise NextBehaviorPartitionError(f"{field} must be a SHA-256 digest")
    if not _clean(code_commit):
        raise NextBehaviorPartitionError("code_commit is required")
    if max_sequence_length < 1:
        raise NextBehaviorPartitionError("max_sequence_length must be positive")

    member_roles = assign_seven_member_roles(source_members)
    receipts = {
        _clean(member["member_id"]): _clean(member["sha256"]).lower()
        for member in source_members
    }
    forbidden = {
        _clean(session_id)
        for session_id in forbidden_historical_session_ids
        if _clean(session_id)
    }
    if not forbidden:
        raise NextBehaviorPartitionError(
            "accepted historical session membership is required for exclusion"
        )
    seen_sessions: set[str] = set()
    role_sessions: Dict[str, List[str]] = {role: [] for role in MEMBER_ROLES}
    role_examples: Dict[str, List[str]] = {role: [] for role in MEMBER_ROLES}
    historical_overlap: List[str] = []

    for raw_record in session_records:
        try:
            record = require_valid_next_behavior_session(raw_record)
        except NextBehaviorContractError as exc:
            raise NextBehaviorPartitionError(str(exc)) from exc
        session_id = _clean(record["session_id"])
        if session_id in seen_sessions:
            raise NextBehaviorPartitionError(
                f"session {session_id} occurs more than once"
            )
        seen_sessions.add(session_id)
        if session_id in forbidden:
            historical_overlap.append(session_id)
        member_id = _clean(record["source_member_id"])
        if member_id not in member_roles:
            raise NextBehaviorPartitionError(
                f"session {session_id} references an unassigned source member"
            )
        if _clean(record["source_member_sha256"]).lower() != receipts[member_id]:
            raise NextBehaviorPartitionError(
                f"session {session_id} source receipt does not match its member"
            )
        role = member_roles[member_id]
        examples = build_next_behavior_examples(
            record,
            max_sequence_length=max_sequence_length,
        )
        role_sessions[role].append(session_id)
        role_examples[role].extend(
            _clean(example["example_id"]) for example in examples
        )
    if historical_overlap:
        raise NextBehaviorPartitionError(
            "redesigned membership overlaps the accepted historical corpus: "
            + ", ".join(sorted(historical_overlap))
        )

    session_intersections = _role_intersections(role_sessions)
    example_intersections = _role_intersections(role_examples)
    if not session_intersections["all_empty"] or not example_intersections["all_empty"]:
        raise NextBehaviorPartitionError("partition membership intersects")

    roles: Dict[str, Dict[str, Any]] = {}
    for role in MEMBER_ROLES:
        session_ids = sorted(role_sessions[role])
        example_ids = sorted(role_examples[role])
        if not session_ids or not example_ids:
            raise NextBehaviorPartitionError(
                f"{role} has no eligible sessions or examples"
            )
        role_member_ids = sorted(
            member_id
            for member_id, member_role in member_roles.items()
            if member_role == role
        )
        roles[role] = {
            "source_member_ids": role_member_ids,
            "source_member_receipts_sha256": membership_sha256(
                f"{member_id}:{receipts[member_id]}" for member_id in role_member_ids
            ),
            "session_count": len(session_ids),
            "session_membership_sha256": membership_sha256(session_ids),
            "example_count": len(example_ids),
            "example_membership_sha256": membership_sha256(example_ids),
        }

    manifest: Dict[str, Any] = {
        "schema_version": PARTITION_SCHEMA_VERSION,
        "target_contract_id": TARGET_CONTRACT_ID,
        "status": "membership_frozen",
        "protocol": "seven_member_chronological_4_1_1_1.v1",
        "code_commit": _clean(code_commit),
        **{field: _clean(hashes[field]).lower() for field in _SHA_FIELDS},
        "max_sequence_length": max_sequence_length,
        "roles": roles,
        "intersection_proofs": {
            "sessions": session_intersections,
            "examples": example_intersections,
        },
        "accepted_historical_membership_exclusion": {
            "forbidden_session_count": len(forbidden),
            "forbidden_session_membership_sha256": membership_sha256(forbidden),
            "intersection_count": 0,
        },
        "access_policy": deepcopy(PURPOSE_TO_ROLE),
    }
    manifest["manifest_id"] = stable_id("nextbehaviorpartition", manifest)
    return manifest


def records_for_purpose(
    session_records: Sequence[Mapping[str, Any]],
    source_members: Sequence[Mapping[str, Any]],
    *,
    purpose: str,
) -> List[Dict[str, Any]]:
    """Return only the role permitted for a single declared operation."""

    required_role = PURPOSE_TO_ROLE.get(_clean(purpose))
    if required_role is None:
        raise NextBehaviorPartitionError("unknown partition access purpose")
    member_roles = assign_seven_member_roles(source_members)
    receipts = {
        _clean(member["member_id"]): _clean(member["sha256"]).lower()
        for member in source_members
    }
    output: List[Dict[str, Any]] = []
    for raw_record in session_records:
        try:
            record = require_valid_next_behavior_session(raw_record)
        except NextBehaviorContractError as exc:
            raise NextBehaviorPartitionError(str(exc)) from exc
        role = member_roles.get(_clean(record["source_member_id"]))
        if role is None:
            raise NextBehaviorPartitionError(
                "session references an unassigned source member"
            )
        member_id = _clean(record["source_member_id"])
        if _clean(record["source_member_sha256"]).lower() != receipts[member_id]:
            raise NextBehaviorPartitionError(
                "session source receipt does not match its member"
            )
        if role == required_role:
            output.append(record)
    return output


def load_partition_for_purpose(
    partition_paths: Mapping[str, Any],
    *,
    purpose: str,
    reader: Any,
) -> Any:
    """Open exactly one role artifact through an injected strict reader.

    Training and selection callers never receive the test path. This small
    boundary is intentionally independent of any file format so private corpus
    storage can remain outside the repository.
    """

    role = PURPOSE_TO_ROLE.get(_clean(purpose))
    if role is None:
        raise NextBehaviorPartitionError("unknown partition access purpose")
    if set(partition_paths) != set(MEMBER_ROLES):
        raise NextBehaviorPartitionError(
            "partition path map must define train, selection, calibration, and test"
        )
    if not callable(reader):
        raise NextBehaviorPartitionError("partition reader must be callable")
    return reader(partition_paths[role])
