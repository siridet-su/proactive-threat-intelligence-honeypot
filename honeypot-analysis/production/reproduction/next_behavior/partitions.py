"""Partition and membership controls for the final next-behavior experiment.

This module does not create a real split without provenance-complete source
members. It supplies deterministic, fail-closed controls for a future private
corpus build while keeping every accepted historical benchmark unchanged.
"""

from __future__ import annotations

import hashlib
from copy import deepcopy
from datetime import date, datetime, time, timedelta, timezone
from typing import Any, Dict, Iterable, List, Mapping, Sequence

from production.prediction.next_behavior_contract import (
    TARGET_CONTRACT_ID,
    NextBehaviorContractError,
    require_valid_next_behavior_session,
)
from production.reproduction.next_behavior.corpus import (
    NextBehaviorCorpusError,
    require_valid_corpus_receipt,
)
from production.prediction.next_behavior_preprocessing import (
    build_next_behavior_examples,
)
from production.utils.serialization import stable_id, stable_json

PARTITION_SCHEMA_VERSION = "next_behavior_partition_manifest.v1"
PARTITION_SCHEMA_VERSION_V2 = "next_behavior_partition_manifest.v2"
MEMBER_ROLES = ("train", "selection", "calibration", "test")
MEMBER_COHORTS = ("development", "final")
PURPOSE_TO_ROLE = {
    "fit_model": "train",
    "select_model": "selection",
    "fit_calibration": "calibration",
    "final_evaluation": "test",
}
PURPOSE_TO_COHORT = {
    "fit_model": "development",
    "select_model": "development",
    "fit_calibration": "development",
    "final_evaluation": "final",
}
V2_PROTOCOL = "thirteen_member_chronological_4_1_1_7_with_embargo.v1"
V2_DEVELOPMENT_CUTOFF = "2025-08-07"
V2_EMBARGO_DATE = "2025-08-08"
V2_FINAL_WINDOW_START = "2025-08-09"
_SHA_FIELDS = (
    "preprocessing_sha256",
    "label_policy_sha256",
    "trust_policy_sha256",
)
_HISTORICAL_SPLITS = ("train", "calibration", "test")
_HISTORICAL_EVIDENCE_VALUES = (*_HISTORICAL_SPLITS, "not_present")
_SOURCE_MEMBER_FIELDS = {
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


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(stable_json(value).encode("utf-8")).hexdigest()


def require_historical_membership_independence(
    build_receipt: Mapping[str, Any],
    corpus_receipt: Mapping[str, Any],
) -> Dict[str, Any]:
    """Fail closed when a rebuilt corpus reuses accepted historical sessions.

    A new HMAC key changes public session identifiers, so comparing only the
    safe identifiers can falsely imply independence. The private corpus
    builder records the accepted historical split for each original session.
    This boundary validates those aggregate counts against the safe-corpus
    receipt before any partition artifact may be frozen.
    """

    if not isinstance(build_receipt, Mapping):
        raise NextBehaviorPartitionError("build receipt must be an object")
    if build_receipt.get("schema_version") != (
        "next_behavior_zenodo_build_receipt.v1"
    ):
        raise NextBehaviorPartitionError(
            "build receipt has an unsupported schema"
        )
    if build_receipt.get("status") != "safe_corpus_built":
        raise NextBehaviorPartitionError("safe corpus build is incomplete")
    try:
        corpus = require_valid_corpus_receipt(dict(corpus_receipt))
    except NextBehaviorCorpusError as exc:
        raise NextBehaviorPartitionError(
            "corpus receipt is invalid"
        ) from exc
    if build_receipt.get("code_commit") != corpus["code_commit"]:
        raise NextBehaviorPartitionError(
            "build and corpus receipts use different code commits"
        )
    if build_receipt.get("corpus_receipt_id") != corpus["receipt_id"]:
        raise NextBehaviorPartitionError(
            "build and corpus receipt identities do not match"
        )
    safe_payload = build_receipt.get("safe_payload")
    if (
        not isinstance(safe_payload, Mapping)
        or safe_payload.get("line_count") != corpus["safe_session_count"]
    ):
        raise NextBehaviorPartitionError(
            "build and corpus safe-session counts do not match"
        )
    reconciliation = build_receipt.get("pipeline_reconciliation")
    if not isinstance(reconciliation, Mapping):
        raise NextBehaviorPartitionError(
            "build receipt has no pipeline reconciliation"
        )
    private_count = reconciliation.get(
        "private_sessions_entering_safe_adapter"
    )
    if (
        isinstance(private_count, bool)
        or not isinstance(private_count, int)
        or private_count < 0
        or private_count != corpus["private_session_count"]
    ):
        raise NextBehaviorPartitionError(
            "build and corpus private-session counts do not match"
        )
    historical = build_receipt.get("historical_membership")
    if not isinstance(historical, Mapping):
        raise NextBehaviorPartitionError(
            "build receipt has no historical membership evidence"
        )
    accepted_count = historical.get("accepted_payload_session_count")
    if (
        isinstance(accepted_count, bool)
        or not isinstance(accepted_count, int)
        or accepted_count < 1
    ):
        raise NextBehaviorPartitionError(
            "accepted historical membership count is invalid"
        )
    overlap_by_split = historical.get("overlap_by_historical_split")
    if (
        not isinstance(overlap_by_split, Mapping)
        or set(overlap_by_split) != {*_HISTORICAL_SPLITS, "not_present"}
    ):
        raise NextBehaviorPartitionError(
            "historical overlap must define train, calibration, test, "
            "and not_present"
        )
    for split, count in overlap_by_split.items():
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise NextBehaviorPartitionError(
                f"historical overlap count for {split} is invalid"
            )
    if sum(overlap_by_split.values()) != private_count:
        raise NextBehaviorPartitionError(
            "historical overlap counts do not reconcile to private sessions"
        )
    overlap_count = sum(
        overlap_by_split[split] for split in _HISTORICAL_SPLITS
    )
    if overlap_count > accepted_count:
        raise NextBehaviorPartitionError(
            "historical overlap exceeds accepted membership"
        )
    historical_payload_sha256 = _clean(
        build_receipt.get("historical_payload_sha256")
    ).lower()
    if not _is_sha256(historical_payload_sha256):
        raise NextBehaviorPartitionError(
            "historical payload SHA-256 is invalid"
        )
    if overlap_count:
        split_summary = ", ".join(
            f"{split}={overlap_by_split[split]}"
            for split in _HISTORICAL_SPLITS
            if overlap_by_split[split]
        )
        raise NextBehaviorPartitionError(
            "redesigned membership overlaps the accepted historical corpus "
            f"({overlap_count} sessions; {split_summary})"
        )
    return {
        "status": "historical_membership_independent",
        "accepted_historical_session_count": accepted_count,
        "candidate_private_session_count": private_count,
        "overlap_count": 0,
        "historical_payload_sha256": historical_payload_sha256,
    }


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
        unknown = set(member) - _SOURCE_MEMBER_FIELDS
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


def assign_thirteen_member_roles(
    source_members: Sequence[Mapping[str, Any]],
) -> Dict[str, str]:
    """Assign the additive v2 four/one/one/seven chronological protocol."""

    if len(source_members) != 13:
        raise NextBehaviorPartitionError(
            "the v2 thirteen-member protocol requires exactly 13 source members"
        )
    member_ids: List[str] = []
    orders: List[int] = []
    for index, member in enumerate(source_members):
        if not isinstance(member, Mapping):
            raise NextBehaviorPartitionError(
                f"source_members[{index}] must be an object"
            )
        unknown = set(member) - _SOURCE_MEMBER_FIELDS
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
        member_ids.append(member_id)
        orders.append(order)
    if orders != list(range(1, 14)):
        raise NextBehaviorPartitionError(
            "v2 source members must have chronological orders 1 through 13"
        )
    return {
        **{member_id: "train" for member_id in member_ids[:4]},
        member_ids[4]: "selection",
        member_ids[5]: "calibration",
        **{member_id: "test" for member_id in member_ids[6:]},
    }


def assign_thirteen_member_cohorts(
    source_members: Sequence[Mapping[str, Any]],
) -> Dict[str, str]:
    """Assign v2 members to the development or final cohort."""

    assign_thirteen_member_roles(source_members)
    member_ids = [_clean(member["member_id"]) for member in source_members]
    return {
        **{member_id: "development" for member_id in member_ids[:6]},
        **{member_id: "final" for member_id in member_ids[6:]},
    }


def _parse_member_datetime(value: Any, *, field: str, member_id: str) -> datetime:
    text = _clean(value)
    if not text:
        raise NextBehaviorPartitionError(
            f"source member {member_id} {field} is required for v2"
        )
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise NextBehaviorPartitionError(
            f"source member {member_id} {field} must be an ISO-8601 datetime"
        ) from exc
    if parsed.tzinfo is None:
        raise NextBehaviorPartitionError(
            f"source member {member_id} {field} must include a timezone"
        )
    return parsed.astimezone(timezone.utc)


def _require_v2_temporal_policy(
    source_members: Sequence[Mapping[str, Any]],
    *,
    development_cutoff: str,
    final_window_start: str,
) -> Dict[str, Any]:
    if _clean(development_cutoff) != V2_DEVELOPMENT_CUTOFF:
        raise NextBehaviorPartitionError(
            f"v2 development_cutoff must be {V2_DEVELOPMENT_CUTOFF}"
        )
    if _clean(final_window_start) != V2_FINAL_WINDOW_START:
        raise NextBehaviorPartitionError(
            f"v2 final_window_start must be {V2_FINAL_WINDOW_START}"
        )
    cutoff_date = date.fromisoformat(V2_DEVELOPMENT_CUTOFF)
    final_window_date = date.fromisoformat(V2_FINAL_WINDOW_START)
    cutoff_exclusive = datetime.combine(
        cutoff_date + timedelta(days=1),
        time.min,
        tzinfo=timezone.utc,
    )
    final_window_start_utc = datetime.combine(
        final_window_date,
        time.min,
        tzinfo=timezone.utc,
    )
    for index, member in enumerate(source_members):
        member_id = _clean(member["member_id"])
        collection_start = _parse_member_datetime(
            member.get("collection_start"),
            field="collection_start",
            member_id=member_id,
        )
        collection_end = _parse_member_datetime(
            member.get("collection_end"),
            field="collection_end",
            member_id=member_id,
        )
        if collection_start > collection_end:
            raise NextBehaviorPartitionError(
                f"source member {member_id} collection interval is reversed"
            )
        if index < 6 and collection_end >= cutoff_exclusive:
            raise NextBehaviorPartitionError(
                "development source members must end on or before the "
                f"{V2_DEVELOPMENT_CUTOFF} cutoff"
            )
        if index >= 6 and collection_start < final_window_start_utc:
            raise NextBehaviorPartitionError(
                "final source members must start on or after the "
                f"{V2_FINAL_WINDOW_START} final window boundary"
            )
    return {
        "development_cutoff": V2_DEVELOPMENT_CUTOFF,
        "embargo_date": V2_EMBARGO_DATE,
        "final_window_start": V2_FINAL_WINDOW_START,
        "development_member_orders": list(range(1, 7)),
        "final_member_orders": list(range(7, 14)),
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


def _cohort_intersections(
    cohort_values: Mapping[str, Sequence[str]],
) -> Dict[str, Any]:
    development = set(cohort_values.get("development") or [])
    final = set(cohort_values.get("final") or [])
    values = sorted(development.intersection(final))
    return {
        "all_empty": not values,
        "pairs": {"development__final": values},
    }


def _historical_overlap_summary(
    values_by_split: Mapping[str, Sequence[str]],
) -> Dict[str, Dict[str, Any]]:
    return {
        split: {
            "session_count": len(values_by_split.get(split) or []),
            "session_membership_sha256": membership_sha256(
                values_by_split.get(split) or []
            ),
        }
        for split in _HISTORICAL_EVIDENCE_VALUES
    }


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


def build_partition_manifest_v2(
    session_records: Sequence[Mapping[str, Any]],
    source_members: Sequence[Mapping[str, Any]],
    *,
    preprocessing_sha256: str,
    label_policy_sha256: str,
    trust_policy_sha256: str,
    code_commit: str,
    historical_split_by_session: Mapping[str, str],
    development_cutoff: str,
    final_window_start: str,
    max_sequence_length: int = 8,
) -> Dict[str, Any]:
    """Build the role-aware, two-cohort corrected-target v2 manifest.

    Historical train/calibration reuse is disclosed for the development
    cohort. Historical test membership is forbidden there, and every
    historical split is forbidden in the final cohort.
    """

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
    if (
        isinstance(max_sequence_length, bool)
        or not isinstance(max_sequence_length, int)
        or max_sequence_length < 1
    ):
        raise NextBehaviorPartitionError("max_sequence_length must be positive")
    if not isinstance(historical_split_by_session, Mapping):
        raise NextBehaviorPartitionError(
            "historical_split_by_session must be an object"
        )

    member_roles = assign_thirteen_member_roles(source_members)
    member_cohorts = assign_thirteen_member_cohorts(source_members)
    temporal_policy = _require_v2_temporal_policy(
        source_members,
        development_cutoff=development_cutoff,
        final_window_start=final_window_start,
    )
    receipts = {
        _clean(member["member_id"]): _clean(member["sha256"]).lower()
        for member in source_members
    }

    evidence: Dict[str, str] = {}
    for raw_session_id, raw_split in historical_split_by_session.items():
        session_id = _clean(raw_session_id)
        split = _clean(raw_split)
        if not session_id or session_id in evidence:
            raise NextBehaviorPartitionError(
                "historical split evidence session IDs must be non-empty and unique"
            )
        if split not in _HISTORICAL_EVIDENCE_VALUES:
            raise NextBehaviorPartitionError(
                f"historical split evidence for {session_id} is invalid"
            )
        evidence[session_id] = split

    seen_sessions: set[str] = set()
    seen_examples: set[str] = set()
    seen_members: set[str] = set()
    validated_records: List[Dict[str, Any]] = []
    role_members: Dict[str, List[str]] = {role: [] for role in MEMBER_ROLES}
    role_sessions: Dict[str, List[str]] = {role: [] for role in MEMBER_ROLES}
    role_examples: Dict[str, List[str]] = {role: [] for role in MEMBER_ROLES}
    cohort_members: Dict[str, List[str]] = {
        cohort: [] for cohort in MEMBER_COHORTS
    }
    cohort_sessions: Dict[str, List[str]] = {
        cohort: [] for cohort in MEMBER_COHORTS
    }
    cohort_examples: Dict[str, List[str]] = {
        cohort: [] for cohort in MEMBER_COHORTS
    }
    role_historical = {
        role: {split: [] for split in _HISTORICAL_EVIDENCE_VALUES}
        for role in MEMBER_ROLES
    }
    cohort_historical = {
        cohort: {split: [] for split in _HISTORICAL_EVIDENCE_VALUES}
        for cohort in MEMBER_COHORTS
    }

    for member_id, role in member_roles.items():
        role_members[role].append(member_id)
        cohort_members[member_cohorts[member_id]].append(member_id)

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
        cohort = member_cohorts[member_id]
        examples = build_next_behavior_examples(
            record,
            max_sequence_length=max_sequence_length,
        )
        example_ids = [_clean(example["example_id"]) for example in examples]
        duplicate_examples = seen_examples.intersection(example_ids)
        if duplicate_examples:
            raise NextBehaviorPartitionError(
                "example membership occurs in more than one session: "
                + ", ".join(sorted(duplicate_examples))
            )
        seen_examples.update(example_ids)
        seen_members.add(member_id)
        validated_records.append(record)
        role_sessions[role].append(session_id)
        role_examples[role].extend(example_ids)
        cohort_sessions[cohort].append(session_id)
        cohort_examples[cohort].extend(example_ids)

    if seen_members != set(member_roles):
        missing = sorted(set(member_roles) - seen_members)
        raise NextBehaviorPartitionError(
            "every v2 source member must contribute an eligible session: "
            + ", ".join(missing)
        )
    missing_evidence = sorted(seen_sessions - set(evidence))
    extra_evidence = sorted(set(evidence) - seen_sessions)
    if missing_evidence or extra_evidence:
        details = []
        if missing_evidence:
            details.append("missing=" + ", ".join(missing_evidence))
        if extra_evidence:
            details.append("extra=" + ", ".join(extra_evidence))
        raise NextBehaviorPartitionError(
            "historical split evidence must exactly cover v2 sessions ("
            + "; ".join(details)
            + ")"
        )

    for role in MEMBER_ROLES:
        cohort = "final" if role == "test" else "development"
        for session_id in role_sessions[role]:
            split = evidence[session_id]
            role_historical[role][split].append(session_id)
            cohort_historical[cohort][split].append(session_id)
            if cohort == "development" and split == "test":
                raise NextBehaviorPartitionError(
                    "development cohort overlaps the forbidden historical test: "
                    + session_id
                )
            if cohort == "final" and split != "not_present":
                raise NextBehaviorPartitionError(
                    "final cohort overlaps an accepted historical split "
                    f"({split}): {session_id}"
                )

    role_intersections = {
        "source_members": _role_intersections(role_members),
        "sessions": _role_intersections(role_sessions),
        "examples": _role_intersections(role_examples),
    }
    cohort_intersections = {
        "source_members": _cohort_intersections(cohort_members),
        "sessions": _cohort_intersections(cohort_sessions),
        "examples": _cohort_intersections(cohort_examples),
    }
    if not all(
        proof["all_empty"]
        for proof_set in (role_intersections, cohort_intersections)
        for proof in proof_set.values()
    ):
        raise NextBehaviorPartitionError("v2 partition membership intersects")

    roles: Dict[str, Dict[str, Any]] = {}
    for role in MEMBER_ROLES:
        member_ids = sorted(role_members[role])
        session_ids = sorted(role_sessions[role])
        example_ids = sorted(role_examples[role])
        if not session_ids or not example_ids:
            raise NextBehaviorPartitionError(
                f"{role} has no eligible sessions or examples"
            )
        roles[role] = {
            "cohort": "final" if role == "test" else "development",
            "source_member_count": len(member_ids),
            "source_member_ids": member_ids,
            "source_member_membership_sha256": membership_sha256(member_ids),
            "source_member_receipts_sha256": membership_sha256(
                f"{member_id}:{receipts[member_id]}" for member_id in member_ids
            ),
            "session_count": len(session_ids),
            "session_membership_sha256": membership_sha256(session_ids),
            "example_count": len(example_ids),
            "example_membership_sha256": membership_sha256(example_ids),
            "historical_split_disclosure": _historical_overlap_summary(
                role_historical[role]
            ),
        }

    cohorts: Dict[str, Dict[str, Any]] = {}
    for cohort in MEMBER_COHORTS:
        member_ids = sorted(cohort_members[cohort])
        session_ids = sorted(cohort_sessions[cohort])
        example_ids = sorted(cohort_examples[cohort])
        cohorts[cohort] = {
            "roles": [
                role
                for role in MEMBER_ROLES
                if ("final" if role == "test" else "development") == cohort
            ],
            "source_member_count": len(member_ids),
            "source_member_membership_sha256": membership_sha256(member_ids),
            "source_member_receipts_sha256": membership_sha256(
                f"{member_id}:{receipts[member_id]}" for member_id in member_ids
            ),
            "session_count": len(session_ids),
            "session_membership_sha256": membership_sha256(session_ids),
            "example_count": len(example_ids),
            "example_membership_sha256": membership_sha256(example_ids),
            "historical_split_disclosure": _historical_overlap_summary(
                cohort_historical[cohort]
            ),
        }

    canonical_records = sorted(
        validated_records,
        key=lambda record: _clean(record["session_id"]),
    )
    canonical_members = [dict(member) for member in source_members]
    canonical_evidence = {
        session_id: evidence[session_id] for session_id in sorted(evidence)
    }
    manifest: Dict[str, Any] = {
        "schema_version": PARTITION_SCHEMA_VERSION_V2,
        "target_contract_id": TARGET_CONTRACT_ID,
        "status": "membership_frozen",
        "protocol": V2_PROTOCOL,
        "code_commit": _clean(code_commit),
        **{field: _clean(hashes[field]).lower() for field in _SHA_FIELDS},
        "max_sequence_length": max_sequence_length,
        "temporal_policy": temporal_policy,
        "input_hashes": {
            "session_records_sha256": _canonical_sha256(canonical_records),
            "source_members_sha256": _canonical_sha256(canonical_members),
            "historical_split_evidence_sha256": _canonical_sha256(
                canonical_evidence
            ),
        },
        "roles": roles,
        "cohorts": cohorts,
        "intersection_proofs": {
            "roles": role_intersections,
            "cohorts": cohort_intersections,
        },
        "historical_membership_policy": {
            "evidence_session_count": len(evidence),
            "evidence_sha256": _canonical_sha256(canonical_evidence),
            "development": {
                "permitted_reuse_splits": ["train", "calibration"],
                "forbidden_splits": ["test"],
                "disclosure": _historical_overlap_summary(
                    cohort_historical["development"]
                ),
            },
            "final": {
                "permitted_reuse_splits": [],
                "forbidden_splits": list(_HISTORICAL_SPLITS),
                "disclosure": _historical_overlap_summary(
                    cohort_historical["final"]
                ),
            },
        },
        "access_policy": {
            purpose: {
                "role": role,
                "cohort": PURPOSE_TO_COHORT[purpose],
            }
            for purpose, role in PURPOSE_TO_ROLE.items()
        },
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


def records_for_purpose_v2(
    session_records: Sequence[Mapping[str, Any]],
    source_members: Sequence[Mapping[str, Any]],
    *,
    purpose: str,
) -> List[Dict[str, Any]]:
    """Return only the single v2 role authorized for the declared purpose."""

    required_role = PURPOSE_TO_ROLE.get(_clean(purpose))
    if required_role is None:
        raise NextBehaviorPartitionError("unknown partition access purpose")
    member_roles = assign_thirteen_member_roles(source_members)
    receipts = {
        _clean(member["member_id"]): _clean(member["sha256"]).lower()
        for member in source_members
    }
    output: List[Dict[str, Any]] = []
    seen_sessions: set[str] = set()
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
        member_id = _clean(record["source_member_id"])
        role = member_roles.get(member_id)
        if role is None:
            raise NextBehaviorPartitionError(
                "session references an unassigned source member"
            )
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


def load_partition_for_purpose_v2(
    partition_paths: Mapping[str, Any],
    *,
    purpose: str,
    reader: Any,
) -> Any:
    """Open one authorized v2 artifact without accepting any other role path."""

    role = PURPOSE_TO_ROLE.get(_clean(purpose))
    if role is None:
        raise NextBehaviorPartitionError("unknown partition access purpose")
    if not isinstance(partition_paths, Mapping) or set(partition_paths) != {role}:
        raise NextBehaviorPartitionError(
            f"v2 partition path map for {purpose} must define only {role}"
        )
    if not callable(reader):
        raise NextBehaviorPartitionError("partition reader must be callable")
    return reader(partition_paths[role])
