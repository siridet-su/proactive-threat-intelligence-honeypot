"""Private-to-safe adapter for a future provenance-complete behavior corpus.

The adapter accepts already classified private event groups. It does not infer
labels and does not replace the raw Zenodo parser, SecureBERT inference, or
trust policy. Its purpose is to make pseudonymization, redaction, provenance,
relative timing, and count reconciliation deterministic and testable before
authorized raw members become available.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, Sequence

from production.prediction.next_behavior_contract import (
    AUDIT_ONLY_TIERS,
    SESSION_SCHEMA_VERSION,
    TRUSTED_TIER,
    NextBehaviorContractError,
    normalize_label_source,
    require_valid_next_behavior_session,
)
from production.utils.serialization import stable_id, stable_json

SOURCE_MEMBER_RECEIPT_SCHEMA_VERSION = "next_behavior_source_member_receipt.v1"
CORPUS_RECEIPT_SCHEMA_VERSION = "next_behavior_corpus_receipt.v1"
PSEUDONYMIZATION_SCHEME = "hmac-sha256-v1"
_SAFE_KEY_ID = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_CORPUS_RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "status",
        "code_commit",
        "preprocessing_sha256",
        "label_policy_sha256",
        "trust_policy_sha256",
        "classification_checkpoint_sha256",
        "source_member_count",
        "source_member_receipts_sha256",
        "source_member_receipts_artifact_sha256",
        "private_session_count",
        "safe_session_count",
        "dropped_session_count",
        "safe_session_membership_sha256",
        "safe_payload_sha256",
        "counts",
        "receipt_id",
    }
)
_SOURCE_MEMBER_RECEIPT_FIELDS = frozenset(
    {
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
)
_RECONCILIATION_FIELDS = frozenset(
    {
        "private_group_count",
        "safe_trusted_group_count",
        "audit_only_group_count",
        "private_label_count",
        "trusted_label_count",
        "audit_only_label_count",
    }
)


class NextBehaviorCorpusError(ValueError):
    """Raised when a private-to-safe build cannot be audited safely."""


def validate_source_member_receipt(value: Any) -> List[str]:
    if not isinstance(value, dict):
        return ["source member receipt must be an object"]
    errors = [
        f"$.{field} is not defined by the source receipt contract"
        for field in sorted(set(value) - _SOURCE_MEMBER_RECEIPT_FIELDS)
    ]
    if value.get("schema_version") != SOURCE_MEMBER_RECEIPT_SCHEMA_VERSION:
        errors.append(
            f"schema_version must be {SOURCE_MEMBER_RECEIPT_SCHEMA_VERSION}"
        )
    if not re.fullmatch(r"nbmember_[0-9a-f]{64}", _clean(value.get("member_id"))):
        errors.append("member_id must be a pseudonymous member ID")
    if not _is_sha256(value.get("sha256")):
        errors.append("sha256 must be a SHA-256 digest")
    for field in ("byte_size", "chronological_order"):
        count = value.get(field)
        if isinstance(count, bool) or not isinstance(count, int) or count < 1:
            errors.append(f"{field} must be a positive integer")
    try:
        start = _parse_timestamp(value.get("collection_start"))
        end = _parse_timestamp(value.get("collection_end"))
    except NextBehaviorCorpusError as exc:
        errors.append(str(exc))
    else:
        if end < start:
            errors.append("source member collection range is reversed")
    if value.get("pseudonymization_scheme") != PSEUDONYMIZATION_SCHEME:
        errors.append(f"pseudonymization_scheme must be {PSEUDONYMIZATION_SCHEME}")
    if not _SAFE_KEY_ID.fullmatch(_clean(value.get("pseudonymization_key_id"))):
        errors.append("pseudonymization_key_id is invalid")
    return errors


def require_valid_source_member_receipt(value: Any) -> Dict[str, Any]:
    errors = validate_source_member_receipt(value)
    if errors:
        raise NextBehaviorCorpusError("; ".join(errors))
    return dict(value)


def validate_corpus_receipt(value: Any) -> List[str]:
    """Return strict errors for the public-safe aggregate receipt."""

    if not isinstance(value, dict):
        return ["corpus receipt must be an object"]
    errors = [
        f"$.{field} is not defined by the receipt contract"
        for field in sorted(set(value) - _CORPUS_RECEIPT_FIELDS)
    ]
    if value.get("schema_version") != CORPUS_RECEIPT_SCHEMA_VERSION:
        errors.append(f"schema_version must be {CORPUS_RECEIPT_SCHEMA_VERSION}")
    if value.get("status") != "safe_payload_reconciled":
        errors.append("status must be safe_payload_reconciled")
    if not _clean(value.get("code_commit")):
        errors.append("code_commit is required")
    for field in (
        "preprocessing_sha256",
        "label_policy_sha256",
        "trust_policy_sha256",
        "classification_checkpoint_sha256",
        "source_member_receipts_sha256",
        "source_member_receipts_artifact_sha256",
        "safe_session_membership_sha256",
        "safe_payload_sha256",
    ):
        if not _is_sha256(value.get(field)):
            errors.append(f"{field} must be a SHA-256 digest")
    for field in (
        "source_member_count",
        "private_session_count",
        "safe_session_count",
        "dropped_session_count",
    ):
        count = value.get(field)
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            errors.append(f"{field} must be a non-negative integer")
    private_count = value.get("private_session_count")
    safe_count = value.get("safe_session_count")
    dropped_count = value.get("dropped_session_count")
    if all(
        isinstance(item, int) and not isinstance(item, bool)
        for item in (private_count, safe_count, dropped_count)
    ) and private_count != safe_count + dropped_count:
        errors.append("session counts do not reconcile")
    counts = value.get("counts")
    if not isinstance(counts, dict) or set(counts) != _RECONCILIATION_FIELDS:
        errors.append("counts must define every reconciliation field")
    else:
        for field in _RECONCILIATION_FIELDS:
            count = counts.get(field)
            if isinstance(count, bool) or not isinstance(count, int) or count < 0:
                errors.append(f"counts.{field} must be a non-negative integer")
        if counts.get("private_group_count") != (
            counts.get("safe_trusted_group_count", 0)
            + counts.get("audit_only_group_count", 0)
        ):
            errors.append("group counts do not reconcile")
        if counts.get("private_label_count") != (
            counts.get("trusted_label_count", 0)
            + counts.get("audit_only_label_count", 0)
        ):
            errors.append("label counts do not reconcile")
    receipt_id = _clean(value.get("receipt_id"))
    identity_payload = dict(value)
    identity_payload.pop("receipt_id", None)
    if stable_id("nextbehaviorcorpus", identity_payload) != receipt_id:
        errors.append("receipt_id does not match receipt content")
    return errors


def require_valid_corpus_receipt(value: Any) -> Dict[str, Any]:
    errors = validate_corpus_receipt(value)
    if errors:
        raise NextBehaviorCorpusError("; ".join(errors))
    return dict(value)


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _is_sha256(value: Any) -> bool:
    text = _clean(value).lower()
    return len(text) == 64 and all(character in "0123456789abcdef" for character in text)


def _require_key(key: Any, key_id: Any) -> tuple[bytes, str]:
    if not isinstance(key, bytes) or len(key) < 32:
        raise NextBehaviorCorpusError(
            "pseudonymization key must contain at least 32 bytes"
        )
    clean_key_id = _clean(key_id)
    if not _SAFE_KEY_ID.fullmatch(clean_key_id):
        raise NextBehaviorCorpusError("pseudonymization key ID is invalid")
    return key, clean_key_id


def pseudonymous_id(kind: str, private_value: Any, *, key: bytes) -> str:
    """Return a domain-separated identifier without exposing private input."""

    clean_kind = _clean(kind).lower()
    clean_value = _clean(private_value)
    if not clean_kind or not clean_value:
        raise NextBehaviorCorpusError("pseudonymous identity inputs are required")
    digest = hmac.new(
        key,
        f"next-behavior:{clean_kind}:{clean_value}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"nb{clean_kind}_{digest}"


def _parse_timestamp(value: Any) -> datetime:
    text = _clean(value)
    if not text:
        raise NextBehaviorCorpusError("observed_at timestamp is required")
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise NextBehaviorCorpusError("observed_at timestamp is invalid") from exc
    if parsed.tzinfo is None:
        raise NextBehaviorCorpusError("observed_at timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)


def build_source_member_receipt(
    *,
    private_member_identifier: str,
    source_sha256: str,
    byte_size: int,
    chronological_order: int,
    collection_start: str,
    collection_end: str,
    pseudonymization_key: bytes,
    pseudonymization_key_id: str,
) -> Dict[str, Any]:
    """Create a public-safe receipt while keeping the raw member name private."""

    key, key_id = _require_key(
        pseudonymization_key,
        pseudonymization_key_id,
    )
    if not _is_sha256(source_sha256):
        raise NextBehaviorCorpusError("source member SHA-256 is invalid")
    if isinstance(byte_size, bool) or not isinstance(byte_size, int) or byte_size < 1:
        raise NextBehaviorCorpusError("source member byte_size must be positive")
    if (
        isinstance(chronological_order, bool)
        or not isinstance(chronological_order, int)
        or chronological_order < 1
    ):
        raise NextBehaviorCorpusError(
            "source member chronological_order must be positive"
        )
    start = _parse_timestamp(collection_start)
    end = _parse_timestamp(collection_end)
    if end < start:
        raise NextBehaviorCorpusError("source member collection range is reversed")
    return {
        "schema_version": SOURCE_MEMBER_RECEIPT_SCHEMA_VERSION,
        "member_id": pseudonymous_id(
            "member",
            private_member_identifier,
            key=key,
        ),
        "sha256": _clean(source_sha256).lower(),
        "byte_size": byte_size,
        "chronological_order": chronological_order,
        "collection_start": start.isoformat().replace("+00:00", "Z"),
        "collection_end": end.isoformat().replace("+00:00", "Z"),
        "pseudonymization_scheme": PSEUDONYMIZATION_SCHEME,
        "pseudonymization_key_id": key_id,
    }


def _relative_times(groups: Sequence[Mapping[str, Any]]) -> List[int | float | None]:
    relative_values = [group.get("relative_time_ms") for group in groups]
    timestamp_values = [group.get("observed_at") for group in groups]
    has_relative = [value is not None for value in relative_values]
    has_timestamp = [bool(_clean(value)) for value in timestamp_values]
    if all(has_relative) and not any(has_timestamp):
        return relative_values
    if all(has_timestamp) and not any(has_relative):
        timestamps = [_parse_timestamp(value) for value in timestamp_values]
        start = timestamps[0]
        return [
            int((timestamp - start).total_seconds() * 1000)
            for timestamp in timestamps
        ]
    raise NextBehaviorCorpusError(
        "groups must use either complete observed_at timestamps or complete "
        "relative_time_ms values"
    )


def _safe_label(
    label: Mapping[str, Any],
    *,
    session_private_id: str,
    group_private_id: str,
    label_index: int,
    key: bytes,
) -> Dict[str, Any]:
    source = normalize_label_source(label.get("source"))
    private_evidence_ref = _clean(label.get("evidence_ref")) or (
        f"{session_private_id}:{group_private_id}:{label_index}"
    )
    safe = {
        "tactic": _clean(label.get("tactic")).lower(),
        "technique": _clean(label.get("technique")).upper(),
        "source": source,
        "trust_tier": _clean(label.get("trust_tier")),
        "policy_sha256": _clean(label.get("policy_sha256")).lower(),
        "trust_policy_sha256": _clean(label.get("trust_policy_sha256")).lower(),
        "checkpoint_sha256": _clean(label.get("checkpoint_sha256")).lower(),
        "confidence": label.get("confidence"),
        "confidence_bucket": _clean(label.get("confidence_bucket")).lower(),
        "agreement_status": _clean(label.get("agreement_status")).lower(),
        "evidence_ref": pseudonymous_id(
            "evidence",
            private_evidence_ref,
            key=key,
        ),
    }
    if safe["trust_tier"] in AUDIT_ONLY_TIERS:
        safe["exclusion_reason"] = _clean(label.get("exclusion_reason"))
    return safe


def build_privacy_safe_session(
    private_session: Mapping[str, Any],
    source_member_receipt: Mapping[str, Any],
    *,
    pseudonymization_key: bytes,
    pseudonymization_key_id: str,
) -> Dict[str, Any]:
    """Redact a classified private session and return record plus reconciliation."""

    key, key_id = _require_key(
        pseudonymization_key,
        pseudonymization_key_id,
    )
    source_member_receipt = require_valid_source_member_receipt(
        source_member_receipt
    )
    if source_member_receipt.get("pseudonymization_key_id") != key_id:
        raise NextBehaviorCorpusError(
            "source member and session pseudonymization key IDs differ"
        )
    private_session_id = _clean(private_session.get("session_id"))
    if not private_session_id:
        raise NextBehaviorCorpusError("private session_id is required")
    raw_groups = private_session.get("observation_groups")
    if not isinstance(raw_groups, list) or not raw_groups:
        raise NextBehaviorCorpusError(
            "private observation_groups must be a non-empty array"
        )
    if not all(isinstance(group, Mapping) for group in raw_groups):
        raise NextBehaviorCorpusError("every private observation group must be an object")

    relative_times = _relative_times(raw_groups)
    safe_groups: List[Dict[str, Any]] = []
    audit_reasons: Counter[str] = Counter()
    trusted_label_count = 0
    audit_label_count = 0
    audit_only_group_count = 0

    indexed_groups = list(enumerate(zip(raw_groups, relative_times)))
    for source_index, (raw_group, relative_time) in indexed_groups:
        private_group_id = _clean(raw_group.get("group_id"))
        if not private_group_id:
            raise NextBehaviorCorpusError("private group_id is required")
        raw_labels = raw_group.get("labels")
        if not isinstance(raw_labels, list) or not raw_labels:
            raise NextBehaviorCorpusError("private group labels must be non-empty")
        if not all(isinstance(label, Mapping) for label in raw_labels):
            raise NextBehaviorCorpusError("every private label must be an object")
        safe_labels = [
            _safe_label(
                label,
                session_private_id=private_session_id,
                group_private_id=private_group_id,
                label_index=label_index,
                key=key,
            )
            for label_index, label in enumerate(raw_labels)
        ]
        trusted = sorted(
            (
                label
                for label in safe_labels
                if label["trust_tier"] == TRUSTED_TIER
            ),
            key=stable_json,
        )
        audit_only = sorted(
            (
                label
                for label in safe_labels
                if label["trust_tier"] in AUDIT_ONLY_TIERS
            ),
            key=stable_json,
        )
        if len(trusted) + len(audit_only) != len(safe_labels):
            raise NextBehaviorCorpusError("private label has an undefined trust tier")
        for label in audit_only:
            audit_reasons[_clean(label.get("exclusion_reason"))] += 1
        trusted_label_count += len(trusted)
        audit_label_count += len(audit_only)
        if not trusted:
            audit_only_group_count += 1
            continue

        safe_group = {
            "group_id": pseudonymous_id(
                "group",
                f"{private_session_id}:{private_group_id}",
                key=key,
            ),
            "event_order": raw_group.get("event_order"),
            "relative_time_ms": relative_time,
            "tactics": sorted({label["tactic"] for label in trusted}),
            "techniques": sorted({label["technique"] for label in trusted}),
            "evidence_refs": sorted(
                {label["evidence_ref"] for label in trusted}
            ),
            "label_provenance": trusted,
            "audit_only_labels": audit_only,
            "session_context": {
                key_name: (raw_group.get("session_context") or {}).get(key_name)
                for key_name in (
                    "login_outcome",
                    "command_count_bucket",
                    "session_age_bucket",
                    "confirmed_transfer_observed",
                )
            },
        }
        safe_groups.append(safe_group)

    if not safe_groups:
        safe_record = None
    else:
        safe_record = {
            "schema_version": SESSION_SCHEMA_VERSION,
            "session_id": pseudonymous_id(
                "session",
                private_session_id,
                key=key,
            ),
            "source_member_id": _clean(source_member_receipt.get("member_id")),
            "source_member_sha256": _clean(
                source_member_receipt.get("sha256")
            ).lower(),
            "protocol": _clean(private_session.get("protocol")).lower(),
            "status": _clean(private_session.get("status")).lower(),
            "pseudonymization_key_id": key_id,
            "audit_summary": {
                "total": audit_label_count,
                "by_reason": dict(sorted(audit_reasons.items())),
            },
            "observation_groups": safe_groups,
        }
        for private_field, safe_field in (
            ("configuration_id", "configuration_id"),
            ("template_family_id", "template_family_id"),
        ):
            if _clean(private_session.get(private_field)):
                safe_record[safe_field] = pseudonymous_id(
                    safe_field.replace("_id", ""),
                    private_session[private_field],
                    key=key,
                )
        try:
            safe_record = require_valid_next_behavior_session(safe_record)
        except NextBehaviorContractError as exc:
            raise NextBehaviorCorpusError(str(exc)) from exc

    return {
        "safe_session": safe_record,
        "reconciliation": {
            "private_group_count": len(raw_groups),
            "safe_trusted_group_count": len(safe_groups),
            "audit_only_group_count": audit_only_group_count,
            "private_label_count": sum(
                len(group.get("labels") or []) for group in raw_groups
            ),
            "trusted_label_count": trusted_label_count,
            "audit_only_label_count": audit_label_count,
        },
    }


def build_corpus_receipt(
    build_results: Sequence[Mapping[str, Any]],
    source_member_receipts: Sequence[Mapping[str, Any]],
    *,
    code_commit: str,
    preprocessing_sha256: str,
    label_policy_sha256: str,
    trust_policy_sha256: str,
    classification_checkpoint_sha256: str,
) -> Dict[str, Any]:
    """Reconcile a safe corpus without exposing raw member or event values."""

    for name, digest in (
        ("preprocessing_sha256", preprocessing_sha256),
        ("label_policy_sha256", label_policy_sha256),
        ("trust_policy_sha256", trust_policy_sha256),
        ("classification_checkpoint_sha256", classification_checkpoint_sha256),
    ):
        if not _is_sha256(digest):
            raise NextBehaviorCorpusError(f"{name} is invalid")
    if not _clean(code_commit):
        raise NextBehaviorCorpusError("code_commit is required")
    raw_safe_sessions = [
        result.get("safe_session")
        for result in build_results
        if isinstance(result.get("safe_session"), dict)
    ]
    reconciliations = [
        result.get("reconciliation") or {} for result in build_results
    ]
    count_fields = tuple(sorted(_RECONCILIATION_FIELDS))
    for index, item in enumerate(reconciliations):
        if set(item) != set(count_fields):
            raise NextBehaviorCorpusError(
                f"reconciliation[{index}] fields are invalid"
            )
        for field in count_fields:
            value = item.get(field)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise NextBehaviorCorpusError(
                    f"reconciliation[{index}].{field} must be non-negative"
                )
    totals = {
        key: sum(item[key] for item in reconciliations) for key in count_fields
    }
    if totals["private_group_count"] != (
        totals["safe_trusted_group_count"] + totals["audit_only_group_count"]
    ):
        raise NextBehaviorCorpusError("group reconciliation does not balance")
    if totals["private_label_count"] != (
        totals["trusted_label_count"] + totals["audit_only_label_count"]
    ):
        raise NextBehaviorCorpusError("label reconciliation does not balance")
    member_receipt_hashes = []
    seen_member_ids: set[str] = set()
    for receipt in source_member_receipts:
        validated_receipt = require_valid_source_member_receipt(receipt)
        member_id = _clean(validated_receipt.get("member_id"))
        if member_id in seen_member_ids:
            raise NextBehaviorCorpusError(
                "source member receipt identity is invalid or duplicated"
            )
        seen_member_ids.add(member_id)
        member_receipt_hashes.append(
            hashlib.sha256(
                stable_json(validated_receipt).encode("utf-8")
            ).hexdigest()
        )
    ordered_source_receipts = sorted(
        (dict(receipt) for receipt in source_member_receipts),
        key=lambda receipt: _clean(receipt.get("member_id")),
    )
    safe_sessions: List[Dict[str, Any]] = []
    for raw_session in raw_safe_sessions:
        try:
            session = require_valid_next_behavior_session(raw_session)
        except NextBehaviorContractError as exc:
            raise NextBehaviorCorpusError(str(exc)) from exc
        if _clean(session.get("source_member_id")) not in seen_member_ids:
            raise NextBehaviorCorpusError(
                "safe session references a source member absent from receipts"
            )
        safe_sessions.append(session)
    safe_sessions.sort(key=lambda session: _clean(session.get("session_id")))
    receipt: Dict[str, Any] = {
        "schema_version": CORPUS_RECEIPT_SCHEMA_VERSION,
        "status": "safe_payload_reconciled",
        "code_commit": _clean(code_commit),
        "preprocessing_sha256": _clean(preprocessing_sha256).lower(),
        "label_policy_sha256": _clean(label_policy_sha256).lower(),
        "trust_policy_sha256": _clean(trust_policy_sha256).lower(),
        "classification_checkpoint_sha256": _clean(
            classification_checkpoint_sha256
        ).lower(),
        "source_member_count": len(source_member_receipts),
        "source_member_receipts_sha256": hashlib.sha256(
            stable_json(sorted(member_receipt_hashes)).encode("utf-8")
        ).hexdigest(),
        "source_member_receipts_artifact_sha256": hashlib.sha256(
            stable_json(ordered_source_receipts).encode("utf-8")
        ).hexdigest(),
        "private_session_count": len(build_results),
        "safe_session_count": len(safe_sessions),
        "dropped_session_count": len(build_results) - len(safe_sessions),
        "safe_session_membership_sha256": hashlib.sha256(
            stable_json(
                sorted(_clean(session["session_id"]) for session in safe_sessions)
            ).encode("utf-8")
        ).hexdigest(),
        "safe_payload_sha256": hashlib.sha256(
            stable_json(safe_sessions).encode("utf-8")
        ).hexdigest(),
        "counts": totals,
    }
    receipt["receipt_id"] = stable_id("nextbehaviorcorpus", receipt)
    return require_valid_corpus_receipt(receipt)


def build_streaming_corpus_receipt(
    build_results: Iterable[Mapping[str, Any]],
    source_member_receipts: Sequence[Mapping[str, Any]],
    *,
    code_commit: str,
    preprocessing_sha256: str,
    label_policy_sha256: str,
    trust_policy_sha256: str,
    classification_checkpoint_sha256: str,
) -> Dict[str, Any]:
    """Reconcile a session-ID-ordered build stream with bounded memory.

    Safe sessions must arrive in strictly increasing ``session_id`` order.
    Dropped audit-only sessions may occur anywhere in the stream. The produced
    membership and payload hashes are byte-identical to
    :func:`build_corpus_receipt` for the same records.
    """

    for name, digest in (
        ("preprocessing_sha256", preprocessing_sha256),
        ("label_policy_sha256", label_policy_sha256),
        ("trust_policy_sha256", trust_policy_sha256),
        ("classification_checkpoint_sha256", classification_checkpoint_sha256),
    ):
        if not _is_sha256(digest):
            raise NextBehaviorCorpusError(f"{name} is invalid")
    if not _clean(code_commit):
        raise NextBehaviorCorpusError("code_commit is required")

    member_receipt_hashes: List[str] = []
    seen_member_ids: set[str] = set()
    ordered_source_receipts: List[Dict[str, Any]] = []
    for receipt in source_member_receipts:
        validated = require_valid_source_member_receipt(receipt)
        member_id = _clean(validated.get("member_id"))
        if member_id in seen_member_ids:
            raise NextBehaviorCorpusError(
                "source member receipt identity is invalid or duplicated"
            )
        seen_member_ids.add(member_id)
        ordered_source_receipts.append(validated)
        member_receipt_hashes.append(
            hashlib.sha256(stable_json(validated).encode("utf-8")).hexdigest()
        )
    ordered_source_receipts.sort(
        key=lambda receipt: _clean(receipt.get("member_id"))
    )

    payload_digest = hashlib.sha256()
    membership_digest = hashlib.sha256()
    payload_digest.update(b"[")
    membership_digest.update(b"[")
    payload_first = True
    membership_first = True
    previous_session_id = ""
    private_session_count = 0
    safe_session_count = 0
    totals = {field: 0 for field in _RECONCILIATION_FIELDS}
    count_fields = set(_RECONCILIATION_FIELDS)

    for index, result in enumerate(build_results):
        if not isinstance(result, Mapping):
            raise NextBehaviorCorpusError(f"build_results[{index}] is invalid")
        private_session_count += 1
        reconciliation = result.get("reconciliation")
        if not isinstance(reconciliation, Mapping) or set(reconciliation) != count_fields:
            raise NextBehaviorCorpusError(
                f"reconciliation[{index}] fields are invalid"
            )
        for field in count_fields:
            value = reconciliation.get(field)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise NextBehaviorCorpusError(
                    f"reconciliation[{index}].{field} must be non-negative"
                )
            totals[field] += value

        raw_session = result.get("safe_session")
        if raw_session is None:
            continue
        if not isinstance(raw_session, dict):
            raise NextBehaviorCorpusError(
                f"build_results[{index}].safe_session is invalid"
            )
        try:
            session = require_valid_next_behavior_session(raw_session)
        except NextBehaviorContractError as exc:
            raise NextBehaviorCorpusError(str(exc)) from exc
        member_id = _clean(session.get("source_member_id"))
        if member_id not in seen_member_ids:
            raise NextBehaviorCorpusError(
                "safe session references a source member absent from receipts"
            )
        session_id = _clean(session.get("session_id"))
        if previous_session_id and session_id <= previous_session_id:
            raise NextBehaviorCorpusError(
                "safe sessions are not in strict session_id order"
            )
        previous_session_id = session_id
        serialized_session = stable_json(session).encode("utf-8")
        serialized_id = stable_json(session_id).encode("utf-8")
        if not payload_first:
            payload_digest.update(b",")
        if not membership_first:
            membership_digest.update(b",")
        payload_digest.update(serialized_session)
        membership_digest.update(serialized_id)
        payload_first = False
        membership_first = False
        safe_session_count += 1

    payload_digest.update(b"]")
    membership_digest.update(b"]")
    if totals["private_group_count"] != (
        totals["safe_trusted_group_count"] + totals["audit_only_group_count"]
    ):
        raise NextBehaviorCorpusError("group reconciliation does not balance")
    if totals["private_label_count"] != (
        totals["trusted_label_count"] + totals["audit_only_label_count"]
    ):
        raise NextBehaviorCorpusError("label reconciliation does not balance")

    receipt: Dict[str, Any] = {
        "schema_version": CORPUS_RECEIPT_SCHEMA_VERSION,
        "status": "safe_payload_reconciled",
        "code_commit": _clean(code_commit),
        "preprocessing_sha256": _clean(preprocessing_sha256).lower(),
        "label_policy_sha256": _clean(label_policy_sha256).lower(),
        "trust_policy_sha256": _clean(trust_policy_sha256).lower(),
        "classification_checkpoint_sha256": _clean(
            classification_checkpoint_sha256
        ).lower(),
        "source_member_count": len(source_member_receipts),
        "source_member_receipts_sha256": hashlib.sha256(
            stable_json(sorted(member_receipt_hashes)).encode("utf-8")
        ).hexdigest(),
        "source_member_receipts_artifact_sha256": hashlib.sha256(
            stable_json(ordered_source_receipts).encode("utf-8")
        ).hexdigest(),
        "private_session_count": private_session_count,
        "safe_session_count": safe_session_count,
        "dropped_session_count": private_session_count - safe_session_count,
        "safe_session_membership_sha256": membership_digest.hexdigest(),
        "safe_payload_sha256": payload_digest.hexdigest(),
        "counts": totals,
    }
    receipt["receipt_id"] = stable_id("nextbehaviorcorpus", receipt)
    return require_valid_corpus_receipt(receipt)
