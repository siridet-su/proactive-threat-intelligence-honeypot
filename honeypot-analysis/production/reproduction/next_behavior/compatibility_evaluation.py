"""Privacy-safe current-policy compatibility evaluation helpers.

The retained role sessions already contain immutable, pseudonymous classifier
provenance from the original Zenodo source membership.  The reviewed rule and
MITRE artifacts are unchanged.  This module therefore applies only the
documented trust-policy delta: model-only SecureBERT labels without explicit
reviewed authority are demoted from trusted observations to audit context.

It never reclassifies commands, invents labels, or changes the frozen target.
"""

from __future__ import annotations

from collections import Counter
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Mapping

from production.prediction.next_behavior_chronology import order_model_chronology
from production.prediction.next_behavior_contract import (
    NextBehaviorContractError,
    require_valid_next_behavior_session,
)
from production.utils.serialization import stable_id


COMPATIBILITY_CORPUS_SCHEMA_VERSION = (
    "next_behavior_current_policy_compatibility_corpus.v1"
)
TRUST_DELTA_REASON = "model_only_not_observed_evidence"


class NextBehaviorCompatibilityError(ValueError):
    """Raised when an immutable role record cannot be safely reprocessed."""


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _sha(value: Any, field: str) -> str:
    text = _clean(value).lower()
    if len(text) != 64 or any(character not in "0123456789abcdef" for character in text):
        raise NextBehaviorCompatibilityError(f"{field} must be a SHA-256 digest")
    return text


def _ordered_group_copies(groups: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Exercise the shared chronology contract using retained relative times."""

    epoch = datetime(2000, 1, 1, tzinfo=timezone.utc)
    records = []
    for group in groups:
        relative = group.get("relative_time_ms")
        if isinstance(relative, bool) or not isinstance(relative, (int, float)):
            raise NextBehaviorCompatibilityError(
                "retained role group lacks numeric relative chronology"
            )
        timestamp = epoch + timedelta(milliseconds=float(relative))
        records.append(
            {
                "source_timestamp": timestamp.isoformat(timespec="microseconds"),
                "durable_sequence": int(group["event_order"]),
                "durable_id": _clean(group["group_id"]),
                "group": deepcopy(group),
            }
        )
    chronology = order_model_chronology(records)
    return [dict(record["group"]) for record in chronology.records]


def _current_label(
    value: Mapping[str, Any],
    *,
    rule_policy_sha256: str,
    current_trust_policy_sha256: str,
    classifier_checkpoint_sha256: str,
    audit_only: bool,
) -> dict[str, Any]:
    label = deepcopy(dict(value))
    if _clean(label.get("policy_sha256")).lower() != rule_policy_sha256:
        raise NextBehaviorCompatibilityError(
            "retained label does not match the frozen reviewed rule policy"
        )
    source = _clean(label.get("source"))
    checkpoint = _clean(label.get("checkpoint_sha256")).lower()
    if source in {"securebert", "rule_model_agreement"}:
        if checkpoint != classifier_checkpoint_sha256:
            raise NextBehaviorCompatibilityError(
                "retained model label does not match the frozen classifier"
            )
    elif checkpoint:
        raise NextBehaviorCompatibilityError(
            "non-model retained label unexpectedly binds a checkpoint"
        )
    label["trust_policy_sha256"] = current_trust_policy_sha256
    if audit_only:
        if label.get("trust_tier") not in {
            "audit_only_candidate",
            "excluded",
        }:
            raise NextBehaviorCompatibilityError(
                "retained audit label has an invalid trust tier"
            )
    elif label.get("trust_tier") != "trusted_observation":
        raise NextBehaviorCompatibilityError(
            "retained trusted label has an invalid trust tier"
        )
    return label


def reprocess_retained_safe_session(
    retained_session: Mapping[str, Any],
    *,
    rule_policy_sha256: str,
    current_trust_policy_sha256: str,
    classifier_checkpoint_sha256: str,
) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    """Apply the current trust policy to one immutable privacy-safe session.

    Model-only SecureBERT provenance is the only supported trust delta.  Any
    unexpected trusted SecureBERT agreement form fails closed instead of being
    guessed.  Groups left without trusted labels are omitted from model phases,
    while all representable candidates remain counted in the audit summary.
    """

    rule_sha = _sha(rule_policy_sha256, "rule_policy_sha256")
    trust_sha = _sha(
        current_trust_policy_sha256,
        "current_trust_policy_sha256",
    )
    checkpoint_sha = _sha(
        classifier_checkpoint_sha256,
        "classifier_checkpoint_sha256",
    )
    try:
        retained = require_valid_next_behavior_session(retained_session)
    except NextBehaviorContractError as exc:
        raise NextBehaviorCompatibilityError(
            "retained safe session is invalid"
        ) from exc

    output = {
        key: deepcopy(value)
        for key, value in retained.items()
        if key not in {"audit_summary", "observation_groups"}
    }
    output_groups: list[dict[str, Any]] = []
    reasons: Counter[str] = Counter()
    delta: Counter[str] = Counter(
        {
            "retained_group_count": len(retained["observation_groups"]),
            "retained_trusted_label_count": 0,
            "retained_audit_label_count": 0,
            "current_group_count": 0,
            "current_trusted_label_count": 0,
            "current_audit_label_count": 0,
            "demoted_model_only_label_count": 0,
            "groups_removed_by_trust_policy": 0,
        }
    )

    for group in _ordered_group_copies(retained["observation_groups"]):
        current_trusted: list[dict[str, Any]] = []
        current_audit: list[dict[str, Any]] = []
        retained_trusted = group.get("label_provenance") or []
        retained_audit = group.get("audit_only_labels") or []
        delta["retained_trusted_label_count"] += len(retained_trusted)
        delta["retained_audit_label_count"] += len(retained_audit)

        for raw_label in retained_trusted:
            label = _current_label(
                raw_label,
                rule_policy_sha256=rule_sha,
                current_trust_policy_sha256=trust_sha,
                classifier_checkpoint_sha256=checkpoint_sha,
                audit_only=False,
            )
            if label["source"] == "securebert":
                if label.get("agreement_status") != "model_only":
                    raise NextBehaviorCompatibilityError(
                        "trusted SecureBERT label has unsupported agreement semantics"
                    )
                label["trust_tier"] = "audit_only_candidate"
                label["exclusion_reason"] = TRUST_DELTA_REASON
                current_audit.append(label)
                delta["demoted_model_only_label_count"] += 1
            else:
                current_trusted.append(label)

        for raw_label in retained_audit:
            current_audit.append(
                _current_label(
                    raw_label,
                    rule_policy_sha256=rule_sha,
                    current_trust_policy_sha256=trust_sha,
                    classifier_checkpoint_sha256=checkpoint_sha,
                    audit_only=True,
                )
            )
        for label in current_audit:
            reasons[_clean(label.get("exclusion_reason"))] += 1
        delta["current_audit_label_count"] += len(current_audit)
        delta["current_trusted_label_count"] += len(current_trusted)

        if not current_trusted:
            delta["groups_removed_by_trust_policy"] += 1
            continue
        updated = deepcopy(group)
        updated["label_provenance"] = sorted(
            current_trusted,
            key=lambda item: (
                item["tactic"],
                item["technique"],
                item["source"],
                item["evidence_ref"],
            ),
        )
        updated["audit_only_labels"] = sorted(
            current_audit,
            key=lambda item: (
                item["tactic"],
                item["technique"],
                item["source"],
                item["evidence_ref"],
            ),
        )
        updated["tactics"] = sorted(
            {label["tactic"] for label in current_trusted}
        )
        updated["techniques"] = sorted(
            {label["technique"] for label in current_trusted}
        )
        updated["evidence_refs"] = sorted(
            {label["evidence_ref"] for label in current_trusted}
        )
        output_groups.append(updated)

    delta["current_group_count"] = len(output_groups)
    if not output_groups:
        return None, dict(delta)
    output["audit_summary"] = {
        "total": sum(reasons.values()),
        "by_reason": dict(sorted(reasons.items())),
    }
    output["observation_groups"] = output_groups
    try:
        current = require_valid_next_behavior_session(output)
    except NextBehaviorContractError as exc:
        raise NextBehaviorCompatibilityError(
            "current-policy safe session is invalid"
        ) from exc
    return current, dict(delta)


def force_zero_audit_model_input(model_input: Mapping[str, Any]) -> dict[str, Any]:
    """Create the exact audit-ablation input without changing other fields."""

    value = deepcopy(dict(model_input))
    phases = value.get("phase_sequence")
    if not isinstance(phases, list) or not phases:
        raise NextBehaviorCompatibilityError(
            "audit ablation requires a non-empty phase sequence"
        )
    for phase in phases:
        if not isinstance(phase, dict):
            raise NextBehaviorCompatibilityError(
                "audit ablation phase is invalid"
            )
        phase["audit_only_label_count"] = 0
    value.pop("input_hash", None)
    value["input_hash"] = stable_id("nextbehaviorinput", value)
    return value


def force_zero_audit_example(example: Mapping[str, Any]) -> dict[str, Any]:
    """Return an evaluation-only example with only audit counts ablated."""

    value = deepcopy(dict(example))
    value["model_input"] = force_zero_audit_model_input(value["model_input"])
    return value

