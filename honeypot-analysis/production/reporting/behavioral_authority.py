"""Single promotion boundary for typed and legacy behavioral outputs."""

from __future__ import annotations

import hashlib
from copy import deepcopy
from typing import Any, Iterable, Mapping

from production.utils.serialization import stable_json


SCHEMA_VERSION = "behavioral_authority_decision.v1"
DEFERRED_FAMILIES = frozenset({"scheduled_task", "identity"})
LEGACY_PERSISTENCE_TYPES = frozenset({
    "possible_continued_access_preparation",
    "observed_persistence_preparation",
})
DEFAULT_AUTHORITY_POLICY = {
    "schema_version": SCHEMA_VERSION,
    "legacy_explicit_reviewed_fallback_rule_ids": (),
    "deferred_families": tuple(sorted(DEFERRED_FAMILIES)),
}


def _text(value: Any) -> str:
    return str(value or "").strip()


def _sha(value: Any) -> str:
    return hashlib.sha256(stable_json(value).encode("utf-8")).hexdigest()


def _decision_for_item(
    item: Mapping[str, Any],
    *,
    typed_status: str,
    activated_families: set[str],
    authority_policy: Mapping[str, Any],
) -> dict[str, Any]:
    family = _text(item.get("semantic_family"))
    basis = _text(item.get("claim_basis"))
    finding_type = _text(item.get("finding_type") or item.get("claim_type"))
    refs = sorted({
        _text(ref)
        for ref in (item.get("evidence_refs") or [])
        if _text(ref)
    })
    relationship_refs = sorted({
        _text(ref)
        for ref in (item.get("relationship_refs") or [])
        if _text(ref)
    })
    chain_refs = sorted({
        _text(ref)
        for ref in (
            item.get("chain_refs")
            or ([item.get("connected_chain_id")] if item.get("connected_chain_id") else [])
        )
        if _text(ref)
    })
    deferred_families = {
        _text(value)
        for value in authority_policy.get("deferred_families")
        or DEFAULT_AUTHORITY_POLICY["deferred_families"]
        if _text(value)
    }
    explicit_fallbacks = {
        _text(value)
        for value in authority_policy.get(
            "legacy_explicit_reviewed_fallback_rule_ids"
        )
        or DEFAULT_AUTHORITY_POLICY["legacy_explicit_reviewed_fallback_rule_ids"]
        if _text(value)
    }
    if family and family in activated_families:
        mode = "typed_required"
        trusted = typed_status == "valid" and basis.startswith("typed_semantic")
        reason = [] if trusted else ["typed_semantic_selection_unavailable"]
    elif family and family in deferred_families:
        mode = "audit_only_until_typed"
        trusted = False
        reason = ["typed_family_not_activated"]
    elif finding_type in LEGACY_PERSISTENCE_TYPES or "persistence" in finding_type:
        mode = "audit_only_until_typed"
        trusted = False
        reason = ["legacy_persistence_requires_typed_authority"]
    elif basis.startswith("typed_semantic"):
        mode = "typed_required"
        trusted = typed_status == "valid"
        reason = [] if trusted else ["typed_semantic_selection_unavailable"]
    elif (
        not family
        and _text(item.get("behavior_policy_rule_id") or item.get("policy_rule_id"))
        in explicit_fallbacks
    ):
        mode = "explicit_reviewed_legacy_fallback"
        trusted = True
        reason = []
    else:
        # Legacy candidates are not promoted by ATT&CK or regex provenance
        # alone.  Explicit literal fallback policy can be added later without
        # changing this boundary.
        mode = "audit_only_until_typed"
        trusted = False
        reason = ["legacy_candidate_not_explicitly_reviewed_fallback"]
    result = {
        "schema_version": SCHEMA_VERSION,
        "candidate_id": _text(item.get("finding_id") or item.get("claim_id"))
        or _sha({"type": finding_type, "refs": refs}),
        "semantic_family": family,
        "candidate_source": basis or "legacy",
        "authority_mode": mode,
        "typed_family_state": "active" if family in activated_families else "deferred",
        "decision": "trusted" if trusted else "audit_only",
        "reason_codes": reason,
        "policy_rule_id": _text(
            item.get("behavior_policy_rule_id") or item.get("policy_rule_id")
        ),
        "evidence_refs": refs,
        "relationship_refs": relationship_refs,
        "chain_refs": chain_refs,
    }
    result["decision_sha256"] = _sha(result)
    return result


def apply_behavioral_authority(
    items: Iterable[Mapping[str, Any]],
    *,
    typed_status: str,
    activated_families: Iterable[str],
    authority_policy: Mapping[str, Any] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    active = {_text(item) for item in activated_families if _text(item)}
    policy = dict(DEFAULT_AUTHORITY_POLICY)
    if isinstance(authority_policy, Mapping):
        policy.update(dict(authority_policy))
    if _text(policy.get("schema_version")) not in {
        "",
        SCHEMA_VERSION,
    }:
        raise ValueError("behavioral authority policy schema is invalid")
    trusted: list[dict[str, Any]] = []
    audit_only: list[dict[str, Any]] = []
    decisions: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, Mapping):
            continue
        decision = _decision_for_item(
            item,
            typed_status=typed_status,
            activated_families=active,
            authority_policy=policy,
        )
        decisions.append(decision)
        if decision["decision"] == "trusted":
            trusted.append(deepcopy(dict(item)))
        else:
            audit_only.append(deepcopy(dict(item)))
    decisions.sort(key=lambda item: item["candidate_id"])
    return trusted, audit_only, decisions


def validate_behavioral_authority(value: Any) -> list[str]:
    if not isinstance(value, Mapping):
        return ["behavioral authority decision must be an object"]
    errors = []
    if value.get("schema_version") != SCHEMA_VERSION:
        errors.append("behavioral authority schema is invalid")
    if value.get("decision") not in {"trusted", "audit_only"}:
        errors.append("behavioral authority decision is invalid")
    digest = _text(value.get("decision_sha256"))
    copied = deepcopy(dict(value))
    copied.pop("decision_sha256", None)
    if len(digest) != 64 or _sha(copied) != digest:
        errors.append("behavioral authority decision hash mismatch")
    return errors
