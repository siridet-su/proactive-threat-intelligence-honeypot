"""Development-only support analysis for the frozen trusted-group target.

The analyzer consumes only already privacy-safe sessions from frozen train,
selection, and calibration roles.  It cannot select source members, inspect a
sealed-test session, train a model, or change deterministic semantics.
"""

from __future__ import annotations

import hashlib
import re
from collections import Counter, defaultdict
from copy import deepcopy
from decimal import Decimal
from typing import Any, Dict, Iterable, Mapping

from production.prediction.next_trusted_group_target import (
    BINARY_CLASSES,
    DEVELOPMENT_ROLES,
    TARGET_CONTRACT_ID,
    build_next_trusted_group_examples,
)
from production.utils.serialization import stable_id, stable_json


SCHEMA_VERSION = "next_trusted_group_support.v1"
MINIMUM_TARGETS = 30
MINIMUM_DISTINCT_SESSIONS = 30
MINIMUM_REPORTABLE_TACTICS = 2
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_GIT_ID = re.compile(r"^[0-9a-f]{40}$")


class GroupTargetSupportError(ValueError):
    """Raised when a support run violates its frozen development boundary."""


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(stable_json(value).encode("utf-8")).hexdigest()


def _percentage(numerator: int, denominator: int) -> str:
    if denominator == 0:
        return "0.000000"
    return str(
        (Decimal(numerator) * Decimal(100) / Decimal(denominator)).quantize(
            Decimal("0.000001")
        )
    )


def _ratio(numerator: int, denominator: int) -> str | None:
    if denominator == 0:
        return None
    return str(
        (Decimal(numerator) / Decimal(denominator)).quantize(Decimal("0.000001"))
    )


class _OrderedMembership:
    def __init__(self) -> None:
        self._digest = hashlib.sha256()
        self.count = 0

    def add(self, value: str) -> None:
        encoded = stable_json(_clean(value)).encode("utf-8") + b"\n"
        self._digest.update(encoded)
        self.count += 1

    def hexdigest(self) -> str:
        return self._digest.hexdigest()


def _aggregate_role(
    sessions: Iterable[Mapping[str, Any]],
) -> tuple[Dict[str, Any], set[str]]:
    session_membership = _OrderedMembership()
    example_membership = _OrderedMembership()
    sessions_count = 0
    trusted_groups = 0
    total_targets = 0
    terminal_targets = 0
    continuation_targets = 0
    repeated_same = 0
    multi_tactic = 0
    continuation_sessions = 0
    tactic_counts: Counter[str] = Counter()
    technique_counts: Counter[str] = Counter()
    tactic_set_counts: Counter[str] = Counter()
    tactic_sessions: Counter[str] = Counter()
    technique_sessions: Counter[str] = Counter()
    seen_session_ids: set[str] = set()

    for raw in sessions:
        session = dict(raw)
        examples = build_next_trusted_group_examples(session)
        groups = session["observation_groups"]
        session_id = _clean(session.get("session_id"))
        if session_id in seen_session_ids:
            raise GroupTargetSupportError(
                "development support contains a duplicated session identity"
            )
        seen_session_ids.add(session_id)
        sessions_count += 1
        trusted_groups += len(groups)
        session_membership.add(session_id)
        session_tactics: set[str] = set()
        session_techniques: set[str] = set()
        has_continuation = False
        for index, example in enumerate(examples):
            example_membership.add(example["example_id"])
            total_targets += 1
            target = example["target"]
            if target["outcome_type"] == "session_end":
                terminal_targets += 1
                continue
            has_continuation = True
            continuation_targets += 1
            tactics = tuple(target["tactics"])
            techniques = tuple(target["techniques"])
            tactic_counts.update(tactics)
            technique_counts.update(techniques)
            session_tactics.update(tactics)
            session_techniques.update(techniques)
            tactic_set_counts["+".join(tactics)] += 1
            if len(tactics) > 1:
                multi_tactic += 1
            current_tactics = tuple(groups[index]["tactics"])
            if tactics == current_tactics:
                repeated_same += 1
        if has_continuation:
            continuation_sessions += 1
        tactic_sessions.update(session_tactics)
        technique_sessions.update(session_techniques)

    if total_targets != terminal_targets + continuation_targets:
        raise GroupTargetSupportError("binary target counts do not reconcile")
    if terminal_targets != sessions_count:
        raise GroupTargetSupportError(
            "closed development sessions must contribute exactly one terminal target"
        )
    return {
        "sessions": sessions_count,
        "trusted_groups": trusted_groups,
        "total_targets": total_targets,
        "terminal_targets": terminal_targets,
        "continuation_targets": continuation_targets,
        "terminal_percentage": _percentage(terminal_targets, total_targets),
        "continuation_percentage": _percentage(continuation_targets, total_targets),
        "terminal_to_continuation_ratio": _ratio(
            terminal_targets, continuation_targets
        ),
        "binary_distinct_session_support": {
            "session_end": terminal_targets,
            "continuation": continuation_sessions,
        },
        "next_tactic_counts": dict(sorted(tactic_counts.items())),
        "next_tactic_distinct_session_support": dict(
            sorted(tactic_sessions.items())
        ),
        "next_technique_counts": dict(sorted(technique_counts.items())),
        "next_technique_distinct_session_support": dict(
            sorted(technique_sessions.items())
        ),
        "next_tactic_set_counts": dict(sorted(tactic_set_counts.items())),
        "repeated_same_tactic_set_continuations": repeated_same,
        "multi_tactic_continuations": multi_tactic,
        "ordered_session_membership_sha256": session_membership.hexdigest(),
        "ordered_example_membership_sha256": example_membership.hexdigest(),
    }, seen_session_ids


def _support_gate(roles: Mapping[str, Mapping[str, Any]]) -> Dict[str, Any]:
    binary: Dict[str, Any] = {}
    binary_pass = True
    for role in DEVELOPMENT_ROLES:
        metrics = roles[role]
        role_gate: Dict[str, Any] = {}
        for label, count_field in (
            ("continuation", "continuation_targets"),
            ("session_end", "terminal_targets"),
        ):
            targets = int(metrics[count_field])
            sessions = int(metrics["binary_distinct_session_support"][label])
            passed = targets >= MINIMUM_TARGETS and sessions >= MINIMUM_DISTINCT_SESSIONS
            role_gate[label] = {
                "targets": targets,
                "distinct_sessions": sessions,
                "minimum_targets": MINIMUM_TARGETS,
                "minimum_distinct_sessions": MINIMUM_DISTINCT_SESSIONS,
                "passed": passed,
            }
            binary_pass = binary_pass and passed
        binary[role] = role_gate

    all_tactics = sorted(
        {
            tactic
            for metrics in roles.values()
            for tactic in metrics["next_tactic_counts"]
        }
    )
    tactics: Dict[str, Any] = {}
    reportable = []
    for tactic in all_tactics:
        role_gate = {}
        tactic_pass = True
        for role in DEVELOPMENT_ROLES:
            targets = int(roles[role]["next_tactic_counts"].get(tactic, 0))
            sessions = int(
                roles[role]["next_tactic_distinct_session_support"].get(tactic, 0)
            )
            passed = targets >= MINIMUM_TARGETS and sessions >= MINIMUM_DISTINCT_SESSIONS
            role_gate[role] = {
                "targets": targets,
                "distinct_sessions": sessions,
                "minimum_targets": MINIMUM_TARGETS,
                "minimum_distinct_sessions": MINIMUM_DISTINCT_SESSIONS,
                "passed": passed,
            }
            tactic_pass = tactic_pass and passed
        tactics[tactic] = {"roles": role_gate, "reportable": tactic_pass}
        if tactic_pass:
            reportable.append(tactic)

    passed = binary_pass and len(reportable) >= MINIMUM_REPORTABLE_TACTICS
    return {
        "minimum_targets": MINIMUM_TARGETS,
        "minimum_distinct_sessions": MINIMUM_DISTINCT_SESSIONS,
        "required_binary_classes": list(BINARY_CLASSES),
        "minimum_reportable_conditional_tactics": MINIMUM_REPORTABLE_TACTICS,
        "binary_classes": binary,
        "conditional_tactics": tactics,
        "reportable_conditional_tactics": reportable,
        "binary_gate_passed": binary_pass,
        "conditional_gate_passed": len(reportable) >= MINIMUM_REPORTABLE_TACTICS,
        "passed": passed,
    }


def _validate_role_metrics(role: str, value: Any) -> list[str]:
    if not isinstance(value, Mapping):
        return [f"roles.{role} must be an object"]
    expected = {
        "sessions", "trusted_groups", "total_targets", "terminal_targets",
        "continuation_targets", "terminal_percentage", "continuation_percentage",
        "terminal_to_continuation_ratio", "binary_distinct_session_support",
        "next_tactic_counts", "next_tactic_distinct_session_support",
        "next_technique_counts", "next_technique_distinct_session_support",
        "next_tactic_set_counts", "repeated_same_tactic_set_continuations",
        "multi_tactic_continuations", "ordered_session_membership_sha256",
        "ordered_example_membership_sha256",
    }
    errors: list[str] = []
    if set(value) != expected:
        errors.append(f"roles.{role} fields are invalid")
    integer_fields = (
        "sessions", "trusted_groups", "total_targets", "terminal_targets",
        "continuation_targets", "repeated_same_tactic_set_continuations",
        "multi_tactic_continuations",
    )
    if any(
        isinstance(value.get(field), bool)
        or not isinstance(value.get(field), int)
        or value.get(field, -1) < 0
        for field in integer_fields
    ):
        errors.append(f"roles.{role} counts are invalid")
        return errors
    sessions = value["sessions"]
    groups = value["trusted_groups"]
    total = value["total_targets"]
    terminal = value["terminal_targets"]
    continuation = value["continuation_targets"]
    if total != terminal + continuation or total != groups or terminal != sessions:
        errors.append(f"roles.{role} target counts do not reconcile")
    if value.get("terminal_percentage") != _percentage(terminal, total):
        errors.append(f"roles.{role} terminal percentage is inconsistent")
    if value.get("continuation_percentage") != _percentage(continuation, total):
        errors.append(f"roles.{role} continuation percentage is inconsistent")
    if value.get("terminal_to_continuation_ratio") != _ratio(terminal, continuation):
        errors.append(f"roles.{role} terminal/continuation ratio is inconsistent")
    binary = value.get("binary_distinct_session_support")
    if (
        not isinstance(binary, Mapping)
        or set(binary) != set(BINARY_CLASSES)
        or binary.get("session_end") != terminal
        or not isinstance(binary.get("continuation"), int)
        or not 0 <= binary.get("continuation", -1) <= continuation
    ):
        errors.append(f"roles.{role} binary distinct-session support is invalid")
    for counts_field, sessions_field in (
        ("next_tactic_counts", "next_tactic_distinct_session_support"),
        ("next_technique_counts", "next_technique_distinct_session_support"),
    ):
        counts = value.get(counts_field)
        distinct = value.get(sessions_field)
        if not isinstance(counts, Mapping) or not isinstance(distinct, Mapping) or set(counts) != set(distinct):
            errors.append(f"roles.{role}.{counts_field} support is invalid")
            continue
        if any(
            isinstance(count, bool)
            or not isinstance(count, int)
            or count < 1
            or not isinstance(distinct.get(label), int)
            or not 1 <= distinct[label] <= count
            for label, count in counts.items()
        ):
            errors.append(f"roles.{role}.{counts_field} counts are invalid")
    tactic_sets = value.get("next_tactic_set_counts")
    if (
        not isinstance(tactic_sets, Mapping)
        or any(not label or not isinstance(count, int) or count < 1 for label, count in tactic_sets.items())
        or sum(tactic_sets.values()) != continuation
    ):
        errors.append(f"roles.{role} next tactic-set counts are invalid")
    if value["repeated_same_tactic_set_continuations"] > continuation or value["multi_tactic_continuations"] > continuation:
        errors.append(f"roles.{role} continuation subtype counts are invalid")
    for field in ("ordered_session_membership_sha256", "ordered_example_membership_sha256"):
        if not _SHA256.fullmatch(_clean(value.get(field))):
            errors.append(f"roles.{role}.{field} is invalid")
    return errors


def build_group_target_support_receipt(
    *,
    safe_sessions_by_role: Mapping[str, Iterable[Mapping[str, Any]]],
    target_policy_sha256: str,
    design_commit: str,
    design_tree: str,
    source_selection_sha256: str,
    successor_inventory_id: str,
    successor_inventory_sha256: str,
    classification_receipt_sha256: str,
    pseudonymization_key_id: str,
    pseudonymization_key_fingerprint_sha256: str,
    historical_test_membership_receipt_sha256: str,
    operational_observations: Mapping[str, Any] | None = None,
) -> Dict[str, Any]:
    if set(safe_sessions_by_role) != set(DEVELOPMENT_ROLES):
        raise GroupTargetSupportError(
            "support analysis requires exactly train, selection, and calibration"
        )
    aggregates = {
        role: _aggregate_role(safe_sessions_by_role[role])
        for role in DEVELOPMENT_ROLES
    }
    roles = {role: aggregates[role][0] for role in DEVELOPMENT_ROLES}
    memberships = {role: aggregates[role][1] for role in DEVELOPMENT_ROLES}
    intersections = {
        "train_selection": len(memberships["train"] & memberships["selection"]),
        "train_calibration": len(memberships["train"] & memberships["calibration"]),
        "selection_calibration": len(
            memberships["selection"] & memberships["calibration"]
        ),
    }
    if any(intersections.values()):
        raise GroupTargetSupportError("development role session memberships overlap")
    gate = _support_gate(roles)
    totals = {
        field: sum(int(roles[role][field]) for role in DEVELOPMENT_ROLES)
        for field in (
            "sessions",
            "trusted_groups",
            "total_targets",
            "terminal_targets",
            "continuation_targets",
        )
    }
    totals["terminal_percentage"] = _percentage(
        totals["terminal_targets"], totals["total_targets"]
    )
    totals["continuation_percentage"] = _percentage(
        totals["continuation_targets"], totals["total_targets"]
    )
    totals["terminal_to_continuation_ratio"] = _ratio(
        totals["terminal_targets"], totals["continuation_targets"]
    )
    semantic = {
        "target_contract_id": TARGET_CONTRACT_ID,
        "target_policy_sha256": _clean(target_policy_sha256),
        "design_commit": _clean(design_commit),
        "design_tree": _clean(design_tree),
        "source_selection_sha256": _clean(source_selection_sha256),
        "successor_inventory_id": _clean(successor_inventory_id),
        "successor_inventory_sha256": _clean(successor_inventory_sha256),
        "classification_receipt_sha256": _clean(classification_receipt_sha256),
        "pseudonymization_key_id": _clean(pseudonymization_key_id),
        "pseudonymization_key_fingerprint_sha256": _clean(
            pseudonymization_key_fingerprint_sha256
        ),
        "historical_test_membership_receipt_sha256": _clean(
            historical_test_membership_receipt_sha256
        ),
        "roles": roles,
        "role_membership_intersections": intersections,
        "totals": totals,
        "gate": gate,
    }
    receipt = {
        "schema_version": SCHEMA_VERSION,
        "status": "support_gate_passed" if gate["passed"] else "support_gate_failed",
        "purpose": "development_only_successor_group_target_feasibility",
        **semantic,
        "semantic_support_sha256": _sha256_json(semantic),
        "sealed_test_boundary": {
            "test_behavioral_content_accessed": False,
            "test_metrics_used": False,
            "test_role_accepted_by_analyzer": False,
        },
        "authority": {
            "deterministic_analysis_authoritative": True,
            "prediction_non_authoritative": True,
            "training_performed": False,
            "production_changed": False,
        },
        "operational_observations": dict(operational_observations or {}),
    }
    receipt["receipt_id"] = stable_id("nexttrustedgroupsupport", receipt)
    errors = validate_group_target_support_receipt(receipt)
    if errors:
        raise GroupTargetSupportError("; ".join(errors))
    return receipt


def validate_group_target_support_receipt(value: Any) -> list[str]:
    if not isinstance(value, Mapping):
        return ["support receipt must be an object"]
    required = {
        "schema_version", "status", "purpose", "target_contract_id",
        "target_policy_sha256", "design_commit", "design_tree",
        "source_selection_sha256", "successor_inventory_id",
        "successor_inventory_sha256", "classification_receipt_sha256",
        "pseudonymization_key_id", "pseudonymization_key_fingerprint_sha256",
        "historical_test_membership_receipt_sha256", "roles", "totals",
        "role_membership_intersections", "gate", "semantic_support_sha256", "sealed_test_boundary", "authority",
        "operational_observations", "receipt_id",
    }
    errors: list[str] = []
    if set(value) != required:
        errors.append("support receipt fields are invalid")
    if value.get("schema_version") != SCHEMA_VERSION:
        errors.append("support receipt schema is invalid")
    if value.get("target_contract_id") != TARGET_CONTRACT_ID:
        errors.append("support receipt target is invalid")
    for field in (
        "target_policy_sha256", "source_selection_sha256",
        "successor_inventory_sha256", "classification_receipt_sha256",
        "pseudonymization_key_fingerprint_sha256",
        "historical_test_membership_receipt_sha256", "semantic_support_sha256",
    ):
        if not _SHA256.fullmatch(_clean(value.get(field))):
            errors.append(f"support receipt {field} is invalid")
    for field in ("design_commit", "design_tree"):
        if not _GIT_ID.fullmatch(_clean(value.get(field))):
            errors.append(f"support receipt {field} is invalid")
    expected_key_id = "next-behavior-hmac-" + _clean(
        value.get("pseudonymization_key_fingerprint_sha256")
    )[:16]
    if value.get("pseudonymization_key_id") != expected_key_id:
        errors.append("support receipt pseudonymization key identity is invalid")
    roles = value.get("roles")
    if not isinstance(roles, Mapping) or set(roles) != set(DEVELOPMENT_ROLES):
        errors.append("support receipt roles are invalid")
    else:
        for role in DEVELOPMENT_ROLES:
            errors.extend(_validate_role_metrics(role, roles[role]))
        expected_gate = _support_gate(roles)
        if value.get("gate") != expected_gate:
            errors.append("support gate cannot be recomputed")
        expected_status = "support_gate_passed" if expected_gate["passed"] else "support_gate_failed"
        if value.get("status") != expected_status:
            errors.append("support receipt status is inconsistent")
    if value.get("role_membership_intersections") != {
        "train_selection": 0,
        "train_calibration": 0,
        "selection_calibration": 0,
    }:
        errors.append("development role memberships overlap")
    boundary = value.get("sealed_test_boundary")
    if boundary != {
        "test_behavioral_content_accessed": False,
        "test_metrics_used": False,
        "test_role_accepted_by_analyzer": False,
    }:
        errors.append("sealed-test boundary is invalid")
    authority = value.get("authority")
    if authority != {
        "deterministic_analysis_authoritative": True,
        "prediction_non_authoritative": True,
        "training_performed": False,
        "production_changed": False,
    }:
        errors.append("support authority boundary is invalid")
    totals = value.get("totals")
    if isinstance(roles, Mapping) and isinstance(totals, Mapping):
        expected_totals = {
            field: sum(int(roles[role][field]) for role in DEVELOPMENT_ROLES)
            for field in (
                "sessions", "trusted_groups", "total_targets",
                "terminal_targets", "continuation_targets",
            )
        }
        expected_totals["terminal_percentage"] = _percentage(
            expected_totals["terminal_targets"], expected_totals["total_targets"]
        )
        expected_totals["continuation_percentage"] = _percentage(
            expected_totals["continuation_targets"], expected_totals["total_targets"]
        )
        expected_totals["terminal_to_continuation_ratio"] = _ratio(
            expected_totals["terminal_targets"], expected_totals["continuation_targets"]
        )
        if totals != expected_totals:
            errors.append("support receipt totals are inconsistent")
    else:
        errors.append("support receipt totals are invalid")
    semantic_keys = (
        "target_contract_id", "target_policy_sha256", "design_commit",
        "design_tree", "source_selection_sha256", "successor_inventory_id",
        "successor_inventory_sha256", "classification_receipt_sha256",
        "pseudonymization_key_id", "pseudonymization_key_fingerprint_sha256",
        "historical_test_membership_receipt_sha256", "roles",
        "role_membership_intersections", "totals", "gate",
    )
    semantic = {key: deepcopy(value.get(key)) for key in semantic_keys}
    if value.get("semantic_support_sha256") != _sha256_json(semantic):
        errors.append("semantic support hash is invalid")
    basis = dict(value)
    receipt_id = basis.pop("receipt_id", None)
    if receipt_id != stable_id("nexttrustedgroupsupport", basis):
        errors.append("support receipt identity is invalid")
    return errors


def attach_operational_observations(
    receipt: Mapping[str, Any], observations: Mapping[str, Any]
) -> Dict[str, Any]:
    """Attach non-semantic run measurements without changing support identity."""

    checked = dict(receipt)
    errors = validate_group_target_support_receipt(checked)
    if errors:
        raise GroupTargetSupportError("; ".join(errors))
    checked["operational_observations"] = dict(observations)
    checked.pop("receipt_id", None)
    checked["receipt_id"] = stable_id("nexttrustedgroupsupport", checked)
    errors = validate_group_target_support_receipt(checked)
    if errors:
        raise GroupTargetSupportError("; ".join(errors))
    return checked
