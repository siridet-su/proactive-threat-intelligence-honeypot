"""Auditable, additive approval record for the corrected-target PoC.

This module deliberately does *not* alter the frozen selection policy or make
an ineligible seed eligible in that original experiment.  It records a second,
explicitly authorised PoC decision whose only selection input is the already
sealed Selection partition.  Final-test access is intentionally outside this
module and must be guarded by a separately frozen manifest and ledger.
"""

from __future__ import annotations

import hashlib
from copy import deepcopy
from typing import Any, Dict, Mapping, Sequence

from production.utils.serialization import stable_json


STATUS = "PROFESSOR_APPROVED_POC_EVALUATION"
SCHEMA_VERSION = "next_behavior_professor_approved_poc_decision.v1"
ORIGINAL_CLOSURE_COMMIT = "3d3fca68a814ce6dd5b206bc008f9f79216ffea7"
DECLARED_RULE = (
    "highest_selection_macro_f1_then_highest_selection_balanced_accuracy_"
    "then_highest_terminal_f1_then_lowest_p95_latency_then_lowest_seed"
)


class ProfessorApprovedPocError(ValueError):
    """Raised when an approval record would hide or weaken original evidence."""


def _sha256(value: Any) -> str:
    return hashlib.sha256(stable_json(value).encode("utf-8")).hexdigest()


def _require_sha256(value: Any, name: str) -> str:
    text = str(value or "").strip().lower()
    if len(text) != 64:
        raise ProfessorApprovedPocError(f"{name} must be a SHA-256 digest")
    try:
        int(text, 16)
    except ValueError as exc:
        raise ProfessorApprovedPocError(f"{name} must be a SHA-256 digest") from exc
    return text


def rank_complete_selection_candidates(
    selection_blocked_receipt: Mapping[str, Any],
) -> list[Dict[str, Any]]:
    """Rank complete seeds without changing the original eligibility result.

    The caller must retain the original receipt, including each candidate's
    ``eligible=false`` and blocker list.  This ranking is for the separately
    authorised PoC decision only; it never calls the original selector.
    """

    if not isinstance(selection_blocked_receipt, Mapping):
        raise ProfessorApprovedPocError("selection receipt must be an object")
    if selection_blocked_receipt.get("status") != "selection_blocked_pre_test":
        raise ProfessorApprovedPocError("original selection receipt is not blocked")
    if selection_blocked_receipt.get("test_opened") is not False:
        raise ProfessorApprovedPocError("original blocked receipt already opened test")
    records = selection_blocked_receipt.get("seed_candidates")
    if not isinstance(records, list) or not records:
        raise ProfessorApprovedPocError("selection receipt has no seed candidates")
    complete: list[Dict[str, Any]] = []
    for record in records:
        if not isinstance(record, Mapping):
            raise ProfessorApprovedPocError("selection candidate is malformed")
        if record.get("status") != "complete" or record.get("completion_marker_verified") is not True:
            raise ProfessorApprovedPocError("all declared selection seeds must be complete")
        candidate = record.get("candidate")
        checkpoint = record.get("checkpoint")
        if not isinstance(candidate, Mapping) or not isinstance(checkpoint, Mapping):
            raise ProfessorApprovedPocError("selection candidate binding is malformed")
        values = candidate.get("selection_values")
        if not isinstance(values, Mapping):
            raise ProfessorApprovedPocError("selection candidate has no aggregate values")
        try:
            key = (
                -float(values["macro_f1"]),
                -float(values["balanced_accuracy"]),
                -float(values["terminal_f1"]),
                float(values["p95_single_case_cpu_latency_ms"]),
                int(record["seed"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ProfessorApprovedPocError("selection candidate values are invalid") from exc
        _require_sha256(checkpoint.get("sha256"), "checkpoint.sha256")
        complete.append({"key": key, "record": deepcopy(dict(record))})
    if len({item["record"].get("seed") for item in complete}) != len(complete):
        raise ProfessorApprovedPocError("selection seeds are duplicated")
    return [item["record"] for item in sorted(complete, key=lambda item: item["key"])]


def build_professor_approved_decision(
    selection_blocked_receipt: Mapping[str, Any],
    *,
    selection_blocked_receipt_sha256: str,
    source_code_commit: str,
) -> Dict[str, Any]:
    """Create a content-addressed decision preserving the old blocker verbatim."""

    receipt_hash = _require_sha256(
        selection_blocked_receipt_sha256, "selection_blocked_receipt_sha256"
    )
    ranked = rank_complete_selection_candidates(selection_blocked_receipt)
    winner = ranked[0]
    candidate = winner["candidate"]
    if candidate.get("eligible") is not False:
        raise ProfessorApprovedPocError("approval must not relabel original eligibility")
    blockers = candidate.get("blockers")
    if not isinstance(blockers, list) or "reportable_zero_recall:defense-evasion" not in blockers:
        raise ProfessorApprovedPocError("original defense-evasion blocker is not preserved")
    checkpoint = winner["checkpoint"]
    value: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "status": STATUS,
        "original_experiment": {
            "closure_commit": ORIGINAL_CLOSURE_COMMIT,
            "status": "BLOCKED_AT_SELECTION",
            "selection_blocked_receipt_sha256": receipt_hash,
            "original_eligibility_preserved": False,
            "preserved_blockers": deepcopy(blockers),
        },
        "approval_basis": {
            "authority": "supervising_professor_and_project_team",
            "purpose": "advisory_offline_poc_evaluation",
            "accepted_limitation": "zero_selection_recall_for_defense-evasion",
            "observed_command_derived_evidence_remains_authoritative": True,
            "prediction_may_authorize_alerts_hypotheses_guidance_recommendations_or_actions": False,
        },
        "selection": {
            "partition_role": "selection",
            "ranking_rule": DECLARED_RULE,
            "all_declared_seeds_complete": True,
            "ranked_seeds": [
                {
                    "seed": record["seed"],
                    "selection_values": deepcopy(record["candidate"]["selection_values"]),
                    "original_eligible": record["candidate"]["eligible"],
                    "original_blockers": deepcopy(record["candidate"]["blockers"]),
                    "checkpoint_sha256": record["checkpoint"]["sha256"],
                }
                for record in ranked
            ],
            "selected_seed": winner["seed"],
            "selected_checkpoint_sha256": checkpoint["sha256"],
            "selection_used_final_test": False,
        },
        "source_code_commit": str(source_code_commit),
    }
    value["decision_sha256"] = _sha256(value)
    return value


def require_valid_professor_approved_decision(value: Any) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise ProfessorApprovedPocError("approval decision must be an object")
    required = {
        "schema_version", "status", "original_experiment", "approval_basis",
        "selection", "source_code_commit", "decision_sha256",
    }
    if set(value) != required:
        raise ProfessorApprovedPocError("approval decision fields are invalid")
    if value["schema_version"] != SCHEMA_VERSION or value["status"] != STATUS:
        raise ProfessorApprovedPocError("approval decision status is invalid")
    original = value["original_experiment"]
    if not isinstance(original, dict) or original.get("closure_commit") != ORIGINAL_CLOSURE_COMMIT or original.get("status") != "BLOCKED_AT_SELECTION" or original.get("original_eligibility_preserved") is not False:
        raise ProfessorApprovedPocError("approval decision does not preserve original block")
    _require_sha256(original.get("selection_blocked_receipt_sha256"), "original receipt")
    if "reportable_zero_recall:defense-evasion" not in original.get("preserved_blockers", []):
        raise ProfessorApprovedPocError("approval decision lost defense-evasion blocker")
    selection = value["selection"]
    if not isinstance(selection, dict) or selection.get("ranking_rule") != DECLARED_RULE or selection.get("selection_used_final_test") is not False:
        raise ProfessorApprovedPocError("approval selection rule is invalid")
    ranked = selection.get("ranked_seeds")
    if not isinstance(ranked, list) or not ranked or selection.get("selected_seed") != ranked[0].get("seed"):
        raise ProfessorApprovedPocError("approval selected seed is invalid")
    if selection.get("selected_checkpoint_sha256") != ranked[0].get("checkpoint_sha256"):
        raise ProfessorApprovedPocError("approval selected checkpoint is invalid")
    _require_sha256(selection.get("selected_checkpoint_sha256"), "selected checkpoint")
    identity = deepcopy(value)
    actual = identity.pop("decision_sha256")
    if actual != _sha256(identity):
        raise ProfessorApprovedPocError("approval decision hash mismatch")
    return deepcopy(value)
