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
from pathlib import Path
from typing import Any, Dict, Mapping, Sequence

from production.prediction.next_behavior_calibration import (
    require_valid_calibration_mapping,
)

from production.utils.serialization import stable_json


STATUS = "PROFESSOR_APPROVED_POC_EVALUATION"
SCHEMA_VERSION = "next_behavior_professor_approved_poc_decision.v1"
ORIGINAL_CLOSURE_COMMIT = "3d3fca68a814ce6dd5b206bc008f9f79216ffea7"
DECLARED_RULE = (
    "highest_selection_macro_f1_then_highest_selection_balanced_accuracy_"
    "then_highest_terminal_f1_then_lowest_p95_latency_then_lowest_seed"
)
PRETEST_MANIFEST_SCHEMA_VERSION = "next_behavior_professor_approved_pretest_manifest.v1"
PRETEST_MANIFEST_STATUS = "frozen_pre_test"
_REQUIRED_AUTHORITY_RESTRICTIONS = {
    "prediction_may_authorize_alerts": False,
    "prediction_may_authorize_hypotheses": False,
    "prediction_may_authorize_guidance": False,
    "prediction_may_authorize_recommendations": False,
    "prediction_may_authorize_blocking": False,
    "prediction_may_authorize_response_actions": False,
    "observed_command_derived_evidence_remains_authoritative": True,
}


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


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _valid_artifact_descriptor(value: Any, *, name: str, allow_test: bool = False) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ProfessorApprovedPocError(f"{name} descriptor must be an object")
    required = {"path", "sha256"}
    if set(value) - (required | {"semantic_sha256", "membership_sha256", "role", "kind"}):
        raise ProfessorApprovedPocError(f"{name} descriptor has unknown fields")
    if not required <= set(value):
        raise ProfessorApprovedPocError(f"{name} descriptor is incomplete")
    path = value.get("path")
    if not isinstance(path, str) or not path:
        raise ProfessorApprovedPocError(f"{name} path is invalid")
    result = deepcopy(dict(value))
    result["sha256"] = _require_sha256(result["sha256"], f"{name}.sha256")
    for field in ("semantic_sha256", "membership_sha256"):
        if field in result:
            result[field] = _require_sha256(result[field], f"{name}.{field}")
    if not allow_test and result.get("role") == "test":
        raise ProfessorApprovedPocError("test descriptor may only occur in final_test")
    return result


def build_professor_approved_pretest_manifest(
    *,
    decision: Mapping[str, Any],
    calibration: Mapping[str, Any],
    decision_policy: Mapping[str, Any],
    code_commit: str,
    artifacts: Mapping[str, Mapping[str, Any]],
    final_test: Mapping[str, Any],
    environment: Mapping[str, Any],
) -> Dict[str, Any]:
    """Create a strict additive freeze without reading Final Test payloads.

    ``final_test`` is a descriptor only.  Its bytes may be hash-verified by a
    caller but are never parsed or semantically inspected by this constructor.
    """
    approved = require_valid_professor_approved_decision(dict(decision))
    try:
        valid_calibration = require_valid_calibration_mapping(dict(calibration))
    except Exception as exc:
        raise ProfessorApprovedPocError("calibration mapping is invalid") from exc
    if valid_calibration.get("status") != "valid":
        raise ProfessorApprovedPocError("calibration mapping is not valid")
    if not isinstance(decision_policy, Mapping):
        raise ProfessorApprovedPocError("decision policy must be an object")
    policy = deepcopy(dict(decision_policy))
    expected_policy = {
        "schema_version": "next_behavior_professor_approved_decision_policy.v1",
        "status": "frozen_pre_test",
        "score_semantics": "global_temperature_sigmoid_probabilities",
        "tactic_threshold": 0.5,
        "terminal_threshold": 0.5,
        "terminal_precedence": True,
        "empty_nonterminal_rule": "highest_ranked_tactic",
        "abstention": {"score_based": False, "asset_or_schema_failure": True, "fallback_model": None},
        "objective": "calibration_binary_log_loss_only; thresholds_fixed_by_probability_semantics",
    }
    for field, expected in expected_policy.items():
        if policy.get(field) != expected:
            raise ProfessorApprovedPocError(f"decision policy {field} is not frozen")
    policy_hash = policy.pop("sha256", None)
    if policy_hash != _sha256(policy):
        raise ProfessorApprovedPocError("decision policy hash mismatch")
    if not isinstance(artifacts, Mapping):
        raise ProfessorApprovedPocError("artifacts must be an object")
    required_artifacts = {
        "original_selection_blocked_receipt", "selected_checkpoint", "model_spec",
        "vocabulary", "preprocessing_contract", "hard_backoff_vomm",
        "partition_manifest", "train_receipt", "selection_receipt",
        "calibration_receipt", "final_receipt", "environment_receipt",
        "evaluator_source", "metrics_source", "ledger_contract",
    }
    if set(artifacts) != required_artifacts:
        raise ProfessorApprovedPocError("pre-test artifacts do not match required bindings")
    bound = {
        name: _valid_artifact_descriptor(value, name=name)
        for name, value in artifacts.items()
    }
    selected = bound["selected_checkpoint"]
    if selected["sha256"] != approved["selection"]["selected_checkpoint_sha256"]:
        raise ProfessorApprovedPocError("selected checkpoint disagrees with approval")
    if valid_calibration["checkpoint_sha256"] != selected["sha256"]:
        raise ProfessorApprovedPocError("calibration checkpoint binding mismatch")
    if valid_calibration["vocabulary_sha256"] != bound["vocabulary"].get("semantic_sha256"):
        raise ProfessorApprovedPocError("calibration vocabulary binding mismatch")
    if valid_calibration["preprocessing_sha256"] != bound["preprocessing_contract"].get("semantic_sha256"):
        raise ProfessorApprovedPocError("calibration preprocessing binding mismatch")
    test = _valid_artifact_descriptor(final_test, name="final_test", allow_test=True)
    if test.get("role") != "test" or "membership_sha256" not in test:
        raise ProfessorApprovedPocError("final_test must be a sealed test descriptor")
    if not isinstance(environment, Mapping) or set(environment) != {"python", "torch", "cpu", "receipt_sha256"}:
        raise ProfessorApprovedPocError("environment receipt is incomplete")
    env = deepcopy(dict(environment))
    env["receipt_sha256"] = _require_sha256(env["receipt_sha256"], "environment.receipt_sha256")
    restriction = deepcopy(_REQUIRED_AUTHORITY_RESTRICTIONS)
    result: Dict[str, Any] = {
        "schema_version": PRETEST_MANIFEST_SCHEMA_VERSION,
        "status": PRETEST_MANIFEST_STATUS,
        "test_opened": False,
        "decision": approved,
        "calibration": valid_calibration,
        "decision_policy": deepcopy(decision_policy),
        "code_commit": str(code_commit),
        "artifacts": bound,
        "final_test": test,
        "environment": env,
        "authority_restrictions": restriction,
    }
    result["manifest_sha256"] = _sha256(result)
    return result


def require_valid_professor_approved_pretest_manifest(value: Any) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise ProfessorApprovedPocError("pre-test manifest must be an object")
    required = {
        "schema_version", "status", "test_opened", "decision", "calibration",
        "decision_policy", "code_commit", "artifacts", "final_test", "environment",
        "authority_restrictions", "manifest_sha256",
    }
    if set(value) != required:
        raise ProfessorApprovedPocError("pre-test manifest fields are invalid")
    if value["schema_version"] != PRETEST_MANIFEST_SCHEMA_VERSION or value["status"] != PRETEST_MANIFEST_STATUS or value["test_opened"] is not False:
        raise ProfessorApprovedPocError("pre-test manifest is not sealed")
    identity = deepcopy(value)
    actual = identity.pop("manifest_sha256")
    if actual != _sha256(identity):
        raise ProfessorApprovedPocError("pre-test manifest hash mismatch")
    # Rebuilding performs all semantic cross-binding checks without inspecting
    # the Final payload.
    rebuilt = build_professor_approved_pretest_manifest(
        decision=value["decision"], calibration=value["calibration"],
        decision_policy=value["decision_policy"], code_commit=value["code_commit"],
        artifacts=value["artifacts"], final_test=value["final_test"],
        environment=value["environment"],
    )
    if rebuilt != value:
        raise ProfessorApprovedPocError("pre-test manifest is noncanonical")
    if value["authority_restrictions"] != _REQUIRED_AUTHORITY_RESTRICTIONS:
        raise ProfessorApprovedPocError("authority restrictions are invalid")
    return deepcopy(value)


def verify_professor_approved_pretest_artifacts(
    manifest: Mapping[str, Any], *, verify_final_test_bytes: bool = False
) -> Dict[str, Any]:
    """Hash-check immutable artifacts without parsing Final Test by default."""
    frozen = require_valid_professor_approved_pretest_manifest(dict(manifest))
    descriptors = dict(frozen["artifacts"])
    if verify_final_test_bytes:
        descriptors["final_test"] = frozen["final_test"]
    verified: Dict[str, Any] = {}
    for name, descriptor in descriptors.items():
        path = Path(descriptor["path"])
        if not path.is_file():
            raise ProfessorApprovedPocError(f"pre-test artifact missing: {name}")
        actual = _file_sha256(path)
        if actual != descriptor["sha256"]:
            raise ProfessorApprovedPocError(f"pre-test artifact hash mismatch: {name}")
        verified[name] = {"path": str(path), "sha256": actual}
    return {"status": "verified_pre_test", "test_opened": False, "artifacts": verified}
