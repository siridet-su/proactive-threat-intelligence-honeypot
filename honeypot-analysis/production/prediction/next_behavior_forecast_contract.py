"""Strict additive v3 forecast boundary for the redesigned experiment.

Nothing in the active v2 predictor imports this module. It exists so future
offline evaluation and shadow integration cannot invent authority, present raw
scores as probabilities, or accept forged nested forecast payloads.
"""

from __future__ import annotations

import re
from copy import deepcopy
from datetime import datetime
from math import isfinite
from typing import Any, Dict, List, Mapping, Sequence

from production.prediction.next_behavior_contract import (
    AGREEMENT_STATUSES,
    CONFIDENCE_BUCKETS,
    ELAPSED_TIME_BUCKETS,
    LOGIN_OUTCOMES,
    MODEL_INPUT_SCHEMA_VERSION,
    REPETITION_BUCKETS,
    SESSION_AGE_BUCKETS,
    COMMAND_COUNT_BUCKETS,
    TACTIC_VOCABULARY,
    TARGET_CONTRACT_ID,
    TERMINAL_OUTCOME,
    TRUSTED_LABEL_SOURCES,
)
from production.utils.serialization import stable_id

FORECAST_SCHEMA_VERSION = "next_behavior_forecast.v3"
SCORE_SEMANTICS = "raw_model_scores_not_probabilities"
FORECAST_STATUSES = frozenset(
    {"predicted", "abstained", "insufficient_history", "model_unavailable"}
)
STATUS_REASON_CODES = frozenset(
    {
        "prediction_available",
        "coverage_policy_abstention",
        "no_trusted_behavior_phase",
        "artifact_missing",
        "artifact_hash_mismatch",
        "manifest_invalid",
        "input_schema_invalid",
        "model_load_failed",
        "inference_failed",
    }
)
STATUS_REASON_TEXT = {
    "prediction_available": "A frozen experimental model produced raw rank scores.",
    "coverage_policy_abstention": "The frozen coverage policy required abstention.",
    "no_trusted_behavior_phase": "No eligible trusted behavior phase was available.",
    "artifact_missing": "A required frozen model artifact is unavailable.",
    "artifact_hash_mismatch": "A frozen model artifact failed hash verification.",
    "manifest_invalid": "The frozen experiment manifest is invalid.",
    "input_schema_invalid": "The causal model input failed schema validation.",
    "model_load_failed": "The experimental model could not be loaded.",
    "inference_failed": "Experimental inference failed.",
}
STATUS_ALLOWED_REASON_CODES = {
    "predicted": frozenset({"prediction_available"}),
    "abstained": frozenset({"coverage_policy_abstention"}),
    "insufficient_history": frozenset(
        {"no_trusted_behavior_phase", "input_schema_invalid"}
    ),
    "model_unavailable": frozenset(
        {
            "artifact_missing",
            "artifact_hash_mismatch",
            "manifest_invalid",
            "model_load_failed",
            "inference_failed",
        }
    ),
}
DISAGREEMENT_STATUSES = frozenset(
    {"agree", "disagree", "not_comparable", "baseline_unavailable"}
)
FIXED_AUTHORITY = {
    "observed_evidence": False,
    "establishes_attacker_intent": False,
    "may_create_alert_alone": False,
    "may_support_hypothesis_claim": False,
    "may_select_guidance": False,
    "may_select_recommendation": False,
    "may_authorize_action": False,
    "automatic_execution": False,
    "display_semantics": "experimental_statistical_forecast_only",
}
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_TECHNIQUE = re.compile(r"^T[0-9]{4}(?:\.[0-9]{3})?$")
_EVIDENCE_ID = re.compile(r"^nbevidence_[0-9a-f]{64}$")
_SESSION_ID = re.compile(r"^nbsession_[0-9a-f]{64}$")
_FORECAST_ID = re.compile(r"^nextbehaviorforecast_[0-9a-f]{32}$")
_INPUT_HASH = re.compile(r"^nextbehaviorinput_[0-9a-f]{32}$")
_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")

_TOP_FIELDS = frozenset(
    {
        "schema_version",
        "forecast_id",
        "session_id",
        "observation_timestamp",
        "generated_at",
        "status",
        "status_reason",
        "model",
        "input",
        "output",
        "baseline",
        "disagreement",
        "authority",
        "audit",
    }
)
_MODEL_FIELDS = frozenset(
    {
        "role",
        "model_id",
        "model_family",
        "checkpoint_sha256",
        "artifact_sha256",
        "manifest_id",
        "code_commit",
        "device",
        "dtype",
    }
)
_INPUT_FIELDS = frozenset(
    {
        "schema_version",
        "target_contract_id",
        "max_sequence_length",
        "truncated",
        "phase_sequence",
        "session_context",
        "input_evidence_refs",
        "input_hash",
        "preprocessing_sha256",
        "vocabulary_sha256",
    }
)
_PHASE_FIELDS = frozenset(
    {
        "tactics",
        "techniques",
        "repetition_bucket",
        "elapsed_time_bucket",
        "label_provenance_sources",
        "label_confidence_buckets",
        "label_agreement_statuses",
        "audit_only_label_count",
        "evidence_refs",
    }
)
_CONTEXT_FIELDS = frozenset(
    {
        "login_outcome",
        "command_count_bucket",
        "session_age_bucket",
        "confirmed_transfer_observed",
    }
)
_OUTPUT_FIELDS = frozenset(
    {
        "ranked_tactics",
        "terminal_outcome",
        "prediction_set",
        "score_semantics",
        "calibration",
        "abstention",
    }
)
_RANK_FIELDS = frozenset(
    {"tactic", "raw_score", "rank", "calibrated_probability"}
)
_TERMINAL_FIELDS = frozenset(
    {"label", "raw_score", "calibrated_probability"}
)
_CALIBRATION_FIELDS = frozenset(
    {
        "status",
        "method",
        "mapping_sha256",
        "fit_partition_membership_sha256",
    }
)
_ABSTENTION_FIELDS = frozenset(
    {"abstained", "reason_code", "coverage_policy_id"}
)
_BASELINE_FIELDS = frozenset(
    {
        "status",
        "model_id",
        "artifact_sha256",
        "ranked_tactics",
        "terminal_outcome",
        "authority",
    }
)
_DISAGREEMENT_FIELDS = frozenset(
    {
        "status",
        "top_tactic_differs",
        "terminal_decision_differs",
        "semantics",
    }
)
_AUDIT_FIELDS = frozenset(
    {
        "historical_snapshot",
        "recomputed",
        "supersedes_forecast_id",
        "retention_policy_id",
        "redaction_policy_version",
        "failure_codes",
    }
)


class NextBehaviorForecastContractError(ValueError):
    """Raised when a v3 forecast violates semantics or authority."""


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _is_sha(value: Any, *, allow_empty: bool = False) -> bool:
    text = _clean(value).lower()
    return bool((allow_empty and not text) or _SHA256.fullmatch(text))


def _unexpected(
    value: Mapping[str, Any],
    allowed: frozenset[str],
    path: str,
) -> List[str]:
    return [
        f"{path}.{key} is not defined by the contract"
        for key in sorted(value)
        if key not in allowed
    ]


def _timestamp(value: Any, path: str, errors: List[str]) -> datetime | None:
    text = _clean(value)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        errors.append(f"{path} must be an ISO-8601 timestamp")
        return None
    if parsed.tzinfo is None:
        errors.append(f"{path} must include a timezone")
        return None
    return parsed


def _string_array(
    value: Any,
    path: str,
    errors: List[str],
    *,
    allowed: frozenset[str] | None = None,
    pattern: re.Pattern[str] | None = None,
) -> List[str]:
    if not isinstance(value, list):
        errors.append(f"{path} must be an array")
        return []
    output: List[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            errors.append(f"{path} must contain non-empty strings")
            continue
        text = item.strip()
        if text in output:
            errors.append(f"{path} must not contain duplicates")
        if allowed is not None and text not in allowed:
            errors.append(f"{path} contains an unsupported value")
        if pattern is not None and not pattern.fullmatch(text):
            errors.append(f"{path} contains a malformed identifier")
        output.append(text)
    return output


def bind_forecast_input(
    model_input: Mapping[str, Any],
    *,
    preprocessing_sha256: str,
    vocabulary_sha256: str,
) -> Dict[str, Any]:
    """Bind a causal input to frozen preprocessing and vocabulary artifacts."""

    if not _is_sha(preprocessing_sha256) or not _is_sha(vocabulary_sha256):
        raise NextBehaviorForecastContractError(
            "preprocessing and vocabulary hashes are required"
        )
    output = deepcopy(dict(model_input))
    output["preprocessing_sha256"] = _clean(preprocessing_sha256).lower()
    output["vocabulary_sha256"] = _clean(vocabulary_sha256).lower()
    errors = _validate_input(output)
    if errors:
        raise NextBehaviorForecastContractError("; ".join(errors))
    return output


def _validate_input(value: Any) -> List[str]:
    if not isinstance(value, dict):
        return ["input must be an object"]
    errors = _unexpected(value, _INPUT_FIELDS, "input")
    if value.get("schema_version") != MODEL_INPUT_SCHEMA_VERSION:
        errors.append(f"input.schema_version must be {MODEL_INPUT_SCHEMA_VERSION}")
    if value.get("target_contract_id") != TARGET_CONTRACT_ID:
        errors.append(f"input.target_contract_id must be {TARGET_CONTRACT_ID}")
    maximum = value.get("max_sequence_length")
    if isinstance(maximum, bool) or not isinstance(maximum, int) or maximum < 1:
        errors.append("input.max_sequence_length must be positive")
    if type(value.get("truncated")) is not bool:
        errors.append("input.truncated must be boolean")
    if not _is_sha(value.get("preprocessing_sha256")):
        errors.append("input.preprocessing_sha256 must be a SHA-256 digest")
    if not _is_sha(value.get("vocabulary_sha256")):
        errors.append("input.vocabulary_sha256 must be a SHA-256 digest")
    phases = value.get("phase_sequence")
    if not isinstance(phases, list) or not phases:
        errors.append("input.phase_sequence must be a non-empty array")
        phases = []
    elif isinstance(maximum, int) and len(phases) > maximum:
        errors.append("input.phase_sequence exceeds max_sequence_length")
    flattened_refs: List[str] = []
    for index, phase in enumerate(phases):
        path = f"input.phase_sequence[{index}]"
        if not isinstance(phase, dict):
            errors.append(f"{path} must be an object")
            continue
        errors.extend(_unexpected(phase, _PHASE_FIELDS, path))
        _string_array(
            phase.get("tactics"),
            f"{path}.tactics",
            errors,
            allowed=TACTIC_VOCABULARY,
        )
        _string_array(
            phase.get("techniques"),
            f"{path}.techniques",
            errors,
            pattern=_TECHNIQUE,
        )
        if _clean(phase.get("repetition_bucket")) not in REPETITION_BUCKETS:
            errors.append(f"{path}.repetition_bucket is invalid")
        if _clean(phase.get("elapsed_time_bucket")) not in ELAPSED_TIME_BUCKETS:
            errors.append(f"{path}.elapsed_time_bucket is invalid")
        _string_array(
            phase.get("label_provenance_sources"),
            f"{path}.label_provenance_sources",
            errors,
            allowed=TRUSTED_LABEL_SOURCES,
        )
        _string_array(
            phase.get("label_confidence_buckets"),
            f"{path}.label_confidence_buckets",
            errors,
            allowed=CONFIDENCE_BUCKETS,
        )
        _string_array(
            phase.get("label_agreement_statuses"),
            f"{path}.label_agreement_statuses",
            errors,
            allowed=AGREEMENT_STATUSES,
        )
        audit_count = phase.get("audit_only_label_count")
        if (
            isinstance(audit_count, bool)
            or not isinstance(audit_count, int)
            or audit_count < 0
        ):
            errors.append(f"{path}.audit_only_label_count must be non-negative")
        flattened_refs.extend(
            _string_array(
                phase.get("evidence_refs"),
                f"{path}.evidence_refs",
                errors,
                pattern=_EVIDENCE_ID,
            )
        )
    context = value.get("session_context")
    if not isinstance(context, dict):
        errors.append("input.session_context must be an object")
    else:
        errors.extend(_unexpected(context, _CONTEXT_FIELDS, "input.session_context"))
        if _clean(context.get("login_outcome")) not in LOGIN_OUTCOMES:
            errors.append("input.session_context.login_outcome is invalid")
        if _clean(context.get("command_count_bucket")) not in COMMAND_COUNT_BUCKETS:
            errors.append("input.session_context.command_count_bucket is invalid")
        if _clean(context.get("session_age_bucket")) not in SESSION_AGE_BUCKETS:
            errors.append("input.session_context.session_age_bucket is invalid")
        if type(context.get("confirmed_transfer_observed")) is not bool:
            errors.append(
                "input.session_context.confirmed_transfer_observed must be boolean"
            )
    top_refs = _string_array(
        value.get("input_evidence_refs"),
        "input.input_evidence_refs",
        errors,
        pattern=_EVIDENCE_ID,
    )
    if sorted(set(flattened_refs)) != sorted(set(top_refs)):
        errors.append("input.input_evidence_refs does not match phase evidence")
    if len(flattened_refs) != len(set(flattened_refs)):
        errors.append("input phase evidence references must not be reused")
    input_hash = _clean(value.get("input_hash"))
    if not _INPUT_HASH.fullmatch(input_hash):
        errors.append("input.input_hash is invalid")
    else:
        hash_payload = deepcopy(value)
        hash_payload.pop("input_hash", None)
        hash_payload.pop("preprocessing_sha256", None)
        hash_payload.pop("vocabulary_sha256", None)
        if stable_id("nextbehaviorinput", hash_payload) != input_hash:
            errors.append("input.input_hash does not match the causal input")
    return errors


def _validate_model(value: Any) -> List[str]:
    if not isinstance(value, dict):
        return ["model must be an object"]
    errors = _unexpected(value, _MODEL_FIELDS, "model")
    if value.get("role") != "experimental_primary":
        errors.append("model.role must be experimental_primary")
    family = _clean(value.get("model_family"))
    if family != "small_causal_transformer":
        errors.append("model.model_family must be small_causal_transformer")
    for field in ("model_id", "manifest_id", "code_commit"):
        if not _clean(value.get(field)):
            errors.append(f"model.{field} is required")
    if not _is_sha(value.get("checkpoint_sha256")):
        errors.append("model.checkpoint_sha256 must be a SHA-256 digest")
    if not _is_sha(value.get("artifact_sha256"), allow_empty=True):
        errors.append("model.artifact_sha256 must be empty or a SHA-256 digest")
    if value.get("device") != "cpu":
        errors.append("model.device must be cpu")
    if value.get("dtype") != "float32":
        errors.append("model.dtype must be float32")
    return errors


def _raw_score(value: Any, path: str, errors: List[str]) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        errors.append(f"{path} must be a finite number")
        return None
    number = float(value)
    if not isfinite(number):
        errors.append(f"{path} must be a finite number")
        return None
    return number


def _validate_ranked(
    value: Any,
    path: str,
    errors: List[str],
    *,
    calibrated: bool,
) -> None:
    if not isinstance(value, list):
        errors.append(f"{path} must be an array")
        return
    seen_tactics: set[str] = set()
    previous_score: float | None = None
    for index, item in enumerate(value):
        item_path = f"{path}[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{item_path} must be an object")
            continue
        errors.extend(_unexpected(item, _RANK_FIELDS, item_path))
        tactic = _clean(item.get("tactic"))
        if tactic not in TACTIC_VOCABULARY or tactic in seen_tactics:
            errors.append(f"{item_path}.tactic is invalid or duplicated")
        seen_tactics.add(tactic)
        rank = item.get("rank")
        if isinstance(rank, bool) or not isinstance(rank, int) or rank != index + 1:
            errors.append(f"{item_path}.rank must match list order")
        score = _raw_score(item.get("raw_score"), f"{item_path}.raw_score", errors)
        if score is not None:
            if previous_score is not None and score > previous_score:
                errors.append(f"{path} must be ordered by descending raw_score")
            previous_score = score
        probability = item.get("calibrated_probability")
        if calibrated:
            number = _raw_score(
                probability,
                f"{item_path}.calibrated_probability",
                errors,
            )
            if number is not None and not 0.0 <= number <= 1.0:
                errors.append(
                    f"{item_path}.calibrated_probability must be in [0, 1]"
                )
        elif probability is not None:
            errors.append(
                f"{item_path}.calibrated_probability must be null when uncalibrated"
            )


def _validate_terminal(
    value: Any,
    path: str,
    errors: List[str],
    *,
    calibrated: bool,
    require_score: bool,
) -> None:
    if not isinstance(value, dict):
        errors.append(f"{path} must be an object")
        return
    errors.extend(_unexpected(value, _TERMINAL_FIELDS, path))
    if value.get("label") != TERMINAL_OUTCOME:
        errors.append(f"{path}.label is invalid")
    raw_score = value.get("raw_score")
    if require_score:
        _raw_score(raw_score, f"{path}.raw_score", errors)
    elif raw_score is not None:
        errors.append(f"{path}.raw_score must be null without a prediction")
    probability = value.get("calibrated_probability")
    if calibrated and require_score:
        number = _raw_score(
            probability,
            f"{path}.calibrated_probability",
            errors,
        )
        if number is not None and not 0.0 <= number <= 1.0:
            errors.append(f"{path}.calibrated_probability must be in [0, 1]")
    elif probability is not None:
        errors.append(
            f"{path}.calibrated_probability must be null when uncalibrated"
        )


def _validate_output(value: Any, status: str) -> List[str]:
    if not isinstance(value, dict):
        return ["output must be an object"]
    errors = _unexpected(value, _OUTPUT_FIELDS, "output")
    calibration = value.get("calibration")
    calibrated = False
    if not isinstance(calibration, dict):
        errors.append("output.calibration must be an object")
        calibration = {}
    else:
        errors.extend(
            _unexpected(calibration, _CALIBRATION_FIELDS, "output.calibration")
        )
        calibration_status = _clean(calibration.get("status"))
        if calibration_status not in {"not_implemented", "valid", "invalid"}:
            errors.append("output.calibration.status is invalid")
        calibrated = calibration_status == "valid"
        if calibrated:
            for field in (
                "method",
                "mapping_sha256",
                "fit_partition_membership_sha256",
            ):
                if field == "method":
                    if not _clean(calibration.get(field)):
                        errors.append(f"output.calibration.{field} is required")
                elif not _is_sha(calibration.get(field)):
                    errors.append(
                        f"output.calibration.{field} must be a SHA-256 digest"
                    )
        elif any(
            _clean(calibration.get(field))
            for field in (
                "method",
                "mapping_sha256",
                "fit_partition_membership_sha256",
            )
        ):
            errors.append("uncalibrated output cannot name a calibration mapping")
    ranked = value.get("ranked_tactics")
    _validate_ranked(
        ranked,
        "output.ranked_tactics",
        errors,
        calibrated=calibrated,
    )
    _validate_terminal(
        value.get("terminal_outcome"),
        "output.terminal_outcome",
        errors,
        calibrated=calibrated,
        require_score=status == "predicted",
    )
    prediction_set = _string_array(
        value.get("prediction_set"),
        "output.prediction_set",
        errors,
        allowed=TACTIC_VOCABULARY | frozenset({TERMINAL_OUTCOME}),
    )
    if prediction_set and not calibrated:
        errors.append("output.prediction_set requires valid calibration")
    if value.get("score_semantics") != SCORE_SEMANTICS:
        errors.append(f"output.score_semantics must be {SCORE_SEMANTICS}")
    abstention = value.get("abstention")
    if not isinstance(abstention, dict):
        errors.append("output.abstention must be an object")
        abstained = None
    else:
        errors.extend(
            _unexpected(abstention, _ABSTENTION_FIELDS, "output.abstention")
        )
        abstained = abstention.get("abstained")
        if type(abstained) is not bool:
            errors.append("output.abstention.abstained must be boolean")
        if abstained and not _clean(abstention.get("reason_code")):
            errors.append("output.abstention.reason_code is required")
    if status == "predicted":
        if not isinstance(ranked, list) or not ranked:
            errors.append("predicted output requires ranked_tactics")
        if abstained is not False:
            errors.append("predicted output cannot be abstained")
    else:
        if isinstance(ranked, list) and ranked:
            errors.append(f"{status} output cannot contain ranked_tactics")
        if abstained is not True:
            errors.append(f"{status} output must be abstained")
    return errors


def _validate_baseline(value: Any) -> List[str]:
    if not isinstance(value, dict):
        return ["baseline must be an object"]
    errors = _unexpected(value, _BASELINE_FIELDS, "baseline")
    status = _clean(value.get("status"))
    if status not in {"available", "abstained", "model_unavailable"}:
        errors.append("baseline.status is invalid")
    if not _clean(value.get("model_id")):
        errors.append("baseline.model_id is required")
    if status == "available" and not _is_sha(value.get("artifact_sha256")):
        errors.append("baseline.artifact_sha256 is required when available")
    if status != "available" and not _is_sha(
        value.get("artifact_sha256"), allow_empty=True
    ):
        errors.append("baseline.artifact_sha256 is malformed")
    ranked = value.get("ranked_tactics")
    terminal = value.get("terminal_outcome")
    if status == "available":
        _validate_ranked(
            ranked,
            "baseline.ranked_tactics",
            errors,
            calibrated=False,
        )
        if not isinstance(ranked, list) or not ranked:
            errors.append("available baseline requires ranked_tactics")
        _validate_terminal(
            terminal,
            "baseline.terminal_outcome",
            errors,
            calibrated=False,
            require_score=True,
        )
    elif ranked not in ([], None) or terminal not in ({}, None):
        errors.append("unavailable baseline cannot contain predictions")
    if value.get("authority") != "interpretable_disagreement_reference_only":
        errors.append("baseline.authority is invalid")
    return errors


def validate_next_behavior_forecast(value: Any) -> List[str]:
    """Return stable validation errors for a complete v3 forecast payload."""

    if not isinstance(value, dict):
        return ["forecast must be an object"]
    errors = _unexpected(value, _TOP_FIELDS, "$")
    if value.get("schema_version") != FORECAST_SCHEMA_VERSION:
        errors.append(f"schema_version must be {FORECAST_SCHEMA_VERSION}")
    if not _FORECAST_ID.fullmatch(_clean(value.get("forecast_id"))):
        errors.append("forecast_id is invalid")
    if not _SESSION_ID.fullmatch(_clean(value.get("session_id"))):
        errors.append("session_id is invalid")
    observed_at = _timestamp(
        value.get("observation_timestamp"),
        "observation_timestamp",
        errors,
    )
    generated_at = _timestamp(value.get("generated_at"), "generated_at", errors)
    if observed_at and generated_at and generated_at < observed_at:
        errors.append("generated_at cannot precede observation_timestamp")
    status = _clean(value.get("status"))
    if status not in FORECAST_STATUSES:
        errors.append("status is invalid")
    reason = value.get("status_reason")
    if not isinstance(reason, dict) or set(reason) != {"code", "text"}:
        errors.append("status_reason must contain exactly code and text")
    else:
        if _clean(reason.get("code")) not in STATUS_REASON_CODES:
            errors.append("status_reason.code is invalid")
        code = _clean(reason.get("code"))
        if code in STATUS_REASON_TEXT and reason.get("text") != STATUS_REASON_TEXT[code]:
            errors.append("status_reason.text must match the stable reason code")
        if status in STATUS_ALLOWED_REASON_CODES and code not in (
            STATUS_ALLOWED_REASON_CODES[status]
        ):
            errors.append("status_reason.code contradicts status")
    errors.extend(_validate_model(value.get("model")))
    errors.extend(_validate_input(value.get("input")))
    errors.extend(_validate_output(value.get("output"), status))
    errors.extend(_validate_baseline(value.get("baseline")))
    disagreement = value.get("disagreement")
    if not isinstance(disagreement, dict):
        errors.append("disagreement must be an object")
    else:
        errors.extend(
            _unexpected(disagreement, _DISAGREEMENT_FIELDS, "disagreement")
        )
        if _clean(disagreement.get("status")) not in DISAGREEMENT_STATUSES:
            errors.append("disagreement.status is invalid")
        for field in ("top_tactic_differs", "terminal_decision_differs"):
            if type(disagreement.get(field)) is not bool:
                errors.append(f"disagreement.{field} must be boolean")
        if (
            disagreement.get("semantics")
            != "diagnostic_only_no_score_blending_no_routing"
        ):
            errors.append("disagreement.semantics is invalid")
    if value.get("authority") != FIXED_AUTHORITY:
        errors.append("authority must equal the fixed non-authoritative contract")
    audit = value.get("audit")
    if not isinstance(audit, dict):
        errors.append("audit must be an object")
    else:
        errors.extend(_unexpected(audit, _AUDIT_FIELDS, "audit"))
        for field in ("historical_snapshot", "recomputed"):
            if type(audit.get(field)) is not bool:
                errors.append(f"audit.{field} must be boolean")
        for field in (
            "supersedes_forecast_id",
            "retention_policy_id",
            "redaction_policy_version",
        ):
            if not isinstance(audit.get(field), str):
                errors.append(f"audit.{field} must be a string")
            elif audit.get(field) and not _SAFE_IDENTIFIER.fullmatch(
                audit.get(field)
            ):
                errors.append(f"audit.{field} is not a safe identifier")
        if audit.get("recomputed") and not _FORECAST_ID.fullmatch(
            _clean(audit.get("supersedes_forecast_id"))
        ):
            errors.append(
                "audit.supersedes_forecast_id is required for reevaluation"
            )
        failure_codes = audit.get("failure_codes")
        if not isinstance(failure_codes, list) or not all(
            isinstance(item, str) and item in STATUS_REASON_CODES
            for item in failure_codes
        ):
            errors.append("audit.failure_codes contains an invalid code")
    return errors


def require_valid_next_behavior_forecast(value: Any) -> Dict[str, Any]:
    errors = validate_next_behavior_forecast(value)
    if errors:
        raise NextBehaviorForecastContractError("; ".join(errors))
    return deepcopy(value)


def forecast_id_for(
    *,
    session_id: str,
    observation_timestamp: str,
    model_id: str,
    input_hash: str,
) -> str:
    return stable_id(
        "nextbehaviorforecast",
        {
            "session_id": session_id,
            "observation_timestamp": observation_timestamp,
            "model_id": model_id,
            "input_hash": input_hash,
        },
    )
