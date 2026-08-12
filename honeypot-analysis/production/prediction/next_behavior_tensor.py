"""Deterministic tensor contract shared by offline and future live paths.

The adapter returns plain integer arrays so it can be tested without NumPy or
Torch. A future model module may convert these arrays to framework tensors, but
must not reimplement preprocessing or vocabulary handling.
"""

from __future__ import annotations

import hashlib
import re
from copy import deepcopy
from typing import Any, Dict, Iterable, List, Mapping, Sequence

from production.prediction.next_behavior_contract import (
    AGREEMENT_STATUSES,
    CONFIDENCE_BUCKETS,
    ELAPSED_TIME_BUCKETS,
    MODEL_INPUT_SCHEMA_VERSION,
    REPETITION_BUCKETS,
    TACTIC_VOCABULARY,
    TARGET_CONTRACT_ID,
    TERMINAL_OUTCOME,
    TRUSTED_LABEL_SOURCES,
)
from production.prediction.next_behavior_forecast_contract import (
    bind_forecast_input,
)
from production.prediction.next_behavior_preprocessing import (
    build_live_model_input,
)
from production.utils.serialization import stable_id, stable_json

VOCABULARY_SCHEMA_VERSION = "next_behavior_vocabulary.v2"
TENSOR_SCHEMA_VERSION = "next_behavior_tensor_input.v2"
TARGET_TENSOR_SCHEMA_VERSION = "next_behavior_target_tensor.v2"
UNKNOWN_TECHNIQUE = "<UNK>"
AUDIT_COUNT_BUCKETS = ("0", "1", "2-5", "6+")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_TECHNIQUE = re.compile(r"^T[0-9]{4}(?:\.[0-9]{3})?$")
_VOCABULARY_FIELDS = frozenset(
    {
        "schema_version",
        "vocabulary_id",
        "target_contract_id",
        "input_schema_version",
        "tactics",
        "techniques",
        "label_sources",
        "confidence_buckets",
        "agreement_statuses",
        "repetition_buckets",
        "elapsed_time_buckets",
        "audit_count_buckets",
        "login_outcomes",
        "command_count_buckets",
        "session_age_buckets",
        "maximum_sequence_length",
        "terminal_outcome",
        "preprocessing_sha256",
        "training_membership_sha256",
    }
)


class NextBehaviorTensorError(ValueError):
    """Raised when a vocabulary or tensor input is inconsistent."""


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _is_sha(value: Any) -> bool:
    return bool(_SHA256.fullmatch(_clean(value).lower()))


def _ordered_unique(values: Iterable[Any]) -> List[str]:
    return sorted({_clean(value) for value in values if _clean(value)})


def vocabulary_sha256(value: Mapping[str, Any]) -> str:
    validated = require_valid_vocabulary(value)
    return hashlib.sha256(stable_json(validated).encode("utf-8")).hexdigest()


def build_vocabulary(
    training_inputs: Sequence[Mapping[str, Any]],
    *,
    preprocessing_sha256: str,
    training_membership_sha256: str,
) -> Dict[str, Any]:
    """Build technique vocabulary only from purpose-scoped training inputs."""

    if not _is_sha(preprocessing_sha256):
        raise NextBehaviorTensorError("preprocessing_sha256 is invalid")
    if not _is_sha(training_membership_sha256):
        raise NextBehaviorTensorError("training_membership_sha256 is invalid")
    if not training_inputs:
        raise NextBehaviorTensorError("training inputs must not be empty")
    techniques: set[str] = set()
    for input_index, model_input in enumerate(training_inputs):
        try:
            validated_input = bind_forecast_input(
                model_input,
                preprocessing_sha256=preprocessing_sha256,
                vocabulary_sha256="0" * 64,
            )
        except Exception as exc:
            raise NextBehaviorTensorError(
                f"training_inputs[{input_index}] is invalid"
            ) from exc
        phases = validated_input["phase_sequence"]
        for phase in phases:
            for technique in phase.get("techniques") or []:
                text = _clean(technique).upper()
                if not _TECHNIQUE.fullmatch(text):
                    raise NextBehaviorTensorError(
                        "training input contains an invalid technique"
                    )
                techniques.add(text)
    value: Dict[str, Any] = {
        "schema_version": VOCABULARY_SCHEMA_VERSION,
        "target_contract_id": TARGET_CONTRACT_ID,
        "input_schema_version": MODEL_INPUT_SCHEMA_VERSION,
        "tactics": sorted(TACTIC_VOCABULARY),
        "techniques": [UNKNOWN_TECHNIQUE, *sorted(techniques)],
        "label_sources": sorted(TRUSTED_LABEL_SOURCES),
        "confidence_buckets": sorted(CONFIDENCE_BUCKETS),
        "agreement_statuses": sorted(AGREEMENT_STATUSES),
        "repetition_buckets": sorted(REPETITION_BUCKETS),
        "elapsed_time_buckets": sorted(ELAPSED_TIME_BUCKETS),
        "audit_count_buckets": list(AUDIT_COUNT_BUCKETS),
        "login_outcomes": ["failed", "success", "unknown"],
        "command_count_buckets": ["0", "1", "2-5", "6-20", "21+"],
        "session_age_buckets": [
            "under_10s",
            "10_to_60s",
            "1_to_5m",
            "over_5m",
            "unknown",
        ],
        "maximum_sequence_length": 8,
        "terminal_outcome": TERMINAL_OUTCOME,
        "preprocessing_sha256": _clean(preprocessing_sha256).lower(),
        "training_membership_sha256": _clean(training_membership_sha256).lower(),
    }
    value["vocabulary_id"] = stable_id("nextbehaviorvocabulary", value)
    return require_valid_vocabulary(value)


def validate_vocabulary(value: Any) -> List[str]:
    if not isinstance(value, dict):
        return ["vocabulary must be an object"]
    errors = [
        f"$.{field} is not defined by the vocabulary contract"
        for field in sorted(set(value) - _VOCABULARY_FIELDS)
    ]
    if value.get("schema_version") != VOCABULARY_SCHEMA_VERSION:
        errors.append(f"schema_version must be {VOCABULARY_SCHEMA_VERSION}")
    if value.get("target_contract_id") != TARGET_CONTRACT_ID:
        errors.append(f"target_contract_id must be {TARGET_CONTRACT_ID}")
    if value.get("input_schema_version") != MODEL_INPUT_SCHEMA_VERSION:
        errors.append(
            f"input_schema_version must be {MODEL_INPUT_SCHEMA_VERSION}"
        )
    exact_arrays = {
        "tactics": sorted(TACTIC_VOCABULARY),
        "label_sources": sorted(TRUSTED_LABEL_SOURCES),
        "confidence_buckets": sorted(CONFIDENCE_BUCKETS),
        "agreement_statuses": sorted(AGREEMENT_STATUSES),
        "repetition_buckets": sorted(REPETITION_BUCKETS),
        "elapsed_time_buckets": sorted(ELAPSED_TIME_BUCKETS),
        "audit_count_buckets": list(AUDIT_COUNT_BUCKETS),
        "login_outcomes": ["failed", "success", "unknown"],
        "command_count_buckets": ["0", "1", "2-5", "6-20", "21+"],
        "session_age_buckets": [
            "under_10s",
            "10_to_60s",
            "1_to_5m",
            "over_5m",
            "unknown",
        ],
    }
    for field, expected in exact_arrays.items():
        if value.get(field) != expected:
            errors.append(f"{field} does not match the frozen ordered vocabulary")
    techniques = value.get("techniques")
    if (
        not isinstance(techniques, list)
        or not techniques
        or techniques[0] != UNKNOWN_TECHNIQUE
        or techniques[1:] != sorted(set(techniques[1:]))
        or any(not _TECHNIQUE.fullmatch(_clean(item)) for item in techniques[1:])
    ):
        errors.append("techniques is not a canonical training-only vocabulary")
    if value.get("terminal_outcome") != TERMINAL_OUTCOME:
        errors.append(f"terminal_outcome must be {TERMINAL_OUTCOME}")
    if value.get("maximum_sequence_length") != 8:
        errors.append("maximum_sequence_length must be 8")
    for field in ("preprocessing_sha256", "training_membership_sha256"):
        if not _is_sha(value.get(field)):
            errors.append(f"{field} must be a SHA-256 digest")
    vocabulary_id = _clean(value.get("vocabulary_id"))
    identity = deepcopy(value)
    identity.pop("vocabulary_id", None)
    if stable_id("nextbehaviorvocabulary", identity) != vocabulary_id:
        errors.append("vocabulary_id does not match vocabulary content")
    return errors


def require_valid_vocabulary(value: Any) -> Dict[str, Any]:
    errors = validate_vocabulary(value)
    if errors:
        raise NextBehaviorTensorError("; ".join(errors))
    return deepcopy(value)


def _multi_hot(values: Iterable[Any], vocabulary: Sequence[str]) -> List[int]:
    selected = {_clean(value) for value in values if _clean(value)}
    return [1 if token in selected else 0 for token in vocabulary]


def _technique_multi_hot(
    values: Iterable[Any],
    vocabulary: Sequence[str],
) -> List[int]:
    known = set(vocabulary[1:])
    selected = {_clean(value).upper() for value in values if _clean(value)}
    unknown = bool(selected - known)
    return [
        1 if (token == UNKNOWN_TECHNIQUE and unknown) or token in selected else 0
        for token in vocabulary
    ]


def _categorical_index(value: Any, vocabulary: Sequence[str]) -> int:
    text = _clean(value)
    try:
        return vocabulary.index(text) + 1
    except ValueError as exc:
        raise NextBehaviorTensorError(
            f"categorical value is outside vocabulary: {text}"
        ) from exc


def _audit_bucket(value: Any) -> str:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise NextBehaviorTensorError("audit-only label count is invalid")
    if value == 0:
        return "0"
    if value == 1:
        return "1"
    if value <= 5:
        return "2-5"
    return "6+"


def tensorize_model_input(
    model_input: Mapping[str, Any],
    vocabulary: Mapping[str, Any],
) -> Dict[str, Any]:
    """Encode one input through the frozen vocabulary and padding contract."""

    vocab = require_valid_vocabulary(vocabulary)
    vocab_sha = vocabulary_sha256(vocab)
    bound_input = bind_forecast_input(
        model_input,
        preprocessing_sha256=vocab["preprocessing_sha256"],
        vocabulary_sha256=vocab_sha,
    )
    maximum = int(bound_input["max_sequence_length"])
    if maximum != vocab["maximum_sequence_length"]:
        raise NextBehaviorTensorError(
            "input maximum sequence length does not match vocabulary"
        )
    phases = bound_input["phase_sequence"]
    padding = maximum - len(phases)
    tactics = vocab["tactics"]
    techniques = vocab["techniques"]
    sources = vocab["label_sources"]
    confidence = vocab["confidence_buckets"]
    agreements = vocab["agreement_statuses"]
    repetitions = vocab["repetition_buckets"]
    elapsed = vocab["elapsed_time_buckets"]

    tactic_rows = [[0] * len(tactics) for _ in range(padding)]
    technique_rows = [[0] * len(techniques) for _ in range(padding)]
    source_rows = [[0] * len(sources) for _ in range(padding)]
    confidence_rows = [[0] * len(confidence) for _ in range(padding)]
    agreement_rows = [[0] * len(agreements) for _ in range(padding)]
    repetition_indices = [0] * padding
    elapsed_indices = [0] * padding
    audit_indices = [0] * padding
    for phase in phases:
        tactic_rows.append(_multi_hot(phase["tactics"], tactics))
        technique_rows.append(
            _technique_multi_hot(phase["techniques"], techniques)
        )
        source_rows.append(
            _multi_hot(phase["label_provenance_sources"], sources)
        )
        confidence_rows.append(
            _multi_hot(phase["label_confidence_buckets"], confidence)
        )
        agreement_rows.append(
            _multi_hot(phase["label_agreement_statuses"], agreements)
        )
        repetition_indices.append(
            _categorical_index(phase["repetition_bucket"], repetitions)
        )
        elapsed_indices.append(
            _categorical_index(phase["elapsed_time_bucket"], elapsed)
        )
        audit_indices.append(
            _categorical_index(
                _audit_bucket(phase["audit_only_label_count"]),
                vocab["audit_count_buckets"],
            )
        )
    context = bound_input["session_context"]
    tensor: Dict[str, Any] = {
        "schema_version": TENSOR_SCHEMA_VERSION,
        "target_contract_id": TARGET_CONTRACT_ID,
        "vocabulary_id": vocab["vocabulary_id"],
        "vocabulary_sha256": vocab_sha,
        "preprocessing_sha256": vocab["preprocessing_sha256"],
        "source_input_hash": bound_input["input_hash"],
        "sequence_length": len(phases),
        "maximum_sequence_length": maximum,
        "attention_mask": [0] * padding + [1] * len(phases),
        "phase_tactic_multi_hot": tactic_rows,
        "phase_technique_multi_hot": technique_rows,
        "phase_source_multi_hot": source_rows,
        "phase_confidence_multi_hot": confidence_rows,
        "phase_agreement_multi_hot": agreement_rows,
        "phase_repetition_index": repetition_indices,
        "phase_elapsed_time_index": elapsed_indices,
        "phase_audit_count_index": audit_indices,
        "context_login_outcome_index": _categorical_index(
            context["login_outcome"],
            vocab["login_outcomes"],
        ),
        "context_command_count_index": _categorical_index(
            context["command_count_bucket"],
            vocab["command_count_buckets"],
        ),
        "context_session_age_index": _categorical_index(
            context["session_age_bucket"],
            vocab["session_age_buckets"],
        ),
        "context_confirmed_transfer": int(
            context["confirmed_transfer_observed"]
        ),
    }
    tensor_payload = deepcopy(tensor)
    tensor_payload.pop("source_input_hash")
    tensor["tensor_hash"] = stable_id("nextbehaviortensor", tensor_payload)
    return tensor


def tensorize_live_session(
    session_record: Mapping[str, Any],
    vocabulary: Mapping[str, Any],
    *,
    max_sequence_length: int = 8,
) -> Dict[str, Any]:
    return tensorize_model_input(
        build_live_model_input(
            session_record,
            max_sequence_length=max_sequence_length,
        ),
        vocabulary,
    )


def tensorize_example(
    example: Mapping[str, Any],
    vocabulary: Mapping[str, Any],
) -> Dict[str, Any]:
    if example.get("target_contract_id") != TARGET_CONTRACT_ID:
        raise NextBehaviorTensorError("example target contract is invalid")
    return tensorize_model_input(example.get("model_input") or {}, vocabulary)


def tensorize_target(
    target: Mapping[str, Any],
    vocabulary: Mapping[str, Any],
) -> Dict[str, Any]:
    vocab = require_valid_vocabulary(vocabulary)
    outcome_type = _clean(target.get("outcome_type"))
    tactics = target.get("tactics")
    if outcome_type == "next_behavior_phase":
        if not isinstance(tactics, list) or not tactics:
            raise NextBehaviorTensorError(
                "next behavior target requires at least one tactic"
            )
        if target.get("terminal_outcome") not in ("", None):
            raise NextBehaviorTensorError(
                "next behavior target cannot also be terminal"
            )
        terminal = 0
    elif outcome_type == "session_end":
        if tactics not in ([], None) or target.get("terminal_outcome") != (
            TERMINAL_OUTCOME
        ):
            raise NextBehaviorTensorError("session-end target is malformed")
        tactics = []
        terminal = 1
    else:
        raise NextBehaviorTensorError("target outcome_type is invalid")
    tensor = {
        "schema_version": TARGET_TENSOR_SCHEMA_VERSION,
        "target_contract_id": TARGET_CONTRACT_ID,
        "vocabulary_id": vocab["vocabulary_id"],
        "tactic_multi_hot": _multi_hot(tactics, vocab["tactics"]),
        "terminal_outcome": terminal,
    }
    if sum(tensor["tactic_multi_hot"]) != len(set(tactics)):
        raise NextBehaviorTensorError("target contains an unknown tactic")
    return tensor
