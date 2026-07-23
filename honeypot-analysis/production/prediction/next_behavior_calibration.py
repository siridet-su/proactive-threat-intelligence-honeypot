"""Fail-closed temperature calibration for corrected next-behavior targets.

This additive module does not train or load the forecasting model.  It accepts
already-produced raw logits for an explicitly supplied calibration membership
and fits exactly two global scalar temperatures:

* one temperature shared by every tactic logit; and
* one temperature shared by the terminal-outcome logit.

The mapping is bound to the calibration membership and to the exact model,
vocabulary, and preprocessing artifacts.  Applying a missing, unimplemented,
malformed, or differently bound mapping raises instead of silently presenting
raw model scores as probabilities.
"""

from __future__ import annotations

import hashlib
import re
from copy import deepcopy
from math import exp, isfinite, log, log1p
from typing import Any, Dict, List, Mapping, Sequence

from production.prediction.next_behavior_contract import (
    TACTIC_VOCABULARY,
    TARGET_CONTRACT_ID,
    TERMINAL_OUTCOME,
)
from production.prediction.next_behavior_partitions import membership_sha256
from production.utils.serialization import stable_json

CALIBRATION_MAPPING_SCHEMA_VERSION = "next_behavior_calibration_mapping.v1"
CALIBRATION_SCHEMA_VERSION = CALIBRATION_MAPPING_SCHEMA_VERSION
CALIBRATION_METHOD = "global_scalar_temperature_sigmoid.v1"
RAW_SCORE_SEMANTICS = "raw_model_scores_not_probabilities"
SCORE_SEMANTICS = RAW_SCORE_SEMANTICS
MIN_TEMPERATURE = 0.05
MAX_TEMPERATURE = 20.0
OPTIMIZATION_ITERATIONS = 160

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_EXAMPLE_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,200}$")
_MAPPING_FIELDS = frozenset(
    {
        "schema_version",
        "status",
        "target_contract_id",
        "score_semantics",
        "method",
        "tactic_temperature",
        "terminal_temperature",
        "fit_example_count",
        "fit_partition_membership_sha256",
        "checkpoint_sha256",
        "vocabulary_sha256",
        "preprocessing_sha256",
        "mapping_sha256",
    }
)
_FIT_ROW_FIELDS = frozenset(
    {
        "example_id",
        "partition_role",
        "target_contract_id",
        "score_semantics",
        "checkpoint_sha256",
        "vocabulary_sha256",
        "preprocessing_sha256",
        "tactic_logits",
        "target_tactics",
        "terminal_logit",
        "terminal_target",
    }
)
_FORECAST_CALIBRATION_FIELDS = frozenset(
    {
        "status",
        "method",
        "mapping_sha256",
        "fit_partition_membership_sha256",
    }
)
_RANK_FIELDS = frozenset(
    {"tactic", "raw_score", "rank", "calibrated_probability"}
)
_TERMINAL_FIELDS = frozenset(
    {"label", "raw_score", "calibrated_probability"}
)


class NextBehaviorCalibrationError(ValueError):
    """Raised when calibration fit provenance or mapping use is unsafe."""


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _is_sha256(value: Any) -> bool:
    return bool(_SHA256.fullmatch(_clean(value).lower()))


def _finite_number(value: Any, path: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise NextBehaviorCalibrationError(f"{path} must be a finite number")
    number = float(value)
    if not isfinite(number):
        raise NextBehaviorCalibrationError(f"{path} must be a finite number")
    return number


def _require_hash(value: Any, path: str) -> str:
    text = _clean(value).lower()
    if not _is_sha256(text):
        raise NextBehaviorCalibrationError(f"{path} must be a SHA-256 digest")
    return text


def _mapping_identity(value: Mapping[str, Any]) -> Dict[str, Any]:
    identity = deepcopy(dict(value))
    identity.pop("mapping_sha256", None)
    return identity


def _mapping_digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        stable_json(_mapping_identity(value)).encode("utf-8")
    ).hexdigest()


def build_not_implemented_mapping(
    *,
    fit_partition_membership_sha256: str,
    checkpoint_sha256: str,
    vocabulary_sha256: str,
    preprocessing_sha256: str,
) -> Dict[str, Any]:
    """Return an explicit, artifact-bound declaration of no calibration.

    This object is valid provenance, but :func:`apply_temperature_mapping`
    deliberately refuses to apply it.
    """

    value = {
        "schema_version": CALIBRATION_MAPPING_SCHEMA_VERSION,
        "status": "not_implemented",
        "target_contract_id": TARGET_CONTRACT_ID,
        "score_semantics": RAW_SCORE_SEMANTICS,
        "method": "",
        "tactic_temperature": None,
        "terminal_temperature": None,
        "fit_example_count": 0,
        "fit_partition_membership_sha256": _require_hash(
            fit_partition_membership_sha256,
            "fit_partition_membership_sha256",
        ),
        "checkpoint_sha256": _require_hash(
            checkpoint_sha256,
            "checkpoint_sha256",
        ),
        "vocabulary_sha256": _require_hash(
            vocabulary_sha256,
            "vocabulary_sha256",
        ),
        "preprocessing_sha256": _require_hash(
            preprocessing_sha256,
            "preprocessing_sha256",
        ),
        "mapping_sha256": "",
    }
    return require_valid_calibration_mapping(value)


def not_implemented_calibration(
    *,
    fit_partition_membership_sha256: str,
    checkpoint_sha256: str,
    vocabulary_sha256: str,
    preprocessing_sha256: str,
) -> Dict[str, Any]:
    """Compatibility name for :func:`build_not_implemented_mapping`."""

    return build_not_implemented_mapping(
        fit_partition_membership_sha256=fit_partition_membership_sha256,
        checkpoint_sha256=checkpoint_sha256,
        vocabulary_sha256=vocabulary_sha256,
        preprocessing_sha256=preprocessing_sha256,
    )


def validate_calibration_mapping(value: Any) -> List[str]:
    """Return stable validation errors for a calibration mapping artifact."""

    if not isinstance(value, dict):
        return ["calibration mapping must be an object"]
    errors = [
        f"$.{field} is not defined by the calibration mapping contract"
        for field in sorted(set(value) - _MAPPING_FIELDS)
    ]
    missing = sorted(_MAPPING_FIELDS - set(value))
    errors.extend(f"$.{field} is required" for field in missing)
    if value.get("schema_version") != CALIBRATION_MAPPING_SCHEMA_VERSION:
        errors.append(
            f"schema_version must be {CALIBRATION_MAPPING_SCHEMA_VERSION}"
        )
    if value.get("target_contract_id") != TARGET_CONTRACT_ID:
        errors.append("target_contract_id must name the corrected target")
    if value.get("score_semantics") != RAW_SCORE_SEMANTICS:
        errors.append(
            f"score_semantics must be {RAW_SCORE_SEMANTICS}"
        )
    for field in (
        "fit_partition_membership_sha256",
        "checkpoint_sha256",
        "vocabulary_sha256",
        "preprocessing_sha256",
    ):
        if not _is_sha256(value.get(field)):
            errors.append(f"{field} must be a SHA-256 digest")

    status = _clean(value.get("status"))
    if status not in {"not_implemented", "valid"}:
        errors.append("status must be not_implemented or valid")
    count = value.get("fit_example_count")
    if isinstance(count, bool) or not isinstance(count, int) or count < 0:
        errors.append("fit_example_count must be a non-negative integer")

    if status == "not_implemented":
        if value.get("method") != "":
            errors.append("not_implemented mapping method must be empty")
        if value.get("tactic_temperature") is not None:
            errors.append(
                "not_implemented mapping tactic_temperature must be null"
            )
        if value.get("terminal_temperature") is not None:
            errors.append(
                "not_implemented mapping terminal_temperature must be null"
            )
        if count != 0:
            errors.append("not_implemented mapping fit_example_count must be zero")
        if value.get("mapping_sha256") != "":
            errors.append("not_implemented mapping_sha256 must be empty")
    elif status == "valid":
        if value.get("method") != CALIBRATION_METHOD:
            errors.append(f"method must be {CALIBRATION_METHOD}")
        for field in ("tactic_temperature", "terminal_temperature"):
            temperature = value.get(field)
            if isinstance(temperature, bool) or not isinstance(
                temperature,
                (int, float),
            ):
                errors.append(f"{field} must be a positive finite scalar")
                continue
            number = float(temperature)
            if not isfinite(number) or number <= 0.0:
                errors.append(f"{field} must be a positive finite scalar")
            elif not MIN_TEMPERATURE <= number <= MAX_TEMPERATURE:
                errors.append(
                    f"{field} must be in "
                    f"[{MIN_TEMPERATURE}, {MAX_TEMPERATURE}]"
                )
        if isinstance(count, int) and not isinstance(count, bool) and count < 1:
            errors.append("valid mapping fit_example_count must be positive")
        mapping_hash = _clean(value.get("mapping_sha256")).lower()
        if not _is_sha256(mapping_hash):
            errors.append("mapping_sha256 must be a SHA-256 digest")
        else:
            try:
                expected = _mapping_digest(value)
            except (TypeError, ValueError):
                errors.append("mapping content is not canonically serializable")
            else:
                if mapping_hash != expected:
                    errors.append(
                        "mapping_sha256 does not match calibration mapping content"
                    )
    return errors


def require_valid_calibration_mapping(value: Any) -> Dict[str, Any]:
    """Return a defensive copy or raise on any mapping contract error."""

    errors = validate_calibration_mapping(value)
    if errors:
        raise NextBehaviorCalibrationError("; ".join(errors))
    return deepcopy(value)


def calibration_mapping_sha256(value: Mapping[str, Any]) -> str:
    """Return the verified mapping digest (empty when not implemented)."""

    return str(require_valid_calibration_mapping(value)["mapping_sha256"])


def _validate_fit_rows(
    rows: Sequence[Mapping[str, Any]],
    *,
    calibration_example_ids: Sequence[str],
    fit_partition_membership_sha256: str,
    checkpoint_sha256: str,
    vocabulary_sha256: str,
    preprocessing_sha256: str,
) -> tuple[List[float], List[bool], List[float], List[bool]]:
    if not isinstance(rows, Sequence) or isinstance(rows, (str, bytes)) or not rows:
        raise NextBehaviorCalibrationError(
            "calibration rows must be a non-empty sequence"
        )
    if (
        not isinstance(calibration_example_ids, Sequence)
        or isinstance(calibration_example_ids, (str, bytes))
        or not calibration_example_ids
    ):
        raise NextBehaviorCalibrationError(
            "calibration_example_ids must be a non-empty sequence"
        )
    supplied_ids: List[str] = []
    for index, value in enumerate(calibration_example_ids):
        if not isinstance(value, str) or not _SAFE_EXAMPLE_ID.fullmatch(
            value.strip()
        ):
            raise NextBehaviorCalibrationError(
                f"calibration_example_ids[{index}] is invalid"
            )
        supplied_ids.append(value.strip())
    if len(set(supplied_ids)) != len(supplied_ids):
        raise NextBehaviorCalibrationError(
            "calibration_example_ids must not contain duplicates"
        )

    membership_hash = _require_hash(
        fit_partition_membership_sha256,
        "fit_partition_membership_sha256",
    )
    if membership_sha256(supplied_ids) != membership_hash:
        raise NextBehaviorCalibrationError(
            "supplied calibration membership does not match "
            "fit_partition_membership_sha256"
        )
    bindings = {
        "checkpoint_sha256": _require_hash(
            checkpoint_sha256,
            "checkpoint_sha256",
        ),
        "vocabulary_sha256": _require_hash(
            vocabulary_sha256,
            "vocabulary_sha256",
        ),
        "preprocessing_sha256": _require_hash(
            preprocessing_sha256,
            "preprocessing_sha256",
        ),
    }

    seen_ids: List[str] = []
    tactic_logits: List[float] = []
    tactic_targets: List[bool] = []
    terminal_logits: List[float] = []
    terminal_targets: List[bool] = []
    ordered_rows = sorted(
        enumerate(rows),
        key=lambda indexed: (
            _clean(indexed[1].get("example_id"))
            if isinstance(indexed[1], Mapping)
            else ""
        ),
    )
    for row_index, row in ordered_rows:
        path = f"rows[{row_index}]"
        if not isinstance(row, Mapping):
            raise NextBehaviorCalibrationError(f"{path} must be an object")
        unknown = sorted(set(row) - _FIT_ROW_FIELDS)
        missing = sorted(_FIT_ROW_FIELDS - set(row))
        if unknown:
            raise NextBehaviorCalibrationError(
                f"{path} contains undefined fields: {', '.join(unknown)}"
            )
        if missing:
            raise NextBehaviorCalibrationError(
                f"{path} is missing fields: {', '.join(missing)}"
            )
        example_id = row.get("example_id")
        if not isinstance(example_id, str) or not _SAFE_EXAMPLE_ID.fullmatch(
            example_id.strip()
        ):
            raise NextBehaviorCalibrationError(f"{path}.example_id is invalid")
        example_id = example_id.strip()
        if example_id in seen_ids:
            raise NextBehaviorCalibrationError(
                f"{path}.example_id is duplicated"
            )
        seen_ids.append(example_id)
        if row.get("partition_role") != "calibration":
            raise NextBehaviorCalibrationError(
                f"{path}.partition_role must be calibration"
            )
        if row.get("target_contract_id") != TARGET_CONTRACT_ID:
            raise NextBehaviorCalibrationError(
                f"{path}.target_contract_id does not name the corrected target"
            )
        if row.get("score_semantics") != RAW_SCORE_SEMANTICS:
            raise NextBehaviorCalibrationError(
                f"{path}.score_semantics must be {RAW_SCORE_SEMANTICS}"
            )
        for field, expected in bindings.items():
            actual = _clean(row.get(field)).lower()
            if actual != expected:
                raise NextBehaviorCalibrationError(
                    f"{path}.{field} does not match the fit binding"
                )

        raw_logits = row.get("tactic_logits")
        if not isinstance(raw_logits, Mapping) or set(raw_logits) != set(
            TACTIC_VOCABULARY
        ):
            raise NextBehaviorCalibrationError(
                f"{path}.tactic_logits must define exactly the frozen "
                "tactic vocabulary"
            )
        raw_targets = row.get("target_tactics")
        if not isinstance(raw_targets, list):
            raise NextBehaviorCalibrationError(
                f"{path}.target_tactics must be an array"
            )
        targets: List[str] = []
        for target_index, target in enumerate(raw_targets):
            if (
                not isinstance(target, str)
                or target not in TACTIC_VOCABULARY
                or target in targets
            ):
                raise NextBehaviorCalibrationError(
                    f"{path}.target_tactics[{target_index}] is invalid or "
                    "duplicated"
                )
            targets.append(target)
        terminal_target = row.get("terminal_target")
        if type(terminal_target) is not bool:
            raise NextBehaviorCalibrationError(
                f"{path}.terminal_target must be boolean"
            )
        if terminal_target and targets:
            raise NextBehaviorCalibrationError(
                f"{path} terminal target cannot also contain tactic targets"
            )
        if not terminal_target and not targets:
            raise NextBehaviorCalibrationError(
                f"{path} non-terminal target requires at least one tactic"
            )
        for tactic in sorted(TACTIC_VOCABULARY):
            tactic_logits.append(
                _finite_number(
                    raw_logits[tactic],
                    f"{path}.tactic_logits.{tactic}",
                )
            )
            tactic_targets.append(tactic in targets)
        terminal_logits.append(
            _finite_number(row.get("terminal_logit"), f"{path}.terminal_logit")
        )
        terminal_targets.append(terminal_target)

    if set(seen_ids) != set(supplied_ids) or len(seen_ids) != len(supplied_ids):
        raise NextBehaviorCalibrationError(
            "fit rows do not exactly match the supplied calibration membership"
        )
    return tactic_logits, tactic_targets, terminal_logits, terminal_targets


def _binary_log_loss(
    logits: Sequence[float],
    targets: Sequence[bool],
    log_temperature: float,
) -> float:
    temperature = exp(log_temperature)
    total = 0.0
    for logit, target in zip(logits, targets):
        scaled = logit / temperature
        if target:
            loss = (
                log1p(exp(-scaled))
                if scaled >= 0.0
                else -scaled + log1p(exp(scaled))
            )
        else:
            loss = (
                scaled + log1p(exp(-scaled))
                if scaled >= 0.0
                else log1p(exp(scaled))
            )
        total += loss
    return total / len(logits)


def _fit_temperature(
    logits: Sequence[float],
    targets: Sequence[bool],
) -> float:
    """Deterministic fixed-iteration golden-section minimization in log space."""

    lower = log(MIN_TEMPERATURE)
    upper = log(MAX_TEMPERATURE)
    ratio = (5.0**0.5 - 1.0) / 2.0
    left = upper - ratio * (upper - lower)
    right = lower + ratio * (upper - lower)
    left_loss = _binary_log_loss(logits, targets, left)
    right_loss = _binary_log_loss(logits, targets, right)
    for _ in range(OPTIMIZATION_ITERATIONS):
        if left_loss <= right_loss:
            upper = right
            right = left
            right_loss = left_loss
            left = upper - ratio * (upper - lower)
            left_loss = _binary_log_loss(logits, targets, left)
        else:
            lower = left
            left = right
            left_loss = right_loss
            right = lower + ratio * (upper - lower)
            right_loss = _binary_log_loss(logits, targets, right)
    temperature = exp((lower + upper) / 2.0)
    return min(MAX_TEMPERATURE, max(MIN_TEMPERATURE, temperature))


def fit_temperature_mapping(
    rows: Sequence[Mapping[str, Any]],
    *,
    calibration_example_ids: Sequence[str],
    fit_partition_membership_sha256: str,
    checkpoint_sha256: str,
    vocabulary_sha256: str,
    preprocessing_sha256: str,
) -> Dict[str, Any]:
    """Fit the two allowed temperatures on exactly one supplied membership."""

    (
        tactic_logits,
        tactic_targets,
        terminal_logits,
        terminal_targets,
    ) = _validate_fit_rows(
        rows,
        calibration_example_ids=calibration_example_ids,
        fit_partition_membership_sha256=fit_partition_membership_sha256,
        checkpoint_sha256=checkpoint_sha256,
        vocabulary_sha256=vocabulary_sha256,
        preprocessing_sha256=preprocessing_sha256,
    )
    value: Dict[str, Any] = {
        "schema_version": CALIBRATION_MAPPING_SCHEMA_VERSION,
        "status": "valid",
        "target_contract_id": TARGET_CONTRACT_ID,
        "score_semantics": RAW_SCORE_SEMANTICS,
        "method": CALIBRATION_METHOD,
        "tactic_temperature": _fit_temperature(
            tactic_logits,
            tactic_targets,
        ),
        "terminal_temperature": _fit_temperature(
            terminal_logits,
            terminal_targets,
        ),
        "fit_example_count": len(rows),
        "fit_partition_membership_sha256": _clean(
            fit_partition_membership_sha256
        ).lower(),
        "checkpoint_sha256": _clean(checkpoint_sha256).lower(),
        "vocabulary_sha256": _clean(vocabulary_sha256).lower(),
        "preprocessing_sha256": _clean(preprocessing_sha256).lower(),
        "mapping_sha256": "",
    }
    value["mapping_sha256"] = _mapping_digest(value)
    return require_valid_calibration_mapping(value)


def fit_corrected_target_calibration(
    rows: Sequence[Mapping[str, Any]],
    *,
    calibration_example_ids: Sequence[str],
    fit_partition_membership_sha256: str,
    checkpoint_sha256: str,
    vocabulary_sha256: str,
    preprocessing_sha256: str,
) -> Dict[str, Any]:
    """Compatibility name for :func:`fit_temperature_mapping`."""

    return fit_temperature_mapping(
        rows,
        calibration_example_ids=calibration_example_ids,
        fit_partition_membership_sha256=fit_partition_membership_sha256,
        checkpoint_sha256=checkpoint_sha256,
        vocabulary_sha256=vocabulary_sha256,
        preprocessing_sha256=preprocessing_sha256,
    )


def _sigmoid_temperature(raw_score: float, temperature: float) -> float:
    scaled = raw_score / temperature
    if scaled >= 0.0:
        inverse = exp(-scaled)
        return 1.0 / (1.0 + inverse)
    forward = exp(scaled)
    return forward / (1.0 + forward)


def _require_mapping_bindings(
    mapping: Mapping[str, Any],
    *,
    fit_partition_membership_sha256: str,
    checkpoint_sha256: str,
    vocabulary_sha256: str,
    preprocessing_sha256: str,
) -> Dict[str, Any]:
    validated = require_valid_calibration_mapping(mapping)
    if validated["status"] != "valid":
        raise NextBehaviorCalibrationError(
            "calibration mapping is not implemented and cannot be applied"
        )
    expected = {
        "fit_partition_membership_sha256": _require_hash(
            fit_partition_membership_sha256,
            "fit_partition_membership_sha256",
        ),
        "checkpoint_sha256": _require_hash(
            checkpoint_sha256,
            "checkpoint_sha256",
        ),
        "vocabulary_sha256": _require_hash(
            vocabulary_sha256,
            "vocabulary_sha256",
        ),
        "preprocessing_sha256": _require_hash(
            preprocessing_sha256,
            "preprocessing_sha256",
        ),
    }
    for field, digest in expected.items():
        if _clean(validated[field]).lower() != digest:
            raise NextBehaviorCalibrationError(
                f"calibration mapping {field} mismatch"
            )
    return validated


def apply_temperature_mapping(
    raw_output: Mapping[str, Any],
    mapping: Mapping[str, Any] | None,
    *,
    fit_partition_membership_sha256: str,
    checkpoint_sha256: str,
    vocabulary_sha256: str,
    preprocessing_sha256: str,
) -> Dict[str, Any]:
    """Apply a verified mapping while retaining the original raw-score fields.

    Tactic probabilities are independent sigmoid probabilities for the
    corrected multi-label target.  A single positive tactic temperature and a
    monotonic sigmoid cannot change tactic rank.
    """

    if mapping is None:
        raise NextBehaviorCalibrationError("calibration mapping is missing")
    if not isinstance(raw_output, Mapping):
        raise NextBehaviorCalibrationError("raw_output must be an object")
    validated = _require_mapping_bindings(
        mapping,
        fit_partition_membership_sha256=fit_partition_membership_sha256,
        checkpoint_sha256=checkpoint_sha256,
        vocabulary_sha256=vocabulary_sha256,
        preprocessing_sha256=preprocessing_sha256,
    )
    if raw_output.get("score_semantics") != RAW_SCORE_SEMANTICS:
        raise NextBehaviorCalibrationError(
            f"raw_output.score_semantics must be {RAW_SCORE_SEMANTICS}"
        )
    existing_calibration = raw_output.get("calibration")
    if existing_calibration is not None:
        if not isinstance(existing_calibration, Mapping):
            raise NextBehaviorCalibrationError(
                "raw_output.calibration must be an object"
            )
        unknown = set(existing_calibration) - _FORECAST_CALIBRATION_FIELDS
        if unknown:
            raise NextBehaviorCalibrationError(
                "raw_output.calibration contains undefined fields"
            )
        if existing_calibration.get("status") == "valid":
            raise NextBehaviorCalibrationError(
                "raw_output is already calibrated"
            )
        if existing_calibration.get("status") not in {
            "not_implemented",
            "invalid",
        } or any(
            _clean(existing_calibration.get(field))
            for field in (
                "method",
                "mapping_sha256",
                "fit_partition_membership_sha256",
            )
        ):
            raise NextBehaviorCalibrationError(
                "raw_output.calibration is not an uncalibrated descriptor"
            )

    ranked = raw_output.get("ranked_tactics")
    if not isinstance(ranked, list) or not ranked:
        raise NextBehaviorCalibrationError(
            "raw_output.ranked_tactics must be a non-empty array"
        )
    parsed_ranks: List[tuple[Mapping[str, Any], float]] = []
    seen_tactics: set[str] = set()
    previous_score: float | None = None
    for index, item in enumerate(ranked):
        path = f"raw_output.ranked_tactics[{index}]"
        if not isinstance(item, Mapping):
            raise NextBehaviorCalibrationError(f"{path} must be an object")
        unknown = sorted(set(item) - _RANK_FIELDS)
        if unknown:
            raise NextBehaviorCalibrationError(
                f"{path} contains undefined fields: {', '.join(unknown)}"
            )
        tactic = item.get("tactic")
        if tactic not in TACTIC_VOCABULARY or tactic in seen_tactics:
            raise NextBehaviorCalibrationError(
                f"{path}.tactic is invalid or duplicated"
            )
        seen_tactics.add(str(tactic))
        if item.get("rank") != index + 1 or isinstance(item.get("rank"), bool):
            raise NextBehaviorCalibrationError(
                f"{path}.rank must match list order"
            )
        score = _finite_number(item.get("raw_score"), f"{path}.raw_score")
        if previous_score is not None and score > previous_score:
            raise NextBehaviorCalibrationError(
                "raw_output.ranked_tactics must be ordered by raw_score"
            )
        previous_score = score
        if item.get("calibrated_probability") is not None:
            raise NextBehaviorCalibrationError(
                f"{path}.calibrated_probability must be null before mapping"
            )
        parsed_ranks.append((item, score))

    terminal = raw_output.get("terminal_outcome")
    if not isinstance(terminal, Mapping):
        raise NextBehaviorCalibrationError(
            "raw_output.terminal_outcome must be an object"
        )
    unknown_terminal = sorted(set(terminal) - _TERMINAL_FIELDS)
    if unknown_terminal:
        raise NextBehaviorCalibrationError(
            "raw_output.terminal_outcome contains undefined fields: "
            + ", ".join(unknown_terminal)
        )
    if terminal.get("label") != TERMINAL_OUTCOME:
        raise NextBehaviorCalibrationError(
            "raw_output.terminal_outcome.label is invalid"
        )
    terminal_score = _finite_number(
        terminal.get("raw_score"),
        "raw_output.terminal_outcome.raw_score",
    )
    if terminal.get("calibrated_probability") is not None:
        raise NextBehaviorCalibrationError(
            "raw_output.terminal_outcome.calibrated_probability must be null "
            "before mapping"
        )

    output = deepcopy(dict(raw_output))
    tactic_temperature = float(validated["tactic_temperature"])
    for index, (_, score) in enumerate(parsed_ranks):
        output["ranked_tactics"][index]["calibrated_probability"] = (
            _sigmoid_temperature(score, tactic_temperature)
        )
    output["terminal_outcome"]["calibrated_probability"] = (
        _sigmoid_temperature(
            terminal_score,
            float(validated["terminal_temperature"]),
        )
    )
    output["calibration"] = {
        "status": "valid",
        "method": CALIBRATION_METHOD,
        "mapping_sha256": validated["mapping_sha256"],
        "fit_partition_membership_sha256": validated[
            "fit_partition_membership_sha256"
        ],
    }
    return output


def apply_calibration_mapping(
    raw_output: Mapping[str, Any],
    mapping: Mapping[str, Any] | None,
    *,
    fit_partition_membership_sha256: str,
    checkpoint_sha256: str,
    vocabulary_sha256: str,
    preprocessing_sha256: str,
) -> Dict[str, Any]:
    """Compatibility name for :func:`apply_temperature_mapping`."""

    return apply_temperature_mapping(
        raw_output,
        mapping,
        fit_partition_membership_sha256=fit_partition_membership_sha256,
        checkpoint_sha256=checkpoint_sha256,
        vocabulary_sha256=vocabulary_sha256,
        preprocessing_sha256=preprocessing_sha256,
    )
