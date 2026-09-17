"""Deterministic, applicability-aware late fusion of Model1 and Model2.

Model1 is the frozen command/event-level S1 LinearSVC.  Model2 is a bounded
completed-run result.  Their scores have different semantics, so this module
keeps them as separate evidence and emits typed states rather than a merged
number.  The output is advisory context only and cannot alter canonical
classification, trusted history, alerts, or response guidance.
"""

from __future__ import annotations

import hashlib
import json
import math
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from production.utils.sensor_identity import (
    canonical_session_id as authenticated_canonical_session_id,
)


ENSEMBLE_SCHEMA_VERSION = "model1_model2_late_evidence_ensemble.v1"
MODEL1_SCORE_TYPE = "linear_svc_decision_margin"
MODEL2_SHADOW_STATUS = "INCONCLUSIVE_EXPERIMENTAL_SHADOW"
MODEL2_V5_RESULT_SCHEMA = "model2_v5_style_unified_production_native_shadow_result.v1"
MODEL2_V5_COMPLETED_EVIDENCE_SCHEMA = "model2_v5_completed_run_evidence.v1"
MODEL2_V5_SHADOW_STATUS = "MODEL2_V5_STYLE_UNIFIED_PRODUCTION_NATIVE_SHADOW"
MODEL2_V5_ARTIFACT_SHA256 = "104d4c77a3e1536b847561abb19fc7c0d6d7dc0111cd98d1ff2d9c9d74a2ed1a"
MODEL2_V5_FEATURE_CONTRACT_SHA256 = "cf985643ce89c3d1f86f6c45943c3ba3af6cf13c60c4b41e215c7c7bc8990a20"
MODEL2_V5_RESULT_ROOT = Path("/var/lib/model2-v7/results")
MODEL2_V5_BRIDGE_SOCKET = Path("/run/model2-v7-ensemble/bridge.sock")
SHARED_TECHNIQUES = ("T1105", "T1046", "T1110")
# Model2/ensemble presentation is intentionally parent-technique only.  A
# sub-technique label is normalized to its parent; no sub-technique graph or
# sub-technique prediction is introduced by this runtime.
TECHNIQUE_GRANULARITY = "PARENT_TECHNIQUE_ONLY"
ENSEMBLE_STATES = (
    "AGREE",
    "DISAGREE",
    "MODEL1_ONLY",
    "MODEL2_ONLY",
    "NEITHER",
    "MODEL2_UNAVAILABLE",
    "MODEL1_NOT_APPLICABLE",
)


class EnsembleContractError(ValueError):
    """Raised when evidence does not satisfy the ensemble contract."""


class CrossSessionEvidenceError(EnsembleContractError):
    """Raised when Model2 evidence is bound to a different session or run."""


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _timestamp(value: Any) -> str:
    return _clean(value)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _finite_float(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) else None


def _hash_json(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _digest(value: Any, field: str) -> str:
    digest = _clean(value).lower()
    if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        raise EnsembleContractError(f"{field} must be a SHA-256 hex digest")
    return digest


def _technique(value: Any) -> str:
    text = _clean(value).upper()
    return text.split(".", 1)[0] if text.startswith("T") else text


def _result(value: Any) -> str | None:
    if isinstance(value, bool):
        return "PRESENT" if value else "ABSENT"
    text = _clean(value).upper()
    if text in {"PRESENT", "TRUE", "YES", "POSITIVE", "DETECTED", "1"}:
        return "PRESENT"
    if text in {"ABSENT", "FALSE", "NO", "NEGATIVE", "NOT_DETECTED", "0"}:
        return "ABSENT"
    return None


def _model1_event_prediction(event: Mapping[str, Any]) -> Mapping[str, Any] | None:
    value = event.get("s1_advisory")
    if isinstance(value, Mapping):
        return value
    # A normalized event is useful for deterministic replay and test fixtures.
    if _clean(event.get("score_type")) == MODEL1_SCORE_TYPE or "predicted_technique" in event:
        return event
    return None


def _model1_usable(prediction: Mapping[str, Any]) -> bool:
    status = _clean(prediction.get("status")).lower()
    if status in {"inference_error", "unavailable", "error", "empty_input_skipped"}:
        return False
    if status and status not in {"loaded", "predicted", "ok"}:
        return False
    if _clean(prediction.get("score_type")) not in {"", MODEL1_SCORE_TYPE}:
        return False
    topk = prediction.get("topk")
    return bool(
        _clean(prediction.get("predicted_technique"))
        or isinstance(topk, Sequence)
        or _finite_float(prediction.get("decision_score")) is not None
    )


def summarize_model1_classification_events(
    events: Any,
    *,
    session_id: str,
    observed_at: str | None = None,
    run_id: str = "",
) -> dict[str, Any]:
    """Summarize native S1 outputs without changing their score semantics."""

    expected_session = _clean(session_id)
    if not expected_session:
        raise EnsembleContractError("session_id is required")
    usable: list[Mapping[str, Any]] = []
    labels: dict[str, dict[str, Any]] = {}
    target_margins: dict[str, float] = {}
    target_margin_events: dict[str, int] = {}
    observed_values: list[str] = []

    for raw_event in events if isinstance(events, Sequence) else []:
        if not isinstance(raw_event, Mapping):
            continue
        event_session = _clean(raw_event.get("session_id"))
        if event_session and event_session != expected_session:
            raise CrossSessionEvidenceError(
                "Model1 classification event is bound to a different session"
            )
        prediction = _model1_event_prediction(raw_event)
        if prediction is None or not _model1_usable(prediction):
            continue
        usable.append(prediction)
        timestamp = _timestamp(
            raw_event.get("event_timestamp")
            or raw_event.get("timestamp")
            or prediction.get("observed_at")
        )
        if timestamp:
            observed_values.append(timestamp)
        predicted = _technique(prediction.get("predicted_technique"))
        if predicted:
            item = labels.setdefault(
                predicted,
                {
                    "technique_id": predicted,
                    "result": "PRESENT",
                    "decision_score": None,
                    "score_type": MODEL1_SCORE_TYPE,
                },
            )
            score = _finite_float(prediction.get("decision_score"))
            if score is None:
                topk = prediction.get("topk")
                if isinstance(topk, Sequence):
                    for ranked in topk:
                        if isinstance(ranked, Mapping) and _technique(ranked.get("technique_id")) == predicted:
                            score = _finite_float(ranked.get("decision_score"))
                            break
            if score is not None and (
                item["decision_score"] is None or score > float(item["decision_score"])
            ):
                item["decision_score"] = score
        topk = prediction.get("topk")
        if isinstance(topk, Sequence):
            for ranked in topk:
                if not isinstance(ranked, Mapping):
                    continue
                label = _technique(ranked.get("technique_id"))
                score = _finite_float(ranked.get("decision_score"))
                if label and score is not None:
                    if label not in target_margins or score > target_margins[label]:
                        target_margins[label] = score
                        target_margin_events[label] = len(usable) - 1

    applicable = bool(usable)
    if observed_at:
        model1_observed_at = _timestamp(observed_at)
    elif observed_values:
        model1_observed_at = max(observed_values)
    else:
        model1_observed_at = ""

    shared: dict[str, dict[str, Any]] = {}
    for label in SHARED_TECHNIQUES:
        item = labels.get(label, {})
        margin = item.get("decision_score")
        if margin is None:
            margin = target_margins.get(label)
        shared[label] = {
            "technique_id": label,
            "applicable": applicable,
            "result": "PRESENT" if item else ("ABSENT" if applicable else None),
            "decision_score": margin,
            "score_type": MODEL1_SCORE_TYPE if margin is not None else None,
            "calibrated_probability": None,
            "observed_at": model1_observed_at,
        }

    model1_only_labels = []
    for label, item in sorted(labels.items()):
        if label not in SHARED_TECHNIQUES:
            model1_only_labels.append(
                {
                    "technique_id": label,
                    "result": item.get("result") or "PRESENT",
                    "decision_score": item.get("decision_score"),
                    "score_type": MODEL1_SCORE_TYPE,
                    "calibrated_probability": None,
                    "observed_at": model1_observed_at,
                    "evidence_state": "MODEL1_ONLY",
                    "model2_supported": False,
                    "model2_result": None,
                    "primary_source": "MODEL1",
                    "ensemble_authority": "ADVISORY_ONLY",
                    "trusted_eligible": False,
                    "canonical_write_authority": False,
                    "response_authority": False,
                }
            )
    return {
        "schema_version": "model1_s1_evidence_summary.v1",
        "session_id": expected_session,
        "run_id": _clean(run_id),
        "applicable": applicable,
        "observed_at": model1_observed_at,
        "score_type": MODEL1_SCORE_TYPE,
        "calibrated_probability": None,
        "shared": shared,
        "model1_only_labels": model1_only_labels,
        "event_count": len(usable),
        "source": "MODEL1",
        "authority": "ADVISORY_ONLY",
        "trusted_eligible": False,
        "canonical_write_authority": False,
        "response_authority": False,
    }


def _iter_model2_outputs(value: Any) -> list[tuple[str, Mapping[str, Any]]]:
    if isinstance(value, Mapping):
        return [(_technique(key), item) for key, item in value.items() if isinstance(item, Mapping)]
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        output: list[tuple[str, Mapping[str, Any]]] = []
        for item in value:
            if not isinstance(item, Mapping):
                continue
            label = _technique(item.get("technique_id") or item.get("label") or item.get("technique"))
            if label:
                output.append((label, item))
        return output
    return []


def _normalize_model2_item(label: str, item: Mapping[str, Any], top_status: str) -> dict[str, Any] | None:
    result = _result(item.get("result"))
    if result is None:
        result = _result(item.get("present"))
    if result is None:
        result = _result(item.get("prediction"))
    if result is None:
        return None
    score = _finite_float(
        item.get("score")
        if item.get("score") is not None
        else item.get("native_score")
    )
    score_type = _clean(item.get("score_type") or item.get("native_score_type")) or "model2_native_score"
    return {
        "technique_id": label,
        "available": True,
        "result": result,
        "score": score,
        "score_type": score_type,
        "status": _clean(item.get("status") or top_status) or MODEL2_SHADOW_STATUS,
        # Neither the current Model2 artifact nor this adapter validates
        # probability calibration.
        "calibrated_probability": None,
        "available_at": _timestamp(item.get("available_at")),
    }


def normalize_model2_completed_run_evidence(
    value: Any,
    *,
    session_id: str,
    run_id: str = "",
) -> dict[str, Any]:
    """Validate a completed-run result and bind it to one session/run."""

    expected_session = _clean(session_id)
    expected_run = _clean(run_id)
    if not expected_session:
        raise EnsembleContractError("session_id is required")
    if not isinstance(value, Mapping):
        return _unavailable_model2(
            expected_session,
            expected_run,
            MODEL2_SHADOW_STATUS,
        )
    actual_session = _clean(value.get("session_id"))
    if not actual_session:
        raise EnsembleContractError(
            "Model2 completed-run evidence must include an exact session_id"
        )
    if actual_session != expected_session:
        raise CrossSessionEvidenceError(
            "Model2 completed-run evidence is bound to a different session"
        )
    actual_run = _clean(value.get("run_id") or value.get("completed_run_id"))
    if expected_run and not actual_run:
        raise EnsembleContractError(
            "Model2 completed-run evidence must include the expected run_id"
        )
    if expected_run and actual_run != expected_run:
        raise CrossSessionEvidenceError(
            "Model2 completed-run evidence is bound to a different run"
        )
    available = value.get("available", value.get("model2_available", True))
    if not isinstance(available, bool):
        available = bool(available)
    status = _clean(value.get("status")) or MODEL2_SHADOW_STATUS
    available_at = _timestamp(value.get("available_at") or value.get("completed_at"))
    outputs = value.get("results")
    if outputs is None:
        outputs = value.get("outputs")
    normalized: dict[str, dict[str, Any]] = {}
    for label, item in _iter_model2_outputs(outputs):
        if label not in SHARED_TECHNIQUES:
            continue
        normalized_item = _normalize_model2_item(label, item, status)
        if normalized_item is not None:
            if not normalized_item["available_at"]:
                normalized_item["available_at"] = available_at
            normalized[label] = normalized_item
    if not available:
        return _unavailable_model2(expected_session, expected_run, status, available_at=available_at)
    return {
        "schema_version": "model2_completed_run_evidence.v1",
        "session_id": expected_session,
        "run_id": actual_run or expected_run,
        "available": bool(normalized),
        "status": status,
        "artifact_id": _clean(value.get("artifact_id") or value.get("model_version")),
        "artifact_sha256": _clean(value.get("artifact_sha256") or value.get("model_sha256")),
        "feature_contract_sha256": _clean(value.get("feature_contract_sha256")),
        "calibrated_probability": None,
        "available_at": available_at,
        "outputs": normalized,
        "authority": "ADVISORY_ONLY",
        "trusted_eligible": False,
        "canonical_write_authority": False,
        "response_authority": False,
    }


def normalize_model2_v5_shadow_result(
    value: Any,
    *,
    binding: Mapping[str, Any],
    expected_model_sha256: str,
    expected_feature_contract_sha256: str,
) -> dict[str, Any]:
    """Bind one V5 runtime result to one exact production measurement.

    The V5 runtime intentionally returns the inference result separately from
    the source row. This adapter is the boundary that combines them for
    ensemble display. The caller must provide the exact session/run,
    measurement, and episode identifiers from the same validated row; a
    source IP is never accepted as a substitute. A valid V5 result is then
    translated into the generic completed-run evidence shape consumed by the
    typed late-fusion code.
    """

    if not isinstance(binding, Mapping):
        raise EnsembleContractError("V5 ensemble binding must be an object")
    bound = {
        field: _clean(binding.get(field))
        for field in ("session_id", "run_id", "measurement_id", "episode_id")
    }
    if any(not value for value in bound.values()):
        raise EnsembleContractError(
            "V5 ensemble binding requires session_id, run_id, measurement_id, and episode_id"
        )
    expected_model = _digest(expected_model_sha256, "expected_model_sha256")
    expected_features = _digest(
        expected_feature_contract_sha256,
        "expected_feature_contract_sha256",
    )

    unavailable = _unavailable_model2(
        bound["session_id"],
        bound["run_id"],
        MODEL2_V5_SHADOW_STATUS,
    )
    unavailable.update(
        {
            "schema_version": "model2_v5_completed_run_evidence.v1",
            "measurement_id": bound["measurement_id"],
            "episode_id": bound["episode_id"],
            "feature_contract_sha256": expected_features,
            "binding": dict(bound),
        }
    )
    if not isinstance(value, Mapping):
        unavailable["status"] = "MODEL2_UNAVAILABLE"
        unavailable["reason"] = "v5_shadow_result_missing"
        return unavailable

    for field in ("session_id", "run_id", "measurement_id", "episode_id"):
        actual = _clean(value.get(field))
        if actual and actual != bound[field]:
            raise CrossSessionEvidenceError(
                f"V5 Model2 result {field} does not match the bound measurement"
            )

    status = _clean(value.get("status"))
    availability = _clean(value.get("availability"))
    if status != "VALID_SHADOW" or availability != "AVAILABLE":
        unavailable["status"] = "MODEL2_UNAVAILABLE"
        unavailable["reason"] = _clean(value.get("reason")) or "v5_shadow_unavailable"
        unavailable["available_at"] = _timestamp(
            value.get("available_at") or value.get("completed_at")
        )
        return unavailable

    if _clean(value.get("schema_version")) != MODEL2_V5_RESULT_SCHEMA:
        raise EnsembleContractError("V5 Model2 result schema is unsupported")
    if _clean(value.get("authority")) != "NON_AUTHORITATIVE_SHADOW_ONLY":
        raise EnsembleContractError("V5 Model2 result authority is invalid")
    if value.get("one_model") is not True or value.get("one_inference_call") is not True:
        raise EnsembleContractError("V5 Model2 result is not a one-model result")
    if value.get("independent_binary_heads") is not False or value.get("argmax_used") is not False:
        raise EnsembleContractError("V5 Model2 result violates the unified-model contract")
    if value.get("canonical_write_authority") is not False:
        raise EnsembleContractError("V5 Model2 result has canonical write authority")
    if _clean(value.get("model_artifact_sha256")).lower() != expected_model:
        raise EnsembleContractError("V5 Model2 artifact identity mismatch")
    reported_features = _clean(value.get("feature_contract_sha256"))
    if reported_features and reported_features.lower() != expected_features:
        raise EnsembleContractError("V5 Model2 feature contract identity mismatch")
    if _clean(value.get("model_version")) == "":
        raise EnsembleContractError("V5 Model2 model_version is required")
    if value.get("output_order") is not None and tuple(value.get("output_order")) != SHARED_TECHNIQUES:
        raise EnsembleContractError("V5 Model2 output order mismatch")

    outputs = value.get("outputs")
    if not isinstance(outputs, Mapping) or set(outputs) != set(SHARED_TECHNIQUES):
        raise EnsembleContractError("V5 Model2 result must contain all shared outputs")
    normalized: dict[str, dict[str, Any]] = {}
    available_at = _timestamp(value.get("available_at") or value.get("completed_at"))
    for label in SHARED_TECHNIQUES:
        item = outputs.get(label)
        if not isinstance(item, Mapping) or _clean(item.get("availability")) != "AVAILABLE":
            raise EnsembleContractError(f"V5 Model2 output is unavailable: {label}")
        result = _result(item.get("decision"))
        score = _finite_float(item.get("raw_score"))
        if result is None or score is None:
            raise EnsembleContractError(f"V5 Model2 output is incomplete: {label}")
        normalized[label] = {
            "technique_id": label,
            "available": True,
            "result": result,
            "score": score,
            "score_type": "raw_score",
            "status": MODEL2_V5_SHADOW_STATUS,
            "calibrated_probability": None,
            "available_at": _timestamp(item.get("available_at")) or available_at,
        }
    return {
        "schema_version": "model2_v5_completed_run_evidence.v1",
        "session_id": bound["session_id"],
        "run_id": bound["run_id"],
        "measurement_id": bound["measurement_id"],
        "episode_id": bound["episode_id"],
        "available": True,
        "status": MODEL2_V5_SHADOW_STATUS,
        "artifact_id": _clean(value.get("model_version")),
        "artifact_sha256": expected_model,
        "feature_contract_sha256": expected_features,
        "model_version": _clean(value.get("model_version")),
        "one_model": True,
        "one_inference_call": True,
        "independent_binary_heads": False,
        "argmax_used": False,
        "calibrated_probability": None,
        "available_at": available_at,
        "outputs": normalized,
        "binding": dict(bound),
        "authority": "ADVISORY_ONLY",
        "trusted_eligible": False,
        "canonical_write_authority": False,
        "response_authority": False,
    }


def load_bound_model2_v5_result(
    *,
    session_id: str,
    run_id: str = "",
    result_root: str | Path = MODEL2_V5_RESULT_ROOT,
) -> dict[str, Any] | None:
    """Resolve exactly one protected V5 result by session/run identity.

    The Model2 V7 receiver owns its result directory.  This resolver is used
    by the production session worker only after the OS grants read access to
    that result directory.  It never falls back to source IP, timestamps, or
    arrival order: zero or multiple matching results are unavailable.
    """

    expected_session = _clean(session_id)
    expected_run = _clean(run_id)
    if not expected_session:
        return None
    bridge_reachable, bridge_value = _query_model2_v5_bridge(
        session_id=expected_session,
        run_id=expected_run,
    )
    if bridge_reachable:
        if not isinstance(bridge_value, Mapping):
            return None
        return _normalize_bound_result(
            bridge_value,
            expected_session=expected_session,
            expected_run=expected_run,
        )

    root = Path(result_root)
    try:
        if not root.is_dir() or root.is_symlink():
            return None
        paths = sorted(root.glob("*.json"))
        # A bounded scan prevents an unbounded production directory from
        # turning session finalization into an expensive operation.
        if len(paths) > 4096:
            return None
    except OSError:
        return None

    matches: list[dict[str, Any]] = []
    for path in paths:
        try:
            info = path.lstat()
            if not path.is_file() or path.is_symlink() or info.st_size > 128 * 1024:
                continue
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError, TypeError):
            continue
        if not isinstance(value, Mapping) or _clean(value.get("session_id")) != expected_session:
            continue
        if expected_run and _clean(value.get("run_id")) != expected_run:
            continue
        if (
            _clean(value.get("schema_version")) != MODEL2_V5_RESULT_SCHEMA
            or _clean(value.get("status")) != "VALID_SHADOW"
            or _clean(value.get("availability")) != "AVAILABLE"
            or value.get("pcap_binding") != "PASS"
            or value.get("zeek_binding") != "PASS"
            or value.get("feature_materialization") != "PASS"
            or value.get("source_binding") != "PASS"
            or value.get("session_binding") != "PASS"
            or value.get("run_id_binding") != "PASS"
            or value.get("feature_count") != 32
            or value.get("source_feature_count") != 32
            or value.get("zero_fill") is not False
            or value.get("source_ip_only_binding") is not False
            or value.get("cross_session_contamination") != "NO"
            or value.get("binding_contract_sha256")
            != "2aa0cfebe1298943517610c3e62e0c9a38651ea93b65747dc69250d814b26c7b"
        ):
            continue
        normalized = _normalize_bound_result(
            value,
            expected_session=expected_session,
            expected_run=expected_run,
        )
        if normalized is None:
            continue
        if normalized.get("available") is True:
            matches.append(normalized)

    if len(matches) != 1:
        return None
    return matches[0]


def _normalize_bound_result(
    value: Mapping[str, Any],
    *,
    expected_session: str,
    expected_run: str,
) -> dict[str, Any] | None:
    if _clean(value.get("session_id")) != expected_session:
        return None
    if expected_run and _clean(value.get("run_id")) != expected_run:
        return None
    try:
        binding = {
            field: value.get(field)
            for field in ("session_id", "run_id", "measurement_id", "episode_id")
        }
        normalized = normalize_model2_v5_shadow_result(
            value,
            binding=binding,
            expected_model_sha256=MODEL2_V5_ARTIFACT_SHA256,
            expected_feature_contract_sha256=MODEL2_V5_FEATURE_CONTRACT_SHA256,
        )
    except EnsembleContractError:
        return None
    return normalized if normalized.get("available") is True else None


def _query_model2_v5_bridge(
    *,
    session_id: str,
    run_id: str,
    socket_path: str | Path = MODEL2_V5_BRIDGE_SOCKET,
) -> tuple[bool, Mapping[str, Any] | None]:
    """Query the local bridge; distinguish unavailable from bridge absence."""

    request = {
        "schema_version": "model2_v5_ensemble_bridge_request.v1",
        "session_id": session_id,
        "run_id": run_id,
    }
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(0.25)
            connection.connect(str(socket_path))
            connection.sendall(
                (json.dumps(request, sort_keys=True, separators=(",", ":")) + "\n").encode()
            )
            response = bytearray()
            while len(response) <= 128 * 1024:
                chunk = connection.recv(min(4096, 128 * 1024 + 1 - len(response)))
                if not chunk:
                    break
                response.extend(chunk)
                if b"\n" in chunk:
                    break
        value = json.loads(bytes(response).split(b"\n", 1)[0].decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
        return False, None
    if not isinstance(value, Mapping) or value.get("schema_version") != "model2_v5_ensemble_bridge_response.v1":
        return True, None
    if value.get("status") != "AVAILABLE":
        return True, None
    result = value.get("result")
    return True, result if isinstance(result, Mapping) else None


def _unavailable_model2(
    session_id: str,
    run_id: str,
    status: str,
    *,
    available_at: str = "",
) -> dict[str, Any]:
    return {
        "schema_version": "model2_completed_run_evidence.v1",
        "session_id": session_id,
        "run_id": run_id,
        "available": False,
        "status": status,
        "artifact_id": "",
        "artifact_sha256": "",
        "feature_contract_sha256": "",
        "calibrated_probability": None,
        "available_at": available_at,
        "outputs": {},
        "authority": "ADVISORY_ONLY",
        "trusted_eligible": False,
        "canonical_write_authority": False,
        "response_authority": False,
    }


def _model2_item(model2: Mapping[str, Any], label: str) -> Mapping[str, Any] | None:
    outputs = model2.get("outputs")
    if not isinstance(outputs, Mapping):
        return None
    item = outputs.get(label)
    return item if isinstance(item, Mapping) else None


def compute_ensemble_evidence(
    *,
    session_id: str,
    model1: Mapping[str, Any],
    model2: Mapping[str, Any],
    observed_at: str = "",
    available_at: str = "",
    computed_at: str = "",
    run_id: str = "",
) -> dict[str, Any]:
    """Produce typed per-technique states with no numeric score fusion."""

    expected_session = _clean(session_id)
    if not expected_session:
        raise EnsembleContractError("session_id is required")
    if _clean(model1.get("session_id")) not in {"", expected_session}:
        raise CrossSessionEvidenceError("Model1 summary is bound to a different session")
    if _clean(model2.get("session_id")) != expected_session:
        raise CrossSessionEvidenceError("Model2 summary is bound to a different session")
    expected_run = _clean(run_id)
    for source in (model1, model2):
        source_run = _clean(source.get("run_id"))
        if expected_run and source_run and source_run != expected_run:
            raise CrossSessionEvidenceError("ensemble evidence is bound to a different run")

    model1_applicable = bool(model1.get("applicable"))
    model2_available = bool(model2.get("available"))
    model2_status = _clean(model2.get("status")) or MODEL2_SHADOW_STATUS
    rows: list[dict[str, Any]] = []
    for label in SHARED_TECHNIQUES:
        m1_item = model1.get("shared", {}).get(label, {}) if isinstance(model1.get("shared"), Mapping) else {}
        m1_result = _result(m1_item.get("result")) if isinstance(m1_item, Mapping) else None
        if model1_applicable and m1_result is None:
            m1_result = "ABSENT"
        m2_item = _model2_item(model2, label) if model2_available else None
        m2_result = _result(m2_item.get("result")) if m2_item else None
        item_available = bool(model2_available and m2_item and m2_result is not None)
        if not model1_applicable:
            state = "MODEL1_NOT_APPLICABLE"
            model2_relation = "MODEL2_ONLY" if item_available and m2_result == "PRESENT" else "NO_EVIDENCE"
        elif not item_available:
            state = "MODEL2_UNAVAILABLE"
            model2_relation = "UNAVAILABLE"
        elif m1_result == "PRESENT" and m2_result == "PRESENT":
            state = "AGREE"
            model2_relation = "CORROBORATES"
        elif m1_result == "PRESENT" and m2_result == "ABSENT":
            state = "DISAGREE"
            model2_relation = "CONTRADICTS"
        elif m1_result == "ABSENT" and m2_result == "PRESENT":
            state = "MODEL2_ONLY"
            model2_relation = "MODEL2_ONLY"
        else:
            state = "NEITHER"
            model2_relation = "NO_EVIDENCE"
        rows.append(
            {
                "technique_id": label,
                "model1_applicable": model1_applicable,
                "model1_result": m1_result,
                "model1_margin": (
                    _finite_float(m1_item.get("decision_score"))
                    if isinstance(m1_item, Mapping)
                    else None
                ),
                "model1_score_type": (
                    _clean(m1_item.get("score_type")) or MODEL1_SCORE_TYPE
                    if isinstance(m1_item, Mapping) and m1_item.get("decision_score") is not None
                    else None
                ),
                "model1_calibrated_probability": None,
                "model1_observed_at": _timestamp(
                    (m1_item.get("observed_at") if isinstance(m1_item, Mapping) else "")
                    or observed_at
                ),
                "model2_available": item_available,
                "model2_result": m2_result if item_available else None,
                "model2_score": _finite_float(m2_item.get("score")) if item_available and m2_item else None,
                "model2_score_type": _clean(m2_item.get("score_type")) if item_available and m2_item else None,
                "model2_status": model2_status,
                "model2_calibrated_probability": None,
                "model2_available_at": _timestamp(
                    (m2_item.get("available_at") if item_available and m2_item else "")
                    or model2.get("available_at")
                    or available_at
                ),
                "model2_relation": model2_relation,
                "evidence_state": state,
                "primary_source": "MODEL1" if model1_applicable else "NONE",
                "ensemble_authority": "ADVISORY_ONLY",
                "trusted_eligible": False,
                "canonical_write_authority": False,
                "response_authority": False,
                "fused_score": None,
            }
        )

    raw_model1_only = model1.get("model1_only_labels")
    model1_only = []
    for raw_item in raw_model1_only if isinstance(raw_model1_only, list) else []:
        if not isinstance(raw_item, Mapping):
            continue
        item = dict(raw_item)
        item.setdefault("evidence_state", "MODEL1_ONLY")
        item.setdefault("model2_supported", False)
        item.setdefault("model2_result", None)
        item.setdefault("primary_source", "MODEL1")
        item.setdefault("ensemble_authority", "ADVISORY_ONLY")
        item.setdefault("trusted_eligible", False)
        item.setdefault("canonical_write_authority", False)
        item.setdefault("response_authority", False)
        item["calibrated_probability"] = None
        model1_only.append(item)
    output = {
        "schema_version": ENSEMBLE_SCHEMA_VERSION,
        "session_id": expected_session,
        "run_id": expected_run or _clean(model1.get("run_id") or model2.get("run_id")),
        "model1": {
            "applicable": model1_applicable,
            "score_type": MODEL1_SCORE_TYPE,
            "calibrated_probability": None,
            "observed_at": _timestamp(model1.get("observed_at") or observed_at),
            "authority": "ADVISORY_ONLY",
        },
        "model2": {
            "available": model2_available,
            "status": model2_status,
            "artifact_id": _clean(model2.get("artifact_id")),
            "artifact_sha256": _clean(model2.get("artifact_sha256")),
            "feature_contract_sha256": _clean(model2.get("feature_contract_sha256")),
            "model_version": _clean(model2.get("model_version")),
            "source_session_id": _clean(model2.get("source_session_id")),
            "measurement_id": _clean(model2.get("measurement_id")),
            "episode_id": _clean(model2.get("episode_id")),
            "binding": (
                dict(model2.get("binding"))
                if isinstance(model2.get("binding"), Mapping)
                else {}
            ),
            "one_model": model2.get("one_model") is True,
            "one_inference_call": model2.get("one_inference_call"),
            "independent_binary_heads": model2.get("independent_binary_heads"),
            "argmax_used": model2.get("argmax_used"),
            "calibrated_probability": None,
            "available_at": _timestamp(model2.get("available_at") or available_at),
            "authority": "ADVISORY_ONLY",
        },
        "results": rows,
        "model1_only_labels": model1_only,
        "fused_score": None,
        "ensemble_computed_at": _timestamp(computed_at) or _now(),
        "ensemble_authority": "ADVISORY_ONLY",
        "trusted_eligible": False,
        "canonical_write_authority": False,
        "response_authority": False,
        "no_numeric_score_fusion": True,
    }
    output["contract_sha256"] = _hash_json(
        {key: value for key, value in output.items() if key != "contract_sha256"}
    )
    return output


def _authenticated_sensor_session_alias(
    payload: Mapping[str, Any],
    *,
    canonical_id: str,
) -> str:
    """Return the authenticated sensor-local ID for one canonical session."""

    sensor_id = _clean(payload.get("sensor_id") or payload.get("sensor"))
    sensor_session_id = _clean(payload.get("sensor_session_id"))
    selected_canonical_id = _clean(canonical_id)
    if not sensor_id or not sensor_session_id or not selected_canonical_id:
        return ""
    if sensor_session_id == selected_canonical_id:
        return ""
    try:
        computed = authenticated_canonical_session_id(sensor_id, sensor_session_id)
    except (TypeError, ValueError):
        return ""
    return sensor_session_id if computed == selected_canonical_id else ""


def _rebind_model2_v5_evidence(
    value: Any,
    *,
    source_session_id: str,
    canonical_id: str,
) -> dict[str, Any] | None:
    """Rebind already-validated V5 evidence through authenticated identity."""

    if not isinstance(value, Mapping):
        return None
    source = _clean(source_session_id)
    canonical = _clean(canonical_id)
    if not source or not canonical or _clean(value.get("session_id")) != source:
        return None
    binding = value.get("binding")
    if not isinstance(binding, Mapping) or _clean(binding.get("session_id")) != source:
        return None
    for field in ("run_id", "measurement_id", "episode_id"):
        actual = _clean(value.get(field))
        bound = _clean(binding.get(field))
        if not actual or actual != bound:
            return None
    rebound = dict(value)
    rebound["session_id"] = canonical
    rebound["source_session_id"] = source
    rebound_binding = dict(binding)
    rebound_binding["session_id"] = canonical
    rebound_binding["source_session_id"] = source
    rebound["binding"] = rebound_binding
    return rebound


def build_ensemble_from_session_payload(
    payload: Mapping[str, Any],
    *,
    computed_at: str = "",
) -> dict[str, Any]:
    """Build an advisory snapshot from one redacted session payload."""

    if not isinstance(payload, Mapping):
        raise EnsembleContractError("session payload must be an object")
    session_id = _clean(payload.get("session_id"))
    if not session_id:
        raise EnsembleContractError("session payload session_id is required")
    run_id = _clean(payload.get("run_id") or payload.get("completed_run_id"))
    model1 = summarize_model1_classification_events(
        payload.get("classification_events") or [],
        session_id=session_id,
        observed_at=_clean(payload.get("model1_observed_at")),
        run_id=run_id,
    )
    model2_value = payload.get("model2_completed_run_evidence")
    if model2_value is None:
        model2_value = load_bound_model2_v5_result(
            session_id=session_id,
            run_id=run_id,
        )
        if model2_value is None:
            source_session_id = _authenticated_sensor_session_alias(
                payload,
                canonical_id=session_id,
            )
            if source_session_id:
                source_value = load_bound_model2_v5_result(
                    session_id=source_session_id,
                    run_id=run_id,
                )
                model2_value = _rebind_model2_v5_evidence(
                    source_value,
                    source_session_id=source_session_id,
                    canonical_id=session_id,
                )
    if (
        isinstance(model2_value, Mapping)
        and _clean(model2_value.get("schema_version"))
        == MODEL2_V5_COMPLETED_EVIDENCE_SCHEMA
    ):
        model2 = dict(model2_value)
    else:
        model2 = normalize_model2_completed_run_evidence(
            model2_value,
            session_id=session_id,
            run_id=run_id,
        )
    return compute_ensemble_evidence(
        session_id=session_id,
        run_id=run_id,
        model1=model1,
        model2=model2,
        observed_at=model1.get("observed_at") or "",
        available_at=model2.get("available_at") or "",
        computed_at=computed_at,
    )


def build_ensemble_from_bound_v5_result(
    payload: Mapping[str, Any],
    model2_result: Any,
    *,
    expected_model_sha256: str,
    expected_feature_contract_sha256: str,
    computed_at: str = "",
) -> dict[str, Any]:
    """Build typed evidence from one session payload and one bound V5 result.

    This explicit entry point prevents a future caller from silently pairing a
    V5 result with a session by source IP or by arrival order. The payload must
    carry all four identities produced by the measurement boundary.
    """

    if not isinstance(payload, Mapping):
        raise EnsembleContractError("session payload must be an object")
    session_id = _clean(payload.get("session_id"))
    run_id = _clean(payload.get("run_id") or payload.get("completed_run_id"))
    if not session_id or not run_id:
        raise EnsembleContractError("V5 ensemble payload requires session_id and run_id")
    binding = {
        field: payload.get(field)
        for field in ("session_id", "run_id", "measurement_id", "episode_id")
    }
    model1 = summarize_model1_classification_events(
        payload.get("classification_events") or [],
        session_id=session_id,
        observed_at=_clean(payload.get("model1_observed_at")),
        run_id=run_id,
    )
    model2 = normalize_model2_v5_shadow_result(
        model2_result,
        binding=binding,
        expected_model_sha256=expected_model_sha256,
        expected_feature_contract_sha256=expected_feature_contract_sha256,
    )
    return compute_ensemble_evidence(
        session_id=session_id,
        run_id=run_id,
        model1=model1,
        model2=model2,
        observed_at=model1.get("observed_at") or "",
        available_at=model2.get("available_at") or "",
        computed_at=computed_at,
    )


def load_model2_status(path: str | Path) -> dict[str, Any]:
    """Load a non-secret Model2 status sidecar without loading torch."""

    candidate = Path(path).expanduser()
    try:
        value = json.loads(candidate.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise EnsembleContractError("Model2 status sidecar is unreadable") from exc
    if not isinstance(value, dict):
        raise EnsembleContractError("Model2 status sidecar must be an object")
    if _clean(value.get("status")) != MODEL2_SHADOW_STATUS:
        raise EnsembleContractError("Model2 status sidecar is not the frozen experimental status")
    if value.get("authority") != "ADVISORY_ONLY":
        raise EnsembleContractError("Model2 status sidecar authority is invalid")
    for key in ("artifact_sha256", "feature_contract_sha256"):
        digest = _clean(value.get(key)).lower()
        if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
            raise EnsembleContractError(f"Model2 status sidecar {key} is invalid")
    return value


__all__ = [
    "ENSEMBLE_SCHEMA_VERSION",
    "MODEL1_SCORE_TYPE",
    "MODEL2_SHADOW_STATUS",
    "SHARED_TECHNIQUES",
    "TECHNIQUE_GRANULARITY",
    "CrossSessionEvidenceError",
    "EnsembleContractError",
    "build_ensemble_from_session_payload",
    "build_ensemble_from_bound_v5_result",
    "compute_ensemble_evidence",
    "load_model2_status",
    "load_bound_model2_v5_result",
    "normalize_model2_completed_run_evidence",
    "normalize_model2_v5_shadow_result",
    "summarize_model1_classification_events",
]
