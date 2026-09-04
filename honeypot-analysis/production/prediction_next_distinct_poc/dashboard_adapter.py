"""Read-only Dashboard adapter for the retained Final next-distinct PoC.

The adapter consumes the sidecar's append-only ``records.jsonl`` output.  It
does not invoke inference, advance progression, write MongoDB, mutate trusted
history, or fall back to the legacy canonical snapshot.  The output is a
versioned advisory contract whose semantics are explicitly next *distinct*
trusted tactic/phase prediction.
"""

from __future__ import annotations

import json
import math
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from production.prediction.trusted_history import validate_prediction_trusted_history_manifest


EXPECTED_CHECKPOINT = "16506e962432f9921d18a514c3a31686a20f9734385ec49439ad2651e4cdd283"
EXPECTED_MODEL = "finalf_refined_v1_prediction_only"
EXPECTED_TEMPERATURE = 0.6990670591704266
EXPECTED_RECORD_SCHEMA = "gcp_cowrie_shadow_prediction_record.v2"
EXPECTED_HISTORY_SCHEMA = "prediction_trusted_history_manifest.v3"
EXPECTED_TARGET_CONTRACT = "next_distinct_trusted_behavior_phase_or_session_end.v2"
EXPECTED_ADAPTER_SCHEMA = "dashboard_next_distinct_prediction.v1"
LABEL_ORDER = (
    "command-and-control",
    "credential-access",
    "defense-evasion",
    "discovery",
    "execution",
    "persistence",
    "privilege-escalation",
)
DEFAULT_SHADOW_ROOT = "/var/lib/honeypot-shadow/prediction-next-distinct/live-integration-20260824-v3mongo-finalizer-a6-403c989d"
DEFAULT_STALE_AFTER_SECONDS = 3600.0
MAX_RECORD_BYTES = 8 * 1024 * 1024
MAX_RECORD_LINES = 20_000


class DashboardAdapterError(ValueError):
    """Raised for malformed or semantically incompatible sidecar data."""


def _text(value: Any) -> str:
    return str(value or "").strip()


def _payload_from_row(row: Mapping[str, Any]) -> dict[str, Any]:
    payload = row.get("payload")
    if isinstance(payload, Mapping):
        return dict(payload)
    raw = row.get("payload_json")
    if raw:
        try:
            value = json.loads(str(raw))
        except (TypeError, ValueError):
            return {}
        return dict(value) if isinstance(value, Mapping) else {}
    return {}


def _manifest_from_row(row: Mapping[str, Any]) -> dict[str, Any]:
    payload = _payload_from_row(row)
    manifest = payload.get("prediction_trusted_history_manifest")
    return dict(manifest) if isinstance(manifest, Mapping) else {}


def _trusted_history(manifest: Mapping[str, Any]) -> tuple[list[str], dict[str, Any]]:
    if not manifest:
        return [], {}
    if manifest.get("schema_version") != EXPECTED_HISTORY_SCHEMA:
        raise DashboardAdapterError("trusted-history manifest schema is not v3")
    if manifest.get("target_contract_id") != EXPECTED_TARGET_CONTRACT:
        raise DashboardAdapterError("trusted-history target contract differs")
    errors = validate_prediction_trusted_history_manifest(manifest)
    if errors:
        raise DashboardAdapterError("trusted-history integrity validation failed: " + "; ".join(errors[:3]))
    phases = manifest.get("ordered_trusted_phases")
    if not isinstance(phases, list):
        raise DashboardAdapterError("trusted-history phases are not a list")
    if len(phases) > 8:
        raise DashboardAdapterError("trusted-history exceeds the sidecar history cap")
    labels: list[str] = []
    for phase in phases:
        if not isinstance(phase, Mapping):
            raise DashboardAdapterError("trusted-history phase is not an object")
        tactics = phase.get("tactics")
        if not isinstance(tactics, list) or len(tactics) != 1 or tactics[0] not in LABEL_ORDER:
            raise DashboardAdapterError("trusted-history phase is not a single frozen tactic")
        labels.append(str(tactics[0]))
    cutoff = manifest.get("evidence_cutoff")
    if not isinstance(cutoff, Mapping):
        raise DashboardAdapterError("trusted-history evidence cutoff is missing")
    return labels, {
        "trusted_only": True,
        "length": len(labels),
        "cutoff": dict(cutoff),
        "manifest_sha256": _text(manifest.get("history_manifest_sha256")),
        "manifest_schema": EXPECTED_HISTORY_SCHEMA,
        "target_contract_id": EXPECTED_TARGET_CONTRACT,
    }


def _iso_from_epoch(value: Any) -> str:
    if isinstance(value, bool):
        raise DashboardAdapterError("sidecar recorded_at is invalid")
    try:
        epoch = float(value)
    except (TypeError, ValueError) as exc:
        raise DashboardAdapterError("sidecar recorded_at is invalid") from exc
    if not math.isfinite(epoch) or epoch <= 0:
        raise DashboardAdapterError("sidecar recorded_at is invalid")
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def _validate_predictor(record: Mapping[str, Any]) -> dict[str, Any]:
    if record.get("schema_version") != EXPECTED_RECORD_SCHEMA:
        raise DashboardAdapterError("sidecar record schema differs")
    predictor = record.get("predictor")
    if not isinstance(predictor, Mapping):
        raise DashboardAdapterError("sidecar predictor metadata is missing")
    # The native v2 record is emitted only after the sidecar startup health
    # gate reports model_ready=true.  Preserve that established record
    # contract while rejecting an explicit false/non-boolean readiness marker
    # from a future producer.
    if "model_ready" in predictor and predictor.get("model_ready") is not True:
        raise DashboardAdapterError("sidecar model is not ready")
    if predictor.get("task") != "next_observed_distinct_tactic":
        raise DashboardAdapterError("sidecar task is not next-distinct tactic prediction")
    if predictor.get("authority") != "non_authoritative" or predictor.get("canonical_write_allowed") is not False:
        raise DashboardAdapterError("sidecar authority boundary is invalid")
    if predictor.get("calibrated") is not True:
        raise DashboardAdapterError("sidecar calibration flag is not true")
    if predictor.get("model_identifier") != EXPECTED_MODEL:
        raise DashboardAdapterError("sidecar model identity differs")
    if _text(predictor.get("checkpoint_sha256")).lower() != EXPECTED_CHECKPOINT:
        raise DashboardAdapterError("sidecar checkpoint identity differs")
    top1 = predictor.get("top1")
    top3 = predictor.get("top3")
    probabilities = predictor.get("probabilities")
    if top1 not in LABEL_ORDER or not isinstance(top3, list) or not top3 or any(item not in LABEL_ORDER for item in top3):
        raise DashboardAdapterError("sidecar ranking is malformed")
    if not isinstance(probabilities, list) or len(probabilities) != len(LABEL_ORDER):
        raise DashboardAdapterError("sidecar score vector is malformed")
    try:
        values = [float(item) for item in probabilities]
    except (TypeError, ValueError) as exc:
        raise DashboardAdapterError("sidecar score vector is non-numeric") from exc
    if any(not math.isfinite(item) or item < 0 for item in values) or abs(sum(values) - 1.0) > 1e-5:
        raise DashboardAdapterError("sidecar score vector is not finite/normalized")
    ranked_labels = [LABEL_ORDER[index] for index in sorted(range(len(LABEL_ORDER)), key=lambda index: (-values[index], index))]
    if str(top1) != ranked_labels[0] or [str(item) for item in top3[:3]] != ranked_labels[:3]:
        raise DashboardAdapterError("sidecar top-k fields do not match score vector")
    calibration = predictor.get("calibration")
    if not isinstance(calibration, Mapping) or calibration.get("method") != "temperature_scaled_softmax.v1":
        raise DashboardAdapterError("sidecar score semantics are not bound")
    try:
        temperature = float(calibration.get("temperature"))
    except (TypeError, ValueError) as exc:
        raise DashboardAdapterError("sidecar calibration temperature is invalid") from exc
    if not math.isfinite(temperature) or abs(temperature - EXPECTED_TEMPERATURE) > 1e-9:
        raise DashboardAdapterError("sidecar calibration temperature differs")
    return {
        "model_identifier": EXPECTED_MODEL,
        "checkpoint_sha256": EXPECTED_CHECKPOINT,
        "top1": str(top1),
        "top3": [str(item) for item in top3[:3]],
        "probabilities": values,
        "temperature": temperature,
        "calibration": dict(calibration),
        "model_ready": True,
        "authority": "non_authoritative",
        "canonical_write_allowed": False,
    }


def _read_latest_record(records_path: Path, session_id: str) -> tuple[dict[str, Any] | None, str | None]:
    if records_path.is_symlink() or not records_path.is_file():
        return None, "sidecar records file is unavailable"
    try:
        if records_path.stat().st_size > MAX_RECORD_BYTES:
            return None, "sidecar records file exceeds safe read bound"
        lines = records_path.read_text(encoding="utf-8").splitlines()[-MAX_RECORD_LINES:]
    except (OSError, UnicodeDecodeError) as exc:
        return None, f"sidecar records file is unreadable: {type(exc).__name__}"
    latest: dict[str, Any] | None = None
    for line in lines:
        try:
            value = json.loads(line)
        except (TypeError, ValueError):
            continue
        if not isinstance(value, Mapping) or _text(value.get("sequence_id")) != session_id:
            continue
        try:
            _validate_predictor(value)
            if isinstance(value.get("progression_index"), bool) or isinstance(value.get("recorded_at"), bool):
                raise DashboardAdapterError("sidecar progression identity is invalid")
            progression = int(value.get("progression_index"))
            recorded_at = float(value.get("recorded_at"))
        except (DashboardAdapterError, TypeError, ValueError):
            continue
        if progression < 1 or not math.isfinite(recorded_at):
            continue
        if latest is None or (progression, recorded_at) > (int(latest.get("progression_index", 0)), float(latest.get("recorded_at", 0))):
            latest = dict(value)
    if latest is None:
        return None, "no eligible sidecar record for this session"
    return latest, None


def _validate_record_history(record: Mapping[str, Any], history: list[str], manifest: Mapping[str, Any]) -> None:
    raw_history = record.get("history")
    if not isinstance(raw_history, list) or not raw_history or len(raw_history) > 8:
        raise DashboardAdapterError("sidecar trusted history is malformed")
    if any(item not in LABEL_ORDER for item in raw_history):
        raise DashboardAdapterError("sidecar history contains an unknown tactic")
    raw_length = record.get("history_length")
    if isinstance(raw_length, bool) or int(raw_length) != len(raw_history):
        raise DashboardAdapterError("sidecar history length is inconsistent")
    expected_manifest = _text(manifest.get("history_manifest_sha256"))
    record_manifest = _text(record.get("history_manifest_sha256"))
    if not re.fullmatch(r"[0-9a-fA-F]{64}", record_manifest):
        raise DashboardAdapterError("sidecar history manifest hash is invalid")
    if expected_manifest and expected_manifest == record_manifest and raw_history != history[-8:]:
        raise DashboardAdapterError("sidecar history does not match trusted manifest")

def _freshness(record: Mapping[str, Any], manifest: Mapping[str, Any], now: float, stale_after: float) -> dict[str, Any]:
    generated_at = _iso_from_epoch(record.get("recorded_at"))
    age = max(0.0, now - float(record.get("recorded_at")))
    state = "STALE" if age > stale_after else "FRESH"
    expected_manifest = _text(manifest.get("history_manifest_sha256"))
    record_manifest = _text(record.get("history_manifest_sha256"))
    if expected_manifest and expected_manifest != record_manifest:
        state = "STALE"
    return {
        "state": state,
        "generated_at": generated_at,
        "age_seconds": round(age, 3),
        "stale_after_seconds": stale_after,
        "history_manifest_match": not expected_manifest or expected_manifest == record_manifest,
    }


def _ranking(predictor: Mapping[str, Any]) -> list[dict[str, Any]]:
    probabilities = list(predictor["probabilities"])
    ranked = sorted(range(len(LABEL_ORDER)), key=lambda index: (-float(probabilities[index]), index))
    return [
        {
            "tactic": LABEL_ORDER[index],
            "score": float(probabilities[index]),
            "score_semantics": "temperature_scaled_softmax_probability",
            "sources": [{
                "name": EXPECTED_MODEL,
                "source_type": "next_distinct_sidecar",
                "weighted_score": float(probabilities[index]),
            }],
        }
        for index in ranked[:3]
    ]


def build_dashboard_prediction(
    session_id: str,
    session_row: Mapping[str, Any] | None,
    *,
    shadow_root: str | Path | None = None,
    now: float | None = None,
    stale_after_seconds: float = DEFAULT_STALE_AFTER_SECONDS,
) -> dict[str, Any]:
    """Build a Dashboard-facing advisory response without legacy fallback."""

    clean_id = _text(session_id)
    if not clean_id:
        return {"schema_version": EXPECTED_ADAPTER_SCHEMA, "dashboard_source": "FINAL_POC", "prediction_status": "UNAVAILABLE", "prediction_status_reason": "session_id is required", "authority": "NON_AUTHORITATIVE_ADVISORY"}
    try:
        stale_after = float(stale_after_seconds)
    except (TypeError, ValueError):
        stale_after = DEFAULT_STALE_AFTER_SECONDS
    stale_after = min(max(stale_after, 60.0), 86_400.0)
    manifest = _manifest_from_row(session_row or {})
    try:
        history, history_meta = _trusted_history(manifest)
    except DashboardAdapterError as exc:
        return _unavailable(clean_id, f"trusted history rejected: {exc}")
    if not history:
        return {
            "schema_version": EXPECTED_ADAPTER_SCHEMA,
            "prediction_type": "NEXT_DISTINCT_TRUSTED_TACTIC",
            "dashboard_source": "FINAL_POC",
            "authority": "NON_AUTHORITATIVE_ADVISORY",
            "source": "next-distinct-sidecar",
            "model": {"family": EXPECTED_MODEL, "checkpoint_sha256": EXPECTED_CHECKPOINT, "temperature": EXPECTED_TEMPERATURE},
            "history": {"trusted_only": True, "length": 0, "cutoff": history_meta.get("cutoff", {})},
            "prediction": [],
            "top1": None,
            "top3": [],
            "prediction_status": "NO_TRUSTED_HISTORY",
            "prediction_status_reason": "no trusted distinct history is available",
            "sequence_id": clean_id,
            "freshness": {"state": "NO_DATA"},
            "canonical_write_allowed": False,
        }
    root = Path(shadow_root or os.environ.get("NEXT_DISTINCT_SHADOW_ROOT") or DEFAULT_SHADOW_ROOT)
    records, error = _read_latest_record(root / "records.jsonl", clean_id)
    if records is None:
        return _unavailable(clean_id, error or "sidecar record unavailable", history=history_meta)
    try:
        predictor = _validate_predictor(records)
        _validate_record_history(records, history, manifest)
        freshness = _freshness(records, manifest, float(time.time() if now is None else now), stale_after)
        prediction = _ranking(predictor)
    except (DashboardAdapterError, TypeError, ValueError) as exc:
        return _unavailable(clean_id, f"sidecar record rejected: {exc}", history=history_meta)
    return {
        "schema_version": EXPECTED_ADAPTER_SCHEMA,
        "prediction_type": "NEXT_DISTINCT_TRUSTED_TACTIC",
        "dashboard_source": "FINAL_POC",
        "authority": "NON_AUTHORITATIVE_ADVISORY",
        "canonical_write_allowed": False,
        "source": "next-distinct-sidecar",
        "model": {
            "family": EXPECTED_MODEL,
            "model_identifier": EXPECTED_MODEL,
            "checkpoint_sha256": EXPECTED_CHECKPOINT,
            "temperature": predictor["temperature"],
            "calibration": predictor["calibration"],
            "model_ready": predictor["model_ready"],
        },
        "model_ready": predictor["model_ready"],
        "history": history_meta,
        "prediction": prediction,
        "top1": predictor["top1"],
        "top3": predictor["top3"],
        "probabilities": predictor["probabilities"],
        "generated_at": freshness["generated_at"],
        "freshness": freshness,
        "prediction_status": "STALE" if freshness["state"] == "STALE" else "PREDICTED",
        "prediction_status_reason": "sidecar output is stale or history has advanced" if freshness["state"] == "STALE" else "latest eligible sidecar progression",
        "progression_index": int(records.get("progression_index")),
        "sequence_id": clean_id,
        "sidecar_record_schema": EXPECTED_RECORD_SCHEMA,
        "warning": "prediction-only advisory; not observed evidence, classification, guidance, or action",
    }


def _unavailable(session_id: str, reason: str, *, history: Mapping[str, Any] | None = None) -> dict[str, Any]:
    return {
        "schema_version": EXPECTED_ADAPTER_SCHEMA,
        "prediction_type": "NEXT_DISTINCT_TRUSTED_TACTIC",
        "dashboard_source": "FINAL_POC",
        "authority": "NON_AUTHORITATIVE_ADVISORY",
        "canonical_write_allowed": False,
        "source": "next-distinct-sidecar",
        "model": {"family": EXPECTED_MODEL, "checkpoint_sha256": EXPECTED_CHECKPOINT, "temperature": EXPECTED_TEMPERATURE},
        "history": dict(history or {"trusted_only": True, "length": 0}),
        "prediction": [],
        "top1": None,
        "top3": [],
        "prediction_status": "UNAVAILABLE",
        "prediction_status_reason": reason,
        "sequence_id": session_id,
        "freshness": {"state": "UNAVAILABLE"},
    }
