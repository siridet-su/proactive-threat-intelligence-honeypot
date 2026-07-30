"""Fail-closed runtime adapter for the frozen corrected-target PoC model.

This adapter is deliberately independent from the legacy next-tactic engine.
It runs exactly one configured Transformer, never consults a VOMM or heuristic
fallback, and emits an advisory snapshot that preserves the historical storage
envelope without claiming that the two target contracts are interchangeable.
"""

from __future__ import annotations

import hashlib
import json
import math
import time
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping

from production.prediction.next_behavior_contract import (
    SESSION_SCHEMA_VERSION,
    TARGET_CONTRACT_ID,
    TERMINAL_OUTCOME,
    TACTIC_VOCABULARY,
    require_valid_next_behavior_session,
)
from production.prediction.next_behavior_label_policy import normalize_classifier_outputs
from production.prediction.evidence_cutoff import require_valid_evidence_cutoff
from production.prediction.prediction_snapshot_contract import (
    SNAPSHOT_SCHEMA_VERSION,
    finalize_prediction_snapshot,
    prediction_snapshot_hash_input,
    validate_prediction_snapshot_integrity,
)
from production.prediction.next_behavior_model import load_checkpoint, predict_next_behavior
from production.prediction.next_behavior_preprocessing import build_live_model_input
from production.prediction.next_behavior_tensor import (
    require_valid_vocabulary,
    tensorize_model_input,
    vocabulary_sha256,
)
from production.utils.serialization import utc_now


MODE = "professor_approved_corrected_target_transformer_poc"
RUNTIME_SCHEMA_VERSION = "next_behavior_poc_runtime.v1"
AUTHORITY = {
    "advisory_only": True,
    "observed_evidence": False,
    "establishes_attacker_intent": False,
    "may_create_alert_alone": False,
    "may_support_hypothesis_claim": False,
    "may_select_guidance": False,
    "may_select_recommendation": False,
    "may_authorize_action": False,
    "automatic_execution": False,
}


class NextBehaviorRuntimeError(ValueError):
    """Raised when the frozen runtime contract or artifact set is invalid."""


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _require_sha(value: Any, field: str) -> str:
    text = _clean(value).lower()
    if len(text) != 64 or any(character not in "0123456789abcdef" for character in text):
        raise NextBehaviorRuntimeError(f"{field} must be a SHA-256 digest")
    return text


def _load_json(path: str | Path, expected_sha256: str, field: str) -> Dict[str, Any]:
    artifact_path = Path(path)
    if not artifact_path.is_file():
        raise NextBehaviorRuntimeError(f"{field} is missing")
    if _sha256_file(artifact_path) != _require_sha(expected_sha256, f"{field}_sha256"):
        raise NextBehaviorRuntimeError(f"{field} SHA-256 mismatch")
    try:
        value = json.loads(artifact_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NextBehaviorRuntimeError(f"{field} is malformed") from exc
    if not isinstance(value, dict):
        raise NextBehaviorRuntimeError(f"{field} must contain an object")
    return value


def _sigmoid_temperature(logit: float, temperature: float) -> float:
    scaled = float(logit) / temperature
    if scaled >= 0:
        return 1.0 / (1.0 + math.exp(-scaled))
    exponential = math.exp(scaled)
    return exponential / (1.0 + exponential)


def _apply_frozen_calibration(
    raw: Mapping[str, Any],
    mapping: Mapping[str, Any],
    policy: Mapping[str, Any],
    vocabulary_hash: str,
) -> Dict[str, Any]:
    expected = {
        "schema_version": "next_behavior_calibration_mapping.v1",
        "status": "valid",
        "method": "global_scalar_temperature_sigmoid.v1",
        "score_semantics": "raw_model_scores_not_probabilities",
        "target_contract_id": TARGET_CONTRACT_ID,
        "checkpoint_sha256": policy["transformer_checkpoint_sha256"],
        "vocabulary_sha256": vocabulary_hash,
        "preprocessing_sha256": policy["transformer_preprocessing_sha256"],
        "fit_partition_membership_sha256": policy[
            "calibration_membership_sha256"
        ],
    }
    for field, expected_value in expected.items():
        if mapping.get(field) != expected_value:
            raise NextBehaviorRuntimeError(
                f"calibration {field} does not match the frozen runtime"
            )
    if mapping.get("mapping_sha256") != policy.get("calibration_mapping_sha256"):
        raise NextBehaviorRuntimeError("calibration semantic SHA-256 mismatch")
    try:
        tactic_temperature = float(mapping["tactic_temperature"])
        terminal_temperature = float(mapping["terminal_temperature"])
    except (KeyError, TypeError, ValueError) as exc:
        raise NextBehaviorRuntimeError("calibration temperatures are invalid") from exc
    if (
        not math.isfinite(tactic_temperature)
        or tactic_temperature <= 0
        or not math.isfinite(terminal_temperature)
        or terminal_temperature <= 0
    ):
        raise NextBehaviorRuntimeError("calibration temperatures are invalid")
    ranked = sorted(
        (
            {
                "tactic": tactic,
                "raw_score": float(score),
                "rank": 0,
                "calibrated_probability": _sigmoid_temperature(
                    float(score), tactic_temperature
                ),
            }
            for tactic, score in raw["tactic_logits"].items()
        ),
        key=lambda item: (-item["raw_score"], item["tactic"]),
    )
    for index, item in enumerate(ranked, start=1):
        item["rank"] = index
    return {
        "ranked_tactics": ranked,
        "terminal_outcome": {
            "label": TERMINAL_OUTCOME,
            "raw_score": float(raw["terminal_logit"]),
            "calibrated_probability": _sigmoid_temperature(
                float(raw["terminal_logit"]), terminal_temperature
            ),
        },
        "calibration": {
            "status": "valid",
            "method": mapping["method"],
            "mapping_sha256": mapping["mapping_sha256"],
            "fit_partition_membership_sha256": mapping[
                "fit_partition_membership_sha256"
            ],
        },
    }


def _pseudonymous_id(kind: str, value: str) -> str:
    digest = hashlib.sha256(f"{kind}\x00{value}".encode("utf-8")).hexdigest()
    return f"nb{kind}_{digest}"


def _event_time_ms(value: Any, start: Any) -> int:
    try:
        event = datetime.fromisoformat(_clean(value).replace("Z", "+00:00"))
        origin = datetime.fromisoformat(_clean(start).replace("Z", "+00:00"))
        if event.tzinfo is None:
            event = event.replace(tzinfo=timezone.utc)
        if origin.tzinfo is None:
            origin = origin.replace(tzinfo=timezone.utc)
        return max(0, int((event - origin).total_seconds() * 1000))
    except (TypeError, ValueError):
        return 0


def _count_bucket(count: int) -> str:
    if count <= 0:
        return "0"
    if count == 1:
        return "1"
    if count <= 5:
        return "2-5"
    if count <= 20:
        return "6-20"
    return "21+"


def _age_bucket(seconds: float | None) -> str:
    if seconds is None or not math.isfinite(seconds) or seconds < 0:
        return "unknown"
    if seconds < 10:
        return "under_10s"
    if seconds < 60:
        return "10_to_60s"
    if seconds < 300:
        return "1_to_5m"
    return "over_5m"


def _confirmed_transfer(payload: Mapping[str, Any]) -> bool:
    for event in payload.get("raw_events") or []:
        if isinstance(event, Mapping) and _clean(event.get("eventid")) in {
            "cowrie.session.file_download",
            "cowrie.session.file_upload",
        }:
            return True
    return False


def build_live_next_behavior_session(
    payload: Mapping[str, Any],
    *,
    rule_policy_sha256: str,
    trust_policy_sha256: str,
    classifier_checkpoint_sha256: str,
    trusted_model_only_threshold: float = 0.90,
) -> Dict[str, Any] | None:
    """Convert bounded trusted runtime classification events to the v1 contract."""

    session_id = _clean(payload.get("session_id"))
    if not session_id:
        raise NextBehaviorRuntimeError("session_id is required")
    events = [
        dict(item)
        for item in payload.get("classification_events") or []
        if isinstance(item, Mapping)
    ]
    if not events:
        return None
    grouped: Dict[tuple[str, str, int], list[Dict[str, Any]]] = {}
    order: list[tuple[str, str, int]] = []
    for index, event in enumerate(events):
        try:
            compound_index = int(event.get("compound_command_index") or 0)
        except (TypeError, ValueError):
            compound_index = 0
        key = (
            _clean(event.get("cowrie_eventid") or event.get("evidence_id") or index),
            _clean(event.get("event_timestamp")),
            compound_index,
        )
        if key not in grouped:
            order.append(key)
            grouped[key] = []
        grouped[key].append(event)

    start = payload.get("start_time")
    command_count = len(payload.get("commands") or [])
    duration = payload.get("duration")
    try:
        age_seconds = float(duration) if duration not in (None, "") else None
    except (TypeError, ValueError):
        age_seconds = None
    context = {
        "login_outcome": (
            "success"
            if payload.get("login_success") is True
            else "failed"
            if int(payload.get("login_attempts") or 0) > 0
            else "unknown"
        ),
        "command_count_bucket": _count_bucket(command_count),
        "session_age_bucket": _age_bucket(age_seconds),
        "confirmed_transfer_observed": _confirmed_transfer(payload),
    }
    groups: list[Dict[str, Any]] = []
    for event_order, key in enumerate(order, start=1):
        normalized = normalize_classifier_outputs(
            grouped[key],
            private_evidence_prefix=f"{session_id}:{event_order}",
            policy_sha256=rule_policy_sha256,
            trust_policy_sha256=trust_policy_sha256,
            checkpoint_sha256=classifier_checkpoint_sha256,
            tactic_lookup=lambda _technique: "",
            trusted_model_only_threshold=trusted_model_only_threshold,
        )
        trusted = [
            item
            for item in normalized["labels"]
            if item.get("trust_tier") == "trusted_observation"
        ]
        if not trusted:
            continue
        timestamp = key[1]
        safe_labels = []
        for label_index, label in enumerate(trusted):
            item = deepcopy(label)
            item["evidence_ref"] = _pseudonymous_id(
                "evidence",
                f"{session_id}:{event_order}:{label_index}:{item['evidence_ref']}",
            )
            safe_labels.append(item)
        groups.append(
            {
                "group_id": _pseudonymous_id("group", f"{session_id}:{event_order}"),
                "event_order": event_order,
                "relative_time_ms": _event_time_ms(timestamp, start),
                "tactics": sorted({item["tactic"] for item in safe_labels}),
                "techniques": sorted({item["technique"] for item in safe_labels}),
                "evidence_refs": sorted({item["evidence_ref"] for item in safe_labels}),
                "label_provenance": sorted(
                    safe_labels,
                    key=lambda item: (
                        item["tactic"],
                        item["technique"],
                        item["source"],
                        item["evidence_ref"],
                    ),
                ),
                "audit_only_labels": [],
                "session_context": context,
            }
        )
    if not groups:
        return None
    safe = {
        "schema_version": SESSION_SCHEMA_VERSION,
        "session_id": _pseudonymous_id("session", session_id),
        "source_member_id": _pseudonymous_id("member", "production-live"),
        "source_member_sha256": hashlib.sha256(b"production-live").hexdigest(),
        "protocol": _clean(payload.get("protocol") or "ssh").lower(),
        "status": "closed" if payload.get("is_ended") or payload.get("status") == "closed" else "active",
        "pseudonymization_key_id": "runtime-derived-identifiers-v1",
        "audit_summary": {"total": 0, "by_reason": {}},
        "observation_groups": groups,
    }
    return require_valid_next_behavior_session(safe)


class FrozenTransformerPocPredictor:
    """Strict single-model corrected-target inference with unavailable snapshots."""

    def __init__(self, policy: Mapping[str, Any]) -> None:
        self.policy = deepcopy(dict(policy))
        self.enabled = bool(self.policy.get("enabled", True))
        self.load_error = ""
        self.model = None
        self.metadata: Dict[str, Any] = {}
        self.spec: Dict[str, Any] = {}
        self.vocabulary: Dict[str, Any] = {}
        self.calibration: Dict[str, Any] = {}
        self.vocabulary_hash = ""
        self.load_time_ms = 0.0
        if not self.enabled:
            return
        started = time.perf_counter()
        try:
            if self.policy.get("prediction_mode") != MODE:
                raise NextBehaviorRuntimeError("prediction mode is not the frozen Transformer PoC")
            self.spec = _load_json(
                self.policy["transformer_model_spec_path"],
                self.policy["transformer_model_spec_file_sha256"],
                "model_spec",
            )
            self.vocabulary = require_valid_vocabulary(
                _load_json(
                    self.policy["transformer_vocabulary_path"],
                    self.policy["transformer_vocabulary_file_sha256"],
                    "vocabulary",
                )
            )
            self.vocabulary_hash = vocabulary_sha256(self.vocabulary)
            if self.vocabulary_hash != _require_sha(
                self.policy["transformer_vocabulary_sha256"],
                "transformer_vocabulary_sha256",
            ):
                raise NextBehaviorRuntimeError("vocabulary semantic SHA-256 mismatch")
            self.calibration = _load_json(
                self.policy["transformer_calibration_path"],
                self.policy["transformer_calibration_file_sha256"],
                "calibration",
            )
            _apply_frozen_calibration(
                {
                    "tactic_logits": {
                        tactic: 0.0 for tactic in self.spec["output"]["tactics"]
                    },
                    "terminal_logit": 0.0,
                },
                self.calibration,
                self.policy,
                self.vocabulary_hash,
            )
            preprocessing_path = Path(self.policy["transformer_preprocessing_path"])
            if _sha256_file(preprocessing_path) != _require_sha(
                self.policy["transformer_preprocessing_sha256"],
                "transformer_preprocessing_sha256",
            ):
                raise NextBehaviorRuntimeError("preprocessing SHA-256 mismatch")
            for path_field, hash_field, label in (
                (
                    "runtime_rule_policy_path",
                    "runtime_rule_policy_sha256",
                    "runtime rule policy",
                ),
                (
                    "runtime_trust_policy_path",
                    "runtime_trust_policy_sha256",
                    "runtime trust policy",
                ),
                (
                    "runtime_classifier_checkpoint_path",
                    "runtime_classifier_checkpoint_sha256",
                    "runtime classifier checkpoint",
                ),
            ):
                runtime_path = Path(self.policy[path_field])
                if not runtime_path.is_file():
                    raise NextBehaviorRuntimeError(f"{label} is missing")
                if _sha256_file(runtime_path) != _require_sha(
                    self.policy[hash_field],
                    hash_field,
                ):
                    raise NextBehaviorRuntimeError(f"{label} SHA-256 mismatch")
            self.model, self.metadata = load_checkpoint(
                self.policy["transformer_checkpoint_path"],
                expected_spec=self.spec,
                expected_checkpoint_sha256=self.policy[
                    "transformer_checkpoint_sha256"
                ],
            )
            if self.metadata["parameter_count"] != int(
                self.policy["transformer_parameter_count"]
            ):
                raise NextBehaviorRuntimeError("Transformer parameter count mismatch")
            if self.metadata["initialization_seed"] != int(
                self.policy["transformer_seed"]
            ):
                raise NextBehaviorRuntimeError("Transformer seed mismatch")
        except Exception as exc:
            self.model = None
            self.load_error = exc.__class__.__name__
        self.load_time_ms = (time.perf_counter() - started) * 1000.0

    def _base_snapshot(
        self,
        payload: Mapping[str, Any],
        *,
        event_id: str,
        status: str,
        reason: str,
        evidence_cutoff: Mapping[str, Any] | None = None,
    ) -> Dict[str, Any]:
        session_id = _clean(payload.get("session_id") or "unknown")
        snapshot = {
            "schema_version": SNAPSHOT_SCHEMA_VERSION,
            "session_id": session_id,
            "generated_at": utc_now(),
            "event_id": event_id,
            "session_status": "closed" if payload.get("is_ended") else "active",
            "prediction_mode": MODE,
            "prediction_contract": TARGET_CONTRACT_ID,
            "prediction_status": status,
            "prediction_status_reason": reason,
            "prediction": [],
            "final_ranking": [],
            "engine": {
                "name": "frozen-corrected-target-transformer",
                "version": "1",
                "target_semantics": "unordered_next_distinct_behavior_phase_or_session_end",
            },
            "active_model": {
                "role": "primary_experimental_poc_predictor",
                "model_type": "small_causal_transformer",
                "checkpoint_sha256": _clean(
                    self.policy.get("transformer_checkpoint_sha256")
                ),
                "seed": self.policy.get("transformer_seed"),
                "parameter_count": self.policy.get("transformer_parameter_count"),
                "vocabulary_sha256": _clean(
                    self.policy.get("transformer_vocabulary_sha256")
                ),
                "preprocessing_sha256": _clean(
                    self.policy.get("transformer_preprocessing_sha256")
                ),
                "immutable_final_result_sha256": _clean(
                    self.policy.get("immutable_final_result_sha256")
                ),
                "runtime_rule_policy_sha256": _clean(
                    self.policy.get("runtime_rule_policy_sha256")
                ),
                "runtime_trust_policy_sha256": _clean(
                    self.policy.get("runtime_trust_policy_sha256")
                ),
                "runtime_classifier_checkpoint_sha256": _clean(
                    self.policy.get("runtime_classifier_checkpoint_sha256")
                ),
            },
            "authority": deepcopy(AUTHORITY),
            "deployment_decision": (
                "Deployed as a professor-approved experimental PoC model for "
                "frequent-behavior aggregate performance despite remaining "
                "BLOCKED_AT_SELECTION under the original rare-class eligibility policy."
            ),
            "original_selection_status": "BLOCKED_AT_SELECTION",
            "predictive_alert": {
                "status": "prohibited",
                "reason": "corrected-target prediction alone cannot create an alert",
                "authority": deepcopy(AUTHORITY),
            },
            "runtime": {
                "schema_version": RUNTIME_SCHEMA_VERSION,
                "model_load_time_ms": self.load_time_ms,
                "inference_latency_ms": None,
                "device": "cpu",
                "dtype": "float32",
            },
        }
        if evidence_cutoff is not None:
            cutoff = require_valid_evidence_cutoff(evidence_cutoff)
            if cutoff["event_id"] != event_id:
                raise NextBehaviorRuntimeError(
                    "prediction event_id does not match evidence cutoff"
                )
            snapshot["evidence_cutoff"] = cutoff
        return snapshot

    def predict_session(
        self,
        payload: Mapping[str, Any],
        *,
        event_id: str = "",
        evidence_cutoff: Mapping[str, Any] | None = None,
    ) -> Dict[str, Any]:
        if not self.enabled:
            return finalize_prediction_snapshot(
                self._base_snapshot(
                    payload,
                    event_id=event_id,
                    status="model_unavailable",
                    reason="predictor_disabled",
                    evidence_cutoff=evidence_cutoff,
                )
            )
        if self.model is None:
            return finalize_prediction_snapshot(
                self._base_snapshot(
                    payload,
                    event_id=event_id,
                    status="model_unavailable",
                    reason=(
                        "frozen_artifact_validation_failed:"
                        f"{self.load_error or 'unknown'}"
                    ),
                    evidence_cutoff=evidence_cutoff,
                )
            )
        started = time.perf_counter()
        try:
            safe_session = build_live_next_behavior_session(
                payload,
                rule_policy_sha256=self.policy["runtime_rule_policy_sha256"],
                trust_policy_sha256=self.policy["runtime_trust_policy_sha256"],
                classifier_checkpoint_sha256=self.policy[
                    "runtime_classifier_checkpoint_sha256"
                ],
                trusted_model_only_threshold=float(
                    self.policy.get("trusted_model_only_threshold", 0.90)
                ),
            )
            if safe_session is None:
                return finalize_prediction_snapshot(self._base_snapshot(
                    payload,
                    event_id=event_id,
                    status="insufficient_history",
                    reason="no_trusted_behavior_phase",
                    evidence_cutoff=evidence_cutoff,
                ))
            model_input = build_live_model_input(
                safe_session,
                max_sequence_length=int(self.spec["architecture"]["maximum_sequence_length"]),
            )
            tensor = tensorize_model_input(model_input, self.vocabulary)
            raw = predict_next_behavior(self.model, tensor, spec=self.spec)
            calibrated = _apply_frozen_calibration(
                raw,
                self.calibration,
                self.policy,
                self.vocabulary_hash,
            )
            threshold = float(self.policy.get("tactic_probability_threshold", 0.5))
            terminal_threshold = float(
                self.policy.get("terminal_probability_threshold", 0.5)
            )
            terminal_probability = calibrated["terminal_outcome"][
                "calibrated_probability"
            ]
            if terminal_probability >= terminal_threshold:
                prediction_set: list[str] = []
                outcome = TERMINAL_OUTCOME
            else:
                prediction_set = sorted(
                    item["tactic"]
                    for item in calibrated["ranked_tactics"]
                    if item["calibrated_probability"] >= threshold
                )
                if not prediction_set:
                    prediction_set = [calibrated["ranked_tactics"][0]["tactic"]]
                outcome = "next_behavior_phase"
            snapshot = self._base_snapshot(
                payload,
                event_id=event_id,
                status="predicted",
                reason="frozen_transformer_inference_succeeded",
                evidence_cutoff=evidence_cutoff,
            )
            snapshot["prediction"] = prediction_set
            snapshot["final_ranking"] = [
                {
                    "tactic": item["tactic"],
                    "score": item["calibrated_probability"],
                    "raw_score": item["raw_score"],
                    "confidence": "not_applicable",
                    "sources": [
                        {
                            "name": "frozen_corrected_target_transformer",
                            "source_type": "experimental_statistical_forecast",
                            "weighted_score": item["calibrated_probability"],
                        }
                    ],
                    "reasons": ["frozen corrected-target Transformer output"],
                }
                for item in calibrated["ranked_tactics"]
                if item["tactic"] in prediction_set
            ]
            snapshot["next_behavior_output"] = {
                "outcome_type": outcome,
                "prediction_set": prediction_set,
                "terminal_outcome": outcome == TERMINAL_OUTCOME,
                "ranked_tactics": calibrated["ranked_tactics"],
                "terminal": calibrated["terminal_outcome"],
                "calibration": calibrated["calibration"],
                "set_semantics": "unordered_multilabel_tactic_set",
            }
            snapshot["model_input"] = {
                "input_hash": model_input["input_hash"],
                "sequence_length": len(model_input["phase_sequence"]),
                "truncated": model_input["truncated"],
                "input_evidence_refs": model_input["input_evidence_refs"],
            }
            snapshot["runtime"]["inference_latency_ms"] = (
                time.perf_counter() - started
            ) * 1000.0
            return finalize_prediction_snapshot(snapshot)
        except Exception as exc:
            snapshot = self._base_snapshot(
                payload,
                event_id=event_id,
                status="model_unavailable",
                reason=f"inference_failed:{exc.__class__.__name__}",
                evidence_cutoff=evidence_cutoff,
            )
            snapshot["runtime"]["inference_latency_ms"] = (
                time.perf_counter() - started
            ) * 1000.0
            return finalize_prediction_snapshot(snapshot)
