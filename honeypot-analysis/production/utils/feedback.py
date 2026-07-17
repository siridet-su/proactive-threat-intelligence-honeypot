"""Typed prediction feedback helpers.

The realtime predictor is allowed to learn from observed evidence and expert
review. SME operator feedback is still valuable, but it measures usefulness and
response workflow, not ATT&CK ground truth.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Iterable, List, Tuple

from production.classification.trust import is_trusted_classification_event
from production.utils.sensitive_data import redact_for_api, redact_for_artifact
from production.utils.serialization import stable_json, utc_now


AUTO_EVIDENCE = "auto_evidence"
OPERATOR_USEFULNESS = "operator_usefulness"
OPERATOR_ACTION = "operator_action"
EXPERT_REVIEW = "expert_review"

LIVE_COWRIE = "live_cowrie"
CONTROLLED_TEST = "controlled_test"
REPLAY = "replay"
EXPERT_REVIEW_ORIGIN = "expert_review"

FEEDBACK_TYPES = {AUTO_EVIDENCE, OPERATOR_USEFULNESS, OPERATOR_ACTION, EXPERT_REVIEW}
EVIDENCE_ORIGINS = {LIVE_COWRIE, CONTROLLED_TEST, REPLAY, EXPERT_REVIEW_ORIGIN}
OPERATOR_USEFULNESS_SIGNALS = {"useful", "not_useful", "not_sure"}
OPERATOR_ACTION_STATUSES = {"done", "ignored", "need_help"}
DEFAULT_WEIGHT_FEEDBACK_TYPES = {AUTO_EVIDENCE, EXPERT_REVIEW}
DEFAULT_PRODUCTION_CALIBRATION_ORIGINS = {LIVE_COWRIE, EXPERT_REVIEW_ORIGIN}
DEFAULT_AUTO_EVIDENCE_CONFIDENCE = 0.90
MAX_SUBMITTED_FEEDBACK_STRING_CHARS = 16_384

SUBMITTED_FEEDBACK_FIELDS = (
    "session_id",
    "snapshot_id",
    "label",
    "feedback_type",
    "evidence_origin",
    "operator_signal",
    "action_status",
    "correct_next_tactic",
    "observed_prefix",
    "predicted_top_tactic",
    "predicted_ranking",
    "smb_decision_id",
    "smb_risk",
    "smb_top_actions",
    "final_actual_next_tactic",
    "tactic_granularity",
    "notes",
)


def _text(value: Any) -> str:
    return str(value or "").strip()


def _lower(value: Any) -> str:
    return _text(value).lower().replace(" ", "_")


def _float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _payload_from_row(row: Dict[str, Any]) -> Dict[str, Any]:
    payload = row.get("payload")
    if isinstance(payload, dict):
        return dict(payload)
    raw = row.get("payload_json")
    if isinstance(raw, dict):
        return dict(raw)
    if isinstance(raw, str) and raw.strip():
        try:
            loaded = json.loads(raw)
        except json.JSONDecodeError:
            loaded = {}
        if isinstance(loaded, dict):
            return loaded
    return {}


def merged_feedback_payload(row: Dict[str, Any]) -> Dict[str, Any]:
    """Return a single feedback dict with row columns overriding payload JSON."""

    payload = _payload_from_row(row)
    merged = dict(payload)
    for key, value in row.items():
        if key in {"payload", "payload_json"}:
            continue
        if value not in (None, ""):
            merged[key] = value
    return merged


def _infer_feedback_type(payload: Dict[str, Any]) -> str:
    explicit = _lower(payload.get("feedback_type"))
    if explicit:
        if explicit not in FEEDBACK_TYPES:
            raise ValueError(f"unsupported feedback_type: {explicit}")
        return explicit

    label = _lower(payload.get("label"))
    if _text(payload.get("action_status")) or label in OPERATOR_ACTION_STATUSES:
        return OPERATOR_ACTION
    if _text(payload.get("operator_signal")) or label in OPERATOR_USEFULNESS_SIGNALS:
        return OPERATOR_USEFULNESS
    if label.startswith("auto_") or _lower(payload.get("source")) == AUTO_EVIDENCE:
        return AUTO_EVIDENCE
    if _text(payload.get("final_actual_next_tactic")) or _text(payload.get("correct_next_tactic")):
        return EXPERT_REVIEW
    return OPERATOR_USEFULNESS


def infer_evidence_origin(payload: Dict[str, Any]) -> str:
    """Return the evidence origin used for production calibration gates."""

    explicit = _lower(payload.get("evidence_origin") or payload.get("feedback_origin"))
    if explicit:
        if explicit not in EVIDENCE_ORIGINS:
            raise ValueError(f"unsupported evidence_origin: {explicit}")
        return explicit

    session_id = _lower(payload.get("session_id"))
    sensor = _lower(payload.get("sensor"))
    source = _lower(payload.get("source") or payload.get("event_source"))
    if bool(payload.get("controlled_test")) or bool(payload.get("controlled_seed")):
        return CONTROLLED_TEST
    if (
        session_id.startswith("sme_auto_evidence_seed")
        or session_id.startswith("sme_feedback_control")
        or session_id.startswith("controlled-test")
    ):
        return CONTROLLED_TEST
    if "controlled" in sensor or "controlled" in source:
        return CONTROLLED_TEST
    if bool(payload.get("replay")) or _text(payload.get("replay_id")) or source == REPLAY:
        return REPLAY
    if _lower(payload.get("feedback_type")) == EXPERT_REVIEW:
        return EXPERT_REVIEW_ORIGIN
    return LIVE_COWRIE


def normalize_feedback_payload(
    feedback: Dict[str, Any],
    *,
    now: str | None = None,
    min_auto_evidence_confidence: float = DEFAULT_AUTO_EVIDENCE_CONFIDENCE,
) -> Dict[str, Any]:
    """Normalize feedback into explicit SME-safe types.

    ``label`` remains for backward compatibility, but ``feedback_type`` is the
    authority for whether a row can be used by calibration.
    """

    payload = redact_for_artifact(dict(feedback))
    current_time = now or _text(payload.get("created_at")) or utc_now()
    payload.setdefault("created_at", current_time)
    payload["session_id"] = _text(payload.get("session_id"))
    payload["snapshot_id"] = _text(payload.get("snapshot_id"))
    payload["tactic_granularity"] = _text(payload.get("tactic_granularity")) or "tactic"

    feedback_type = _infer_feedback_type(payload)
    payload["feedback_type"] = feedback_type
    payload["evidence_origin"] = infer_evidence_origin(payload)

    if feedback_type == OPERATOR_USEFULNESS:
        signal = _lower(payload.get("operator_signal") or payload.get("label"))
        if signal not in OPERATOR_USEFULNESS_SIGNALS:
            signal = "not_sure"
        payload["operator_signal"] = signal
        payload["label"] = signal
        payload["label_authority"] = "sme_operator_usefulness"
        payload["weight_eligible"] = False
    elif feedback_type == OPERATOR_ACTION:
        status = _lower(payload.get("action_status") or payload.get("label"))
        if status not in OPERATOR_ACTION_STATUSES:
            status = "need_help"
        payload["action_status"] = status
        payload["label"] = status
        payload["label_authority"] = "sme_operator_action"
        payload["weight_eligible"] = False
    elif feedback_type == AUTO_EVIDENCE:
        payload["label"] = _text(payload.get("label")) or "auto_observed_next_tactic"
        payload["label_authority"] = "system_later_session_event"
        confidence = _float(payload.get("evidence_confidence"), 0.0)
        payload["evidence_confidence"] = round(confidence, 4)
        payload["weight_eligible"] = bool(
            _text(payload.get("predicted_top_tactic"))
            and _actual_next_tactic(payload)
            and confidence >= float(min_auto_evidence_confidence)
        )
    elif feedback_type == EXPERT_REVIEW:
        if not _text(feedback.get("evidence_origin") or feedback.get("feedback_origin")):
            payload["evidence_origin"] = EXPERT_REVIEW_ORIGIN
        payload["label"] = _text(payload.get("label")) or "expert_review"
        payload["label_authority"] = "security_expert"
        payload.setdefault("analyst_corrected_at", current_time)
        payload["weight_eligible"] = bool(_text(payload.get("predicted_top_tactic")) and _actual_next_tactic(payload))

    for key in ("observed_prefix", "predicted_ranking", "full_prediction_ranking"):
        if isinstance(payload.get(key), (dict, list)):
            payload[key] = stable_json(payload[key])

    return payload


def normalize_submitted_feedback_payload(
    feedback: Dict[str, Any],
    *,
    source: str,
    now: str | None = None,
) -> Dict[str, Any]:
    """Allowlist and redact feedback received at an HTTP trust boundary."""

    if not isinstance(feedback, dict):
        raise ValueError("feedback must be an object")
    selected = {
        key: feedback.get(key)
        for key in SUBMITTED_FEEDBACK_FIELDS
        if key in feedback
    }
    if "evidence_origin" not in selected and "feedback_origin" in feedback:
        selected["evidence_origin"] = feedback.get("feedback_origin")
    current_time = now or utc_now()
    selected["created_at"] = current_time
    selected["source"] = str(source or "http_feedback")
    redacted = redact_for_api(
        selected,
        max_string_chars=MAX_SUBMITTED_FEEDBACK_STRING_CHARS,
    )
    payload = normalize_feedback_payload(redacted, now=current_time)
    if not payload["session_id"]:
        raise ValueError("session_id is required")
    if not payload["label"]:
        raise ValueError("label is required")
    return payload


def _actual_next_tactic(payload: Dict[str, Any]) -> str:
    return _text(payload.get("final_actual_next_tactic") or payload.get("correct_next_tactic"))


def feedback_weight_signal(
    row: Dict[str, Any],
    policy: Dict[str, Any] | None = None,
) -> Tuple[bool, float, str]:
    """Return whether feedback can affect weights and the resulting score.

    Operator usefulness/action feedback intentionally never returns usable.
    """

    policy = policy or {}
    allowed_types = {
        _lower(item)
        for item in (policy.get("allowed_weight_feedback_types") or sorted(DEFAULT_WEIGHT_FEEDBACK_TYPES))
    }
    allowed_origins = {
        _lower(item)
        for item in (
            policy.get("allowed_calibration_evidence_origins")
            or sorted(DEFAULT_PRODUCTION_CALIBRATION_ORIGINS)
        )
    }
    min_auto_confidence = float(
        policy.get("min_auto_evidence_confidence") or DEFAULT_AUTO_EVIDENCE_CONFIDENCE
    )
    payload = normalize_feedback_payload(
        merged_feedback_payload(row),
        min_auto_evidence_confidence=min_auto_confidence,
    )
    feedback_type = _lower(payload.get("feedback_type"))
    if feedback_type not in allowed_types:
        return False, 0.0, f"feedback_type {feedback_type} is not weight eligible"
    evidence_origin = _lower(payload.get("evidence_origin"))
    if evidence_origin not in allowed_origins:
        return False, 0.0, f"evidence_origin {evidence_origin} is not production calibration eligible"
    if feedback_type == AUTO_EVIDENCE and _float(payload.get("evidence_confidence"), 0.0) < min_auto_confidence:
        return False, 0.0, "auto evidence confidence below threshold"
    predicted = _text(payload.get("predicted_top_tactic"))
    actual = _actual_next_tactic(payload)
    if not predicted or not actual:
        return False, 0.0, "missing predicted or actual next tactic"
    return True, 1.0 if predicted == actual else 0.0, "eligible evidence label"


def _classification_confidence(event: Dict[str, Any]) -> float:
    for key in ("confidence", "bert_confidence", "rule_confidence"):
        if event.get(key) not in (None, ""):
            return _float(event.get(key), 0.0)
    source = _lower(event.get("source"))
    if source in {"rule", "both"}:
        return 1.0
    return 0.0


def _tactic_sequence(events: Iterable[Dict[str, Any]]) -> List[str]:
    output: List[str] = []
    for event in events:
        tactic = _text(event.get("tactic"))
        if tactic and tactic != "unknown":
            output.append(tactic)
    return output


def build_auto_evidence_feedback(
    prediction_snapshot: Dict[str, Any],
    session_payload: Dict[str, Any],
    *,
    min_confidence: float = DEFAULT_AUTO_EVIDENCE_CONFIDENCE,
) -> Dict[str, Any] | None:
    """Create a conservative auto label from later observed session evidence.

    The label is only produced when a later classification event exists after
    the snapshot prefix and that event has high classification confidence.
    """

    snapshot_payload = prediction_snapshot.get("payload") if isinstance(prediction_snapshot.get("payload"), dict) else prediction_snapshot
    features = snapshot_payload.get("features") or {}
    prefix_events = [
        event for event in features.get("classification_events") or []
        if isinstance(event, dict) and is_trusted_classification_event(event)
    ]
    all_events = [
        event for event in session_payload.get("classification_events") or []
        if isinstance(event, dict) and is_trusted_classification_event(event)
    ]
    if len(all_events) <= len(prefix_events):
        return None

    ranking = snapshot_payload.get("final_ranking") or []
    predicted_top = ""
    if isinstance(ranking, list) and ranking and isinstance(ranking[0], dict):
        predicted_top = _text(ranking[0].get("tactic"))
    if not predicted_top:
        return None

    for index, event in enumerate(all_events[len(prefix_events) :], start=len(prefix_events)):
        tactic = _text(event.get("tactic"))
        if not tactic or tactic == "unknown":
            continue
        confidence = _classification_confidence(event)
        if confidence < min_confidence:
            continue
        feedback = {
            "feedback_type": AUTO_EVIDENCE,
            "session_id": _text(snapshot_payload.get("session_id") or session_payload.get("session_id")),
            "snapshot_id": _text(snapshot_payload.get("snapshot_id")),
            "label": "auto_observed_next_tactic",
            "observed_prefix": features.get("tactic_sequence") or _tactic_sequence(prefix_events),
            "predicted_top_tactic": predicted_top,
            "predicted_ranking": ranking,
            "final_actual_next_tactic": tactic,
            "correct_next_tactic": tactic,
            "tactic_granularity": "tactic",
            "evidence_confidence": confidence,
            "evidence_event_index": index,
            "evidence_ttp": _text(event.get("ttp")),
            "evidence_tactic": tactic,
            "evidence_source": _text(event.get("source")),
            "evidence_command": _text(event.get("command") or event.get("input")),
            "evidence_origin": infer_evidence_origin(session_payload),
            "notes": "Auto label from later high-confidence classification event.",
        }
        return normalize_feedback_payload(feedback, min_auto_evidence_confidence=min_confidence)
    return None
