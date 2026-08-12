"""Integrity-bound distinct trusted behavior history for Transformer inputs.

Version 3 preserves the causal fields needed to reproduce live preprocessing.
Historical v1/v2 manifests remain readable records, but are not inference
eligible because they do not contain the required time/provenance semantics.
"""

from __future__ import annotations

import hashlib
from copy import deepcopy
from datetime import datetime
from typing import Any, Dict, Iterable, List, Mapping

from production.prediction.evidence_cutoff import validate_evidence_cutoff
from production.utils.serialization import stable_json


SCHEMA_VERSION = "prediction_trusted_history_manifest.v3"
COMPATIBILITY_SCHEMA_VERSION = "prediction_trusted_history_manifest.v2"
LEGACY_SCHEMA_VERSION = "prediction_trusted_history_manifest.v1"
MAX_TRUSTED_PHASES = 8
TARGET_CONTRACT_ID = "next_distinct_trusted_behavior_phase_or_session_end.v2"
PHASE_KEYS = frozenset({
    "phase_index", "start_command_index", "end_command_index", "event_id",
    "start_timestamp", "end_timestamp", "observation_count", "tactics",
    "techniques", "labels", "label_provenance_sources",
    "label_confidence_buckets", "label_agreement_statuses",
    "audit_only_label_count", "command_outcomes", "outcome_scopes",
    "fragment_execution_states", "evidence_refs", "phase_sha256",
})
SOURCE_MAP = {
    "rule": "reviewed_rule",
    "both": "rule_model_agreement",
    "model": "securebert",
    "reviewed_rule": "reviewed_rule",
    "rule_model_agreement": "rule_model_agreement",
    "securebert": "securebert",
}


def _text(value: Any) -> str:
    return str(value or "").strip()


def _sha(value: Any) -> str:
    return hashlib.sha256(stable_json(value).encode("utf-8")).hexdigest()


def _timestamp(value: Any) -> str:
    text = _text(value)
    if not text:
        return ""
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return ""
    return text if parsed.tzinfo is not None else ""


def _source(value: Any) -> str:
    return SOURCE_MAP.get(_text(value).lower(), "")


def _confidence_bucket(label: Mapping[str, Any]) -> str:
    explicit = _text(label.get("confidence_bucket"))
    if explicit in {"high", "medium", "low", "not_applicable"}:
        return explicit
    raw = label.get("confidence")
    if raw in (None, ""):
        return "not_applicable"
    try:
        confidence = float(raw)
    except (TypeError, ValueError):
        return "not_applicable"
    if confidence >= 0.9:
        return "high"
    if confidence >= 0.55:
        return "medium"
    return "low"


def _agreement(value: Any, source: str) -> str:
    text = _text(value).lower()
    if "disagreement" in text:
        return "disagreed"
    if "agreement" in text or text == "agreed":
        return "agreed"
    if "model_only" in text:
        return "model_only"
    if "rule_only" in text:
        return "rule_only"
    if text in {"unreviewed", "emergency"}:
        return text
    return "agreed" if source == "rule_model_agreement" else (
        "model_only" if source == "securebert" else "rule_only"
    )


def _phase_hash_basis(phase: Mapping[str, Any]) -> dict[str, Any]:
    basis = deepcopy(dict(phase))
    basis.pop("phase_sha256", None)
    return basis


def phase_sha256(phase: Mapping[str, Any]) -> str:
    return _sha(_phase_hash_basis(phase))


def _labels(phase: Mapping[str, Any]) -> List[Dict[str, Any]]:
    raw_labels = phase.get("labels")
    if not isinstance(raw_labels, list):
        tactics = [
            _text(item) for item in phase.get("tactics") or []
            if _text(item) and _text(item).lower() != "unknown"
        ]
        techniques = [
            _text(item).upper() for item in phase.get("techniques") or []
            if _text(item) and _text(item).upper() != "T0000_UNKNOWN"
        ]
        raw_labels = (
            [{"tactic": tactics[0], "technique": techniques[0]}]
            if len(tactics) == len(techniques) == 1 else []
        )
    labels: dict[tuple[str, str, str, str, str, str], dict[str, Any]] = {}
    for raw in raw_labels:
        if not isinstance(raw, Mapping):
            continue
        tactic = _text(raw.get("tactic"))
        technique = _text(raw.get("technique")).upper()
        if not tactic or tactic.lower() == "unknown" or not technique or technique == "T0000_UNKNOWN":
            continue
        source = _source(raw.get("source") or phase.get("source")) or "reviewed_rule"
        confidence_bucket = _confidence_bucket(raw)
        agreement_status = _agreement(
            raw.get("agreement_status") or phase.get("agreement_status"), source
        )
        evidence_id = _text(
            raw.get("classification_evidence_id")
            or raw.get("evidence_id")
            or phase.get("event_id")
        )
        item = {
            "tactic": tactic,
            "technique": technique,
            "source": source,
            "confidence_bucket": confidence_bucket,
            "agreement_status": agreement_status,
        }
        if evidence_id:
            item["classification_evidence_id"] = evidence_id
        key = (tactic, technique, source, confidence_bucket, agreement_status, evidence_id)
        labels[key] = item
    return [labels[key] for key in sorted(labels)]


def _one_phase(raw: Mapping[str, Any], index: int) -> Dict[str, Any] | None:
    labels = _labels(raw)
    if not labels:
        return None
    start_index = raw.get("start_command_index", raw.get("command_index", index))
    end_index = raw.get("end_command_index", raw.get("command_index", start_index))
    try:
        start_index, end_index = int(start_index), int(end_index)
    except (TypeError, ValueError):
        start_index = end_index = index
    start_timestamp = _timestamp(raw.get("start_timestamp") or raw.get("event_timestamp"))
    end_timestamp = _timestamp(raw.get("end_timestamp") or raw.get("event_timestamp"))
    evidence_refs = sorted({
        _text(item.get("classification_evidence_id"))
        for item in labels if _text(item.get("classification_evidence_id"))
    } | {
        _text(item) for item in raw.get("evidence_refs") or [] if _text(item)
    })
    return {
        "phase_index": index,
        "start_command_index": max(start_index, 0),
        "end_command_index": max(end_index, start_index, 0),
        "event_id": _text(raw.get("event_id")),
        "start_timestamp": start_timestamp,
        "end_timestamp": end_timestamp,
        "observation_count": max(int(raw.get("observation_count") or 1), 1),
        "tactics": sorted({item["tactic"] for item in labels}),
        "techniques": sorted({item["technique"] for item in labels}),
        "labels": labels,
        "label_provenance_sources": sorted({item["source"] for item in labels}),
        "label_confidence_buckets": sorted({item["confidence_bucket"] for item in labels}),
        "label_agreement_statuses": sorted({item["agreement_status"] for item in labels}),
        "audit_only_label_count": max(int(raw.get("audit_only_label_count") or 0), 0),
        "command_outcomes": sorted({_text(item) for item in raw.get("command_outcomes") or [raw.get("command_outcome")] if _text(item)}),
        "outcome_scopes": sorted({_text(item) for item in raw.get("outcome_scopes") or [raw.get("outcome_scope")] if _text(item)}),
        "fragment_execution_states": sorted({_text(item) for item in raw.get("fragment_execution_states") or [raw.get("fragment_execution")] if _text(item)}),
        "evidence_refs": evidence_refs,
    }


def _merge_phase(left: Dict[str, Any], right: Mapping[str, Any]) -> Dict[str, Any]:
    merged = deepcopy(left)
    merged["end_command_index"] = int(right["end_command_index"])
    merged["event_id"] = _text(right.get("event_id")) or merged["event_id"]
    merged["end_timestamp"] = _text(right.get("end_timestamp")) or merged["end_timestamp"]
    merged["observation_count"] += int(right.get("observation_count") or 1)
    for field in (
        "techniques", "labels", "label_provenance_sources",
        "label_confidence_buckets", "label_agreement_statuses",
        "command_outcomes", "outcome_scopes", "fragment_execution_states",
        "evidence_refs",
    ):
        values = [*merged.get(field, []), *deepcopy(list(right.get(field) or []))]
        if field == "labels":
            keyed = {
                stable_json(item): item for item in values if isinstance(item, Mapping)
            }
            merged[field] = [keyed[key] for key in sorted(keyed)]
        else:
            merged[field] = sorted({_text(item) for item in values if _text(item)})
    merged["audit_only_label_count"] += int(right.get("audit_only_label_count") or 0)
    return merged


def normalize_trusted_phases(
    phases: Iterable[Mapping[str, Any]], *, cap: int | None = MAX_TRUSTED_PHASES
) -> List[Dict[str, Any]]:
    """Collapse consecutive equal tactic sets before applying the phase cap."""

    result: List[Dict[str, Any]] = []
    for raw in phases or []:
        if not isinstance(raw, Mapping):
            continue
        phase = _one_phase(raw, len(result))
        if phase is None:
            continue
        if result and result[-1]["tactics"] == phase["tactics"]:
            result[-1] = _merge_phase(result[-1], phase)
        else:
            phase["phase_index"] = len(result)
            result.append(phase)
    selected = result[-cap:] if cap is not None else result
    return [
        {**deepcopy(phase), "phase_index": index}
        for index, phase in enumerate(selected)
    ]


def _hashed_phases(phases: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return [{**deepcopy(dict(phase)), "phase_sha256": phase_sha256(phase)} for phase in phases]


def validate_prediction_trusted_history_manifest(
    value: Any, *, expected_phases: Iterable[Mapping[str, Any]] | None = None
) -> list[str]:
    errors: list[str] = []
    if not isinstance(value, Mapping):
        return ["prediction trusted history manifest must be an object"]
    if value.get("schema_version") != SCHEMA_VERSION:
        return ["prediction trusted history manifest schema is not v3"]
    errors.extend(validate_evidence_cutoff(value.get("evidence_cutoff")))
    if value.get("target_contract_id") != TARGET_CONTRACT_ID:
        errors.append("target_contract_id is invalid")
    environment_hash = _text(value.get("classifier_environment_sha256")).lower()
    if len(environment_hash) != 64 or any(c not in "0123456789abcdef" for c in environment_hash):
        errors.append("classifier_environment_sha256 is invalid")
    phases = value.get("ordered_trusted_phases")
    if not isinstance(phases, list) or len(phases) > MAX_TRUSTED_PHASES:
        errors.append("ordered_trusted_phases exceeds the v3 maximum")
        phases = phases if isinstance(phases, list) else []
    count_fields = (
        "original_command_count", "original_trusted_label_count",
        "original_distinct_phase_count", "selected_distinct_phase_count",
        "omitted_prefix_phase_count", "audit_only_label_count",
        "upstream_omitted_event_count",
    )
    counts: dict[str, int] = {}
    for field in count_fields:
        raw = value.get(field)
        if isinstance(raw, bool) or not isinstance(raw, int) or raw < 0:
            errors.append(f"{field} is invalid")
        else:
            counts[field] = raw
    if counts.get("selected_distinct_phase_count") != len(phases):
        errors.append("selected_distinct_phase_count does not match phases")
    if counts.get("original_distinct_phase_count") != (
        counts.get("selected_distinct_phase_count", 0)
        + counts.get("omitted_prefix_phase_count", 0)
    ):
        errors.append("distinct phase counts do not reconcile")
    if value.get("truncated") is not (counts.get("omitted_prefix_phase_count", 0) > 0):
        errors.append("truncated does not match omitted_prefix_phase_count")
    if value.get("upstream_truncated") is not (counts.get("upstream_omitted_event_count", 0) > 0):
        errors.append("upstream_truncated does not match upstream_omitted_event_count")
    previous_end = -1
    for index, phase in enumerate(phases):
        path = f"ordered_trusted_phases[{index}]"
        if not isinstance(phase, Mapping):
            errors.append(f"{path} must be an object")
            continue
        if set(phase) != PHASE_KEYS:
            errors.append(f"{path} fields are invalid")
        if phase.get("phase_index") != index:
            errors.append(f"{path}.phase_index is invalid")
        start = phase.get("start_command_index")
        end = phase.get("end_command_index")
        if not isinstance(start, int) or isinstance(start, bool) or not isinstance(end, int) or isinstance(end, bool) or start < 0 or end < start or start <= previous_end:
            errors.append(f"{path} command ordering is invalid")
        else:
            previous_end = end
        if not _timestamp(phase.get("start_timestamp")) or not _timestamp(phase.get("end_timestamp")):
            errors.append(f"{path} timestamps are required")
        if not isinstance(phase.get("observation_count"), int) or isinstance(phase.get("observation_count"), bool) or phase.get("observation_count") < 1:
            errors.append(f"{path}.observation_count is invalid")
        labels = phase.get("labels")
        if not isinstance(labels, list) or not labels:
            errors.append(f"{path}.labels is invalid")
            labels = []
        if phase.get("tactics") != sorted({item.get("tactic") for item in labels if isinstance(item, Mapping)}):
            errors.append(f"{path}.tactics do not match labels")
        if phase.get("techniques") != sorted({item.get("technique") for item in labels if isinstance(item, Mapping)}):
            errors.append(f"{path}.techniques do not match labels")
        if phase_sha256(phase) != _text(phase.get("phase_sha256")).lower():
            errors.append(f"{path}.phase_sha256 mismatch")
    if _sha(phases) != _text(value.get("ordered_trusted_phases_sha256")).lower():
        errors.append("ordered_trusted_phases_sha256 mismatch")
    basis = deepcopy(dict(value))
    basis.pop("history_manifest_sha256", None)
    if _sha(basis) != _text(value.get("history_manifest_sha256")).lower():
        errors.append("history_manifest_sha256 mismatch")
    if expected_phases is not None:
        expected = _hashed_phases(normalize_trusted_phases(expected_phases, cap=None)[-MAX_TRUSTED_PHASES:])
        expected = [{**item, "phase_index": index, "phase_sha256": ""} for index, item in enumerate(expected)]
        expected = [{**item, "phase_sha256": phase_sha256(item)} for item in expected]
        if phases != expected:
            errors.append("trusted history phases do not match the manifest")
    return errors


def build_prediction_trusted_history_manifest(
    *,
    phases: Iterable[Mapping[str, Any]],
    evidence_cutoff: Mapping[str, Any],
    classifier_environment: Mapping[str, Any],
    original_trusted_phase_count: int | None = None,
    original_command_count: int | None = None,
    original_trusted_label_count: int | None = None,
    audit_only_label_count: int = 0,
    upstream_omitted_event_count: int = 0,
) -> Dict[str, Any]:
    complete = normalize_trusted_phases(phases, cap=None)
    selected = complete[-MAX_TRUSTED_PHASES:]
    selected = [{**phase, "phase_index": index} for index, phase in enumerate(selected)]
    normalized = _hashed_phases(selected)
    original_phase_count = len(complete)
    if original_trusted_phase_count is not None:
        original_phase_count = max(original_phase_count, int(original_trusted_phase_count))
    original_labels = original_trusted_label_count
    if original_labels is None:
        original_labels = sum(len(phase.get("labels") or []) for phase in complete)
    command_count = original_command_count
    if command_count is None:
        command_count = max((int(phase.get("end_command_index") or 0) + 1 for phase in complete), default=0)
    omitted = max(original_phase_count - len(normalized), 0)
    basis = {
        "schema_version": SCHEMA_VERSION,
        "target_contract_id": TARGET_CONTRACT_ID,
        "evidence_cutoff": deepcopy(dict(evidence_cutoff or {})),
        "classifier_environment_sha256": _text(classifier_environment.get("environment_sha256")),
        "maximum_trusted_phases": MAX_TRUSTED_PHASES,
        "original_command_count": max(int(command_count), 0),
        "original_trusted_label_count": max(int(original_labels), 0),
        "original_distinct_phase_count": original_phase_count,
        "selected_distinct_phase_count": len(normalized),
        "omitted_prefix_phase_count": omitted,
        "audit_only_label_count": max(int(audit_only_label_count), 0),
        "upstream_omitted_event_count": max(int(upstream_omitted_event_count), 0),
        "upstream_truncated": int(upstream_omitted_event_count) > 0,
        "truncated": omitted > 0,
        "late_arrival_policy": "immutable_cutoff_new_forecast_only",
        "ordered_trusted_phases": normalized,
        "ordered_trusted_phases_sha256": _sha(normalized),
    }
    value = {**basis, "history_manifest_sha256": _sha(basis)}
    errors = validate_prediction_trusted_history_manifest(value)
    if errors:
        raise ValueError("invalid prediction trusted history manifest: " + "; ".join(errors))
    return value
