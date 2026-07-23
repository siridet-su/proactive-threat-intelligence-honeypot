"""Shared causal preprocessing for the final next-behavior experiment.

Offline corpus builders, replay evaluation, and any future shadow adapter must
call these functions directly. No active production prediction path imports
this module yet.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Iterable, List, Mapping, Sequence

from production.prediction.next_behavior_contract import (
    EXAMPLE_SCHEMA_VERSION,
    MODEL_INPUT_SCHEMA_VERSION,
    PHASE_SCHEMA_VERSION,
    TARGET_CONTRACT_ID,
    TERMINAL_OUTCOME,
    NextBehaviorContractError,
    require_valid_next_behavior_session,
)
from production.utils.serialization import stable_id


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _unique_sorted(values: Iterable[Any]) -> List[str]:
    return sorted({_clean(value) for value in values if _clean(value)})


def repetition_bucket(count: int) -> str:
    if count <= 1:
        return "1"
    if count == 2:
        return "2"
    if count <= 5:
        return "3-5"
    return "6+"


def elapsed_time_bucket(milliseconds: float | None) -> str:
    if milliseconds is None:
        return "unknown"
    if milliseconds < 1_000:
        return "under_1s"
    if milliseconds < 10_000:
        return "1_to_10s"
    if milliseconds < 60_000:
        return "10_to_60s"
    return "over_60s"


def _phase_from_groups(
    session_id: str,
    groups: Sequence[Dict[str, Any]],
) -> Dict[str, Any]:
    first = groups[0]
    last = groups[-1]
    start_time = first.get("relative_time_ms")
    end_time = last.get("relative_time_ms")
    duration: float | None = None
    if start_time is not None and end_time is not None:
        duration = max(float(end_time) - float(start_time), 0.0)
    provenance_sources = _unique_sorted(
        item.get("source")
        for group in groups
        for item in group.get("label_provenance") or []
        if isinstance(item, dict)
    )
    confidence_buckets = _unique_sorted(
        item.get("confidence_bucket")
        for group in groups
        for item in group.get("label_provenance") or []
        if isinstance(item, dict)
    )
    agreement_statuses = _unique_sorted(
        item.get("agreement_status")
        for group in groups
        for item in group.get("label_provenance") or []
        if isinstance(item, dict)
    )
    audit_only_label_count = sum(
        len(group.get("audit_only_labels") or []) for group in groups
    )
    tactics = _unique_sorted(first.get("tactics") or [])
    techniques = _unique_sorted(
        technique
        for group in groups
        for technique in group.get("techniques") or []
    )
    evidence_refs = _unique_sorted(
        evidence_ref
        for group in groups
        for evidence_ref in group.get("evidence_refs") or []
    )
    group_ids = [_clean(group.get("group_id")) for group in groups]
    return {
        "schema_version": PHASE_SCHEMA_VERSION,
        "phase_id": stable_id(
            "behaviorphase",
            {
                "session_id": session_id,
                "group_ids": group_ids,
                "tactics": tactics,
            },
        ),
        "group_ids": group_ids,
        "start_event_order": int(first["event_order"]),
        "end_event_order": int(last["event_order"]),
        "start_relative_time_ms": start_time,
        "end_relative_time_ms": end_time,
        "duration_ms": duration,
        "elapsed_time_bucket": elapsed_time_bucket(duration),
        "observation_count": len(groups),
        "repetition_bucket": repetition_bucket(len(groups)),
        "tactics": tactics,
        "techniques": techniques,
        "label_provenance_sources": provenance_sources,
        "label_confidence_buckets": confidence_buckets,
        "label_agreement_statuses": agreement_statuses,
        "audit_only_label_count": audit_only_label_count,
        "evidence_refs": evidence_refs,
        "session_context": deepcopy(last.get("session_context") or {}),
    }


def build_behavior_phases(session_record: Mapping[str, Any]) -> List[Dict[str, Any]]:
    """Group causally ordered observations into run-length-preserving phases."""

    record = require_valid_next_behavior_session(session_record)
    session_id = _clean(record["session_id"])
    phases: List[Dict[str, Any]] = []
    current: List[Dict[str, Any]] = []
    current_tactics: tuple[str, ...] = ()
    for raw_group in record["observation_groups"]:
        group = deepcopy(raw_group)
        group["tactics"] = _unique_sorted(group.get("tactics") or [])
        group["techniques"] = _unique_sorted(group.get("techniques") or [])
        group["evidence_refs"] = _unique_sorted(group.get("evidence_refs") or [])
        tactics = tuple(group["tactics"])
        if current and tactics != current_tactics:
            phases.append(_phase_from_groups(session_id, current))
            current = []
        current.append(group)
        current_tactics = tactics
    if current:
        phases.append(_phase_from_groups(session_id, current))
    return phases


def _model_phase(phase: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "tactics": _unique_sorted(phase.get("tactics") or []),
        "techniques": _unique_sorted(phase.get("techniques") or []),
        "repetition_bucket": _clean(phase.get("repetition_bucket")),
        "elapsed_time_bucket": _clean(phase.get("elapsed_time_bucket")),
        "label_provenance_sources": _unique_sorted(
            phase.get("label_provenance_sources") or []
        ),
        "label_confidence_buckets": _unique_sorted(
            phase.get("label_confidence_buckets") or []
        ),
        "label_agreement_statuses": _unique_sorted(
            phase.get("label_agreement_statuses") or []
        ),
        "audit_only_label_count": int(phase.get("audit_only_label_count") or 0),
    }


def build_model_input(
    phase_sequence: Sequence[Mapping[str, Any]],
    *,
    max_sequence_length: int = 8,
) -> Dict[str, Any]:
    """Return the exact redacted model-visible prefix representation."""

    if max_sequence_length < 1:
        raise NextBehaviorContractError("max_sequence_length must be positive")
    if not phase_sequence:
        raise NextBehaviorContractError("phase_sequence must not be empty")
    selected = list(phase_sequence)[-max_sequence_length:]
    context = deepcopy(selected[-1].get("session_context") or {})
    model_input = {
        "schema_version": MODEL_INPUT_SCHEMA_VERSION,
        "target_contract_id": TARGET_CONTRACT_ID,
        "max_sequence_length": max_sequence_length,
        "truncated": len(phase_sequence) > max_sequence_length,
        "phase_sequence": [_model_phase(phase) for phase in selected],
        "session_context": context,
    }
    model_input["input_hash"] = stable_id("nextbehaviorinput", model_input)
    return model_input


def build_live_model_input(
    session_record: Mapping[str, Any],
    *,
    max_sequence_length: int = 8,
) -> Dict[str, Any]:
    """Use the shared phase builder for a live or replayed causal prefix."""

    return build_model_input(
        build_behavior_phases(session_record),
        max_sequence_length=max_sequence_length,
    )


def build_next_behavior_examples(
    session_record: Mapping[str, Any],
    *,
    max_sequence_length: int = 8,
) -> List[Dict[str, Any]]:
    """Generate one causal prefix target per phase, including closed-session end."""

    record = require_valid_next_behavior_session(session_record)
    phases = build_behavior_phases(record)
    examples: List[Dict[str, Any]] = []
    session_id = _clean(record["session_id"])
    closed = _clean(record.get("status")) == "closed"
    for index, phase in enumerate(phases):
        has_next_phase = index + 1 < len(phases)
        if not has_next_phase and not closed:
            continue
        prefix = phases[: index + 1]
        if has_next_phase:
            target_phase = phases[index + 1]
            target = {
                "outcome_type": "next_behavior_phase",
                "tactics": deepcopy(target_phase["tactics"]),
                "techniques": deepcopy(target_phase["techniques"]),
                "terminal_outcome": "",
                "target_evidence_refs": deepcopy(target_phase["evidence_refs"]),
            }
        else:
            target = {
                "outcome_type": "session_end",
                "tactics": [],
                "techniques": [],
                "terminal_outcome": TERMINAL_OUTCOME,
                "target_evidence_refs": [],
            }
        example = {
            "schema_version": EXAMPLE_SCHEMA_VERSION,
            "target_contract_id": TARGET_CONTRACT_ID,
            "session_id": session_id,
            "source_member_id": _clean(record.get("source_member_id")),
            "prediction_phase_id": phase["phase_id"],
            "prediction_event_order": phase["end_event_order"],
            "model_input": build_model_input(
                prefix,
                max_sequence_length=max_sequence_length,
            ),
            "target": target,
        }
        example["example_id"] = stable_id(
            "nextbehaviorexample",
            {
                "session_id": session_id,
                "prediction_phase_id": phase["phase_id"],
                "target": target,
            },
        )
        examples.append(example)
    return examples
