"""Create a public-safe next-tactic evaluation payload from external sessions.

The source document is the private sessionized output produced by
``build_external_seed_model --session-output``. The output contains only
anonymized identifiers and trusted ATT&CK sequence labels. Raw commands and
source telemetry are intentionally discarded.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, Sequence

from production.correlation.session_ttp_knowledge import main_ttp_id
from production.prediction.prediction_backtest import _tactic_steps
from production.tools.external_seed_weight_fit import (
    DEFAULT_SCOPE,
    _scoped_payload,
    _split_eligible_sessions,
)


SCHEMA_VERSION = "next_tactic_external_session_payload.v1"
DEFAULT_DATASET_SOURCE = "nlaha11/global-ssh-and-telnet-honeypot-logs-cowrie"
DEFAULT_PROTOCOL = "ssh_telnet_mixed_or_unknown"
ALLOWED_SPLITS = ("train", "calibration", "test")


def load_source_sessions(path_text: str) -> tuple[list[Dict[str, Any]], Dict[str, Any]]:
    path = Path(path_text)
    with path.open("r", encoding="utf-8") as handle:
        document = json.load(handle)
    if not isinstance(document, dict):
        raise ValueError("source session payload must be a JSON object")
    sessions = document.get("sessions") or document.get("payloads") or []
    if not isinstance(sessions, list):
        raise ValueError("source session payload must contain a sessions or payloads list")
    provenance = document.get("provenance")
    return (
        [dict(item) for item in sessions if isinstance(item, dict)],
        dict(provenance) if isinstance(provenance, dict) else {},
    )


def anonymized_session_id(raw_session_id: str, dataset_source: str) -> str:
    digest = hashlib.sha256(
        f"{dataset_source}\0{raw_session_id}".encode("utf-8")
    ).hexdigest()
    return f"external-{digest[:24]}"


def _safe_event(source_event: Dict[str, Any]) -> Dict[str, Any]:
    technique = main_ttp_id(source_event.get("ttp") or source_event.get("technique"))
    event: Dict[str, Any] = {
        "tactic": str(source_event.get("tactic") or ""),
        "source": "derived_trusted_external_weak_label",
        "evidence_tier": "trusted_observation",
        "label_quality": "classifier_derived_weak_label",
    }
    if technique and technique != "unknown":
        event["ttp"] = technique
    return event


def sanitized_session(
    payload: Dict[str, Any],
    *,
    split: str,
    dataset_source: str,
    protocol: str,
) -> Dict[str, Any]:
    if split not in ALLOWED_SPLITS:
        raise ValueError(f"unsupported split: {split}")
    raw_session_id = str(payload.get("session_id") or payload.get("session") or "").strip()
    if not raw_session_id:
        raise ValueError("eligible source session is missing a session identifier")
    source_events = [
        event
        for event in payload.get("classification_events") or []
        if isinstance(event, dict)
    ]
    if not source_events:
        raise ValueError("safe evaluation payloads require trusted classification events")
    events = [_safe_event(event) for event in source_events]
    trusted_tactics = [str(event["tactic"]) for event in events]
    techniques = [str(event.get("ttp") or "") for event in events]
    tactics: list[str] = []
    for tactic in trusted_tactics:
        if not tactics or tactics[-1] != tactic:
            tactics.append(tactic)
    transition_examples = [
        {
            "prefix_context": tactics[: index + 1],
            "target_next_tactic": tactics[index + 1],
        }
        for index in range(len(tactics) - 1)
    ]
    return {
        "schema_version": SCHEMA_VERSION,
        "session_id": anonymized_session_id(raw_session_id, dataset_source),
        "dataset_source": dataset_source,
        "protocol": protocol,
        "split": split,
        "status": "closed",
        "is_ended": True,
        "classification_events": events,
        "trusted_tactic_sequence": trusted_tactics,
        "trusted_technique_sequence": [item for item in techniques if item],
        "adjacent_deduplicated_tactic_sequence": tactics,
        "transition_examples": transition_examples,
    }


def build_safe_payloads(
    source_sessions: Iterable[Dict[str, Any]],
    *,
    dataset_source: str = DEFAULT_DATASET_SOURCE,
    protocol: str = DEFAULT_PROTOCOL,
    seed: int = 20260707,
    train_ratio: float = 0.70,
    calibration_ratio: float = 0.15,
    tactic_scope: Sequence[str] = DEFAULT_SCOPE,
) -> tuple[list[Dict[str, Any]], Dict[str, Any]]:
    scope = {str(item).strip() for item in tactic_scope if str(item).strip()}
    total_sessions = 0
    completed_sessions = 0
    usable_completed: list[Dict[str, Any]] = []
    eligible: list[Dict[str, Any]] = []
    for payload in source_sessions:
        total_sessions += 1
        if bool(payload.get("is_ended")) or str(payload.get("status") or "") == "closed":
            completed_sessions += 1
        scoped = _scoped_payload(payload, scope)
        completed = bool(scoped.get("is_ended")) or str(scoped.get("status") or "") == "closed"
        steps = _tactic_steps(scoped)
        if completed and steps:
            usable_completed.append(scoped)
            if len(steps) >= 2:
                eligible.append(scoped)

    split = _split_eligible_sessions(
        eligible,
        seed=seed,
        train_ratio=train_ratio,
        calibration_ratio=calibration_ratio,
    )
    split_by_object_id = {
        id(payload): split_name
        for split_name, items in (
            ("train", split["train_eligible"]),
            ("calibration", split["calibration"]),
            ("test", split["test"]),
        )
        for payload in items
    }
    assigned = [
        (split_by_object_id.get(id(payload), "train"), payload)
        for payload in usable_completed
    ]
    safe_payloads = [
        sanitized_session(
            payload,
            split=split_name,
            dataset_source=dataset_source,
            protocol=protocol,
        )
        for split_name in ALLOWED_SPLITS
        for assigned_split, payload in assigned
        if assigned_split == split_name
    ]
    ids = [str(item["session_id"]) for item in safe_payloads]
    if len(ids) != len(set(ids)):
        raise ValueError("anonymized session identifier collision detected")
    transition_counts = Counter(
        str(item["split"])
        for item in safe_payloads
        for _example in item["transition_examples"]
    )
    summary = {
        "schema_version": SCHEMA_VERSION,
        "dataset_source": dataset_source,
        "protocol_scope": protocol,
        "source_sessions": total_sessions,
        "source_completed_sessions": completed_sessions,
        "safe_usable_completed_sessions": len(safe_payloads),
        "eligible_transition_sessions": len(eligible),
        "adjacent_deduplicated_tactic_transitions": sum(transition_counts.values()),
        "split_method": "deterministic_stratified_by_first_tactic_transition",
        "split_seed": seed,
        "split_sessions": {
            split_name: sum(assigned_split == split_name for assigned_split, _ in assigned)
            for split_name in ALLOWED_SPLITS
        },
        "split_transition_sessions": {
            split_name: sum(
                assigned_split == split_name and len(_tactic_steps(payload)) >= 2
                for assigned_split, payload in assigned
            )
            for split_name in ALLOWED_SPLITS
        },
        "split_transitions": {
            split_name: int(transition_counts.get(split_name, 0))
            for split_name in ALLOWED_SPLITS
        },
        "contains_raw_commands": False,
        "contains_original_session_ids": False,
        "contains_network_identifiers": False,
        "label_quality": "classifier_derived_weak_labels",
    }
    return safe_payloads, summary


def write_jsonl(path_text: str, payloads: Iterable[Dict[str, Any]]) -> None:
    path = Path(path_text)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for payload in payloads:
            handle.write(json.dumps(payload, sort_keys=True) + "\n")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--dataset-source", default=DEFAULT_DATASET_SOURCE)
    parser.add_argument("--protocol", default=DEFAULT_PROTOCOL)
    parser.add_argument("--seed", type=int, default=20260707)
    parser.add_argument("--train-ratio", type=float, default=0.70)
    parser.add_argument("--calibration-ratio", type=float, default=0.15)
    parser.add_argument("--tactic-scope", action="append", default=list(DEFAULT_SCOPE))
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = build_arg_parser().parse_args(list(argv) if argv is not None else None)
    sessions, provenance = load_source_sessions(args.input)
    source_handle = str(provenance.get("dataset_handle") or args.dataset_source)
    payloads, summary = build_safe_payloads(
        sessions,
        dataset_source=source_handle,
        protocol=args.protocol,
        seed=args.seed,
        train_ratio=args.train_ratio,
        calibration_ratio=args.calibration_ratio,
        tactic_scope=args.tactic_scope,
    )
    write_jsonl(args.output, payloads)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
