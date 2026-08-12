"""Exact durable-prefix classification replay and content-addressed manifests."""

from __future__ import annotations

import hashlib
from copy import deepcopy
from typing import Any, Dict, Iterable, List, Sequence

from production.classification.environment import environment_identity
from production.classification.trust import (
    classification_audit_reason,
    classification_evidence_tier,
    is_trusted_classification_event,
)
from production.prediction.trusted_history import (
    build_prediction_trusted_history_manifest,
    normalize_trusted_phases,
)
from production.utils.serialization import stable_id, stable_json
from production.utils.sensitive_data import redact_for_artifact


TRUSTED_CLASSIFICATION_MANIFEST_SCHEMA = "trusted_classification_manifest.v1"
CLASSIFICATION_REPLAY_SCHEMA = "classification_durable_prefix_replay.v1"
COMMAND_EVENTIDS = {
    "cowrie.command.input",
    "cowrie.command.success",
    "cowrie.command.failed",
}


class ClassificationReplayError(ValueError):
    """Raised when a canonical prefix cannot be replayed under its binding."""


def _text(value: Any) -> str:
    return str(value or "").strip()


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(stable_json(value).encode("utf-8")).hexdigest()


def _command_outcome(event: Dict[str, Any]) -> str:
    eventid = _text(event.get("eventid"))
    if event.get("success") == 1 or eventid == "cowrie.command.success":
        return "cowrie_reported_success"
    if event.get("success") == 0 or eventid == "cowrie.command.failed":
        return "cowrie_reported_failure"
    return "outcome_unknown"


def _classification_output_for_hash(events: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Remove only presentation fields whose values are not replay inputs."""

    return [deepcopy(dict(event)) for event in events]


def build_trusted_classification_manifest(
    *,
    durable_manifest: Dict[str, Any],
    environment: Dict[str, Any],
    classifications: Sequence[Dict[str, Any]],
    command_count: int,
    trusted_count: int,
    audit_only_count: int,
) -> Dict[str, Any]:
    ordered_output_hash = _sha256_json(_classification_output_for_hash(classifications))
    identity = environment_identity(environment)
    basis = {
        "schema_version": TRUSTED_CLASSIFICATION_MANIFEST_SCHEMA,
        "durable_event_manifest_sha256": _text(durable_manifest.get("manifest_sha256")),
        "session_id": _text(durable_manifest.get("session_id")),
        "through_event_id": _text(durable_manifest.get("through_event_id")),
        "classifier_environment_sha256": _text(identity.get("environment_sha256")),
        "ordered_command_count": int(command_count),
        "trusted_count": int(trusted_count),
        "audit_only_count": int(audit_only_count),
        "ordered_classification_output_sha256": ordered_output_hash,
    }
    return {
        **basis,
        "classifier_environment": identity,
        "manifest_sha256": _sha256_json(basis),
    }


def reclassify_durable_prefix(
    session_payload: Dict[str, Any],
    durable_snapshot: Dict[str, Any],
    classifier: Any,
    environment: Dict[str, Any],
) -> Dict[str, Any]:
    """Reclassify every command event in the verified durable prefix.

    The returned payload deliberately replaces the monitor's bounded
    ``classification_events`` projection.  It is therefore safe for canonical
    reporting but does not mutate the realtime session state.
    """

    if not isinstance(session_payload, dict) or not isinstance(durable_snapshot, dict):
        raise ClassificationReplayError("replay inputs must be objects")
    expected_environment = session_payload.get("classification_environment")
    current_identity = environment_identity(environment)
    if isinstance(expected_environment, dict):
        expected_hash = _text(
            expected_environment.get("environment_sha256")
            or session_payload.get("classifier_environment_sha256")
        )
        if expected_hash and expected_hash != current_identity.get("environment_sha256"):
            raise ClassificationReplayError(
                "session classifier environment does not match active replay environment"
            )

    events: List[Dict[str, Any]] = [
        item for item in durable_snapshot.get("events") or [] if isinstance(item, dict)
    ]
    entries = [
        item for item in durable_snapshot.get("event_entries") or [] if isinstance(item, dict)
    ]
    manifest_basis = {
        "schema_version": _text(durable_snapshot.get("schema_version")),
        "session_id": _text(durable_snapshot.get("session_id")),
        "through_event_id": _text(durable_snapshot.get("through_event_id")),
        "event_entries": entries,
    }
    if (
        _text(durable_snapshot.get("manifest_sha256"))
        != _sha256_json(manifest_basis)
        or int(durable_snapshot.get("event_count") or -1) != len(events)
        or len(entries) != len(events)
    ):
        raise ClassificationReplayError("durable event manifest is tampered or incomplete")
    classifications: List[Dict[str, Any]] = []
    command_count = 0
    for index, event in enumerate(events):
        eventid = _text(event.get("eventid"))
        if eventid not in COMMAND_EVENTIDS:
            continue
        command = _text(event.get("input"))
        if not command:
            continue
        command_count += 1
        entry = entries[index] if index < len(entries) else {}
        durable_order = {
            "event_id": _text(entry.get("event_id")),
            "payload_sha256": _text(entry.get("payload_sha256")),
            "event_index": index,
        }
        try:
            outputs = classifier.classify(command)
        except Exception as exc:
            raise ClassificationReplayError("durable prefix classification failed") from exc
        for classification_index, candidate in enumerate(outputs or []):
            if not isinstance(candidate, dict):
                continue
            classification = redact_for_artifact(dict(candidate))
            if not isinstance(classification, dict):
                raise ClassificationReplayError("classification redaction failed")
            classified_command = _text(
                classification.get("subcommand")
                or classification.get("command")
                or command
            )
            classification["cowrie_eventid"] = eventid
            classification["event_timestamp"] = _text(event.get("timestamp"))
            classification["durable_evidence_order"] = durable_order
            classification["command_outcome"] = _command_outcome(event)
            classification["compound_command_index"] = command_count - 1
            classification["evidence_tier"] = classification_evidence_tier(classification)
            classification["evidence_id"] = stable_id(
                "class",
                {
                    "session_id": _text(durable_snapshot.get("session_id")),
                    "event_id": durable_order.get("event_id"),
                    "command": classified_command,
                    "classification_index": classification_index,
                    "ttp": classification.get("ttp"),
                    "source": classification.get("source"),
                },
            )
            if classification["evidence_tier"] != "trusted_observation":
                classification["audit_reason"] = classification_audit_reason(classification)
            classifications.append(classification)

    trusted_count = sum(
        item.get("evidence_tier") == "trusted_observation" for item in classifications
    )
    manifest = build_trusted_classification_manifest(
        durable_manifest=durable_snapshot,
        environment=environment,
        classifications=classifications,
        command_count=command_count,
        trusted_count=trusted_count,
        audit_only_count=len(classifications) - trusted_count,
    )
    reconstructed = dict(session_payload)
    reconstructed["classification_events"] = classifications
    reconstructed["classification_environment"] = current_identity
    reconstructed["trusted_classification_manifest"] = manifest
    phases: List[Dict[str, Any]] = []
    for classification in classifications:
        if not is_trusted_classification_event(classification):
            continue
        try:
            command_index = int(
                classification.get("compound_command_index") or len(phases)
            )
        except (TypeError, ValueError):
            command_index = len(phases)
        event_id = _text(
            (classification.get("durable_evidence_order") or {}).get("event_id")
        )
        same_phase = bool(
            phases and phases[-1].get("command_index") == command_index
        )
        current = phases[-1] if same_phase else {
            "command_index": command_index,
            "event_id": event_id,
            "tactics": [],
            "techniques": [],
            "labels": [],
        }
        if not same_phase:
            phases.append(current)
        tactic = _text(classification.get("tactic"))
        ttp = _text(classification.get("ttp")).upper()
        if tactic and tactic != "unknown" and tactic not in current["tactics"]:
            current["tactics"].append(tactic)
        if ttp and ttp != "T0000_UNKNOWN" and ttp not in current["techniques"]:
            current["techniques"].append(ttp)
        if tactic and ttp and ttp != "T0000_UNKNOWN":
            label = {"tactic": tactic, "technique": ttp}
            if event_id:
                label["classification_evidence_id"] = event_id
            if label not in current["labels"]:
                current["labels"].append(label)
    normalized_phases = normalize_trusted_phases(phases, cap=None)
    reconstructed["prediction_trusted_history"] = normalized_phases[-8:]
    cutoff = {
        "schema_version": "prediction_evidence_cutoff.v1",
        "event_id": _text(durable_snapshot.get("through_event_id")),
    }
    reconstructed["prediction_trusted_history_manifest"] = (
        build_prediction_trusted_history_manifest(
            phases=normalized_phases,
            evidence_cutoff=cutoff,
            classifier_environment=current_identity,
        )
    )
    reconstructed["classification_replay"] = {
        "schema_version": CLASSIFICATION_REPLAY_SCHEMA,
        "durable_event_manifest_sha256": _text(durable_snapshot.get("manifest_sha256")),
        "classifier_environment_sha256": _text(current_identity.get("environment_sha256")),
        "status": "replayed_exact_durable_prefix",
    }
    return reconstructed
