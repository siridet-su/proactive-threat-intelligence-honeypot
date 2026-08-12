from __future__ import annotations

import copy
import hashlib

import pytest

from production.classification.authority import candidate_authority_decision
from production.classification.classification_pipeline import NotebookParityClassifier
from production.classification.durable_replay import (
    ClassificationReplayError,
    reclassify_durable_prefix,
)
from production.classification.environment import load_classifier_environment, environment_identity
from production.classification.trust import classification_evidence_tier
from production.prediction.next_behavior_runtime import build_live_next_behavior_session
from production.prediction.trusted_history import (
    MAX_TRUSTED_PHASES,
    build_prediction_trusted_history_manifest,
)
from production.reporting.session_assessment_v4 import build_canonical_evidence_snapshot
from production.workers.session_monitor import SessionMonitor, SessionState
from production.utils.serialization import stable_json


def _classifier(bert=None) -> NotebookParityClassifier:
    return NotebookParityClassifier(
        bert_fn=bert or (lambda _command: (None, 0.0)),
    )


def _snapshot() -> dict:
    value = {
        "schema_version": "durable_session_event_manifest.v1",
        "session_id": "replay-session",
        "through_event_id": "event-2",
        "event_count": 2,
        "manifest_sha256": "",
        "event_entries": [
            {"event_id": "event-1", "payload_sha256": "b" * 64},
            {"event_id": "event-2", "payload_sha256": "c" * 64},
        ],
        "events": [
            {
                "eventid": "cowrie.command.input",
                "session": "replay-session",
                "timestamp": "2026-08-11T00:00:00Z",
                "input": "whoami",
            },
            {
                "eventid": "cowrie.command.input",
                "session": "replay-session",
                "timestamp": "2026-08-11T00:00:01Z",
                "input": "bash $SCRIPT",
            },
        ],
    }
    value["manifest_sha256"] = hashlib.sha256(
        stable_json({
            "schema_version": value["schema_version"],
            "session_id": value["session_id"],
            "through_event_id": value["through_event_id"],
            "event_entries": value["event_entries"],
        }).encode()
    ).hexdigest()
    return value


def test_parser_abstention_blocks_regex_promotion_and_model_agreement() -> None:
    event = _classifier(lambda _command: ("T1059", 0.99)).classify("bash $SCRIPT")[0]
    assert event["source"] in {"rule", "both"}
    assert event["authority_decision"]["decision"] == "audit_only"
    assert event["authority_decision"]["safety_class"] == "explicit_abstention"
    assert classification_evidence_tier(event) == "audit_only_candidate"


def test_literal_safe_reviewed_regex_is_trusted() -> None:
    event = _classifier().classify("whoami")[0]
    assert event["evidence_type"] == "command_regex"
    assert event["authority_decision"]["decision"] == "trusted"
    assert classification_evidence_tier(event) == "trusted_observation"


def test_regex_without_explicit_promotion_metadata_is_audit_only() -> None:
    decision = candidate_authority_decision(
        parser_decision={
            "schema_version": "command_authority_decision.v1",
            "safety_class": "literal_unambiguous",
            "trusted_eligible": False,
            "reasons": [],
        },
        evidence_type="command_regex",
        rule_metadata={"rule_id": "unlisted-rule"},
        policy_provenance={
            "rule_policy_id": "rules",
            "rule_policy_version": "1",
            "rule_policy_sha256": "a" * 64,
            "rule_policy_load_status": "loaded",
        },
    )
    assert decision["decision"] == "audit_only"


def test_missing_new_event_authority_provenance_is_audit_only() -> None:
    event = _classifier().classify("whoami")[0]
    event.pop("authority_decision")
    assert classification_evidence_tier(event) == "audit_only_candidate"


def test_securebert_only_and_disagreement_are_audit_only() -> None:
    model_only = _classifier(lambda _command: ("T1082", 0.99)).classify(
        "echo literal"
    )[0]
    assert model_only["source"] == "securebert"
    assert classification_evidence_tier(model_only) == "audit_only_candidate"
    disagreement = _classifier(lambda _command: ("T1082", 0.99)).classify("whoami")[0]
    assert disagreement["source"] == "rule_securebert_disagreement"
    assert classification_evidence_tier(disagreement) == "audit_only_candidate"


def test_exact_durable_prefix_replay_is_deterministic_and_binds_environment() -> None:
    environment = load_classifier_environment(verify_assets=True)
    payload = {"session_id": "replay-session", "classification_events": []}
    first = reclassify_durable_prefix(
        payload,
        _snapshot(),
        _classifier(),
        environment,
    )
    second = reclassify_durable_prefix(
        payload,
        _snapshot(),
        _classifier(),
        environment,
    )
    assert first["trusted_classification_manifest"] == second[
        "trusted_classification_manifest"
    ]
    assert first["classification_events"] == second["classification_events"]
    mismatched = copy.deepcopy(first)
    mismatched["classification_environment"]["environment_sha256"] = "f" * 64
    with pytest.raises(ClassificationReplayError):
        reclassify_durable_prefix(mismatched, _snapshot(), _classifier(), environment)


def test_tampered_durable_manifest_is_rejected_before_reclassification() -> None:
    environment = load_classifier_environment()
    tampered = _snapshot()
    tampered["event_entries"][0]["payload_sha256"] = "f" * 64
    with pytest.raises(ClassificationReplayError):
        reclassify_durable_prefix(
            {"session_id": "replay-session"},
            tampered,
            _classifier(),
            environment,
        )


def test_audit_noise_cannot_evict_trusted_prediction_phases() -> None:
    state = SessionState("history-session", "192.0.2.1", "2026-08-11T00:00:00Z")
    trusted = _classifier().classify("whoami")[0]
    trusted["compound_command_index"] = 0
    SessionMonitor._append_prediction_trusted_phase(state, trusted)
    for index in range(10_001):
        audit = {
            "classification_event_schema": "classification_event.v2",
            "source": "securebert",
            "ttp": "T1082",
            "tactic": "discovery",
            "confidence": 0.99,
            "authority_decision": {
                "schema_version": "command_authority_decision.v1",
                "decision": "audit_only",
                "trusted_eligible": False,
            },
            "compound_command_index": index + 1,
        }
        SessionMonitor._append_prediction_trusted_phase(state, audit)
    assert len(state.prediction_trusted_history) == 1
    assert state.prediction_trusted_history[0]["techniques"] == ["T1033"]


def test_prediction_history_manifest_is_bounded_and_content_addressed() -> None:
    phases = [
        {
            "command_index": index,
            "event_id": f"event-{index}",
            "tactics": ["discovery"],
            "techniques": [f"T{1000 + index:04d}"],
        }
        for index in range(20)
    ]
    environment = environment_identity(load_classifier_environment())
    cutoff = {"schema_version": "prediction_evidence_cutoff.v1", "event_id": "event-20"}
    manifest = build_prediction_trusted_history_manifest(
        phases=phases,
        evidence_cutoff=cutoff,
        classifier_environment=environment,
    )
    assert manifest["maximum_trusted_phases"] == MAX_TRUSTED_PHASES
    assert len(manifest["ordered_trusted_phases"]) == MAX_TRUSTED_PHASES
    assert manifest == build_prediction_trusted_history_manifest(
        phases=phases,
        evidence_cutoff=cutoff,
        classifier_environment=environment,
    )


def test_transformer_input_uses_explicit_trusted_history_not_classification_tail() -> None:
    payload = {
        "session_id": "history-session",
        "classification_events": [
            {
                "ttp": "T1082",
                "tactic": "discovery",
                "source": "securebert",
                "confidence": 0.99,
            }
            for _ in range(10_001)
        ],
        "prediction_trusted_history": [
            {
                "command_index": 1,
                "event_id": "trusted-event",
                "tactics": ["discovery"],
                "techniques": ["T1033"],
            }
        ],
        "commands": ["whoami"],
        "login_attempts": 0,
        "login_success": True,
        "duration": 1,
    }
    safe = build_live_next_behavior_session(
        payload,
        rule_policy_sha256="a" * 64,
        trust_policy_sha256="b" * 64,
        classifier_checkpoint_sha256="c" * 64,
    )
    assert safe is not None
    assert safe["observation_groups"][0]["techniques"] == ["T1033"]


def test_new_canonical_snapshot_v2_binds_classification_manifest() -> None:
    environment = load_classifier_environment()
    identity = environment_identity(environment)
    payload = {
        "session_id": "snapshot-v2",
        "src_ip": "192.0.2.20",
        "commands": ["whoami"],
        "raw_events": [],
        "classification_events": [],
        "classification_environment": identity,
        "trusted_classification_manifest": {
            "schema_version": "trusted_classification_manifest.v1",
            "manifest_sha256": "d" * 64,
        },
    }
    snapshot, _observed, _source, _policy = build_canonical_evidence_snapshot(payload, [])
    assert snapshot["schema_version"] == "canonical_evidence_snapshot.v2"
    assert snapshot["trusted_classification_manifest"]["manifest_sha256"] == "d" * 64
