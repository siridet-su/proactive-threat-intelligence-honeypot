from __future__ import annotations

import copy
import hashlib
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from production.prediction.evidence_cutoff import make_evidence_cutoff
from production.prediction.next_behavior_contract import (
    MODEL_INPUT_SCHEMA_VERSION,
    TARGET_CONTRACT_ID,
)
from production.prediction.next_behavior_preprocessing import (
    build_behavior_phases,
    build_live_model_input,
    build_model_input_from_trusted_history_manifest,
)
from production.prediction.next_behavior_runtime import build_live_next_behavior_session
from production.prediction.next_behavior_tensor import (
    build_vocabulary,
    tensorize_model_input,
)
from production.prediction.prediction_snapshot_contract import (
    SNAPSHOT_SCHEMA_VERSION,
    finalize_prediction_snapshot,
    validate_prediction_snapshot_integrity,
)
from production.prediction.trusted_history import (
    SCHEMA_VERSION,
    build_prediction_trusted_history_manifest,
    validate_prediction_trusted_history_manifest,
)
from production.utils.feedback import (
    build_auto_evidence_feedback,
    feedback_weight_signal,
)
from production.workers.session_monitor import SessionMonitor, SessionState
from production.workers.session_worker import SessionWorker


HASH_A = "a" * 64
HASH_B = "b" * 64


def _phase(
    index: int,
    tactic: str,
    technique: str,
    *,
    timestamp: str | None = None,
    source: str = "rule",
    confidence: float = 1.0,
    agreement: str = "rule_only",
    outcome: str = "cowrie_reported_success",
) -> dict:
    stamp = timestamp or f"2026-08-13T00:00:{index:02d}Z"
    return {
        "command_index": index,
        "event_id": f"event-{index}",
        "event_timestamp": stamp,
        "labels": [{
            "tactic": tactic,
            "technique": technique,
            "source": source,
            "confidence": confidence,
            "agreement_status": agreement,
            "classification_evidence_id": f"event-{index}",
        }],
        "command_outcome": outcome,
        "outcome_scope": "fragment",
        "fragment_execution": "direct",
    }


def _manifest(phases: list[dict], *, cutoff_index: int | None = None, **kwargs) -> dict:
    index = len(phases) - 1 if cutoff_index is None else cutoff_index
    return build_prediction_trusted_history_manifest(
        phases=phases,
        evidence_cutoff=make_evidence_cutoff(
            f"2026-08-13T00:10:{index:02d}Z", f"event-{index}"
        ),
        classifier_environment={"environment_sha256": HASH_A},
        **kwargs,
    )


def _context() -> dict:
    return {
        "login_outcome": "success",
        "command_count_bucket": "2-5",
        "session_age_bucket": "over_5m",
        "confirmed_transfer_observed": False,
    }


def test_history_v3_collapses_before_cap_and_preserves_causal_metadata() -> None:
    phases = [
        _phase(0, "execution", "T1059"),
        _phase(1, "persistence", "T1547"),
        *[
            _phase(
                index,
                "discovery",
                "T1082",
                timestamp=(
                    datetime(2026, 8, 13, tzinfo=timezone.utc)
                    + timedelta(minutes=index)
                ).isoformat(),
                source="both",
                confidence=0.98,
                agreement="exact_technique_agreement",
            )
            for index in range(2, 11)
        ],
    ]
    manifest = _manifest(
        phases,
        original_command_count=11,
        original_trusted_label_count=11,
        audit_only_label_count=7,
    )
    assert manifest["schema_version"] == SCHEMA_VERSION
    assert manifest["original_command_count"] == 11
    assert manifest["original_distinct_phase_count"] == 3
    assert manifest["selected_distinct_phase_count"] == 3
    assert manifest["truncated"] is False
    assert [item["tactics"] for item in manifest["ordered_trusted_phases"]] == [
        ["execution"], ["persistence"], ["discovery"]
    ]
    discovery = manifest["ordered_trusted_phases"][-1]
    assert discovery["observation_count"] == 9
    assert discovery["start_timestamp"].startswith("2026-08-13T00:02")
    assert discovery["end_timestamp"].startswith("2026-08-13T00:10")
    assert discovery["label_provenance_sources"] == ["rule_model_agreement"]
    assert discovery["label_confidence_buckets"] == ["high"]
    assert discovery["label_agreement_statuses"] == ["agreed"]
    assert manifest["audit_only_label_count"] == 7
    assert validate_prediction_trusted_history_manifest(manifest) == []


def test_newest_eight_distinct_phases_and_upstream_truncation_are_explicit() -> None:
    tactics = ["execution", "persistence", "discovery"]
    techniques = ["T1059", "T1547", "T1082"]
    phases = [
        _phase(index, tactics[index % 3], techniques[index % 3])
        for index in range(11)
    ]
    manifest = _manifest(phases, upstream_omitted_event_count=4)
    assert manifest["original_distinct_phase_count"] == 11
    assert manifest["selected_distinct_phase_count"] == 8
    assert manifest["omitted_prefix_phase_count"] == 3
    assert manifest["truncated"] is True
    assert manifest["upstream_truncated"] is True
    assert manifest["upstream_omitted_event_count"] == 4
    assert manifest["ordered_trusted_phases"][0]["start_command_index"] == 3
    model_input = build_model_input_from_trusted_history_manifest(
        manifest, session_context=_context()
    )
    assert model_input["schema_version"] == MODEL_INPUT_SCHEMA_VERSION
    assert model_input["truncated"] is True
    assert model_input["original_phase_count"] == 11
    assert model_input["selected_phase_count"] == 8
    assert model_input["omitted_prefix_phase_count"] == 3


def _runtime_event(index: int, tactic: str, technique: str, timestamp: str) -> dict:
    return {
        "classification_event_schema": "classification_event.v3",
        "cowrie_eventid": "cowrie.command.success",
        "evidence_id": f"runtime-{index}",
        "event_timestamp": timestamp,
        "compound_command_index": index,
        "ttp": technique,
        "tactic": tactic,
        "source": "both",
        "confidence": 0.98,
        "high_confidence": True,
        "agreement_status": "exact_technique_agreement",
        "evidence_tier": "trusted_observation",
        "authority_decision": {
            "schema_version": "command_authority_decision.v2",
            "decision": "trusted",
            "trusted_eligible": True,
            "safety_class": "reviewed_structural_match",
        },
        "rule_policy_id": "test",
        "rule_policy_version": "test",
        "rule_policy_sha256": HASH_A,
        "rule_policy_load_status": "loaded",
    }


def test_direct_and_manifest_paths_have_identical_input_hash_and_tensor() -> None:
    payload = {
        "session_id": "phase4-parity",
        "protocol": "ssh",
        "status": "active",
        "login_success": True,
        "commands": ["[redacted]", "[redacted]", "[redacted]"],
        "classification_events": [
            _runtime_event(0, "discovery", "T1082", "2026-08-13T00:00:00Z"),
            _runtime_event(1, "discovery", "T1082", "2026-08-13T00:05:00Z"),
            _runtime_event(2, "execution", "T1059", "2026-08-13T00:06:00Z"),
        ],
        "raw_events": [],
        "duration": 360,
    }
    safe = build_live_next_behavior_session(
        payload,
        rule_policy_sha256=HASH_A,
        trust_policy_sha256=HASH_A,
        classifier_checkpoint_sha256=HASH_B,
    )
    assert safe is not None
    direct = build_live_model_input(safe)
    behavior_phases = build_behavior_phases(safe)
    base = datetime(2026, 8, 13, tzinfo=timezone.utc)
    manifest_phases = []
    for index, phase in enumerate(behavior_phases):
        manifest_phases.append({
            "command_index": phase["start_event_order"] - 1,
            "end_command_index": phase["end_event_order"] - 1,
            "event_id": f"runtime-phase-{index}",
            "start_timestamp": (base + timedelta(milliseconds=phase["start_relative_time_ms"])).isoformat(),
            "end_timestamp": (base + timedelta(milliseconds=phase["end_relative_time_ms"])).isoformat(),
            "observation_count": phase["observation_count"],
            "labels": phase["labels"],
            "audit_only_label_count": phase["audit_only_label_count"],
        })
    manifest = _manifest(manifest_phases)
    from_manifest = build_model_input_from_trusted_history_manifest(
        manifest,
        session_context=direct["session_context"],
    )
    assert direct == from_manifest
    vocabulary = build_vocabulary(
        [direct], preprocessing_sha256=HASH_A, training_membership_sha256=HASH_B
    )
    assert tensorize_model_input(direct, vocabulary) == tensorize_model_input(
        from_manifest, vocabulary
    )
    assert direct["phase_sequence"][0]["elapsed_time_bucket"] == "over_60s"
    assert direct["phase_sequence"][0]["label_provenance_sources"] == [
        "rule_model_agreement"
    ]


def test_failed_attempt_is_preserved_and_audit_only_conditional_cannot_evict() -> None:
    failed = _phase(
        0, "execution", "T1059", outcome="cowrie_reported_failure"
    )
    manifest = _manifest([failed])
    assert manifest["ordered_trusted_phases"][0]["command_outcomes"] == [
        "cowrie_reported_failure"
    ]
    state = SessionState("phase4", "192.0.2.1", "2026-08-13T00:00:00Z")
    trusted = _runtime_event(0, "execution", "T1059", "2026-08-13T00:00:00Z")
    trusted["command_outcome"] = "cowrie_reported_failure"
    trusted["outcome_scope"] = "fragment"
    SessionMonitor._append_prediction_trusted_phase(state, trusted)
    revision = state.prediction_trusted_history_revision
    audit = copy.deepcopy(trusted)
    audit["compound_command_index"] = 1
    audit["authority_decision"]["decision"] = "audit_only"
    audit["authority_decision"]["trusted_eligible"] = False
    audit["evidence_tier"] = "audit_only_candidate"
    audit["fragment_execution"] = "conditional_unproven"
    SessionMonitor._append_prediction_trusted_phase(state, audit)
    assert state.prediction_trusted_history_revision == revision
    assert len(state.prediction_trusted_history) == 1
    assert state.prediction_audit_only_label_count == 1


def test_runtime_trigger_is_distinct_phase_only_and_close_is_resolution_only() -> None:
    worker = object.__new__(SessionWorker)
    worker.config = SimpleNamespace(prediction_policy={"prediction_triggers": {"enabled": True}})
    assert worker._prediction_trigger_for_event({"eventid": "cowrie.login.success"})["matched"] is False
    close = worker._prediction_trigger_for_event({"eventid": "cowrie.session.closed"})
    assert close["matched"] is False
    assert close["match_type"] == "terminal_resolution_only"
    assert worker._prediction_trigger_for_event({"eventid": "cowrie.command.success"})["matched"] is True


def _snapshot(prefix: dict, *, prediction: list[str]) -> dict:
    cutoff = prefix["evidence_cutoff"]
    return finalize_prediction_snapshot({
        "schema_version": SNAPSHOT_SCHEMA_VERSION,
        "session_id": "phase4-feedback",
        "event_id": cutoff["event_id"],
        "evidence_cutoff": cutoff,
        "prediction_status": "predicted",
        "prediction": prediction,
        "final_ranking": [
            {"tactic": tactic, "score": 0.5} for tactic in prediction
        ],
        "prediction_history": {
            "schema_version": SCHEMA_VERSION,
            "target_contract_id": TARGET_CONTRACT_ID,
            "history_manifest_sha256": prefix["history_manifest_sha256"],
            "original_distinct_phase_count": prefix["original_distinct_phase_count"],
            "omitted_prefix_phase_count": prefix["omitted_prefix_phase_count"],
            "ordered_phase_sha256": [
                phase["phase_sha256"]
                for phase in prefix["ordered_trusted_phases"]
            ],
            "evidence_cutoff": cutoff,
        },
    })


def test_feedback_v2_resolves_next_distinct_multilabel_and_terminal_but_never_weights() -> None:
    prefix = _manifest([_phase(0, "discovery", "T1082")])
    final = _manifest([
        _phase(0, "discovery", "T1082"),
        {
            **_phase(1, "execution", "T1059"),
            "labels": [
                _phase(1, "execution", "T1059")["labels"][0],
                _phase(1, "persistence", "T1547")["labels"][0],
            ],
        },
    ])
    snapshot = _snapshot(prefix, prediction=["execution", "persistence"])
    feedback = build_auto_evidence_feedback(
        snapshot,
        {
            "session_id": "phase4-feedback",
            "status": "closed",
            "is_ended": True,
            "prediction_trusted_history_manifest": final,
        },
    )
    assert feedback is not None
    assert feedback["actual_outcome_type"] == "next_behavior_phase"
    assert feedback["actual_tactic_set"] == ["execution", "persistence"]
    assert feedback["weight_eligible"] is False
    assert feedback_weight_signal(feedback)[0] is False

    terminal = build_auto_evidence_feedback(
        snapshot,
        {
            "session_id": "phase4-feedback",
            "status": "closed",
            "is_ended": True,
            "prediction_trusted_history_manifest": prefix,
        },
    )
    assert terminal is not None
    assert terminal["actual_outcome_type"] == "session_end"
    assert terminal["terminal_outcome"] == "session_end_no_further_trusted_behavior"


def test_wrong_cutoff_and_snapshot_hash_tamper_fail_closed() -> None:
    prefix = _manifest([_phase(0, "discovery", "T1082")])
    snapshot = _snapshot(prefix, prediction=["execution"])
    assert validate_prediction_snapshot_integrity(snapshot) == []
    tampered = copy.deepcopy(snapshot)
    tampered["prediction_history"]["history_manifest_sha256"] = "f" * 64
    assert validate_prediction_snapshot_integrity(tampered)
    wrong = copy.deepcopy(prefix)
    wrong["evidence_cutoff"] = make_evidence_cutoff(
        "2026-08-12T00:00:00Z", "older-event"
    )
    # Rehashing only the outer snapshot cannot make a mismatched bound cutoff valid.
    assert build_auto_evidence_feedback(
        snapshot,
        {
            "session_id": "phase4-feedback",
            "status": "closed",
            "is_ended": True,
            "prediction_trusted_history_manifest": wrong,
        },
    ) is None
    assert prefix["late_arrival_policy"] == "immutable_cutoff_new_forecast_only"
