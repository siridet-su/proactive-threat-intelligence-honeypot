from __future__ import annotations

import copy
import hashlib
import json

from production.prediction.next_behavior_contract import (
    MODEL_INPUT_SCHEMA_VERSION,
    TACTIC_VOCABULARY,
    TARGET_CONTRACT_ID,
    TERMINAL_OUTCOME,
)
from production.prediction.next_behavior_preprocessing import (
    build_behavior_phases,
    build_live_model_input,
)
from production.prediction.next_behavior_runtime import (
    build_live_next_behavior_session,
)
from production.prediction.next_behavior_tensor import (
    VOCABULARY_SCHEMA_VERSION,
    require_valid_vocabulary,
    tensorize_model_input,
)
from production.utils.serialization import stable_id


RULE_SHA = hashlib.sha256(b"reviewed-rule-policy").hexdigest()
TRUST_SHA = hashlib.sha256(b"runtime-trust-policy").hexdigest()
CHECKPOINT_SHA = hashlib.sha256(b"classifier-checkpoint").hexdigest()
PREPROCESSING_SHA = hashlib.sha256(b"preprocessing").hexdigest()
MEMBERSHIP_SHA = hashlib.sha256(b"training-membership").hexdigest()


def _vocabulary() -> dict:
    value = {
        "schema_version": VOCABULARY_SCHEMA_VERSION,
        "target_contract_id": TARGET_CONTRACT_ID,
        "input_schema_version": MODEL_INPUT_SCHEMA_VERSION,
        "tactics": sorted(TACTIC_VOCABULARY),
        "techniques": ["<UNK>", "T1059", "T1082", "T1547"],
        "label_sources": [
            "reviewed_rule",
            "rule_model_agreement",
            "securebert",
        ],
        "confidence_buckets": [
            "high",
            "low",
            "medium",
            "not_applicable",
        ],
        "agreement_statuses": [
            "agreed",
            "disagreed",
            "emergency",
            "model_only",
            "rule_only",
            "unreviewed",
        ],
        "repetition_buckets": ["1", "2", "3-5", "6+"],
        "elapsed_time_buckets": [
            "10_to_60s",
            "1_to_10s",
            "over_60s",
            "under_1s",
            "unknown",
        ],
        "audit_count_buckets": ["0", "1", "2-5", "6+"],
        "login_outcomes": ["failed", "success", "unknown"],
        "command_count_buckets": ["0", "1", "2-5", "6-20", "21+"],
        "session_age_buckets": [
            "under_10s",
            "10_to_60s",
            "1_to_5m",
            "over_5m",
            "unknown",
        ],
        "maximum_sequence_length": 8,
        "terminal_outcome": TERMINAL_OUTCOME,
        "preprocessing_sha256": PREPROCESSING_SHA,
        "training_membership_sha256": MEMBERSHIP_SHA,
    }
    value["vocabulary_id"] = stable_id("nextbehaviorvocabulary", value)
    return require_valid_vocabulary(value)


def _rule(
    *,
    event_id: str = "event-1",
    timestamp: str = "2026-07-31T00:00:01Z",
    tactic: str = "discovery",
    technique: str = "T1082",
) -> dict:
    return {
        "cowrie_eventid": "cowrie.command.input",
        "evidence_id": event_id,
        "event_timestamp": timestamp,
        "compound_command_index": 0,
        "ttp": technique,
        "tactic": tactic,
        "source": "rule",
        "confidence": 1.0,
        "high_confidence": True,
        "agreement_status": "rule_only",
    }


def _model_candidate(
    *,
    event_id: str = "event-1",
    timestamp: str = "2026-07-31T00:00:01Z",
    confidence: float = 0.40,
    source: str = "securebert_low_confidence",
    command: str = "PRIVATE RAW COMMAND",
) -> dict:
    return {
        "cowrie_eventid": "cowrie.command.input",
        "evidence_id": event_id,
        "event_timestamp": timestamp,
        "compound_command_index": 0,
        "ttp": "T1547",
        "tactic": "persistence",
        "source": source,
        "confidence": confidence,
        "high_confidence": confidence >= 0.90,
        "agreement_status": "model_only",
        "command": command,
    }


def _disagreement(
    *,
    event_id: str = "event-1",
    timestamp: str = "2026-07-31T00:00:01Z",
) -> dict:
    return {
        "cowrie_eventid": "cowrie.command.input",
        "evidence_id": event_id,
        "event_timestamp": timestamp,
        "compound_command_index": 0,
        "ttp": "T1082",
        "tactic": "discovery",
        "source": "rule_securebert_disagreement",
        "high_confidence": False,
        "agreement_status": "technique_and_tactic_disagreement",
        "bert_ttp": "T1547",
        "bert_tactic": "persistence",
        "bert_confidence": 0.97,
    }


def _payload(events: list[dict]) -> dict:
    return {
        "session_id": "audit-runtime-session",
        "protocol": "ssh",
        "status": "active",
        "is_ended": False,
        "login_success": True,
        "login_attempts": 1,
        "commands": ["PRIVATE RAW COMMAND"],
        "classification_events": copy.deepcopy(events),
        "raw_events": [],
    }


def _session(events: list[dict]) -> dict | None:
    return build_live_next_behavior_session(
        _payload(events),
        rule_policy_sha256=RULE_SHA,
        trust_policy_sha256=TRUST_SHA,
        classifier_checkpoint_sha256=CHECKPOINT_SHA,
    )


def _tensor(events: list[dict]) -> tuple[dict, dict]:
    session = _session(events)
    assert session is not None
    model_input = build_live_model_input(session)
    return model_input, tensorize_model_input(model_input, _vocabulary())


def test_zero_one_and_multiple_audit_candidates_use_frozen_buckets() -> None:
    cases = [
        ([_rule()], 0, 1),
        ([_rule(), _model_candidate()], 1, 2),
        ([_rule(), _model_candidate(), _disagreement()], 3, 3),
        ([_rule(), *[_model_candidate() for _ in range(6)]], 6, 4),
    ]
    for events, expected_count, expected_index in cases:
        model_input, tensor = _tensor(events)
        assert model_input["phase_sequence"][0][
            "audit_only_label_count"
        ] == expected_count
        assert tensor["phase_audit_count_index"][-1] == expected_index


def test_audit_only_observations_never_create_trusted_phases() -> None:
    assert _session([_model_candidate()]) is None

    events = [
        _rule(),
        _model_candidate(
            event_id="event-2",
            timestamp="2026-07-31T00:00:02Z",
        ),
        _rule(
            event_id="event-3",
            timestamp="2026-07-31T00:00:03Z",
            tactic="execution",
            technique="T1059",
        ),
    ]
    session = _session(events)
    assert session is not None
    assert len(session["observation_groups"]) == 2
    assert session["audit_summary"] == {
        "total": 1,
        "by_reason": {"below_trusted_threshold": 1},
    }
    assert all(
        not group["audit_only_labels"]
        for group in session["observation_groups"]
    )
    assert [phase["tactics"] for phase in build_behavior_phases(session)] == [
        ["discovery"],
        ["execution"],
    ]


def test_audit_candidates_attach_only_to_their_trusted_observation() -> None:
    session = _session([_rule(), _model_candidate(), _disagreement()])
    assert session is not None
    group = session["observation_groups"][0]
    assert group["tactics"] == ["discovery"]
    assert group["techniques"] == ["T1082"]
    assert len(group["audit_only_labels"]) == 3
    assert {
        item["exclusion_reason"] for item in group["audit_only_labels"]
    } == {"below_trusted_threshold", "unresolved_conflict"}
    assert all(
        item["trust_tier"] == "audit_only_candidate"
        for item in group["audit_only_labels"]
    )


def test_unauthorized_high_confidence_model_output_remains_audit_only() -> None:
    candidate = _model_candidate(
        confidence=0.99,
        source="securebert",
    )
    session = _session([_rule(), candidate])
    assert session is not None
    audit = session["observation_groups"][0]["audit_only_labels"]
    assert len(audit) == 1
    assert audit[0]["exclusion_reason"] == (
        "model_only_not_observed_evidence"
    )
    assert session["observation_groups"][0]["tactics"] == ["discovery"]


def test_adjacent_phase_compression_sums_only_attached_audit_candidates() -> None:
    events = [
        _rule(),
        _model_candidate(),
        _rule(event_id="event-2", timestamp="2026-07-31T00:00:02Z"),
        _disagreement(
            event_id="event-2",
            timestamp="2026-07-31T00:00:02Z",
        ),
    ]
    session = _session(events)
    assert session is not None
    phases = build_behavior_phases(session)
    assert len(phases) == 1
    assert phases[0]["observation_count"] == 2
    assert phases[0]["audit_only_label_count"] == 3
    _, tensor = _tensor(events)
    assert tensor["phase_audit_count_index"][-1] == 3


def test_audit_context_changes_tensor_not_trusted_tactic_membership() -> None:
    without_audit = [_rule()]
    with_audit = [_rule(), _model_candidate()]
    plain_input, plain_tensor = _tensor(without_audit)
    audit_input, audit_tensor = _tensor(with_audit)

    assert plain_input["phase_sequence"][0]["tactics"] == (
        audit_input["phase_sequence"][0]["tactics"]
    )
    assert plain_input["phase_sequence"][0]["techniques"] == (
        audit_input["phase_sequence"][0]["techniques"]
    )
    assert plain_tensor["phase_tactic_multi_hot"] == (
        audit_tensor["phase_tactic_multi_hot"]
    )
    assert plain_tensor["phase_technique_multi_hot"] == (
        audit_tensor["phase_technique_multi_hot"]
    )
    assert plain_tensor["tensor_hash"] != audit_tensor["tensor_hash"]
    assert plain_tensor["phase_audit_count_index"][-1] == 1
    assert audit_tensor["phase_audit_count_index"][-1] == 2


def test_audit_tensor_and_pseudonymous_output_are_deterministic_and_safe() -> None:
    events = [_rule(), _model_candidate(), _disagreement()]
    first_session = _session(events)
    second_session = _session(events)
    first_input, first_tensor = _tensor(events)
    second_input, second_tensor = _tensor(events)

    assert first_session == second_session
    assert first_input == second_input
    assert first_tensor == second_tensor
    assert first_tensor["tensor_hash"] == second_tensor["tensor_hash"]
    serialized = json.dumps(
        {
            "session": first_session,
            "model_input": first_input,
            "tensor": first_tensor,
        },
        sort_keys=True,
    )
    assert "PRIVATE RAW COMMAND" not in serialized
