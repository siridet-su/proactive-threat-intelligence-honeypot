from __future__ import annotations

from copy import deepcopy

import pytest

from production.prediction.next_behavior_chronology import (
    NextBehaviorChronologyError,
    order_model_chronology,
    relative_time_milliseconds,
)
from production.prediction.next_behavior_preprocessing import (
    build_live_model_input,
)
from production.prediction.next_behavior_runtime import (
    FrozenTransformerPocPredictor,
    build_live_next_behavior_session,
    validate_prediction_snapshot_integrity,
)


SHA = "1" * 64


def _record(timestamp: str, sequence: int, identity: str) -> dict:
    return {
        "source_timestamp": timestamp,
        "durable_sequence": sequence,
        "durable_id": identity,
        "marker": identity,
    }


def _classification(
    timestamp: str,
    sequence: int,
    tactic: str,
    technique: str,
) -> dict:
    return {
        "cowrie_eventid": "cowrie.command.input",
        "event_timestamp": timestamp,
        "compound_command_index": sequence,
        "ttp": technique,
        "tactic": tactic,
        "source": "rule",
        "confidence": 1.0,
        "high_confidence": True,
        "agreement_status": "rule_only",
        "durable_evidence_order": {
            "schema_version": "prediction_evidence_cutoff.v1",
            "received_at": (
                f"2026-07-31T00:00:{sequence:02d}.000000+00:00"
            ),
            "event_id": f"event-{sequence}",
        },
    }


def _payload(events: list[dict]) -> dict:
    return {
        "session_id": "chronology-session",
        "protocol": "ssh",
        "status": "active",
        "is_ended": False,
        "login_success": True,
        "login_attempts": 1,
        "commands": ["[redacted]"] * len(events),
        "classification_events": events,
        "raw_events": [],
    }


def _safe(payload: dict) -> dict | None:
    return build_live_next_behavior_session(
        payload,
        rule_policy_sha256=SHA,
        trust_policy_sha256=SHA,
        classifier_checkpoint_sha256=SHA,
    )


def test_increasing_and_late_arrival_use_source_chronology_without_rewrite() -> None:
    increasing = order_model_chronology(
        [
            _record("2026-07-31T00:00:01Z", 0, "a"),
            _record("2026-07-31T00:00:02Z", 1, "b"),
        ]
    )
    late = order_model_chronology(
        [
            _record("2026-07-31T00:00:02Z", 0, "later-source"),
            _record("2026-07-31T00:00:01Z", 1, "late-arrival"),
        ]
    )
    assert [item["marker"] for item in increasing.records] == ["a", "b"]
    assert increasing.late_arrival_count == 0
    assert [item["marker"] for item in late.records] == [
        "late-arrival",
        "later-source",
    ]
    assert late.late_arrival_count == 1
    assert relative_time_milliseconds(late) == (0, 1_000)


def test_equal_timestamps_use_durable_sequence_then_identity() -> None:
    records = [
        _record("2026-07-31T00:00:01Z", 2, "z"),
        _record("2026-07-31T00:00:01Z", 0, "b"),
        _record("2026-07-31T00:00:01Z", 1, "a"),
    ]
    result = order_model_chronology(records)
    assert [item["marker"] for item in result.records] == ["b", "a", "z"]
    assert result.equal_timestamp_count == 2
    assert result.receipt()["ordering"] == (
        "valid_source_timestamp_then_durable_sequence_then_identity"
    )


@pytest.mark.parametrize(
    ("timestamp", "reason"),
    [
        ("", "missing_source_timestamp"),
        ("not-a-time", "invalid_source_timestamp"),
        ("2026-07-31T00:00:01", "timezone_missing_source_timestamp"),
    ],
)
def test_missing_invalid_or_timezone_free_timestamp_abstains_explicitly(
    timestamp: str,
    reason: str,
) -> None:
    with pytest.raises(NextBehaviorChronologyError) as caught:
        order_model_chronology([_record(timestamp, 0, "event")])
    assert caught.value.reason == reason


def test_multiple_late_events_and_replay_are_deterministic() -> None:
    records = [
        _record("2026-07-31T00:00:05Z", 0, "five"),
        _record("2026-07-31T00:00:02Z", 1, "two"),
        _record("2026-07-31T00:00:04Z", 2, "four"),
        _record("2026-07-31T00:00:01Z", 3, "one"),
    ]
    first = order_model_chronology(records)
    second = order_model_chronology(deepcopy(records))
    assert first == second
    assert first.late_arrival_count == 2
    assert [item["marker"] for item in first.records] == [
        "one",
        "two",
        "four",
        "five",
    ]


def test_ambiguous_order_and_record_limit_fail_closed() -> None:
    duplicate = _record("2026-07-31T00:00:01Z", 0, "same")
    with pytest.raises(
        NextBehaviorChronologyError,
        match="ambiguous_durable_evidence_order",
    ):
        order_model_chronology([duplicate, deepcopy(duplicate)])
    with pytest.raises(
        NextBehaviorChronologyError,
        match="chronology_record_limit_exceeded",
    ):
        order_model_chronology(
            [
                _record("2026-07-31T00:00:01Z", 0, "a"),
                _record("2026-07-31T00:00:02Z", 1, "b"),
            ],
            maximum_records=1,
        )


def test_late_runtime_evidence_rebuilds_phases_and_does_not_poison_later_input() -> None:
    late = _payload(
        [
            _classification(
                "2026-07-31T00:00:10Z",
                0,
                "execution",
                "T1059",
            ),
            _classification(
                "2026-07-31T00:00:05Z",
                1,
                "discovery",
                "T1082",
            ),
        ]
    )
    safe = _safe(late)
    assert safe is not None
    model_input = build_live_model_input(safe)
    assert [phase["tactics"] for phase in model_input["phase_sequence"]] == [
        ["discovery"],
        ["execution"],
    ]

    later = deepcopy(late)
    later["classification_events"].append(
        _classification(
            "2026-07-31T00:00:12Z",
            2,
            "collection",
            "T1003",
        )
    )
    later_safe = _safe(later)
    assert later_safe is not None
    later_input = build_live_model_input(later_safe)
    assert [phase["tactics"] for phase in later_input["phase_sequence"]] == [
        ["discovery"],
        ["execution"],
        ["collection"],
    ]
    assert later_input == build_live_model_input(_safe(deepcopy(later)))


def test_bounded_phase_history_remains_last_eight_after_chronology_rebuild() -> None:
    tactics = [
        ("discovery", "T1082"),
        ("execution", "T1059"),
    ]
    events = [
        _classification(
            f"2026-07-31T00:00:{20 - index:02d}Z",
            index,
            tactics[index % 2][0],
            tactics[index % 2][1],
        )
        for index in range(10)
    ]
    safe = _safe(_payload(events))
    assert safe is not None
    model_input = build_live_model_input(safe, max_sequence_length=8)
    assert model_input["truncated"] is True
    assert len(model_input["phase_sequence"]) == 8


def test_irrecoverable_runtime_chronology_has_bounded_unavailable_reason() -> None:
    predictor = object.__new__(FrozenTransformerPocPredictor)
    predictor.enabled = True
    predictor.model = object()
    predictor.load_error = ""
    predictor.load_time_ms = 0.0
    predictor.spec = {"architecture": {"maximum_sequence_length": 8}}
    predictor.vocabulary = {}
    predictor.calibration = {}
    predictor.vocabulary_hash = ""
    predictor.policy = {
        "runtime_rule_policy_sha256": SHA,
        "runtime_trust_policy_sha256": SHA,
        "runtime_classifier_checkpoint_sha256": SHA,
    }
    payload = _payload(
        [_classification("", 0, "execution", "T1059")]
    )
    snapshot = predictor.predict_session(payload, event_id="event-missing")
    assert snapshot["prediction_status"] == "model_unavailable"
    assert snapshot["prediction_status_reason"] == (
        "chronology_unavailable:missing_source_timestamp"
    )
    assert validate_prediction_snapshot_integrity(snapshot) == []
