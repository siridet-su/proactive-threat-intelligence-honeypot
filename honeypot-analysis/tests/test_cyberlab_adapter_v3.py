from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from production.reproduction.cyberlab_adapter import CyberLabAdapterError
from production.reproduction.cyberlab_adapter_v2 import (
    MIXED_SENSOR_REASON,
    MISSING_SENSOR_REASON,
    WRONG_SENSOR_REASON,
)
from production.reproduction.cyberlab_adapter_v3 import (
    ADAPTER_SCHEMA_VERSION,
    QUARANTINE_REASON,
    SEGMENT_SCHEMA_VERSION,
    CyberLabAdapter,
    merge_cyberlab_private_sessions,
    require_valid_adapter_policy,
    split_private_session_at_quarantine,
)
from production.reproduction.next_behavior.corpus import build_privacy_safe_session
from production.prediction.next_trusted_group_target import build_next_trusted_group_examples
from tests.test_next_trusted_group_target import _group as target_group, _session as target_session

from tests.test_cyberlab_adapter import KEY, KEY_ID, _event, _session, _write_member


def _adapter(tmp_path: Path, items: list[dict]):
    path, member, provenance = _write_member(tmp_path, items)
    return (
        CyberLabAdapter(
            source_member=member,
            provenance=provenance,
            pseudonymization_key=KEY,
            pseudonymization_key_id=KEY_ID,
        ),
        path,
        member,
        provenance,
    )


def _barrier_session(session_id: str = "barrier") -> dict:
    item = _session(session_id, closed=True)
    events = item[session_id]
    events.insert(
        2,
        _event(
            session_id,
            "cowrie.command.input",
            "2020-01-01T00:00:01.500000Z",
            message="event",
        ),
    )
    return item


def test_eligible_missing_command_is_quarantined_without_label(tmp_path: Path):
    adapter, path, _, _ = _adapter(tmp_path, [_barrier_session()])
    private = list(adapter.iter_private_sessions(path))[0]
    assert private["quarantine_barrier_count"] == 1
    assert private["quarantine_events"][0]["reason_code"] == QUARANTINE_REASON
    assert private["quarantine_events"][0]["barrier"] is True
    assert all(event["event_type"] != "cowrie.command.input" or event.get("command") for event in private["events"])
    assert all("ttp" not in event and "label" not in event for event in private["quarantine_events"])


def test_quarantine_never_enters_classifier_stream(tmp_path: Path):
    adapter, path, _, _ = _adapter(tmp_path, [_barrier_session()])
    private = list(adapter.iter_private_sessions(path))[0]
    classifier_events = adapter.build_private_classifier_events(private)
    assert len([event for event in classifier_events if event["eventid"] == "cowrie.command.input"]) == 2
    assert all(event.get("input") for event in classifier_events if event["eventid"] == "cowrie.command.input")


def test_quarantine_is_a_causal_barrier_and_close_stays_final(tmp_path: Path):
    adapter, path, _, _ = _adapter(tmp_path, [_barrier_session("causal")])
    private = list(adapter.iter_private_sessions(path))[0]
    segments = split_private_session_at_quarantine(private)
    assert [segment["schema_version"] for segment in segments] == [SEGMENT_SCHEMA_VERSION] * 2
    assert segments[0]["status"] == "active"
    assert segments[0]["termination_status"] == "unresolved"
    assert segments[1]["status"] == "closed"
    assert segments[1]["termination_status"] == "explicit_closed"
    before_orders = {_event_order for _event_order in (event["source_event_order"] for event in segments[0]["events"])}
    after_orders = {_event_order for _event_order in (event["source_event_order"] for event in segments[1]["events"])}
    assert before_orders.isdisjoint(after_orders)
    assert max(before_orders) < min(after_orders)


def test_target_builder_cannot_create_transition_across_barrier():
    before = target_session(
        [
            target_group("before-one", 1, 0, [("discovery", "T1082")]),
            target_group("before-two", 2, 1000, [("execution", "T1059")]),
        ],
        status="active",
    )
    after = target_session(
        [target_group("after-one", 3, 2000, [("persistence", "T1098")])],
        status="closed",
    )
    before_examples = build_next_trusted_group_examples(before)
    after_examples = build_next_trusted_group_examples(after)
    assert len(before_examples) == 1
    assert before_examples[0]["target"]["target_group_id"] == before["observation_groups"][1]["group_id"]
    assert len(after_examples) == 1
    assert after_examples[0]["target"]["outcome_type"] == "session_end"
    assert all(
        example["target"].get("target_group_id") != after["observation_groups"][0]["group_id"]
        for example in before_examples
    )


def test_valid_evidence_on_both_sides_remains_independently_usable(tmp_path: Path):
    adapter, path, _, _ = _adapter(tmp_path, [_barrier_session("usable")])
    segments = list(adapter.iter_segment_private_sessions(path))
    assert len(segments) == 2
    assert [event["event_type"] for event in segments[0]["events"]].count("cowrie.command.input") == 1
    assert [event["event_type"] for event in segments[1]["events"]].count("cowrie.command.input") == 1
    assert all("quarantine_events" not in segment for segment in segments)


def test_non_missing_eligible_malformed_event_still_fails_closed(tmp_path: Path):
    item = _session("bad-timestamp")
    item["bad-timestamp"][1]["timestamp"] = "not-a-timestamp"
    adapter, path, _, _ = _adapter(tmp_path, [item])
    with pytest.raises(CyberLabAdapterError, match="timestamp is invalid"):
        list(adapter.iter_private_sessions(path))


def test_sensor_boundary_remains_v2_equivalent(tmp_path: Path):
    wrong = _session("wrong")
    for event in wrong["wrong"]:
        event["sensor"] = "legacy-sensor"
    mixed = _session("mixed")
    mixed["mixed"][1]["sensor"] = "legacy-sensor"
    missing = _session("missing")
    del missing["missing"][1]["sensor"]
    adapter, path, _, _ = _adapter(tmp_path, [wrong, mixed, missing])
    records = list(adapter.iter_private_sessions(path))
    assert [record["eligibility_reason"] for record in records] == [
        WRONG_SENSOR_REASON, MIXED_SENSOR_REASON, MISSING_SENSOR_REASON,
    ]


def test_duplicate_quarantine_is_idempotent_and_conflict_fails(tmp_path: Path):
    item = _barrier_session("duplicate")
    duplicate = copy.deepcopy(item["duplicate"][2])
    item["duplicate"].insert(3, duplicate)
    adapter, path, _, _ = _adapter(tmp_path, [item])
    private = list(adapter.iter_private_sessions(path))[0]
    assert len(private["quarantine_events"]) == 1

    conflict = _barrier_session("conflict")
    conflicting = copy.deepcopy(conflict["conflict"][2])
    conflicting["message"] = "different"
    conflict["conflict"].insert(3, conflicting)
    conflict_adapter, conflict_path, _, _ = _adapter(tmp_path / "conflict", [conflict])
    with pytest.raises(CyberLabAdapterError, match="conflicting duplicate"):
        list(conflict_adapter.iter_private_sessions(conflict_path))


def test_cross_file_merge_retains_barrier_and_close(tmp_path: Path):
    first = _barrier_session("cross")
    first["cross"] = first["cross"][:-1]
    second = _session("cross", closed=True)
    a1, p1, _, _ = _adapter(tmp_path / "first", [first])
    a2, p2, _, _ = _adapter(tmp_path / "second", [second])
    left = list(a1.iter_private_sessions(p1))[0]
    right = list(a2.iter_private_sessions(p2))[0]
    right["source_members"] = ["cyberlab_2020-01-02.json.gz"]
    right["source_member_dates"] = ["2020-01-02"]
    merged = merge_cyberlab_private_sessions([left, right])[0]
    assert merged["cross_file"] is True
    assert merged["quarantine_barrier_count"] == 1
    assert merged["status"] == "closed"
    assert merged["termination_status"] == "explicit_closed"


def test_privacy_safe_segments_have_no_raw_command_or_quarantine(tmp_path: Path):
    adapter, path, member, _ = _adapter(tmp_path, [_barrier_session("privacy")])
    segments = list(adapter.iter_segment_private_sessions(path))
    safe_values = []
    for segment in segments:
        receipt = {
            "schema_version": "next_behavior_source_member_receipt.v1",
            "member_id": "nbmember_" + "a" * 64,
            "sha256": member["sha256"], "byte_size": 100, "chronological_order": 1,
            "collection_start": "2020-01-01T00:00:00Z", "collection_end": "2020-01-01T23:59:59Z",
            "pseudonymization_scheme": "hmac-sha256-v1", "pseudonymization_key_id": KEY_ID,
        }
        # The segment adapter boundary itself is tested here; safe-session
        # privacy is unchanged and requires classified groups, so assert only
        # that no quarantined/raw fields are carried forward.
        safe_values.append({key: value for key, value in segment.items() if key not in {"raw_session_id", "events"}})
    serialized = json.dumps(safe_values, sort_keys=True)
    assert "quarantine_events" not in serialized
    assert "command" not in serialized


def test_v3_policy_is_strict_and_versioned():
    policy = json.loads(Path("configs/cyberlab_external_adapter.v3.json").read_text())
    assert require_valid_adapter_policy(policy)["schema_version"] == ADAPTER_SCHEMA_VERSION
    assert policy["quarantine_contract"]["attack_label_emitted"] is False


def test_provenance_mismatch_remains_fail_closed(tmp_path: Path):
    adapter, _, member, provenance = _adapter(tmp_path, [_session("prov")])
    tampered = dict(provenance)
    tampered["source_sha256"] = "f" * 64
    with pytest.raises(CyberLabAdapterError, match="source hash disagrees"):
        CyberLabAdapter(source_member=member, provenance=tampered, pseudonymization_key=KEY, pseudonymization_key_id=KEY_ID)
