from __future__ import annotations

import copy
import gzip
import json
from pathlib import Path

import pytest

from production.reproduction.cyberlab_adapter import (
    CyberLabAdapter as V1Adapter,
    CyberLabAdapterError,
    HIGH_INTERACTION_SENSOR,
)
from production.reproduction.cyberlab_adapter_v2 import (
    CyberLabAdapter,
    ELIGIBLE_REASON,
    MIXED_SENSOR_REASON,
    MISSING_SENSOR_REASON,
    WRONG_SENSOR_REASON,
    high_interaction_decision,
    merge_cyberlab_private_sessions,
)

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


def test_wrong_sensor_malformed_command_is_excluded_before_semantic_validation(tmp_path: Path):
    event = _event(
        "wrong",
        "cowrie.command.input",
        "not-a-timestamp",
        sensor="prod-ubuntu-ssh-k8s-local-3",
        message=None,
    )
    adapter, path, _, _ = _adapter(tmp_path, [{"wrong": [event]}])
    records = list(adapter.iter_private_sessions(path))
    assert len(records) == 1
    record = records[0]
    assert record["eligibility_reason"] == WRONG_SENSOR_REASON
    assert record["events"] == []
    assert record["raw_event_count"] == record["excluded_event_count"] == 1
    assert high_interaction_decision(record) == {
        "eligible": False,
        "reason": WRONG_SENSOR_REASON,
    }


def test_eligible_malformed_command_still_fails_closed(tmp_path: Path):
    event = _event(
        "eligible",
        "cowrie.command.input",
        "2020-01-01T00:00:01Z",
        message=None,
    )
    adapter, path, _, _ = _adapter(tmp_path, [{"eligible": [event]}])
    with pytest.raises(CyberLabAdapterError, match="command.input has no exact command text"):
        list(adapter.iter_private_sessions(path))


def test_mixed_and_missing_sensor_are_explicitly_excluded(tmp_path: Path):
    mixed = _session("mixed")
    mixed["mixed"][1]["sensor"] = "other-sensor"
    missing = _session("missing")
    del missing["missing"][1]["sensor"]
    adapter, path, _, _ = _adapter(tmp_path, [mixed, missing])
    records = list(adapter.iter_private_sessions(path))
    assert [record["eligibility_reason"] for record in records] == [
        MIXED_SENSOR_REASON,
        MISSING_SENSOR_REASON,
    ]
    assert all(record["events"] == [] for record in records)


def test_valid_eligible_output_is_byte_equivalent_to_v1(tmp_path: Path):
    item = _session("same")
    v2, path, member, provenance = _adapter(tmp_path / "v2", [item])
    v1 = V1Adapter(
        source_member=member,
        provenance=provenance,
        pseudonymization_key=KEY,
        pseudonymization_key_id=KEY_ID,
    )
    assert list(v2.iter_private_sessions(path)) == list(v1.iter_private_sessions(path))
    assert list(v2.iter_sessions(path)) == list(v1.iter_sessions(path))


def test_ineligible_sessions_never_enter_classifier_stream(tmp_path: Path):
    item = _session("wrong")
    for event in item["wrong"]:
        event["sensor"] = "legacy-sensor"
    adapter, path, _, _ = _adapter(tmp_path, [item])
    assert list(adapter.iter_sessions(path)) == []


def test_exclusion_wins_over_cross_file_eligible_fragment(tmp_path: Path):
    first = _session("cross", closed=False)
    for event in first["cross"]:
        event["sensor"] = "legacy-sensor"
    second = _session("cross", closed=True)
    a1, p1, _, _ = _adapter(tmp_path / "first", [first])
    a2, p2, _, _ = _adapter(tmp_path / "second", [second])
    left = list(a1.iter_private_sessions(p1))[0]
    right = list(a2.iter_private_sessions(p2))[0]
    right["source_members"] = ["cyberlab_2020-01-02.json.gz"]
    right["source_member_dates"] = ["2020-01-02"]
    merged = merge_cyberlab_private_sessions([left, right])[0]
    assert merged["eligibility_reason"] == MIXED_SENSOR_REASON
    assert merged["events"] == []
    assert merged["cross_file"] is True


def test_eligible_cross_file_duplicate_and_close_behavior_unchanged(tmp_path: Path):
    first = _session("cross", closed=False)
    second = _session("cross", closed=True)
    a1, p1, _, _ = _adapter(tmp_path / "first", [first])
    a2, p2, _, _ = _adapter(tmp_path / "second", [second])
    left = list(a1.iter_private_sessions(p1))[0]
    right = list(a2.iter_private_sessions(p2))[0]
    right["source_members"] = ["cyberlab_2020-01-02.json.gz"]
    right["source_member_dates"] = ["2020-01-02"]
    merged = merge_cyberlab_private_sessions([left, right])[0]
    assert "eligibility_reason" not in merged
    assert merged["cross_file"] is True
    assert merged["status"] == "closed"
    assert merged["termination_status"] == "explicit_closed"


def test_privacy_safe_output_remains_unchanged(tmp_path: Path):
    adapter, path, _, _ = _adapter(tmp_path, [_session("private")])
    safe = list(adapter.iter_sessions(path))[0]
    serialized = json.dumps(safe, sort_keys=True)
    assert "private" not in serialized
    assert "whoami" not in serialized
    assert "uname -a" not in serialized
    assert all("command" not in event for event in safe["events"])


def test_source_provenance_mismatch_still_fails_closed(tmp_path: Path):
    adapter, path, _, provenance = _adapter(tmp_path, [_session("prov")])
    tampered = copy.deepcopy(provenance)
    tampered["source_sha256"] = "f" * 64
    with pytest.raises(CyberLabAdapterError, match="source hash disagrees"):
        CyberLabAdapter(
            source_member=adapter.source_member,
            provenance=tampered,
            pseudonymization_key=KEY,
            pseudonymization_key_id=KEY_ID,
        )
