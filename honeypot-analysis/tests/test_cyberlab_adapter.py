from __future__ import annotations

import copy
import gzip
import hashlib
import json
from pathlib import Path

import pytest

from production.reproduction.cyberlab_adapter import (
    ADAPTER_SCHEMA_VERSION,
    CANONICAL_SESSION_SCHEMA_VERSION,
    CyberLabAdapter,
    CyberLabAdapterError,
    HIGH_INTERACTION_SENSOR,
    SOURCE_SCHEMA_VERSION,
    ZENODO_DOI,
    ZENODO_RECORD_ID,
    high_interaction_decision,
    merge_cyberlab_private_sessions,
    require_valid_adapter_policy,
    require_valid_cyberlab_session,
)


KEY = b"cyberlab-fixture-pseudonymization-key-0001"
KEY_ID = "cyberlab-fixture-v1"


def _event(
    session_id: str,
    eventid: str,
    timestamp: str,
    *,
    sensor: str = HIGH_INTERACTION_SENSOR,
    protocol: str | None = None,
    message: str | None = "event",
) -> dict:
    return {
        "session_id": session_id,
        "eventid": eventid,
        "timestamp": timestamp,
        "sensor": sensor,
        "protocol": protocol,
        "message": message,
    }


def _session(session_id: str = "fixture-session", *, closed: bool = True) -> dict:
    events = [
        _event(
            session_id,
            "cowrie.session.connect",
            "2020-01-01T00:00:00Z",
            protocol="ssh",
        ),
        _event(
            session_id,
            "cowrie.command.input",
            "2020-01-01T00:00:01Z",
            message="CMD: whoami",
        ),
        _event(
            session_id,
            "cowrie.command.success",
            "2020-01-01T00:00:01.100000Z",
            message="Command found: whoami",
        ),
        _event(
            session_id,
            "cowrie.command.input",
            "2020-01-01T00:00:02Z",
            message="CMD: uname -a",
        ),
        _event(
            session_id,
            "cowrie.command.failed",
            "2020-01-01T00:00:02.100000Z",
            message="Command not found: uname -a",
        ),
    ]
    if closed:
        events.append(
            _event(
                session_id,
                "cowrie.session.closed",
                "2020-01-01T00:00:03Z",
                message="Connection lost",
            )
        )
    return {session_id: events}


def _write_member(tmp_path: Path, items: list[dict]) -> tuple[Path, dict, dict]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    path = tmp_path / "cyberlab_2020-01-01.json.gz"
    with gzip.open(path, "wt", encoding="utf-8") as handle:
        json.dump(items, handle, separators=(",", ":"))
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    member = {
        "filename": path.name,
        "collection_date": "2020-01-01",
        "sha256": digest,
    }
    provenance = {
        "adapter_schema_version": ADAPTER_SCHEMA_VERSION,
        "source_schema_version": SOURCE_SCHEMA_VERSION,
        "zenodo_record_id": ZENODO_RECORD_ID,
        "doi": ZENODO_DOI,
        "source_filename": path.name,
        "source_member_date": "2020-01-01",
        "source_sha256": digest,
        "source_checksum_md5": "md5:" + "a" * 32,
        "sensor": HIGH_INTERACTION_SENSOR,
        "adapter_sha256": "b" * 64,
        "sanitizer_version": "canonical-sanitizer.v1",
        "classification_policy_sha256": "c" * 64,
        "trust_policy_sha256": "d" * 64,
    }
    return path, member, provenance


def _adapter(tmp_path: Path, items: list[dict] | None = None) -> tuple[CyberLabAdapter, Path]:
    path, member, provenance = _write_member(
        tmp_path,
        items if items is not None else [_session()],
    )
    return (
        CyberLabAdapter(
            source_member=member,
            provenance=provenance,
            pseudonymization_key=KEY,
            pseudonymization_key_id=KEY_ID,
        ),
        path,
    )


def test_streaming_gzip_normalization_close_and_privacy(tmp_path: Path) -> None:
    adapter, path = _adapter(tmp_path)
    private = list(adapter.iter_private_sessions(path))
    safe = list(adapter.iter_sessions(path))

    assert len(private) == len(safe) == 1
    assert safe[0]["schema_version"] == CANONICAL_SESSION_SCHEMA_VERSION
    assert safe[0]["status"] == "closed"
    assert safe[0]["termination_status"] == "explicit_closed"
    assert safe[0]["high_interaction_eligibility"] == "eligible"
    serialized = json.dumps(safe[0], sort_keys=True)
    for forbidden in ("fixture-session", "whoami", "uname -a", "Command found"):
        assert forbidden not in serialized


def test_private_classifier_stream_preserves_inputs_but_not_outcome_pairing(
    tmp_path: Path,
) -> None:
    adapter, path = _adapter(tmp_path)
    private = list(adapter.iter_private_sessions(path))[0]
    events = adapter.build_private_classifier_events(private)
    inputs = [event for event in events if event["eventid"] == "cowrie.command.input"]
    outcomes = [event for event in events if event["eventid"] in {
        "cowrie.command.success", "cowrie.command.failed"
    }]
    assert [event["input"] for event in inputs] == ["whoami", "uname -a"]
    assert all("input" not in event for event in outcomes)
    assert all(
        event["cyberlab_outcome_association"] == "unpaired_contextual"
        for event in outcomes
    )


def test_missing_close_is_unresolved_not_terminal(tmp_path: Path) -> None:
    adapter, path = _adapter(tmp_path, [_session(closed=False)])
    safe = list(adapter.iter_sessions(path))[0]
    assert safe["status"] == "active"
    assert safe["termination_status"] == "unresolved"


def test_sensor_filter_is_label_blind_and_mixed_sensor_fails_closed(
    tmp_path: Path,
) -> None:
    wrong = _session("wrong")
    for event in wrong["wrong"]:
        event["sensor"] = "cowrie-deployment-v02"
    mixed = _session("mixed")
    mixed["mixed"][2]["sensor"] = "cowrie-deployment-v02"
    adapter, path = _adapter(tmp_path, [wrong, mixed])
    private = list(adapter.iter_private_sessions(path))
    assert high_interaction_decision(private[0]) == {
        "eligible": False,
        "reason": "sensor_not_ubuntu_basic_pool",
    }
    assert high_interaction_decision(private[1]) == {
        "eligible": False,
        "reason": "mixed_sensor_values",
    }


def test_duplicate_event_is_idempotent_and_conflict_fails(tmp_path: Path) -> None:
    base = _session("duplicate")
    duplicate = copy.deepcopy(base["duplicate"][1])
    base["duplicate"].insert(2, duplicate)
    adapter, path = _adapter(tmp_path, [base])
    private = list(adapter.iter_private_sessions(path))[0]
    assert len(private["events"]) == len(base["duplicate"]) - 1

    conflict = _session("conflict")
    conflict["conflict"].append(
        _event(
            "conflict",
            "cowrie.command.input",
            "2020-01-01T00:00:01Z",
            message="CMD: id",
        )
    )
    conflict_adapter, conflict_path = _adapter(tmp_path / "conflict", [conflict])
    with pytest.raises(CyberLabAdapterError, match="conflicting duplicate"):
        list(conflict_adapter.iter_private_sessions(conflict_path))


def test_cross_file_merge_preserves_provenance_and_close(tmp_path: Path) -> None:
    first_adapter, first_path = _adapter(tmp_path / "first", [_session("cross", closed=False)])
    second_adapter, second_path = _adapter(tmp_path / "second", [_session("cross", closed=True)])
    first = list(first_adapter.iter_private_sessions(first_path))[0]
    second = list(second_adapter.iter_private_sessions(second_path))[0]
    second["source_members"] = ["cyberlab_2020-01-02.json.gz"]
    second["source_member_dates"] = ["2020-01-02"]
    merged = merge_cyberlab_private_sessions([first, second])[0]
    assert merged["cross_file"] is True
    assert len(merged["source_members"]) == 2
    assert merged["status"] == "closed"
    assert merged["termination_status"] == "explicit_closed"
    with pytest.raises(CyberLabAdapterError, match="multi-member safe receipt"):
        from production.reproduction.cyberlab_adapter import _safe_session

        _safe_session(
            merged,
            provenance=second_adapter.provenance,
            source_member=second_adapter.source_member,
            key=KEY,
            key_id=KEY_ID,
        )


def test_malformed_records_fail_closed(tmp_path: Path) -> None:
    malformed = {"bad": [{"session_id": "bad", "eventid": "cowrie.session.connect", "timestamp": "bad", "sensor": HIGH_INTERACTION_SENSOR}]}
    adapter, path = _adapter(tmp_path, [malformed])
    with pytest.raises(CyberLabAdapterError, match="timestamp is invalid"):
        list(adapter.iter_private_sessions(path))

    mismatch = _session("mismatch")
    mismatch["mismatch"][0]["session_id"] = "other"
    adapter2, path2 = _adapter(tmp_path / "mismatch", [mismatch])
    with pytest.raises(CyberLabAdapterError, match="session_id disagrees"):
        list(adapter2.iter_private_sessions(path2))


def test_repeated_parse_is_byte_deterministic_and_timestamp_ordered(tmp_path: Path) -> None:
    item = _session("stable")
    item["stable"] = list(reversed(item["stable"]))
    adapter, path = _adapter(tmp_path, [item])
    first = list(adapter.iter_sessions(path))
    second = list(adapter.iter_sessions(path))
    assert first == second
    times = [event["event_time"] for event in first[0]["events"]]
    assert times == sorted(times)


def test_existing_internal_adapter_import_and_contract_remain_unchanged() -> None:
    from production.reproduction.next_behavior import zenodo_corpus

    assert zenodo_corpus.HISTORICAL_DATASET_SOURCE.startswith("zenodo:21260400:")
    assert "cowrie.command.input" in zenodo_corpus._SESSION_EVENT_TYPES
    assert "cowrie.command.success" not in zenodo_corpus._SESSION_EVENT_TYPES


def test_tracked_external_policy_is_versioned_and_strict() -> None:
    policy = json.loads(
        Path("configs/cyberlab_external_adapter.v1.json").read_text(
            encoding="utf-8"
        )
    )
    assert require_valid_adapter_policy(policy)["schema_version"] == ADAPTER_SCHEMA_VERSION
