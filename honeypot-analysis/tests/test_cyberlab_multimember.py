from __future__ import annotations

import copy
import gzip
import hashlib
import json
from pathlib import Path

import pytest

from production.reproduction.cyberlab_adapter import (
    ADAPTER_SCHEMA_VERSION,
    HIGH_INTERACTION_SENSOR,
    SOURCE_SCHEMA_VERSION,
    ZENODO_DOI,
    ZENODO_RECORD_ID,
    CyberLabAdapter,
    CyberLabAdapterError,
)
from production.reproduction.cyberlab_multimember import (
    build_multi_member_safe_receipt,
    merge_cyberlab_private_sessions,
    publish_multi_member_receipt,
    require_valid_multi_member_safe_receipt,
)


KEY = b"cyberlab-multimember-fixture-key-0001"
KEY_ID = "cyberlab-multimember-v1"


def _event(session: str, eventid: str, timestamp: str, message: str) -> dict:
    return {
        "session_id": session,
        "eventid": eventid,
        "timestamp": timestamp,
        "sensor": HIGH_INTERACTION_SENSOR,
        "protocol": "ssh" if eventid.endswith("connect") else None,
        "message": message,
    }


def _write(tmp_path: Path, filename: str, events: list[dict]) -> tuple[Path, dict, dict]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    path = tmp_path / filename
    with gzip.open(path, "wt", encoding="utf-8") as handle:
        json.dump([{events[0]["session_id"]: events}], handle)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    date = filename.removeprefix("cyberlab_").removesuffix(".json.gz")
    member = {
        "filename": filename,
        "collection_date": date,
        "sha256": digest,
    }
    provenance = {
        "adapter_schema_version": ADAPTER_SCHEMA_VERSION,
        "source_schema_version": SOURCE_SCHEMA_VERSION,
        "zenodo_record_id": ZENODO_RECORD_ID,
        "doi": ZENODO_DOI,
        "source_filename": filename,
        "source_member_date": date,
        "source_sha256": digest,
        "source_checksum_md5": "md5:" + ("a" if date.endswith("01") else "b") * 32,
        "sensor": HIGH_INTERACTION_SENSOR,
        "adapter_sha256": "c" * 64,
        "sanitizer_version": "canonical-sanitizer.v1",
        "classification_policy_sha256": "d" * 64,
        "trust_policy_sha256": "e" * 64,
    }
    return path, member, provenance


def _private_pair(tmp_path: Path) -> tuple[dict, list[dict], dict]:
    first_events = [
        _event("cross-session", "cowrie.session.connect", "2020-01-01T00:00:00Z", "connect"),
        _event("cross-session", "cowrie.command.input", "2020-01-01T00:00:01Z", "CMD: whoami"),
    ]
    second_events = [
        _event("cross-session", "cowrie.command.input", "2020-01-02T00:00:01Z", "CMD: uname -a"),
        _event("cross-session", "cowrie.session.closed", "2020-01-02T00:00:02Z", "closed"),
    ]
    p1, m1, prov1 = _write(tmp_path / "one", "cyberlab_2020-01-01.json.gz", first_events)
    p2, m2, prov2 = _write(tmp_path / "two", "cyberlab_2020-01-02.json.gz", second_events)
    a1 = CyberLabAdapter(
        source_member=m1,
        provenance=prov1,
        pseudonymization_key=KEY,
        pseudonymization_key_id=KEY_ID,
    )
    a2 = CyberLabAdapter(
        source_member=m2,
        provenance=prov2,
        pseudonymization_key=KEY,
        pseudonymization_key_id=KEY_ID,
    )
    first = list(a1.iter_private_sessions(p1))[0]
    second = list(a2.iter_private_sessions(p2))[0]
    merged = merge_cyberlab_private_sessions([first, second])[0]
    receipts = [
        {
            "filename": m1["filename"],
            "collection_date": m1["collection_date"],
            "chronological_order": 1,
            "size_bytes": p1.stat().st_size,
            "sha256": m1["sha256"],
            "checksum_md5": prov1["source_checksum_md5"],
        },
        {
            "filename": m2["filename"],
            "collection_date": m2["collection_date"],
            "chronological_order": 2,
            "size_bytes": p2.stat().st_size,
            "sha256": m2["sha256"],
            "checksum_md5": prov2["source_checksum_md5"],
        },
    ]
    return merged, receipts, prov2


def test_multimember_receipt_is_deterministic_and_content_bound(tmp_path: Path) -> None:
    private, receipts, provenance = _private_pair(tmp_path)
    first = build_multi_member_safe_receipt(
        private,
        receipts,
        provenance=provenance,
        pseudonymization_key=KEY,
        pseudonymization_key_id=KEY_ID,
    )
    second = build_multi_member_safe_receipt(
        copy.deepcopy(private),
        list(reversed(receipts)),
        provenance=provenance,
        pseudonymization_key=KEY,
        pseudonymization_key_id=KEY_ID,
    )
    assert first == second
    assert require_valid_multi_member_safe_receipt(first) == first
    serialized = json.dumps(first, sort_keys=True)
    assert "cross-session" not in serialized
    assert "whoami" not in serialized
    assert "uname -a" not in serialized
    assert first["session"]["termination_status"] == "explicit_closed"
    assert first["session"]["cross_file"] is True


def test_conflicting_duplicate_fails_closed(tmp_path: Path) -> None:
    private, receipts, provenance = _private_pair(tmp_path)
    conflict = copy.deepcopy(private)
    conflict["events"].append(
        {
            **conflict["events"][1],
            "command": "id",
            "command_digest": hashlib.sha256(b"id").hexdigest(),
        }
    )
    with pytest.raises(CyberLabAdapterError, match="duplicate event"):
        build_multi_member_safe_receipt(
            conflict,
            receipts,
            provenance=provenance,
            pseudonymization_key=KEY,
            pseudonymization_key_id=KEY_ID,
        )


def test_exact_duplicate_is_idempotently_deduplicated(tmp_path: Path) -> None:
    private, _, _ = _private_pair(tmp_path)
    duplicate = copy.deepcopy(private)
    duplicate["events"] = [private["events"][0], private["events"][0]]
    merged = merge_cyberlab_private_sessions([private, duplicate])[0]
    assert len(merged["events"]) == len(private["events"])
    assert merged["events"] == private["events"]


def test_tampering_member_or_session_hash_fails_closed(tmp_path: Path) -> None:
    private, receipts, provenance = _private_pair(tmp_path)
    receipt = build_multi_member_safe_receipt(
        private,
        receipts,
        provenance=provenance,
        pseudonymization_key=KEY,
        pseudonymization_key_id=KEY_ID,
    )
    tampered = copy.deepcopy(receipt)
    tampered["session"]["source_member_receipt_refs"][0]["sha256"] = "f" * 64
    with pytest.raises(CyberLabAdapterError):
        require_valid_multi_member_safe_receipt(tampered)

    tampered = copy.deepcopy(receipt)
    tampered["session"]["provenance"]["unexpected"] = "nope"
    with pytest.raises(CyberLabAdapterError):
        require_valid_multi_member_safe_receipt(tampered)

    tampered = copy.deepcopy(receipt)
    tampered["session"]["events"][0]["event_type"] = "cowrie.command.input"
    with pytest.raises(CyberLabAdapterError):
        require_valid_multi_member_safe_receipt(tampered)


def test_atomic_publish_is_idempotent_and_never_overwrites(tmp_path: Path) -> None:
    private, receipts, provenance = _private_pair(tmp_path)
    receipt = build_multi_member_safe_receipt(
        private,
        receipts,
        provenance=provenance,
        pseudonymization_key=KEY,
        pseudonymization_key_id=KEY_ID,
    )
    target = tmp_path / "receipts" / "session.json"
    assert publish_multi_member_receipt(target, receipt) == "published"
    assert publish_multi_member_receipt(target, receipt) == "already_published"
    tampered = copy.deepcopy(receipt)
    tampered["interruption_safe"] = False
    with pytest.raises(CyberLabAdapterError):
        publish_multi_member_receipt(target, tampered)
