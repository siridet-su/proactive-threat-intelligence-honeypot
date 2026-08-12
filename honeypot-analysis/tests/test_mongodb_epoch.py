from __future__ import annotations

import hashlib
import math

import pytest

from production.storage.canonical_event import CanonicalEventRecord
from production.storage.backend import SQLiteStorage
from production.storage.mongodb_epoch import (
    RUNTIME_ROLE_ID,
    SCHEMA_MANIFEST_ID,
    MongoCapacityGuard,
    MongoEpochStorage,
    capacity_policy,
    load_storage_epoch,
    require_active_release,
)
from production.utils.serialization import stable_json


def _receipt(tmp_path):
    path = tmp_path / "epoch.json"
    document = {
        "schema_version": "canonical_storage_epoch.v1",
        "epoch_id": "mongodb-epoch-test",
        "backend": "mongodb",
        "atlas_org_id": "6a58feef2d2de3b8062f0864",
        "atlas_project_id": "6a7c8771b3b5a11455cc67f1",
        "atlas_cluster_id": "6a7c8d3d368d336cfdbf25df",
        "atlas_cluster_name": "Honeypot-Canonical",
        "database": "honeypot_canonical_v1",
        "start_time": "2026-08-12T00:00:00+00:00",
        "first_eligible_event_cutoff": {"received_at": "2026-08-12T00:00:00+00:00", "event_id": ""},
        "previous_sqlite_archive": {
            "path": "/archive/history.db",
            "sha256": "a" * 64,
            "schema_version": 3,
            "cutoff": {"received_at": "2026-08-12T00:00:00+00:00", "event_id": ""},
            "counts": {"events": 1, "sessions": 1, "reports": 1},
            "final_timestamp": "2026-08-12T00:00:00+00:00",
            "release_sha": "c" * 40,
            "policy_environment_bindings": {
                "classification_rules_file_sha256": "1" * 64,
                "classification_trust_policy_file_sha256": "2" * 64,
                "classifier_environment_file_sha256": "3" * 64,
                "prediction_policy_file_sha256": "4" * 64,
            },
        },
        "reviewed_release_sha": "b" * 40,
        "schema_manifest_identity": SCHEMA_MANIFEST_ID,
        "runtime_role_identity": RUNTIME_ROLE_ID,
        "classifier_policy_environment_bindings": {
            "classification_rules_file_sha256": "1" * 64,
            "classification_trust_policy_file_sha256": "2" * 64,
            "classifier_environment_file_sha256": "3" * 64,
            "prediction_policy_file_sha256": "4" * 64,
        },
        "rollback_mirror_path": "/var/lib/honeypot/mongodb-epoch-mirror.db",
        "capacity_policy": capacity_policy(),
        "receipt_sha256": "",
    }
    document["receipt_sha256"] = hashlib.sha256(
        stable_json({k: v for k, v in document.items() if k != "receipt_sha256"}).encode()
    ).hexdigest()
    path.write_text(stable_json(document) + "\n")
    return path, document


def test_epoch_receipt_is_content_addressed_and_exact(tmp_path):
    path, document = _receipt(tmp_path)
    assert load_storage_epoch(path) == document
    document["epoch_id"] = "tampered"
    path.write_text(stable_json(document) + "\n")
    with pytest.raises(ValueError, match="hash mismatch"):
        load_storage_epoch(path)


def test_epoch_receipt_must_bind_active_release(tmp_path, monkeypatch):
    path, document = _receipt(tmp_path)
    receipt = load_storage_epoch(path)
    monkeypatch.setenv("DEPLOYED_COMMIT", document["reviewed_release_sha"])
    assert require_active_release(receipt) == document["reviewed_release_sha"]
    monkeypatch.setenv("DEPLOYED_COMMIT", "d" * 40)
    with pytest.raises(ValueError, match="active release"):
        require_active_release(receipt)


class _Database:
    def __init__(self, storage, indexes): self.storage, self.indexes = storage, indexes
    def command(self, name, scale=1): return {"storageSize": self.storage, "indexSize": self.indexes}


class _Mongo:
    def __init__(self, storage, indexes): self.database = _Database(storage, indexes)


@pytest.mark.parametrize("percent,state", [(59, "normal"), (60, "warning"), (75, "high"), (85, "fail_safe")])
def test_capacity_thresholds_are_exact(percent, state):
    total = 512 * 1024 * 1024
    guard = MongoCapacityGuard(_Mongo(math.ceil(total * percent / 100), 0))
    assert guard.status()["state"] == state
    if state == "fail_safe":
        with pytest.raises(RuntimeError, match="fail-safe"):
            guard.require_write_capacity()


class _ReplayMongo:
    def __init__(self, persisted):
        self.persisted = persisted

    def get_event(self, event_id):
        return self.persisted


class _Events:
    def __init__(self, first=None):
        self.first = first

    def find_one(self, *args, **kwargs):
        return self.first


class _EpochDatabase:
    def __init__(self, first=None):
        self.events = _Events(first)


class _EpochMongo:
    def __init__(self, first=None):
        self.database = _EpochDatabase(first)


class _ReplayMirror:
    def __init__(self):
        self.record = None

    def persist_for_ack(self, record):
        self.record = record
        return {"ack_eligible": True}


def test_epoch_duplicate_replay_uses_first_durable_received_at(monkeypatch):
    event = {"eventid": "cowrie.command.input", "session": "session-1", "input": "id"}
    first = CanonicalEventRecord.create(
        "sensor-1", event, received_at="2026-08-12T01:02:03+00:00"
    )
    mongo = _ReplayMongo(
        {
            "event_id": first.event_id,
            "sensor_id": first.sensor_id,
            "payload_json": first.payload_json,
            "received_at": first.received_at,
        }
    )
    storage = object.__new__(MongoEpochStorage)
    storage.mongo = mongo
    mirror = _ReplayMirror()
    storage.mirror = mirror
    storage.capacity = object()
    monkeypatch.setattr(
        "production.storage.mongodb_epoch.utc_now",
        lambda: "2026-08-12T09:09:09+00:00",
    )

    event_id, inserted = storage.store_event("sensor-1", event)

    assert event_id == first.event_id
    assert inserted is False
    assert mirror.record.received_at == first.received_at


def test_epoch_boundary_rejects_pre_epoch_mongodb_event(tmp_path):
    _path, receipt = _receipt(tmp_path)
    mirror = SQLiteStorage(f"sqlite:///{tmp_path / 'mirror.db'}")
    mirror.initialize()
    mongo = _EpochMongo(
        {"received_at": "2026-08-11T23:59:59+00:00", "event_id": "event-old"}
    )

    with pytest.raises(RuntimeError, match="outside the canonical epoch"):
        MongoEpochStorage(mongo, mirror, receipt)


def test_epoch_boundary_rejects_historical_mirror_event(tmp_path):
    _path, receipt = _receipt(tmp_path)
    mirror = SQLiteStorage(f"sqlite:///{tmp_path / 'mirror.db'}")
    mirror.initialize()
    record = CanonicalEventRecord.create(
        "sensor-1",
        {"eventid": "cowrie.command.input", "session": "session-old", "input": "id"},
        received_at="2026-08-11T23:59:59+00:00",
    )
    mirror.store_canonical_event(record)

    with pytest.raises(RuntimeError, match="rollback mirror contains"):
        MongoEpochStorage(_EpochMongo(), mirror, receipt)
