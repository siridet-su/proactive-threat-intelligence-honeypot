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
    verify_runtime_deployment,
)
from production.utils.serialization import stable_json
from production.tools.mongodb_epoch_receipt import finalize_epoch_receipt


def _receipt(tmp_path):
    path = tmp_path / "epoch.json"
    document = {
        "schema_version": "canonical_storage_epoch.v2",
        "epoch_id": "mongodb-epoch-test",
        "backend": "mongodb",
        "deployment_identity": {
            "atlas_org_id": "6a58feef2d2de3b8062f0864",
            "atlas_project_id": "6a58feef2d2de3b8062f0922",
            "atlas_cluster_id": "6b1111111111111111111111",
            "atlas_cluster_name": "Honeypot-Canonical-Retry",
            "provider": "GCP",
            "region": "SOUTHEASTERN_ASIA_PACIFIC",
            "srv_hostname": "honeypot-canonical-retry.example.mongodb.net",
            "replica_set_name": "atlas-retry-shard-0",
            "mongodb_server_version": "8.0.29",
        },
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
                "classification_rules_file_sha256": "5" * 64,
                "classification_trust_policy_file_sha256": "6" * 64,
                "classifier_environment_file_sha256": "7" * 64,
                "prediction_policy_file_sha256": "8" * 64,
            },
        },
        "reviewed_release_sha": "b" * 40,
        "reviewed_release_tree": "d" * 40,
        "release_manifest_sha256": "e" * 64,
        "schema_manifest_identity": SCHEMA_MANIFEST_ID,
        "runtime_role_identity": RUNTIME_ROLE_ID,
        "classifier_policy_environment_bindings": {
            "classification_rules_file_sha256": "1" * 64,
            "classification_trust_policy_file_sha256": "2" * 64,
            "classifier_environment_file_sha256": "3" * 64,
            "prediction_policy_file_sha256": "4" * 64,
        },
        "failed_predecessor": {
            "epoch_id": "mongodb-m0-canonical-20260812",
            "preservation_receipt_sha256": "f" * 64,
            "authority": "non_authoritative_failed_software_validation_evidence",
        },
        "provenance_rules": {
            "synthetic_session_source": "e2e_test",
            "exclude_from": [
                "empirical_calibration", "attacker_prevalence", "command_frequency",
                "thesis_ground_truth", "model_quality_evaluation",
            ],
            "attacker_command_markers_authoritative": False,
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


def test_epoch_receipt_finalizer_is_exclusive_and_self_verifying(tmp_path):
    _, document = _receipt(tmp_path)
    document.pop("receipt_sha256")
    output = tmp_path / "final.json"
    receipt = finalize_epoch_receipt(document, output)
    assert receipt == load_storage_epoch(output)
    assert output.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        finalize_epoch_receipt(document, output)


def test_epoch_preserves_distinct_historical_and_new_policy_lineage(tmp_path):
    path, document = _receipt(tmp_path)
    receipt = load_storage_epoch(path)
    assert (
        receipt["previous_sqlite_archive"]["policy_environment_bindings"]
        != receipt["classifier_policy_environment_bindings"]
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("atlas_project_id", "6a7c8771b3b5a11455cc67f1"),
        ("atlas_cluster_id", "6a7c8d3d368d336cfdbf25df"),
        ("atlas_cluster_name", "Honeypot-Canonical"),
        ("srv_hostname", "legacy-honeypot-db.example.mongodb.net"),
    ],
)
def test_epoch_deployment_identity_is_receipt_bound_not_source_bound(tmp_path, field, value):
    path, document = _receipt(tmp_path)
    document["deployment_identity"][field] = value
    document["receipt_sha256"] = hashlib.sha256(
        stable_json({k: v for k, v in document.items() if k != "receipt_sha256"}).encode()
    ).hexdigest()
    path.write_text(stable_json(document) + "\n")
    assert load_storage_epoch(path)["deployment_identity"][field] == value


class _RuntimeClient:
    def server_info(self):
        return {"version": "8.0.29"}


class _RuntimeDatabase:
    def command(self, name):
        assert name == "hello"
        return {"isWritablePrimary": True, "setName": "atlas-retry-shard-0"}


class _RuntimeMongo:
    client = _RuntimeClient()
    database = _RuntimeDatabase()


def _runtime_metadata(receipt):
    deployment = receipt["deployment_identity"]
    return {
        key: deployment[key]
        for key in (
            "atlas_org_id", "atlas_project_id", "atlas_cluster_id",
            "atlas_cluster_name", "provider", "region",
        )
    }


def test_runtime_deployment_requires_exact_receipt_endpoint_and_server(tmp_path):
    path, _ = _receipt(tmp_path)
    receipt = load_storage_epoch(path)
    uri = "mongodb+srv://user:secret@honeypot-canonical-retry.example.mongodb.net/honeypot_canonical_v1"
    assert verify_runtime_deployment(
        receipt, uri, _RuntimeMongo(), runtime_metadata=_runtime_metadata(receipt)
    )["mongodb_server_version"] == "8.0.29"
    with pytest.raises(ValueError, match="endpoint"):
        verify_runtime_deployment(
            receipt,
            "mongodb+srv://user:secret@legacy-honeypot-db.example.mongodb.net/honeypot_canonical_v1",
            _RuntimeMongo(),
            runtime_metadata=_runtime_metadata(receipt),
        )


@pytest.mark.parametrize(
    "field",
    ["atlas_org_id", "atlas_project_id", "atlas_cluster_id", "atlas_cluster_name", "provider", "region"],
)
def test_runtime_deployment_rejects_nonsecret_metadata_mismatch(tmp_path, field):
    path, _ = _receipt(tmp_path)
    receipt = load_storage_epoch(path)
    metadata = _runtime_metadata(receipt)
    metadata[field] = "wrong"
    with pytest.raises(ValueError, match="deployment metadata"):
        verify_runtime_deployment(
            receipt,
            "mongodb+srv://user:secret@honeypot-canonical-retry.example.mongodb.net/honeypot_canonical_v1",
            _RuntimeMongo(),
            runtime_metadata=metadata,
        )


@pytest.mark.parametrize(
    "mutation,error",
    [
        (("replica_set_name", "wrong"), "replica-set"),
        (("mongodb_server_version", "8.0.28"), "server version"),
    ],
)
def test_runtime_deployment_rejects_connected_identity_mismatch(tmp_path, mutation, error):
    path, document = _receipt(tmp_path)
    document["deployment_identity"][mutation[0]] = mutation[1]
    document["receipt_sha256"] = hashlib.sha256(
        stable_json({k: v for k, v in document.items() if k != "receipt_sha256"}).encode()
    ).hexdigest()
    path.write_text(stable_json(document) + "\n")
    with pytest.raises(ValueError, match=error):
        verify_runtime_deployment(
            load_storage_epoch(path),
            "mongodb+srv://user:secret@honeypot-canonical-retry.example.mongodb.net/honeypot_canonical_v1",
            _RuntimeMongo(),
            runtime_metadata=_runtime_metadata(load_storage_epoch(path)),
        )


def test_historical_policy_lineage_must_be_complete_sha256_bindings(tmp_path):
    path, document = _receipt(tmp_path)
    document["previous_sqlite_archive"]["policy_environment_bindings"].pop(
        "prediction_policy_file_sha256"
    )
    document["receipt_sha256"] = hashlib.sha256(
        stable_json(
            {key: value for key, value in document.items() if key != "receipt_sha256"}
        ).encode()
    ).hexdigest()
    path.write_text(stable_json(document) + "\n")
    with pytest.raises(ValueError, match="bindings are incomplete"):
        load_storage_epoch(path)


def test_epoch_receipt_must_bind_active_release(tmp_path, monkeypatch):
    path, document = _receipt(tmp_path)
    receipt = load_storage_epoch(path)
    monkeypatch.setenv("DEPLOYED_COMMIT", document["reviewed_release_sha"])
    monkeypatch.setenv("DEPLOYED_TREE", document["reviewed_release_tree"])
    monkeypatch.setenv("RELEASE_MANIFEST_SHA256", document["release_manifest_sha256"])
    assert require_active_release(receipt) == document["reviewed_release_sha"]
    monkeypatch.setenv("DEPLOYED_COMMIT", "d" * 40)
    with pytest.raises(ValueError, match="active release"):
        require_active_release(receipt)


def test_epoch_receipt_rejects_other_release_tree_or_manifest(tmp_path, monkeypatch):
    path, document = _receipt(tmp_path)
    receipt = load_storage_epoch(path)
    monkeypatch.setenv("DEPLOYED_COMMIT", document["reviewed_release_sha"])
    monkeypatch.setenv("DEPLOYED_TREE", "0" * 40)
    monkeypatch.setenv("RELEASE_MANIFEST_SHA256", document["release_manifest_sha256"])
    with pytest.raises(ValueError, match="release tree"):
        require_active_release(receipt)
    monkeypatch.setenv("DEPLOYED_TREE", document["reviewed_release_tree"])
    monkeypatch.setenv("RELEASE_MANIFEST_SHA256", "0" * 64)
    with pytest.raises(ValueError, match="release manifest"):
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
