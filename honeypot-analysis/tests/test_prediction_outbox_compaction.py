from __future__ import annotations

import copy
import uuid

import pytest

from production.storage.mongodb_operations import (
    MongoDBRuntimeOperations,
    PREDICTION_OUTBOX_COMPACTED_PAYLOAD,
    PREDICTION_OUTBOX_TERMINAL_SCHEMA_VERSION,
)


class _Result:
    def __init__(self, modified_count: int):
        self.modified_count = modified_count


def _matches(document, query):
    def value_matches(value, condition):
        if not isinstance(condition, dict) or not any(
            str(key).startswith("$") for key in condition
        ):
            return value == condition
        for operator, expected in condition.items():
            if operator == "$exists":
                if bool(expected) != ("__missing__" not in (value,)):
                    return False
            elif operator == "$gt":
                if value == "__missing__" or not (value > expected):
                    return False
            elif operator == "$nin":
                if value in expected:
                    return False
            elif operator == "$type":
                if expected == "string" and not isinstance(value, str):
                    return False
            else:
                raise AssertionError(f"unsupported fake operator: {operator}")
        return True

    for key, condition in query.items():
        if key == "$or":
            if not any(_matches(document, child) for child in condition):
                return False
            continue
        if key == "$and":
            if not all(_matches(document, child) for child in condition):
                return False
            continue
        value = document.get(key, "__missing__")
        if not value_matches(value, condition):
            return False
    return True


class _Collection:
    def __init__(self, documents):
        self.documents = {item["_id"]: copy.deepcopy(item) for item in documents}

    def find_one(self, query, projection=None):
        for document in self.documents.values():
            if not _matches(document, query):
                continue
            if projection is None:
                return copy.deepcopy(document)
            return {
                key: value
                for key, value in document.items()
                if projection.get(key, 0) == 1
            }
        return None

    def update_one(self, query, update):
        for identity, document in self.documents.items():
            if not _matches(document, query):
                continue
            before = copy.deepcopy(document)
            for key, value in (update.get("$set") or {}).items():
                document[key] = value
            for key in (update.get("$unset") or {}):
                document.pop(key, None)
            self.documents[identity] = document
            return _Result(int(before != document))
        return _Result(0)


class _Database:
    def __init__(self, outbox, snapshots):
        self.prediction_outbox = _Collection(outbox)
        self.prediction_snapshots = _Collection(snapshots)


def _storage(outbox, snapshots):
    storage = object.__new__(MongoDBRuntimeOperations)
    storage.database = _Database(outbox, snapshots)
    return storage


def _in_progress_row():
    token = str(uuid.uuid4())
    return {
        "_id": "outbox-1",
        "outbox_id": "outbox-1",
        "status": "in_progress",
        "snapshot_id": None,
        "payload_json": '{"session_payload":{"commands":["id"]}}',
        "payload_sha256": "a" * 64,
        "claim_owner": "worker-a",
        "claim_token": token,
        "claim_expires_at": "2026-09-05T11:00:00+00:00",
    }, token


def test_completion_requires_snapshot_and_compacts_atomically():
    row, token = _in_progress_row()
    storage = _storage(
        [row],
        [{"_id": "snapshot-1", "snapshot_id": "snapshot-1"}],
    )

    assert storage.complete_prediction_outbox(
        "outbox-1",
        "worker-a",
        token,
        "snapshot-1",
        now="2026-09-05T10:00:00+00:00",
    )
    result = storage.database.prediction_outbox.documents["outbox-1"]
    assert result["status"] == "completed"
    assert result["payload_json"] == PREDICTION_OUTBOX_COMPACTED_PAYLOAD
    assert result["payload_sha256"] == "a" * 64
    assert result["snapshot_id"] == "snapshot-1"
    assert result["payload_compacted"] is True
    assert result["terminal_schema_version"] == PREDICTION_OUTBOX_TERMINAL_SCHEMA_VERSION
    assert "claim_token" not in result


def test_completion_fails_closed_without_durable_snapshot():
    row, token = _in_progress_row()
    storage = _storage([row], [])

    assert not storage.complete_prediction_outbox(
        "outbox-1",
        "worker-a",
        token,
        "missing-snapshot",
        now="2026-09-05T10:00:00+00:00",
    )
    result = storage.database.prediction_outbox.documents["outbox-1"]
    assert result["status"] == "in_progress"
    assert result["payload_json"] == row["payload_json"]


def test_existing_compaction_is_idempotent_and_nonterminal_rows_are_untouched():
    compacted = {
        "_id": "done",
        "status": "completed",
        "snapshot_id": "snapshot-1",
        "payload_json": PREDICTION_OUTBOX_COMPACTED_PAYLOAD,
        "payload_sha256": "b" * 64,
        "payload_compacted": True,
    }
    retry = {
        "_id": "retry",
        "status": "retry",
        "snapshot_id": None,
        "payload_json": '{"large":"task"}',
        "payload_sha256": "c" * 64,
    }
    storage = _storage(
        [compacted, retry],
        [{"_id": "snapshot-1", "snapshot_id": "snapshot-1"}],
    )

    assert storage.compact_completed_prediction_outbox("done", now="2026-09-05T10:00:00+00:00")
    assert not storage.compact_completed_prediction_outbox("retry", now="2026-09-05T10:00:00+00:00")
    assert storage.database.prediction_outbox.documents["retry"] == retry


@pytest.mark.parametrize("status", ["queued", "in_progress", "retry"])
def test_all_nonterminal_states_retain_full_payload(status):
    row = {
        "_id": f"{status}-row",
        "status": status,
        "snapshot_id": None,
        "payload_json": '{"session_payload":{"commands":["id"]}}',
        "payload_sha256": "d" * 64,
    }
    storage = _storage([row], [])

    assert not storage.compact_completed_prediction_outbox(row["_id"])
    assert storage.database.prediction_outbox.documents[row["_id"]] == row


def test_completed_row_with_active_lease_is_not_compacted():
    row = {
        "_id": "leased",
        "status": "completed",
        "snapshot_id": "snapshot-2",
        "payload_json": '{"session_payload":{"commands":["whoami"]}}',
        "payload_sha256": "e" * 64,
        "claim_owner": "worker-a",
        "claim_token": "lease-token",
        "claim_expires_at": "2026-09-05T11:00:00+00:00",
    }
    storage = _storage([row], [{"_id": "snapshot-2", "snapshot_id": "snapshot-2"}])

    assert not storage.compact_completed_prediction_outbox("leased")
    assert storage.database.prediction_outbox.documents["leased"] == row


def test_completed_row_without_snapshot_link_is_not_compacted():
    row = {
        "_id": "missing-link",
        "status": "completed",
        "snapshot_id": None,
        "payload_json": '{"session_payload":{"commands":["id"]}}',
        "payload_sha256": "1" * 64,
    }
    storage = _storage([row], [])

    assert not storage.compact_completed_prediction_outbox("missing-link")
    assert storage.database.prediction_outbox.documents["missing-link"] == row


def test_completed_row_with_unknown_snapshot_link_is_not_compacted():
    row = {
        "_id": "unknown-link",
        "status": "completed",
        "snapshot_id": "snapshot-missing",
        "payload_json": '{"session_payload":{"commands":["id"]}}',
        "payload_sha256": "2" * 64,
    }
    storage = _storage([row], [])

    assert not storage.compact_completed_prediction_outbox("unknown-link")
    assert storage.database.prediction_outbox.documents["unknown-link"] == row


def test_compaction_preserves_terminal_identity_linkage_and_digest():
    row = {
        "_id": "metadata",
        "schema_version": "mongodb_prediction_outbox.v1",
        "outbox_id": "metadata",
        "job_id": "job-metadata",
        "event_id": "event-metadata",
        "session_id": "session-metadata",
        "status": "completed",
        "snapshot_id": "snapshot-metadata",
        "payload_json": '{"session_payload":{"commands":["exit"]}}',
        "payload_sha256": "f" * 64,
        "attempts": 2,
        "created_at": "2026-09-05T09:00:00+00:00",
        "updated_at": "2026-09-05T09:30:00+00:00",
        "completed_at": "2026-09-05T09:30:00+00:00",
    }
    storage = _storage(
        [row],
        [{"_id": "snapshot-metadata", "snapshot_id": "snapshot-metadata"}],
    )

    assert storage.compact_completed_prediction_outbox(
        "metadata", now="2026-09-05T10:00:00+00:00"
    )
    result = storage.database.prediction_outbox.documents["metadata"]
    for field in (
        "_id",
        "schema_version",
        "outbox_id",
        "job_id",
        "event_id",
        "session_id",
        "status",
        "snapshot_id",
        "payload_sha256",
        "attempts",
        "created_at",
        "completed_at",
    ):
        assert result[field] == row[field]
    assert result["payload_json"] == PREDICTION_OUTBOX_COMPACTED_PAYLOAD
    assert result["payload_compacted"] is True
    assert result["terminal_schema_version"] == PREDICTION_OUTBOX_TERMINAL_SCHEMA_VERSION
    assert result["payload_compacted_at"] == "2026-09-05T10:00:00+00:00"
    assert result["updated_at"] == "2026-09-05T10:00:00+00:00"
