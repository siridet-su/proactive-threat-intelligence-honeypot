from __future__ import annotations

import copy
import inspect
import json
import os
import re
import threading
import uuid
from dataclasses import replace
from functools import cmp_to_key
from pathlib import Path
from typing import Any, Mapping

import pytest

from production.storage.backend import SQLiteStorage, StorageError
from production.storage.contract import StorageBackend
from production.storage.mongodb import (
    ASCENDING,
    INDEX_DEFINITIONS,
    MONGODB_DRIVER_AVAILABLE,
    MONGODB_SCHEMA_VERSION,
    MongoStorage,
    STORAGE_LEASE_INDEX_DEFINITIONS,
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
        **kwargs: Any,
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
        **kwargs: Any,
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

    def find(self, query: Mapping[str, Any], **kwargs: Any) -> FakeCursor:
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
        **kwargs: Any,
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

    def delete_one(self, query: Mapping[str, Any], **kwargs: Any) -> FakeResult:
        for identifier, document in list(self.documents.items()):
            if _matches(document, query):
                self.documents.pop(identifier)
                return FakeResult(deleted_count=1)
        return FakeResult()


class FakeDatabase:
    def __init__(self, name: str = "honeypot_test"):
        self.name = name
        self.collections: dict[str, FakeCollection] = {}

    def __getitem__(self, name: str) -> FakeCollection:
        return self.collections.setdefault(name, FakeCollection(name))

    def command(self, name: str) -> dict[str, int]:
        assert name == "ping"
        return {"ok": 1}


class FakeSession:
    def __init__(self, lock: threading.RLock, database: FakeDatabase | None = None):
        self._lock = lock
        self._database = database
        self._snapshot: dict[str, dict[Any, dict[str, Any]]] | None = None
        self.in_transaction = False

    def __enter__(self) -> "FakeSession":
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        if self.in_transaction:
            self.abort_transaction()

    def start_transaction(self) -> None:
        self._lock.acquire()
        if self._database is not None:
            self._snapshot = {
                name: copy.deepcopy(collection.documents)
                for name, collection in self._database.collections.items()
            }
        self.in_transaction = True

    def commit_transaction(self) -> None:
        if self.in_transaction:
            self._snapshot = None
            self.in_transaction = False
            self._lock.release()

    def abort_transaction(self) -> None:
        if self.in_transaction:
            if self._database is not None and self._snapshot is not None:
                for name in set(self._database.collections) | set(self._snapshot):
                    collection = self._database[name]
                    collection.documents = copy.deepcopy(self._snapshot.get(name, {}))
            self._snapshot = None
            self.in_transaction = False
            self._lock.release()


class FakeClient:
    def __init__(self, database: FakeDatabase | None = None):
        self._transaction_lock = threading.RLock()
        self._database = database

    def start_session(self) -> FakeSession:
        return FakeSession(self._transaction_lock, self._database)


def make_storage() -> tuple[MongoStorage, FakeDatabase]:
    database = FakeDatabase()
    client = FakeClient(database)
    storage = MongoStorage(
        "mongodb://unit-test.invalid/honeypot_test",
        "honeypot_test",
        client=client,
        database=database,
    )
    storage.initialize()
    return storage, database


def store_event_at(
    storage: MongoStorage,
    database: FakeDatabase,
    *,
    session_id: str,
    received_at: str,
    sequence: int,
) -> str:
    event_id, created = storage.store_event(
        "pi-1",
        {
            "session": session_id,
            "src_ip": "192.0.2.10",
            "eventid": "cowrie.command.input",
            "input": f"command-{sequence}",
            "sequence": sequence,
        },
    )
    assert created is True
    database["events"].documents[event_id]["received_at"] = received_at
    return event_id


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

    lease_indexes = {
        (item["name"], item["keys"], item["unique"])
        for item in database["_storage_leases"].indexes
    }
    assert lease_indexes == {
        (definition.name, tuple(definition.keys), definition.unique)
        for definition in STORAGE_LEASE_INDEX_DEFINITIONS
    }

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


def test_initialization_does_not_publish_v2_metadata_before_all_indexes_exist() -> None:
    database = FakeDatabase()
    database["_storage_metadata"].replace_one(
        {"_id": "schema"},
        {
            "_id": "schema",
            "backend": "mongodb",
            "schema_version": 1,
            "updated_at": "2026-07-17T00:00:00+00:00",
        },
        upsert=True,
    )

    def fail_lease_index(*args: Any, **kwargs: Any) -> str:
        raise RuntimeError("simulated private-index failure")

    database["_storage_leases"].create_index = fail_lease_index  # type: ignore[method-assign]
    storage = MongoStorage(
        "mongodb://unit-test.invalid/honeypot_test",
        "honeypot_test",
        database=database,
    )
    with pytest.raises(StorageError, match="RuntimeError: operation_failed"):
        storage.initialize()

    assert database["_storage_metadata"].find_one({"_id": "schema"}) == {
        "_id": "schema",
        "backend": "mongodb",
        "schema_version": 1,
        "updated_at": "2026-07-17T00:00:00+00:00",
    }


def test_leader_fencing_fails_closed_without_transaction_sessions() -> None:
    database = FakeDatabase()
    storage = MongoStorage(
        "mongodb://unit-test.invalid/honeypot_test",
        "honeypot_test",
        database=database,
    )
    storage.initialize()

    with pytest.raises(
        StorageError,
        match="requires transaction-capable sessions",
    ):
        storage.acquire_worker_lease(
            "session-worker",
            "worker-a",
            str(uuid.uuid4()),
            30,
            now="2026-07-18T00:00:00+00:00",
        )


def test_fenced_transactions_retry_only_labeled_transient_errors() -> None:
    storage, _ = make_storage()
    real_start_session = storage.client.start_session
    attempts = 0

    class LabeledTransactionError(RuntimeError):
        def __init__(self, label: str):
            super().__init__("driver detail must not escape")
            self.label = label

        def has_error_label(self, label: str) -> bool:
            return label == self.label

    def transient_start_session() -> FakeSession:
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            raise LabeledTransactionError("TransientTransactionError")
        return real_start_session()

    storage.client.start_session = transient_start_session
    assert storage.acquire_worker_lease(
        "session-worker",
        "worker-a",
        str(uuid.uuid4()),
        30,
        now="2026-07-18T00:00:00+00:00",
    ) is True
    assert attempts == 3

    nontransient_attempts = 0

    def nontransient_start_session() -> FakeSession:
        nonlocal nontransient_attempts
        nontransient_attempts += 1
        raise LabeledTransactionError("NonTransientError")

    storage.client.start_session = nontransient_start_session
    with pytest.raises(StorageError) as raised:
        storage.acquire_worker_lease(
            "other-worker",
            "worker-b",
            str(uuid.uuid4()),
            30,
            now="2026-07-18T00:00:01+00:00",
        )
    assert nontransient_attempts == 1
    assert "driver detail" not in str(raised.value)


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
    assert message == "RuntimeError: operation_failed"

    query_message = _safe_error(
        RuntimeError(
            "cannot connect mongodb://alice:correct-horse@example.invalid/honeypot"
            "?token=query-secret&retry=true"
        )
    )
    assert query_message == "RuntimeError: operation_failed"

    compound_auth_message = _safe_error(
        RuntimeError(
            "cannot connect mongodb://alice:correct-horse@example.invalid/honeypot"
            "?authMechanismProperties=AWS_SESSION_TOKEN:compound-secret"
        )
    )
    assert compound_auth_message == "RuntimeError: operation_failed"


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

    first_claim = storage.claim_analysis_jobs("analysis-a", 1, 30, 3)
    second_claim = storage.claim_analysis_jobs("analysis-b", 10, 30, 3)
    assert len(first_claim) == 1
    assert len(second_claim) == 1
    assert first_claim[0]["job_id"] != second_claim[0]["job_id"]
    assert first_claim[0]["attempts"] == second_claim[0]["attempts"] == 1
    assert storage.claim_analysis_jobs("analysis-c", 10, 30, 3) == []
    assert storage.count_sessions() == 2
    assert storage.count_sessions(ended_only=True) == 1
    assert storage.count_sessions(external_only=True) == 2
    active_rows = storage.list_active_session_rows()
    assert [row["session_id"] for row in active_rows] == ["session-2"]
    assert storage.list_active_session_rows(limit=0) == []

    storage.mark_event_processed(event_id)
    assert storage.fetch_events(processed=True)[0]["processed"] is True
    processed_event = database["events"].documents[event_id]
    assert processed_event["processing_outcome"] == "succeeded"
    assert processed_event["processed_at"]
    assert processed_event["effect_summary"] is None
    assert processed_event["schema_version"] == MONGODB_SCHEMA_VERSION
    assert not {
        "claim_owner",
        "claim_token",
        "claim_expires_at",
        "next_retry_at",
        "last_error_code",
        "last_error_type",
    } & processed_event.keys()
    assert all(
        document["schema_version"] == MONGODB_SCHEMA_VERSION
        for name, collection in database.collections.items()
        if not name.startswith("_")
        for document in collection.documents.values()
    )


def test_event_claims_are_disjoint_and_use_per_event_uuid_tokens() -> None:
    storage, database = make_storage()
    first_id = store_event_at(
        storage,
        database,
        session_id="session-a",
        received_at="2026-07-18T00:00:00+00:00",
        sequence=1,
    )
    second_id = store_event_at(
        storage,
        database,
        session_id="session-b",
        received_at="2026-07-18T00:00:01+00:00",
        sequence=2,
    )

    first = storage.claim_events(
        "worker-a",
        1,
        30,
        now="2026-07-18T00:00:02+00:00",
    )
    second = storage.claim_events(
        "worker-b",
        10,
        30,
        now="2026-07-18T00:00:02+00:00",
    )

    assert [item["event_id"] for item in first] == [first_id]
    assert [item["event_id"] for item in second] == [second_id]
    tokens = {first[0]["claim_token"], second[0]["claim_token"]}
    assert len(tokens) == 2
    assert all(str(uuid.UUID(token)) == token for token in tokens)
    assert first[0]["attempts"] == second[0]["attempts"] == 1
    assert first[0]["claim_leader_scope"] == ""
    assert first[0]["claim_leader_token"] == ""
    assert storage.claim_events(
        "worker-c",
        10,
        30,
        now="2026-07-18T00:00:03+00:00",
    ) == []


def test_expired_claim_gets_new_token_and_stale_owner_cannot_mutate() -> None:
    storage, database = make_storage()
    event_id = store_event_at(
        storage,
        database,
        session_id="session-expiry",
        received_at="2026-07-18T00:00:00+00:00",
        sequence=1,
    )
    original = storage.claim_events(
        "worker-a",
        1,
        10,
        now="2026-07-18T00:00:01+00:00",
    )[0]

    replacement = storage.claim_events(
        "worker-b",
        1,
        10,
        now="2026-07-18T00:00:12+00:00",
    )[0]
    assert replacement["event_id"] == event_id
    assert replacement["attempts"] == 2
    assert replacement["claim_token"] != original["claim_token"]
    assert storage.complete_event(
        event_id,
        "worker-a",
        original["claim_token"],
        now="2026-07-18T00:00:13+00:00",
    ) is False
    assert storage.release_event_claim(
        event_id,
        "worker-a",
        original["claim_token"],
        now="2026-07-18T00:00:13+00:00",
    ) is False
    assert storage.complete_event(
        event_id,
        "worker-b",
        replacement["claim_token"],
        {"session_saved": True, "analysis_job_enqueued": True},
        now="2026-07-18T00:00:13+00:00",
    ) is True

    stored = database["events"].documents[event_id]
    assert stored["processed"] is True
    assert stored["processing_outcome"] == "succeeded"
    assert stored["effect_summary"] == {
        "session_saved": True,
        "analysis_job_enqueued": True,
    }
    assert "claim_token" not in stored


def test_retry_backoff_and_attempt_limit_produce_visible_dead_letter() -> None:
    storage, database = make_storage()
    event_id = store_event_at(
        storage,
        database,
        session_id="session-retry",
        received_at="2026-07-18T00:00:00+00:00",
        sequence=1,
    )
    first = storage.claim_events(
        "worker-a",
        1,
        10,
        max_attempts=2,
        now="2026-07-18T00:00:01+00:00",
    )[0]
    assert storage.fail_event(
        event_id,
        "worker-a",
        first["claim_token"],
        "database_unavailable",
        "StorageError",
        True,
        2,
        10,
        now="2026-07-18T00:00:02+00:00",
    ) == "retry_scheduled"
    assert storage.claim_events(
        "worker-b",
        1,
        10,
        max_attempts=2,
        now="2026-07-18T00:00:11+00:00",
    ) == []

    second = storage.claim_events(
        "worker-b",
        1,
        10,
        max_attempts=2,
        now="2026-07-18T00:00:13+00:00",
    )[0]
    assert second["attempts"] == 2
    assert storage.fail_event(
        event_id,
        "worker-b",
        second["claim_token"],
        "database_unavailable",
        "StorageError",
        True,
        2,
        10,
        now="2026-07-18T00:00:14+00:00",
    ) == "dead_letter"
    assert storage.fail_event(
        event_id,
        "worker-b",
        second["claim_token"],
        "database_unavailable",
        "StorageError",
        False,
        2,
        0,
        now="2026-07-18T00:00:14+00:00",
    ) == "stale_claim"

    failed = storage.list_failed_events()
    assert failed == [
        {
            "event_id": event_id,
            "sensor_id": "pi-1",
            "event": {
                "eventid": "cowrie.command.input",
                "input": "command-1",
                "sequence": 1,
                "session": "session-retry",
                "src_ip": "192.0.2.10",
            },
            "payload_json": json.dumps(
                {
                    "eventid": "cowrie.command.input",
                    "input": "command-1",
                    "sequence": 1,
                    "session": "session-retry",
                    "src_ip": "192.0.2.10",
                },
                sort_keys=True,
                separators=(",", ":"),
            ),
            "attempts": 2,
            "last_error_code": "database_unavailable",
            "last_error_type": "StorageError",
            "last_error_at": "2026-07-18T00:00:14+00:00",
            "processing_outcome": "dead_letter",
            "processed_at": "2026-07-18T00:00:14+00:00",
        }
    ]


def test_schema_v1_event_without_lifecycle_fields_is_claimable() -> None:
    storage, database = make_storage()
    database["events"].documents["legacy-event"] = {
        "_id": "legacy-event",
        "event_id": "legacy-event",
        "sensor_id": "legacy-sensor",
        "session_id": "legacy-session",
        "payload": {"session": "legacy-session", "eventid": "cowrie.session.connect"},
        "received_at": "2026-07-18T00:00:00+00:00",
        "processed": 0,
        "schema_version": 1,
    }

    claimed = storage.claim_events(
        "worker-a",
        1,
        30,
        now="2026-07-18T00:00:01+00:00",
    )
    assert claimed[0]["event_id"] == "legacy-event"
    assert claimed[0]["attempts"] == 1
    assert database["events"].documents["legacy-event"]["schema_version"] == 2


def test_session_head_of_line_blocks_only_its_own_session() -> None:
    storage, database = make_storage()
    head_id = store_event_at(
        storage,
        database,
        session_id="ordered-session",
        received_at="2026-07-18T00:00:00+00:00",
        sequence=1,
    )
    later_id = store_event_at(
        storage,
        database,
        session_id="ordered-session",
        received_at="2026-07-18T00:00:01+00:00",
        sequence=2,
    )
    other_id = store_event_at(
        storage,
        database,
        session_id="independent-session",
        received_at="2026-07-18T00:00:02+00:00",
        sequence=3,
    )

    first_claims = storage.claim_events(
        "worker-a",
        10,
        30,
        now="2026-07-18T00:00:03+00:00",
    )
    assert [item["event_id"] for item in first_claims] == [head_id, other_id]
    assert later_id not in {item["event_id"] for item in first_claims}
    assert storage.claim_events(
        "worker-b",
        10,
        30,
        now="2026-07-18T00:00:04+00:00",
    ) == []

    head = first_claims[0]
    assert storage.complete_event(
        head_id,
        "worker-a",
        head["claim_token"],
        now="2026-07-18T00:00:05+00:00",
    ) is True
    assert storage.claim_events(
        "worker-b",
        10,
        30,
        now="2026-07-18T00:00:06+00:00",
    )[0]["event_id"] == later_id


def test_delayed_session_head_blocks_later_event_during_backoff() -> None:
    storage, database = make_storage()
    head_id = store_event_at(
        storage,
        database,
        session_id="delayed-session",
        received_at="2026-07-18T00:00:00+00:00",
        sequence=1,
    )
    later_id = store_event_at(
        storage,
        database,
        session_id="delayed-session",
        received_at="2026-07-18T00:00:01+00:00",
        sequence=2,
    )
    other_id = store_event_at(
        storage,
        database,
        session_id="other-session",
        received_at="2026-07-18T00:00:02+00:00",
        sequence=3,
    )
    head = storage.claim_events(
        "worker-a",
        1,
        10,
        now="2026-07-18T00:00:03+00:00",
    )[0]
    assert head["event_id"] == head_id
    assert storage.fail_event(
        head_id,
        "worker-a",
        head["claim_token"],
        "temporary_failure",
        "StorageError",
        True,
        3,
        20,
        now="2026-07-18T00:00:04+00:00",
    ) == "retry_scheduled"

    during_backoff = storage.claim_events(
        "worker-b",
        10,
        10,
        now="2026-07-18T00:00:10+00:00",
    )
    assert [item["event_id"] for item in during_backoff] == [other_id]
    assert later_id not in {item["event_id"] for item in during_backoff}


def test_expired_attempt_limited_head_is_dead_lettered_and_unblocks_session() -> None:
    storage, database = make_storage()
    head_id = store_event_at(
        storage,
        database,
        session_id="attempt-limited-session",
        received_at="2026-07-18T00:00:00+00:00",
        sequence=1,
    )
    later_id = store_event_at(
        storage,
        database,
        session_id="attempt-limited-session",
        received_at="2026-07-18T00:00:01+00:00",
        sequence=2,
    )
    assert storage.claim_events(
        "worker-a",
        1,
        5,
        max_attempts=1,
        now="2026-07-18T00:00:02+00:00",
    )[0]["event_id"] == head_id

    recovered = storage.claim_events(
        "worker-b",
        1,
        5,
        max_attempts=1,
        now="2026-07-18T00:00:08+00:00",
    )
    assert [item["event_id"] for item in recovered] == [later_id]
    assert storage.list_failed_events()[0] == {
        "event_id": head_id,
        "sensor_id": "pi-1",
        "event": {
            "eventid": "cowrie.command.input",
            "input": "command-1",
            "sequence": 1,
            "session": "attempt-limited-session",
            "src_ip": "192.0.2.10",
        },
        "payload_json": json.dumps(
            {
                "eventid": "cowrie.command.input",
                "input": "command-1",
                "sequence": 1,
                "session": "attempt-limited-session",
                "src_ip": "192.0.2.10",
            },
            sort_keys=True,
            separators=(",", ":"),
        ),
        "attempts": 1,
        "last_error_code": "event_lease_attempts_exhausted",
        "last_error_type": "LeaseExpired",
        "last_error_at": "2026-07-18T00:00:08+00:00",
        "processing_outcome": "dead_letter",
        "processed_at": "2026-07-18T00:00:08+00:00",
    }


def test_non_mapping_poison_payload_is_dead_lettered_and_unblocks_session() -> None:
    storage, database = make_storage()
    poison_id = store_event_at(
        storage,
        database,
        session_id="poison-session",
        received_at="2026-07-18T00:00:00+00:00",
        sequence=1,
    )
    following_id = store_event_at(
        storage,
        database,
        session_id="poison-session",
        received_at="2026-07-18T00:00:01+00:00",
        sequence=2,
    )
    database["events"].documents[poison_id]["payload"] = [
        "attacker-secret-shaped-payload"
    ]

    claimed = storage.claim_events(
        "worker-a",
        1,
        30,
        now="2026-07-18T00:00:02+00:00",
    )
    assert [item["event_id"] for item in claimed] == [following_id]
    failed = storage.list_failed_events()
    assert failed[0]["event_id"] == poison_id
    assert failed[0]["event"] == {}
    assert failed[0]["payload_json"] == "{}"
    assert failed[0]["last_error_code"] == "event_processing_invalid"
    assert failed[0]["last_error_type"] == "ValidationError"
    assert "attacker-secret-shaped-payload" not in json.dumps(failed[0])


def test_poison_payload_scan_is_bounded_per_claim_call() -> None:
    storage, database = make_storage()
    for index in range(1001):
        event_id = f"poison-{index:04d}"
        database["events"].documents[event_id] = {
            "_id": event_id,
            "event_id": event_id,
            "sensor_id": "sensor-a",
            "session_id": f"poison-session-{index:04d}",
            "payload": ["invalid"],
            "received_at": f"2026-07-18T00:{index // 60:02d}:{index % 60:02d}+00:00",
            "processed": False,
            "attempts": 0,
            "schema_version": 1,
        }

    assert storage.claim_events(
        "worker-a",
        1,
        30,
        now="2026-07-19T00:00:00+00:00",
    ) == []
    outcomes = [
        document.get("processing_outcome")
        for document in database["events"].documents.values()
    ]
    assert outcomes.count("dead_letter") == 1000
    assert outcomes.count(None) == 1


def test_worker_lease_takeover_and_event_leader_fencing() -> None:
    storage, database = make_storage()
    leader_a = str(uuid.uuid4())
    leader_b = str(uuid.uuid4())
    assert storage.acquire_worker_lease(
        "session-worker",
        "worker-a",
        leader_a,
        5,
        now="2026-07-18T00:00:00+00:00",
    ) is True
    assert storage.acquire_worker_lease(
        "session-worker",
        "worker-b",
        leader_b,
        30,
        now="2026-07-18T00:00:01+00:00",
    ) is False

    event_id = store_event_at(
        storage,
        database,
        session_id="leader-session",
        received_at="2026-07-18T00:00:00+00:00",
        sequence=1,
    )
    exhausted_id = store_event_at(
        storage,
        database,
        session_id="exhausted-leader-session",
        received_at="2026-07-17T23:59:59+00:00",
        sequence=2,
    )
    database["events"].documents[exhausted_id]["attempts"] = 5
    assert storage.claim_events(
        "worker-a",
        1,
        10,
        now="2026-07-18T00:00:01+00:00",
        leader_scope="session-worker",
        leader_token=leader_a,
    ) == []
    assert database["events"].documents[event_id]["attempts"] == 0
    assert database["events"].documents[exhausted_id]["processed"] is False

    assert storage.renew_worker_lease(
        "session-worker",
        "worker-a",
        leader_a,
        30,
        now="2026-07-18T00:00:01+00:00",
    ) is True
    claim = storage.claim_events(
        "worker-a",
        1,
        10,
        now="2026-07-18T00:00:01+00:00",
        leader_scope="session-worker",
        leader_token=leader_a,
    )[0]
    assert database["events"].documents[exhausted_id]["processing_outcome"] == "dead_letter"
    assert storage.renew_event_claim(
        event_id,
        "worker-a",
        claim["claim_token"],
        30,
        now="2026-07-18T00:00:05+00:00",
        leader_scope="session-worker",
        leader_token=leader_a,
    ) is False
    assert storage.renew_worker_lease(
        "session-worker",
        "worker-a",
        leader_a,
        60,
        now="2026-07-18T00:00:05+00:00",
    ) is True
    assert storage.renew_event_claim(
        event_id,
        "worker-a",
        claim["claim_token"],
        30,
        now="2026-07-18T00:00:05+00:00",
        leader_scope="session-worker",
        leader_token=leader_a,
    ) is True

    assert storage.acquire_worker_lease(
        "session-worker",
        "worker-b",
        leader_b,
        30,
        now="2026-07-18T00:01:06+00:00",
    ) is True
    assert storage.renew_worker_lease(
        "session-worker",
        "worker-a",
        leader_a,
        10,
        now="2026-07-18T00:01:06+00:00",
    ) is False
    assert storage.release_worker_lease(
        "session-worker",
        "worker-a",
        leader_a,
        now="2026-07-18T00:01:06+00:00",
    ) is False
    assert storage.release_worker_lease(
        "session-worker",
        "worker-b",
        leader_b,
        now="2026-07-18T00:01:07+00:00",
    ) is True


def test_worker_lease_placeholder_duplicate_key_race_is_idempotent() -> None:
    storage, database = make_storage()
    collection = database["_storage_leases"]
    original_update_one = collection.update_one
    raced = False

    class DuplicateKeyError(RuntimeError):
        pass

    def racing_update_one(
        query: Mapping[str, Any],
        update: Mapping[str, Any],
        upsert: bool = False,
    ) -> FakeResult:
        nonlocal raced
        if upsert and not raced:
            raced = True
            original_update_one(query, update, upsert=True)
            raise DuplicateKeyError("simulated concurrent placeholder insert")
        return original_update_one(query, update, upsert=upsert)

    collection.update_one = racing_update_one  # type: ignore[method-assign]
    token = str(uuid.uuid4())
    assert storage.acquire_worker_lease(
        "session-worker",
        "worker-a",
        token,
        30,
        now="2026-07-18T00:00:00+00:00",
    ) is True
    assert collection.find_one({"_id": "session-worker"})["token"] == token

    missing_storage, missing_database = make_storage()

    def duplicate_without_winner(
        query: Mapping[str, Any],
        update: Mapping[str, Any],
        upsert: bool = False,
    ) -> FakeResult:
        raise DuplicateKeyError("no competing scope document exists")

    missing_database["_storage_leases"].update_one = (  # type: ignore[method-assign]
        duplicate_without_winner
    )
    with pytest.raises(DuplicateKeyError, match="no competing scope"):
        missing_storage.acquire_worker_lease(
            "missing-scope",
            "worker-a",
            str(uuid.uuid4()),
            30,
            now="2026-07-18T00:00:00+00:00",
        )


def test_early_leader_release_fences_terminal_writes_and_delays_takeover() -> None:
    storage, database = make_storage()
    leader_a = str(uuid.uuid4())
    leader_b = str(uuid.uuid4())
    assert storage.acquire_worker_lease(
        "session-worker",
        "worker-a",
        leader_a,
        30,
        now="2026-07-18T00:00:00+00:00",
    )
    event_id = store_event_at(
        storage,
        database,
        session_id="early-release-session",
        received_at="2026-07-18T00:00:00+00:00",
        sequence=1,
    )
    claim = storage.claim_events(
        "worker-a",
        1,
        10,
        now="2026-07-18T00:00:01+00:00",
        leader_scope="session-worker",
        leader_token=leader_a,
    )[0]
    assert storage.release_worker_lease(
        "session-worker",
        "worker-a",
        leader_a,
        now="2026-07-18T00:00:02+00:00",
    )

    terminal_kwargs = {
        "now": "2026-07-18T00:00:03+00:00",
        "leader_scope": "session-worker",
        "leader_token": leader_a,
    }
    assert storage.complete_event(
        event_id,
        "worker-a",
        claim["claim_token"],
        **terminal_kwargs,
    ) is False
    assert storage.fail_event(
        event_id,
        "worker-a",
        claim["claim_token"],
        "temporary_failure",
        "StorageError",
        True,
        3,
        0,
        **terminal_kwargs,
    ) == "stale_claim"
    assert storage.release_event_claim(
        event_id,
        "worker-a",
        claim["claim_token"],
        **terminal_kwargs,
    ) is False
    assert database["events"].documents[event_id]["processed"] is False
    assert storage.acquire_worker_lease(
        "session-worker",
        "worker-b",
        leader_b,
        30,
        now="2026-07-18T00:00:03+00:00",
    ) is False

    # At the event-claim boundary, the stale worker is fenced by its expired
    # token and the standby may safely become leader and reclaim the event.
    assert storage.acquire_worker_lease(
        "session-worker",
        "worker-b",
        leader_b,
        30,
        now="2026-07-18T00:00:11+00:00",
    ) is True
    replacement = storage.claim_events(
        "worker-b",
        1,
        10,
        now="2026-07-18T00:00:11+00:00",
        leader_scope="session-worker",
        leader_token=leader_b,
    )[0]
    assert replacement["event_id"] == event_id
    assert replacement["claim_token"] != claim["claim_token"]


def test_transaction_serializes_takeover_at_terminal_write_seam() -> None:
    storage, database = make_storage()
    leader_a = str(uuid.uuid4())
    leader_b = str(uuid.uuid4())
    assert storage.acquire_worker_lease(
        "session-worker",
        "worker-a",
        leader_a,
        60,
        now="2026-07-18T00:00:00+00:00",
    )
    event_id = store_event_at(
        storage,
        database,
        session_id="transaction-race",
        received_at="2026-07-18T00:00:00+00:00",
        sequence=1,
    )
    claim = storage.claim_events(
        "worker-a",
        1,
        30,
        now="2026-07-18T00:00:01+00:00",
        leader_scope="session-worker",
        leader_token=leader_a,
    )[0]

    at_old_seam = threading.Event()
    takeover_started = threading.Event()
    allow_terminal_write = threading.Event()
    original_update_one = database["events"].update_one

    def instrumented_update_one(
        query: Mapping[str, Any],
        update: Mapping[str, Any],
        upsert: bool = False,
        **kwargs: Any,
    ) -> FakeResult:
        set_values = update.get("$set", {})
        if set_values.get("processing_outcome") == "succeeded":
            at_old_seam.set()
            assert allow_terminal_write.wait(timeout=5)
        return original_update_one(query, update, upsert=upsert, **kwargs)

    database["events"].update_one = instrumented_update_one  # type: ignore[method-assign]
    results: dict[str, Any] = {}
    completion_order: list[str] = []

    def finish_event() -> None:
        results["terminal"] = storage.complete_event(
            event_id,
            "worker-a",
            claim["claim_token"],
            {"event_applied": True},
            now="2026-07-18T00:00:02+00:00",
            leader_scope="session-worker",
            leader_token=leader_a,
        )
        completion_order.append("terminal")

    def take_over() -> None:
        assert at_old_seam.wait(timeout=5)
        takeover_started.set()
        results["released"] = storage.release_worker_lease(
            "session-worker",
            "worker-a",
            leader_a,
            now="2026-07-18T00:00:02+00:00",
        )
        results["takeover"] = storage.acquire_worker_lease(
            "session-worker",
            "worker-b",
            leader_b,
            30,
            now="2026-07-18T00:00:02+00:00",
        )
        completion_order.append("takeover")

    terminal_thread = threading.Thread(target=finish_event)
    takeover_thread = threading.Thread(target=take_over)
    terminal_thread.start()
    takeover_thread.start()
    assert at_old_seam.wait(timeout=5)
    assert takeover_started.wait(timeout=5)
    # The standby has started but cannot pass the transaction-held lease
    # fence and mutate leadership before the terminal event write.
    assert takeover_thread.is_alive()
    allow_terminal_write.set()
    terminal_thread.join(timeout=5)
    takeover_thread.join(timeout=5)
    assert not terminal_thread.is_alive()
    assert not takeover_thread.is_alive()
    assert results == {"terminal": True, "released": True, "takeover": True}
    assert completion_order == ["terminal", "takeover"]
    assert database["events"].documents[event_id]["processed"] is True


def test_transaction_serializes_takeover_at_event_claim_write_seam() -> None:
    storage, database = make_storage()
    leader_a = str(uuid.uuid4())
    leader_b = str(uuid.uuid4())
    assert storage.acquire_worker_lease(
        "session-worker",
        "worker-a",
        leader_a,
        60,
        now="2026-07-18T00:00:00+00:00",
    )
    event_id = store_event_at(
        storage,
        database,
        session_id="claim-transaction-race",
        received_at="2026-07-18T00:00:00+00:00",
        sequence=1,
    )

    at_old_seam = threading.Event()
    takeover_started = threading.Event()
    allow_claim_write = threading.Event()
    original_find_one_and_update = database["events"].find_one_and_update

    def instrumented_find_one_and_update(
        query: Mapping[str, Any],
        update: Mapping[str, Any],
        **kwargs: Any,
    ) -> dict[str, Any] | None:
        if update.get("$set", {}).get("claim_owner") == "worker-a":
            at_old_seam.set()
            assert allow_claim_write.wait(timeout=5)
        return original_find_one_and_update(query, update, **kwargs)

    database["events"].find_one_and_update = (  # type: ignore[method-assign]
        instrumented_find_one_and_update
    )
    results: dict[str, Any] = {}
    completion_order: list[str] = []

    def claim_event() -> None:
        results["claims"] = storage.claim_events(
            "worker-a",
            1,
            30,
            now="2026-07-18T00:00:01+00:00",
            leader_scope="session-worker",
            leader_token=leader_a,
        )
        completion_order.append("claim")

    def take_over() -> None:
        assert at_old_seam.wait(timeout=5)
        takeover_started.set()
        results["released"] = storage.release_worker_lease(
            "session-worker",
            "worker-a",
            leader_a,
            now="2026-07-18T00:00:01+00:00",
        )
        results["takeover"] = storage.acquire_worker_lease(
            "session-worker",
            "worker-b",
            leader_b,
            30,
            now="2026-07-18T00:00:01+00:00",
        )
        completion_order.append("takeover")

    claim_thread = threading.Thread(target=claim_event)
    takeover_thread = threading.Thread(target=take_over)
    claim_thread.start()
    takeover_thread.start()
    assert at_old_seam.wait(timeout=5)
    assert takeover_started.wait(timeout=5)
    assert takeover_thread.is_alive()
    allow_claim_write.set()
    claim_thread.join(timeout=5)
    takeover_thread.join(timeout=5)
    assert not claim_thread.is_alive()
    assert not takeover_thread.is_alive()
    assert [item["event_id"] for item in results["claims"]] == [event_id]
    assert results["released"] is True
    assert results["takeover"] is False
    assert completion_order == ["claim", "takeover"]
    stored = database["events"].documents[event_id]
    assert stored["claim_owner"] == "worker-a"
    assert stored["claim_leader_token"] == leader_a


def test_stored_leader_binding_cannot_be_bypassed_by_omitting_context() -> None:
    storage, database = make_storage()
    leader_token = str(uuid.uuid4())
    assert storage.acquire_worker_lease(
        "session-worker",
        "worker-a",
        leader_token,
        60,
        now="2026-07-18T00:00:00+00:00",
    )
    event_id = store_event_at(
        storage,
        database,
        session_id="bound-session",
        received_at="2026-07-18T00:00:00+00:00",
        sequence=1,
    )
    claim = storage.claim_events(
        "worker-a",
        1,
        30,
        now="2026-07-18T00:00:01+00:00",
        leader_scope="session-worker",
        leader_token=leader_token,
    )[0]
    assert claim["claim_leader_scope"] == "session-worker"
    assert claim["claim_leader_token"] == leader_token
    stored = database["events"].documents[event_id]
    assert stored["claim_leader_scope"] == "session-worker"
    assert stored["claim_leader_token"] == leader_token

    assert storage.renew_event_claim(
        event_id,
        "worker-a",
        claim["claim_token"],
        20,
        now="2026-07-18T00:00:02+00:00",
    ) is False
    assert storage.complete_event(
        event_id,
        "worker-a",
        claim["claim_token"],
        now="2026-07-18T00:00:02+00:00",
    ) is False
    assert storage.fail_event(
        event_id,
        "worker-a",
        claim["claim_token"],
        "temporary_failure",
        "StorageError",
        True,
        3,
        0,
        now="2026-07-18T00:00:02+00:00",
    ) == "stale_claim"
    assert storage.release_event_claim(
        event_id,
        "worker-a",
        claim["claim_token"],
        now="2026-07-18T00:00:02+00:00",
    ) is False
    assert stored["processed"] is False
    assert stored["claim_leader_token"] == leader_token

    assert storage.complete_event(
        event_id,
        "worker-a",
        claim["claim_token"],
        {"event_applied": True},
        now="2026-07-18T00:00:03+00:00",
        leader_scope="session-worker",
        leader_token=leader_token,
    ) is True
    assert not {
        "claim_owner",
        "claim_token",
        "claim_expires_at",
        "claim_leader_scope",
        "claim_leader_token",
    } & stored.keys()


def test_unbound_claim_rejects_supplied_leader_context_without_retrofit() -> None:
    storage, database = make_storage()
    event_id = store_event_at(
        storage,
        database,
        session_id="unbound-session",
        received_at="2026-07-18T00:00:00+00:00",
        sequence=1,
    )
    claim = storage.claim_events(
        "worker-a",
        1,
        30,
        now="2026-07-18T00:00:01+00:00",
    )[0]
    leader_token = str(uuid.uuid4())
    assert storage.acquire_worker_lease(
        "session-worker",
        "worker-a",
        leader_token,
        60,
        now="2026-07-18T00:00:01+00:00",
    )

    assert storage.renew_event_claim(
        event_id,
        "worker-a",
        claim["claim_token"],
        20,
        now="2026-07-18T00:00:02+00:00",
        leader_scope="session-worker",
        leader_token=leader_token,
    ) is False
    assert storage.complete_event(
        event_id,
        "worker-a",
        claim["claim_token"],
        now="2026-07-18T00:00:02+00:00",
        leader_scope="session-worker",
        leader_token=leader_token,
    ) is False
    stored = database["events"].documents[event_id]
    assert "claim_leader_scope" not in stored
    assert "claim_leader_token" not in stored
    assert storage.complete_event(
        event_id,
        "worker-a",
        claim["claim_token"],
        {"event_applied": True},
        now="2026-07-18T00:00:03+00:00",
    ) is True


def test_leader_takeover_guard_is_scope_and_token_specific() -> None:
    storage, database = make_storage()
    old_token = str(uuid.uuid4())
    same_owner_new_token = str(uuid.uuid4())
    other_owner_token = str(uuid.uuid4())
    unrelated_token = str(uuid.uuid4())
    assert storage.acquire_worker_lease(
        "scope-a",
        "worker-a",
        old_token,
        60,
        now="2026-07-18T00:00:00+00:00",
    )
    event_id = store_event_at(
        storage,
        database,
        session_id="scope-session",
        received_at="2026-07-18T00:00:00+00:00",
        sequence=1,
    )
    claim = storage.claim_events(
        "worker-a",
        1,
        10,
        now="2026-07-18T00:00:01+00:00",
        leader_scope="scope-a",
        leader_token=old_token,
    )[0]
    assert storage.release_worker_lease(
        "scope-a",
        "worker-a",
        old_token,
        now="2026-07-18T00:00:02+00:00",
    )

    assert storage.acquire_worker_lease(
        "scope-b",
        "worker-b",
        unrelated_token,
        30,
        now="2026-07-18T00:00:03+00:00",
    ) is True
    assert storage.acquire_worker_lease(
        "scope-a",
        "worker-a",
        same_owner_new_token,
        30,
        now="2026-07-18T00:00:03+00:00",
    ) is False
    assert storage.acquire_worker_lease(
        "scope-a",
        "worker-b",
        other_owner_token,
        30,
        now="2026-07-18T00:00:03+00:00",
    ) is False
    assert database["events"].documents[event_id]["claim_leader_token"] == old_token

    assert storage.acquire_worker_lease(
        "scope-a",
        "worker-a",
        same_owner_new_token,
        30,
        now="2026-07-18T00:00:11+00:00",
    ) is True
    replacement = storage.claim_events(
        "worker-a",
        1,
        10,
        now="2026-07-18T00:00:11+00:00",
        leader_scope="scope-a",
        leader_token=same_owner_new_token,
    )[0]
    assert replacement["claim_token"] != claim["claim_token"]
    rebound = database["events"].documents[event_id]
    assert rebound["claim_leader_token"] == same_owner_new_token
    assert storage.release_event_claim(
        event_id,
        "worker-a",
        replacement["claim_token"],
        now="2026-07-18T00:00:12+00:00",
        leader_scope="scope-a",
        leader_token=same_owner_new_token,
    ) is True
    assert "claim_leader_scope" not in rebound
    assert "claim_leader_token" not in rebound


def test_event_fencing_rejects_non_uuid_tokens_and_unpaired_leader_fields() -> None:
    storage, database = make_storage()
    event_id = store_event_at(
        storage,
        database,
        session_id="validation-session",
        received_at="2026-07-18T00:00:00+00:00",
        sequence=1,
    )
    claim = storage.claim_events(
        "worker-a",
        1,
        10,
        now="2026-07-18T00:00:01+00:00",
    )[0]
    with pytest.raises(ValueError, match="UUID fencing token"):
        storage.complete_event(
            event_id,
            "worker-a",
            "not-a-uuid",
            now="2026-07-18T00:00:02+00:00",
        )
    with pytest.raises(ValueError, match="provided together"):
        storage.renew_event_claim(
            event_id,
            "worker-a",
            claim["claim_token"],
            10,
            now="2026-07-18T00:00:02+00:00",
            leader_scope="session-worker",
        )
    with pytest.raises(ValueError, match="provided together"):
        storage.complete_event(
            event_id,
            "worker-a",
            claim["claim_token"],
            now="2026-07-18T00:00:02+00:00",
            leader_scope="session-worker",
        )
    with pytest.raises(ValueError, match="provided together"):
        storage.fail_event(
            event_id,
            "worker-a",
            claim["claim_token"],
            "temporary_failure",
            "StorageError",
            True,
            3,
            0,
            now="2026-07-18T00:00:02+00:00",
            leader_token=str(uuid.uuid4()),
        )
    with pytest.raises(ValueError, match="provided together"):
        storage.release_event_claim(
            event_id,
            "worker-a",
            claim["claim_token"],
            now="2026-07-18T00:00:02+00:00",
            leader_scope="session-worker",
        )
    with pytest.raises(ValueError, match="positive number"):
        storage.claim_events(
            "worker-b",
            1,
            float("nan"),
            now="2026-07-18T00:00:02+00:00",
        )
    with pytest.raises(ValueError, match="positive number"):
        storage.acquire_worker_lease(
            "session-worker",
            "worker-a",
            str(uuid.uuid4()),
            float("inf"),
            now="2026-07-18T00:00:02+00:00",
        )
    with pytest.raises(ValueError, match="non-negative number"):
        storage.fail_event(
            event_id,
            "worker-a",
            claim["claim_token"],
            "temporary_failure",
            "StorageError",
            True,
            3,
            float("nan"),
            now="2026-07-18T00:00:02+00:00",
        )
    with pytest.raises(ValueError, match="registered event failure code"):
        storage.fail_event(
            event_id,
            "worker-a",
            claim["claim_token"],
            "correcthorsebatterystaple",
            "StorageError",
            False,
            3,
            0,
            now="2026-07-18T00:00:02+00:00",
        )
    with pytest.raises(ValueError, match="mapping or null"):
        storage.complete_event(
            event_id,
            "worker-a",
            claim["claim_token"],
            "session saved",  # type: ignore[arg-type]
            now="2026-07-18T00:00:02+00:00",
        )
    with pytest.raises(ValueError, match="unsupported key"):
        storage.complete_event(
            event_id,
            "worker-a",
            claim["claim_token"],
            {"attacker_secret": True},
            now="2026-07-18T00:00:02+00:00",
        )
    with pytest.raises(ValueError, match="booleans or bounded"):
        storage.complete_event(
            event_id,
            "worker-a",
            claim["claim_token"],
            {"session_saved": {"nested": True}},  # type: ignore[dict-item]
            now="2026-07-18T00:00:02+00:00",
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
    claimed = storage.claim_enrichment_jobs("enrichment-a", 2, 30, 3)
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


def test_webhook_per_target_lease_recovery_and_stale_completion_parity() -> None:
    storage, _ = make_storage()
    alert_id = storage.store_alert(
        {
            "alert_id": "mongo-webhook-alert",
            "session_id": "mongo-webhook-session",
            "severity": "HIGH",
        }
    )
    target_a = "a" * 64
    target_b = "b" * 64
    payload = {
        "type": "alert",
        "idempotency_key": "delivery-mongo-webhook",
    }
    assert [
        row["alert_id"]
        for row in storage.pending_webhooks(
            target_url_hash=target_a,
            max_attempts=3,
            now="2026-07-19T00:00:00+00:00",
        )
    ] == [alert_id]

    first = storage.claim_webhook_delivery(
        payload,
        target_a,
        "worker-a",
        60,
        3,
        alert_id=alert_id,
        now="2026-07-19T00:00:00+00:00",
    )
    assert first is not None
    assert first["attempts"] == 1
    assert storage.claim_webhook_delivery(
        payload,
        target_a,
        "worker-b",
        60,
        3,
        alert_id=alert_id,
        now="2026-07-19T00:00:30+00:00",
    ) is None
    assert storage.pending_webhooks(
        target_url_hash=target_a,
        max_attempts=3,
        now="2026-07-19T00:00:30+00:00",
    ) == []
    assert storage.pending_webhooks(
        target_url_hash=target_b,
        max_attempts=3,
        now="2026-07-19T00:00:30+00:00",
    )

    recovered = storage.claim_webhook_delivery(
        payload,
        target_a,
        "worker-b",
        60,
        3,
        alert_id=alert_id,
        now="2026-07-19T00:01:01+00:00",
    )
    assert recovered is not None
    assert recovered["delivery_id"] == first["delivery_id"]
    assert recovered["attempts"] == 2
    assert storage.complete_webhook_delivery(
        first["delivery_id"],
        "worker-a",
        first["claim_token"],
        "delivered",
        now="2026-07-19T00:01:01+00:00",
    ) is False
    assert storage.complete_webhook_delivery(
        recovered["delivery_id"],
        "worker-b",
        recovered["claim_token"],
        "delivered",
        response_status=204,
        now="2026-07-19T00:01:01+00:00",
    ) is True
    assert storage.pending_webhooks(
        target_url_hash=target_a,
        max_attempts=3,
        now="2026-07-19T00:01:01+00:00",
    ) == []


def test_webhook_mongodb_indexes_include_target_claim_state() -> None:
    _storage, database = make_storage()
    definitions = {
        index["name"]: index["keys"]
        for index in database["webhook_deliveries"].indexes
    }
    assert definitions["idx_webhook_target_claimable"] == (
        ("target_url_hash", ASCENDING),
        ("status", ASCENDING),
        ("next_retry_at", ASCENDING),
        ("claim_expires_at", ASCENDING),
        ("updated_at", ASCENDING),
    )


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
    claim = storage.claim_analysis_jobs("analysis-a", 1, 30, 3)[0]
    assert claim["job_id"] == job_id
    report_id = storage.complete_analysis_job(
        job_id,
        claim["claim_owner"],
        claim["claim_token"],
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
        claim = storage.claim_events("real-worker", 1, 30)
        assert claim[0]["event_id"] == event_id
        assert storage.complete_event(
            event_id,
            "real-worker",
            claim[0]["claim_token"],
            {"event_applied": True},
        ) is True

        leader_token = str(uuid.uuid4())
        assert storage.acquire_worker_lease(
            "real-session-worker",
            "real-worker",
            leader_token,
            60,
        ) is True
        second_event_id, second_created = storage.store_event(
            "integration-sensor",
            {
                "session": "real-integration-session-2",
                "src_ip": "192.0.2.11",
                "eventid": "cowrie.session.connect",
            },
        )
        assert second_created is True
        fenced = storage.claim_events(
            "real-worker",
            1,
            30,
            leader_scope="real-session-worker",
            leader_token=leader_token,
        )
        assert fenced[0]["event_id"] == second_event_id
        for table, definitions in INDEX_DEFINITIONS.items():
            index_information = storage.database[table].index_information()
            for definition in definitions:
                assert definition.name in index_information
                assert bool(index_information[definition.name].get("unique", False)) is definition.unique
        lease_index_information = storage.database["_storage_leases"].index_information()
        for definition in STORAGE_LEASE_INDEX_DEFINITIONS:
            assert definition.name in lease_index_information
            assert bool(
                lease_index_information[definition.name].get("unique", False)
            ) is definition.unique
    finally:
        if storage is not None:
            # The name is generated in this test and cannot refer to a
            # pre-existing database supplied by the URI.
            storage.client.drop_database(database_name)
