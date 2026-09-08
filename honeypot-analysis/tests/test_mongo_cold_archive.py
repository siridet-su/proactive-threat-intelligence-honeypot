from __future__ import annotations

import json
from datetime import datetime, timezone
from functools import cmp_to_key
from pathlib import Path
from typing import Any, Mapping

import pytest

from production.archive.cold_archive import (
    ArchiveCapacityError,
    ArchiveIDConflict,
    ArchivePrivacyError,
    ArchiveSpec,
    ArchiveVerificationError,
    PurgeSafetyError,
    archive_paths,
    build_archive_id,
    canonical_ejson_dumps,
    canonical_ejson_loads,
    compare_index_policy,
    create_purge_candidate,
    export_archive,
    pi_capacity_gate,
    plan_archive,
    read_archive_verified,
    redacted_uri_metadata,
    validate_purge_candidate,
    verify_archive_file,
)
from production.archive.purge import (
    PILOT_AUTHORIZED_MAX,
    _append_progress,
    _self_hash,
    _records_digest,
    build_exact_delete_filter,
    execute_exact_purge,
    identity_set_sha256,
    validate_frozen_purge_set,
)
from production.archive.policy import (
    LIFECYCLE_CLASSES,
    lifecycle_gate,
    validate_archive_lifecycle_policy,
)


def test_uri_metadata_never_contains_credential_material() -> None:
    metadata = redacted_uri_metadata(
        "mongodb+srv://user:password@example.mongodb.net/honeypot_db?retryWrites=true"
    )
    assert metadata == {
        "scheme": "mongodb+srv",
        "host": "example.mongodb.net",
        "database": "honeypot_db",
        "credential_exposed": False,
    }
    assert "user" not in json.dumps(metadata)
    assert "password" not in json.dumps(metadata)


def test_pi_capacity_gate_fails_closed_below_reserve() -> None:
    with pytest.raises(ArchiveCapacityError):
        pi_capacity_gate(
            {"total_bytes": 1000, "used_bytes": 500, "free_bytes": 500},
            100,
            reserve_bytes=450,
            max_used_ratio=0.90,
        )


def test_purge_candidate_requires_verified_manifest() -> None:
    with pytest.raises(PurgeSafetyError, match="VERIFIED"):
        create_purge_candidate({"archive_status": "PENDING"})


def test_purge_guard_rejects_target_mismatch_and_missing_confirmation() -> None:
    manifest = {
        "archive_status": "VERIFIED",
        "archive_id": "mongoarc_test",
        "source_target": {
            "project_id": "project",
            "cluster_id": "cluster",
            "cluster_name": "cluster-name",
            "srv_hostname": "cluster.mongodb.net",
            "database": "legacy",
            "collection": "hardware_metrics",
            "storage_epoch": "legacy",
        },
        "query_predicate": {},
        "sort": [["timestamp", 1]],
        "limit": None,
        "first_sort_key": {},
        "last_sort_key": {},
        "first_document_id": {"$oid": "000000000000000000000001"},
        "last_document_id": {"$oid": "000000000000000000000002"},
        "selected_count": 2,
        "records_sha256": "a" * 64,
    }
    candidate = create_purge_candidate(manifest)
    with pytest.raises(PurgeSafetyError, match="target"):
        validate_purge_candidate(
            candidate,
            manifest,
            target={**manifest["source_target"], "database": "other"},
            current_source_count=2,
            explicit_confirmation=True,
        )
    with pytest.raises(PurgeSafetyError, match="confirmation"):
        validate_purge_candidate(
            candidate,
            manifest,
            target=manifest["source_target"],
            current_source_count=2,
            explicit_confirmation=False,
        )


def test_lifecycle_policy_requires_explicit_terminal_state_and_unset_default_window() -> None:
    policy = {
        "schema_version": "mongo_pi_archive_lifecycle_policy.v1",
        "capacity_thresholds": {"warning": 0.7, "critical": 0.8, "emergency": 0.9},
        "default_hot_window_days": None,
        "collections": {
            "sessions": {
                "classification": "ARCHIVE_ELIGIBLE_HISTORICAL",
                "archive_eligible": True,
                "purge_eligible": False,
                "reconstructable": False,
                "required_terminal_fields": ["session_finalized", "analysis_complete"],
                "dependencies": ["events", "reports"],
            }
        },
    }
    validate_archive_lifecycle_policy(policy)
    assert LIFECYCLE_CLASSES
    assert lifecycle_gate(policy, "sessions", {"session_finalized": True})["eligible"] is False
    assert lifecycle_gate(
        policy,
        "sessions",
        {"session_finalized": True, "analysis_complete": True},
    )["eligible"] is True


def test_operational_policy_refuses_age_only_archive() -> None:
    policy = {
        "schema_version": "mongo_pi_archive_lifecycle_policy.v1",
        "capacity_thresholds": {"warning": 0.7, "critical": 0.8, "emergency": 0.9},
        "default_hot_window_days": None,
        "collections": {
            "worker_leases": {
                "classification": "HOT_OPERATIONAL_STATE",
                "archive_eligible": False,
                "purge_eligible": False,
                "reconstructable": True,
                "required_terminal_fields": [],
                "dependencies": [],
            }
        },
    }
    assert lifecycle_gate(policy, "worker_leases", {})["eligible"] is False


def test_index_policy_reports_unexpected_ttl_without_mutating() -> None:
    result = compare_index_policy(
        {"events": [{"name": "expires_at_1", "key": [["expires_at", 1]], "expireAfterSeconds": 0}]},
        expected={"events": [{"name": "_id_", "key": [["_id", 1]]}]},
    )
    assert result["status"] == "DISCREPANCY"
    assert len(result["unexpected_ttl_indexes"]) == 1
    assert result["mutations_performed"] is False
class _Cursor:
    def __init__(self, documents: list[dict[str, Any]]) -> None:
        self.documents = documents

    def sort(self, fields: list[list[Any]]) -> "_Cursor":
        def compare(left: Mapping[str, Any], right: Mapping[str, Any]) -> int:
            for field, direction in fields:
                left_value = left[field]
                right_value = right[field]
                if left_value == right_value:
                    continue
                result = -1 if left_value < right_value else 1
                return result if direction == 1 else -result
            return 0

        self.documents.sort(key=cmp_to_key(compare))
        return self

    def limit(self, amount: int) -> "_Cursor":
        self.documents = self.documents[:amount]
        return self

    def __iter__(self):
        return iter(self.documents)


class _Collection:
    name = "hardware_metrics"

    def __init__(self, documents: list[dict[str, Any]]) -> None:
        self.documents = documents
        self.count_calls = 0

    @staticmethod
    def _matches(document: Mapping[str, Any], query: Mapping[str, Any]) -> bool:
        for field, condition in query.items():
            value = document[field]
            for operator, expected in condition.items():
                if operator == "$gte" and not value >= expected:
                    return False
                if operator == "$lt" and not value < expected:
                    return False
        return True

    def count_documents(self, query: Mapping[str, Any]) -> int:
        self.count_calls += 1
        return sum(self._matches(document, query) for document in self.documents)

    def find(self, query: Mapping[str, Any]) -> _Cursor:
        return _Cursor([
            dict(document)
            for document in self.documents
            if self._matches(document, query)
        ])


def _spec(query: Mapping[str, Any] | None = None) -> ArchiveSpec:
    start = datetime(2026, 8, 15, 6, 42, 17, tzinfo=timezone.utc)
    end = datetime(2026, 8, 15, 6, 50, tzinfo=timezone.utc)
    return ArchiveSpec(
        project_id="project-id",
        cluster_id="cluster-id",
        cluster_name="Honeypot-DB",
        srv_hostname="honeypot-db.mongodb.net",
        database="honeypot_db",
        collection="hardware_metrics",
        query=query or {
            "timestamp": {
                "$gte": start,
                "$lt": end,
            }
        },
        sort=(("timestamp", 1), ("_id", 1)),
        limit=None,
        provenance="LEGACY_TARGET_A_ARCHIVE_PILOT",
        schema_info={"status": "LEGACY_TARGET_A_SOURCE_SCHEMA_UNVERSIONED"},
    )


def _documents() -> list[dict[str, Any]]:
    bson = pytest.importorskip("bson")
    return [
        {
            "_id": bson.ObjectId("000000000000000000000002"),
            "timestamp": datetime(2026, 8, 15, 6, 44, tzinfo=timezone.utc),
            "metric": bson.int64.Int64(2),
            "nested": {"binary": bson.binary.Binary(b"two")},
            "values": [2, True],
        },
        {
            "_id": bson.ObjectId("000000000000000000000001"),
            "timestamp": datetime(2026, 8, 15, 6, 43, tzinfo=timezone.utc),
            "metric": bson.int64.Int64(1),
            "nested": {"binary": bson.binary.Binary(b"one")},
            "values": [1, False],
        },
    ]


def test_canonical_bson_extended_json_round_trip() -> None:
    bson = pytest.importorskip("bson")
    value = {
        "_id": bson.ObjectId("000000000000000000000001"),
        "when": datetime(2026, 8, 15, 6, 43, tzinfo=timezone.utc),
        "int32": 7,
        "int64": bson.int64.Int64(8),
        "binary": bson.binary.Binary(b"payload"),
        "nested": [{"value": bson.Decimal128("1.20")}],
    }
    encoded = canonical_ejson_dumps(value)
    decoded = canonical_ejson_loads(encoded)
    assert canonical_ejson_dumps(decoded) == encoded
    assert '"$oid":"000000000000000000000001"' in encoded
    assert '"$binary"' in encoded
    assert '"$numberInt":"7"' in encoded
    assert '"$numberLong":"8"' in encoded


def test_export_verify_restore_and_idempotency(tmp_path: Path) -> None:
    documents = _documents()
    collection = _Collection(documents)
    spec = _spec()
    plan = plan_archive(collection, spec)
    assert plan.selected_count == 2
    result = export_archive(collection, spec, tmp_path, plan=plan)
    assert result["status"] == "VERIFIED"
    assert result["manifest"]["selected_count"] == 2
    assert result["manifest"]["source_match_count_before"] == 2
    assert result["manifest"]["source_match_count_after"] == 2
    assert result["manifest"]["serialization"] == "canonical_extended_json_one_document_per_line"
    assert result["manifest"]["compression"] == "zstd"
    assert result["catalog_added"] is True
    assert result["manifest"]["privacy"]["nonempty_sensitive_field_occurrences"] == 0

    second = export_archive(collection, spec, tmp_path)
    assert second["status"] == "ALREADY_VERIFIED"
    assert second["archive_id"] == result["archive_id"]
    restored = read_archive_verified(
        result["paths"]["archive"], manifest=result["manifest"]
    )
    assert restored["success"] is True
    assert restored["record_count"] == 2
    assert restored["source_mutations"] == 0
    assert collection.count_documents(spec.query) == 2


def test_verification_rejects_wrong_hash_count_and_truncation(tmp_path: Path) -> None:
    collection = _Collection(_documents())
    spec = _spec()
    result = export_archive(collection, spec, tmp_path)
    archive = Path(result["paths"]["archive"])

    with pytest.raises(ArchiveVerificationError, match="SHA"):
        verify_archive_file(
            archive,
            spec=spec,
            expected_count=2,
            expected_sha256="0" * 64,
        )
    with pytest.raises(ArchiveVerificationError, match="count"):
        verify_archive_file(archive, spec=spec, expected_count=3)

    truncated = tmp_path / "truncated.ejsonl.zst"
    truncated.write_bytes(archive.read_bytes()[:-3])
    truncated.chmod(0o600)
    with pytest.raises(ArchiveVerificationError):
        verify_archive_file(truncated, spec=spec, expected_count=2)


def test_privacy_gate_rejects_nonempty_secret_shaped_field(tmp_path: Path) -> None:
    bson = pytest.importorskip("bson")
    document = _documents()[0]
    document["password"] = "must-not-be-archived"
    collection = _Collection([document])
    spec = _spec({
        "timestamp": {
            "$gte": document["timestamp"],
            "$lt": datetime(2026, 8, 15, 6, 50, tzinfo=timezone.utc),
        }
    })
    with pytest.raises(ArchivePrivacyError):
        export_archive(collection, spec, tmp_path)


def test_partial_archive_path_is_a_conflict_and_never_verified(tmp_path: Path) -> None:
    collection = _Collection(_documents())
    spec = _spec()
    plan = plan_archive(collection, spec)
    archive_id = build_archive_id(plan)
    partial = archive_paths(tmp_path, archive_id)["archive"].with_suffix(".zst.partial")
    partial.write_bytes(b"partial")
    partial.chmod(0o600)
    with pytest.raises(ArchiveIDConflict, match="partial"):
        export_archive(collection, spec, tmp_path, plan=plan)
    assert not archive_paths(tmp_path, archive_id)["manifest"].exists()


class _DeleteResult:
    def __init__(self, deleted_count: int, acknowledged: bool = True) -> None:
        self.deleted_count = deleted_count
        self.acknowledged = acknowledged


class _DestructiveCollection:
    name = "hardware_metrics"

    def __init__(self, documents: list[dict[str, Any]], *, partial: bool = False) -> None:
        self.documents = list(documents)
        self.delete_filters: list[Mapping[str, Any]] = []
        self.partial = partial

    @staticmethod
    def _ids(query: Mapping[str, Any]) -> set[str]:
        condition = query.get("_id")
        if not isinstance(condition, Mapping) or set(condition) != {"$in"}:
            raise AssertionError("test collection received a non-exact filter")
        return {canonical_ejson_dumps(value) for value in condition["$in"]}

    def count_documents(self, query: Mapping[str, Any]) -> int:
        ids = self._ids(query)
        return sum(canonical_ejson_dumps(document["_id"]) in ids for document in self.documents)

    def find(self, query: Mapping[str, Any]) -> _Cursor:
        ids = self._ids(query)
        return _Cursor(
            [
                dict(document)
                for document in self.documents
                if canonical_ejson_dumps(document["_id"]) in ids
            ]
        )

    def delete_many(self, query: Mapping[str, Any]) -> _DeleteResult:
        self.delete_filters.append(query)
        ids = self._ids(query)
        matching = [
            document
            for document in self.documents
            if canonical_ejson_dumps(document["_id"]) in ids
        ]
        delete_count = len(matching) - 1 if self.partial and matching else len(matching)
        retained = matching[delete_count:]
        retained_ids = {canonical_ejson_dumps(document["_id"]) for document in retained}
        self.documents = [
            document
            for document in self.documents
            if canonical_ejson_dumps(document["_id"]) not in ids or canonical_ejson_dumps(document["_id"]) in retained_ids
        ]
        return _DeleteResult(delete_count)


def _purge_fixture() -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any], dict[str, Any]]:
    bson = pytest.importorskip("bson")
    documents = [
        {
            "_id": bson.ObjectId(f"{index + 1:024x}"),
            "timestamp": datetime(2026, 8, 15, 6, 42, tzinfo=timezone.utc),
            "metric": bson.int64.Int64(index),
            "nested": {"values": [index, False]},
        }
        for index in range(PILOT_AUTHORIZED_MAX)
    ]
    target = {
        "project_id": "6a549939366a569efa96236e",
        "cluster_id": "6a549b2a17450a688c455e7e",
        "cluster_name": "Honeypot-DB",
        "srv_hostname": "honeypot-db.o4c0xzu.mongodb.net",
        "database": "honeypot_db",
        "collection": "hardware_metrics",
        "storage_epoch": "LEGACY_TARGET_A_NO_CANONICAL_EPOCH",
    }
    records_sha = _records_digest(documents)
    manifest = {
        "archive_status": "VERIFIED",
        "archive_id": "mongoarc_test_pilot",
        "sha256": "a" * 64,
        "selected_count": PILOT_AUTHORIZED_MAX,
        "records_sha256": records_sha,
        "source_target": target,
    }
    ids = sorted((document["_id"] for document in documents), key=canonical_ejson_dumps)
    frozen: dict[str, Any] = {
        "schema_version": "mongo_pi_archive_purge_exact_set.v1",
        "purge_set_status": "FROZEN_VERIFIED",
        "archive_id": manifest["archive_id"],
        "source_target": target,
        "archive_sha256": manifest["sha256"],
        "records_sha256": records_sha,
        "exact_document_count": PILOT_AUTHORIZED_MAX,
        "authorized_maximum": PILOT_AUTHORIZED_MAX,
        "identity_order": "canonical_extended_json_id_ascending",
        "identity_set_sha256": identity_set_sha256(ids),
        "document_ids": [json.loads(canonical_ejson_dumps(value)) for value in ids],
        "primary_copy": {"path": "/var/lib/honeypot-cold-archive/archives/test", "sha256": manifest["sha256"], "verified": True},
        "secondary_copy": {"path": "/persistent/secondary/test", "sha256": manifest["sha256"], "verified": True},
        "mutations_performed": False,
        "purge_set_sha256": "",
    }
    frozen["purge_set_sha256"] = _self_hash(frozen, "purge_set_sha256")
    return documents, target, manifest, frozen


def _execute_args(tmp_path: Path) -> dict[str, Any]:
    return {
        "target": None,
        "predelete_receipt_path": tmp_path / "predelete.json",
        "progress_path": tmp_path / "progress.jsonl",
        "execution_receipt_path": tmp_path / "execution.json",
        "storage_before": {},
        "pi_capacity": {},
        "secondary_capacity": {},
        "sentinels": None,
        "bson_tests_passed": True,
        "recovery_procedure_written": True,
        "explicit_confirmation": True,
        "batch_size": 50,
    }


def test_exact_purge_deletes_only_frozen_ids_in_bounded_batches(tmp_path: Path) -> None:
    documents, target, manifest, frozen = _purge_fixture()
    collection = _DestructiveCollection(documents)
    kwargs = _execute_args(tmp_path)
    kwargs["target"] = target
    result = execute_exact_purge(collection, frozen, manifest, **kwargs)
    assert result["status"] == "COMPLETED"
    assert result["acknowledged_deleted_total"] == PILOT_AUTHORIZED_MAX
    assert result["remaining_archived_ids"] == 0
    assert [len(query["_id"]["$in"]) for query in collection.delete_filters] == [50] * 9 + [13]
    assert all(set(query) == {"_id"} for query in collection.delete_filters)
    assert collection.documents == []


def test_exact_purge_resume_skips_only_receipted_completed_batch(tmp_path: Path) -> None:
    documents, target, manifest, frozen = _purge_fixture()
    ids = [canonical_ejson_loads(json.dumps(value)) for value in frozen["document_ids"]]
    first_batch = ids[:50]
    first_tokens = {canonical_ejson_dumps(value) for value in first_batch}
    remaining_documents = [
        document
        for document in documents
        if canonical_ejson_dumps(document["_id"]) not in first_tokens
    ]
    collection = _DestructiveCollection(remaining_documents)
    _append_progress(
        tmp_path / "progress.jsonl",
        {
            "schema_version": "mongo_pi_archive_purge_batch_receipt.v1",
            "status": "COMPLETED",
            "batch_index": 0,
            "expected_count": 50,
            "acknowledged_deleted_count": 50,
            "identity_set_sha256": identity_set_sha256(first_batch),
        },
    )
    kwargs = _execute_args(tmp_path)
    kwargs["target"] = target
    result = execute_exact_purge(collection, frozen, manifest, **kwargs)
    assert result["acknowledged_deleted_total"] == PILOT_AUTHORIZED_MAX
    assert all(
        canonical_ejson_dumps(value) not in first_tokens
        for query in collection.delete_filters
        for value in query["_id"]["$in"]
    )


def test_purge_empty_or_over_limit_filter_fails_closed() -> None:
    bson = pytest.importorskip("bson")
    with pytest.raises(PurgeSafetyError, match="empty"):
        build_exact_delete_filter([], authorized_remaining=0)
    with pytest.raises(PurgeSafetyError, match="maximum"):
        build_exact_delete_filter(
            [bson.ObjectId(f"{index + 1:024x}") for index in range(464)],
            authorized_remaining=464,
        )


def test_purge_rejects_source_count_mismatch_without_delete(tmp_path: Path) -> None:
    documents, target, manifest, frozen = _purge_fixture()
    collection = _DestructiveCollection(documents[:-1])
    kwargs = _execute_args(tmp_path)
    kwargs["target"] = target
    with pytest.raises(PurgeSafetyError, match="NO_GO"):
        execute_exact_purge(collection, frozen, manifest, **kwargs)
    assert collection.delete_filters == []
    assert json.loads((tmp_path / "predelete.json").read_text())["status"] == "NO_GO"


def test_purge_rejects_unexpected_delete_count_and_records_partial_stop(tmp_path: Path) -> None:
    documents, target, manifest, frozen = _purge_fixture()
    collection = _DestructiveCollection(documents, partial=True)
    kwargs = _execute_args(tmp_path)
    kwargs["target"] = target
    with pytest.raises(PurgeSafetyError, match="acknowledgement"):
        execute_exact_purge(collection, frozen, manifest, **kwargs)
    progress = (tmp_path / "progress.jsonl").read_text().splitlines()
    assert json.loads(progress[-1])["status"] == "PARTIAL_DELETE_STOPPED"
    assert len(collection.delete_filters) == 1


def test_frozen_purge_set_rejects_wrong_hash_or_secondary_copy() -> None:
    _, _, manifest, frozen = _purge_fixture()
    wrong_hash = dict(frozen)
    wrong_hash["archive_sha256"] = "b" * 64
    wrong_hash["purge_set_sha256"] = _self_hash(wrong_hash, "purge_set_sha256")
    with pytest.raises(PurgeSafetyError, match="archive hash"):
        validate_frozen_purge_set(wrong_hash, manifest)
    missing_secondary = dict(frozen)
    missing_secondary["secondary_copy"] = {"verified": False}
    missing_secondary["purge_set_sha256"] = _self_hash(missing_secondary, "purge_set_sha256")
    with pytest.raises(PurgeSafetyError, match="secondary"):
        validate_frozen_purge_set(missing_secondary, manifest)
    wrong_secondary = dict(frozen)
    wrong_secondary["secondary_copy"] = {**frozen["secondary_copy"], "sha256": "b" * 64}
    wrong_secondary["purge_set_sha256"] = _self_hash(wrong_secondary, "purge_set_sha256")
    with pytest.raises(PurgeSafetyError, match="secondary archive hash"):
        validate_frozen_purge_set(wrong_secondary, manifest)
    wrong_manifest = dict(manifest)
    wrong_manifest["archive_status"] = "PENDING"
    with pytest.raises(PurgeSafetyError, match="VERIFIED"):
        validate_frozen_purge_set(frozen, wrong_manifest)
    wrong_target_manifest = dict(manifest)
    wrong_target_manifest["source_target"] = {**manifest["source_target"], "database": "other_db"}
    with pytest.raises(PurgeSafetyError, match="Target A"):
        validate_frozen_purge_set(frozen, wrong_target_manifest)
