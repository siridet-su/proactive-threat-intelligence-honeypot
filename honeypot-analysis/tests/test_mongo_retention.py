from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping

import pytest

import production.archive.retention_orchestrator as retention_orchestrator
import production.archive.retention_planner as retention_planner
from production.archive.cold_archive import ArchiveIDConflict, PurgeSafetyError
from production.archive.retention_orchestrator import FilesystemSecondaryBackend, RetentionOrchestrator
from production.archive.retention_planner import RetentionPlan, plan_retention
from production.archive.retention_policy import (
    RetentionConfig,
    RetentionPolicyError,
    capacity_state,
    capacity_state_with_hysteresis,
    lifecycle_document_is_safe,
    lifecycle_query,
    load_retention_config,
)


CONFIG_PATH = Path(__file__).parents[1] / "configs" / "mongo_pi_retention.final.json"


def _config():
    return load_retention_config(CONFIG_PATH)


def _hardware_config(
    *,
    auto_archive: bool = True,
    max_documents: int = 5000,
    max_bytes: int = 67108864,
    max_batches: int = 10,
    batch_size: int = 500,
):
    raw = json.loads(CONFIG_PATH.read_text())
    raw["legacy_collections"]["hardware_metrics"]["auto_archive_eligible"] = auto_archive
    raw["capacity"].update(
        {
            "max_documents_per_cycle": max_documents,
            "max_logical_bytes_per_cycle": max_bytes,
            "max_batches_per_run": max_batches,
            "batch_size_documents": batch_size,
        }
    )
    return RetentionConfig.from_mapping(raw)


def _database_for(collection: _Collection):
    class _Database:
        name = "honeypot_db"

        def __getitem__(self, name: str) -> _Collection:
            assert name == collection.name
            return collection

        def list_collection_names(self) -> list[str]:
            return [collection.name]

    return _Database()


def _jsonish(value: Any) -> str:
    return json.dumps(value, sort_keys=True, default=lambda item: item.isoformat())


class _Cursor:
    def __init__(self, documents: list[dict[str, Any]]) -> None:
        self.documents = documents

    def sort(self, fields: list[list[Any]]) -> "_Cursor":
        for field, direction in reversed(fields):
            self.documents.sort(key=lambda item: item[field], reverse=direction == -1)
        return self

    def limit(self, amount: int) -> "_Cursor":
        self.documents = self.documents[:amount]
        return self

    def __iter__(self):
        return iter(self.documents)


class _Collection:
    def __init__(self, name: str, documents: list[dict[str, Any]]) -> None:
        self.name = name
        self.documents = documents
        self.delete_calls = 0

    @staticmethod
    def _value(document: Mapping[str, Any], field: str) -> Any:
        value: Any = document
        for part in field.split("."):
            if not isinstance(value, Mapping):
                return None
            value = value.get(part)
        return value

    @classmethod
    def _matches(cls, document: Mapping[str, Any], query: Mapping[str, Any]) -> bool:
        for field, condition in query.items():
            if field == "$and":
                if not all(cls._matches(document, item) for item in condition):
                    return False
                continue
            actual = cls._value(document, field)
            if isinstance(condition, Mapping):
                for operator, expected in condition.items():
                    if operator == "$type" and expected == "date" and not isinstance(actual, datetime):
                        return False
                    if operator == "$lt" and not (actual is not None and actual < expected):
                        return False
                    if operator == "$nin" and actual in expected:
                        return False
            elif actual != condition:
                return False
        return True

    def count_documents(self, query: Mapping[str, Any]) -> int:
        return sum(self._matches(document, query) for document in self.documents)

    def find(self, query: Mapping[str, Any]) -> _Cursor:
        return _Cursor([dict(document) for document in self.documents if self._matches(document, query)])

    def delete_many(self, query: Mapping[str, Any]) -> Any:
        self.delete_calls += 1
        raise AssertionError("plan-only test attempted a Mongo delete")


def test_final_config_covers_canonical_and_legacy_scopes_without_name_collision() -> None:
    config = _config()
    assert len(config.canonical_collection_names) == 31
    assert set(config.canonical_collection_policies) == set(config.canonical_collection_names)
    assert set(config.legacy_collection_policies) == {
        "events",
        "hardware_metrics",
        "normalized_events",
        "enriched_events",
        "threat_intel",
        "users",
    }
    assert config.policy_for("events").authority_state_role == "legacy_go_processor_input"
    assert config.canonical_collection_policies["events"].authority_state_role == "canonical_evidence"
    assert config.automatic_purge is False


def test_capacity_state_thresholds_are_explicit() -> None:
    config = _config()
    assert capacity_state(0.69, config.capacity) == "NORMAL"
    assert capacity_state(0.70, config.capacity) == "WARNING"
    assert capacity_state(0.80, config.capacity) == "HIGH"
    assert capacity_state(0.90, config.capacity) == "CRITICAL"


def test_hysteresis_holds_prior_action_until_recovery_target() -> None:
    config = _config()
    assert capacity_state_with_hysteresis(0.68, config.capacity, previous_state="HIGH") == "HIGH"
    assert capacity_state_with_hysteresis(0.65, config.capacity, previous_state="HIGH") == "NORMAL"


def test_lifecycle_requires_bson_date_and_terminal_marker() -> None:
    policy = _config().policy_for("hardware_metrics")
    cutoff = datetime.now(timezone.utc) - timedelta(days=30)
    query = lifecycle_query(policy, cutoff=cutoff)
    assert query is not None
    assert {"timestamp": {"$type": "date", "$lt": cutoff}} in query["$and"]
    assert {"legacy_archive_eligible": True} in query["$and"]
    assert lifecycle_document_is_safe(policy, {"timestamp": cutoff - timedelta(days=1)}) is False


def test_plan_normal_is_non_destructive_and_does_not_delete(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(retention_planner, "canonical_ejson_dumps", _jsonish)
    collection = _Collection(
        "hardware_metrics",
        [
            {
                "_id": 1,
                "timestamp": datetime(2026, 1, 1, tzinfo=timezone.utc),
                "legacy_archive_eligible": True,
                "privacy_scan_passed": True,
            }
        ],
    )

    class _Database:
        name = "honeypot_db"

        def __getitem__(self, name: str) -> _Collection:
            assert name == "hardware_metrics"
            return collection

        def list_collection_names(self) -> list[str]:
            return ["hardware_metrics"]

    config = _config()
    plan = plan_retention(
        _Database(),
        config,
        now=datetime(2026, 8, 31, tzinfo=timezone.utc),
        capacity={
            "logical_data_plus_index_bytes": 300,
            "tier_limit_bytes": config.capacity.quota_bytes,
            "used_ratio": 300 / config.capacity.quota_bytes,
        },
        collection_names=["hardware_metrics"],
    )
    assert plan.status == "NO_ACTION"
    assert plan.payload["mutations_performed"] is False
    assert collection.delete_calls == 0


def test_high_plan_selects_oldest_bounded_candidates(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(retention_planner, "canonical_ejson_dumps", _jsonish)
    collection = _Collection(
        "hardware_metrics",
        [
            {
                "_id": 2,
                "timestamp": datetime(2026, 1, 2, tzinfo=timezone.utc),
                "legacy_archive_eligible": True,
                "privacy_scan_passed": True,
            },
            {
                "_id": 1,
                "timestamp": datetime(2026, 1, 1, tzinfo=timezone.utc),
                "legacy_archive_eligible": True,
                "privacy_scan_passed": True,
            },
        ],
    )

    class _Database:
        name = "honeypot_db"

        def __getitem__(self, name: str) -> _Collection:
            return collection

        def list_collection_names(self) -> list[str]:
            return ["hardware_metrics"]

    config = _hardware_config()
    plan = plan_retention(
        _Database(),
        config,
        now=datetime(2026, 8, 31, tzinfo=timezone.utc),
        capacity={
            "logical_data_plus_index_bytes": int(config.capacity.quota_bytes * 0.85),
            "tier_limit_bytes": config.capacity.quota_bytes,
            "used_ratio": 0.85,
        },
        collection_names=["hardware_metrics"],
    )
    assert plan.status == "ACTIONABLE_PLAN"
    assert [item["document_id"] for item in plan.selected] == [1, 2]
    assert plan.payload["selection_is_deterministic"] is True


def test_warning_plan_is_plan_only_and_unknown_capacity_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(retention_planner, "canonical_ejson_dumps", _jsonish)
    collection = _Collection(
        "hardware_metrics",
        [{
            "_id": 1,
            "timestamp": datetime(2026, 1, 1, tzinfo=timezone.utc),
            "legacy_archive_eligible": True,
            "privacy_scan_passed": True,
        }],
    )
    config = _hardware_config()
    warning = plan_retention(
        _database_for(collection),
        config,
        now=datetime(2026, 8, 31, tzinfo=timezone.utc),
        capacity={"logical_data_plus_index_bytes": 400000000, "tier_limit_bytes": config.capacity.quota_bytes, "used_ratio": 0.75},
        collection_names=["hardware_metrics"],
    )
    assert warning.status == "PLAN_ONLY"
    assert warning.selected == ()
    unknown = plan_retention(
        _database_for(collection),
        config,
        capacity={"tier_limit_bytes": config.capacity.quota_bytes, "used_ratio": None},
        collection_names=["hardware_metrics"],
    )
    assert unknown.status == "CAPACITY_UNRESOLVED"
    assert unknown.selected == ()


def test_mongo_read_interruption_fails_before_any_write() -> None:
    class _InterruptedDatabase:
        name = "honeypot_db"

        def command(self, name: str) -> dict[str, Any]:
            raise RuntimeError("simulated read interruption")

    with pytest.raises(RuntimeError, match="read interruption"):
        plan_retention(_InterruptedDatabase(), _config())


def test_unreachable_secondary_capacity_fails_closed_without_creating_it(tmp_path: Path) -> None:
    missing = tmp_path / "missing-parent" / "root"
    backend = FilesystemSecondaryBackend(missing, reserve_bytes=1, max_used_ratio=0.99)
    with pytest.raises(Exception, match="unavailable"):
        backend.capacity()
    assert not missing.exists()


def test_document_and_batch_limits_are_hard_bounds(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(retention_planner, "canonical_ejson_dumps", _jsonish)
    docs = [
        {
            "_id": index,
            "timestamp": datetime(2026, 1, index + 1, tzinfo=timezone.utc),
            "legacy_archive_eligible": True,
            "privacy_scan_passed": True,
        }
        for index in range(4)
    ]
    config = _hardware_config(max_documents=2, max_bytes=10**9, max_batches=1, batch_size=2)
    plan = plan_retention(
        _database_for(_Collection("hardware_metrics", docs)),
        config,
        now=datetime(2026, 8, 31, tzinfo=timezone.utc),
        capacity={"logical_data_plus_index_bytes": int(config.capacity.quota_bytes * 0.95), "tier_limit_bytes": config.capacity.quota_bytes, "used_ratio": 0.95},
        collection_names=["hardware_metrics"],
    )
    assert len(plan.selected) <= 2
    assert len(plan.selected) <= 1 * 2
    assert plan.payload["estimated_selected_archive_bytes"] <= 10**9


def test_byte_limit_prevents_oversized_candidate_selection(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(retention_planner, "canonical_ejson_dumps", _jsonish)
    collection = _Collection(
        "hardware_metrics",
        [{
            "_id": 1,
            "timestamp": datetime(2026, 1, 1, tzinfo=timezone.utc),
            "legacy_archive_eligible": True,
            "privacy_scan_passed": True,
            "large": "x" * 100,
        }],
    )
    config = _hardware_config(max_bytes=1)
    plan = plan_retention(
        _database_for(collection),
        config,
        now=datetime(2026, 8, 31, tzinfo=timezone.utc),
        capacity={"logical_data_plus_index_bytes": int(config.capacity.quota_bytes * 0.95), "tier_limit_bytes": config.capacity.quota_bytes, "used_ratio": 0.95},
        collection_names=["hardware_metrics"],
    )
    assert plan.selected == ()
    assert plan.payload["estimated_selected_archive_bytes"] == 0


def test_secondary_copy_is_idempotent_and_low_space_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source.ejsonl.zst"
    source.write_bytes(b"archive-bytes")
    source.chmod(0o600)
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    manifest = {"archive_id": "mongoarc_test", "sha256": digest, "selected_count": 1}
    monkeypatch.setattr(
        retention_orchestrator,
        "read_archive_verified",
        lambda path, manifest: {
            "sha256": digest,
            "records_sha256": "r" * 64,
            "record_count": 1,
        },
    )
    backend = FilesystemSecondaryBackend(tmp_path / "secondary", reserve_bytes=1, max_used_ratio=0.99)
    first = backend.replicate(source, manifest)
    second = backend.replicate(source, manifest)
    assert first["verified"] is True
    assert second["status"] == "ALREADY_VERIFIED"
    blocked = FilesystemSecondaryBackend(tmp_path / "blocked", reserve_bytes=10**18, max_used_ratio=0.99)
    with pytest.raises(Exception, match="capacity"):
        blocked.replicate(source, manifest)


def test_secondary_conflict_and_count_mismatch_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source.ejsonl.zst"
    source.write_bytes(b"archive-bytes")
    source.chmod(0o600)
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    manifest = {"archive_id": "mongoarc_conflict", "sha256": digest, "selected_count": 1}
    monkeypatch.setattr(
        retention_orchestrator,
        "read_archive_verified",
        lambda path, manifest: {"sha256": digest, "records_sha256": "r" * 64, "record_count": 1},
    )
    backend = FilesystemSecondaryBackend(tmp_path / "secondary", reserve_bytes=1, max_used_ratio=0.99)
    backend.replicate(source, manifest)
    destination = tmp_path / "secondary" / "archives" / "mongoarc_conflict.ejsonl.zst"
    destination.write_bytes(b"different")
    destination.chmod(0o600)
    with pytest.raises(ArchiveIDConflict, match="conflicting"):
        backend.replicate(source, manifest)

    mismatch_manifest = {"archive_id": "mongoarc_count", "sha256": digest, "selected_count": 2}
    mismatch = FilesystemSecondaryBackend(tmp_path / "mismatch", reserve_bytes=1, max_used_ratio=0.99)
    with pytest.raises(Exception, match="count"):
        mismatch.replicate(source, mismatch_manifest)


def test_purge_requires_dependency_receipt_before_any_frozen_set_validation() -> None:
    raw_config = json.loads(CONFIG_PATH.read_text())
    raw_config["active_policy_scope"] = "canonical"
    config = RetentionConfig.from_mapping(raw_config)
    collection = _Collection("prediction_snapshots", [])
    manifest = {"source_target": {"collection": "prediction_snapshots"}}
    with pytest.raises(Exception, match="dependency"):
        retention_orchestrator.execute_retention_exact_purge(
            collection,
            {},
            manifest,
            config,
            run_dir=Path("/tmp/unused-retention-test"),
            explicit_confirmation=True,
        )


def test_purge_confirmation_and_target_epoch_guards_fail_closed() -> None:
    raw_config = json.loads(CONFIG_PATH.read_text())
    raw_config["active_policy_scope"] = "canonical"
    config = RetentionConfig.from_mapping(raw_config)
    collection = _Collection("prediction_backtest_runs", [])
    target = config.target.source_target("prediction_backtest_runs")
    manifest = {"source_target": target}
    with pytest.raises(PurgeSafetyError, match="confirmation"):
        retention_orchestrator.execute_retention_exact_purge(
            collection, {}, manifest, config, run_dir=Path("/tmp/unused-retention-test"), explicit_confirmation=False
        )
    wrong = {**target, "storage_epoch": "wrong-epoch"}
    with pytest.raises(PurgeSafetyError, match="target"):
        retention_orchestrator._validate_retention_frozen_set(
            {"schema_version": retention_orchestrator.RETENTION_FROZEN_SET_VERSION, "purge_set_status": "FROZEN_VERIFIED"},
            {"archive_status": "VERIFIED", "source_target": wrong},
            config,
        )


def test_stage_receipt_is_idempotent_and_catalog_event_conflicts() -> None:
    import tempfile

    with tempfile.TemporaryDirectory() as selected:
        path = Path(selected)
        first = retention_orchestrator._write_stage(path, "capacity-status", {"value": 1})
        second = retention_orchestrator._write_stage(path, "capacity-status", {"value": 1})
        assert first["stage"] == second["stage"]
        assert len((path / "stages.jsonl").read_text().splitlines()) == 1


def test_automation_mode_with_default_flags_is_non_destructive() -> None:
    config = _config()
    plan = RetentionPlan(
        payload={"status": "NO_ACTION", "automatic_purge": False, "automatic_archive": False},
        selected=(),
        selected_by_collection={},
    )
    orchestrator = RetentionOrchestrator(None, config)
    orchestrator.plan = lambda now=None: plan  # type: ignore[method-assign]
    result = orchestrator.run(automation=True)
    assert result["status"] == "NO_ACTION"
    assert result["mutations_performed"] is False


def test_invalid_config_rejects_unknown_active_scope() -> None:
    raw = json.loads(CONFIG_PATH.read_text())
    raw["active_policy_scope"] = "guess"
    with pytest.raises(RetentionPolicyError, match="active_policy_scope"):
        RetentionConfig.from_mapping(raw)
