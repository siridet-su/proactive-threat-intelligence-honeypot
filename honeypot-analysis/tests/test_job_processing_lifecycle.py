from __future__ import annotations

import json
import inspect
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from production.storage import PostgresStorage, SQLiteStorage, StorageError, open_storage
from production.storage.contract import StorageBackend
from production.storage.mongodb import MongoStorage
from production.tools.job_queue import execute as execute_job_queue_command
from production.utils.config import ProductionConfig
from production.workers.enrichment_worker import EnrichmentWorker
from production.workers.job_lifecycle import JobLeaseHeartbeat
from production.workers.threat_hunt_worker import ThreatHuntWorker
from tests.test_mongodb_storage import make_storage


BASE = "2026-07-18T10:00:00+00:00"


def _sqlite(tmp_path: Path):
    return open_storage(f"sqlite:///{tmp_path / 'jobs.db'}")


@pytest.fixture(params=["sqlite", "mongodb"])
def storage(request: pytest.FixtureRequest, tmp_path: Path):
    if request.param == "sqlite":
        return _sqlite(tmp_path)
    return make_storage()[0]


def _enqueue(storage: Any, queue: str) -> str:
    if queue == "analysis":
        return storage.enqueue_analysis_job(
            {"session_id": f"session-{queue}", "src_ip": "203.0.113.27"}
        )
    if queue == "enrichment":
        return storage.enqueue_enrichment_job(
            "ip", "203.0.113.27", session_id=f"session-{queue}"
        )[0]
    return storage.enqueue_threat_hunt_job(
        f"session-{queue}", "ip", "203.0.113.27"
    )[0]


def _complete(storage: Any, queue: str, claim: dict, now: str) -> bool:
    if queue == "analysis":
        return bool(
            storage.complete_analysis_job(
                claim["job_id"],
                claim["claim_owner"],
                claim["claim_token"],
                {"session_id": "session-analysis", "summary": "complete"},
                now=now,
            )
        )
    if queue == "enrichment":
        return storage.complete_enrichment_job(
            claim["job_id"],
            claim["claim_owner"],
            claim["claim_token"],
            now=now,
        )
    return storage.complete_threat_hunt_job(
        claim["job_id"],
        claim["claim_owner"],
        claim["claim_token"],
        {"status": "complete"},
        now=now,
    )


@pytest.mark.parametrize("queue", ["analysis", "enrichment", "threat_hunt"])
def test_job_claim_retry_expiry_dead_letter_manual_retry_and_completion(
    storage: Any,
    queue: str,
) -> None:
    job_id = _enqueue(storage, queue)
    first = storage.claim_jobs(queue, "worker-a", 1, 10, 3, now=BASE)[0]
    assert first["job_id"] == job_id
    assert first["attempts"] == 1
    assert storage.claim_jobs(queue, "worker-b", 1, 10, 3, now=BASE) == []
    assert storage.renew_job_claim(
        queue,
        job_id,
        "worker-a",
        first["claim_token"],
        10,
        now="2026-07-18T10:00:01+00:00",
    )

    assert storage.claim_jobs(
        queue,
        "worker-b",
        1,
        10,
        3,
        now="2026-07-18T10:00:10+00:00",
    ) == []
    reports_before_stale_completion = storage.list_rows("reports")
    second = storage.claim_jobs(
        queue,
        "worker-b",
        1,
        10,
        3,
        now="2026-07-18T10:00:11+00:00",
    )[0]
    assert second["attempts"] == 2
    assert not _complete(
        storage,
        queue,
        {**second, "claim_token": first["claim_token"]},
        "2026-07-18T10:00:12+00:00",
    )
    assert storage.list_rows("reports") == reports_before_stale_completion
    assert storage.fail_job(
        queue,
        job_id,
        "worker-b",
        second["claim_token"],
        "job_processing_failed",
        "RuntimeError",
        True,
        3,
        5,
        now="2026-07-18T10:00:12+00:00",
    ) == "retry_scheduled"
    assert storage.claim_jobs(
        queue,
        "worker-c",
        1,
        10,
        3,
        now="2026-07-18T10:00:16+00:00",
    ) == []
    third = storage.claim_jobs(
        queue,
        "worker-c",
        1,
        10,
        3,
        now="2026-07-18T10:00:17+00:00",
    )[0]
    assert third["attempts"] == 3
    assert storage.fail_job(
        queue,
        job_id,
        "worker-c",
        third["claim_token"],
        "job_processing_failed",
        "RuntimeError",
        True,
        3,
        5,
        now="2026-07-18T10:00:18+00:00",
    ) == "failed"
    metrics = storage.job_queue_metrics(
        queue, now="2026-07-18T10:00:19+00:00"
    )
    assert metrics["status_counts"]["failed"] == 1
    assert metrics["ready"] == 0
    assert storage.retry_failed_job(
        queue, job_id, now="2026-07-18T10:00:20+00:00"
    )
    manual = storage.claim_jobs(
        queue,
        "worker-manual",
        1,
        10,
        3,
        now="2026-07-18T10:00:20+00:00",
    )[0]
    assert manual["attempts"] == 1
    assert _complete(
        storage, queue, manual, "2026-07-18T10:00:21+00:00"
    )


def test_unregistered_failure_metadata_is_rejected_without_mutating_claim(
    storage: Any,
) -> None:
    job_id = _enqueue(storage, "analysis")
    claim = storage.claim_jobs("analysis", "worker-a", 1, 30, 3, now=BASE)[0]
    with pytest.raises(ValueError, match="registered job failure code"):
        storage.fail_job(
            "analysis",
            job_id,
            "worker-a",
            claim["claim_token"],
            "token=attacker-secret",
            "RuntimeError",
            True,
            3,
            1,
            now="2026-07-18T10:00:01+00:00",
        )
    assert storage.renew_job_claim(
        "analysis",
        job_id,
        "worker-a",
        claim["claim_token"],
        30,
        now="2026-07-18T10:00:02+00:00",
    )


def test_release_makes_claim_immediately_recoverable(storage: Any) -> None:
    job_id = _enqueue(storage, "threat_hunt")
    first = storage.claim_jobs("threat_hunt", "worker-a", 1, 30, 3, now=BASE)[0]
    assert storage.release_job_claim(
        "threat_hunt",
        job_id,
        "worker-a",
        first["claim_token"],
        now="2026-07-18T10:00:01+00:00",
    )
    second = storage.claim_jobs(
        "threat_hunt",
        "worker-b",
        1,
        30,
        3,
        now="2026-07-18T10:00:01+00:00",
    )[0]
    assert second["attempts"] == 2


def test_sqlite_concurrent_claims_have_one_owner(tmp_path: Path) -> None:
    first = _sqlite(tmp_path)
    second = open_storage(f"sqlite:///{tmp_path / 'jobs.db'}")
    job_id = _enqueue(first, "analysis")
    barrier = threading.Barrier(2)
    claims: list[dict] = []

    def claim(storage: Any, owner: str) -> None:
        barrier.wait()
        claims.extend(storage.claim_jobs("analysis", owner, 1, 30, 3))

    threads = [
        threading.Thread(target=claim, args=(first, "worker-a")),
        threading.Thread(target=claim, args=(second, "worker-b")),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)
    assert [claim["job_id"] for claim in claims] == [job_id]


def test_job_heartbeat_prevents_takeover_during_slow_work(tmp_path: Path) -> None:
    storage = _sqlite(tmp_path)
    _enqueue(storage, "analysis")
    claim = storage.claim_jobs("analysis", "worker-a", 1, 0.08, 3)[0]
    config = SimpleNamespace(
        job_lease_seconds=0.08,
        job_lease_heartbeat_seconds=0.02,
    )
    with JobLeaseHeartbeat(storage, config, "analysis", claim):
        time.sleep(0.14)
        assert storage.claim_jobs("analysis", "worker-b", 1, 0.08, 3) == []


class _FailingProvider:
    name = "failing-fixture"

    def supports(self, observable_type: str) -> bool:
        return observable_type == "ip"

    def enrich(self, _observable_type: str, _observable_value: str):
        raise ConnectionError("Authorization: Bearer provider-secret")


def test_provider_failure_is_visible_and_job_remains_retryable(tmp_path: Path) -> None:
    config = ProductionConfig(
        database_url=f"sqlite:///{tmp_path / 'enrichment.db'}",
        enrichment_batch_size=1,
        enrichment_max_attempts=2,
        job_retry_base_seconds=30,
        job_retry_max_seconds=30,
    )
    storage = open_storage(config.database_url)
    job_id, _ = storage.enqueue_enrichment_job("ip", "203.0.113.44")
    worker = EnrichmentWorker(config, providers=[_FailingProvider()])
    assert worker.process_once() == 0
    job = next(row for row in storage.list_rows("enrichment_jobs") if row["job_id"] == job_id)
    assert job["status"] == "retry"
    assert job["last_error_code"] == "enrichment_failed"
    assert job["last_error_type"] == "ConnectionError"
    assert "provider-secret" not in json.dumps(job, sort_keys=True)
    record = storage.get_enrichment_record("ip", "203.0.113.44", allow_stale=True)
    assert record is not None
    assert record["provider_status"]["failing-fixture"]["status"] == "error"
    assert worker.process_once() == 0


def test_job_schema_upgrade_and_backend_contract_are_structurally_complete(
    tmp_path: Path,
) -> None:
    storage = _sqlite(tmp_path)
    lifecycle_columns = {
        "next_retry_at",
        "claim_owner",
        "claim_token",
        "claim_expires_at",
        "last_error_code",
        "last_error_type",
        "last_error_at",
        "completed_at",
    }
    with storage.connection() as connection:
        for table in ("analysis_jobs", "enrichment_jobs", "threat_hunt_jobs"):
            columns = {
                row["name"]
                for row in connection.execute(f"PRAGMA table_info({table})")
            }
            indexes = {
                row["name"]
                for row in connection.execute(f"PRAGMA index_list({table})")
            }
            assert lifecycle_columns <= columns
            assert f"idx_{table}_claimable" in indexes

    for method in (
        "claim_jobs",
        "renew_job_claim",
        "fail_job",
        "release_job_claim",
        "retry_failed_job",
        "job_queue_metrics",
        "claim_analysis_jobs",
        "complete_analysis_job",
        "fail_analysis_job",
        "skip_analysis_job",
        "claim_enrichment_jobs",
        "complete_enrichment_job",
        "fail_enrichment_job",
        "claim_threat_hunt_jobs",
        "complete_threat_hunt_job",
        "fail_threat_hunt_job",
    ):
        protocol_signature = inspect.signature(getattr(StorageBackend, method))
        for implementation in (SQLiteStorage, PostgresStorage, MongoStorage):
            assert inspect.signature(getattr(implementation, method)) == protocol_signature

    postgres_schema = (
        Path(__file__).parents[1] / "production/storage/postgres_schema.sql"
    ).read_text(encoding="utf-8")
    for table in ("analysis_jobs", "enrichment_jobs", "threat_hunt_jobs"):
        assert f"idx_{table}_claimable" in postgres_schema
    postgres = PostgresStorage.__new__(PostgresStorage)
    with pytest.raises(Exception, match="compatibility backend"):
        postgres.claim_jobs("analysis", "worker-a", 1, 30, 3)


def test_operator_queue_command_reports_age_and_retries_only_terminal_jobs(
    tmp_path: Path,
) -> None:
    storage = _sqlite(tmp_path)
    job_id = _enqueue(storage, "analysis")
    code, queued = execute_job_queue_command(storage, "analysis")
    assert code == 0
    assert queued["metrics"]["ready"] == 1

    code, refused = execute_job_queue_command(
        storage, "analysis", retry_job_id=job_id
    )
    assert code == 2
    assert refused["retried"] is False

    claim = storage.claim_jobs("analysis", "worker-a", 1, 30, 1)[0]
    assert storage.fail_job(
        "analysis",
        job_id,
        "worker-a",
        claim["claim_token"],
        "analysis_failed",
        "RuntimeError",
        False,
        1,
        0,
    ) == "failed"
    code, retried = execute_job_queue_command(
        storage, "analysis", retry_job_id=job_id
    )
    assert code == 0
    assert retried["retried"] is True
    assert retried["metrics"]["ready"] == 1


def test_mongodb_analysis_completion_rolls_back_report_on_job_write_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    storage, database = make_storage()
    job_id = _enqueue(storage, "analysis")
    claim = storage.claim_jobs("analysis", "worker-a", 1, 30, 3)[0]

    def fail_job_update(*_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError("injected job write failure")

    monkeypatch.setattr(database["analysis_jobs"], "update_one", fail_job_update)
    with pytest.raises(StorageError, match="fenced transaction failed"):
        storage.complete_analysis_job(
            job_id,
            "worker-a",
            claim["claim_token"],
            {"session_id": "session-analysis", "summary": "complete"},
        )

    assert database["reports"].documents == {}
    persisted = database["analysis_jobs"].documents[job_id]
    assert persisted["status"] == "running"
    assert persisted["claim_token"] == claim["claim_token"]


def test_threat_hunt_effect_is_idempotent_when_completion_is_interrupted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = ProductionConfig(
        database_url=f"sqlite:///{tmp_path / 'hunt.db'}",
        threat_hunt_batch_size=1,
    )
    storage = open_storage(config.database_url)
    job_id = _enqueue(storage, "threat_hunt")
    worker = ThreatHuntWorker(config)

    def write_stable_effect(job: dict[str, Any]) -> dict[str, Any]:
        worker.storage.store_alert(
            {
                "alert_id": "alert-stable-retry",
                "session_id": job["session_id"],
                "severity": "LOW",
                "reason": "bounded retry fixture",
            }
        )
        return {"status": "succeeded"}

    monkeypatch.setattr(worker, "_process_job", write_stable_effect)
    original_complete = worker.storage.complete_threat_hunt_job
    monkeypatch.setattr(
        worker.storage,
        "complete_threat_hunt_job",
        lambda *_args, **_kwargs: False,
    )
    assert worker.process_once() == 0
    assert len(storage.list_rows("alerts")) == 1

    running = next(
        row for row in storage.list_rows("threat_hunt_jobs") if row["job_id"] == job_id
    )
    assert worker.storage.release_job_claim(
        "threat_hunt",
        job_id,
        running["claim_owner"],
        running["claim_token"],
    )
    monkeypatch.setattr(worker.storage, "complete_threat_hunt_job", original_complete)
    assert worker.process_once() == 1
    assert len(storage.list_rows("alerts")) == 1
    completed = next(
        row for row in storage.list_rows("threat_hunt_jobs") if row["job_id"] == job_id
    )
    assert completed["status"] == "succeeded"
