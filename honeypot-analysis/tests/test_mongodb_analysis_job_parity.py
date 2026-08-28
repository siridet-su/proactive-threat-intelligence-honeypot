from __future__ import annotations

import os

import pytest

from production.storage import MongoDBStorageBackend, open_storage
from production.storage.job_materialization import JobMaterializationError
from tests.mongodb_test_support import (
    cleanup_canonical_test_database,
    prepare_canonical_test_database,
)


NOW = "2026-08-13T01:00:00.000000+00:00"
CLAIM_FIELDS = {
    "job_id",
    "session_id",
    "session",
    "attempts",
    "claim_owner",
    "claim_token",
    "claim_expires_at",
}


@pytest.fixture()
def analysis_job_backends(tmp_path):
    uri = os.getenv("MONGODB_TEST_URI", "")
    if not uri:
        pytest.skip("MONGODB_TEST_URI is not configured for an isolated replica set")
    pymongo = pytest.importorskip("pymongo")
    client = pymongo.MongoClient(uri, serverSelectionTimeoutMS=5_000)
    client.admin.command("ping")
    prepare_canonical_test_database(client)
    mongo = MongoDBStorageBackend(client=client)
    mongo.initialize()
    sqlite = open_storage(f"sqlite:///{tmp_path / 'analysis-parity.db'}")
    try:
        yield sqlite, mongo
    finally:
        cleanup_canonical_test_database(client)
        client.close()


def _assert_claim_parity(left, right, expected_session, attempts):
    assert set(left) == set(right) == CLAIM_FIELDS
    assert left["session"] == right["session"] == expected_session
    for field in CLAIM_FIELDS - {"claim_token", "session"}:
        assert left[field] == right[field]
    assert left["attempts"] == right["attempts"] == attempts


def test_analysis_claim_normal_duplicate_retry_fencing_and_completion_are_equal(
    analysis_job_backends,
) -> None:
    sqlite, mongo = analysis_job_backends
    session = {
        "session_id": "sensor-a:multi-event",
        "commands": ["id", "whoami"],
        "raw_events": [
            {"eventid": "cowrie.command.input", "input": "id"},
            {"eventid": "cowrie.command.input", "input": "whoami"},
        ],
    }
    left_id = sqlite.enqueue_analysis_job(session)
    right_id = mongo.enqueue_analysis_job(session)
    assert left_id == right_id
    assert sqlite.enqueue_analysis_job(session) == left_id
    assert mongo.enqueue_analysis_job(session) == right_id

    left = sqlite.claim_analysis_jobs("worker-a", 1, 30, 3, now=NOW)[0]
    right = mongo.claim_analysis_jobs("worker-a", 1, 30, 3, now=NOW)[0]
    _assert_claim_parity(left, right, session, 1)

    assert sqlite.complete_analysis_job(
        left_id,
        "worker-a",
        "22222222-2222-4222-8222-222222222222",
        {"schema_version": "legacy-report.v1", "session_id": session["session_id"]},
        now="2026-08-13T01:00:01+00:00",
    ) is None
    assert mongo.complete_analysis_job(
        right_id,
        "worker-a",
        "22222222-2222-4222-8222-222222222222",
        {"schema_version": "legacy-report.v1", "session_id": session["session_id"]},
        now="2026-08-13T01:00:01+00:00",
    ) is None

    assert sqlite.fail_analysis_job(
        left_id,
        "worker-a",
        left["claim_token"],
        "analysis_failed",
        "TimeoutError",
        True,
        3,
        1,
        now="2026-08-13T01:00:01+00:00",
    ) == "retry_scheduled"
    assert mongo.fail_analysis_job(
        right_id,
        "worker-a",
        right["claim_token"],
        "analysis_failed",
        "TimeoutError",
        True,
        3,
        1,
        now="2026-08-13T01:00:01+00:00",
    ) == "retry_scheduled"

    left = sqlite.claim_analysis_jobs(
        "worker-b", 1, 30, 3, now="2026-08-13T01:00:02+00:00"
    )[0]
    right = mongo.claim_analysis_jobs(
        "worker-b", 1, 30, 3, now="2026-08-13T01:00:02+00:00"
    )[0]
    _assert_claim_parity(left, right, session, 2)

    report = {
        "schema_version": "legacy-report.v1",
        "session_id": session["session_id"],
        "findings": [],
    }
    left_report = sqlite.complete_analysis_job(
        left_id, "worker-b", left["claim_token"], report, now="2026-08-13T01:00:03+00:00"
    )
    right_report = mongo.complete_analysis_job(
        right_id, "worker-b", right["claim_token"], report, now="2026-08-13T01:00:03+00:00"
    )
    assert left_report == right_report
    assert sqlite.get_report_by_id(left_report)["payload"] == report
    assert mongo.get_report_by_id(right_report)["payload"] == report


def test_analysis_claim_terminal_failure_and_explicit_retry_are_equal(
    analysis_job_backends,
) -> None:
    sqlite, mongo = analysis_job_backends
    session = {"session_id": "sensor-a:terminal"}
    job_id = sqlite.enqueue_analysis_job(session)
    assert mongo.enqueue_analysis_job(session) == job_id
    left = sqlite.claim_analysis_jobs("worker-a", 1, 30, 1, now=NOW)[0]
    right = mongo.claim_analysis_jobs("worker-a", 1, 30, 1, now=NOW)[0]
    assert sqlite.fail_analysis_job(
        job_id, "worker-a", left["claim_token"], "analysis_failed", "ValueError", False, 1, 0, now=NOW
    ) == "failed"
    assert mongo.fail_analysis_job(
        job_id, "worker-a", right["claim_token"], "analysis_failed", "ValueError", False, 1, 0, now=NOW
    ) == "failed"
    assert sqlite.claim_analysis_jobs("worker-b", 1, 30, 1, now=NOW) == []
    assert mongo.claim_analysis_jobs("worker-b", 1, 30, 1, now=NOW) == []
    assert sqlite.retry_failed_job("analysis", job_id, now=NOW)
    assert mongo.retry_failed_job("analysis", job_id, now=NOW)
    left = sqlite.claim_analysis_jobs("worker-b", 1, 30, 1, now=NOW)[0]
    right = mongo.claim_analysis_jobs("worker-b", 1, 30, 1, now=NOW)[0]
    _assert_claim_parity(left, right, session, 1)


def test_analysis_claim_malformed_payload_fails_closed_on_both_backends(
    analysis_job_backends,
) -> None:
    sqlite, mongo = analysis_job_backends
    session = {"session_id": "sensor-a:malformed"}
    job_id = sqlite.enqueue_analysis_job(session)
    assert mongo.enqueue_analysis_job(session) == job_id
    with sqlite.connection() as connection:
        connection.execute(
            "UPDATE analysis_jobs SET payload_json=? WHERE job_id=?", ("{", job_id)
        )
    mongo.database.analysis_jobs.update_one(
        {"_id": job_id}, {"$set": {"payload_json": "{"}}
    )
    with pytest.raises(JobMaterializationError):
        sqlite.claim_analysis_jobs("worker-a", 1, 30, 3, now=NOW)
    with pytest.raises(JobMaterializationError):
        mongo.claim_analysis_jobs("worker-a", 1, 30, 3, now=NOW)
    assert sqlite.list_rows("analysis_jobs", 1)[0]["status"] == "running"
    assert mongo.list_rows("analysis_jobs", 1)[0]["status"] == "running"
