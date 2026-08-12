from __future__ import annotations

import pytest

from production.storage import open_storage
from production.storage.job_materialization import (
    JobMaterializationError,
    materialize_ai_advisory_job_claim,
    materialize_analysis_job_claim,
)


def _claim_row(**overrides):
    row = {
        "job_id": "job-a",
        "session_id": "sensor-a:session-a",
        "payload_json": '{"commands":["id","whoami"],"session_id":"sensor-a:session-a"}',
        "attempts": 2,
        "claim_owner": "worker-a",
        "claim_token": "11111111-1111-4111-8111-111111111111",
        "claim_expires_at": "2026-08-13T01:01:00+00:00",
    }
    row.update(overrides)
    return row


def test_analysis_claim_materializes_only_the_domain_contract() -> None:
    claim = materialize_analysis_job_claim(_claim_row())
    assert claim == {
        "job_id": "job-a",
        "session_id": "sensor-a:session-a",
        "session": {
            "commands": ["id", "whoami"],
            "session_id": "sensor-a:session-a",
        },
        "attempts": 2,
        "claim_owner": "worker-a",
        "claim_token": "11111111-1111-4111-8111-111111111111",
        "claim_expires_at": "2026-08-13T01:01:00+00:00",
    }


@pytest.mark.parametrize(
    "payload_json",
    ["{", "[]", "null", 7, None],
)
def test_analysis_claim_rejects_malformed_or_non_object_payload(payload_json) -> None:
    with pytest.raises(JobMaterializationError):
        materialize_analysis_job_claim(_claim_row(payload_json=payload_json))


def test_analysis_claim_rejects_missing_persisted_fields() -> None:
    row = _claim_row()
    del row["claim_token"]
    with pytest.raises(JobMaterializationError, match="claim_token"):
        materialize_analysis_job_claim(row)


def test_ai_claim_preserves_reviewed_malformed_task_failure_path() -> None:
    row = _claim_row(
        report_id="report-a",
        assessment_id="assessment-a",
        payload_json="{",
    )
    claim = materialize_ai_advisory_job_claim(row)
    assert claim["task"] is None
    assert claim["report_id"] == "report-a"
    assert claim["assessment_id"] == "assessment-a"


def test_sqlite_claim_uses_the_shared_analysis_materializer(tmp_path) -> None:
    storage = open_storage(f"sqlite:///{tmp_path / 'jobs.db'}")
    session = {
        "session_id": "sensor-a:multi-event",
        "raw_events": [
            {"eventid": "cowrie.command.input", "input": "id"},
            {"eventid": "cowrie.command.input", "input": "whoami"},
        ],
    }
    job_id = storage.enqueue_analysis_job(session)
    claim = storage.claim_analysis_jobs(
        "worker-a", 1, 30, 3, now="2026-08-13T01:00:00+00:00"
    )[0]
    assert claim["job_id"] == job_id
    assert claim["session"] == session
    assert set(claim) == {
        "job_id",
        "session_id",
        "session",
        "attempts",
        "claim_owner",
        "claim_token",
        "claim_expires_at",
    }


def test_sqlite_malformed_analysis_payload_fails_closed(tmp_path) -> None:
    storage = open_storage(f"sqlite:///{tmp_path / 'malformed.db'}")
    job_id = storage.enqueue_analysis_job({"session_id": "sensor-a:malformed"})
    with storage.connection() as connection:
        connection.execute(
            "UPDATE analysis_jobs SET payload_json=? WHERE job_id=?", ("{", job_id)
        )
    with pytest.raises(JobMaterializationError):
        storage.claim_analysis_jobs(
            "worker-a", 1, 30, 3, now="2026-08-13T01:00:00+00:00"
        )
