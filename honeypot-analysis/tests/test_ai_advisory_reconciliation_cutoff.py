from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from production.ai_advisory.security import validate_activation_receipt
from production.prediction.evidence_cutoff import PredictionEvidenceCutoffError
from production.storage.backend import SQLiteStorage
from production.utils.config import ProductionConfig
from production.utils.serialization import stable_json


CUTOFF = {
    "schema_version": "prediction_evidence_cutoff.v1",
    "received_at": "2026-08-10T12:00:00.000000+00:00",
    "event_id": "event-cutoff",
}


def _storage(tmp_path: Path) -> SQLiteStorage:
    storage = SQLiteStorage(f"sqlite:///{tmp_path / 'state.db'}")
    storage.initialize()
    storage.initialize_ai_advisory_extension()
    return storage


def _insert_event(
    storage: SQLiteStorage,
    session_id: str,
    received_at: str,
    event_id: str,
) -> None:
    event = {
        "eventid": "cowrie.session.connect",
        "session": session_id,
    }
    with storage.connection() as connection:
        connection.execute(
            """
            INSERT INTO events
            (event_id, sensor_id, session_id, src_ip, eventid, timestamp,
             payload_json, received_at)
            VALUES (?, 'sensor-test', ?, '192.0.2.10', ?, NULL, ?, ?)
            """,
            (
                event_id,
                session_id,
                event["eventid"],
                stable_json(event),
                received_at,
            ),
        )


def _commit_report(storage: SQLiteStorage, session_id: str) -> tuple[str, str]:
    storage.save_session({"session_id": session_id, "src_ip": "192.0.2.10"})
    job_id = storage.enqueue_analysis_job({"session_id": session_id})
    job = storage.claim_analysis_jobs("analysis-owner", 1, 60, 3)[0]
    assessment_id = f"assessment-{session_id}"
    report_id = storage.complete_analysis_job(
        job_id,
        "analysis-owner",
        job["claim_token"],
        {
            "schema_version": "session_assessment.v4",
            "assessment_id": assessment_id,
            "session_id": session_id,
        },
        enqueue_ai_advisory=False,
    )
    assert report_id is not None
    return report_id, assessment_id


def _reconcile(storage: SQLiteStorage, *, max_queue_records: int = 10_000):
    return storage.reconcile_ai_advisory_outbox(
        reconciliation_cutoff=CUTOFF,
        limit=100,
        max_queue_records=max_queue_records,
    )


def test_report_before_cutoff_is_excluded_even_with_later_session_events(
    tmp_path: Path,
) -> None:
    storage = _storage(tmp_path)
    _insert_event(
        storage,
        "before-session",
        "2026-08-10T11:59:59.999999+00:00",
        "event-before",
    )
    _insert_event(
        storage,
        "before-session",
        "2026-08-10T12:00:01.000000+00:00",
        "event-later",
    )
    report_id, _ = _commit_report(storage, "before-session")
    before = storage.get_report_by_id(report_id)["payload_json"]

    assert _reconcile(storage) == {"scanned": 0, "enqueued": 0, "bounded": 0}
    assert storage.list_rows("ai_advisory_outbox") == []
    assert storage.get_report_by_id(report_id)["payload_json"] == before


def test_report_exactly_at_cutoff_is_excluded(tmp_path: Path) -> None:
    storage = _storage(tmp_path)
    _insert_event(
        storage,
        "boundary-session",
        CUTOFF["received_at"],
        CUTOFF["event_id"],
    )
    _commit_report(storage, "boundary-session")

    assert _reconcile(storage)["enqueued"] == 0
    assert storage.list_rows("ai_advisory_outbox") == []


def test_report_after_cutoff_is_eligible_and_reconciliation_is_idempotent(
    tmp_path: Path,
) -> None:
    storage = _storage(tmp_path)
    _insert_event(
        storage,
        "after-session",
        "2026-08-10T12:00:00.000001+00:00",
        "event-after",
    )
    _commit_report(storage, "after-session")

    assert _reconcile(storage) == {"scanned": 1, "enqueued": 1, "bounded": 0}
    assert _reconcile(storage) == {"scanned": 0, "enqueued": 0, "bounded": 0}
    assert len(storage.list_rows("ai_advisory_outbox")) == 1


@pytest.mark.parametrize(
    "cutoff",
    [
        {},
        {
            "schema_version": "prediction_evidence_cutoff.v1",
            "received_at": "not-a-timestamp",
            "event_id": "event-cutoff",
        },
    ],
)
def test_missing_or_malformed_cutoff_fails_closed(
    tmp_path: Path,
    cutoff: dict,
) -> None:
    storage = _storage(tmp_path)
    with pytest.raises(PredictionEvidenceCutoffError):
        storage.reconcile_ai_advisory_outbox(
            reconciliation_cutoff=cutoff,
        )


def test_enabled_configuration_requires_cutoff() -> None:
    with pytest.raises(ValueError, match="requires a reconciliation cutoff"):
        ProductionConfig(
            enable_ai_advisory=True,
            ai_advisory_provider="fixture",
            ai_advisory_model="fixture-model",
        )


def test_enabled_configuration_rejects_malformed_cutoff() -> None:
    with pytest.raises(PredictionEvidenceCutoffError):
        ProductionConfig(
            enable_ai_advisory=True,
            ai_advisory_provider="fixture",
            ai_advisory_model="fixture-model",
            ai_advisory_reconciliation_cutoff={
                "schema_version": "prediction_evidence_cutoff.v1",
                "received_at": "not-a-timestamp",
                "event_id": "event-cutoff",
            },
        )


def _activation_receipt(path: Path, cutoff: dict) -> Path:
    checked = datetime.now(timezone.utc) - timedelta(minutes=1)
    path.write_text(
        json.dumps(
            {
                "schema_version": "ai_advisory_activation_receipt.v1",
                "status": "ready",
                "provider_id": "fixture",
                "model_id": "fixture-model",
                "adapter_revision": "fixture.v1",
                "endpoint_sha256": "",
                "provider_adapter_reviewed": True,
                "managed_worker_unit": "honeypot-ai-advisory-worker.service",
                "worker_status": "ready",
                "credentials_status": "not_required",
                "reconciliation_mode": "new_sessions_only",
                "reconciliation_cutoff": cutoff,
                "health_checked_at": checked.isoformat(),
                "expires_at": (checked + timedelta(minutes=30)).isoformat(),
            }
        ),
        encoding="utf-8",
    )
    path.chmod(0o600)
    return path.resolve()


def test_activation_receipt_cutoff_mismatch_fails_closed(tmp_path: Path) -> None:
    receipt = _activation_receipt(tmp_path / "activation.json", CUTOFF)
    moved = dict(CUTOFF, event_id="event-moved")

    with pytest.raises(ValueError, match="reconciliation_cutoff"):
        validate_activation_receipt(
            str(receipt),
            provider_id="fixture",
            model_id="fixture-model",
            adapter_revision="fixture.v1",
            endpoint="",
            hosted=False,
            reconciliation_cutoff=moved,
        )


def test_cutoff_persists_across_config_reload_and_worker_restart_boundary(
    tmp_path: Path,
) -> None:
    key = tmp_path / "alias.key"
    key.write_bytes(b"a" * 32)
    key.chmod(0o600)
    fixture = tmp_path / "response.json"
    fixture.write_text("{}", encoding="utf-8")
    receipt = _activation_receipt(tmp_path / "activation.json", CUTOFF)
    config_path = tmp_path / "production.json"
    config_path.write_text(
        json.dumps(
            {
                "enable_ai_advisory": True,
                "ai_advisory_provider": "fixture",
                "ai_advisory_model": "fixture-model",
                "ai_advisory_adapter_revision": "fixture.v1",
                "ai_advisory_fixture_response_path": str(fixture),
                "ai_advisory_alias_key_file": str(key.resolve()),
                "ai_advisory_activation_receipt_path": str(receipt),
                "ai_advisory_reconciliation_cutoff": CUTOFF,
            }
        ),
        encoding="utf-8",
    )

    first = ProductionConfig.from_env(str(config_path))
    second = ProductionConfig.from_env(str(config_path))

    assert first.ai_advisory_reconciliation_cutoff == CUTOFF
    assert second.ai_advisory_reconciliation_cutoff == CUTOFF


def test_existing_outbox_row_remains_idempotent(tmp_path: Path) -> None:
    storage = _storage(tmp_path)
    _insert_event(
        storage,
        "idempotent-session",
        "2026-08-10T12:00:01.000000+00:00",
        "event-idempotent",
    )
    report_id, assessment_id = _commit_report(storage, "idempotent-session")

    first = storage.enqueue_ai_advisory_job(
        report_id,
        "idempotent-session",
        assessment_id,
        reconciliation_cutoff=CUTOFF,
    )
    second = storage.enqueue_ai_advisory_job(
        report_id,
        "idempotent-session",
        assessment_id,
        reconciliation_cutoff=CUTOFF,
    )

    assert first == second
    assert len(storage.list_rows("ai_advisory_outbox")) == 1


def test_reconciliation_preserves_active_queue_count_bound(tmp_path: Path) -> None:
    storage = _storage(tmp_path)
    for index in range(2):
        session_id = f"bounded-session-{index}"
        _insert_event(
            storage,
            session_id,
            f"2026-08-10T12:00:0{index + 1}.000000+00:00",
            f"event-bounded-{index}",
        )
        _commit_report(storage, session_id)

    result = _reconcile(storage, max_queue_records=1)

    assert result == {"scanned": 2, "enqueued": 1, "bounded": 1}
    assert len(storage.list_rows("ai_advisory_outbox")) == 1


def test_missing_cutoff_cannot_roll_back_canonical_report(tmp_path: Path) -> None:
    storage = _storage(tmp_path)
    _insert_event(
        storage,
        "canonical-session",
        "2026-08-10T12:00:01.000000+00:00",
        "event-canonical",
    )
    storage.save_session({"session_id": "canonical-session"})
    job_id = storage.enqueue_analysis_job({"session_id": "canonical-session"})
    job = storage.claim_analysis_jobs("owner", 1, 60, 3)[0]

    report_id = storage.complete_analysis_job(
        job_id,
        "owner",
        job["claim_token"],
        {
            "schema_version": "session_assessment.v4",
            "assessment_id": "assessment-canonical",
            "session_id": "canonical-session",
        },
        enqueue_ai_advisory=True,
        ai_advisory_reconciliation_cutoff=None,
    )

    assert report_id is not None
    assert storage.get_report_by_id(report_id) is not None
    assert storage.list_rows("ai_advisory_outbox") == []
