from __future__ import annotations

from pathlib import Path

import pytest

from production.api.dashboard_api import _current_prediction_payload
from production.api.monitor_web import MonitorConfig, load_session_detail
from production.prediction.evidence_cutoff import make_evidence_cutoff
from production.prediction.next_behavior_runtime import (
    finalize_prediction_snapshot,
)
from production.storage import open_storage
from production.storage.backend import StorageError


def _v3(
    *,
    session_id: str,
    event_id: str,
    received_at: str,
    generated_at: str,
    prediction: str,
) -> dict:
    return finalize_prediction_snapshot(
        {
            "schema_version": "prediction_snapshot.v3",
            "session_id": session_id,
            "event_id": event_id,
            "session_status": "active",
            "generated_at": generated_at,
            "prediction_status": "predicted",
            "prediction": [prediction],
            "evidence_cutoff": make_evidence_cutoff(received_at, event_id),
        }
    )


def _legacy(
    *,
    session_id: str,
    snapshot_id: str,
    event_id: str,
    generated_at: str,
) -> dict:
    return {
        "schema_version": "prediction_snapshot.v2",
        "snapshot_id": snapshot_id,
        "session_id": session_id,
        "event_id": event_id,
        "session_status": "active",
        "generated_at": generated_at,
        "prediction": ["legacy"],
    }


def test_delayed_old_completion_cannot_supersede_newer_evidence(
    tmp_path: Path,
) -> None:
    storage = open_storage(f"sqlite:///{tmp_path / 'order.sqlite3'}")
    storage.initialize()
    newer = _v3(
        session_id="ordered-session",
        event_id="event-new",
        received_at="2026-07-31T00:00:02Z",
        generated_at="2026-07-31T00:00:03Z",
        prediction="execution",
    )
    older = _v3(
        session_id="ordered-session",
        event_id="event-old",
        received_at="2026-07-31T00:00:01Z",
        generated_at="2026-07-31T00:00:10Z",
        prediction="discovery",
    )
    storage.save_prediction_snapshot(newer)
    storage.save_prediction_snapshot(older)

    current = storage.get_current_prediction_snapshot("ordered-session")
    rows = storage.list_prediction_snapshots_for_session(
        "ordered-session", limit=10
    )
    assert current is not None
    assert current["snapshot_id"] == newer["snapshot_id"]
    assert [row["snapshot_id"] for row in rows] == [
        newer["snapshot_id"],
        older["snapshot_id"],
    ]
    assert storage.get_latest_prediction_snapshot("ordered-session") == current


def test_cutoff_selection_is_shared_by_api_monitor_and_recovery_order(
    tmp_path: Path,
) -> None:
    database = tmp_path / "shared.sqlite3"
    storage = open_storage(f"sqlite:///{database}")
    storage.initialize()
    storage.save_session(
        {
            "session_id": "shared-session",
            "src_ip": "unknown",
            "status": "active",
            "is_ended": False,
            "commands": [],
            "classification_events": [],
            "raw_events": [],
        }
    )
    latest_evidence = _v3(
        session_id="shared-session",
        event_id="event-z",
        received_at="2026-07-31T00:00:05Z",
        generated_at="2026-07-31T00:00:06Z",
        prediction="execution",
    )
    storage.save_prediction_snapshot(latest_evidence)
    storage.save_prediction_snapshot(
        _legacy(
            session_id="shared-session",
            snapshot_id="legacy-late-completion",
            event_id="legacy-event",
            generated_at="2026-07-31T23:59:59Z",
        )
    )
    current = storage.get_current_prediction_snapshot("shared-session")
    assert current is not None
    api = _current_prediction_payload(current, [])
    detail = load_session_detail(
        MonitorConfig(
            db_path=str(database),
            database_url=f"sqlite:///{database}",
            reports_dir=str(tmp_path / "reports"),
            enable_response_guidance=False,
        ),
        "shared-session",
        _storage=storage,
    )
    assert api["snapshot_id"] == latest_evidence["snapshot_id"]
    assert detail["latest_prediction_snapshot"]["snapshot_id"] == (
        latest_evidence["snapshot_id"]
    )
    assert detail["prediction_snapshots"][0]["snapshot_id"] == (
        latest_evidence["snapshot_id"]
    )
    assert storage.get_prediction_snapshot("legacy-late-completion") is not None


def test_equal_received_times_use_event_then_content_identity(
    tmp_path: Path,
) -> None:
    storage = open_storage(f"sqlite:///{tmp_path / 'ties.sqlite3'}")
    storage.initialize()
    same_time = "2026-07-31T00:00:01Z"
    event_a = _v3(
        session_id="tie-session",
        event_id="event-a",
        received_at=same_time,
        generated_at="2026-07-31T00:00:09Z",
        prediction="discovery",
    )
    event_z = _v3(
        session_id="tie-session",
        event_id="event-z",
        received_at=same_time,
        generated_at="2026-07-31T00:00:02Z",
        prediction="execution",
    )
    storage.save_prediction_snapshot(event_z)
    storage.save_prediction_snapshot(event_a)
    rows = storage.list_prediction_snapshots_for_session("tie-session")
    assert [row["payload"]["event_id"] for row in rows] == [
        "event-z",
        "event-a",
    ]

    duplicate_cutoff = _v3(
        session_id="tie-session",
        event_id="event-z",
        received_at=same_time,
        generated_at="2026-07-31T00:00:20Z",
        prediction="collection",
    )
    storage.save_prediction_snapshot(duplicate_cutoff)
    tied = [
        row
        for row in storage.list_prediction_snapshots_for_session("tie-session")
        if row["payload"]["event_id"] == "event-z"
    ]
    assert [row["snapshot_id"] for row in tied] == sorted(
        (row["snapshot_id"] for row in tied),
        reverse=True,
    )


def test_outbox_retry_retains_captured_cutoff_and_claim_exposes_durable_order(
    tmp_path: Path,
) -> None:
    storage = open_storage(f"sqlite:///{tmp_path / 'outbox.sqlite3'}")
    storage.initialize()
    event_id, inserted = storage.store_event(
        "sensor",
        {
            "eventid": "cowrie.command.input",
            "session": "cutoff-session",
            "timestamp": "2026-07-31T00:00:00Z",
            "input": "[redacted]",
        },
    )
    assert inserted is True
    claimed_event = storage.claim_events(
        "event-worker",
        1,
        30,
        now="2026-07-31T00:00:01Z",
    )[0]
    cutoff = make_evidence_cutoff(
        claimed_event["received_at"],
        claimed_event["event_id"],
    )
    task = {
        "schema_version": "prediction_outbox_task.v2",
        "event_id": event_id,
        "session_id": "cutoff-session",
        "prediction_mode": "fixture",
        "evidence_cutoff": cutoff,
    }
    outbox_id = storage.enqueue_prediction_outbox(task)
    first = storage.claim_prediction_outbox(
        "prediction-worker",
        1,
        30,
        2,
        now="2026-07-31T00:00:01Z",
    )[0]
    assert first["task"]["evidence_cutoff"] == cutoff
    assert (
        storage.fail_prediction_outbox(
            outbox_id,
            "prediction-worker",
            first["claim_token"],
            "retry",
            "RuntimeError",
            True,
            2,
            1,
            now="2026-07-31T00:00:02Z",
        )
        == "retry"
    )
    second = storage.claim_prediction_outbox(
        "prediction-worker",
        1,
        30,
        2,
        now="2026-07-31T00:00:04Z",
    )[0]
    assert second["task"]["evidence_cutoff"] == cutoff


def test_cutoff_is_payload_bound_without_a_database_schema_change(
    tmp_path: Path,
) -> None:
    database = tmp_path / "migration.sqlite3"
    storage = open_storage(f"sqlite:///{database}")
    storage.initialize()

    invalid = _v3(
        session_id="invalid-session",
        event_id="event-valid",
        received_at="2026-07-31T00:00:01Z",
        generated_at="2026-07-31T00:00:02Z",
        prediction="execution",
    )
    invalid["event_id"] = "event-mismatch"
    with pytest.raises(StorageError, match="does not match"):
        storage.save_prediction_snapshot(invalid)


def test_retention_protects_evidence_current_not_latest_completion(
    tmp_path: Path,
) -> None:
    storage = open_storage(f"sqlite:///{tmp_path / 'retention.sqlite3'}")
    storage.initialize()
    current = _v3(
        session_id="retention-session",
        event_id="event-current",
        received_at="2026-01-01T00:00:02Z",
        generated_at="2026-01-01T00:00:02Z",
        prediction="execution",
    )
    legacy = _legacy(
        session_id="retention-session",
        snapshot_id="legacy-completed-later",
        event_id="legacy",
        generated_at="2026-02-01T00:00:00Z",
    )
    storage.save_prediction_snapshot(current)
    storage.save_prediction_snapshot(legacy)
    result = storage.prune_prediction_snapshots(
        retention_days=1,
        now="2026-07-31T00:00:00Z",
        keep_latest_per_session=True,
        dry_run=False,
    )
    assert result["protected_as_latest"] == 1
    assert storage.get_prediction_snapshot(current["snapshot_id"]) is not None
    assert storage.get_prediction_snapshot(legacy["snapshot_id"]) is None
