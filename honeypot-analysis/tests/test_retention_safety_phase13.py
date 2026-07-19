from __future__ import annotations

import json
from pathlib import Path

from production.prediction.prune_prediction_snapshots import main
from production.storage import open_storage


REFERENCE_NOW = "2026-07-19T00:00:00+00:00"
OLD = "2026-01-01T00:00:00+00:00"
NEW = "2026-07-01T00:00:00+00:00"


def _snapshot(snapshot_id: str, session_id: str, generated_at: str) -> dict:
    return {
        "snapshot_id": snapshot_id,
        "session_id": session_id,
        "src_ip": "203.0.113.20",
        "generated_at": generated_at,
        "prediction": ["discovery"],
    }


def _seed_retention_graph(path: Path):
    storage = open_storage(f"sqlite:///{path}")
    storage.initialize()
    storage.save_prediction_snapshot(_snapshot("old-intermediate", "session-a", OLD))
    storage.save_prediction_snapshot(_snapshot("new-a", "session-a", NEW))
    storage.save_prediction_snapshot(_snapshot("old-feedback", "session-b", OLD))
    storage.save_prediction_snapshot(_snapshot("new-b", "session-b", NEW))
    storage.save_prediction_snapshot(_snapshot("old-only", "session-c", OLD))
    storage.record_analyst_feedback(
        {
            "session_id": "session-b",
            "snapshot_id": "old-feedback",
            "label": "reviewed",
        }
    )
    return storage


def test_sqlite_retention_is_dry_run_by_default_and_reference_safe(tmp_path) -> None:
    storage = _seed_retention_graph(tmp_path / "retention.db")
    before = {
        row["snapshot_id"]
        for row in storage.list_rows("prediction_snapshots", limit=20)
    }

    result = storage.prune_prediction_snapshots(
        retention_days=90,
        now=REFERENCE_NOW,
    )
    after = {
        row["snapshot_id"]
        for row in storage.list_rows("prediction_snapshots", limit=20)
    }

    assert result == {
        "retention_days": 90,
        "cutoff": "2026-04-20T00:00:00+00:00",
        "keep_latest_per_session": True,
        "dry_run": True,
        "candidates_older_than_cutoff": 3,
        "protected_by_feedback": 1,
        "protected_by_retention_marker": 0,
        "protected_as_latest": 1,
        "eligible": 1,
        "deleted": 0,
        "before": 5,
        "after": 5,
    }
    assert after == before

    applied = storage.prune_prediction_snapshots(
        retention_days=90,
        now=REFERENCE_NOW,
        dry_run=False,
    )
    remaining = {
        row["snapshot_id"]
        for row in storage.list_rows("prediction_snapshots", limit=20)
    }
    assert applied["eligible"] == 1
    assert applied["deleted"] == 1
    assert "old-intermediate" not in remaining
    assert {"old-feedback", "old-only", "new-a", "new-b"}.issubset(remaining)


def test_latest_tie_break_is_deterministic_and_dry_run_does_not_write(tmp_path) -> None:
    storage = open_storage(f"sqlite:///{tmp_path / 'tie.db'}")
    storage.initialize()
    storage.save_prediction_snapshot(_snapshot("snapshot-a", "same-session", OLD))
    storage.save_prediction_snapshot(_snapshot("snapshot-z", "same-session", OLD))

    result = storage.prune_prediction_snapshots(
        retention_days=1,
        now=REFERENCE_NOW,
    )

    assert result["protected_as_latest"] == 1
    assert result["eligible"] == 1
    assert result["deleted"] == 0
    assert storage.get_prediction_snapshot("snapshot-a") is not None
    assert storage.get_prediction_snapshot("snapshot-z") is not None


def test_retention_cli_requires_apply_for_deletion(tmp_path, capsys) -> None:
    database = tmp_path / "cli.db"
    storage = _seed_retention_graph(database)
    arguments = [
        "--database-url",
        f"sqlite:///{database}",
        "--retention-days",
        "90",
        "--now",
        REFERENCE_NOW,
    ]

    assert main(arguments) == 0
    dry_output = json.loads(capsys.readouterr().out)
    assert dry_output["schema_version"] == "prediction_snapshot_retention.v2"
    assert dry_output["dry_run"] is True
    assert dry_output["eligible"] == 1
    assert dry_output["deleted"] == 0
    assert storage.get_prediction_snapshot("old-intermediate") is not None

    assert main([*arguments, "--apply"]) == 0
    applied_output = json.loads(capsys.readouterr().out)
    assert applied_output["dry_run"] is False
    assert applied_output["deleted"] == 1
    assert storage.get_prediction_snapshot("old-intermediate") is None


def test_scheduled_retention_is_auditing_only_and_inventory_is_complete() -> None:
    root = Path(__file__).resolve().parents[1]
    unit = (
        root / "deployment/systemd/honeypot-prediction-retention.service"
    ).read_text(encoding="utf-8")
    policy = (root / "docs/RETENTION_POLICY.md").read_text(encoding="utf-8")
    entities = {
        "events",
        "sessions",
        "alerts",
        "analysis_jobs",
        "reports",
        "feed_status",
        "observables",
        "observable_sightings",
        "enrichment_records",
        "enrichment_jobs",
        "webhook_deliveries",
        "prediction_snapshots",
        "prediction_backtest_runs",
        "prediction_calibration_runs",
        "analyst_feedback",
        "classification_review_labels",
        "threat_hunt_jobs",
        "session_links",
        "campaigns",
        "campaign_sessions",
        "worker_leases",
    }

    assert "--apply" not in next(
        line for line in unit.splitlines() if line.startswith("ExecStart=")
    )
    for entity in entities:
        assert f"`{entity}`" in policy
