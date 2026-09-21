from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import production.api.monitor_web as monitor_web
from production.api.security import session_detail_view


SESSION_ID = "session-detail-contract"


class DetailStorage:
    def __init__(
        self,
        *,
        present: bool = True,
        prediction_rows: list[dict[str, object]] | None = None,
        event_rows: list[dict[str, object]] | None = None,
    ) -> None:
        self.present = present
        self.prediction_rows = list(prediction_rows or [])
        self.event_rows = list(event_rows) if event_rows is not None else None
        self.calls: list[tuple[str, str, int]] = []
        self.global_reads = 0
        self.single_enrichment_reads = 0

    def list_rows_for_session(
        self,
        table: str,
        session_id: str,
        limit: int = 100,
    ) -> list[dict[str, object]]:
        assert session_id == SESSION_ID
        self.calls.append((table, session_id, limit))
        if table == "sessions":
            if not self.present:
                return []
            return [
                {
                    "session_id": SESSION_ID,
                    "src_ip": "192.0.2.10",
                    "updated_at": "2026-09-01T00:00:00Z",
                    "payload_json": json.dumps(
                        {
                            "session_id": SESSION_ID,
                            "src_ip": "192.0.2.10",
                            "sensor_id": "sensor-test",
                            "start_time": "2026-09-01T00:00:00Z",
                            "commands": ["id"],
                            "observed_trusted_ttps": ["T1033"],
                            "session_ttp_correlations": [
                                {"ttp": "T1059", "confidence": 0.5}
                            ],
                            "tactics": ["discovery"],
                        }
                    ),
                }
            ]
        if table == "events":
            if self.event_rows is not None:
                return self.event_rows
            return [
                {
                    "event_id": "event-detail-1",
                    "session_id": SESSION_ID,
                    "eventid": "cowrie.command.input",
                    "timestamp": "2026-09-01T00:00:01Z",
                    "received_at": "2026-09-01T00:00:02Z",
                    "payload_json": json.dumps(
                        {"eventid": "cowrie.command.input", "input": "id"}
                    ),
                }
            ]
        if table == "analysis_jobs":
            return [
                {
                    "job_id": "job-detail-1",
                    "session_id": SESSION_ID,
                    "status": "succeeded",
                    "updated_at": "2026-09-01T00:00:03Z",
                    "report_id": "report-detail-1",
                    "payload_json": "{}",
                }
            ]
        if table == "reports":
            return [
                {
                    "report_id": "report-detail-1",
                    "session_id": SESSION_ID,
                    "created_at": "2026-09-01T00:00:04Z",
                    "payload_json": json.dumps(
                        {"schema_version": "session_assessment.v4", "status": "complete"}
                    ),
                }
            ]
        if table == "prediction_snapshots":
            return self.prediction_rows
        if table in {"analyst_feedback", "observable_sightings"}:
            return []
        raise AssertionError(f"unexpected table: {table}")

    def list_rows(self, *_args, **_kwargs):
        self.global_reads += 1
        raise AssertionError("dashboard session detail must not perform a global read")

    def get_enrichment_record(self, *_args, **_kwargs):
        self.single_enrichment_reads += 1
        raise AssertionError("dashboard session detail must not perform enrichment fanout")


class BatchEnrichmentStorage:
    def __init__(self) -> None:
        self.batch_calls: list[list[tuple[str, str]]] = []
        self.single_calls = 0

    def list_enrichment_records_for_observables(self, observables, *, allow_stale=True):
        assert allow_stale is True
        self.batch_calls.append(list(observables))
        return [{"observable_type": "ip", "observable_value": "192.0.2.10"}]

    def list_rows_for_session(self, table, session_id, limit=100):
        assert table == "enrichment_jobs"
        return []

    def list_rows(self, table, limit=100):
        assert table == "enrichment_jobs"
        return []

    def get_enrichment_record(self, *_args, **_kwargs):
        self.single_calls += 1
        raise AssertionError("batch enrichment contract must not use single-record reads")


def _config(tmp_path: Path) -> monitor_web.MonitorConfig:
    return monitor_web.MonitorConfig(
        db_path="",
        database_url="sqlite:///:memory:",
        reports_dir=str(tmp_path / "reports"),
        production_config=SimpleNamespace(enable_response_guidance=True),
    )


def test_dashboard_detail_is_session_scoped_bounded_and_publicly_redacted(
    tmp_path: Path,
    monkeypatch,
) -> None:
    storage = DetailStorage()
    monkeypatch.setattr(monitor_web, "build_ensemble_from_session_payload", lambda *_args, **_kwargs: {})

    detail = monitor_web.load_dashboard_session_detail(
        _config(tmp_path), SESSION_ID, _storage=storage
    )
    public = session_detail_view(detail)
    compact = session_detail_view(detail, compact=True)

    assert detail["ok"] is True
    assert detail["schema_version"] == "monitor.dashboard_session_detail.v1"
    assert public["session_id"] == SESSION_ID
    assert [row["event_id"] for row in public["events"]] == ["event-detail-1"]
    assert public["overview"]["command_count"] == 1
    assert public["commands"] == ["[REDACTED]"]
    assert public["observed_trusted_ttps"] == ["T1033"]
    assert public["correlated_ttp_hypotheses"][0]["ttp"] == "T1059"
    assert public["response_guidance"]["requires_manual_approval"] is True
    assert public["response_guidance"]["safe_to_auto_execute"] is False
    assert compact["schema_version"] == "monitor.dashboard_session_detail.v1"
    assert compact["events"] == public["events"]
    assert compact["correlated_ttp_hypotheses"][0]["ttp"] == "T1059"
    assert "session_ttp_correlations" not in compact
    assert "classification_events" not in compact
    assert compact["response_guidance"]["requires_manual_approval"] is True
    assert compact["response_guidance"]["safe_to_auto_execute"] is False
    assert storage.global_reads == 0
    assert storage.single_enrichment_reads == 0
    assert {table for table, _, _ in storage.calls} == {
        "sessions",
        "events",
        "analysis_jobs",
        "reports",
        "analyst_feedback",
        "observable_sightings",
        "prediction_snapshots",
    }
    assert {table: limit for table, _, limit in storage.calls} == {
        "sessions": 1,
        "events": monitor_web.MAX_SESSION_EVENTS,
        "analysis_jobs": 50,
        "reports": 50,
        "analyst_feedback": 50,
        "observable_sightings": 100,
        "prediction_snapshots": 50,
    }
    serialized = json.dumps(public, sort_keys=True)
    assert "payload_json" not in serialized
    assert '"input": "id"' not in serialized
    compact_serialized = json.dumps(compact, sort_keys=True)
    assert "payload_json" not in compact_serialized
    assert '"input": "id"' not in compact_serialized


def test_compact_session_detail_includes_bounded_authentication_without_passwords(
    tmp_path: Path,
    monkeypatch,
) -> None:
    password_sentinel = "e2e-password-must-never-be-projected"
    storage = DetailStorage(
        event_rows=[
            {
                "event_id": "auth-success",
                "session_id": SESSION_ID,
                "eventid": "cowrie.login.success",
                "timestamp": "2026-09-01T00:00:01Z",
                "payload_json": json.dumps(
                    {
                        "eventid": "cowrie.login.success",
                        "session": SESSION_ID,
                        "timestamp": "2026-09-01T00:00:01Z",
                        "username": "observed-test-account",
                        "password": password_sentinel,
                    }
                ),
            }
        ]
    )
    monkeypatch.setattr(monitor_web, "build_ensemble_from_session_payload", lambda *_args, **_kwargs: {})

    detail = monitor_web.load_dashboard_session_detail(
        _config(tmp_path), SESSION_ID, _storage=storage
    )
    compact = session_detail_view(detail, compact=True)

    authentication = compact["authentication_activity"]
    assert authentication["attempt_count"] == 1
    assert authentication["success_count"] == 1
    assert authentication["failure_count"] == 0
    assert authentication["attempts"] == [
        {
            "outcome": "success",
            "timestamp": "2026-09-01T00:00:01Z",
            "username_visibility": "AVAILABLE",
            "attacker_username": "observed-test-account",
        }
    ]
    serialized = json.dumps(compact, sort_keys=True)
    assert password_sentinel not in serialized
    assert "password_values_suppressed" not in serialized
    assert "payload_json" not in serialized


def test_dashboard_detail_projects_bound_prediction_snapshot_and_model2(tmp_path: Path, monkeypatch) -> None:
    ensemble = {
        "schema_version": "model1_model2_late_evidence_ensemble.v1",
        "session_id": SESSION_ID,
        "model2": {
            "available": True,
            "one_model": True,
            "one_inference_call": True,
            "independent_binary_heads": False,
            "binding": {"session_id": SESSION_ID, "run_id": "run-bound"},
        },
    }
    storage = DetailStorage(
        prediction_rows=[
            {
                "snapshot_id": "snapshot-bound",
                "session_id": SESSION_ID,
                "created_at": "2026-09-01T00:00:05Z",
                "payload_json": json.dumps(
                    {
                        "session_id": SESSION_ID,
                        "generated_at": "2026-09-01T00:00:05Z",
                        "ensemble_evidence": ensemble,
                    }
                ),
            }
        ]
    )

    def unexpected_live_lookup(*_args, **_kwargs):
        raise AssertionError("available session-bound Model2 evidence must be reused")

    monkeypatch.setattr(monitor_web, "build_ensemble_from_session_payload", unexpected_live_lookup)
    detail = monitor_web.load_dashboard_session_detail(
        _config(tmp_path), SESSION_ID, _storage=storage
    )
    public = session_detail_view(detail, compact=True)

    assert detail["ensemble_evidence"] == ensemble
    assert detail["latest_prediction_snapshot"]["snapshot_id"] == "snapshot-bound"
    assert public["ensemble_evidence"]["model2"]["available"] is True
    assert public["latest_prediction_snapshot"]["snapshot_id"] == "snapshot-bound"
    assert public["prediction_snapshots"][0]["generated_at"] == "2026-09-01T00:00:05Z"


def test_dashboard_detail_uses_exact_session_live_model2_when_snapshot_missing(tmp_path: Path, monkeypatch) -> None:
    ensemble = {
        "schema_version": "model1_model2_late_evidence_ensemble.v1",
        "session_id": SESSION_ID,
        "model2": {
            "available": True,
            "one_model": True,
            "one_inference_call": True,
            "independent_binary_heads": False,
            "binding": {"session_id": SESSION_ID, "run_id": "run-bound"},
        },
    }
    monkeypatch.setattr(
        monitor_web,
        "build_ensemble_from_session_payload",
        lambda payload, *, computed_at: ensemble if payload.get("session_id") == SESSION_ID else {},
    )
    detail = monitor_web.load_dashboard_session_detail(
        _config(tmp_path), SESSION_ID, _storage=DetailStorage()
    )

    assert detail["ensemble_evidence"] == ensemble
    assert detail["prediction_snapshots"] == []
    assert detail["latest_prediction_snapshot"] == {}


def test_dashboard_detail_rejects_cross_session_model2_snapshot(tmp_path: Path, monkeypatch) -> None:
    storage = DetailStorage(
        prediction_rows=[
            {
                "snapshot_id": "snapshot-cross-session",
                "session_id": SESSION_ID,
                "created_at": "2026-09-01T00:00:05Z",
                "payload_json": json.dumps(
                    {
                        "session_id": SESSION_ID,
                        "ensemble_evidence": {
                            "session_id": SESSION_ID,
                            "model2": {
                                "available": True,
                                "binding": {
                                    "session_id": "another-session",
                                    "run_id": "run-other",
                                },
                            },
                        },
                    }
                ),
            }
        ]
    )
    monkeypatch.setattr(monitor_web, "build_ensemble_from_session_payload", lambda *_args, **_kwargs: {})

    detail = monitor_web.load_dashboard_session_detail(
        _config(tmp_path), SESSION_ID, _storage=storage
    )

    assert detail["ensemble_evidence"] == {}
    assert detail["prediction_snapshots"][0]["session_id"] == SESSION_ID


def test_dashboard_detail_missing_and_malformed_identity_fail_closed(tmp_path: Path) -> None:
    config = _config(tmp_path)
    missing = monitor_web.load_dashboard_session_detail(
        config, SESSION_ID, _storage=DetailStorage(present=False)
    )
    assert missing["ok"] is False
    assert missing["error_code"] == "session_not_found"

    assert monitor_web.load_dashboard_session_detail(config, "", _storage=DetailStorage())["error_code"] == "missing_session_id"
    assert monitor_web.load_dashboard_session_detail(config, "bad\nidentity", _storage=DetailStorage())["error_code"] == "malformed_session_id"


def test_dashboard_detail_guidance_defaults_to_manual_only() -> None:
    guidance = monitor_web._fail_closed_session_guidance("session-safe", {})

    assert guidance["requires_manual_approval"] is True
    assert guidance["safe_to_auto_execute"] is False
    assert guidance["authority"] == "policy_unavailable"


def test_legacy_enrichment_projection_uses_one_bounded_batch_lookup() -> None:
    storage = BatchEnrichmentStorage()

    records, jobs, error = monitor_web._storage_enrichment_rows(
        storage,
        SESSION_ID,
        [("ip", "192.0.2.10"), ("domain", "example.invalid")],
    )

    assert error == ""
    assert len(records) == 1
    assert jobs == []
    assert storage.batch_calls == [[("ip", "192.0.2.10"), ("domain", "example.invalid")]]
    assert storage.single_calls == 0


def test_mongodb_session_detail_allowlist_contains_only_explicit_session_tables() -> None:
    from production.storage.mongodb_operations import _SESSION_TABLES

    assert {"sessions", "events", "reports", "analysis_jobs", "prediction_snapshots"} <= _SESSION_TABLES
    assert "campaigns" not in _SESSION_TABLES
    assert "enrichment_records" not in _SESSION_TABLES
