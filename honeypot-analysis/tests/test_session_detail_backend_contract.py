from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import production.api.monitor_web as monitor_web
from production.api.security import _compact_session_guidance, session_detail_view
import production.prediction_next_distinct_poc.dashboard_adapter as next_distinct_adapter


SESSION_ID = "session-detail-contract"


class DetailStorage:
    def __init__(
        self,
        *,
        present: bool = True,
        prediction_rows: list[dict[str, object]] | None = None,
        event_rows: list[dict[str, object]] | None = None,
        session_payload_extra: dict[str, object] | None = None,
        report_payload_extra: dict[str, object] | None = None,
    ) -> None:
        self.present = present
        self.prediction_rows = list(prediction_rows or [])
        self.event_rows = list(event_rows) if event_rows is not None else None
        self.session_payload_extra = dict(session_payload_extra or {})
        self.report_payload_extra = dict(report_payload_extra or {})
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
                    **self.session_payload_extra,
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
                        {
                            "schema_version": "session_assessment.v4",
                            "status": "complete",
                            **self.report_payload_extra,
                        }
                    ),
                }
            ]
        if table == "prediction_snapshots":
            return self.prediction_rows
        if table in {"analyst_feedback", "observable_sightings", "enrichment_jobs"}:
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
    assert compact["classification_events"] == []
    assert compact["observed_tactic_path"] == []
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


def test_session_model1_advisory_matches_full_and_compact_projection(
    tmp_path: Path, monkeypatch,
) -> None:
    monkeypatch.setattr(monitor_web, "build_ensemble_from_session_payload", lambda *_args, **_kwargs: {})
    classification = {
        "session_id": SESSION_ID,
        "compound_command_index": 0,
        "evidence_id": "class-one",
        "event_timestamp": "2026-09-01T00:00:01Z",
        "command": "private command text",
        "s1_advisory": {
            "status": "loaded", "predicted_technique": "T1033",
            "score_type": "linear_svc_decision_margin",
            "decision_score": 0.7,
        },
    }
    storage = DetailStorage(session_payload_extra={"classification_events": [classification, dict(classification, evidence_id="class-two")]})
    detail = monitor_web.load_dashboard_session_detail(_config(tmp_path), SESSION_ID, _storage=storage)
    full = session_detail_view(detail)
    compact = session_detail_view(detail, compact=True)
    assert full["session_ttp_advisory"] == compact["session_ttp_advisory"]
    advisory = full["session_ttp_advisory"]
    assert advisory["assessed_command_events"] == 1
    assert advisory["techniques"][0]["supporting_command_events"] == 1
    assert "private command text" not in json.dumps(advisory)
    assert "decision_score" not in json.dumps(advisory)


def test_dashboard_detail_merges_hypothesis_sets_from_report_artifact(
    tmp_path: Path,
    monkeypatch,
) -> None:
    reports_dir = tmp_path / "reports"
    reports_dir.mkdir()
    artifact_path = reports_dir / "session-detail-contract_report.json"
    artifact_path.write_text(
        json.dumps(
            {
                "schema_version": "session_assessment.v4",
                "canonical_evidence": {"entities": []},
                "hypothesis_sets": [
                    {
                        "hypothesis_set_id": "hypothesis-set-1",
                        "question": "What explains the observed sequence?",
                        "scope": "session",
                        "hypotheses": [
                            {
                                "hypothesis_id": "hypothesis-1",
                                "statement": "The activity may have stopped before execution.",
                                "status": "bounded_alternative",
                                "supporting_evidence_refs": ["event-detail-1"],
                                "falsification_conditions": ["Observe a bound execution event."],
                            }
                        ],
                    }
                ],
                "session_hypothesis_assessment": {
                    "schema_version": "session_hypothesis_assessment.v1",
                    "status": "findings_available",
                    "hypothesis_set_ids": ["hypothesis-set-1"],
                },
            }
        ),
        encoding="utf-8",
    )
    storage = DetailStorage(
        report_payload_extra={"artifacts": {"json": str(artifact_path)}}
    )
    monkeypatch.setattr(
        monitor_web,
        "build_ensemble_from_session_payload",
        lambda *_args, **_kwargs: {},
    )

    detail = monitor_web.load_dashboard_session_detail(
        _config(tmp_path), SESSION_ID, _storage=storage
    )
    compact = session_detail_view(detail, compact=True)

    assert detail["hypothesis_sets"][0]["hypothesis_set_id"] == "hypothesis-set-1"
    assert compact["hypothesis_sets"][0]["hypotheses"][0]["hypothesis_id"] == "hypothesis-1"
    assert compact["session_hypothesis_assessment"]["hypothesis_set_ids"] == [
        "hypothesis-set-1"
    ]


def test_dashboard_detail_end_time_uses_latest_event_not_storage_row_order(
    tmp_path: Path,
    monkeypatch,
) -> None:
    storage = DetailStorage(
        event_rows=[
            {
                "event_id": "event-latest",
                "session_id": SESSION_ID,
                "eventid": "cowrie.session.closed",
                "timestamp": "2026-09-01T00:00:12Z",
                "payload_json": json.dumps(
                    {"eventid": "cowrie.session.closed", "timestamp": "2026-09-01T00:00:12Z"}
                ),
            },
            {
                "event_id": "event-earliest",
                "session_id": SESSION_ID,
                "eventid": "cowrie.session.connect",
                "timestamp": "2026-09-01T00:00:00Z",
                "payload_json": json.dumps(
                    {"eventid": "cowrie.session.connect", "timestamp": "2026-09-01T00:00:00Z"}
                ),
            },
        ],
        session_payload_extra={"ended": True, "is_ended": True, "duration": 37.5},
    )
    monkeypatch.setattr(
        monitor_web,
        "build_ensemble_from_session_payload",
        lambda *_args, **_kwargs: {},
    )

    detail = monitor_web.load_dashboard_session_detail(
        _config(tmp_path), SESSION_ID, _storage=storage
    )

    assert detail["overview"]["end_time"] == "2026-09-01T00:00:12Z"
    assert detail["overview"]["duration"] == 12.0
    assert detail["overview"]["recorded_duration"] == 37.5


def test_compact_guidance_preserves_safe_manual_action_content_only() -> None:
    credential_sentinel = "credential-value-must-not-cross-read-model"
    guidance = _compact_session_guidance(
        {
            "schema_version": "response_guidance.v3",
            "status": "available",
            "authority": "deterministic_observed_evidence_policy",
            "requires_manual_approval": True,
            "safe_to_auto_execute": False,
            "findings": [
                {
                    "finding_id": "finding-1",
                    "finding_type": "authentication_review",
                    "severity": "medium",
                    "statement": "Review the observed authentication activity.",
                    "rule_id": "rule-auth-review",
                    "evidence_status": "observed",
                    "evidence_refs": [credential_sentinel],
                }
            ],
            "advisory_actions": [
                {
                    "action_id": "action-1",
                    "description": "Review the authenticated source in authorized logs.",
                    "rationale": "Confirm whether the activity repeats or escalates.",
                    "rule_id": "rule-auth-review",
                    "priority": "P20",
                    "preconditions": ["Use the exact session time window."],
                    "verification_steps": ["Record the analyst review outcome."],
                    "requires_manual_approval": True,
                    "safe_to_auto_execute": False,
                    "evidence_refs": [credential_sentinel],
                    "command": credential_sentinel,
                }
            ],
        }
    )

    assert guidance["finding_count"] == 1
    assert guidance["advisory_action_count"] == 1
    assert guidance["findings"] == [
        {
            "finding_id": "finding-1",
            "finding_type": "authentication_review",
            "severity": "medium",
            "statement": "Review the observed authentication activity.",
            "rule_id": "rule-auth-review",
            "evidence_status": "observed",
        }
    ]
    assert guidance["advisory_actions"] == [
        {
            "action_id": "action-1",
            "description": "Review the authenticated source in authorized logs.",
            "rationale": "Confirm whether the activity repeats or escalates.",
            "rule_id": "rule-auth-review",
            "priority": "P20",
            "preconditions": ["Use the exact session time window."],
            "verification_steps": ["Record the analyst review outcome."],
            "requires_manual_approval": True,
            "safe_to_auto_execute": False,
        }
    ]
    serialized = json.dumps(guidance, sort_keys=True)
    assert credential_sentinel not in serialized
    assert "evidence_refs" not in serialized
    assert "command" not in guidance["advisory_actions"][0]


def test_cwd_history_projects_canonical_cowrie_event_without_payload_text(tmp_path: Path) -> None:
    command_sentinel = "cd /tmp && cat secret.txt"
    storage = DetailStorage(
        event_rows=[
            {
                "event_id": "cwd-event-1",
                "session_id": SESSION_ID,
                "eventid": "cowrie.session.cwd",
                "timestamp": "2026-09-01T00:00:01Z",
                "payload_json": json.dumps(
                    {
                        "eventid": "cowrie.session.cwd",
                        "cwd": "/tmp",
                        "oldcwd": "/home/test",
                        "input": command_sentinel,
                    }
                ),
            }
        ]
    )

    history = monitor_web.load_session_cwd_history(
        _config(tmp_path), SESSION_ID, _storage=storage
    )
    assert history["ok"] is True
    assert history["source"] == "canonical_events"
    assert history["totalItems"] == 1
    assert history["totalSuccessfulItems"] == 1
    assert history["items"] == [
        {
            "sessionId": SESSION_ID,
            "at": "2026-09-01T00:00:01Z",
            "eventId": "cwd-event-1",
            "sequence": 1,
            "fromPath": "/home/test",
            "toPath": "/tmp",
            "action": "changed",
            "status": "observed",
            "sourceEventId": "cwd-event-1",
        }
    ]
    assert command_sentinel not in json.dumps(history, sort_keys=True)

    hop = monitor_web.load_session_cwd_history(
        _config(tmp_path), SESSION_ID, hop="cwd-event-1", _storage=storage
    )
    assert hop["item"]["toPath"] == "/tmp"
    assert hop["hopNumber"] == 1


def test_cwd_history_projects_cowrie_before_after_fields(tmp_path: Path) -> None:
    storage = DetailStorage(
        event_rows=[
            {
                "event_id": "cwd-event-before-after",
                "session_id": SESSION_ID,
                "eventid": "cowrie.session.cwd",
                "timestamp": "2026-09-01T00:00:02Z",
                "payload_json": json.dumps(
                    {
                        "eventid": "cowrie.session.cwd",
                        "cwd_before": "/home/test",
                        "cwd_after": "/tmp",
                    }
                ),
            }
        ]
    )

    history = monitor_web.load_session_cwd_history(
        _config(tmp_path), SESSION_ID, _storage=storage
    )

    assert history["ok"] is True
    assert history["totalItems"] == 1
    assert history["items"][0]["fromPath"] == "/home/test"
    assert history["items"][0]["toPath"] == "/tmp"
    assert history["items"][0]["action"] == "changed"


def test_compact_session_detail_exposes_bounded_classification_chain_without_command_text() -> None:
    command_sentinel = "classification-command-must-not-cross-api-boundary"
    detail = {
        "ok": True,
        "schema_version": "monitor.dashboard_session_detail.v1",
        "session_id": "session-classification-chain",
        "overview": {},
        "events_table_rows": [],
        "classification_events": [
            {
                "evidence_id": "classification-1",
                "event_id": "event-1",
                "event_timestamp": "2026-09-01T00:00:01Z",
                "ttp": "T1082.001",
                "tactic": "discovery",
                "name": "System Information Discovery",
                "source": "reviewed_classifier",
                "evidence_tier": "trusted_observation",
                "command": command_sentinel,
                "source_command": command_sentinel,
                "original_command": command_sentinel,
                "traceability": {
                    "event_id": "event-1",
                    "source_commands": [command_sentinel],
                },
                "durable_evidence_order": {"event_id": "event-1", "event_index": 0},
            }
        ],
        "observed_tactic_path": [
            {
                "tactic": "discovery",
                "techniques": ["T1082"],
                "event_ids": ["event-1"],
                "commands": [command_sentinel],
            },
            {"tactic": "execution", "techniques": ["T1059"]},
        ],
        "observed_trusted_ttps": [
            {"technique_id": "T1082.001", "tactics": ["discovery"], "commands": [command_sentinel]}
        ],
        "session_payload": {"session_id": "session-classification-chain"},
    }

    compact = session_detail_view(detail, compact=True)

    assert compact["classification_events"] == [
        {
            "evidence_id": "classification-1",
            "event_id": "event-1",
            "event_timestamp": "2026-09-01T00:00:01Z",
            "ttp": "T1082",
            "tactic": "discovery",
            "name": "System Information Discovery",
            "source": "reviewed_classifier",
            "evidence_tier": "trusted_observation",
            "durable_evidence_order": {"event_id": "event-1", "event_index": 0},
            "traceability": {"event_id": "event-1"},
        }
    ]
    assert compact["observed_tactic_path"] == [
        {"tactic": "discovery", "technique_count": 1, "event_count": 1},
        {"tactic": "execution", "technique_count": 1},
    ]
    assert compact["observed_trusted_ttps"][0]["technique_id"] == "T1082"
    serialized = json.dumps(compact, sort_keys=True)
    assert command_sentinel not in serialized
    assert all(
        key not in compact["classification_events"][0]
        for key in ("command", "source_command", "original_command")
    )
    assert "source_commands" not in compact["classification_events"][0]["traceability"]
    assert "commands" not in compact["observed_tactic_path"][0]
    assert "commands" not in compact["observed_trusted_ttps"][0]


def test_public_session_detail_normalizes_legacy_disabled_classifier_marker() -> None:
    detail = {
        "ok": True,
        "schema_version": "monitor.dashboard_session_detail.v1",
        "session_id": "session-disabled-classifier",
        "overview": {},
        "events_table_rows": [],
        "classification_events": [
            {
                "event_id": "event-legacy-model",
                "source": "securebert_unavailable",
                "name": "SecureBERT unavailable",
                "evidence_type": "securebert",
                "authority_decision": {"reasons": ["securebert_unavailable"]},
            }
        ],
        "session_payload": {"session_id": "session-disabled-classifier"},
    }

    compact = session_detail_view(detail, compact=True)
    serialized = json.dumps(compact, sort_keys=True).lower()
    assert "securebert" not in serialized
    assert compact["classification_events"][0]["source"] == "unclassified"
    assert compact["classification_events"][0]["evidence_type"] == "unclassified"


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


def test_dashboard_detail_and_next_distinct_share_the_same_sidecar_projection(
    tmp_path: Path,
    monkeypatch,
) -> None:
    sidecar_projection = {
        "schema_version": "dashboard_next_distinct_prediction.v1",
        "prediction_type": "NEXT_DISTINCT_TRUSTED_TACTIC",
        "dashboard_source": "NEXT_DISTINCT_POC",
        "source": "NEXT_DISTINCT_POC",
        "authority": "NON_AUTHORITATIVE_ADVISORY",
        "canonical_write_allowed": False,
        "model": {
            "model_identifier": "finalf_refined_v1_prediction_only",
            "checkpoint_sha256": "a" * 64,
        },
        "history": {"trusted_only": True, "length": 1},
        "prediction": [{"tactic": "discovery", "score": 0.9}],
        "top1": "discovery",
        "top3": ["discovery"],
        "probabilities": [0.9],
        "generated_at": "2026-09-01T00:00:05Z",
        "freshness": {
            "state": "FRESH",
            "generated_at": "2026-09-01T00:00:05Z",
            "history_manifest_match": True,
        },
        "prediction_status": "PREDICTED",
        "prediction_status_reason": "latest eligible sidecar progression",
        "progression_index": 3,
        "sequence_id": SESSION_ID,
    }
    monkeypatch.setattr(
        monitor_web,
        "build_dashboard_prediction",
        lambda session_id, _row: dict(sidecar_projection, sequence_id=session_id),
    )
    storage = DetailStorage()
    detail = monitor_web.load_dashboard_session_detail(
        _config(tmp_path), SESSION_ID, _storage=storage
    )
    dedicated = monitor_web.load_next_distinct_prediction(
        _config(tmp_path), SESSION_ID, _storage=storage
    )
    dedicated = monitor_web._dashboard_next_distinct_projection(
        dedicated,
        SESSION_ID,
    )
    row = detail["latest_prediction_snapshot"]
    payload = row["payload"]

    assert detail["next_distinct_prediction"]["source"] == "NEXT_DISTINCT_POC"
    assert payload["source"] == dedicated["source"]
    assert payload["prediction_status"] == dedicated["prediction_status"]
    assert payload["next_distinct_tactic"] == dedicated["next_distinct_tactic"]
    assert payload["freshness"] == dedicated["freshness"]
    assert payload["read_only"] is True
    assert payload["advisory_only"] is True
    public = session_detail_view(detail, compact=True)
    assert public["latest_prediction_snapshot"]["source"] == "NEXT_DISTINCT_POC"
    assert public["next_distinct_prediction"]["top1"] == dedicated["top1"]


def test_dashboard_detail_prefers_bound_terminal_session_model2_over_stale_snapshot(
    tmp_path: Path,
    monkeypatch,
) -> None:
    terminal_ensemble = {
        "schema_version": "model1_model2_late_evidence_ensemble.v1",
        "session_id": SESSION_ID,
        "model2": {
            "available": True,
            "one_model": True,
            "one_inference_call": True,
            "independent_binary_heads": False,
            "binding": {"session_id": SESSION_ID, "run_id": "terminal-run"},
        },
    }
    stale_snapshot = {
        "schema_version": "model1_model2_late_evidence_ensemble.v1",
        "session_id": SESSION_ID,
        "model2": {
            "available": False,
            "status": "INCONCLUSIVE_EXPERIMENTAL_SHADOW",
        },
    }
    storage = DetailStorage(
        prediction_rows=[
            {
                "snapshot_id": "snapshot-stale",
                "session_id": SESSION_ID,
                "created_at": "2026-09-01T00:00:05Z",
                "payload_json": json.dumps(
                    {"session_id": SESSION_ID, "ensemble_evidence": stale_snapshot}
                ),
            }
        ],
        session_payload_extra={"ensemble_evidence": terminal_ensemble},
    )
    monkeypatch.setattr(
        monitor_web,
        "build_ensemble_from_session_payload",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("bound terminal Model2 evidence must be reused")
        ),
    )

    detail = monitor_web.load_dashboard_session_detail(
        _config(tmp_path), SESSION_ID, _storage=storage
    )

    assert detail["ensemble_evidence"] == terminal_ensemble


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


def test_next_distinct_reads_recent_session_record_from_large_append_only_file(
    tmp_path: Path,
    monkeypatch,
) -> None:
    records_path = tmp_path / "records.jsonl"
    prefix = '{"sequence_id":"other","padding":"' + ("x" * (9 * 1024 * 1024)) + '"}\n'
    target = {
        "sequence_id": SESSION_ID,
        "progression_index": 7,
        "recorded_at": 100.0,
    }
    records_path.write_text(prefix + json.dumps(target) + "\n", encoding="utf-8")
    monkeypatch.setattr(next_distinct_adapter, "_validate_predictor", lambda _value: {})

    stats = {}
    result, error = next_distinct_adapter._read_latest_record(
        records_path,
        SESSION_ID,
        stats=stats,
    )

    assert error is None
    assert result == target
    assert stats["bytes_read"] <= next_distinct_adapter.MAX_LOOKUP_BYTES
    assert stats["records_scanned"] == 1


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
