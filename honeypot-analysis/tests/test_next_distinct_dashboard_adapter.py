from __future__ import annotations

import io
import json
import time
from http import HTTPStatus
from pathlib import Path

import production.api.dashboard_api as dashboard_api
import production.api.monitor_web as monitor_web

from production.prediction.trusted_history import build_prediction_trusted_history_manifest
from production.prediction_next_distinct_poc.dashboard_adapter import (
    EXPECTED_CHECKPOINT,
    EXPECTED_MODEL,
    build_dashboard_prediction,
)

SESSION_ID = "session_v1_0123456789abcdef0123456789abcdef"


def _manifest():
    phase = {
        "start_command_index": 0,
        "end_command_index": 0,
        "event_id": "evt-1",
        "start_timestamp": "2026-09-04T00:00:00.000000+00:00",
        "end_timestamp": "2026-09-04T00:00:01.000000+00:00",
        "observation_count": 1,
        "tactics": ["discovery"],
        "techniques": ["T1087"],
        "labels": [{
            "tactic": "discovery",
            "technique": "T1087",
            "source": "reviewed_rule",
            "agreement_status": "agreed",
            "confidence": 0.99,
            "classification_evidence_id": "evt-1",
        }],
        "command_outcomes": [],
        "outcome_scopes": [],
        "fragment_execution_states": [],
        "evidence_refs": [],
    }
    return build_prediction_trusted_history_manifest(
        phases=[phase],
        evidence_cutoff={
            "schema_version": "prediction_evidence_cutoff.v1",
            "received_at": "2026-09-04T00:00:01.000000+00:00",
            "event_id": "evt-1",
        },
        classifier_environment={"environment_sha256": "a" * 64},
    )


def _session_row(manifest=None):
    return {"session_id": SESSION_ID, "payload": {"prediction_trusted_history_manifest": manifest or _manifest()}}


def _record(progression=1, recorded_at=100.0, *, checkpoint=EXPECTED_CHECKPOINT, history=None):
    probabilities = [0.01, 0.02, 0.03, 0.10, 0.70, 0.08, 0.06]
    return {
        "schema_version": "gcp_cowrie_shadow_prediction_record.v2",
        "prediction_id": "prediction-" + str(progression),
        "sequence_id": SESSION_ID,
        "progression_index": progression,
        "history": history or ["discovery"],
        "history_length": len(history or ["discovery"]),
        "session_ended": False,
        "updated_at": "2026-09-04T00:00:01.000000+00:00",
        "revision": progression,
        "evidence_cutoff_sha256": "b" * 64,
        "history_manifest_sha256": _manifest()["history_manifest_sha256"],
        "predictor": {
            "task": "next_observed_distinct_tactic",
            "model_ready": True,
            "authority": "non_authoritative",
            "canonical_write_allowed": False,
            "model_identifier": EXPECTED_MODEL,
            "checkpoint_sha256": checkpoint,
            "calibrated": True,
            "top1": "execution",
            "top3": ["execution", "discovery", "persistence"],
            "probabilities": probabilities,
            "calibration": {"method": "temperature_scaled_softmax.v1", "temperature": 0.6990670591704266},
        },
        "recorded_at": recorded_at,
    }


def _write_records(root: Path, records):
    root.mkdir(exist_ok=True)
    (root / "records.jsonl").write_text("".join(json.dumps(item) + "\n" for item in records), encoding="utf-8")


def test_current_record_maps_to_versioned_final_poc_contract(tmp_path):
    _write_records(tmp_path, [_record()])
    result = build_dashboard_prediction(SESSION_ID, _session_row(), shadow_root=tmp_path, now=100.5)
    assert result["schema_version"] == "dashboard_next_distinct_prediction.v1"
    assert result["dashboard_source"] == "FINAL_POC"
    assert result["prediction_type"] == "NEXT_DISTINCT_TRUSTED_TACTIC"
    assert result["prediction_status"] == "PREDICTED"
    assert result["model"]["checkpoint_sha256"] == EXPECTED_CHECKPOINT
    assert result["history"]["trusted_only"] is True
    assert result["prediction"][0]["tactic"] == "execution"
    assert result["prediction"][0]["score_semantics"] == "temperature_scaled_softmax_probability"
    assert result["canonical_write_allowed"] is False


def test_latest_progression_wins_over_file_order(tmp_path):
    _write_records(tmp_path, [_record(2, 102.0), _record(1, 101.0), _record(3, 103.0)])
    result = build_dashboard_prediction(SESSION_ID, _session_row(), shadow_root=tmp_path, now=103.1)
    assert result["progression_index"] == 3


def test_no_trusted_history_is_explicit_and_does_not_read_legacy_snapshot(tmp_path):
    _write_records(tmp_path, [_record()])
    row = {"session_id": SESSION_ID, "payload": {}}
    result = build_dashboard_prediction(SESSION_ID, row, shadow_root=tmp_path, now=100.0)
    assert result["prediction_status"] == "NO_TRUSTED_HISTORY"
    assert result["prediction"] == []
    assert result["dashboard_source"] == "FINAL_POC"


def test_stale_age_and_manifest_advance_are_visible(tmp_path):
    record = _record(1, 1.0)
    _write_records(tmp_path, [record])
    result = build_dashboard_prediction(SESSION_ID, _session_row(), shadow_root=tmp_path, now=5000.0)
    assert result["prediction_status"] == "STALE"
    assert result["freshness"]["state"] == "STALE"


def test_bad_checkpoint_and_malformed_rows_are_unavailable(tmp_path):
    _write_records(tmp_path, [_record(checkpoint="c" * 64), {"not": "a prediction"}])
    result = build_dashboard_prediction(SESSION_ID, _session_row(), shadow_root=tmp_path, now=100.0)
    assert result["prediction_status"] == "UNAVAILABLE"
    assert "eligible sidecar" in result["prediction_status_reason"]


def test_model_not_ready_is_fail_closed(tmp_path):
    record = _record()
    record["predictor"]["model_ready"] = False
    _write_records(tmp_path, [record])
    result = build_dashboard_prediction(SESSION_ID, _session_row(), shadow_root=tmp_path, now=100.0)
    assert result["prediction_status"] == "UNAVAILABLE"
    assert "eligible sidecar" in result["prediction_status_reason"]


def test_unsupported_record_schema_is_fail_closed(tmp_path):
    record = _record()
    record["schema_version"] = "gcp_cowrie_shadow_prediction_record.v999"
    _write_records(tmp_path, [record])
    result = build_dashboard_prediction(SESSION_ID, _session_row(), shadow_root=tmp_path, now=100.0)
    assert result["prediction_status"] == "UNAVAILABLE"
    assert result["prediction"] == []


def test_session_end_is_not_a_final_poc_output(tmp_path):
    record = _record()
    record["predictor"]["top1"] = "SESSION_END"
    record["predictor"]["top3"] = ["SESSION_END", "execution", "discovery"]
    _write_records(tmp_path, [record])
    result = build_dashboard_prediction(SESSION_ID, _session_row(), shadow_root=tmp_path, now=100.0)
    assert result["prediction_status"] == "UNAVAILABLE"
    assert result["prediction"] == []


def test_monitor_renderer_does_not_fallback_to_legacy_prediction_snapshots():
    renderer = Path(monitor_web.__file__).with_name("static") / "monitor.html"
    source = renderer.read_text(encoding="utf-8")
    assert "const finalRanking = Array.isArray(cp.prediction) ? cp.prediction : [];" in source
    assert "const ranking = snapshots[0]?.payload?.final_ranking || [];" not in source


def test_manifest_integrity_rejection_is_fail_closed(tmp_path):
    manifest = _manifest()
    manifest["history_manifest_sha256"] = "d" * 64
    _write_records(tmp_path, [_record()])
    result = build_dashboard_prediction(SESSION_ID, _session_row(manifest), shadow_root=tmp_path, now=100.0)
    assert result["prediction_status"] == "UNAVAILABLE"
    assert "trusted history rejected" in result["prediction_status_reason"]


def test_missing_sidecar_is_unavailable_without_mutation(tmp_path):
    before = sorted(tmp_path.iterdir())
    result = build_dashboard_prediction(SESSION_ID, _session_row(), shadow_root=tmp_path, now=100.0)
    assert result["prediction_status"] == "UNAVAILABLE"
    assert sorted(tmp_path.iterdir()) == before
    assert result["canonical_write_allowed"] is False


def test_monitor_current_route_uses_final_poc_without_legacy_snapshot(monkeypatch):
    class RouteStorage:
        def get_session(self, session_id):
            return _session_row()

        def get_current_prediction_snapshot(self, session_id):
            raise AssertionError("legacy prediction snapshot must not be read")

    storage = RouteStorage()
    monkeypatch.setattr(monitor_web, "_open_monitor_storage", lambda _config: storage)
    monkeypatch.setattr(
        monitor_web,
        "build_dashboard_prediction",
        lambda session_id, row: {
            "schema_version": "dashboard_next_distinct_prediction.v1",
            "dashboard_source": "FINAL_POC",
            "prediction_status": "PREDICTED",
            "prediction": [{"tactic": "execution", "score": 0.7}],
        },
    )
    config = monitor_web.MonitorConfig(
        db_path="", database_url="sqlite:///:memory:", reports_dir="", enable_response_guidance=False
    )
    status, payload = monitor_web._dashboard_get_payload(
        config, "/predictions/current", {"session_id": [SESSION_ID]}
    )
    assert status == HTTPStatus.OK
    assert payload["prediction_source"] == "FINAL_POC"
    assert payload["item"]["source"] == "FINAL_POC"
    assert payload["current_prediction"]["prediction_status"] == "PREDICTED"


def test_dashboard_api_handler_current_route_uses_final_poc(monkeypatch):
    class RouteStorage:
        def get_session(self, session_id):
            return _session_row()

        def get_current_prediction_snapshot(self, session_id):
            raise AssertionError("legacy prediction snapshot must not be read")

    storage = RouteStorage()
    monkeypatch.setattr(
        dashboard_api,
        "build_dashboard_prediction",
        lambda session_id, row: {
            "schema_version": "dashboard_next_distinct_prediction.v1",
            "dashboard_source": "FINAL_POC",
            "prediction_status": "NO_TRUSTED_HISTORY",
            "prediction": [],
        },
    )
    config = type("Config", (), {
        "dashboard_host": "127.0.0.1",
        "dashboard_read_token": "",
        "dashboard_write_token": "",
        "enable_response_guidance": False,
    })()
    handler = object.__new__(dashboard_api.DashboardHandler)
    handler.config = config
    handler.path = "/predictions/current?session_id=" + SESSION_ID
    handler.command = "GET"
    handler.client_address = ("127.0.0.1", 54321)
    handler.headers = {"X-Request-ID": "route-request"}
    handler.rfile = io.BytesIO()
    handler.server = type("Server", (), {"storage": storage})()
    responses = []
    handler._send_json = lambda status, payload: responses.append((status, payload))
    dashboard_api.DashboardHandler.do_GET(handler)
    assert responses[0][0] == HTTPStatus.OK
    assert responses[0][1]["prediction_source"] == "FINAL_POC"
    assert responses[0][1]["current_prediction"]["dashboard_source"] == "FINAL_POC"


def test_monitor_route_maps_real_sidecar_fixture_to_dashboard_contract(tmp_path, monkeypatch):
    _write_records(tmp_path, [_record(progression=4, recorded_at=time.time())])

    class RouteStorage:
        def get_session(self, session_id):
            return _session_row()

    monkeypatch.setenv("NEXT_DISTINCT_SHADOW_ROOT", str(tmp_path))
    monkeypatch.setattr(monitor_web, "_open_monitor_storage", lambda _config: RouteStorage())
    config = monitor_web.MonitorConfig(
        db_path="", database_url="sqlite:///:memory:", reports_dir="", enable_response_guidance=False
    )
    status, payload = monitor_web._dashboard_get_payload(
        config, "/predictions/current", {"session_id": [SESSION_ID]}
    )
    assert status == HTTPStatus.OK
    assert payload["prediction_source"] == "FINAL_POC"
    assert payload["current_prediction"]["prediction_status"] == "PREDICTED"
    assert payload["current_prediction"]["progression_index"] == 4
    assert payload["current_prediction"]["model"]["temperature"] == 0.6990670591704266
