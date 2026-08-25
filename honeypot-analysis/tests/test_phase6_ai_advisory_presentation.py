from __future__ import annotations

from production.api.monitor_web import MonitorConfig, load_ai_advisory_detail
from production.ai_advisory.provider import AIProviderResponse
from production.ai_advisory.contracts import sha256_json
from production.storage.backend import SQLiteStorage
from production.workers.ai_advisory_worker import AIAdvisoryWorker
from tests.test_phase5_ai_integration_v2 import (
    _V2Provider,
    _config,
    _report,
    _storage_with_report,
)


class _RejectedV2Provider(_V2Provider):
    def generate(self, projection, **kwargs):
        del kwargs
        self.calls += 1
        output = {"schema_version": "ai_provider_output.v2"}
        return AIProviderResponse(
            provider_id=self.provider_id,
            model_id=self.model_id,
            structured_output=output,
            response_sha256=sha256_json(output),
            adapter_revision=self.adapter_revision,
        )


def _monitor_config() -> MonitorConfig:
    return MonitorConfig(db_path=":memory:", reports_dir="reports")


def test_v2_api_is_versioned_graph_grounded_and_shadow_free(tmp_path) -> None:
    report = _report("phase6-v2-api")
    storage, _ = _storage_with_report(tmp_path, report)
    worker = AIAdvisoryWorker(_config(tmp_path), provider=_V2Provider(), storage=storage)
    assert worker.process_once() == 1

    session_id = report["canonical_evidence"]["session_id"]
    result = load_ai_advisory_detail(_monitor_config(), session_id, _storage=storage)
    assert result["ok"] is True
    assert result["advisory_schema_version"] == "ai_advisory_record.v2"
    assert "graph-grounded" in result["authority_label"]
    assert result["advisory"]["schema_version"] == "ai_advisory_record.v2"
    assert "shadow_candidates" not in result["advisory"]
    assert result["advisory"]["rendered_advisory"]["schema_version"] == "ai_advisory_rendered.v2"


def test_v2_api_exposes_pending_then_deterministic_abstention(tmp_path) -> None:
    report = _report("phase6-pending")
    storage, _ = _storage_with_report(tmp_path, report)
    session_id = report["canonical_evidence"]["session_id"]
    pending = load_ai_advisory_detail(
        _monitor_config(), session_id, _storage=storage
    )
    assert pending["status"] == "pending"
    assert pending["advisory_schema_version"] == "ai_advisory_record.v2"
    assert pending["advisory"] == {}

    abstained_report = _report("phase6-abstained", commands=("pwd",))
    abstained_dir = tmp_path / "abstained"
    abstained_dir.mkdir()
    abstained_storage, _ = _storage_with_report(abstained_dir, abstained_report)
    worker = AIAdvisoryWorker(
        _config(abstained_dir), provider=_V2Provider(), storage=abstained_storage
    )
    assert worker.process_once() == 1
    abstained_session_id = abstained_report["canonical_evidence"]["session_id"]
    abstained = load_ai_advisory_detail(
        _monitor_config(), abstained_session_id, _storage=abstained_storage
    )
    assert abstained["status"] == "abstained"
    assert abstained["advisory"]["rendered_advisory"]["status"] == "abstained"
    assert "shadow_candidates" not in abstained["advisory"]


def test_v2_api_rejects_version_mismatch_and_does_not_merge_prediction(tmp_path) -> None:
    report = _report("phase6-mismatch")
    storage, report_id = _storage_with_report(tmp_path, report)
    # A v1 advisory attached to a v6 report is not rendered as a compatible
    # current result. The current report remains the only canonical source.
    with storage.connection() as conn:
        row = conn.execute(
            "SELECT advisory_id FROM ai_advisories WHERE report_id=?",
            (report_id,),
        ).fetchone()
        assert row is None
    result = load_ai_advisory_detail(
        _monitor_config(), report["canonical_evidence"]["session_id"], _storage=storage
    )
    assert result["status"] == "pending"
    assert "prediction" not in result
    assert "canonical_evidence" not in result["advisory"]


def test_v2_api_exposes_rejected_and_failed_as_non_authoritative_states(tmp_path) -> None:
    rejected_report = _report("phase6-rejected")
    rejected_dir = tmp_path / "rejected"
    rejected_dir.mkdir()
    rejected_storage, _ = _storage_with_report(rejected_dir, rejected_report)
    rejected_worker = AIAdvisoryWorker(
        _config(rejected_dir),
        provider=_RejectedV2Provider(),
        storage=rejected_storage,
    )
    assert rejected_worker.process_once() == 1
    rejected = load_ai_advisory_detail(
        _monitor_config(),
        rejected_report["canonical_evidence"]["session_id"],
        _storage=rejected_storage,
    )
    assert rejected["status"] == "rejected"
    assert rejected["advisory"]["authority"] == "non_authoritative_rejected_output"

    failed_report = _report("phase6-failed")
    failed_dir = tmp_path / "failed"
    failed_dir.mkdir()
    failed_storage, _ = _storage_with_report(failed_dir, failed_report)
    with failed_storage.connection() as conn:
        conn.execute(
            "UPDATE ai_advisory_outbox SET status='failed' WHERE report_id=?",
            (failed_storage.list_rows("reports")[0]["report_id"],),
        )
    failed = load_ai_advisory_detail(
        _monitor_config(),
        failed_report["canonical_evidence"]["session_id"],
        _storage=failed_storage,
    )
    assert failed["status"] == "unavailable"
    assert failed["advisory"] == {}


def test_missing_advisory_is_unavailable_without_affecting_current_report(tmp_path) -> None:
    storage = SQLiteStorage(f"sqlite:///{tmp_path / 'state.db'}")
    storage.initialize()
    storage.save_session({"session_id": "sensor-phase6:missing"})
    result = load_ai_advisory_detail(
        _monitor_config(), "sensor-phase6:missing", _storage=storage
    )
    assert result["status"] == "not_available"
    assert result["advisory"] == {}
