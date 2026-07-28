from __future__ import annotations

import asyncio
import io
import json
import signal
import threading
import time
from http import HTTPStatus
from types import SimpleNamespace
from typing import Any

import pytest

import production.api.dashboard_api as dashboard_api
import production.workers.analysis_worker as analysis_worker_module
import production.workers.sensor_forwarder as sensor_forwarder
from production.api.ingest_api import IngestHTTPServer
from production.enrichment.enrichment_providers import ProviderResult
from production.storage import open_storage
from production.utils.config import ProductionConfig
from production.utils.http_security import safe_correlation_id
from production.utils.service_lifecycle import ServiceLifecycle, serve_http_until_stopped
from production.workers.enrichment_worker import EnrichmentWorker
from production.workers.analysis_worker import AnalysisWorker
from production.workers.session_monitor import CampaignTracker, SessionMonitor, SessionState
from production.workers.session_worker import SessionWorker


def test_lifecycle_signal_is_interruptible_and_previous_handler_is_restored() -> None:
    lifecycle = ServiceLifecycle()
    previous = signal.getsignal(signal.SIGTERM)
    with lifecycle.signal_handlers():
        installed = signal.getsignal(signal.SIGTERM)
        assert callable(installed)
        installed(signal.SIGTERM, None)
        assert lifecycle.wait(0.01)
        assert lifecycle.stopping
        assert lifecycle.reason == "sigterm"
    assert signal.getsignal(signal.SIGTERM) == previous


def test_http_lifecycle_stops_accepting_and_closes_boundedly() -> None:
    lifecycle = ServiceLifecycle()

    class FakeServer:
        def __init__(self) -> None:
            self.shutdown_requested = threading.Event()
            self.closed = False

        def serve_forever(self, poll_interval: float) -> None:
            assert poll_interval <= 0.2
            self.shutdown_requested.wait(1)

        def shutdown(self) -> None:
            self.shutdown_requested.set()

        def server_close(self) -> None:
            self.closed = True

    server = FakeServer()
    thread = threading.Thread(
        target=serve_http_until_stopped,
        args=(server, lifecycle),
    )
    thread.start()
    lifecycle.request_stop("test")
    thread.join(timeout=1)

    assert not thread.is_alive()
    assert server.shutdown_requested.is_set()
    assert server.closed


def test_shutdown_after_claim_releases_job_without_processing() -> None:
    claim = {
        "job_id": "job-safe",
        "claim_owner": "worker-safe",
        "claim_token": "00000000-0000-4000-8000-000000000001",
    }

    class FakeStorage:
        def __init__(self) -> None:
            self.released: list[tuple[Any, ...]] = []

        def claim_enrichment_jobs(self, *_args: Any, **_kwargs: Any) -> list[dict]:
            return [claim]

        def release_job_claim(self, *args: Any, **_kwargs: Any) -> bool:
            self.released.append(args)
            return True

    worker = object.__new__(EnrichmentWorker)
    worker.config = SimpleNamespace(
        enrichment_batch_size=1,
        job_lease_seconds=60,
        enrichment_max_attempts=3,
    )
    worker.storage = FakeStorage()
    worker.worker_owner = "worker-safe"
    worker.providers = []
    stop_checks = iter((False, True))

    assert worker.process_once(should_stop=lambda: next(stop_checks)) == 0
    assert worker.storage.released == [
        (
            "enrichment",
            claim["job_id"],
            claim["claim_owner"],
            claim["claim_token"],
        )
    ]


def test_idle_worker_cycle_is_not_logged(capsys: pytest.CaptureFixture[str]) -> None:
    lifecycle = ServiceLifecycle()
    worker = object.__new__(EnrichmentWorker)
    worker.config = SimpleNamespace(worker_poll_seconds=60)

    def stop_without_work(**_kwargs: Any) -> int:
        lifecycle.request_stop("test")
        return 0

    worker.process_once = stop_without_work  # type: ignore[method-assign]
    worker.run_forever(lifecycle)

    assert capsys.readouterr().out == ""


def test_analysis_report_logs_latency_and_preserves_event_correlation(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config = ProductionConfig(database_url=f"sqlite:///{tmp_path / 'analysis.db'}")
    config.analysis_skip_empty_sessions = False
    config.analysis_batch_size = 1
    storage = open_storage(config.database_url)
    storage.enqueue_analysis_job(
        {
            "session_id": "session-analysis",
            "src_ip": "203.0.113.50",
            "correlation_id": "evt-safe-correlation",
        }
    )

    async def fake_analyze(*_args: Any, **_kwargs: Any) -> dict:
        return {"session_id": "session-analysis", "summary": "safe"}

    monkeypatch.setattr(analysis_worker_module, "analyze_job", fake_analyze)
    worker = AnalysisWorker(config)
    assert asyncio.run(worker.process_once()) == 1

    report_row = storage.list_rows("reports", limit=1)[0]
    report = json.loads(report_row["payload_json"])
    lines = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    completed = next(item for item in lines if item.get("status") == "succeeded")
    assert report["correlation_id"] == "evt-safe-correlation"
    assert completed["correlation_id"] == "evt-safe-correlation"
    assert completed["report_generation_latency_ms"] >= 0


def test_enrichment_provider_status_includes_measured_latency() -> None:
    class Provider:
        name = "safe-provider"

        def supports(self, observable_type: str) -> bool:
            return observable_type == "ip"

        def enrich(self, *_args: Any) -> ProviderResult:
            return ProviderResult(self.name, "ok", {"safe": True})

    worker = object.__new__(EnrichmentWorker)
    worker.config = SimpleNamespace(enrichment_ttl_seconds=3600)
    worker.providers = [Provider()]
    result = worker._run_providers("ip", "203.0.113.51")[0]

    assert result.status == "ok"
    assert result.latency_ms >= 0
    assert result.to_status()["latency_ms"] == result.latency_ms


def test_prediction_failure_metric_uses_central_exception_redaction(
    capsys: pytest.CaptureFixture[str],
) -> None:
    worker = object.__new__(SessionWorker)
    worker._prediction_generation_errors = 0

    def fail(*_args: Any, **_kwargs: Any) -> bool:
        raise RuntimeError("must-not-appear-secret")

    worker._save_prediction_snapshot_unobserved = fail  # type: ignore[method-assign]
    with pytest.raises(RuntimeError):
        worker._save_prediction_snapshot(
            object(),
            {},
            event_id="evt-safe",
        )

    output = capsys.readouterr().out
    assert "must-not-appear-secret" not in output
    assert '"prediction_generation_errors": 1' in output
    assert '"correlation_id": "evt-safe"' in output


def test_forwarder_logs_idle_spool_status_initially_but_not_each_poll(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeLifecycle:
        def __init__(self) -> None:
            self.stopping = False
            self.cycles = 0

        def signal_handlers(self):
            class Context:
                def __enter__(inner_self):
                    return self

                def __exit__(inner_self, *_args: Any) -> None:
                    return None

            return Context()

        def wait(self, _seconds: float) -> bool:
            self.cycles += 1
            if self.cycles >= 3:
                self.stopping = True
            return self.stopping

    results: list[sensor_forwarder.ForwardResult] = []
    idle = sensor_forwarder.ForwardResult(sent=0, remaining=0, spool_bytes=0)
    monkeypatch.setattr(sensor_forwarder, "_forward_once_unlocked", lambda _cfg: idle)
    monkeypatch.setattr(sensor_forwarder, "_log_result", results.append)
    config = ProductionConfig(spool_path=str(tmp_path / "spool.ndjson"))

    sensor_forwarder.run_forever(config, FakeLifecycle())

    assert results == [idle]


def test_operational_metrics_cover_connectivity_counts_queues_and_webhooks(
    tmp_path,
) -> None:
    storage = open_storage(f"sqlite:///{tmp_path / 'metrics.db'}")

    event_id, inserted = storage.store_event(
        "sensor-a",
        {
            "eventid": "cowrie.session.connect",
            "session": "session-metrics",
            "src_ip": "203.0.113.40",
        },
    )
    assert event_id and inserted
    assert storage.store_event(
        "sensor-a",
        {
            "eventid": "cowrie.session.connect",
            "session": "session-metrics",
            "src_ip": "203.0.113.40",
        },
    )[1] is False
    storage.enqueue_analysis_job(
        {"session_id": "session-metrics", "src_ip": "203.0.113.40"}
    )
    storage.enqueue_enrichment_job(
        "ip", "203.0.113.40", session_id="session-metrics"
    )
    storage.enqueue_threat_hunt_job("session-metrics", "ip", "203.0.113.40")

    metrics = storage.operational_metrics()

    assert metrics["backend_connectivity"]["ok"] is True
    assert metrics["collection_counts"]["events"] == 1
    assert set(metrics["queues"]) == {"analysis", "enrichment", "threat_hunt"}
    for queue in metrics["queues"].values():
        assert queue["ready"] == 1
        assert queue["status_counts"]["queued"] == 1
        assert queue["oldest_ready_age_seconds"] is not None
    assert isinstance(metrics["webhook_delivery_status"], dict)
    assert "checked_at" in metrics
    assert metrics["database_bytes"] > 0


def test_ingest_process_metrics_report_duplicate_rate_without_event_content() -> None:
    server = object.__new__(IngestHTTPServer)
    server._metrics_lock = threading.Lock()
    server._metrics_started_at = time.monotonic() - 1
    server._ingest_counts = {"accepted": 0, "duplicates": 0, "rejected": 0}

    metrics = server.record_ingest_outcome(accepted=3, duplicates=1, rejected=2)

    assert metrics["accepted"] == 3
    assert metrics["duplicates"] == 1
    assert metrics["rejected"] == 2
    assert metrics["duplicate_event_rate"] == 0.25
    assert metrics["event_ingest_rate_per_second"] > 0


def test_secret_shaped_correlation_candidate_falls_back_without_echo() -> None:
    candidate = "authorization=must-not-survive"
    fallback = "job_safe-correlation"
    selected = safe_correlation_id(candidate, fallback)
    assert selected == fallback
    assert "must-not-survive" not in selected


def test_dashboard_operational_metrics_require_read_auth_and_correlate_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeStorage:
        def operational_metrics(self) -> dict:
            return {
                "backend": "sqlite",
                "backend_connectivity": {"ok": True, "backend": "sqlite"},
                "database_bytes": 42,
                "collection_counts": {"events": 3},
                "queues": {},
                "webhook_delivery_status": {},
            }

    monkeypatch.setattr(dashboard_api, "open_storage", lambda _url: FakeStorage())
    config = SimpleNamespace(
        dashboard_read_token="read-secret",
        dashboard_write_token="",
        database_url="sqlite:///:memory:",
    )

    def request(authorization: str = "") -> tuple[HTTPStatus, dict]:
        handler = object.__new__(dashboard_api.DashboardHandler)
        handler.config = config
        handler.path = "/operational/metrics"
        handler.command = "GET"
        handler.client_address = ("127.0.0.1", 1234)
        handler.headers = {"X-Request-ID": "metrics-request"}
        if authorization:
            handler.headers["Authorization"] = authorization
        handler.rfile = io.BytesIO()
        responses: list[tuple[HTTPStatus, dict]] = []
        handler._send_json = lambda status, payload: responses.append((status, payload))
        dashboard_api.DashboardHandler.do_GET(handler)
        return responses[0]

    denied_status, _ = request()
    status, payload = request("Bearer read-secret")

    assert denied_status == HTTPStatus.UNAUTHORIZED
    assert status == HTTPStatus.OK
    assert payload["request_id"] == "metrics-request"
    assert payload["metrics"]["database_bytes"] == 42


def test_campaign_history_and_closed_worker_state_are_bounded() -> None:
    tracker = CampaignTracker(max_profiles=2)
    for index in range(3):
        tracker.check_and_register(
            SessionState(
                session_id=f"session-{index}",
                src_ip=f"203.0.113.{index + 1}",
                start_time="2026-07-19T00:00:00Z",
            )
        )
    assert tracker.profile_count == 2
    assert [item["session_id"] for item in tracker._profiles] == [
        "session-1",
        "session-2",
    ]

    worker = object.__new__(SessionWorker)
    worker.monitor = SimpleNamespace(
        _sessions={
            "active": SimpleNamespace(is_ended=False),
            "closed": SimpleNamespace(is_ended=True),
        }
    )
    worker._session_latest_snapshots = {"active": {}, "closed": {}}
    worker._session_prediction_snapshots = {"active": [], "closed": []}

    assert worker._evict_closed_sessions() == 1
    assert set(worker.monitor._sessions) == {"active"}
    assert set(worker._session_latest_snapshots) == {"active"}
    assert set(worker._session_prediction_snapshots) == {"active"}

    monitor = SessionMonitor(session_event_history_limit=2)
    for index in range(5):
        monitor.on_event(
            {
                "eventid": "cowrie.command.input",
                "session": "long-running",
                "src_ip": "203.0.113.60",
                "timestamp": f"2026-07-19T00:00:0{index}Z",
                "input": f"echo {index}",
                "success": 1,
            }
        )
    state = monitor.get_session("long-running")
    assert state is not None
    assert len(state.raw_events) == 2
    assert state.commands == ["echo 3", "echo 4"]


def test_phase12_config_bounds_campaign_history(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CAMPAIGN_PROFILE_CACHE_LIMIT", "37")
    monkeypatch.setenv("SESSION_EVENT_HISTORY_LIMIT", "41")
    config = ProductionConfig.from_env()
    assert config.campaign_profile_cache_limit == 37
    assert config.session_event_history_limit == 41
    config.campaign_profile_cache_limit = 0
    with pytest.raises(ValueError, match="campaign_profile_cache_limit"):
        config.validate_event_processing()
    config.campaign_profile_cache_limit = 37
    config.session_event_history_limit = 0
    with pytest.raises(ValueError, match="session_event_history_limit"):
        config.validate_event_processing()
