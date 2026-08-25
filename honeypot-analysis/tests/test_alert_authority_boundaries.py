from __future__ import annotations

import copy
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from production.api.security import api_row_view
from production.correlation.campaign_clustering import create_or_update_campaign
from production.policies.alert_authority_policy import (
    load_alert_authority_policy,
    validate_alert_authority_policy,
)
from production.storage import open_storage
from production.utils.config import ProductionConfig
from production.workers.session_worker import SessionWorker
from production.workers.session_monitor import SessionMonitor
from production.workers.threat_hunt_worker import ThreatHuntWorker
from production.workers.webhook_dispatcher import WebhookDispatcher


POLICY_PATH = "configs/alert_authority_policy.v1.json"


def _loaded_policy():
    return load_alert_authority_policy(POLICY_PATH)


def test_reviewed_alert_policy_is_strict_hash_bound_and_fail_closed() -> None:
    loaded = _loaded_policy()
    assert len(loaded.sha256) == 64
    assert loaded.automatic_alerts_authorized is False
    assert loaded.external_delivery_authorized is False

    source = json.loads(Path(POLICY_PATH).read_text(encoding="utf-8"))
    mutations = []
    enabled_alert = copy.deepcopy(source)
    enabled_alert["automatic_authority"]["alert_creation_authorized"] = True
    mutations.append(enabled_alert)
    enabled_webhook = copy.deepcopy(source)
    enabled_webhook["webhook"]["configured_targets_authorized"] = True
    mutations.append(enabled_webhook)
    actor_claim = copy.deepcopy(source)
    actor_claim["correlation"]["actor_identity_claims_authorized"] = True
    mutations.append(actor_claim)
    invented_source = copy.deepcopy(source)
    invented_source["non_authoritative_sources"].append("invented_authority")
    mutations.append(invented_source)
    extra_field = copy.deepcopy(source)
    extra_field["automatic_authority"]["manual_override"] = True
    mutations.append(extra_field)

    for document in mutations:
        with pytest.raises(ValueError):
            validate_alert_authority_policy(document)


def test_campaign_similarity_emits_neutral_signal_and_never_alerts(tmp_path: Path) -> None:
    storage = open_storage(f"sqlite:///{tmp_path / 'campaign.db'}")
    policy = {
        "enabled": True,
        "min_commands_active": 1,
        "min_match_score": 0.20,
        "min_match_raw_score": 0.20,
        "min_independent_evidence_classes": 1,
        "emit_observational_signals": True,
    }
    first = {
        "session_id": "similar-session-one",
        "commands": ["uname -a", "id"],
        "start_time": "2026-07-30T00:00:00Z",
        "updated_at": "2026-07-30T00:01:00Z",
    }
    second = {
        **first,
        "session_id": "similar-session-two",
        "start_time": "2026-07-30T00:02:00Z",
        "updated_at": "2026-07-30T00:03:00Z",
    }

    created = create_or_update_campaign(
        storage,
        first,
        policy,
        alert_authority_policy=_loaded_policy(),
    )
    matched = create_or_update_campaign(
        storage,
        second,
        policy,
        alert_authority_policy=_loaded_policy(),
    )

    assert created["status"] == "created"
    assert matched["status"] == "matched"
    signal = matched["correlation_signal"]
    assert signal["schema_version"] == "correlation_signal.v1"
    assert signal["signal_type"] == "similar_session_pattern_observed"
    assert signal["authority"] == {
        "semantics": "observation_only_non_authoritative",
        "may_claim_actor_identity": False,
        "may_create_alert": False,
        "may_authorize_response": False,
    }
    assert "actor" not in json.dumps(signal, sort_keys=True).lower().replace(
        "may_claim_actor_identity", ""
    ).replace("actor identity", "")
    assert matched["automatic_alerts"]["status"] == "prohibited"
    assert storage.list_rows("alerts") == []


class _ThreatHuntStorage:
    def __init__(self) -> None:
        self.links: list[dict] = []
        self.alert_calls = 0

    def find_sessions_by_observable(self, *_args, **_kwargs):
        return [
            {
                "session_id": "related-active",
                "ended": False,
                "sighting_count": 2,
                "first_seen": "2026-07-30T00:00:00Z",
                "last_seen": "2026-07-30T00:10:00Z",
                "roles": ["command_url"],
                "sources": ["event"],
            }
        ]

    def save_session_link(self, payload):
        self.links.append(dict(payload))
        return "link_stable"

    def store_alert(self, _payload):
        self.alert_calls += 1
        raise AssertionError("threat-hunt observations must not store alerts")


def test_threat_hunt_match_is_observational_and_cannot_bypass_policy() -> None:
    worker = object.__new__(ThreatHuntWorker)
    worker.policy = {
        "max_related_sessions_per_job": 10,
        "signal_active_sessions": True,
        "confidence_by_observable_type": {"hash": 0.95},
    }
    worker.storage = _ThreatHuntStorage()
    worker.alert_authority_policy = _loaded_policy()

    result = worker._process_job(
        {
            "job_id": "job-observational",
            "session_id": "source-closed",
            "observable_type": "hash",
            "observable_value": "a" * 64,
        }
    )

    assert result["signals_created"] == 1
    assert result["alerts_created"] == 0
    assert result["alert_ids"] == []
    assert worker.storage.alert_calls == 0
    signal = result["correlation_signals"][0]
    assert signal["authority"]["may_create_alert"] is False
    assert signal["authority"]["may_claim_actor_identity"] is False
    assert signal["link_id"] == "link_stable"


class _AlertRejectingStorage:
    def __init__(self) -> None:
        self.calls = 0

    def store_alert(self, _payload):
        self.calls += 1
        raise AssertionError("session callback must not store alerts")


@pytest.mark.parametrize(
    "source",
    [
        "session_assessment.v4",
        "response_guidance.v3",
        "typed_semantic_fact_set.v2",
        "prediction",
        "enrichment",
        "correlation",
    ],
)
def test_contextual_sources_cannot_use_session_alert_callback(source: str) -> None:
    worker = object.__new__(SessionWorker)
    worker.storage = _AlertRejectingStorage()
    worker._on_alert(
        SimpleNamespace(
            session_id="authority-boundary",
            reason=f"attempted bypass from {source}",
            severity="CRITICAL",
        )
    )
    assert worker.storage.calls == 0


def test_runtime_monitor_can_disable_threshold_alert_evaluation() -> None:
    observed: list[object] = []
    monitor = SessionMonitor(
        on_alert=observed.append,
        enable_legacy_campaign_tracker=False,
        enable_alert_evaluation=False,
    )
    for index in range(6):
        alerts = monitor.on_event(
            {
                "eventid": "cowrie.login.failed",
                "session": "no-auto-alerts",
                "src_ip": "203.0.113.20",
                "timestamp": f"2026-07-30T00:00:0{index}Z",
            }
        )
        assert alerts == []
    assert observed == []
    assert monitor.get_session("no-auto-alerts").alerts_fired == []


def test_configured_webhook_is_validated_but_never_dispatched(tmp_path: Path) -> None:
    key = tmp_path / "webhook.key"
    key.write_bytes(b"test-only-key-material" * 4)
    os.chmod(key, 0o600)
    config = ProductionConfig(
        database_url=f"sqlite:///{tmp_path / 'webhook.db'}",
        webhook_targets=[
            {
                "target_id": "denied",
                "url": "https://example.test/webhook",
                "signing_key_file": str(key),
            }
        ],
    )
    storage = open_storage(config.database_url)
    storage.store_alert(
        {
            "alert_id": "historical-alert",
            "session_id": "historical-session",
            "severity": "HIGH",
            "reason": "historical compatibility fixture",
        }
    )

    dispatcher = WebhookDispatcher(config, storage=storage)
    assert len(dispatcher.configured_targets) == 1
    assert dispatcher.targets == []
    assert dispatcher.dispatch_once() == 0
    assert storage.list_rows("webhook_deliveries") == []


def test_historical_alert_rows_remain_readable_and_are_labeled(tmp_path: Path) -> None:
    storage = open_storage(f"sqlite:///{tmp_path / 'history.db'}")
    storage.store_alert(
        {
            "alert_id": "legacy-alert-readable",
            "session_id": "legacy-session",
            "severity": "MEDIUM",
            "reason": "retained historical row",
        }
    )
    row = storage.list_rows("alerts", limit=1)[0]
    assert row["alert_id"] == "legacy-alert-readable"
    public = api_row_view("alerts", row)
    assert public["authority_display"] == "historical_legacy_alert"
    assert public["reason"] == "retained historical row"
