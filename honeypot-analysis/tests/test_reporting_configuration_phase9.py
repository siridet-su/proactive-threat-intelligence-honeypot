from __future__ import annotations

import asyncio
import json
import sys
import threading
import time
import types
from pathlib import Path
from types import SimpleNamespace

import pytest

import production.enrichment.mitre_attack_loader as mitre_loader
import production.enrichment.threat_feed_loader as feed_loader
import production.reporting.reporting_pipeline as reporting_pipeline
import production.workers.analysis_worker as analysis_worker
from production.reporting.reporting_pipeline import (
    ImprovedAsyncSwarmCoordinator,
    TokenBudget,
    VertexAIClient,
    _completed_actions_from_observed_ttps,
)
from production.utils.config import ProductionConfig
from production.workers.session_monitor import SessionState, build_pipeline_trigger


class _Mitre:
    @staticmethod
    def get_name(ttp: str) -> str:
        return ttp

    @staticmethod
    def get_tactics(_ttp: str) -> list[str]:
        return ["discovery"]

    @staticmethod
    def get(_ttp: str, default: str = "") -> str:
        return default


class _Sigma:
    @staticmethod
    def get_keywords_for_level(level: str) -> list[str]:
        return [f"sigma-{level}"]


class _Feeds:
    sigma = _Sigma()

    @staticmethod
    def get_bruteforce_keywords() -> list[str]:
        return ["sigma-bruteforce"]


def test_explicit_disabled_dependencies_prevent_hidden_default_reloads(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = {"feeds": 0, "mitre": 0}

    def unexpected_feed_load(*_args, **_kwargs):
        calls["feeds"] += 1
        raise AssertionError("default feed loader must not run")

    def unexpected_mitre_load(*_args, **_kwargs):
        calls["mitre"] += 1
        raise AssertionError("default MITRE loader must not run")

    monkeypatch.setattr(feed_loader, "load_threat_feeds", unexpected_feed_load)
    monkeypatch.setattr(mitre_loader, "load_mitre_attack_db", unexpected_mitre_load)
    coordinator = ImprovedAsyncSwarmCoordinator(
        base_url="",
        model="",
        threat_intel_config={},
        threat_feeds=None,
        mitre_db=None,
    )

    assert calls == {"feeds": 0, "mitre": 0}
    assert coordinator.config == {}
    assert coordinator.threat_feeds is None
    assert coordinator.mitre_db.version == "disabled"


def test_coordinator_preserves_injected_configuration_without_mutating_it() -> None:
    threat_config = {
        "sophistication_rules": {
            "high": {"keywords": ["configured-high"]},
        },
        "behavioral_rules": {"probe": ["whoami"]},
    }
    prediction_policy = {
        "predictive_alerts": {
            "tactic_severity": {"discovery": "critical"},
        }
    }
    prediction_context = {
        "snapshot_id": "snapshot-phase9",
        "final_ranking": [{"tactic": "execution", "score": 0.6}],
    }
    original = json.loads(json.dumps(threat_config))
    feeds = _Feeds()
    mitre = _Mitre()

    coordinator = ImprovedAsyncSwarmCoordinator(
        base_url="",
        model="unit-model",
        threat_intel_config=threat_config,
        threat_feeds=feeds,
        mitre_db=mitre,
        behavior_policy_document={"policy_id": "behavior-phase9"},
        behavior_policy_path="configured-behavior.json",
        classification_policy={"strategy": "configured"},
        classification_rules_path="configured-classification.json",
        prediction_policy=prediction_policy,
        prediction_policy_path="configured-prediction.json",
        prediction_context=prediction_context,
        recommendation_asset_profile_path="configured-asset.json",
        recommendation_action_policy_path="configured-actions.json",
        cisa_cache_path="configured-kev.json",
        sigma_cache_path="configured-sigma.json",
        mitre_cache_path="configured-mitre.json",
    )

    assert coordinator.threat_feeds is feeds
    assert coordinator.mitre_db is mitre
    assert coordinator.classification_policy == {"strategy": "configured"}
    assert coordinator.prediction_policy == prediction_policy
    assert coordinator.prediction_context == prediction_context
    assert coordinator.recommendation_action_policy_path == "configured-actions.json"
    assert coordinator.cisa_cache_path == "configured-kev.json"
    assert "sigma-high" in coordinator.sophistication_rules["high"]["keywords"]
    assert threat_config == original


def test_disabled_analysis_context_never_loads_feeds_or_mitre(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    threat_config_path = tmp_path / "threat-intel.json"
    threat_config_path.write_text(
        json.dumps({"behavioral_rules": {"configured": ["whoami"]}}),
        encoding="utf-8",
    )
    config = ProductionConfig(
        database_url=f"sqlite:///{tmp_path / 'phase9.db'}",
        enable_feed_loading=False,
        threat_intel_config_path=str(threat_config_path),
        enrichment_db_path="",
    )
    monkeypatch.setattr(
        analysis_worker,
        "load_threat_feeds",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("feeds must remain disabled")
        ),
    )
    monkeypatch.setattr(
        analysis_worker,
        "load_mitre_attack_db",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("MITRE loading must remain disabled")
        ),
    )

    context = analysis_worker.load_analysis_context(config)

    assert context["config"] == {
        "behavioral_rules": {"configured": ["whoami"]}
    }
    assert context["feeds"] is None
    assert context["mitre_attack"] is None
    assert context["feed_status"] == {
        "status": "disabled",
        "loading_enabled": False,
    }
    assert context["behavior_policy"]["policy_id"]


def test_pipeline_trigger_forwards_all_resolved_dependencies() -> None:
    captured: dict = {}

    class CapturingCoordinator:
        def __init__(self, **kwargs) -> None:
            captured.update(kwargs)

        async def analyze(self, *_args, **_kwargs) -> dict:
            return {
                "confidence": "low",
                "confidence_source": "phase9-test",
                "threat_hypothesis": {},
            }

    state = SessionState(
        session_id="phase9-context",
        src_ip="192.0.2.90",
        start_time="2026-07-19T00:00:00Z",
    )
    state.commands.append("whoami")
    state.commands_success.append("whoami")
    state.classification_events.append({
        "command": "whoami",
        "ttp": "T1033",
        "tactic": "discovery",
        "source": "rule",
        "high_confidence": True,
    })
    state.ttps.append("T1033")
    state.tactics.append("discovery")
    state.ttp_command_map["T1033"] = ["whoami"]

    feeds = _Feeds()
    mitre = _Mitre()
    behavior = {"policy_id": "behavior-phase9"}
    prediction = {"policy_id": "prediction-phase9"}
    snapshot = {"snapshot_id": "snapshot-phase9", "final_ranking": []}
    trigger = build_pipeline_trigger(
        CapturingCoordinator,
        feeds=feeds,
        mitre_db=mitre,
        config={"configured": True},
        feed_loading_enabled=False,
        feed_status={"status": "disabled", "loading_enabled": False},
        behavior_policy_document=behavior,
        behavior_policy_path="behavior.json",
        classification_policy={"strategy": "configured"},
        classification_rules_path="classification.json",
        prediction_policy=prediction,
        prediction_policy_path="prediction.json",
        prediction_context=snapshot,
        smb_asset_profile_path="asset.json",
        smb_action_policy_path="actions.json",
        cisa_cache_path="kev.json",
        sigma_cache_path="sigma.json",
        mitre_cache_path="mitre.json",
        vertex_project_id="project-phase9",
        vertex_location="location-phase9",
        vertex_model="model-phase9",
        vertex_request_timeout_seconds=3.0,
        vertex_outer_timeout_seconds=4.0,
        vertex_max_retries=1,
        vertex_retry_delay_seconds=0.0,
    )

    report = trigger(state)

    assert captured["threat_feeds"] is feeds
    assert captured["mitre_db"] is mitre
    assert captured["threat_intel_config"] == {"configured": True}
    assert captured["behavior_policy_document"] is behavior
    assert captured["prediction_policy"] is prediction
    assert captured["prediction_context"] is snapshot
    assert captured["recommendation_action_policy_path"] == "actions.json"
    assert captured["vertex_request_timeout_seconds"] == 3.0
    assert report["data_provenance"]["feeds"] == {
        "status": "disabled",
        "loading_enabled": False,
    }


def test_in_memory_prediction_policy_avoids_default_path_reload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        reporting_pipeline,
        "_default_prediction_policy_path",
        lambda: (_ for _ in ()).throw(
            AssertionError("in-memory policy must prevent default reload")
        ),
    )
    actions = _completed_actions_from_observed_ttps(
        {
            "impact": ["T1499"],
            "discovery": ["T1033"],
        },
        {
            "T1499": ["impact-command"],
            "T1033": ["discovery-command"],
        },
        policy_document={
            "predictive_alerts": {
                "tactic_severity": {
                    "impact": "low",
                    "discovery": "critical",
                }
            }
        },
    )

    assert actions == ["discovery-command", "impact-command"]


def test_vertex_client_configures_actual_sdk_timeout_and_disables_sdk_retries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict = {}
    google_module = types.ModuleType("google")
    genai_module = types.ModuleType("google.genai")
    genai_types_module = types.ModuleType("google.genai.types")
    genai_types_module.HttpRetryOptions = lambda **kwargs: {"retry": kwargs}
    genai_types_module.HttpOptions = lambda **kwargs: {"http": kwargs}

    def client_factory(**kwargs):
        captured.update(kwargs)
        return SimpleNamespace(models=SimpleNamespace())

    genai_module.Client = client_factory
    genai_module.types = genai_types_module
    google_module.genai = genai_module
    monkeypatch.setitem(sys.modules, "google", google_module)
    monkeypatch.setitem(sys.modules, "google.genai", genai_module)
    monkeypatch.setitem(sys.modules, "google.genai.types", genai_types_module)

    client = VertexAIClient(
        TokenBudget(max_tokens=100),
        project_id="project-phase9",
        location="location-phase9",
    )
    client._get_client(0.125)

    assert captured["project"] == "project-phase9"
    assert captured["location"] == "location-phase9"
    assert captured["http_options"]["http"]["timeout"] == 125
    assert captured["http_options"]["http"]["retry_options"] == {
        "retry": {"attempts": 1}
    }


def test_vertex_outer_timeout_returns_without_waiting_for_never_returning_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    release = threading.Event()
    client = VertexAIClient(
        TokenBudget(max_tokens=100),
        request_timeout_seconds=0.01,
        outer_timeout_seconds=0.03,
        max_retries=1,
        retry_delay_seconds=0.0,
    )
    monkeypatch.setattr(client, "available", lambda: True)
    monkeypatch.setattr(
        client,
        "_post_sync",
        lambda *_args, **_kwargs: release.wait(5.0) and "{}",
    )

    started = time.monotonic()
    try:
        result = asyncio.run(client.infer_analytical("{}", []))
    finally:
        release.set()

    assert result == {}
    assert time.monotonic() - started < 0.5


def test_vertex_outer_boundary_propagates_cancellation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    release = threading.Event()
    client = VertexAIClient(
        TokenBudget(max_tokens=100),
        request_timeout_seconds=1.0,
        outer_timeout_seconds=1.1,
        max_retries=1,
        retry_delay_seconds=0.0,
    )
    monkeypatch.setattr(client, "available", lambda: True)
    monkeypatch.setattr(
        client,
        "_post_sync",
        lambda *_args, **_kwargs: release.wait(5.0) and "{}",
    )

    async def scenario() -> None:
        task = asyncio.create_task(client.infer_analytical("{}", []))
        await asyncio.sleep(0.02)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    try:
        asyncio.run(scenario())
    finally:
        release.set()


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"vertex_max_retries": 0}, "vertex_max_retries"),
        ({"vertex_max_retries": 6}, "vertex_max_retries"),
        ({"vertex_retry_delay_seconds": -1.0}, "vertex_retry_delay_seconds"),
        (
            {
                "vertex_request_timeout_seconds": 5.0,
                "vertex_outer_timeout_seconds": 4.0,
            },
            "vertex_outer_timeout_seconds",
        ),
    ],
)
def test_vertex_bounds_are_validated(overrides: dict, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        ProductionConfig(**overrides)
