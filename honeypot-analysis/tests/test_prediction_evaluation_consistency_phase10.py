from __future__ import annotations

import json
import subprocess
import sys
from collections import Counter
from pathlib import Path
from types import SimpleNamespace

import pytest

from production.classification.trust import classification_evidence_tier
from production.policies.validate_prediction_policy import validate_policy_document
from production.prediction import prediction_backtest
from production.prediction.prediction_backtest import (
    METRIC_TACTIC_VOCABULARY,
    _brier_score,
    _prefix_payload,
    _tactic_steps,
    backtest_sessions,
)
from production.prediction.realtime_prediction import RealtimePredictionEngine
from production.prediction.session_features import build_session_features
from production.tools.build_external_seed_model import _accepted_classifications
from production.workers.calibration_worker import build_calibration_run
from production.workers.session_worker import SessionWorker


ROOT = Path(__file__).resolve().parents[1]


def _event(tactic: str, index: int) -> dict:
    return {
        "command": f"command-{index}",
        "ttp": f"T10{index:02d}",
        "tactic": tactic,
        "source": "rule",
        "confidence": 1.0,
    }


def _payload(session_id: str, tactics: list[str]) -> dict:
    return {
        "session_id": session_id,
        "status": "closed",
        "is_ended": True,
        "classification_events": [
            _event(tactic, index) for index, tactic in enumerate(tactics, start=1)
        ],
    }


def test_primary_mode_labels_weights_as_diagnostic_only() -> None:
    engine = RealtimePredictionEngine(
        {
            "enabled": True,
            "prediction_mode": "primary_transition_with_fallback",
            "compute_weighted_ensemble_baseline": True,
            "weights": {"fallback_progression": 1.0},
            "min_sessions_for_local": 99,
            "external_min_sessions": 99,
        }
    )
    snapshot = engine.predict(
        {
            "session_id": "scope-test",
            "last_tactic": "discovery",
            "tactic_sequence": ["discovery"],
            "observed_tactics": ["discovery"],
        }
    )

    assert snapshot["prediction_mode"] == "primary_transition_with_fallback"
    assert snapshot["weight_influence_scope"] == "diagnostic_only"
    assert snapshot["ranking_influence"]["configured_weights"] == "diagnostic_only"
    assert snapshot["ranking_influence"]["effective_weights"] == "diagnostic_only"
    assert snapshot["ranking_influence"]["production_effective_scorers"] == [
        "fallback_progression"
    ]


def test_weight_influence_policy_must_match_prediction_mode() -> None:
    document = {
        "schema_version": "prediction_policy.v1",
        "policy": {
            "prediction_mode": "primary_transition_with_fallback",
            "weight_influence_scope": "production_ranking",
            "weights": {"fallback_progression": 1.0},
        },
    }

    errors = validate_policy_document(document)

    assert any("weight_influence_scope must match" in error for error in errors)


def test_idle_session_worker_does_not_rebuild_prediction_models() -> None:
    worker = SessionWorker.__new__(SessionWorker)
    worker.config = SimpleNamespace(
        worker_batch_size=10,
        event_lease_seconds=30,
        event_max_attempts=3,
    )
    worker.worker_owner = "idle-test"
    worker.worker_token = "leader-token"
    worker.storage = SimpleNamespace(claim_events=lambda *_args, **_kwargs: [])
    worker._ensure_leadership = lambda: True
    worker._refresh_enrichment_cache = lambda: None
    refreshes: list[bool] = []
    worker._refresh_prediction_engine = lambda: refreshes.append(True)

    assert worker.process_unprocessed() == 0
    assert refreshes == []


def test_prefix_backtest_removes_future_derived_state() -> None:
    payload = _payload("prefix-test", ["discovery", "execution"])
    payload.update(
        {
            "commands": ["command-1", "future-secret-command"],
            "raw_events": [{"input": "future-secret-command"}],
            "session_ttp_correlations": [
                {"tactic": "exfiltration", "apply_to_prediction": True}
            ],
            "session_evidence_graph_summary": {"future": 1},
            "sigma_hits": ["future-rule"],
            "kev_matches": [{"cve": "CVE-2099-9999"}],
            "ioc_summary": {"domains": [{"value": "future.invalid"}]},
            "enrichment_status": {"status": "complete"},
            "country": "future-country",
            "open_ports": [31337],
        }
    )
    steps = _tactic_steps(payload)

    prefix = _prefix_payload(payload, steps, 0)
    features = build_session_features(prefix)

    assert prefix["commands"] == ["command-1"]
    assert features["commands"] == ["command-1"]
    assert features["raw_event_count"] == 0
    assert features["session_ttp_correlations"] == []
    assert features["sigma_hits"] == []
    assert features["kev_matches"] == []
    assert features["enrichment_context"] == {"status": "", "source": "", "providers": []}
    assert features["observables"] == []
    assert "future-secret-command" not in json.dumps(features, sort_keys=True)


def test_backtest_uses_live_history_recency_and_prefix_settings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payloads = [
        _payload("newest", ["discovery", "execution"]),
        _payload("middle", ["discovery", "persistence"]),
        _payload("oldest", ["discovery", "collection"]),
    ]
    calls: list[tuple[int, dict]] = []
    original = prediction_backtest.build_transition_model

    def recording_builder(items, *args, **kwargs):
        materialized = list(items)
        calls.append((len(materialized), dict(kwargs)))
        return original(materialized, *args, **kwargs)

    monkeypatch.setattr(prediction_backtest, "build_transition_model", recording_builder)
    result = backtest_sessions(
        payloads,
        policy={
            "enabled": True,
            "prediction_mode": "primary_transition_with_fallback",
            "transition_history_limit": 2,
            "recency_decay_half_life_sessions": 7,
            "prefix_max_length": 2,
            "min_sessions_for_local": 1,
            "min_transition_count": 1,
            "weights": {"local_transition": 1.0},
        },
        leave_one_out=False,
    )

    local_calls = [
        (count, kwargs)
        for count, kwargs in calls
        if kwargs.get("source_name") == "local_transition"
    ]
    assert local_calls == [
        (
            2,
            {
                "prefix_max_length": 2,
                "source_name": "local_transition",
                "recency_half_life_sessions": 7.0,
            },
        )
    ]
    assert result["model_construction"] == {
        "transition_history_limit": 2,
        "actor_history_limit": 2,
        "prefix_max_length": 2,
        "recency_decay_half_life_sessions": 7.0,
        "completed_sessions_only": True,
        "classification_eligibility": "central_trusted_classification_predicate",
        "storage_scope": (
            "backtest_from_storage defaults to production_live external sessions; "
            "direct callers must supply an explicit reviewed scope"
        ),
        "prefix_context": "reconstructed_observations_only",
        "training_order": "supplied_newest_first_matching_storage_query",
    }


def test_brier_metrics_use_one_explicit_tactic_vocabulary() -> None:
    ranking = [
        {"tactic": "execution", "score": 0.75},
        {"tactic": "persistence", "score": 0.25},
    ]

    score = _brier_score(ranking, "persistence")

    assert score == pytest.approx((0.75**2) + ((0.25 - 1.0) ** 2))
    assert "execution" in METRIC_TACTIC_VOCABULARY
    assert "persistence" in METRIC_TACTIC_VOCABULARY


def test_keep_disagreements_retains_only_audit_evidence() -> None:
    classification = {
        "source": "rule_securebert_disagreement",
        "agreement_status": "technique_and_tactic_disagreement",
        "ttp": "T1033",
        "tactic": "discovery",
        "confidence": 0.99,
        "high_confidence": True,
    }
    stats: Counter = Counter()
    review: list[dict] = []

    retained = _accepted_classifications(
        "ambiguous-command",
        [classification],
        stats,
        Counter(),
        review,
        min_label_confidence=0.9,
        drop_disagreements=False,
        review_limit=10,
    )

    assert len(retained) == 1
    assert retained[0]["external_seed_validation"]["status"] == "audit_only_retained"
    assert classification_evidence_tier(retained[0]) == "audit_only_candidate"
    assert stats["disagreement_commands_retained_audit_only"] == 1
    assert stats["disagreement_commands_skipped"] == 0
    assert stats["accepted_classification_events"] == 0
    assert review == []


def test_calibration_weights_are_labeled_diagnostic_in_primary_mode() -> None:
    class EmptyStorage:
        def list_rows(self, _collection: str, limit: int = 0) -> list[dict]:
            return []

    config = SimpleNamespace(
        prediction_policy={
            "prediction_mode": "primary_transition_with_fallback",
            "weights": {"local_transition": 1.0},
        },
        calibration_policy={
            "enabled": True,
            "auto_evidence_enabled": False,
            "min_feedback_rows": 0,
            "min_backtest_cases": 0,
        },
    )

    result = build_calibration_run(config, EmptyStorage())

    assert result["applied"] is True
    assert result["influence_scope"] == "diagnostic_only"
    assert result["production_ranking_changed"] is False


def test_checked_in_external_model_is_not_labeled_local() -> None:
    model = json.loads(
        (ROOT / "data/models/external_cowrie_seed_transition_model.compound_securebert.json").read_text(
            encoding="utf-8"
        )
    )

    assert model["source_name"] == "external_cowrie_seed"
    assert model["source_name"] == model["source_type"]
    assert model["source_name"] != "local_transition"


@pytest.mark.parametrize(
    "module",
    [
        "production.prediction.prediction_backtest",
        "production.tools.primary_transition_evaluation",
        "production.tools.evaluate_next_tactic_model_comparison",
        "production.tools.external_seed_weight_fit",
        "production.tools.build_external_seed_model",
    ],
)
def test_supported_prediction_evaluation_tools_have_reproducible_help(module: str) -> None:
    completed = subprocess.run(
        [sys.executable, "-m", module, "--help"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )

    assert completed.returncode == 0, completed.stderr
    assert "usage:" in completed.stdout.lower()
