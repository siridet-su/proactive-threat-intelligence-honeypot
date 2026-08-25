from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace

from production.api.dashboard_api import _current_prediction_payload
from production.api.monitor_web import _render_prediction_panel
from production.policies.validate_prediction_policy import validate_policy_document
from production.prediction.vomm_rollback import (
    ValidatedVommRollbackPredictor,
)
from production.workers.session_worker import SessionWorker


def _payload(session_id: str, tactics: list[str]) -> dict:
    return {
        "session_id": session_id,
        "status": "closed",
        "is_ended": True,
        "classification_events": [
            {"tactic": tactic, "ttp": f"T10{index:02d}", "source": "rule", "confidence": 1.0}
            for index, tactic in enumerate(tactics, start=1)
        ],
    }


def _external_only_policy() -> dict:
    return {
        "enabled": True,
        "prediction_mode": "external_hard_backoff_vomm",
        "compute_weighted_ensemble_baseline": False,
        "weight_influence_scope": "not_applicable_external_authority",
        "primary_transition": {
            "primary_model": "external_hard_backoff_vomm",
            "source_order": ["external_seed_transition"],
            "fallback_scorer": "",
            "min_transition_score": 0.01,
        },
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
        "max_hypotheses": 5,
        "min_score": 0.01,
        "fallback_progression": {"discovery": ["credential-access"], "execution": ["persistence"]},
        "predictive_alerts": {
            "enabled": True,
            "min_confidence": "low",
            "min_score": 0.0,
            "min_severity": "info",
            "block_external_seed_only": True,
            "block_context_only": True,
            "alert_on_session_status": ["active"],
        },
    }


def _model() -> dict:
    return {
            "schema_version": "external_transition_model.v1",
            "model_id": "external-fixture-v1",
            "artifact_version": "fixture-v1",
            "source_type": "external_cowrie_seed",
            "provenance": {"manifest_id": "manifest-fixture-v1"},
            "usable_sessions": 1,
            "transition_count": 1,
            "prefix_transition_count": 0,
            "technique_transition_count": 0,
            "prefix_max_length": 3,
            "transitions": {"discovery": {"execution": 1}},
            "prefix_transitions": {},
            "technique_transitions": {},
            "technique_tactics": {},
            "start_counts": {"discovery": 1},
        }


def _valid_artifact() -> dict:
    return {
        "status": "valid",
        "valid": True,
        "reasons": [],
        "model_id": "external-fixture-v1",
        "manifest_id": "manifest-fixture-v1",
        "artifact_version": "fixture-v1",
        "actual_artifact_sha256": "a" * 64,
        "manifest_sha256": "b" * 64,
    }


def _features(last_tactic: str = "discovery") -> dict:
    return {
        "session_id": "runtime-external-only",
        "status": "active",
        "tactic_sequence": [last_tactic],
        "observed_tactics": [last_tactic],
        "last_tactic": last_tactic,
        "classification_events": [
            {"tactic": last_tactic, "ttp": "T1001", "source": "rule", "confidence": 1.0}
        ],
        "classification_confidence_available": True,
        "classification_chain_confidence_geomean": 1.0,
    }


def test_external_only_uses_only_validated_external_output() -> None:
    engine = ValidatedVommRollbackPredictor(
        _external_only_policy(),
        model=_model(),
        artifact_validation=_valid_artifact(),
    )

    snapshot = engine.predict(_features(), event_id="external-only-supported")

    assert snapshot["schema_version"] == "prediction_snapshot.v2"
    assert snapshot["prediction_status"] == "predicted"
    assert snapshot["prediction"] == ["execution"]
    assert snapshot["final_ranking"][0]["tactic"] == "execution"
    assert snapshot["primary_transition"]["source_order"] == ["external_seed_transition"]
    assert snapshot["fallback_used"] is False
    assert snapshot["external_artifact"]["artifact_sha256"] == "a" * 64
    assert snapshot["external_artifact"]["manifest_id"] == "manifest-fixture-v1"
    assert snapshot["local_shadow_prediction"]["authority"] == "removed"
    assert snapshot["local_shadow_prediction"]["ranking"] == []
    assert snapshot["ranking_influence"]["local_transition"] == "not_computed"
    assert snapshot["generic_progression_prior"]["not_empirical_prediction"] is True
    assert snapshot["generic_progression_prior"]["tactics"] == []
    assert set(snapshot["scorer_outputs"]) == {"external_seed_transition"}
    assert "fallback_progression" not in snapshot["scorer_outputs"]
    assert "local_transition" not in snapshot["scorer_outputs"]

def test_external_only_abstains_for_unsupported_context_without_heuristic_fallback() -> None:
    engine = ValidatedVommRollbackPredictor(
        _external_only_policy(),
        model=_model(),
        artifact_validation=_valid_artifact(),
    )

    snapshot = engine.predict(_features("execution"), event_id="external-only-unsupported")

    assert snapshot["prediction_status"] == "abstained"
    assert snapshot["prediction"] == []
    assert snapshot["final_ranking"] == []
    assert snapshot["fallback_used"] is False
    assert snapshot["coverage"]["below_minimum"] is True
    assert snapshot["generic_progression_prior"]["tactics"] == []


def test_external_only_fails_closed_when_manifest_validation_is_missing_or_invalid() -> None:
    invalid = _valid_artifact()
    invalid.update({"status": "unavailable", "valid": False, "reasons": ["artifact_sha256_mismatch"]})
    engine = ValidatedVommRollbackPredictor(
        _external_only_policy(),
        model=_model(),
        artifact_validation=invalid,
    )

    snapshot = engine.predict(_features(), event_id="external-only-invalid")

    assert snapshot["prediction_status"] == "model_unavailable"
    assert snapshot["final_ranking"] == []
    assert snapshot["local_shadow_prediction"]["ranking"] == []
    assert snapshot["ranking_influence"]["production_effective_scorers"] == []
    assert "artifact_sha256_mismatch" in snapshot["prediction_status_reason"]


def test_api_and_report_preserve_new_status_and_old_snapshot_reading() -> None:
    snapshot = ValidatedVommRollbackPredictor(
        _external_only_policy(),
        model=_model(),
        artifact_validation=_valid_artifact(),
    ).predict(_features("execution"), event_id="report-abstained")
    current = _current_prediction_payload({"payload": snapshot}, [])
    assert current["prediction_status"] == "abstained"
    assert current["generic_progression_prior"]["not_for_response_guidance"] is True
    html = _render_prediction_panel({"ok": True, "latest_prediction_snapshot": {"payload": snapshot}})
    assert "explicitly abstained" in html
    assert "Generic Progression Prior (Non-empirical, Offline Planning Only)" in html

    historical = {"payload": {"snapshot_id": "old", "final_ranking": [{"tactic": "discovery"}]}}
    assert _current_prediction_payload(historical, [])["prediction_status"] == "predicted"


def test_external_only_policy_contract_rejects_fallback_or_missing_pins() -> None:
    valid = _external_only_policy()
    valid.update({
        "external_transition_model_path": "artifact.json",
        "external_transition_manifest_path": "manifest.json",
        "external_transition_expected_artifact_sha256": "a" * 64,
        "external_transition_expected_model_id": "model",
        "external_transition_expected_manifest_id": "manifest",
    })
    assert validate_policy_document({"policy": valid}) == []

    invalid = deepcopy(valid)
    invalid["primary_transition"]["fallback_scorer"] = "fallback_progression"
    errors = validate_policy_document({"policy": invalid})
    assert any("must not configure a primary fallback" in error for error in errors)


def test_worker_requires_manifest_bound_artifact_for_external_only_mode(tmp_path) -> None:
    policy = _external_only_policy()
    policy.update({
        "external_transition_model_path": str(tmp_path / "missing-artifact.json"),
        "external_transition_manifest_path": "",
    })
    worker = SessionWorker.__new__(SessionWorker)
    worker.config = SimpleNamespace(prediction_policy=policy)

    model = worker._load_external_transition_model()

    assert model["transition_count"] == 0.0
    assert worker.external_artifact_validation == {
        "status": "unavailable",
        "valid": False,
        "reasons": ["external_only_mode_requires_manifest_path"],
        "artifact_path": str(tmp_path / "missing-artifact.json"),
    }
