from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

from production.policies.validate_prediction_policy import validate_policy_document
from production.api.dashboard_api import _current_prediction_payload
from production.api.monitor_web import _render_prediction_panel
from production.prediction.next_behavior_runtime import (
    AUTHORITY,
    MODE,
    FrozenTransformerPocPredictor,
    build_live_next_behavior_session,
)


ROOT = Path(__file__).resolve().parents[1]
PRIVATE_ROOT = Path(
    "/home/rubchek/.cache/honeypot-analysis/zenodo/21260400"
)
TRAINING = (
    PRIVATE_ROOT
    / "experiment_20260724_v3_generation_dde7495"
    / "training.selection_blocked"
)
CALIBRATION = (
    PRIVATE_ROOT
    / "professor_approved_poc_evaluation_73b902e"
    / "calibration.json"
)


def _policy() -> dict:
    document = json.loads(
        (ROOT / "configs/prediction_policy.transformer_poc.trusted.json").read_text()
    )
    policy = document["policy"]
    policy.update(
        {
            "transformer_checkpoint_path": str(
                TRAINING
                / "seed_runs/transformer_seed_20260721/checkpoint.pt"
            ),
            "transformer_model_spec_path": str(TRAINING / "model_spec.json"),
            "transformer_vocabulary_path": str(TRAINING / "vocabulary.json"),
            "transformer_preprocessing_path": str(
                ROOT / "configs/next_behavior_preprocessing.v1.json"
            ),
            "transformer_calibration_path": str(CALIBRATION),
            "runtime_rule_policy_path": str(
                ROOT / "configs/classification_rules.trusted.json"
            ),
            "runtime_rule_policy_sha256": (
                "33f332946c53578f2e609a3a039dda712355b9e209721bcc073c61a623d6342b"
            ),
            "runtime_trust_policy_path": str(
                ROOT / "production/classification/trust.py"
            ),
            "runtime_classifier_checkpoint_path": str(
                Path("/home/rubchek/Desktop/honeypot-threat-intelligence")
                / "securebert_ttp_model_v2-20260714T172948Z-1-002"
                / "securebert_ttp_model_v2/checkpoint-6765/model.safetensors"
            ),
        }
    )
    return policy


def _payload() -> dict:
    return {
        "session_id": "runtime-session",
        "start_time": "2026-07-27T00:00:00Z",
        "protocol": "ssh",
        "status": "active",
        "is_ended": False,
        "login_success": True,
        "login_attempts": 1,
        "commands": ["redacted-command"],
        "classification_events": [
            {
                "cowrie_eventid": "cowrie.command.input",
                "event_timestamp": "2026-07-27T00:00:01Z",
                "compound_command_index": 0,
                "ttp": "T1059",
                "tactic": "execution",
                "source": "rule",
                "confidence": 1.0,
                "high_confidence": True,
                "agreement_status": "rule_only",
            }
        ],
        "raw_events": [],
    }


def test_transformer_policy_is_explicit_single_model() -> None:
    document = json.loads(
        (ROOT / "configs/prediction_policy.transformer_poc.trusted.json").read_text()
    )
    assert validate_policy_document(document) == []
    policy = document["policy"]
    assert policy["prediction_mode"] == MODE
    assert "primary_transition" not in policy
    assert policy["predictive_alerts"] == {"enabled": False}


def test_transformer_production_config_uses_policy_bound_rule_file() -> None:
    """The live classifier must use the exact artifact stamped into forecasts."""

    config = json.loads((ROOT / "configs/production_config.example.json").read_text())
    policy = json.loads(
        (ROOT / "configs/prediction_policy.transformer_poc.trusted.json").read_text()
    )["policy"]
    assert config["prediction_policy_path"] == (
        "configs/prediction_policy.transformer_poc.trusted.json"
    )
    assert config["classification_rules_path"] == policy["runtime_rule_policy_path"]
    assert hashlib.sha256(
        (ROOT / config["classification_rules_path"]).read_bytes()
    ).hexdigest() == policy["runtime_rule_policy_sha256"]


def test_live_adapter_uses_no_raw_command_text() -> None:
    safe = build_live_next_behavior_session(
        _payload(),
        rule_policy_sha256=_policy()["runtime_rule_policy_sha256"],
        trust_policy_sha256=_policy()["runtime_trust_policy_sha256"],
        classifier_checkpoint_sha256=_policy()[
            "runtime_classifier_checkpoint_sha256"
        ],
    )
    assert safe is not None
    serialized = json.dumps(safe, sort_keys=True)
    assert "redacted-command" not in serialized
    assert safe["observation_groups"][0]["tactics"] == ["execution"]


@pytest.mark.skipif(
    not (TRAINING / "seed_runs/transformer_seed_20260721/checkpoint.pt").is_file()
    or importlib.util.find_spec("torch") is None,
    reason="private frozen checkpoint or PyTorch is unavailable",
)
def test_exact_frozen_checkpoint_predicts_deterministically() -> None:
    predictor = FrozenTransformerPocPredictor(_policy())
    assert predictor.load_error == ""
    first = predictor.predict_session(_payload(), event_id="event-1")
    second = predictor.predict_session(_payload(), event_id="event-1")
    assert first["prediction_status"] == "predicted"
    assert first["prediction"] == second["prediction"]
    assert first["next_behavior_output"] == second["next_behavior_output"]
    assert first["active_model"]["checkpoint_sha256"] == (
        "7fbd73c4bd071336fa52a589bf41e39f5a3122a67aee398dfb8e6dd9cfdfb04a"
    )
    assert first["authority"] == AUTHORITY
    assert first["predictive_alert"]["status"] == "prohibited"


def test_corrupt_checkpoint_fails_only_the_predictor(tmp_path: Path) -> None:
    checkpoint = tmp_path / "checkpoint.pt"
    checkpoint.write_bytes(b"not-the-frozen-checkpoint")
    policy = _policy()
    policy["transformer_checkpoint_path"] = str(checkpoint)
    predictor = FrozenTransformerPocPredictor(policy)
    snapshot = predictor.predict_session(_payload(), event_id="event-2")
    assert snapshot["prediction_status"] == "model_unavailable"
    assert snapshot["prediction"] == []
    assert snapshot["final_ranking"] == []
    assert snapshot["authority"]["may_authorize_action"] is False


def test_no_trusted_phase_is_explicit_not_a_fallback() -> None:
    if importlib.util.find_spec("torch") is None:
        pytest.skip("PyTorch is unavailable")
    predictor = FrozenTransformerPocPredictor(_policy())
    payload = _payload()
    payload["classification_events"][0]["source"] = "shell_noise"
    payload["classification_events"][0]["tactic"] = "unknown"
    payload["classification_events"][0]["ttp"] = None
    snapshot = predictor.predict_session(payload, event_id="event-3")
    assert snapshot["prediction_status"] == "insufficient_history"
    assert snapshot["prediction_status_reason"] == "no_trusted_behavior_phase"
    assert snapshot["prediction"] == []
    assert "vomm" not in json.dumps(snapshot).lower()


def test_api_and_ui_expose_advisory_corrected_target_semantics() -> None:
    predictor = FrozenTransformerPocPredictor(_policy())
    snapshot = predictor.predict_session(_payload(), event_id="event-4")
    api = _current_prediction_payload({"payload": snapshot}, [])
    assert api["prediction_contract"] == (
        "next_distinct_command_behavior_phase_or_session_end.v1"
    )
    assert api["active_model"]["model_type"] == "small_causal_transformer"
    assert api["authority"]["may_create_alert_alone"] is False
    html = _render_prediction_panel(
        {"ok": True, "latest_prediction_snapshot": {"payload": snapshot}}
    )
    assert "primary experimental PoC forecast" in html
    assert "advisory / non-authoritative" in html
    assert "BLOCKED_AT_SELECTION" in html
