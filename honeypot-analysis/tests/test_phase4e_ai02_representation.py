"""Phase 4E AI-02 classifier score-semantics presentation tests."""

from __future__ import annotations

import copy

from production.api.monitor_web import (
    _render_classifications,
    _render_prediction_panel,
)


def _classification_events() -> list[dict]:
    return [
        {
            "command": "id",
            "ttp": "T1033",
            "tactic": "discovery",
            "source": "rule",
            "confidence": 1.0,
            "high_confidence": True,
            "agreement_status": "rule_only",
            "confidence_semantics": (
                "reviewed_rule_policy_match_not_calibrated_probability"
            ),
            "authority_decision": {"decision": "trusted", "trusted_eligible": True},
        },
        {
            "command": "whoami",
            "ttp": "T1033",
            "tactic": "discovery",
            "source": "both",
            "confidence": 1.0,
            "bert_confidence": 0.83,
            "high_confidence": True,
            "agreement_status": "exact_technique_agreement",
            "confidence_semantics": (
                "rule_model_agreement_not_calibrated_probability"
            ),
            "authority_decision": {"decision": "trusted", "trusted_eligible": True},
        },
        {
            "command": "uname -a",
            "ttp": "T1082",
            "tactic": "discovery",
            "source": "securebert",
            "confidence": 0.91,
            "high_confidence": False,
            "agreement_status": "model_only",
            "confidence_semantics": "model_score_not_calibrated_probability",
            "authority_decision": {"decision": "audit_only", "trusted_eligible": False},
        },
        {
            "command": "cat /etc/passwd",
            "ttp": "T1005",
            "tactic": "collection",
            "source": "rule_securebert_disagreement",
            "confidence": 0.80,
            "bert_confidence": 0.70,
            "high_confidence": False,
            "agreement_status": "technique_and_tactic_disagreement",
            "confidence_semantics": "conflicting_classifier_outputs_audit_only",
            "authority_decision": {"decision": "audit_only", "trusted_eligible": False},
        },
        {
            "command": "ps",
            "ttp": "T1057",
            "tactic": "discovery",
            "source": "both",
            "confidence": 1.0,
            "bert_confidence": None,
            "high_confidence": True,
            "agreement_status": "rule_only",
            "confidence_semantics": (
                "rule_model_agreement_not_calibrated_probability"
            ),
            "authority_decision": {"decision": "trusted", "trusted_eligible": True},
        },
    ]


def _selected(events: list[dict]) -> dict:
    return {"payload": {"classification_events": events}}


def _normal_prediction_detail(events: list[dict]) -> dict:
    return {
        "ok": True,
        "latest_prediction_snapshot": {
            "payload": {
                "prediction_status": "abstained",
                "prediction_status_reason": "no supported context",
                "features": {
                    "commands": ["id", "whoami"],
                    "classification_events": events,
                },
            }
        },
    }


def test_reviewed_rule_value_is_explicitly_non_probabilistic() -> None:
    html = _render_classifications(_selected([_classification_events()[0]]))

    assert "rule/policy value" in html
    assert "model/SecureBERT score" in html
    assert "reviewed rule policy match (not a calibrated probability)" in html
    assert '<td class="num">1.00</td><td class="num">-</td>' in html
    assert "<th>confidence</th>" not in html


def test_rule_model_agreement_keeps_rule_and_model_values_separate() -> None:
    event = _classification_events()[1]
    before = copy.deepcopy(event)
    html = _render_classifications(_selected([event]))

    assert '<td class="num">1.00</td><td class="num">0.83</td>' in html
    assert "rule policy match; model score shown separately" in html
    assert "neither is a calibrated probability" in html
    assert event == before


def test_model_only_and_disagreement_remain_audit_only() -> None:
    events = _classification_events()[2:4]
    html = _render_classifications(_selected(events))

    assert '<td class="num">-</td><td class="num">0.91</td>' in html
    assert "SecureBERT/model score (not a calibrated probability; audit-only)" in html
    assert '<td class="num">0.80</td><td class="num">0.70</td>' in html
    assert "audit-only rule/model disagreement" in html
    assert all(item["authority_decision"]["trusted_eligible"] is False for item in events)
    assert all(item["high_confidence"] is False for item in events)


def test_missing_optional_model_score_and_unknown_marker_fail_closed_in_presentation() -> None:
    events = [_classification_events()[4], {
        "command": "printf x",
        "ttp": "T0000_UNKNOWN",
        "tactic": "unknown",
        "source": "rule",
        "confidence": 1.0,
        "confidence_semantics": "unrecognized_marker",
    }]
    html = _render_classifications(_selected(events))

    assert '<td class="num">1.00</td><td class="num">-</td>' in html
    assert "classifier score semantics unavailable (not a calibrated probability)" in html
    assert "Traceback" not in html


def test_prediction_feature_renderer_uses_same_semantics_without_changing_events() -> None:
    events = _classification_events()
    before = copy.deepcopy(events)
    html = _render_prediction_panel(_normal_prediction_detail(events))

    assert "Raw classification audit trail" in html
    assert "rule/policy value" in html
    assert "model/SecureBERT score" in html
    assert "Model-only and disagreement entries remain audit-only." in html
    assert "probability of attack" not in html.lower()
    assert events == before


def test_changed_classifier_output_contains_no_prohibited_probability_claims() -> None:
    html = _render_classifications(_selected(_classification_events())).lower()
    prohibited = (
        "100% probability",
        "probability of attack",
        "probability attacker performed",
        "100% accurate",
        "ai probability",
        "confirmed attack",
        "confirmed attacker intent",
    )
    assert all(term not in html for term in prohibited)


def test_calibrated_forecast_table_remains_explicitly_separate() -> None:
    html = _render_prediction_panel(
        {
            "ok": True,
            "latest_prediction_snapshot": {
                "payload": {
                    "prediction_mode": (
                        "professor_approved_corrected_target_transformer_poc"
                    ),
                    "prediction_status": "predicted",
                    "active_model": {"model_type": "small_causal_transformer"},
                    "next_behavior_output": {
                        "ranked_tactics": [
                            {
                                "rank": 1,
                                "tactic": "discovery",
                                "calibrated_probability": 0.61,
                                "raw_score": 0.44,
                            }
                        ]
                    },
                }
            },
        }
    )
    assert "calibrated probability" in html
    assert "raw logit" in html
