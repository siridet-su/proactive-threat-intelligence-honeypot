from __future__ import annotations

import json

import pytest

from production.tools.score_threat_hypothesis_single_reviewer import (
    CRITERIA,
    RUBRIC_VERSION,
    build_review_templates,
    score_judgments,
    validate_judgment,
)


def _judgment(case_id: str, review_round: int, **overrides: str) -> dict:
    row = {
        "case_id": case_id,
        "review_round": review_round,
        "rubric_version": RUBRIC_VERSION,
        "relationship_links_correct": "yes",
        "claims_evidence_grounded": "yes",
        "evidence_references_correct": "yes",
        "abstention_appropriate": "yes",
        "overclaim_present": "no",
    }
    row.update(overrides)
    return row


def test_review_templates_are_pseudonymous_and_round_two_reverses_order() -> None:
    templates = build_review_templates(3)
    assert [item["case_id"] for item in templates[1]] == [
        "case-001",
        "case-002",
        "case-003",
    ]
    assert [item["case_id"] for item in templates[2]] == [
        "case-003",
        "case-002",
        "case-001",
    ]
    assert all(item["rubric_version"] == RUBRIC_VERSION for item in templates[1] + templates[2])
    assert all(item[criterion] is None for item in templates[1] for criterion in CRITERIA)


def test_single_reviewer_scoring_reports_repeat_agreement_without_case_ids() -> None:
    judgments = [
        _judgment("case-001", 1),
        _judgment("case-001", 2),
        _judgment("case-002", 1),
        _judgment(
            "case-002",
            2,
            relationship_links_correct="no",
            abstention_appropriate="no",
            overclaim_present="yes",
        ),
    ]
    result = score_judgments(judgments)
    assert result["judgment_count"] == 4
    assert result["unique_case_count"] == 2
    assert result["paired_case_count"] == 2
    assert result["derived_quality_rates"] == {
        "relationship_correctness_rate": 0.75,
        "claim_grounding_rate": 1.0,
        "evidence_reference_correctness_rate": 1.0,
        "abstention_appropriateness_rate": 0.75,
        "overclaim_concern_rate": 0.25,
    }
    assert result["repeat_agreement"]["relationship_links_correct"]["percent_agreement"] == 0.5
    assert result["repeat_agreement"]["claims_evidence_grounded"]["percent_agreement"] == 1.0
    assert result["repeat_agreement"]["claims_evidence_grounded"]["cohen_kappa"] is None
    assert result["round_quality_rates"]["1"]["relationship_correctness_rate"] == 1.0
    assert result["round_quality_rates"]["2"]["relationship_correctness_rate"] == 0.5
    assert "not independent observations" in result["derived_rate_semantics"]
    encoded = json.dumps(result, sort_keys=True)
    assert "case-001" not in encoded
    assert "case-002" not in encoded


def test_single_reviewer_input_rejects_free_form_or_identifying_fields() -> None:
    with pytest.raises(ValueError, match="free-form telemetry"):
        validate_judgment(
            {**_judgment("case-001", 1), "notes": "raw command here"},
            source="unit",
        )
    with pytest.raises(ValueError, match="pseudonym"):
        validate_judgment(_judgment("person@example.com", 1), source="unit")
    with pytest.raises(ValueError, match="must be one of"):
        validate_judgment(
            _judgment("case-001", 1, claims_evidence_grounded="probably"),
            source="unit",
        )
    with pytest.raises(ValueError, match="Duplicate"):
        score_judgments([
            _judgment("case-001", 1),
            _judgment("case-001", 1),
        ])
