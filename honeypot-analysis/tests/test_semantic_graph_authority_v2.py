from __future__ import annotations

from copy import deepcopy

import pytest

from production.prediction.trusted_history import (
    build_prediction_trusted_history_manifest,
    validate_prediction_trusted_history_manifest,
)
from production.reporting.behavioral_authority import (
    apply_behavioral_authority,
)
from production.reporting.canonical_semantic_graph import (
    build_canonical_semantic_graph,
    validate_canonical_semantic_graph,
)
from production.reporting.semantic_coverage import (
    build_semantic_coverage,
    validate_semantic_coverage,
)
from production.utils.serialization import stable_id


def test_history_v2_preserves_exact_tactic_technique_pairs_and_truncation() -> None:
    phases = [
        {
            "command_index": index,
            "event_id": f"event-{index}",
            "labels": [
                {"tactic": "execution", "technique": f"T{index + 1000:04d}"},
                {"tactic": "execution", "technique": f"T{index + 2000:04d}"},
            ],
        }
        for index in range(10)
    ]
    manifest = build_prediction_trusted_history_manifest(
        phases=phases,
        evidence_cutoff={"schema_version": "prediction_evidence_cutoff.v1", "event_id": "event-10"},
        classifier_environment={"environment_sha256": "a" * 64},
    )
    assert manifest["schema_version"] == "prediction_trusted_history_manifest.v2"
    assert manifest["original_trusted_phase_count"] == 10
    assert manifest["selected_trusted_phase_count"] == 8
    assert manifest["omitted_prefix_phase_count"] == 2
    assert manifest["truncated"] is True
    assert manifest["ordered_trusted_phases"][-1]["labels"] == [
        {"tactic": "execution", "technique": "T1009"},
        {"tactic": "execution", "technique": "T2009"},
    ]


def test_unversioned_partial_coverage_is_rejected() -> None:
    observed = {
        "ordered_command_observations": [
            {"evidence_id": f"command-{index}", "command": "id"}
            for index in range(3)
        ],
        "transfer_event_observations": [],
    }
    with pytest.raises(ValueError, match="invalid semantic coverage status"):
        build_semantic_coverage(
            observed,
            typed_analyzed_count=2,
            status="partial",
            reason_code="bounded_test",
            limit_reached="max_facts",
            typed_metrics={
                "fact_count": 2,
                "entity_count": 1,
                "relationship_count": 0,
                "chain_count": 0,
            },
        )


def test_unavailable_coverage_has_zero_typed_analysis() -> None:
    observed = {
        "ordered_command_observations": [
            {"evidence_id": "command-0", "command": "id"}
        ],
        "transfer_event_observations": [],
    }
    coverage = build_semantic_coverage(
        observed,
        typed_analyzed_count=0,
        status="unavailable",
        reason_code="typed_policy_validation_failed",
    )
    assert validate_semantic_coverage(coverage) == []
    assert coverage["coverage_status"] == "unavailable"
    assert coverage["typed_analyzed_count"] == 0
    assert coverage["omitted_count"] == 1


def test_tampered_v2_history_phase_ordered_and_manifest_hashes_fail_closed() -> None:
    manifest = build_prediction_trusted_history_manifest(
        phases=[
            {
                "command_index": 1,
                "event_id": "event-1",
                "labels": [{"tactic": "execution", "technique": "T1059"}],
            }
        ],
        evidence_cutoff={
            "schema_version": "prediction_evidence_cutoff.v1",
            "received_at": "2026-08-12T00:00:00.000000+00:00",
            "event_id": "event-1",
        },
        classifier_environment={"environment_sha256": "a" * 64},
    )
    assert validate_prediction_trusted_history_manifest(manifest) == []
    for field, mutate in (
        ("phase_sha256", lambda value: value["ordered_trusted_phases"][0].update({"phase_sha256": "d" * 64})),
        ("ordered_trusted_phases_sha256", lambda value: value.update({"ordered_trusted_phases_sha256": "b" * 64})),
        ("history_manifest_sha256", lambda value: value.update({"history_manifest_sha256": "c" * 64})),
    ):
        tampered = deepcopy(manifest)
        mutate(tampered)
        assert validate_prediction_trusted_history_manifest(tampered)


def test_conflicting_duplicate_evidence_and_unresolved_authority_reference_fail_closed() -> None:
    observed = {
        "evidence_sha256": "a" * 64,
        "observations": [{"evidence_id": "e1", "status": "observed"}],
        "direct_cowrie_events": [{"evidence_id": "e1", "status": "rejected"}],
    }
    coverage = build_semantic_coverage(observed)
    with pytest.raises(ValueError, match="conflicting semantic/status/provenance"):
        build_canonical_semantic_graph(
            observed,
            typed_fact_set={"fact_set_sha256": "b" * 64, "facts": [], "relationships": [], "chains": []},
            coverage=coverage,
        )
    clean_observed = {
        "evidence_sha256": "a" * 64,
        "observations": [{"evidence_id": "e1", "status": "observed"}],
    }
    graph = build_canonical_semantic_graph(
        clean_observed,
        typed_fact_set={"fact_set_sha256": "b" * 64, "facts": [], "relationships": [], "chains": []},
        coverage=build_semantic_coverage(clean_observed),
        authority_decisions=[
            {
                "schema_version": "behavioral_authority_decision.v1",
                "candidate_id": "candidate-1",
                "semantic_family": "",
                "candidate_source": "legacy",
                "authority_mode": "audit_only_until_typed",
                "typed_family_state": "deferred",
                "decision": "audit_only",
                "reason_codes": ["legacy_candidate_not_explicitly_reviewed_fallback"],
                "policy_rule_id": "",
                "evidence_refs": ["missing"],
                "relationship_refs": [],
                "chain_refs": [],
                "decision_sha256": "0" * 64,
            }
        ],
    )
    # Recompute the graph digest to isolate reference validation from hash
    # tampering; the unresolved reference must still fail closed.
    import hashlib
    from production.utils.serialization import stable_json
    graph["authority_decisions"][0]["decision_sha256"] = hashlib.sha256(
        stable_json({key: value for key, value in graph["authority_decisions"][0].items() if key != "decision_sha256"}).encode()
    ).hexdigest()
    graph["graph_sha256"] = hashlib.sha256(
        stable_json({key: value for key, value in graph.items() if key != "graph_sha256"}).encode()
    ).hexdigest()
    assert any("authority evidence reference" in error for error in validate_canonical_semantic_graph(graph))


def test_graph_rejects_unresolved_fact_relationship_chain_and_entity_references() -> None:
    observed = {"evidence_sha256": "a" * 64, "observations": [{"evidence_id": "e1"}]}
    fact_set = {
        "fact_set_sha256": "b" * 64,
        "facts": [
            {
                "fact_id": "f1",
                "entities": {},
                "evidence_references": [{"evidence_ref": "missing-evidence"}],
            }
        ],
        "entities": [],
        "relationships": [
            {
                "relationship_id": "r1",
                "source_fact_id": "missing-fact",
                "target_fact_id": "f1",
                "entity_ref": "missing-entity",
                "evidence_references": [{"evidence_ref": "missing-evidence"}],
            }
        ],
        "chains": [
            {
                "chain_id": "c1",
                "fact_refs": ["missing-fact"],
                "relationship_refs": ["missing-relationship"],
                "entity_refs": ["missing-entity"],
            }
        ],
    }
    graph = build_canonical_semantic_graph(
        observed,
        typed_fact_set=fact_set,
        coverage=build_semantic_coverage(observed),
    )
    errors = validate_canonical_semantic_graph(graph)
    assert any("fact evidence reference" in error for error in errors)
    assert any("relationship fact reference" in error for error in errors)
    assert any("relationship entity reference" in error for error in errors)
    assert any("chain fact reference" in error for error in errors)
    assert any("chain required relationship" in error for error in errors)
    assert any("chain entity reference" in error for error in errors)


def test_graph_deduplicates_evidence_and_keeps_references_content_addressed() -> None:
    observed = {
        "evidence_sha256": "a" * 64,
        "observations": [{"evidence_id": "e1", "eventid": "command"}],
        "direct_cowrie_events": [{"evidence_id": "e1", "eventid": "command"}],
    }
    coverage = build_semantic_coverage(observed)
    graph = build_canonical_semantic_graph(
        observed,
        typed_fact_set={"fact_set_sha256": "b" * 64, "facts": [], "relationships": [], "chains": []},
        coverage=coverage,
    )
    assert len(graph["evidence_nodes"]) == 1
    assert graph["evidence_nodes"][0]["evidence_kinds"] == [
        "command_observation",
        "cowrie_event_observation",
    ]
    assert validate_canonical_semantic_graph(graph) == []


def test_authority_boundary_demotes_legacy_regex_and_keeps_typed_selection() -> None:
    legacy = {
        "finding_id": stable_id("finding", {"legacy": "one"}),
        "finding_type": "observed_legacy_candidate",
        "claim_basis": "reviewed_regex",
        "evidence_refs": ["e1"],
    }
    typed = {
        "finding_id": stable_id("finding", {"typed": "one"}),
        "finding_type": "observed_cowrie_inspection_command",
        "semantic_family": "inspection",
        "claim_basis": "typed_semantic_fact_set.v2",
        "evidence_refs": ["e1"],
    }
    trusted, audit_only, decisions = apply_behavioral_authority(
        [legacy, typed],
        typed_status="valid",
        activated_families=["inspection"],
    )
    assert [item["finding_type"] for item in trusted] == [
        "observed_cowrie_inspection_command"
    ]
    assert [item["finding_type"] for item in audit_only] == [
        "observed_legacy_candidate"
    ]
    assert {item["decision"] for item in decisions} == {"trusted", "audit_only"}


def test_v3_report_graph_and_coverage_are_consumed_without_rewriting_v1_v2() -> None:
    from tests.test_session_assessment_v4 import _payload
    from production.reporting.session_assessment_v4 import (
        build_session_assessment_v4,
        validate_session_assessment_v4,
    )

    payload = _payload()
    report = build_session_assessment_v4(
        [payload],
        raw_events=payload["raw_events"],
        behavior_policy_path="configs/threat_hypothesis_behavior.trusted.json",
        classification_policy_path="configs/classification_rules.trusted.json",
    )
    evidence = report["canonical_evidence"]
    assert evidence["schema_version"] == "canonical_evidence_snapshot.v3"
    assert evidence["observed_evidence_schema_version"] in {
        "canonical_evidence_snapshot.v1",
        "canonical_evidence_snapshot.v2",
    }
    assert evidence["semantic_coverage"]["coverage_status"] == "full"
    assert evidence["semantic_graph"]["schema_version"] == "canonical_semantic_graph.v1"
    assert validate_session_assessment_v4(report) == []
