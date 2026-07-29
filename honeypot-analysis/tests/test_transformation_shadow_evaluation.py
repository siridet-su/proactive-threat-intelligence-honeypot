from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from production.policies.threat_hypothesis_behavior_policy import (
    policy_summary,
)
from production.reporting.session_assessment_v4 import (
    build_canonical_evidence_snapshot,
    build_session_assessment_v4,
    validate_session_assessment_v4,
)
from production.reporting.typed_semantic_facts import (
    build_typed_semantic_fact_set,
    build_typed_semantic_provenance,
    validate_typed_semantic_fact_set,
)
from production.reporting.typed_semantic_family_selection import (
    TypedSemanticFamilySelectionError,
    select_activated_semantic_family,
)


ROOT = Path(__file__).resolve().parents[1]
SPEC_PATH = (
    ROOT
    / "evaluation/transformation_shadow_independent_frozen.v1.json"
)
SPEC_SHA256 = (
    "759b485fd471bad75abef787ec747ff9e2369c76fcfe9ccbfc69d722024c8518"
)
HOLDOUT_PATH = (
    ROOT / "evaluation/transformation_shadow_holdout_frozen.v1.json"
)
HOLDOUT_SHA256 = (
    "8dc32288c153c29d711b3e3091ca9be49086ed26deb099f1e2a5873391baf7fa"
)
BEHAVIOR_POLICY = (
    ROOT / "configs/threat_hypothesis_behavior.trusted.json"
)
CLASSIFICATION_POLICY = ROOT / "configs/classification_rules.trusted.json"
EVALUATOR_REVISION = "574df6c140a5fec186fbdc2d8f9aa4411d392723"


def _spec() -> dict[str, Any]:
    raw = SPEC_PATH.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == SPEC_SHA256
    value = json.loads(raw)
    assert value["schema_version"] == (
        "typed_transformation_shadow_evaluation.v1"
    )
    assert value["expected_labels_frozen_before_execution"] is True
    assert len(value["cases"]) == 12
    return value


def _holdout() -> dict[str, Any]:
    raw = HOLDOUT_PATH.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == HOLDOUT_SHA256
    value = json.loads(raw)
    assert value["schema_version"] == (
        "typed_transformation_shadow_holdout.v1"
    )
    assert value["expected_labels_frozen_before_execution"] is True
    assert len(value["cases"]) == 6
    return value


def _payload(case: dict[str, Any]) -> dict[str, Any]:
    session_id = f"transformation-shadow-{case['case_id'].lower()}"
    eventid = {
        "success": "cowrie.command.success",
        "failure": "cowrie.command.failed",
        "unknown": "cowrie.command.input",
    }[case["outcome"]]
    event: dict[str, Any] = {
        "session": session_id,
        "src_ip": "192.0.2.92",
        "timestamp": "2026-07-30T18:00:00Z",
        "eventid": eventid,
        "input": case["command"],
    }
    if case["outcome"] != "unknown":
        event["success"] = int(case["outcome"] == "success")
    return {
        "session_id": session_id,
        "src_ip": "192.0.2.92",
        "commands": [case["command"]],
        "commands_success": (
            [case["command"]] if case["outcome"] == "success" else []
        ),
        "commands_failed": (
            [case["command"]] if case["outcome"] == "failure" else []
        ),
        "classification_events": [],
        "raw_events": [event],
    }


def _build(
    case: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    payload = _payload(case)
    snapshot, observed, _source, behavior = (
        build_canonical_evidence_snapshot(
            payload,
            payload["raw_events"],
            behavior_policy_path=str(BEHAVIOR_POLICY),
        )
    )
    provenance = build_typed_semantic_provenance(
        snapshot,
        observed_behavior=observed,
        behavior_policy_sha256=policy_summary(
            behavior,
            include_integrity=True,
        )["sha256"],
        classification_policy_sha256=hashlib.sha256(
            CLASSIFICATION_POLICY.read_bytes()
        ).hexdigest(),
        evaluator_git_revision=EVALUATOR_REVISION,
    )
    fact_set = build_typed_semantic_fact_set(
        observed,
        provenance=provenance,
    )
    report = build_session_assessment_v4(
        [payload],
        raw_events=payload["raw_events"],
        behavior_policy_path=str(BEHAVIOR_POLICY),
        classification_policy_path=str(CLASSIFICATION_POLICY),
    )
    return fact_set, report


def _operations(fact_set: dict[str, Any]) -> list[str]:
    result: list[str] = []
    for fact in fact_set["facts"]:
        operations = [
            operation["operation_type"]
            for operation in fact["operations"]
        ]
        result.extend(operations or ["unknown"])
    return result


def _assert_case(case: dict[str, Any]) -> None:
    fact_set, report = _build(case)

    assert _operations(fact_set) == case["expected_operations"], (
        case["case_id"]
    )
    assert validate_typed_semantic_fact_set(fact_set) == []
    assert validate_session_assessment_v4(report) == []
    assert not any(
        item.get("semantic_family") == "transformation"
        for item in report["behavioral_findings"]
    )
    assert not any(
        item.get("semantic_family") == "transformation"
        for item in report["hypothesis_sets"]
    )
    assert not any(
        item.get("semantic_family") == "transformation"
        for item in report["response_guidance_v3"]["findings"]
    )
    assert not any(
        item.get("semantic_family") == "transformation"
        for item in report["response_guidance_v3"][
            "advisory_actions"
        ]
    )
    with pytest.raises(
        TypedSemanticFamilySelectionError,
        match="not activated",
    ):
        select_activated_semantic_family(
            fact_set,
            family="transformation",
        )

    facts_two, report_two = _build(case)
    assert facts_two == fact_set
    assert report_two["assessment_id"] == report["assessment_id"]
    assert (
        report_two["behavioral_findings"]
        == report["behavioral_findings"]
    )
    assert (
        report_two["response_guidance_v3"]["guidance_id"]
        == report["response_guidance_v3"]["guidance_id"]
    )


def test_frozen_transformation_shadow_evaluation() -> None:
    for case in _spec()["cases"]:
        _assert_case(case)


def test_frozen_transformation_shadow_holdout() -> None:
    for case in _holdout()["cases"]:
        _assert_case(case)
