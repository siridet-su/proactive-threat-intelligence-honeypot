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
BEHAVIOR_POLICY = (
    ROOT / "configs/threat_hypothesis_behavior.trusted.json"
)
CLASSIFICATION_POLICY = ROOT / "configs/classification_rules.trusted.json"
EVALUATOR_REVISION = "8db3744fd7544d3045d4273a82c8d3173443b69d"
SCHEDULE_SPECS = (
    (
        ROOT
        / "evaluation/scheduled_task_shadow_independent_frozen.v1.json",
        "58ee45986f455fa9273511094033e602bfffce927a95650cdbdcbdd74e782fbf",
        "typed_scheduled_task_shadow_evaluation.v1",
        12,
    ),
    (
        ROOT
        / "evaluation/scheduled_task_shadow_holdout_frozen.v1.json",
        "f96dc470e6547d6fa63639d18f2626c8a83c94d2573a9530f3ba9a7b696dba0a",
        "typed_scheduled_task_shadow_holdout.v1",
        6,
    ),
)
SERVICE_SPECS = (
    (
        ROOT / "evaluation/service_shadow_independent_frozen.v1.json",
        "90620bfa3441873c01950a4b9af337fb4585070cd0509a7db5a7e4e00ee48a6c",
        "typed_service_shadow_evaluation.v1",
        12,
    ),
    (
        ROOT / "evaluation/service_shadow_holdout_frozen.v1.json",
        "905cb17e33fe88061973a5344b8bbbca1869096e4c3f484019925fcd4725f728",
        "typed_service_shadow_holdout.v1",
        6,
    ),
)


def _load_spec(
    path: Path,
    digest: str,
    schema: str,
    count: int,
) -> dict[str, Any]:
    raw = path.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == digest
    value = json.loads(raw)
    assert value["schema_version"] == schema
    assert value["expected_labels_frozen_before_execution"] is True
    assert len(value["cases"]) == count
    return value


def _payload(case: dict[str, Any], family: str) -> dict[str, Any]:
    session_id = f"{family}-shadow-{case['case_id'].lower()}"
    eventid = {
        "success": "cowrie.command.success",
        "failure": "cowrie.command.failed",
        "unknown": "cowrie.command.input",
    }[case["outcome"]]
    event: dict[str, Any] = {
        "session": session_id,
        "src_ip": "192.0.2.148",
        "timestamp": "2026-07-30T20:00:00Z",
        "eventid": eventid,
        "input": case["command"],
    }
    if case["outcome"] != "unknown":
        event["success"] = int(case["outcome"] == "success")
    return {
        "session_id": session_id,
        "src_ip": "192.0.2.148",
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
    family: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    payload = _payload(case, family)
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


def _assert_shadow_case(
    case: dict[str, Any],
    family: str,
) -> None:
    fact_set, report = _build(case, family)
    assert _operations(fact_set) == case["expected_operations"], (
        case["case_id"]
    )
    assert validate_typed_semantic_fact_set(fact_set) == []
    assert validate_session_assessment_v4(report) == []
    assert not any(
        item.get("semantic_family") == family
        for item in report["behavioral_findings"]
    )
    assert not any(
        item.get("semantic_family") == family
        for item in report["hypothesis_sets"]
    )
    assert not any(
        item.get("semantic_family") == family
        for item in report["response_guidance_v3"]["findings"]
    )
    assert not any(
        item.get("semantic_family") == family
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
            family=family,
        )
    facts_two, report_two = _build(case, family)
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


def test_frozen_scheduled_task_shadow_sets() -> None:
    for path, digest, schema, count in SCHEDULE_SPECS:
        for case in _load_spec(
            path,
            digest,
            schema,
            count,
        )["cases"]:
            _assert_shadow_case(case, "scheduled_task")


def test_frozen_service_shadow_sets() -> None:
    for path, digest, schema, count in SERVICE_SPECS:
        for case in _load_spec(
            path,
            digest,
            schema,
            count,
        )["cases"]:
            _assert_shadow_case(case, "service")
