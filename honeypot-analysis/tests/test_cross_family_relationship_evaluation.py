from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

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


ROOT = Path(__file__).resolve().parents[1]
BEHAVIOR_POLICY = (
    ROOT / "configs/threat_hypothesis_behavior.trusted.json"
)
CLASSIFICATION_POLICY = ROOT / "configs/classification_rules.trusted.json"
EVALUATOR_REVISION = "c5554e944587b1148548a0bc02bb8ff0016c8006"
SPECS = (
    (
        ROOT
        / "evaluation/cross_family_relationship_independent_frozen.v1.json",
        "943a96e0dd1f796c90ed625e952905b40fc1199050312429dedea3fe7ab79822",
        "typed_cross_family_relationship_evaluation.v1",
        8,
    ),
    (
        ROOT
        / "evaluation/cross_family_relationship_holdout_frozen.v1.json",
        "bf681044edffb5c663b7b85702f19dc8e632e0df0b1d03c4d0a7ed38cb9ef161",
        "typed_cross_family_relationship_holdout.v1",
        4,
    ),
)


def _load(
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


def _payload(case: dict[str, Any]) -> dict[str, Any]:
    session_id = f"cross-family-{case['case_id'].lower()}"
    base = datetime(2026, 7, 30, 22, 0, tzinfo=timezone.utc)
    events = []
    successful = []
    failed = []
    commands = []
    for index, (command, outcome) in enumerate(case["events"]):
        eventid = {
            "success": "cowrie.command.success",
            "failure": "cowrie.command.failed",
            "unknown": "cowrie.command.input",
        }[outcome]
        event: dict[str, Any] = {
            "session": session_id,
            "src_ip": "192.0.2.181",
            "timestamp": (
                base + timedelta(seconds=index)
            ).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "eventid": eventid,
            "input": command,
        }
        if outcome != "unknown":
            event["success"] = int(outcome == "success")
        events.append(event)
        commands.append(command)
        if outcome == "success":
            successful.append(command)
        elif outcome == "failure":
            failed.append(command)
    return {
        "session_id": session_id,
        "src_ip": "192.0.2.181",
        "commands": commands,
        "commands_success": successful,
        "commands_failed": failed,
        "classification_events": [],
        "raw_events": events,
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
        prediction_context={
            "predicted_tactic": "exfiltration",
            "recommendations": ["invent causal chain"],
        },
        enrichment_context={
            "reputation": "malicious",
            "recommendations": ["invent archive contents"],
        },
        correlation_context=[{
            "claim": "invent cross-session execution",
        }],
        llm_context={
            "hypothesis": "invented attacker intent",
        },
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
    semantic_families = {
        item.get("semantic_family")
        for item in report["behavioral_findings"]
        if item.get("semantic_family")
    }
    action_families = {
        item.get("semantic_family")
        for item in report["response_guidance_v3"][
            "advisory_actions"
        ]
        if item.get("semantic_family")
    }

    assert _operations(fact_set) == case["expected_operations"], (
        case["case_id"]
    )
    assert semantic_families == set(case["expected_families"])
    assert action_families == set(
        case["expected_action_families"]
    )
    assert report["hypothesis_sets"] == []
    assert not {
        "transformation",
        "collection",
        "scheduled_task",
        "service",
    }.intersection(semantic_families)
    assert validate_typed_semantic_fact_set(fact_set) == []
    assert validate_session_assessment_v4(report) == []
    for relationship in fact_set["relationships"]:
        assert relationship["causality_semantics"] == (
            "evidence_link_not_causal_or_intent_proof"
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


def test_frozen_cross_family_relationship_sets() -> None:
    for path, digest, schema, count in SPECS:
        for case in _load(path, digest, schema, count)["cases"]:
            _assert_case(case)

