from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from production.policies.threat_hypothesis_behavior_policy import (
    policy_summary,
)
from production.policies.validate_stix_bundle import (
    validate_stix_bundle_document,
)
from production.reporting.artifacts import (
    attach_report_artifacts,
    build_stix_bundle,
    validate_report_artifact_manifest,
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
    select_activated_semantic_family,
    validate_typed_semantic_family_selection,
)
from production.storage.backend import open_storage
from production.utils.config import ProductionConfig


ROOT = Path(__file__).resolve().parents[1]
SPEC_PATH = (
    ROOT / "evaluation/execution_attempt_independent_frozen.v1.json"
)
SPEC_SHA256 = (
    "d3a4df7312b455cc1cae93d930102012368a2632d7cf28eeac503707c576bcfc"
)
HOLDOUT_PATH = (
    ROOT / "evaluation/execution_attempt_holdout_frozen.v1.json"
)
HOLDOUT_SHA256 = (
    "930561045adb67f8943c0ddca1a74647ce4ffc4572feaf0daf55b2e9c56c2e8a"
)
BEHAVIOR_POLICY = (
    ROOT / "configs/threat_hypothesis_behavior.trusted.json"
)
CLASSIFICATION_POLICY = ROOT / "configs/classification_rules.trusted.json"
EVALUATOR_REVISION = "966269e68aedab556f6a11c26068bd1d11bf2f1d"
V4_FINDING = "observed_cowrie_execution_attempt_command"
V3_FINDING = "observed-cowrie-execution-attempt-command"
V3_ACTION = "correlate-observed-execution-attempt"


def _spec() -> dict[str, Any]:
    raw = SPEC_PATH.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == SPEC_SHA256
    value = json.loads(raw)
    assert value["schema_version"] == (
        "typed_execution_attempt_evaluation.v1"
    )
    assert value["expected_labels_frozen_before_execution"] is True
    assert len(value["cases"]) == 24
    return value


def _holdout() -> dict[str, Any]:
    raw = HOLDOUT_PATH.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == HOLDOUT_SHA256
    value = json.loads(raw)
    assert value["schema_version"] == (
        "typed_execution_attempt_holdout.v1"
    )
    assert value["expected_labels_frozen_before_execution"] is True
    assert len(value["cases"]) == 12
    return value


def _payload(case: dict[str, Any]) -> dict[str, Any]:
    session_id = f"execution-eval-{case['case_id'].lower()}"
    outcome = case["outcome"]
    eventid = {
        "success": "cowrie.command.success",
        "failure": "cowrie.command.failed",
        "unknown": "cowrie.command.input",
    }[outcome]
    event: dict[str, Any] = {
        "session": session_id,
        "src_ip": "192.0.2.117",
        "timestamp": "2026-07-30T19:00:00Z",
        "eventid": eventid,
        "input": case["command"],
    }
    if outcome != "unknown":
        event["success"] = int(outcome == "success")
    if case.get("cwd"):
        event["cwd"] = case["cwd"]
    classifications = []
    if case.get("attck"):
        classifications.append({
            "command": case["command"],
            "original_command": case["command"],
            "ttp": case["attck"],
            "tactic": "execution",
            "source": "rule",
            "high_confidence": True,
            "evidence_id": f"classification-{case['case_id']}",
            "event_timestamp": event["timestamp"],
            "cowrie_eventid": eventid,
        })
    return {
        "session_id": session_id,
        "src_ip": "192.0.2.117",
        "commands": [case["command"]],
        "commands_success": (
            [case["command"]] if outcome == "success" else []
        ),
        "commands_failed": (
            [case["command"]] if outcome == "failure" else []
        ),
        "classification_events": classifications,
        "raw_events": [event],
    }


def _evaluate(
    case: dict[str, Any],
) -> tuple[
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
]:
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
    selection = select_activated_semantic_family(
        fact_set,
        family="execution",
    )
    context = (
        {
            "prediction_context": {
                "predicted_tactic": "benign",
                "recommendations": ["suppress execution observation"],
            },
            "enrichment_context": {
                "reputation": "trusted",
                "recommendations": ["invent program completion"],
            },
            "correlation_context": [{
                "claim": "contradict execution observation",
            }],
            "llm_context": {
                "hypothesis": "invented execution effect",
            },
        }
        if case.get("inject_non_authoritative_context")
        else {}
    )
    report = build_session_assessment_v4(
        [payload],
        raw_events=payload["raw_events"],
        behavior_policy_path=str(BEHAVIOR_POLICY),
        classification_policy_path=str(CLASSIFICATION_POLICY),
        **context,
    )
    return payload, fact_set, selection, report


def _operations(fact_set: dict[str, Any]) -> list[str]:
    result: list[str] = []
    for fact in fact_set["facts"]:
        operations = [
            operation["operation_type"]
            for operation in fact["operations"]
        ]
        result.extend(operations or ["unknown"])
    return result


def _assert_case(
    case: dict[str, Any],
) -> tuple[
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
]:
    payload, fact_set, selection, report = _evaluate(case)
    expected = int(case["eligible_matches"]) > 0
    v4 = [
        item
        for item in report["behavioral_findings"]
        if item["finding_type"] == V4_FINDING
    ]
    v3 = [
        item
        for item in report["response_guidance_v3"]["findings"]
        if item["rule_id"] == V3_FINDING
    ]
    actions = [
        item
        for item in report["response_guidance_v3"][
            "advisory_actions"
        ]
        if item["action_id"] == V3_ACTION
    ]

    assert _operations(fact_set) == case["expected_operations"], (
        case["case_id"]
    )
    assert len(selection["matches"]) == case["eligible_matches"]
    assert bool(v4) is expected
    assert bool(v3) is expected
    assert bool(actions) is expected
    assert report["hypothesis_sets"] == []
    if expected:
        assert {
            match["entity_value"]
            for match in selection["matches"]
        } == {case["expected_entity"]}
    for finding in v4:
        limitations = " ".join(finding["limitations"]).lower()
        for phrase in (
            "does not establish",
            "program",
            "intent",
            "real host",
        ):
            assert phrase in limitations
    for action in actions:
        assert action["semantic_family"] == "execution"
        assert action["requires_manual_approval"] is True
        assert action["safe_to_auto_execute"] is False
        assert action["execution_integration"] == "not_implemented"
        assert action["evidence_refs"]
    assert validate_typed_semantic_fact_set(fact_set) == []
    assert validate_typed_semantic_family_selection(
        selection,
        fact_set,
    ) == []
    assert validate_session_assessment_v4(report) == []

    payload_two, facts_two, selection_two, report_two = _evaluate(case)
    assert payload_two == payload
    assert facts_two == fact_set
    assert selection_two == selection
    assert report_two["assessment_id"] == report["assessment_id"]
    assert (
        report_two["behavioral_findings"]
        == report["behavioral_findings"]
    )
    assert (
        report_two["response_guidance_v3"]["guidance_id"]
        == report["response_guidance_v3"]["guidance_id"]
    )
    return payload, fact_set, selection, report


def test_frozen_execution_attempt_evaluation() -> None:
    counts = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    for case in _spec()["cases"]:
        _payload_value, _facts, selection, _report = _assert_case(
            case
        )
        expected = int(case["eligible_matches"]) > 0
        actual = bool(selection["matches"])
        counts[
            "tp" if actual and expected
            else "fp" if actual
            else "fn" if expected
            else "tn"
        ] += 1
    assert counts == {"tp": 8, "fp": 0, "fn": 0, "tn": 16}


def test_frozen_execution_attempt_holdout() -> None:
    counts = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    for case in _holdout()["cases"]:
        _payload_value, _facts, selection, _report = _assert_case(
            case
        )
        expected = int(case["eligible_matches"]) > 0
        actual = bool(selection["matches"])
        counts[
            "tp" if actual and expected
            else "fp" if actual
            else "fn" if expected
            else "tn"
        ] += 1
    assert counts == {"tp": 4, "fp": 0, "fn": 0, "tn": 8}


def test_frozen_execution_cases_persist_and_render(
    tmp_path: Path,
) -> None:
    storage = open_storage(
        f"sqlite:///{tmp_path / 'execution-eval.db'}"
    )
    config = ProductionConfig(
        reports_dir=str(tmp_path / "reports"),
        enable_artifacts=True,
        enable_stix_export=True,
        enable_pdf_export=True,
    )
    for case in _spec()["cases"]:
        payload, _facts, _selection, report = _evaluate(case)
        storage.save_session(payload)
        job_id = storage.enqueue_analysis_job(payload)
        claim = storage.claim_analysis_jobs(
            f"execution-{case['case_id']}",
            1,
            30,
            1,
        )[0]
        storage.complete_analysis_job(
            job_id,
            claim["claim_owner"],
            claim["claim_token"],
            report,
        )
        persisted = json.loads(
            storage.list_rows_for_session(
                "reports",
                payload["session_id"],
                limit=1,
            )[0]["payload_json"]
        )
        assert persisted == report
        bundle = build_stix_bundle(report, payload)
        assert validate_stix_bundle_document(bundle) == []
        rendered = attach_report_artifacts(report, payload, config)
        assert validate_report_artifact_manifest(
            rendered["artifacts"]["integrity_manifest"]
        ) == []
        assert validate_session_assessment_v4(rendered) == []
