from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from production.policies.validate_stix_bundle import (
    validate_stix_bundle_document,
)
from production.reporting.artifacts import (
    attach_report_artifacts,
    build_stix_bundle,
    validate_report_artifact_manifest,
)
from production.reporting.session_assessment_v4 import (
    build_session_assessment_v4,
    validate_session_assessment_v4,
)
from production.reporting.typed_semantic_facts import (
    validate_typed_semantic_fact_set,
)
from production.storage.backend import open_storage
from production.utils.config import ProductionConfig
from tests.semantic_fixture_loader import load_fixture


ROOT = Path(__file__).resolve().parents[1]
BEHAVIOR_POLICY = (
    ROOT / "configs/threat_hypothesis_behavior.trusted.json"
)
CLASSIFICATION_POLICY = ROOT / "configs/classification_rules.trusted.json"


def _spec() -> dict[str, Any]:
    value = load_fixture("typed_semantic_poc_combined", "combined")
    assert value["schema_version"] == (
        "typed_semantic_poc_combined_evaluation.v1"
    )
    assert value["expected_labels_frozen_before_execution"] is True
    assert len(value["cases"]) == 18
    return value


def _payload(case: dict[str, Any]) -> dict[str, Any]:
    session_id = f"poc-combined-{case['case_id'].lower()}"
    base = datetime(2026, 7, 30, 23, 0, tzinfo=timezone.utc)
    events: list[dict[str, Any]] = []
    commands: list[str] = []
    successful: list[str] = []
    failed: list[str] = []
    for index, source in enumerate(case["events"]):
        timestamp = (
            base + timedelta(seconds=index)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        if source["kind"] == "command":
            outcome = source["outcome"]
            eventid = {
                "success": "cowrie.command.success",
                "failure": "cowrie.command.failed",
                "unknown": "cowrie.command.input",
            }[outcome]
            event: dict[str, Any] = {
                "session": session_id,
                "src_ip": "192.0.2.203",
                "timestamp": timestamp,
                "eventid": eventid,
                "input": source["command"],
            }
            if outcome != "unknown":
                event["success"] = int(outcome == "success")
            commands.append(source["command"])
            if outcome == "success":
                successful.append(source["command"])
            elif outcome == "failure":
                failed.append(source["command"])
        else:
            event = {
                "session": session_id,
                "src_ip": "192.0.2.203",
                "timestamp": timestamp,
                "eventid": source["eventid"],
                "url": source["url"],
                "destfile": source["path"],
                "filename": source["path"],
                "shasum": source["sha256"],
            }
        events.append(event)
    classifications = []
    if case.get("inject_non_authoritative_context"):
        command = commands[0]
        classifications.append({
            "command": command,
            "original_command": command,
            "ttp": "T1105",
            "tactic": "command-and-control",
            "source": "rule",
            "high_confidence": True,
            "evidence_id": f"classification-{case['case_id']}",
            "event_timestamp": events[0]["timestamp"],
            "cowrie_eventid": events[0]["eventid"],
        })
    return {
        "session_id": session_id,
        "src_ip": "192.0.2.203",
        "commands": commands,
        "commands_success": successful,
        "commands_failed": failed,
        "classification_events": classifications,
        "raw_events": events,
    }


def _report(case: dict[str, Any]) -> dict[str, Any]:
    payload = _payload(case)
    context = (
        {
            "prediction_context": {
                "predicted_tactic": "exfiltration",
                "recommendations": [
                    "invent transfer and execution findings",
                ],
            },
            "enrichment_context": {
                "reputation": "malicious",
                "recommendations": ["invent a response action"],
            },
            "correlation_context": [{
                "claim": "invent cross-session causality",
            }],
            "llm_context": {
                "hypothesis": "invented malicious intent",
            },
        }
        if case.get("inject_non_authoritative_context")
        else {}
    )
    return build_session_assessment_v4(
        [payload],
        raw_events=payload["raw_events"],
        behavior_policy_path=str(BEHAVIOR_POLICY),
        classification_policy_path=str(CLASSIFICATION_POLICY),
        **context,
    )


def _operations(report: dict[str, Any]) -> list[str]:
    # Rebuild through the canonical report path and use the persisted shadow
    # comparison's operation records only via the separately validated builder
    # in this test's companion assertion.
    from production.policies.threat_hypothesis_behavior_policy import (
        policy_summary,
    )
    from production.reporting.session_assessment_v4 import (
        build_canonical_evidence_snapshot,
    )
    from production.reporting.typed_semantic_facts import (
        build_typed_semantic_fact_set,
        build_typed_semantic_provenance,
    )

    payload = report.pop("_test_payload")
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
        evaluator_git_revision="6001b7cec3ad3c91073366257726ae0e185e6c88",
    )
    fact_set = build_typed_semantic_fact_set(
        observed,
        provenance=provenance,
    )
    report["_test_fact_set"] = fact_set
    result: list[str] = []
    for fact in fact_set["facts"]:
        operations = [
            operation["operation_type"]
            for operation in fact["operations"]
        ]
        result.extend(operations or ["unknown"])
    return result


def _build_case(
    case: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    payload = _payload(case)
    report = _report(case)
    carrier = {"_test_payload": payload}
    operations = _operations(carrier)
    return payload, carrier["_test_fact_set"], report | {
        "_test_operations": operations,
    }


def _assert_case(
    case: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    payload, fact_set, report_with_test = _build_case(case)
    operations = report_with_test.pop("_test_operations")
    report = report_with_test
    finding_families = {
        item.get("semantic_family")
        for item in report["behavioral_findings"]
        if item.get("semantic_family")
    }
    guidance_families = {
        item.get("semantic_family")
        for item in report["response_guidance_v3"]["findings"]
        if item.get("semantic_family")
    }
    action_families = {
        item.get("semantic_family")
        for item in report["response_guidance_v3"][
            "advisory_actions"
        ]
        if item.get("semantic_family")
    }

    assert operations == case["expected_operations"], case["case_id"]
    assert finding_families == set(case["expected_families"])
    assert guidance_families == set(case["expected_families"])
    assert action_families == set(
        case["expected_action_families"]
    )
    assert report["hypothesis_sets"] == []
    assert report["authority"] == {
        "observed_evidence_authoritative": True,
        "predictions_authoritative": False,
        "enrichment_authoritative": False,
        "correlations_authoritative": False,
        "llm_authoritative": False,
        "automatic_response_authorized": False,
        "automatic_alerts_authorized": False,
    }
    assert report["response_guidance_v3"]["safety"] == {
        "automatic_execution": False,
        "manual_approval_required": True,
        "alerting_side_effect": False,
        "response_action_side_effect": False,
        "execution_integration": "not_implemented",
    }
    for action in report["response_guidance_v3"][
        "advisory_actions"
    ]:
        assert action["requires_manual_approval"] is True
        assert action["safe_to_auto_execute"] is False
    assert validate_typed_semantic_fact_set(fact_set) == []
    assert validate_session_assessment_v4(report) == []

    _payload_two, facts_two, report_two = _build_case(case)
    report_two.pop("_test_operations")
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
    return payload, fact_set, report


def test_frozen_combined_semantic_acceptance() -> None:
    expected_pairs: set[tuple[str, str]] = set()
    actual_pairs: set[tuple[str, str]] = set()
    for case in _spec()["cases"]:
        _payload_value, _facts, report = _assert_case(case)
        expected_pairs.update(
            (case["case_id"], family)
            for family in case["expected_families"]
        )
        actual_pairs.update(
            (case["case_id"], item["semantic_family"])
            for item in report["behavioral_findings"]
            if item.get("semantic_family")
        )
    assert actual_pairs == expected_pairs


def test_frozen_combined_persistence_and_artifacts(
    tmp_path: Path,
) -> None:
    storage = open_storage(
        f"sqlite:///{tmp_path / 'poc-combined.db'}"
    )
    config = ProductionConfig(
        reports_dir=str(tmp_path / "reports"),
        enable_artifacts=True,
        enable_stix_export=True,
        enable_pdf_export=True,
    )
    for case in _spec()["cases"]:
        payload, _facts, report = _assert_case(case)
        storage.save_session(payload)
        job_id = storage.enqueue_analysis_job(payload)
        claim = storage.claim_analysis_jobs(
            f"poc-{case['case_id']}",
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
