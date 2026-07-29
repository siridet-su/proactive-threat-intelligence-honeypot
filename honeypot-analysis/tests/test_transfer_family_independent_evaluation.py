from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
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
BEHAVIOR_POLICY = (
    ROOT / "configs/threat_hypothesis_behavior.trusted.json"
)
CLASSIFICATION_POLICY = ROOT / "configs/classification_rules.trusted.json"
FROZEN_EVALUATION = (
    ROOT / "evaluation/transfer_family_independent_frozen.v1.json"
)
FROZEN_EVALUATION_SHA256 = (
    "3b235d4f247f7506079452c8da869c9dc21eb26fb57c5a235850aa2b2ec20cd9"
)
FROZEN_HOLDOUT = (
    ROOT / "evaluation/transfer_family_holdout_frozen.v1.json"
)
FROZEN_HOLDOUT_SHA256 = (
    "6050f6c0c6cf23b8cf47729cdcf94510dbf30858f2cf50d90a292237516e545a"
)
FIXED_EVALUATOR_REVISION = (
    "aaa0f3dac4b9c02a8ef3d09251de003504c56a2f"
)
TRANSFER_FINDING = "observed_cowrie_transfer_event"
TRANSFER_ACTION = "hunt-observed-transfer-indicators"
DIRECT_EVENT_IDS = {
    "cowrie.session.file_download",
    "cowrie.session.file_upload",
}


def _load_spec_path(
    path: Path,
    expected_sha256: str,
) -> dict[str, Any]:
    raw = path.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == expected_sha256
    value = json.loads(raw)
    assert value["expected_labels_frozen_before_execution"] is True
    return value


def _load_spec() -> dict[str, Any]:
    value = _load_spec_path(
        FROZEN_EVALUATION,
        FROZEN_EVALUATION_SHA256,
    )
    assert value["schema_version"] == (
        "typed_transfer_independent_evaluation.v1"
    )
    assert len(value["cases"]) == 34
    return value


def _payload(case: dict[str, Any]) -> dict[str, Any]:
    session_id = f"transfer-eval-{case['case_id'].lower()}"
    base_time = datetime(2026, 7, 30, 8, 0, tzinfo=timezone.utc)
    commands: list[str] = []
    successful: list[str] = []
    failed: list[str] = []
    raw_events: list[dict[str, Any]] = []
    classifications: list[dict[str, Any]] = []
    for index, item in enumerate(case["events"]):
        timestamp = (
            base_time + timedelta(seconds=index)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        if item["kind"] == "transfer":
            event: dict[str, Any] = {
                "session": session_id,
                "src_ip": "192.0.2.230",
                "timestamp": timestamp,
                "eventid": item["eventid"],
                "destfile": item.get("path", ""),
                "url": item.get("url", ""),
                "shasum": item.get("digest", ""),
            }
            if item.get("cwd"):
                event["cwd"] = item["cwd"]
            raw_events.append(event)
            continue

        command = str(item["command"])
        outcome = str(item.get("outcome") or "unknown")
        eventid = (
            "cowrie.command.failed"
            if outcome == "failure"
            else "cowrie.command.success"
        )
        event = {
            "session": session_id,
            "src_ip": "192.0.2.230",
            "timestamp": timestamp,
            "eventid": eventid,
            "input": command,
        }
        if outcome != "unknown":
            event["success"] = 0 if outcome == "failure" else 1
        if item.get("cwd"):
            event["cwd"] = item["cwd"]
        raw_events.append(event)
        commands.append(command)
        if outcome == "success":
            successful.append(command)
        elif outcome == "failure":
            failed.append(command)
        if item.get("attck"):
            classifications.append({
                "command": command,
                "original_command": command,
                "ttp": item["attck"],
                "tactic": "command-and-control",
                "source": "rule",
                "high_confidence": True,
                "evidence_id": (
                    f"classification-{case['case_id']}-{index}"
                ),
                "event_timestamp": timestamp,
                "cowrie_eventid": eventid,
            })
    return {
        "session_id": session_id,
        "src_ip": "192.0.2.230",
        "commands": commands,
        "commands_success": successful,
        "commands_failed": failed,
        "classification_events": classifications,
        "raw_events": raw_events,
    }


def _evaluate(
    case: dict[str, Any],
    *,
    inject_context: bool = False,
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
        evaluator_git_revision=FIXED_EVALUATOR_REVISION,
    )
    fact_set = build_typed_semantic_fact_set(
        observed,
        provenance=provenance,
    )
    selection = select_activated_semantic_family(
        fact_set,
        family="transfer",
    )
    context = (
        {
            "prediction_context": {
                "predicted_tactic": "benign",
                "recommendations": ["suppress exact-hash review"],
            },
            "enrichment_context": {
                "reputation": "trusted",
                "recommendations": ["auto-allow"],
            },
            "llm_context": {
                "hypothesis": "invented execution claim",
            },
        }
        if inject_context
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


def _operation_types(fact_set: dict[str, Any]) -> list[str]:
    return [
        operation["operation_type"]
        for fact in fact_set["facts"]
        for operation in fact["operations"]
    ]


def _nonempty_entity_roles(fact_set: dict[str, Any]) -> set[str]:
    return {
        role
        for fact in fact_set["facts"]
        for role, values in fact["entities"].items()
        if values
    }


def _artifact_hashes(fact_set: dict[str, Any]) -> list[str]:
    return list(dict.fromkeys(
        entity["normalized_value"]
        for fact in fact_set["facts"]
        for entity in fact["entities"]["artifact_hashes"]
    ))


def _specialized(
    report: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    findings = [
        item
        for item in report["behavioral_findings"]
        if item["finding_type"] == TRANSFER_FINDING
    ]
    actions = [
        item
        for item in report["response_guidance_v3"]["advisory_actions"]
        if item["action_id"] == TRANSFER_ACTION
    ]
    return findings, actions


def _binary_bucket(
    counts: dict[str, int],
    *,
    actual: bool,
    expected: bool,
) -> None:
    counts[
        "tp" if actual and expected
        else "fp" if actual
        else "fn" if expected
        else "tn"
    ] += 1


def _assert_case(
    case: dict[str, Any],
    *,
    check_entity_roles: bool = True,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    inject_context = (
        case["case_id"] == "TFI-033"
        or case.get("inject_non_authoritative_context") is True
    )
    payload, fact_set, selection, report = _evaluate(
        case,
        inject_context=inject_context,
    )
    operations = _operation_types(fact_set)
    findings, actions = _specialized(report)
    expected_eligible = int(case["eligible_matches"]) > 0

    assert operations == case["expected_operations"], case["case_id"]
    if check_entity_roles:
        assert set(case["expected_entity_roles"]).issubset(
            _nonempty_entity_roles(fact_set)
        ), case["case_id"]
    assert _artifact_hashes(fact_set) == case[
        "expected_artifact_hashes"
    ], case["case_id"]
    assert len(selection["matches"]) == int(
        case["eligible_matches"]
    ), case["case_id"]
    assert bool(findings) is case["specialized_finding"]
    assert bool(actions) is case["specialized_guidance"]
    assert bool(findings) is expected_eligible
    assert bool(actions) is expected_eligible
    assert report["hypothesis_sets"] == [], case["case_id"]

    direct_refs = {
        item["evidence_id"]
        for item in report["canonical_evidence"]["direct_cowrie_events"]
        if item["eventid"] in DIRECT_EVENT_IDS
    }
    for finding in findings:
        assert set(finding["evidence_refs"]) <= direct_refs
        assert finding["semantic_family"] == "transfer"
        assert any(
            "honeypot" in limitation.lower()
            for limitation in finding["limitations"]
        )
        assert any(
            "real host" in limitation.lower()
            or "external system" in limitation.lower()
            for limitation in finding["limitations"]
        )
    for action in actions:
        assert set(action["evidence_refs"]) <= direct_refs
        assert action["semantic_family"] == "transfer"
        assert action["requires_manual_approval"] is True
        assert action["safe_to_auto_execute"] is False
        assert action["execution_integration"] == "not_implemented"
        assert "exact artifact SHA-256" in action["description"]

    safety = report["response_guidance_v3"]["safety"]
    assert safety == {
        "automatic_execution": False,
        "manual_approval_required": True,
        "alerting_side_effect": False,
        "response_action_side_effect": False,
        "execution_integration": "not_implemented",
    }
    assert validate_typed_semantic_fact_set(fact_set) == []
    assert validate_typed_semantic_family_selection(
        selection,
        fact_set,
    ) == []
    assert validate_session_assessment_v4(report) == []

    _second_payload, second_facts, second_selection, second_report = (
        _evaluate(
            case,
            inject_context=inject_context,
        )
    )
    assert second_facts == fact_set
    assert second_selection == selection
    assert second_report["assessment_id"] == report["assessment_id"]
    assert second_report["behavioral_findings"] == report[
        "behavioral_findings"
    ]
    assert second_report["hypothesis_sets"] == report["hypothesis_sets"]
    assert second_report["response_guidance_v3"]["guidance_id"] == (
        report["response_guidance_v3"]["guidance_id"]
    )
    assert second_report["response_guidance_v3"]["findings"] == (
        report["response_guidance_v3"]["findings"]
    )
    assert second_report["response_guidance_v3"][
        "advisory_actions"
    ] == report["response_guidance_v3"]["advisory_actions"]
    return fact_set, selection, report


def test_frozen_independent_evaluation_meets_semantic_acceptance() -> None:
    spec = _load_spec()
    typed = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    eligible = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    finding = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    guidance = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    for case in spec["cases"]:
        fact_set, selection, report = _assert_case(case)
        expected_typed = (
            "transfer_observed" in case["expected_operations"]
        )
        expected_eligible = int(case["eligible_matches"]) > 0
        findings, actions = _specialized(report)
        _binary_bucket(
            typed,
            actual="transfer_observed" in _operation_types(fact_set),
            expected=expected_typed,
        )
        _binary_bucket(
            eligible,
            actual=bool(selection["matches"]),
            expected=expected_eligible,
        )
        _binary_bucket(
            finding,
            actual=bool(findings),
            expected=case["specialized_finding"],
        )
        _binary_bucket(
            guidance,
            actual=bool(actions),
            expected=case["specialized_guidance"],
        )

    assert typed == {"tp": 17, "fp": 0, "fn": 0, "tn": 17}
    assert eligible == {"tp": 12, "fp": 0, "fn": 0, "tn": 22}
    assert finding == eligible
    assert guidance == eligible


def test_separately_frozen_holdout_authority_acceptance_records_spec_defect(
) -> None:
    spec = _load_spec_path(
        FROZEN_HOLDOUT,
        FROZEN_HOLDOUT_SHA256,
    )
    assert spec["schema_version"] == "typed_transfer_holdout.v1"
    assert len(spec["cases"]) == 21
    typed = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    eligible = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    finding = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    guidance = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    entity_role_discrepancies: list[dict[str, Any]] = []
    for case in spec["cases"]:
        _payload_value, inspected_facts, _selection, _report = _evaluate(
            case,
            inject_context=(
                case.get("inject_non_authoritative_context") is True
            ),
        )
        actual_roles = _nonempty_entity_roles(inspected_facts)
        missing_roles = sorted(
            set(case["expected_entity_roles"]) - actual_roles
        )
        if missing_roles:
            entity_role_discrepancies.append({
                "case_id": case["case_id"],
                "missing_frozen_roles": missing_roles,
                "actual_roles": sorted(actual_roles),
                "classification": "evaluation_spec_defect",
            })
        fact_set, selection, report = _assert_case(
            case,
            check_entity_roles=False,
        )
        expected_typed = (
            "transfer_observed" in case["expected_operations"]
        )
        expected_eligible = int(case["eligible_matches"]) > 0
        findings, actions = _specialized(report)
        _binary_bucket(
            typed,
            actual="transfer_observed" in _operation_types(fact_set),
            expected=expected_typed,
        )
        _binary_bucket(
            eligible,
            actual=bool(selection["matches"]),
            expected=expected_eligible,
        )
        _binary_bucket(
            finding,
            actual=bool(findings),
            expected=case["specialized_finding"],
        )
        _binary_bucket(
            guidance,
            actual=bool(actions),
            expected=case["specialized_guidance"],
        )

    assert typed == {"tp": 14, "fp": 0, "fn": 0, "tn": 7}
    assert eligible == {"tp": 9, "fp": 0, "fn": 0, "tn": 12}
    assert finding == eligible
    assert guidance == eligible
    assert entity_role_discrepancies == [{
        "case_id": "TFH-013",
        "missing_frozen_roles": ["source_paths"],
        "actual_roles": ["created_paths", "read_paths"],
        "classification": "evaluation_spec_defect",
    }]


def test_non_authoritative_context_cannot_change_transfer_authority() -> None:
    case = next(
        item
        for item in _load_spec()["cases"]
        if item["case_id"] == "TFI-033"
    )
    _payload_value, _facts, _selection, baseline = _evaluate(case)
    _payload_value, _facts, _selection, contextual = _evaluate(
        case,
        inject_context=True,
    )

    assert contextual["assessment_id"] == baseline["assessment_id"]
    assert contextual["behavioral_findings"] == baseline[
        "behavioral_findings"
    ]
    assert contextual["hypothesis_sets"] == baseline["hypothesis_sets"]
    assert contextual["response_guidance_v3"]["guidance_id"] == (
        baseline["response_guidance_v3"]["guidance_id"]
    )
    assert contextual["response_guidance_v3"]["findings"] == (
        baseline["response_guidance_v3"]["findings"]
    )
    assert contextual["response_guidance_v3"][
        "advisory_actions"
    ] == baseline["response_guidance_v3"]["advisory_actions"]


def test_all_frozen_cases_survive_sqlite_and_artifact_validation(
    tmp_path: Path,
) -> None:
    storage = open_storage(f"sqlite:///{tmp_path / 'transfer-eval.db'}")
    reports_dir = tmp_path / "reports"
    config = ProductionConfig(
        reports_dir=str(reports_dir),
        enable_artifacts=True,
        enable_stix_export=True,
        enable_pdf_export=True,
    )

    specs = [
        _load_spec(),
        _load_spec_path(FROZEN_HOLDOUT, FROZEN_HOLDOUT_SHA256),
    ]
    for case in [
        case
        for spec in specs
        for case in spec["cases"]
    ]:
        payload, _facts, _selection, report = _evaluate(
            case,
            inject_context=(
                case["case_id"] == "TFI-033"
                or case.get("inject_non_authoritative_context") is True
            ),
        )
        storage.save_session(payload)
        job_id = storage.enqueue_analysis_job(payload)
        claim = storage.claim_analysis_jobs(
            f"transfer-eval-{case['case_id']}",
            1,
            30,
            1,
        )[0]
        report_id = storage.complete_analysis_job(
            job_id,
            claim["claim_owner"],
            claim["claim_token"],
            report,
        )
        assert report_id
        persisted = storage.list_rows_for_session(
            "reports",
            payload["session_id"],
            limit=1,
        )[0]
        persisted_report = json.loads(persisted["payload_json"])
        assert persisted_report == report
        assert validate_session_assessment_v4(persisted_report) == []

        bundle = build_stix_bundle(report, payload)
        assert validate_stix_bundle_document(bundle) == []
        rendered = attach_report_artifacts(report, payload, config)
        assert {
            "json",
            "markdown",
            "stix",
            "integrity_manifest",
        } <= set(rendered["artifacts"])
        assert (
            "pdf" in rendered["artifacts"]
            or "pdf_fallback_markdown" in rendered["artifacts"]
        )
        assert validate_report_artifact_manifest(
            rendered["artifacts"]["integrity_manifest"]
        ) == []
        assert validate_session_assessment_v4(rendered) == []
