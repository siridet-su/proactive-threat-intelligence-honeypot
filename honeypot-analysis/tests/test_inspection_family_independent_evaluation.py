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
    INSPECTION_OPERATIONS,
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
    ROOT / "evaluation/inspection_family_independent_frozen.v1.json"
)
FROZEN_EVALUATION_SHA256 = (
    "ef6254418ba8971eb591f424e9cbd9dd1a123b90692d65bd9da1b8424dcf9cf9"
)
FROZEN_HOLDOUT = (
    ROOT / "evaluation/inspection_family_holdout_frozen.v1.json"
)
FROZEN_HOLDOUT_SHA256 = (
    "f14acf430b8449d985895d59fd494a2ad1f8deac4380f6bce67fae24592518ec"
)
HOLDOUT_PROVENANCE_CORRECTION = (
    ROOT
    / "evaluation/inspection_family_holdout_provenance_correction.v1.json"
)
FIXED_EVALUATOR_REVISION = (
    "92900870d036fb34157043fd129571a8c3c0f430"
)
INSPECTION_FINDING = "observed_cowrie_inspection_command"
INSPECTION_GUIDANCE_FINDING = "observed-cowrie-inspection-command"


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
        "typed_inspection_independent_evaluation.v1"
    )
    assert len(value["cases"]) == 45
    return value


def _load_holdout() -> dict[str, Any]:
    value = _load_spec_path(
        FROZEN_HOLDOUT,
        FROZEN_HOLDOUT_SHA256,
    )
    assert value["schema_version"] == "typed_inspection_holdout.v1"
    assert len(value["cases"]) == 34
    correction = json.loads(
        HOLDOUT_PROVENANCE_CORRECTION.read_text(encoding="utf-8")
    )
    assert correction == {
        "schema_version": "evaluation_provenance_correction.v1",
        "correction_id": (
            "inspection-holdout-implementation-revision-20260730"
        ),
        "recorded_at": "2026-07-30",
        "target_path": (
            "evaluation/inspection_family_holdout_frozen.v1.json"
        ),
        "target_sha256": FROZEN_HOLDOUT_SHA256,
        "field": "implementation_revision_before_authoring",
        "recorded_value": value[
            "implementation_revision_before_authoring"
        ],
        "correct_value": FIXED_EVALUATOR_REVISION,
        "evidence": {
            "git_commit_subject": (
                "Activate bounded Cowrie inspection findings"
            ),
            "parent_commit": (
                "02a96243733381015795e018f57e2cd8ff3d62cd"
            ),
        },
        "classification": (
            "ancillary_provenance_transcription_error"
        ),
        "frozen_target_modified": False,
        "expected_labels_changed": False,
        "evaluation_cases_changed": False,
        "measured_results_changed": False,
        "semantics": (
            "The frozen holdout bytes and expected labels remain immutable. "
            "Consumers must use correct_value when interpreting the "
            "implementation revision metadata."
        ),
    }
    return value


def _payload(case: dict[str, Any]) -> dict[str, Any]:
    session_id = f"inspection-eval-{case['case_id'].lower()}"
    base_time = datetime(2026, 7, 30, 14, 0, tzinfo=timezone.utc)
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
            raw_events.append({
                "session": session_id,
                "src_ip": "192.0.2.214",
                "timestamp": timestamp,
                "eventid": item["eventid"],
                "destfile": item.get("path", ""),
                "url": item.get("url", ""),
                "shasum": item.get("digest", ""),
            })
            continue

        command = str(item["command"])
        outcome = str(item.get("outcome") or "unknown")
        eventid = {
            "success": "cowrie.command.success",
            "failure": "cowrie.command.failed",
            "unknown": "cowrie.command.input",
        }[outcome]
        event: dict[str, Any] = {
            "session": session_id,
            "src_ip": "192.0.2.214",
            "timestamp": timestamp,
            "eventid": eventid,
            "input": command,
        }
        if outcome != "unknown":
            event["success"] = 1 if outcome == "success" else 0
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
                "tactic": "discovery",
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
        "src_ip": "192.0.2.214",
        "commands": commands,
        "commands_success": successful,
        "commands_failed": failed,
        "classification_events": classifications,
        "raw_events": raw_events,
    }


def _evaluate(
    case: dict[str, Any],
    *,
    inject_context: bool | None = None,
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
        family="inspection",
    )
    should_inject = (
        case.get("inject_non_authoritative_context") is True
        if inject_context is None
        else inject_context
    )
    context = (
        {
            "prediction_context": {
                "predicted_tactic": "benign",
                "recommendations": ["suppress observed inspection"],
            },
            "enrichment_context": {
                "reputation": "trusted",
                "recommendations": ["invent privileged action"],
            },
            "correlation_context": [{
                "claim": "unrelated campaign context",
            }],
            "llm_context": {
                "hypothesis": "invented attacker intent",
            },
        }
        if should_inject
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


def _entity_values(fact_set: dict[str, Any]) -> set[str]:
    return {
        entity["normalized_value"]
        for entity in fact_set["entities"]
        if entity.get("normalized_value")
    }


def _specialized(
    report: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    v4_findings = [
        item
        for item in report["behavioral_findings"]
        if item["finding_type"] == INSPECTION_FINDING
    ]
    v3_findings = [
        item
        for item in report["response_guidance_v3"]["findings"]
        if item["rule_id"] == INSPECTION_GUIDANCE_FINDING
    ]
    return v4_findings, v3_findings


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
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    _payload_value, fact_set, selection, report = _evaluate(case)
    operation_types = _operation_types(fact_set)
    v4_findings, v3_findings = _specialized(report)
    expected_eligible = int(case["eligible_matches"]) > 0

    assert operation_types == case[
        "expected_operation_types"
    ], case["case_id"]
    assert set(case["expected_entity_values"]).issubset(
        _entity_values(fact_set)
    ), case["case_id"]
    assert len(selection["matches"]) == int(
        case["eligible_matches"]
    ), case["case_id"]
    assert bool(v4_findings) is case[
        "specialized_finding"
    ], case["case_id"]
    assert bool(v3_findings) is case[
        "specialized_finding"
    ], case["case_id"]
    assert bool(selection["matches"]) is expected_eligible
    assert report["hypothesis_sets"] == [], case["case_id"]

    assert not any(
        action.get("semantic_family") == "inspection"
        for action in report["response_guidance_v3"][
            "advisory_actions"
        ]
    ), case["case_id"]
    for finding in v4_findings:
        assert finding["semantic_family"] == "inspection"
        limitation_text = " ".join(
            finding["limitations"]
        ).lower()
        assert "intent" in limitation_text
        assert "real host" in limitation_text
        assert "result" in limitation_text
        assert finding["evidence_refs"]
    for finding in v3_findings:
        assert finding["semantic_family"] == "inspection"
        assert finding["supporting_evidence_refs"]
        assert "not established" in finding["statement"]
    for action in report["response_guidance_v3"][
        "advisory_actions"
    ]:
        assert action["requires_manual_approval"] is True
        assert action["safe_to_auto_execute"] is False
        assert action["execution_integration"] == "not_implemented"
    assert report["response_guidance_v3"]["safety"] == {
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

    _payload_two, facts_two, selection_two, report_two = _evaluate(case)
    assert facts_two == fact_set
    assert selection_two == selection
    assert report_two["assessment_id"] == report["assessment_id"]
    assert report_two["behavioral_findings"] == report[
        "behavioral_findings"
    ]
    assert report_two["hypothesis_sets"] == report["hypothesis_sets"]
    assert report_two["response_guidance_v3"]["guidance_id"] == (
        report["response_guidance_v3"]["guidance_id"]
    )
    assert report_two["response_guidance_v3"]["findings"] == (
        report["response_guidance_v3"]["findings"]
    )
    assert report_two["response_guidance_v3"][
        "advisory_actions"
    ] == report["response_guidance_v3"]["advisory_actions"]
    return fact_set, selection, report


def test_frozen_inspection_evaluation_meets_semantic_acceptance() -> None:
    spec = _load_spec()
    typed = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    eligible = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    finding = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    guidance = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    for case in spec["cases"]:
        fact_set, selection, report = _assert_case(case)
        expected_typed = bool(
            set(case["expected_operation_types"]).intersection(
                INSPECTION_OPERATIONS
            )
        )
        expected_eligible = int(case["eligible_matches"]) > 0
        v4_findings, v3_findings = _specialized(report)
        _binary_bucket(
            typed,
            actual=bool(
                set(_operation_types(fact_set)).intersection(
                    INSPECTION_OPERATIONS
                )
            ),
            expected=expected_typed,
        )
        _binary_bucket(
            eligible,
            actual=bool(selection["matches"]),
            expected=expected_eligible,
        )
        _binary_bucket(
            finding,
            actual=bool(v4_findings),
            expected=case["specialized_finding"],
        )
        _binary_bucket(
            guidance,
            actual=bool(v3_findings),
            expected=case["specialized_finding"],
        )

    assert typed["fp"] == typed["fn"] == 0
    assert eligible["fp"] == eligible["fn"] == 0
    assert finding == eligible
    assert guidance == eligible


def test_non_authoritative_context_cannot_change_inspection_authority(
) -> None:
    case = next(
        item
        for item in _load_spec()["cases"]
        if item["case_id"] == "IFI-041"
    )
    _payload_one, facts_one, selection_one, baseline = _evaluate(
        case,
        inject_context=False,
    )
    _payload_two, facts_two, selection_two, contextual = _evaluate(
        case,
        inject_context=True,
    )

    assert facts_two == facts_one
    assert selection_two == selection_one
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


def test_frozen_inspection_holdout_meets_semantic_acceptance() -> None:
    typed = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    eligible = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    finding = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    guidance = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    for case in _load_holdout()["cases"]:
        fact_set, selection, report = _assert_case(case)
        expected_typed = bool(
            set(case["expected_operation_types"]).intersection(
                INSPECTION_OPERATIONS
            )
        )
        expected_eligible = int(case["eligible_matches"]) > 0
        v4_findings, v3_findings = _specialized(report)
        _binary_bucket(
            typed,
            actual=bool(
                set(_operation_types(fact_set)).intersection(
                    INSPECTION_OPERATIONS
                )
            ),
            expected=expected_typed,
        )
        _binary_bucket(
            eligible,
            actual=bool(selection["matches"]),
            expected=expected_eligible,
        )
        _binary_bucket(
            finding,
            actual=bool(v4_findings),
            expected=case["specialized_finding"],
        )
        _binary_bucket(
            guidance,
            actual=bool(v3_findings),
            expected=case["specialized_finding"],
        )

    assert typed["fp"] == typed["fn"] == 0
    assert eligible["fp"] == eligible["fn"] == 0
    assert finding == eligible
    assert guidance == eligible


def test_all_frozen_cases_survive_sqlite_and_artifact_validation(
    tmp_path: Path,
) -> None:
    storage = open_storage(
        f"sqlite:///{tmp_path / 'inspection-evaluation.db'}"
    )
    config = ProductionConfig(
        reports_dir=str(tmp_path / "reports"),
        enable_artifacts=True,
        enable_stix_export=True,
        enable_pdf_export=True,
    )
    for case in [
        case
        for spec in (_load_spec(), _load_holdout())
        for case in spec["cases"]
    ]:
        payload, _facts, _selection, report = _evaluate(case)
        storage.save_session(payload)
        job_id = storage.enqueue_analysis_job(payload)
        claim = storage.claim_analysis_jobs(
            f"inspection-eval-{case['case_id']}",
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
        rendered = attach_report_artifacts(
            report,
            payload,
            config,
        )
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
