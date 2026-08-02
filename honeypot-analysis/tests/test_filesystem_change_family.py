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
    FILESYSTEM_CHANGE_OPERATIONS,
    select_activated_semantic_family,
    validate_typed_semantic_family_selection,
)
from production.storage.backend import open_storage
from production.utils.config import ProductionConfig
from tests.semantic_fixture_loader import load_fixture


ROOT = Path(__file__).resolve().parents[1]
BEHAVIOR_POLICY = (
    ROOT / "configs/threat_hypothesis_behavior.trusted.json"
)
CLASSIFICATION_POLICY = ROOT / "configs/classification_rules.trusted.json"
EVALUATOR_REVISION = "975fa0b27ba5a1b4abe19281ef717de2483777cd"
V4_FINDING = "observed_cowrie_filesystem_change_command"
V3_FINDING = "observed-cowrie-filesystem-change-command"


def _spec() -> dict[str, Any]:
    value = load_fixture("filesystem_change", "independent")
    assert value["schema_version"] == (
        "typed_filesystem_change_evaluation.v1"
    )
    assert value["expected_labels_frozen_before_execution"] is True
    assert len(value["cases"]) == 24
    return value


def _holdout_spec() -> dict[str, Any]:
    value = load_fixture("filesystem_change", "holdout")
    assert value["schema_version"] == (
        "typed_filesystem_change_holdout.v1"
    )
    assert value["expected_labels_frozen_before_execution"] is True
    assert len(value["cases"]) == 16
    return value


def _payload(case: dict[str, Any]) -> dict[str, Any]:
    session_id = f"filesystem-eval-{case['case_id'].lower()}"
    outcome = case["outcome"]
    eventid = {
        "success": "cowrie.command.success",
        "failure": "cowrie.command.failed",
        "unknown": "cowrie.command.input",
    }[outcome]
    event: dict[str, Any] = {
        "session": session_id,
        "src_ip": "192.0.2.219",
        "timestamp": "2026-07-30T16:00:00Z",
        "eventid": eventid,
        "input": case["command"],
    }
    if outcome != "unknown":
        event["success"] = 1 if outcome == "success" else 0
    if case.get("cwd"):
        event["cwd"] = case["cwd"]
    classifications = []
    if case.get("attck"):
        classifications.append({
            "command": case["command"],
            "original_command": case["command"],
            "ttp": case["attck"],
            "tactic": "defense-evasion",
            "source": "rule",
            "high_confidence": True,
            "evidence_id": f"classification-{case['case_id']}",
            "event_timestamp": event["timestamp"],
            "cowrie_eventid": eventid,
        })
    return {
        "session_id": session_id,
        "src_ip": "192.0.2.219",
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
        family="filesystem",
    )
    context = (
        {
            "prediction_context": {
                "predicted_tactic": "benign",
                "recommendations": ["suppress filesystem finding"],
            },
            "enrichment_context": {
                "reputation": "trusted",
                "recommendations": ["invent deletion effect"],
            },
            "llm_context": {"hypothesis": "invented cleanup intent"},
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
    return [
        operation["operation_type"]
        for fact in fact_set["facts"]
        for operation in fact["operations"]
    ]


def _targets(fact_set: dict[str, Any]) -> set[str]:
    return {
        entity["normalized_value"]
        for entity in fact_set["entities"]
        if entity.get("entity_type") == "path"
    }


def _outputs(
    report: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
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
    return v4, v3


def _assert_case(
    case: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    _payload_value, fact_set, selection, report = _evaluate(case)
    expected = int(case["eligible_matches"]) > 0
    v4, v3 = _outputs(report)

    assert _operations(fact_set) == case["expected_operations"], (
        case["case_id"]
    )
    assert set(case["expected_targets"]).issubset(_targets(fact_set))
    assert len(selection["matches"]) == case["eligible_matches"]
    assert bool(v4) is expected
    assert bool(v3) is expected
    assert report["hypothesis_sets"] == []
    assert not any(
        item.get("semantic_family") == "filesystem"
        for item in report["response_guidance_v3"][
            "advisory_actions"
        ]
    )
    for finding in v4:
        text = " ".join(finding["limitations"]).lower()
        assert "filesystem state" in text
        assert "real host" in text
        assert "intent" in text
    for action in report["response_guidance_v3"][
        "advisory_actions"
    ]:
        assert action["requires_manual_approval"] is True
        assert action["safe_to_auto_execute"] is False
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
    assert report_two["response_guidance_v3"]["guidance_id"] == (
        report["response_guidance_v3"]["guidance_id"]
    )
    return fact_set, selection, report


def test_frozen_filesystem_evaluation() -> None:
    counts = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    for case in _spec()["cases"]:
        fact_set, selection, _report = _assert_case(case)
        expected = int(case["eligible_matches"]) > 0
        actual = bool(selection["matches"])
        counts[
            "tp" if actual and expected
            else "fp" if actual
            else "fn" if expected
            else "tn"
        ] += 1
        assert bool(
            set(_operations(fact_set)).intersection(
                FILESYSTEM_CHANGE_OPERATIONS
            )
        ) is bool(
            set(case["expected_operations"]).intersection(
                FILESYSTEM_CHANGE_OPERATIONS
            )
        )
    assert counts == {"tp": 11, "fp": 0, "fn": 0, "tn": 13}


def test_frozen_filesystem_holdout() -> None:
    counts = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    for case in _holdout_spec()["cases"]:
        _facts, selection, _report = _assert_case(case)
        expected = int(case["eligible_matches"]) > 0
        actual = bool(selection["matches"])
        counts[
            "tp" if actual and expected
            else "fp" if actual
            else "fn" if expected
            else "tn"
        ] += 1
    assert counts == {"tp": 8, "fp": 0, "fn": 0, "tn": 8}


def test_frozen_filesystem_cases_persist_and_render(
    tmp_path: Path,
) -> None:
    storage = open_storage(
        f"sqlite:///{tmp_path / 'filesystem-eval.db'}"
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
            f"filesystem-{case['case_id']}",
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


def test_existing_activated_families_remain_present() -> None:
    session_id = "filesystem-combined-existing"
    base = datetime(2026, 7, 30, 17, 0, tzinfo=timezone.utc)
    events = [
        {
            "session": session_id,
            "src_ip": "192.0.2.219",
            "timestamp": (
                base + timedelta(seconds=index)
            ).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "eventid": "cowrie.command.success",
            "input": command,
            "success": 1,
        }
        for index, command in enumerate(
            ["whoami", "cat /etc/shadow", "chmod 600 /tmp/x"]
        )
    ]
    events.append({
        "session": session_id,
        "src_ip": "192.0.2.219",
        "timestamp": (
            base + timedelta(seconds=3)
        ).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "eventid": "cowrie.session.file_download",
        "destfile": "/tmp/x",
        "url": "https://combined.invalid/x",
        "shasum": "f" * 64,
    })
    payload = {
        "session_id": session_id,
        "src_ip": "192.0.2.219",
        "commands": [
            "whoami",
            "cat /etc/shadow",
            "chmod 600 /tmp/x",
        ],
        "commands_success": [
            "whoami",
            "cat /etc/shadow",
            "chmod 600 /tmp/x",
        ],
        "commands_failed": [],
        "classification_events": [],
        "raw_events": events,
    }
    report = build_session_assessment_v4(
        [payload],
        raw_events=events,
        behavior_policy_path=str(BEHAVIOR_POLICY),
        classification_policy_path=str(CLASSIFICATION_POLICY),
    )
    assert {
        "observed_cowrie_inspection_command",
        "observed_credential_path_read_command",
        "observed_cowrie_transfer_event",
        V4_FINDING,
    }.issubset({
        item["finding_type"]
        for item in report["behavioral_findings"]
    })
    assert validate_session_assessment_v4(report) == []
