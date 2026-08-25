from __future__ import annotations

import copy
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

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
from tests.semantic_fixture_loader import load_fixture


ROOT = Path(__file__).resolve().parents[1]
BEHAVIOR_POLICY = ROOT / "configs/threat_hypothesis_behavior.trusted.json"
CLASSIFICATION_POLICY = ROOT / "configs/classification_rules.trusted.json"
SOURCE_SPEC_SHA256 = (
    "4a9d5826253109f93c05f82fc671d0be57979d8e717458d3553ea387dbae78a9"
)
FIXED_REVISION = "70671d18930c1a866eb7dd48fdc0301ea0b27618"
SPECIAL_FINDING = "observed_credential_path_read_command"
SPECIAL_ACTION = "review-credential-exposure-and-reuse"


def _load_spec(role: str) -> dict[str, Any]:
    value = load_fixture("sensitive_read", role)
    assert isinstance(value, dict)
    assert isinstance(value.get("cases"), list)
    return value


def _payload(case: dict[str, Any]) -> dict[str, Any]:
    session_id = f"independent-{case['case_id'].lower()}"
    event_specs = case.get("events") or [{
        "command": case["command"],
        "outcome": case.get("outcome", "success"),
        "cwd": case.get("cwd", ""),
    }]
    base_time = datetime(2026, 7, 29, 17, 0, tzinfo=timezone.utc)
    commands: list[str] = []
    successful: list[str] = []
    failed: list[str] = []
    raw_events: list[dict[str, Any]] = []
    classifications: list[dict[str, Any]] = []
    for index, item in enumerate(event_specs):
        command = str(item["command"])
        outcome = str(item.get("outcome") or "unknown")
        timestamp = (
            base_time + timedelta(seconds=index)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        eventid = (
            "cowrie.command.failed"
            if outcome == "failure"
            else "cowrie.command.input"
        )
        event: dict[str, Any] = {
            "session": session_id,
            "src_ip": "192.0.2.119",
            "timestamp": timestamp,
            "eventid": eventid,
            "input": command,
        }
        if outcome != "unknown":
            event["success"] = 1 if outcome == "success" else 0
        cwd = str(item.get("cwd") or case.get("cwd") or "")
        if cwd:
            event["cwd"] = cwd
        commands.append(command)
        if outcome == "success":
            successful.append(command)
        elif outcome == "failure":
            failed.append(command)
        raw_events.append(event)
        classifications.append({
            "command": command,
            "original_command": command,
            "ttp": "T1552" if not case.get("attck_only") else "T1552",
            "tactic": "credential-access",
            "source": "rule",
            "high_confidence": True,
            "evidence_id": f"classification-{case['case_id']}-{index}",
            "event_timestamp": timestamp,
            "cowrie_eventid": eventid,
        })
    return {
        "session_id": session_id,
        "src_ip": "192.0.2.119",
        "commands": commands,
        "commands_success": successful,
        "commands_failed": failed,
        "classification_events": classifications,
        "raw_events": raw_events,
    }


def _evaluate(
    case: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
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
        evaluator_git_revision=FIXED_REVISION,
    )
    fact_set = build_typed_semantic_fact_set(
        observed,
        provenance=provenance,
    )
    selection = select_activated_semantic_family(
        fact_set,
        family="sensitive_read",
    )
    report = build_session_assessment_v4(
        [payload],
        raw_events=payload["raw_events"],
        behavior_policy_path=str(BEHAVIOR_POLICY),
        classification_policy_path=str(CLASSIFICATION_POLICY),
    )
    return fact_set, selection, report


def _metrics(
    spec: dict[str, Any],
) -> tuple[dict[str, int], dict[str, int]]:
    typed = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    eligible = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    for case in spec["cases"]:
        fact_set, selection, report = _evaluate(case)
        second_fact_set, second_selection, second_report = _evaluate(case)
        actual_typed = any(
            operation.get("operation_type") == "credential_material_read"
            for fact in fact_set["facts"]
            for operation in fact["operations"]
        )
        command = " ".join(
            [str(case.get("command") or "")]
            + [
                str(event.get("command") or "")
                for event in case.get("events") or []
                if isinstance(event, dict)
            ]
        )
        account_metadata = "/etc/passwd" in command
        secret_material = any(
            marker in command
            for marker in (
                "/etc/shadow",
                "/etc//shadow",
                "/etc/./shadow",
                "/etc/shad'ow",
                "/etc/'shadow'",
                ".ssh/id_",
                ".aws/credentials",
                "application_default_credentials.json",
            )
        )
        expected_typed = (
            case["credential_path_read"] is True and secret_material
        )
        actual_matches = len(selection["matches"])
        expected_matches = (
            max(0, int(case["eligible_matches"]) - int(account_metadata))
        )
        actual_eligible = bool(actual_matches)
        expected_eligible = expected_matches > 0
        typed[
            "tp" if actual_typed and expected_typed
            else "fp" if actual_typed
            else "fn" if expected_typed
            else "tn"
        ] += 1
        eligible[
            "tp" if actual_eligible and expected_eligible
            else "fp" if actual_eligible
            else "fn" if expected_eligible
            else "tn"
        ] += 1

        finding_types = {
            item["finding_type"]
            for item in report["behavioral_findings"]
        }
        action_ids = {
            item["action_id"]
            for item in report["response_guidance_v3"]["advisory_actions"]
        }
        assert actual_typed is expected_typed, case["case_id"]
        assert actual_matches == expected_matches, case["case_id"]
        assert (SPECIAL_FINDING in finding_types) is expected_eligible
        assert (SPECIAL_ACTION in action_ids) is expected_eligible
        assert report["hypothesis_sets"] == []
        assert all(
            action["requires_manual_approval"] is True
            and action["safe_to_auto_execute"] is False
            for action in report["response_guidance_v3"][
                "advisory_actions"
            ]
        )
        assert validate_typed_semantic_fact_set(fact_set) == []
        assert validate_typed_semantic_family_selection(
            selection,
            fact_set,
        ) == []
        assert validate_session_assessment_v4(report) == []
        assert second_fact_set == fact_set
        assert second_selection == selection
        assert second_report["assessment_id"] == report["assessment_id"]
        assert (
            second_report["response_guidance_v3"]["guidance_id"]
            == report["response_guidance_v3"]["guidance_id"]
        )
    return typed, eligible


def test_exact_frozen_50_case_replay_has_no_semantic_discrepancies() -> None:
    spec = _load_spec("replay")
    assert spec["source_evaluation_spec_sha256"] == SOURCE_SPEC_SHA256
    assert len(spec["cases"]) == 50

    typed, eligible = _metrics(spec)

    assert typed == {"tp": 19, "fp": 0, "fn": 0, "tn": 31}
    assert eligible == {"tp": 12, "fp": 0, "fn": 0, "tn": 38}


def test_independently_authored_holdout_has_no_semantic_discrepancies() -> None:
    spec = _load_spec("holdout")
    assert spec["authored_independently_of_implementation_tests"] is True
    assert spec["expected_labels_frozen_before_execution"] is True
    assert len(spec["cases"]) == 24

    typed, eligible = _metrics(spec)

    assert typed == {"tp": 10, "fp": 0, "fn": 0, "tn": 14}
    assert eligible == {"tp": 9, "fp": 0, "fn": 0, "tn": 15}


def test_corrected_family_survives_persistence_and_artifact_validation(
    tmp_path: Path,
) -> None:
    case = _load_spec("replay")["cases"][11]
    payload = _payload(case)
    _fact_set, _selection, report = _evaluate(case)
    storage = open_storage(f"sqlite:///{tmp_path / 'evaluation.db'}")
    storage.save_session(payload)
    job_id = storage.enqueue_analysis_job(payload)
    claim = storage.claim_analysis_jobs("evaluation-worker", 1, 30, 1)[0]
    report_id = storage.complete_analysis_job(
        job_id,
        "evaluation-worker",
        claim["claim_token"],
        report,
    )
    assert report_id
    persisted = storage.list_rows("reports", limit=1)[0]
    assert persisted["session_id"] == payload["session_id"]

    bundle = build_stix_bundle(report, payload)
    assert validate_stix_bundle_document(bundle) == []
    reports_dir = tmp_path / "reports"
    result = attach_report_artifacts(
        report,
        payload,
        ProductionConfig(
            reports_dir=str(reports_dir),
            enable_artifacts=True,
            enable_stix_export=True,
            enable_pdf_export=True,
        ),
    )
    assert "integrity_manifest" in result["artifacts"]
    assert validate_report_artifact_manifest(
        result["artifacts"]["integrity_manifest"]
    ) == []
    assert validate_session_assessment_v4(result) == []


def test_v4_stix_identity_excludes_runtime_only_report_fields() -> None:
    case = _load_spec("replay")["cases"][0]
    payload = _payload(case)
    _fact_set, _selection, report = _evaluate(case)
    baseline = build_stix_bundle(report, payload)
    changed = copy.deepcopy(report)
    changed["generated_at"] = "2031-01-02T03:04:05Z"
    changed["non_authoritative_context"]["prediction"] = {
        "status": "changed",
    }
    changed["response_guidance_v3"]["generated_at"] = (
        "2031-01-02T03:04:05Z"
    )
    changed["response_guidance_v3"]["non_authoritative_context"][
        "forecast"
    ] = {"status": "changed"}

    rebuilt = build_stix_bundle(changed, payload)

    assert rebuilt == baseline
    assert baseline["objects"][0]["modified"] == "2026-07-29T17:00:00Z"


@pytest.mark.parametrize(
    ("command", "expected_operations", "expected_match_count"),
    [
        (
            "cat < /etc/shadow",
            ["file_read", "credential_material_read"],
            1,
        ),
        (
            "head -c 20 < /etc/passwd",
            ["file_read", "account_metadata_read"],
            0,
        ),
        ("cat 2>/etc/shadow", ["unknown"], 0),
        ("cat 2 > /etc/shadow", ["file_read", "file_write"], 0),
        ("stat --dereference /etc/shadow", ["unknown"], 0),
        ("cat \"$(printf /etc/shadow)\"", ["unknown"], 0),
    ],
)
def test_redirect_metadata_and_nested_syntax_regressions(
    command: str,
    expected_operations: list[str],
    expected_match_count: int,
) -> None:
    case = {
        "case_id": hashlib.sha256(command.encode()).hexdigest()[:8],
        "command": command,
        "outcome": "success",
    }
    fact_set, selection, _report = _evaluate(case)
    operations = [
        item["operation_type"]
        for fact in fact_set["facts"]
        for item in fact["operations"]
    ]
    assert operations == expected_operations
    assert len(selection["matches"]) == expected_match_count
    if "$(" in command:
        assert all(
            not fact["entities"]["credential_paths"]
            for fact in fact_set["facts"]
        )


def test_complete_parsed_path_identity_is_shared_across_roles() -> None:
    case = {
        "case_id": "identity",
        "command": "less .aws/credentials",
        "cwd": "/home/identity",
        "outcome": "success",
    }
    fact_set, selection, _report = _evaluate(case)
    fact = fact_set["facts"][0]
    read_entity = fact["entities"]["read_paths"][0]
    credential_entity = fact["entities"]["credential_paths"][0]

    assert read_entity["entity_id"] == credential_entity["entity_id"]
    assert read_entity["normalized_value"] == (
        "/home/identity/.aws/credentials"
    )
    assert selection["matches"][0]["entity_ref"] == read_entity["entity_id"]


@pytest.mark.parametrize(
    "path",
    [
        "/home/user/.ssh/id_dsa",
        "/home/user/.ssh/id_ecdsa",
        "/home/user/.ssh/id_ed25519",
        "/home/user/.ssh/id_rsa",
        "/home/user/.aws/credentials",
        (
            "/home/user/.config/gcloud/"
            "application_default_credentials.json"
        ),
        "/etc/shadow",
    ],
)
def test_every_reviewed_complete_credential_path_is_supported(
    path: str,
) -> None:
    case = {
        "case_id": hashlib.sha256(path.encode()).hexdigest()[:8],
        "command": f"cat {path}",
        "outcome": "success",
    }
    fact_set, selection, _report = _evaluate(case)

    assert len(selection["matches"]) == 1
    assert selection["matches"][0]["entity_value"] == path
    assert validate_typed_semantic_fact_set(fact_set) == []


def test_meaningful_path_whitespace_is_not_trimmed_or_promoted() -> None:
    case = {
        "case_id": "path-whitespace",
        "command": "cat \"/etc/shadow \"",
        "outcome": "success",
    }
    fact_set, selection, _report = _evaluate(case)
    path = fact_set["facts"][0]["entities"]["read_paths"][0]

    assert path["original_value"] == "/etc/shadow "
    assert path["normalized_value"] == "/etc/shadow "
    assert fact_set["facts"][0]["entities"]["credential_paths"] == []
    assert selection["matches"] == []


@pytest.mark.parametrize(
    "path",
    [
        " /etc/shadow",
        "/etc/shadow ",
        "/etc/passwd\t",
        "/home/user/.ssh/id_rsa ",
        "/home/user/.aws/credentials\n",
    ],
)
def test_boundary_whitespace_is_preserved_and_never_promoted(
    path: str,
) -> None:
    case = {
        "case_id": hashlib.sha256(path.encode()).hexdigest()[:8],
        "command": f'cat "{path}"',
        "outcome": "success",
    }
    fact_set, selection, _report = _evaluate(case)
    read_path = fact_set["facts"][0]["entities"]["read_paths"][0]

    assert read_path["original_value"] == path
    assert fact_set["facts"][0]["entities"]["credential_paths"] == []
    assert selection["matches"] == []
