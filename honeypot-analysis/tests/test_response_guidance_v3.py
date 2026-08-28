from __future__ import annotations

import copy
import json
from pathlib import Path

from production.policies.validate_response_guidance_policy import (
    validate_response_guidance_policy,
)
from production.api.monitor_web import _report_recommendations
from production.reporting.artifacts import build_stix_bundle
from production.reporting.response_guidance_v3 import (
    build_response_guidance_v3_from_paths,
    build_response_guidance_v3_from_session,
    load_response_guidance_asset_profile,
    load_response_guidance_policy,
    read_legacy_response_guidance,
    validate_response_guidance_v3,
)
from production.reporting.session_assessment_v4 import build_session_assessment_v4


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "configs" / "response_guidance_policy.v3.json"


def _session() -> dict:
    return {
        "session_id": "response-guidance-v3-test",
        "src_ip": "192.0.2.44",
        "protocol": "ssh",
        "dst_port": 22,
        "commands": ["cat /home/alice/.ssh/id_rsa"],
        "classification_events": [{
            "command": "cat /home/alice/.ssh/id_rsa",
            "ttp": "T1552",
            "tactic": "credential-access",
            "source": "rule",
            "evidence_id": "v3-credential-observation",
            "cowrie_eventid": "cowrie.command.input",
        }],
    }


def test_v3_is_content_addressed_and_forecast_context_cannot_change_guidance() -> None:
    baseline = build_response_guidance_v3_from_session(_session())
    contextual = build_response_guidance_v3_from_session(
        _session(),
        forecast_context={"final_ranking": [{"tactic": "execution", "score": 1.0}]},
        enrichment_context={"reputation_risk_score": 100, "vt_hit": True},
    )

    assert baseline["validation"] == {"status": "valid", "errors": []}
    assert baseline["guidance_id"] == contextual["guidance_id"]
    assert baseline["findings"] == contextual["findings"]
    assert baseline["triage"] == contextual["triage"]
    assert baseline["advisory_actions"] == contextual["advisory_actions"]
    assert contextual["non_authoritative_context"]["forecast"]["final_ranking"]
    assert contextual["provenance"]["policy"]["sha256"] == load_response_guidance_policy()["sha256"]

    scored = _session()
    scored["classification_events"][0].update({
        "confidence": 0.01,
        "score": 1,
        "reputation_risk_score": 100,
        "predicted_tactic": "execution",
    })
    score_attached = build_response_guidance_v3_from_session(scored)
    assert score_attached["guidance_id"] == baseline["guidance_id"]
    assert score_attached["canonical_evidence"] == baseline["canonical_evidence"]


def test_v3_rejects_prediction_enrichment_and_automatic_action_policy_constructs() -> None:
    policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    policy["action_playbooks"][0]["applies_when"] = {
        "any_predicted_tactics": ["execution"],
    }
    policy["action_playbooks"][0]["actions"][0]["safe_to_auto_execute"] = True
    policy["action_playbooks"][0]["actions"][0]["requires_manual_approval"] = False

    errors = validate_response_guidance_policy(policy)

    assert any("non-canonical" in error for error in errors)
    assert any("requires_manual_approval must be true" in error for error in errors)
    assert any("safe_to_auto_execute must be false" in error for error in errors)


def test_v3_requires_observed_evidence_but_validly_represents_no_applicable_action() -> None:
    guidance = build_response_guidance_v3_from_session({"session_id": "no-observed-evidence"})

    assert guidance["status"] == "available"
    assert guidance["guidance_state"] == "no_applicable_grounded_action"
    assert guidance["advisory_actions"] == []
    assert guidance["findings"] == []
    assert validate_response_guidance_v3(guidance) == []


def test_v3_detects_tampered_canonical_refs_and_uses_explicit_profile_hash(tmp_path: Path) -> None:
    profile_path = tmp_path / "authorized_asset_profile.json"
    profile_path.write_text(json.dumps({
        "schema_version": "smb_asset_profile.v1",
        "assets": [{
            "asset_id": "authorized-ssh",
            "display_name": "Authorized SSH",
            "service_category": "remote_access",
            "criticality": "high",
        }],
    }), encoding="utf-8")
    guidance = build_response_guidance_v3_from_session(
        _session(), asset_profile_path=str(profile_path)
    )
    forged = copy.deepcopy(guidance)
    forged["advisory_actions"][0]["evidence_refs"] = ["forged-reference"]

    assert guidance["provenance"]["asset_profile"]["sha256"]
    assert load_response_guidance_asset_profile(str(ROOT / "configs/smb_asset_profile.example.json"))["status"] == "invalid"
    assert any("canonical observed-evidence grounding" in error for error in validate_response_guidance_v3(forged))


def test_new_reports_store_v3_only_and_preserve_legacy_input_as_read_only_metadata() -> None:
    historical = {
        "schema_version": "response_guidance.v2",
        "guidance_id": "historical",
    }
    original = copy.deepcopy(historical)
    adapter = read_legacy_response_guidance(historical)
    report = build_session_assessment_v4(
        [_session()],
        behavior_policy_path="configs/threat_hypothesis_behavior.trusted.json",
        classification_policy_path="configs/classification_rules.trusted.json",
    )

    assert historical == original
    assert adapter["status"] == "legacy_read_only"
    assert adapter["record"] == historical
    assert adapter["recomputed"] is False
    assert report["response_guidance_v3"]["schema_version"] == "response_guidance.v3"
    assert "response_guidance_v2" not in report
    assert "legacy_recommendation_adapter" not in report


def test_report_monitor_and_artifact_consumers_use_the_same_v3_actions() -> None:
    report = build_session_assessment_v4(
        [_session()],
        behavior_policy_path="configs/threat_hypothesis_behavior.trusted.json",
        classification_policy_path="configs/classification_rules.trusted.json",
    )
    guidance = report["response_guidance_v3"]
    monitor = _report_recommendations(report, {}, _session())
    bundle = build_stix_bundle(report, _session())

    assert monitor["response_guidance"]["guidance_id"] == guidance["guidance_id"]
    assert monitor["recommended_actions_structured"] == guidance["advisory_actions"]
    assert all(
        action["requires_manual_approval"] is True
        and action["safe_to_auto_execute"] is False
        for action in guidance["advisory_actions"]
    )
    assert len([
        item for item in bundle["objects"]
        if item.get("type") == "course-of-action"
    ]) == len(guidance["advisory_actions"])
