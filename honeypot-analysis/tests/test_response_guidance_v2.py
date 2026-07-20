from __future__ import annotations

import copy
import json
from pathlib import Path
from types import SimpleNamespace

from production.reporting.response_guidance import (
    ANALYST_DECISION_STATES,
    OUTCOME_STATES,
    validate_analyst_decision_record,
    validate_response_guidance,
)
from production.reporting.smb_decision import build_smb_decision
from production.reporting.smb_decision import build_smb_decision_from_paths
from production.reporting.reporting_pipeline import _build_trusted_recommendation_decision
from production.reporting.threat_hypothesis import build_v2_report
from production.api.dashboard_api import _current_decision_payload
from production.api.monitor_web import _render_next_steps
from production.utils.config import ProductionConfig


ROOT = Path(__file__).resolve().parents[1]


def _policy() -> dict:
    return json.loads((ROOT / "configs/smb_action_playbooks.trusted.json").read_text(encoding="utf-8"))


def _asset_profile() -> dict:
    return json.loads((ROOT / "configs/smb_asset_profile.example.json").read_text(encoding="utf-8"))


def _session() -> dict:
    command = "whoami"
    return {
        "session_id": "response-guidance-v2",
        "protocol": "ssh",
        "dst_port": 22,
        "commands": [command],
        "classification_events": [{
            "command": command,
            "ttp": "T1033",
            "tactic": "discovery",
            "source": "rule",
            "high_confidence": True,
            "evidence_id": "guidance-discovery",
            "event_timestamp": "2026-07-20T02:00:00Z",
            "cowrie_eventid": "cowrie.command.input",
        }],
    }


def test_v2_is_additive_and_actions_preserve_trusted_policy_provenance() -> None:
    decision = build_smb_decision(
        _session(),
        action_policy=_policy(),
        asset_profile=_asset_profile(),
    )
    guidance = decision["response_guidance_v2"]

    assert decision["schema_version"] == "smb_decision.v1"
    assert guidance["schema_version"] == "response_guidance.v2"
    assert guidance["compatibility"]["smb_decision_v1_preserved"] is True
    assert guidance["validation"] == {"status": "valid", "errors": []}
    assert guidance["advisory_actions"]
    for action in guidance["advisory_actions"]:
        assert action["source_action"] in decision["immediate_actions"]
        assert action["applicability"]["status"] in {
            "applicable_under_policy", "context_dependent"
        }
        assert action["preconditions"]
        assert action["owner_role"] == "security_analyst"
        assert action["verification_steps"]
        assert action["rollback_guidance"]
        assert action["expires_at"] is None
        assert action["manual_approval"] == {
            "required": True,
            "state": "pending",
            "execution_authority": False,
        }


def test_v2_separates_finding_triage_and_inert_analyst_record() -> None:
    guidance = build_smb_decision(
        _session(), action_policy=_policy(), asset_profile=_asset_profile()
    )["response_guidance_v2"]

    assert guidance["finding"]["kind"] == "cowrie_session_policy_finding"
    assert guidance["triage"]["semantics"] == "categorical_policy_triage_not_numeric_risk"
    assert "score" not in guidance["triage"]
    assert validate_analyst_decision_record(guidance["analyst_decision"]) == []
    assert guidance["analyst_decision"]["decision_state"] in ANALYST_DECISION_STATES
    assert guidance["analyst_decision"]["outcome"]["state"] in OUTCOME_STATES
    assert guidance["analyst_decision"]["semantics"] == "record_only_no_execution_authority"
    assert guidance["safety"]["automatic_execution"] is False


def test_prediction_cannot_be_the_sole_advisory_action_basis() -> None:
    decision = build_smb_decision(
        _session(), action_policy=_policy(), asset_profile=_asset_profile()
    )
    forged = copy.deepcopy(decision["response_guidance_v2"])
    forged_action = forged["advisory_actions"][0]
    forged_action["applicability"]["evidence_scope"] = ["model_prediction"]
    forged_action["applicability"]["evidence_refs"] = []

    assert any(
        "relies only on statistical prediction" in error
        for error in validate_response_guidance(forged)
    )
    assert guidance_prediction_authority(decision) == "advisory_forecast_only_no_action_selection"


def guidance_prediction_authority(decision: dict) -> str:
    return decision["response_guidance_v2"]["provenance"]["prediction_authority"]


def test_canonical_degraded_mode_suppresses_v2_actions_but_preserves_v1() -> None:
    decision = build_smb_decision(
        _session(), action_policy=_policy(), asset_profile=_asset_profile()
    )
    assert decision["immediate_actions"]
    degraded = copy.deepcopy(decision)
    degraded["evidence"]["canonical_summary"]["status"] = "unavailable"

    from production.reporting.response_guidance import build_response_guidance_v2

    guidance = build_response_guidance_v2(degraded)
    assert guidance["status"] == "unavailable"
    assert guidance["advisory_actions"] == []
    assert guidance["provenance"]["degraded_mode"] == "canonical_evidence_unavailable"
    assert degraded["immediate_actions"] == decision["immediate_actions"]


def test_report_exposes_both_additive_contracts_without_rewriting_v1_v2() -> None:
    decision = build_smb_decision(
        _session(), action_policy=_policy(), asset_profile=_asset_profile()
    )
    report = build_v2_report(
        {"trusted_recommendation_decision": decision},
        [_session()],
    )

    assert report["schema_version"] == "threat_hypothesis.v2"
    assert report["trusted_recommendation_decision"]["schema_version"] == "smb_decision.v1"
    assert report["response_guidance_v2"]["schema_version"] == "response_guidance.v2"
    assert report["session_assessment_v3"]["response_guidance_ref"] == {
        "schema_version": "response_guidance.v2",
        "guidance_id": report["response_guidance_v2"]["guidance_id"],
        "status": report["response_guidance_v2"]["status"],
    }


def test_report_worker_api_and_direct_builder_share_one_guidance_semantics() -> None:
    prediction = {
        "snapshot_id": "guidance-parity-snapshot",
        "final_ranking": [{
            "tactic": "execution",
            "confidence": "possible",
            "score": 0.6,
            "reasons": ["separate forecast"],
        }],
    }
    asset_path = str(ROOT / "configs/smb_asset_profile.example.json")
    policy_path = str(ROOT / "configs/smb_action_playbooks.trusted.json")
    direct = build_smb_decision_from_paths(
        _session(),
        prediction_snapshot=prediction,
        asset_profile_path=asset_path,
        action_policy_path=policy_path,
    )
    report_path = _build_trusted_recommendation_decision(
        [SimpleNamespace(**_session())],
        [],
        {"discovery": ["T1033"]},
        {"T1033": ["whoami"]},
        asset_profile_path=asset_path,
        action_policy_path=policy_path,
        prediction_snapshot=prediction,
    )

    class Storage:
        @staticmethod
        def get_session(_session_id: str) -> dict:
            return {"payload": _session(), "src_ip": "192.0.2.10"}

    config = ProductionConfig(
        smb_asset_profile_path=asset_path,
        smb_action_policy_path=policy_path,
        enable_smb_decisions=True,
    )
    api_path = _current_decision_payload(
        config,
        Storage(),
        _session()["session_id"],
        {"payload": prediction},
    )

    for result in (report_path, api_path):
        assert result["likely_next_step"] == direct["likely_next_step"]
        assert result["response_guidance_v2"]["guidance_id"] == (
            direct["response_guidance_v2"]["guidance_id"]
        )
        assert [
            item["action_id"] for item in result["response_guidance_v2"]["advisory_actions"]
        ] == [
            item["action_id"] for item in direct["response_guidance_v2"]["advisory_actions"]
        ]


def test_monitor_renders_advisory_contract_without_duplicate_forecast() -> None:
    decision = build_smb_decision(
        _session(),
        prediction_snapshot={
            "final_ranking": [{
                "tactic": "execution",
                "confidence": "possible",
                "score": 0.6,
                "reasons": ["separate forecast"],
            }]
        },
        action_policy=_policy(),
        asset_profile=_asset_profile(),
    )
    html = _render_next_steps(
        {"payload": _session()},
        {
            "smb_decision": decision,
            "report_recommendations": {
                "post_session_follow_on_hypothesis": "No bounded hypothesis.",
                "source": "trusted_policy_engine",
            },
        },
    )

    assert "Advisory Response Guidance" in html
    assert "Advisory Actions" in html
    assert "no execution authority" in html
    assert "predicted_next_tactic" not in html
    assert "Likely Attacker Next Step" not in html


def test_counterfactual_removing_observed_commands_removes_advisory_actions() -> None:
    observed = build_smb_decision(
        _session(), action_policy=_policy(), asset_profile=_asset_profile()
    )["response_guidance_v2"]
    without_evidence = copy.deepcopy(_session())
    without_evidence["commands"] = []
    without_evidence["classification_events"] = []
    counterfactual = build_smb_decision(
        without_evidence, action_policy=_policy(), asset_profile=_asset_profile()
    )["response_guidance_v2"]

    assert observed["advisory_actions"]
    observed_ids = {item["action_id"] for item in observed["advisory_actions"]}
    counterfactual_ids = {
        item["action_id"] for item in counterfactual["advisory_actions"]
    }
    assert counterfactual_ids == {"track-scan-volume"}
    assert observed_ids.isdisjoint(counterfactual_ids)


def test_prediction_changes_forecast_context_but_not_action_selection() -> None:
    baseline = build_smb_decision(
        _session(), action_policy=_policy(), asset_profile=_asset_profile()
    )
    predicted = build_smb_decision(
        _session(),
        prediction_snapshot={
            "final_ranking": [{
                "tactic": "execution",
                "confidence": "possible",
                "score": 0.9,
                "reasons": ["separate transition forecast"],
            }]
        },
        action_policy=_policy(),
        asset_profile=_asset_profile(),
    )

    assert predicted["likely_next_step"]["tactic"] == "execution"
    assert [item["action_id"] for item in predicted["response_guidance_v2"]["advisory_actions"]] == [
        item["action_id"] for item in baseline["response_guidance_v2"]["advisory_actions"]
    ]


def test_forged_v1_action_produces_zero_v2_advisory_actions() -> None:
    decision = build_smb_decision(
        _session(), action_policy=_policy(), asset_profile=_asset_profile()
    )
    forged = copy.deepcopy(decision)
    forged["immediate_actions"] = [{
        "action_id": "forged-action",
        "action": "Untrusted action",
        "evidence_scope": ["observed_session_evidence"],
        "evidence_refs": ["forged-ref"],
    }]

    from production.reporting.response_guidance import build_response_guidance_v2

    guidance = build_response_guidance_v2(forged)
    assert guidance["status"] == "unavailable"
    assert guidance["advisory_actions"] == []
    assert guidance["validation"]["status"] == "rejected"
