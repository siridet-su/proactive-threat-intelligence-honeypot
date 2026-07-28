from __future__ import annotations

from production.api.monitor_web import _render_next_steps, _report_recommendations
from production.reporting.threat_hypothesis import build_v2_report


def _classification(command: str, evidence_id: str = "classification-1") -> dict:
    return {
        "command": command,
        "ttp": "T1098",
        "tactic": "persistence",
        "source": "rule",
        "high_confidence": True,
        "evidence_id": evidence_id,
        "event_timestamp": "2026-07-20T00:00:00Z",
        "cowrie_eventid": "cowrie.command.input",
    }


def test_authorized_keys_read_cannot_be_promoted_to_persistence_claim() -> None:
    command = "cat /home/alice/.ssh/authorized_keys"
    report = build_v2_report({}, [{
        "session_id": "read-only-authorized-keys",
        "commands": [command],
        "classification_events": [_classification(command)],
    }])

    assert report["observed_behavior"]["ordered_command_observations"][0]["action_types"] == []
    assert "possible_continued_access_preparation" not in {
        claim["claim_type"]
        for claim in report["supported_assessment"]["possible_objectives"]
    }


def test_authorized_keys_write_remains_persistence_evidence() -> None:
    command = "printf placeholder >> /home/alice/.ssh/authorized_keys"
    report = build_v2_report({}, [{
        "session_id": "write-authorized-keys",
        "commands": [command],
        "classification_events": [_classification(command)],
    }])

    assert "account_modification_attempt" in (
        report["observed_behavior"]["ordered_command_observations"][0]["action_types"]
    )
    assert "possible_continued_access_preparation" in {
        claim["claim_type"]
        for claim in report["supported_assessment"]["possible_objectives"]
    }


def test_same_timestamp_duplicate_occurrences_have_distinct_identity() -> None:
    command = "whoami"
    events = [
        {
            "session": "duplicate-occurrences",
            "timestamp": "2026-07-20T00:00:00Z",
            "eventid": "cowrie.command.input",
            "input": command,
        },
        {
            "session": "duplicate-occurrences",
            "timestamp": "2026-07-20T00:00:00Z",
            "eventid": "cowrie.command.input",
            "input": command,
        },
    ]
    report = build_v2_report({}, [{
        "session_id": "duplicate-occurrences",
        "commands": [command, command],
        "classification_events": [],
        "raw_events": events,
    }], raw_events=events)
    observations = report["observed_behavior"]["ordered_command_observations"]

    assert len({item["evidence_id"] for item in observations}) == 2
    assert observations[1]["duplicate_of"] == observations[0]["evidence_id"]


def test_monitor_does_not_generate_legacy_next_action_heuristics() -> None:
    report = {
        "follow_on_hypothesis": {
            "claims": [],
            "abstention_reason": "No bounded follow-on hypothesis is supported.",
        }
    }
    recommendations = _report_recommendations(
        report,
        {},
        {"commands": ["whoami"], "tactics": ["discovery"]},
    )
    assert "rule_based_likely_next_steps" not in recommendations
    assert "predicted_next_action" not in recommendations
    assert "post_session_follow_on_hypothesis" not in recommendations

    html = _render_next_steps(
        {"payload": {"commands": ["whoami"], "tactics": ["discovery"]}},
        {"report_recommendations": recommendations},
    )
    assert "Likely Attacker Next Step" not in html
    assert "possible next steps" not in html
    assert "predicted next actions" in html
