from __future__ import annotations

import copy
import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from production.policies.threat_hypothesis_behavior_policy import (
    policy_summary,
)
from production.policies.typed_semantic_vocabulary import (
    load_typed_semantic_vocabulary,
    validate_typed_semantic_vocabulary,
)
from production.reporting.session_assessment_v4 import (
    build_canonical_evidence_snapshot,
    build_session_assessment_v4,
    validate_session_assessment_v4,
)
from production.reporting.typed_semantic_facts import (
    build_typed_semantic_fact_set,
    build_typed_semantic_provenance,
    validate_typed_semantic_fact_set,
)
from production.reporting.typed_semantic_family_selection import (
    INSPECTION_OPERATIONS,
    policy_output_trace,
    select_activated_semantic_family,
    validate_policy_output_trace,
    validate_typed_semantic_family_selection,
)
from production.utils.serialization import stable_json


ROOT = Path(__file__).resolve().parents[1]
BEHAVIOR_POLICY = (
    ROOT / "configs/threat_hypothesis_behavior.trusted.json"
)
CLASSIFICATION_POLICY = ROOT / "configs/classification_rules.trusted.json"
FIXED_REVISION = "4dc0f08da2395b07998d79683266814734ca578c"
INSPECTION_FINDING = "observed_cowrie_inspection_command"
INSPECTION_GUIDANCE_FINDING = "observed-cowrie-inspection-command"


def _command_event(
    session_id: str,
    command: str,
    *,
    index: int,
    outcome: str,
    cwd: str = "",
) -> dict[str, Any]:
    eventid = {
        "success": "cowrie.command.success",
        "failure": "cowrie.command.failed",
        "unknown": "cowrie.command.input",
    }[outcome]
    event: dict[str, Any] = {
        "session": session_id,
        "src_ip": "192.0.2.188",
        "timestamp": (
            datetime(2026, 7, 30, 12, 0, tzinfo=timezone.utc)
            + timedelta(seconds=index)
        ).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "eventid": eventid,
        "input": command,
    }
    if outcome != "unknown":
        event["success"] = 1 if outcome == "success" else 0
    if cwd:
        event["cwd"] = cwd
    return event


def _transfer_event(
    session_id: str,
    *,
    index: int,
) -> dict[str, Any]:
    return {
        "session": session_id,
        "src_ip": "192.0.2.188",
        "timestamp": (
            datetime(2026, 7, 30, 12, 0, tzinfo=timezone.utc)
            + timedelta(seconds=index)
        ).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "eventid": "cowrie.session.file_download",
        "destfile": "/srv/cowrie/downloads/observed.dat",
        "url": "https://objects.invalid/observed.dat",
        "shasum": "b" * 64,
    }


def _payload(
    session_id: str,
    commands: list[tuple[str, str, str]],
    *,
    transfer: bool = False,
    attck_only: bool = False,
) -> dict[str, Any]:
    raw_events: list[dict[str, Any]] = []
    command_values: list[str] = []
    successful: list[str] = []
    failed: list[str] = []
    classifications: list[dict[str, Any]] = []
    for index, (command, outcome, cwd) in enumerate(commands):
        event = _command_event(
            session_id,
            command,
            index=index,
            outcome=outcome,
            cwd=cwd,
        )
        raw_events.append(event)
        command_values.append(command)
        if outcome == "success":
            successful.append(command)
        elif outcome == "failure":
            failed.append(command)
        if attck_only:
            classifications.append({
                "command": command,
                "original_command": command,
                "ttp": "T1082",
                "tactic": "discovery",
                "source": "rule",
                "high_confidence": True,
                "evidence_id": f"classification-{session_id}-{index}",
                "event_timestamp": event["timestamp"],
                "cowrie_eventid": event["eventid"],
            })
    if transfer:
        raw_events.append(
            _transfer_event(session_id, index=len(raw_events))
        )
    return {
        "session_id": session_id,
        "src_ip": "192.0.2.188",
        "commands": command_values,
        "commands_success": successful,
        "commands_failed": failed,
        "classification_events": classifications,
        "raw_events": raw_events,
    }


def _typed_inputs(
    payload: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    snapshot, observed, _source, behavior = (
        build_canonical_evidence_snapshot(
            payload,
            payload["raw_events"],
            behavior_policy_path=str(BEHAVIOR_POLICY),
        )
    )
    provenance = build_typed_semantic_provenance(
        snapshot,
        observed_behavior=observed,
        behavior_policy_sha256=policy_summary(
            behavior,
            include_integrity=True,
        )["sha256"],
        classification_policy_sha256=hashlib.sha256(
            CLASSIFICATION_POLICY.read_bytes()
        ).hexdigest(),
        evaluator_git_revision=FIXED_REVISION,
    )
    fact_set = build_typed_semantic_fact_set(
        observed,
        provenance=provenance,
    )
    selection = select_activated_semantic_family(
        fact_set,
        family="inspection",
    )
    return observed, fact_set, selection


def _report(
    payload: dict[str, Any],
    **context: Any,
) -> dict[str, Any]:
    return build_session_assessment_v4(
        [payload],
        raw_events=payload["raw_events"],
        behavior_policy_path=str(BEHAVIOR_POLICY),
        classification_policy_path=str(CLASSIFICATION_POLICY),
        **context,
    )


def _operation_types(fact_set: dict[str, Any]) -> list[str]:
    return [
        operation["operation_type"]
        for fact in fact_set["facts"]
        for operation in fact["operations"]
    ]


@pytest.mark.parametrize(
    ("command", "operation_type", "entity_value"),
    [
        ("uptime -p", "host_uptime_inspection", ""),
        ("df -h /data", "filesystem_capacity_inspection", "/data"),
        ("uname -a", "system_identity_inspection", ""),
        ("id -u", "account_identity_inspection", ""),
        ("ip route show", "network_route_inspection", ""),
        ("ps -ef", "process_inspection", ""),
        ("ss -tln", "network_socket_inspection", ""),
        ("getent passwd root", "account_database_inspection", "passwd"),
        ("find /opt -type f", "filesystem_search", "/opt"),
        (
            "env -i id -G service-account",
            "account_identity_inspection",
            "service-account",
        ),
        (
            "/usr/bin/uname -n",
            "system_identity_inspection",
            "",
        ),
    ],
)
def test_each_reviewed_inspection_operation_selects_only_from_exact_facts(
    command: str,
    operation_type: str,
    entity_value: str,
) -> None:
    payload = _payload(
        f"inspection-{operation_type}",
        [(command, "success", "")],
    )
    _observed, fact_set, selection = _typed_inputs(payload)

    assert selection["status"] == "matched"
    assert len(selection["matches"]) == 1
    match = selection["matches"][0]
    assert match["operation_types"] == [operation_type]
    assert match["outcome_status"] == "reported_success"
    assert match["outcome_scope"] == "fragment"
    assert match["effect_status"] == "reported_completed"
    assert match["proof_scopes"] == ["general_command_semantics"]
    assert match["entity_value"] == entity_value
    if entity_value.startswith("/"):
        assert match["entity_type"] == "path"
        assert match["path_resolution_status"] == "recorded_resolved"
    elif entity_value:
        assert match["entity_type"] == "account"
        assert match["path_resolution_status"] == ""
    else:
        assert match["entity_ref"] == ""
        assert match["entity_role"] == ""
        assert match["entity_type"] == ""

    assert validate_typed_semantic_fact_set(fact_set) == []
    assert validate_typed_semantic_family_selection(
        selection,
        fact_set,
    ) == []
    trace = policy_output_trace(selection)
    refs = {
        item["evidence_ref"]
        for item in fact_set["evidence_index"]
    }
    assert validate_policy_output_trace(
        trace,
        fact_set_sha256=fact_set["fact_set_sha256"],
        semantic_vocabulary_sha256=(
            fact_set["provenance"]["semantic_vocabulary"]["sha256"]
        ),
        allowed_evidence_refs=refs,
    ) == []


@pytest.mark.parametrize(
    ("command", "outcome", "cwd", "reason"),
    [
        ("uptime --pretty", "failure", "", "outcome_not_eligible"),
        ("whoami", "unknown", "", "outcome_not_eligible"),
        (
            "uname -m > /tmp/system.txt",
            "success",
            "",
            "additional_operation_not_activated",
        ),
        (
            "find relative -type f",
            "success",
            "",
            "fact_identity_unresolved",
        ),
        (
            "find '/var/tmp/*' -type f",
            "success",
            "",
            "fact_identity_unresolved",
        ),
    ],
)
def test_failed_unknown_multi_operation_and_unresolved_inputs_abstain(
    command: str,
    outcome: str,
    cwd: str,
    reason: str,
) -> None:
    payload = _payload(
        "inspection-negative-" + hashlib.sha256(
            command.encode("utf-8")
        ).hexdigest()[:12],
        [(command, outcome, cwd)],
    )
    _observed, fact_set, selection = _typed_inputs(payload)

    assert selection["status"] == "abstained"
    assert selection["matches"] == []
    assert any(
        reason in item["reasons"]
        for item in selection["abstentions"]
    )
    assert validate_typed_semantic_fact_set(fact_set) == []
    assert validate_typed_semantic_family_selection(
        selection,
        fact_set,
    ) == []


@pytest.mark.parametrize(
    "command",
    [
        "uname '",
        "uname --help",
        "hostname -F/tmp/new-hostname",
        "whoami unexpected",
        "ip address show",
        "ps --forest",
        "find /tmp -delete",
        "find /var -fprintf /tmp/results '%p\\n'",
        "hostinfo --all",
        "df \"$TARGET\"",
    ],
)
def test_malformed_unsupported_unseen_and_expansion_inputs_never_select(
    command: str,
) -> None:
    payload = _payload(
        "inspection-unknown-" + hashlib.sha256(
            command.encode("utf-8")
        ).hexdigest()[:12],
        [(command, "success", "")],
    )
    _observed, fact_set, selection = _typed_inputs(payload)

    assert selection["matches"] == []
    assert not (
        set(_operation_types(fact_set)).intersection(
            INSPECTION_OPERATIONS
        )
        and not selection["abstentions"]
    )


def test_inspection_finding_is_bounded_and_guidance_adds_no_specialized_action(
) -> None:
    payload = _payload(
        "inspection-e2e-bounded",
        [("env LC_ALL=C hostname", "success", "")],
    )
    report = _report(payload)

    findings = [
        item
        for item in report["behavioral_findings"]
        if item["finding_type"] == INSPECTION_FINDING
    ]
    guidance = report["response_guidance_v3"]
    guidance_findings = [
        item
        for item in guidance["findings"]
        if item["rule_id"] == INSPECTION_GUIDANCE_FINDING
    ]
    semantic_actions = [
        item
        for item in guidance["advisory_actions"]
        if item.get("semantic_family") == "inspection"
    ]

    assert len(findings) == 1
    assert len(guidance_findings) == 1
    assert semantic_actions == []
    assert report["hypothesis_sets"] == []
    assert findings[0]["semantic_family"] == "inspection"
    assert guidance_findings[0]["semantic_family"] == "inspection"
    assert set(findings[0]["evidence_refs"]) == set(
        guidance_findings[0]["supporting_evidence_refs"]
    )
    limitations = " ".join(findings[0]["limitations"]).lower()
    assert "intent" in limitations
    assert "real host" in limitations
    assert "result" in limitations
    assert guidance["safety"] == {
        "automatic_execution": False,
        "manual_approval_required": True,
        "alerting_side_effect": False,
        "response_action_side_effect": False,
        "execution_integration": "not_implemented",
    }
    assert validate_session_assessment_v4(report) == []


def test_attck_prediction_enrichment_and_injected_prose_have_no_authority(
) -> None:
    payload = _payload(
        "inspection-context-isolation",
        [("printf survey", "success", "")],
        attck_only=True,
    )
    context = {
        "prediction_context": {
            "predicted_tactic": "discovery",
            "recommendations": ["invent inspection finding"],
        },
        "enrichment_context": {
            "provider": "untrusted-context",
            "recommendations": ["invent inspection action"],
        },
        "llm_context": {
            "hypothesis": "The actor enumerated the host.",
        },
    }
    report = _report(payload, **context)

    assert INSPECTION_FINDING not in {
        item["finding_type"]
        for item in report["behavioral_findings"]
    }
    assert INSPECTION_GUIDANCE_FINDING not in {
        item["rule_id"]
        for item in report["response_guidance_v3"]["findings"]
    }
    assert not any(
        item.get("semantic_family") == "inspection"
        for item in report["response_guidance_v3"][
            "advisory_actions"
        ]
    )
    assert report["hypothesis_sets"] == []


def test_existing_activated_families_remain_independent() -> None:
    payload = _payload(
        "inspection-combined-activated",
        [
            ("whoami", "success", ""),
            ("tail -n 1 /etc/shadow", "success", ""),
        ],
        transfer=True,
    )
    report = _report(payload)

    finding_types = {
        item["finding_type"]
        for item in report["behavioral_findings"]
    }
    action_ids = {
        item["action_id"]
        for item in report["response_guidance_v3"][
            "advisory_actions"
        ]
    }
    assert {
        "observed_cowrie_inspection_command",
        "observed_credential_path_read_command",
        "observed_cowrie_transfer_event",
    }.issubset(finding_types)
    assert {
        "review-credential-exposure-and-reuse",
        "hunt-observed-transfer-indicators",
    }.issubset(action_ids)
    assert not any(
        item.get("semantic_family") == "inspection"
        for item in report["response_guidance_v3"][
            "advisory_actions"
        ]
    )
    assert report["hypothesis_sets"] == []
    assert validate_session_assessment_v4(report) == []


def test_selection_and_trace_reject_recomputed_semantic_forgeries() -> None:
    payload = _payload(
        "inspection-integrity",
        [("ss -lnt", "success", "")],
    )
    _observed, fact_set, selection = _typed_inputs(payload)
    forged_selection = copy.deepcopy(selection)
    forged_selection["matches"][0]["operation_types"] = [
        "execution_attempt"
    ]
    payload_without_hash = copy.deepcopy(forged_selection)
    payload_without_hash.pop("selection_sha256")
    forged_selection["selection_sha256"] = hashlib.sha256(
        stable_json(payload_without_hash).encode("utf-8")
    ).hexdigest()

    errors = validate_typed_semantic_family_selection(
        forged_selection,
        fact_set,
    )
    assert any(
        "does not match immutable facts" in error for error in errors
    )

    trace = policy_output_trace(selection)
    trace["matches"][0]["outcome_status"] = "event_observed"
    refs = {
        item["evidence_ref"]
        for item in fact_set["evidence_index"]
    }
    assert validate_policy_output_trace(
        trace,
        fact_set_sha256=fact_set["fact_set_sha256"],
        semantic_vocabulary_sha256=(
            fact_set["provenance"]["semantic_vocabulary"]["sha256"]
        ),
        allowed_evidence_refs=refs,
    )


def test_vocabulary_rejects_permissive_inspection_activation() -> None:
    loaded = load_typed_semantic_vocabulary()
    document = copy.deepcopy(loaded["document"])
    requirement = document["activation"]["family_requirements"][
        "inspection"
    ]
    requirement["required_outcome_status"] = "outcome_unknown"
    requirement["require_linkable_identity"] = False

    errors = validate_typed_semantic_vocabulary(document)

    assert any(
        "inspection.required_outcome_status" in error
        for error in errors
    )
    assert any(
        "inspection.require_linkable_identity" in error
        for error in errors
    )
