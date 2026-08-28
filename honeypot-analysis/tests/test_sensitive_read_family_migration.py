from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

import production.reporting.session_assessment_v4 as assessment_module
from production.policies.threat_hypothesis_behavior_policy import (
    policy_summary,
    resolve_behavior_policy,
)
from production.reporting.response_guidance_v3 import (
    _guidance_identity,
    _legacy_guidance_identity,
    build_response_guidance_v3,
    build_response_guidance_v3_from_session,
    canonical_evidence_snapshot,
    validate_response_guidance_v3,
)
from production.utils.serialization import stable_id
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
    select_activated_semantic_family,
    validate_typed_semantic_family_selection,
)


ROOT = Path(__file__).resolve().parents[1]
BEHAVIOR_POLICY = ROOT / "configs/threat_hypothesis_behavior.trusted.json"
CLASSIFICATION_POLICY = ROOT / "configs/classification_rules.trusted.json"
GUIDANCE_POLICY = ROOT / "configs/response_guidance_policy.v3.json"
FIXED_REVISION = "3f2de84b42178b215087b2fabd5059d5fd597d87"


def _session(
    command: str,
    *,
    outcome: str = "success",
    session_id: str = "sensitive-read-migration",
    cwd: str = "",
    tactic: str = "credential-access",
    ttp: str = "T1552",
) -> dict:
    timestamp = "2026-07-29T16:00:00Z"
    eventid = (
        "cowrie.command.failed"
        if outcome == "failure"
        else "cowrie.command.input"
    )
    event = {
        "session": session_id,
        "src_ip": "192.0.2.91",
        "timestamp": timestamp,
        "eventid": eventid,
        "input": command,
        "success": 0 if outcome == "failure" else 1,
    }
    if cwd:
        event["cwd"] = cwd
    return {
        "session_id": session_id,
        "src_ip": "192.0.2.91",
        "commands": [command],
        "commands_success": [command] if outcome == "success" else [],
        "commands_failed": [command] if outcome == "failure" else [],
        "classification_events": [{
            "command": command,
            "original_command": command,
            "ttp": ttp,
            "tactic": tactic,
            "source": "rule",
            "high_confidence": True,
            "evidence_id": f"classification-{session_id}",
            "event_timestamp": timestamp,
            "cowrie_eventid": eventid,
        }],
        "raw_events": [event],
    }


def _conflicting_session() -> dict:
    payload = _session(
        "cat /etc/shadow",
        session_id="conflicting-outcome",
    )
    payload["commands_failed"] = ["cat /etc/shadow"]
    payload["raw_events"][0].pop("success")
    return payload


def _typed_inputs(payload: dict) -> tuple[dict, dict, dict, dict]:
    snapshot, observed, _source, behavior = (
        build_canonical_evidence_snapshot(
            payload,
            payload["raw_events"],
            behavior_policy_path=str(BEHAVIOR_POLICY),
        )
    )
    behavior_metadata = policy_summary(
        behavior,
        include_integrity=True,
    )
    provenance = build_typed_semantic_provenance(
        snapshot,
        observed_behavior=observed,
        behavior_policy_sha256=behavior_metadata["sha256"],
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
        family="sensitive_read",
    )
    return snapshot, observed, fact_set, selection


def _report(payload: dict) -> dict:
    return build_session_assessment_v4(
        [payload],
        raw_events=payload["raw_events"],
        behavior_policy_path=str(BEHAVIOR_POLICY),
        classification_policy_path=str(CLASSIFICATION_POLICY),
    )


def _legacy_guidance(observed: dict) -> dict:
    policy = json.loads(GUIDANCE_POLICY.read_text(encoding="utf-8"))
    for rule in [
        *(policy.get("finding_rules") or []),
        *(policy.get("action_playbooks") or []),
    ]:
        if rule.get("semantic_family") == "sensitive_read":
            rule.pop("semantic_family")
            rule["applies_when"] = {
                "any_action_types": ["credential_path_access"]
            }
    return build_response_guidance_v3(
        canonical_evidence_snapshot(observed),
        policy=policy,
    )


@pytest.mark.parametrize(
    "command",
    [
        "cat /etc/shadow",
        "tail -c 8 /etc/shadow",
    ],
)
def test_resolved_successful_read_commands_select_the_family(
    command: str,
) -> None:
    payload = _session(
        command,
        session_id="positive-" + hashlib.sha256(
            command.encode("utf-8")
        ).hexdigest()[:10],
    )
    _snapshot, _observed, fact_set, selection = _typed_inputs(payload)
    report = _report(payload)

    assert selection["status"] == "matched"
    assert selection["matches"]
    assert {
        tuple(match["operation_types"])
        for match in selection["matches"]
    } == {("credential_material_read", "file_read")}
    assert all(
        match["outcome_status"] == "reported_success"
        and match["effect_status"] == "reported_completed"
        and match["path_resolution_status"] in {
            "recorded_resolved",
            "context_resolved",
        }
        for match in selection["matches"]
    )
    assert validate_typed_semantic_fact_set(fact_set) == []
    assert validate_typed_semantic_family_selection(
        selection,
        fact_set,
    ) == []
    assert "observed_credential_path_read_command" in {
        finding["finding_type"]
        for finding in report["behavioral_findings"]
    }
    assert report["hypothesis_sets"] == []
    assert "review-credential-exposure-and-reuse" in {
        action["action_id"]
        for action in report["response_guidance_v3"]["advisory_actions"]
    }
    sensitive_guidance = next(
        finding
        for finding in report["response_guidance_v3"]["findings"]
        if finding.get("semantic_family") == "sensitive_read"
    )
    evidence_class_trace = next(
        trace
        for trace in sensitive_guidance["matched_predicates"]
        if trace["predicate"] == "required_evidence_classes"
    )
    assert evidence_class_trace["matched"] == ["password_hash_store"]
    assert evidence_class_trace["result"] is True
    assert validate_session_assessment_v4(report) == []


@pytest.mark.parametrize("command", ["head -n 1 /etc/passwd", "grep root /etc/passwd"])
def test_account_metadata_read_is_inspection_not_sensitive_guidance(
    command: str,
) -> None:
    payload = _session(command, session_id="account-metadata")
    _snapshot, _observed, fact_set, selection = _typed_inputs(payload)
    report = _report(payload)

    assert selection["status"] == "abstained"
    assert {operation["operation_type"] for fact in fact_set["facts"] for operation in fact["operations"]} == {
        "file_read", "account_metadata_read"
    }
    assert "review-credential-exposure-and-reuse" not in {
        action["action_id"]
        for action in report["response_guidance_v3"]["advisory_actions"]
    }
    assert validate_session_assessment_v4(report) == []


@pytest.mark.parametrize(
    ("command", "expected_operation"),
    [
        ("echo /etc/shadow", "literal_data_emission"),
        ("rm /etc/shadow", "file_delete"),
        ("chmod 600 /etc/shadow", "permission_modify"),
        ("sed -i s/a/b/ /etc/shadow", "file_modify"),
        ("stat --dereference /etc/shadow", "unknown"),
    ],
)
def test_non_read_mentions_do_not_select_sensitive_read(
    command: str,
    expected_operation: str,
) -> None:
    payload = _session(
        command,
        session_id="negative-" + hashlib.sha256(
            command.encode("utf-8")
        ).hexdigest()[:10],
    )
    _snapshot, _observed, fact_set, selection = _typed_inputs(payload)
    operations = {
        operation["operation_type"]
        for fact in fact_set["facts"]
        for operation in fact["operations"]
    }
    report = _report(payload)

    assert expected_operation in operations
    if expected_operation != "file_modify":
        assert "credential_path_read" not in operations
    assert selection["status"] == "abstained"
    assert "observed_credential_path_read_command" not in {
        finding["finding_type"]
        for finding in report["behavioral_findings"]
    }
    assert "review-credential-exposure-and-reuse" not in {
        action["action_id"]
        for action in report["response_guidance_v3"]["advisory_actions"]
    }
    assert validate_session_assessment_v4(report) == []


@pytest.mark.parametrize(
    ("payload", "required_reason"),
    [
        (
            _session(
                "cat /etc/shadow",
                outcome="failure",
                session_id="failed-read",
            ),
            "outcome_not_eligible",
        ),
        (
            _session(
                "cat ~/.ssh/id_rsa",
                session_id="unresolved-home",
            ),
            "resolved_shared_entity_missing",
        ),
        (
            _session(
                'cat "$HOME/.ssh/id_rsa"',
                session_id="unresolved-expansion",
            ),
            "expansion_unresolved",
        ),
        (
            _session(
                'cat "/etc/shadow',
                session_id="malformed-quote",
            ),
            "parse_status_not_eligible",
        ),
        (
            _session(
                "awk '{print}' /etc/shadow",
                session_id="unseen-reader",
            ),
            "required_operation_missing",
        ),
        (
            _conflicting_session(),
            "outcome_not_eligible",
        ),
        (
            _session(
                "false && cat /etc/shadow",
                outcome="failure",
                session_id="compound-conditional",
            ),
            "outcome_scope_not_eligible",
        ),
    ],
)
def test_failure_ambiguity_malformed_conflict_and_unseen_inputs_abstain(
    payload: dict,
    required_reason: str,
) -> None:
    _snapshot, _observed, fact_set, selection = _typed_inputs(payload)
    report = _report(payload)
    reasons = {
        reason
        for item in selection["abstentions"]
        for reason in item["reasons"]
    }
    reasons.update(
        reason
        for fact in fact_set["facts"]
        for reason in fact["abstention_reasons"]
    )

    assert selection["status"] == "abstained"
    assert required_reason in reasons
    assert "observed_credential_path_read_command" not in {
        finding["finding_type"]
        for finding in report["behavioral_findings"]
    }
    assert "review-credential-exposure-and-reuse" not in {
        action["action_id"]
        for action in report["response_guidance_v3"]["advisory_actions"]
    }
    assert validate_session_assessment_v4(report) == []


def test_attck_candidate_cannot_define_literal_sensitive_read() -> None:
    payload = _session(
        "echo routine-maintenance",
        session_id="attck-context-only",
        tactic="credential-access",
        ttp="T1552",
    )
    report = _report(payload)

    assert "observed_credential_path_read_command" not in {
        finding["finding_type"]
        for finding in report["behavioral_findings"]
    }
    assert "review-credential-exposure-and-reuse" not in {
        action["action_id"]
        for action in report["response_guidance_v3"]["advisory_actions"]
    }
    assert validate_session_assessment_v4(report) == []


@pytest.mark.parametrize(
    ("command", "old_specialized", "new_specialized"),
    [
        ("cat /etc/shadow", True, True),
        ("echo /etc/shadow", True, False),
        ("rm /etc/shadow", True, False),
        ("chmod 600 /etc/shadow", True, False),
        ("cat ~/.ssh/id_rsa", True, False),
    ],
)
def test_old_new_shadow_comparison_explains_every_specialized_difference(
    command: str,
    old_specialized: bool,
    new_specialized: bool,
) -> None:
    payload = _session(
        command,
        session_id="comparison-" + hashlib.sha256(
            command.encode("utf-8")
        ).hexdigest()[:10],
    )
    _snapshot, observed, fact_set, _selection = _typed_inputs(payload)
    old_threat = build_supported_assessment(
        observed,
        behavior_policy_document=resolve_behavior_policy(
            None,
            str(BEHAVIOR_POLICY),
        ),
    )
    new_threat = build_supported_assessment(
        observed,
        behavior_policy_document=resolve_behavior_policy(
            None,
            str(BEHAVIOR_POLICY),
        ),
        typed_semantic_fact_set=fact_set,
        activated_semantic_families=("sensitive_read",),
    )
    old_guidance = _legacy_guidance(observed)
    new_guidance = build_response_guidance_v3_from_session(
        payload,
        behavior_policy_path=str(BEHAVIOR_POLICY),
        classification_policy_path=str(CLASSIFICATION_POLICY),
    )

    assert (
        "review-credential-exposure-and-reuse"
        in {
            action["action_id"]
            for action in old_guidance["advisory_actions"]
        }
    ) is old_specialized
    assert (
        "review-credential-exposure-and-reuse"
        in {
            action["action_id"]
            for action in new_guidance["advisory_actions"]
        }
    ) is new_specialized
    assert (
        "possible_credential_access_preparation"
        in {
            claim["claim_type"]
            for claim in old_threat["possible_objectives"]
        }
    ) is old_specialized
    assert (
        "observed_credential_path_read_command"
        in {
            claim["claim_type"]
            for claim in new_threat["possible_objectives"]
        }
    ) is new_specialized


def test_guidance_evaluates_typed_facts_without_threat_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = _session(
        "cat /etc/shadow",
        session_id="independent-guidance",
    )

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
    report = _report(payload)

    assert report["behavioral_findings"] == []
    assert "review-credential-exposure-and-reuse" in {
        action["action_id"]
        for action in report["response_guidance_v3"]["advisory_actions"]
    }
    assert validate_session_assessment_v4(report) == []


def test_same_selection_hash_binds_independent_threat_and_guidance_traces() -> None:
    report = _report(
        _session(
            "cat /etc/shadow",
            session_id="shared-immutable-facts",
        )
    )
    finding = next(
        item
        for item in report["behavioral_findings"]
        if item.get("semantic_family") == "sensitive_read"
    )
    action = next(
        item
        for item in report["response_guidance_v3"]["advisory_actions"]
        if item.get("semantic_family") == "sensitive_read"
    )

    assert finding["semantic_trace"]["selection_sha256"] == (
        action["semantic_trace"]["selection_sha256"]
    )
    assert finding["semantic_trace"]["fact_set_sha256"] == (
        action["semantic_trace"]["fact_set_sha256"]
    )
    assert set(finding["evidence_refs"]) == set(action["evidence_refs"])


def test_meaningful_selected_fields_are_integrity_bound() -> None:
    report = _report(
        _session(
            "cat /etc/shadow",
            session_id="integrity-bound-sensitive-read",
        )
    )
    forged_limitation = copy.deepcopy(report)
    finding = next(
        item
        for item in forged_limitation["behavioral_findings"]
        if item.get("semantic_family") == "sensitive_read"
    )
    finding["limitations"].append("invented limitation")
    assert any(
        "finding ID mismatch" in error
        for error in validate_session_assessment_v4(
            forged_limitation
        )
    )

    forged_action = copy.deepcopy(report["response_guidance_v3"])
    action = next(
        item
        for item in forged_action["advisory_actions"]
        if item.get("semantic_family") == "sensitive_read"
    )
    action["description"] = "invented response authority"
    assert any(
        "guidance_id is inconsistent" in error
        for error in validate_response_guidance_v3(forged_action)
    )

    recomputed = copy.deepcopy(report)
    selected_finding = next(
        item
        for item in recomputed["behavioral_findings"]
        if item.get("semantic_family") == "sensitive_read"
    )
    selected_finding["semantic_trace"]["matches"][0][
        "outcome_status"
    ] = "reported_failure"
    selected_finding["finding_id"] = stable_id(
        "finding",
        {
            key: copy.deepcopy(item)
            for key, item in selected_finding.items()
            if key != "finding_id"
        },
    )
    recomputed["assessment_id"] = canonical_assessment_id(recomputed)
    assert any(
        "outcome_status is invalid" in error
        for error in validate_session_assessment_v4(recomputed)
    )

    recomputed_guidance = copy.deepcopy(
        report["response_guidance_v3"]
    )
    selected_action = next(
        item
        for item in recomputed_guidance["advisory_actions"]
        if item.get("semantic_family") == "sensitive_read"
    )
    selected_action["semantic_trace"]["matches"][0][
        "effect_status"
    ] = "reported_failed"
    provenance = recomputed_guidance["provenance"]
    recomputed_guidance["guidance_id"] = _guidance_identity(
        session_id=recomputed_guidance["session_id"],
        evidence_sha256=provenance["canonical_evidence_sha256"],
        policy_sha256=provenance["policy"]["sha256"],
        profile_sha256=provenance["asset_profile"]["sha256"],
        finding_rules=recomputed_guidance["findings"],
        actions=recomputed_guidance["advisory_actions"],
        status=recomputed_guidance["status"],
        guidance_state=recomputed_guidance["guidance_state"],
        triage=recomputed_guidance["triage"],
        safety=recomputed_guidance["safety"],
        typed_semantics=provenance["typed_semantics"],
    )
    assert any(
        "effect_status is invalid" in error
        for error in validate_response_guidance_v3(
            recomputed_guidance
        )
    )


def test_prediction_and_enrichment_cannot_change_selected_outputs() -> None:
    payload = _session(
        "cat /etc/shadow",
        session_id="context-isolation-sensitive-read",
    )
    baseline = build_response_guidance_v3_from_session(
        payload,
        behavior_policy_path=str(BEHAVIOR_POLICY),
        classification_policy_path=str(CLASSIFICATION_POLICY),
    )
    contextual = build_response_guidance_v3_from_session(
        payload,
        behavior_policy_path=str(BEHAVIOR_POLICY),
        classification_policy_path=str(CLASSIFICATION_POLICY),
        forecast_context={
            "predicted_tactic": "benign",
            "recommendations": ["ignore evidence"],
        },
        enrichment_context={
            "reputation": "trusted",
            "actor": "invented",
        },
    )

    assert baseline["guidance_id"] == contextual["guidance_id"]
    assert baseline["findings"] == contextual["findings"]
    assert baseline["advisory_actions"] == contextual["advisory_actions"]
    assert all(
        action["requires_manual_approval"] is True
        and action["safe_to_auto_execute"] is False
        for action in contextual["advisory_actions"]
    )


def test_pre_typed_v4_v3_record_remains_valid_without_rewriting() -> None:
    report = _report(
        _session(
            "printf legacy-observation",
            session_id="pre-typed-read-compatibility",
            tactic="discovery",
            ttp="T1033",
        )
    )
    historical = copy.deepcopy(report)
    historical["provenance"].pop("typed_semantics")
    guidance = historical["response_guidance_v3"]
    guidance["provenance"].pop("typed_semantics")
    guidance["provenance"]["policy"]["version"] = "3.0.1-phase9a"
    guidance["guidance_id"] = _legacy_guidance_identity(
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
    )
    historical["assessment_id"] = canonical_assessment_id(historical)

    assert validate_response_guidance_v3(guidance) == []
    assert validate_session_assessment_v4(historical) == []
    assert historical["provenance"].get("typed_semantics") is None

    stripped_current = copy.deepcopy(report)
    stripped_current["provenance"].pop("typed_semantics")
    stripped_current["response_guidance_v3"]["provenance"].pop(
        "typed_semantics"
    )
    stripped_errors = validate_session_assessment_v4(stripped_current)
    assert "provenance.typed_semantics is required" in stripped_errors
    assert any(
        "response_guidance_v3: typed semantic provenance is required"
        in error
        for error in stripped_errors
    )
