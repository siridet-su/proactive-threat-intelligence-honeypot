from __future__ import annotations

from production.classification.classification_pipeline import NotebookParityClassifier
from production.classification.trust import (
    classification_evidence_tier,
    is_trusted_classification_event,
)
from production.correlation.campaign_clustering import (
    _campaign_id_for_fingerprint,
    _confirmed_tactics,
    find_matching_campaigns,
    score_campaign_match,
)
from production.correlation.session_behavior_relationships import extract_command_entities
from production.correlation.session_evidence_graph import build_session_evidence_graph
from production.correlation.session_ttp_correlation import (
    correlate_session,
    correlation_allows_influence,
    validate_policy_document,
)
from production.prediction.session_features import build_session_features
from production.workers.threat_hunt_worker import _source_severity, _tactics


class _Mitre:
    @staticmethod
    def get_name(ttp: str) -> str:
        return ttp

    @staticmethod
    def get_tactics(ttp: str) -> list[str]:
        return {
            "T1033": ["discovery"],
            "T1082": ["discovery"],
        }.get(ttp, [])


def _correlation_policy(
    *,
    reviewed: bool = False,
    prediction: bool = False,
    campaign: bool = False,
    threat_hunt: bool = False,
    alert: bool = False,
) -> dict:
    rule = {
        "rule_id": "phase8-impact-candidate",
        "enabled": True,
        "ttp": "T1499",
        "tactic": "impact",
        "technique_name": "Endpoint Denial of Service",
        "confidence": 0.8,
        "evidence_type": "session_correlated_candidate",
        "source_type": "human_curated_attck_detection",
        "temporal_claim": False,
        "apply_to_prediction": prediction,
        "apply_to_campaign": campaign,
        "apply_to_threat_hunt": threat_hunt,
        "apply_to_alert": alert,
        "reason": "Phase 8 influence-scope regression fixture.",
        "conditions": {"any": [{"type": "command_regex", "pattern": r"\bwhoami\b"}]},
        "references": [
            {
                "name": "MITRE ATT&CK T1499",
                "url": "https://attack.mitre.org/techniques/T1499/",
            }
        ],
        "provenance": {
            "method": "unit_test",
            "basis": ["Phase 8 regression"],
            "author": "test",
            "reviewed": reviewed,
            "generated": False,
            "created": "2026-07-19",
            "version": "1",
        },
    }
    if prediction:
        rule["prediction_eligibility"] = {
            "reviewed": reviewed,
            "evaluated": reviewed,
        }
    return {
        "schema_version": "session_ttp_correlation_policy.v1",
        "policy_id": "phase8-influence-policy",
        "version": "1",
        "policy": {"enabled": True, "rules": [rule]},
    }


def test_disagreement_and_emergency_fallback_are_audit_only(tmp_path) -> None:
    reviewed = NotebookParityClassifier(
        bert_fn=lambda _command: ("T1082", 0.99),
        mitre_db=_Mitre(),
        rule_policy_path="configs/classification_rules.trusted.json",
    )
    disagreement = reviewed.classify("whoami")[0]
    assert disagreement["source"] == "rule_securebert_disagreement"
    assert classification_evidence_tier(disagreement) == "audit_only_candidate"
    assert is_trusted_classification_event(disagreement) is False

    disagreement_payload = {
        "session_id": "phase8-disagreement",
        "commands": ["whoami"],
        "classification_events": [disagreement],
    }
    assert build_session_features(disagreement_payload)["observed_ttps"] == []
    assert _confirmed_tactics(disagreement_payload) == []
    assert _tactics(disagreement_payload) == []
    graph = build_session_evidence_graph(disagreement_payload)
    assert graph["summary"]["classification_event_count"] == 0
    assert graph["summary"]["audit_only_classification_event_count"] == 1
    assert graph["audit_only_classification_candidates"][0]["source"] == (
        "rule_securebert_disagreement"
    )

    missing_policy = tmp_path / "missing-classification-policy.json"
    emergency = NotebookParityClassifier(
        bert_fn=lambda _command: ("T1033", 0.99),
        mitre_db=_Mitre(),
        rule_policy_path=str(missing_policy),
    ).classify("whoami")[0]
    assert emergency["rule_policy_id"] == "emergency-python-fallback"
    assert emergency["source"] == "emergency_python_fallback"
    assert emergency["agreement_status"] == "emergency_rule_model_agreement_audit_only"
    assert emergency["high_confidence"] is False
    assert classification_evidence_tier(emergency) == "audit_only_candidate"
    assert build_session_features(
        {
            "session_id": "phase8-emergency",
            "commands": ["whoami"],
            "classification_events": [emergency],
        }
    )["observed_ttps"] == []


def test_report_only_correlations_cannot_influence_downstream_consumers() -> None:
    session = {
        "session_id": "phase8-report-only",
        "commands": ["whoami"],
        "classification_events": [],
    }
    result = correlate_session(session, _correlation_policy())
    correlation = result["correlations"][0]
    assert correlation_allows_influence(correlation, "report") is True
    for consumer in ("prediction", "campaign", "threat_hunt", "alert"):
        assert correlation_allows_influence(correlation, consumer) is False

    payload = {**session, "session_ttp_correlations": [correlation]}
    assert build_session_features(payload)["correlated_tactics"] == []
    assert _confirmed_tactics(payload) == []
    assert _tactics(payload) == []
    severity_policy = {
        "severity_by_observable_type": {"ip": "low"},
        "tactic_severity": {"impact": "critical"},
    }
    assert _source_severity(severity_policy, "ip", payload) == "low"

    scoped_policy = _correlation_policy(
        reviewed=True,
        prediction=True,
        campaign=True,
        threat_hunt=True,
        alert=False,
    )
    assert validate_policy_document(scoped_policy) == []
    scoped = correlate_session(session, scoped_policy)["correlations"][0]
    scoped_payload = {**session, "session_ttp_correlations": [scoped]}
    # Reviewed correlation remains available to its declared downstream
    # consumers, but the simplified rollback predictor consumes only direct,
    # trusted classification evidence.
    assert build_session_features(scoped_payload)["correlated_tactics"] == []
    assert _confirmed_tactics(scoped_payload) == ["impact"]
    assert _tactics(scoped_payload) == ["impact"]
    assert _source_severity(severity_policy, "ip", scoped_payload) == "low"

    alert_policy = _correlation_policy(reviewed=True, alert=True)
    alert_correlation = correlate_session(session, alert_policy)["correlations"][0]
    assert _source_severity(
        severity_policy,
        "ip",
        {**session, "session_ttp_correlations": [alert_correlation]},
    ) == "critical"

    legacy_reviewed_prediction = {
        "apply_to_prediction": True,
        "prediction_eligibility": {
            "effective": True,
            "reviewed": True,
            "evaluated": True,
        },
    }
    assert correlation_allows_influence(legacy_reviewed_prediction, "prediction") is True
    assert correlation_allows_influence(
        {"apply_to_prediction": True},
        "prediction",
    ) is False


def test_unreviewed_policy_cannot_enable_strong_correlation_consumers() -> None:
    for consumer in ("campaign", "threat_hunt", "alert"):
        policy = _correlation_policy(**{consumer: True})
        errors = validate_policy_document(policy)
        assert any(f"apply_to_{consumer} requires provenance.reviewed=true" in item for item in errors)


def test_authorized_keys_reads_are_not_account_modifications() -> None:
    for command in (
        "cat /home/alice/.ssh/authorized_keys",
        "ls /home/alice/.ssh/authorized_keys",
        "cp /home/alice/.ssh/authorized_keys /tmp/authorized-keys-copy",
    ):
        extracted = extract_command_entities(command)
        assert "account_modified" not in extracted["action_types"]
        assert extracted["entities"]["modified_paths"] == []

    credential_read = extract_command_entities("cat /etc/shadow")
    assert "credential_path_access" in credential_read["action_types"]
    assert "account_modified" not in credential_read["action_types"]
    assert credential_read["entities"]["modified_paths"] == []

    redirected = extract_command_entities(
        "printf placeholder >> /home/alice/.ssh/authorized_keys"
    )
    assert "account_modification_attempt" in redirected["action_types"]
    assert redirected["entities"]["modified_paths"]

    copied = extract_command_entities(
        "cp /tmp/public-key /home/alice/.ssh/authorized_keys"
    )
    assert "account_modification_attempt" in copied["action_types"]
    assert copied["entities"]["modified_paths"]


def test_duplicate_command_occurrences_link_to_distinct_graph_nodes() -> None:
    command = "whoami"
    payload = {
        "session_id": "phase8-duplicate-occurrences",
        "commands": [command, command],
        "classification_events": [
            {
                "command": command,
                "ttp": "T1033",
                "tactic": "discovery",
                "source": "rule",
                "high_confidence": True,
            },
            {
                "command": command,
                "ttp": "T1033",
                "tactic": "discovery",
                "source": "rule",
                "high_confidence": True,
            },
        ],
        "raw_events": [
            {"eventid": "cowrie.command.input", "input": command},
            {"eventid": "cowrie.command.input", "input": command},
        ],
    }
    edges = build_session_evidence_graph(payload)["edges"]
    classified_edges = [item for item in edges if item["relation"] == "classified_as"]
    emitted_edges = [item for item in edges if item["relation"] == "emitted_command"]
    assert classified_edges == [
        {"source": "command:0", "target": "classification:0", "relation": "classified_as"},
        {"source": "command:1", "target": "classification:1", "relation": "classified_as"},
    ]
    assert emitted_edges == [
        {"source": "event:0", "target": "command:0", "relation": "emitted_command"},
        {"source": "event:1", "target": "command:1", "relation": "emitted_command"},
    ]


class _CampaignStorage:
    def __init__(self, campaign: dict) -> None:
        self.campaign = campaign

    def find_matching_campaigns(self, fingerprint: dict, limit: int) -> list[dict]:
        del fingerprint, limit
        return [self.campaign]


def test_source_ip_only_campaign_match_is_capped_and_rejected_by_default() -> None:
    campaign = {"campaign_id": "campaign-existing", "source_ip": "192.0.2.40"}
    fingerprint = {
        "src_ip": "192.0.2.40",
        "hassh_fingerprint": "",
        "ja3_fingerprint": "",
        "command_pattern_hash": "",
        "tactic_sequence_hash": "",
        "primary_fingerprint_type": "src_ip",
        "primary_fingerprint_value": "192.0.2.40",
    }
    policy = {
        "field_weights": {"source_ip": 0.2},
        "min_match_score": 0.1,
        "min_match_raw_score": 0.1,
        "min_independent_evidence_classes": 1,
        "allow_source_ip_only_match": False,
        "source_ip_only_confidence": 0.2,
        "max_matches": 10,
    }
    score = score_campaign_match(campaign, fingerprint, policy)
    assert score["raw_score"] == 0.2
    assert score["score"] == 0.2
    assert score["source_ip_only"] is True
    assert score["match_category"] == "source_ip_only_low_confidence"
    assert find_matching_campaigns(_CampaignStorage(campaign), fingerprint, policy) == []

    explicitly_allowed = {**policy, "allow_source_ip_only_match": True}
    matches = find_matching_campaigns(
        _CampaignStorage(campaign),
        fingerprint,
        explicitly_allowed,
    )
    assert len(matches) == 1
    assert matches[0]["score"] == 0.2

    first_id = _campaign_id_for_fingerprint(fingerprint, "session-one")
    second_id = _campaign_id_for_fingerprint(fingerprint, "session-two")
    assert first_id != second_id
