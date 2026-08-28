from __future__ import annotations

import copy
import hashlib
from pathlib import Path

import pytest

from production.prediction.next_behavior_contract import SESSION_SCHEMA_VERSION
from production.prediction.next_trusted_group_target import (
    EXAMPLE_SCHEMA_VERSION,
    MAXIMUM_TRUSTED_GROUPS,
    TARGET_CONTRACT_ID,
    TERMINAL_OUTCOME,
    NextTrustedGroupTargetError,
    build_next_trusted_group_examples,
    load_next_trusted_group_target_policy,
    target_policy_file_sha256,
    validate_next_trusted_group_example,
)


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "configs" / "next_trusted_group_target_policy.v1.json"
HASH_A = "a" * 64
HASH_B = "b" * 64


def _safe_id(kind: str, value: str) -> str:
    return f"nb{kind}_{hashlib.sha256(value.encode()).hexdigest()}"


def _context(count: int) -> dict:
    bucket = "1" if count == 1 else "2-5" if count <= 5 else "6-20" if count <= 20 else "21+"
    return {
        "login_outcome": "success",
        "command_count_bucket": bucket,
        "session_age_bucket": "under_10s",
        "confirmed_transfer_observed": False,
    }


def _label(
    group_name: str,
    index: int,
    tactic: str,
    technique: str,
    *,
    trust_tier: str = "trusted_observation",
) -> dict:
    value = {
        "tactic": tactic,
        "technique": technique,
        "source": "reviewed_rule",
        "trust_tier": trust_tier,
        "policy_sha256": HASH_A,
        "trust_policy_sha256": HASH_B,
        "checkpoint_sha256": "",
        "confidence": 1.0,
        "confidence_bucket": "high",
        "agreement_status": "rule_only",
        "evidence_ref": _safe_id("evidence", f"{group_name}:{index}"),
    }
    if trust_tier != "trusted_observation":
        value["exclusion_reason"] = "unreviewed_rule"
    return value


def _group(
    name: str,
    order: int,
    time_ms: int,
    labels: list[tuple[str, str]],
    *,
    audit_labels: list[tuple[str, str]] | None = None,
) -> dict:
    trusted = [
        _label(name, index, tactic, technique)
        for index, (tactic, technique) in enumerate(labels)
    ]
    audit = [
        _label(f"{name}:audit", index, tactic, technique, trust_tier="audit_only_candidate")
        for index, (tactic, technique) in enumerate(audit_labels or [])
    ]
    return {
        "group_id": _safe_id("group", name),
        "event_order": order,
        "relative_time_ms": time_ms,
        "tactics": sorted({item[0] for item in labels}),
        "techniques": sorted({item[1] for item in labels}),
        "evidence_refs": sorted(item["evidence_ref"] for item in trusted),
        "label_provenance": trusted,
        "audit_only_labels": audit,
        "session_context": _context(order),
    }


def _session(groups: list[dict], *, status: str = "closed") -> dict:
    return {
        "schema_version": SESSION_SCHEMA_VERSION,
        "session_id": _safe_id("session", "session-one"),
        "source_member_id": _safe_id("member", "member-one"),
        "source_member_sha256": HASH_A,
        "protocol": "ssh",
        "status": status,
        "observation_groups": groups,
    }


def test_frozen_policy_defines_separate_non_training_target() -> None:
    policy = load_next_trusted_group_target_policy(POLICY_PATH)

    assert policy["target_contract_id"] == TARGET_CONTRACT_ID
    assert policy["lineage"] == {
        "predecessor_target_contract_id": "next_distinct_trusted_behavior_phase_or_session_end.v2",
        "predecessor_evidence_status": "immutable_historical_no_go",
        "predecessor_examples_reused": False,
        "predecessor_contract_modified": False,
    }
    assert policy["input_history"]["same_tactic_groups_collapsed"] is False
    assert policy["training_authorization"] == {
        "support_analysis_only": True,
        "transformer_training_authorized": False,
        "production_change_authorized": False,
    }
    assert len(target_policy_file_sha256(POLICY_PATH)) == 64


def test_one_closed_group_yields_one_terminal_example() -> None:
    examples = build_next_trusted_group_examples(
        _session([_group("one", 1, 0, [("discovery", "T1082")])])
    )

    assert len(examples) == 1
    assert examples[0]["schema_version"] == EXAMPLE_SCHEMA_VERSION
    assert examples[0]["target"] == {
        "outcome_type": "session_end",
        "will_continue": False,
        "tactics": [],
        "techniques": [],
        "labels": [],
        "terminal_outcome": TERMINAL_OUTCOME,
        "target_group_id": "",
        "target_event_order": None,
        "target_evidence_refs": [],
    }


def test_two_different_groups_yield_continuation_then_terminal() -> None:
    groups = [
        _group("one", 1, 0, [("discovery", "T1082")]),
        _group("two", 2, 2500, [("execution", "T1059")]),
    ]

    examples = build_next_trusted_group_examples(_session(groups))

    assert len(examples) == 2
    assert examples[0]["target"]["outcome_type"] == "continuation"
    assert examples[0]["target"]["tactics"] == ["execution"]
    assert examples[0]["target"]["labels"] == [
        {"tactic": "execution", "technique": "T1059"}
    ]
    assert examples[1]["target"]["outcome_type"] == "session_end"


def test_repeated_same_tactic_groups_are_not_collapsed() -> None:
    groups = [
        _group("one", 1, 0, [("discovery", "T1082")]),
        _group("two", 2, 500, [("discovery", "T1033")]),
    ]

    examples = build_next_trusted_group_examples(_session(groups))

    assert len(examples) == 2
    assert examples[0]["target"]["outcome_type"] == "continuation"
    assert examples[0]["target"]["tactics"] == ["discovery"]
    assert examples[0]["target"]["target_group_id"] == groups[1]["group_id"]
    assert examples[1]["target"]["outcome_type"] == "session_end"


def test_multilabel_target_preserves_exact_tactic_technique_pairing() -> None:
    groups = [
        _group("one", 1, 0, [("discovery", "T1082")]),
        _group(
            "two",
            2,
            500,
            [("execution", "T1059"), ("persistence", "T1053")],
        ),
    ]

    target = build_next_trusted_group_examples(_session(groups))[0]["target"]

    assert target["labels"] == [
        {"tactic": "execution", "technique": "T1059"},
        {"tactic": "persistence", "technique": "T1053"},
    ]
    assert target["tactics"] == ["execution", "persistence"]
    assert target["techniques"] == ["T1053", "T1059"]


def test_active_final_group_is_unresolved_but_observed_continuation_is_eligible() -> None:
    groups = [
        _group("one", 1, 0, [("discovery", "T1082")]),
        _group("two", 2, 1000, [("execution", "T1059")]),
    ]

    examples = build_next_trusted_group_examples(_session(groups, status="active"))

    assert len(examples) == 1
    assert examples[0]["target"]["outcome_type"] == "continuation"


def test_audit_only_labels_are_context_never_target_truth() -> None:
    groups = [
        _group(
            "one",
            1,
            0,
            [("discovery", "T1082")],
            audit_labels=[("execution", "T1059")],
        ),
        _group("two", 2, 1000, [("persistence", "T1098")]),
    ]

    example = build_next_trusted_group_examples(_session(groups))[0]

    assert example["model_input"]["group_sequence"][0]["audit_only_label_count"] == 1
    assert example["target"]["tactics"] == ["persistence"]
    assert "execution" not in example["target"]["tactics"]


def test_future_target_mutation_does_not_change_causal_input() -> None:
    groups = [
        _group("one", 1, 0, [("discovery", "T1082")]),
        _group("two", 2, 1000, [("execution", "T1059")]),
    ]
    before = build_next_trusted_group_examples(_session(groups))[0]
    changed = copy.deepcopy(groups)
    changed[1] = _group("changed", 2, 8000, [("persistence", "T1098")])
    after = build_next_trusted_group_examples(_session(changed))[0]

    assert before["model_input"] == after["model_input"]
    assert before["target"] != after["target"]
    assert not (
        set(after["model_input"]["input_evidence_refs"])
        & set(after["target"]["target_evidence_refs"])
    )


def test_history_is_last_eight_groups_without_phase_collapse() -> None:
    groups = [
        _group(f"group-{index}", index, index * 1000, [("discovery", "T1082")])
        for index in range(1, 11)
    ]

    final = build_next_trusted_group_examples(_session(groups))[-1]["model_input"]

    assert final["maximum_trusted_groups"] == MAXIMUM_TRUSTED_GROUPS
    assert final["original_trusted_group_count"] == 10
    assert final["selected_trusted_group_count"] == 8
    assert final["omitted_prefix_trusted_group_count"] == 2
    assert final["truncated"] is True
    assert len(final["group_sequence"]) == 8


@pytest.mark.parametrize(
    "mutation, expected",
    [
        (lambda value: value["model_input"].__setitem__("input_hash", "0" * 64), "input_hash"),
        (lambda value: value["target"].__setitem__("tactics", ["impact"]), "aggregates"),
        (lambda value: value["target"].__setitem__("target_group_id", "forged"), "identity"),
        (lambda value: value["target"].__setitem__("target_evidence_refs", value["model_input"]["input_evidence_refs"]), "leaked"),
    ],
)
def test_tampered_example_fails_closed(mutation, expected: str) -> None:
    value = build_next_trusted_group_examples(
        _session(
            [
                _group("one", 1, 0, [("discovery", "T1082")]),
                _group("two", 2, 1000, [("execution", "T1059")]),
            ]
        )
    )[0]
    mutation(value)

    assert any(expected in error for error in validate_next_trusted_group_example(value))


def test_invalid_policy_does_not_satisfy_frozen_design(tmp_path: Path) -> None:
    value = POLICY_PATH.read_text(encoding="utf-8").replace(
        '"same_tactic_groups_collapsed": false',
        '"same_tactic_groups_collapsed": true',
    )
    path = tmp_path / "policy.json"
    path.write_text(value, encoding="utf-8")

    with pytest.raises(NextTrustedGroupTargetError):
        load_next_trusted_group_target_policy(path)
