from __future__ import annotations

import copy
import hashlib

import pytest

from production.prediction.next_behavior_contract import SESSION_SCHEMA_VERSION
from production.prediction.next_behavior_preprocessing import (
    build_live_model_input,
    build_next_behavior_examples,
)
from production.prediction.next_behavior_tensor import (
    NextBehaviorTensorError,
    build_vocabulary,
    tensorize_example,
    tensorize_live_session,
    tensorize_model_input,
    tensorize_target,
    validate_vocabulary,
    vocabulary_sha256,
)
from production.utils.serialization import stable_id, stable_json


HASH_A = "a" * 64
HASH_B = "b" * 64


def _opaque(kind: str, value: str) -> str:
    return f"nb{kind}_{hashlib.sha256(value.encode()).hexdigest()}"


def _group(
    name: str,
    order: int,
    tactic: str,
    technique: str,
    *,
    command_count: str,
) -> dict:
    evidence = _opaque("evidence", name)
    return {
        "group_id": _opaque("group", name),
        "event_order": order,
        "relative_time_ms": (order - 1) * 1000,
        "tactics": [tactic],
        "techniques": [technique],
        "evidence_refs": [evidence],
        "label_provenance": [
            {
                "tactic": tactic,
                "technique": technique,
                "source": "reviewed_rule",
                "trust_tier": "trusted_observation",
                "policy_sha256": HASH_A,
                "trust_policy_sha256": HASH_B,
                "checkpoint_sha256": "",
                "confidence": 1.0,
                "confidence_bucket": "high",
                "agreement_status": "rule_only",
                "evidence_ref": evidence,
            }
        ],
        "session_context": {
            "login_outcome": "success",
            "command_count_bucket": command_count,
            "session_age_bucket": "under_10s",
            "confirmed_transfer_observed": False,
        },
    }


def _session(groups: list[dict], *, status: str) -> dict:
    return {
        "schema_version": SESSION_SCHEMA_VERSION,
        "session_id": _opaque("session", "fixture"),
        "source_member_id": _opaque("member", "fixture"),
        "source_member_sha256": HASH_A,
        "protocol": "ssh",
        "status": status,
        "observation_groups": groups,
    }


def _closed() -> dict:
    return _session(
        [
            _group("one", 1, "discovery", "T1082", command_count="1"),
            _group("two", 2, "execution", "T1059.004", command_count="2-5"),
        ],
        status="closed",
    )


def _vocabulary() -> dict:
    training_input = build_next_behavior_examples(_closed())[0]["model_input"]
    return build_vocabulary(
        [training_input],
        preprocessing_sha256=HASH_A,
        training_membership_sha256=HASH_B,
    )


def test_vocabulary_is_deterministic_and_training_only() -> None:
    first_input = build_next_behavior_examples(_closed())[0]["model_input"]
    second_input = copy.deepcopy(first_input)

    first = build_vocabulary(
        [first_input, second_input],
        preprocessing_sha256=HASH_A,
        training_membership_sha256=HASH_B,
    )
    second = build_vocabulary(
        [second_input, first_input],
        preprocessing_sha256=HASH_A,
        training_membership_sha256=HASH_B,
    )

    assert first == second
    assert first["techniques"] == ["<UNK>", "T1082"]
    assert validate_vocabulary(first) == []
    assert len(vocabulary_sha256(first)) == 64


def test_offline_example_and_live_prefix_have_identical_tensors() -> None:
    closed = _closed()
    example = build_next_behavior_examples(closed)[0]
    live = _session(
        [copy.deepcopy(closed["observation_groups"][0])],
        status="active",
    )
    vocabulary = _vocabulary()

    offline_tensor = tensorize_example(example, vocabulary)
    live_tensor = tensorize_live_session(live, vocabulary)

    assert offline_tensor == live_tensor
    assert stable_json(offline_tensor).encode("utf-8") == stable_json(
        live_tensor
    ).encode("utf-8")
    assert offline_tensor["attention_mask"] == [0] * 7 + [1]
    assert offline_tensor["sequence_length"] == 1


def test_future_target_changes_cannot_change_prefix_tensor() -> None:
    closed = _closed()
    before_example = build_next_behavior_examples(closed)[0]
    changed = copy.deepcopy(closed)
    changed["observation_groups"][1] = _group(
        "future",
        2,
        "persistence",
        "T1098",
        command_count="2-5",
    )
    after_example = build_next_behavior_examples(changed)[0]
    vocabulary = _vocabulary()

    before = tensorize_example(before_example, vocabulary)
    after = tensorize_example(after_example, vocabulary)

    assert before == after


def test_unseen_techniques_use_unknown_channel_without_changing_dimensions() -> None:
    vocabulary = _vocabulary()
    live = _session(
        [_group("future", 1, "persistence", "T1098", command_count="1")],
        status="active",
    )

    tensor = tensorize_live_session(live, vocabulary)

    row = tensor["phase_technique_multi_hot"][-1]
    assert row[0] == 1
    assert len(row) == len(vocabulary["techniques"])


def test_evidence_identity_is_audit_metadata_not_a_tensor_feature() -> None:
    first = build_live_model_input(
        _session(
            [_group("one", 1, "discovery", "T1082", command_count="1")],
            status="active",
        )
    )
    second = copy.deepcopy(first)
    replacement = _opaque("evidence", "different")
    second["phase_sequence"][0]["evidence_refs"] = [replacement]
    second["input_evidence_refs"] = [replacement]
    second_without_hash = copy.deepcopy(second)
    second_without_hash.pop("input_hash")
    second["input_hash"] = stable_id("nextbehaviorinput", second_without_hash)
    vocabulary = _vocabulary()

    first_tensor = tensorize_model_input(first, vocabulary)
    second_tensor = tensorize_model_input(second, vocabulary)

    assert first_tensor["source_input_hash"] != second_tensor["source_input_hash"]
    comparable_first = copy.deepcopy(first_tensor)
    comparable_second = copy.deepcopy(second_tensor)
    comparable_first.pop("source_input_hash")
    comparable_second.pop("source_input_hash")
    assert comparable_first == comparable_second


def test_multilabel_and_terminal_targets_use_separate_channels() -> None:
    vocabulary = _vocabulary()
    multi = tensorize_target(
        {
            "outcome_type": "next_behavior_phase",
            "tactics": ["execution", "persistence"],
            "terminal_outcome": "",
        },
        vocabulary,
    )
    terminal = tensorize_target(
        {
            "outcome_type": "session_end",
            "tactics": [],
            "terminal_outcome": "session_end_no_further_trusted_behavior",
        },
        vocabulary,
    )

    assert sum(multi["tactic_multi_hot"]) == 2
    assert multi["terminal_outcome"] == 0
    assert sum(terminal["tactic_multi_hot"]) == 0
    assert terminal["terminal_outcome"] == 1


def test_tampered_vocabulary_and_unknown_target_fail_closed() -> None:
    vocabulary = _vocabulary()
    vocabulary["tactics"].reverse()
    assert any("frozen ordered" in error for error in validate_vocabulary(vocabulary))

    with pytest.raises(NextBehaviorTensorError, match="unknown tactic"):
        tensorize_target(
            {
                "outcome_type": "next_behavior_phase",
                "tactics": ["not-a-tactic"],
                "terminal_outcome": "",
            },
            _vocabulary(),
        )
