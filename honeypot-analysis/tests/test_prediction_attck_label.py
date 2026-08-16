from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from production.classification.trust import classification_evidence_tier
from production.prediction.prediction_attck_label import (
    AUTHORITY,
    BARRIER_SCHEMA_VERSION,
    CONTINUATION_OUTCOME,
    EXAMPLE_SCHEMA_VERSION,
    GROUP_SCHEMA_VERSION,
    HISTORY_SCHEMA_VERSION,
    LABEL_SCHEMA_VERSION,
    MAXIMUM_HISTORY_GROUPS,
    PredictionAttckLabelError,
    TARGET_CONTRACT_ID,
    TERMINAL_OUTCOME,
    build_next_prediction_label_examples,
    build_prediction_attck_environment,
    build_prediction_label_group,
    evaluate_prediction_candidate,
    load_prediction_attck_label_policy,
    validate_prediction_attck_environment,
    validate_prediction_attck_label_policy,
    validate_prediction_label_group,
    validate_prediction_label,
)


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "configs" / "prediction_attck_label_policy.v1.json"
RULE_HASH = "51cfae25ff39238bbb48ee7143fda675dcb22a2be369b3c558970759799f89ee"
MEMBER_HASH = "a" * 64


def _id(prefix: str, value: str) -> str:
    return f"nb{prefix}_{hashlib.sha256(value.encode()).hexdigest()}"


@pytest.fixture(scope="module")
def policy() -> dict:
    return load_prediction_attck_label_policy(POLICY_PATH)


def _candidate(
    policy: dict,
    *,
    name: str = "event",
    tactic: str = "discovery",
    technique: str = "T1082",
    rule_id: str = "cmd-rule-002-t1082-system-information-discovery",
    evidence_type: str = "command_regex",
    source: str = "rule",
    event_order: int = 1,
    parser_status: str = "parsed",
    prediction_context: dict | None = None,
    **extra,
) -> dict:
    value = {
        "event_id": _id("event", name),
        "source_member_id": _id("member", "member-one"),
        "source_member_sha256": MEMBER_HASH,
        "event_order": event_order,
        "relative_time_ms": event_order * 1000,
        "source": source,
        "evidence_type": evidence_type,
        "rule_id": rule_id,
        "rule_reviewed": True,
        "rule_policy_sha256": RULE_HASH,
        "reviewed_technique": technique,
        "reviewed_tactic": tactic,
        "tactic": tactic,
        "parser_status": parser_status,
        "prediction_context": prediction_context or {
            "reviewed": True,
            "class": "reviewed_literal_command_pattern",
        },
        "policy_sha256": policy["policy_sha256"],
    }
    value.update(extra)
    return value


def _label(policy: dict, **kwargs) -> dict:
    result = evaluate_prediction_candidate(
        _candidate(policy, **kwargs),
        policy=policy,
        sanitizer_policy_id="cowrie_output_privacy.v1",
        pseudonymization_policy_id="next-behavior-hmac-test",
        parser_identity="command_operations.v2",
        splitter_identity="classification_splitter.v1",
        labeler_identity="prediction_attck_labeler.v1",
    )
    assert result["status"] == "eligible", result
    return result["label"]


def _group(policy: dict, name: str, order: int, tactic: str = "discovery", technique: str = "T1082") -> dict:
    rule_ids = {
        ("discovery", "T1082"): "cmd-rule-002-t1082-system-information-discovery",
        ("discovery", "T1033"): "cmd-rule-001-t1033-system-owner-user-discovery",
        ("execution", "T1059"): "cmd-rule-033-t1059-command-and-scripting-interpreter",
        ("persistence", "T1098"): "cmd-rule-022-t1098-account-manipulation",
    }
    return build_prediction_label_group(
        [_label(policy, name=name, event_order=order, tactic=tactic, technique=technique, rule_id=rule_ids[(tactic, technique)])],
        relative_time_ms=order * 1000,
    )


def _session(policy: dict, groups: list[dict], *, barriers: list[dict] | None = None, status: str = "closed") -> dict:
    return {
        "session_id": _id("session", "session-one"),
        "source_member_id": groups[0]["source_member_id"],
        "source_member_sha256": MEMBER_HASH,
        "status": status,
        "close_event_order": 100 if status == "closed" else None,
        "close_event_id": _id("event", "close") if status == "closed" else "",
        "durable_watermark_id": _id("watermark", "watermark-one"),
        "groups": groups,
        "barriers": barriers or [],
        "policy": policy,
        "sanitizer_policy_id": "cowrie_output_privacy.v1",
        "pseudonymization_policy_id": "next-behavior-hmac-test",
        "parser_identity": "command_operations.v2",
        "splitter_identity": "classification_splitter.v1",
        "labeler_identity": "prediction_attck_labeler.v1",
    }


def test_policy_is_separate_and_frozen(policy: dict) -> None:
    assert policy["authority"] == AUTHORITY
    assert policy["target_contract_id"] == TARGET_CONTRACT_ID
    assert policy["training_authorization"]["model_training_authorized"] is False
    assert validate_prediction_attck_label_policy(policy) == []


def test_known_answer_fixture_is_versioned_and_complete() -> None:
    fixture = json.loads(
        (ROOT / "configs" / "prediction_attck_label_known_answers.v1.json").read_text(
            encoding="utf-8"
        )
    )
    assert fixture["schema_version"] == "prediction_attck_label_known_answers.v1"
    assert fixture["authority"] == AUTHORITY
    assert len(fixture["cases"]) == 26
    assert len({case["case_id"] for case in fixture["cases"]}) == 26


def test_structural_rule_is_prediction_eligible(policy: dict) -> None:
    result = evaluate_prediction_candidate(
        _candidate(
            policy,
            name="structural",
            rule_id="cmd-rule-v2-passwd-account-discovery-t1087-001",
            evidence_type="command_operation",
            technique="T1087.001",
        ),
        policy=policy,
        sanitizer_policy_id="privacy.v1",
        pseudonymization_policy_id="hmac.v1",
        parser_identity="parser.v2",
        splitter_identity="splitter.v1",
        labeler_identity="labeler.v1",
    )
    assert result["status"] == "eligible"
    assert result["label"]["authority"] == AUTHORITY
    assert result["label"]["technique"] == "T1087.001"


def test_reviewed_regex_allowlist_is_prediction_eligible(policy: dict) -> None:
    label = _label(policy, name="regex")
    assert label["rule_match_type"] == "command_regex"
    assert label["authority"] != "trusted_observation"


def test_rule_mapping_mismatch_is_a_causal_barrier(policy: dict) -> None:
    result = evaluate_prediction_candidate(
        _candidate(policy, tactic="execution", technique="T1059"),
        policy=policy,
        sanitizer_policy_id="privacy.v1",
        pseudonymization_policy_id="hmac.v1",
        parser_identity="parser.v2",
        splitter_identity="splitter.v1",
        labeler_identity="labeler.v1",
    )
    assert result["status"] == "barrier"
    assert result["reason_code"] == "ambiguous_tactic_mapping"


def test_unreviewed_or_unallowlisted_regex_is_excluded(policy: dict) -> None:
    result = evaluate_prediction_candidate(
        _candidate(policy, rule_id="cmd-rule-016-t1053-scheduled-task-job", rule_reviewed=False),
        policy=policy,
        sanitizer_policy_id="privacy.v1",
        pseudonymization_policy_id="hmac.v1",
        parser_identity="parser.v2",
        splitter_identity="splitter.v1",
        labeler_identity="labeler.v1",
    )
    assert result["status"] == "excluded"
    assert result["reason_code"] in {"rule_not_allowlisted", "unreviewed_rule"}


def test_rule_model_agreement_uses_rule_authority_only(policy: dict) -> None:
    label = _label(policy, source="both", bert_ttp="T1082", model_tactic="discovery")
    assert label["rule_source_kind"] == "reviewed_rule"
    assert label["audit_metadata"]["model_side_present"] is True


def test_model_only_is_excluded(policy: dict) -> None:
    result = evaluate_prediction_candidate(
        _candidate(policy, source="securebert", rule_id="", evidence_type="securebert"),
        policy=policy,
        sanitizer_policy_id="privacy.v1",
        pseudonymization_policy_id="hmac.v1",
        parser_identity="parser.v2",
        splitter_identity="splitter.v1",
        labeler_identity="labeler.v1",
    )
    assert result["status"] == "excluded"
    assert result["reason_code"] == "model_only_or_unsupported_source"


def test_rule_side_of_disagreement_can_be_eligible_without_model_authority(policy: dict) -> None:
    label = _label(policy, source="rule_securebert_disagreement", bert_ttp="T1059", model_tactic="execution")
    assert label["rule_source_kind"] == "rule_side_of_disagreement"
    assert label["audit_metadata"]["model_label_excluded"] is True


@pytest.mark.parametrize(
    "overrides,reason",
    [
        ({"ambiguous_tactic": True}, "ambiguous_tactic_mapping"),
        ({"parser_status": "abstained"}, "parser_abstention"),
        ({"malformed": True}, "malformed_evidence"),
        ({"operator_before": "&&"}, "conditional_execution_unproven"),
        ({"unresolved": True}, "unresolved_value"),
    ],
)
def test_unknown_evidence_creates_barrier(policy: dict, overrides: dict, reason: str) -> None:
    result = evaluate_prediction_candidate(
        _candidate(policy, **overrides),
        policy=policy,
        sanitizer_policy_id="privacy.v1",
        pseudonymization_policy_id="hmac.v1",
        parser_identity="parser.v2",
        splitter_identity="splitter.v1",
        labeler_identity="labeler.v1",
    )
    assert result["status"] == "barrier"
    assert result["reason_code"] == reason


def test_inert_lexical_match_does_not_become_a_tactic(policy: dict) -> None:
    result = evaluate_prediction_candidate(
        _candidate(
            policy,
            name="echo-whoami",
            prediction_context={"reviewed": True, "class": "reviewed_literal_command_pattern", "inert_text_match": True},
        ),
        policy=policy,
        sanitizer_policy_id="privacy.v1",
        pseudonymization_policy_id="hmac.v1",
        parser_identity="parser.v2",
        splitter_identity="splitter.v1",
        labeler_identity="labeler.v1",
    )
    assert result["status"] == "excluded"
    assert result["reason_code"] == "inert_lexical_match"


def test_group_preserves_multilabel_pairing_and_deduplicates_compatible_duplicates(policy: dict) -> None:
    first = _label(policy, name="multilabel", tactic="execution", technique="T1059", rule_id="cmd-rule-033-t1059-command-and-scripting-interpreter")
    second = _label(policy, name="multilabel", tactic="persistence", technique="T1053", rule_id="cmd-rule-014-t1053-scheduled-task-job")
    group = build_prediction_label_group([first, second, copy.deepcopy(first)], relative_time_ms=1000)
    assert group["schema_version"] == GROUP_SCHEMA_VERSION
    assert group["tactics"] == ["execution", "persistence"]
    assert group["evidence_refs"] == [first["event_id"]]
    assert validate_prediction_label_group(group) == []


def test_conflicting_duplicate_labels_fail_closed(policy: dict) -> None:
    first = _label(policy, name="conflict", tactic="execution", technique="T1059", rule_id="cmd-rule-097-t1059-command-and-scripting-interpreter-explicit-execution")
    second = _label(policy, name="conflict", tactic="execution", technique="T1059", rule_id="cmd-rule-033-t1059-command-and-scripting-interpreter")
    with pytest.raises(PredictionAttckLabelError, match="conflicting duplicate"):
        build_prediction_label_group([first, second])


def test_repeated_same_tactic_groups_remain_separate(policy: dict) -> None:
    groups = [_group(policy, "one", 1), _group(policy, "two", 2, technique="T1033")]
    assert groups[0]["group_id"] != groups[1]["group_id"]


def test_next_group_target_and_changed_from_current(policy: dict) -> None:
    groups = [_group(policy, "one", 1), _group(policy, "two", 2, tactic="execution", technique="T1059")]
    examples = build_next_prediction_label_examples(_session(policy, groups))
    assert len(examples) == 2
    assert examples[0]["target"]["outcome_type"] == "continuation"
    assert examples[0]["target"]["tactics"] == ["execution"]
    assert examples[0]["changed_from_current"] is True
    assert examples[1]["target"]["terminal_outcome"] == TERMINAL_OUTCOME


def test_same_tactic_target_is_not_collapsed_and_not_changed(policy: dict) -> None:
    groups = [_group(policy, "one", 1), _group(policy, "two", 2, technique="T1033")]
    examples = build_next_prediction_label_examples(_session(policy, groups))
    assert examples[0]["target"]["outcome_type"] == "continuation"
    assert examples[0]["changed_from_current"] is False


def test_active_final_group_has_no_terminal_target(policy: dict) -> None:
    groups = [_group(policy, "one", 1)]
    assert build_next_prediction_label_examples(_session(policy, groups, status="active")) == []


def test_barrier_prevents_transition_but_later_segment_remains_usable(policy: dict) -> None:
    groups = [_group(policy, "before", 1), _group(policy, "after", 3, tactic="execution", technique="T1059")]
    barrier = {
        "schema_version": BARRIER_SCHEMA_VERSION,
        "authority": AUTHORITY,
        "barrier_id": _id("barrier", "one"),
        "event_id": _id("event", "barrier"),
        "source_member_id": groups[0]["source_member_id"],
        "source_member_sha256": MEMBER_HASH,
        "event_order": 2,
        "reason_code": "parser_abstention",
        "prediction_policy_id": "prediction-only-reviewed-rule-labels-20260816.v1",
        "prediction_policy_sha256": "b" * 64,
        "sanitizer_policy_id": "privacy.v1",
        "pseudonymization_policy_id": "hmac.v1",
        "status": "causal_barrier",
    }
    # Use the policy hash in the barrier so its receipt is internally valid.
    barrier["prediction_policy_sha256"] = load_prediction_attck_label_policy(POLICY_PATH)["policy_sha256"]
    examples = build_next_prediction_label_examples(_session(policy, groups, barriers=[barrier]))
    assert len(examples) == 1
    assert examples[0]["prediction_group_id"] == groups[1]["group_id"]
    assert examples[0]["target"]["outcome_type"] == "session_end"


def test_history_is_bounded_to_eight_and_has_correct_truncation(policy: dict) -> None:
    groups = [_group(policy, f"g-{index}", index) for index in range(1, 11)]
    examples = build_next_prediction_label_examples(_session(policy, groups))
    history = examples[-1]["model_input"]
    assert history["schema_version"] == HISTORY_SCHEMA_VERSION
    assert history["maximum_history_groups"] == MAXIMUM_HISTORY_GROUPS
    assert history["original_group_count"] == 10
    assert history["selected_group_count"] == 8
    assert history["omitted_prefix_group_count"] == 2
    assert history["truncated"] is True


def test_target_mutation_does_not_change_causal_input(policy: dict) -> None:
    groups = [_group(policy, "one", 1), _group(policy, "two", 2, tactic="execution", technique="T1059")]
    before = build_next_prediction_label_examples(_session(policy, groups))[0]
    changed = [_group(policy, "one", 1), _group(policy, "other", 2, tactic="persistence", technique="T1098")]
    after = build_next_prediction_label_examples(_session(policy, changed))[0]
    assert before["model_input"] == after["model_input"]
    assert before["target"] != after["target"]
    assert not (set(before["model_input"]["input_evidence_refs"]) & set(before["target"]["target_evidence_refs"]))


def test_duplicate_replay_is_deterministic_and_privacy_safe(policy: dict) -> None:
    label = _label(policy, name="replay")
    replay = copy.deepcopy(label)
    assert replay == label
    assert validate_prediction_label(replay) == []
    serialized = str(label)
    assert "whoami" not in serialized
    assert "src_ip" not in serialized
    # ``command_regex`` is a safe schema value; assert the forbidden raw
    # evidence keys structurally rather than rejecting that legitimate token.
    assert "raw_command" not in serialized
    assert "raw_commands" not in serialized
    assert "commands" not in serialized


def test_canonical_trust_decision_is_not_modified_by_prediction_evaluation(policy: dict) -> None:
    canonical = {
        "classification_event_schema": "classification_event.v3",
        "source": "securebert",
        "ttp": "T1059",
        "tactic": "execution",
        "high_confidence": True,
    }
    before = classification_evidence_tier(canonical)
    result = evaluate_prediction_candidate(
        _candidate(policy, source="securebert", evidence_type="securebert", rule_id=""),
        policy=policy,
        sanitizer_policy_id="privacy.v1",
        pseudonymization_policy_id="hmac.v1",
        parser_identity="parser.v2",
        splitter_identity="splitter.v1",
        labeler_identity="labeler.v1",
    )
    after = classification_evidence_tier(canonical)
    assert before == after == "audit_only_candidate"
    assert result["status"] == "excluded"
    assert result["authority"] == AUTHORITY


def test_environment_contract_is_content_addressed() -> None:
    kwargs = {
        "policy_id": "prediction-only-reviewed-rule-labels-20260816.v1",
        "policy_sha256": "a" * 64,
        "source_corpus_membership_id": "internal-frozen-membership.v1",
        "source_corpus_membership_sha256": "b" * 64,
        "classification_rule_policy_id": "honeypot-command-classification-rules",
        "classification_rule_policy_sha256": RULE_HASH,
        "attack_mapping_id": "mitre-cache.v1",
        "attack_mapping_sha256": "c" * 64,
        "parser_id": "command_operations.v2",
        "parser_sha256": "d" * 64,
        "splitter_id": "classification_splitter.v1",
        "splitter_sha256": "e" * 64,
        "sanitizer_id": "cowrie_output_privacy.v1",
        "sanitizer_sha256": "f" * 64,
        "pseudonymization_id": "hmac.v1",
        "pseudonymization_sha256": "1" * 64,
        "group_builder_id": "prediction_attck_label_group.v1",
        "group_builder_sha256": "2" * 64,
        "history_builder_id": "prediction_attck_label_history_manifest.v1",
        "history_builder_sha256": "3" * 64,
        "target_builder_id": "next_prediction_attck_label_group_or_session_end.v1",
        "target_builder_sha256": "4" * 64,
        "barrier_policy_id": "prediction_attck_causal_barrier.v1",
        "barrier_policy_sha256": "5" * 64,
        "runtime_id": "CPython-3.12.13",
        "runtime_sha256": "6" * 64,
        "repository_commit": "be01598ba824c8c71e4ed258d03aa9ea362cae1f",
        "repository_tree": "fe357260d79f128bbf5f6495ecf96ef384c9d2ee",
        "dependency_identity_sha256": "7" * 64,
    }
    environment = build_prediction_attck_environment(**kwargs)
    assert validate_prediction_attck_environment(environment) == []
    tampered = dict(environment)
    tampered["target_contract_id"] = "next_distinct_trusted_behavior_phase_or_session_end.v2"
    assert validate_prediction_attck_environment(tampered)
