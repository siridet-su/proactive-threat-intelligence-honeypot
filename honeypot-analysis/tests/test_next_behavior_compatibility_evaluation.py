from __future__ import annotations

import copy
import hashlib

import pytest

from production.prediction.next_behavior_preprocessing import (
    build_next_behavior_examples,
)
from production.reproduction.next_behavior.compatibility_evaluation import (
    NextBehaviorCompatibilityError,
    force_zero_audit_example,
    reprocess_retained_safe_session,
)


RULE_SHA = hashlib.sha256(b"rule").hexdigest()
OLD_TRUST_SHA = hashlib.sha256(b"old-trust").hexdigest()
CURRENT_TRUST_SHA = hashlib.sha256(b"current-trust").hexdigest()
CHECKPOINT_SHA = hashlib.sha256(b"classifier").hexdigest()


def _identifier(kind: str, token: str) -> str:
    return f"nb{kind}_{hashlib.sha256(token.encode()).hexdigest()}"


def _label(
    *,
    source: str,
    tactic: str,
    technique: str,
    evidence: str,
    trust_tier: str = "trusted_observation",
    agreement: str = "rule_only",
    confidence: float | None = None,
    confidence_bucket: str = "not_applicable",
    exclusion_reason: str = "",
) -> dict:
    label = {
        "tactic": tactic,
        "technique": technique,
        "source": source,
        "trust_tier": trust_tier,
        "policy_sha256": RULE_SHA,
        "trust_policy_sha256": OLD_TRUST_SHA,
        "checkpoint_sha256": (
            CHECKPOINT_SHA
            if source in {"securebert", "rule_model_agreement"}
            else ""
        ),
        "confidence": confidence,
        "confidence_bucket": confidence_bucket,
        "agreement_status": agreement,
        "evidence_ref": _identifier("evidence", evidence),
    }
    if exclusion_reason:
        label["exclusion_reason"] = exclusion_reason
    return label


def _group(
    order: int,
    relative_ms: int,
    *,
    trusted: list[dict],
    audit: list[dict] | None = None,
) -> dict:
    return {
        "group_id": _identifier("group", str(order)),
        "event_order": order,
        "relative_time_ms": relative_ms,
        "tactics": sorted({item["tactic"] for item in trusted}),
        "techniques": sorted({item["technique"] for item in trusted}),
        "evidence_refs": sorted({item["evidence_ref"] for item in trusted}),
        "label_provenance": copy.deepcopy(trusted),
        "audit_only_labels": copy.deepcopy(audit or []),
        "session_context": {
            "login_outcome": "success",
            "command_count_bucket": "2-5",
            "session_age_bucket": "under_10s",
            "confirmed_transfer_observed": False,
        },
    }


def _session() -> dict:
    rule = _label(
        source="reviewed_rule",
        tactic="discovery",
        technique="T1082",
        evidence="rule",
    )
    model = _label(
        source="securebert",
        tactic="persistence",
        technique="T1547",
        evidence="model",
        agreement="model_only",
        confidence=0.95,
        confidence_bucket="high",
    )
    old_audit = _label(
        source="securebert",
        tactic="execution",
        technique="T1059",
        evidence="audit",
        trust_tier="audit_only_candidate",
        agreement="model_only",
        confidence=0.2,
        confidence_bucket="low",
        exclusion_reason="below_trusted_threshold",
    )
    return {
        "schema_version": "next_behavior_session.v1",
        "session_id": _identifier("session", "session"),
        "source_member_id": _identifier("member", "member"),
        "source_member_sha256": hashlib.sha256(b"member").hexdigest(),
        "protocol": "ssh",
        "status": "closed",
        "pseudonymization_key_id": "fixture-only",
        "audit_summary": {
            "total": 1,
            "by_reason": {"below_trusted_threshold": 1},
        },
        "observation_groups": [
            _group(1, 0, trusted=[rule, model], audit=[old_audit]),
            _group(2, 1000, trusted=[model]),
        ],
    }


def _reprocess(value: dict) -> tuple[dict | None, dict]:
    return reprocess_retained_safe_session(
        value,
        rule_policy_sha256=RULE_SHA,
        current_trust_policy_sha256=CURRENT_TRUST_SHA,
        classifier_checkpoint_sha256=CHECKPOINT_SHA,
    )


def test_current_policy_demotes_only_model_only_securebert_provenance() -> None:
    retained = _session()
    original = copy.deepcopy(retained)
    current, delta = _reprocess(retained)

    assert retained == original
    assert current is not None
    assert len(current["observation_groups"]) == 1
    group = current["observation_groups"][0]
    assert group["tactics"] == ["discovery"]
    assert group["techniques"] == ["T1082"]
    assert len(group["audit_only_labels"]) == 2
    assert current["audit_summary"] == {
        "total": 3,
        "by_reason": {
            "below_trusted_threshold": 1,
            "model_only_not_observed_evidence": 2,
        },
    }
    assert delta["demoted_model_only_label_count"] == 2
    assert delta["groups_removed_by_trust_policy"] == 1
    assert all(
        label["trust_policy_sha256"] == CURRENT_TRUST_SHA
        for label in [
            *group["label_provenance"],
            *group["audit_only_labels"],
        ]
    )


def test_session_with_only_unauthorized_model_evidence_is_excluded() -> None:
    retained = _session()
    retained["observation_groups"] = [retained["observation_groups"][1]]
    retained["audit_summary"] = {"total": 0, "by_reason": {}}

    current, delta = _reprocess(retained)

    assert current is None
    assert delta["current_trusted_label_count"] == 0
    assert delta["demoted_model_only_label_count"] == 1


def test_current_policy_reprocessing_is_deterministic_and_target_preserving() -> None:
    first, first_delta = _reprocess(_session())
    second, second_delta = _reprocess(_session())

    assert first == second
    assert first_delta == second_delta
    assert first is not None
    examples = build_next_behavior_examples(first)
    assert len(examples) == 1
    assert examples[0]["target"]["outcome_type"] == "session_end"


def test_unexpected_policy_or_model_semantics_fail_closed() -> None:
    wrong_rule = _session()
    wrong_rule["observation_groups"][0]["label_provenance"][0][
        "policy_sha256"
    ] = "f" * 64
    with pytest.raises(
        NextBehaviorCompatibilityError,
        match="reviewed rule policy",
    ):
        _reprocess(wrong_rule)

    unsupported = _session()
    unsupported["observation_groups"][0]["label_provenance"][1][
        "agreement_status"
    ] = "agreed"
    with pytest.raises(
        NextBehaviorCompatibilityError,
        match="unsupported agreement semantics",
    ):
        _reprocess(unsupported)


def test_audit_ablation_changes_only_counts_and_bound_input_identity() -> None:
    current, _ = _reprocess(_session())
    assert current is not None
    original = build_next_behavior_examples(current)[0]
    ablated = force_zero_audit_example(original)

    assert original["model_input"]["phase_sequence"][0][
        "audit_only_label_count"
    ] == 2
    assert ablated["model_input"]["phase_sequence"][0][
        "audit_only_label_count"
    ] == 0
    assert original["model_input"]["input_hash"] != (
        ablated["model_input"]["input_hash"]
    )
    original_without_input = copy.deepcopy(original)
    ablated_without_input = copy.deepcopy(ablated)
    original_without_input["model_input"].pop("input_hash")
    ablated_without_input["model_input"].pop("input_hash")
    original_without_input["model_input"]["phase_sequence"][0][
        "audit_only_label_count"
    ] = 0
    assert original_without_input == ablated_without_input

