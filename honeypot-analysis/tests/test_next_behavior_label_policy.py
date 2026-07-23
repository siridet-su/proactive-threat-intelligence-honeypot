from __future__ import annotations

import hashlib

import pytest

from production.prediction.next_behavior_label_policy import (
    NextBehaviorLabelPolicyError,
    normalize_classifier_outputs,
)


POLICY_SHA = hashlib.sha256(b"policy").hexdigest()
TRUST_SHA = hashlib.sha256(b"trust").hexdigest()
CHECKPOINT_SHA = hashlib.sha256(b"checkpoint").hexdigest()


def _normalize(outputs: list[dict]) -> dict:
    return normalize_classifier_outputs(
        outputs,
        private_evidence_prefix="member:line:session",
        policy_sha256=POLICY_SHA,
        trust_policy_sha256=TRUST_SHA,
        checkpoint_sha256=CHECKPOINT_SHA,
        tactic_lookup=lambda technique: {
            "T1059": "execution",
            "T1082": "discovery",
            "T1547": "persistence",
        }.get(technique),
    )


def test_reviewed_rule_is_trusted_without_fake_probability() -> None:
    result = _normalize(
        [
            {
                "ttp": "T1082",
                "tactic": "discovery",
                "source": "rule",
                "high_confidence": True,
                "agreement_status": "rule_only",
                "confidence": 1.0,
            }
        ]
    )
    label = result["labels"][0]
    assert label["source"] == "reviewed_rule"
    assert label["trust_tier"] == "trusted_observation"
    assert label["confidence"] is None
    assert label["confidence_bucket"] == "not_applicable"
    assert label["checkpoint_sha256"] == ""


def test_model_only_uses_frozen_ninety_percent_threshold() -> None:
    outputs = [
        {
            "ttp": "T1059",
            "tactic": "execution",
            "source": "securebert",
            "high_confidence": True,
            "agreement_status": "model_only",
            "confidence": 0.89,
            "command": "synthetic command",
        },
        {
            "ttp": "T1547",
            "tactic": "persistence",
            "source": "securebert",
            "high_confidence": True,
            "agreement_status": "model_only",
            "confidence": 0.91,
            "command": "synthetic command",
        },
    ]
    result = _normalize(outputs)

    assert result["labels"][0]["trust_tier"] == "audit_only_candidate"
    assert result["labels"][0]["exclusion_reason"] == "below_trusted_threshold"
    assert result["labels"][1]["trust_tier"] == "trusted_observation"
    assert all(
        label["checkpoint_sha256"] == CHECKPOINT_SHA
        for label in result["labels"]
    )


def test_exact_agreement_is_trusted_but_retains_model_score_semantics() -> None:
    result = _normalize(
        [
            {
                "ttp": "T1082",
                "tactic": "discovery",
                "source": "both",
                "high_confidence": True,
                "agreement_status": "exact_technique_agreement",
                "bert_ttp": "T1082",
                "bert_confidence": 0.70,
            }
        ]
    )
    label = result["labels"][0]
    assert label["source"] == "rule_model_agreement"
    assert label["trust_tier"] == "trusted_observation"
    assert label["confidence"] == 0.70
    assert label["confidence_bucket"] == "medium"
    assert label["agreement_status"] == "agreed"


def test_disagreement_retains_both_candidates_as_audit_only() -> None:
    result = _normalize(
        [
            {
                "ttp": "T1082",
                "tactic": "discovery",
                "source": "rule_securebert_disagreement",
                "high_confidence": False,
                "agreement_status": "technique_and_tactic_disagreement",
                "bert_ttp": "T1547",
                "bert_tactic": "persistence",
                "bert_confidence": 0.97,
            }
        ]
    )
    assert [(item["source"], item["technique"]) for item in result["labels"]] == [
        ("reviewed_rule", "T1082"),
        ("securebert", "T1547"),
    ]
    assert {
        item["exclusion_reason"] for item in result["labels"]
    } == {"unresolved_conflict"}
    assert all(
        item["trust_tier"] == "audit_only_candidate"
        for item in result["labels"]
    )


def test_emergency_rule_and_opaque_probe_remain_audit_only() -> None:
    result = _normalize(
        [
            {
                "ttp": "T1082",
                "tactic": "discovery",
                "source": "emergency_python_fallback",
                "high_confidence": False,
            },
            {
                "ttp": "T1059",
                "tactic": "execution",
                "source": "securebert",
                "high_confidence": True,
                "confidence": 0.99,
                "command": "busybox ABCDE",
            },
        ]
    )
    assert [item["exclusion_reason"] for item in result["labels"]] == [
        "emergency_rule",
        "opaque_model_probe",
    ]
    assert not any(
        item["trust_tier"] == "trusted_observation"
        for item in result["labels"]
    )


def test_unknown_and_shell_noise_are_counted_without_fabricated_labels() -> None:
    result = _normalize(
        [
            {"source": "shell_noise", "ttp": None, "tactic": "unknown"},
            {
                "source": "securebert_low_confidence",
                "ttp": "T0000_UNKNOWN",
                "tactic": "unknown",
                "confidence": 0.1,
            },
        ]
    )
    assert result["labels"] == []
    assert result["unrepresented_by_reason"] == {
        "malformed_label": 1,
        "shell_noise": 1,
    }


def test_missing_tactic_is_recovered_only_from_registered_technique() -> None:
    result = _normalize(
        [
            {
                "source": "securebert_low_confidence",
                "ttp": "T1059",
                "tactic": "unknown",
                "confidence": 0.2,
            }
        ]
    )
    assert result["labels"][0]["tactic"] == "execution"
    assert result["labels"][0]["exclusion_reason"] == "below_trusted_threshold"


@pytest.mark.parametrize("threshold", [float("nan"), 0.4, 1.1, True])
def test_invalid_thresholds_fail_closed(threshold) -> None:
    with pytest.raises(NextBehaviorLabelPolicyError):
        normalize_classifier_outputs(
            [],
            private_evidence_prefix="evidence",
            policy_sha256=POLICY_SHA,
            trust_policy_sha256=TRUST_SHA,
            checkpoint_sha256=CHECKPOINT_SHA,
            tactic_lookup=lambda _technique: None,
            trusted_model_only_threshold=threshold,
        )
