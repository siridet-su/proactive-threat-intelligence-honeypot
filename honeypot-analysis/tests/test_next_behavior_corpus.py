from __future__ import annotations

import copy
import hashlib
import json

import pytest

from production.prediction.next_behavior_corpus import (
    NextBehaviorCorpusError,
    build_corpus_receipt,
    build_privacy_safe_session,
    build_source_member_receipt,
)
from production.prediction.next_behavior_preprocessing import (
    build_next_behavior_examples,
)


TEST_KEY = b"fixture-only-pseudonymization-key-0001"
KEY_ID = "fixture-key-v1"
SOURCE_SHA = hashlib.sha256(b"private source member bytes").hexdigest()
POLICY_SHA = hashlib.sha256(b"classification policy").hexdigest()
TRUST_SHA = hashlib.sha256(b"trust policy").hexdigest()
CHECKPOINT_SHA = hashlib.sha256(b"securebert checkpoint").hexdigest()


def _member() -> dict:
    return build_source_member_receipt(
        private_member_identifier="raw-member-name-that-must-not-escape.json.gz",
        source_sha256=SOURCE_SHA,
        byte_size=1234,
        chronological_order=1,
        collection_start="2026-01-01T00:00:00Z",
        collection_end="2026-01-01T23:59:59Z",
        pseudonymization_key=TEST_KEY,
        pseudonymization_key_id=KEY_ID,
    )


def _label(
    tactic: str,
    *,
    source: str = "rule",
    trust_tier: str = "trusted_observation",
    confidence: float = 1.0,
    confidence_bucket: str = "high",
    agreement_status: str = "rule_only",
    exclusion_reason: str = "",
) -> dict:
    value = {
        "tactic": tactic,
        "technique": "T1082",
        "source": source,
        "trust_tier": trust_tier,
        "policy_sha256": POLICY_SHA,
        "trust_policy_sha256": TRUST_SHA,
        "checkpoint_sha256": (
            CHECKPOINT_SHA if source in {"model", "both"} else ""
        ),
        "confidence": confidence,
        "confidence_bucket": confidence_bucket,
        "agreement_status": agreement_status,
        "evidence_ref": f"raw-evidence-for-{tactic}",
    }
    if exclusion_reason:
        value["exclusion_reason"] = exclusion_reason
    return value


def _private_session() -> dict:
    return {
        "session_id": "private-session-id",
        "protocol": "ssh",
        "status": "closed",
        "configuration_id": "private-sensor-config",
        "raw_commands": ["echo ULTRA-SECRET-COMMAND"],
        "source_ip": "192.0.2.55",
        "observation_groups": [
            {
                "group_id": "private-group-one",
                "event_order": 1,
                "observed_at": "2026-01-01T00:00:01Z",
                "raw_command": "echo ULTRA-SECRET-COMMAND",
                "labels": [
                    _label("discovery"),
                    _label(
                        "persistence",
                        source="model",
                        trust_tier="audit_only_candidate",
                        confidence=0.2,
                        confidence_bucket="low",
                        agreement_status="model_only",
                        exclusion_reason="below_trusted_threshold",
                    ),
                ],
                "session_context": {
                    "login_outcome": "success",
                    "command_count_bucket": "1",
                    "session_age_bucket": "under_10s",
                    "confirmed_transfer_observed": False,
                    "geo": "must be discarded",
                },
            },
            {
                "group_id": "private-group-two",
                "event_order": 2,
                "observed_at": "2026-01-01T00:00:03Z",
                "labels": [
                    _label("execution"),
                ],
                "session_context": {
                    "login_outcome": "success",
                    "command_count_bucket": "2-5",
                    "session_age_bucket": "under_10s",
                    "confirmed_transfer_observed": False,
                },
            },
        ],
    }


def _build(private_session: dict | None = None) -> dict:
    return build_privacy_safe_session(
        private_session or _private_session(),
        _member(),
        pseudonymization_key=TEST_KEY,
        pseudonymization_key_id=KEY_ID,
    )


def test_private_to_safe_build_is_deterministic_and_redacts_raw_values() -> None:
    first = _build()
    second = _build()

    assert first == second
    serialized = json.dumps(first, sort_keys=True)
    for forbidden in (
        "ULTRA-SECRET-COMMAND",
        "192.0.2.55",
        "private-session-id",
        "private-group-one",
        "raw-member-name-that-must-not-escape",
        "raw_command",
        "source_ip",
        "geo",
    ):
        assert forbidden not in serialized
    safe = first["safe_session"]
    assert safe["session_id"].startswith("nbsession_")
    assert safe["source_member_id"].startswith("nbmember_")
    assert safe["configuration_id"].startswith("nbconfiguration_")
    assert safe["observation_groups"][0]["relative_time_ms"] == 0
    assert safe["observation_groups"][1]["relative_time_ms"] == 2000


def test_label_order_is_irrelevant_and_legacy_sources_are_canonicalized() -> None:
    original = _private_session()
    permuted = copy.deepcopy(original)
    permuted["observation_groups"][0]["labels"].reverse()

    first = _build(original)["safe_session"]
    second = _build(permuted)["safe_session"]

    assert first == second
    provenance = first["observation_groups"][0]["label_provenance"]
    assert provenance[0]["source"] == "reviewed_rule"


def test_audit_only_labels_are_preserved_but_excluded_from_targets() -> None:
    result = _build()
    safe = result["safe_session"]
    examples = build_next_behavior_examples(safe)

    assert safe["audit_summary"] == {
        "total": 1,
        "by_reason": {"below_trusted_threshold": 1},
    }
    assert len(safe["observation_groups"][0]["audit_only_labels"]) == 1
    assert examples[0]["target"]["tactics"] == ["execution"]
    assert "persistence" not in examples[0]["target"]["tactics"]
    assert result["reconciliation"] == {
        "private_group_count": 2,
        "safe_trusted_group_count": 2,
        "audit_only_group_count": 0,
        "private_label_count": 3,
        "trusted_label_count": 2,
        "audit_only_label_count": 1,
    }


def test_audit_only_groups_are_counted_and_not_emitted_as_behavior() -> None:
    private = _private_session()
    private["observation_groups"].insert(
        1,
        {
            "group_id": "audit-only-group",
            "event_order": 2,
            "observed_at": "2026-01-01T00:00:02Z",
            "labels": [
                _label(
                    "persistence",
                    trust_tier="excluded",
                    confidence=0.0,
                    confidence_bucket="low",
                    agreement_status="unreviewed",
                    exclusion_reason="unreviewed_rule",
                )
            ],
            "session_context": {
                "login_outcome": "success",
                "command_count_bucket": "2-5",
                "session_age_bucket": "under_10s",
                "confirmed_transfer_observed": False,
            },
        },
    )
    private["observation_groups"][2]["event_order"] = 3

    result = _build(private)

    assert len(result["safe_session"]["observation_groups"]) == 2
    assert result["safe_session"]["audit_summary"]["total"] == 2
    assert result["reconciliation"]["audit_only_group_count"] == 1


def test_corpus_receipt_reconciles_counts_and_hashes_safe_payload() -> None:
    result = _build()

    receipt = build_corpus_receipt(
        [result],
        [_member()],
        code_commit="test-commit",
        preprocessing_sha256=POLICY_SHA,
        label_policy_sha256=POLICY_SHA,
        trust_policy_sha256=TRUST_SHA,
    )

    assert receipt["status"] == "safe_payload_reconciled"
    assert receipt["source_member_count"] == 1
    assert receipt["private_session_count"] == 1
    assert receipt["safe_session_count"] == 1
    assert receipt["counts"]["private_label_count"] == 3
    assert receipt["receipt_id"].startswith("nextbehaviorcorpus_")


def test_corpus_receipt_rejects_forged_counts_or_unknown_members() -> None:
    result = _build()
    forged = copy.deepcopy(result)
    forged["reconciliation"]["private_label_count"] = -1
    with pytest.raises(NextBehaviorCorpusError, match="must be non-negative"):
        build_corpus_receipt(
            [forged],
            [_member()],
            code_commit="test-commit",
            preprocessing_sha256=POLICY_SHA,
            label_policy_sha256=POLICY_SHA,
            trust_policy_sha256=TRUST_SHA,
        )

    unknown_member = copy.deepcopy(result)
    unknown_member["safe_session"]["source_member_id"] = (
        "nbmember_" + "f" * 64
    )
    with pytest.raises(NextBehaviorCorpusError, match="absent from receipts"):
        build_corpus_receipt(
            [unknown_member],
            [_member()],
            code_commit="test-commit",
            preprocessing_sha256=POLICY_SHA,
            label_policy_sha256=POLICY_SHA,
            trust_policy_sha256=TRUST_SHA,
        )


def test_invalid_key_receipt_and_mixed_time_encodings_fail_closed() -> None:
    with pytest.raises(NextBehaviorCorpusError, match="at least 32 bytes"):
        build_source_member_receipt(
            private_member_identifier="member",
            source_sha256=SOURCE_SHA,
            byte_size=1,
            chronological_order=1,
            collection_start="2026-01-01T00:00:00Z",
            collection_end="2026-01-01T00:00:01Z",
            pseudonymization_key=b"short",
            pseudonymization_key_id=KEY_ID,
        )

    private = _private_session()
    private["observation_groups"][0]["relative_time_ms"] = 0
    with pytest.raises(NextBehaviorCorpusError, match="either complete"):
        _build(private)


def test_unregistered_audit_reason_and_missing_trust_hash_fail_closed() -> None:
    private = _private_session()
    private["observation_groups"][0]["labels"][1][
        "exclusion_reason"
    ] = "secret-shaped-unregistered-reason"
    with pytest.raises(NextBehaviorCorpusError, match="registered"):
        _build(private)

    private = _private_session()
    private["observation_groups"][0]["labels"][0]["trust_policy_sha256"] = ""
    with pytest.raises(NextBehaviorCorpusError, match="trust_policy_sha256"):
        _build(private)


def test_unregistered_tactic_cannot_carry_secret_shaped_metadata() -> None:
    private = _private_session()
    private["observation_groups"][0]["labels"][0]["tactic"] = (
        "secret-shaped-unregistered-tactic"
    )

    with pytest.raises(NextBehaviorCorpusError, match="frozen vocabulary"):
        _build(private)
