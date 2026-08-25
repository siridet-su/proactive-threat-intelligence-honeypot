from __future__ import annotations

import json
from pathlib import Path

import pytest

from production.prediction.prediction_attck_label_poc_v3 import (
    DATASET_PATH,
    POLICY_PATH,
    PredictionAttckLabelPocV3Error,
    load_prediction_attck_label_poc_policy,
    require_materialized_poc_examples,
    validate_prediction_attck_label_poc_freeze_receipt,
    validate_prediction_attck_label_poc_policy,
)


ROOT = Path(__file__).resolve().parents[1]
POLICY_FILE = ROOT / POLICY_PATH
DATASET_FILE = ROOT / DATASET_PATH
RECEIPT_FILE = ROOT / "configs" / "prediction_attck_label_poc_freeze_receipt.v1.json"


def _policy() -> dict:
    return json.loads(POLICY_FILE.read_text(encoding="utf-8"))


def test_frozen_poc_policy_validates_against_real_support_receipts() -> None:
    loaded = load_prediction_attck_label_poc_policy(POLICY_FILE)
    assert loaded["schema_version"] == "prediction_attck_label_policy.poc.v3"
    assert loaded["predecessor_policy"]["policy_id"] == (
        "prediction-only-reviewed-rule-labels-legacy-parity-20260816.v2"
    )
    assert loaded["poc_training_authorization"] == {
        "empirical_support_qualified": False,
        "production_model_qualified": False,
        "experimental_poc_training_authorized": True,
        "scope": "offline_non_authoritative_experiment_only",
        "does_not_override_failed_support_gates": True,
        "does_not_authorize_sealed_test_access": True,
        "does_not_authorize_production_deployment": True,
    }


def test_predecessor_v2_and_target_identity_are_unchanged() -> None:
    document = _policy()
    assert document["predecessor_policy_sha256"] == (
        "03160fd9fad7cbf9e3db652112c47e1b88242ecbe91c8884a6ddc7324d735a61"
    )
    assert document["target_contract_id"] == "next_prediction_attck_label_group_or_session_end.v1"
    assert document["target_policy_identity"]["no_transition_across_barrier"] is True
    assert document["runtime_boundary"]["authoritative"] is False


def test_failed_support_gates_are_bound_and_cannot_be_relabelled_as_passed() -> None:
    document = _policy()
    document["support_evidence"]["pooled"]["support_gate_passed"] = True
    errors = validate_prediction_attck_label_poc_policy(
        document, repository_root=ROOT, verify_external_receipts=False
    )
    assert any("support gates" in error for error in errors)


def test_unknown_policy_fields_fail_closed() -> None:
    document = _policy()
    document["runtime_override"] = {"production_enabled": True}
    errors = validate_prediction_attck_label_poc_policy(
        document, repository_root=ROOT, verify_external_receipts=False
    )
    assert any("runtime_override" in error for error in errors)


def test_policy_hash_is_content_bound() -> None:
    document = _policy()
    document["claims"]["supported"].append("unreviewed claim")
    errors = validate_prediction_attck_label_poc_policy(
        document, repository_root=ROOT, verify_external_receipts=False
    )
    assert "policy_sha256 does not match canonical policy body" in errors


def test_dataset_membership_is_frozen_but_examples_are_not_present() -> None:
    dataset = json.loads(DATASET_FILE.read_text(encoding="utf-8"))
    assert dataset["status"] == "membership_frozen_examples_not_materialized"
    assert dataset["example_corpus"]["examples_present"] is False
    assert dataset["example_corpus"]["raw_replay_authorized_by_this_manifest"] is False
    assert dataset["role_protocol"]["domain_session_merge"] is False
    assert dataset["sealed_boundary"]["sealed_internal_accessed"] is False
    assert dataset["sealed_boundary"]["sealed_cyberlab_accessed"] is False


def test_training_guard_refuses_unmaterialized_examples() -> None:
    loaded = load_prediction_attck_label_poc_policy(POLICY_FILE)
    with pytest.raises(PredictionAttckLabelPocV3Error, match="not materialized"):
        require_materialized_poc_examples(loaded)


def test_external_receipt_tampering_fails_closed() -> None:
    document = _policy()
    source = Path(document["support_evidence"]["internal"]["path"])
    if not source.is_file():
        pytest.skip("preserved support evidence is not mounted")
    document["support_evidence"]["internal"]["file_sha256"] = "0" * 64
    errors = validate_prediction_attck_label_poc_policy(
        document, repository_root=ROOT, verify_external_receipts=True
    )
    assert any("support receipt internal bytes do not match" in error for error in errors)


def test_load_rejects_missing_predecessor(tmp_path: Path) -> None:
    document = _policy()
    document["predecessor_policy_path"] = "configs/no-such-v2.json"
    target = tmp_path / "policy.json"
    target.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(PredictionAttckLabelPocV3Error):
        load_prediction_attck_label_poc_policy(target, verify_external_receipts=False)


def test_freeze_receipt_is_content_and_repository_bound() -> None:
    receipt = json.loads(RECEIPT_FILE.read_text(encoding="utf-8"))
    assert validate_prediction_attck_label_poc_freeze_receipt(
        receipt, repository_root=ROOT
    ) == []
