import copy
import hashlib
from pathlib import Path

import pytest

from production.prediction.next_behavior_professor_approved import (
    ProfessorApprovedPocError,
    build_professor_approved_decision,
    build_professor_approved_pretest_manifest,
    rank_complete_selection_candidates,
    require_valid_professor_approved_decision,
    require_valid_professor_approved_pretest_manifest,
    verify_professor_approved_pretest_artifacts,
)
from production.prediction.next_behavior_calibration import fit_temperature_mapping
from production.prediction.next_behavior_contract import TARGET_CONTRACT_ID, TACTIC_VOCABULARY
from production.prediction.next_behavior_partitions import membership_sha256


HASH = "a" * 64
HASH_B = "b" * 64
HASH_C = "c" * 64


def _record(seed, macro, balanced, terminal, latency):
    return {
        "seed": seed,
        "status": "complete",
        "completion_marker_verified": True,
        "checkpoint": {"sha256": f"{seed:064x}"[-64:]},
        "candidate": {
            "eligible": False,
            "blockers": ["reportable_zero_recall:defense-evasion"],
            "selection_values": {
                "macro_f1": macro,
                "balanced_accuracy": balanced,
                "terminal_f1": terminal,
                "p95_single_case_cpu_latency_ms": latency,
            },
        },
    }


def _receipt():
    return {
        "status": "selection_blocked_pre_test",
        "test_opened": False,
        "seed_candidates": [
            _record(2, 0.6, 0.8, 0.5, 2.0),
            _record(1, 0.7, 0.7, 0.4, 3.0),
        ],
    }


def test_professor_approval_ranks_aggregate_candidate_without_changing_blocker():
    receipt = _receipt()
    ranked = rank_complete_selection_candidates(receipt)
    assert [item["seed"] for item in ranked] == [1, 2]
    decision = build_professor_approved_decision(
        receipt, selection_blocked_receipt_sha256=HASH, source_code_commit="b" * 40
    )
    assert decision["selection"]["selected_seed"] == 1
    assert decision["original_experiment"]["status"] == "BLOCKED_AT_SELECTION"
    assert decision["selection"]["ranked_seeds"][0]["original_eligible"] is False
    assert require_valid_professor_approved_decision(decision) == decision


def test_professor_approval_fails_closed_when_original_blocker_is_lost():
    receipt = _receipt()
    receipt["seed_candidates"][1]["candidate"]["blockers"] = []
    with pytest.raises(ProfessorApprovedPocError, match="defense-evasion"):
        build_professor_approved_decision(
            receipt, selection_blocked_receipt_sha256=HASH, source_code_commit="b" * 40
        )


def test_professor_approval_rejects_posthoc_tampering():
    decision = build_professor_approved_decision(
        _receipt(), selection_blocked_receipt_sha256=HASH, source_code_commit="b" * 40
    )
    changed = copy.deepcopy(decision)
    changed["selection"]["selected_seed"] = 2
    with pytest.raises(ProfessorApprovedPocError, match="selected seed"):
        require_valid_professor_approved_decision(changed)


def _calibration(checkpoint_sha256=HASH):
    ids = ["nextbehaviorexample_" + "1" * 32, "nextbehaviorexample_" + "2" * 32]
    logits = {tactic: 0.0 for tactic in TACTIC_VOCABULARY}
    rows = []
    for index, example_id in enumerate(ids):
        row_logits = dict(logits)
        row_logits["execution"] = 2.0 if index == 0 else -2.0
        rows.append({
            "example_id": example_id, "partition_role": "calibration",
            "target_contract_id": TARGET_CONTRACT_ID,
            "score_semantics": "raw_model_scores_not_probabilities",
            "checkpoint_sha256": checkpoint_sha256, "vocabulary_sha256": HASH_B,
            "preprocessing_sha256": HASH_C, "tactic_logits": row_logits,
            "target_tactics": ["execution"] if index == 0 else [],
            "terminal_logit": -1.0 if index == 0 else 2.0,
            "terminal_target": index == 1,
        })
    return fit_temperature_mapping(
        rows, calibration_example_ids=ids,
        fit_partition_membership_sha256=membership_sha256(ids),
        checkpoint_sha256=checkpoint_sha256, vocabulary_sha256=HASH_B,
        preprocessing_sha256=HASH_C,
    )


def _write_descriptor(tmp_path: Path, name: str, **extra):
    path = tmp_path / name
    path.write_text(name, encoding="utf-8")
    result = {"path": str(path), "sha256": hashlib.sha256(name.encode()).hexdigest()}
    result.update(extra)
    return result


def _manifest(tmp_path: Path):
    decision = build_professor_approved_decision(
        _receipt(), selection_blocked_receipt_sha256=HASH, source_code_commit="b" * 40
    )
    artifacts = {
        name: _write_descriptor(tmp_path, name)
        for name in (
                "original_selection_blocked_receipt", "selected_checkpoint", "model_spec",
                "hard_backoff_vomm", "partition_manifest", "train_receipt", "selection_receipt",
                "calibration_receipt", "final_receipt", "environment_receipt",
                "evaluator_source", "metrics_source", "ledger_contract",
        )
    }
    # Set an actual checkpoint byte binding before creating the approval record.
    Path(artifacts["selected_checkpoint"]["path"]).write_text("selected", encoding="utf-8")
    artifacts["selected_checkpoint"]["sha256"] = hashlib.sha256(b"selected").hexdigest()
    seeded = _receipt()
    seeded["seed_candidates"][1]["checkpoint"]["sha256"] = artifacts["selected_checkpoint"]["sha256"]
    decision = build_professor_approved_decision(seeded, selection_blocked_receipt_sha256=HASH, source_code_commit="b" * 40)
    artifacts["vocabulary"] = _write_descriptor(tmp_path, "vocabulary", semantic_sha256=HASH_B)
    artifacts["preprocessing_contract"] = _write_descriptor(tmp_path, "preprocessing", semantic_sha256=HASH_C)
    calibration = _calibration(artifacts["selected_checkpoint"]["sha256"])
    policy = {
        "schema_version": "next_behavior_professor_approved_decision_policy.v1", "status": "frozen_pre_test",
        "score_semantics": "global_temperature_sigmoid_probabilities", "tactic_threshold": 0.5,
        "terminal_threshold": 0.5, "terminal_precedence": True,
        "empty_nonterminal_rule": "highest_ranked_tactic",
        "abstention": {"score_based": False, "asset_or_schema_failure": True, "fallback_model": None},
        "objective": "calibration_binary_log_loss_only; thresholds_fixed_by_probability_semantics",
    }
    from production.utils.serialization import stable_json
    policy["sha256"] = hashlib.sha256(stable_json(policy).encode()).hexdigest()
    final = _write_descriptor(tmp_path, "final", role="test", membership_sha256="d" * 64)
    environment = {"python": "3.12", "torch": "2.13", "cpu": "test", "receipt_sha256": "e" * 64}
    return build_professor_approved_pretest_manifest(
        decision=decision, calibration=calibration, decision_policy=policy,
        code_commit="b" * 40, artifacts=artifacts, final_test=final, environment=environment,
    )


def test_pretest_manifest_is_fail_closed_and_does_not_read_final_by_default(tmp_path):
    manifest = _manifest(tmp_path)
    assert require_valid_professor_approved_pretest_manifest(manifest) == manifest
    verified = verify_professor_approved_pretest_artifacts(manifest)
    assert verified["status"] == "verified_pre_test"
    assert "final_test" not in verified["artifacts"]
    changed = copy.deepcopy(manifest)
    changed["authority_restrictions"]["prediction_may_authorize_alerts"] = True
    with pytest.raises(ProfessorApprovedPocError, match="manifest hash mismatch"):
        require_valid_professor_approved_pretest_manifest(changed)
