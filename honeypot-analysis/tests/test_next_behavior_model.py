from __future__ import annotations

import copy
import importlib.util
from pathlib import Path

import pytest

from production.prediction.next_behavior_contract import (
    TACTIC_VOCABULARY,
    TARGET_CONTRACT_ID,
    TERMINAL_OUTCOME,
)
from production.prediction.next_behavior_model import (
    ARCHITECTURE,
    OUTPUT_TACTICS,
    NextBehaviorCheckpointError,
    NextBehaviorModelError,
    build_model,
    build_model_spec,
    load_checkpoint,
    predict_next_behavior,
    require_valid_model_spec,
    require_valid_tensor_input,
    save_checkpoint,
    sha256_file,
)
from production.prediction.next_behavior_tensor import (
    TENSOR_SCHEMA_VERSION,
    VOCABULARY_SCHEMA_VERSION,
    require_valid_vocabulary,
    vocabulary_sha256,
)
from production.utils.serialization import stable_id


HASH_A = "a" * 64
HASH_B = "b" * 64
TORCH_AVAILABLE = importlib.util.find_spec("torch") is not None


def _vocabulary(*, preprocessing_sha256: str = HASH_A) -> dict:
    value = {
        "schema_version": VOCABULARY_SCHEMA_VERSION,
        "target_contract_id": TARGET_CONTRACT_ID,
        "input_schema_version": "next_behavior_input.v1",
        "tactics": [
            "collection",
            "command-and-control",
            "credential-access",
            "defense-evasion",
            "discovery",
            "execution",
            "exfiltration",
            "impact",
            "initial-access",
            "lateral-movement",
            "persistence",
            "privilege-escalation",
            "reconnaissance",
            "resource-development",
        ],
        "techniques": ["<UNK>", "T1082"],
        "label_sources": [
            "reviewed_rule",
            "rule_model_agreement",
            "securebert",
        ],
        "confidence_buckets": [
            "high",
            "low",
            "medium",
            "not_applicable",
        ],
        "agreement_statuses": [
            "agreed",
            "disagreed",
            "emergency",
            "model_only",
            "rule_only",
            "unreviewed",
        ],
        "repetition_buckets": ["1", "2", "3-5", "6+"],
        "elapsed_time_buckets": [
            "10_to_60s",
            "1_to_10s",
            "over_60s",
            "under_1s",
            "unknown",
        ],
        "audit_count_buckets": ["0", "1", "2-5", "6+"],
        "login_outcomes": ["failed", "success", "unknown"],
        "command_count_buckets": ["0", "1", "2-5", "6-20", "21+"],
        "session_age_buckets": [
            "under_10s",
            "10_to_60s",
            "1_to_5m",
            "over_5m",
            "unknown",
        ],
        "maximum_sequence_length": 8,
        "terminal_outcome": TERMINAL_OUTCOME,
        "preprocessing_sha256": preprocessing_sha256,
        "training_membership_sha256": HASH_B,
    }
    value["vocabulary_id"] = stable_id("nextbehaviorvocabulary", value)
    return require_valid_vocabulary(value)


def _tensor(spec: dict) -> dict:
    dimensions = spec["input_dimensions"]
    padding = 7
    value = {
        "schema_version": TENSOR_SCHEMA_VERSION,
        "target_contract_id": TARGET_CONTRACT_ID,
        "vocabulary_id": spec["vocabulary_id"],
        "vocabulary_sha256": spec["vocabulary_sha256"],
        "preprocessing_sha256": spec["preprocessing_sha256"],
        "source_input_hash": "nextbehaviorinput_" + "1" * 32,
        "sequence_length": 1,
        "maximum_sequence_length": 8,
        "attention_mask": [0] * padding + [1],
        "phase_tactic_multi_hot": [
            [0] * dimensions["phase_tactic_count"] for _ in range(8)
        ],
        "phase_technique_multi_hot": [
            [0] * dimensions["phase_technique_count"] for _ in range(8)
        ],
        "phase_source_multi_hot": [
            [0] * dimensions["phase_source_count"] for _ in range(8)
        ],
        "phase_confidence_multi_hot": [
            [0] * dimensions["phase_confidence_count"] for _ in range(8)
        ],
        "phase_agreement_multi_hot": [
            [0] * dimensions["phase_agreement_count"] for _ in range(8)
        ],
        "phase_repetition_index": [0] * padding + [1],
        "phase_elapsed_time_index": [0] * padding + [1],
        "phase_audit_count_index": [0] * padding + [1],
        "context_login_outcome_index": 2,
        "context_command_count_index": 2,
        "context_session_age_index": 1,
        "context_confirmed_transfer": 0,
    }
    value["phase_tactic_multi_hot"][-1][4] = 1
    value["phase_technique_multi_hot"][-1][1] = 1
    value["phase_source_multi_hot"][-1][0] = 1
    value["phase_confidence_multi_hot"][-1][0] = 1
    value["phase_agreement_multi_hot"][-1][4] = 1
    payload = copy.deepcopy(value)
    payload.pop("source_input_hash")
    value["tensor_hash"] = stable_id("nextbehaviortensor", payload)
    return value


def test_model_spec_binds_frozen_architecture_vocabulary_and_preprocessing() -> None:
    vocabulary = _vocabulary()
    spec = build_model_spec(vocabulary)

    assert spec["architecture"] == ARCHITECTURE
    assert spec["output"]["tactics"] == list(OUTPUT_TACTICS)
    assert spec["output"]["tactics"] == sorted(TACTIC_VOCABULARY)
    assert spec["output"]["tactic_logit_count"] == len(TACTIC_VOCABULARY)
    assert spec["output"]["terminal_logit_count"] == 1
    assert spec["vocabulary_sha256"] == vocabulary_sha256(vocabulary)
    assert spec["preprocessing_sha256"] == HASH_A
    assert require_valid_model_spec(spec) == spec

    changed = copy.deepcopy(spec)
    changed["architecture"]["dropout"] = 0.2
    with pytest.raises(NextBehaviorModelError, match="frozen architecture"):
        require_valid_model_spec(changed)


def test_adapter_tensor_validation_is_hash_bound_without_requiring_torch() -> None:
    spec = build_model_spec(_vocabulary())
    tensor = _tensor(spec)

    assert require_valid_tensor_input(tensor, spec) == tensor

    tensor["phase_repetition_index"][-1] = 2
    with pytest.raises(NextBehaviorModelError, match="tensor_hash"):
        require_valid_tensor_input(tensor, spec)


@pytest.mark.skipif(not TORCH_AVAILABLE, reason="PyTorch is genuinely unavailable")
def test_inference_is_cpu_eval_deterministic_and_has_separate_heads() -> None:
    spec = build_model_spec(_vocabulary())
    model = build_model(spec, seed=20260723)
    tensor = _tensor(spec)

    first = predict_next_behavior(model, tensor, spec=spec)
    second = predict_next_behavior(model, tensor, spec=spec)

    assert model.training is False
    assert all(parameter.device.type == "cpu" for parameter in model.parameters())
    assert first == second
    assert list(first["tactic_logits"]) == list(OUTPUT_TACTICS)
    assert len(first["tactic_logits"]) == len(TACTIC_VOCABULARY)
    assert isinstance(first["terminal_logit"], float)
    assert first["score_semantics"] == "raw_uncalibrated_logits"


@pytest.mark.skipif(not TORCH_AVAILABLE, reason="PyTorch is genuinely unavailable")
def test_checkpoint_round_trip_verifies_all_frozen_hashes(tmp_path: Path) -> None:
    spec = build_model_spec(_vocabulary())
    original = build_model(spec, seed=17)
    checkpoint = tmp_path / "next-behavior.pt"
    receipt = save_checkpoint(checkpoint, original, spec=spec)

    loaded, metadata = load_checkpoint(
        checkpoint,
        expected_spec=spec,
        expected_checkpoint_sha256=receipt["checkpoint_sha256"],
    )

    assert loaded.training is False
    assert metadata["checkpoint_sha256"] == receipt["checkpoint_sha256"]
    assert (
        metadata["state_dictionary_sha256"]
        == receipt["state_dictionary_sha256"]
    )
    assert metadata["architecture_sha256"] == spec["architecture_sha256"]
    assert metadata["vocabulary_sha256"] == spec["vocabulary_sha256"]
    assert metadata["preprocessing_sha256"] == spec["preprocessing_sha256"]
    assert predict_next_behavior(loaded, _tensor(spec), spec=spec) == (
        predict_next_behavior(original, _tensor(spec), spec=spec)
    )


@pytest.mark.skipif(not TORCH_AVAILABLE, reason="PyTorch is genuinely unavailable")
def test_corrupted_and_mismatched_checkpoints_fail_closed(tmp_path: Path) -> None:
    import torch

    spec = build_model_spec(_vocabulary())
    checkpoint = tmp_path / "next-behavior.pt"
    receipt = save_checkpoint(checkpoint, build_model(spec, seed=3), spec=spec)

    corrupted = bytearray(checkpoint.read_bytes())
    corrupted[len(corrupted) // 2] ^= 1
    checkpoint.write_bytes(corrupted)
    with pytest.raises(NextBehaviorCheckpointError, match="SHA-256 mismatch"):
        load_checkpoint(
            checkpoint,
            expected_spec=spec,
            expected_checkpoint_sha256=receipt["checkpoint_sha256"],
        )

    second_checkpoint = tmp_path / "clean.pt"
    second_receipt = save_checkpoint(
        second_checkpoint, build_model(spec, seed=3), spec=spec
    )
    mismatched = build_model_spec(
        _vocabulary(preprocessing_sha256="c" * 64)
    )
    with pytest.raises(NextBehaviorCheckpointError, match="model spec mismatch"):
        load_checkpoint(
            second_checkpoint,
            expected_spec=mismatched,
            expected_checkpoint_sha256=second_receipt["checkpoint_sha256"],
        )

    payload = torch.load(
        second_checkpoint,
        map_location="cpu",
        weights_only=True,
    )
    first_key = sorted(payload["state_dict"])[0]
    payload["state_dict"][first_key].view(-1)[0] += 1
    torch.save(payload, second_checkpoint)
    with pytest.raises(
        NextBehaviorCheckpointError,
        match="state_dict hash mismatch",
    ):
        load_checkpoint(
            second_checkpoint,
            expected_spec=spec,
            expected_checkpoint_sha256=sha256_file(second_checkpoint),
        )


@pytest.mark.skipif(not TORCH_AVAILABLE, reason="PyTorch is genuinely unavailable")
def test_tampered_tensor_hash_and_vocabulary_fail_closed() -> None:
    spec = build_model_spec(_vocabulary())
    model = build_model(spec, seed=5)
    tensor = _tensor(spec)
    tensor["phase_repetition_index"][-1] = 2
    with pytest.raises(NextBehaviorModelError, match="tensor_hash"):
        predict_next_behavior(model, tensor, spec=spec)

    tensor = _tensor(spec)
    tensor["vocabulary_sha256"] = "0" * 64
    with pytest.raises(NextBehaviorModelError, match="vocabulary_sha256"):
        predict_next_behavior(model, tensor, spec=spec)
