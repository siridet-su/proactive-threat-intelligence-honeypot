from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path

import pytest

from production.tools.evaluate_frozen_transformer_candidate import (
    _load_candidate,
    _paired_bootstrap,
    _template_analysis,
)
from production.tools.next_tactic_offline_benchmark import (
    BenchmarkCase,
    Prediction,
    _make_neural_model,
    _neural_probabilities,
    _record_for_case,
    _torch_modules,
)


VOCABULARY = ["discovery", "execution", "persistence"]
SETTINGS = {
    "attention_heads": 1,
    "batch_size": 4,
    "dropout": 0.5,
    "embedding_dimension": 6,
    "hidden_dimension": 8,
    "layers": 1,
    "learning_rate": 0.003,
    "max_sequence_length": 4,
    "patience": 2,
    "weight_decay": 0.0,
}


def _case(case_id: str, session_id: str, actual: str, sequence: tuple[str, ...]) -> BenchmarkCase:
    return BenchmarkCase(case_id, session_id, 0, actual, sequence, {})


@pytest.mark.skipif(importlib.util.find_spec("torch") is None, reason="optional neural dependency")
def test_frozen_checkpoint_load_is_strict_eval_and_deterministic(tmp_path: Path) -> None:
    torch, _np = _torch_modules()
    torch.manual_seed(7)
    original = _make_neural_model(
        "transformer", vocabulary_size=len(VOCABULARY), settings=SETTINGS, torch=torch
    )
    checkpoint = tmp_path / "candidate.pt"
    torch.save(original.state_dict(), checkpoint)
    digest = hashlib.sha256(checkpoint.read_bytes()).hexdigest()
    parameter_count = sum(parameter.numel() for parameter in original.parameters())

    loaded, metadata = _load_candidate(
        checkpoint, VOCABULARY, SETTINGS, digest,
        expected_parameter_count=parameter_count,
    )
    cases = [_case("one", "session-one", "execution", ("discovery",))]
    first = _neural_probabilities(loaded, cases, VOCABULARY, SETTINGS, torch)
    second = _neural_probabilities(loaded, cases, VOCABULARY, SETTINGS, torch)

    assert metadata["state_dictionary_compatible"] is True
    assert metadata["model_eval"] is True
    assert loaded.training is False
    assert first == second


@pytest.mark.skipif(importlib.util.find_spec("torch") is None, reason="optional neural dependency")
def test_frozen_checkpoint_rejects_hash_and_architecture_mismatch(tmp_path: Path) -> None:
    torch, _np = _torch_modules()
    model = _make_neural_model(
        "transformer", vocabulary_size=len(VOCABULARY), settings=SETTINGS, torch=torch
    )
    checkpoint = tmp_path / "candidate.pt"
    torch.save(model.state_dict(), checkpoint)
    digest = hashlib.sha256(checkpoint.read_bytes()).hexdigest()
    parameter_count = sum(parameter.numel() for parameter in model.parameters())

    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        _load_candidate(
            checkpoint, VOCABULARY, SETTINGS, "0" * 64,
            expected_parameter_count=parameter_count,
        )
    with pytest.raises(RuntimeError):
        _load_candidate(
            checkpoint, [*VOCABULARY, "impact"], SETTINGS, digest,
            expected_parameter_count=parameter_count,
        )


def test_paired_bootstrap_requires_case_alignment_and_uses_sessions() -> None:
    cases = [
        _case("one", "session-a", "execution", ("discovery",)),
        _case("two", "session-b", "persistence", ("execution",)),
    ]
    reference = [
        _record_for_case(cases[0], Prediction({"execution": 1.0}), VOCABULARY),
        _record_for_case(cases[1], Prediction({"execution": 1.0}), VOCABULARY),
    ]
    candidate = [
        _record_for_case(cases[0], Prediction({"execution": 1.0}), VOCABULARY),
        _record_for_case(cases[1], Prediction({"persistence": 1.0}), VOCABULARY),
    ]

    result = _paired_bootstrap(reference, candidate, VOCABULARY, iterations=20, seed=4)
    assert result["unit"] == "whole_session"
    assert result["iterations"] == 20
    assert result["candidate_minus_vomm_95ci"]["top1_accuracy"][1] > 0
    with pytest.raises(ValueError, match="identical case IDs"):
        _paired_bootstrap(reference, candidate[:1], VOCABULARY, iterations=2, seed=4)


def test_template_analysis_does_not_claim_template_causality() -> None:
    cases = [
        _case(str(index), f"session-{index}", "persistence", ("execution",))
        for index in range(12)
    ]
    reference = [
        _record_for_case(case, Prediction({"execution": 1.0}), VOCABULARY)
        for case in cases
    ]
    candidate = [
        _record_for_case(case, Prediction({"persistence": 1.0}), VOCABULARY)
        for case in cases
    ]

    result = _template_analysis(candidate, reference)
    assert result["persistence_candidate_win_count"] == 12
    assert result["candidate_wins_in_input_patterns_repeated_at_least_10_times_fraction"] == 1.0
    assert "causality cannot be established" in result["note"]
