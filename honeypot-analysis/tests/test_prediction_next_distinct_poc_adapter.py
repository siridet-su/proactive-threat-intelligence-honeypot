from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path

import pytest

from production.prediction_next_distinct_poc.adapter import (
    LABEL_ORDER,
    PocAdapterError,
    load_runtime_binding,
    predict_from_logits,
    prepare_history,
    temperature_scaled_softmax,
)


def test_history_contract_and_revisits() -> None:
    result = prepare_history(
        [
            "execution",
            "execution",
            "persistence",
            "execution",
            "discovery",
            "discovery",
        ]
    )
    assert result["sequence"] == ["execution", "persistence", "execution", "discovery"]
    assert result["adjacent_duplicates_removed"] == 2
    assert result["history_truncated"] is False


def test_history_truncates_to_last_eight() -> None:
    source = [LABEL_ORDER[index % len(LABEL_ORDER)] for index in range(12)]
    result = prepare_history(source)
    assert len(result["sequence"]) == 8
    assert result["history_truncated"] is True


@pytest.mark.parametrize("value", [[], ["not-a-tactic"], "execution", None])
def test_invalid_or_empty_inputs_fail_closed(value) -> None:
    if value == []:
        assert prepare_history(value)["sequence"] == []
    else:
        with pytest.raises(PocAdapterError):
            prepare_history(value)


def test_temperature_and_top3_are_deterministic() -> None:
    logits = [0.0, -1.0, 0.5, 1.0, 3.0, 2.0, -2.0]
    probs = temperature_scaled_softmax(logits, 0.6191339280332447)
    assert abs(sum(probs) - 1.0) < 1e-12
    assert all(p == p and p >= 0.0 for p in probs)
    first = predict_from_logits(
        ["execution", "execution", "persistence"],
        logits,
        temperature=0.6191339280332447,
        model_identifier="test-fixture-only",
        checkpoint_sha256="0" * 64,
    )
    second = predict_from_logits(
        ["execution", "execution", "persistence"],
        logits,
        temperature=0.6191339280332447,
        model_identifier="test-fixture-only",
        checkpoint_sha256="0" * 64,
    )
    assert first == second
    assert first["authority"] == "non_authoritative"
    assert first["canonical_write_allowed"] is False
    assert len(first["top3"]) == 3


def test_temperature_does_not_change_ranking() -> None:
    logits = [0.2, 1.7, -0.1, 0.8, 0.4, 0.9, 0.3]
    cold = temperature_scaled_softmax(logits, 0.6191339280332447)
    warm = temperature_scaled_softmax(logits, 1.7)
    assert sorted(range(7), key=lambda i: (-cold[i], i)) == sorted(
        range(7), key=lambda i: (-warm[i], i)
    )


def test_binding_hash_and_authority_guard() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        checkpoint = Path(tmp) / "fixture.bin"
        checkpoint.write_bytes(b"fixture-only")
        digest = hashlib.sha256(checkpoint.read_bytes()).hexdigest()
        binding = {
            "status": "COMPLETE_VALID",
            "authority": "non_authoritative",
            "canonical_write_allowed": False,
            "label_order": list(LABEL_ORDER),
            "checkpoint_path": str(checkpoint),
            "checkpoint_sha256": digest,
            "temperature": 0.6191339280332447,
        }
        path = Path(tmp) / "binding.json"
        path.write_text(json.dumps(binding), encoding="utf-8")
        assert load_runtime_binding(path)["checkpoint_sha256"] == digest
        binding["canonical_write_allowed"] = True
        path.write_text(json.dumps(binding), encoding="utf-8")
        with pytest.raises(PocAdapterError):
            load_runtime_binding(path)
