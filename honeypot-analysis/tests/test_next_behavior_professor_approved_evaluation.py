import json

import pytest

from production.tools.evaluate_professor_approved_poc import (
    ProfessorApprovedEvaluationError,
    _claim,
    _finalize,
    _ledger_path,
)


def _manifest(tmp_path):
    final = tmp_path / "final.examples.jsonl"
    final.write_text("{}\n", encoding="utf-8")
    return {
        "manifest_sha256": "a" * 64,
        "final_test": {"path": str(final), "sha256": "b" * 64},
        "decision": {"selection": {"selected_seed": 20260721}},
        "code_commit": "c" * 40,
    }


def test_access_claim_is_atomic_and_second_open_fails(tmp_path):
    manifest = _manifest(tmp_path)
    claim = _claim(manifest, tmp_path / "output")
    record = json.loads(claim.read_text(encoding="utf-8"))
    assert record["state"] == "opened"
    assert claim == _ledger_path(manifest)
    with pytest.raises(ProfessorApprovedEvaluationError, match="already opened"):
        _claim(manifest, tmp_path / "other")
    _finalize(claim, "completed", tmp_path / "output")
    assert json.loads(claim.read_text(encoding="utf-8"))["state"] == "completed"


def test_finalize_rejects_interrupted_or_tampered_ledger(tmp_path):
    manifest = _manifest(tmp_path)
    claim = _claim(manifest, tmp_path / "output")
    value = json.loads(claim.read_text(encoding="utf-8"))
    value["state"] = "completed"
    claim.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ProfessorApprovedEvaluationError, match="ledger changed"):
        _finalize(claim, "failed")
