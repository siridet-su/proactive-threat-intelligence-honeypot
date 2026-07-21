from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

from production.tools.generate_next_tactic_decision_figures import generate, validate_evidence


EVIDENCE = Path("evaluation/next_tactic_benchmark_evidence/single_checkpoint_evaluation.json")


def _evidence() -> dict:
    return json.loads(EVIDENCE.read_text(encoding="utf-8"))


def test_figure_evidence_validation_rejects_changed_decision_values() -> None:
    accepted = _evidence()
    validate_evidence(accepted)

    changed_count = copy.deepcopy(accepted)
    changed_count["confusion_matrices"]["transformer_seed_20260723"]["counts"]["execution"]["persistence"] = 818
    with pytest.raises(ValueError, match="Execution to Persistence count"):
        validate_evidence(changed_count)

    changed_gate = copy.deepcopy(accepted)
    changed_gate["promotion_gate"]["criterion_4_tactic_safety"]["pass"] = True
    with pytest.raises(ValueError, match="tactic-safety failed"):
        validate_evidence(changed_gate)


@pytest.mark.skipif(importlib.util.find_spec("matplotlib") is None, reason="optional plotting dependency")
def test_figure_package_is_complete_hash_bound_and_compact(tmp_path: Path) -> None:
    output = tmp_path / "figures"
    manifest = generate(EVIDENCE, output)

    png = sorted(output.glob("*.png"))
    pdf = sorted(output.glob("*.pdf"))
    assert len(png) == 10
    assert len(pdf) == 10
    assert (output / "FIGURE_SUMMARY.md").is_file()
    stored = json.loads((output / "figures_manifest.json").read_text(encoding="utf-8"))
    assert stored["schema_version"] == "next_tactic_figure_manifest.v1"
    assert stored["benchmark_values_modified"] is False
    assert stored["production_modified"] is False
    assert stored["generator_code_sha256"] == hashlib.sha256(
        Path("production/tools/generate_next_tactic_decision_figures.py").read_bytes()
    ).hexdigest()
    assert stored["source_files"][0]["sha256"] == hashlib.sha256(EVIDENCE.read_bytes()).hexdigest()
    assert len(manifest["figures"]) == 21
    for item in manifest["figures"]:
        path = Path(item["path"])
        assert path.is_file()
        assert hashlib.sha256(path.read_bytes()).hexdigest() == item["sha256"]
    assert sum(path.stat().st_size for path in output.iterdir()) < 8 * 1024 * 1024
