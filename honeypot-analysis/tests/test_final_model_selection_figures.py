from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from production.tools.generate_final_model_selection_figures import (
    DECISION_MATRIX,
    FIGURE_INFO,
    _decision_totals,
    generate,
    load_evidence,
)


EVIDENCE = Path("evaluation/next_tactic_benchmark_evidence")


def test_final_figure_evidence_and_decision_values_are_bound() -> None:
    data = load_evidence(EVIDENCE)
    single = data["single_checkpoint_evaluation.json"]
    assert single["metrics"]["transformer_seed_20260723"]["top1_accuracy"] == pytest.approx(0.886554965263588)
    assert single["metrics"]["hard_backoff_vomm"]["top1_accuracy"] == pytest.approx(0.8008173273395995)
    assert single["paired_comparison"]["outcomes"]["candidate_win"] == 1887
    assert single["paired_comparison"]["by_tactic"]["persistence"]["candidate_win"] == 1718
    assert single["confusion_matrices"]["hard_backoff_vomm"]["counts"]["persistence"]["execution"] == 1718
    assert single["confusion_matrices"]["transformer_seed_20260723"]["counts"]["execution"]["persistence"] == 819
    assert len(FIGURE_INFO) == 29
    assert sum(item["weight"] for item in DECISION_MATRIX["criteria"]) == pytest.approx(1.0)
    assert _decision_totals() == pytest.approx(
        {
            "vomm_only": 3.572,
            "transformer_primary": 3.861,
            "dual_reporting": 4.395,
            "tactic_routing": 2.471,
            "insufficient": 3.025,
        }
    )


@pytest.mark.skipif(importlib.util.find_spec("matplotlib") is None, reason="optional plotting dependency")
def test_final_figure_package_is_complete_readable_and_hash_bound(tmp_path: Path) -> None:
    output = tmp_path / "figures"
    manifest = generate(EVIDENCE, output)
    png_paths = sorted(output.glob("*.png"))
    pdf_paths = sorted(output.glob("*.pdf"))
    assert len(png_paths) == 29
    assert len(pdf_paths) == 29
    assert len(manifest["artifacts"]) == 60
    assert manifest["aggregate_neural_runtime_excluded"] is True
    assert manifest["unsupported_runtime_values_fabricated"] is False
    assert manifest["benchmark_values_modified"] is False
    assert manifest["production_authority_modified"] is False
    assert manifest["displayed_key_values"]["transformer_execution_to_persistence"] == 819
    assert manifest["displayed_key_values"]["vomm_persistence_to_execution"] == 1718
    assert manifest["displayed_key_values"]["decision_total_dual_reporting"] == pytest.approx(4.395)

    import matplotlib.image as mpimg

    for path in png_paths:
        image = mpimg.imread(path)
        assert image.shape[0] > 100
        assert image.shape[1] > 100
    pdfinfo = shutil.which("pdfinfo")
    if pdfinfo:
        for path in pdf_paths:
            result = subprocess.run([pdfinfo, str(path)], check=True, capture_output=True, text=True)
            assert "Pages:           1" in result.stdout
    else:
        for path in pdf_paths:
            assert path.read_bytes().startswith(b"%PDF-")

    stored = json.loads((output / "figures_manifest.json").read_text(encoding="utf-8"))
    for item in stored["artifacts"]:
        path = Path(item["path"])
        assert path.is_file()
        assert hashlib.sha256(path.read_bytes()).hexdigest() == item["sha256"]
    for source in stored["input_evidence"]:
        path = Path(source["path"])
        assert hashlib.sha256(path.read_bytes()).hexdigest() == source["sha256"]
    serialized = json.dumps(stored).lower()
    assert "next_tactic_offline_benchmark_20260721/" not in serialized
    assert "superseded" not in serialized
    assert (output / "FIGURE_SUMMARY.md").read_text(encoding="utf-8").count("## ") == 30
    assert sum(path.stat().st_size for path in output.iterdir()) < 15 * 1024 * 1024
