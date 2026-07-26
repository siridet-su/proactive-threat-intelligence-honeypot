#!/usr/bin/env python3
"""Derive privacy-safe post-evaluation aggregates without reopening Final data."""
from __future__ import annotations
import argparse, csv, hashlib, json, os, tempfile
from pathlib import Path
from typing import Any, Sequence
from production.utils.serialization import stable_json

NOT_DETERMINABLE = "NOT_DETERMINABLE_FROM_IMMUTABLE_FINAL_OUTPUT"

def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()

def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")

def _aggregate(metrics: dict[str, Any]) -> dict[str, Any]:
    all_classes = metrics["multilabel_tactics"]["all_classes"]
    reportable = metrics["multilabel_tactics"]["reportable_class_aggregates"]
    return {
        "macro_all_14": all_classes["macro"],
        "micro_all_14": all_classes["micro"],
        "weighted_all_14": all_classes["weighted"],
        "macro_reportable_6": reportable["macro"],
        "micro_reportable_6": reportable["micro"],
        "weighted_reportable_6": reportable["weighted"],
        "coverage": metrics["coverage"],
        "terminal": metrics["terminal"],
        "tactic_vs_end": metrics["tactic_vs_end"],
        "ranking": metrics["nonterminal_ranking"],
        "session_cluster_bootstrap": metrics["session_cluster_bootstrap"],
    }

def analyze(result_path: Path, output: Path, *, expected_sha256: str, runtime_path: Path | None = None) -> dict[str, Any]:
    actual = sha256_file(result_path)
    if actual != expected_sha256:
        raise ValueError("immutable Final result hash mismatch")
    if output.exists():
        raise FileExistsError(output)
    result = json.loads(result_path.read_text(encoding="utf-8"))
    if result.get("status") != "complete":
        raise ValueError("immutable Final result is incomplete")
    transformer = result["metrics"]["transformer"]
    vomm = result["metrics"]["hard_backoff_vomm"]
    staging = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=output.parent))
    try:
        per_label: list[dict[str, Any]] = []
        for label in sorted(transformer["multilabel_tactics"]["per_class"]):
            left = transformer["multilabel_tactics"]["per_class"][label]
            right = vomm["multilabel_tactics"]["per_class"][label]
            row: dict[str, Any] = {"label": label, "support": left["support"]}
            for prefix, values in (("transformer", left), ("vomm", right)):
                row.update({
                    f"{prefix}_predicted_positive": values["tp"] + values["fp"],
                    f"{prefix}_tp": values["tp"], f"{prefix}_fp": values["fp"],
                    f"{prefix}_fn": values["fn"], f"{prefix}_precision": values["precision"],
                    f"{prefix}_recall": values["recall"], f"{prefix}_f1": values["f1"],
                    f"{prefix}_specificity": values["specificity"],
                    f"{prefix}_balanced_accuracy": values["balanced_accuracy"],
                })
            row["transformer_minus_vomm_f1"] = left["f1"] - right["f1"]
            row["winner_by_f1"] = "transformer" if left["f1"] > right["f1"] else "vomm" if right["f1"] > left["f1"] else "tie"
            row["low_support_or_unstable"] = left["support"] < 30
            per_label.append(row)
        terminal_row = {"label": "session_end_no_further_trusted_behavior", "support": transformer["terminal"]["support"]}
        for prefix, values in (("transformer", transformer["terminal"]), ("vomm", vomm["terminal"])):
            terminal_row.update({f"{prefix}_predicted_positive": values["tp"] + values["fp"], f"{prefix}_tp": values["tp"], f"{prefix}_fp": values["fp"], f"{prefix}_fn": values["fn"], f"{prefix}_precision": values["precision"], f"{prefix}_recall": values["recall"], f"{prefix}_f1": values["f1"], f"{prefix}_specificity": values["specificity"], f"{prefix}_balanced_accuracy": values["balanced_accuracy"]})
        terminal_row["transformer_minus_vomm_f1"] = transformer["terminal"]["f1"] - vomm["terminal"]["f1"]
        terminal_row["winner_by_f1"] = "transformer" if terminal_row["transformer_minus_vomm_f1"] > 0 else "vomm" if terminal_row["transformer_minus_vomm_f1"] < 0 else "tie"
        terminal_row["low_support_or_unstable"] = False
        per_label.append(terminal_row)
        with (staging / "per_label_metrics.csv").open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(per_label[0])); writer.writeheader(); writer.writerows(per_label)
        paired = result["paired"]
        paired_rows = [{"analysis": "nonterminal_top1", **paired["paired_top1_outcomes"]}, {"analysis": "session_macro_f1", **paired["macro_f1_session_wins"]}]
        with (staging / "paired_comparison.csv").open("w", newline="", encoding="utf-8") as handle:
            fields = sorted({key for row in paired_rows for key in row}); writer = csv.DictWriter(handle, fieldnames=fields); writer.writeheader(); writer.writerows(paired_rows)
        unavailable = {
            key: NOT_DETERMINABLE for key in (
                "exact_set_match", "subset_accuracy", "hamming_loss", "macro_jaccard",
                "micro_jaccard", "fully_correct_partial_incorrect_counts", "predicted_set_size",
                "target_set_size", "overprediction_underprediction", "set_size_groups",
                "per_example_paired_set_comparison", "mcnemar_full_set_test", "calibration_diagnostics",
                "sequence_length", "truncation", "provenance", "confidence", "agreement_conflict",
                "repetition", "elapsed_time", "login_outcome", "command_count", "session_age", "transfer_observed",
            )
        }
        context_rows = [{"dimension": key, "status": value} for key, value in unavailable.items()]
        with (staging / "context_analysis.csv").open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=["dimension", "status"]); writer.writeheader(); writer.writerows(context_rows)
        runtime = None
        if runtime_path is not None:
            runtime = json.loads(runtime_path.read_text(encoding="utf-8"))
            if runtime.get("status") != "complete" or runtime.get("input_scope") != "sealed_calibration_inputs_labels_removed_before_inference":
                raise ValueError("runtime evidence is invalid")
        analysis = {
            "schema_version": "next_behavior_professor_approved_post_evaluation.v1",
            "status": "derived_from_immutable_final_output",
            "source": {"path": str(result_path), "sha256": actual, "manifest_sha256": result["manifest_sha256"]},
            "final_counts": result["final_counts"], "transformer": _aggregate(transformer),
            "hard_backoff_vomm": _aggregate(vomm), "per_label": per_label,
            "paired": {"top1": paired["paired_top1_outcomes"], "session_macro_f1": paired["macro_f1_session_wins"], "metric_differences_and_ci": paired["metrics"]},
            "runtime_from_authorized_evaluator": result["runtime"], "unavailable": unavailable,
            "runtime_from_calibration_inputs": runtime,
            "interpretation": {"frequent_behavior_objective": "transformer", "balanced_and_rare_behavior_objective": "hard_backoff_vomm", "universal_winner": False},
        }
        _write(staging / "post_evaluation_analysis.json", stable_json(analysis) + "\n")
        headers = ["# Immutable professor-approved Final Test: post-evaluation analysis", "", "This is descriptive analysis of the already-written aggregate output. It did not reopen Final source data or invoke either model.", "", "## Result", "", f"Final cohort: {result['final_counts']['sessions']:,} sessions and {result['final_counts']['examples']:,} examples.", "", "Transformer concentrates performance on high-support execution, discovery, and persistence. This raises micro/weighted F1 while zero recall on credential-access, defense-evasion, and privilege-escalation lowers macro-F1 and balanced accuracy. VOMM is more balanced because it detects defense-evasion, but it entirely misses persistence and has much weaker execution F1.", "", "The original experiment remains `BLOCKED_AT_SELECTION`; the professor-approved evaluation accepted, but did not remove, that limitation. The holdout is within-Zenodo with classifier-derived weak labels, not external validation.", "", "All unavailable set-valued, calibration, and context analyses are `NOT_DETERMINABLE_FROM_IMMUTABLE_FINAL_OUTPUT` because the evaluator retained aggregates and identifiers, but not per-example targets, prediction sets, probabilities, or context fields."]
        _write(staging / "REPORT_EN.md", "\n".join(headers) + "\n")
        thai = ["# การวิเคราะห์หลังการประเมิน Final Test แบบคงที่", "", "รายงานนี้ใช้เฉพาะผลรวมที่ถูกบันทึกจากการประเมินครั้งเดียว ไม่ได้เปิดข้อมูล Final ซ้ำและไม่ได้เรียกใช้โมเดลอีกครั้ง", "", "Transformer ให้ผลดีต่อพฤติกรรมที่มีจำนวนมาก จึงมี Micro-F1 และ Weighted-F1 สูงกว่า แต่ไม่ตรวจพบ credential-access, defense-evasion และ privilege-escalation ทำให้ Macro-F1 และ Balanced Accuracy ต่ำกว่า VOMM", "", "การทดลองเดิมยังคงมีสถานะ `BLOCKED_AT_SELECTION` และข้อมูลเป็น temporal holdout ภายใน Zenodo ที่ใช้ weak labels จากตัวจำแนก ไม่ใช่ external validation"]
        _write(staging / "REPORT_TH.md", "\n".join(thai) + "\n")
        # Compact SVGs are deterministic and contain aggregate values only.
        labels = [row for row in per_label if row["support"] > 0]
        for name, field, title in (("per_label_f1.svg", "transformer_f1", "Transformer per-label F1"), ("support_vs_f1.svg", "support", "Label support"), ("f1_difference.svg", "transformer_minus_vomm_f1", "Transformer minus VOMM F1")):
            width, height = 900, 35 * len(labels) + 60
            lines = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}"><text x="10" y="22">{title}</text>']
            max_value = max(abs(float(row[field])) for row in labels) or 1
            for index, row in enumerate(labels):
                y = 48 + index * 32; value = float(row[field]); length = 500 * abs(value) / max_value
                lines.append(f'<text x="10" y="{y}">{row["label"]}</text><rect x="280" y="{y-16}" width="{length:.2f}" height="18" fill="#286090"/><text x="{290+length:.2f}" y="{y}">{value:.6g}</text>')
            lines.append("</svg>"); _write(staging / name, "".join(lines))
        if runtime is not None:
            t95 = runtime["transformer"]["latency_ms"]["p95"]; v95 = runtime["hard_backoff_vomm"]["latency_ms"]["p95"]
            _write(staging / "runtime_comparison.svg", f'<svg xmlns="http://www.w3.org/2000/svg" width="700" height="180"><text x="10" y="24">Calibration-input real inference p95 (ms)</text><text x="10" y="70">Transformer</text><rect x="130" y="50" width="{t95*20:.2f}" height="25" fill="#286090"/><text x="{140+t95*20:.2f}" y="70">{t95:.6f}</text><text x="10" y="120">VOMM</text><rect x="130" y="100" width="{v95*20:.2f}" height="25" fill="#777"/><text x="{140+v95*20:.2f}" y="120">{v95:.6f}</text></svg>')
        hashes = {str(path.relative_to(staging)): sha256_file(path) for path in sorted(staging.rglob("*")) if path.is_file()}
        sources = {"immutable_final_result": actual}
        if runtime_path is not None: sources["calibration_runtime"] = sha256_file(runtime_path)
        _write(staging / "SHA256SUMS.json", stable_json({"sources": sources, "files": hashes}) + "\n")
        os.replace(staging, output)
    except BaseException:
        import shutil; shutil.rmtree(staging, ignore_errors=True); raise
    return analysis

def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(); parser.add_argument("--result", type=Path, required=True); parser.add_argument("--output", type=Path, required=True); parser.add_argument("--expected-sha256", required=True); parser.add_argument("--runtime", type=Path)
    args = parser.parse_args(argv); analyze(args.result, args.output, expected_sha256=args.expected_sha256, runtime_path=args.runtime); return 0

if __name__ == "__main__": raise SystemExit(main())
