"""Generate the compact next-tactic model-decision figure package.

Only the accepted, machine-readable single-checkpoint evaluation is read.
This tool does not train, select, score, deploy, or modify either model.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence


SCHEMA_VERSION = "next_tactic_figure_manifest.v1"
DEFAULT_EVIDENCE = "evaluation/next_tactic_benchmark_evidence/single_checkpoint_evaluation.json"
DEFAULT_OUTPUT = "evaluation/next_tactic_benchmark_evidence/figures"
EXPECTED_CHECKPOINT_SHA256 = "d9b316d76e63b15b175668aa0bf69cfe4172bbd812d6b19743a628cd0ec8073d"
VOMM = "hard_backoff_vomm"
TRANSFORMER = "transformer_seed_20260723"
VOMM_LABEL = "External hard-backoff VOMM"
TRANSFORMER_LABEL = "Selected Transformer"
VOMM_COLOR = "#2F5D8C"
TRANSFORMER_COLOR = "#D97706"
PASS_COLOR = "#2E7D32"
FAIL_COLOR = "#B3261E"
MUTED_COLOR = "#5F6368"
GRID_COLOR = "#D9DEE5"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("single-checkpoint evidence must be a JSON object")
    return value


def _plot_modules() -> tuple[Any, Any, Any]:
    cache = Path(tempfile.gettempdir()) / "honeypot-matplotlib"
    cache.mkdir(parents=True, exist_ok=True)
    os.environ.setdefault("MPLCONFIGDIR", str(cache))
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.colors import LinearSegmentedColormap

    plt.rcParams.update(
        {
            "font.family": "DejaVu Sans",
            "font.size": 10,
            "axes.titlesize": 13,
            "axes.labelsize": 10,
            "axes.edgecolor": "#4A5568",
            "axes.linewidth": 0.8,
            "axes.grid": True,
            "axes.axisbelow": True,
            "grid.color": GRID_COLOR,
            "grid.linewidth": 0.7,
            "legend.frameon": False,
            "figure.facecolor": "white",
            "savefig.facecolor": "white",
        }
    )
    return plt, matplotlib, LinearSegmentedColormap


def validate_evidence(data: Mapping[str, Any]) -> None:
    metrics = data.get("metrics") or {}
    paired = data.get("paired_comparison") or {}
    confusion = data.get("confusion_matrices") or {}
    gate = data.get("promotion_gate") or {}
    checkpoint = ((data.get("integrity") or {}).get("checkpoint") or {})
    checks = {
        "accepted schema": data.get("schema_version") == "frozen_transformer_poc_evaluation.v1",
        "VOMM metrics": VOMM in metrics,
        "Transformer metrics": TRANSFORMER in metrics,
        "same 12,235 cases": (
            (metrics.get(VOMM) or {}).get("evaluated_examples") == 12235
            and (metrics.get(TRANSFORMER) or {}).get("evaluated_examples") == 12235
        ),
        "checkpoint hash": checkpoint.get("checkpoint_sha256") == EXPECTED_CHECKPOINT_SHA256,
        "paired case count": paired.get("case_count") == 12235,
        "Execution to Persistence count": (
            (((confusion.get(TRANSFORMER) or {}).get("counts") or {}).get("execution") or {}).get("persistence") == 819
        ),
        "tactic-safety failed": not bool((gate.get("criterion_4_tactic_safety") or {}).get("pass")),
        "promotion rejected": (
            data.get("promotion_gate_passed") is False
            and data.get("authoritative_poc_model_decision") == "retain_external_hard_backoff_vomm"
        ),
        "raw scores not calibrated": data.get("raw_transformer_scores_are_calibrated_probabilities") is False,
    }
    failed = [name for name, passed in checks.items() if not passed]
    if failed:
        raise ValueError(f"accepted evidence validation failed: {', '.join(failed)}")


def _save_figure(
    fig: Any,
    output_dir: Path,
    stem: str,
    caption: str,
    generated: list[dict[str, Any]],
) -> None:
    fig.text(0.01, 0.012, caption, ha="left", va="bottom", fontsize=7.2, color=MUTED_COLOR)
    fig.tight_layout(rect=(0, 0.055, 1, 0.97))
    for extension in ("png", "pdf"):
        path = output_dir / f"{stem}.{extension}"
        options = {"bbox_inches": "tight", "metadata": {"Title": stem, "Subject": caption}}
        if extension == "png":
            options["dpi"] = 240
        fig.savefig(path, **options)
        generated.append(
            {
                "path": str(path),
                "format": extension,
                "sha256": _sha256(path),
                "size_bytes": path.stat().st_size,
            }
        )


def _bar_labels(ax: Any, bars: Any, *, digits: int = 3) -> None:
    for bar in bars:
        value = float(bar.get_height())
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            value + 0.015,
            f"{value:.{digits}f}",
            ha="center",
            va="bottom",
            fontsize=8,
        )


def figure_overall(plt: Any, data: Mapping[str, Any]) -> Any:
    fig, ax = plt.subplots(figsize=(9.2, 5.4))
    fields = ["top1_accuracy", "top3_accuracy", "macro_f1", "balanced_accuracy", "mean_reciprocal_rank"]
    labels = ["Top-1", "Top-3", "Macro-F1", "Balanced accuracy", "MRR"]
    x = list(range(len(fields)))
    width = 0.36
    vomm = [float(data["metrics"][VOMM][field]) for field in fields]
    transformer = [float(data["metrics"][TRANSFORMER][field]) for field in fields]
    left = ax.bar([value - width / 2 for value in x], vomm, width, label=VOMM_LABEL, color=VOMM_COLOR)
    right = ax.bar([value + width / 2 for value in x], transformer, width, label=TRANSFORMER_LABEL, color=TRANSFORMER_COLOR)
    _bar_labels(ax, left)
    _bar_labels(ax, right)
    ax.set_xticks(x, labels)
    ax.set_ylim(0, 1.09)
    ax.set_ylabel("Held-out metric value")
    ax.set_title("Overall held-out model comparison")
    ax.legend(loc="lower right")
    return fig


def figure_paired(plt: Any, data: Mapping[str, Any]) -> Any:
    fig, ax = plt.subplots(figsize=(8.8, 5.2))
    outcomes = data["paired_comparison"]["outcomes"]
    labels = ["Transformer wins", "VOMM wins", "Both correct", "Both wrong"]
    values = [
        int(outcomes.get("candidate_win", 0)),
        int(outcomes.get("production_vomm_win", 0)),
        int(outcomes.get("tie_both_correct", 0)),
        int(outcomes.get("both_wrong_or_abstained", 0)),
    ]
    colors = [TRANSFORMER_COLOR, VOMM_COLOR, PASS_COLOR, MUTED_COLOR]
    bars = ax.barh(labels, values, color=colors)
    for bar, value in zip(bars, values):
        ax.text(value + 90, bar.get_y() + bar.get_height() / 2, f"{value:,}", va="center", fontsize=9)
    ax.set_xlim(0, max(values) * 1.12)
    ax.set_xlabel("Paired held-out cases")
    ax.set_title("Case-by-case outcomes on the identical 12,235-case test set")
    ax.invert_yaxis()
    return fig


def figure_gate(plt: Any, data: Mapping[str, Any]) -> Any:
    fig, ax = plt.subplots(figsize=(9.8, 5.5))
    gate = data["promotion_gate"]
    keys = [
        "criterion_1_primary_metrics",
        "criterion_2_paired_wins",
        "criterion_3_confidence_intervals",
        "criterion_4_tactic_safety",
        "criterion_5_integrity",
        "criterion_6_operational",
        "criterion_7_prediction_authority_boundary",
    ]
    labels = [
        "Aggregate metrics", "Paired wins", "Confidence intervals", "Tactic safety",
        "Integrity / provenance", "Latency / memory", "Authority policy",
    ]
    states = [bool(gate[key]["pass"]) for key in keys]
    y = list(range(len(keys)))
    ax.barh(y, [1] * len(y), color=[PASS_COLOR if state else FAIL_COLOR for state in states], height=0.62)
    for index, state in enumerate(states):
        ax.text(0.5, index, "PASS" if state else "FAIL", ha="center", va="center", color="white", weight="bold")
    ax.set_yticks(y, labels)
    ax.set_xlim(0, 1)
    ax.set_xticks([])
    ax.set_title("Predeclared Transformer promotion gate")
    ax.invert_yaxis()
    ax.text(1.01, keys.index("criterion_4_tactic_safety"), "Execution recall regression: −23.80 points", va="center", color=FAIL_COLOR, fontsize=9)
    return fig


def figure_per_tactic(plt: Any, data: Mapping[str, Any]) -> Any:
    tactics = ["persistence", "execution", "discovery", "defense-evasion", "command-and-control", "privilege-escalation"]
    labels = ["Persistence", "Execution", "Discovery", "Defense evasion", "Command & control", "Privilege escalation"]
    fig, axes = plt.subplots(3, 1, figsize=(10.8, 10.2), sharex=True)
    width = 0.36
    x = list(range(len(tactics)))
    for ax, field, title in zip(axes, ("precision", "recall", "f1"), ("Precision", "Recall", "F1")):
        vomm = [float(data["metrics"][VOMM]["per_tactic"][tactic][field]) for tactic in tactics]
        transformer = [float(data["metrics"][TRANSFORMER]["per_tactic"][tactic][field]) for tactic in tactics]
        ax.bar([value - width / 2 for value in x], vomm, width, color=VOMM_COLOR, label=VOMM_LABEL)
        ax.bar([value + width / 2 for value in x], transformer, width, color=TRANSFORMER_COLOR, label=TRANSFORMER_LABEL)
        ax.set_ylim(0, 1.05)
        ax.set_ylabel(title)
    axes[0].legend(loc="upper right", ncol=2)
    axes[-1].set_xticks(x, labels, rotation=20, ha="right")
    fig.suptitle("Per-tactic held-out precision, recall, and F1", y=0.995, fontsize=14)
    return fig


def figure_tradeoff(plt: Any, data: Mapping[str, Any]) -> Any:
    fig, axes = plt.subplots(1, 2, figsize=(10.2, 5.2), sharey=True)
    width = 0.36
    for ax, tactic, title in zip(axes, ("persistence", "execution"), ("Persistence", "Execution")):
        fields = ("precision", "recall")
        x = [0, 1]
        vomm = [float(data["metrics"][VOMM]["per_tactic"][tactic][field]) for field in fields]
        transformer = [float(data["metrics"][TRANSFORMER]["per_tactic"][tactic][field]) for field in fields]
        left = ax.bar([value - width / 2 for value in x], vomm, width, color=VOMM_COLOR, label=VOMM_LABEL)
        right = ax.bar([value + width / 2 for value in x], transformer, width, color=TRANSFORMER_COLOR, label=TRANSFORMER_LABEL)
        _bar_labels(ax, left)
        _bar_labels(ax, right)
        ax.set_xticks(x, ["Precision", "Recall"])
        ax.set_ylim(0, 1.10)
        ax.set_title(title)
    axes[0].set_ylabel("Held-out metric value")
    axes[1].legend(loc="lower right")
    fig.suptitle("Persistence gain versus Execution recall cost", y=0.99, fontsize=14)
    return fig


def figure_confusion(plt: Any, data: Mapping[str, Any], colormap_factory: Any) -> Any:
    fig, axes = plt.subplots(1, 2, figsize=(9.7, 4.8))
    cmap = colormap_factory.from_list("formal_blues", ["#F7FAFC", "#8BB3D9", VOMM_COLOR])
    for ax, model, title in zip(axes, (VOMM, TRANSFORMER), (VOMM_LABEL, TRANSFORMER_LABEL)):
        counts = data["confusion_matrices"][model]["counts"]
        values = [
            [int(counts["execution"]["execution"]), int(counts["execution"]["persistence"])],
            [int(counts["persistence"]["execution"]), int(counts["persistence"]["persistence"])],
        ]
        image = ax.imshow(values, cmap=cmap, vmin=0, vmax=max(max(row) for row in values))
        for row in range(2):
            for column in range(2):
                ax.text(column, row, f"{values[row][column]:,}", ha="center", va="center", color="white" if values[row][column] > 1000 else "#172B4D", weight="bold")
        ax.set_xticks([0, 1], ["Pred. Execution", "Pred. Persistence"])
        ax.set_yticks([0, 1], ["Actual Execution", "Actual Persistence"])
        ax.set_title(title)
        ax.grid(False)
        fig.colorbar(image, ax=ax, fraction=0.046, pad=0.04, label="Case count")
    axes[1].annotate(
        "819 Execution → Persistence",
        xy=(1, 0), xytext=(0.35, -0.48), textcoords="axes fraction",
        arrowprops={"arrowstyle": "->", "color": FAIL_COLOR, "lw": 1.5},
        color=FAIL_COLOR, weight="bold", ha="center",
    )
    fig.suptitle("Focused Execution / Persistence confusion matrix", y=0.99, fontsize=14)
    return fig


def figure_nonpromotion(plt: Any, data: Mapping[str, Any]) -> Any:
    fig, ax = plt.subplots(figsize=(10.4, 5.6))
    ax.axis("off")
    cards = [
        (0.04, 0.57, "1,718 / 1,887", "Transformer wins were Persistence", TRANSFORMER_COLOR),
        (0.52, 0.57, "91.0%", "of Transformer wins came from Persistence", TRANSFORMER_COLOR),
        (0.04, 0.14, "0.9497 → 0.7118", "Execution recall fell 23.80 points", FAIL_COLOR),
        (0.52, 0.14, "0.0194 → 0", "Privilege-escalation recall", FAIL_COLOR),
    ]
    for x, y, headline, detail, color in cards:
        ax.add_patch(plt.Rectangle((x, y), 0.43, 0.30, transform=ax.transAxes, facecolor="#F8FAFC", edgecolor=color, linewidth=2))
        ax.text(x + 0.215, y + 0.19, headline, transform=ax.transAxes, ha="center", va="center", fontsize=18, color=color, weight="bold")
        ax.text(x + 0.215, y + 0.075, detail, transform=ax.transAxes, ha="center", va="center", fontsize=9.5, color="#263238")
    ax.text(0.5, 0.96, "Why the Transformer was not promoted", transform=ax.transAxes, ha="center", va="top", fontsize=15, weight="bold")
    ax.text(0.5, 0.03, "Aggregate improvement did not satisfy the tactic-safety requirement.", transform=ax.transAxes, ha="center", color=FAIL_COLOR, fontsize=11, weight="bold")
    return fig


def figure_windows(plt: Any, data: Mapping[str, Any]) -> Any:
    windows = data["chronological_windows"]
    x = [int(row["window"]) for row in windows]
    fig, axes = plt.subplots(1, 2, figsize=(10.5, 4.9))
    panels: list[tuple[Callable[[Mapping[str, Any]], float], str]] = [
        (lambda row: float(row["top1_accuracy"]), "Overall Top-1"),
        (lambda row: float(row["per_tactic"]["execution"]["recall"]), "Execution recall"),
    ]
    for ax, (selector, title) in zip(axes, panels):
        ax.plot(x, [selector(row["hard_backoff_vomm"]) for row in windows], marker="o", lw=2, color=VOMM_COLOR, label=VOMM_LABEL)
        ax.plot(x, [selector(row["transformer"]) for row in windows], marker="o", lw=2, color=TRANSFORMER_COLOR, label=TRANSFORMER_LABEL)
        ax.set_xticks(x)
        ax.set_xlabel("Chronological test window")
        ax.set_ylabel(title)
        ax.set_ylim(0.6 if title == "Execution recall" else 0.75, 1.0)
        ax.set_title(title)
    axes[0].legend(loc="lower right")
    fig.suptitle("Chronological stability: aggregate gain and persistent Execution regression", y=0.99, fontsize=14)
    return fig


def figure_repetition(plt: Any, data: Mapping[str, Any]) -> Any:
    values = data["template_and_weak_label_analysis"]
    fig, axes = plt.subplots(1, 2, figsize=(10.3, 5.0))
    left_values = [12235, int(values["unique_input_sequences"])]
    bars = axes[0].bar(["Held-out cases", "Distinct input\nsequences"], left_values, color=[VOMM_COLOR, TRANSFORMER_COLOR])
    axes[0].set_yscale("log")
    axes[0].set_ylabel("Count (log scale)")
    axes[0].set_title("Sequence-pattern concentration")
    for bar, value in zip(bars, left_values):
        axes[0].text(bar.get_x() + bar.get_width() / 2, value * 1.12, f"{value:,}", ha="center", fontsize=9)
    fractions = [
        float(values["candidate_wins_in_input_patterns_repeated_at_least_10_times_fraction"]),
        float(values["persistence_cases_in_input_patterns_repeated_at_least_10_times_fraction"]),
    ]
    bars = axes[1].bar(["Transformer wins", "Persistence cases"], [item * 100 for item in fractions], color=[TRANSFORMER_COLOR, FAIL_COLOR])
    axes[1].set_ylim(0, 105)
    axes[1].set_ylabel("In patterns repeated ≥10 times (%)")
    axes[1].set_title("Repeated-pattern exposure")
    for bar, value in zip(bars, fractions):
        axes[1].text(bar.get_x() + bar.get_width() / 2, value * 100 + 1.2, f"{value * 100:.2f}%", ha="center", fontsize=9)
    fig.suptitle("Repeated-pattern warning: formal external-corpus caveat", y=0.99, fontsize=14)
    return fig


def figure_executive(plt: Any, data: Mapping[str, Any]) -> Any:
    fig, ax = plt.subplots(figsize=(11.0, 6.0))
    ax.axis("off")
    ax.text(0.5, 0.94, "Next-tactic PoC model decision", ha="center", va="center", fontsize=18, weight="bold", transform=ax.transAxes)
    ax.add_patch(plt.Rectangle((0.05, 0.55), 0.39, 0.25, transform=ax.transAxes, facecolor="#FFF7ED", edgecolor=TRANSFORMER_COLOR, linewidth=2))
    ax.text(0.245, 0.72, "Best aggregate held-out model", ha="center", transform=ax.transAxes, fontsize=10, color=MUTED_COLOR)
    ax.text(0.245, 0.62, "Transformer", ha="center", transform=ax.transAxes, fontsize=20, weight="bold", color=TRANSFORMER_COLOR)
    ax.add_patch(plt.Rectangle((0.56, 0.55), 0.39, 0.25, transform=ax.transAxes, facecolor="#EFF6FF", edgecolor=VOMM_COLOR, linewidth=2))
    ax.text(0.755, 0.72, "Authoritative PoC model", ha="center", transform=ax.transAxes, fontsize=10, color=MUTED_COLOR)
    ax.text(0.755, 0.62, "Hard-backoff VOMM", ha="center", transform=ax.transAxes, fontsize=18, weight="bold", color=VOMM_COLOR)
    ax.annotate("Promotion gate", xy=(0.55, 0.675), xytext=(0.45, 0.675), xycoords=ax.transAxes, textcoords=ax.transAxes, ha="center", va="center", arrowprops={"arrowstyle": "-|>", "lw": 2, "color": FAIL_COLOR}, color=FAIL_COLOR, weight="bold")
    ax.add_patch(plt.Rectangle((0.10, 0.15), 0.80, 0.24, transform=ax.transAxes, facecolor="#FFF5F5", edgecolor=FAIL_COLOR, linewidth=1.8))
    ax.text(0.5, 0.32, "Decision rationale", ha="center", transform=ax.transAxes, fontsize=11, color=FAIL_COLOR, weight="bold")
    ax.text(0.5, 0.23, "Gains were dominated by Persistence (1,718 wins), while Execution recall fell\nfrom 0.9497 to 0.7118. The tactic-safety criterion therefore failed.", ha="center", transform=ax.transAxes, fontsize=11)
    ax.text(0.5, 0.06, "Conclusion applies only to this external, weak-label held-out corpus.", ha="center", transform=ax.transAxes, fontsize=9, color=MUTED_COLOR)
    return fig


def _summary_text(source: Path) -> str:
    return f"""# Next-tactic model-decision figure summary

All figures use the accepted single-checkpoint evidence in `{source}`. The
Transformer checkpoint is the validation-only-selected seed 20260723 with
SHA-256 `{EXPECTED_CHECKPOINT_SHA256}`. Raw Transformer scores are not treated
as calibrated probabilities. Conclusions are limited to the external,
classifier-derived weak-label held-out corpus.

1. **Overall metric comparison.** Shows higher Transformer Top-1, Macro-F1,
   balanced accuracy, and MRR, while VOMM retains higher Top-3.
2. **Paired outcomes.** Reports the exact 1,887 Transformer wins, 838 VOMM
   wins, 8,960 both-correct cases, and 550 both-wrong cases.
3. **Promotion gate.** Six criteria pass and tactic safety fails; this is the
   direct reason the Transformer was not promoted.
4. **Per-tactic metrics.** Compares precision, recall, and F1 for all requested
   supported tactics without suppressing regressions or weak classes.
5. **Persistence versus Execution.** Contrasts the Persistence recall increase
   with the Execution recall decline.
6. **Focused confusion matrix.** Shows the exact 819 Execution cases predicted
   as Persistence by the Transformer.
7. **Non-promotion explanation.** Summarizes that 1,718 of 1,887 Transformer
   wins were Persistence, alongside Execution and privilege-escalation losses.
8. **Chronological stability.** Shows higher Transformer Top-1 in all four
   windows and lower Transformer Execution recall in every window.
9. **Repeated-pattern warning.** Records 45 distinct tactic-sequence patterns
   across 12,235 cases, 99.47% of Transformer wins in patterns repeated at
   least ten times, and all Persistence cases in such patterns. This is a
   caveat, not a causal claim about templates.
10. **Executive summary.** Distinguishes the best aggregate held-out model
    from the selected authoritative PoC model and states the failed gate.

The previously accepted aggregate benchmark files remain unchanged. This
package neither recomputes metrics nor modifies production behavior.
"""


def generate(evidence_path: Path, output_dir: Path) -> dict[str, Any]:
    data = _load(evidence_path)
    validate_evidence(data)
    output_dir.mkdir(parents=True, exist_ok=True)
    plt, matplotlib, colormap_factory = _plot_modules()
    generated: list[dict[str, Any]] = []
    figures: list[tuple[str, Any, str]] = [
        ("01_overall_metrics", figure_overall(plt, data), "Source: single_checkpoint_evaluation.json · identical 12,235-case held-out set."),
        ("02_paired_outcomes", figure_paired(plt, data), "Source: paired comparison in single_checkpoint_evaluation.json · outcomes are mutually exclusive."),
        ("03_promotion_gate", figure_gate(plt, data), "Source: predeclared promotion gate · one failed criterion prevents promotion."),
        ("04_per_tactic_metrics", figure_per_tactic(plt, data), "Source: single-checkpoint per-tactic metrics · low/zero-support limitations remain documented."),
        ("05_persistence_execution_tradeoff", figure_tradeoff(plt, data), "Source: per-tactic metrics · Persistence gain must be read with the Execution recall cost."),
        ("06_execution_persistence_confusion", figure_confusion(plt, data, colormap_factory), "Source: machine-readable confusion counts · focused crop; other tactics are omitted only from this view."),
        ("07_why_not_promoted", figure_nonpromotion(plt, data), "Source: paired-by-tactic and per-tactic evidence · unfavorable results are retained."),
        ("08_chronological_stability", figure_windows(plt, data), "Source: four ordered held-out windows · privacy minimization omits per-session timestamps."),
        ("09_repeated_pattern_warning", figure_repetition(plt, data), "Source: exact sequence repetition analysis · association does not establish template causality."),
        ("10_executive_summary", figure_executive(plt, data), "Source: final promotion gate · external hard-backoff VOMM remains authoritative."),
    ]
    for stem, figure, caption in figures:
        _save_figure(figure, output_dir, stem, caption, generated)
        plt.close(figure)
    summary = output_dir / "FIGURE_SUMMARY.md"
    summary.write_text(_summary_text(evidence_path), encoding="utf-8")
    generated.append({"path": str(summary), "format": "markdown", "sha256": _sha256(summary), "size_bytes": summary.stat().st_size})
    manifest_path = output_dir / "figures_manifest.json"
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generator": "production.tools.generate_next_tactic_decision_figures",
        "generator_code_sha256": _sha256(Path(__file__)),
        "matplotlib_version": matplotlib.__version__,
        "source_files": [
            {"path": str(evidence_path), "sha256": _sha256(evidence_path), "role": "authoritative final single-checkpoint evaluation"},
        ],
        "checkpoint_sha256": EXPECTED_CHECKPOINT_SHA256,
        "benchmark_values_modified": False,
        "production_modified": False,
        "figures": generated,
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", default=DEFAULT_EVIDENCE)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    manifest = generate(Path(args.evidence), Path(args.output_dir))
    print(json.dumps({"status": "complete", "figure_file_count": len(manifest["figures"]), "output_dir": args.output_dir}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
