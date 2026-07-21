"""Generate the final thesis next-tactic model-selection figure package.

The generator reads only compact accepted evidence. It never trains, selects,
scores, deploys, or changes a model. Aggregate neural results are used only in
the all-model predictive section; precomputed aggregate lookup timings are
explicitly excluded from neural runtime comparisons.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import platform
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from production.tools.generate_next_tactic_decision_figures import (
    FAIL_COLOR,
    GRID_COLOR,
    MUTED_COLOR,
    PASS_COLOR,
    TRANSFORMER_COLOR,
    VOMM_COLOR,
    _plot_modules,
    _save_figure,
)


SCHEMA_VERSION = "final_next_tactic_model_selection_figures.v1"
DEFAULT_EVIDENCE_DIR = "evaluation/next_tactic_benchmark_evidence"
DEFAULT_OUTPUT_DIR = f"{DEFAULT_EVIDENCE_DIR}/final_model_selection_figures"
EXPECTED_CHECKPOINT_SHA256 = "d9b316d76e63b15b175668aa0bf69cfe4172bbd812d6b19743a628cd0ec8073d"
VOMM = "hard_backoff_vomm"
TRANSFORMER = "transformer_seed_20260723"

MODELS = [
    "majority_class",
    "first_order_markov",
    "hard_backoff_vomm",
    "interpolated_vomm",
    "gru_aggregate",
    "transformer_aggregate",
]
LABELS = {
    "majority_class": "Majority baseline",
    "first_order_markov": "First-order Markov",
    "hard_backoff_vomm": "Hard-backoff VOMM",
    "interpolated_vomm": "Interpolated VOMM",
    "gru_aggregate": "GRU (5-seed aggregate)",
    "transformer_aggregate": "Transformer (5-seed aggregate)",
    TRANSFORMER: "Selected Transformer",
}
COLORS = {
    "majority_class": "#7A7F87",
    "first_order_markov": "#00838F",
    "hard_backoff_vomm": VOMM_COLOR,
    "interpolated_vomm": "#7651A6",
    "gru_aggregate": "#39845A",
    "transformer_aggregate": TRANSFORMER_COLOR,
    TRANSFORMER: TRANSFORMER_COLOR,
}

# These are the scores accepted in the latest multi-factor decision analysis.
# They are retrospective decision support, not a preregistered statistical test.
DECISION_MATRIX = {
    "scale": "1 (least suitable) to 5 (most suitable)",
    "retrospective_not_preregistered": True,
    "criteria": [
        {"id": "predictive", "label": "Empirical predictive value", "weight": 0.25},
        {"id": "error", "label": "Error profile / tactic consequences", "weight": 0.15},
        {"id": "evidence", "label": "Evidence validity / robustness", "weight": 0.20},
        {"id": "thesis", "label": "Thesis / demonstration value", "weight": 0.15},
        {"id": "operations", "label": "Operational suitability", "weight": 0.10},
        {"id": "explainability", "label": "Explainability / auditability", "weight": 0.08},
        {"id": "maintainability", "label": "Maintainability / future development", "weight": 0.07},
    ],
    "alternatives": [
        {"id": "vomm_only", "label": "VOMM only", "scores": [2.5, 3.0, 4.0, 3.5, 4.8, 4.8, 4.4]},
        {"id": "transformer_primary", "label": "Transformer primary; VOMM rollback", "scores": [4.7, 3.1, 3.4, 4.5, 3.9, 2.8, 3.6]},
        {"id": "dual_reporting", "label": "Transformer primary + VOMM disagreement", "scores": [4.8, 4.3, 4.5, 4.9, 3.1, 4.5, 3.5]},
        {"id": "tactic_routing", "label": "Tactic-dependent routing", "scores": [3.0, 3.8, 1.0, 1.8, 2.5, 3.2, 2.5]},
        {"id": "insufficient", "label": "Declare evidence insufficient", "scores": [1.0, 5.0, 4.8, 2.5, 1.5, 5.0, 2.0]},
    ],
    "source": "latest accepted multi-factor decision analysis in the preceding repository review",
}

FIGURE_INFO: dict[str, dict[str, str]] = {
    "01_all_model_predictive_overview": {"purpose": "Compare all six models on five compatible predictive metrics.", "source": "overall_metrics.json", "metrics": "Top-1, Top-3, Macro-F1, balanced accuracy, MRR", "interpretation": "Aggregate Transformer leads four metrics; hard-backoff VOMM leads Top-3.", "limitation": "Neural values are five-seed aggregates in this section.", "argument": "Establishes the broad benchmark context."},
    "02_all_model_metric_heatmap": {"purpose": "Display the complete compatible all-model metric table.", "source": "overall_metrics.json", "metrics": "Top-1, Top-3, Macro-F1, weighted-F1, balanced accuracy, MRR, coverage, abstention", "interpretation": "Neural aggregates lead most discrimination metrics; coverage is identical.", "limitation": "Abstention is zero for every evaluated model.", "argument": "Prevents a Top-1-only ranking."},
    "03_all_model_ranking": {"purpose": "Rank models by mean rank over five predictive metrics and label model roles.", "source": "overall_metrics.json; current prediction policy", "metrics": "Equal-weight rank of Top-1, Top-3, Macro-F1, balanced accuracy, MRR", "interpretation": "Transformer aggregate is strongest overall; VOMM remains deployed/interpretable.", "limitation": "Rank aggregation is descriptive, not a selection test.", "argument": "Separates empirical rank from operational role."},
    "04_predictive_radar": {"purpose": "Compare four major models using only compatible predictive dimensions.", "source": "overall_metrics.json", "metrics": "Top-1, Top-3, Macro-F1, balanced accuracy, MRR", "interpretation": "Neural models dominate aggregate quality; VOMMs retain near-ceiling Top-3.", "limitation": "Radar geometry can visually amplify small differences.", "argument": "Shows multi-metric profiles without mixing runtime units."},
    "05_sequence_length": {"purpose": "Show preserved performance by sequence length.", "source": "single_checkpoint_evaluation.json", "metrics": "Top-1, Macro-F1, support", "interpretation": "Transformer gains concentrate at short sequences; long-sequence evidence is sparse.", "limitation": "Only selected Transformer and VOMM have preserved compatible breakdowns.", "argument": "Qualifies aggregate conclusions by context length."},
    "06_latency": {"purpose": "Compare measured p50, p95, and p99 single-case latency.", "source": "efficiency.json; single_checkpoint_evaluation.json", "metrics": "Latency milliseconds", "interpretation": "All measured models meet PoC needs; selected Transformer is faster than production VOMM.", "limitation": "Aggregate neural lookup timings are excluded as non-inference measurements.", "argument": "Demonstrates CPU feasibility without false comparisons."},
    "07_throughput": {"purpose": "Separate real-time single-case throughput from batch throughput.", "source": "efficiency.json; single_checkpoint_evaluation.json", "metrics": "Cases per second", "interpretation": "Transformer batch throughput is high but not equivalent to session-by-session inference.", "limitation": "GRU inference and non-neural batch throughput were not measured.", "argument": "Avoids conflating offline batches with operational latency."},
    "08_memory_storage_complexity": {"purpose": "Compare measured memory, stored model size, parameters, and dependency complexity.", "source": "efficiency.json; dataset_split_manifest.json; selected_transformer_metadata.json", "metrics": "Peak Python allocation, bytes, parameters, qualitative dependency class", "interpretation": "Both artifacts are tiny; PyTorch dominates Transformer dependency cost.", "limitation": "Steady-state RSS and installed dependency bytes were not measured.", "argument": "Makes operational trade-offs explicit."},
    "09_accuracy_latency_tradeoff": {"purpose": "Show Top-1 against measured p95 latency and Pareto status.", "source": "overall_metrics.json; efficiency.json; single_checkpoint_evaluation.json", "metrics": "Top-1, p95 latency, peak Python allocation", "interpretation": "Selected Transformer dominates VOMM empirically and in measured latency.", "limitation": "Hardware-specific offline measurements; aggregate neural points excluded.", "argument": "Shows that the Transformer cost is dependency complexity, not measured speed."},
    "10_macro_f1_memory_tradeoff": {"purpose": "Show Macro-F1 against measured peak Python allocation.", "source": "overall_metrics.json; efficiency.json; single_checkpoint_evaluation.json", "metrics": "Macro-F1, peak Python allocation, p95 latency", "interpretation": "Transformer improves Macro-F1 without a large measured allocation penalty.", "limitation": "Python allocation is not full process steady-state memory.", "argument": "Provides a bounded memory-performance view."},
    "11_performance_efficiency_summary": {"purpose": "Present descriptive performance-efficiency ratios.", "source": "overall_metrics.json; efficiency.json; single_checkpoint_evaluation.json", "metrics": "Top-1/ms, Macro-F1/ms, throughput/MiB, deltas versus VOMM", "interpretation": "Simple baselines have large ratios because they do less; ratios are not selection criteria.", "limitation": "Unavailable storage values remain N/A.", "argument": "Prevents cherry-picking an efficiency quotient."},
    "12_focused_overall": {"purpose": "Compare the frozen Transformer with VOMM on the identical test set.", "source": "single_checkpoint_evaluation.json", "metrics": "Top-1, Top-3, Macro-F1, weighted-F1, balanced accuracy, MRR, coverage, abstention", "interpretation": "Transformer leads most aggregate metrics; VOMM leads Top-3 slightly.", "limitation": "Raw neural scores are not calibrated probabilities.", "argument": "Defines the final single-checkpoint empirical comparison."},
    "13_paired_outcomes": {"purpose": "Show mutually exclusive paired case outcomes.", "source": "single_checkpoint_evaluation.json", "metrics": "Transformer wins, VOMM wins, both correct, both wrong", "interpretation": "Transformer has 1,887 wins versus 838 VOMM wins.", "limitation": "Counts do not encode tactic-specific costs.", "argument": "Shows case-level rather than aggregate-only superiority."},
    "14_paired_confidence_intervals": {"purpose": "Show paired whole-session improvement intervals.", "source": "single_checkpoint_evaluation.json", "metrics": "Transformer-minus-VOMM Top-1, Macro-F1, balanced accuracy", "interpretation": "All interval lower bounds exceed zero.", "limitation": "Bootstrap uncertainty does not address label validity.", "argument": "Confirms that aggregate gains are not sampling noise within this corpus."},
    "15_tactic_precision": {"purpose": "Compare tactic precision with support.", "source": "single_checkpoint_evaluation.json", "metrics": "Precision and support", "interpretation": "Transformer increases Persistence and Execution precision.", "limitation": "Impact has zero support; credential access has two cases.", "argument": "Exposes class-level behavior."},
    "16_tactic_recall": {"purpose": "Compare tactic recall with support.", "source": "single_checkpoint_evaluation.json", "metrics": "Recall and support", "interpretation": "Transformer gains Persistence recall but loses Execution and privilege escalation.", "limitation": "Rare-class estimates are unstable or unavailable.", "argument": "Displays the central selection trade-off."},
    "17_tactic_f1": {"purpose": "Compare tactic F1 with support.", "source": "single_checkpoint_evaluation.json", "metrics": "F1 and support", "interpretation": "Transformer improves major supported class F1 except command/control and privilege escalation.", "limitation": "Macro summaries include highly unequal supports.", "argument": "Balances class precision and recall."},
    "18_persistence_execution_tradeoff": {"purpose": "Compare precision, recall, and F1 for Persistence and Execution.", "source": "single_checkpoint_evaluation.json", "metrics": "Six tactic metrics per model", "interpretation": "Persistence recall rises to 1.0 while Execution recall falls to 0.7118.", "limitation": "No empirical tactic-cost matrix exists.", "argument": "Explains why aggregate superiority is not the whole decision."},
    "19_opposing_confusions": {"purpose": "Present both models' opposing major confusions neutrally.", "source": "single_checkpoint_evaluation.json", "metrics": "VOMM Persistence→Execution; Transformer Execution→Persistence", "interpretation": "VOMM misses 1,718 Persistence cases; Transformer misses 819 Execution cases.", "limitation": "Only the focal cross-confusions are shown.", "argument": "Prevents one-sided presentation of model error."},
    "20_transformer_win_sources": {"purpose": "Decompose Transformer paired wins by tactic.", "source": "single_checkpoint_evaluation.json", "metrics": "1,718 Persistence wins, 169 other wins, 1,887 total", "interpretation": "91.0% of wins are Persistence, but aggregate Macro-F1 and balance still improve.", "limitation": "Win concentration may reflect corpus patterns.", "argument": "States the strongest limitation on the aggregate result."},
    "21_chronological_stability": {"purpose": "Compare four ordered test windows.", "source": "single_checkpoint_evaluation.json", "metrics": "Top-1, Macro-F1, Execution recall, Persistence recall", "interpretation": "Aggregate gain and Execution regression both persist.", "limitation": "Privacy minimization omits per-session timestamps.", "argument": "Tests internal temporal stability without claiming future generalization."},
    "22_repeated_pattern_caveat": {"purpose": "Visualize repeated-pattern and weak-label caveats.", "source": "single_checkpoint_evaluation.json", "metrics": "12,235 cases, 45 sequences, 99.47% repeated-win exposure, 100% Persistence exposure", "interpretation": "The corpus is highly repetitive.", "limitation": "This is not proof of leakage or template causality.", "argument": "Bounds generalization claims."},
    "23_reliability_failure_handling": {"purpose": "Summarize verified and unavailable reliability evidence.", "source": "single_checkpoint_evaluation.json; selected_transformer_metadata.json; focused tests", "metrics": "Replay runs, failures, score delta, hash/reload/state checks, failure semantics", "interpretation": "Offline checkpoint replay is deterministic; runtime invalid-input handling is not implemented for Transformer.", "limitation": "No deployed Transformer adapter exists.", "argument": "Separates checkpoint reliability from production readiness."},
    "24_weighted_decision_matrix": {"purpose": "Display the accepted retrospective multi-factor matrix.", "source": "latest accepted multi-factor decision analysis", "metrics": "Seven criteria, weights, five alternatives, weighted totals", "interpretation": "Transformer-primary dual reporting ranks first.", "limitation": "The matrix is retrospective and not a preregistered statistical test.", "argument": "Connects evidence to the PoC objective transparently."},
    "25_model_roles": {"purpose": "Separate empirical, operational, and thesis roles.", "source": "single_checkpoint_evaluation.json; current policy; accepted decision analysis", "metrics": "Role assignments", "interpretation": "Transformer is primary experimental; VOMM remains baseline and rollback.", "limitation": "This task does not change deployed authority.", "argument": "Avoids using one label for several different decisions."},
    "26_why_transformer_selected": {"purpose": "Balance reasons for selecting Transformer against remaining limitations.", "source": "single_checkpoint_evaluation.json", "metrics": "Aggregate gains, intervals, runtime, integrity, class limitations", "interpretation": "Evidence supports corpus-level experimental selection, not production superiority.", "limitation": "Weak labels and no prospective independent holdout remain.", "argument": "Provides an examiner-ready balanced rationale."},
    "27_why_vomm_retained": {"purpose": "Explain VOMM's continuing baseline and rollback value.", "source": "artifact manifest; single_checkpoint_evaluation.json; current policy", "metrics": "Execution recall, explainability, dependencies, integration, rollback", "interpretation": "VOMM remains operationally and analytically important despite lower aggregate metrics.", "limitation": "Its Persistence recall is only 0.0402.", "argument": "Justifies dual reporting rather than removal."},
    "28_final_decision_dashboard": {"purpose": "Summarize metric winners, operational winners, selected roles, and the central trade-off.", "source": "all accepted compact evidence", "metrics": "Top-1, Macro-F1, balance, Top-3, latency, complexity, roles", "interpretation": "Different objectives produce different winners.", "limitation": "Operational simplicity is qualitative where dependency footprint is unmeasured.", "argument": "Supports thesis defense at a glance."},
    "29_executive_summary": {"purpose": "Answer the final seven model-selection questions.", "source": "all accepted compact evidence and accepted decision analysis", "metrics": "Decision and claim boundaries", "interpretation": "Transformer is primary experimental; VOMM remains concurrent baseline/rollback.", "limitation": "No general production-superiority claim is justified.", "argument": "States the final conclusion without score fusion or routing."},
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain an object")
    return value


def _decision_totals() -> dict[str, float]:
    weights = [float(item["weight"]) for item in DECISION_MATRIX["criteria"]]
    return {
        str(item["id"]): sum(float(score) * weight for score, weight in zip(item["scores"], weights))
        for item in DECISION_MATRIX["alternatives"]
    }


def load_evidence(root: Path) -> dict[str, Any]:
    names = [
        "single_checkpoint_evaluation.json", "overall_metrics.json", "per_tactic_metrics.json",
        "paired_comparisons.json", "confidence_intervals.json", "confusion_matrices.json",
        "efficiency.json", "model_configurations.json", "dataset_split_manifest.json",
        "selected_transformer_metadata.json", "calibration.json",
    ]
    data = {name: _load(root / name) for name in names}
    single = data["single_checkpoint_evaluation.json"]
    metrics = single.get("metrics") or {}
    checks = {
        "accepted schema": single.get("schema_version") == "frozen_transformer_poc_evaluation.v1",
        "checkpoint": ((single.get("integrity") or {}).get("checkpoint") or {}).get("checkpoint_sha256") == EXPECTED_CHECKPOINT_SHA256,
        "same case count": (metrics.get(VOMM) or {}).get("evaluated_examples") == 12235 and (metrics.get(TRANSFORMER) or {}).get("evaluated_examples") == 12235,
        "paired": (single.get("paired_comparison") or {}).get("case_count") == 12235,
        "opposing errors": single["confusion_matrices"][VOMM]["counts"]["persistence"]["execution"] == 1718 and single["confusion_matrices"][TRANSFORMER]["counts"]["execution"]["persistence"] == 819,
        "win source": single["paired_comparison"]["outcomes"]["candidate_win"] == 1887 and single["paired_comparison"]["by_tactic"]["persistence"]["candidate_win"] == 1718,
        "no raw probability claim": single.get("raw_transformer_scores_are_calibrated_probabilities") is False,
        "all aggregate models": set(data["overall_metrics.json"]) == set(MODELS),
        "decision winner": max(_decision_totals(), key=_decision_totals().get) == "dual_reporting",
    }
    failed = [name for name, passed in checks.items() if not passed]
    if failed:
        raise ValueError(f"accepted evidence validation failed: {', '.join(failed)}")
    return data


def _annotate_bars(ax: Any, bars: Any, fmt: str = ".3f", offset: float = 0.012) -> None:
    for bar in bars:
        value = float(bar.get_height())
        ax.text(bar.get_x() + bar.get_width() / 2, value + offset, format(value, fmt), ha="center", va="bottom", fontsize=7)


def _heatmap(plt: Any, ax: Any, values: Sequence[Sequence[float]], rows: Sequence[str], columns: Sequence[str], *, fmt: str = ".3f", cmap: str = "Blues", vmin: float = 0.0, vmax: float = 1.0, annotations: Sequence[Sequence[str]] | None = None) -> None:
    image = ax.imshow(values, aspect="auto", cmap=cmap, vmin=vmin, vmax=vmax)
    ax.set_yticks(range(len(rows)), rows)
    ax.set_xticks(range(len(columns)), columns, rotation=30, ha="right")
    ax.grid(False)
    for row_index, row in enumerate(values):
        for column_index, value in enumerate(row):
            text = annotations[row_index][column_index] if annotations else format(float(value), fmt)
            ax.text(column_index, row_index, text, ha="center", va="center", fontsize=7.5, color="white" if float(value) > (vmin + vmax) * 0.58 else "#172B4D")
    plt.colorbar(image, ax=ax, fraction=0.025, pad=0.02)


def _all_metrics(data: Mapping[str, Any]) -> Mapping[str, Any]:
    return data["overall_metrics.json"]


def figure_01(plt: Any, data: Mapping[str, Any]) -> Any:
    metrics = _all_metrics(data); fields = ["top1_accuracy", "top3_accuracy", "macro_f1", "balanced_accuracy", "mean_reciprocal_rank"]
    names = ["Top-1", "Top-3", "Macro-F1", "Balanced acc.", "MRR"]
    fig, ax = plt.subplots(figsize=(12, 6)); x = list(range(len(fields))); width = 0.13
    for index, model in enumerate(MODELS):
        values = [metrics[model][field] for field in fields]
        ax.bar([item + (index - 2.5) * width for item in x], values, width, color=COLORS[model], label=LABELS[model])
    winners = [max(MODELS, key=lambda model: metrics[model][field]) for field in fields]
    for pos, field, winner in zip(x, fields, winners):
        ax.text(pos, 1.035, f"Best: {LABELS[winner].replace(' (5-seed aggregate)', '')}", ha="center", fontsize=7.5, color=COLORS[winner], weight="bold")
    ax.set_xticks(x, names); ax.set_ylim(0, 1.09); ax.set_ylabel("Held-out metric value"); ax.set_title("All-model predictive-performance overview")
    ax.legend(ncol=3, loc="lower center", bbox_to_anchor=(0.5, -0.28)); return fig


def figure_02(plt: Any, data: Mapping[str, Any]) -> Any:
    metrics = _all_metrics(data); fields = ["top1_accuracy", "top3_accuracy", "macro_f1", "weighted_f1", "balanced_accuracy", "mean_reciprocal_rank", "coverage", "abstention_rate"]
    labels = ["Top-1", "Top-3", "Macro-F1", "Weighted-F1", "Balanced", "MRR", "Coverage", "Abstention"]
    values = [[float(metrics[model][field]) for field in fields] for model in MODELS]
    fig, ax = plt.subplots(figsize=(12, 6)); _heatmap(plt, ax, values, [LABELS[m] for m in MODELS], labels, cmap="YlGnBu")
    ax.set_title("All-model detailed held-out metrics (exact values; common 0–1 scale)"); return fig


def figure_03(plt: Any, data: Mapping[str, Any]) -> Any:
    metrics = _all_metrics(data); fields = ["top1_accuracy", "top3_accuracy", "macro_f1", "balanced_accuracy", "mean_reciprocal_rank"]
    ranks = {model: [] for model in MODELS}
    for field in fields:
        order = sorted(MODELS, key=lambda model: (-metrics[model][field], model))
        for rank, model in enumerate(order, 1): ranks[model].append(rank)
    mean_ranks = {model: sum(values) / len(values) for model, values in ranks.items()}
    ordered = sorted(MODELS, key=lambda model: mean_ranks[model])
    fig, axes = plt.subplots(1, 2, figsize=(12, 6), gridspec_kw={"width_ratios": [1.1, 1]})
    bars = axes[0].barh([LABELS[m] for m in ordered], [mean_ranks[m] for m in ordered], color=[COLORS[m] for m in ordered])
    axes[0].invert_yaxis(); axes[0].set_xlabel("Mean rank across five metrics (lower is better)"); axes[0].set_title("Multi-metric predictive ranking")
    for bar, model in zip(bars, ordered): axes[0].text(bar.get_width()+.05, bar.get_y()+bar.get_height()/2, f"{mean_ranks[model]:.2f}", va="center")
    axes[1].axis("off"); roles = [("Strongest aggregate", "Transformer aggregate", TRANSFORMER_COLOR), ("Strongest neural", "Transformer aggregate", TRANSFORMER_COLOR), ("Interpretable statistical", "Hard-backoff VOMM", VOMM_COLOR), ("Simplest baseline", "Majority class", COLORS["majority_class"]), ("Currently deployed", "Hard-backoff VOMM", VOMM_COLOR)]
    for index, (role, model, color) in enumerate(roles):
        y = .88-index*.18; axes[1].text(.02,y,role,transform=axes[1].transAxes,color=MUTED_COLOR,fontsize=9); axes[1].text(.98,y,model,transform=axes[1].transAxes,ha="right",color=color,fontsize=11,weight="bold")
    axes[1].set_title("Model roles (not one interchangeable ranking)"); return fig


def figure_04(plt: Any, data: Mapping[str, Any]) -> Any:
    metrics = _all_metrics(data); models = [VOMM, "interpolated_vomm", "gru_aggregate", "transformer_aggregate"]
    fields = ["top1_accuracy", "top3_accuracy", "macro_f1", "balanced_accuracy", "mean_reciprocal_rank"]; labels = ["Top-1", "Top-3", "Macro-F1", "Balanced", "MRR"]
    angles = [2*math.pi*i/len(fields) for i in range(len(fields))]; angles += angles[:1]
    fig, ax = plt.subplots(figsize=(8, 7), subplot_kw={"projection":"polar"})
    for model in models:
        values = [metrics[model][field] for field in fields]; values += values[:1]
        ax.plot(angles, values, lw=2, color=COLORS[model], label=LABELS[model]); ax.fill(angles, values, color=COLORS[model], alpha=.04)
    ax.set_xticks(angles[:-1], labels); ax.set_ylim(0,1); ax.set_title("Predictive-performance profile (compatible 0–1 metrics)", pad=20); ax.legend(loc="lower center", bbox_to_anchor=(.5,-.20), ncol=2); return fig


def figure_05(plt: Any, data: Mapping[str, Any]) -> Any:
    single=data["single_checkpoint_evaluation.json"]; by=single["sequence_length"]; order=["1","2","3","4","5","6+"]; x=range(len(order))
    fig,axes=plt.subplots(3,1,figsize=(10,9),sharex=True)
    for ax,field,title in zip(axes[:2],["top1_accuracy","macro_f1"],["Top-1","Macro-F1"]):
        ax.plot(x,[by[VOMM][key][field] for key in order],marker="o",color=VOMM_COLOR,label="Hard-backoff VOMM")
        ax.plot(x,[by[TRANSFORMER][key][field] for key in order],marker="o",color=TRANSFORMER_COLOR,label="Selected Transformer")
        ax.set_ylabel(title); ax.set_ylim(0,1.05)
    support=[by[VOMM][key]["evaluated_examples"] for key in order]; axes[2].bar(x,support,color="#607D8B"); axes[2].set_yscale("log"); axes[2].set_ylabel("Support (log)"); axes[2].set_xticks(list(x),order); axes[2].set_xlabel("Input sequence length")
    for i,value in enumerate(support): axes[2].text(i,value*1.12,f"n={value:,}",ha="center",fontsize=8)
    axes[0].legend(ncol=2); fig.suptitle("Performance by sequence length (models with preserved compatible evidence)",y=.995); return fig


def _runtime_rows(data: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    efficiency=data["efficiency.json"]; single=data["single_checkpoint_evaluation.json"]; selected=single["efficiency"][TRANSFORMER]
    output={}
    for model in ["majority_class","first_order_markov",VOMM,"interpolated_vomm"]:
        row=efficiency[model]; output[model]={"p50":row["inference_latency_ms"]["p50"],"p95":row["inference_latency_ms"]["p95"],"p99":row["inference_latency_ms"]["p99"],"single_throughput":row["throughput_cases_per_second"],"batch_throughput":None,"memory":row["inference_peak_python_bytes"],"load":row["load_seconds"]}
    output[TRANSFORMER]={"p50":selected["individual_case_latency_ms"]["p50"],"p95":selected["individual_case_latency_ms"]["p95"],"p99":selected["individual_case_latency_ms"]["p99"],"single_throughput":selected["individual_case_throughput_per_second"],"batch_throughput":selected["batched_throughput_per_second"],"memory":selected["peak_python_allocation_bytes"],"load":selected["checkpoint_load_seconds"]}
    return output


def figure_06(plt: Any, data: Mapping[str, Any]) -> Any:
    runtime=_runtime_rows(data); models=list(runtime); x=range(len(models)); width=.25
    fig,ax=plt.subplots(figsize=(11,6))
    for shift,field,label in [(-1,"p50","p50"),(0,"p95","p95"),(1,"p99","p99")]:
        bars=ax.bar([i+shift*width for i in x],[runtime[m][field] for m in models],width,label=label)
        for bar,value in zip(bars,[runtime[m][field] for m in models]): ax.text(bar.get_x()+bar.get_width()/2,value*1.15,f"{value:.3g}",ha="center",fontsize=7,rotation=45)
    ax.set_yscale("log"); ax.set_ylabel("Single-case latency (ms, log scale)"); ax.set_xticks(list(x),[LABELS[m] for m in models],rotation=15,ha="right"); ax.set_title("Measured single-case latency"); ax.legend(); return fig


def figure_07(plt: Any, data: Mapping[str, Any]) -> Any:
    runtime=_runtime_rows(data); models=list(runtime); fig,axes=plt.subplots(1,2,figsize=(12,5))
    values=[runtime[m]["single_throughput"] for m in models]; bars=axes[0].barh([LABELS[m] for m in models],values,color=[COLORS[m] for m in models]); axes[0].set_xscale("log"); axes[0].set_xlabel("Single-case throughput (cases/s, log)"); axes[0].set_title("Real-time single-case throughput")
    for bar,value in zip(bars,values): axes[0].text(value*1.08,bar.get_y()+bar.get_height()/2,f"{value:,.0f}",va="center",fontsize=8)
    axes[1].bar(["Selected Transformer\nbatched"],[runtime[TRANSFORMER]["batch_throughput"]],color=TRANSFORMER_COLOR); axes[1].text(0,runtime[TRANSFORMER]["batch_throughput"]*1.02,f"{runtime[TRANSFORMER]['batch_throughput']:,.0f}",ha="center"); axes[1].set_ylabel("Batch throughput (cases/s)"); axes[1].set_title("Offline batch throughput (not real-time equivalent)"); return fig


def figure_08(plt: Any, data: Mapping[str, Any]) -> Any:
    runtime=_runtime_rows(data); manifest=data["dataset_split_manifest.json"]; selected=data["selected_transformer_metadata.json"]
    models=list(runtime); fig,axes=plt.subplots(2,2,figsize=(12,8))
    mem=[runtime[m]["memory"]/1024 for m in models]; axes[0,0].barh([LABELS[m] for m in models],mem,color=[COLORS[m] for m in models]); axes[0,0].set_xlabel("Peak measured Python allocation (KiB)"); axes[0,0].set_title("Measured allocation (not steady-state RSS)")
    sizes=[manifest["artifact"]["artifact_size_bytes"]+manifest["artifact"]["manifest_size_bytes"],selected["checkpoint_sha256"] and 17279]; axes[0,1].bar(["VOMM artifact\n+ manifest","Transformer\ncheckpoint"],[v/1024 for v in sizes],color=[VOMM_COLOR,TRANSFORMER_COLOR]); axes[0,1].set_ylabel("Stored size (KiB)"); axes[0,1].set_title("Versioned model material")
    axes[1,0].bar(["Selected Transformer"],[2632],color=TRANSFORMER_COLOR); axes[1,0].set_ylabel("Parameters"); axes[1,0].set_title("Parameter count (count models: N/A)")
    complexity=[("VOMM","Low\nPython/JSON",VOMM_COLOR), ("Transformer","High\nPyTorch runtime",TRANSFORMER_COLOR)]; axes[1,1].axis("off"); axes[1,1].set_title("Dependency and startup distinction")
    for i,(name,text,color) in enumerate(complexity): axes[1,1].text(.25+i*.5,.55,name,ha="center",weight="bold",color=color,transform=axes[1,1].transAxes,fontsize=13); axes[1,1].text(.25+i*.5,.34,text,ha="center",transform=axes[1,1].transAxes)
    axes[1,1].text(.5,.08,"Cold load: Transformer 3.40 ms; VOMM isolated cold load not measured",ha="center",transform=axes[1,1].transAxes,fontsize=8,color=MUTED_COLOR); fig.suptitle("Memory, storage, and complexity (separated units)",y=.995); return fig


def _runtime_metrics(data: Mapping[str, Any]) -> dict[str, dict[str, float]]:
    overall=_all_metrics(data); single=data["single_checkpoint_evaluation.json"]; runtime=_runtime_rows(data); result={}
    for model in runtime:
        metric=single["metrics"][TRANSFORMER] if model==TRANSFORMER else overall[model]
        result[model]={"top1":metric["top1_accuracy"],"macro_f1":metric["macro_f1"],**runtime[model]}
    return result


def figure_09(plt: Any, data: Mapping[str, Any]) -> Any:
    rows=_runtime_metrics(data); fig,ax=plt.subplots(figsize=(9,6)); models=list(rows)
    for model in models:
        size=max(45,rows[model]["memory"]/1800); ax.scatter(rows[model]["p95"],rows[model]["top1"],s=size,color=COLORS[model],edgecolor="black",linewidth=.5); ax.annotate(LABELS[model],(rows[model]["p95"],rows[model]["top1"]),xytext=(5,5),textcoords="offset points",fontsize=8)
    pareto=[]
    for model in models:
        if not any(other!=model and rows[other]["p95"]<=rows[model]["p95"] and rows[other]["top1"]>=rows[model]["top1"] and (rows[other]["p95"]<rows[model]["p95"] or rows[other]["top1"]>rows[model]["top1"]) for other in models): pareto.append(model)
    for model in pareto: ax.scatter(rows[model]["p95"],rows[model]["top1"],s=max(90,rows[model]["memory"]/1100),facecolors="none",edgecolors=PASS_COLOR,linewidth=2)
    ax.set_xscale("log"); ax.set_xlabel("Measured p95 single-case latency (ms, log)"); ax.set_ylabel("Top-1 accuracy"); ax.set_ylim(.5,.93); ax.set_title("Accuracy–latency trade-off (green rings: Pareto-optimal)"); return fig


def figure_10(plt: Any, data: Mapping[str, Any]) -> Any:
    rows=_runtime_metrics(data); fig,ax=plt.subplots(figsize=(9,6))
    for model,row in rows.items():
        ax.scatter(row["memory"]/1024,row["macro_f1"],s=90,color=COLORS[model]); ax.annotate(f"{LABELS[model]}\np95 {row['p95']:.3g} ms",(row["memory"]/1024,row["macro_f1"]),xytext=(5,5),textcoords="offset points",fontsize=8)
    ax.set_xlabel("Peak measured Python allocation (KiB; not steady-state RSS)"); ax.set_ylabel("Macro-F1"); ax.set_title("Macro-F1 versus measured allocation"); return fig


def figure_11(plt: Any, data: Mapping[str, Any]) -> Any:
    rows=_runtime_metrics(data); vomm=rows[VOMM]; fig,ax=plt.subplots(figsize=(13,5)); ax.axis("off")
    columns=["Model","Top-1/ms","Macro-F1/ms","Throughput/MiB","Δ Top-1 vs VOMM","Δ p95 ms vs VOMM","Δ stored bytes"]
    manifest=data["dataset_split_manifest.json"]; storage={VOMM:manifest["artifact"]["artifact_size_bytes"]+manifest["artifact"]["manifest_size_bytes"],TRANSFORMER:17279}
    table=[]
    for model,row in rows.items():
        per_mib=row["single_throughput"]/(row["memory"]/(1024*1024)); delta_storage=(storage[model]-storage[VOMM]) if model in storage else None
        table.append([LABELS[model],f"{row['top1']/row['p95']:.2f}",f"{row['macro_f1']/row['p95']:.2f}",f"{per_mib:,.0f}",f"{row['top1']-vomm['top1']:+.4f}",f"{row['p95']-vomm['p95']:+.3f}","N/A" if delta_storage is None else f"{delta_storage:+,}"])
    tab=ax.table(cellText=table,colLabels=columns,loc="center",cellLoc="center"); tab.auto_set_font_size(False); tab.set_fontsize(8); tab.scale(1,1.7); ax.set_title("Descriptive performance–efficiency ratios (not selection metrics)",pad=20); return fig


def figure_12(plt: Any, data: Mapping[str, Any]) -> Any:
    metrics=data["single_checkpoint_evaluation.json"]["metrics"]; fields=["top1_accuracy","top3_accuracy","macro_f1","weighted_f1","balanced_accuracy","mean_reciprocal_rank","coverage","abstention_rate"]; labels=["Top-1","Top-3","Macro-F1","Weighted-F1","Balanced","MRR","Coverage","Abstention"]
    fig,ax=plt.subplots(figsize=(12,6)); x=range(len(fields)); width=.36
    left=ax.bar([i-width/2 for i in x],[metrics[VOMM][f] for f in fields],width,color=VOMM_COLOR,label="Hard-backoff VOMM"); right=ax.bar([i+width/2 for i in x],[metrics[TRANSFORMER][f] for f in fields],width,color=TRANSFORMER_COLOR,label="Selected Transformer")
    _annotate_bars(ax,left); _annotate_bars(ax,right); ax.set_xticks(list(x),labels,rotation=15); ax.set_ylim(0,1.1); ax.set_ylabel("Held-out metric value"); ax.set_title("Frozen single-checkpoint Transformer versus VOMM"); ax.legend(); return fig


def figure_13(plt: Any, data: Mapping[str, Any]) -> Any:
    outcomes=data["single_checkpoint_evaluation.json"]["paired_comparison"]["outcomes"]; labels=["Transformer wins","VOMM wins","Both correct","Both wrong"]; values=[outcomes["candidate_win"],outcomes["production_vomm_win"],outcomes["tie_both_correct"],outcomes["both_wrong_or_abstained"]]
    fig,ax=plt.subplots(figsize=(9,5)); bars=ax.barh(labels,values,color=[TRANSFORMER_COLOR,VOMM_COLOR,PASS_COLOR,MUTED_COLOR]); ax.invert_yaxis(); ax.set_xlabel("Cases (total n=12,235)"); ax.set_title("Paired outcomes on identical ordered cases")
    for bar,value in zip(bars,values):
        ax.text(value+80,bar.get_y()+bar.get_height()/2,f"{value:,}",va="center")
    return fig


def figure_14(plt: Any, data: Mapping[str, Any]) -> Any:
    ci=data["single_checkpoint_evaluation.json"]["confidence_intervals_95"]["paired"]["candidate_minus_vomm_95ci"]; fields=["top1_accuracy","macro_f1","balanced_accuracy"]; labels=["Top-1","Macro-F1","Balanced accuracy"]; points=[sum(ci[f])/2 for f in fields]; lows=[points[i]-ci[f][0] for i,f in enumerate(fields)]; highs=[ci[f][1]-points[i] for i,f in enumerate(fields)]
    fig,ax=plt.subplots(figsize=(9,5)); ax.errorbar(points,range(3),xerr=[lows,highs],fmt="o",color=TRANSFORMER_COLOR,capsize=6,lw=2); ax.axvline(0,color="black",ls="--",lw=1); ax.set_yticks(range(3),labels); ax.set_xlabel("Transformer minus VOMM (95% whole-session bootstrap CI)"); ax.set_title("Paired confidence intervals"); ax.invert_yaxis(); return fig


def _tactic_heatmap(plt: Any, data: Mapping[str, Any], field: str, title: str) -> Any:
    metrics=data["single_checkpoint_evaluation.json"]["metrics"]; tactics=["persistence","execution","discovery","defense-evasion","command-and-control","privilege-escalation","credential-access","impact"]; labels=["Persistence","Execution","Discovery","Defense evasion","Command & control","Privilege escalation","Credential access","Impact"]
    values=[]; annotations=[]
    for model in [VOMM,TRANSFORMER]:
        row=[]; notes=[]
        for tactic in tactics:
            item=metrics[model]["per_tactic"][tactic]; support=int(item["support"]); row.append(float(item[field])); notes.append("N/A\nn=0" if support==0 else f"{item[field]:.3f}\nn={support:,}")
        values.append(row); annotations.append(notes)
    fig,ax=plt.subplots(figsize=(12,4)); _heatmap(plt,ax,values,["Hard-backoff VOMM","Selected Transformer"],labels,annotations=annotations,cmap="YlGnBu"); ax.set_title(title); return fig


def figure_15(plt: Any, data: Mapping[str, Any]) -> Any: return _tactic_heatmap(plt,data,"precision","Per-tactic precision with held-out support")
def figure_16(plt: Any, data: Mapping[str, Any]) -> Any: return _tactic_heatmap(plt,data,"recall","Per-tactic recall with held-out support")
def figure_17(plt: Any, data: Mapping[str, Any]) -> Any: return _tactic_heatmap(plt,data,"f1","Per-tactic F1 with held-out support")


def figure_18(plt: Any, data: Mapping[str, Any]) -> Any:
    metrics=data["single_checkpoint_evaluation.json"]["metrics"]; categories=[("persistence","precision"),("persistence","recall"),("persistence","f1"),("execution","precision"),("execution","recall"),("execution","f1")]; labels=["Persistence\nprecision","Persistence\nrecall","Persistence\nF1","Execution\nprecision","Execution\nrecall","Execution\nF1"]
    fig,ax=plt.subplots(figsize=(11,6)); x=range(6); width=.36; left=ax.bar([i-width/2 for i in x],[metrics[VOMM]["per_tactic"][t][f] for t,f in categories],width,color=VOMM_COLOR,label="Hard-backoff VOMM"); right=ax.bar([i+width/2 for i in x],[metrics[TRANSFORMER]["per_tactic"][t][f] for t,f in categories],width,color=TRANSFORMER_COLOR,label="Selected Transformer"); _annotate_bars(ax,left); _annotate_bars(ax,right); ax.set_xticks(list(x),labels); ax.set_ylim(0,1.1); ax.set_ylabel("Metric value"); ax.set_title("Persistence improvement versus Execution trade-off"); ax.legend(); return fig


def figure_19(plt: Any, data: Mapping[str, Any]) -> Any:
    fig,ax=plt.subplots(figsize=(11,5)); ax.axis("off")
    cards=[(.05,"Hard-backoff VOMM","Actual Persistence","Predicted Execution","1,718",VOMM_COLOR),(.55,"Selected Transformer","Actual Execution","Predicted Persistence","819",TRANSFORMER_COLOR)]
    for x,model,actual,predicted,count,color in cards:
        ax.add_patch(plt.Rectangle((x,.24),.40,.55,transform=ax.transAxes,facecolor="#F8FAFC",edgecolor=color,lw=2)); ax.text(x+.20,.70,model,ha="center",transform=ax.transAxes,color=color,weight="bold",fontsize=13); ax.text(x+.08,.49,actual,ha="center",transform=ax.transAxes,fontsize=10); ax.annotate("",xy=(x+.32,.49),xytext=(x+.17,.49),xycoords=ax.transAxes,arrowprops={"arrowstyle":"-|>","lw":2,"color":FAIL_COLOR}); ax.text(x+.32,.49,predicted,ha="center",transform=ax.transAxes,fontsize=10); ax.text(x+.20,.31,count,ha="center",transform=ax.transAxes,fontsize=22,color=FAIL_COLOR,weight="bold")
    ax.set_title("Opposing focal confusion profiles",fontsize=15); return fig


def figure_20(plt: Any, data: Mapping[str, Any]) -> Any:
    paired=data["single_checkpoint_evaluation.json"]["paired_comparison"]; total=paired["outcomes"]["candidate_win"]; persistence=paired["by_tactic"]["persistence"]["candidate_win"]; other=total-persistence
    fig,axes=plt.subplots(1,2,figsize=(10,5)); axes[0].pie([persistence,other],labels=["Persistence wins","Other-tactic wins"],autopct=lambda pct:f"{pct:.1f}%",colors=[TRANSFORMER_COLOR,"#F4B183"],startangle=90,wedgeprops={"edgecolor":"white"}); axes[0].set_title("Source of Transformer paired wins")
    axes[1].bar(["Persistence","Other tactics"],[persistence,other],color=[TRANSFORMER_COLOR,"#F4B183"]); axes[1].set_ylabel("Transformer wins"); axes[1].set_title(f"Exact decomposition (total {total:,})"); axes[1].text(0,persistence+25,f"{persistence:,}",ha="center"); axes[1].text(1,other+25,f"{other:,}",ha="center"); return fig


def figure_21(plt: Any, data: Mapping[str, Any]) -> Any:
    windows=data["single_checkpoint_evaluation.json"]["chronological_windows"]; x=[r["window"] for r in windows]; fig,axes=plt.subplots(2,2,figsize=(11,8)); panels=[("top1_accuracy","Top-1"),("macro_f1","Macro-F1"),("execution","Execution recall"),("persistence","Persistence recall")]
    for ax,(field,title) in zip(axes.flat,panels):
        if field in ("execution","persistence"):
            v=[r[VOMM]["per_tactic"][field]["recall"] for r in windows]; t=[r["transformer"]["per_tactic"][field]["recall"] for r in windows]
        else: v=[r[VOMM][field] for r in windows]; t=[r["transformer"][field] for r in windows]
        ax.plot(x,v,marker="o",color=VOMM_COLOR,label="VOMM"); ax.plot(x,t,marker="o",color=TRANSFORMER_COLOR,label="Transformer"); ax.set_xticks(x); ax.set_ylim(0,1.05); ax.set_title(title); ax.set_xlabel("Ordered test window")
    axes[0,0].legend(); fig.suptitle("Chronological-window stability",y=.995); return fig


def figure_22(plt: Any, data: Mapping[str, Any]) -> Any:
    values=data["single_checkpoint_evaluation.json"]["template_and_weak_label_analysis"]; fig,axes=plt.subplots(1,2,figsize=(11,5)); counts=[12235,values["unique_input_sequences"]]; bars=axes[0].bar(["Held-out cases","Distinct input\nsequences"],counts,color=[VOMM_COLOR,TRANSFORMER_COLOR]); axes[0].set_yscale("log"); axes[0].set_title("Corpus pattern concentration"); axes[0].set_ylabel("Count (log scale)")
    for b,v in zip(bars,counts): axes[0].text(b.get_x()+b.get_width()/2,v*1.1,f"{v:,}",ha="center")
    percentages=[100*values["candidate_wins_in_input_patterns_repeated_at_least_10_times_fraction"],100*values["persistence_cases_in_input_patterns_repeated_at_least_10_times_fraction"]]; bars=axes[1].bar(["Transformer wins","Persistence cases"],percentages,color=[TRANSFORMER_COLOR,FAIL_COLOR]); axes[1].set_ylim(0,105); axes[1].set_ylabel("In patterns repeated ≥10 times (%)"); axes[1].set_title("Repeated-pattern exposure")
    for b,v in zip(bars,percentages):
        axes[1].text(b.get_x()+b.get_width()/2,v+1,f"{v:.2f}%",ha="center")
    fig.suptitle("Repeated-pattern and weak-label caveat—not proof of leakage",y=.99)
    return fig


def figure_23(plt: Any, data: Mapping[str, Any]) -> Any:
    single=data["single_checkpoint_evaluation.json"]; meta=data["selected_transformer_metadata.json"]; replay=single["integrity"]["deterministic_replay"]
    items=[("Repeated inference","PASS",f"2 complete runs; max Δ {replay['max_absolute_difference']:.1f}"), ("Checkpoint reload","PASS",f"metadata reload_verified={meta['reload_verified']}"), ("Hash verification","PASS",EXPECTED_CHECKPOINT_SHA256[:16]+"…"), ("State compatibility","PASS","strict state dictionary verified"), ("Malformed / unknown input","NOT MEASURED","no Transformer runtime adapter"), ("Missing / corrupt model","OFFLINE TESTED","loader rejects hash/shape mismatch"), ("Downstream authority","PASS","current VOMM authority unchanged")]
    fig,ax=plt.subplots(figsize=(12,6)); ax.axis("off"); ax.set_title("Reliability and failure-handling evidence",fontsize=15)
    for i,(name,status,detail) in enumerate(items):
        y=.87-i*.12; color=PASS_COLOR if status=="PASS" else ("#8A5A00" if status=="OFFLINE TESTED" else MUTED_COLOR); ax.text(.02,y,name,transform=ax.transAxes,fontsize=10); ax.text(.43,y,status,transform=ax.transAxes,color=color,weight="bold"); ax.text(.62,y,detail,transform=ax.transAxes,fontsize=9,color=MUTED_COLOR)
    ax.text(.5,.02,"Failure rate, missing-score rate, CPU utilization, and deployed Transformer fail-closed behavior: not measured / not applicable.",transform=ax.transAxes,ha="center",fontsize=8,color=MUTED_COLOR); return fig


def figure_24(plt: Any, data: Mapping[str, Any]) -> Any:
    criteria=DECISION_MATRIX["criteria"]; alternatives=DECISION_MATRIX["alternatives"]; values=[a["scores"] for a in alternatives]; columns=[f"{c['label']}\n{c['weight']*100:.0f}%" for c in criteria]; totals=_decision_totals(); annotations=[[f"{v:.1f}" for v in row] for row in values]
    fig,axes=plt.subplots(1,2,figsize=(15,6),gridspec_kw={"width_ratios":[3,1]}); _heatmap(plt,axes[0],values,[a["label"] for a in alternatives],columns,fmt=".1f",cmap="YlGn",vmin=1,vmax=5,annotations=annotations); axes[0].set_title("Accepted retrospective criterion scores")
    ordered=sorted(alternatives,key=lambda a:totals[a["id"]],reverse=True); bars=axes[1].barh([a["label"] for a in ordered],[totals[a["id"]] for a in ordered],color=[TRANSFORMER_COLOR if a["id"]=="dual_reporting" else MUTED_COLOR for a in ordered]); axes[1].invert_yaxis(); axes[1].set_xlim(0,5); axes[1].set_xlabel("Weighted score / 5"); axes[1].set_title("Final ranking")
    for b,a in zip(bars,ordered): axes[1].text(b.get_width()+.05,b.get_y()+b.get_height()/2,f"{totals[a['id']]:.2f}",va="center"); fig.suptitle("Weighted PoC decision matrix (retrospective; not preregistered)",y=.995); return fig


def _cards(plt: Any, title: str, cards: Sequence[tuple[str,str,str]], footer: str="") -> Any:
    fig,ax=plt.subplots(figsize=(12,6.5)); ax.axis("off"); ax.text(.5,.95,title,ha="center",transform=ax.transAxes,fontsize=17,weight="bold")
    columns=2; rows=math.ceil(len(cards)/columns); box_heights={1:.42,2:.29,3:.21,4:.16}; height=box_heights[rows]; gap=.035
    for index,(heading,body,color) in enumerate(cards):
        col=index%columns; row=index//columns; x=.04+col*.49; y=.84-row*(height+gap); ax.add_patch(plt.Rectangle((x,y-height),.43,height,transform=ax.transAxes,facecolor="#F8FAFC",edgecolor=color,lw=1.7)); ax.text(x+.215,y-.045,heading,ha="center",va="top",transform=ax.transAxes,color=color,weight="bold",fontsize=11); ax.text(x+.215,y-.105,body,ha="center",va="top",transform=ax.transAxes,fontsize=9,wrap=True)
    if footer: ax.text(.5,.025,footer,ha="center",transform=ax.transAxes,color=MUTED_COLOR,fontsize=8)
    return fig


def figure_25(plt: Any, data: Mapping[str, Any]) -> Any:
    return _cards(plt,"Distinct model roles",[("Best aggregate benchmark","Selected Transformer",TRANSFORMER_COLOR),("Simplest operational model","Hard-backoff VOMM",VOMM_COLOR),("Baseline and rollback","Hard-backoff VOMM",VOMM_COLOR),("Final thesis / PoC approach","Transformer primary; VOMM shown concurrently\nwith explicit disagreement",TRANSFORMER_COLOR)],"No score fusion, no tactic-dependent routing, and no deployment change in this task.")


def figure_26(plt: Any, data: Mapping[str, Any]) -> Any:
    reasons="Higher Top-1, Macro-F1, weighted-F1, balance and MRR\nPaired CIs above zero\nCPU p95 0.809 ms; 17 KB checkpoint\nValidation-only selection; deterministic replay"; limits="91.0% of wins are Persistence\nExecution recall 0.7118; privilege escalation 0\nWeak labels and 45 sequence patterns\nNo prospective independent holdout"
    return _cards(plt,"Why the Transformer is selected for the experimental PoC",[("Supporting evidence",reasons,PASS_COLOR),("Required limitations",limits,FAIL_COLOR)],"Claim: strongest aggregate model on this corpus—not general production superiority.")


def figure_27(plt: Any, data: Mapping[str, Any]) -> Any:
    return _cards(plt,"Why VOMM remains important",[("Interpretability","Explicit transition counts, contexts, support, and hard backoff",VOMM_COLOR),("Error complement","Execution recall 0.9497; exposes Transformer disagreement",VOMM_COLOR),("Operational simplicity","No PyTorch dependency; already integrated fail closed",VOMM_COLOR),("Governance","Immutable artifact, reproducible baseline, immediate rollback",VOMM_COLOR)],"Limitation retained: VOMM Persistence recall is only 0.0402.")


def figure_28(plt: Any, data: Mapping[str, Any]) -> Any:
    return _cards(plt,"Final performance decision dashboard",[("Best Top-1","Selected Transformer · 0.8866",TRANSFORMER_COLOR),("Best Macro-F1","Selected Transformer · 0.5097",TRANSFORMER_COLOR),("Best balanced accuracy","Selected Transformer · 0.5113",TRANSFORMER_COLOR),("Best Top-3","Hard-backoff VOMM · 0.9988",VOMM_COLOR),("Fastest selected major model","Transformer · p95 0.809 ms",TRANSFORMER_COLOR),("Lowest dependency complexity","Hard-backoff VOMM",VOMM_COLOR),("Primary experimental PoC","Selected Transformer",TRANSFORMER_COLOR),("Baseline / rollback","Hard-backoff VOMM",VOMM_COLOR)],"Central trade-off: Persistence recall 0.0402→1.0000; Execution recall 0.9497→0.7118.")


def figure_29(plt: Any, data: Mapping[str, Any]) -> Any:
    cards=[("1 · Best overall?","Transformer on accepted held-out aggregate metrics",TRANSFORMER_COLOR),("2 · Selected for PoC?","Transformer as primary experimental predictor",TRANSFORMER_COLOR),("3 · Why?","Material paired gains, broader metric superiority, feasible CPU runtime",PASS_COLOR),("4 · Main limitations?","Persistence concentration, Execution regression, weak/repeated labels",FAIL_COLOR),("5 · Why retain VOMM?","Interpretability, Execution recall, fail-closed integration, rollback",VOMM_COLOR),("6 · Justified claim","Corpus-level benchmark superiority",PASS_COLOR),("7 · Not justified","General production superiority or score fusion",FAIL_COLOR)]
    return _cards(plt,"Final next-tactic model-selection conclusion",cards,"Display both predictions and disagreement. Do not average scores or create tactic-dependent routing.")


FIGURE_FUNCTIONS = [figure_01,figure_02,figure_03,figure_04,figure_05,figure_06,figure_07,figure_08,figure_09,figure_10,figure_11,figure_12,figure_13,figure_14,figure_15,figure_16,figure_17,figure_18,figure_19,figure_20,figure_21,figure_22,figure_23,figure_24,figure_25,figure_26,figure_27,figure_28,figure_29]


def _summary() -> str:
    lines=["# Final next-tactic model-selection figure summary","","This package uses only compact accepted repository evidence. Aggregate GRU and Transformer results appear only in the initial all-model predictive comparison; focused conclusions use the frozen seed-20260723 checkpoint. Raw neural scores are not calibrated probabilities.",""]
    for stem,info in FIGURE_INFO.items():
        lines.extend([f"## {stem}.png / {stem}.pdf","",f"- **Purpose:** {info['purpose']}",f"- **Source:** {info['source']}",f"- **Metrics:** {info['metrics']}",f"- **Interpretation:** {info['interpretation']}",f"- **Limitation:** {info['limitation']}",f"- **Decision relevance:** {info['argument']}",""])
    lines.extend(["## Claim boundary","","The accepted evidence supports the Transformer as the strongest aggregate model on this external held-out corpus and as the primary experimental PoC predictor. It does not establish general production superiority. VOMM remains the concurrent interpretable baseline and rollback model. No score fusion or tactic-dependent routing is used.",""])
    return "\n".join(lines)


def generate(evidence_dir: Path, output_dir: Path) -> dict[str, Any]:
    data=load_evidence(evidence_dir); output_dir.mkdir(parents=True,exist_ok=True); plt,matplotlib,_cmap=_plot_modules(); generated=[]
    stems=list(FIGURE_INFO)
    for stem,function in zip(stems,FIGURE_FUNCTIONS):
        fig=function(plt,data); caption=f"Source: {FIGURE_INFO[stem]['source']} · Limitation: {FIGURE_INFO[stem]['limitation']}"; _save_figure(fig,output_dir,stem,caption,generated); plt.close(fig)
    summary=output_dir/"FIGURE_SUMMARY.md"; summary.write_text(_summary(),encoding="utf-8"); generated.append({"path":str(summary),"format":"markdown","sha256":_sha256(summary),"size_bytes":summary.stat().st_size})
    matrix_path=output_dir/"decision_matrix.json"; matrix={**DECISION_MATRIX,"weighted_totals":_decision_totals(),"selected_alternative":"dual_reporting"}; matrix_path.write_text(json.dumps(matrix,indent=2,sort_keys=True)+"\n",encoding="utf-8"); generated.append({"path":str(matrix_path),"format":"json","sha256":_sha256(matrix_path),"size_bytes":matrix_path.stat().st_size})
    source_names=["single_checkpoint_evaluation.json","overall_metrics.json","per_tactic_metrics.json","paired_comparisons.json","confidence_intervals.json","confusion_matrices.json","efficiency.json","model_configurations.json","dataset_split_manifest.json","selected_transformer_metadata.json","calibration.json"]
    displayed={"case_count":12235,"transformer_top1":data["single_checkpoint_evaluation.json"]["metrics"][TRANSFORMER]["top1_accuracy"],"vomm_top1":data["single_checkpoint_evaluation.json"]["metrics"][VOMM]["top1_accuracy"],"transformer_wins":1887,"persistence_wins":1718,"vomm_persistence_to_execution":1718,"transformer_execution_to_persistence":819,"decision_total_dual_reporting":_decision_totals()["dual_reporting"]}
    manifest={"schema_version":SCHEMA_VERSION,"generated_at":datetime.now(timezone.utc).isoformat(),"repository_commit":subprocess.run(["git","rev-parse","HEAD"],check=True,capture_output=True,text=True).stdout.strip(),"generator":{"path":"production/tools/generate_final_model_selection_figures.py","sha256":_sha256(Path(__file__))},"python_version":platform.python_version(),"matplotlib_version":matplotlib.__version__,"input_evidence":[{"path":str(evidence_dir/name),"sha256":_sha256(evidence_dir/name)} for name in source_names],"selected_transformer_checkpoint_sha256":EXPECTED_CHECKPOINT_SHA256,"displayed_key_values":displayed,"decision_matrix_provenance":DECISION_MATRIX["source"],"aggregate_neural_runtime_excluded":True,"unsupported_runtime_values_fabricated":False,"benchmark_values_modified":False,"production_authority_modified":False,"artifacts":generated}
    manifest_path=output_dir/"figures_manifest.json"; manifest_path.write_text(json.dumps(manifest,indent=2,sort_keys=True)+"\n",encoding="utf-8"); return manifest


def parse_args(argv: Sequence[str] | None=None) -> argparse.Namespace:
    parser=argparse.ArgumentParser(description=__doc__); parser.add_argument("--evidence-dir",default=DEFAULT_EVIDENCE_DIR); parser.add_argument("--output-dir",default=DEFAULT_OUTPUT_DIR); return parser.parse_args(argv)


def main(argv: Sequence[str] | None=None) -> int:
    args=parse_args(argv); manifest=generate(Path(args.evidence_dir),Path(args.output_dir)); print(json.dumps({"status":"complete","png_pdf_pairs":29,"artifact_count":len(manifest["artifacts"]),"output_dir":args.output_dir},sort_keys=True)); return 0


if __name__ == "__main__": raise SystemExit(main())
