"""Proposal-only transition-frequency scorer weight sweep.

This companion analysis reuses the external Cowrie seed calibration split from
external_seed_weight_fit.py. It does not update production policy; it only
writes thesis/report artifacts showing how held-out performance changes as the
transition-frequency scorer weight is varied.
"""

from __future__ import annotations

import argparse
import json
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, Iterable, List

from production.prediction.weight_fitting import (
    _mean_loss,
    _normalize_weights,
    _prepare_cases,
    _round_simplex,
)
from production.tools.external_seed_weight_fit import (
    DEFAULT_SCOPE,
    DEFAULT_SCORERS,
    _build_external_model,
    _case_payloads_for_fit,
    _dataset_statistics,
    _delta,
    _evaluate_weight_set,
    _load_policy,
    _load_seed_sessions,
    _markdown_table,
    _normalize_selected_weights,
    _policy_for_fit,
    _pct,
    _scoped_payload,
    _split_eligible_sessions,
    _num,
)
from production.utils.serialization import utc_now


DEFAULT_SWEEP_VALUES = [
    0.00,
    0.10,
    0.20,
    0.30,
    0.40,
    0.50,
    0.60,
    0.70,
    0.80,
    0.90,
    0.96,
    0.960386,
    1.00,
]


def _metric_row(label: str, weights: Dict[str, float], metrics: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "label": label,
        "transition_frequency_weight": round(float(weights.get("local_transition") or 0.0), 6),
        "local_transition_weight": round(float(weights.get("local_transition") or 0.0), 6),
        "external_seed_transition_weight": round(float(weights.get("external_seed_transition") or 0.0), 6),
        "fallback_progression_weight": round(float(weights.get("fallback_progression") or 0.0), 6),
        "tactic_combination_weight": round(float(weights.get("tactic_combination") or 0.0), 6),
        "mitre_association_weight": round(float(weights.get("mitre_association") or 0.0), 6),
        "top1_accuracy": metrics.get("top1_accuracy", 0.0),
        "top3_accuracy": metrics.get("top3_accuracy", 0.0),
        "mean_reciprocal_rank": metrics.get("mean_reciprocal_rank", 0.0),
        "brier_score": metrics.get("brier_score", 0.0),
        "coverage": metrics.get("coverage", 0.0),
        "evaluated_examples": metrics.get("total_cases", 0),
    }


def _baseline_remainder_proportions(baseline_weights: Dict[str, float], remainder_scorers: List[str]) -> Dict[str, float]:
    total = sum(max(float(baseline_weights.get(name) or 0.0), 0.0) for name in remainder_scorers)
    if total <= 0.0:
        return {name: 1.0 / len(remainder_scorers) for name in remainder_scorers}
    return {
        name: max(float(baseline_weights.get(name) or 0.0), 0.0) / total
        for name in remainder_scorers
    }


def _proportional_weights(
    transition_weight: float,
    proportions: Dict[str, float],
    scorers: List[str],
) -> Dict[str, float]:
    remaining = max(1.0 - float(transition_weight), 0.0)
    weights = {name: 0.0 for name in scorers}
    weights["local_transition"] = float(transition_weight)
    for scorer, proportion in proportions.items():
        weights[scorer] = remaining * float(proportion)
    return _round_simplex(weights)


def _compose_fixed_transition_weights(
    transition_weight: float,
    remainder_proportions: Dict[str, float],
    remainder_scorers: List[str],
    scorers: List[str],
) -> Dict[str, float]:
    remaining = max(1.0 - float(transition_weight), 0.0)
    weights = {name: 0.0 for name in scorers}
    weights["local_transition"] = float(transition_weight)
    if remaining <= 0.0:
        return _round_simplex(weights)
    normalized = _normalize_weights(remainder_proportions, remainder_scorers)
    for scorer in remainder_scorers:
        weights[scorer] = remaining * float(normalized.get(scorer) or 0.0)
    return _round_simplex(weights)


def _fixed_transition_loss(
    prepared_cases: List[Dict[str, Any]],
    transition_weight: float,
    remainder_proportions: Dict[str, float],
    remainder_scorers: List[str],
    scorers: List[str],
    loss: str,
) -> float:
    weights = _compose_fixed_transition_weights(
        transition_weight,
        remainder_proportions,
        remainder_scorers,
        scorers,
    )
    return _mean_loss(prepared_cases, weights, loss)


def _optimize_remainder_proportions(
    prepared_cases: List[Dict[str, Any]],
    transition_weight: float,
    starting_proportions: Dict[str, float],
    remainder_scorers: List[str],
    scorers: List[str],
    loss: str,
    initial_step: float = 0.05,
    min_step: float = 0.001,
    max_iterations: int = 200,
) -> Dict[str, Any]:
    if transition_weight >= 1.0:
        weights = _compose_fixed_transition_weights(
            transition_weight,
            {name: 0.0 for name in remainder_scorers},
            remainder_scorers,
            scorers,
        )
        return {"weights": weights, "loss": _mean_loss(prepared_cases, weights, loss), "iterations": 0}

    proportions = _normalize_weights(starting_proportions, remainder_scorers)
    current_loss = _fixed_transition_loss(
        prepared_cases,
        transition_weight,
        proportions,
        remainder_scorers,
        scorers,
        loss,
    )
    step = min(max(initial_step, min_step), 0.5)
    iterations = 0
    tolerance = 1e-10

    while step >= min_step and iterations < max_iterations:
        best_proportions = proportions
        best_loss = current_loss
        for donor in remainder_scorers:
            donor_weight = float(proportions.get(donor) or 0.0)
            if donor_weight <= 0.0:
                continue
            amount = min(step, donor_weight)
            if amount <= 0.0:
                continue
            for receiver in remainder_scorers:
                if donor == receiver:
                    continue
                candidate = dict(proportions)
                candidate[donor] = max(float(candidate.get(donor) or 0.0) - amount, 0.0)
                candidate[receiver] = float(candidate.get(receiver) or 0.0) + amount
                candidate = _normalize_weights(candidate, remainder_scorers)
                candidate_loss = _fixed_transition_loss(
                    prepared_cases,
                    transition_weight,
                    candidate,
                    remainder_scorers,
                    scorers,
                    loss,
                )
                if candidate_loss < best_loss - tolerance:
                    best_loss = candidate_loss
                    best_proportions = candidate
        iterations += 1
        if best_proportions is proportions:
            step *= 0.5
            continue
        proportions = best_proportions
        current_loss = best_loss

    weights = _compose_fixed_transition_weights(
        transition_weight,
        proportions,
        remainder_scorers,
        scorers,
    )
    return {"weights": weights, "loss": current_loss, "iterations": iterations}


def _evaluate_row(
    label: str,
    weights: Dict[str, float],
    split_payloads: List[Dict[str, Any]],
    policy: Dict[str, Any],
    external_model: Dict[str, Any],
    local_training_payloads: List[Dict[str, Any]],
    tactic_scope: set[str],
    scorers: List[str],
) -> Dict[str, Any]:
    evaluated = _evaluate_weight_set(
        label,
        weights,
        split_payloads,
        policy,
        external_model,
        local_training_payloads,
        tactic_scope,
        scorers,
    )
    row = _metric_row(label, evaluated["weights"], evaluated["metrics"])
    row["weights"] = evaluated["weights"]
    row["metrics"] = evaluated["metrics"]
    return row


def _markdown_sweep_table(rows: Iterable[Dict[str, Any]]) -> str:
    return _markdown_table(
        [
            "Row",
            "transition_frequency_weight",
            "external_seed_transition_weight",
            "fallback_progression_weight",
            "tactic_combination_weight",
            "mitre_association_weight",
            "Top-1 Accuracy",
            "Top-3 Accuracy",
            "MRR",
            "Brier Score",
            "Coverage",
            "Evaluated Examples",
        ],
        [
            (
                row["label"],
                _num(row["transition_frequency_weight"], 6),
                _num(row["external_seed_transition_weight"], 6),
                _num(row["fallback_progression_weight"], 6),
                _num(row["tactic_combination_weight"], 6),
                _num(row["mitre_association_weight"], 6),
                _pct(row["top1_accuracy"]),
                _pct(row["top3_accuracy"]),
                _num(row["mean_reciprocal_rank"], 4),
                _num(row["brier_score"], 6),
                _pct(row["coverage"]),
                row["evaluated_examples"],
            )
            for row in rows
        ],
    )


def _inspect_existing_artifact(path: str) -> Dict[str, Any]:
    if not path:
        return {"path": "", "exists": False}
    artifact_path = Path(path)
    if not artifact_path.exists():
        return {"path": str(artifact_path), "exists": False}
    data = json.loads(artifact_path.read_text(encoding="utf-8"))
    candidates = {
        "optimization_trace": data.get("optimization_trace"),
        "candidate_weights": data.get("candidate_weights"),
        "grid_search_results": data.get("grid_search_results"),
        "sensitivity_analysis": data.get("sensitivity_analysis"),
        "ablation": data.get("ablation"),
        "per_weight_sweep_results": data.get("per_weight_sweep_results"),
        "transition_weight_sweep": data.get("transition_weight_sweep"),
    }
    return {
        "path": str(artifact_path),
        "exists": True,
        "top_level_keys": sorted(data.keys()),
        "contains": {
            key: bool(value)
            for key, value in candidates.items()
        },
        "list_lengths": {
            key: len(value)
            for key, value in candidates.items()
            if isinstance(value, list)
        },
    }


def run_transition_weight_sweep(args: argparse.Namespace) -> Dict[str, Any]:
    existing_artifact = _inspect_existing_artifact(args.existing_artifact)
    scope = {str(item).strip() for item in args.tactic_scope if str(item).strip()}
    scorers = [str(item).strip() for item in args.scorer if str(item).strip()]
    remainder_scorers = [name for name in scorers if name != "local_transition"]
    raw_payloads, provenance = _load_seed_sessions(args.input, limit=max(int(args.limit or 0), 0))
    scoped_payloads = [_scoped_payload(payload, scope) for payload in raw_payloads]
    split = _split_eligible_sessions(
        scoped_payloads,
        seed=int(args.seed),
        train_ratio=float(args.train_ratio),
        calibration_ratio=float(args.calibration_ratio),
    )
    policy = _policy_for_fit(
        _load_policy(args.policy),
        _normalize_selected_weights(_load_policy(args.policy), scorers),
    )
    baseline_weights = {name: float(policy["weights"].get(name) or 0.0) for name in scorers}
    external_model = _build_external_model(split["train"], provenance, seed=int(args.seed))

    calibration_cases = _case_payloads_for_fit(
        split["calibration"],
        policy,
        external_model,
        local_training_payloads=split["calibration"],
        leave_one_out_local=True,
        tactic_scope=scope,
    )
    prepared_calibration_cases, excluded_output_counts, cases_with_candidate_output = _prepare_cases(
        calibration_cases,
        scorers,
        include_context=False,
    )
    fitted_weights = {
        "local_transition": 0.960386,
        "external_seed_transition": 0.021324,
        "fallback_progression": 0.018290,
        "tactic_combination": 0.0,
        "mitre_association": 0.0,
    }
    if args.fitted_weights:
        fitted_weights.update(json.loads(args.fitted_weights))

    sweep_values = []
    seen = set()
    for value in args.transition_weight:
        rounded = round(float(value), 6)
        if rounded not in seen:
            seen.add(rounded)
            sweep_values.append(rounded)

    proportional_proportions = _baseline_remainder_proportions(baseline_weights, remainder_scorers)
    fitted_remainder_proportions = _baseline_remainder_proportions(fitted_weights, remainder_scorers)
    table_a = []
    table_b = []

    for value in sweep_values:
        proportional = _proportional_weights(value, proportional_proportions, scorers)
        table_a.append(
            _evaluate_row(
                f"w={value:.6f}",
                proportional,
                split["test"],
                policy,
                external_model,
                local_training_payloads=split["calibration"],
                tactic_scope=scope,
                scorers=scorers,
            )
        )
        optimized = _optimize_remainder_proportions(
            prepared_calibration_cases,
            value,
            fitted_remainder_proportions,
            remainder_scorers,
            scorers,
            loss=str(args.loss),
        )
        row_b = _evaluate_row(
            f"w={value:.6f}",
            optimized["weights"],
            split["test"],
            policy,
            external_model,
            local_training_payloads=split["calibration"],
            tactic_scope=scope,
            scorers=scorers,
        )
        row_b["calibration_loss"] = round(float(optimized["loss"]), 6)
        row_b["optimizer_iterations"] = int(optimized["iterations"])
        table_b.append(row_b)

    final_row = _evaluate_row(
        "final_fitted_weights",
        fitted_weights,
        split["test"],
        policy,
        external_model,
        local_training_payloads=split["calibration"],
        tactic_scope=scope,
        scorers=scorers,
    )
    baseline_row = _evaluate_row(
        "current_selected_weights",
        baseline_weights,
        split["test"],
        policy,
        external_model,
        local_training_payloads=split["calibration"],
        tactic_scope=scope,
        scorers=scorers,
    )
    result = {
        "schema_version": "external_seed_transition_weight_sweep.v1",
        "generated_at": utc_now(),
        "production_policy_changed": False,
        "input": args.input,
        "policy": args.policy,
        "existing_artifact_inspection": existing_artifact,
        "recomputed": True,
        "recompute_reason": "Existing fit artifact did not contain a one-dimensional transition-frequency per-weight sweep table.",
        "primary_fitting_objective": str(args.loss),
        "methodology": {
            "split_method": "deterministic_stratified_by_first_tactic_transition",
            "seed": int(args.seed),
            "train_ratio": float(args.train_ratio),
            "calibration_ratio": float(args.calibration_ratio),
            "test_ratio": round(1.0 - float(args.train_ratio) - float(args.calibration_ratio), 4),
            "table_a": "Fix local_transition/transition-frequency weight to w; distribute 1-w across the four remaining scorers using current selected baseline proportions.",
            "table_b": "Fix local_transition/transition-frequency weight to w; fit the four remaining weights on the calibration split using Brier score, then evaluate on held-out test.",
            "metrics_split": "All reported accuracy/MRR/Brier/coverage metrics in Table A and Table B are held-out test metrics.",
        },
        "scorers": scorers,
        "transition_weight_values": sweep_values,
        "baseline_weights": baseline_weights,
        "fitted_weights": fitted_weights,
        "baseline_remainder_proportions": proportional_proportions,
        "fitted_remainder_starting_proportions": fitted_remainder_proportions,
        "split": {
            "total_sessions_loaded": len(raw_payloads),
            "train_sessions_total": len(split["train"]),
            "train_eligible_sessions": len(split["train_eligible"]),
            "calibration_sessions": len(split["calibration"]),
            "test_sessions": len(split["test"]),
        },
        "dataset_statistics": _dataset_statistics(scoped_payloads),
        "calibration_case_summary": {
            "cases": len(calibration_cases),
            "prepared_cases": len(prepared_calibration_cases),
            "cases_with_candidate_output": cases_with_candidate_output,
            "excluded_output_counts": excluded_output_counts,
        },
        "current_selected_row": baseline_row,
        "final_fitted_row": final_row,
        "final_vs_current_delta": _delta(final_row["metrics"], baseline_row["metrics"]),
        "table_a_proportional_remainder_sweep": table_a,
        "table_b_optimized_remainder_sweep": table_b,
    }
    result["markdown_tables"] = {
        "current_selected_row": _markdown_sweep_table([baseline_row]),
        "final_fitted_row": _markdown_sweep_table([final_row]),
        "table_a_proportional_remainder_sweep": _markdown_sweep_table(table_a),
        "table_b_optimized_remainder_sweep": _markdown_sweep_table(table_b),
    }
    return result


def write_markdown(result: Dict[str, Any], path: Path) -> None:
    inspection = result["existing_artifact_inspection"]
    tables = result["markdown_tables"]
    lines = [
        "# External Seed Transition-Frequency Weight Sweep",
        "",
        "This artifact is proposal-only and does not change production weights or runtime configuration.",
        "",
        "## Extraction/Recomputation Status",
        "",
        f"- Existing artifact inspected: `{inspection.get('path', '')}`",
        f"- Existing artifact contained per-weight sweep: `{inspection.get('contains', {}).get('per_weight_sweep_results') or inspection.get('contains', {}).get('transition_weight_sweep')}`",
        f"- Recomputed: `{result.get('recomputed')}`",
        f"- Reason: {result.get('recompute_reason')}",
        f"- Primary fitting objective: `{result.get('primary_fitting_objective')}`",
        f"- Metrics split: {result.get('methodology', {}).get('metrics_split')}",
        "",
        "## Baseline Remainder Proportions Used In Table A",
        "",
        _markdown_table(
            ["Scorer", "Proportion of non-transition remainder"],
            [
                (scorer, _num(value, 6))
                for scorer, value in result["baseline_remainder_proportions"].items()
            ],
        ),
        "",
        "## Current Selected Row",
        "",
        tables["current_selected_row"],
        "",
        "## Final Fitted Row",
        "",
        tables["final_fitted_row"],
        "",
        "## Table A: Proportional Remainder Sweep",
        "",
        result["methodology"]["table_a"],
        "",
        tables["table_a_proportional_remainder_sweep"],
        "",
        "## Table B: Optimized Remainder Sweep",
        "",
        result["methodology"]["table_b"],
        "",
        tables["table_b_optimized_remainder_sweep"],
        "",
        "## Caveats",
        "",
        "- Table A and Table B metrics are held-out test metrics.",
        "- Table B chooses remaining non-transition weights on the calibration split, then evaluates the selected weights on held-out test.",
        "- The final fitted row is included as the known fitted full-simplex solution from the completed experiment.",
        "- Production policy was not changed.",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate a transition-frequency weight sweep for thesis/reporting.")
    parser.add_argument("--input", required=True)
    parser.add_argument("--policy", required=True)
    parser.add_argument("--existing-artifact", default="evaluation/external_seed_weight_fit.json")
    parser.add_argument("--output", required=True)
    parser.add_argument("--markdown-output", required=True)
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--seed", type=int, default=20260707)
    parser.add_argument("--train-ratio", type=float, default=0.70)
    parser.add_argument("--calibration-ratio", type=float, default=0.15)
    parser.add_argument("--loss", choices=["brier_score", "negative_log_likelihood"], default="brier_score")
    parser.add_argument("--tactic-scope", action="append", default=list(DEFAULT_SCOPE))
    parser.add_argument("--scorer", action="append", default=list(DEFAULT_SCORERS))
    parser.add_argument("--transition-weight", action="append", type=float, default=list(DEFAULT_SWEEP_VALUES))
    parser.add_argument("--fitted-weights", help="Optional JSON object overriding the known final fitted weights.")
    return parser


def main(argv: List[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    result = run_transition_weight_sweep(args)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_markdown(result, Path(args.markdown_output))
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
