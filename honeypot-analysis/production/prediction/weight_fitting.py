"""Proposal-only empirical fitting for prediction scorer weights.

The fitter uses completed backtest cases with raw per-scorer tactic scores and
estimates a non-negative set of behavioral scorer weights that sums to one
within the fitted voter set. It is intended for audit and thesis methodology:
the returned policy overlay is a proposal and must be reviewed before use.
"""

from __future__ import annotations

import math
from collections import defaultdict
from typing import Any, Dict, Iterable, List, Tuple


CONTEXT_SCORERS = {"enrichment_context"}
RISK_SCORERS = {"vulnerability_risk"}
CONTEXT_SOURCE_TYPES = {"context_modifier"}
RISK_SOURCE_TYPES = {"risk_modifier"}
SUPPORTED_LOSSES = {"brier_score", "negative_log_likelihood"}


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return default
    return parsed if math.isfinite(parsed) else default


def _round_simplex(weights: Dict[str, float], precision: int = 6) -> Dict[str, float]:
    if not weights:
        return {}
    rounded = {name: round(max(value, 0.0), precision) for name, value in weights.items()}
    total = round(sum(rounded.values()), precision)
    if total <= 0.0:
        return rounded
    residual = round(1.0 - total, precision)
    if residual:
        largest = max(rounded, key=lambda name: rounded[name])
        rounded[largest] = round(max(rounded[largest] + residual, 0.0), precision)
    return rounded


def _normalize_weights(weights: Dict[str, Any], scorer_names: Iterable[str]) -> Dict[str, float]:
    names = [str(name) for name in scorer_names if str(name)]
    numeric = {name: max(_safe_float(weights.get(name)), 0.0) for name in names}
    total = sum(numeric.values())
    if total <= 0.0:
        return {name: 0.0 for name in names}
    return {name: numeric[name] / total for name in names}


def _fittable_scorers(
    current_weights: Dict[str, Any],
    scorer_names: Iterable[str] | None,
    include_context: bool,
) -> Tuple[List[str], Dict[str, str]]:
    names = list(scorer_names or current_weights.keys())
    seen = set()
    included: List[str] = []
    excluded: Dict[str, str] = {}
    for raw_name in names:
        name = str(raw_name or "").strip()
        if not name or name in seen:
            continue
        seen.add(name)
        if name in RISK_SCORERS:
            excluded[name] = "risk annotator; excluded from behavioral weight fitting"
            continue
        if name in CONTEXT_SCORERS and not include_context:
            excluded[name] = "context modifier; enable include_context to fit it"
            continue
        if scorer_names is None and _safe_float(current_weights.get(name)) <= 0.0:
            excluded[name] = "not in active configured voter set"
            continue
        included.append(name)
    return sorted(included), excluded


def _excluded_by_source_type(scorer: str, source_type: str, include_context: bool) -> str:
    if scorer in RISK_SCORERS or source_type in RISK_SOURCE_TYPES:
        return "risk annotator; excluded from behavioral weight fitting"
    if not include_context and (scorer in CONTEXT_SCORERS or source_type in CONTEXT_SOURCE_TYPES):
        return "context modifier; enable include_context to fit it"
    return ""


def _scorer_tactic_scores(
    scorer: str,
    outputs_raw: Any,
    include_context: bool,
    excluded_output_counts: Dict[str, int],
) -> Dict[str, float]:
    if not isinstance(outputs_raw, list):
        return {}
    tactic_scores: Dict[str, float] = {}
    for output in outputs_raw:
        if not isinstance(output, dict):
            continue
        source_type = str(output.get("source_type") or "")
        exclusion = _excluded_by_source_type(scorer, source_type, include_context)
        if exclusion:
            excluded_output_counts[f"{scorer}: {exclusion}"] += 1
            continue
        tactic = str(output.get("tactic") or "").strip()
        score = max(_safe_float(output.get("score")), 0.0)
        if not tactic or score <= 0.0:
            continue
        tactic_scores[tactic] = max(tactic_scores.get(tactic, 0.0), score)
    return tactic_scores


def _prepare_cases(
    cases: Iterable[Dict[str, Any]],
    scorers: List[str],
    include_context: bool,
) -> Tuple[List[Dict[str, Any]], Dict[str, int], int]:
    prepared: List[Dict[str, Any]] = []
    excluded_output_counts: Dict[str, int] = defaultdict(int)
    cases_with_candidate_output = 0
    for case in cases:
        if not isinstance(case, dict):
            continue
        actual = str(case.get("actual_next") or "").strip()
        if not actual:
            continue
        scorer_outputs = case.get("scorer_outputs") or {}
        if not isinstance(scorer_outputs, dict):
            scorer_outputs = {}
        case_scores: Dict[str, Dict[str, float]] = {}
        for scorer in scorers:
            tactic_scores = _scorer_tactic_scores(
                scorer,
                scorer_outputs.get(scorer),
                include_context,
                excluded_output_counts,
            )
            if tactic_scores:
                case_scores[scorer] = tactic_scores
        if case_scores:
            cases_with_candidate_output += 1
        prepared.append({"actual": actual, "scorers": case_scores})
    return prepared, dict(excluded_output_counts), cases_with_candidate_output


def _case_probabilities(prepared_case: Dict[str, Any], weights: Dict[str, float]) -> Dict[str, float]:
    scorer_scores = prepared_case.get("scorers") or {}
    active = {
        scorer: weight
        for scorer, weight in weights.items()
        if weight > 0.0 and scorer_scores.get(scorer)
    }
    active_total = sum(active.values())
    if active_total <= 0.0:
        return {}

    tactic_scores: Dict[str, float] = {}
    for scorer, weight in active.items():
        normalized_weight = weight / active_total
        for tactic, score in scorer_scores[scorer].items():
            tactic_scores[tactic] = tactic_scores.get(tactic, 0.0) + max(score, 0.0) * normalized_weight
    score_total = sum(tactic_scores.values())
    if score_total <= 0.0:
        return {}
    return {tactic: score / score_total for tactic, score in tactic_scores.items()}


def _case_loss(prepared_case: Dict[str, Any], weights: Dict[str, float], loss: str) -> float:
    actual = str(prepared_case.get("actual") or "")
    probabilities = _case_probabilities(prepared_case, weights)
    if loss == "negative_log_likelihood":
        return -math.log(max(float(probabilities.get(actual, 0.0)), 1e-12))

    labels = set(probabilities)
    labels.add(actual)
    return sum(
        (float(probabilities.get(label, 0.0)) - (1.0 if label == actual else 0.0)) ** 2
        for label in labels
    )


def _mean_loss(prepared_cases: List[Dict[str, Any]], weights: Dict[str, float], loss: str) -> float:
    if not prepared_cases:
        return 0.0
    return sum(_case_loss(case, weights, loss) for case in prepared_cases) / len(prepared_cases)


def _optimize_simplex(
    prepared_cases: List[Dict[str, Any]],
    starting_weights: Dict[str, float],
    loss: str,
    initial_step: float,
    min_step: float,
    max_iterations: int,
) -> Tuple[Dict[str, float], float, int]:
    weights = dict(starting_weights)
    current_loss = _mean_loss(prepared_cases, weights, loss)
    scorer_names = list(weights)
    step = min(max(initial_step, min_step), 0.5)
    iterations = 0
    tolerance = 1e-10

    while step >= min_step and iterations < max_iterations:
        best_weights = weights
        best_loss = current_loss
        for donor in scorer_names:
            donor_weight = float(weights.get(donor, 0.0))
            if donor_weight <= 0.0:
                continue
            amount = min(step, donor_weight)
            if amount <= 0.0:
                continue
            for receiver in scorer_names:
                if donor == receiver:
                    continue
                candidate = dict(weights)
                candidate[donor] = max(candidate[donor] - amount, 0.0)
                candidate[receiver] = candidate.get(receiver, 0.0) + amount
                candidate = _normalize_weights(candidate, scorer_names)
                candidate_loss = _mean_loss(prepared_cases, candidate, loss)
                if candidate_loss < best_loss - tolerance:
                    best_loss = candidate_loss
                    best_weights = candidate
        iterations += 1
        if best_weights is weights:
            step *= 0.5
            continue
        weights = best_weights
        current_loss = best_loss
    return weights, current_loss, iterations


def fit_weights_from_cases(
    cases: Iterable[Dict[str, Any]],
    current_weights: Dict[str, Any],
    scorer_names: Iterable[str] | None = None,
    include_context: bool = False,
    loss: str = "brier_score",
    initial_step: float = 0.05,
    min_step: float = 0.001,
    max_iterations: int = 200,
    min_cases: int = 1,
) -> Dict[str, Any]:
    """Fit behavioral scorer weights from replay cases and return a proposal.

    The optimization is constrained to the simplex: all fitted weights are
    non-negative and sum to one across the selected behavioral voter set.
    """

    objective = str(loss or "brier_score")
    if objective not in SUPPORTED_LOSSES:
        objective = "brier_score"
    fittable_scorers, excluded_scorers = _fittable_scorers(
        current_weights,
        scorer_names,
        include_context,
    )
    starting_weights = _normalize_weights(current_weights, fittable_scorers)
    prepared_cases, excluded_output_counts, cases_with_candidate_output = _prepare_cases(
        cases,
        fittable_scorers,
        include_context,
    )
    base_result: Dict[str, Any] = {
        "schema_version": "prediction_weight_fit.v1",
        "status": "insufficient_data",
        "apply_automatically": False,
        "method": "coordinate_search_simplex",
        "objective": objective,
        "case_count": len(prepared_cases),
        "cases_with_candidate_output": cases_with_candidate_output,
        "scorers": fittable_scorers,
        "current_weights": _round_simplex(starting_weights),
        "excluded_scorers": excluded_scorers,
        "excluded_output_counts": excluded_output_counts,
        "constraints": {
            "non_negative": True,
            "sum_to_one_within_fitted_voter_set": True,
            "risk_annotations_excluded": True,
            "context_excluded_unless_include_context": not include_context,
        },
        "policy_overlay": {},
        "notes": (
            "Proposal only. The fit minimizes replay loss over completed-session "
            "backtest cases and does not overwrite the trusted prediction policy."
        ),
    }
    if not fittable_scorers:
        base_result["reason"] = "no eligible behavioral scorers in the active configured voter set"
        return base_result
    if sum(starting_weights.values()) <= 0.0:
        base_result["reason"] = "eligible scorers have no positive configured weight"
        return base_result
    if len(prepared_cases) < max(int(min_cases), 1):
        base_result["reason"] = f"case count {len(prepared_cases)} below minimum {max(int(min_cases), 1)}"
        return base_result
    if cases_with_candidate_output <= 0:
        base_result["reason"] = "no replay case contained output from the eligible behavioral scorers"
        return base_result

    current_loss = _mean_loss(prepared_cases, starting_weights, objective)
    fitted_weights, fitted_loss, iterations = _optimize_simplex(
        prepared_cases,
        starting_weights,
        objective,
        initial_step=initial_step,
        min_step=min_step,
        max_iterations=max_iterations,
    )
    rounded_fitted = _round_simplex(fitted_weights)
    base_result.update(
        {
            "status": "fit_completed",
            "loss_current": round(current_loss, 6),
            "loss_fitted": round(fitted_loss, 6),
            "loss_improvement": round(current_loss - fitted_loss, 6),
            "optimizer_iterations": iterations,
            "fitted_weights": rounded_fitted,
            "policy_overlay": {
                "weights": rounded_fitted,
                "weight_fitting": {
                    "method": "coordinate_search_simplex",
                    "objective": objective,
                    "case_count": len(prepared_cases),
                    "include_context": include_context,
                    "apply_automatically": False,
                },
            },
        }
    )
    return base_result
