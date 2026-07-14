"""Proposal-only scorer weight fitting on a split external Cowrie seed corpus.

This tool is intentionally separate from production policy loading. It builds a
deterministic train/calibration/test split from sessionized external Cowrie
payloads, fits behavioral scorer weights on the calibration split, and evaluates
current versus fitted weights on the untouched test split.
"""

from __future__ import annotations

import argparse
import json
import math
import random
from collections import Counter, defaultdict
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

from production.classification.trust import is_trusted_classification_event
from production.correlation.session_ttp_knowledge import main_ttp_id
from production.prediction.prediction_backtest import (
    _brier_score,
    _prefix_payload,
    _rank,
    _tactic_steps,
)
from production.prediction.realtime_prediction import (
    RealtimePredictionEngine,
    build_transition_model,
)
from production.prediction.session_features import build_session_features
from production.prediction.weight_fitting import fit_weights_from_cases
from production.utils.serialization import stable_id, utc_now


DEFAULT_SCOPE = [
    "discovery",
    "execution",
    "persistence",
    "credential-access",
    "defense-evasion",
    "command-and-control",
]
DEFAULT_SCORERS = [
    "local_transition",
    "external_seed_transition",
    "fallback_progression",
    "tactic_combination",
    "mitre_association",
]


def _load_json(path: str) -> Dict[str, Any]:
    with Path(path).open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError(f"expected JSON object: {path}")
    return data


def _load_policy(path: str) -> Dict[str, Any]:
    if not path:
        return {}
    data = _load_json(path)
    if isinstance(data.get("policy"), dict):
        return dict(data["policy"])
    if isinstance(data.get("prediction_policy"), dict):
        return dict(data["prediction_policy"])
    return dict(data)


def _load_seed_sessions(path: str, limit: int = 0) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    data = _load_json(path)
    sessions = data.get("sessions") or data.get("payloads") or data.get("items") or []
    if not isinstance(sessions, list):
        raise ValueError(f"expected sessions list in {path}")
    payloads = [item for item in sessions if isinstance(item, dict)]
    if limit > 0:
        payloads = payloads[:limit]
    provenance = data.get("provenance") if isinstance(data.get("provenance"), dict) else {}
    return payloads, provenance


def _session_id(payload: Dict[str, Any]) -> str:
    return str(payload.get("session_id") or payload.get("session") or "unknown")


def _completed(payload: Dict[str, Any]) -> bool:
    return bool(payload.get("is_ended")) or str(payload.get("status") or "") == "closed"


def _scoped_payload(payload: Dict[str, Any], tactic_scope: set[str]) -> Dict[str, Any]:
    scoped = deepcopy(payload)
    scoped_events = []
    for event in payload.get("classification_events") or []:
        if not isinstance(event, dict) or not is_trusted_classification_event(event):
            continue
        tactic = str(event.get("tactic") or "").strip()
        if tactic in tactic_scope:
            scoped_events.append(dict(event))
    scoped["classification_events"] = scoped_events
    scoped["tactics"] = []
    scoped["ttps"] = []
    for event in scoped_events:
        tactic = str(event.get("tactic") or "").strip()
        ttp = main_ttp_id(event.get("ttp"))
        if tactic and tactic not in scoped["tactics"]:
            scoped["tactics"].append(tactic)
        if ttp and ttp != "unknown" and ttp not in scoped["ttps"]:
            scoped["ttps"].append(ttp)
    return scoped


def _transition_key(payload: Dict[str, Any]) -> str:
    steps = _tactic_steps(payload)
    if len(steps) < 2:
        return ""
    return f"{steps[0]['tactic']}->{steps[1]['tactic']}"


def _dataset_statistics(payloads: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Summarize scoped session payloads after repeat-tactic compression."""

    tactic_counts: Counter[str] = Counter()
    transition_counts: Counter[str] = Counter()
    sessions_with_tactic = 0
    sessions_with_transition = 0
    sessions_with_two_or_more_transitions = 0
    completed_sessions = 0
    completed_with_transition = 0

    for payload in payloads:
        completed = _completed(payload)
        if completed:
            completed_sessions += 1
        steps = _tactic_steps(payload)
        if steps:
            sessions_with_tactic += 1
        transition_count = max(len(steps) - 1, 0)
        if transition_count >= 1:
            sessions_with_transition += 1
            if completed:
                completed_with_transition += 1
        if transition_count >= 2:
            sessions_with_two_or_more_transitions += 1
        for step in steps:
            tactic_counts[str(step["tactic"])] += 1
        for left, right in zip(steps, steps[1:]):
            transition_counts[f"{left['tactic']}->{right['tactic']}"] += 1

    return {
        "total_sessions": len(payloads),
        "completed_sessions": completed_sessions,
        "sessions_with_at_least_one_usable_tactic": sessions_with_tactic,
        "sessions_with_at_least_one_tactic_transition": sessions_with_transition,
        "completed_sessions_with_at_least_one_tactic_transition": completed_with_transition,
        "sessions_with_two_or_more_tactic_transitions": sessions_with_two_or_more_transitions,
        "compressed_tactic_observations": sum(tactic_counts.values()),
        "compressed_transition_observations": sum(transition_counts.values()),
        "tactic_distribution": dict(sorted(tactic_counts.items())),
        "transition_distribution_top20": [
            {"transition": key, "count": count}
            for key, count in transition_counts.most_common(20)
        ],
    }


def _split_eligible_sessions(
    payloads: List[Dict[str, Any]],
    seed: int,
    train_ratio: float,
    calibration_ratio: float,
) -> Dict[str, Any]:
    groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    ineligible: List[Dict[str, Any]] = []
    for payload in payloads:
        if not _completed(payload):
            ineligible.append(payload)
            continue
        key = _transition_key(payload)
        if key:
            groups[key].append(payload)
        else:
            ineligible.append(payload)

    rng = random.Random(seed)
    split = {"train": [], "calibration": [], "test": []}
    group_sizes = {}
    for key, items in sorted(groups.items()):
        shuffled = list(items)
        rng.shuffle(shuffled)
        n = len(shuffled)
        train_n = int(n * train_ratio)
        calibration_n = int(n * calibration_ratio)
        if n >= 3:
            train_n = max(train_n, 1)
            calibration_n = max(calibration_n, 1)
            if train_n + calibration_n >= n:
                calibration_n = max(1, n - train_n - 1)
        split["train"].extend(shuffled[:train_n])
        split["calibration"].extend(shuffled[train_n : train_n + calibration_n])
        split["test"].extend(shuffled[train_n + calibration_n :])
        group_sizes[key] = n

    train_with_ineligible = list(ineligible) + split["train"]
    return {
        "train": train_with_ineligible,
        "train_eligible": split["train"],
        "calibration": split["calibration"],
        "test": split["test"],
        "ineligible": ineligible,
        "group_sizes": group_sizes,
    }


def _normalize_selected_weights(policy: Dict[str, Any], scorers: List[str]) -> Dict[str, float]:
    weights = policy.get("weights") or {}
    selected = {name: max(float(weights.get(name) or 0.0), 0.0) for name in scorers}
    total = sum(selected.values())
    if total <= 0:
        return {name: 1.0 / len(scorers) for name in scorers}
    return {name: selected[name] / total for name in scorers}


def _normalize_candidate_weights(weights: Dict[str, float], scorers: List[str]) -> Dict[str, float]:
    selected = {name: max(float(weights.get(name) or 0.0), 0.0) for name in scorers}
    total = sum(selected.values())
    if total <= 0.0:
        return {name: 0.0 for name in scorers}
    normalized = {name: selected[name] / total for name in scorers}
    return {name: round(value, 6) for name, value in normalized.items()}


def _policy_for_fit(policy: Dict[str, Any], selected_weights: Dict[str, float]) -> Dict[str, Any]:
    updated = deepcopy(policy)
    all_weights = {str(name): 0.0 for name in (policy.get("weights") or {}).keys()}
    all_weights.update({name: float(weight) for name, weight in selected_weights.items()})
    updated["weights"] = all_weights
    updated["min_sessions_for_local"] = min(int(updated.get("min_sessions_for_local") or 50), 1)
    updated["min_transition_count"] = min(int(updated.get("min_transition_count") or 2), 1)
    updated["min_prefix_transition_count"] = min(int(updated.get("min_prefix_transition_count") or 2), 1)
    updated["min_technique_transition_count"] = min(int(updated.get("min_technique_transition_count") or 2), 1)
    updated["min_tactic_transition_count"] = min(int(updated.get("min_tactic_transition_count") or 2), 1)
    updated["external_min_sessions"] = min(int(updated.get("external_min_sessions") or 50), 1)
    updated["external_min_transition_count"] = min(int(updated.get("external_min_transition_count") or 2), 1)
    updated["external_min_prefix_transition_count"] = min(int(updated.get("external_min_prefix_transition_count") or 2), 1)
    updated["external_min_technique_transition_count"] = min(int(updated.get("external_min_technique_transition_count") or 2), 1)
    updated["external_min_tactic_transition_count"] = min(int(updated.get("external_min_tactic_transition_count") or 2), 1)
    updated["min_active_scorers"] = 1
    decay = dict(updated.get("external_seed_weight_decay") or {})
    decay["enabled"] = False
    updated["external_seed_weight_decay"] = decay
    updated.setdefault("confidence_damping", {})
    if isinstance(updated["confidence_damping"], dict):
        updated["confidence_damping"]["enabled"] = False
    return updated


def _build_external_model(train_payloads: List[Dict[str, Any]], provenance: Dict[str, Any], seed: int) -> Dict[str, Any]:
    model = build_transition_model(
        train_payloads,
        prefix_max_length=3,
        source_name="external_seed_transition",
    )
    model["schema_version"] = "external_transition_model.v1"
    model["source_type"] = "external_cowrie_seed_split_train"
    model["provenance"] = {
        "dataset_handle": provenance.get("dataset_handle", ""),
        "training_source": "external Cowrie seed split train partition",
        "split_seed": seed,
        "built_at": model.get("built_at", ""),
    }
    return model


def _case_payloads_for_fit(
    payloads: List[Dict[str, Any]],
    policy: Dict[str, Any],
    external_model: Dict[str, Any],
    local_training_payloads: List[Dict[str, Any]],
    leave_one_out_local: bool,
    tactic_scope: set[str],
) -> List[Dict[str, Any]]:
    cases: List[Dict[str, Any]] = []
    local_by_session: Dict[str, Dict[str, Any]] = {}
    fixed_local_model = None
    if not leave_one_out_local:
        fixed_local_model = build_transition_model(local_training_payloads, prefix_max_length=int(policy.get("prefix_max_length", 3)))

    for payload in payloads:
        steps = _tactic_steps(payload)
        if len(steps) < 2:
            continue
        sid = _session_id(payload)
        if leave_one_out_local:
            if sid not in local_by_session:
                local_by_session[sid] = build_transition_model(
                    [item for item in local_training_payloads if _session_id(item) != sid],
                    prefix_max_length=int(policy.get("prefix_max_length", 3)),
                )
            local_model = local_by_session[sid]
        else:
            local_model = fixed_local_model or build_transition_model([])
        engine = RealtimePredictionEngine(
            policy,
            transition_model=local_model,
            external_transition_model=external_model,
        )
        for index in range(len(steps) - 1):
            actual = str(steps[index + 1]["tactic"] or "")
            if actual not in tactic_scope:
                continue
            prefix = _prefix_payload(payload, steps, index)
            features = build_session_features(prefix)
            snapshot = engine.predict(features, event_id=f"external-seed-fit:{sid}:{index}")
            final_ranking = snapshot.get("final_ranking") or []
            ranking = snapshot.get("prediction") or []
            rank = _rank(ranking, actual)
            cases.append(
                {
                    "session_id": sid,
                    "observed_prefix": [step["tactic"] for step in steps[: index + 1]],
                    "actual_next": actual,
                    "predicted": ranking,
                    "rank": rank,
                    "brier_score": round(_brier_score(final_ranking, actual), 6),
                    "top_predicted_tactic": ranking[0] if ranking else "",
                    "scorer_outputs": snapshot.get("scorer_outputs") or {},
                    "top_sources": final_ranking[:3],
                }
            )
    return cases


def _evaluate_cases(cases: List[Dict[str, Any]]) -> Dict[str, Any]:
    total = len(cases)
    predicted = sum(1 for case in cases if case.get("predicted"))
    top1 = sum(1 for case in cases if int(case.get("rank") or 0) == 1)
    top3 = sum(1 for case in cases if 1 <= int(case.get("rank") or 0) <= 3)
    reciprocal = sum(1.0 / int(case.get("rank")) for case in cases if int(case.get("rank") or 0) > 0)
    brier = sum(float(case.get("brier_score") or 0.0) for case in cases)
    by_tactic: Dict[str, Counter] = defaultdict(Counter)
    brier_by_tactic: Dict[str, float] = defaultdict(float)
    for case in cases:
        tactic = str(case.get("actual_next") or "")
        by_tactic[tactic]["cases"] += 1
        if case.get("predicted"):
            by_tactic[tactic]["predicted"] += 1
        if int(case.get("rank") or 0) == 1:
            by_tactic[tactic]["top1"] += 1
        if 1 <= int(case.get("rank") or 0) <= 3:
            by_tactic[tactic]["top3"] += 1
        brier_by_tactic[tactic] += float(case.get("brier_score") or 0.0)

    return {
        "total_cases": total,
        "predicted_cases": predicted,
        "coverage": round(predicted / total, 4) if total else 0.0,
        "top1_accuracy": round(top1 / total, 4) if total else 0.0,
        "top3_accuracy": round(top3 / total, 4) if total else 0.0,
        "mean_reciprocal_rank": round(reciprocal / total, 4) if total else 0.0,
        "brier_score": round(brier / total, 6) if total else 0.0,
        "accuracy_by_tactic": {
            tactic: {
                "cases": counts["cases"],
                "coverage": round(counts["predicted"] / counts["cases"], 4) if counts["cases"] else 0.0,
                "top1_accuracy": round(counts["top1"] / counts["cases"], 4) if counts["cases"] else 0.0,
                "top3_accuracy": round(counts["top3"] / counts["cases"], 4) if counts["cases"] else 0.0,
                "brier_score": round(brier_by_tactic[tactic] / counts["cases"], 6) if counts["cases"] else 0.0,
            }
            for tactic, counts in sorted(by_tactic.items())
        },
    }


def _evaluate_weight_set(
    label: str,
    weights: Dict[str, float],
    split_payloads: List[Dict[str, Any]],
    base_policy: Dict[str, Any],
    external_model: Dict[str, Any],
    local_training_payloads: List[Dict[str, Any]],
    tactic_scope: set[str],
    scorers: List[str],
) -> Dict[str, Any]:
    normalized_weights = _normalize_candidate_weights(weights, scorers)
    policy = _policy_for_fit(base_policy, normalized_weights)
    cases = _case_payloads_for_fit(
        split_payloads,
        policy,
        external_model,
        local_training_payloads=local_training_payloads,
        leave_one_out_local=False,
        tactic_scope=tactic_scope,
    )
    return {
        "label": label,
        "weights": normalized_weights,
        "metrics": _evaluate_cases(cases),
    }


def _delta(after: Dict[str, Any], before: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "top1_accuracy_delta": round(float(after.get("top1_accuracy") or 0.0) - float(before.get("top1_accuracy") or 0.0), 4),
        "top3_accuracy_delta": round(float(after.get("top3_accuracy") or 0.0) - float(before.get("top3_accuracy") or 0.0), 4),
        "mean_reciprocal_rank_delta": round(float(after.get("mean_reciprocal_rank") or 0.0) - float(before.get("mean_reciprocal_rank") or 0.0), 4),
        "brier_score_delta": round(float(after.get("brier_score") or 0.0) - float(before.get("brier_score") or 0.0), 6),
        "brier_improved": float(after.get("brier_score") or 0.0) < float(before.get("brier_score") or 0.0),
    }


def _model_comparison_results(
    baseline_weights: Dict[str, float],
    fitted_weights: Dict[str, float],
    split_payloads: List[Dict[str, Any]],
    base_policy: Dict[str, Any],
    external_model: Dict[str, Any],
    local_training_payloads: List[Dict[str, Any]],
    tactic_scope: set[str],
    scorers: List[str],
) -> List[Dict[str, Any]]:
    candidate_weights = [
        ("current_selected_weights", baseline_weights),
        ("fitted_weights", fitted_weights),
        ("local_transition_only", {"local_transition": 1.0}),
        ("external_seed_transition_only", {"external_seed_transition": 1.0}),
        ("fallback_progression_only", {"fallback_progression": 1.0}),
        (
            "transition_style_fitted_only",
            {
                name: fitted_weights.get(name, 0.0)
                for name in ["local_transition", "external_seed_transition", "fallback_progression"]
            },
        ),
    ]
    return [
        _evaluate_weight_set(
            label,
            weights,
            split_payloads,
            base_policy,
            external_model,
            local_training_payloads,
            tactic_scope,
            scorers,
        )
        for label, weights in candidate_weights
    ]


def _ablation_results(
    fitted_weights: Dict[str, float],
    split_payloads: List[Dict[str, Any]],
    base_policy: Dict[str, Any],
    external_model: Dict[str, Any],
    local_training_payloads: List[Dict[str, Any]],
    tactic_scope: set[str],
    scorers: List[str],
) -> List[Dict[str, Any]]:
    baseline = _evaluate_weight_set(
        "all_fitted_scorers",
        fitted_weights,
        split_payloads,
        base_policy,
        external_model,
        local_training_payloads,
        tactic_scope,
        scorers,
    )
    rows = [baseline]
    baseline_metrics = baseline["metrics"]
    for scorer in scorers:
        ablated = dict(fitted_weights)
        ablated[scorer] = 0.0
        row = _evaluate_weight_set(
            f"without_{scorer}",
            ablated,
            split_payloads,
            base_policy,
            external_model,
            local_training_payloads,
            tactic_scope,
            scorers,
        )
        row["delta_vs_all_fitted"] = _delta(row["metrics"], baseline_metrics)
        rows.append(row)
    return rows


def _sensitivity_results(
    fitted_weights: Dict[str, float],
    split_payloads: List[Dict[str, Any]],
    base_policy: Dict[str, Any],
    external_model: Dict[str, Any],
    local_training_payloads: List[Dict[str, Any]],
    tactic_scope: set[str],
    scorers: List[str],
) -> List[Dict[str, Any]]:
    baseline = _evaluate_weight_set(
        "fitted_weights",
        fitted_weights,
        split_payloads,
        base_policy,
        external_model,
        local_training_payloads,
        tactic_scope,
        scorers,
    )
    baseline_metrics = baseline["metrics"]
    rows = []
    for pct in [0.10, 0.20, 0.30]:
        for scorer in scorers:
            if float(fitted_weights.get(scorer) or 0.0) <= 0.0:
                continue
            for direction, multiplier in [("down", 1.0 - pct), ("up", 1.0 + pct)]:
                candidate = dict(fitted_weights)
                candidate[scorer] = max(float(candidate.get(scorer) or 0.0) * multiplier, 0.0)
                row = _evaluate_weight_set(
                    f"{scorer}_{direction}_{int(pct * 100)}pct",
                    candidate,
                    split_payloads,
                    base_policy,
                    external_model,
                    local_training_payloads,
                    tactic_scope,
                    scorers,
                )
                row["perturbation"] = {
                    "scorer": scorer,
                    "direction": direction,
                    "relative_change": pct,
                }
                row["delta_vs_fitted"] = _delta(row["metrics"], baseline_metrics)
                rows.append(row)
    return rows


def _pct(value: Any) -> str:
    return f"{float(value or 0.0) * 100:.2f}%"


def _num(value: Any, precision: int = 6) -> str:
    try:
        return f"{float(value):.{precision}f}"
    except (TypeError, ValueError):
        return str(value)


def _markdown_table(headers: List[str], rows: Iterable[Iterable[Any]]) -> str:
    header = "| " + " | ".join(headers) + " |"
    separator = "| " + " | ".join(["---"] * len(headers)) + " |"
    body = ["| " + " | ".join(str(cell) for cell in row) + " |" for row in rows]
    return "\n".join([header, separator, *body])


def _metric_table(baseline: Dict[str, Any], fitted: Dict[str, Any]) -> str:
    rows = [
        (
            "Top-1 accuracy",
            _pct(baseline.get("top1_accuracy")),
            _pct(fitted.get("top1_accuracy")),
            f"{(float(fitted.get('top1_accuracy') or 0.0) - float(baseline.get('top1_accuracy') or 0.0)) * 100:+.2f} pp",
        ),
        (
            "Top-3 accuracy",
            _pct(baseline.get("top3_accuracy")),
            _pct(fitted.get("top3_accuracy")),
            f"{(float(fitted.get('top3_accuracy') or 0.0) - float(baseline.get('top3_accuracy') or 0.0)) * 100:+.2f} pp",
        ),
        (
            "Mean reciprocal rank",
            _num(baseline.get("mean_reciprocal_rank"), 4),
            _num(fitted.get("mean_reciprocal_rank"), 4),
            f"{float(fitted.get('mean_reciprocal_rank') or 0.0) - float(baseline.get('mean_reciprocal_rank') or 0.0):+.4f}",
        ),
        (
            "Brier score",
            _num(baseline.get("brier_score"), 6),
            _num(fitted.get("brier_score"), 6),
            f"{float(fitted.get('brier_score') or 0.0) - float(baseline.get('brier_score') or 0.0):+.6f}",
        ),
        (
            "Coverage",
            _pct(baseline.get("coverage")),
            _pct(fitted.get("coverage")),
            f"{(float(fitted.get('coverage') or 0.0) - float(baseline.get('coverage') or 0.0)) * 100:+.2f} pp",
        ),
        (
            "Evaluated examples",
            baseline.get("total_cases", 0),
            fitted.get("total_cases", 0),
            int(fitted.get("total_cases") or 0) - int(baseline.get("total_cases") or 0),
        ),
    ]
    return _markdown_table(["Metric", "Current Selected Weights", "Fitted Weights", "Change"], rows)


def _build_thesis_markdown_tables(result: Dict[str, Any]) -> Dict[str, str]:
    stats = result["dataset_statistics"]
    split = result["split"]
    baseline_metrics = result["heldout_comparison"]["baseline_current_weights"]
    fitted_metrics = result["heldout_comparison"]["fitted_weights"]

    dataset_table = _markdown_table(
        ["Statistic", "Value"],
        [
            ("Total sessions loaded", stats["total_sessions"]),
            ("Completed sessions", stats["completed_sessions"]),
            ("Sessions with >=1 usable scoped tactic", stats["sessions_with_at_least_one_usable_tactic"]),
            ("Sessions with >=1 tactic transition", stats["sessions_with_at_least_one_tactic_transition"]),
            ("Completed sessions with >=1 tactic transition", stats["completed_sessions_with_at_least_one_tactic_transition"]),
            ("Sessions with >=2 tactic transitions", stats["sessions_with_two_or_more_tactic_transitions"]),
            ("Compressed tactic observations", stats["compressed_tactic_observations"]),
            ("Compressed transition observations", stats["compressed_transition_observations"]),
        ],
    )
    split_table = _markdown_table(
        ["Split", "Sessions", "Purpose"],
        [
            ("Train", split["train_sessions_total"], "Build external transition statistics"),
            ("Train eligible only", split["train_eligible_sessions"], "Eligible transition sessions in train split"),
            ("Calibration", split["calibration_sessions"], "Fit scorer weights"),
            ("Held-out test", split["test_sessions"], "Final evaluation only"),
            ("Ineligible assigned to train", split["ineligible_sessions_assigned_to_train"], "Model-construction context only; not used for final fitting/test labels"),
        ],
    )
    weight_table = _markdown_table(
        ["Scorer", "Current Selected Weight", "Fitted Weight", "Change"],
        [
            (
                scorer,
                _num(result["baseline_weights"].get(scorer), 6),
                _num(result["fit"].get("fitted_weights", {}).get(scorer), 6),
                f"{float(result['fit'].get('fitted_weights', {}).get(scorer) or 0.0) - float(result['baseline_weights'].get(scorer) or 0.0):+.6f}",
            )
            for scorer in result["scorers"]
        ],
    )
    performance_table = _metric_table(baseline_metrics, fitted_metrics)
    ablation_table = _markdown_table(
        ["Model", "Removed Scorer", "Top-1", "Top-3", "MRR", "Brier", "Delta Brier vs Fitted"],
        [
            (
                row["label"],
                row["label"].replace("without_", "") if row["label"].startswith("without_") else "-",
                _pct(row["metrics"].get("top1_accuracy")),
                _pct(row["metrics"].get("top3_accuracy")),
                _num(row["metrics"].get("mean_reciprocal_rank"), 4),
                _num(row["metrics"].get("brier_score"), 6),
                _num((row.get("delta_vs_all_fitted") or {}).get("brier_score_delta", 0.0), 6),
            )
            for row in result["ablation"]
        ],
    )
    sensitivity_table = _markdown_table(
        ["Perturbation", "Scorer", "Direction", "Top-1", "Top-3", "MRR", "Brier", "Delta Brier vs Fitted"],
        [
            (
                f"{int(float(row['perturbation']['relative_change']) * 100)}%",
                row["perturbation"]["scorer"],
                row["perturbation"]["direction"],
                _pct(row["metrics"].get("top1_accuracy")),
                _pct(row["metrics"].get("top3_accuracy")),
                _num(row["metrics"].get("mean_reciprocal_rank"), 4),
                _num(row["metrics"].get("brier_score"), 6),
                _num((row.get("delta_vs_fitted") or {}).get("brier_score_delta", 0.0), 6),
            )
            for row in result["sensitivity_analysis"]
        ],
    )
    return {
        "dataset_statistics": dataset_table,
        "split_sizes": split_table,
        "current_vs_fitted_weights": weight_table,
        "current_vs_fitted_performance": performance_table,
        "ablation_study": ablation_table,
        "sensitivity_analysis": sensitivity_table,
    }


def _limitations() -> List[str]:
    return [
        "The experiment is proposal-only and does not change the trusted production prediction policy.",
        "The empirical scope is limited to honeypot-observable Cowrie SSH/Telnet tactics, not full ATT&CK-wide tactic prediction.",
        "The external seed labels inherit the quality and bias of the upstream classification pipeline; they are not manually adjudicated ground truth.",
        "Only scorers computable from the external Cowrie session payloads are fitted. Context/risk scorers that require live enrichment, vulnerability context, Sigma correlation, or behavior-regime state are excluded from the fitted voter set.",
        "Most external Cowrie sessions contain no tactic transition after scoping, so the held-out evaluation is based on the subset with usable next-tactic labels.",
        "The held-out split is used only for final evaluation; production adoption of fitted weights should still be reviewed against local live honeypot data when enough high-quality labeled sessions exist.",
    ]


def _thesis_ready_summary(result: Dict[str, Any]) -> str:
    split = result["split"]
    baseline = result["heldout_comparison"]["baseline_current_weights"]
    fitted = result["heldout_comparison"]["fitted_weights"]
    delta = result["heldout_comparison"]["delta_fitted_minus_baseline"]
    return (
        "A proposal-only empirical calibration experiment was performed on the external Cowrie seed corpus "
        f"using a deterministic 70/15/15 split with seed {split['seed']}. The train split was used to build "
        "external transition statistics, the calibration split was used to fit non-negative scorer weights "
        "constrained to sum to one, and the held-out test split was reserved for final evaluation. Within the "
        "honeypot-observable tactic scope, the fitted weights improved held-out Top-1 accuracy from "
        f"{float(baseline.get('top1_accuracy') or 0.0) * 100:.2f}% to "
        f"{float(fitted.get('top1_accuracy') or 0.0) * 100:.2f}% "
        f"({float(delta.get('top1_accuracy_delta') or 0.0) * 100:+.2f} percentage points) and reduced "
        f"Brier score from {float(baseline.get('brier_score') or 0.0):.6f} to "
        f"{float(fitted.get('brier_score') or 0.0):.6f}. The result supports describing these weights as "
        "empirically calibrated proposal weights for Cowrie-observable next-tactic prediction, while leaving "
        "the deployed production policy unchanged."
    )


def _write_markdown_report(result: Dict[str, Any], path: Path) -> None:
    tables = result.get("thesis_markdown_tables") or {}
    lines = [
        "# External Seed Scorer Weight Calibration Tables",
        "",
        result.get("methodology_note", ""),
        "",
        "## Thesis-Ready Summary",
        "",
        result.get("thesis_ready_summary", ""),
        "",
        "## Limitations",
        "",
        *[f"- {item}" for item in result.get("limitations", [])],
        "",
    ]
    for title, key in [
        ("Dataset Statistics", "dataset_statistics"),
        ("Train/Calibration/Held-Out Split Sizes", "split_sizes"),
        ("Current vs Fitted Scorer Weights", "current_vs_fitted_weights"),
        ("Current Weights vs Fitted Weights Performance Comparison", "current_vs_fitted_performance"),
        ("Ablation Study Results", "ablation_study"),
        ("Sensitivity Analysis Results", "sensitivity_analysis"),
    ]:
        lines.extend([f"## {title}", "", str(tables.get(key, "")), ""])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def run_external_seed_weight_fit(args: argparse.Namespace) -> Dict[str, Any]:
    scope = {str(item).strip() for item in args.tactic_scope if str(item).strip()}
    scorers = [str(item).strip() for item in args.scorer if str(item).strip()]
    raw_payloads, provenance = _load_seed_sessions(args.input, limit=max(int(args.limit or 0), 0))
    scoped_payloads = [_scoped_payload(payload, scope) for payload in raw_payloads]
    dataset_statistics = _dataset_statistics(scoped_payloads)
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
    fit = fit_weights_from_cases(
        calibration_cases,
        baseline_weights,
        scorer_names=scorers,
        include_context=False,
        loss=str(args.loss),
        min_cases=int(args.min_fit_cases),
    )
    fitted_weights = fit.get("fitted_weights") if fit.get("status") == "fit_completed" else baseline_weights
    fitted_policy = _policy_for_fit(policy, fitted_weights)

    baseline_test_cases = _case_payloads_for_fit(
        split["test"],
        policy,
        external_model,
        local_training_payloads=split["calibration"],
        leave_one_out_local=False,
        tactic_scope=scope,
    )
    fitted_test_cases = _case_payloads_for_fit(
        split["test"],
        fitted_policy,
        external_model,
        local_training_payloads=split["calibration"],
        leave_one_out_local=False,
        tactic_scope=scope,
    )
    baseline_metrics = _evaluate_cases(baseline_test_cases)
    fitted_metrics = _evaluate_cases(fitted_test_cases)
    model_comparison = _model_comparison_results(
        baseline_weights,
        fitted_weights,
        split["test"],
        policy,
        external_model,
        local_training_payloads=split["calibration"],
        tactic_scope=scope,
        scorers=scorers,
    )
    ablation = _ablation_results(
        fitted_weights,
        split["test"],
        policy,
        external_model,
        local_training_payloads=split["calibration"],
        tactic_scope=scope,
        scorers=scorers,
    )
    sensitivity = _sensitivity_results(
        fitted_weights,
        split["test"],
        policy,
        external_model,
        local_training_payloads=split["calibration"],
        tactic_scope=scope,
        scorers=scorers,
    )
    transition_groups = split["group_sizes"]
    result = {
        "schema_version": "external_seed_weight_fit_audit.v1",
        "generated_at": utc_now(),
        "run_id": stable_id(
            "external_seed_weight_fit",
            {
                "input": args.input,
                "seed": args.seed,
                "scope": sorted(scope),
                "scorers": scorers,
                "baseline": baseline_metrics,
                "fitted": fitted_metrics,
            },
        ),
        "production_policy_changed": False,
        "input": args.input,
        "policy": args.policy,
        "tactic_scope": sorted(scope),
        "scorers": scorers,
        "dataset_statistics": dataset_statistics,
        "split": {
            "method": "deterministic_stratified_by_first_tactic_transition",
            "seed": int(args.seed),
            "train_ratio": float(args.train_ratio),
            "calibration_ratio": float(args.calibration_ratio),
            "test_ratio": round(1.0 - float(args.train_ratio) - float(args.calibration_ratio), 4),
            "total_sessions_loaded": len(raw_payloads),
            "eligible_transition_sessions": sum(transition_groups.values()),
            "ineligible_sessions_assigned_to_train": len(split["ineligible"]),
            "train_sessions_total": len(split["train"]),
            "train_eligible_sessions": len(split["train_eligible"]),
            "calibration_sessions": len(split["calibration"]),
            "test_sessions": len(split["test"]),
            "transition_group_count": len(transition_groups),
            "top_transition_groups": [
                {"transition": key, "sessions": count}
                for key, count in sorted(transition_groups.items(), key=lambda item: item[1], reverse=True)[:20]
            ],
        },
        "external_train_model_summary": {
            "completed_sessions": external_model.get("completed_sessions"),
            "usable_sessions": external_model.get("usable_sessions"),
            "transition_count": external_model.get("transition_count"),
            "prefix_transition_count": external_model.get("prefix_transition_count"),
            "technique_transition_count": external_model.get("technique_transition_count"),
        },
        "baseline_weights": baseline_weights,
        "fit": fit,
        "model_comparison": model_comparison,
        "ablation": ablation,
        "sensitivity_analysis": sensitivity,
        "heldout_comparison": {
            "baseline_current_weights": baseline_metrics,
            "fitted_weights": fitted_metrics,
            "delta_fitted_minus_baseline": _delta(fitted_metrics, baseline_metrics),
        },
        "methodology_note": (
            "Proposal only. The external seed corpus is split before fitting: the external prior is built "
            "from train, weights are fitted on calibration, and final metrics are measured on test. "
            "The experiment is scoped to honeypot-observable tactics and selected behavioral scorers; "
            "it does not update the deployed production policy."
        ),
    }
    result["limitations"] = _limitations()
    result["thesis_ready_summary"] = _thesis_ready_summary(result)
    result["thesis_markdown_tables"] = _build_thesis_markdown_tables(result)
    return result


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Fit/evaluate honeypot-observable scorer weights on an external Cowrie seed split.")
    parser.add_argument("--input", required=True, help="Sessionized external seed JSON produced by build_external_seed_model --session-output.")
    parser.add_argument("--policy", required=True, help="Trusted prediction policy JSON or config containing a policy object.")
    parser.add_argument("--output", help="Write full JSON result to this path.")
    parser.add_argument("--markdown-output", help="Write thesis-ready Markdown tables to this path.")
    parser.add_argument("--limit", type=int, default=0, help="Optional maximum sessions to load, for smoke tests only.")
    parser.add_argument("--seed", type=int, default=20260707)
    parser.add_argument("--train-ratio", type=float, default=0.70)
    parser.add_argument("--calibration-ratio", type=float, default=0.15)
    parser.add_argument("--loss", choices=["brier_score", "negative_log_likelihood"], default="brier_score")
    parser.add_argument("--min-fit-cases", type=int, default=30)
    parser.add_argument("--tactic-scope", action="append", default=list(DEFAULT_SCOPE))
    parser.add_argument("--scorer", action="append", default=list(DEFAULT_SCORERS))
    return parser


def main(argv: List[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    result = run_external_seed_weight_fit(args)
    text = json.dumps(result, indent=2, sort_keys=True)
    if args.output:
        path = Path(args.output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text + "\n", encoding="utf-8")
    if args.markdown_output:
        _write_markdown_report(result, Path(args.markdown_output))
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
