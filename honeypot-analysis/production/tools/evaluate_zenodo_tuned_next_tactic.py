"""Calibration-only tuning for the Zenodo 500 MB next-tactic comparison.

This module is evaluation-only. It consumes the privacy-minimized, pre-split
session payload and writes aggregate metrics; it does not alter runtime policy,
weights, transition artifacts, or services.
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Sequence

from production.prediction.realtime_prediction import build_transition_model
from production.tools.evaluate_next_tactic_model_comparison import (
    DEFAULT_SEED,
    EvaluationCase,
    Predictor,
    _engine_predictor,
    _fallback_predictor,
    _first_order_predictor,
    build_cases,
    load_policy,
    load_session_payloads,
    split_session_payloads,
    summarize_predictions,
    trusted_tactic_sequence,
)


DEFAULT_INPUT = "evaluation/next_tactic_zenodo_500mb_session_payload.jsonl"
DEFAULT_PRIOR_PAYLOAD = "evaluation/next_tactic_zenodo_session_payload.jsonl"
DEFAULT_PRIOR_RESULT = "evaluation/next_tactic_zenodo_model_comparison.json"
DEFAULT_500MB_RESULT = "evaluation/next_tactic_zenodo_500mb_model_comparison.json"
DEFAULT_OUTPUT_JSON = "evaluation/next_tactic_zenodo_500mb_tuned_comparison.json"
DEFAULT_OUTPUT_CSV = "evaluation/next_tactic_zenodo_500mb_tuned_comparison.csv"
DEFAULT_POLICY = "configs/prediction_policy.trusted.json"
MIN_REPORTABLE_SUPPORT = 30
DIFFICULT_TACTICS = (
    "persistence",
    "privilege-escalation",
    "credential-access",
    "lateral-movement",
)


@dataclass(frozen=True)
class CountModel:
    contexts: Dict[int, Dict[tuple[str, ...], Counter[str]]]
    target_counts: Counter[str]
    configuration_contexts: Dict[
        str, Dict[int, Dict[tuple[str, ...], Counter[str]]]
    ]


def _sequence(payload: Mapping[str, Any]) -> list[str]:
    return trusted_tactic_sequence(dict(payload))


def _configuration(payload: Mapping[str, Any]) -> str:
    return str(payload.get("honeypot_configuration") or "unknown")


def build_count_model(
    payloads: Iterable[Mapping[str, Any]], *, max_order: int
) -> CountModel:
    contexts: Dict[int, Dict[tuple[str, ...], Counter[str]]] = {
        order: defaultdict(Counter) for order in range(1, max_order + 1)
    }
    configuration_contexts: Dict[
        str, Dict[int, Dict[tuple[str, ...], Counter[str]]]
    ] = {}
    targets: Counter[str] = Counter()
    for payload in payloads:
        sequence = _sequence(payload)
        if len(sequence) < 2:
            continue
        config = _configuration(payload)
        if config not in configuration_contexts:
            configuration_contexts[config] = {
                order: defaultdict(Counter)
                for order in range(1, max_order + 1)
            }
        for target_index in range(1, len(sequence)):
            target = sequence[target_index]
            targets[target] += 1
            prefix = sequence[:target_index]
            for order in range(1, min(max_order, len(prefix)) + 1):
                context = tuple(prefix[-order:])
                contexts[order][context][target] += 1
                configuration_contexts[config][order][context][target] += 1
    return CountModel(
        contexts={order: dict(values) for order, values in contexts.items()},
        target_counts=targets,
        configuration_contexts={
            config: {order: dict(values) for order, values in by_order.items()}
            for config, by_order in configuration_contexts.items()
        },
    )


def _normalize(values: Mapping[str, float]) -> Dict[str, float]:
    clean = {
        str(label): max(float(value), 0.0)
        for label, value in values.items()
        if str(label) and float(value) > 0.0
    }
    total = sum(clean.values())
    return {label: value / total for label, value in clean.items()} if total else {}


def _categorical(
    counts: Mapping[str, int | float],
    vocabulary: Sequence[str],
    *,
    alpha: float,
) -> Dict[str, float]:
    denominator = sum(float(value) for value in counts.values()) + alpha * len(
        vocabulary
    )
    if denominator <= 0.0:
        return {}
    return {
        label: (float(counts.get(label, 0.0)) + alpha) / denominator
        for label in vocabulary
    }


def _blend(
    primary: Mapping[str, float],
    lower: Mapping[str, float],
    weight: float,
    vocabulary: Sequence[str],
) -> Dict[str, float]:
    return _normalize(
        {
            label: weight * float(primary.get(label, 0.0))
            + (1.0 - weight) * float(lower.get(label, 0.0))
            for label in vocabulary
        }
    )


def _prefix(case: EvaluationCase) -> list[str]:
    return [
        str(value)
        for value in case.features.get("tactic_sequence") or []
        if str(value)
    ]


def hard_backoff_probabilities(
    model: CountModel,
    case: EvaluationCase,
    vocabulary: Sequence[str],
    *,
    max_context: int,
    min_support: int,
    alpha: float,
) -> Dict[str, float]:
    prefix = _prefix(case)
    for order in range(min(max_context, len(prefix)), 0, -1):
        counts = model.contexts.get(order, {}).get(tuple(prefix[-order:]), Counter())
        if sum(counts.values()) >= min_support:
            return _categorical(counts, vocabulary, alpha=alpha)
    return {}


def interpolated_probabilities(
    model: CountModel,
    case: EvaluationCase,
    vocabulary: Sequence[str],
    *,
    max_context: int,
    min_support: int,
    alpha: float,
    kappa: float,
) -> Dict[str, float]:
    distribution = _categorical(model.target_counts, vocabulary, alpha=alpha)
    prefix = _prefix(case)
    for order in range(1, min(max_context, len(prefix)) + 1):
        counts = model.contexts.get(order, {}).get(tuple(prefix[-order:]), Counter())
        support = sum(counts.values())
        if support < min_support:
            continue
        context_distribution = _categorical(counts, vocabulary, alpha=alpha)
        interpolation_weight = support / (support + kappa)
        distribution = _blend(
            context_distribution,
            distribution,
            interpolation_weight,
            vocabulary,
        )
    return distribution


def configuration_aware_probabilities(
    model: CountModel,
    case: EvaluationCase,
    vocabulary: Sequence[str],
    *,
    max_context: int,
    min_support: int,
    alpha: float,
    kappa: float,
) -> Dict[str, float]:
    distribution = interpolated_probabilities(
        model,
        case,
        vocabulary,
        max_context=max_context,
        min_support=min_support,
        alpha=alpha,
        kappa=kappa,
    )
    configuration = str(case.features.get("honeypot_configuration") or "unknown")
    config_contexts = model.configuration_contexts.get(configuration, {})
    prefix = _prefix(case)
    for order in range(1, min(max_context, len(prefix)) + 1):
        counts = config_contexts.get(order, {}).get(tuple(prefix[-order:]), Counter())
        support = sum(counts.values())
        if support < min_support:
            continue
        context_distribution = _categorical(counts, vocabulary, alpha=alpha)
        configuration_weight = support / (support + kappa)
        distribution = _blend(
            context_distribution,
            distribution,
            configuration_weight,
            vocabulary,
        )
    return distribution


def configuration_hard_backoff_probabilities(
    model: CountModel,
    case: EvaluationCase,
    vocabulary: Sequence[str],
    *,
    max_context: int,
    min_support: int,
    alpha: float,
) -> Dict[str, float]:
    """Use the longest supported configuration context, then global backoff."""

    configuration = str(case.features.get("honeypot_configuration") or "unknown")
    config_contexts = model.configuration_contexts.get(configuration, {})
    prefix = _prefix(case)
    for order in range(min(max_context, len(prefix)), 0, -1):
        counts = config_contexts.get(order, {}).get(tuple(prefix[-order:]), Counter())
        if sum(counts.values()) >= min_support:
            return _categorical(counts, vocabulary, alpha=alpha)
    return hard_backoff_probabilities(
        model,
        case,
        vocabulary,
        max_context=max_context,
        min_support=min_support,
        alpha=alpha,
    )


def _thresholded(
    probabilities: Mapping[str, float],
    case: EvaluationCase,
    *,
    threshold: float,
    fallback: Predictor | None,
) -> Dict[str, float]:
    normalized = _normalize(probabilities)
    if normalized and max(normalized.values()) >= threshold:
        return normalized
    return fallback.predict(case) if fallback is not None else {}


def _count_predictor(
    model_kind: str,
    model: CountModel,
    vocabulary: Sequence[str],
    settings: Mapping[str, Any],
    fallback: Predictor,
) -> Predictor:
    fallback_model = fallback if settings["fallback_mode"] == "fixed_progression" else None

    def predict(case: EvaluationCase) -> Dict[str, float]:
        common = {
            "max_context": int(settings["max_context"]),
            "min_support": int(settings["min_support"]),
            "alpha": float(settings["alpha"]),
        }
        if model_kind == "dirichlet_vomm":
            probabilities = hard_backoff_probabilities(
                model, case, vocabulary, **common
            )
        elif model_kind == "interpolated_ngram":
            probabilities = interpolated_probabilities(
                model,
                case,
                vocabulary,
                kappa=float(settings["kappa"]),
                **common,
            )
        elif model_kind == "configuration_aware_vomm":
            probabilities = configuration_aware_probabilities(
                model,
                case,
                vocabulary,
                kappa=float(settings["kappa"]),
                **common,
            )
        elif model_kind == "configuration_hard_backoff_vomm":
            probabilities = configuration_hard_backoff_probabilities(
                model, case, vocabulary, **common
            )
        else:
            raise ValueError(f"unknown model kind: {model_kind}")
        return _thresholded(
            probabilities,
            case,
            threshold=float(settings["confidence_threshold"]),
            fallback=fallback_model,
        )

    return Predictor(predict=predict, metadata={"settings": dict(settings)})


def _search_options(model_kind: str) -> Dict[str, Sequence[Any]]:
    options: Dict[str, Sequence[Any]] = {
        "max_context": (1, 2, 3, 4),
        "min_support": (1, 2, 5, 10),
        "alpha": (0.01, 0.05, 0.1, 0.5),
        "confidence_threshold": (0.0, 0.5, 0.7),
        "fallback_mode": ("abstain", "fixed_progression"),
    }
    if model_kind in {"interpolated_ngram", "configuration_aware_vomm"}:
        options["kappa"] = (1.0, 5.0, 20.0, 100.0)
    return options


def _selection_key(row: Mapping[str, Any]) -> tuple[Any, ...]:
    metrics = row["metrics"]
    return (
        -float(metrics.get("balanced_accuracy") or -1.0),
        -float(metrics.get("top1_accuracy") or -1.0),
        -float(metrics.get("mean_reciprocal_rank") or -1.0),
        float(metrics.get("normalized_multiclass_brier_score") or 1.0),
        -float(metrics.get("coverage") or 0.0),
        int(row["settings"]["max_context"]),
        int(row["settings"]["min_support"]),
        float(row["settings"]["alpha"]),
        float(row["settings"].get("kappa", 0.0)),
        float(row["settings"]["confidence_threshold"]),
        str(row["settings"]["fallback_mode"]),
    )


def _selection_metrics(metrics: Mapping[str, Any]) -> Dict[str, Any]:
    """Keep only calibration fields used for selection and audit."""

    fields = (
        "evaluated_examples",
        "top1_accuracy",
        "top3_accuracy_secondary",
        "mean_reciprocal_rank",
        "normalized_multiclass_brier_score",
        "coverage",
        "abstention_rate",
        "selective_top1_accuracy",
        "balanced_accuracy",
    )
    return {field: metrics.get(field) for field in fields}


def tune_model(
    model_kind: str,
    training_payloads: Sequence[Mapping[str, Any]],
    calibration_cases: Sequence[EvaluationCase],
    vocabulary: Sequence[str],
    fallback: Predictor,
) -> Dict[str, Any]:
    model = build_count_model(training_payloads, max_order=4)
    current: Dict[str, Any] = {
        "max_context": 3,
        "min_support": 2,
        "alpha": 0.05,
        "confidence_threshold": 0.0,
        "fallback_mode": "abstain",
    }
    if model_kind in {"interpolated_ngram", "configuration_aware_vomm"}:
        current["kappa"] = 20.0
    evaluated: Dict[str, Dict[str, Any]] = {}

    def evaluate_settings(settings: Mapping[str, Any]) -> Dict[str, Any]:
        key = json.dumps(dict(settings), sort_keys=True)
        if key in evaluated:
            return evaluated[key]
        predictor = _count_predictor(
            model_kind, model, vocabulary, settings, fallback
        )
        metrics = summarize_predictions(
            calibration_cases,
            predictor,
            bootstrap_iterations=0,
            seed=DEFAULT_SEED,
            min_per_tactic_support=1,
            target_vocabulary=vocabulary,
        )
        row = {
            "settings": dict(settings),
            "metrics": _selection_metrics(metrics),
        }
        evaluated[key] = row
        return row

    coordinate_trace = []
    evaluate_settings(current)
    for pass_number in (1, 2):
        for parameter, values in _search_options(model_kind).items():
            candidates = []
            for value in values:
                candidate = dict(current)
                candidate[parameter] = value
                candidates.append(evaluate_settings(candidate))
            selected = min(candidates, key=_selection_key)
            current = dict(selected["settings"])
            coordinate_trace.append(
                {
                    "pass": pass_number,
                    "parameter": parameter,
                    "selected_value": current[parameter],
                    "selected_metrics": selected["metrics"],
                }
            )
    rows = list(evaluated.values())
    ranked = sorted(rows, key=_selection_key)
    return {
        "model_id": model_kind,
        "selection_partition": "calibration_only",
        "search_method": "deterministic_two_pass_coordinate_search",
        "search_limitation": "not an exhaustive Cartesian grid and not guaranteed to find the global optimum",
        "primary_objective": "balanced_accuracy",
        "tie_breakers": [
            "pooled_top1_accuracy",
            "mean_reciprocal_rank",
            "lower_normalized_multiclass_brier_score",
            "coverage",
            "lower_complexity",
        ],
        "candidate_count": len(rows),
        "coordinate_trace": coordinate_trace,
        "selected_settings": dict(ranked[0]["settings"]),
        "selected_calibration_metrics": ranked[0]["metrics"],
        "top_20_calibration_candidates": ranked[:20],
    }


def _attach_configurations(
    cases: Sequence[EvaluationCase], payloads: Sequence[Mapping[str, Any]]
) -> None:
    configurations = {
        str(payload.get("session_id") or "unknown"): _configuration(payload)
        for payload in payloads
    }
    for case in cases:
        case.features["honeypot_configuration"] = configurations.get(
            case.session_id, "unknown"
        )


def _distribution_summary(
    split: Mapping[str, Sequence[Mapping[str, Any]]]
) -> Dict[str, Any]:
    output: Dict[str, Any] = {}
    for split_name, payloads in split.items():
        by_tactic: Counter[str] = Counter()
        by_configuration: Counter[str] = Counter()
        by_configuration_tactic: Dict[str, Counter[str]] = defaultdict(Counter)
        transition_sessions = 0
        for payload in payloads:
            sequence = _sequence(payload)
            config = _configuration(payload)
            by_configuration[config] += 1
            if len(sequence) >= 2:
                transition_sessions += 1
                for target in sequence[1:]:
                    by_tactic[target] += 1
                    by_configuration_tactic[config][target] += 1
        output[split_name] = {
            "sessions": len(payloads),
            "transition_sessions": transition_sessions,
            "transitions": sum(by_tactic.values()),
            "target_tactics": dict(sorted(by_tactic.items())),
            "sessions_by_configuration": dict(sorted(by_configuration.items())),
            "targets_by_configuration": {
                config: dict(sorted(counts.items()))
                for config, counts in sorted(by_configuration_tactic.items())
            },
        }
    return output


def _transition_summary(
    split: Mapping[str, Sequence[Mapping[str, Any]]]
) -> Dict[str, Dict[str, int]]:
    output = {}
    for split_name, payloads in split.items():
        counts: Counter[str] = Counter()
        for payload in payloads:
            sequence = _sequence(payload)
            counts.update(
                f"{source}>{target}"
                for source, target in zip(sequence, sequence[1:])
            )
        output[split_name] = dict(counts.most_common())
    return output


def _split_overlap(split: Mapping[str, Sequence[Mapping[str, Any]]]) -> Dict[str, bool]:
    ids = {
        name: {str(payload.get("session_id") or "unknown") for payload in payloads}
        for name, payloads in split.items()
    }
    return {
        "train_calibration": bool(ids["train"] & ids["calibration"]),
        "train_test": bool(ids["train"] & ids["test"]),
        "calibration_test": bool(ids["calibration"] & ids["test"]),
    }


def _row(model_id: str, model_name: str, metrics: Mapping[str, Any], metadata: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "model_id": model_id,
        "model": model_name,
        "metrics": dict(metrics),
        "model_metadata": dict(metadata),
    }


def _group_metrics(
    cases: Sequence[EvaluationCase],
    predictor: Predictor,
    vocabulary: Sequence[str],
) -> Dict[str, Any]:
    grouped: Dict[str, list[EvaluationCase]] = defaultdict(list)
    for case in cases:
        grouped[str(case.features.get("honeypot_configuration") or "unknown")].append(case)
    return {
        config: summarize_predictions(
            config_cases,
            predictor,
            bootstrap_iterations=0,
            seed=DEFAULT_SEED,
            min_per_tactic_support=MIN_REPORTABLE_SUPPORT,
            target_vocabulary=vocabulary,
        )
        for config, config_cases in sorted(grouped.items())
    }


def _load_prior_summary(path: str) -> Dict[str, Any]:
    source = Path(path)
    if not source.exists():
        return {"available": False, "path": path}
    document = json.loads(source.read_text(encoding="utf-8"))
    rows = document.get("rows") or []
    if not rows:
        evaluations = document.get("evaluations") or []
        external = next(
            (
                evaluation
                for evaluation in evaluations
                if isinstance(evaluation, dict)
                and evaluation.get("scope") == "external"
            ),
            {},
        )
        rows = external.get("rows") or []
    return {
        "available": True,
        "path": path,
        "models": {
            str(row.get("model_id")): row.get("metrics")
            for row in rows
            if row.get("metrics")
        },
    }


def evaluate(args: argparse.Namespace) -> Dict[str, Any]:
    payloads = load_session_payloads(args.input)
    split, split_method = split_session_payloads(payloads)
    train = split["train"]
    calibration = split["calibration"]
    test = split["test"]
    train_cases = build_cases(train)
    calibration_cases = build_cases(calibration)
    test_cases = build_cases(test)
    for cases, source in (
        (train_cases, train),
        (calibration_cases, calibration),
        (test_cases, test),
    ):
        _attach_configurations(cases, source)

    policy = load_policy(args.policy)
    fallback = _fallback_predictor(policy)
    train_vocabulary = sorted({case.actual for case in train_cases})
    fit_payloads = list(train) + list(calibration)
    fit_vocabulary = sorted({case.actual for case in train_cases + calibration_cases})

    tuning = {}
    for model_kind in (
        "dirichlet_vomm",
        "interpolated_ngram",
        "configuration_aware_vomm",
    ):
        print(f"calibrating {model_kind}", flush=True)
        tuning[model_kind] = tune_model(
            model_kind,
            train,
            calibration_cases,
            train_vocabulary,
            fallback,
        )
        print(
            f"selected {model_kind}: {tuning[model_kind]['selected_settings']}",
            flush=True,
        )

    fit_count_model = build_count_model(fit_payloads, max_order=4)
    external_transition_model = build_transition_model(
        fit_payloads,
        prefix_max_length=int(policy.get("prefix_max_length", 3)),
        source_name="external_seed_transition",
    )
    empty_local_model = build_transition_model([])
    predictors: Dict[str, tuple[str, Predictor]] = {
        "first_order_markov": (
            "First-order Markov Chain (maximum likelihood)",
            _first_order_predictor(fit_payloads),
        ),
        "current_hard_backoff_vomm": (
            "Current support-gated hard-backoff VOMM with fixed fallback",
            _engine_predictor(
                policy,
                empty_local_model,
                external_transition_model,
            ),
        ),
        "external_only_vomm": (
            "External-only support-gated hard-backoff VOMM",
            _engine_predictor(
                policy,
                empty_local_model,
                external_transition_model,
                source_order=["external_seed_transition"],
                fallback_scorer="__no_fallback__",
            ),
        ),
    }
    for model_kind, model_name in (
        ("dirichlet_vomm", "Calibration-tuned Dirichlet-smoothed hard-backoff VOMM"),
        ("interpolated_ngram", "Calibration-tuned interpolated n-gram Markov model"),
        ("configuration_aware_vomm", "Calibration-tuned configuration-aware interpolated VOMM"),
    ):
        predictors[model_kind] = (
            model_name,
            _count_predictor(
                model_kind,
                fit_count_model,
                fit_vocabulary,
                tuning[model_kind]["selected_settings"],
                fallback,
            ),
        )

    rows = []
    for index, (model_id, (model_name, predictor)) in enumerate(predictors.items()):
        print(f"testing {model_id}", flush=True)
        metrics = summarize_predictions(
            test_cases,
            predictor,
            bootstrap_iterations=args.bootstrap_iterations,
            seed=args.seed + index * 1009,
            min_per_tactic_support=MIN_REPORTABLE_SUPPORT,
            target_vocabulary=fit_vocabulary,
        )
        metadata = dict(predictor.metadata)
        if model_id in tuning:
            metadata["calibration_selection"] = {
                "primary_objective": tuning[model_id]["primary_objective"],
                "selected_settings": tuning[model_id]["selected_settings"],
                "selected_calibration_metrics": tuning[model_id][
                    "selected_calibration_metrics"
                ],
            }
        rows.append(_row(model_id, model_name, metrics, metadata))

    selected_model = max(
        rows,
        key=lambda row: (
            float(row["metrics"].get("balanced_accuracy") or -1.0),
            float(row["metrics"].get("top1_accuracy") or -1.0),
        ),
    )
    rows_by_id = {row["model_id"]: row for row in rows}
    configuration_metrics = {
        model_id: _group_metrics(test_cases, predictor, fit_vocabulary)
        for model_id, (_name, predictor) in predictors.items()
    }
    reaches_70 = [
        row["model_id"]
        for row in rows
        if float(row["metrics"].get("top1_accuracy") or 0.0) >= 0.70
    ]

    prior_payload_distribution: Dict[str, Any] = {"available": False}
    if Path(args.prior_payload).exists():
        prior_payloads = load_session_payloads(args.prior_payload)
        prior_split, prior_split_method = split_session_payloads(prior_payloads)
        prior_payload_distribution = {
            "available": True,
            "path": args.prior_payload,
            "split_method": prior_split_method,
            "data_distribution": _distribution_summary(prior_split),
        }

    return {
        "schema_version": "next_tactic_zenodo_tuned_comparison.v1",
        "evaluation_scope": "Zenodo COW160x4 500 MB privacy-minimized weak-label sample",
        "runtime_behavior_changed": False,
        "input": args.input,
        "split_method": split_method,
        "split_integrity": {
            "whole_session_split": True,
            "overlap_detected": _split_overlap(split),
            "test_used_for_hyperparameter_selection": False,
            "calibration_used_for_hyperparameter_selection": True,
            "final_models_refit_on_train_plus_calibration": True,
            "important_limitation": (
                "This held-out partition appeared in an earlier evaluation and is therefore "
                "a repeated-holdout comparative test, not a fresh confirmatory holdout."
            ),
        },
        "selection_policy": {
            "primary_objective": "balanced_accuracy on calibration only",
            "reason": "reduce majority-class optimization under severe target imbalance",
            "test_evaluations_per_final_model": 1,
            "no_daily_member_cherry_picking": True,
            "no_tactics_removed": True,
        },
        "data_distribution": _distribution_summary(split),
        "transition_distribution": _transition_summary(split),
        "daily_distribution_availability": {
            "available": False,
            "reason": (
                "The privacy-minimized payload intentionally omits dates/timestamps and raw "
                "staging data was deleted; the two selected daily members cannot be separated "
                "without reprocessing private raw telemetry."
            ),
            "known_members": ["2025-06-29", "2025-08-17"],
        },
        "tuning": tuning,
        "test_rows": rows,
        "configuration_level_test_metrics": configuration_metrics,
        "best_test_row_for_descriptive_comparison_only": selected_model["model_id"],
        "models_reaching_pooled_top1_70_percent": reaches_70,
        "seventy_percent_conclusion": (
            "At least one calibration-selected model reached pooled Top-1 >= 70%; because this "
            "test split was previously inspected, confirmation requires fresh chronological days."
            if reaches_70
            else "No defensible calibration-selected model reached pooled Top-1 >= 70% on this held-out split."
        ),
        "difficult_tactic_results": {
            model_id: {
                tactic: row["metrics"]["per_tactic"].get(tactic)
                for tactic in DIFFICULT_TACTICS
            }
            for model_id, row in rows_by_id.items()
        },
        "comparison_context": {
            "previous_one_day": _load_prior_summary(args.prior_result),
            "previous_one_day_payload_distribution": prior_payload_distribution,
            "previous_500mb": _load_prior_summary(args.previous_500mb_result),
            "drop_explanation_evidence": [
                "The one-day sample was dominated by repeated configuration-specific transition cycles.",
                "The 500 MB test partition contains target and transition patterns that are absent or rare in train/calibration.",
                "Privilege escalation has 151 test targets but no calibration targets and only 12 train targets.",
                "The privacy-minimized 500 MB sample has fewer trusted transitions than the prior one-day sample despite more compressed bytes.",
            ],
        },
        "claim_limits": [
            "Targets are classifier-derived weak labels, not independent expert ground truth.",
            "Pooled Top-1 is imbalance-sensitive and must be reported with balanced and per-tactic metrics.",
            "No held-out lateral-movement target exists, so its accuracy is not estimable.",
            "Calibration contains no privilege-escalation target, preventing direct tuning for that class.",
            "Configuration-aware results may reflect collection configuration as well as attacker behavior.",
            "A fresh chronological member set is required for a confirmatory improvement claim.",
        ],
    }


def write_csv(path: str, result: Mapping[str, Any]) -> None:
    fields = [
        "row_type",
        "model_id",
        "configuration",
        "tactic",
        "support",
        "top1_accuracy",
        "balanced_accuracy",
        "top3_accuracy_secondary",
        "mean_reciprocal_rank",
        "normalized_multiclass_brier_score",
        "coverage",
        "abstention_rate",
        "selective_top1_accuracy",
    ]
    rows = []
    for model in result["test_rows"]:
        metrics = model["metrics"]
        rows.append(
            {
                "row_type": "pooled",
                "model_id": model["model_id"],
                "configuration": "all",
                "tactic": "all",
                "support": metrics["evaluated_examples"],
                **{field: metrics.get(field) for field in fields if field in metrics},
            }
        )
        for tactic, tactic_metrics in metrics["per_tactic"].items():
            descriptive = tactic_metrics.get("descriptive_only") or {}
            rows.append(
                {
                    "row_type": "per_tactic",
                    "model_id": model["model_id"],
                    "configuration": "all",
                    "tactic": tactic,
                    "support": tactic_metrics["support"],
                    "top1_accuracy": tactic_metrics.get("top1_accuracy")
                    if tactic_metrics.get("top1_accuracy") is not None
                    else descriptive.get("top1_accuracy"),
                    "mean_reciprocal_rank": tactic_metrics.get("mean_reciprocal_rank")
                    if tactic_metrics.get("mean_reciprocal_rank") is not None
                    else descriptive.get("mean_reciprocal_rank"),
                    "normalized_multiclass_brier_score": tactic_metrics.get(
                        "normalized_multiclass_brier_score"
                    )
                    if tactic_metrics.get("normalized_multiclass_brier_score") is not None
                    else descriptive.get("normalized_multiclass_brier_score"),
                }
            )
    for model_id, by_configuration in result["configuration_level_test_metrics"].items():
        for configuration, metrics in by_configuration.items():
            rows.append(
                {
                    "row_type": "per_configuration",
                    "model_id": model_id,
                    "configuration": configuration,
                    "tactic": "all",
                    "support": metrics["evaluated_examples"],
                    **{field: metrics.get(field) for field in fields if field in metrics},
                }
            )
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", default=DEFAULT_INPUT)
    parser.add_argument("--policy", default=DEFAULT_POLICY)
    parser.add_argument("--prior-payload", default=DEFAULT_PRIOR_PAYLOAD)
    parser.add_argument("--prior-result", default=DEFAULT_PRIOR_RESULT)
    parser.add_argument("--previous-500mb-result", default=DEFAULT_500MB_RESULT)
    parser.add_argument("--output-json", default=DEFAULT_OUTPUT_JSON)
    parser.add_argument("--output-csv", default=DEFAULT_OUTPUT_CSV)
    parser.add_argument("--bootstrap-iterations", type=int, default=500)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    result = evaluate(args)
    destination = Path(args.output_json)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    write_csv(args.output_csv, result)
    print(json.dumps({
        "output_json": args.output_json,
        "output_csv": args.output_csv,
        "models_reaching_70_percent": result["models_reaching_pooled_top1_70_percent"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
