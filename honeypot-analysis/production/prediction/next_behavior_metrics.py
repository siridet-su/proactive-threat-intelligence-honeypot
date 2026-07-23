"""Dependency-aware metrics for corrected next-behavior predictions.

All ranking metrics exclude terminal examples.  Reportability requires both
the configured number of positive target rows and independently identified
sessions.  Confidence intervals resample whole sessions, never transition
rows, and paired comparisons keep the same sampled clusters for both models.
"""

from __future__ import annotations

import math
import random
from collections import Counter, defaultdict
from copy import deepcopy
from typing import Any, Callable, Dict, Iterable, List, Mapping, Sequence

from production.prediction.next_behavior_contract import (
    TARGET_CONTRACT_ID,
    TACTIC_VOCABULARY,
)

DEFAULT_MIN_TARGET_SESSIONS = 30
DEFAULT_MIN_TARGETS = 30
DEFAULT_BOOTSTRAP_SEED = 1729
METRICS_SCHEMA_VERSION = "next_behavior_metrics.v1"
PAIRED_COMPARISON_SCHEMA_VERSION = "next_behavior_paired_comparison.v1"


class NextBehaviorMetricsError(ValueError):
    """Raised when examples and predictions cannot be compared exactly."""


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _ordered_strings(value: Any, *, path: str) -> List[str]:
    if not isinstance(value, list):
        raise NextBehaviorMetricsError(f"{path} must be a list")
    output: List[str] = []
    for item in value:
        if not isinstance(item, str):
            raise NextBehaviorMetricsError(f"{path} must contain only strings")
        text = _clean(item)
        if not text:
            raise NextBehaviorMetricsError(f"{path} contains an empty value")
        if text in output:
            raise NextBehaviorMetricsError(f"{path} contains a duplicate value")
        output.append(text)
    return output


def _targets(examples: Sequence[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    if not isinstance(examples, Sequence) or isinstance(examples, (str, bytes)):
        raise NextBehaviorMetricsError("examples must be a sequence")
    rows: List[Dict[str, Any]] = []
    seen: set[str] = set()
    for index, example in enumerate(examples):
        if not isinstance(example, Mapping):
            raise NextBehaviorMetricsError(f"examples[{index}] must be an object")
        if example.get("target_contract_id") != TARGET_CONTRACT_ID:
            raise NextBehaviorMetricsError(
                f"examples[{index}] does not use the corrected target"
            )
        raw_example_id = example.get("example_id")
        raw_session_id = example.get("session_id")
        if (
            not isinstance(raw_example_id, str)
            or not raw_example_id.strip()
            or raw_example_id != raw_example_id.strip()
            or not isinstance(raw_session_id, str)
            or not raw_session_id.strip()
            or raw_session_id != raw_session_id.strip()
        ):
            raise NextBehaviorMetricsError(
                f"examples[{index}] must preserve example_id and session_id"
            )
        example_id = raw_example_id
        session_id = raw_session_id
        if example_id in seen:
            raise NextBehaviorMetricsError("example_id values must be unique")
        seen.add(example_id)
        target = example.get("target")
        if not isinstance(target, Mapping):
            raise NextBehaviorMetricsError(f"examples[{index}].target is invalid")
        outcome = target.get("outcome_type")
        tactics = _ordered_strings(
            target.get("tactics"), path=f"examples[{index}].target.tactics"
        )
        if tactics != sorted(tactics):
            raise NextBehaviorMetricsError(
                f"examples[{index}].target.tactics must be sorted"
            )
        if outcome == "session_end":
            if tactics:
                raise NextBehaviorMetricsError("terminal target tactics must be empty")
            terminal = True
        elif outcome == "next_behavior_phase":
            if not tactics:
                raise NextBehaviorMetricsError(
                    "nonterminal target tactics must not be empty"
                )
            terminal = False
        else:
            raise NextBehaviorMetricsError("target outcome_type is invalid")
        rows.append(
            {
                "example_id": example_id,
                "session_id": session_id,
                "target_tactics": tactics,
                "target_terminal": terminal,
            }
        )
    if not rows:
        raise NextBehaviorMetricsError("examples must not be empty")
    return rows


def _prediction_map(
    predictions: Sequence[Mapping[str, Any]],
) -> Dict[str, Dict[str, Any]]:
    if not isinstance(predictions, Sequence) or isinstance(predictions, (str, bytes)):
        raise NextBehaviorMetricsError("predictions must be a sequence")
    output: Dict[str, Dict[str, Any]] = {}
    for index, prediction in enumerate(predictions):
        if not isinstance(prediction, Mapping):
            raise NextBehaviorMetricsError(
                f"predictions[{index}] must be an object"
            )
        raw_example_id = prediction.get("example_id")
        raw_session_id = prediction.get("session_id")
        if (
            not isinstance(raw_example_id, str)
            or not raw_example_id.strip()
            or raw_example_id != raw_example_id.strip()
            or not isinstance(raw_session_id, str)
            or not raw_session_id.strip()
            or raw_session_id != raw_session_id.strip()
        ):
            raise NextBehaviorMetricsError(
                f"predictions[{index}] must preserve example_id and session_id"
            )
        example_id = raw_example_id
        session_id = raw_session_id
        if example_id in output:
            raise NextBehaviorMetricsError("prediction example_id values must be unique")
        status = prediction.get("status", "predicted")
        if status not in {"predicted", "abstained"}:
            raise NextBehaviorMetricsError("prediction status is invalid")
        ranked = _ordered_strings(
            prediction.get("ranked_tactics", []),
            path=f"predictions[{index}].ranked_tactics",
        )
        predicted = _ordered_strings(
            prediction.get("predicted_tactics", []),
            path=f"predictions[{index}].predicted_tactics",
        )
        predicted_terminal = prediction.get("predicted_terminal")
        if status == "predicted" and type(predicted_terminal) is not bool:
            raise NextBehaviorMetricsError(
                "predicted rows require an explicit predicted_terminal boolean"
            )
        if status == "abstained" and predicted_terminal is not None:
            raise NextBehaviorMetricsError(
                "abstained rows cannot contain a terminal decision"
            )
        if predicted_terminal is True and predicted:
            raise NextBehaviorMetricsError(
                "terminal predictions cannot also predict tactic labels"
            )
        output[example_id] = {
            "example_id": example_id,
            "session_id": session_id,
            "status": status,
            "ranked_tactics": ranked,
            "predicted_tactics": predicted,
            "predicted_terminal": predicted_terminal,
        }
    return output


def align_examples_and_predictions(
    examples: Sequence[Mapping[str, Any]],
    predictions: Sequence[Mapping[str, Any]],
) -> List[Dict[str, Any]]:
    """Join by stable example identity and reject missing, extra, or moved rows."""

    targets = _targets(examples)
    by_id = _prediction_map(predictions)
    target_ids = {row["example_id"] for row in targets}
    if set(by_id) != target_ids:
        missing = sorted(target_ids - set(by_id))
        extra = sorted(set(by_id) - target_ids)
        raise NextBehaviorMetricsError(
            f"prediction membership mismatch (missing={missing}, extra={extra})"
        )
    aligned: List[Dict[str, Any]] = []
    for target in targets:
        prediction = by_id[target["example_id"]]
        if prediction["session_id"] != target["session_id"]:
            raise NextBehaviorMetricsError(
                f"prediction {target['example_id']} changed session identity"
            )
        aligned.append({**target, **prediction})
    return aligned


def _divide(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


def _binary_metrics(tp: int, fp: int, fn: int, tn: int) -> Dict[str, Any]:
    precision = _divide(tp, tp + fp)
    recall = _divide(tp, tp + fn)
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "support": tp + fn,
        "precision": precision,
        "recall": recall,
        "f1": _divide(2.0 * precision * recall, precision + recall),
        "specificity": _divide(tn, tn + fp),
        "accuracy": _divide(tp + tn, tp + fp + fn + tn),
        "balanced_accuracy": (
            _divide(tp, tp + fn) + _divide(tn, tn + fp)
        )
        / 2.0,
    }


def _aggregate_classes(
    per_class: Mapping[str, Mapping[str, Any]],
    labels: Sequence[str],
) -> Dict[str, Dict[str, float]]:
    selected = [per_class[label] for label in labels]
    total_tp = sum(item["tp"] for item in selected)
    total_fp = sum(item["fp"] for item in selected)
    total_fn = sum(item["fn"] for item in selected)
    micro_precision = _divide(total_tp, total_tp + total_fp)
    micro_recall = _divide(total_tp, total_tp + total_fn)
    supports = [item["support"] for item in selected]
    support_total = sum(supports)

    def mean(field: str) -> float:
        return _divide(sum(item[field] for item in selected), len(selected))

    def weighted(field: str) -> float:
        return _divide(
            sum(item[field] * item["support"] for item in selected),
            support_total,
        )

    return {
        "micro": {
            "precision": micro_precision,
            "recall": micro_recall,
            "f1": _divide(
                2.0 * micro_precision * micro_recall,
                micro_precision + micro_recall,
            ),
            "support": support_total,
        },
        "macro": {
            "precision": mean("precision"),
            "recall": mean("recall"),
            "f1": mean("f1"),
            "balanced_accuracy": mean("balanced_accuracy"),
            "class_count": len(selected),
        },
        "weighted": {
            "precision": weighted("precision"),
            "recall": weighted("recall"),
            "f1": weighted("f1"),
            "support": support_total,
        },
    }


def multilabel_tactic_metrics(
    aligned_rows: Sequence[Mapping[str, Any]],
    *,
    tactic_vocabulary: Iterable[str] = TACTIC_VOCABULARY,
    minimum_target_sessions: int = DEFAULT_MIN_TARGET_SESSIONS,
    minimum_targets: int = DEFAULT_MIN_TARGETS,
) -> Dict[str, Any]:
    """Compute per-class, micro, macro, and support-weighted PR/F1."""

    if minimum_target_sessions < 1 or minimum_targets < 1:
        raise NextBehaviorMetricsError("reportability minima must be positive")
    labels = sorted({_clean(item) for item in tactic_vocabulary if _clean(item)})
    observed = {
        tactic
        for row in aligned_rows
        for field in ("target_tactics", "predicted_tactics")
        for tactic in row[field]
    }
    unknown = observed - set(labels)
    if unknown:
        raise NextBehaviorMetricsError(
            f"tactics outside the evaluation vocabulary: {sorted(unknown)}"
        )
    per_class: Dict[str, Dict[str, Any]] = {}
    for label in labels:
        tp = fp = fn = tn = 0
        positive_sessions: set[str] = set()
        for row in aligned_rows:
            actual = label in row["target_tactics"]
            predicted = (
                row["status"] == "predicted"
                and label in row["predicted_tactics"]
            )
            if actual:
                positive_sessions.add(row["session_id"])
            if actual and predicted:
                tp += 1
            elif predicted:
                fp += 1
            elif actual:
                fn += 1
            else:
                tn += 1
        metrics = _binary_metrics(tp, fp, fn, tn)
        metrics["target_count"] = metrics["support"]
        metrics["target_session_count"] = len(positive_sessions)
        metrics["reportable"] = (
            metrics["target_count"] >= minimum_targets
            and metrics["target_session_count"] >= minimum_target_sessions
        )
        per_class[label] = metrics
    reportable = [label for label in labels if per_class[label]["reportable"]]
    return {
        "minimum_target_sessions": minimum_target_sessions,
        "minimum_targets": minimum_targets,
        "per_class": per_class,
        "all_classes": _aggregate_classes(per_class, labels),
        "reportable_classes": reportable,
        "reportable_class_aggregates": (
            _aggregate_classes(per_class, reportable) if reportable else None
        ),
    }


def terminal_and_discrimination_metrics(
    aligned_rows: Sequence[Mapping[str, Any]],
    *,
    minimum_target_sessions: int = DEFAULT_MIN_TARGET_SESSIONS,
    minimum_targets: int = DEFAULT_MIN_TARGETS,
) -> Dict[str, Any]:
    """Evaluate terminal detection and the mutually exclusive tactic/end choice."""

    tp = fp = fn = tn = 0
    covered = 0
    correct = 0
    terminal_targets = 0
    tactic_targets = 0
    correct_terminal = 0
    correct_tactic = 0
    terminal_as_tactic = 0
    terminal_sessions: set[str] = set()
    for row in aligned_rows:
        actual = row["target_terminal"]
        terminal_targets += int(actual)
        tactic_targets += int(not actual)
        if actual:
            terminal_sessions.add(row["session_id"])
        if row["status"] != "predicted":
            predicted = False
        else:
            covered += 1
            predicted = row["predicted_terminal"]
            correct += int(predicted == actual)
            correct_terminal += int(actual and predicted)
            correct_tactic += int(not actual and not predicted)
            terminal_as_tactic += int(actual and not predicted)
        if actual and predicted:
            tp += 1
        elif predicted:
            fp += 1
        elif actual:
            fn += 1
        else:
            tn += 1
    binary = _binary_metrics(tp, fp, fn, tn)
    binary["target_count"] = binary["support"]
    binary["target_session_count"] = len(terminal_sessions)
    binary["reportable"] = (
        binary["target_count"] >= minimum_targets
        and binary["target_session_count"] >= minimum_target_sessions
    )
    tactic_binary = _binary_metrics(
        correct_tactic,
        terminal_as_tactic,
        tactic_targets - correct_tactic,
        terminal_targets - terminal_as_tactic,
    )
    terminal_choice_recall = _divide(correct_terminal, terminal_targets)
    tactic_choice_recall = _divide(correct_tactic, tactic_targets)
    return {
        "terminal": binary,
        "tactic_vs_end": {
            "covered_count": covered,
            "total_count": len(aligned_rows),
            "coverage": _divide(covered, len(aligned_rows)),
            "covered_accuracy": _divide(correct, covered),
            "all_case_accuracy": _divide(correct, len(aligned_rows)),
            "terminal_recall": terminal_choice_recall,
            "tactic_recall": tactic_choice_recall,
            "balanced_accuracy": (
                terminal_choice_recall + tactic_choice_recall
            )
            / 2.0,
            "macro_f1": (binary["f1"] + tactic_binary["f1"]) / 2.0,
            "per_class": {
                "session_end": binary,
                "next_behavior_phase": tactic_binary,
            },
        },
    }


def nonterminal_ranking_metrics(
    aligned_rows: Sequence[Mapping[str, Any]],
) -> Dict[str, Any]:
    """Compute Top-1, Top-3, and set-aware MRR on nonterminal targets only."""

    eligible = [row for row in aligned_rows if not row["target_terminal"]]
    top1 = top3 = 0
    reciprocal_ranks: List[float] = []
    covered = 0
    for row in eligible:
        ranking = row["ranked_tactics"] if row["status"] == "predicted" else []
        if ranking:
            covered += 1
        truth = set(row["target_tactics"])
        top1 += int(bool(ranking) and ranking[0] in truth)
        top3 += int(bool(set(ranking[:3]) & truth))
        first = next(
            (index for index, tactic in enumerate(ranking, start=1) if tactic in truth),
            None,
        )
        reciprocal_ranks.append(0.0 if first is None else 1.0 / first)
    count = len(eligible)
    return {
        "nonterminal_target_count": count,
        "covered_count": covered,
        "coverage": _divide(covered, count),
        "top1_correct": top1,
        "top3_correct": top3,
        "top1_accuracy": _divide(top1, count),
        "top3_accuracy": _divide(top3, count),
        "reciprocal_rank_sum": sum(reciprocal_ranks),
        "mrr": _divide(sum(reciprocal_ranks), count),
    }


def _point_metrics(
    rows: Sequence[Mapping[str, Any]],
    *,
    tactic_vocabulary: Iterable[str],
    minimum_target_sessions: int,
    minimum_targets: int,
    aggregate_labels: Sequence[str] | None = None,
) -> Dict[str, float]:
    multi = multilabel_tactic_metrics(
        rows,
        tactic_vocabulary=tactic_vocabulary,
        minimum_target_sessions=minimum_target_sessions,
        minimum_targets=minimum_targets,
    )
    terminal = terminal_and_discrimination_metrics(
        rows,
        minimum_target_sessions=minimum_target_sessions,
        minimum_targets=minimum_targets,
    )
    ranking = nonterminal_ranking_metrics(rows)
    if aggregate_labels is not None:
        aggregates = _aggregate_classes(multi["per_class"], aggregate_labels)
    else:
        aggregates = multi["reportable_class_aggregates"]
        if aggregates is None:
            aggregates = multi["all_classes"]
    class_count = aggregates["macro"]["class_count"]
    primary_macro_f1 = _divide(
        aggregates["macro"]["f1"] * class_count
        + terminal["terminal"]["f1"],
        class_count + 1,
    )
    primary_balanced_accuracy = _divide(
        aggregates["macro"]["balanced_accuracy"] * class_count
        + terminal["terminal"]["balanced_accuracy"],
        class_count + 1,
    )
    covered_count = sum(row["status"] == "predicted" for row in rows)
    return {
        "macro_f1": primary_macro_f1,
        "micro_f1": aggregates["micro"]["f1"],
        "weighted_f1": aggregates["weighted"]["f1"],
        "balanced_accuracy": primary_balanced_accuracy,
        "terminal_f1": terminal["terminal"]["f1"],
        "tactic_vs_end_balanced_accuracy": terminal["tactic_vs_end"][
            "balanced_accuracy"
        ],
        "top1_accuracy": ranking["top1_accuracy"],
        "top3_accuracy": ranking["top3_accuracy"],
        "mrr": ranking["mrr"],
        "coverage": _divide(covered_count, len(rows)),
    }


def _percentile(values: Sequence[float], probability: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    position = (len(ordered) - 1) * probability
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    weight = position - lower
    return ordered[lower] * (1.0 - weight) + ordered[upper] * weight


def session_cluster_bootstrap(
    aligned_rows: Sequence[Mapping[str, Any]],
    metric_function: Callable[[Sequence[Mapping[str, Any]]], Mapping[str, float]],
    *,
    samples: int = 1000,
    seed: int = DEFAULT_BOOTSTRAP_SEED,
) -> Dict[str, Any]:
    """Bootstrap arbitrary flat metrics by resampling complete session clusters."""

    if isinstance(samples, bool) or not isinstance(samples, int) or samples < 1:
        raise NextBehaviorMetricsError("bootstrap samples must be positive")
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise NextBehaviorMetricsError("bootstrap seed must be an integer")
    by_session: Dict[str, List[Mapping[str, Any]]] = defaultdict(list)
    for row in aligned_rows:
        by_session[row["session_id"]].append(row)
    sessions = sorted(by_session)
    if not sessions:
        raise NextBehaviorMetricsError("bootstrap needs at least one session")
    point = dict(metric_function(aligned_rows))
    draws: Dict[str, List[float]] = {key: [] for key in point}
    generator = random.Random(seed)
    for _ in range(samples):
        sampled: List[Mapping[str, Any]] = []
        for session_id in generator.choices(sessions, k=len(sessions)):
            sampled.extend(by_session[session_id])
        values = metric_function(sampled)
        if set(values) != set(point):
            raise NextBehaviorMetricsError(
                "bootstrap metric fields changed between resamples"
            )
        for key, value in values.items():
            draws[key].append(float(value))
    return {
        "unit": "session",
        "session_count": len(sessions),
        "samples": samples,
        "seed": seed,
        "confidence_level": 0.95,
        "metrics": {
            key: {
                "estimate": float(point[key]),
                "lower": _percentile(values, 0.025),
                "upper": _percentile(values, 0.975),
            }
            for key, values in draws.items()
        },
    }


def _equal_session_aggregates(
    rows: Sequence[Mapping[str, Any]],
    *,
    tactic_vocabulary: Iterable[str],
    minimum_target_sessions: int,
    minimum_targets: int,
    aggregate_labels: Sequence[str],
) -> Dict[str, Any]:
    by_session: Dict[str, List[Mapping[str, Any]]] = defaultdict(list)
    for row in rows:
        by_session[row["session_id"]].append(row)
    values = [
        _point_metrics(
            by_session[session_id],
            tactic_vocabulary=tactic_vocabulary,
            minimum_target_sessions=minimum_target_sessions,
            minimum_targets=minimum_targets,
            aggregate_labels=aggregate_labels,
        )
        for session_id in sorted(by_session)
    ]
    return {
        "aggregation": "equal_weight_per_session",
        "session_count": len(values),
        "metrics": {
            key: sum(item[key] for item in values) / len(values)
            for key in values[0]
        },
    }


def evaluate_next_behavior_predictions(
    examples: Sequence[Mapping[str, Any]],
    predictions: Sequence[Mapping[str, Any]],
    *,
    tactic_vocabulary: Iterable[str] = TACTIC_VOCABULARY,
    minimum_target_sessions: int = DEFAULT_MIN_TARGET_SESSIONS,
    minimum_targets: int = DEFAULT_MIN_TARGETS,
    bootstrap_samples: int = 1000,
    bootstrap_seed: int = DEFAULT_BOOTSTRAP_SEED,
) -> Dict[str, Any]:
    """Evaluate exact corrected-target predictions with clustered uncertainty."""

    vocabulary = tuple(sorted({_clean(item) for item in tactic_vocabulary if _clean(item)}))
    rows = align_examples_and_predictions(examples, predictions)
    multi = multilabel_tactic_metrics(
        rows,
        tactic_vocabulary=vocabulary,
        minimum_target_sessions=minimum_target_sessions,
        minimum_targets=minimum_targets,
    )
    terminal = terminal_and_discrimination_metrics(
        rows,
        minimum_target_sessions=minimum_target_sessions,
        minimum_targets=minimum_targets,
    )
    ranking = nonterminal_ranking_metrics(rows)
    aggregate_labels = multi["reportable_classes"] or list(vocabulary)
    covered_count = sum(row["status"] == "predicted" for row in rows)

    def point(sample: Sequence[Mapping[str, Any]]) -> Mapping[str, float]:
        return _point_metrics(
            sample,
            tactic_vocabulary=vocabulary,
            minimum_target_sessions=minimum_target_sessions,
            minimum_targets=minimum_targets,
            aggregate_labels=aggregate_labels,
        )

    return {
        "schema_version": METRICS_SCHEMA_VERSION,
        "target_contract_id": TARGET_CONTRACT_ID,
        "example_count": len(rows),
        "session_count": len({row["session_id"] for row in rows}),
        "example_ids": [row["example_id"] for row in rows],
        "session_ids": sorted({row["session_id"] for row in rows}),
        "coverage": {
            "covered_count": covered_count,
            "abstained_count": len(rows) - covered_count,
            "coverage": _divide(covered_count, len(rows)),
            "abstention_rate": _divide(len(rows) - covered_count, len(rows)),
        },
        "multilabel_tactics": multi,
        **terminal,
        "nonterminal_ranking": ranking,
        "session_clustered_aggregates": _equal_session_aggregates(
            rows,
            tactic_vocabulary=vocabulary,
            minimum_target_sessions=minimum_target_sessions,
            minimum_targets=minimum_targets,
            aggregate_labels=aggregate_labels,
        ),
        "session_cluster_bootstrap": session_cluster_bootstrap(
            rows,
            point,
            samples=bootstrap_samples,
            seed=bootstrap_seed,
        ),
    }


def paired_model_comparison(
    examples: Sequence[Mapping[str, Any]],
    predictions_a: Sequence[Mapping[str, Any]],
    predictions_b: Sequence[Mapping[str, Any]],
    *,
    model_a: str = "model_a",
    model_b: str = "model_b",
    tactic_vocabulary: Iterable[str] = TACTIC_VOCABULARY,
    minimum_target_sessions: int = DEFAULT_MIN_TARGET_SESSIONS,
    minimum_targets: int = DEFAULT_MIN_TARGETS,
    bootstrap_samples: int = 1000,
    bootstrap_seed: int = DEFAULT_BOOTSTRAP_SEED,
) -> Dict[str, Any]:
    """Compare two models with paired whole-session bootstrap differences."""

    if (
        isinstance(bootstrap_samples, bool)
        or not isinstance(bootstrap_samples, int)
        or bootstrap_samples < 1
    ):
        raise NextBehaviorMetricsError("bootstrap samples must be positive")
    if isinstance(bootstrap_seed, bool) or not isinstance(bootstrap_seed, int):
        raise NextBehaviorMetricsError("bootstrap seed must be an integer")
    vocabulary = tuple(sorted({_clean(item) for item in tactic_vocabulary if _clean(item)}))
    rows_a = align_examples_and_predictions(examples, predictions_a)
    rows_b = align_examples_and_predictions(examples, predictions_b)
    by_b = {row["example_id"]: row for row in rows_b}
    pairs = [(row, by_b[row["example_id"]]) for row in rows_a]
    support = multilabel_tactic_metrics(
        rows_a,
        tactic_vocabulary=vocabulary,
        minimum_target_sessions=minimum_target_sessions,
        minimum_targets=minimum_targets,
    )
    aggregate_labels = support["reportable_classes"] or list(vocabulary)

    def metrics(rows: Sequence[Mapping[str, Any]]) -> Dict[str, float]:
        return _point_metrics(
            rows,
            tactic_vocabulary=vocabulary,
            minimum_target_sessions=minimum_target_sessions,
            minimum_targets=minimum_targets,
            aggregate_labels=aggregate_labels,
        )

    point_a = metrics(rows_a)
    point_b = metrics(rows_b)
    deltas = {key: point_a[key] - point_b[key] for key in point_a}
    by_session: Dict[str, List[tuple[Mapping[str, Any], Mapping[str, Any]]]] = defaultdict(list)
    for pair in pairs:
        by_session[pair[0]["session_id"]].append(pair)
    sessions = sorted(by_session)
    draws: Dict[str, List[float]] = {key: [] for key in deltas}
    generator = random.Random(bootstrap_seed)
    for _ in range(bootstrap_samples):
        sample_a: List[Mapping[str, Any]] = []
        sample_b: List[Mapping[str, Any]] = []
        for session_id in generator.choices(sessions, k=len(sessions)):
            for row_a, row_b in by_session[session_id]:
                sample_a.append(row_a)
                sample_b.append(row_b)
        values_a = metrics(sample_a)
        values_b = metrics(sample_b)
        for key in draws:
            draws[key].append(values_a[key] - values_b[key])

    session_wins = session_losses = session_ties = 0
    for session_id in sessions:
        session_a = [pair[0] for pair in by_session[session_id]]
        session_b = [pair[1] for pair in by_session[session_id]]
        difference = metrics(session_a)["macro_f1"] - metrics(session_b)["macro_f1"]
        if difference > 0:
            session_wins += 1
        elif difference < 0:
            session_losses += 1
        else:
            session_ties += 1
    paired_top1 = Counter()
    for row_a, row_b in pairs:
        if row_a["target_terminal"]:
            continue
        truth = set(row_a["target_tactics"])
        correct_a = bool(row_a["ranked_tactics"]) and row_a["ranked_tactics"][0] in truth
        correct_b = bool(row_b["ranked_tactics"]) and row_b["ranked_tactics"][0] in truth
        paired_top1[
            (
                "both_correct"
                if correct_a and correct_b
                else "model_a_only"
                if correct_a
                else "model_b_only"
                if correct_b
                else "both_incorrect"
            )
        ] += 1
    return {
        "schema_version": PAIRED_COMPARISON_SCHEMA_VERSION,
        "target_contract_id": TARGET_CONTRACT_ID,
        "model_a": model_a,
        "model_b": model_b,
        "difference_direction": "model_a_minus_model_b",
        "paired_example_count": len(pairs),
        "paired_session_count": len(sessions),
        "example_ids": [row["example_id"] for row in rows_a],
        "session_ids": sessions,
        "bootstrap_samples": bootstrap_samples,
        "bootstrap_seed": bootstrap_seed,
        "macro_f1_session_wins": {
            "model_a": session_wins,
            "model_b": session_losses,
            "ties": session_ties,
        },
        "paired_top1_outcomes": {
            key: paired_top1[key]
            for key in (
                "both_correct",
                "model_a_only",
                "model_b_only",
                "both_incorrect",
            )
        },
        "metrics": {
            key: {
                "model_a": point_a[key],
                "model_b": point_b[key],
                "difference": deltas[key],
                "lower": _percentile(draws[key], 0.025),
                "upper": _percentile(draws[key], 0.975),
            }
            for key in deltas
        },
    }


paired_comparison = paired_model_comparison
evaluate_predictions = evaluate_next_behavior_predictions
cluster_bootstrap = session_cluster_bootstrap
