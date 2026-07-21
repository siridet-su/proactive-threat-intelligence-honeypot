"""Offline, reproducible comparison of next-tactic prediction models.

This module deliberately has no production write path.  It consumes a
privacy-minimised, pre-split payload and the *already deployed* manifest-bound
external hard-backoff VOMM.  It never edits the prediction policy, artifacts,
storage, workers, or services.  Neural dependencies are imported lazily, so
the ordinary application/runtime does not acquire a PyTorch dependency.

The benchmark keeps the held-out test partition opaque until all model choices
are made.  The existing deployed artifact is exceptional: its immutable
manifest proves it was built from train plus validation, and the comparison
reports that fact rather than rebuilding or altering it.
"""

from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import io
import json
import math
import os
import random
import resource
import statistics
import sys
import time
import tracemalloc
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence

from production.prediction.realtime_prediction import RealtimePredictionEngine
from production.tools.evaluate_authoritative_external_vomm import (
    _membership_sha256,
    _verify_manifest_evaluation_membership,
    file_sha256,
    load_exact_external_artifact,
)
from production.tools.evaluate_next_tactic_model_comparison import (
    EvaluationCase,
    build_cases,
    load_policy,
    load_session_payloads,
    split_session_payloads,
)
from production.tools.evaluate_zenodo_tuned_next_tactic import (
    CountModel,
    build_count_model,
    hard_backoff_probabilities,
    interpolated_probabilities,
)


SCHEMA_VERSION = "next_tactic_offline_benchmark.v1"
DEFAULT_PAYLOAD = "evaluation/next_tactic_zenodo_7day_session_payload.jsonl"
DEFAULT_ARTIFACT = "data/models/external_cowrie_vomm_zenodo_7day_20260721.json"
DEFAULT_MANIFEST = "data/models/external_cowrie_vomm_zenodo_7day_20260721.manifest.json"
DEFAULT_POLICY = "configs/prediction_policy.trusted.json"
DEFAULT_OUTPUT_DIR = "evaluation/next_tactic_offline_benchmark_20260721"
DEFAULT_SEEDS = (20260721, 20260722, 20260723, 20260724, 20260725)
DEFAULT_BOOTSTRAP = 500
DEFAULT_MAX_SEQUENCE_LENGTH = 8
DEFAULT_MIN_PER_TACTIC_SUPPORT = 30
EPSILON = 1e-15


@dataclass(frozen=True)
class BenchmarkCase:
    """One next-tactic target, derived only after the session split."""

    case_id: str
    session_id: str
    chronological_position: int
    actual: str
    sequence: tuple[str, ...]
    features: dict[str, Any]


@dataclass(frozen=True)
class Prediction:
    """Normalized raw model scores and non-authoritative benchmark metadata."""

    probabilities: dict[str, float]
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ModelRun:
    model_id: str
    display_name: str
    predictor: Callable[[BenchmarkCase], Prediction]
    metadata: dict[str, Any]
    training_seconds: float = 0.0
    training_peak_bytes: int = 0
    serialized_size_bytes: int = 0
    load_seconds: float = 0.0


def canonical_json_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _normalize(values: Mapping[str, float], vocabulary: Sequence[str]) -> dict[str, float]:
    cleaned = {str(label): max(float(values.get(label, 0.0)), 0.0) for label in vocabulary}
    total = sum(cleaned.values())
    return {label: value / total for label, value in cleaned.items()} if total else {}


def _ranking(probabilities: Mapping[str, float]) -> list[str]:
    return [label for label, _ in sorted(probabilities.items(), key=lambda item: (-item[1], item[0]))]


def _case_identifier(session_id: str, index: int, actual: str) -> str:
    # Do not emit an external safe-session identifier again in prediction-level
    # examples.  A deterministic one-way identifier is enough for pairing.
    digest = hashlib.sha256(f"{session_id}:{index}:{actual}".encode("utf-8")).hexdigest()
    return f"case-{digest[:20]}"


def make_cases(payloads: Iterable[Mapping[str, Any]]) -> list[BenchmarkCase]:
    """Use the shared trusted-label and adjacent-deduplication implementation."""

    output: list[BenchmarkCase] = []
    chronological_position = 0
    for payload in payloads:
        for within_session, case in enumerate(build_cases([dict(payload)])):
            sequence = tuple(str(item) for item in case.features.get("tactic_sequence") or [] if str(item))
            if not sequence:
                continue
            output.append(
                BenchmarkCase(
                    case_id=_case_identifier(case.session_id, within_session, case.actual),
                    session_id=case.session_id,
                    chronological_position=chronological_position,
                    actual=case.actual,
                    sequence=sequence,
                    features=dict(case.features),
                )
            )
            chronological_position += 1
    return output


def split_validation_sessions(
    payloads: Sequence[Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    """Split the recorded validation partition chronologically into two roles.

    The first half is used for architecture/hyperparameter selection and the
    second half only for secondary calibration.  Both are whole-session sets.
    This prevents a neural model's calibration map from being fit on test data.
    """

    rows = [dict(item) for item in payloads]
    midpoint = len(rows) // 2
    selection, calibration = rows[:midpoint], rows[midpoint:]
    if not selection or not calibration:
        raise ValueError("validation partition must contain at least two sessions")
    selection_ids = {str(item.get("session_id") or "") for item in selection}
    calibration_ids = {str(item.get("session_id") or "") for item in calibration}
    if selection_ids.intersection(calibration_ids):
        raise ValueError("validation selection/calibration session intersection is not empty")
    return selection, calibration, {
        "method": "chronological_half_of_preassigned_validation_whole_sessions.v1",
        "selection": {"session_count": len(selection), "membership_sha256": _membership_sha256(selection)},
        "calibration": {"session_count": len(calibration), "membership_sha256": _membership_sha256(calibration)},
        "intersection_count": 0,
    }


def split_summary(
    split: Mapping[str, Sequence[Mapping[str, Any]]],
    vocabulary: Sequence[str],
) -> dict[str, Any]:
    details: dict[str, Any] = {}
    memberships = {name: {str(item.get("session_id") or "") for item in rows} for name, rows in split.items()}
    intersections = {
        "train_validation": len(memberships["train"].intersection(memberships["calibration"])),
        "train_test": len(memberships["train"].intersection(memberships["test"])),
        "validation_test": len(memberships["calibration"].intersection(memberships["test"])),
    }
    for name, rows in split.items():
        cases = make_cases(rows)
        lengths = Counter(len(case.sequence) for case in cases)
        targets = Counter(case.actual for case in cases)
        details[name] = {
            "session_count": len(rows),
            "membership_sha256": _membership_sha256(rows),
            "transition_case_count": len(cases),
            "transition_session_count": len({case.session_id for case in cases}),
            "sequence_length_distribution": {str(key): value for key, value in sorted(lengths.items())},
            "target_tactic_distribution": {label: int(targets.get(label, 0)) for label in vocabulary},
        }
    return {
        "partitions": details,
        "partition_intersections": {"all_empty": not any(intersections.values()), "counts": intersections},
    }


def _count_context_support(model: CountModel, case: BenchmarkCase, max_context: int) -> tuple[int, int]:
    sequence = case.sequence
    for order in range(min(max_context, len(sequence)), 0, -1):
        counts = model.contexts.get(order, {}).get(tuple(sequence[-order:]), Counter())
        if counts:
            return order, int(sum(counts.values()))
    return 0, 0


def majority_model(cases: Sequence[BenchmarkCase], vocabulary: Sequence[str]) -> ModelRun:
    counts = Counter(case.actual for case in cases)
    probabilities = _normalize(counts, vocabulary)
    return ModelRun(
        "majority_class",
        "Majority-class baseline",
        lambda _case: Prediction(dict(probabilities), {"source": "training_target_prevalence"}),
        {"algorithm": "zero_order_categorical", "target_counts": dict(counts)},
    )


def first_order_model(
    sessions: Sequence[Mapping[str, Any]], vocabulary: Sequence[str]
) -> ModelRun:
    count_model = build_count_model(sessions, max_order=1)

    def predict(case: BenchmarkCase) -> Prediction:
        probabilities = hard_backoff_probabilities(
            count_model, EvaluationCase(case.session_id, case.actual, dict(case.features)), vocabulary,
            max_context=1, min_support=1, alpha=0.0,
        )
        order, support = _count_context_support(count_model, case, 1)
        return Prediction(probabilities, {"context_order": order, "support_count": support})

    return ModelRun(
        "first_order_markov", "First-order Markov model", predict,
        {"algorithm": "maximum_likelihood_first_order_markov", "max_context": 1, "smoothing": 0.0},
    )


def select_interpolated_vomm(
    train_sessions: Sequence[Mapping[str, Any]],
    validation_cases: Sequence[BenchmarkCase],
    vocabulary: Sequence[str],
    *,
    experiment_log: list[dict[str, Any]],
) -> dict[str, Any]:
    """Select count-model settings only from the first validation half."""

    candidates = [
        {"max_context": max_context, "min_support": min_support, "alpha": alpha, "kappa": kappa}
        for max_context in (2, 3)
        for min_support in (1, 2)
        for alpha in (0.01, 0.05)
        for kappa in (5.0, 20.0)
    ]
    count_model = build_count_model(train_sessions, max_order=3)
    best: dict[str, Any] | None = None
    for settings in candidates:
        run = ModelRun(
            "interpolated_vomm_tuning", "Interpolated VOMM tuning",
            lambda case, values=settings: Prediction(
                interpolated_probabilities(
                    count_model, EvaluationCase(case.session_id, case.actual, dict(case.features)), vocabulary,
                    max_context=int(values["max_context"]), min_support=int(values["min_support"]),
                    alpha=float(values["alpha"]), kappa=float(values["kappa"]),
                )
            ),
            {"settings": settings},
        )
        result = evaluate_model(run, validation_cases, vocabulary, bootstrap_iterations=0, seed=DEFAULT_SEEDS[0])
        record = {"stage": "validation_selection", "model_id": "interpolated_vomm", "settings": settings, "metrics": result["metrics"]}
        experiment_log.append(record)
        key = (
            -float(result["metrics"].get("macro_f1") or -1.0),
            -float(result["metrics"].get("balanced_accuracy") or -1.0),
            -float(result["metrics"].get("top1_accuracy") or -1.0),
            float(result["metrics"].get("raw_log_loss") or float("inf")),
            int(settings["max_context"]), int(settings["min_support"]), float(settings["alpha"]), float(settings["kappa"]),
        )
        if best is None or key < best["key"]:
            best = {"settings": settings, "key": key, "validation_metrics": result["metrics"]}
    assert best is not None
    return best


def interpolated_vomm_model(
    sessions: Sequence[Mapping[str, Any]],
    vocabulary: Sequence[str],
    settings: Mapping[str, Any],
) -> ModelRun:
    count_model = build_count_model(sessions, max_order=int(settings["max_context"]))

    def predict(case: BenchmarkCase) -> Prediction:
        values = interpolated_probabilities(
            count_model, EvaluationCase(case.session_id, case.actual, dict(case.features)), vocabulary,
            max_context=int(settings["max_context"]), min_support=int(settings["min_support"]),
            alpha=float(settings["alpha"]), kappa=float(settings["kappa"]),
        )
        order, support = _count_context_support(count_model, case, int(settings["max_context"]))
        return Prediction(values, {"context_order": order, "support_count": support, "interpolated": True})

    return ModelRun(
        "interpolated_vomm", "Interpolated variable-order Markov model", predict,
        {"algorithm": "support_weighted_dirichlet_interpolation", "settings": dict(settings),
         "weighting": "context_weight = support / (support + kappa); recursively blends orders 1..max_context",
         "raw_scores_are_calibrated_probabilities": False},
    )


def external_hard_backoff_model(
    policy: Mapping[str, Any], external_artifact: Mapping[str, Any], vocabulary: Sequence[str]
) -> ModelRun:
    """Use the exact loaded immutable artifact, never a rebuilt count model."""

    engine = RealtimePredictionEngine(dict(policy), transition_model={}, external_transition_model=dict(external_artifact))

    def predict(case: BenchmarkCase) -> Prediction:
        snapshot = engine.predict(dict(case.features), event_id=f"offline-benchmark:{case.case_id}")
        ranking = snapshot.get("final_ranking") or []
        probabilities = _normalize(
            {str(item.get("tactic") or ""): float(item.get("score") or 0.0) for item in ranking if isinstance(item, dict)},
            vocabulary,
        )
        primary = snapshot.get("primary_transition") if isinstance(snapshot.get("primary_transition"), dict) else {}
        top = ranking[0] if ranking and isinstance(ranking[0], dict) else {}
        source_metadata = ((top.get("sources") or [{}])[0].get("metadata") or {}) if top else {}
        context = str(source_metadata.get("transition_context") or "")
        kind = str(source_metadata.get("transition_type") or "")
        order = len(context.split(">")) if kind == "prefix" and context else (1 if kind else 0)
        return Prediction(probabilities, {
            "context_order": order,
            "support_count": int(float(source_metadata.get("transition_total") or 0.0)),
            "selected_source": str(primary.get("selected_source") or ""),
            "abstention_reason": str((snapshot.get("coverage") or {}).get("reason") or "") if not probabilities else "",
            "artifact_backed": True,
        })

    return ModelRun(
        "hard_backoff_vomm", "Production hard-backoff VOMM (exact deployed artifact)", predict,
        {"algorithm": "deployed_external_hard_backoff_vomm", "artifact_is_immutable": True,
         "raw_scores_are_calibrated_probabilities": False},
    )


def _record_for_case(case: BenchmarkCase, prediction: Prediction, vocabulary: Sequence[str]) -> dict[str, Any]:
    probabilities = _normalize(prediction.probabilities, vocabulary)
    ranking = _ranking(probabilities)
    rank = ranking.index(case.actual) + 1 if case.actual in ranking else 0
    actual_probability = probabilities.get(case.actual, 0.0)
    brier = sum((probabilities.get(label, 0.0) - float(label == case.actual)) ** 2 for label in vocabulary)
    return {
        "case_id": case.case_id,
        "session_id": case.session_id,
        "chronological_position": case.chronological_position,
        "actual": case.actual,
        "sequence": list(case.sequence),
        "sequence_length": len(case.sequence),
        "top1": ranking[0] if ranking else "",
        "top3": ranking[:3],
        "rank": rank,
        "covered": bool(ranking),
        "abstained": not bool(ranking),
        "correct": rank == 1,
        "raw_probabilities": probabilities,
        "raw_brier_score": brier,
        "raw_log_loss": -math.log(max(actual_probability, EPSILON)),
        "metadata": dict(prediction.metadata),
    }


def _classification_metrics(records: Sequence[Mapping[str, Any]], vocabulary: Sequence[str], min_support: int) -> dict[str, Any]:
    total = len(records)
    covered = [row for row in records if row["covered"]]
    target_counts = Counter(str(row["actual"]) for row in records)
    predicted_counts = Counter(str(row["top1"]) for row in covered)
    true_positives = Counter(str(row["actual"]) for row in records if row["correct"])
    per_tactic: dict[str, Any] = {}
    f1s: list[float] = []
    weighted_f1_total = 0.0
    recalls: list[float] = []
    precisions: list[float] = []
    for label in vocabulary:
        support = int(target_counts[label])
        predicted = int(predicted_counts[label])
        tp = int(true_positives[label])
        precision = tp / predicted if predicted else 0.0
        recall = tp / support if support else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        if support:
            f1s.append(f1)
            recalls.append(recall)
            precisions.append(precision)
            weighted_f1_total += f1 * support
        per_tactic[label] = {
            "support": support,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "reportable": support >= min_support,
            "support_status": "sufficient_support" if support >= min_support else ("low_support_descriptive_only" if support else "no_heldout_support"),
        }
    top1 = sum(bool(row["correct"]) for row in records) / total if total else 0.0
    top3 = sum(1 <= int(row["rank"]) <= 3 for row in records) / total if total else 0.0
    mrr = sum(1 / int(row["rank"]) for row in records if int(row["rank"]) > 0) / total if total else 0.0
    return {
        "evaluated_examples": total,
        "covered_examples": len(covered),
        "coverage": len(covered) / total if total else 0.0,
        "abstention_rate": 1 - len(covered) / total if total else 0.0,
        "top1_accuracy": top1,
        "top3_accuracy": top3,
        "selective_top1_accuracy": sum(bool(row["correct"]) for row in covered) / len(covered) if covered else None,
        "balanced_accuracy": statistics.fmean(recalls) if recalls else 0.0,
        "macro_precision": statistics.fmean(precisions) if precisions else 0.0,
        "macro_recall": statistics.fmean(recalls) if recalls else 0.0,
        "macro_f1": statistics.fmean(f1s) if f1s else 0.0,
        "weighted_f1": weighted_f1_total / total if total else 0.0,
        "mean_reciprocal_rank": mrr,
        "raw_brier_score": statistics.fmean(float(row["raw_brier_score"]) for row in records) if records else None,
        "raw_log_loss": statistics.fmean(float(row["raw_log_loss"]) for row in records) if records else None,
        "per_tactic": per_tactic,
    }


def normalized_confusion(records: Sequence[Mapping[str, Any]], vocabulary: Sequence[str]) -> dict[str, dict[str, float]]:
    labels = list(vocabulary) + ["<abstained>"]
    counts: dict[str, Counter[str]] = {label: Counter() for label in vocabulary}
    for row in records:
        counts[str(row["actual"])][str(row["top1"]) or "<abstained>"] += 1
    return {
        actual: {predicted: (counts[actual][predicted] / sum(counts[actual].values()) if sum(counts[actual].values()) else 0.0) for predicted in labels}
        for actual in vocabulary
    }


def expected_calibration_error(records: Sequence[Mapping[str, Any]], bins: int = 10) -> tuple[float | None, list[dict[str, Any]]]:
    covered = [row for row in records if row["covered"]]
    if not covered:
        return None, []
    rows: list[dict[str, Any]] = []
    ece = 0.0
    for index in range(bins):
        lower, upper = index / bins, (index + 1) / bins
        selected = [row for row in covered if lower <= max(row["raw_probabilities"].values()) < upper or (index == bins - 1 and max(row["raw_probabilities"].values()) == 1.0)]
        if not selected:
            rows.append({"lower": lower, "upper": upper, "count": 0, "mean_confidence": None, "accuracy": None})
            continue
        confidence = statistics.fmean(max(row["raw_probabilities"].values()) for row in selected)
        accuracy = statistics.fmean(float(row["correct"]) for row in selected)
        ece += len(selected) / len(covered) * abs(confidence - accuracy)
        rows.append({"lower": lower, "upper": upper, "count": len(selected), "mean_confidence": confidence, "accuracy": accuracy})
    return ece, rows


def _bootstrap(records: Sequence[Mapping[str, Any]], vocabulary: Sequence[str], *, iterations: int, seed: int) -> dict[str, list[float] | None]:
    fields = ("top1_accuracy", "top3_accuracy", "balanced_accuracy", "macro_f1", "mean_reciprocal_rank", "raw_brier_score", "raw_log_loss")
    grouped: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for row in records:
        grouped[str(row["session_id"])].append(row)
    session_ids = sorted(grouped)
    if iterations <= 0 or len(session_ids) < 2:
        return {field: None for field in fields}
    rng = random.Random(seed)
    samples: dict[str, list[float]] = {field: [] for field in fields}
    for _ in range(iterations):
        resampled: list[Mapping[str, Any]] = []
        for _unused in session_ids:
            resampled.extend(grouped[session_ids[rng.randrange(len(session_ids))]])
        metrics = _classification_metrics(resampled, vocabulary, 1)
        for field in fields:
            samples[field].append(float(metrics[field]))
    def percentile(values: list[float], fraction: float) -> float:
        values = sorted(values)
        return values[int(round((len(values) - 1) * fraction))]
    return {field: [percentile(values, 0.025), percentile(values, 0.975)] for field, values in samples.items()}


def _bucket(value: int, boundaries: Sequence[tuple[int, str]]) -> str:
    for maximum, name in boundaries:
        if value <= maximum:
            return name
    return boundaries[-1][1]


def _bucket_metrics(records: Sequence[Mapping[str, Any]], vocabulary: Sequence[str], selector: Callable[[Mapping[str, Any]], str]) -> dict[str, Any]:
    grouped: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for row in records:
        grouped[selector(row)].append(row)
    return {name: _classification_metrics(rows, vocabulary, 1) for name, rows in sorted(grouped.items())}


def _quantile(values: Sequence[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    return ordered[max(0, min(len(ordered) - 1, int(math.ceil(fraction * len(ordered))) - 1))]


def evaluate_model(
    model: ModelRun,
    cases: Sequence[BenchmarkCase],
    vocabulary: Sequence[str],
    *,
    bootstrap_iterations: int,
    seed: int,
) -> dict[str, Any]:
    """Score one fixed model.  This function has no file or production writes."""

    records: list[dict[str, Any]] = []
    for case in cases:
        started = time.perf_counter_ns()
        prediction = model.predictor(case)
        record = _record_for_case(case, prediction, vocabulary)
        record["latency_ms"] = (time.perf_counter_ns() - started) / 1_000_000
        records.append(record)
    metrics = _classification_metrics(records, vocabulary, DEFAULT_MIN_PER_TACTIC_SUPPORT)
    ece, reliability = expected_calibration_error(records)
    metrics["expected_calibration_error"] = ece
    return {
        "model_id": model.model_id,
        "display_name": model.display_name,
        "metadata": dict(model.metadata),
        "metrics": metrics,
        "confidence_intervals_95": _bootstrap(records, vocabulary, iterations=bootstrap_iterations, seed=seed),
        "normalized_confusion_matrix": normalized_confusion(records, vocabulary),
        "reliability": reliability,
        "by_sequence_length": _bucket_metrics(records, vocabulary, lambda row: _bucket(int(row["sequence_length"]), ((1, "1"), (2, "2"), (3, "3"), (5, "4-5"), (10_000, "6+")))),
        "by_context_support": _bucket_metrics(records, vocabulary, lambda row: _bucket(int((row.get("metadata") or {}).get("support_count") or 0), ((0, "0"), (1, "1"), (4, "2-4"), (19, "5-19"), (99, "20-99"), (10**9, "100+")))),
        "records": records,
    }


def paired_comparison(reference: Sequence[Mapping[str, Any]], candidate: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    ref = {str(row["case_id"]): row for row in reference}
    other = {str(row["case_id"]): row for row in candidate}
    if set(ref) != set(other):
        raise ValueError("paired comparison requires an identical held-out case set")
    outcomes: Counter[str] = Counter()
    by_tactic: dict[str, Counter[str]] = defaultdict(Counter)
    for key in sorted(ref):
        left, right = ref[key], other[key]
        if left["correct"] and not right["correct"]:
            outcome = "production_vomm_win"
        elif right["correct"] and not left["correct"]:
            outcome = "candidate_win"
        elif left["correct"]:
            outcome = "tie_both_correct"
        else:
            outcome = "both_wrong_or_abstained"
        outcomes[outcome] += 1
        by_tactic[str(left["actual"])][outcome] += 1
    return {"case_count": len(ref), "outcomes": dict(outcomes), "by_tactic": {key: dict(value) for key, value in sorted(by_tactic.items())}}


def _torch_modules() -> tuple[Any, Any]:
    try:
        import numpy as np
        import torch
    except ImportError as exc:  # pragma: no cover - exercised in minimal runtime environments
        raise RuntimeError("Neural benchmark requires numpy and torch; install requirements-next-tactic-benchmark.txt") from exc
    return torch, np


def _neural_examples(cases: Sequence[BenchmarkCase], vocabulary: Sequence[str], max_length: int) -> tuple[list[list[int]], list[int]]:
    token = {label: index + 1 for index, label in enumerate(vocabulary)}
    target = {label: index for index, label in enumerate(vocabulary)}
    inputs: list[list[int]] = []
    labels: list[int] = []
    for case in cases:
        if case.actual not in target:
            continue
        values = [token[item] for item in case.sequence if item in token][-max_length:]
        if not values:
            continue
        inputs.append(values)
        labels.append(target[case.actual])
    return inputs, labels


def _pad_batch(torch: Any, values: Sequence[Sequence[int]], labels: Sequence[int] | None = None) -> tuple[Any, Any, Any | None]:
    length = max(len(item) for item in values)
    tokens = torch.zeros((len(values), length), dtype=torch.long)
    lengths = torch.zeros(len(values), dtype=torch.long)
    for index, item in enumerate(values):
        tokens[index, :len(item)] = torch.tensor(item, dtype=torch.long)
        lengths[index] = len(item)
    output_labels = torch.tensor(labels, dtype=torch.long) if labels is not None else None
    return tokens, lengths, output_labels


def _make_neural_model(kind: str, *, vocabulary_size: int, settings: Mapping[str, Any], torch: Any) -> Any:
    nn = torch.nn
    embedding_dimension = int(settings["embedding_dimension"])
    hidden_dimension = int(settings["hidden_dimension"])
    dropout = float(settings["dropout"])
    max_length = int(settings["max_sequence_length"])

    class GRUModel(nn.Module):
        def __init__(self) -> None:
            super().__init__()
            self.embedding = nn.Embedding(vocabulary_size + 1, embedding_dimension, padding_idx=0)
            self.gru = nn.GRU(embedding_dimension, hidden_dimension, batch_first=True)
            self.dropout = nn.Dropout(dropout)
            self.output = nn.Linear(hidden_dimension, vocabulary_size)

        def forward(self, tokens: Any, lengths: Any) -> Any:
            embedded = self.embedding(tokens)
            packed = nn.utils.rnn.pack_padded_sequence(embedded, lengths.cpu(), batch_first=True, enforce_sorted=False)
            _encoded, hidden = self.gru(packed)
            return self.output(self.dropout(hidden[-1]))

    class CausalTransformerModel(nn.Module):
        def __init__(self) -> None:
            super().__init__()
            self.embedding = nn.Embedding(vocabulary_size + 1, embedding_dimension, padding_idx=0)
            self.position = nn.Embedding(max_length, embedding_dimension)
            layer = nn.TransformerEncoderLayer(
                d_model=embedding_dimension,
                nhead=int(settings["attention_heads"]),
                dim_feedforward=hidden_dimension,
                dropout=dropout,
                batch_first=True,
                activation="gelu",
            )
            self.encoder = nn.TransformerEncoder(layer, num_layers=int(settings["layers"]), enable_nested_tensor=False)
            self.output = nn.Linear(embedding_dimension, vocabulary_size)

        @staticmethod
        def causal_mask(length: int, device: Any) -> Any:
            return torch.triu(torch.ones((length, length), dtype=torch.bool, device=device), diagonal=1)

        def encode_states(self, tokens: Any, lengths: Any) -> Any:
            positions = torch.arange(tokens.size(1), device=tokens.device).unsqueeze(0)
            embedded = self.embedding(tokens) + self.position(positions)
            return self.encoder(embedded, mask=self.causal_mask(tokens.size(1), tokens.device), src_key_padding_mask=tokens.eq(0))

        def forward(self, tokens: Any, lengths: Any) -> Any:
            states = self.encode_states(tokens, lengths)
            final = states[torch.arange(tokens.size(0), device=tokens.device), lengths - 1]
            return self.output(final)

    if kind == "gru":
        return GRUModel()
    if kind == "transformer":
        return CausalTransformerModel()
    raise ValueError(f"unknown neural model kind {kind}")


def _set_seed(torch: Any, seed: int) -> None:
    random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)
    torch.use_deterministic_algorithms(True, warn_only=True)


def _neural_probabilities(model: Any, cases: Sequence[BenchmarkCase], vocabulary: Sequence[str], settings: Mapping[str, Any], torch: Any, *, batch_size: int = 2048) -> list[dict[str, float]]:
    inputs, _unused = _neural_examples(cases, vocabulary, int(settings["max_sequence_length"]))
    output: list[dict[str, float]] = []
    model.eval()
    with torch.no_grad():
        for start in range(0, len(inputs), batch_size):
            tokens, lengths, _ = _pad_batch(torch, inputs[start:start + batch_size])
            probs = torch.softmax(model(tokens, lengths), dim=1).tolist()
            output.extend({label: float(value) for label, value in zip(vocabulary, row)} for row in probs)
    return output


def _fit_neural(
    kind: str,
    train_cases: Sequence[BenchmarkCase],
    validation_cases: Sequence[BenchmarkCase],
    vocabulary: Sequence[str],
    settings: Mapping[str, Any],
    *,
    seed: int,
    max_epochs: int,
    early_stopping: bool,
) -> tuple[Any, dict[str, Any]]:
    torch, _np = _torch_modules()
    _set_seed(torch, seed)
    model = _make_neural_model(kind, vocabulary_size=len(vocabulary), settings=settings, torch=torch)
    train_inputs, train_labels = _neural_examples(train_cases, vocabulary, int(settings["max_sequence_length"]))
    if not train_inputs:
        raise ValueError("neural model has no train examples")
    optimizer = torch.optim.AdamW(model.parameters(), lr=float(settings["learning_rate"]), weight_decay=float(settings.get("weight_decay", 0.0)))
    loss_function = torch.nn.CrossEntropyLoss()
    batch_size = int(settings["batch_size"])
    generator = torch.Generator().manual_seed(seed)
    best_state: dict[str, Any] | None = None
    best_epoch, best_validation_loss, stale = 0, float("inf"), 0
    history: list[dict[str, Any]] = []
    started = time.perf_counter()
    tracemalloc.start()
    for epoch in range(1, max_epochs + 1):
        model.train()
        ordering = torch.randperm(len(train_inputs), generator=generator).tolist()
        losses: list[float] = []
        for start in range(0, len(ordering), batch_size):
            selected = ordering[start:start + batch_size]
            batch_inputs = [train_inputs[index] for index in selected]
            batch_labels = [train_labels[index] for index in selected]
            tokens, lengths, labels = _pad_batch(torch, batch_inputs, batch_labels)
            optimizer.zero_grad(set_to_none=True)
            loss = loss_function(model(tokens, lengths), labels)
            loss.backward()
            optimizer.step()
            losses.append(float(loss.item()))
        if early_stopping:
            validation_probabilities = _neural_probabilities(model, validation_cases, vocabulary, settings, torch)
            validation_records = [_record_for_case(case, Prediction(probability), vocabulary) for case, probability in zip(validation_cases, validation_probabilities)]
            validation_metrics = _classification_metrics(validation_records, vocabulary, 1)
            validation_loss = float(validation_metrics["raw_log_loss"] or float("inf"))
            history.append({"epoch": epoch, "training_loss": statistics.fmean(losses), "validation_metrics": validation_metrics})
            if validation_loss < best_validation_loss - 1e-10:
                best_validation_loss, best_epoch, stale = validation_loss, epoch, 0
                best_state = {name: value.detach().clone() for name, value in model.state_dict().items()}
            else:
                stale += 1
                if stale >= int(settings["patience"]):
                    break
        else:
            # Final models use the epoch selected on the validation-selection
            # partition exactly.  Do not look at calibration or test output to
            # choose a checkpoint.
            history.append({"epoch": epoch, "training_loss": statistics.fmean(losses), "validation_metrics": None})
            best_epoch = epoch
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    if early_stopping and best_state is not None:
        model.load_state_dict(best_state)
    return model, {
        "seed": seed,
        "epochs_requested": max_epochs,
        "epochs_completed": len(history),
        "selected_epoch": best_epoch,
        "early_stopping": bool(early_stopping),
        "stopping_criterion": "minimum validation raw multiclass log loss with patience",
        "validation_loss": best_validation_loss,
        "history": history,
        "training_seconds": time.perf_counter() - started,
        "training_peak_bytes": int(peak),
        "training_current_bytes": int(current),
        "parameter_count": sum(parameter.numel() for parameter in model.parameters()),
    }


def serialize_and_reload_neural_model(
    model: Any,
    *,
    kind: str,
    vocabulary_size: int,
    settings: Mapping[str, Any],
) -> tuple[bytes, Any]:
    """Round-trip a neural state in memory for reproducibility verification.

    This stores no checkpoint in the application tree and therefore cannot
    become a production artifact.  The caller checks prediction equivalence
    before recording the byte size in the offline result.
    """

    torch, _np = _torch_modules()
    buffer = io.BytesIO()
    torch.save(model.state_dict(), buffer)
    payload = buffer.getvalue()
    reloaded = _make_neural_model(kind, vocabulary_size=vocabulary_size, settings=settings, torch=torch)
    reloaded.load_state_dict(torch.load(io.BytesIO(payload), map_location="cpu", weights_only=True))
    reloaded.eval()
    return payload, reloaded


def _neural_settings(kind: str) -> list[dict[str, Any]]:
    common = {"learning_rate": 0.003, "batch_size": 2048, "dropout": 0.10, "weight_decay": 0.0, "max_sequence_length": DEFAULT_MAX_SEQUENCE_LENGTH, "patience": 2}
    if kind == "gru":
        return [
            {**common, "embedding_dimension": 12, "hidden_dimension": 16, "layers": 1, "attention_heads": 1},
            {**common, "embedding_dimension": 16, "hidden_dimension": 24, "layers": 1, "attention_heads": 1},
        ]
    return [
        {**common, "embedding_dimension": 12, "hidden_dimension": 24, "layers": 1, "attention_heads": 3},
        {**common, "embedding_dimension": 16, "hidden_dimension": 32, "layers": 1, "attention_heads": 4},
    ]


def select_neural_settings(
    kind: str,
    train_cases: Sequence[BenchmarkCase],
    selection_cases: Sequence[BenchmarkCase],
    vocabulary: Sequence[str],
    *,
    seed: int,
    experiment_log: list[dict[str, Any]],
) -> dict[str, Any]:
    best: dict[str, Any] | None = None
    for settings in _neural_settings(kind):
        model, training = _fit_neural(kind, train_cases, selection_cases, vocabulary, settings, seed=seed, max_epochs=6, early_stopping=True)
        torch, _np = _torch_modules()
        probabilities = _neural_probabilities(model, selection_cases, vocabulary, settings, torch)
        records = [_record_for_case(case, Prediction(value), vocabulary) for case, value in zip(selection_cases, probabilities)]
        metrics = _classification_metrics(records, vocabulary, 1)
        item = {"stage": "validation_selection", "model_id": kind, "seed": seed, "settings": settings, "training": training, "metrics": metrics}
        experiment_log.append(item)
        key = (-float(metrics["macro_f1"]), -float(metrics["balanced_accuracy"]), -float(metrics["top1_accuracy"]), float(metrics["raw_log_loss"] or float("inf")))
        if best is None or key < best["key"]:
            best = {"settings": settings, "selected_epoch": max(int(training["selected_epoch"]), 1), "key": key, "selection_metrics": metrics}
    assert best is not None
    return best


def train_neural_aggregate(
    kind: str,
    train_cases: Sequence[BenchmarkCase],
    calibration_cases: Sequence[BenchmarkCase],
    test_cases: Sequence[BenchmarkCase],
    vocabulary: Sequence[str],
    *,
    settings: Mapping[str, Any],
    epochs: int,
    seeds: Sequence[int],
    experiment_log: list[dict[str, Any]],
) -> tuple[ModelRun, list[dict[str, Any]], dict[str, list[dict[str, float]]]]:
    """Fit five declared seeds; aggregation is a reporting ensemble, not tuning."""

    torch, _np = _torch_modules()
    fitted: list[Any] = []
    logs: list[dict[str, Any]] = []
    test_by_seed: dict[str, list[dict[str, float]]] = {}
    calibration_by_seed: dict[str, list[dict[str, float]]] = {}
    total_training = total_peak = total_parameters = total_serialized_size = 0
    total_load_seconds = 0.0
    for seed in seeds:
        model, log = _fit_neural(kind, train_cases, calibration_cases, vocabulary, settings, seed=seed, max_epochs=epochs, early_stopping=False)
        fitted.append(model)
        log["stage"] = "final_seed_fit"
        log["model_id"] = kind
        log["settings"] = dict(settings)
        logs.append(log)
        experiment_log.append(log)
        test_by_seed[str(seed)] = _neural_probabilities(model, test_cases, vocabulary, settings, torch)
        calibration_by_seed[str(seed)] = _neural_probabilities(model, calibration_cases, vocabulary, settings, torch)
        total_training += float(log["training_seconds"])
        total_peak = max(total_peak, int(log["training_peak_bytes"]))
        total_parameters += int(log["parameter_count"])
        load_started = time.perf_counter()
        serialized, reloaded = serialize_and_reload_neural_model(
            model, kind=kind, vocabulary_size=len(vocabulary), settings=settings
        )
        total_load_seconds += time.perf_counter() - load_started
        # Verify the stored architecture/state mapping immediately, before its
        # size is reported.  A selected held-out case is sufficient because all
        # parameters are loaded as one state dict; dedicated tests cover a
        # broader deterministic fixture.
        if test_cases:
            original = _neural_probabilities(model, test_cases[:1], vocabulary, settings, torch)[0]
            restored = _neural_probabilities(reloaded, test_cases[:1], vocabulary, settings, torch)[0]
            if any(abs(original[label] - restored[label]) > 1e-10 for label in vocabulary):
                raise RuntimeError("neural serialization/reload changed prediction output")
        total_serialized_size += len(serialized)

    def aggregate(cases: Sequence[BenchmarkCase], values_by_seed: Mapping[str, Sequence[Mapping[str, float]]]) -> list[dict[str, float]]:
        output: list[dict[str, float]] = []
        for index in range(len(cases)):
            output.append({label: statistics.fmean(float(values_by_seed[str(seed)][index].get(label, 0.0)) for seed in seeds) for label in vocabulary})
        return output

    test_values = aggregate(test_cases, test_by_seed)
    calibration_values = aggregate(calibration_cases, calibration_by_seed)
    test_lookup = {case.case_id: value for case, value in zip(test_cases, test_values)}
    model_id = f"{kind}_aggregate"
    run = ModelRun(
        model_id,
        f"{kind.upper()} sequence model (mean of five fixed seeds)",
        lambda case: Prediction(dict(test_lookup[case.case_id]), {"seed_aggregate": list(seeds), "max_sequence_length": int(settings["max_sequence_length"])}),
        {"algorithm": kind, "aggregation": "mean_raw_score_across_declared_seed_models", "settings": dict(settings), "seeds": list(seeds),
         "raw_scores_are_calibrated_probabilities": False, "training_partition": "train plus validation_selection only; calibration held aside"},
        training_seconds=total_training,
        training_peak_bytes=total_peak,
        serialized_size_bytes=total_serialized_size,
        load_seconds=total_load_seconds,
    )
    return run, logs, {"test": test_values, "calibration": calibration_values, "test_by_seed": test_by_seed}


def fit_temperature(calibration_cases: Sequence[BenchmarkCase], raw_probabilities: Sequence[Mapping[str, float]], vocabulary: Sequence[str]) -> dict[str, Any]:
    """Fit one temperature on a calibration-only partition by raw NLL grid search."""

    candidates = [0.5, 0.67, 0.8, 1.0, 1.25, 1.5, 2.0, 3.0]
    scores: list[dict[str, float]] = []
    for temperature in candidates:
        losses = []
        for case, values in zip(calibration_cases, raw_probabilities):
            scaled = _normalize({label: max(float(values.get(label, 0.0)), EPSILON) ** (1.0 / temperature) for label in vocabulary}, vocabulary)
            losses.append(-math.log(max(scaled.get(case.actual, 0.0), EPSILON)))
        scores.append({"temperature": temperature, "calibration_raw_log_loss": statistics.fmean(losses)})
    selected = min(scores, key=lambda item: (item["calibration_raw_log_loss"], item["temperature"]))
    return {"method": "temperature_scaling_grid_calibration_only.v1", "scores_are_model_outputs_not_claimed_calibrated_before_this_mapping": True, "candidate_temperatures": scores, "selected_temperature": selected["temperature"], "selection_metric": "raw multiclass log loss", "calibration_case_count": len(calibration_cases)}


def apply_temperature(values: Mapping[str, float], vocabulary: Sequence[str], temperature: float) -> dict[str, float]:
    return _normalize({label: max(float(values.get(label, 0.0)), EPSILON) ** (1.0 / temperature) for label in vocabulary}, vocabulary)


def _inference_efficiency(model: ModelRun, cases: Sequence[BenchmarkCase], vocabulary: Sequence[str]) -> dict[str, Any]:
    warmup = list(cases[: min(32, len(cases))])
    for case in warmup:
        model.predictor(case)
    sample = list(cases[: min(2000, len(cases))])
    tracemalloc.start()
    before, _ = tracemalloc.get_traced_memory()
    timings: list[float] = []
    started = time.perf_counter()
    for case in sample:
        point = time.perf_counter_ns()
        model.predictor(case)
        timings.append((time.perf_counter_ns() - point) / 1_000_000)
    elapsed = time.perf_counter() - started
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return {
        "sample_cases": len(sample),
        "warmup_cases": len(warmup),
        "inference_latency_ms": {"p50": _quantile(timings, 0.50), "p95": _quantile(timings, 0.95), "p99": _quantile(timings, 0.99), "mean": statistics.fmean(timings) if timings else 0.0},
        "throughput_cases_per_second": len(sample) / elapsed if elapsed else 0.0,
        "inference_peak_python_bytes": max(int(peak - before), 0),
        "training_seconds": model.training_seconds,
        "training_peak_python_bytes": model.training_peak_bytes,
        "serialized_model_size_bytes": model.serialized_size_bytes,
        "load_seconds": model.load_seconds,
        "cpu_user_seconds_process": resource.getrusage(resource.RUSAGE_SELF).ru_utime,
        "gpu": {"used": False, "note": "CPU-only offline benchmark environment"},
    }


def _select_examples(results: Mapping[str, Mapping[str, Any]], vocabulary: Sequence[str], limit_per_category: int = 5) -> dict[str, list[dict[str, Any]]]:
    ids = sorted(next(iter(results.values()))["records"], key=lambda row: int(row["chronological_position"]))
    by_model = {name: {row["case_id"]: row for row in result["records"]} for name, result in results.items()}
    categories: dict[str, Callable[[Mapping[str, Mapping[str, Any]]], bool]] = {
        "all_models_correct": lambda rows: all(bool(row["correct"]) for row in rows.values()),
        "production_vomm_correct_neural_wrong": lambda rows: bool(rows["hard_backoff_vomm"]["correct"]) and not rows["gru_aggregate"]["correct"] and not rows["transformer_aggregate"]["correct"],
        "gru_correct_production_vomm_wrong": lambda rows: bool(rows["gru_aggregate"]["correct"]) and not rows["hard_backoff_vomm"]["correct"],
        "transformer_correct_production_vomm_wrong": lambda rows: bool(rows["transformer_aggregate"]["correct"]) and not rows["hard_backoff_vomm"]["correct"],
        "interpolated_correct_hard_backoff_wrong": lambda rows: bool(rows["interpolated_vomm"]["correct"]) and not rows["hard_backoff_vomm"]["correct"],
        "all_models_wrong": lambda rows: all(not bool(row["correct"]) for row in rows.values()),
        "rare_target": lambda rows: int(results["hard_backoff_vomm"]["metrics"]["per_tactic"][rows["hard_backoff_vomm"]["actual"]]["support"]) < DEFAULT_MIN_PER_TACTIC_SUPPORT,
        "long_input": lambda rows: int(rows["hard_backoff_vomm"]["sequence_length"]) >= 6,
        "short_input": lambda rows: int(rows["hard_backoff_vomm"]["sequence_length"]) <= 1,
        "model_disagreement": lambda rows: len({str(row["top1"]) for row in rows.values()}) >= 3,
        "production_vomm_abstention": lambda rows: bool(rows["hard_backoff_vomm"]["abstained"]),
        "low_support_context": lambda rows: int((rows["hard_backoff_vomm"].get("metadata") or {}).get("support_count") or 0) <= 4,
        "high_support_context": lambda rows: int((rows["hard_backoff_vomm"].get("metadata") or {}).get("support_count") or 0) >= 100,
    }
    selections: dict[str, list[dict[str, Any]]] = {name: [] for name in categories}
    for base in ids:
        rows = {name: records[base["case_id"]] for name, records in by_model.items()}
        for category, predicate in categories.items():
            if len(selections[category]) >= limit_per_category or not predicate(rows):
                continue
            # Store only anonymized case identity and factual per-model output.
            selections[category].append({
                "case_id": base["case_id"], "chronological_position": base["chronological_position"], "input_tactic_sequence": base["sequence"], "sequence_length": base["sequence_length"], "true_next_tactic": base["actual"],
                "models": {name: {"top1": row["top1"], "top3": row["top3"], "raw_score_vector": row["raw_probabilities"], "correct": row["correct"], "abstained": row["abstained"], "metadata": row["metadata"]} for name, row in rows.items()},
                "explanation": f"Deterministically selected chronological held-out case satisfying category '{category}'.",
            })
    return selections


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_csv(path: Path, rows: Sequence[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = sorted({key for row in rows for key in row}) if rows else ["model_id"]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _write_prediction_rows(path: Path, results: Mapping[str, Mapping[str, Any]]) -> None:
    by_model = {name: {row["case_id"]: row for row in result["records"]} for name, result in results.items()}
    case_ids = sorted(next(iter(by_model.values())), key=lambda case_id: int(next(iter(by_model.values()))[case_id]["chronological_position"]))
    with gzip.open(path, "wt", encoding="utf-8") as handle:
        for case_id in case_ids:
            reference = by_model["hard_backoff_vomm"][case_id]
            row = {"case_id": case_id, "chronological_position": reference["chronological_position"], "actual": reference["actual"], "sequence": reference["sequence"], "models": {name: {key: value for key, value in model[case_id].items() if key not in {"session_id", "sequence"}} for name, model in by_model.items()}}
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def _metric_rows(results: Mapping[str, Mapping[str, Any]]) -> list[dict[str, Any]]:
    return [{"model_id": key, **{field: value for field, value in result["metrics"].items() if field not in {"per_tactic"}}} for key, result in results.items()]


def _per_tactic_rows(results: Mapping[str, Mapping[str, Any]]) -> list[dict[str, Any]]:
    return [{"model_id": model_id, "tactic": tactic, **metrics} for model_id, result in results.items() for tactic, metrics in result["metrics"]["per_tactic"].items()]


def _figure_backend() -> Any:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError as exc:  # pragma: no cover - runtime requirement
        raise RuntimeError("Figure export requires matplotlib; install requirements-next-tactic-benchmark.txt") from exc
    return plt


def write_figures(destination: Path, result: Mapping[str, Any]) -> list[str]:
    """Create required non-truncated PNG/PDF figures from one immutable result."""

    plt = _figure_backend()
    destination.mkdir(parents=True, exist_ok=True)
    results = result["models"]
    vocabulary = result["dataset"]["tactic_vocabulary"]
    model_ids = list(results)
    labels = [results[key]["display_name"] for key in model_ids]
    paths: list[str] = []
    def save(name: str, caption: str) -> None:
        plt.tight_layout()
        for suffix in ("png", "pdf"):
            path = destination / f"{name}.{suffix}"
            plt.savefig(path, dpi=180 if suffix == "png" else None, bbox_inches="tight")
            paths.append(str(path))
        plt.close()
    distributions = result["dataset"]["split_summary"]["partitions"]
    plt.figure(figsize=(11, 5)); x = range(len(vocabulary)); width = 0.25
    for offset, split_name in enumerate(("train", "calibration", "test")):
        values = [distributions[split_name]["target_tactic_distribution"].get(tactic, 0) for tactic in vocabulary]
        plt.bar([item + (offset - 1) * width for item in x], values, width, label=split_name)
    plt.xticks(list(x), vocabulary, rotation=35, ha="right"); plt.ylabel("Next-tactic cases"); plt.title("Target tactic distribution by chronological split"); plt.legend(); save("01_target_tactic_distribution", "Counts are not normalized; imbalance remains visible.")
    lengths = Counter();
    for value, count in distributions["test"]["sequence_length_distribution"].items(): lengths[int(value)] += int(count)
    plt.figure(figsize=(9, 5)); plt.bar(sorted(lengths), [lengths[key] for key in sorted(lengths)]); plt.xlabel("Input sequence length"); plt.ylabel("Held-out cases"); plt.title("Held-out input sequence-length distribution"); save("02_input_sequence_length_distribution", "Full held-out distribution.")
    metric_names = ("top1_accuracy", "top3_accuracy", "macro_f1", "balanced_accuracy", "mean_reciprocal_rank")
    plt.figure(figsize=(13, 6)); x = list(range(len(model_ids))); width = 0.15
    for offset, metric in enumerate(metric_names): plt.bar([item + (offset - 2) * width for item in x], [results[key]["metrics"][metric] for key in model_ids], width, label=metric)
    plt.xticks(x, labels, rotation=30, ha="right"); plt.ylim(0, 1); plt.ylabel("Score"); plt.title("Overall raw-model comparison"); plt.legend(ncol=3); save("03_overall_model_comparison", "All axes use the complete 0–1 metric scale.")
    for metric, name, title in (("f1", "04_per_tactic_f1_heatmap", "Per-tactic F1"), ("recall", "05_per_tactic_recall_heatmap", "Per-tactic recall")):
        matrix = [[results[model]["metrics"]["per_tactic"][tactic][metric] for tactic in vocabulary] for model in model_ids]
        plt.figure(figsize=(12, 5)); image = plt.imshow(matrix, aspect="auto", vmin=0, vmax=1, cmap="viridis"); plt.colorbar(image, label=metric); plt.xticks(range(len(vocabulary)), vocabulary, rotation=35, ha="right"); plt.yticks(range(len(model_ids)), labels); plt.title(title); save(name, "Values are raw held-out metrics; rare tactics are visible but not over-interpreted.")
    for model_id, name in (("hard_backoff_vomm", "06_confusion_hard_backoff"), ("interpolated_vomm", "07_confusion_interpolated"), ("gru_aggregate", "08_confusion_gru"), ("transformer_aggregate", "09_confusion_transformer")):
        confusion = results[model_id]["normalized_confusion_matrix"]; predicted = list(vocabulary) + ["<abstained>"]
        matrix = [[confusion[actual][item] for item in predicted] for actual in vocabulary]
        plt.figure(figsize=(10, 7)); image = plt.imshow(matrix, vmin=0, vmax=1, cmap="Blues"); plt.colorbar(image, label="row-normalized frequency"); plt.xticks(range(len(predicted)), predicted, rotation=35, ha="right"); plt.yticks(range(len(vocabulary)), vocabulary); plt.title(f"Normalized confusion: {results[model_id]['display_name']}"); save(name, "Rows sum to one; axes are not truncated.")
    plt.figure(figsize=(10, 5))
    for model_id in model_ids:
        bucket = results[model_id]["by_sequence_length"]
        keys = ["1", "2", "3", "4-5", "6+"]
        plt.plot(keys, [bucket.get(key, {}).get("top1_accuracy", float("nan")) for key in keys], marker="o", label=model_id)
    plt.ylim(0, 1); plt.ylabel("Top-1 accuracy"); plt.title("Performance by input sequence length"); plt.legend(fontsize=8); save("10_performance_by_sequence_length", "All-case Top-1; absent buckets are omitted.")
    plt.figure(figsize=(10, 5))
    for model_id in model_ids:
        bucket = results[model_id]["by_context_support"]; keys = ["0", "1", "2-4", "5-19", "20-99", "100+"]
        plt.plot(keys, [bucket.get(key, {}).get("top1_accuracy", float("nan")) for key in keys], marker="o", label=model_id)
    plt.ylim(0, 1); plt.ylabel("Top-1 accuracy"); plt.title("Performance by available context support"); plt.legend(fontsize=8); save("11_performance_by_context_support", "Support metadata is unavailable for some non-count models and shown as zero.")
    plt.figure(figsize=(9, 5)); plt.bar(range(len(model_ids)), [results[key]["metrics"]["coverage"] for key in model_ids], label="coverage"); plt.bar(range(len(model_ids)), [results[key]["metrics"]["selective_top1_accuracy"] or 0 for key in model_ids], alpha=.55, label="selective Top-1"); plt.xticks(range(len(model_ids)), labels, rotation=30, ha="right"); plt.ylim(0, 1); plt.title("Coverage versus selective accuracy"); plt.legend(); save("12_coverage_vs_selective_accuracy", "Selective accuracy excludes abstentions; coverage is shown beside it.")
    plt.figure(figsize=(10, 5));
    for model_id in model_ids:
        reliability = results[model_id]["reliability"]; xs = [row["mean_confidence"] for row in reliability if row["count"]]; ys = [row["accuracy"] for row in reliability if row["count"]]
        plt.plot(xs, ys, marker="o", label=model_id)
    plt.plot([0,1],[0,1],"k--", label="ideal"); plt.xlim(0,1); plt.ylim(0,1); plt.xlabel("Mean raw score"); plt.ylabel("Observed Top-1 accuracy"); plt.title("Reliability diagram (raw scores)"); plt.legend(fontsize=8); save("13_raw_score_reliability", "Raw scores are not described as calibrated probabilities.")
    raw_metrics = ("raw_brier_score", "raw_log_loss", "expected_calibration_error")
    plt.figure(figsize=(11, 5)); x = list(range(len(model_ids))); width=.24
    for offset, metric in enumerate(raw_metrics): plt.bar([item + (offset-1)*width for item in x], [results[key]["metrics"].get(metric) or 0 for key in model_ids], width, label=metric)
    plt.xticks(x, labels, rotation=30, ha="right"); plt.ylim(bottom=0); plt.title("Raw score quality (lower is better)"); plt.legend(); save("14_raw_brier_logloss_ece", "Metrics have different units; bars are grouped but not treated as interchangeable.")
    paired = result["paired_comparisons"]
    keys = [key for key in model_ids if key != "hard_backoff_vomm"]
    plt.figure(figsize=(10, 5)); wins = [paired[key]["outcomes"].get("candidate_win", 0) for key in keys]; losses = [paired[key]["outcomes"].get("production_vomm_win", 0) for key in keys]; x=range(len(keys)); plt.bar(x,wins,label="candidate wins"); plt.bar(x,[-value for value in losses],label="production VOMM wins"); plt.axhline(0,color="black"); plt.xticks(list(x),keys,rotation=30,ha="right"); plt.title("Paired case-level wins/losses versus production VOMM"); plt.legend(); save("15_paired_wins_losses", "Negative bars are production-VOMM wins, not negative counts.")
    windows = result["chronological_windows"]
    plt.figure(figsize=(10,5));
    for model_id in model_ids: plt.plot([item["window"] for item in windows], [item["models"][model_id]["top1_accuracy"] for item in windows], marker="o", label=model_id)
    plt.ylim(0,1); plt.xlabel("Chronological held-out window"); plt.ylabel("Top-1 accuracy"); plt.title("Temporal held-out stability"); plt.legend(fontsize=8); save("16_chronological_windows", "Windows preserve held-out input order.")
    stability = result["neural_seed_stability"]
    plt.figure(figsize=(8,5)); names=list(stability); means=[stability[name]["macro_f1"]["mean"] for name in names]; errors=[stability[name]["macro_f1"]["stddev"] for name in names]; plt.bar(range(len(names)),means,yerr=errors,capsize=5); plt.xticks(range(len(names)),names); plt.ylim(0,1); plt.title("Neural seed stability (macro-F1 mean ± SD)"); save("17_neural_seed_stability", "Five declared final seeds per neural architecture.")
    efficiency = result["efficiency"]
    plt.figure(figsize=(9,5)); plt.scatter([efficiency[key]["inference_latency_ms"]["p95"] for key in model_ids], [results[key]["metrics"]["macro_f1"] for key in model_ids]);
    for key in model_ids: plt.annotate(key, (efficiency[key]["inference_latency_ms"]["p95"], results[key]["metrics"]["macro_f1"]), fontsize=8)
    plt.xlabel("p95 inference latency (ms)"); plt.ylabel("Macro-F1"); plt.title("Macro-F1 versus p95 inference latency"); save("18_macro_f1_vs_latency", "Same machine, warmed model, same sample-size benchmark.")
    plt.figure(figsize=(9,5)); plt.scatter([efficiency[key]["serialized_model_size_bytes"] for key in model_ids], [results[key]["metrics"]["macro_f1"] for key in model_ids]);
    for key in model_ids: plt.annotate(key, (efficiency[key]["serialized_model_size_bytes"], results[key]["metrics"]["macro_f1"]), fontsize=8)
    plt.xlabel("Serialized model size (bytes)"); plt.ylabel("Macro-F1"); plt.title("Macro-F1 versus model size"); save("19_macro_f1_vs_model_size", "Count models report JSON artifact/model representation; neural aggregate is five seed models.")
    plt.figure(figsize=(11,5)); x=list(range(len(model_ids))); plt.bar([item-.25 for item in x],[efficiency[key]["training_seconds"] for key in model_ids],.25,label="training seconds"); plt.bar(x,[efficiency[key]["training_peak_python_bytes"]/(1024*1024) for key in model_ids],.25,label="peak training RAM MiB"); plt.bar([item+.25 for item in x],[efficiency[key]["throughput_cases_per_second"] for key in model_ids],.25,label="inference throughput cases/s"); plt.xticks(x,labels,rotation=30,ha="right"); plt.title("Training time, Python peak RAM, and inference throughput"); plt.legend(); save("20_efficiency_comparison", "Units differ and are labeled separately; no axes are truncated.")
    return paths


def _windowed_results(results: Mapping[str, Mapping[str, Any]], vocabulary: Sequence[str], window_count: int = 4) -> list[dict[str, Any]]:
    reference = results["hard_backoff_vomm"]["records"]
    width = math.ceil(len(reference) / window_count)
    output = []
    for index, start in enumerate(range(0, len(reference), width), start=1):
        identifiers = {row["case_id"] for row in reference[start:start+width]}
        output.append({"window": index, "case_count": len(identifiers), "models": {model_id: _classification_metrics([row for row in item["records"] if row["case_id"] in identifiers], vocabulary, 1) for model_id, item in results.items()}})
    return output


def _seed_stability(seed_results: Mapping[str, Sequence[Mapping[str, Any]]], test_cases: Sequence[BenchmarkCase], vocabulary: Sequence[str]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for kind, sequences in seed_results.items():
        metrics = []
        for probabilities in sequences:
            records = [_record_for_case(case, Prediction(values), vocabulary) for case, values in zip(test_cases, probabilities)]
            metrics.append(_classification_metrics(records, vocabulary, 1))
        output[kind] = {field: {"mean": statistics.fmean(float(item[field]) for item in metrics), "stddev": statistics.stdev(float(item[field]) for item in metrics) if len(metrics) > 1 else 0.0, "minimum": min(float(item[field]) for item in metrics), "maximum": max(float(item[field]) for item in metrics)} for field in ("top1_accuracy", "macro_f1", "balanced_accuracy", "mean_reciprocal_rank")} | {"individual_seed_metrics": metrics}
    return output


def _report_markdown(result: Mapping[str, Any]) -> str:
    lines = ["# Offline next-tactic model comparison", "", "## Scope", "", "This offline benchmark does not modify production policy, the deployed artifact, storage, workers, services, or infrastructure. Raw model scores are not called calibrated probabilities.", "", "## Dataset and controls", "", f"- Dataset SHA-256: `{result['dataset']['payload_sha256']}`", f"- Production artifact SHA-256: `{result['artifact']['actual_sha256']}`", f"- Production manifest SHA-256: `{result['artifact']['manifest_sha256']}`", f"- Exact manifest/split verification: `{result['artifact']['membership_verification']['valid']}`", "- All cases use the shared trusted-label predicate and adjacent tactic deduplication before case extraction.", "", "## Primary metrics", "", "| Model | Top-1 | Top-3 | Balanced acc. | Macro-F1 | MRR | Coverage | Raw Brier | Raw log loss | ECE |", "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for model_id, item in result["models"].items():
        metrics = item["metrics"]
        lines.append(f"| {model_id} | {metrics['top1_accuracy']:.4f} | {metrics['top3_accuracy']:.4f} | {metrics['balanced_accuracy']:.4f} | {metrics['macro_f1']:.4f} | {metrics['mean_reciprocal_rank']:.4f} | {metrics['coverage']:.4f} | {metrics['raw_brier_score']:.4f} | {metrics['raw_log_loss']:.4f} | {(metrics['expected_calibration_error'] or 0):.4f} |")
    lines.extend(["", "## Interpretation", "", "The immutable deployed hard-backoff VOMM remains the production model regardless of this offline comparison. Any apparent difference must be interpreted with bootstrap intervals, paired cases, rare-tactic support, chronological windows, seed variability, and operational costs—not Top-1 alone.", "", "Neural candidates are deliberately small and use five declared final seeds. Their validation selection and calibration roles are separate whole-session chronological halves. The external artifact uses the train-plus-validation partition proven in its immutable manifest; this unavoidable incumbent-training asymmetry is recorded rather than hidden.", "", "## Calibration", "", "Raw outputs are evaluated first. Temperature mappings, where present, are secondary and fit only on the retained calibration sessions; they do not alter benchmark raw metrics or any production behavior.", "", "## Outputs", "", "See JSON/CSV tables, compressed case-level comparisons, deterministic held-out examples, and paired PNG/PDF figures in this directory."])
    return "\n".join(lines) + "\n"


def run_benchmark(args: argparse.Namespace) -> dict[str, Any]:
    """Run the benchmark without a production mutation path."""

    payloads = load_session_payloads(args.payload)
    split, split_method = split_session_payloads(payloads)
    policy = load_policy(args.policy)
    artifact, artifact_validation = load_exact_external_artifact(
        args.artifact,
        expected_sha256=args.expected_artifact_sha256 or file_sha256(args.artifact),
        expected_model_id=args.expected_model_id,
        manifest_path=args.manifest,
        expected_manifest_id=args.expected_manifest_id,
    )
    if not artifact_validation.get("valid"):
        raise ValueError(f"exact production artifact is unavailable: {artifact_validation.get('reasons')}")
    manifest = artifact_validation.get("manifest") if isinstance(artifact_validation.get("manifest"), dict) else {}
    membership = _verify_manifest_evaluation_membership(payloads, split, manifest)
    if not membership.get("valid"):
        raise ValueError(f"payload split does not match the immutable artifact manifest: {membership.get('reasons')}")
    vocabulary = [str(item) for item in artifact.get("tactic_vocabulary") or manifest.get("tactic_vocabulary") or [] if str(item)]
    if not vocabulary:
        raise ValueError("artifact does not define a tactic vocabulary")
    selection_sessions, calibration_sessions, validation_roles = split_validation_sessions(split["calibration"])
    train_cases = make_cases(split["train"])
    selection_cases = make_cases(selection_sessions)
    calibration_cases = make_cases(calibration_sessions)
    test_cases = make_cases(split["test"])
    if not all((train_cases, selection_cases, calibration_cases, test_cases)):
        raise ValueError("each benchmark role must contain at least one next-tactic case")
    checkpoint_dir = Path(getattr(args, "checkpoint_dir", "") or args.output_dir) / "stages"
    checkpoint_dir.mkdir(parents=True, exist_ok=True)
    def checkpoint(name: str, value: Any) -> None:
        _write_json(checkpoint_dir / f"{name}.json", value)
        print(f"[offline-benchmark] checkpoint={name}", flush=True)
    experiment_log: list[dict[str, Any]] = []
    checkpoint("01_validation", {"dataset_sha256": file_sha256(args.payload), "artifact": artifact_validation, "membership": membership})
    # Candidate count models never observe test cases. Keep calibration held out
    # from their raw fit, so it remains valid for secondary neural calibration.
    fit_sessions = [*split["train"], *selection_sessions]
    fit_cases = [*train_cases, *selection_cases]
    majority = majority_model(fit_cases, vocabulary)
    first_order = first_order_model(fit_sessions, vocabulary)
    interpolated_selection = select_interpolated_vomm(split["train"], selection_cases, vocabulary, experiment_log=experiment_log)
    interpolated = interpolated_vomm_model(fit_sessions, vocabulary, interpolated_selection["settings"])
    production = external_hard_backoff_model(policy, artifact, vocabulary)
    # Finish and persist every deterministic model before neural training.
    results = {}
    for model in (majority, first_order, production, interpolated):
        print(f"[offline-benchmark] evaluating={model.model_id}", flush=True)
        results[model.model_id] = evaluate_model(model, test_cases, vocabulary, bootstrap_iterations=args.bootstrap_iterations, seed=int(args.seeds[0]))
        checkpoint(f"02_model_{model.model_id}", results[model.model_id])
    neural_settings: dict[str, Any] = {}
    neural_runs: list[ModelRun] = []
    neural_seed_records: dict[str, list[dict[str, Any]]] = {}
    neural_values: dict[str, dict[str, list[dict[str, float]]]] = {}
    for kind in ("gru", "transformer"):
        print(f"[offline-benchmark] selecting={kind}", flush=True)
        selected = select_neural_settings(kind, train_cases, selection_cases, vocabulary, seed=int(args.seeds[0]), experiment_log=experiment_log)
        neural_settings[kind] = selected
        run, logs, values = train_neural_aggregate(kind, fit_cases, calibration_cases, test_cases, vocabulary, settings=selected["settings"], epochs=int(selected["selected_epoch"]), seeds=args.seeds, experiment_log=experiment_log)
        neural_runs.append(run); neural_seed_records[kind] = logs; neural_values[kind] = values
        checkpoint(f"03_neural_{kind}_seeds", {"selection": selected, "seed_logs": logs, "test_prediction_counts": {seed: len(rows) for seed, rows in values["test_by_seed"].items()}})
    models = [majority, first_order, production, interpolated, *neural_runs]
    for model in neural_runs:
        print(f"[offline-benchmark] evaluating={model.model_id}", flush=True)
        results[model.model_id] = evaluate_model(model, test_cases, vocabulary, bootstrap_iterations=args.bootstrap_iterations, seed=int(args.seeds[0]))
        checkpoint(f"04_model_{model.model_id}", results[model.model_id])
    # The neural aggregate is precomputed over test cases, so its ModelRun is a
    # read-only lookup. Its per-seed metric distribution remains independently
    # recorded below.
    calibration: dict[str, Any] = {}
    for kind, values in neural_values.items():
        mapping = fit_temperature(calibration_cases, values["calibration"], vocabulary)
        calibrated_records = [_record_for_case(case, Prediction(apply_temperature(probabilities, vocabulary, float(mapping["selected_temperature"]))), vocabulary) for case, probabilities in zip(test_cases, values["test"])]
        calibrated_metrics = _classification_metrics(calibrated_records, vocabulary, DEFAULT_MIN_PER_TACTIC_SUPPORT)
        calibrated_ece, calibrated_reliability = expected_calibration_error(calibrated_records)
        calibrated_metrics["expected_calibration_error"] = calibrated_ece
        calibration[kind] = {**mapping, "raw_test_metrics": results[f"{kind}_aggregate"]["metrics"], "calibrated_test_metrics": calibrated_metrics, "calibrated_reliability": calibrated_reliability}
    paired = {model_id: paired_comparison(results["hard_backoff_vomm"]["records"], item["records"]) for model_id, item in results.items() if model_id != "hard_backoff_vomm"}
    # Re-evaluate seed arrays only in-memory; they are never a production model.
    stability = _seed_stability({kind: [values["test_by_seed"][str(seed)] for seed in args.seeds] for kind, values in neural_values.items()}, test_cases, vocabulary)
    efficiency = {model.model_id: _inference_efficiency(model, test_cases, vocabulary) for model in models}
    for model in models:
        efficiency[model.model_id]["training_seconds"] = model.training_seconds
        efficiency[model.model_id]["training_peak_python_bytes"] = model.training_peak_bytes
        efficiency[model.model_id]["serialized_model_size_bytes"] = model.serialized_size_bytes
    dataset = {
        "payload_path": args.payload,
        "payload_sha256": file_sha256(args.payload),
        "split_method": split_method,
        "tactic_vocabulary": vocabulary,
        "split_summary": split_summary(split, vocabulary),
        "validation_roles": validation_roles,
        "preprocessing": manifest.get("preprocessing") or {},
        "preprocessing_sha256": str(manifest.get("preprocessing_sha256") or ""),
        "classification_policy_sha256": str((manifest.get("classification") or {}).get("sha256") or ""),
        "trust_policy_sha256": str((manifest.get("trust_policy") or {}).get("sha256") or ""),
    }
    result = {
        "schema_version": SCHEMA_VERSION,
        "generated_at_epoch_seconds": time.time(),
        "offline_only": True,
        "production_mutations": {"prediction_policy": False, "artifact": False, "database": False, "services": False, "networking": False},
        "dataset": dataset,
        "artifact": {**artifact_validation, "membership_verification": membership},
        "experimental_controls": {"whole_session_split_before_case_extraction": True, "test_used_for_training_or_selection": False, "declared_neural_seeds": list(args.seeds), "raw_scores_called_calibrated_probabilities": False, "production_artifact_rebuilt": False},
        "model_configurations": {"majority_class": majority.metadata, "first_order_markov": first_order.metadata, "hard_backoff_vomm": production.metadata, "interpolated_vomm": {**interpolated.metadata, "selection": interpolated_selection}, "neural": neural_settings},
        "experiment_log": experiment_log,
        "models": results,
        "paired_comparisons": paired,
        "chronological_windows": _windowed_results(results, vocabulary),
        "neural_seed_stability": stability,
        "calibration": calibration,
        "efficiency": efficiency,
        "limitations": ["All targets are trusted classifier-derived weak labels, not independent analyst labels.", "The immutable incumbent artifact was trained on manifest train plus validation; candidate models retain a calibration half, so equal-data superiority is not claimed.", "This is offline external-corpus evaluation only and does not establish deployment-local accuracy.", "No raw score is a calibrated probability unless reported separately in the secondary calibration analysis."],
    }
    result["selected_examples"] = _select_examples(results, vocabulary)
    checkpoint("05_aggregate_complete", {"model_ids": list(results), "test_case_count": len(test_cases)})
    return result


def write_outputs(result: Mapping[str, Any], output_dir: str | Path, *, figures: bool = True) -> dict[str, str]:
    destination = Path(output_dir); destination.mkdir(parents=True, exist_ok=True)
    compact = dict(result); compact["models"] = {key: {field: value for field, value in item.items() if field != "records"} for key, item in result["models"].items()}
    _write_json(destination / "dataset_split_manifest.json", {"dataset": result["dataset"], "artifact": result["artifact"], "experimental_controls": result["experimental_controls"]})
    _write_json(destination / "model_configurations.json", result["model_configurations"])
    with (destination / "experiment_log.jsonl").open("w", encoding="utf-8") as handle:
        for item in result["experiment_log"]: handle.write(json.dumps(item, sort_keys=True) + "\n")
    _write_json(destination / "overall_metrics.json", {key: value["metrics"] for key, value in result["models"].items()}); _write_csv(destination / "overall_metrics.csv", _metric_rows(result["models"]))
    _write_json(destination / "per_tactic_metrics.json", {key: value["metrics"]["per_tactic"] for key, value in result["models"].items()}); _write_csv(destination / "per_tactic_metrics.csv", _per_tactic_rows(result["models"]))
    _write_prediction_rows(destination / "prediction_level_comparison.jsonl.gz", result["models"])
    _write_json(destination / "confusion_matrices.json", {key: value["normalized_confusion_matrix"] for key, value in result["models"].items()})
    _write_json(destination / "paired_comparisons.json", result["paired_comparisons"]); _write_json(destination / "confidence_intervals.json", {key: value["confidence_intervals_95"] for key, value in result["models"].items()})
    _write_json(destination / "calibration.json", result["calibration"]); _write_json(destination / "efficiency.json", result["efficiency"]); _write_json(destination / "selected_heldout_examples.json", result["selected_examples"])
    _write_json(destination / "final_decision.json", {"production_model_changed": False, "decision": "offline comparison only; production external hard-backoff VOMM remains unchanged", "replacement_evidence_required": ["independent labels", "deployment-local chronological holdout", "reviewed promotion gate"]})
    (destination / "evaluation_report.md").write_text(_report_markdown(result), encoding="utf-8")
    (destination / "thesis_results_summary.md").write_text("# Thesis-ready result summary\n\n" + _report_markdown(result).split("## Primary metrics", 1)[-1], encoding="utf-8")
    _write_json(destination / "benchmark_result.json", compact)
    figure_paths = write_figures(destination / "figures", result) if figures else []
    return {"output_dir": str(destination), "figures": ",".join(figure_paths)}


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--payload", default=DEFAULT_PAYLOAD)
    parser.add_argument("--artifact", default=DEFAULT_ARTIFACT)
    parser.add_argument("--manifest", default=DEFAULT_MANIFEST)
    parser.add_argument("--policy", default=DEFAULT_POLICY)
    parser.add_argument("--expected-artifact-sha256", default="")
    parser.add_argument("--expected-model-id", default="externalvomm_8dabca1f770b06e73fb051766539435a")
    parser.add_argument("--expected-manifest-id", default="externalvommmanifest_f97d2d3770c6ac44f9eb7e7905c7736b")
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--checkpoint-dir", default="")
    parser.add_argument("--seeds", type=int, nargs="+", default=list(DEFAULT_SEEDS))
    parser.add_argument("--bootstrap-iterations", type=int, default=DEFAULT_BOOTSTRAP)
    parser.add_argument("--no-figures", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    if len(args.seeds) < 5:
        raise SystemExit("at least five declared neural seeds are required")
    result = run_benchmark(args)
    paths = write_outputs(result, args.output_dir, figures=not args.no_figures)
    print(json.dumps({"status": "complete_offline_only", **paths}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
