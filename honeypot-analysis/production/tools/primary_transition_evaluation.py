"""Chronological held-out evaluation for the active primary-transition design."""

from __future__ import annotations

import argparse
import json
import random
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence, Tuple

from production.prediction.prediction_backtest import (
    _brier_score,
    _prefix_payload,
    _rank,
    _tactic_steps,
    load_external_transition_model,
    load_session_payloads,
)
from production.prediction.realtime_prediction import (
    RealtimePredictionEngine,
    build_actor_fingerprint_transition_model,
    build_transition_model,
)
from production.prediction.session_features import build_session_features
from production.utils.config import ProductionConfig
from production.utils.serialization import utc_now


def _time(payload: Dict[str, Any]) -> datetime:
    for key in ("start_time", "created_at", "first_seen", "timestamp", "end_time"):
        value = payload.get(key)
        if not value:
            continue
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            continue
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    return datetime.min.replace(tzinfo=timezone.utc)


def chronological_split(
    payloads: Iterable[Dict[str, Any]],
    *,
    train_fraction: float = 0.70,
    calibration_fraction: float = 0.15,
) -> Dict[str, List[Dict[str, Any]]]:
    eligible = [
        payload for payload in payloads
        if isinstance(payload, dict) and len(_tactic_steps(payload)) >= 2
    ]
    eligible.sort(key=lambda payload: (_time(payload), str(payload.get("session_id") or "")))
    size = len(eligible)
    train_end = min(max(int(size * train_fraction), 0), size)
    calibration_end = min(
        max(train_end + int(size * calibration_fraction), train_end),
        size,
    )
    return {
        "train": eligible[:train_end],
        "calibration": eligible[train_end:calibration_end],
        "test": eligible[calibration_end:],
    }


def live_model_training_payloads(
    payloads: Iterable[Dict[str, Any]],
    policy: Dict[str, Any],
    *,
    history_limit: int | None = None,
) -> List[Dict[str, Any]]:
    """Order and cap offline training exactly as the live newest-first query."""

    ordered = [payload for payload in payloads if isinstance(payload, dict)]
    minimum_time = datetime.min.replace(tzinfo=timezone.utc)
    if any(_time(payload) != minimum_time for payload in ordered):
        ordered.sort(
            key=lambda payload: (_time(payload), str(payload.get("session_id") or "")),
            reverse=True,
        )
    limit = max(
        int(
            history_limit
            if history_limit is not None
            else policy.get("transition_history_limit", 500)
        ),
        1,
    )
    return ordered[:limit]


def _policy_variant(
    policy: Dict[str, Any],
    *,
    mode: str = "primary_transition_with_fallback",
    source_order: Sequence[str] | None = None,
    fallback_scorer: str | None = None,
) -> Dict[str, Any]:
    updated = json.loads(json.dumps(policy or {}))
    updated["prediction_mode"] = mode
    if source_order is not None or fallback_scorer is not None:
        primary = dict(updated.get("primary_transition") or {})
        if source_order is not None:
            primary["source_order"] = list(source_order)
        if fallback_scorer is not None:
            primary["fallback_scorer"] = fallback_scorer
        updated["primary_transition"] = primary
    return updated


def _ece(rows: List[Dict[str, Any]], bins: int = 10) -> float:
    if not rows:
        return 0.0
    total = len(rows)
    value = 0.0
    for index in range(bins):
        low = index / bins
        high = (index + 1) / bins
        bucket = [
            row for row in rows
            if low <= float(row["top_score"]) <= high
            and (index == bins - 1 or float(row["top_score"]) < high)
        ]
        if not bucket:
            continue
        confidence = sum(float(row["top_score"]) for row in bucket) / len(bucket)
        accuracy = sum(1.0 if row["rank"] == 1 else 0.0 for row in bucket) / len(bucket)
        value += (len(bucket) / total) * abs(accuracy - confidence)
    return round(value, 4)


def _bootstrap_ci(values: List[float], *, seed: int, iterations: int = 1000) -> List[float] | None:
    if not values:
        return None
    rng = random.Random(seed)
    estimates = []
    for _ in range(max(iterations, 1)):
        sample = [values[rng.randrange(len(values))] for _ in values]
        estimates.append(sum(sample) / len(sample))
    estimates.sort()
    low = estimates[int(0.025 * (len(estimates) - 1))]
    high = estimates[int(0.975 * (len(estimates) - 1))]
    return [round(low, 4), round(high, 4)]


def _summarize_cases(cases: List[Dict[str, Any]], *, seed: int = 20260712) -> Dict[str, Any]:
    total = len(cases)
    predicted = sum(bool(case["predicted"]) for case in cases)
    top1_values = [1.0 if case["rank"] == 1 else 0.0 for case in cases]
    top3_values = [1.0 if 1 <= case["rank"] <= 3 else 0.0 for case in cases]
    mrr_values = [1.0 / case["rank"] if case["rank"] else 0.0 for case in cases]
    brier_values = [float(case["brier_score"]) for case in cases]
    fallback_cases = [case for case in cases if case.get("primary_mode")]
    source_counts = Counter(str(case.get("selected_source") or "none") for case in fallback_cases)
    by_support: Dict[str, Dict[str, Any]] = {}
    support_levels = sorted({str(case.get("support_level") or "not_applicable") for case in cases})
    for support_level in support_levels:
        bucket = [case for case in cases if str(case.get("support_level") or "not_applicable") == support_level]
        bucket_total = len(bucket)
        by_support[support_level] = {
            "evaluated_examples": bucket_total,
            "coverage": round(sum(bool(case.get("predicted")) for case in bucket) / bucket_total, 4),
            "top1_accuracy": round(sum(case.get("rank") == 1 for case in bucket) / bucket_total, 4),
            "top3_accuracy": round(sum(1 <= int(case.get("rank") or 0) <= 3 for case in bucket) / bucket_total, 4),
        }
    return {
        "evaluated_examples": total,
        "coverage": round(predicted / total, 4) if total else 0.0,
        "abstention_rate": round((total - predicted) / total, 4) if total else 0.0,
        "top1_accuracy": round(sum(top1_values) / total, 4) if total else 0.0,
        "top3_accuracy": round(sum(top3_values) / total, 4) if total else 0.0,
        "mean_reciprocal_rank": round(sum(mrr_values) / total, 4) if total else 0.0,
        "brier_score": round(sum(brier_values) / total, 4) if total else 0.0,
        "expected_calibration_error": _ece(cases),
        "fallback_use_rate": round(
            sum(bool(case.get("fallback_used")) for case in fallback_cases) / len(fallback_cases),
            4,
        ) if fallback_cases else None,
        "selected_source_counts": dict(sorted(source_counts.items())),
        "performance_by_support_level": by_support,
        "bootstrap_95ci": {
            "top1_accuracy": _bootstrap_ci(top1_values, seed=seed + 1),
            "top3_accuracy": _bootstrap_ci(top3_values, seed=seed + 2),
            "mean_reciprocal_rank": _bootstrap_ci(mrr_values, seed=seed + 3),
            "brier_score": _bootstrap_ci(brier_values, seed=seed + 4),
        },
    }


def evaluate_variant(
    train: List[Dict[str, Any]],
    test: List[Dict[str, Any]],
    policy: Dict[str, Any],
    external_model: Dict[str, Any],
) -> Dict[str, Any]:
    prefix_max_length = int(policy.get("prefix_max_length", 3))
    recency_half_life = float(policy.get("recency_decay_half_life_sessions") or 0.0)
    model_train = live_model_training_payloads(train, policy)
    local_model = build_transition_model(
        model_train,
        prefix_max_length=prefix_max_length,
        source_name="local_transition",
        recency_half_life_sessions=recency_half_life,
    )
    actor_policy = policy.get("actor_fingerprint_prior") or {}
    if not isinstance(actor_policy, dict):
        actor_policy = {}
    actor_train = live_model_training_payloads(
        train,
        policy,
        history_limit=int(
            actor_policy.get("history_limit")
            or policy.get("transition_history_limit", 500)
        ),
    )
    actor_model = build_actor_fingerprint_transition_model(
        actor_train,
        policy=policy,
        prefix_max_length=prefix_max_length,
        recency_half_life_sessions=recency_half_life,
    )
    engine = RealtimePredictionEngine(
        policy,
        transition_model=local_model,
        external_transition_model=external_model,
        actor_fingerprint_transition_model=actor_model,
    )
    cases: List[Dict[str, Any]] = []
    for payload in test:
        steps = _tactic_steps(payload)
        for index in range(len(steps) - 1):
            actual = str(steps[index + 1]["tactic"])
            snapshot = engine.predict(
                build_session_features(_prefix_payload(payload, steps, index)),
                event_id=f"chronological:{payload.get('session_id', 'unknown')}:{index}",
            )
            predicted = list(snapshot.get("prediction") or [])
            ranking = list(snapshot.get("final_ranking") or [])
            rank = _rank(predicted, actual)
            primary = snapshot.get("primary_transition") or {}
            evidence_count = float(primary.get("evidence_count") or 0.0)
            if primary.get("fallback_used"):
                support_level = "fallback_no_transition_support"
            elif evidence_count >= 5:
                support_level = "transition_support_5_plus"
            elif evidence_count >= 2:
                support_level = "transition_support_2_to_4"
            elif evidence_count > 0:
                support_level = "transition_support_1"
            else:
                support_level = "no_supported_prediction"
            cases.append(
                {
                    "session_id": str(payload.get("session_id") or "unknown"),
                    "actual": actual,
                    "predicted": predicted,
                    "rank": rank,
                    "top_score": float(ranking[0].get("score") or 0.0) if ranking else 0.0,
                    "brier_score": _brier_score(ranking, actual),
                    "primary_mode": snapshot.get("prediction_mode") == "primary_transition_with_fallback",
                    "selected_source": primary.get("selected_source") or "",
                    "fallback_used": bool(primary.get("fallback_used")),
                    "evidence_count": evidence_count,
                    "support_level": support_level,
                }
            )
    return {"metrics": _summarize_cases(cases), "model_provenance": local_model, "cases": cases}


def _majority_baseline(train: List[Dict[str, Any]], test: List[Dict[str, Any]]) -> Dict[str, Any]:
    counts: Counter = Counter()
    for payload in train:
        steps = _tactic_steps(payload)
        counts.update(step["tactic"] for step in steps[1:])
    total_count = sum(counts.values())
    ranking = [
        {"tactic": tactic, "score": count / total_count}
        for tactic, count in counts.most_common()
    ] if total_count else []
    predicted = [item["tactic"] for item in ranking]
    cases = []
    for payload in test:
        steps = _tactic_steps(payload)
        for index in range(len(steps) - 1):
            actual = str(steps[index + 1]["tactic"])
            cases.append(
                {
                    "session_id": str(payload.get("session_id") or "unknown"),
                    "actual": actual,
                    "predicted": predicted,
                    "rank": _rank(predicted, actual),
                    "top_score": float(ranking[0]["score"]) if ranking else 0.0,
                    "brier_score": _brier_score(ranking, actual),
                    "primary_mode": False,
                    "support_level": "global_majority",
                }
            )
    return {"metrics": _summarize_cases(cases), "training_next_tactic_counts": dict(counts)}


def _last_tactic_majority_baseline(
    train: List[Dict[str, Any]],
    test: List[Dict[str, Any]],
) -> Dict[str, Any]:
    counts: Dict[str, Counter] = {}
    for payload in train:
        steps = _tactic_steps(payload)
        for index in range(len(steps) - 1):
            current = str(steps[index]["tactic"])
            actual = str(steps[index + 1]["tactic"])
            counts.setdefault(current, Counter())[actual] += 1
    cases = []
    for payload in test:
        steps = _tactic_steps(payload)
        for index in range(len(steps) - 1):
            current = str(steps[index]["tactic"])
            actual = str(steps[index + 1]["tactic"])
            current_counts = counts.get(current, Counter())
            total_count = sum(current_counts.values())
            ranking = [
                {"tactic": tactic, "score": count / total_count}
                for tactic, count in current_counts.most_common()
            ] if total_count else []
            predicted = [item["tactic"] for item in ranking]
            cases.append({
                "session_id": str(payload.get("session_id") or "unknown"),
                "actual": actual,
                "predicted": predicted,
                "rank": _rank(predicted, actual),
                "top_score": float(ranking[0]["score"]) if ranking else 0.0,
                "brier_score": _brier_score(ranking, actual),
                "primary_mode": False,
                "support_level": "last_tactic_seen_in_train" if total_count else "last_tactic_unseen_in_train",
            })
    return {
        "metrics": _summarize_cases(cases),
        "training_transition_counts": {
            current: dict(next_counts) for current, next_counts in sorted(counts.items())
        },
    }


def evaluate(
    payloads: Iterable[Dict[str, Any]],
    policy: Dict[str, Any],
    external_model: Dict[str, Any],
    *,
    min_evaluation_examples: int = 30,
) -> Dict[str, Any]:
    split = chronological_split(payloads)
    train, calibration, test = split["train"], split["calibration"], split["test"]
    variants = {
        # This tool evaluates the historical local-first cascade as a fixed
        # offline baseline.  It must not silently inherit the active
        # external-only production mode when comparing that legacy design.
        "current_primary_transition_with_fallback": _policy_variant(
            policy,
            mode="primary_transition_with_fallback",
            source_order=["local_transition", "external_seed_transition"],
            fallback_scorer="fallback_progression",
        ),
        "local_transition_only": _policy_variant(
            policy, source_order=["local_transition"], fallback_scorer="__no_fallback__"
        ),
        "external_transition_only": _policy_variant(
            policy, source_order=["external_seed_transition"], fallback_scorer="__no_fallback__"
        ),
        "fallback_progression_only": _policy_variant(
            policy, source_order=["__no_transition__"], fallback_scorer="fallback_progression"
        ),
        "weighted_ensemble_baseline": _policy_variant(policy, mode="weighted_ensemble_baseline"),
    }
    results = {
        name: evaluate_variant(train, test, variant, external_model)
        for name, variant in variants.items()
    }
    results["global_majority_baseline"] = _majority_baseline(train, test)
    results["last_tactic_majority_baseline"] = _last_tactic_majority_baseline(train, test)
    evaluated_examples = int(
        results["current_primary_transition_with_fallback"]["metrics"].get("evaluated_examples") or 0
    )
    required_examples = max(int(min_evaluation_examples), 1)
    sufficient = evaluated_examples >= required_examples
    return {
        "schema_version": "primary_transition_chronological_evaluation.v1",
        "generated_at": utc_now(),
        "architecture": "primary_transition_with_fallback",
        "split_method": "chronological_70_15_15_by_eligible_session",
        "split_sizes": {key: len(value) for key, value in split.items()},
        "calibration_usage": "reserved_not_used_for_parameter_fitting_in_this_run",
        "label_origin": "trusted classifier-derived Cowrie tactic labels; not independent human ground truth",
        "session_filter": "production_live AND is_external_source=true by default in load_session_payloads",
        "data_sufficiency": {
            "status": "descriptive_evaluation" if sufficient else "insufficient_data",
            "evaluated_examples": evaluated_examples,
            "minimum_examples_for_comparative_reporting": required_examples,
            "metrics_are_descriptive_only": not sufficient,
            "reason": (
                "The held-out test set meets the project reporting threshold; uncertainty intervals still apply."
                if sufficient else
                "Too few held-out next-tactic examples for a defensible comparative performance claim."
            ),
        },
        "production_policy_changed": False,
        "results": results,
    }


def render_markdown(result: Dict[str, Any]) -> str:
    """Render the scoped comparison without upgrading descriptive metrics to claims."""

    sufficiency = result["data_sufficiency"]
    lines = [
        "# Scoped Primary-Transition Evaluation (2026-07-13)",
        "",
        "## Interpretation boundary",
        "",
        "This is a chronological, offline comparison of the current "
        "`primary_transition_with_fallback` design and fixed baselines. It uses only "
        "trusted classifier-derived Cowrie tactic labels; those labels are not "
        "independent human ground truth. Production policy and scorer weights were not changed.",
        "",
    ]
    if sufficiency["status"] == "insufficient_data":
        lines.extend([
            "**Prediction evaluation is limited by insufficient clean held-out transition data.**",
            "",
        ])
    lines.extend([
        "## Data",
        "",
        "| Item | Value |",
        "|---|---:|",
        f"| Eligible train sessions | {result['split_sizes']['train']} |",
        f"| Eligible calibration sessions | {result['split_sizes']['calibration']} |",
        f"| Eligible held-out test sessions | {result['split_sizes']['test']} |",
        f"| Held-out transition examples | {sufficiency['evaluated_examples']} |",
        f"| Minimum comparative-reporting threshold | {sufficiency['minimum_examples_for_comparative_reporting']} |",
        "",
        "Repeated adjacent tactics are deduplicated before model construction and evaluation. "
        "Audit-only classification events are excluded by the shared trust predicate.",
        "",
        "## Results",
        "",
        "| Variant | Top-1 | Top-3 | MRR | Brier | Coverage | Fallback rate | Abstention rate | Examples |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ])
    for name, document in result["results"].items():
        metrics = document["metrics"]
        fallback = metrics.get("fallback_use_rate")
        fallback_text = "n/a" if fallback is None else f"{float(fallback):.4f}"
        lines.append(
            f"| `{name}` | {float(metrics['top1_accuracy']):.4f} | "
            f"{float(metrics['top3_accuracy']):.4f} | "
            f"{float(metrics['mean_reciprocal_rank']):.4f} | "
            f"{float(metrics['brier_score']):.4f} | "
            f"{float(metrics['coverage']):.4f} | {fallback_text} | "
            f"{float(metrics['abstention_rate']):.4f} | {metrics['evaluated_examples']} |"
        )
    lines.extend([
        "",
        "## Support-level detail for the current design",
        "",
        "| Support level | Examples | Coverage | Top-1 | Top-3 |",
        "|---|---:|---:|---:|---:|",
    ])
    current = result["results"]["current_primary_transition_with_fallback"]["metrics"]
    for level, metrics in current.get("performance_by_support_level", {}).items():
        lines.append(
            f"| `{level}` | {metrics['evaluated_examples']} | {float(metrics['coverage']):.4f} | "
            f"{float(metrics['top1_accuracy']):.4f} | {float(metrics['top3_accuracy']):.4f} |"
        )
    lines.extend([
        "",
        "## Limitation",
        "",
        sufficiency["reason"],
        "The values above are descriptive diagnostics, not a defensible estimate of "
        "deployment accuracy, whenever `metrics_are_descriptive_only` is true.",
        "",
    ])
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config")
    parser.add_argument("--database-url")
    parser.add_argument("--payload-json", help="Offline JSON list of projected session payloads")
    parser.add_argument("--external-model", help="Explicit external transition-model JSON")
    parser.add_argument("--limit", type=int, default=5000)
    parser.add_argument("--min-evaluation-examples", type=int, default=30)
    parser.add_argument("--output", required=True)
    parser.add_argument("--markdown-output")
    args = parser.parse_args()
    config = ProductionConfig.from_env(args.config)
    if args.database_url:
        config.database_url = args.database_url
    if args.payload_json:
        payloads = json.loads(Path(args.payload_json).read_text(encoding="utf-8"))
        if not isinstance(payloads, list):
            raise ValueError("--payload-json must contain a JSON list")
    else:
        payloads = load_session_payloads(config, limit=max(args.limit, 1))
    external_model = (
        json.loads(Path(args.external_model).read_text(encoding="utf-8"))
        if args.external_model
        else load_external_transition_model(config.prediction_policy)
    )
    output = evaluate(
        payloads,
        config.prediction_policy,
        external_model,
        min_evaluation_examples=max(int(args.min_evaluation_examples), 1),
    )
    output["input_provenance"] = {
        "payload_source": str(args.payload_json or "configured_production_database"),
        "external_model_source": str(args.external_model or "configured_prediction_policy"),
        "input_payload_count": len(payloads),
    }
    path = Path(args.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.markdown_output:
        markdown_path = Path(args.markdown_output)
        markdown_path.parent.mkdir(parents=True, exist_ok=True)
        markdown_path.write_text(render_markdown(output), encoding="utf-8")
    print(json.dumps({
        "split_sizes": output["split_sizes"],
        "data_sufficiency": output["data_sufficiency"],
        "results": {k: v["metrics"] for k, v in output["results"].items()},
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
