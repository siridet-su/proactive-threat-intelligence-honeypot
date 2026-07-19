"""Offline backtesting for real-time prediction snapshots.

The backtester replays completed session tactic prefixes and asks the current
prediction engine to rank the next tactic. It does not call external services
and does not mutate the database.
"""

from __future__ import annotations

import argparse
import json
import math
import random
from collections import defaultdict
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

from production.classification.trust import is_trusted_classification_event
from production.utils.config import ProductionConfig
from production.utils.feedback import EVIDENCE_ORIGINS, LIVE_COWRIE, infer_evidence_origin
from production.prediction.realtime_prediction import (
    RealtimePredictionEngine,
    build_actor_fingerprint_transition_model,
    build_transition_model,
    tactic_sequence_from_payload,
)
from production.prediction.weight_fitting import fit_weights_from_cases
from production.utils.serialization import stable_id, utc_now
from production.prediction.session_features import build_session_features
from production.correlation.session_ttp_knowledge import main_ttp_id
from production.storage import open_storage
from production.storage.session_provenance import (
    SESSION_SOURCE_PRODUCTION_LIVE,
    normalize_session_source,
)


EXTERNAL_SEED_SHRINKAGE_K_GRID = [10, 20, 50, 100, 200, 500, 1000, 2000]
EXTERNAL_SEED_SHRINKAGE_COUNT_SOURCES = ["transitions", "sessions"]
EXTERNAL_SEED_SHRINKAGE_MIN_HELDOUT_SESSIONS = 30
EXTERNAL_SEED_SHRINKAGE_MIN_BRIER_DELTA = 0.001
SWEEP_ROW_METRIC_FIELDS = {
    "brier_score",
    "top_k_accuracy",
    "top1_accuracy",
    "delta_brier_vs_default_k",
    "delta_brier_vs_legacy_maturity",
}
SWEEP_BASELINE_METRIC_FIELDS = {
    "coverage",
    "top1_accuracy",
    "top3_accuracy",
    "mean_reciprocal_rank",
    "brier_score",
    "scorer_disagreement_rate",
}
SWEEP_BOOTSTRAP_METRIC_FIELDS = {"mean", "std", "ci95"}
METRIC_TACTIC_VOCABULARY = (
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
)


def _decode_payload(row: Dict[str, Any]) -> Dict[str, Any]:
    raw = row.get("payload_json")
    if isinstance(raw, dict):
        return dict(raw)
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def load_external_transition_model(policy: Dict[str, Any] | None) -> Dict[str, Any]:
    """Load the external seed model so backtests match live prediction behavior."""
    path_text = str((policy or {}).get("external_transition_model_path") or "").strip()
    if not path_text:
        return build_transition_model([])
    path = Path(path_text)
    if not path.exists():
        return build_transition_model([])
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return build_transition_model([])
    if isinstance(loaded, dict) and isinstance(loaded.get("model"), dict):
        return loaded["model"]
    if isinstance(loaded, dict):
        return loaded
    return build_transition_model([])


def load_session_payloads(
    config: ProductionConfig,
    limit: int = 1000,
    session_source: str | None = SESSION_SOURCE_PRODUCTION_LIVE,
    external_only: bool = True,
) -> List[Dict[str, Any]]:
    storage = open_storage(config.database_url)
    payloads: List[Dict[str, Any]] = []
    if hasattr(storage, "list_session_rows"):
        rows = storage.list_session_rows(limit=limit, session_source=session_source, external_only=external_only)
    else:
        rows = storage.list_rows("sessions", limit=limit)
    for row in rows:
        payload = _decode_payload(row)
        if payload:
            payload.setdefault("session_source", row.get("session_source") or session_source)
            payload.setdefault("is_external_source", bool(row.get("is_external_source")))
            payloads.append(payload)
    return payloads


def _completed(payload: Dict[str, Any]) -> bool:
    return bool(payload.get("is_ended")) or str(payload.get("status") or "") == "closed"


def _evidence_origin(payload: Dict[str, Any]) -> str:
    try:
        return infer_evidence_origin(payload)
    except ValueError:
        return LIVE_COWRIE


def _known_tactic(tactic: Any) -> str:
    text = str(tactic or "").strip()
    return text if text and text != "unknown" else ""


def _tactic_steps(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    steps: List[Dict[str, Any]] = []
    classification_events = payload.get("classification_events") or []
    for index, event in enumerate(classification_events):
        if not isinstance(event, dict) or not is_trusted_classification_event(event):
            continue
        tactic = _known_tactic(event.get("tactic"))
        if not tactic:
            continue
        if steps and steps[-1]["tactic"] == tactic:
            continue
        steps.append({"tactic": tactic, "event_index": index, "event": event})

    if steps:
        return steps

    for index, tactic in enumerate(tactic_sequence_from_payload(payload)):
        steps.append(
            {
                "tactic": tactic,
                "event_index": index,
                "event": {"tactic": tactic, "command": "", "source": "stored_tactics"},
            }
        )
    return steps


def _prefix_payload(payload: Dict[str, Any], steps: List[Dict[str, Any]], step_index: int) -> Dict[str, Any]:
    prefix = deepcopy(payload)
    prefix["is_ended"] = False
    prefix["status"] = "active"

    event_index = int(steps[step_index]["event_index"])
    classification_events = payload.get("classification_events") or []
    if classification_events:
        prefix_events = [
            dict(event)
            for event in classification_events[: event_index + 1]
            if isinstance(event, dict)
        ]
    else:
        prefix_events = [dict(step["event"]) for step in steps[: step_index + 1]]

    prefix["classification_events"] = prefix_events
    commands = [
        str(event.get("command") or "").strip()
        for event in prefix_events
        if str(event.get("command") or "").strip()
    ]
    # A stored closed-session payload contains final derived state. Only retain
    # fields that can be reconstructed at this prefix; otherwise later events,
    # correlations, enrichment, or IOCs can leak into an earlier prediction.
    prefix["commands"] = commands
    prefix["raw_events"] = []
    prefix["session_ttp_correlations"] = []
    prefix["session_ttp_correlation_summary"] = {}
    prefix["session_evidence_graph"] = {}
    prefix["session_evidence_graph_summary"] = {}
    prefix["sigma_hits"] = []
    prefix["kev_matches"] = []
    prefix["ioc_summary"] = {}
    prefix["enrichment_status"] = {}
    prefix["duration"] = None
    prefix["session_outcome"] = ""
    prefix["login_success"] = False
    prefix["login_attempts"] = 0
    for field in (
        "asn",
        "geo",
        "country",
        "isp",
        "risk_score",
        "vt_hit",
        "vt_detection_ratio",
        "vt_malware_family",
        "is_tor_exit",
        "is_vpn",
        "host_type",
        "infrastructure_tags",
        "otx_tags",
        "abuse_tags",
        "abuseipdb_categories",
        "shodan_tags",
        "censys_labels",
        "open_ports",
        "running_services",
        "provider_status",
        "total_reports",
        "raw_otx_pulse",
        "shodan_hostnames",
        "shodan_cpes",
        "shodan_vulns",
        "censys_api",
        "shodan_api",
    ):
        prefix.pop(field, None)

    tactics: List[str] = []
    ttps: List[str] = []
    for event in prefix_events:
        tactic = _known_tactic(event.get("tactic"))
        ttp = main_ttp_id(event.get("ttp"))
        if tactic and tactic not in tactics:
            tactics.append(tactic)
        if ttp and ttp != "unknown" and ttp not in ttps:
            ttps.append(ttp)
    prefix["tactics"] = tactics
    prefix["ttps"] = ttps
    return prefix


def _rank(predictions: List[str], actual: str) -> int:
    for index, tactic in enumerate(predictions, start=1):
        if tactic == actual:
            return index
    return 0


def _stats_bucket() -> Dict[str, float]:
    return {
        "cases": 0,
        "predicted": 0,
        "top1": 0,
        "top3": 0,
        "reciprocal_sum": 0.0,
        "brier_sum": 0.0,
    }


def _stats_summary(bucket: Dict[str, float]) -> Dict[str, Any]:
    cases = int(bucket.get("cases") or 0)
    predicted = int(bucket.get("predicted") or 0)
    return {
        "cases": cases,
        "predicted": predicted,
        "coverage": round(predicted / cases, 4) if cases else 0.0,
        "top1_accuracy": round(float(bucket.get("top1") or 0.0) / cases, 4) if cases else 0.0,
        "top3_accuracy": round(float(bucket.get("top3") or 0.0) / cases, 4) if cases else 0.0,
        "mean_reciprocal_rank": round(float(bucket.get("reciprocal_sum") or 0.0) / cases, 4) if cases else 0.0,
        "brier_score": round(float(bucket.get("brier_sum") or 0.0) / cases, 4) if cases else 0.0,
    }


def _top_source_names(final_ranking: List[Dict[str, Any]]) -> List[str]:
    if not final_ranking:
        return ["none"]
    sources = final_ranking[0].get("sources") or []
    names = [
        str(source.get("name") or "unknown")
        for source in sources
        if isinstance(source, dict)
    ]
    return names or ["unknown"]


def _ranking_probabilities(final_ranking: List[Dict[str, Any]]) -> Dict[str, float]:
    """Normalize returned tactic scores for calibration-sensitive metrics."""

    scores: Dict[str, float] = {}
    for item in final_ranking:
        if not isinstance(item, dict):
            continue
        tactic = str(item.get("tactic") or "").strip()
        score = max(float(item.get("calibrated_score", item.get("score")) or 0.0), 0.0)
        if tactic and score > 0.0:
            scores[tactic] = scores.get(tactic, 0.0) + score
    total = sum(scores.values())
    if total <= 0.0:
        return {}
    return {tactic: score / total for tactic, score in scores.items()}


def _brier_score(
    final_ranking: List[Dict[str, Any]],
    actual: str,
    vocabulary: Iterable[str] | None = None,
) -> float:
    probabilities = _ranking_probabilities(final_ranking)
    labels = {
        str(label)
        for label in (vocabulary or METRIC_TACTIC_VOCABULARY)
        if str(label)
    }
    labels.update(probabilities)
    labels.add(actual)
    return sum(
        (float(probabilities.get(label, 0.0)) - (1.0 if label == actual else 0.0)) ** 2
        for label in labels
    )


def _scorer_case_analysis(snapshot: Dict[str, Any], actual: str) -> Dict[str, Any]:
    scorer_outputs = snapshot.get("scorer_outputs") or {}
    if not isinstance(scorer_outputs, dict):
        scorer_outputs = {}
    analysis: Dict[str, Any] = {}
    for scorer, outputs_raw in scorer_outputs.items():
        outputs = [item for item in outputs_raw or [] if isinstance(item, dict)]
        ranked = sorted(outputs, key=lambda item: float(item.get("score") or 0.0), reverse=True)
        top = ranked[0] if ranked else {}
        top3 = [
            str(item.get("tactic") or "")
            for item in ranked[:3]
            if str(item.get("tactic") or "")
        ]
        analysis[str(scorer)] = {
            "has_output": bool(ranked),
            "top_tactic": str(top.get("tactic") or ""),
            "top_score": round(float(top.get("score") or 0.0), 4) if top else 0.0,
            "top_source_type": str(top.get("source_type") or ""),
            "top_rule_id": str(top.get("rule_id") or ""),
            "top3_tactics": top3,
            "top1_correct": bool(top and top.get("tactic") == actual),
            "top3_contains_actual": actual in top3,
        }
    return analysis


def _final_contributors(final_ranking: List[Dict[str, Any]], actual: str) -> List[Dict[str, Any]]:
    if not final_ranking:
        return []
    top = final_ranking[0]
    top_tactic = str(top.get("tactic") or "")
    contributors = []
    for source in top.get("sources") or []:
        if not isinstance(source, dict):
            continue
        contributors.append(
            {
                "name": str(source.get("name") or ""),
                "source_type": str(source.get("source_type") or ""),
                "weighted_score": round(float(source.get("weighted_score") or 0.0), 4),
                "raw_score": round(float(source.get("raw_score") or 0.0), 4),
                "damped_by_classification_confidence": bool(source.get("damped_by_classification_confidence")),
                "contributed_to_correct_top1": top_tactic == actual,
                "contributed_to_wrong_top1": bool(top_tactic and top_tactic != actual),
            }
        )
    return contributors


def _empty_scorer_bucket() -> Dict[str, float]:
    return {
        "cases": 0,
        "outputs": 0,
        "top1": 0,
        "top3": 0,
        "final_contributor_cases": 0,
        "final_correct_contributor_cases": 0,
        "final_wrong_contributor_cases": 0,
        "weighted_score_sum": 0.0,
    }


def _scorer_summary(bucket: Dict[str, float]) -> Dict[str, Any]:
    cases = int(bucket.get("cases") or 0)
    outputs = int(bucket.get("outputs") or 0)
    return {
        "cases": cases,
        "outputs": outputs,
        "output_rate": round(outputs / cases, 4) if cases else 0.0,
        "top1_accuracy": round(float(bucket.get("top1") or 0.0) / outputs, 4) if outputs else 0.0,
        "top3_usefulness": round(float(bucket.get("top3") or 0.0) / outputs, 4) if outputs else 0.0,
        "final_contributor_cases": int(bucket.get("final_contributor_cases") or 0),
        "final_correct_contributor_cases": int(bucket.get("final_correct_contributor_cases") or 0),
        "final_wrong_contributor_cases": int(bucket.get("final_wrong_contributor_cases") or 0),
        "average_final_weighted_contribution": round(
            float(bucket.get("weighted_score_sum") or 0.0) / float(bucket.get("final_contributor_cases") or 1),
            4,
        ) if bucket.get("final_contributor_cases") else 0.0,
    }


def _weight_proposal(
    current_weights: Dict[str, Any],
    scorer_buckets: Dict[str, Dict[str, float]],
    min_cases: int = 10,
) -> Dict[str, Any]:
    configured = {
        str(name): max(float(weight or 0.0), 0.0)
        for name, weight in (current_weights or {}).items()
    }
    excluded_scorers: Dict[str, str] = {}
    current: Dict[str, float] = {}
    for scorer, weight in sorted(configured.items()):
        if scorer == "vulnerability_risk":
            excluded_scorers[scorer] = "risk annotator; excluded from ranking weight proposal"
            continue
        if weight <= 0.0:
            excluded_scorers[scorer] = "zero configured ranking weight; not in active voter set"
            continue
        current[scorer] = weight
    for scorer in sorted(str(name) for name in scorer_buckets if str(name)):
        if scorer in current or scorer in excluded_scorers:
            continue
        if scorer == "vulnerability_risk":
            excluded_scorers[scorer] = "risk annotator; excluded from ranking weight proposal"
        elif scorer not in configured:
            excluded_scorers[scorer] = "not present in configured ranking weights"

    if not current:
        return {
            "status": "insufficient_data",
            "apply_automatically": False,
            "min_cases_per_scorer": min_cases,
            "current_weights": current,
            "proposed_weights_bounded": {},
            "excluded_scorers": excluded_scorers,
            "reason": "No active configured ranking scorers are eligible for the legacy proposal.",
            "scorer_reasons": {},
        }

    raw_scores: Dict[str, float] = {}
    reasons: Dict[str, List[str]] = {}
    for scorer, current_weight in current.items():
        bucket = scorer_buckets.get(scorer) or _empty_scorer_bucket()
        summary = _scorer_summary(bucket)
        outputs = int(summary["outputs"])
        reasons[scorer] = []
        if outputs < min_cases:
            raw_scores[scorer] = current_weight
            reasons[scorer].append(f"kept current weight; only {outputs} output cases (<{min_cases})")
            continue
        quality = (0.65 * float(summary["top3_usefulness"])) + (0.35 * float(summary["top1_accuracy"]))
        if summary["final_wrong_contributor_cases"] > summary["final_correct_contributor_cases"]:
            quality *= 0.85
            reasons[scorer].append("downweighted quality because scorer contributed to more wrong than correct top predictions")
        raw_scores[scorer] = max(quality, 0.01)
        reasons[scorer].append(
            f"quality={quality:.4f} from top1={summary['top1_accuracy']:.4f}, top3={summary['top3_usefulness']:.4f}, outputs={outputs}"
        )

    total = sum(raw_scores.values())
    proposed = {
        scorer: round(score / total, 4)
        for scorer, score in raw_scores.items()
    } if total > 0 else dict(current)
    bounded: Dict[str, float] = {}
    for scorer, weight in proposed.items():
        old = current.get(scorer, 0.0)
        max_step = 0.05
        if old <= 0:
            bounded[scorer] = round(min(weight, max_step), 4)
        else:
            bounded[scorer] = round(min(max(weight, old - max_step), old + max_step), 4)
    bounded_total = sum(bounded.values())
    normalized = {
        scorer: round(weight / bounded_total, 4)
        for scorer, weight in bounded.items()
    } if bounded_total > 0 else bounded
    return {
        "status": "proposal_only",
        "apply_automatically": False,
        "min_cases_per_scorer": min_cases,
        "current_weights": current,
        "proposed_weights_bounded": normalized,
        "excluded_scorers": excluded_scorers,
        "reason": "Backtest-derived proposal only; requires manual review before trusted policy update.",
        "scorer_reasons": reasons,
    }


def _ranking_weight_policy(policy: Dict[str, Any] | None) -> Dict[str, float]:
    weights = (policy or {}).get("weights") or {}
    if not isinstance(weights, dict):
        return {}
    return {
        str(name): max(float(weight or 0.0), 0.0)
        for name, weight in weights.items()
        if str(name) != "vulnerability_risk"
    }


def _policy_with_weights(policy: Dict[str, Any] | None, weights: Dict[str, float]) -> Dict[str, Any]:
    updated = deepcopy(policy or {})
    updated["weights"] = dict(weights)
    return updated


def _policy_with_primary_sources(
    policy: Dict[str, Any] | None,
    source_order: List[str],
    fallback_scorer: str,
) -> Dict[str, Any]:
    updated = deepcopy(policy or {})
    updated["prediction_mode"] = "primary_transition_with_fallback"
    primary = dict(updated.get("primary_transition") or {})
    primary["source_order"] = list(source_order)
    primary["fallback_scorer"] = str(fallback_scorer)
    updated["primary_transition"] = primary
    return updated


def _policy_with_prediction_mode(policy: Dict[str, Any] | None, mode: str) -> Dict[str, Any]:
    updated = deepcopy(policy or {})
    updated["prediction_mode"] = str(mode)
    return updated


def _policy_with_enrichment_mode(policy: Dict[str, Any] | None, mode: str) -> Dict[str, Any]:
    updated = deepcopy(policy or {})
    updated["enrichment_context_mode"] = mode
    return updated


def _policy_with_external_seed_decay_method(policy: Dict[str, Any] | None, method: str) -> Dict[str, Any]:
    updated = deepcopy(policy or {})
    decay = dict(updated.get("external_seed_weight_decay") or {})
    decay["enabled"] = True
    decay["method"] = method
    decay.setdefault("shrinkage_count_source", "transitions")
    decay.setdefault("shrinkage_k", 200.0)
    decay.setdefault("min_multiplier", 0.0)
    decay.setdefault("max_multiplier", 1.0)
    updated["external_seed_weight_decay"] = decay
    return updated


def _policy_with_external_seed_shrinkage(
    policy: Dict[str, Any] | None,
    shrinkage_k: float,
    count_source: str,
) -> Dict[str, Any]:
    updated = _policy_with_external_seed_decay_method(policy, "empirical_shrinkage")
    decay = dict(updated.get("external_seed_weight_decay") or {})
    decay["shrinkage_k"] = float(shrinkage_k)
    source = str(count_source or "transitions").strip().lower()
    decay["shrinkage_count_source"] = source if source in {"transitions", "sessions"} else "transitions"
    updated["external_seed_weight_decay"] = decay
    return updated


def _policy_with_actor_fingerprint_prior(policy: Dict[str, Any] | None, enabled: bool) -> Dict[str, Any]:
    updated = deepcopy(policy or {})
    actor_policy = dict(updated.get("actor_fingerprint_prior") or {})
    actor_policy["enabled"] = bool(enabled)
    actor_policy.setdefault("min_sessions", 2)
    actor_policy.setdefault("min_transition_count", 1)
    actor_policy.setdefault("min_prefix_transition_count", 1)
    actor_policy.setdefault("min_tactic_transition_count", 1)
    actor_policy.setdefault("comparison_weight", 0.15)
    updated["actor_fingerprint_prior"] = actor_policy
    weights = dict(updated.get("weights") or {})
    if enabled:
        configured = float(weights.get("actor_fingerprint_transition") or 0.0)
        weights["actor_fingerprint_transition"] = configured if configured > 0 else float(actor_policy.get("comparison_weight") or 0.15)
    else:
        weights["actor_fingerprint_transition"] = 0.0
    updated["weights"] = weights
    return updated


def _metric_delta(primary: Dict[str, Any], comparison: Dict[str, Any]) -> Dict[str, float]:
    fields = [
        "coverage",
        "top1_accuracy",
        "top3_accuracy",
        "mean_reciprocal_rank",
        "brier_score",
        "scorer_disagreement_rate",
    ]
    return {
        field: round(float(comparison.get(field) or 0.0) - float(primary.get(field) or 0.0), 4)
        for field in fields
        if field in primary or field in comparison
    }


def _comparison_payload(
    result: Dict[str, Any],
    primary_metrics: Dict[str, Any],
    label: str,
    disabled_scorer: str = "",
) -> Dict[str, Any]:
    metrics = result.get("metrics") or {}
    payload = {
        "label": label,
        "metrics": metrics,
        "delta_vs_primary": _metric_delta(primary_metrics, metrics),
    }
    if disabled_scorer:
        payload["disabled_scorer"] = disabled_scorer
    return payload


def _percentile(values: List[float], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * min(max(percentile, 0.0), 1.0)
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[int(position)]
    weight = position - lower
    return (ordered[lower] * (1.0 - weight)) + (ordered[upper] * weight)


def _bootstrap_brier_by_session(
    cases: List[Dict[str, Any]],
    iterations: int,
    random_seed: int,
) -> Dict[str, Any]:
    by_session: Dict[str, List[float]] = defaultdict(list)
    for case in cases:
        session_id = str(case.get("session_id") or "").strip()
        if not session_id:
            continue
        by_session[session_id].append(float(case.get("brier_score") or 0.0))
    session_ids = sorted(by_session)
    if not session_ids or iterations <= 0:
        return {
            "resampling_unit": "held_out_session",
            "iterations": 0,
            "session_count": len(session_ids),
            "case_count": sum(len(values) for values in by_session.values()),
            "mean": 0.0,
            "std": 0.0,
            "ci95": [0.0, 0.0],
        }

    rng = random.Random(random_seed)
    samples: List[float] = []
    for _ in range(iterations):
        values: List[float] = []
        for _index in range(len(session_ids)):
            sampled_session = rng.choice(session_ids)
            values.extend(by_session[sampled_session])
        if values:
            samples.append(sum(values) / len(values))

    if not samples:
        std = 0.0
        mean = 0.0
    else:
        mean = sum(samples) / len(samples)
        std = (
            math.sqrt(sum((value - mean) ** 2 for value in samples) / (len(samples) - 1))
            if len(samples) > 1
            else 0.0
        )
    return {
        "resampling_unit": "held_out_session",
        "iterations": len(samples),
        "session_count": len(session_ids),
        "case_count": sum(len(values) for values in by_session.values()),
        "mean": round(mean, 6),
        "std": round(std, 6),
        "ci95": [
            round(_percentile(samples, 0.025), 6),
            round(_percentile(samples, 0.975), 6),
        ] if samples else [0.0, 0.0],
    }


def _backtest_for_shrinkage_fit(
    session_payloads: List[Dict[str, Any]],
    policy: Dict[str, Any] | None,
    leave_one_out: bool,
) -> Dict[str, Any]:
    return backtest_sessions(
        session_payloads,
        policy=_policy_with_prediction_mode(policy, "weighted_ensemble_baseline"),
        leave_one_out=leave_one_out,
        include_cases=True,
        max_cases=1_000_000,
        include_comparisons=False,
    )


def _null_metric_values_for_insufficient_sweep(
    rows: List[Dict[str, Any]],
    baselines: Dict[str, Any],
    stability: Dict[str, Any],
) -> None:
    for row in rows:
        for field in SWEEP_ROW_METRIC_FIELDS:
            if field in row:
                row[field] = None
        bootstrap = row.get("bootstrap_brier")
        if isinstance(bootstrap, dict):
            for field in SWEEP_BOOTSTRAP_METRIC_FIELDS:
                if field in bootstrap:
                    bootstrap[field] = None

    for baseline in baselines.values():
        if not isinstance(baseline, dict):
            continue
        metrics = baseline.get("metrics")
        if not isinstance(metrics, dict):
            continue
        for field in SWEEP_BASELINE_METRIC_FIELDS:
            if field in metrics:
                metrics[field] = None

    stability["best_vs_runner_up_brier_delta"] = None
    stability["bootstrap_expected_noise"] = None


def _assert_missing_sweep_metrics_are_null(
    rows: List[Dict[str, Any]],
    baselines: Dict[str, Any],
    stability: Dict[str, Any],
) -> None:
    violations: List[str] = []
    for index, row in enumerate(rows):
        for field in SWEEP_ROW_METRIC_FIELDS:
            if isinstance(row.get(field), (int, float)):
                violations.append(f"results[{index}].{field}")
        bootstrap = row.get("bootstrap_brier")
        if isinstance(bootstrap, dict):
            for field in SWEEP_BOOTSTRAP_METRIC_FIELDS:
                if isinstance(bootstrap.get(field), (int, float, list)):
                    violations.append(f"results[{index}].bootstrap_brier.{field}")
    for name, baseline in baselines.items():
        metrics = baseline.get("metrics") if isinstance(baseline, dict) else {}
        if not isinstance(metrics, dict):
            continue
        for field in SWEEP_BASELINE_METRIC_FIELDS:
            if isinstance(metrics.get(field), (int, float)):
                violations.append(f"baselines.{name}.metrics.{field}")
    for field in ("best_vs_runner_up_brier_delta", "bootstrap_expected_noise"):
        if isinstance(stability.get(field), (int, float)):
            violations.append(f"stability.{field}")
    if violations:
        raise RuntimeError(
            "insufficient external seed shrinkage data must emit null metric values; "
            f"numeric values found at {', '.join(violations)}"
        )


def evaluate_external_seed_shrinkage_grid(
    session_payloads: Iterable[Dict[str, Any]],
    policy: Dict[str, Any] | None = None,
    leave_one_out: bool = True,
    k_values: List[int] | None = None,
    count_sources: List[str] | None = None,
    bootstrap_iterations: int = 200,
    min_heldout_sessions: int = EXTERNAL_SEED_SHRINKAGE_MIN_HELDOUT_SESSIONS,
    min_brier_delta: float = EXTERNAL_SEED_SHRINKAGE_MIN_BRIER_DELTA,
    random_seed: int = 20260704,
) -> Dict[str, Any]:
    """Evaluate optional external-seed shrinkage parameters as proposal-only output.

    This reuses `backtest_sessions`, so each grid point uses the same
    leave-one-session-out replay cases, Brier score, and top-3 accuracy as the
    existing comparison pipeline.
    """

    payloads = [payload for payload in session_payloads if isinstance(payload, dict)]
    grid_k = [int(value) for value in (k_values or EXTERNAL_SEED_SHRINKAGE_K_GRID)]
    grid_sources = [
        source
        for source in (str(item or "").strip().lower() for item in (count_sources or EXTERNAL_SEED_SHRINKAGE_COUNT_SOURCES))
        if source in {"transitions", "sessions"}
    ] or list(EXTERNAL_SEED_SHRINKAGE_COUNT_SOURCES)

    decay = (policy or {}).get("external_seed_weight_decay") or {}
    if not isinstance(decay, dict):
        decay = {}
    default_k = float(decay.get("shrinkage_k", 200.0) or 200.0)
    default_source = str(decay.get("shrinkage_count_source") or "transitions").strip().lower()
    if default_source not in {"transitions", "sessions"}:
        default_source = "transitions"

    default_empirical = _backtest_for_shrinkage_fit(
        payloads,
        _policy_with_external_seed_shrinkage(policy, default_k, default_source),
        leave_one_out,
    )
    legacy = _backtest_for_shrinkage_fit(
        payloads,
        _policy_with_external_seed_decay_method(policy, "maturity_multiplier"),
        leave_one_out,
    )
    default_metrics = default_empirical.get("metrics") or {}
    legacy_metrics = legacy.get("metrics") or {}
    default_brier = float(default_metrics.get("brier_score") or 0.0)
    legacy_brier = float(legacy_metrics.get("brier_score") or 0.0)

    rows: List[Dict[str, Any]] = []
    for count_source in grid_sources:
        for shrinkage_k in grid_k:
            candidate_policy = _policy_with_external_seed_shrinkage(policy, shrinkage_k, count_source)
            result = _backtest_for_shrinkage_fit(payloads, candidate_policy, leave_one_out)
            metrics = result.get("metrics") or {}
            brier = float(metrics.get("brier_score") or 0.0)
            row = {
                "k": int(shrinkage_k),
                "count_source": count_source,
                "brier_score": round(brier, 4),
                "top_k": 3,
                "top_k_accuracy": round(float(metrics.get("top3_accuracy") or 0.0), 4),
                "top1_accuracy": round(float(metrics.get("top1_accuracy") or 0.0), 4),
                "total_cases": int(metrics.get("total_cases") or 0),
                "evaluated_sessions": int(result.get("evaluated_sessions") or 0),
                "delta_brier_vs_default_k": round(brier - default_brier, 4),
                "delta_brier_vs_legacy_maturity": round(brier - legacy_brier, 4),
                "bootstrap_brier": _bootstrap_brier_by_session(
                    result.get("cases") or [],
                    iterations=bootstrap_iterations,
                    random_seed=random_seed + (int(shrinkage_k) * 17) + (0 if count_source == "transitions" else 1),
                ),
            }
            rows.append(row)

    comparable_rows = [row for row in rows if int(row.get("total_cases") or 0) > 0]
    sorted_rows = sorted(
        comparable_rows,
        key=lambda row: (
            float(row.get("brier_score") or 0.0),
            -float(row.get("top_k_accuracy") or 0.0),
            str(row.get("count_source") or ""),
            int(row.get("k") or 0),
        ),
    )
    best = sorted_rows[0] if sorted_rows else {}
    runner_up = sorted_rows[1] if len(sorted_rows) > 1 else {}
    heldout_sessions = max([int(row.get("evaluated_sessions") or 0) for row in rows] or [0])
    heldout_cases = max([int(row.get("total_cases") or 0) for row in rows] or [0])

    nearby: List[Dict[str, Any]] = []
    if best:
        same_source = sorted(
            [row for row in rows if row.get("count_source") == best.get("count_source")],
            key=lambda row: int(row.get("k") or 0),
        )
        best_index = next(
            (index for index, row in enumerate(same_source) if int(row.get("k") or 0) == int(best.get("k") or 0)),
            -1,
        )
        for index in [best_index - 1, best_index + 1]:
            if 0 <= index < len(same_source):
                row = same_source[index]
                nearby.append(
                    {
                        "k": row.get("k"),
                        "count_source": row.get("count_source"),
                        "brier_score": row.get("brier_score"),
                        "delta_brier_vs_best": round(float(row.get("brier_score") or 0.0) - float(best.get("brier_score") or 0.0), 4),
                    }
                )

    status = "insufficient_data"
    stability_reason = (
        f"only {heldout_sessions} held-out sessions are available; "
        f"minimum for k selection is {min_heldout_sessions}"
    )
    expected_noise = 0.0
    best_vs_runner_up_delta = 0.0
    if heldout_sessions >= min_heldout_sessions and best and runner_up:
        best_std = float((best.get("bootstrap_brier") or {}).get("std") or 0.0)
        runner_std = float((runner_up.get("bootstrap_brier") or {}).get("std") or 0.0)
        expected_noise = math.sqrt((best_std ** 2) + (runner_std ** 2))
        best_vs_runner_up_delta = round(float(runner_up.get("brier_score") or 0.0) - float(best.get("brier_score") or 0.0), 6)
        required_delta = max(float(min_brier_delta), 1.96 * expected_noise)
        if best_vs_runner_up_delta > required_delta:
            status = "proposal_only"
            stability_reason = (
                "best candidate improves Brier score beyond the configured "
                "minimum delta and bootstrap-estimated noise"
            )
        else:
            status = "no_clear_winner"
            stability_reason = (
                "best candidate's Brier score is not separated from the next "
                "candidate beyond the bootstrap-estimated noise level"
            )
    elif heldout_sessions >= min_heldout_sessions and not comparable_rows:
        stability_reason = "no scored transition cases were produced for the held-out sessions"

    proposal = {
        "status": status,
        "apply_automatically": False,
        "reason": stability_reason,
    }
    if status == "proposal_only" and best:
        proposal["policy_overlay"] = {
            "external_seed_weight_decay": {
                "enabled": True,
                "method": "empirical_shrinkage",
                "shrinkage_count_source": best.get("count_source"),
                "shrinkage_k": best.get("k"),
            },
            "notes": "Proposal only; production keeps legacy maturity_multiplier until explicitly adopted.",
        }

    baselines = {
        "empirical_default_k": {
            "method": "empirical_shrinkage",
            "k": default_k,
            "count_source": default_source,
            "metrics": dict(default_metrics),
        },
        "legacy_maturity_multiplier": {
            "method": "maturity_multiplier",
            "metrics": dict(legacy_metrics),
        },
    }
    stability = {
        "status": status,
        "reason": stability_reason,
        "min_heldout_sessions": int(min_heldout_sessions),
        "min_brier_delta": float(min_brier_delta),
        "best_vs_runner_up_brier_delta": best_vs_runner_up_delta,
        "bootstrap_expected_noise": round(expected_noise, 6),
        "bootstrap_iterations": int(bootstrap_iterations),
    }
    best_candidate = {
        key: best.get(key)
        for key in [
            "k",
            "count_source",
            "brier_score",
            "top_k_accuracy",
            "total_cases",
            "evaluated_sessions",
            "delta_brier_vs_default_k",
            "delta_brier_vs_legacy_maturity",
        ]
    } if best and status != "insufficient_data" else {}
    if status == "insufficient_data":
        nearby = []
        _null_metric_values_for_insufficient_sweep(rows, baselines, stability)
        _assert_missing_sweep_metrics_are_null(rows, baselines, stability)

    return {
        "schema_version": "external_seed_shrinkage_k_sweep.v1",
        "status": status,
        "selection_metric": "brier_score",
        "reported_secondary_metric": "top_k_accuracy",
        "top_k": 3,
        "split": {
            "method": "leave_one_session_out" if leave_one_out else "shared_in_sample_transition_model",
            "completed_sessions": int(default_empirical.get("completed_sessions") or 0),
            "heldout_sessions": heldout_sessions,
            "heldout_cases": heldout_cases,
        },
        "grid": {
            "k_values": grid_k,
            "count_sources": grid_sources,
        },
        "baselines": baselines,
        "results": rows,
        "best_candidate": best_candidate,
        "nearby_candidate_deltas": nearby,
        "stability": stability,
        "proposal": proposal,
    }


def _evaluation_comparisons(
    session_payloads: List[Dict[str, Any]],
    policy: Dict[str, Any] | None,
    leave_one_out: bool,
    primary_metrics: Dict[str, Any],
    ablation_scorers: List[str] | None = None,
) -> Dict[str, Any]:
    current_weights = _ranking_weight_policy(policy)
    if not current_weights:
        current_weights = {"local_transition": 1.0}

    local_only = backtest_sessions(
        session_payloads,
        policy=_policy_with_primary_sources(policy, ["local_transition"], "__no_fallback__"),
        leave_one_out=leave_one_out,
        include_cases=False,
        include_comparisons=False,
    )
    external_only = backtest_sessions(
        session_payloads,
        policy=_policy_with_primary_sources(policy, ["external_seed_transition"], "__no_fallback__"),
        leave_one_out=leave_one_out,
        include_cases=False,
        include_comparisons=False,
    )
    fallback_only = backtest_sessions(
        session_payloads,
        policy=_policy_with_primary_sources(policy, ["__no_transition_source__"], "fallback_progression"),
        leave_one_out=leave_one_out,
        include_cases=False,
        include_comparisons=False,
    )
    weighted_baseline = backtest_sessions(
        session_payloads,
        policy=_policy_with_prediction_mode(policy, "weighted_ensemble_baseline"),
        leave_one_out=leave_one_out,
        include_cases=False,
        include_comparisons=False,
    )

    scorers = ablation_scorers or [
        name
        for name, weight in sorted(current_weights.items())
        if weight > 0.0
    ]
    ablations: Dict[str, Any] = {}
    for scorer in scorers:
        name = str(scorer or "").strip()
        if not name or name not in current_weights:
            continue
        ablated_weights = dict(current_weights)
        ablated_weights[name] = 0.0
        if sum(ablated_weights.values()) <= 0.0:
            ablations[name] = {
                "label": f"disable_{name}",
                "disabled_scorer": name,
                "status": "skipped",
                "reason": "ablation would leave no positive ranking weights",
            }
            continue
        ablation = backtest_sessions(
            session_payloads,
            policy=_policy_with_prediction_mode(
                _policy_with_weights(policy, ablated_weights),
                "weighted_ensemble_baseline",
            ),
            leave_one_out=leave_one_out,
            include_cases=False,
            include_comparisons=False,
        )
        ablations[name] = _comparison_payload(
            ablation,
            primary_metrics,
            label=f"disable_{name}",
            disabled_scorer=name,
        )

    enrichment_modes: Dict[str, Any] = {}
    for mode in ["excluded", "scorer", "score_multiplier"]:
        comparison = backtest_sessions(
            session_payloads,
            policy=_policy_with_prediction_mode(
                _policy_with_enrichment_mode(policy, mode),
                "weighted_ensemble_baseline",
            ),
            leave_one_out=leave_one_out,
            include_cases=False,
            include_comparisons=False,
        )
        enrichment_modes[mode] = _comparison_payload(
            comparison,
            primary_metrics,
            label=f"enrichment_context_{mode}",
        )

    external_seed_decay_methods: Dict[str, Any] = {}
    for method in ["maturity_multiplier", "empirical_shrinkage"]:
        comparison = backtest_sessions(
            session_payloads,
            policy=_policy_with_prediction_mode(
                _policy_with_external_seed_decay_method(policy, method),
                "weighted_ensemble_baseline",
            ),
            leave_one_out=leave_one_out,
            include_cases=False,
            include_comparisons=False,
        )
        external_seed_decay_methods[method] = _comparison_payload(
            comparison,
            primary_metrics,
            label=f"external_seed_decay_{method}",
        )

    external_seed_shrinkage_k_sweep = evaluate_external_seed_shrinkage_grid(
        session_payloads,
        policy=policy,
        leave_one_out=leave_one_out,
    )

    actor_fingerprint_prior: Dict[str, Any] = {}
    for enabled in [False, True]:
        label = "enabled" if enabled else "disabled"
        comparison = backtest_sessions(
            session_payloads,
            policy=_policy_with_prediction_mode(
                _policy_with_actor_fingerprint_prior(policy, enabled),
                "weighted_ensemble_baseline",
            ),
            leave_one_out=leave_one_out,
            include_cases=False,
            include_comparisons=False,
        )
        actor_fingerprint_prior[label] = _comparison_payload(
            comparison,
            primary_metrics,
            label=f"actor_fingerprint_prior_{label}",
        )

    return {
        "schema_version": "prediction_evaluation_comparisons.v1",
        "baseline": {
            "local_transition_only": _comparison_payload(
                local_only,
                primary_metrics,
                label="local_transition_only",
            ),
            "external_transition_only": _comparison_payload(
                external_only,
                primary_metrics,
                label="external_transition_only",
            ),
            "fallback_progression_only": _comparison_payload(
                fallback_only,
                primary_metrics,
                label="fallback_progression_only",
            ),
            "weighted_ensemble_baseline": _comparison_payload(
                weighted_baseline,
                primary_metrics,
                label="weighted_ensemble_baseline",
            ),
        },
        "ablation": ablations,
        "enrichment_context_modes": enrichment_modes,
        "external_seed_decay_methods": external_seed_decay_methods,
        "external_seed_shrinkage_k_sweep": external_seed_shrinkage_k_sweep,
        "actor_fingerprint_prior": actor_fingerprint_prior,
        "notes": (
            "Comparison runs reuse the same replay cases and policy settings, "
            "Architecture baselines compare primary-source selection directly. Scorer "
            "ablations and context/decay/fingerprint comparisons explicitly run the retained "
            "weighted_ensemble_baseline, changing only ranking weights or configured context "
            "handling/backoff/fingerprint-prior modes. They are offline diagnostics and do not "
            "modify the trusted policy."
        ),
    }


def backtest_sessions(
    session_payloads: Iterable[Dict[str, Any]],
    policy: Dict[str, Any] | None = None,
    leave_one_out: bool = True,
    include_cases: bool = False,
    max_cases: int = 50,
    include_comparisons: bool = False,
    ablation_scorers: List[str] | None = None,
    fit_weights: bool = False,
    weight_fit_include_context: bool | None = None,
    weight_fit_loss: str | None = None,
) -> Dict[str, Any]:
    policy = policy or {}
    payloads = [payload for payload in session_payloads if isinstance(payload, dict) and _completed(payload)]
    candidate_sessions = []
    for payload in payloads:
        steps = _tactic_steps(payload)
        if len(steps) >= 2:
            candidate_sessions.append((payload, steps))

    total = 0
    predicted = 0
    top1 = 0
    top3 = 0
    reciprocal_sum = 0.0
    brier_sum = 0.0
    calibration_buckets: Dict[str, Dict[str, float]] = {
        "low": {"cases": 0, "top1": 0, "score_sum": 0.0},
        "medium": {"cases": 0, "top1": 0, "score_sum": 0.0},
        "high": {"cases": 0, "top1": 0, "score_sum": 0.0},
    }
    confidence_label_buckets: Dict[str, Dict[str, float]] = {
        "low": {"cases": 0, "top1": 0, "score_sum": 0.0},
        "medium": {"cases": 0, "top1": 0, "score_sum": 0.0},
        "high": {"cases": 0, "top1": 0, "score_sum": 0.0},
        "unknown": {"cases": 0, "top1": 0, "score_sum": 0.0},
    }
    by_actual_tactic: Dict[str, Dict[str, float]] = defaultdict(_stats_bucket)
    by_evidence_origin: Dict[str, Dict[str, float]] = defaultdict(_stats_bucket)
    disagreement_by_origin: Dict[str, int] = defaultdict(int)
    by_scorer_source: Dict[str, Dict[str, float]] = defaultdict(_stats_bucket)
    by_scorer_level: Dict[str, Dict[str, float]] = defaultdict(_empty_scorer_bucket)
    external_local_disagreements = 0
    external_local_overlap_cases = 0
    local_unavailable_or_cold_cases = 0
    classification_uncertainty_error_cases = 0
    incorrect_tactic_pairs: Dict[str, int] = defaultdict(int)
    disagreement_cases = 0
    primary_mode_cases = 0
    fallback_used_cases = 0
    selected_source_counts: Dict[str, int] = defaultdict(int)
    cases: List[Dict[str, Any]] = []
    weight_fit_cases: List[Dict[str, Any]] = []

    prefix_max_length = int(policy.get("prefix_max_length", 3))
    history_limit = max(int(policy.get("transition_history_limit", 500)), 1)
    recency_half_life = float(policy.get("recency_decay_half_life_sessions") or 0.0)
    model_payloads = payloads[:history_limit]
    shared_model = build_transition_model(
        model_payloads,
        prefix_max_length=prefix_max_length,
        source_name="local_transition",
        recency_half_life_sessions=recency_half_life,
    )
    actor_policy = policy.get("actor_fingerprint_prior") or {}
    if not isinstance(actor_policy, dict):
        actor_policy = {}
    actor_history_limit = max(int(actor_policy.get("history_limit") or history_limit), 1)
    shared_actor_model = build_actor_fingerprint_transition_model(
        payloads[:actor_history_limit],
        policy=policy,
        prefix_max_length=prefix_max_length,
        recency_half_life_sessions=recency_half_life,
    )
    external_transition_model = load_external_transition_model(policy)
    for payload, steps in candidate_sessions:
        session_id = str(payload.get("session_id") or "unknown")
        evidence_origin = _evidence_origin(payload)
        training_payloads = model_payloads
        if leave_one_out:
            training_payloads = [
                item
                for item in payloads
                if str(item.get("session_id") or "unknown") != session_id
            ][:history_limit]
        transition_model = (
            build_transition_model(
                training_payloads,
                prefix_max_length=prefix_max_length,
                source_name="local_transition",
                recency_half_life_sessions=recency_half_life,
            )
            if leave_one_out
            else shared_model
        )
        actor_fingerprint_transition_model = (
            build_actor_fingerprint_transition_model(
                training_payloads[:actor_history_limit],
                policy=policy,
                prefix_max_length=prefix_max_length,
                recency_half_life_sessions=recency_half_life,
            )
            if leave_one_out
            else shared_actor_model
        )
        engine = RealtimePredictionEngine(
            policy,
            transition_model=transition_model,
            external_transition_model=external_transition_model,
            actor_fingerprint_transition_model=actor_fingerprint_transition_model,
        )

        for index in range(len(steps) - 1):
            actual = steps[index + 1]["tactic"]
            prefix = _prefix_payload(payload, steps, index)
            features = build_session_features(prefix)
            snapshot = engine.predict(features, event_id=f"backtest:{session_id}:{index}")
            ranking = snapshot.get("prediction") or []
            final_ranking = snapshot.get("final_ranking") or []
            top_score = float(final_ranking[0].get("score") or 0.0) if final_ranking else 0.0
            top_confidence_label = str(final_ranking[0].get("confidence") or "unknown") if final_ranking else "unknown"
            if top_score >= 0.70:
                bucket = "high"
            elif top_score >= 0.40:
                bucket = "medium"
            else:
                bucket = "low"
            rank = _rank(ranking, actual)
            case_brier = _brier_score(final_ranking, actual)
            if snapshot.get("prediction_mode") == "primary_transition_with_fallback":
                primary_mode_cases += 1
                primary = snapshot.get("primary_transition") or {}
                selected_source = str(primary.get("selected_source") or "none")
                selected_source_counts[selected_source] += 1
                if bool(primary.get("fallback_used")):
                    fallback_used_cases += 1

            total += 1
            if ranking:
                predicted += 1
            if rank == 1:
                top1 += 1
            if 1 <= rank <= 3:
                top3 += 1
            if rank:
                reciprocal_sum += 1.0 / rank
            brier_sum += case_brier

            origin_bucket = by_evidence_origin[evidence_origin]
            origin_bucket["cases"] += 1
            if ranking:
                origin_bucket["predicted"] += 1
            if rank == 1:
                origin_bucket["top1"] += 1
            if 1 <= rank <= 3:
                origin_bucket["top3"] += 1
            if rank:
                origin_bucket["reciprocal_sum"] += 1.0 / rank
            origin_bucket["brier_sum"] += case_brier
            calibration_buckets[bucket]["cases"] += 1
            calibration_buckets[bucket]["score_sum"] += top_score
            if rank == 1:
                calibration_buckets[bucket]["top1"] += 1

            if top_confidence_label not in confidence_label_buckets:
                top_confidence_label = "unknown"
            confidence_label_buckets[top_confidence_label]["cases"] += 1
            confidence_label_buckets[top_confidence_label]["score_sum"] += top_score
            if rank == 1:
                confidence_label_buckets[top_confidence_label]["top1"] += 1

            actual_bucket = by_actual_tactic[actual]
            actual_bucket["cases"] += 1
            if ranking:
                actual_bucket["predicted"] += 1
            if rank == 1:
                actual_bucket["top1"] += 1
            if 1 <= rank <= 3:
                actual_bucket["top3"] += 1
            if rank:
                actual_bucket["reciprocal_sum"] += 1.0 / rank
            actual_bucket["brier_sum"] += case_brier

            for source_name in _top_source_names(final_ranking):
                source_bucket = by_scorer_source[source_name]
                source_bucket["cases"] += 1
                if ranking:
                    source_bucket["predicted"] += 1
                if rank == 1:
                    source_bucket["top1"] += 1
                if 1 <= rank <= 3:
                    source_bucket["top3"] += 1
                if rank:
                    source_bucket["reciprocal_sum"] += 1.0 / rank
                source_bucket["brier_sum"] += case_brier

            if (snapshot.get("agreement") or {}).get("disagreement"):
                disagreement_cases += 1
                disagreement_by_origin[evidence_origin] += 1

            scorer_analysis = _scorer_case_analysis(snapshot, actual)
            contributors = _final_contributors(final_ranking, actual)
            for scorer, item in scorer_analysis.items():
                bucket = by_scorer_level[scorer]
                bucket["cases"] += 1
                if item.get("has_output"):
                    bucket["outputs"] += 1
                    if item.get("top1_correct"):
                        bucket["top1"] += 1
                    if item.get("top3_contains_actual"):
                        bucket["top3"] += 1
            for contributor in contributors:
                name = str(contributor.get("name") or "")
                if not name:
                    continue
                bucket = by_scorer_level[name]
                bucket["final_contributor_cases"] += 1
                bucket["weighted_score_sum"] += float(contributor.get("weighted_score") or 0.0)
                if contributor.get("contributed_to_correct_top1"):
                    bucket["final_correct_contributor_cases"] += 1
                if contributor.get("contributed_to_wrong_top1"):
                    bucket["final_wrong_contributor_cases"] += 1

            local_top = (scorer_analysis.get("local_transition") or {}).get("top_tactic") or ""
            external_top = (scorer_analysis.get("external_seed_transition") or {}).get("top_tactic") or ""
            if local_top and external_top:
                external_local_overlap_cases += 1
                if local_top != external_top:
                    external_local_disagreements += 1
            maturity = (snapshot.get("model_maturity") or {}).get("maturity", "cold")
            if maturity == "cold" or not local_top:
                local_unavailable_or_cold_cases += 1
            classification_quality = snapshot.get("classification_quality") or {}
            classification_uncertain = (
                bool(classification_quality.get("confidence_available"))
                and float(classification_quality.get("confidence_geomean") or 1.0) < 0.70
            ) or int(classification_quality.get("unknown_count") or 0) > 0
            if rank != 1 and classification_uncertain:
                classification_uncertainty_error_cases += 1
            top_predicted = ranking[0] if ranking else ""
            if rank != 1 and top_predicted:
                observed = [step["tactic"] for step in steps[: index + 1]]
                pair = f"{observed[-1] if observed else 'none'}->{actual}|predicted:{top_predicted}"
                incorrect_tactic_pairs[pair] += 1

            if include_cases or fit_weights:
                case_payload = {
                    "snapshot_id": snapshot.get("snapshot_id") or "",
                    "session_id": session_id,
                    "evidence_origin": evidence_origin,
                    "observed_tactic_sequence": [step["tactic"] for step in steps[: index + 1]],
                    "observed_prefix": [step["tactic"] for step in steps[: index + 1]],
                    "actual_next": actual,
                    "final_predicted_ranking": ranking,
                    "predicted": ranking,
                    "top_predicted_tactic": top_predicted,
                    "top_score": round(top_score, 4),
                    "brier_score": round(case_brier, 4),
                    "final_confidence": top_confidence_label,
                    "confidence": top_confidence_label,
                    "rank": rank,
                    "top_sources": final_ranking[:3],
                    "scorer_outputs": snapshot.get("scorer_outputs") or {},
                    "scorer_level_top_tactic": {
                        scorer: item.get("top_tactic", "")
                        for scorer, item in scorer_analysis.items()
                    },
                    "scorer_correctness": scorer_analysis,
                    "final_contributors": contributors,
                    "disagreement_score": (snapshot.get("agreement") or {}).get("divergence_ratio", 0.0),
                    "agreement": snapshot.get("agreement") or {},
                    "classification_quality": snapshot.get("classification_quality") or {},
                    "trust_status": snapshot.get("trust_status") or {},
                }
                if fit_weights:
                    weight_fit_cases.append(case_payload)
                if include_cases and len(cases) < max_cases:
                    cases.append(case_payload)

    metrics = {
        "total_cases": total,
        "predicted_cases": predicted,
        "coverage": round(predicted / total, 4) if total else 0.0,
        "top1_accuracy": round(top1 / total, 4) if total else 0.0,
        "top3_accuracy": round(top3 / total, 4) if total else 0.0,
        "mean_reciprocal_rank": round(reciprocal_sum / total, 4) if total else 0.0,
        "brier_score": round(brier_sum / total, 4) if total else 0.0,
        "scorer_disagreement_rate": round(disagreement_cases / total, 4) if total else 0.0,
        "fallback_use_rate": round(fallback_used_cases / primary_mode_cases, 4) if primary_mode_cases else None,
        "selected_source_counts": dict(sorted(selected_source_counts.items())),
    }
    metrics_by_evidence_origin: Dict[str, Dict[str, Any]] = {}
    for origin in sorted(EVIDENCE_ORIGINS | set(by_evidence_origin.keys())):
        summary = _stats_summary(by_evidence_origin[origin])
        origin_cases = int(summary.get("cases") or 0)
        summary["scorer_disagreement_rate"] = round(
            int(disagreement_by_origin.get(origin) or 0) / origin_cases,
            4,
        ) if origin_cases else 0.0
        metrics_by_evidence_origin[origin] = summary
    calibration = {}
    calibration_bins = []
    bin_ranges = {
        "low": (0.0, 0.40, False),
        "medium": (0.40, 0.70, False),
        "high": (0.70, 1.0, True),
    }
    for bucket, values in calibration_buckets.items():
        cases_count = int(values["cases"])
        empirical_accuracy = round(values["top1"] / cases_count, 4) if cases_count else 0.0
        calibration[bucket] = {
            "cases": cases_count,
            "average_score": round(values["score_sum"] / cases_count, 4) if cases_count else 0.0,
            "top1_accuracy": empirical_accuracy,
        }
        lower, upper, include_upper = bin_ranges[bucket]
        calibration_bins.append(
            {
                "label": bucket,
                "min_score": lower,
                "max_score": upper,
                "include_upper": include_upper,
                "cases": cases_count,
                "empirical_accuracy": empirical_accuracy,
                "average_score": calibration[bucket]["average_score"],
            }
        )
    confidence_labels = {}
    for label, values in confidence_label_buckets.items():
        cases_count = int(values["cases"])
        confidence_labels[label] = {
            "cases": cases_count,
            "average_score": round(values["score_sum"] / cases_count, 4) if cases_count else 0.0,
            "top1_accuracy": round(values["top1"] / cases_count, 4) if cases_count else 0.0,
        }
    result = {
        "schema_version": "prediction_backtest.v1",
        "generated_at": utc_now(),
        "leave_one_out": leave_one_out,
        "completed_sessions": len(payloads),
        "evaluated_sessions": len(candidate_sessions),
        "metrics": metrics,
        "metrics_by_evidence_origin": metrics_by_evidence_origin,
        "accuracy_by_tactic": {
            tactic: _stats_summary(bucket)
            for tactic, bucket in sorted(by_actual_tactic.items())
        },
        "accuracy_by_scorer_source": {
            source: _stats_summary(bucket)
            for source, bucket in sorted(by_scorer_source.items())
        },
        "scorer_level_report": {
            "accuracy_per_scorer": {
                scorer: _scorer_summary(bucket)
                for scorer, bucket in sorted(by_scorer_level.items())
            },
            "external_seed_vs_local_transition": {
                "overlap_cases": external_local_overlap_cases,
                "disagreement_cases": external_local_disagreements,
                "disagreement_rate": round(external_local_disagreements / external_local_overlap_cases, 4)
                if external_local_overlap_cases else 0.0,
            },
            "local_transition_unavailable_or_cold_cases": local_unavailable_or_cold_cases,
            "classification_uncertainty_error_cases": classification_uncertainty_error_cases,
            "incorrect_tactic_pairs": [
                {"pair": pair, "count": count}
                for pair, count in sorted(incorrect_tactic_pairs.items(), key=lambda item: item[1], reverse=True)[:20]
            ],
            "weight_adjustment_proposal": _weight_proposal(
                (policy or {}).get("weights") or {},
                by_scorer_level,
            ),
        },
        "scorer_disagreement": {
            "cases": disagreement_cases,
            "rate": metrics["scorer_disagreement_rate"],
        },
        "calibration": calibration,
        "confidence_label_calibration": confidence_labels,
        "calibration_model": {
            "enabled": True,
            "method": "empirical_binning",
            "min_cases_per_bin": 20,
            "bins": calibration_bins,
            "usage": "Copy this object into prediction_policy.calibration after enough cases exist.",
        },
        "policy": policy or {},
        "metric_tactic_vocabulary": list(METRIC_TACTIC_VOCABULARY),
        "model_construction": {
            "transition_history_limit": history_limit,
            "actor_history_limit": actor_history_limit,
            "prefix_max_length": prefix_max_length,
            "recency_decay_half_life_sessions": recency_half_life,
            "completed_sessions_only": True,
            "classification_eligibility": "central_trusted_classification_predicate",
            "storage_scope": (
                "backtest_from_storage defaults to production_live external sessions; "
                "direct callers must supply an explicit reviewed scope"
            ),
            "prefix_context": "reconstructed_observations_only",
            "training_order": "supplied_newest_first_matching_storage_query",
        },
    }
    if include_comparisons:
        result["evaluation_comparisons"] = _evaluation_comparisons(
            payloads,
            policy,
            leave_one_out,
            primary_metrics=metrics,
            ablation_scorers=ablation_scorers,
        )
    if fit_weights:
        weight_fit_policy = (policy or {}).get("weight_fitting") or {}
        if not isinstance(weight_fit_policy, dict):
            weight_fit_policy = {}
        include_context = bool(
            weight_fit_include_context
            if weight_fit_include_context is not None
            else weight_fit_policy.get("include_context", False)
        )
        result["empirical_weight_fit"] = fit_weights_from_cases(
            weight_fit_cases,
            (policy or {}).get("weights") or {},
            include_context=include_context,
            loss=weight_fit_loss or str(weight_fit_policy.get("loss") or "brier_score"),
        )
    result["run_id"] = stable_id(
        "predbacktest",
        {
            "generated_at": result["generated_at"],
            "metrics": metrics,
            "completed_sessions": len(payloads),
            "evaluated_sessions": len(candidate_sessions),
        },
    )
    if include_cases:
        result["cases"] = cases
    return result


def backtest_from_storage(
    config: ProductionConfig,
    limit: int = 1000,
    include_cases: bool = False,
    leave_one_out: bool = True,
    max_cases: int = 50,
    include_comparisons: bool = False,
    ablation_scorers: List[str] | None = None,
    fit_weights: bool = False,
    weight_fit_include_context: bool | None = None,
    weight_fit_loss: str | None = None,
    session_source: str | None = SESSION_SOURCE_PRODUCTION_LIVE,
    external_only: bool = True,
) -> Dict[str, Any]:
    normalized_source = normalize_session_source(session_source, "") if session_source else ""
    result = backtest_sessions(
        load_session_payloads(
            config,
            limit=limit,
            session_source=normalized_source or None,
            external_only=external_only,
        ),
        policy=config.prediction_policy,
        leave_one_out=leave_one_out,
        include_cases=include_cases,
        max_cases=max_cases,
        include_comparisons=include_comparisons,
        ablation_scorers=ablation_scorers,
        fit_weights=fit_weights,
        weight_fit_include_context=weight_fit_include_context,
        weight_fit_loss=weight_fit_loss,
    )
    result["session_source_filter"] = normalized_source or "all"
    result["external_source_filter"] = bool(external_only)
    return result


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Backtest real-time prediction on completed sessions.")
    parser.add_argument("--config", help="Path to production JSON config.")
    parser.add_argument("--database-url", help="Override DATABASE_URL for this backtest.")
    parser.add_argument("--limit", type=int, default=1000, help="Maximum stored sessions to read.")
    parser.add_argument(
        "--session-source",
        default=SESSION_SOURCE_PRODUCTION_LIVE,
        help="Session provenance to include. Default: production_live.",
    )
    parser.add_argument(
        "--all-session-sources",
        action="store_true",
        help="Include all session provenance values. Intended for audits only.",
    )
    parser.add_argument(
        "--include-non-external-source-ips",
        action="store_true",
        help="Audit mode: include private, loopback, CGNAT/Tailscale, and unknown source IPs.",
    )
    parser.add_argument("--include-cases", action="store_true", help="Include per-transition case details.")
    parser.add_argument("--max-cases", type=int, default=50, help="Maximum per-case details to include.")
    parser.add_argument("--include-comparisons", action="store_true", help="Include local-transition baseline and scorer ablation comparison runs.")
    parser.add_argument("--ablation-scorer", action="append", default=[], help="Limit ablation comparisons to this scorer; can be repeated.")
    parser.add_argument("--fit-weights", action="store_true", help="Include proposal-only empirical scorer weight fitting.")
    parser.add_argument(
        "--weight-fit-include-context",
        action="store_true",
        default=None,
        help="Allow context-modifier scorers in empirical weight fitting.",
    )
    parser.add_argument(
        "--weight-fit-loss",
        choices=["brier_score", "negative_log_likelihood"],
        default=None,
        help="Loss function for proposal-only empirical weight fitting.",
    )
    parser.add_argument("--review-queue-output", help="Write a compact JSON queue of high-value cases for analyst review.")
    parser.add_argument("--no-leave-one-out", action="store_true", help="Allow transition model to train on evaluated sessions.")
    parser.add_argument("--save", action="store_true", help="Store this backtest run in prediction_backtest_runs.")
    return parser


def _write_review_queue(result: Dict[str, Any], path_text: str, max_cases: int = 30) -> None:
    if not path_text:
        return
    cases = [case for case in result.get("cases") or [] if isinstance(case, dict)]
    selected = sorted(
        cases,
        key=lambda case: (
            0 if int(case.get("rank") or 0) != 1 else 1,
            -float(case.get("disagreement_score") or 0.0),
            0 if str(case.get("final_confidence") or "") in {"medium", "high"} else 1,
        ),
    )[: max(max_cases, 1)]
    document = {
        "schema_version": "prediction_review_queue.v1",
        "generated_at": utc_now(),
        "run_id": result.get("run_id") or "",
        "selection_policy": "wrong predictions first, then high scorer disagreement, then medium/high confidence",
        "review_case_count": len(selected),
        "review_cases": selected,
    }
    path = Path(path_text)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main(argv: List[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    config = ProductionConfig.from_env(args.config)
    if args.database_url:
        config.database_url = args.database_url
    result = backtest_from_storage(
        config,
        limit=max(args.limit, 1),
        include_cases=args.include_cases or bool(args.review_queue_output),
        leave_one_out=not args.no_leave_one_out,
        max_cases=max(args.max_cases, 1),
        include_comparisons=bool(args.include_comparisons),
        ablation_scorers=list(args.ablation_scorer or []),
        fit_weights=bool(args.fit_weights),
        weight_fit_include_context=args.weight_fit_include_context,
        weight_fit_loss=args.weight_fit_loss,
        session_source=None if args.all_session_sources else args.session_source,
        external_only=not bool(args.include_non_external_source_ips),
    )
    if args.save:
        storage = open_storage(config.database_url)
        storage.initialize()
        result["run_id"] = storage.save_prediction_backtest_run(result)
    if args.review_queue_output:
        _write_review_queue(result, args.review_queue_output, max_cases=min(max(args.max_cases, 1), 200))
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
