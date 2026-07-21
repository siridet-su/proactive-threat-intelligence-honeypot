"""Evaluate a pinned external VOMM against local-shadow alternatives.

This is an offline, fail-closed experiment.  It deliberately does not edit a
prediction policy, transition artifact, database, or service.  The evaluator
holds an exact external artifact fixed while it compares it with a local model
trained only on sessions that precede each chronological test window.

The local result is a *proxy* unless the input explicitly carries the
``production_live`` / ``is_external_source`` provenance required by the normal
local evaluator.  It must not be used to claim deployment-local accuracy.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import html
import json
import math
import statistics
import time
import tracemalloc
from collections import Counter, defaultdict
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Sequence

from production.prediction.predictive_alerts import evaluate_predictive_alert
from production.prediction.realtime_prediction import (
    RealtimePredictionEngine,
    build_transition_model,
)
from production.tools.evaluate_next_tactic_model_comparison import (
    EvaluationCase,
    Predictor,
    build_cases,
    load_policy,
    load_session_payloads,
    split_session_payloads,
    summarize_predictions,
    tactic_vocabulary,
)


SCHEMA_VERSION = "authoritative_external_vomm_evaluation.v1"
DEFAULT_POLICY_PATH = "configs/prediction_policy.trusted.json"
DEFAULT_MODEL_PATH = "data/models/external_cowrie_seed_transition_model.compound_securebert.json"
DEFAULT_PAYLOAD_PATH = "evaluation/next_tactic_zenodo_7day_session_payload.jsonl"
DEFAULT_OUTPUT_DIR = "evaluation/authoritative_external_vomm"
DEFAULT_BOOTSTRAP_ITERATIONS = 500
DEFAULT_MIN_PER_TACTIC_SUPPORT = 30
DEFAULT_WINDOW_COUNT = 3
MEMORY_PROFILE_CASE_LIMIT = 250


@dataclass(frozen=True)
class CaseKey:
    """Stable identity for one next-tactic case inside a whole session."""

    session_id: str
    index: int
    actual: str

    @property
    def text(self) -> str:
        return f"{self.session_id}:{self.index}:{self.actual}"


def file_sha256(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _load_json(path: str | Path) -> Dict[str, Any]:
    with Path(path).open("r", encoding="utf-8") as handle:
        document = json.load(handle)
    if not isinstance(document, dict):
        raise ValueError("JSON document must be an object")
    return document


def _number(value: Any, default: float = 0.0) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    return number if math.isfinite(number) else default


def _model_count(model: Mapping[str, Any], key: str) -> float:
    return max(_number(model.get(key)), 0.0)


def _context_count(model: Mapping[str, Any], key: str) -> int:
    value = model.get(key) or {}
    return len(value) if isinstance(value, dict) else 0


def validate_external_transition_artifact(
    document: Mapping[str, Any] | None,
    *,
    actual_sha256: str = "",
    expected_sha256: str = "",
    expected_model_id: str = "",
) -> Dict[str, Any]:
    """Validate a frozen external model before an authority comparison.

    This is intentionally stricter than the legacy loader: an absent,
    malformed, or identity-mismatched artifact is unavailable.  Callers must
    use an empty ranking (abstention), never a heuristic substitute.
    """

    document = dict(document or {})
    reasons: List[str] = []
    if not document:
        reasons.append("artifact_document_missing_or_not_an_object")
    if str(document.get("schema_version") or "") != "external_transition_model.v1":
        reasons.append("unsupported_or_missing_schema_version")
    model_id = str(document.get("model_id") or "").strip()
    if not model_id:
        reasons.append("missing_model_id")
    if expected_model_id and model_id != expected_model_id:
        reasons.append("model_id_mismatch")
    if expected_sha256 and actual_sha256.lower() != expected_sha256.lower():
        reasons.append("artifact_sha256_mismatch")
    if not str(document.get("built_at") or "").strip():
        reasons.append("missing_built_at")
    for key in ("transitions", "prefix_transitions", "technique_transitions"):
        if not isinstance(document.get(key), dict):
            reasons.append(f"missing_or_malformed_{key}")
    for key in (
        "completed_sessions",
        "usable_sessions",
        "transition_count",
        "prefix_transition_count",
        "technique_transition_count",
    ):
        raw_value = document.get(key)
        if not isinstance(raw_value, (int, float)) or not math.isfinite(float(raw_value)) or float(raw_value) < 0.0:
            reasons.append(f"invalid_{key}")

    provenance = document.get("provenance")
    provenance = provenance if isinstance(provenance, dict) else {}
    training_manifest_sha256 = str(
        provenance.get("training_data_manifest_sha256")
        or provenance.get("training_member_manifest_sha256")
        or ""
    )
    return {
        "status": "valid" if not reasons else "unavailable",
        "valid": not reasons,
        "reasons": reasons,
        "schema_version": str(document.get("schema_version") or ""),
        "model_id": model_id,
        "built_at": str(document.get("built_at") or ""),
        "actual_sha256": actual_sha256,
        "expected_sha256": expected_sha256,
        "expected_model_id": expected_model_id,
        "dataset_handle": str(provenance.get("dataset_handle") or ""),
        "classifier": str(provenance.get("classifier") or ""),
        "classification_rule_policy_sha256": str(
            provenance.get("classification_rule_policy_sha256")
            or (provenance.get("classification_quality") or {}).get("classification_rule_policy_sha256")
            or ""
        ),
        "securebert_checkpoint_sha256": str(
            provenance.get("securebert_checkpoint_sha256") or ""
        ),
        "training_data_manifest_sha256": training_manifest_sha256,
        "training_input_root": str(provenance.get("input_root") or ""),
        "source_type": str(provenance.get("source_type") or ""),
        "counts": {
            "completed_sessions": int(_model_count(document, "completed_sessions")),
            "usable_sessions": int(_model_count(document, "usable_sessions")),
            "transition_count": _model_count(document, "transition_count"),
            "prefix_transition_count": _model_count(document, "prefix_transition_count"),
            "technique_transition_count": _model_count(document, "technique_transition_count"),
            "tactic_contexts": _context_count(document, "transitions"),
            "prefix_contexts": _context_count(document, "prefix_transitions"),
            "technique_contexts": _context_count(document, "technique_transitions"),
        },
    }


def load_exact_external_artifact(
    path: str | Path,
    *,
    expected_sha256: str = "",
    expected_model_id: str = "",
) -> tuple[Dict[str, Any], Dict[str, Any]]:
    """Load one artifact and return an unavailable result instead of guessing."""

    candidate = Path(path)
    if not candidate.exists():
        validation = validate_external_transition_artifact(
            {}, expected_sha256=expected_sha256, expected_model_id=expected_model_id
        )
        validation["reasons"] = ["artifact_path_missing", *validation["reasons"]]
        validation["path"] = str(candidate)
        validation["artifact_size_bytes"] = 0
        return {}, validation
    actual_sha256 = file_sha256(candidate)
    try:
        document = _load_json(candidate)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
        validation = validate_external_transition_artifact(
            {},
            actual_sha256=actual_sha256,
            expected_sha256=expected_sha256,
            expected_model_id=expected_model_id,
        )
        validation["reasons"] = ["artifact_json_malformed", *validation["reasons"]]
        validation["path"] = str(candidate)
        validation["artifact_size_bytes"] = candidate.stat().st_size
        return {}, validation
    validation = validate_external_transition_artifact(
        document,
        actual_sha256=actual_sha256,
        expected_sha256=expected_sha256,
        expected_model_id=expected_model_id,
    )
    validation["path"] = str(candidate)
    validation["artifact_size_bytes"] = candidate.stat().st_size
    return (document if validation["valid"] else {}), validation


def _policy_variant(
    policy: Mapping[str, Any],
    *,
    source_order: Sequence[str],
    fallback_scorer: str,
) -> Dict[str, Any]:
    result = deepcopy(dict(policy))
    result["prediction_mode"] = "primary_transition_with_fallback"
    result["compute_weighted_ensemble_baseline"] = False
    primary = dict(result.get("primary_transition") or {})
    primary["source_order"] = list(source_order)
    primary["fallback_scorer"] = fallback_scorer
    result["primary_transition"] = primary
    return result


def _case_keys(cases: Sequence[EvaluationCase]) -> List[CaseKey]:
    per_session: Counter[str] = Counter()
    keys: List[CaseKey] = []
    for case in cases:
        session_id = str(case.session_id)
        keys.append(CaseKey(session_id, per_session[session_id], str(case.actual)))
        per_session[session_id] += 1
    return keys


def _ranking_probabilities(snapshot: Mapping[str, Any]) -> Dict[str, float]:
    raw: Dict[str, float] = {}
    for item in snapshot.get("final_ranking") or []:
        if not isinstance(item, dict):
            continue
        tactic = str(item.get("tactic") or "").strip()
        score = _number(item.get("calibrated_score", item.get("score")))
        if tactic and score > 0:
            raw[tactic] = score
    total = sum(raw.values())
    return {key: value / total for key, value in raw.items()} if total else {}


def _snapshot_record(
    key: CaseKey,
    snapshot: Mapping[str, Any],
    latency_ms: float,
) -> Dict[str, Any]:
    ranking = [item for item in snapshot.get("final_ranking") or [] if isinstance(item, dict)]
    primary = snapshot.get("primary_transition") or {}
    coverage = snapshot.get("coverage") or {}
    top = ranking[0] if ranking else {}
    source_metadata = ((top.get("sources") or [{}])[0].get("metadata") or {}) if top else {}
    transition_context = str(source_metadata.get("transition_context") or snapshot.get("transition_context") or "")
    transition_type = str(source_metadata.get("transition_type") or snapshot.get("transition_evidence_type") or "")
    if transition_type == "prefix":
        context_length = len([part for part in transition_context.split(">") if part])
    elif transition_type in {"technique", "tactic"}:
        context_length = 1
    else:
        context_length = 0
    return {
        "case_id": key.text,
        "session_id": key.session_id,
        "actual": key.actual,
        "predicted": str(top.get("tactic") or ""),
        "top_score": round(_number(top.get("calibrated_score", top.get("score"))), 6),
        "confidence": str(top.get("confidence") or "unknown"),
        "covered": bool(ranking),
        "correct": bool(ranking and str(top.get("tactic") or "") == key.actual),
        "abstained": not bool(ranking),
        "selected_source": str(primary.get("selected_source") or ""),
        "fallback_used": bool(primary.get("fallback_used")),
        "fallback_reason": str(primary.get("fallback_reason") or ""),
        "coverage_reason": str(coverage.get("reason") or ""),
        "transition_type": transition_type,
        "transition_context": transition_context,
        "context_length": context_length,
        "transition_total": round(_number(source_metadata.get("transition_total", snapshot.get("transition_count"))), 6),
        "transition_support": round(_number(source_metadata.get("transition_support", snapshot.get("evidence_count"))), 6),
        "latency_ms": round(latency_ms, 6),
        "snapshot": dict(snapshot),
    }


def _quantile(values: Sequence[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(max(int(math.ceil(fraction * len(ordered))) - 1, 0), len(ordered) - 1)
    return float(ordered[index])


def _run_model(
    *,
    model_id: str,
    policy: Mapping[str, Any],
    local_model: Mapping[str, Any],
    external_model: Mapping[str, Any],
    cases: Sequence[EvaluationCase],
    min_per_tactic_support: int,
    bootstrap_iterations: int,
    seed: int,
) -> Dict[str, Any]:
    variants = {
        "external_authoritative_abstain": (["external_seed_transition"], "__abstain__"),
        "local_shadow_only": (["local_transition"], "__abstain__"),
        "current_local_first_cascade": (["local_transition", "external_seed_transition"], "fallback_progression"),
        "external_then_heuristic": (["external_seed_transition"], "fallback_progression"),
        "heuristic_only": (["__no_transition_source__"], "fallback_progression"),
    }
    source_order, fallback_scorer = variants[model_id]
    engine = RealtimePredictionEngine(
        _policy_variant(policy, source_order=source_order, fallback_scorer=fallback_scorer),
        transition_model=dict(local_model),
        external_transition_model=dict(external_model),
    )
    case_keys = _case_keys(cases)
    keyed_cases = [
        EvaluationCase(
            case.session_id,
            case.actual,
            {**case.features, "_architecture_case_id": key.text},
        )
        for key, case in zip(case_keys, cases)
    ]
    records: List[Dict[str, Any]] = []
    probabilities: Dict[str, Dict[str, float]] = {}
    memory_sample_limit = min(len(keyed_cases), MEMORY_PROFILE_CASE_LIMIT)
    memory_before_current = memory_before_peak = memory_after_current = memory_after_peak = 0
    if memory_sample_limit:
        tracemalloc.start()
        memory_before_current, memory_before_peak = tracemalloc.get_traced_memory()
    for index, (key, case) in enumerate(zip(case_keys, keyed_cases), start=1):
        start = time.perf_counter_ns()
        snapshot = engine.predict(case.features, event_id=f"architecture-eval:{model_id}:{key.text}")
        elapsed = (time.perf_counter_ns() - start) / 1_000_000
        record = _snapshot_record(key, snapshot, elapsed)
        records.append(record)
        probabilities[key.text] = _ranking_probabilities(snapshot)
        if index == memory_sample_limit:
            memory_after_current, memory_after_peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
    by_key = {key.text: probabilities[key.text] for key in case_keys}
    metrics = summarize_predictions(
        keyed_cases,
        Predictor(
            predict=lambda case: by_key[str(case.features["_architecture_case_id"])],
            metadata={"model_id": model_id},
        ),
        bootstrap_iterations=bootstrap_iterations,
        seed=seed,
        min_per_tactic_support=min_per_tactic_support,
        target_vocabulary=tactic_vocabulary([], dict(external_model), dict(local_model)),
    )
    latencies = [float(record["latency_ms"]) for record in records]
    return {
        "model_id": model_id,
        "metrics": metrics,
        "records": records,
        "resource_profile": {
            "prediction_latency_ms": {
                "count": len(latencies),
                "mean": round(statistics.fmean(latencies), 6) if latencies else 0.0,
                "p50": round(_quantile(latencies, 0.50), 6),
                "p95": round(_quantile(latencies, 0.95), 6),
                "max": round(max(latencies), 6) if latencies else 0.0,
            },
            "tracemalloc_bytes": {
                "sample_case_limit": memory_sample_limit,
                "current_delta": int(memory_after_current - memory_before_current),
                "peak_delta": int(max(memory_after_peak - memory_before_peak, 0)),
            },
        },
    }


def _local_model_from_history(
    history: Sequence[Dict[str, Any]],
    policy: Mapping[str, Any],
) -> Dict[str, Any]:
    # The live storage query is newest-first.  Input history is chronological,
    # so reversing first preserves the same recency weighting semantics.
    history_limit = max(int(policy.get("transition_history_limit") or 1000), 1)
    newest_first = list(reversed(history))[:history_limit]
    return build_transition_model(
        newest_first,
        prefix_max_length=int(policy.get("prefix_max_length") or 3),
        source_name="local_transition",
        recency_half_life_sessions=float(policy.get("recency_decay_half_life_sessions") or 0.0),
    )


def _split_windows(payloads: Sequence[Dict[str, Any]], count: int) -> List[List[Dict[str, Any]]]:
    if count < 1:
        raise ValueError("window count must be positive")
    if not payloads:
        return []
    width = int(math.ceil(len(payloads) / count))
    return [list(payloads[index:index + width]) for index in range(0, len(payloads), width)]


def _confusion(records: Iterable[Mapping[str, Any]]) -> Dict[str, Dict[str, int]]:
    output: Dict[str, Counter[str]] = defaultdict(Counter)
    for record in records:
        actual = str(record.get("actual") or "unknown")
        predicted = str(record.get("predicted") or "<abstained>")
        output[actual][predicted] += 1
    return {actual: dict(sorted(counts.items())) for actual, counts in sorted(output.items())}


def _calibration_diagnostic(records: Iterable[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    bins = [(0.0, 0.25), (0.25, 0.50), (0.50, 0.75), (0.75, 1.000001)]
    rows = []
    materialized = list(records)
    for lower, upper in bins:
        selected = [
            item for item in materialized
            if item.get("covered") and lower <= _number(item.get("top_score")) < upper
        ]
        rows.append({
            "lower": lower,
            "upper": min(upper, 1.0),
            "cases": len(selected),
            "mean_score": round(statistics.fmean(_number(item.get("top_score")) for item in selected), 6) if selected else None,
            "top1_accuracy": round(sum(bool(item.get("correct")) for item in selected) / len(selected), 6) if selected else None,
        })
    return rows


def _paired_comparison(
    left: Sequence[Mapping[str, Any]],
    right: Sequence[Mapping[str, Any]],
    *,
    left_name: str,
    right_name: str,
) -> Dict[str, Any]:
    left_by_case = {str(item["case_id"]): item for item in left}
    right_by_case = {str(item["case_id"]): item for item in right}
    if set(left_by_case) != set(right_by_case):
        raise ValueError("paired comparison requires identical cases")
    counts: Counter[str] = Counter()
    by_tactic: Dict[str, Counter[str]] = defaultdict(Counter)
    for case_id in sorted(left_by_case):
        left_record, right_record = left_by_case[case_id], right_by_case[case_id]
        left_correct, right_correct = bool(left_record["correct"]), bool(right_record["correct"])
        if left_correct and not right_correct:
            outcome = f"{left_name}_win"
        elif right_correct and not left_correct:
            outcome = f"{right_name}_win"
        elif left_correct:
            outcome = "both_correct"
        else:
            outcome = "both_incorrect_or_abstained"
        counts[outcome] += 1
        by_tactic[str(left_record["actual"])][outcome] += 1
    return {
        "case_count": len(left_by_case),
        "outcomes": dict(sorted(counts.items())),
        "by_actual_tactic": {
            tactic: dict(sorted(values.items())) for tactic, values in sorted(by_tactic.items())
        },
    }


def _override_summary(
    current_records: Sequence[Mapping[str, Any]],
    external_records: Sequence[Mapping[str, Any]],
) -> Dict[str, Any]:
    external_by_case = {str(item["case_id"]): item for item in external_records}
    overrides = [
        item for item in current_records
        if str(item.get("selected_source") or "") == "local_transition"
    ]
    outcome_counts: Counter[str] = Counter()
    support: List[float] = []
    by_tactic: Dict[str, Counter[str]] = defaultdict(Counter)
    for item in overrides:
        external = external_by_case[str(item["case_id"])]
        local_correct, external_correct = bool(item["correct"]), bool(external["correct"])
        if local_correct and not external_correct:
            outcome = "local_override_win"
        elif external_correct and not local_correct:
            outcome = "local_override_loss"
        elif local_correct:
            outcome = "both_correct"
        else:
            outcome = "both_incorrect_or_abstained"
        outcome_counts[outcome] += 1
        by_tactic[str(item["actual"])][outcome] += 1
        support.append(_number(item.get("transition_total")))
    return {
        "override_count": len(overrides),
        "override_rate": round(len(overrides) / len(current_records), 6) if current_records else 0.0,
        "outcomes": dict(sorted(outcome_counts.items())),
        "transition_total": {
            "min": round(min(support), 6) if support else 0.0,
            "median": round(statistics.median(support), 6) if support else 0.0,
            "max": round(max(support), 6) if support else 0.0,
        },
        "by_actual_tactic": {
            tactic: dict(sorted(values.items())) for tactic, values in sorted(by_tactic.items())
        },
    }


def _cost_summary(records: Sequence[Mapping[str, Any]], abstention_cost: float) -> float:
    total = 0.0
    for item in records:
        if bool(item.get("correct")):
            continue
        total += abstention_cost if bool(item.get("abstained")) else 1.0
    return round(total / len(records), 6) if records else 0.0


def _abstention_comparison(
    abstaining: Sequence[Mapping[str, Any]],
    heuristic: Sequence[Mapping[str, Any]],
    abstaining_metrics: Mapping[str, Any],
    heuristic_metrics: Mapping[str, Any],
) -> Dict[str, Any]:
    heuristic_by_case = {str(item["case_id"]): item for item in heuristic}
    unsupported = [item for item in abstaining if bool(item.get("abstained"))]
    fallback_cases = [
        heuristic_by_case[str(item["case_id"])] for item in unsupported
        if str(item["case_id"]) in heuristic_by_case
    ]
    fallback_correct = sum(bool(item.get("correct")) for item in fallback_cases)
    return {
        "same_case_count": len(abstaining),
        "unsupported_external_context_cases": len(unsupported),
        "unsupported_external_context_rate": round(len(unsupported) / len(abstaining), 6) if abstaining else 0.0,
        "external_abstention_metrics": {
            key: abstaining_metrics.get(key)
            for key in ("coverage", "abstention_rate", "all_case_accuracy", "selective_top1_accuracy", "balanced_accuracy")
        },
        "external_then_heuristic_metrics": {
            key: heuristic_metrics.get(key)
            for key in ("coverage", "abstention_rate", "all_case_accuracy", "selective_top1_accuracy", "balanced_accuracy")
        },
        "heuristic_on_unsupported_external_contexts": {
            "cases": len(fallback_cases),
            "top1_accuracy": round(fallback_correct / len(fallback_cases), 6) if fallback_cases else None,
        },
        "error_cost_sensitivity": {
            f"abstention_cost_{cost:g}": {
                "external_abstain": _cost_summary(abstaining, cost),
                "external_then_heuristic": _cost_summary(heuristic, cost),
            }
            for cost in (0.0, 0.25, 0.5, 1.0)
        },
        "alert_effect": {
            "external_abstain_triggered": sum(
                _alert_triggered(item["snapshot"], {}) for item in abstaining
            ),
            "external_then_heuristic_triggered": sum(
                _alert_triggered(item["snapshot"], {}) for item in heuristic
            ),
        },
        "guidance_effect": {
            "forecast_is_not_an_action_authority": True,
            "expected_actions_created_from_prediction_only": 0,
            "contract": "response_guidance.v2 requires canonical trusted actions and evidence; forecast is advisory context only",
        },
    }


def _alert_triggered(snapshot: Mapping[str, Any], policy: Mapping[str, Any]) -> bool:
    _alert, evaluation = evaluate_predictive_alert(dict(snapshot), dict(policy))
    return str(evaluation.get("status") or "") == "triggered"


def _model_summary(row: Mapping[str, Any]) -> Dict[str, Any]:
    metrics = row.get("metrics") or {}
    resource = row.get("resource_profile") or {}
    latency = resource.get("prediction_latency_ms") or {}
    memory = resource.get("tracemalloc_bytes") or {}
    return {
        "model_id": row.get("model_id"),
        "cases": metrics.get("evaluated_examples"),
        "coverage": metrics.get("coverage"),
        "abstention_rate": metrics.get("abstention_rate"),
        "all_case_accuracy": metrics.get("all_case_accuracy"),
        "selective_top1_accuracy": metrics.get("selective_top1_accuracy"),
        "balanced_accuracy": metrics.get("balanced_accuracy"),
        "mean_reciprocal_rank": metrics.get("mean_reciprocal_rank"),
        "normalized_multiclass_brier_score": metrics.get("normalized_multiclass_brier_score"),
        "latency_p50_ms": latency.get("p50"),
        "latency_p95_ms": latency.get("p95"),
        "peak_memory_bytes": memory.get("peak_delta"),
    }


def _promotion_gate(
    *,
    artifact_validation: Mapping[str, Any],
    provenance_scope: str,
    windows: Sequence[Mapping[str, Any]],
    abstention: Mapping[str, Any],
) -> Dict[str, Any]:
    # The gate intentionally refuses to treat external-corpus proxy adaptation
    # as local-deployment evidence.  No numeric performance threshold is chosen
    # after viewing results; a future production promotion needs an independent
    # pre-registered local dataset and decision threshold.
    reasons: List[str] = []
    if not artifact_validation.get("valid"):
        reasons.append("exact_external_artifact_is_not_valid")
    if not artifact_validation.get("training_data_manifest_sha256"):
        reasons.append("external_artifact_training_data_manifest_missing_no_overlap_proof")
    if provenance_scope != "production_live_external_source":
        reasons.append("no_clean_local_production_chronological_evidence")
    if not windows:
        reasons.append("no_heldout_chronological_windows")
    if not abstention.get("same_case_count"):
        reasons.append("no_common_cases_for_abstention_comparison")
    return {
        "status": "supported_for_production_change" if not reasons else "not_supported_for_production_change",
        "reasons": reasons,
        "predeclared_rule": (
            "Do not change production authority without a valid pinned artifact, leakage-safe "
            "chronological evaluation, and clean production_live external-source evidence for "
            "whether local authority provides repeatable benefit."
        ),
    }


def _svg_bar_chart(title: str, rows: Sequence[tuple[str, float]], *, y_label: str = "value") -> str:
    width, height, margin = 960, 560, 90
    plot_width, plot_height = width - 2 * margin, height - 2 * margin
    safe_rows = list(rows) or [("no data", 0.0)]
    maximum = max(max(value, 0.0) for _, value in safe_rows) or 1.0
    bar_width = plot_width / len(safe_rows) * 0.68
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="white"/>',
        f'<text x="{margin}" y="42" font-family="Arial" font-size="24" font-weight="bold">{html.escape(title)}</text>',
        f'<text x="22" y="{margin + plot_height / 2}" font-family="Arial" font-size="14" transform="rotate(-90 22 {margin + plot_height / 2})">{html.escape(y_label)}</text>',
        f'<line x1="{margin}" y1="{margin + plot_height}" x2="{margin + plot_width}" y2="{margin + plot_height}" stroke="#334155"/>',
        f'<line x1="{margin}" y1="{margin}" x2="{margin}" y2="{margin + plot_height}" stroke="#334155"/>',
    ]
    for index, (label, value) in enumerate(safe_rows):
        center = margin + (index + 0.5) * plot_width / len(safe_rows)
        bar_height = max(value, 0.0) / maximum * plot_height
        x, y = center - bar_width / 2, margin + plot_height - bar_height
        parts.extend([
            f'<rect x="{x:.2f}" y="{y:.2f}" width="{bar_width:.2f}" height="{bar_height:.2f}" fill="#2563eb"/>',
            f'<text x="{center:.2f}" y="{y - 8:.2f}" text-anchor="middle" font-family="Arial" font-size="12">{value:.3f}</text>',
            f'<text x="{center:.2f}" y="{margin + plot_height + 22}" text-anchor="middle" font-family="Arial" font-size="11">{html.escape(label)}</text>',
        ])
    parts.append("</svg>")
    return "\n".join(parts) + "\n"


def _svg_table(title: str, headers: Sequence[str], rows: Sequence[Sequence[Any]]) -> str:
    width, margin, row_height = 1120, 36, 28
    height = max(170, 100 + row_height * (len(rows) + 1))
    columns = max(len(headers), 1)
    column_width = (width - 2 * margin) / columns
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="white"/>',
        f'<text x="{margin}" y="30" font-family="Arial" font-size="22" font-weight="bold">{html.escape(title)}</text>',
    ]
    for row_index, row in enumerate([headers, *rows]):
        y = 58 + row_index * row_height
        fill = "#dbeafe" if row_index == 0 else ("#f8fafc" if row_index % 2 else "#ffffff")
        parts.append(f'<rect x="{margin}" y="{y - 18}" width="{width - 2 * margin}" height="{row_height}" fill="{fill}" stroke="#cbd5e1"/>')
        for column_index, value in enumerate(row):
            text = str(value)
            if len(text) > 24:
                text = text[:21] + "..."
            x = margin + 8 + column_index * column_width
            weight = " font-weight=\"bold\"" if row_index == 0 else ""
            parts.append(f'<text x="{x:.2f}" y="{y}" font-family="Arial" font-size="11"{weight}>{html.escape(text)}</text>')
    parts.append("</svg>")
    return "\n".join(parts) + "\n"


def _write_figures(result: Mapping[str, Any], destination: Path) -> List[str]:
    destination.mkdir(parents=True, exist_ok=True)
    summaries = result.get("model_summaries") or []
    datasets = result.get("dataset") or {}
    windows = result.get("windows") or []
    models = result.get("models") or {}
    external = models.get("external_authoritative_abstain") or {}
    external_metrics = external.get("metrics") or {}
    external_per_tactic = external_metrics.get("per_tactic") or {}
    external_context = external.get("context_length") or {}
    calibration = external.get("calibration_diagnostic") or []
    confusion = external.get("confusion_matrix") or {}
    confusion_rows = [
        (actual, predicted, count)
        for actual, values in sorted(confusion.items())
        for predicted, count in sorted((values or {}).items())
    ]
    figures = {
        "dataset_composition.svg": _svg_bar_chart(
            "Dataset composition",
            [
                ("sessions", float(datasets.get("sessions") or 0)),
                ("transitions", float(sum((datasets.get("transition_cases") or {}).values()))),
            ],
            y_label="count",
        ),
        "temporal_splits.svg": _svg_bar_chart(
            "Chronological whole-session split",
            [(name, float(value)) for name, value in sorted((datasets.get("split_sessions") or {}).items())],
            y_label="sessions",
        ),
        "model_performance.svg": _svg_bar_chart(
            "All-case Top-1 accuracy",
            [(str(item.get("model_id")), float(item.get("all_case_accuracy") or 0.0)) for item in summaries],
            y_label="accuracy",
        ),
        "coverage_vs_accuracy.svg": _svg_bar_chart(
            "Coverage × selective accuracy",
            [(str(item.get("model_id")), float(item.get("coverage") or 0.0) * float(item.get("selective_top1_accuracy") or 0.0)) for item in summaries],
            y_label="coverage × accuracy",
        ),
        "latency_profile.svg": _svg_bar_chart(
            "Prediction p95 latency (ms)",
            [(str(item.get("model_id")), float(item.get("latency_p95_ms") or 0.0)) for item in summaries],
            y_label="milliseconds",
        ),
        "memory_profile.svg": _svg_bar_chart(
            "Prediction peak memory sample (MiB)",
            [
                (
                    str(item.get("model_id")),
                    float(item.get("peak_memory_bytes") or 0.0) / (1024 * 1024),
                )
                for item in summaries
            ],
            y_label="MiB; bounded 250-case window sample",
        ),
        "window_stability.svg": _svg_bar_chart(
            "External authoritative accuracy by time window",
            [(f"window-{item.get('window_index')}", float(((item.get("models") or {}).get("external_authoritative_abstain") or {}).get("metrics", {}).get("all_case_accuracy") or 0.0)) for item in windows],
            y_label="all-case Top-1",
        ),
        "per_tactic_results.svg": _svg_bar_chart(
            "External VOMM per-tactic Top-1",
            [
                (str(tactic), float((values or {}).get("top1_accuracy") or 0.0))
                for tactic, values in sorted(external_per_tactic.items())
                if (values or {}).get("top1_accuracy") is not None
            ],
            y_label="Top-1 accuracy",
        ),
        "context_length.svg": _svg_bar_chart(
            "External VOMM context-length use",
            [(str(length), float(count)) for length, count in sorted(external_context.items())],
            y_label="cases",
        ),
        "calibration_diagnostic.svg": _svg_bar_chart(
            "External VOMM score-to-accuracy diagnostic",
            [
                (f"{item.get('lower'):.2f}-{item.get('upper'):.2f}", float(item.get("top1_accuracy") or 0.0))
                for item in calibration
            ],
            y_label="empirical Top-1 accuracy",
        ),
        "confusion_matrix_external.svg": _svg_table(
            "External authoritative VOMM confusion matrix",
            ["actual", "predicted", "cases"],
            confusion_rows[:30] or [("no cases", "", "0")],
        ),
        "artifact_size.svg": _svg_bar_chart(
            "Pinned artifact size",
            [("artifact MB", float((result.get("artifact") or {}).get("artifact_size_bytes") or 0) / (1024 * 1024))],
            y_label="MiB",
        ),
    }
    written = []
    for name, text in figures.items():
        (destination / name).write_text(text, encoding="utf-8")
        written.append(str(destination / name))
    return written


def _write_csv(result: Mapping[str, Any], destination: Path) -> None:
    rows = list(result.get("model_summaries") or [])
    columns = [
        "model_id", "cases", "coverage", "abstention_rate", "all_case_accuracy",
        "selective_top1_accuracy", "balanced_accuracy", "mean_reciprocal_rank",
        "normalized_multiclass_brier_score", "latency_p50_ms", "latency_p95_ms", "peak_memory_bytes",
    ]
    with destination.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, lineterminator="\n")
        writer.writeheader()
        writer.writerows({key: row.get(key) for key in columns} for row in rows)


def _write_detail_tables(result: Mapping[str, Any], destination: Path) -> List[str]:
    destination.mkdir(parents=True, exist_ok=True)
    outputs: List[str] = []
    models = result.get("models") or {}
    per_tactic_rows = []
    context_rows = []
    calibration_rows = []
    confusion_rows = []
    for model_id, model in sorted(models.items()):
        metrics = model.get("metrics") or {}
        for tactic, values in sorted((metrics.get("per_tactic") or {}).items()):
            values = values or {}
            per_tactic_rows.append({
                "model_id": model_id,
                "tactic": tactic,
                "support": values.get("support"),
                "reportable": values.get("reportable"),
                "top1_accuracy": values.get("top1_accuracy"),
                "normalized_multiclass_brier_score": values.get("normalized_multiclass_brier_score"),
                "mean_reciprocal_rank": values.get("mean_reciprocal_rank"),
            })
        for length, count in sorted((model.get("context_length") or {}).items()):
            context_rows.append({"model_id": model_id, "context_length": length, "cases": count})
        for row in model.get("calibration_diagnostic") or []:
            calibration_rows.append({"model_id": model_id, **row})
        for actual, predictions in sorted((model.get("confusion_matrix") or {}).items()):
            for predicted, count in sorted((predictions or {}).items()):
                confusion_rows.append({"model_id": model_id, "actual": actual, "predicted": predicted, "cases": count})
    tables = {
        "authoritative_external_vomm_per_tactic.csv": per_tactic_rows,
        "authoritative_external_vomm_context_length.csv": context_rows,
        "authoritative_external_vomm_calibration_diagnostic.csv": calibration_rows,
        "authoritative_external_vomm_confusion_matrices.csv": confusion_rows,
    }
    for name, rows in tables.items():
        path = destination / name
        keys = list(rows[0]) if rows else ["status"]
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=keys, lineterminator="\n")
            writer.writeheader()
            if rows:
                writer.writerows(rows)
            else:
                writer.writerow({"status": "no_rows"})
        outputs.append(str(path))
    return outputs


def _write_markdown(result: Mapping[str, Any], destination: Path) -> None:
    artifact = result.get("artifact") or {}
    gate = result.get("promotion_gate") or {}
    parameters = result.get("experiment_parameters") or {}
    dataset = result.get("dataset") or {}
    reproducibility = result.get("reproducibility") or {}
    classifier = reproducibility.get("classifier") or {}
    training_data = reproducibility.get("external_training_data") or {}
    lines = [
        "# Authoritative external VOMM evaluation",
        "",
        f"- Evaluation schema: `{result.get('schema_version')}`",
        f"- Exact artifact: `{artifact.get('model_id')}`",
        f"- Artifact SHA-256: `{artifact.get('actual_sha256')}`",
        f"- Dataset SHA-256: `{(result.get('dataset') or {}).get('sha256')}`",
        f"- Dataset sessions / held-out transition cases: `{dataset.get('sessions')}` / `{(dataset.get('transition_cases') or {}).get('test')}`",
        f"- Split: `{dataset.get('split_method')}`",
        f"- Windows / bootstrap resamples / seed: `{parameters.get('window_count')}` / `{parameters.get('bootstrap_iterations')}` / `{parameters.get('seed')}`",
        f"- Classifier provenance: `{classifier.get('provenance_status')}`",
        f"- External training overlap proof: `{training_data.get('overlap_proof')}`",
        f"- Promotion gate: **{gate.get('status')}**",
        "",
        "| Model | Coverage | All-case Top-1 | Selective Top-1 | Balanced Top-1 | Normalized Brier |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for item in result.get("model_summaries") or []:
        lines.append(
            "| {model_id} | {coverage:.4f} | {all_case_accuracy:.4f} | {selective_top1_accuracy:.4f} | {balanced_accuracy:.4f} | {normalized_multiclass_brier_score:.4f} |".format(
                model_id=item.get("model_id") or "",
                coverage=float(item.get("coverage") or 0.0),
                all_case_accuracy=float(item.get("all_case_accuracy") or 0.0),
                selective_top1_accuracy=float(item.get("selective_top1_accuracy") or 0.0),
                balanced_accuracy=float(item.get("balanced_accuracy") or 0.0),
                normalized_multiclass_brier_score=float(item.get("normalized_multiclass_brier_score") or 0.0),
            )
        )
    lines.extend(["", "## Gate reasons", ""])
    for reason in gate.get("reasons") or ["none"]:
        lines.append(f"- {reason}")
    lines.extend([
        "",
        "## Interpretation boundary",
        "",
        "- This is an offline external-corpus comparison. It does not change the production policy, artifact, service, alerting, or response-guidance authority.",
        "- The local scorer is a chronology-limited proxy trained on this external corpus; it is not evidence about the deployment-local model.",
        "- An absent training-member manifest prevents proof that the frozen artifact and the held-out corpus do not overlap. The recorded result therefore cannot authorize a production architecture change.",
    ])
    destination.write_text("\n".join(lines) + "\n", encoding="utf-8")


def evaluate_authoritative_external_vomm(
    *,
    payload_path: str,
    policy_path: str,
    artifact_path: str,
    expected_artifact_sha256: str = "",
    expected_model_id: str = "",
    window_count: int = DEFAULT_WINDOW_COUNT,
    bootstrap_iterations: int = DEFAULT_BOOTSTRAP_ITERATIONS,
    min_per_tactic_support: int = DEFAULT_MIN_PER_TACTIC_SUPPORT,
    seed: int = 20260721,
) -> Dict[str, Any]:
    """Run a leakage-safe, exact-artifact architecture comparison."""

    artifact, validation = load_exact_external_artifact(
        artifact_path,
        expected_sha256=expected_artifact_sha256,
        expected_model_id=expected_model_id,
    )
    policy = load_policy(policy_path)
    payloads = load_session_payloads(payload_path)
    split, split_method = split_session_payloads(payloads)
    if not validation["valid"]:
        return {
            "schema_version": SCHEMA_VERSION,
            "status": "blocked_invalid_external_artifact",
            "artifact": validation,
            "dataset": {"path": payload_path, "sha256": file_sha256(payload_path), "sessions": len(payloads)},
            "promotion_gate": _promotion_gate(
                artifact_validation=validation,
                provenance_scope="not_evaluated",
                windows=[],
                abstention={},
            ),
        }

    train, calibration, test = split["train"], split["calibration"], split["test"]
    history: List[Dict[str, Any]] = list(train) + list(calibration)
    windows = _split_windows(test, window_count)
    window_results: List[Dict[str, Any]] = []
    aggregate: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for window_index, window_payloads in enumerate(windows, start=1):
        local_model = _local_model_from_history(history, policy)
        cases = build_cases(window_payloads)
        models: Dict[str, Dict[str, Any]] = {}
        for offset, model_id in enumerate((
            "external_authoritative_abstain",
            "local_shadow_only",
            "current_local_first_cascade",
            "external_then_heuristic",
            "heuristic_only",
        )):
            models[model_id] = _run_model(
                model_id=model_id,
                policy=policy,
                local_model=local_model,
                external_model=artifact,
                cases=cases,
                min_per_tactic_support=min_per_tactic_support,
                # Window rows establish temporal stability.  The final pooled
                # result below carries the requested bootstrap interval; doing
                # the same resampling inside every window only repeats work and
                # does not create independent uncertainty evidence.
                bootstrap_iterations=0,
                seed=seed + window_index * 100 + offset,
            )
            aggregate[model_id].extend(models[model_id]["records"])
        window_results.append({
            "window_index": window_index,
            "history_sessions": len(history),
            "test_sessions": len(window_payloads),
            "test_cases": len(cases),
            "local_shadow_model": {
                key: local_model.get(key)
                for key in ("model_id", "completed_sessions", "usable_sessions", "transition_count", "prefix_transition_count", "technique_transition_count")
            },
            "models": {
                key: {name: value for name, value in model.items() if name != "records"}
                for key, model in models.items()
            },
        })
        # A subsequent window may learn only from sessions that are wholly in
        # the past.  No target from the current window enters its local model.
        history.extend(window_payloads)

    aggregate_models: Dict[str, Dict[str, Any]] = {}
    # Aggregate metrics from stored rankings without recomputing a model.
    for offset, (model_id, records) in enumerate(sorted(aggregate.items())):
        probabilities = {
            record["case_id"]: _ranking_probabilities(record["snapshot"])
            for record in records
        }
        aggregate_cases = [
            EvaluationCase(record["session_id"], record["actual"], {"case_id": record["case_id"]})
            for record in records
        ]
        metrics = summarize_predictions(
            aggregate_cases,
            Predictor(
                predict=lambda case, values=probabilities: values[str(case.features["case_id"])],
                metadata={"model_id": model_id},
            ),
            bootstrap_iterations=bootstrap_iterations,
            seed=seed + 10_000 + offset,
            min_per_tactic_support=min_per_tactic_support,
            target_vocabulary=tactic_vocabulary([], artifact),
        )
        resource = {
            "prediction_latency_ms": {
                "count": len(records),
                "mean": round(statistics.fmean(_number(item["latency_ms"]) for item in records), 6) if records else 0.0,
                "p50": round(_quantile([_number(item["latency_ms"]) for item in records], 0.5), 6),
                "p95": round(_quantile([_number(item["latency_ms"]) for item in records], 0.95), 6),
                "max": round(max((_number(item["latency_ms"]) for item in records), default=0.0), 6),
            },
            "tracemalloc_bytes": {
                "measurement": "maximum window sample; each sample is bounded to 250 prediction cases",
                "sample_case_limit": MEMORY_PROFILE_CASE_LIMIT,
                "peak_delta": max(
                    int((((window.get("models") or {}).get(model_id) or {}).get("resource_profile") or {}).get("tracemalloc_bytes", {}).get("peak_delta") or 0)
                    for window in window_results
                ) if window_results else 0,
            },
        }
        aggregate_models[model_id] = {
            "model_id": model_id,
            "metrics": metrics,
            "resource_profile": resource,
            "confusion_matrix": _confusion(records),
            "context_length": dict(sorted(Counter(int(item["context_length"]) for item in records).items())),
            "calibration_diagnostic": _calibration_diagnostic(records),
        }

    external_records = aggregate["external_authoritative_abstain"]
    current_records = aggregate["current_local_first_cascade"]
    result = {
        "schema_version": SCHEMA_VERSION,
        "status": "evaluated_external_proxy_only",
        "artifact": validation,
        "dataset": {
            "path": payload_path,
            "sha256": file_sha256(payload_path),
            "sessions": len(payloads),
            "split_method": split_method,
            "split_sessions": {name: len(items) for name, items in split.items()},
            "transition_cases": {name: len(build_cases(items)) for name, items in split.items()},
            "source_scope": "external_classifier_derived_weak_labels",
        },
        "experiment_parameters": {
            "window_count": len(windows),
            "bootstrap_iterations": bootstrap_iterations,
            "min_per_tactic_support": min_per_tactic_support,
            "seed": seed,
            "memory_profile_case_limit": MEMORY_PROFILE_CASE_LIMIT,
        },
        "reproducibility": {
            "policy_path": policy_path,
            "policy_sha256": file_sha256(policy_path),
            "artifact_path": artifact_path,
            "artifact_sha256": validation.get("actual_sha256"),
            "code_sha256": {
                "realtime_prediction": file_sha256("production/prediction/realtime_prediction.py"),
                "session_features": file_sha256("production/prediction/session_features.py"),
                "evaluator": file_sha256(__file__),
            },
            "classifier": {
                "name": validation.get("classifier"),
                "rule_policy_sha256": validation.get("classification_rule_policy_sha256"),
                "securebert_checkpoint_sha256": validation.get("securebert_checkpoint_sha256"),
                "provenance_status": (
                    "recorded_in_external_artifact"
                    if validation.get("classification_rule_policy_sha256")
                    and validation.get("securebert_checkpoint_sha256")
                    else "not_recorded_in_external_artifact"
                ),
            },
            "external_training_data": {
                "manifest_sha256": validation.get("training_data_manifest_sha256"),
                "input_root": validation.get("training_input_root"),
                "source_type": validation.get("source_type"),
                "overlap_proof": (
                    "available" if validation.get("training_data_manifest_sha256")
                    else "not_available"
                ),
            },
            "leakage_controls": [
                "whole sessions remain in one recorded chronological split",
                "the external artifact is fixed and never rebuilt from evaluation sessions",
                "each local shadow window uses only complete sessions before that window",
                "all compared models receive identical case identities per window",
            ],
        },
        "windows": window_results,
        "models": aggregate_models,
        "model_summaries": [_model_summary(aggregate_models[key]) for key in sorted(aggregate_models)],
        "local_authority": {
            "scope": "external_corpus_proxy_not_production_local",
            "paired_current_vs_external": _paired_comparison(
                current_records, external_records,
                left_name="current_local_first", right_name="external_authoritative",
            ),
            "local_override_summary": _override_summary(current_records, external_records),
            "conclusion": "not_established_without_clean_production_live_external_source_holdout",
        },
        "abstention_vs_heuristic": _abstention_comparison(
            external_records,
            aggregate["external_then_heuristic"],
            aggregate_models["external_authoritative_abstain"]["metrics"],
            aggregate_models["external_then_heuristic"]["metrics"],
        ),
    }
    result["promotion_gate"] = _promotion_gate(
        artifact_validation=validation,
        provenance_scope="external_corpus_proxy_not_production_local",
        windows=window_results,
        abstention=result["abstention_vs_heuristic"],
    )
    return result


def write_evaluation_outputs(result: Mapping[str, Any], output_dir: str | Path) -> Dict[str, str]:
    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    json_path = destination / "authoritative_external_vomm_evaluation.json"
    csv_path = destination / "authoritative_external_vomm_model_summary.csv"
    markdown_path = destination / "authoritative_external_vomm_evaluation.md"
    json_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    _write_csv(result, csv_path)
    tables = _write_detail_tables(result, destination)
    _write_markdown(result, markdown_path)
    figures = _write_figures(result, destination / "figures")
    return {
        "json": str(json_path),
        "csv": str(csv_path),
        "markdown": str(markdown_path),
        "tables": ",".join(tables),
        "figures": ",".join(figures),
    }


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--payload", default=DEFAULT_PAYLOAD_PATH)
    parser.add_argument("--policy", default=DEFAULT_POLICY_PATH)
    parser.add_argument("--artifact", default=DEFAULT_MODEL_PATH)
    parser.add_argument("--expected-artifact-sha256", default="")
    parser.add_argument("--expected-model-id", default="")
    parser.add_argument("--windows", type=int, default=DEFAULT_WINDOW_COUNT)
    parser.add_argument("--bootstrap-iterations", type=int, default=DEFAULT_BOOTSTRAP_ITERATIONS)
    parser.add_argument("--min-per-tactic-support", type=int, default=DEFAULT_MIN_PER_TACTIC_SUPPORT)
    parser.add_argument("--seed", type=int, default=20260721)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    result = evaluate_authoritative_external_vomm(
        payload_path=args.payload,
        policy_path=args.policy,
        artifact_path=args.artifact,
        expected_artifact_sha256=args.expected_artifact_sha256,
        expected_model_id=args.expected_model_id,
        window_count=max(int(args.windows), 1),
        bootstrap_iterations=max(int(args.bootstrap_iterations), 0),
        min_per_tactic_support=max(int(args.min_per_tactic_support), 1),
        seed=int(args.seed),
    )
    paths = write_evaluation_outputs(result, args.output_dir)
    print(json.dumps({"status": result.get("status"), "promotion_gate": result.get("promotion_gate"), "outputs": paths}, sort_keys=True))
    return 0 if result.get("status") == "evaluated_external_proxy_only" else 2


if __name__ == "__main__":
    raise SystemExit(main())
