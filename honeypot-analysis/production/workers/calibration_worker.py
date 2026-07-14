"""Auditable weight calibration for realtime prediction.

This worker does not overwrite the trusted prediction policy. It reads analyst
feedback and the latest prediction backtest, computes bounded scorer-weight
adjustments, stores a calibration run, and writes a small policy overlay file
that the session worker can hot-load.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

from production.utils.config import ProductionConfig
from production.utils.serialization import stable_id, stable_json, utc_now
from production.utils.feedback import (
    EVIDENCE_ORIGINS,
    build_auto_evidence_feedback,
    feedback_weight_signal,
    merged_feedback_payload,
    normalize_feedback_payload,
)
from production.storage import open_storage
from production.storage.session_provenance import SESSION_SOURCE_PRODUCTION_LIVE


DEFAULT_POSITIVE_LABELS = {"correct", "useful"}
DEFAULT_NEGATIVE_LABELS = {"wrong", "not_useful", "not useful", "incorrect", "false_positive"}


def _decode_payload(row: Dict[str, Any]) -> Dict[str, Any]:
    payload = row.get("payload")
    if isinstance(payload, dict):
        return payload
    raw = row.get("payload_json")
    if isinstance(raw, dict):
        return dict(raw)
    if isinstance(raw, str):
        try:
            loaded = json.loads(raw)
        except json.JSONDecodeError:
            return {}
        return loaded if isinstance(loaded, dict) else {}
    return {}


def _parse_jsonish(value: Any) -> Any:
    if isinstance(value, (dict, list)):
        return value
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return None


def _feedback_label(row: Dict[str, Any]) -> str:
    payload = _decode_payload(row)
    return str(row.get("label") or payload.get("label") or "").strip().lower()


def _predicted_top_tactic(row: Dict[str, Any]) -> str:
    payload = _decode_payload(row)
    return str(row.get("predicted_top_tactic") or payload.get("predicted_top_tactic") or "").strip()


def _actual_next_tactic(row: Dict[str, Any]) -> str:
    payload = _decode_payload(row)
    return str(
        row.get("final_actual_next_tactic")
        or payload.get("final_actual_next_tactic")
        or row.get("correct_next_tactic")
        or payload.get("correct_next_tactic")
        or ""
    ).strip()


def _predicted_ranking(row: Dict[str, Any]) -> List[Dict[str, Any]]:
    payload = _decode_payload(row)
    raw = row.get("predicted_ranking") or payload.get("predicted_ranking") or []
    parsed = _parse_jsonish(raw)
    if parsed is None:
        parsed = raw
    if not isinstance(parsed, list):
        return []
    return [item for item in parsed if isinstance(item, dict)]


def _top_scorer_names(ranking: List[Dict[str, Any]]) -> List[str]:
    if not ranking:
        return []
    top = ranking[0]
    names: List[str] = []
    for source in top.get("sources") or []:
        if not isinstance(source, dict):
            continue
        name = str(source.get("name") or "").strip()
        if name and name not in names:
            names.append(name)
    return names


def _feedback_rows_with_snapshot_context(storage: Any, rows: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], int]:
    enriched_rows: List[Dict[str, Any]] = []
    hydrated = 0
    get_snapshot = getattr(storage, "get_prediction_snapshot", None)
    for row in rows:
        if _predicted_ranking(row) or not callable(get_snapshot):
            enriched_rows.append(row)
            continue
        snapshot_id = str(row.get("snapshot_id") or _decode_payload(row).get("snapshot_id") or "").strip()
        if not snapshot_id:
            enriched_rows.append(row)
            continue
        snapshot = get_snapshot(snapshot_id)
        payload = (snapshot or {}).get("payload") or {}
        ranking = payload.get("final_ranking") or []
        if not isinstance(ranking, list) or not ranking:
            enriched_rows.append(row)
            continue
        enriched = dict(row)
        row_payload = _decode_payload(row)
        row_payload.setdefault("predicted_ranking", ranking)
        row_payload.setdefault("predicted_top_tactic", str((ranking[0] or {}).get("tactic") or ""))
        enriched["payload"] = row_payload
        if not enriched.get("predicted_ranking"):
            enriched["predicted_ranking"] = stable_json(ranking)
        if not enriched.get("predicted_top_tactic"):
            enriched["predicted_top_tactic"] = row_payload.get("predicted_top_tactic") or ""
        enriched_rows.append(enriched)
        hydrated += 1
    return enriched_rows, hydrated


def _normalized_feedback(row: Dict[str, Any], policy: Dict[str, Any]) -> Dict[str, Any]:
    return normalize_feedback_payload(
        merged_feedback_payload(row),
        min_auto_evidence_confidence=float(policy.get("min_auto_evidence_confidence") or 0.9),
    )


def _feedback_signal(row: Dict[str, Any], policy: Dict[str, Any]) -> Tuple[bool, float]:
    usable, score, _ = feedback_weight_signal(row, policy)
    return usable, score


def _feedback_by_scorer(rows: Iterable[Dict[str, Any]], policy: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    summary: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        usable, score = _feedback_signal(row, policy)
        if not usable:
            continue
        names = _top_scorer_names(_predicted_ranking(row))
        if not names:
            names = ["unknown"]
        for name in names:
            item = summary.setdefault(name, {"cases": 0, "positive": 0.0, "accuracy": 0.0})
            item["cases"] += 1
            item["positive"] += score
    for item in summary.values():
        cases = int(item.get("cases") or 0)
        item["accuracy"] = round(float(item.get("positive") or 0.0) / cases, 4) if cases else 0.0
    return summary


def _feedback_row_counts(
    rows: Iterable[Dict[str, Any]],
    policy: Dict[str, Any],
    known_scorers: set[str],
) -> Dict[str, int]:
    """Count usable feedback rows separately from per-scorer evidence.

    A single prediction can contain multiple contributing scorers. Calibration
    still needs the minimum-feedback gate to count analyst decisions, not the
    expanded scorer-source cases, otherwise one feedback row with many sources
    could satisfy a row threshold by itself.
    """
    usable_rows = 0
    weighted_scorer_rows = 0
    ignored_rows = 0
    origin_counts: Dict[str, int] = {origin: 0 for origin in sorted(EVIDENCE_ORIGINS)}
    usable_origin_counts: Dict[str, int] = {origin: 0 for origin in sorted(EVIDENCE_ORIGINS)}
    excluded_origin_counts: Dict[str, int] = {origin: 0 for origin in sorted(EVIDENCE_ORIGINS)}
    for row in rows:
        normalized = _normalized_feedback(row, policy)
        origin = str(normalized.get("evidence_origin") or "live_cowrie")
        origin_counts[origin] = origin_counts.get(origin, 0) + 1
        usable, _ = _feedback_signal(row, policy)
        if not usable:
            excluded_origin_counts[origin] = excluded_origin_counts.get(origin, 0) + 1
            continue
        usable_origin_counts[origin] = usable_origin_counts.get(origin, 0) + 1
        usable_rows += 1
        names = _top_scorer_names(_predicted_ranking(row))
        if any(name in known_scorers for name in names):
            weighted_scorer_rows += 1
        else:
            ignored_rows += 1
    return {
        "usable_feedback_rows": usable_rows,
        "weighted_scorer_feedback_rows": weighted_scorer_rows,
        "ignored_feedback_rows_without_weighted_scorer": ignored_rows,
        "feedback_origin_counts": origin_counts,
        "usable_feedback_origin_counts": usable_origin_counts,
        "excluded_feedback_origin_counts": excluded_origin_counts,
    }


def _feedback_identity(row: Dict[str, Any]) -> Tuple[str, str, str, str, str]:
    payload = merged_feedback_payload(row)
    return (
        str(payload.get("session_id") or ""),
        str(payload.get("snapshot_id") or ""),
        str(payload.get("feedback_type") or ""),
        str(payload.get("evidence_event_index") or ""),
        str(payload.get("final_actual_next_tactic") or payload.get("correct_next_tactic") or ""),
    )


def _auto_evidence_feedback_rows(
    storage: Any,
    policy: Dict[str, Any],
    existing_rows: List[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
    if not bool(policy.get("auto_evidence_enabled", True)):
        return [], {"auto_evidence_enabled": 0, "auto_evidence_rows": 0, "auto_evidence_snapshots_checked": 0}
    min_confidence = float(policy.get("min_auto_evidence_confidence") or 0.9)
    snapshot_limit = int(policy.get("auto_evidence_snapshot_limit") or policy.get("feedback_limit") or 500)
    session_limit = int(policy.get("auto_evidence_session_limit") or max(snapshot_limit, 500))
    snapshots = storage.list_rows("prediction_snapshots", limit=snapshot_limit)
    if hasattr(storage, "list_session_rows"):
        sessions = storage.list_session_rows(
            limit=session_limit,
            session_source=SESSION_SOURCE_PRODUCTION_LIVE,
            external_only=True,
        )
    else:
        sessions = storage.list_rows("sessions", limit=session_limit)
    sessions_by_id: Dict[str, Dict[str, Any]] = {}
    for row in sessions:
        session_id = str(row.get("session_id") or "")
        if session_id:
            sessions_by_id[session_id] = row
    existing = {_feedback_identity(row) for row in existing_rows}
    generated: List[Dict[str, Any]] = []
    for snapshot_row in snapshots:
        snapshot_payload = _decode_payload(snapshot_row)
        session_id = str(snapshot_row.get("session_id") or snapshot_payload.get("session_id") or "")
        session_row = sessions_by_id.get(session_id)
        if not session_row:
            continue
        session_payload = _decode_payload(session_row)
        feedback = build_auto_evidence_feedback(
            {"payload": snapshot_payload},
            session_payload,
            min_confidence=min_confidence,
        )
        if not feedback:
            continue
        identity = _feedback_identity(feedback)
        if identity in existing:
            continue
        existing.add(identity)
        generated.append(feedback)
    return generated, {
        "auto_evidence_enabled": 1,
        "auto_evidence_rows": len(generated),
        "auto_evidence_snapshots_checked": len(snapshots),
    }


def _latest_backtest(storage: Any) -> Dict[str, Any]:
    rows = storage.list_rows("prediction_backtest_runs", limit=1)
    if not rows:
        return {}
    return _decode_payload(rows[0])


def _backtest_by_scorer(backtest: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    raw = backtest.get("accuracy_by_scorer_source") or {}
    output: Dict[str, Dict[str, Any]] = {}
    if not isinstance(raw, dict):
        return output
    for name, metrics in raw.items():
        if not isinstance(metrics, dict):
            continue
        output[str(name)] = {
            "cases": int(metrics.get("cases") or 0),
            "accuracy": float(metrics.get("top1_accuracy") or 0.0),
            "top3_accuracy": float(metrics.get("top3_accuracy") or 0.0),
            "coverage": float(metrics.get("coverage") or 0.0),
        }
    return output


def _clamp(value: float, lower: float, upper: float) -> float:
    return max(lower, min(upper, value))


def _quality_scores(
    weights: Dict[str, float],
    feedback_summary: Dict[str, Dict[str, Any]],
    backtest_summary: Dict[str, Dict[str, Any]],
    calibration_policy: Dict[str, Any],
) -> Dict[str, Dict[str, Any]]:
    feedback_case_weight = float(calibration_policy.get("feedback_case_weight") or 2.0)
    backtest_case_weight = float(calibration_policy.get("backtest_case_weight") or 1.0)
    output: Dict[str, Dict[str, Any]] = {}
    for name in weights:
        feedback = feedback_summary.get(name) or {}
        backtest = backtest_summary.get(name) or {}
        feedback_cases = int(feedback.get("cases") or 0)
        backtest_cases = int(backtest.get("cases") or 0)
        weighted_cases = feedback_cases * feedback_case_weight + backtest_cases * backtest_case_weight
        if weighted_cases <= 0:
            quality = 0.0
        else:
            weighted_correct = (
                feedback_cases * feedback_case_weight * float(feedback.get("accuracy") or 0.0)
                + backtest_cases * backtest_case_weight * float(backtest.get("accuracy") or 0.0)
            )
            quality = weighted_correct / weighted_cases
        output[name] = {
            "quality": round(quality, 4),
            "feedback_cases": feedback_cases,
            "feedback_accuracy": feedback.get("accuracy", 0.0),
            "backtest_cases": backtest_cases,
            "backtest_accuracy": backtest.get("accuracy", 0.0),
            "weighted_cases": round(weighted_cases, 4),
        }
    return output


def _calibrated_weights(
    current_weights: Dict[str, Any],
    quality: Dict[str, Dict[str, Any]],
    max_step: float,
) -> Tuple[Dict[str, float], Dict[str, Dict[str, Any]]]:
    numeric_weights = {name: max(float(value or 0.0), 0.0) for name, value in current_weights.items()}
    total_weight = sum(numeric_weights.values()) or 1.0
    quality_total = sum(float(item.get("quality") or 0.0) for item in quality.values())
    adjustments: Dict[str, Dict[str, Any]] = {}
    output: Dict[str, float] = {}
    for name, old_weight in numeric_weights.items():
        if quality_total <= 0:
            target = old_weight
        else:
            target = total_weight * float((quality.get(name) or {}).get("quality") or 0.0) / quality_total
        delta = _clamp(target - old_weight, -max_step, max_step)
        new_weight = max(old_weight + delta, 0.0)
        output[name] = round(new_weight, 4)
        adjustments[name] = {
            "old_weight": round(old_weight, 4),
            "target_weight": round(target, 4),
            "new_weight": round(new_weight, 4),
            "delta": round(delta, 4),
            **(quality.get(name) or {}),
        }
    return output, adjustments


def build_calibration_run(config: ProductionConfig, storage: Any) -> Dict[str, Any]:
    policy = config.calibration_policy or {}
    prediction_policy = config.prediction_policy or {}
    weights = {
        str(name): float(value or 0.0)
        for name, value in (prediction_policy.get("weights") or {}).items()
    }
    feedback_limit = int(policy.get("feedback_limit") or 500)
    feedback_rows = storage.list_rows("analyst_feedback", limit=feedback_limit)
    feedback_rows, hydrated_feedback_rows = _feedback_rows_with_snapshot_context(storage, feedback_rows)
    auto_evidence_rows, auto_evidence_summary = _auto_evidence_feedback_rows(storage, policy, feedback_rows)
    feedback_rows = feedback_rows + auto_evidence_rows
    feedback_summary = _feedback_by_scorer(feedback_rows, policy)
    feedback_row_counts = _feedback_row_counts(feedback_rows, policy, set(weights))
    backtest = _latest_backtest(storage)
    backtest_summary = _backtest_by_scorer(backtest)
    backtest_metrics = backtest.get("metrics") or {}
    backtest_cases = int(backtest_metrics.get("total_cases") or 0)
    feedback_scorer_cases = sum(
        int(item.get("cases") or 0)
        for scorer, item in feedback_summary.items()
        if scorer in weights
    )
    feedback_cases = int(feedback_row_counts["weighted_scorer_feedback_rows"])
    min_feedback = int(policy.get("min_feedback_rows") or 0)
    min_backtest = int(policy.get("min_backtest_cases") or 0)
    max_step = max(float(policy.get("max_weight_step") or 0.05), 0.0)
    enabled = bool(policy.get("enabled", True))

    quality = _quality_scores(weights, feedback_summary, backtest_summary, policy)
    calibrated_weights, adjustments = _calibrated_weights(weights, quality, max_step)
    reasons: List[str] = []
    if not enabled:
        reasons.append("calibration policy disabled")
    if not weights:
        reasons.append("prediction policy has no scorer weights")
    if feedback_cases < min_feedback:
        reasons.append(f"usable feedback rows {feedback_cases} below threshold {min_feedback}")
    if backtest_cases < min_backtest:
        reasons.append(f"backtest cases {backtest_cases} below threshold {min_backtest}")
    applied = enabled and not reasons and bool(weights)
    status = "applied" if applied else "insufficient_data"
    if not enabled:
        status = "disabled"

    generated_at = utc_now()
    result = {
        "schema_version": "prediction_weight_calibration.v1",
        "generated_at": generated_at,
        "status": status,
        "applied": applied,
        "apply": applied,
        "reason": "; ".join(reasons) if reasons else "bounded calibration overlay generated",
        "inputs": {
            "feedback_rows_read": len(feedback_rows),
            "stored_feedback_rows_read": len(feedback_rows) - len(auto_evidence_rows),
            "auto_evidence_rows_generated": auto_evidence_summary.get("auto_evidence_rows", 0),
            "auto_evidence_snapshots_checked": auto_evidence_summary.get("auto_evidence_snapshots_checked", 0),
            "feedback_rows_hydrated_from_snapshots": hydrated_feedback_rows,
            "feedback_cases": feedback_cases,
            "usable_feedback_rows": feedback_row_counts["usable_feedback_rows"],
            "weighted_scorer_feedback_rows": feedback_row_counts["weighted_scorer_feedback_rows"],
            "scorer_feedback_cases": feedback_scorer_cases,
            "ignored_feedback_rows_without_weighted_scorer": feedback_row_counts[
                "ignored_feedback_rows_without_weighted_scorer"
            ],
            "feedback_origin_counts": feedback_row_counts["feedback_origin_counts"],
            "usable_feedback_origin_counts": feedback_row_counts["usable_feedback_origin_counts"],
            "excluded_feedback_origin_counts": feedback_row_counts["excluded_feedback_origin_counts"],
            "min_feedback_rows": min_feedback,
            "backtest_run_id": backtest.get("run_id") or "",
            "backtest_cases": backtest_cases,
            "min_backtest_cases": min_backtest,
            "max_weight_step": max_step,
        },
        "current_weights": weights,
        "calibrated_weights": calibrated_weights if applied else weights,
        "adjustments": adjustments,
        "feedback_by_scorer": feedback_summary,
        "backtest_by_scorer": backtest_summary,
        "policy_overlay": {},
    }
    if applied:
        result["policy_overlay"] = {
            "weights": calibrated_weights,
            "weight_calibration": {
                "enabled": True,
                "source": "calibration_worker",
                "run_id": "",
                "generated_at": generated_at,
                "status": status,
                "inputs": result["inputs"],
            },
        }
    result["run_id"] = stable_id(
        "predcalibration",
        {
            "generated_at": generated_at,
            "status": status,
            "inputs": result["inputs"],
            "calibrated_weights": result["calibrated_weights"],
        },
    )
    if applied:
        result["policy_overlay"]["weight_calibration"]["run_id"] = result["run_id"]
    return result


def write_calibration_output(result: Dict[str, Any], output_path: str) -> str:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(stable_json(result) + "\n", encoding="utf-8")
    return str(path)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Calibrate realtime prediction weights from feedback/backtests.")
    parser.add_argument("--config", help="Path to production JSON config.")
    parser.add_argument("--database-url", help="Override DATABASE_URL for calibration.")
    parser.add_argument("--output", help="Override calibration output JSON path.")
    parser.add_argument("--dry-run", action="store_true", help="Do not write output file or save calibration run.")
    parser.add_argument("--no-save", action="store_true", help="Write output but do not save prediction_calibration_runs.")
    return parser


def main(argv: List[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    config = ProductionConfig.from_env(args.config)
    if args.database_url:
        config.database_url = args.database_url
    storage = open_storage(config.database_url)
    storage.initialize()
    result = build_calibration_run(config, storage)
    output_path = args.output or str((config.calibration_policy or {}).get("output_path") or "")
    if output_path and not args.dry_run:
        result["output_path"] = write_calibration_output(result, output_path)
    if not args.dry_run and not args.no_save:
        result["run_id"] = storage.save_prediction_calibration_run(result)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
