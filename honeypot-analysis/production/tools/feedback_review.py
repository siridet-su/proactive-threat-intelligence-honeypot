"""Summarize analyst feedback for safe prediction tuning review."""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from typing import Any, Dict, Iterable, List

from production.utils.config import ProductionConfig
from production.utils.serialization import utc_now
from production.storage import open_storage


NEGATIVE_LABELS = {"wrong", "not_useful", "false_positive"}
POSITIVE_LABELS = {"useful", "correct"}
REVIEW_LABELS = {"needs_review"}
FEEDBACK_FILTERS = {
    "all",
    "wrong",
    "useful",
    "needs_review",
    "high_confidence_wrong",
    "low_confidence_useful",
    "missing_actual",
    "classification_error",
    "missing_transition_evidence",
    "policy_review",
}


def _decode_payload(row: Dict[str, Any]) -> Dict[str, Any]:
    payload = row.get("payload")
    if isinstance(payload, dict):
        return payload
    raw = row.get("payload_json")
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def _json_value(value: Any) -> Any:
    if isinstance(value, (list, dict)):
        return value
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return value


def _row_value(row: Dict[str, Any], key: str) -> Any:
    value = row.get(key)
    if value not in (None, ""):
        return value
    return _decode_payload(row).get(key)


def _ranking(row: Dict[str, Any]) -> List[Dict[str, Any]]:
    value = _json_value(_row_value(row, "predicted_ranking"))
    if isinstance(value, list):
        return [dict(item) for item in value if isinstance(item, dict)]
    return []


def _top_confidence(row: Dict[str, Any]) -> str:
    ranking = _ranking(row)
    if ranking:
        return str(ranking[0].get("confidence") or "")
    return ""


def _top_score(row: Dict[str, Any]) -> float:
    ranking = _ranking(row)
    if not ranking:
        return 0.0
    try:
        return float(ranking[0].get("score") or 0.0)
    except (TypeError, ValueError):
        return 0.0


def _top_sources(row: Dict[str, Any]) -> List[Dict[str, str]]:
    sources: List[Dict[str, str]] = []
    ranking = _ranking(row)
    for item in ranking[:3]:
        if not isinstance(item, dict):
            continue
        nested = item.get("sources")
        if isinstance(nested, list):
            for source in nested:
                if not isinstance(source, dict):
                    continue
                sources.append(
                    {
                        "name": str(source.get("name") or source.get("source") or "unknown"),
                        "source_type": str(source.get("source_type") or ""),
                        "rule_id": str(source.get("rule_id") or ""),
                    }
                )
        elif item.get("source") or item.get("source_type"):
            sources.append(
                {
                    "name": str(item.get("source") or "unknown"),
                    "source_type": str(item.get("source_type") or ""),
                    "rule_id": str(item.get("rule_id") or ""),
                }
            )
    return sources


def _source_names(row: Dict[str, Any]) -> List[str]:
    return sorted({source["name"] for source in _top_sources(row) if source.get("name")})


def _source_types(row: Dict[str, Any]) -> List[str]:
    return sorted({source["source_type"] for source in _top_sources(row) if source.get("source_type")})


def _notes_hint_classification(row: Dict[str, Any]) -> bool:
    notes = str(_row_value(row, "notes") or "").lower()
    return any(token in notes for token in ("classif", "securebert", "bert", "ttp", "technique", "tactic", "wrong label"))


def _failure_categories(row: Dict[str, Any]) -> List[str]:
    label = str(_row_value(row, "label") or "unknown")
    predicted = str(_row_value(row, "predicted_top_tactic") or "")
    actual = str(_row_value(row, "final_actual_next_tactic") or _row_value(row, "correct_next_tactic") or "")
    confidence = _top_confidence(row)
    score = _top_score(row)
    names = set(_source_names(row))
    source_types = set(_source_types(row))
    categories: List[str] = []

    if not actual:
        categories.append("missing_actual_next_tactic")
    if label in REVIEW_LABELS:
        categories.append("needs_review")
    if label in NEGATIVE_LABELS:
        if predicted and actual and predicted != actual:
            categories.append("prediction_mismatch")
        if confidence == "high" or score >= 0.70:
            categories.append("calibration_or_weighting_review")
        if "local_transition" not in names and "empirical_local" not in source_types:
            categories.append("missing_local_transition_evidence")
        if source_types.intersection({"heuristic_prior", "human_curated_attck_prior", "detection_correlation"}):
            categories.append("policy_rule_review")
        if _notes_hint_classification(row):
            categories.append("possible_classification_error")
        if not names and not source_types:
            categories.append("insufficient_feedback_payload")
    if label in POSITIVE_LABELS and (confidence == "low" or score < 0.40):
        categories.append("useful_low_confidence_case")
    return sorted(set(categories))


def filter_feedback_rows(feedback_rows: Iterable[Dict[str, Any]], filter_name: str = "all") -> List[Dict[str, Any]]:
    rows = [row for row in feedback_rows if isinstance(row, dict)]
    normalized = str(filter_name or "all").strip().lower()
    if normalized not in FEEDBACK_FILTERS:
        normalized = "all"
    if normalized == "all":
        return rows

    filtered: List[Dict[str, Any]] = []
    for row in rows:
        label = str(_row_value(row, "label") or "unknown")
        confidence = _top_confidence(row)
        score = _top_score(row)
        actual = str(_row_value(row, "final_actual_next_tactic") or _row_value(row, "correct_next_tactic") or "")
        categories = set(_failure_categories(row))
        if normalized == "wrong" and label in NEGATIVE_LABELS:
            filtered.append(row)
        elif normalized == "useful" and label in POSITIVE_LABELS:
            filtered.append(row)
        elif normalized == "needs_review" and label in REVIEW_LABELS:
            filtered.append(row)
        elif normalized == "high_confidence_wrong" and label in NEGATIVE_LABELS and (confidence == "high" or score >= 0.70):
            filtered.append(row)
        elif normalized == "low_confidence_useful" and label in POSITIVE_LABELS and (confidence == "low" or score < 0.40):
            filtered.append(row)
        elif normalized == "missing_actual" and not actual:
            filtered.append(row)
        elif normalized == "classification_error" and "possible_classification_error" in categories:
            filtered.append(row)
        elif normalized == "missing_transition_evidence" and "missing_local_transition_evidence" in categories:
            filtered.append(row)
        elif normalized == "policy_review" and "policy_rule_review" in categories:
            filtered.append(row)
    return filtered


def build_feedback_review(feedback_rows: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    rows = [row for row in feedback_rows if isinstance(row, dict)]
    labels = Counter(str(_row_value(row, "label") or "unknown") for row in rows)
    by_predicted = defaultdict(lambda: {"total": 0, "negative": 0, "positive": 0})
    by_actual = defaultdict(lambda: {"total": 0, "negative": 0, "positive": 0})
    failure_categories = Counter()
    weak_scorer_sources = Counter()
    weak_source_types = Counter()
    high_confidence_wrong: List[Dict[str, Any]] = []
    low_confidence_useful: List[Dict[str, Any]] = []
    classification_error_candidates: List[Dict[str, Any]] = []
    missing_transition_evidence_cases: List[Dict[str, Any]] = []
    policy_review_candidates: List[Dict[str, Any]] = []
    missing_actual = 0

    for row in rows:
        label = str(_row_value(row, "label") or "unknown")
        predicted = str(_row_value(row, "predicted_top_tactic") or "")
        actual = str(_row_value(row, "final_actual_next_tactic") or _row_value(row, "correct_next_tactic") or "")
        confidence = _top_confidence(row)
        score = _top_score(row)
        if not actual:
            missing_actual += 1

        for bucket in (by_predicted[predicted or "unknown"], by_actual[actual or "unknown"]):
            bucket["total"] += 1
            if label in NEGATIVE_LABELS:
                bucket["negative"] += 1
            if label in POSITIVE_LABELS:
                bucket["positive"] += 1

        case = {
            "session_id": _row_value(row, "session_id") or "",
            "snapshot_id": _row_value(row, "snapshot_id") or "",
            "label": label,
            "predicted_top_tactic": predicted,
            "final_actual_next_tactic": actual,
            "confidence": confidence,
            "score": round(score, 4),
            "created_at": _row_value(row, "created_at") or "",
            "notes": _row_value(row, "notes") or "",
            "source_names": _source_names(row),
            "source_types": _source_types(row),
            "failure_categories": _failure_categories(row),
        }
        for category in case["failure_categories"]:
            failure_categories[category] += 1
        if label in NEGATIVE_LABELS:
            for source in _top_sources(row):
                weak_scorer_sources[source.get("name") or "unknown"] += 1
                if source.get("source_type"):
                    weak_source_types[source["source_type"]] += 1
        if label in NEGATIVE_LABELS and (confidence == "high" or score >= 0.70):
            high_confidence_wrong.append(case)
        if label in POSITIVE_LABELS and (confidence == "low" or score < 0.40):
            low_confidence_useful.append(case)
        if "possible_classification_error" in case["failure_categories"]:
            classification_error_candidates.append(case)
        if "missing_local_transition_evidence" in case["failure_categories"]:
            missing_transition_evidence_cases.append(case)
        if "policy_rule_review" in case["failure_categories"]:
            policy_review_candidates.append(case)

    weak_predicted = [
        {"tactic": tactic, **stats}
        for tactic, stats in by_predicted.items()
        if stats["negative"] > 0
    ]
    weak_predicted.sort(key=lambda item: (item["negative"], item["total"]), reverse=True)

    return {
        "schema_version": "feedback_review.v1",
        "generated_at": utc_now(),
        "feedback_count": len(rows),
        "label_counts": dict(labels),
        "filter_counts": {
            name: len(filter_feedback_rows(rows, name))
            for name in sorted(FEEDBACK_FILTERS)
        },
        "missing_final_actual_next_tactic": missing_actual,
        "high_confidence_wrong": high_confidence_wrong,
        "low_confidence_useful": low_confidence_useful,
        "classification_error_candidates": classification_error_candidates[:20],
        "missing_transition_evidence_cases": missing_transition_evidence_cases[:20],
        "policy_review_candidates": policy_review_candidates[:20],
        "failure_categories": dict(sorted(failure_categories.items())),
        "weak_scorer_sources": dict(weak_scorer_sources.most_common(20)),
        "weak_source_types": dict(weak_source_types.most_common(20)),
        "by_predicted_tactic": dict(sorted(by_predicted.items())),
        "by_actual_next_tactic": dict(sorted(by_actual.items())),
        "recurring_weak_predictions": weak_predicted[:20],
        "recommendations": _recommendations(
            len(rows),
            missing_actual,
            high_confidence_wrong,
            weak_predicted,
            failure_categories,
            weak_scorer_sources,
        ),
    }


def _recommendations(
    count: int,
    missing_actual: int,
    high_confidence_wrong: List[Dict[str, Any]],
    weak_predicted: List[Dict[str, Any]],
    failure_categories: Counter,
    weak_scorer_sources: Counter,
) -> List[str]:
    recommendations: List[str] = []
    if count == 0:
        recommendations.append("No analyst feedback exists yet; collect at least 5-10 reviewed predictions before tuning.")
    if missing_actual:
        recommendations.append("Some feedback lacks final_actual_next_tactic; add it when possible so backtests can consume the correction.")
    if high_confidence_wrong:
        recommendations.append("Review high-confidence wrong predictions before raising any scorer weights or enabling calibration.")
    if failure_categories.get("possible_classification_error"):
        recommendations.append("Review possible classification-error feedback before tuning prediction weights; bad TTP labels contaminate every tactic-dependent scorer.")
    if failure_categories.get("missing_local_transition_evidence"):
        recommendations.append("Some wrong predictions lacked local transition evidence; keep them prior-dominated until more completed local sessions exist.")
    if failure_categories.get("policy_rule_review"):
        recommendations.append("Policy-backed or heuristic scorers appear in wrong predictions; inspect rule provenance and references before increasing those weights.")
    if weak_scorer_sources:
        top_source = weak_scorer_sources.most_common(1)[0][0]
        recommendations.append(f"Most negative feedback touching scorer evidence currently involves '{top_source}'; inspect its reasons and source type.")
    if weak_predicted:
        recommendations.append("Inspect recurring weak predicted tactics and map failures to classification errors, scorer errors, or missing transition evidence.")
    if not recommendations:
        recommendations.append("Feedback volume and fields look usable for manual policy review.")
    return recommendations


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Summarize analyst prediction feedback.")
    parser.add_argument("--config", help="Path to production JSON config.")
    parser.add_argument("--database-url", help="Override DATABASE_URL.")
    parser.add_argument("--limit", type=int, default=1000, help="Maximum feedback rows to read.")
    return parser


def main(argv: List[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    config = ProductionConfig.from_env(args.config)
    if args.database_url:
        config.database_url = args.database_url
    storage = open_storage(config.database_url)
    review = build_feedback_review(storage.list_rows("analyst_feedback", limit=max(args.limit, 1)))
    print(json.dumps(review, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
