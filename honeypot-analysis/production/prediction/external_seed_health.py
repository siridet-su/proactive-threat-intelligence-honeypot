"""Summarize external Cowrie seed model and classifier health.

The realtime predictor treats external Cowrie data as a cold-start prior. This
module turns the model, holdout validation, and review queue artifacts into a
small summary that can be shown in APIs/monitors without loading the large
review queue on every page refresh.
"""

from __future__ import annotations

import argparse
import json
import os
import re
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

from production.utils.serialization import utc_now


DEFAULT_HEALTH_NAME = "external_seed_health.compound_securebert.json"
DEFAULT_VALIDATION_NAME = "external_seed_validation.compound_securebert.full_all.json"
DEFAULT_REVIEW_NAME = "external_seed_review_queue.compound_securebert.json"


def _load_json(path_text: str) -> Dict[str, Any]:
    if not path_text:
        return {}
    path = Path(path_text)
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as handle:
        loaded = json.load(handle)
    return loaded if isinstance(loaded, dict) else {}


def _round(value: Any, digits: int = 4) -> Any:
    try:
        return round(float(value), digits)
    except (TypeError, ValueError):
        return value


def _positive_int(value: Any) -> int:
    try:
        return max(0, int(float(value)))
    except (TypeError, ValueError):
        return 0


def _top_items(counter: Counter[str], limit: int) -> list[Dict[str, Any]]:
    return [{"value": _short_text(_redact_command(value)), "count": count} for value, count in counter.most_common(limit)]


def _short_text(value: Any, limit: int = 180) -> str:
    text = str(value or "")
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "..."


def _redact_command(value: Any) -> str:
    text = str(value or "")
    text = re.sub(r"(?i)\b(root|admin|ubuntu|oracle|test|user):[^\"'\s|;]+", r"\1:[REDACTED]", text)
    text = re.sub(r"(?i)(password\s*[=:]\s*)[^\"'\s|;]+", r"\1[REDACTED]", text)
    return text


def infer_external_seed_paths(
    policy: Optional[Dict[str, Any]] = None,
    *,
    environ: Optional[Dict[str, str]] = None,
) -> Dict[str, str]:
    """Infer model/validation/review/health artifact paths from policy and env."""

    env = environ if environ is not None else os.environ
    policy = policy or {}
    model_path = (
        env.get("EXTERNAL_SEED_MODEL_PATH")
        or str(policy.get("external_transition_model_path") or "").strip()
    )
    base_dir = Path(model_path).parent if model_path else Path("data/models")
    return {
        "model": model_path,
        "validation": env.get("EXTERNAL_SEED_VALIDATION_PATH") or str(base_dir / DEFAULT_VALIDATION_NAME),
        "review": env.get("EXTERNAL_SEED_REVIEW_PATH") or str(base_dir / DEFAULT_REVIEW_NAME),
        "health": env.get("EXTERNAL_SEED_HEALTH_PATH") or str(base_dir / DEFAULT_HEALTH_NAME),
    }


def _summarize_review_queue(review: Dict[str, Any], *, limit: int = 12) -> Dict[str, Any]:
    records = review.get("review_records")
    if not isinstance(records, list):
        records = []

    reason_counts: Counter[str] = Counter()
    command_counts_by_reason: Dict[str, Counter[str]] = {}
    for record in records:
        if not isinstance(record, dict):
            continue
        reason = str(record.get("reason") or "unknown")
        command = str(record.get("command") or "").strip()
        reason_counts[reason] += 1
        if command:
            command_counts_by_reason.setdefault(reason, Counter())[command] += 1

    top_commands_by_reason = {
        reason: _top_items(counter, limit)
        for reason, counter in sorted(command_counts_by_reason.items())
    }
    return {
        "generated_at": review.get("generated_at") or "",
        "review_count": _positive_int(review.get("review_count") or len(records)),
        "reason_counts": dict(reason_counts),
        "top_commands_by_reason": top_commands_by_reason,
    }


def _validation_metrics(validation: Dict[str, Any]) -> Dict[str, Any]:
    metrics = validation.get("metrics") or {}
    return {
        "generated_at": validation.get("generated_at") or "",
        "completed_sessions": _positive_int(validation.get("completed_sessions")),
        "evaluated_sessions": _positive_int(validation.get("evaluated_sessions")),
        "total_cases": _positive_int(metrics.get("total_cases")),
        "predicted_cases": _positive_int(metrics.get("predicted_cases")),
        "coverage": _round(metrics.get("coverage", 0.0)),
        "top1_accuracy": _round(metrics.get("top1_accuracy", 0.0)),
        "top3_accuracy": _round(metrics.get("top3_accuracy", 0.0)),
        "mean_reciprocal_rank": _round(metrics.get("mean_reciprocal_rank", 0.0)),
        "scorer_disagreement_rate": _round(metrics.get("scorer_disagreement_rate", 0.0)),
        "recommendation": validation.get("recommendation") or "",
        "interpretation": validation.get("interpretation") or "",
        "accuracy_by_tactic": validation.get("accuracy_by_tactic") or {},
        "calibration": validation.get("calibration") or validation.get("confidence_label_calibration") or {},
    }


def _classification_quality(model: Dict[str, Any]) -> Dict[str, Any]:
    quality = model.get("classification_quality") or (model.get("provenance") or {}).get("classification_quality") or {}
    raw = _positive_int(quality.get("raw_command_events"))
    accepted_commands = _positive_int(quality.get("accepted_command_events"))
    accepted_classifications = _positive_int(quality.get("accepted_classification_events"))
    unused = max(0, raw - accepted_commands) if raw else 0
    return {
        "raw_command_events": raw,
        "accepted_command_events": accepted_commands,
        "accepted_classification_events": accepted_classifications,
        "unused_command_events": unused,
        "acceptance_rate": _round(quality.get("acceptance_rate", (accepted_commands / raw) if raw else 0.0)),
        "min_label_confidence": _round(quality.get("min_label_confidence", 0.0)),
        "low_confidence_commands_skipped": _positive_int(quality.get("low_confidence_commands_skipped")),
        "low_confidence_rate": _round(quality.get("low_confidence_rate", 0.0)),
        "noise_commands_skipped": _positive_int(quality.get("noise_commands_skipped")),
        "shell_noise_rate": _round(quality.get("shell_noise_rate", 0.0)),
        "disagreement_commands_skipped": _positive_int(quality.get("disagreement_commands_skipped")),
        "disagreement_rate": _round(quality.get("disagreement_rate", 0.0)),
        "unknown_commands_skipped": _positive_int(quality.get("unknown_commands_skipped")),
        "unknown_rate": _round(quality.get("unknown_rate", 0.0)),
        "source_counts": quality.get("source_counts") or {},
        "securebert_invocations": _positive_int(quality.get("securebert_invocations")),
        "securebert_cache_hits": _positive_int(quality.get("securebert_cache_hits")),
        "unique_classification_cache_entries": _positive_int(quality.get("unique_classification_cache_entries")),
    }


def _model_summary(model: Dict[str, Any], model_path: str) -> Dict[str, Any]:
    provenance = model.get("provenance") or {}
    return {
        "path": model_path,
        "schema_version": model.get("schema_version") or "",
        "model_id": model.get("model_id") or "",
        "built_at": model.get("built_at") or provenance.get("built_at") or "",
        "dataset_handle": model.get("dataset_handle") or provenance.get("dataset_handle") or "",
        "source_type": model.get("source_type") or provenance.get("source_type") or "",
        "training_source": model.get("training_source") or provenance.get("training_source") or "",
        "classifier": provenance.get("classifier") or "",
        "securebert_used": bool(provenance.get("securebert_used")),
        "securebert_scope": provenance.get("securebert_scope") or "",
        "securebert_source": provenance.get("securebert_source") or "",
        "completed_sessions": _positive_int(model.get("completed_sessions") or provenance.get("closed_sessions")),
        "usable_sessions": _positive_int(model.get("usable_sessions")),
        "transition_count": _round(model.get("transition_count", 0.0)),
        "prefix_transition_count": _round(model.get("prefix_transition_count", 0.0)),
        "technique_transition_count": _round(model.get("technique_transition_count", 0.0)),
        "tactic_transition_count": _round(model.get("tactic_transition_count", 0.0)),
        "prefix_max_length": _positive_int(model.get("prefix_max_length")),
    }


def _build_warnings(
    quality: Dict[str, Any],
    validation: Dict[str, Any],
    review: Dict[str, Any],
) -> list[str]:
    warnings: list[str] = []
    if not quality.get("raw_command_events"):
        warnings.append("External seed classifier quality metrics are missing.")
    elif float(quality.get("acceptance_rate") or 0.0) < 0.25:
        warnings.append("Most external seed commands were not trusted enough to enter the transition model.")
    if float(quality.get("low_confidence_rate") or 0.0) > 0.5:
        warnings.append("Low-confidence SecureBERT/rule outputs dominate the unused command pool.")
    if validation.get("total_cases", 0) and float(validation.get("top1_accuracy") or 0.0) < 0.6:
        warnings.append("External seed top-1 accuracy is weak; keep external seed weight low.")
    if validation.get("total_cases", 0) and float(validation.get("top3_accuracy") or 0.0) >= 0.7:
        warnings.append("External seed top-3 accuracy is useful as a cold-start prior, not local proof.")
    medium = (validation.get("calibration") or {}).get("medium") or {}
    if medium.get("cases") and float(medium.get("top1_accuracy") or 0.0) < 0.2:
        warnings.append("Medium-confidence external seed predictions validated poorly; do not promote calibration from this seed alone.")
    if review.get("review_count"):
        warnings.append("Review queue exists for skipped commands; these are candidates for future classifier improvement.")
    return warnings


def build_external_seed_health(
    *,
    model_path: str,
    validation_path: str = "",
    review_path: str = "",
    include_review: bool = True,
) -> Dict[str, Any]:
    """Build a compact, public-safe external seed health document."""

    model = _load_json(model_path)
    validation_doc = _load_json(validation_path)
    review_doc = _load_json(review_path) if include_review and review_path else {}

    quality = _classification_quality(model)
    validation = _validation_metrics(validation_doc)
    review = _summarize_review_queue(review_doc) if review_doc else {
        "generated_at": "",
        "review_count": 0,
        "reason_counts": {},
        "top_commands_by_reason": {},
    }
    paths = {
        "model": model_path,
        "validation": validation_path,
        "review": review_path if include_review else "",
    }
    available = bool(model)
    return {
        "schema_version": "external_seed_health.v1",
        "generated_at": utc_now(),
        "available": available,
        "paths": paths,
        "model": _model_summary(model, model_path),
        "classification_quality": quality,
        "validation": validation,
        "review_queue": review,
        "warnings": _build_warnings(quality, validation, review),
    }


def load_external_seed_health(
    health_path: str,
    *,
    model_path: str = "",
    validation_path: str = "",
    review_path: str = "",
    include_review: bool = False,
) -> Dict[str, Any]:
    """Load a precomputed health file, or build a lightweight fallback."""

    health = _load_json(health_path)
    if health:
        return health
    if not model_path:
        return {
            "schema_version": "external_seed_health.v1",
            "generated_at": utc_now(),
            "available": False,
            "paths": {"health": health_path, "model": model_path, "validation": validation_path, "review": review_path},
            "warnings": ["External seed health artifact is missing and no model path is configured."],
        }
    return build_external_seed_health(
        model_path=model_path,
        validation_path=validation_path,
        review_path=review_path,
        include_review=include_review,
    )


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Summarize external seed transition model health.")
    parser.add_argument("--model", required=True, help="Path to external seed transition model JSON.")
    parser.add_argument("--validation", default="", help="Path to external seed validation JSON.")
    parser.add_argument("--review", default="", help="Path to external seed review queue JSON.")
    parser.add_argument("--output", default="", help="Optional output path for compact health JSON.")
    parser.add_argument("--no-review", action="store_true", help="Do not read the review queue.")
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    health = build_external_seed_health(
        model_path=args.model,
        validation_path=args.validation,
        review_path=args.review,
        include_review=not args.no_review,
    )
    text = json.dumps(health, indent=2, sort_keys=True)
    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
