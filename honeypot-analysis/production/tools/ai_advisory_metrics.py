"""Export aggregate, non-sensitive Hybrid AI evaluation counters."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from typing import Any, Dict, Iterable, List, Mapping, Optional

from production.storage import open_storage
from production.utils.config import ProductionConfig
from production.utils.serialization import utc_now


def _rate(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 6) if denominator else 0.0


def summarize_ai_advisory_metrics(
    rows: Iterable[Mapping[str, Any]],
    outbox_rows: Iterable[Mapping[str, Any]] = (),
) -> Dict[str, Any]:
    """Summarize persisted counters without exporting sessions or AI content."""

    items = list(rows)
    outbox_items = list(outbox_rows)
    statuses: Counter[str] = Counter()
    reasons: Counter[str] = Counter()
    provider_models: Counter[str] = Counter()
    totals = Counter()
    for row in items:
        status = str(row.get("status") or "unknown")
        statuses[status] += 1
        provider_models[
            f"{str(row.get('provider_id') or 'unknown')}:{str(row.get('model_id') or 'unknown')}"
        ] += 1
        metrics = row.get("metrics")
        if not isinstance(metrics, Mapping):
            try:
                metrics = json.loads(str(row.get("metrics_json") or "{}"))
            except (TypeError, json.JSONDecodeError):
                metrics = {}
        reason = str(metrics.get("validator_reason_code") or "")
        if reason:
            reasons[reason] += 1
        totals["schema_valid"] += int(metrics.get("schema_valid") is True)
        totals["validator_accepted"] += int(metrics.get("validator_accepted") is True)
        totals["abstained"] += int(metrics.get("abstained") is True)
        totals["cache_hit"] += int(metrics.get("cache_hit") is True)
        totals["selected_findings"] += int(metrics.get("selected_finding_count") or 0)
        totals["selected_relationships"] += int(metrics.get("selected_relationship_count") or 0)
        totals["selected_actions"] += int(metrics.get("selected_action_count") or 0)
        totals["shadow_candidates"] += int(metrics.get("shadow_candidate_count") or 0)
        totals["shadow_evidence_references"] += int(
            metrics.get("shadow_evidence_reference_count") or 0
        )
    count = len(items)
    rejected = count - totals["validator_accepted"]
    invented = reasons.get("invented_reference", 0)
    prohibited = reasons.get("prohibited_field", 0)
    outbox_statuses = Counter(str(row.get("status") or "unknown") for row in outbox_items)
    outbox_failures = Counter(
        str(row.get("last_error_code") or "")
        for row in outbox_items
        if str(row.get("last_error_code") or "")
    )
    cache_replays = sum(
        str(row.get("completion_code") or "") == "cache_replayed"
        for row in outbox_items
    )
    completed_outbox = sum(
        str(row.get("status") or "") == "succeeded" for row in outbox_items
    )
    return {
        "schema_version": "ai_advisory_evaluation_metrics.v1",
        "record_count": count,
        "outbox_record_count": len(outbox_items),
        "status_counts": dict(sorted(statuses.items())),
        "outbox_status_counts": dict(sorted(outbox_statuses.items())),
        "outbox_failure_code_counts": dict(sorted(outbox_failures.items())),
        "provider_model_counts": dict(sorted(provider_models.items())),
        "validator_reason_counts": dict(sorted(reasons.items())),
        "rates": {
            "schema_valid_rate": _rate(totals["schema_valid"], count),
            "validator_accept_rate": _rate(totals["validator_accepted"], count),
            "validator_rejection_rate": _rate(rejected, count),
            "invented_reference_rate": _rate(invented, count),
            "prohibited_field_rate": _rate(prohibited, count),
            "abstention_rate": _rate(totals["abstained"], count),
            "cache_hit_rate": (
                _rate(cache_replays, completed_outbox)
                if outbox_items
                else _rate(totals["cache_hit"], count)
            ),
        },
        "selection_totals": {
            "findings": totals["selected_findings"],
            "relationships": totals["selected_relationships"],
            "actions": totals["selected_actions"],
            "shadow_candidates": totals["shadow_candidates"],
            "shadow_evidence_references": totals["shadow_evidence_references"],
        },
        "interpretation": (
            "Aggregate structural metrics only. They do not establish analyst "
            "usefulness, semantic correctness, or improvement over deterministic-only output."
        ),
    }


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Export non-sensitive AI advisory evaluation metrics."
    )
    parser.add_argument("--config", help="Path to production JSON config.")
    parser.add_argument("--limit", type=int, default=10_000)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    config = ProductionConfig.from_env(args.config)
    storage = open_storage(config.database_url)
    rows = storage.list_rows(
        "ai_advisories", limit=min(max(int(args.limit), 1), 100_000)
    )
    outbox_rows = storage.list_rows(
        "ai_advisory_outbox", limit=min(max(int(args.limit), 1), 100_000)
    )
    result = summarize_ai_advisory_metrics(rows, outbox_rows)
    result["generated_at"] = utc_now()
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
