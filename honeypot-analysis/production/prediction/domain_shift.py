"""Domain-shift analysis for local and external transition models.

The external Cowrie seed is an empirical prior, but it is trained outside the
deployment environment. This module compares its transition distributions with
the local honeypot transition model so the thesis can discuss domain shift
quantitatively instead of treating the external prior as local ground truth.

Jensen-Shannon divergence is reported as the primary metric because it is
symmetric and bounded when using base-2 logarithms. Directional KL divergence is
also reported with additive smoothing for readers who expect KL-style language.
"""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple


TRANSITION_SECTIONS = {
    "tactic_transitions": "transitions",
    "prefix_transitions": "prefix_transitions",
    "technique_transitions": "technique_transitions",
}


def _safe_float(value: Any) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0.0
    if not math.isfinite(number) or number < 0:
        return 0.0
    return number


def _nested_counts(model: Dict[str, Any], field: str) -> Dict[str, Dict[str, float]]:
    raw = model.get(field) or {}
    if not isinstance(raw, dict):
        return {}
    result: Dict[str, Dict[str, float]] = {}
    for context, targets in raw.items():
        if not isinstance(targets, dict):
            continue
        clean_targets = {
            str(target): _safe_float(count)
            for target, count in targets.items()
            if str(target) and _safe_float(count) > 0.0
        }
        if clean_targets:
            result[str(context)] = clean_targets
    return result


def _distribution(counts: Dict[str, float], universe: Iterable[str], smoothing: float) -> Dict[str, float]:
    keys = sorted({str(key) for key in universe if str(key)})
    if not keys:
        return {}
    smoothed = {key: _safe_float(counts.get(key)) + smoothing for key in keys}
    total = sum(smoothed.values())
    if total <= 0.0:
        return {key: 1.0 / len(keys) for key in keys}
    return {key: value / total for key, value in smoothed.items()}


def _kl(p: Dict[str, float], q: Dict[str, float]) -> float:
    total = 0.0
    for key, p_value in p.items():
        q_value = q.get(key, 0.0)
        if p_value > 0.0 and q_value > 0.0:
            total += p_value * math.log2(p_value / q_value)
    return total


def _js(p: Dict[str, float], q: Dict[str, float]) -> float:
    keys = sorted(set(p).union(q))
    if not keys:
        return 0.0
    midpoint = {key: (p.get(key, 0.0) + q.get(key, 0.0)) / 2.0 for key in keys}
    return 0.5 * _kl(p, midpoint) + 0.5 * _kl(q, midpoint)


def _metrics(local_counts: Dict[str, float], external_counts: Dict[str, float], smoothing: float) -> Dict[str, float]:
    keys = sorted(set(local_counts).union(external_counts))
    local_distribution = _distribution(local_counts, keys, smoothing)
    external_distribution = _distribution(external_counts, keys, smoothing)
    return {
        "jensen_shannon_divergence": round(_js(local_distribution, external_distribution), 6),
        "kl_local_to_external": round(_kl(local_distribution, external_distribution), 6),
        "kl_external_to_local": round(_kl(external_distribution, local_distribution), 6),
    }


def _flatten_edges(section: Dict[str, Dict[str, float]]) -> Dict[str, float]:
    edges: Dict[str, float] = {}
    for context, targets in section.items():
        for target, count in targets.items():
            edges[f"{context}->{target}"] = edges.get(f"{context}->{target}", 0.0) + _safe_float(count)
    return edges


def _compare_section(
    local_section: Dict[str, Dict[str, float]],
    external_section: Dict[str, Dict[str, float]],
    smoothing: float,
) -> Dict[str, Any]:
    contexts = sorted(set(local_section).union(external_section))
    context_rows: List[Dict[str, Any]] = []
    for context in contexts:
        local_counts = local_section.get(context, {})
        external_counts = external_section.get(context, {})
        row = {
            "context": context,
            "local_support": round(sum(local_counts.values()), 4),
            "external_support": round(sum(external_counts.values()), 4),
            "target_count": len(set(local_counts).union(external_counts)),
        }
        row.update(_metrics(local_counts, external_counts, smoothing))
        context_rows.append(row)

    overall = _metrics(_flatten_edges(local_section), _flatten_edges(external_section), smoothing)
    overall.update(
        {
            "local_support": round(sum(sum(targets.values()) for targets in local_section.values()), 4),
            "external_support": round(sum(sum(targets.values()) for targets in external_section.values()), 4),
            "context_count": len(contexts),
        }
    )
    return {
        "overall": overall,
        "contexts": context_rows,
    }


def _model_summary(model: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "schema_version": model.get("schema_version"),
        "source_name": model.get("source_name") or model.get("source_type"),
        "model_id": model.get("model_id"),
        "built_at": model.get("built_at"),
        "completed_sessions": model.get("completed_sessions", 0),
        "usable_sessions": model.get("usable_sessions", 0),
        "transition_count": model.get("transition_count", 0),
        "prefix_transition_count": model.get("prefix_transition_count", 0),
        "technique_transition_count": model.get("technique_transition_count", 0),
    }


def compare_transition_domain_shift(
    local_model: Dict[str, Any],
    external_model: Dict[str, Any],
    smoothing: float = 1e-6,
) -> Dict[str, Any]:
    """Compare local and external transition distributions.

    The result is intended for offline evaluation and thesis reporting. It does
    not recommend or apply production weight changes.
    """

    smooth = max(_safe_float(smoothing), 1e-12)
    sections = {
        name: _compare_section(
            _nested_counts(local_model, field),
            _nested_counts(external_model, field),
            smooth,
        )
        for name, field in TRANSITION_SECTIONS.items()
    }
    return {
        "schema_version": "transition_domain_shift.v1",
        "metric_notes": {
            "primary_metric": "jensen_shannon_divergence",
            "log_base": 2,
            "smoothing": smooth,
            "interpretation": (
                "Higher divergence means the external seed transition distribution "
                "differs more from the local honeypot distribution. This is a "
                "domain-shift diagnostic, not an automatic weight calibration."
            ),
        },
        "local_model": _model_summary(local_model),
        "external_model": _model_summary(external_model),
        "sections": sections,
    }


def load_transition_model(path: str | Path) -> Dict[str, Any]:
    with Path(path).open("r", encoding="utf-8") as f:
        loaded = json.load(f)
    if not isinstance(loaded, dict):
        raise ValueError("transition model file must contain a JSON object")
    if isinstance(loaded.get("model"), dict):
        return loaded["model"]
    return loaded


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compare local and external transition-model domain shift.")
    parser.add_argument("--local-model", required=True, help="Path to the local transition model JSON.")
    parser.add_argument("--external-model", required=True, help="Path to the external seed transition model JSON.")
    parser.add_argument("--smoothing", type=float, default=1e-6, help="Additive smoothing for KL/JSD metrics.")
    parser.add_argument("--output", help="Optional path to write the JSON report.")
    args = parser.parse_args(argv)

    report = compare_transition_domain_shift(
        load_transition_model(args.local_model),
        load_transition_model(args.external_model),
        smoothing=args.smoothing,
    )
    payload = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        Path(args.output).write_text(payload + "\n", encoding="utf-8")
    else:
        print(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
