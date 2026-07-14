"""Validate an external Cowrie seed transition corpus before trusting it.

This command evaluates whether a candidate external Cowrie seed dataset is
useful for next-step prediction. It expects already-sessionized payloads
compatible with `build_transition_model()` and `prediction_backtest`.

The important output is not "can this dataset build a model?" but "when we
hold out the next tactic in completed seed sessions, how often does a transition
model trained on the rest rank that tactic in the top 1/top 3?"
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List

from production.utils.config import ProductionConfig
from production.prediction.prediction_backtest import backtest_sessions
from production.utils.serialization import stable_id, utc_now
from production.storage import open_storage


def _decode_payload(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        if isinstance(value.get("payload"), dict):
            return dict(value["payload"])
        if isinstance(value.get("payload_json"), str):
            try:
                loaded = json.loads(value["payload_json"])
            except json.JSONDecodeError:
                return {}
            return loaded if isinstance(loaded, dict) else {}
        return dict(value)
    return {}


def load_seed_document(path: str, limit: int = 1000) -> Dict[str, Any]:
    source = Path(path)
    if not source.exists():
        raise FileNotFoundError(f"external seed validation input not found: {source}")
    payloads: List[Dict[str, Any]] = []
    provenance: Dict[str, Any] = {}
    source_quality: Dict[str, Any] = {}
    suffix = source.suffix.lower()
    if suffix in {".ndjson", ".jsonl"}:
        with source.open("r", encoding="utf-8") as f:
            for line in f:
                if len(payloads) >= limit:
                    break
                text = line.strip()
                if not text:
                    continue
                try:
                    payload = _decode_payload(json.loads(text))
                except json.JSONDecodeError:
                    continue
                if payload:
                    payloads.append(payload)
        return {"payloads": payloads, "provenance": provenance, "source_quality": source_quality}

    with source.open("r", encoding="utf-8") as f:
        loaded = json.load(f)
    if isinstance(loaded, dict):
        provenance = loaded.get("provenance") if isinstance(loaded.get("provenance"), dict) else {}
        source_quality = (
            loaded.get("classification_quality")
            if isinstance(loaded.get("classification_quality"), dict)
            else provenance.get("classification_quality")
            if isinstance(provenance.get("classification_quality"), dict)
            else {}
        )
        candidates = (
            loaded.get("sessions")
            or loaded.get("items")
            or loaded.get("payloads")
            or loaded.get("data")
            or []
        )
        if isinstance(candidates, dict):
            candidates = list(candidates.values())
    elif isinstance(loaded, list):
        candidates = loaded
    else:
        candidates = []
    for item in candidates:
        if len(payloads) >= limit:
            break
        payload = _decode_payload(item)
        if payload:
            payloads.append(payload)
    return {"payloads": payloads, "provenance": provenance, "source_quality": source_quality}


def load_seed_payloads(path: str, limit: int = 1000) -> List[Dict[str, Any]]:
    return list(load_seed_document(path, limit=limit).get("payloads") or [])


def validate_external_seed_payloads(
    payloads: Iterable[Dict[str, Any]],
    policy: Dict[str, Any] | None = None,
    include_cases: bool = False,
    max_cases: int = 50,
) -> Dict[str, Any]:
    validation_policy = dict(policy or {})
    weights = {
        "local_transition": 1.0,
        "external_seed_transition": 0.0,
        "fallback_progression": 0.0,
        "tactic_combination": 0.0,
        "mitre_association": 0.0,
        "sigma_correlation": 0.0,
        "enrichment_context": 0.0,
        "vulnerability_risk": 0.0,
    }
    validation_policy.update(
        {
            "min_sessions_for_local": 1,
            "min_transition_count": 1,
            "min_prefix_transition_count": 1,
            "min_technique_transition_count": 1,
            "min_tactic_transition_count": 1,
            "min_active_scorers": 1,
            "weights": weights,
            "maturity": {"cold_confidence_cap": ""},
        }
    )
    result = backtest_sessions(
        list(payloads),
        policy=validation_policy,
        leave_one_out=True,
        include_cases=include_cases,
        max_cases=max_cases,
    )
    metrics = result.get("metrics") or {}
    top3 = float(metrics.get("top3_accuracy") or 0.0)
    if top3 >= 0.70:
        recommendation = "seed_model_weight_can_be_moderate"
    elif top3 >= 0.50:
        recommendation = "seed_model_weight_should_be_conservative"
    else:
        recommendation = "seed_model_weight_should_be_low"
    result.update(
        {
            "schema_version": "external_seed_validation.v1",
            "generated_at": utc_now(),
            "recommendation": recommendation,
            "interpretation": (
                "This validates external seed transition usefulness only. It does not prove "
                "that local attackers will follow the same distribution."
            ),
        }
    )
    result["run_id"] = stable_id(
        "extseedvalidation",
        {
            "generated_at": result["generated_at"],
            "metrics": metrics,
            "recommendation": recommendation,
        },
    )
    return result


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate an external Cowrie seed transition corpus.")
    parser.add_argument("--config", help="Path to production JSON config.")
    parser.add_argument("--database-url", help="Override DATABASE_URL when --save is used.")
    parser.add_argument("--input", required=True, help="JSON/NDJSON file containing session payloads.")
    parser.add_argument("--limit", type=int, default=1000, help="Maximum seed sessions to load.")
    parser.add_argument("--include-cases", action="store_true", help="Include example validation cases.")
    parser.add_argument("--max-cases", type=int, default=50, help="Maximum case details when --include-cases is set.")
    parser.add_argument("--output", help="Optional path to write the validation JSON.")
    parser.add_argument("--save", action="store_true", help="Store result in prediction_backtest_runs.")
    return parser


def main(argv: List[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    config = ProductionConfig.from_env(args.config)
    if args.database_url:
        config.database_url = args.database_url
    seed_document = load_seed_document(args.input, limit=max(args.limit, 1))
    payloads = list(seed_document.get("payloads") or [])
    result = validate_external_seed_payloads(
        payloads,
        policy=config.prediction_policy,
        include_cases=args.include_cases,
        max_cases=max(args.max_cases, 1),
    )
    result["source"] = {"input": args.input, "loaded_sessions": len(payloads)}
    if seed_document.get("source_quality"):
        result["source"]["classification_quality"] = seed_document["source_quality"]
    if seed_document.get("provenance"):
        result["source"]["provenance"] = seed_document["provenance"]
    if args.save:
        storage = open_storage(config.database_url)
        storage.initialize()
        result["run_id"] = storage.save_prediction_backtest_run(result)
    text = json.dumps(result, indent=2, sort_keys=True)
    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
