"""Read-only detection quality audit for command classification coverage.

This module does not add or tune mappings. It summarizes the current
classification policy, optional Cowrie event samples, and optional external seed
review/model artifacts so weak coverage is visible before policy changes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from production.classification.classification_evaluation import command_pattern
from production.classification.classification_pipeline import NotebookParityClassifier
from production.classification.normalize_main_ttps import main_ttp_id
from production.utils.serialization import utc_now


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _load_json_or_ndjson(path_text: str) -> List[Dict[str, Any]]:
    if not path_text:
        return []
    path = Path(path_text)
    if not path.exists():
        return []
    text = path.read_text(encoding="utf-8", errors="replace").strip()
    if not text:
        return []
    if text.startswith("["):
        loaded = json.loads(text)
        return [item for item in loaded if isinstance(item, dict)] if isinstance(loaded, list) else []
    if text.startswith("{"):
        try:
            loaded = json.loads(text)
        except json.JSONDecodeError:
            loaded = None
        if isinstance(loaded, dict):
            for key in ("review_records", "records", "cases", "review_cases"):
                values = loaded.get(key)
                if isinstance(values, list):
                    return [item for item in values if isinstance(item, dict)]
            return [loaded]
    rows: List[Dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            loaded = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(loaded, dict):
            rows.append(loaded)
    return rows


def _load_json(path_text: str) -> Dict[str, Any]:
    if not path_text:
        return {}
    path = Path(path_text)
    if not path.exists():
        return {}
    loaded = json.loads(path.read_text(encoding="utf-8"))
    return loaded if isinstance(loaded, dict) else {}


def _rules(policy: Dict[str, Any]) -> List[Dict[str, Any]]:
    body = policy.get("policy", policy)
    if not isinstance(body, dict):
        return []
    return [rule for rule in body.get("rules") or [] if isinstance(rule, dict)]


def _provenance(rule: Dict[str, Any]) -> Dict[str, Any]:
    provenance = rule.get("provenance")
    return provenance if isinstance(provenance, dict) else {}


def _command_hash(command: str) -> str:
    return hashlib.sha256(command.encode("utf-8", errors="replace")).hexdigest()


def _command_preview(command: str, limit: int = 160) -> str:
    text = " ".join(str(command or "").split())
    if len(text) <= limit:
        return text
    return text[: max(limit - 3, 1)] + "..."


def summarize_classification_policy(policy_path: str) -> Dict[str, Any]:
    policy = _load_json(policy_path)
    rules = _rules(policy)
    enabled = [rule for rule in rules if rule.get("enabled") is not False]
    source_counts = Counter(str(rule.get("source_type") or "unknown") for rule in enabled)
    evidence_counts = Counter(str(rule.get("evidence_type") or "unknown") for rule in enabled)
    confidence_counts = Counter(str(rule.get("confidence") or "unknown") for rule in enabled)
    ttps = [main_ttp_id(str(rule.get("ttp") or "").upper()) for rule in enabled if rule.get("ttp")]
    ttp_counts = Counter(ttps)

    unreviewed = []
    generated = 0
    broad_regex = []
    review_status_counts: Counter[str] = Counter()
    for rule in enabled:
        provenance = _provenance(rule)
        review_status_counts[str(provenance.get("review_status") or "missing")] += 1
        if provenance.get("generated") is True:
            generated += 1
        if provenance.get("reviewed") is not True:
            unreviewed.append(rule)
        pattern = str(rule.get("pattern") or "")
        if ".*" in pattern or ".+" in pattern or "\\S+" in pattern:
            broad_regex.append(rule)

    return {
        "policy_path": policy_path,
        "policy_id": policy.get("policy_id") or "",
        "version": policy.get("version") or "",
        "rule_review_mode": (policy.get("policy") or {}).get("rule_review_mode")
        if isinstance(policy.get("policy"), dict)
        else policy.get("rule_review_mode", ""),
        "total_rules": len(rules),
        "enabled_rules": len(enabled),
        "unique_main_ttps": len(set(ttps)),
        "source_type_counts": dict(sorted(source_counts.items())),
        "evidence_type_counts": dict(sorted(evidence_counts.items())),
        "confidence_counts": dict(sorted(confidence_counts.items())),
        "generated_rules": generated,
        "reviewed_rules": len(enabled) - len(unreviewed),
        "unreviewed_rules": len(unreviewed),
        "review_status_counts": dict(review_status_counts.most_common()),
        "unreviewed_rule_samples": [
            {
                "rule_id": rule.get("rule_id"),
                "ttp": rule.get("ttp"),
                "source_type": rule.get("source_type"),
                "method": _provenance(rule).get("method"),
                "review_status": _provenance(rule).get("review_status"),
                "review_deferred_reason": _provenance(rule).get("review_deferred_reason"),
            }
            for rule in unreviewed[:20]
        ],
        "rules_per_ttp_top": [
            {"ttp": ttp, "rule_count": count}
            for ttp, count in ttp_counts.most_common(15)
        ],
        "broad_regex_candidates": [
            {"rule_id": rule.get("rule_id"), "ttp": rule.get("ttp"), "pattern": rule.get("pattern")}
            for rule in broad_regex[:20]
        ],
    }


def _extract_commands(rows: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    commands: List[Dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        if row.get("commands"):
            session_id = str(row.get("session_id") or row.get("session") or "unknown")
            for index, command in enumerate(_as_list(row.get("commands"))):
                text = str(command or "").strip()
                if text:
                    commands.append({"session_id": session_id, "command": text, "command_index": index})
            continue
        eventid = str(row.get("eventid") or "")
        if not eventid.startswith("cowrie.command."):
            continue
        text = str(row.get("input") or row.get("command") or "").strip()
        if text:
            commands.append(
                {
                    "session_id": str(row.get("session") or row.get("session_id") or "unknown"),
                    "command": text,
                    "eventid": eventid,
                }
            )
    return commands


def summarize_commands(rows: Iterable[Dict[str, Any]], classifier: NotebookParityClassifier, limit: int = 5000) -> Dict[str, Any]:
    commands = _extract_commands(rows)[: max(limit, 1)]
    source_counts: Counter[str] = Counter()
    tactic_counts: Counter[str] = Counter()
    ttp_counts: Counter[str] = Counter()
    pattern_counts: Counter[str] = Counter()
    shell_noise: List[Dict[str, Any]] = []
    unknown: List[Dict[str, Any]] = []
    low_confidence: List[Dict[str, Any]] = []
    classified_command_count = 0
    fragment_count = 0
    missing_tactic_count = 0

    for item in commands:
        command = item["command"]
        outputs = classifier.classify(command)
        fragment_count += len(outputs)
        pattern_counts[command_pattern(command)] += 1
        accepted = False
        for output in outputs:
            source = str(output.get("source") or "unknown")
            tactic = str(output.get("tactic") or "unknown")
            ttp = str(output.get("ttp") or "")
            source_counts[source] += 1
            tactic_counts[tactic] += 1
            if ttp:
                ttp_counts[main_ttp_id(ttp)] += 1
                if tactic == "unknown":
                    missing_tactic_count += 1
            if source == "shell_noise":
                if len(shell_noise) < 20:
                    shell_noise.append({"command": command, "session_id": item.get("session_id")})
            elif not ttp:
                if len(unknown) < 20:
                    unknown.append(
                        {
                            "command": command,
                            "session_id": item.get("session_id"),
                            "source": source,
                            "confidence": output.get("confidence"),
                        }
                    )
            elif float(output.get("confidence") or 0.0) < classifier.high_confidence:
                if len(low_confidence) < 20:
                    low_confidence.append(
                        {
                            "command": command,
                            "session_id": item.get("session_id"),
                            "ttp": ttp,
                            "tactic": tactic,
                            "source": source,
                            "confidence": output.get("confidence"),
                        }
                    )
            else:
                accepted = True
        if accepted:
            classified_command_count += 1

    total = len(commands)
    return {
        "command_count": total,
        "classification_event_count": fragment_count,
        "classified_command_count": classified_command_count,
        "classified_command_rate": round(classified_command_count / total, 4) if total else 0.0,
        "missing_tactic_count": missing_tactic_count,
        "source_counts": dict(sorted(source_counts.items())),
        "tactic_counts": dict(tactic_counts.most_common()),
        "ttp_counts_top": [{"ttp": ttp, "count": count} for ttp, count in ttp_counts.most_common(20)],
        "command_pattern_counts": dict(pattern_counts.most_common()),
        "unknown_or_unclassified_samples": unknown,
        "shell_noise_samples": shell_noise,
        "low_confidence_samples": low_confidence,
    }


def summarize_external_model(path_text: str) -> Dict[str, Any]:
    model = _load_json(path_text)
    if not model:
        return {}
    quality = model.get("classification_quality") or (model.get("provenance") or {}).get("classification_quality") or {}
    warnings: List[str] = []
    acceptance = float(quality.get("acceptance_rate") or 0.0)
    low_confidence = float(quality.get("low_confidence_rate") or 0.0)
    disagreement = float(quality.get("disagreement_rate") or 0.0)
    if quality and acceptance < 0.5:
        warnings.append("External seed accepted less than half of raw command events; treat as conservative partial coverage.")
    if quality and low_confidence > 0.5:
        warnings.append("Most skipped external seed commands were low-confidence; use review queue before expanding labels.")
    if quality and disagreement > 0.02:
        warnings.append("Rule/SecureBERT disagreement is elevated; inspect disagreement samples before tuning.")
    return {
        "path": path_text,
        "model_id": model.get("model_id"),
        "source_type": model.get("source_type") or (model.get("provenance") or {}).get("source_type"),
        "completed_sessions": model.get("completed_sessions"),
        "usable_sessions": model.get("usable_sessions"),
        "transition_count": model.get("transition_count"),
        "classification_quality": quality,
        "warnings": warnings,
    }


def summarize_review_queue(path_text: str, limit: int = 20) -> Dict[str, Any]:
    rows = _load_json_or_ndjson(path_text)
    if not rows:
        return {}
    reason_counts = Counter(str(row.get("reason") or "unknown") for row in rows)
    command_counts = Counter(str(row.get("command") or "").strip() for row in rows if row.get("command"))
    output_source_counts: Counter[str] = Counter()
    suggested_ttps: Counter[str] = Counter()
    for row in rows:
        for output in _as_list(row.get("classifier_outputs")):
            if not isinstance(output, dict):
                continue
            output_source_counts[str(output.get("source") or "unknown")] += 1
            if output.get("ttp"):
                suggested_ttps[main_ttp_id(str(output.get("ttp")).upper())] += 1
    return {
        "path": path_text,
        "review_count": len(rows),
        "reason_counts": dict(reason_counts.most_common()),
        "output_source_counts": dict(output_source_counts.most_common()),
        "suggested_ttp_counts_top": [{"ttp": ttp, "count": count} for ttp, count in suggested_ttps.most_common(20)],
        "repeated_commands_top": [
            {
                "command_preview": _command_preview(command),
                "command_sha256": _command_hash(command),
                "count": count,
            }
            for command, count in command_counts.most_common(limit)
        ],
        "sample": rows[: min(limit, len(rows))],
    }


def build_detection_quality_audit(
    *,
    classification_policy_path: str,
    events_path: str = "",
    external_model_path: str = "",
    review_queue_path: str = "",
    limit: int = 5000,
) -> Dict[str, Any]:
    classifier = NotebookParityClassifier(rule_policy_path=classification_policy_path)
    policy_summary = summarize_classification_policy(classification_policy_path)
    command_summary = summarize_commands(_load_json_or_ndjson(events_path), classifier, limit=limit) if events_path else {}
    external_model = summarize_external_model(external_model_path) if external_model_path else {}
    review_queue = summarize_review_queue(review_queue_path) if review_queue_path else {}
    recommendations = [
        "Keep adding command mappings only through versioned classification policy files, not Python fallback tables.",
        "Review unreviewed classification rules before presenting them as validated labels.",
        "Use repeated unknown/low-confidence commands from the review queue as candidates for reviewed policy rules or future SecureBERT training data.",
        "Do not tune realtime prediction weights from labels produced only by weak or low-confidence command classification.",
    ]
    if external_model.get("warnings"):
        recommendations.append("Treat the external seed transition model as a cold-start prior until its skipped-command review queue is addressed.")
    return {
        "schema_version": "detection_quality_audit.v1",
        "generated_at": utc_now(),
        "classification_policy": policy_summary,
        "sample_command_classification": command_summary,
        "external_seed_model": external_model,
        "review_queue": review_queue,
        "recommendations": recommendations,
    }


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Audit detection/classification quality without changing mappings.")
    parser.add_argument("--classification-policy", default="configs/classification_rules.trusted.json")
    parser.add_argument("--events", default="", help="Optional Cowrie NDJSON or session-payload JSON/NDJSON file.")
    parser.add_argument("--external-model", default="", help="Optional external transition model JSON.")
    parser.add_argument("--review-queue", default="", help="Optional external/classification review queue JSON/NDJSON.")
    parser.add_argument("--limit", type=int, default=5000)
    parser.add_argument("--json", action="store_true")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    audit = build_detection_quality_audit(
        classification_policy_path=args.classification_policy,
        events_path=args.events,
        external_model_path=args.external_model,
        review_queue_path=args.review_queue,
        limit=args.limit,
    )
    print(json.dumps(audit, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
