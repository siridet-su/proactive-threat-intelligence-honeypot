"""Classification validation workflow for Cowrie command labels.

This module deliberately evaluates the observed-command classifier, not the
next-step prediction engine. The output is meant to answer whether the
classification layer is trustworthy enough for realtime prediction to consume.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from typing import Any, Dict, Iterable, List, Optional

from production.enrichment.mitre_attack_loader import load_mitre_attack_db

from production.classification.classification_pipeline import NotebookParityClassifier
from production.utils.config import ProductionConfig
from production.classification.securebert_classifier import load_securebert_classifier
from production.utils.serialization import stable_id, stable_json, utc_now
from production.storage import open_storage
from production.storage.session_provenance import (
    SESSION_SOURCE_PRODUCTION_LIVE,
    normalize_session_source,
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


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def command_pattern(command: str) -> str:
    text = str(command or "").strip().lower()
    if not text:
        return "empty"
    if text in {"sh", "bash", "/bin/sh", "/bin/bash"}:
        return "shell_noise"
    if re.search(r"\b(wget|curl|tftp|ftp)\b", text):
        return "downloader"
    if any(token in text for token in ("/etc/passwd", "/etc/shadow", "id_rsa", "authorized_keys")):
        return "credential_file"
    if any(token in text for token in ("history -c", "rm -rf /var/log", "auth.log", "wtmp", "utmp")):
        return "cleanup"
    if re.search(r"\b(whoami|uname|id|hostname|ifconfig|ip addr|ps |netstat|ss )\b", text):
        return "discovery_basic"
    if any(token in text for token in ("chmod +x", "bash ", "python ", "perl ", "sh ")):
        return "execution"
    return "other"


def _stored_event_for_command(payload: Dict[str, Any], command: str, command_index: int) -> Dict[str, Any]:
    matches = [
        event
        for event in _as_list(payload.get("classification_events"))
        if isinstance(event, dict) and str(event.get("command") or "").strip() == command
    ]
    if command_index < len(matches):
        return dict(matches[command_index])
    return dict(matches[0]) if matches else {}


def _best_prediction(predictions: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not predictions:
        return {}
    return max(
        predictions,
        key=lambda item: float(item.get("confidence") or 0.0),
    )


def collect_review_cases(
    session_payloads: Iterable[Dict[str, Any]],
    classifier: NotebookParityClassifier,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    cases: List[Dict[str, Any]] = []
    for payload in session_payloads:
        if not isinstance(payload, dict):
            continue
        session_id = str(payload.get("session_id") or "unknown")
        command_counts: Dict[str, int] = {}
        for index, command_raw in enumerate(_as_list(payload.get("commands"))):
            command = str(command_raw or "").strip()
            if not command:
                continue
            command_counts[command] = command_counts.get(command, 0) + 1
            local_command_index = command_counts[command] - 1
            predictions = classifier.classify(command)
            predicted = _best_prediction(predictions)
            stored = _stored_event_for_command(payload, command, local_command_index)
            case = {
                "review_id": stable_id("classreview", {"session_id": session_id, "index": index, "command": command}),
                "session_id": session_id,
                "src_ip": payload.get("src_ip") or "",
                "sensor": payload.get("sensor") or "",
                "command_index": index,
                "command": command,
                "command_pattern": command_pattern(command),
                "predicted_ttp": predicted.get("ttp"),
                "predicted_tactic": predicted.get("tactic"),
                "predicted_source": predicted.get("source"),
                "predicted_confidence": predicted.get("confidence"),
                "classifier_outputs": predictions,
                "stored_ttp": stored.get("ttp"),
                "stored_tactic": stored.get("tactic"),
                "stored_source": stored.get("source"),
                "stored_confidence": stored.get("confidence"),
                "reviewed_ttp": "",
                "reviewed_tactic": "",
                "reviewer": "",
                "notes": "",
            }
            cases.append(case)
            if len(cases) >= limit:
                return cases
    return cases


def load_session_payloads(
    config: ProductionConfig,
    limit: int = 1000,
    session_source: str | None = SESSION_SOURCE_PRODUCTION_LIVE,
    external_only: bool = True,
) -> List[Dict[str, Any]]:
    storage = open_storage(config.database_url)
    if hasattr(storage, "list_session_rows"):
        rows = storage.list_session_rows(limit=limit, session_source=session_source, external_only=external_only)
    else:
        rows = storage.list_rows("sessions", limit=limit)
    payloads: List[Dict[str, Any]] = []
    for row in rows:
        payload = _decode_payload(row)
        if payload:
            payload.setdefault("session_source", row.get("session_source") or session_source)
            payload.setdefault("is_external_source", bool(row.get("is_external_source")))
            payloads.append(payload)
    return payloads


def load_review_labels(path: str) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        content = f.read().strip()
    if not content:
        return []
    if content.startswith("["):
        parsed = json.loads(content)
        return [dict(item) for item in parsed if isinstance(item, dict)]
    labels = []
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        parsed = json.loads(line)
        if isinstance(parsed, dict):
            labels.append(parsed)
    return labels


def import_review_labels(storage: Any, labels: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    stored_ids: List[str] = []
    for label in labels:
        if not isinstance(label, dict):
            continue
        stored_ids.append(storage.record_classification_review_label(label))
    return {
        "imported": len(stored_ids),
        "label_ids": stored_ids,
        "timestamp": utc_now(),
    }


def _float_value(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _auto_validation_decision(case: Dict[str, Any], min_confidence: float = 0.90) -> Dict[str, Any]:
    predicted_ttp = str(case.get("predicted_ttp") or "").strip()
    predicted_tactic = str(case.get("predicted_tactic") or "").strip()
    predicted_source = str(case.get("predicted_source") or "").strip()
    predicted_confidence = _float_value(case.get("predicted_confidence"))
    stored_ttp = str(case.get("stored_ttp") or "").strip()
    stored_tactic = str(case.get("stored_tactic") or "").strip()
    bert_ttp = ""
    bert_tactic = ""
    for output in _as_list(case.get("classifier_outputs")):
        if isinstance(output, dict) and output.get("bert_ttp"):
            bert_ttp = str(output.get("bert_ttp") or "").strip()
            bert_tactic = str(output.get("bert_tactic") or "").strip()
            break

    reasons: List[str] = []
    if not predicted_ttp or not predicted_tactic or predicted_tactic == "unknown":
        return {
            "status": "needs_review",
            "validation_source": "auto_reject_unknown",
            "reasons": ["classifier did not produce a usable TTP/tactic"],
        }
    if predicted_confidence < min_confidence:
        return {
            "status": "needs_review",
            "validation_source": "auto_reject_low_confidence",
            "reasons": [f"classifier confidence {predicted_confidence:.2f} is below auto threshold {min_confidence:.2f}"],
        }
    if predicted_source == "both" and bert_ttp and bert_ttp != predicted_ttp and bert_tactic != predicted_tactic:
        return {
            "status": "needs_review",
            "validation_source": "auto_reject_classifier_disagreement",
            "reasons": [f"rule predicted {predicted_ttp} but SecureBERT predicted {bert_ttp}"],
        }

    if stored_ttp and stored_ttp == predicted_ttp:
        reasons.append("stored session classification matches current classifier output")
    if stored_tactic and stored_tactic == predicted_tactic:
        reasons.append("stored session tactic matches current classifier output")
    if predicted_source == "both" and bert_ttp == predicted_ttp:
        reasons.append("rule and SecureBERT agree on the TTP")
        validation_source = "auto_rule_securebert_consensus"
        strength = "strong_weak_label"
    elif predicted_source == "both" and bert_ttp and bert_ttp != predicted_ttp and bert_tactic == predicted_tactic:
        reasons.append(
            f"rule and SecureBERT disagree on technique ({predicted_ttp} vs {bert_ttp}) but agree on tactic {predicted_tactic}"
        )
        validation_source = "auto_rule_securebert_tactic_consensus"
        strength = "tactic_only_weak_label"
    elif predicted_source == "rule":
        reasons.append("deterministic rule produced a high-confidence ATT&CK mapping")
        validation_source = "auto_rule_high_confidence"
        strength = "weak_label"
    elif predicted_source == "securebert":
        reasons.append("SecureBERT produced a high-confidence ATT&CK mapping")
        validation_source = "auto_securebert_high_confidence"
        strength = "weak_label"
    else:
        reasons.append("classifier produced a high-confidence ATT&CK mapping")
        validation_source = "auto_classifier_high_confidence"
        strength = "weak_label"

    return {
        "status": "auto_accepted",
        "validation_source": validation_source,
        "validation_strength": strength,
        "reasons": reasons,
        "technique_review_required": strength == "tactic_only_weak_label",
    }


def auto_validate_cases(
    cases: Iterable[Dict[str, Any]],
    min_confidence: float = 0.90,
) -> Dict[str, Any]:
    accepted: List[Dict[str, Any]] = []
    needs_review: List[Dict[str, Any]] = []
    for case in cases:
        if not isinstance(case, dict):
            continue
        decision = _auto_validation_decision(case, min_confidence=min_confidence)
        labeled = dict(case)
        labeled["validation_status"] = decision["status"]
        labeled["validation_source"] = decision["validation_source"]
        labeled["validation_strength"] = decision.get("validation_strength", "")
        labeled["validation_reasons"] = decision.get("reasons", [])
        labeled["technique_review_required"] = bool(decision.get("technique_review_required", False))
        if decision["status"] == "auto_accepted":
            labeled["reviewed_ttp"] = labeled.get("predicted_ttp") or ""
            labeled["reviewed_tactic"] = labeled.get("predicted_tactic") or ""
            labeled["reviewer"] = "auto_confidence_consensus_v1"
            labeled["notes"] = "; ".join(decision.get("reasons", []))
            accepted.append(labeled)
        else:
            labeled["reviewed_ttp"] = labeled.get("reviewed_ttp") or ""
            labeled["reviewed_tactic"] = labeled.get("reviewed_tactic") or ""
            labeled["reviewer"] = ""
            labeled["notes"] = "; ".join(decision.get("reasons", []))
            needs_review.append(labeled)
    return {
        "schema_version": "classification_auto_validation.v1",
        "generated_at": utc_now(),
        "min_confidence": min_confidence,
        "total_cases": len(accepted) + len(needs_review),
        "auto_accepted": accepted,
        "needs_review": needs_review,
        "auto_accepted_count": len(accepted),
        "needs_review_count": len(needs_review),
    }


def _empty_bucket() -> Dict[str, float]:
    return {"total": 0, "correct": 0, "precision_denominator": 0, "recall_denominator": 0}


def _metric_bucket_summary(bucket: Dict[str, float]) -> Dict[str, Any]:
    precision_denominator = bucket.get("precision_denominator", 0) or 0
    recall_denominator = bucket.get("recall_denominator", 0) or 0
    correct = bucket.get("correct", 0) or 0
    precision = correct / precision_denominator if precision_denominator else 0.0
    recall = correct / recall_denominator if recall_denominator else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if precision + recall else 0.0
    return {
        "cases": int(bucket.get("total", 0) or 0),
        "correct": int(correct),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
    }


def _macro_f1(buckets: Dict[str, Dict[str, float]]) -> float:
    values = [
        _metric_bucket_summary(bucket)["f1"]
        for bucket in buckets.values()
        if bucket.get("recall_denominator", 0)
    ]
    return round(sum(values) / len(values), 4) if values else 0.0


def _reviewed_value(row: Dict[str, Any], key: str) -> str:
    value = row.get(key)
    if value in (None, ""):
        payload = row.get("payload")
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except json.JSONDecodeError:
                payload = {}
        if isinstance(payload, dict):
            value = payload.get(key)
    return str(value or "").strip()


def classification_metrics(labels: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    rows = [row for row in labels if isinstance(row, dict)]
    total = 0
    tactic_correct = 0
    ttp_correct = 0
    by_tactic: Dict[str, Dict[str, float]] = {}
    by_ttp: Dict[str, Dict[str, float]] = {}
    by_source: Dict[str, Dict[str, float]] = {}
    by_pattern: Dict[str, Dict[str, float]] = {}
    validation_sources: Dict[str, int] = {}
    validation_statuses: Dict[str, int] = {}
    human_reviewed = 0
    weak_labeled = 0
    usable_prediction_count = 0
    tactic_labeled_count = 0
    ttp_labeled_count = 0
    tactic_confusion: Dict[str, Dict[str, int]] = {}
    ttp_confusion: Dict[str, Dict[str, int]] = {}

    for row in rows:
        predicted_tactic = str(row.get("predicted_tactic") or "").strip()
        reviewed_tactic = _reviewed_value(row, "reviewed_tactic")
        predicted_ttp = str(row.get("predicted_ttp") or "").strip()
        reviewed_ttp = _reviewed_value(row, "reviewed_ttp")
        if not reviewed_tactic and not reviewed_ttp:
            continue
        total += 1
        if predicted_tactic and predicted_tactic != "unknown" and predicted_ttp and predicted_ttp != "T0000_UNKNOWN":
            usable_prediction_count += 1
        payload = row.get("payload")
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except json.JSONDecodeError:
                payload = {}
        if not isinstance(payload, dict):
            payload = {}
        validation_source = str(row.get("validation_source") or payload.get("validation_source") or "manual_or_legacy")
        validation_status = str(row.get("validation_status") or payload.get("validation_status") or "reviewed")
        validation_sources[validation_source] = validation_sources.get(validation_source, 0) + 1
        validation_statuses[validation_status] = validation_statuses.get(validation_status, 0) + 1
        reviewer = str(row.get("reviewer") or payload.get("reviewer") or "")
        if reviewer.startswith("auto_") or validation_source.startswith("auto_"):
            weak_labeled += 1
        else:
            human_reviewed += 1
        source = str(row.get("predicted_source") or "unknown")
        pattern = str(row.get("command_pattern") or command_pattern(str(row.get("command") or "")))
        tactic_match = bool(reviewed_tactic and predicted_tactic == reviewed_tactic)
        ttp_match = bool(reviewed_ttp and predicted_ttp == reviewed_ttp)
        if reviewed_tactic:
            tactic_labeled_count += 1
            predicted_key = predicted_tactic or "abstain"
            tactic_confusion.setdefault(reviewed_tactic, {})[predicted_key] = (
                tactic_confusion.setdefault(reviewed_tactic, {}).get(predicted_key, 0) + 1
            )
        if reviewed_ttp:
            ttp_labeled_count += 1
            predicted_key = predicted_ttp or "abstain"
            ttp_confusion.setdefault(reviewed_ttp, {})[predicted_key] = (
                ttp_confusion.setdefault(reviewed_ttp, {}).get(predicted_key, 0) + 1
            )
        if tactic_match:
            tactic_correct += 1
        if ttp_match:
            ttp_correct += 1

        if reviewed_tactic:
            bucket = by_tactic.setdefault(reviewed_tactic, _empty_bucket())
            bucket["total"] += 1
            bucket["recall_denominator"] += 1
            if predicted_tactic == reviewed_tactic:
                bucket["correct"] += 1
            predicted_bucket = by_tactic.setdefault(predicted_tactic or "unknown", _empty_bucket())
            predicted_bucket["precision_denominator"] += 1

        if reviewed_ttp:
            bucket = by_ttp.setdefault(reviewed_ttp, _empty_bucket())
            bucket["total"] += 1
            bucket["recall_denominator"] += 1
            if predicted_ttp == reviewed_ttp:
                bucket["correct"] += 1
            predicted_bucket = by_ttp.setdefault(predicted_ttp or "unknown", _empty_bucket())
            predicted_bucket["precision_denominator"] += 1

        for container, key in ((by_source, source), (by_pattern, pattern)):
            bucket = container.setdefault(key, _empty_bucket())
            bucket["total"] += 1
            bucket["precision_denominator"] += 1
            bucket["recall_denominator"] += 1
            if tactic_match or ttp_match:
                bucket["correct"] += 1

    return {
        "schema_version": "classification_evaluation.v1",
        "generated_at": utc_now(),
        "reviewed_cases": total,
        "human_reviewed_cases": human_reviewed,
        "weak_labeled_cases": weak_labeled,
        "label_origin_warning": (
            "Metrics mix independent human review and classifier-derived weak labels; "
            "use human_reviewed_cases for defensible accuracy claims."
            if weak_labeled else "Metrics contain no classifier-derived weak labels."
        ),
        "validation_sources": dict(sorted(validation_sources.items())),
        "validation_statuses": dict(sorted(validation_statuses.items())),
        "coverage": round(usable_prediction_count / total, 4) if total else 0.0,
        "abstention_rate": round(1 - (usable_prediction_count / total), 4) if total else 0.0,
        "tactic_accuracy": round(tactic_correct / tactic_labeled_count, 4) if tactic_labeled_count else 0.0,
        "ttp_accuracy": round(ttp_correct / ttp_labeled_count, 4) if ttp_labeled_count else 0.0,
        "tactic_macro_f1": _macro_f1(by_tactic),
        "ttp_macro_f1": _macro_f1(by_ttp),
        "tactic_confusion": {key: dict(sorted(value.items())) for key, value in sorted(tactic_confusion.items())},
        "ttp_confusion": {key: dict(sorted(value.items())) for key, value in sorted(ttp_confusion.items())},
        "by_tactic": {key: _metric_bucket_summary(value) for key, value in sorted(by_tactic.items())},
        "by_ttp": {key: _metric_bucket_summary(value) for key, value in sorted(by_ttp.items())},
        "by_source": {key: _metric_bucket_summary(value) for key, value in sorted(by_source.items())},
        "by_command_pattern": {key: _metric_bucket_summary(value) for key, value in sorted(by_pattern.items())},
    }


def build_classifier(config: ProductionConfig, use_securebert: bool = True) -> NotebookParityClassifier:
    mitre_db = None
    try:
        mitre_db = load_mitre_attack_db(cache_path=config.mitre_attack_path or None, silent=True)
    except Exception:
        mitre_db = None
    bert_fn = load_securebert_classifier(config) if use_securebert else None
    return NotebookParityClassifier(
        bert_fn=bert_fn,
        mitre_db=mitre_db,
        high_confidence=float(config.classification_policy.get("bert_min_confidence", 0.55)),
        rule_policy_path=config.classification_rules_path,
    )


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Evaluate and review command classification labels.")
    parser.add_argument("--config", help="Path to production JSON config.")
    parser.add_argument("--database-url", help="Override DATABASE_URL.")
    parser.add_argument("--limit", type=int, default=1000, help="Maximum sessions/cases to read.")
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
    parser.add_argument(
        "--export-review-cases",
        nargs="?",
        const="-",
        default="",
        metavar="PATH",
        help="Export review cases as JSON. Omit PATH to print to stdout.",
    )
    parser.add_argument("--import-reviewed-labels", metavar="PATH", help="Import reviewed JSON/JSONL labels.")
    parser.add_argument(
        "--auto-validate",
        action="store_true",
        help="Automatically store high-confidence weak labels and only queue uncertain cases for optional review.",
    )
    parser.add_argument(
        "--min-auto-confidence",
        type=float,
        default=0.90,
        help="Minimum classifier confidence required for --auto-validate. Default: 0.90.",
    )
    parser.add_argument(
        "--write-review-queue",
        metavar="PATH",
        help="Write uncertain/conflicted cases from --auto-validate to a JSON file for optional later review.",
    )
    parser.add_argument("--report", action="store_true", help="Print metrics from stored or supplied reviewed labels.")
    parser.add_argument("--labels", help="Use this reviewed JSON/JSONL file for --report instead of database labels.")
    parser.add_argument("--no-securebert", action="store_true", help="Evaluate rules only.")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    config = ProductionConfig.from_env(args.config)
    if args.database_url:
        config.database_url = args.database_url
    session_source = None if args.all_session_sources else normalize_session_source(args.session_source)
    storage = open_storage(config.database_url)
    output: Dict[str, Any] = {}

    if args.export_review_cases:
        cases = collect_review_cases(
            load_session_payloads(
                config,
                limit=max(args.limit, 1),
                session_source=session_source,
                external_only=not bool(args.include_non_external_source_ips),
            ),
            build_classifier(config, use_securebert=not args.no_securebert),
            limit=max(args.limit, 1),
        )
        if args.export_review_cases == "-":
            output["review_cases"] = cases
        else:
            with open(args.export_review_cases, "w", encoding="utf-8") as f:
                f.write(json.dumps(cases, indent=2, sort_keys=True))
            output["exported_review_cases"] = args.export_review_cases
            output["case_count"] = len(cases)

    if args.import_reviewed_labels:
        storage.initialize()
        output["import"] = import_review_labels(storage, load_review_labels(args.import_reviewed_labels))

    if args.auto_validate:
        storage.initialize()
        cases = collect_review_cases(
            load_session_payloads(
                config,
                limit=max(args.limit, 1),
                session_source=session_source,
                external_only=not bool(args.include_non_external_source_ips),
            ),
            build_classifier(config, use_securebert=not args.no_securebert),
            limit=max(args.limit, 1),
        )
        auto_result = auto_validate_cases(cases, min_confidence=max(float(args.min_auto_confidence), 0.0))
        output["auto_validation"] = {
            key: value
            for key, value in auto_result.items()
            if key not in {"auto_accepted", "needs_review"}
        }
        output["auto_validation"]["import"] = import_review_labels(storage, auto_result["auto_accepted"])
        if args.write_review_queue:
            with open(args.write_review_queue, "w", encoding="utf-8") as f:
                f.write(json.dumps(auto_result["needs_review"], indent=2, sort_keys=True))
            output["auto_validation"]["review_queue_path"] = args.write_review_queue
        output["auto_validation"]["review_queue_sample"] = auto_result["needs_review"][:5]

    if args.report:
        if args.labels:
            labels = load_review_labels(args.labels)
        else:
            labels = storage.list_classification_review_labels(limit=max(args.limit, 1))
        output["report"] = classification_metrics(labels)

    if not output:
        output["usage"] = "Use --export-review-cases, --import-reviewed-labels, or --report."
    sys.stdout.write(stable_json(output) if args.export_review_cases == "-" and set(output) == {"review_cases"} else json.dumps(output, indent=2, sort_keys=True))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
