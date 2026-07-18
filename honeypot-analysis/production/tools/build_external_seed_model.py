"""Build an external Cowrie seed transition model for realtime prediction.

The output contains aggregate transition counts only. It intentionally does not
store raw commands, usernames, passwords, or attacker IPs from the source data.
"""

from __future__ import annotations

import argparse
from collections import Counter
import gzip
import json
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional

from production.enrichment.mitre_attack_loader import load_mitre_attack_db

from production.classification.classification_pipeline import NotebookParityClassifier, is_shell_noise, rule_based_ttp
from production.prediction.realtime_prediction import build_transition_model
from production.utils.serialization import stable_id, utc_now
from production.utils.sensitive_data import redact_exception_for_log
from production.classification.securebert_classifier import SecureBertCommandClassifier


def _iter_json_paths(root: Path) -> List[Path]:
    if root.is_file():
        return [root]
    patterns = ("cowrie.json", "cowrie.json.*", "*.ndjson", "*.jsonl")
    paths: List[Path] = []
    for pattern in patterns:
        paths.extend(path for path in root.rglob(pattern) if path.is_file())
    return sorted(set(paths))


def _open_text(path: Path) -> Iterator[str]:
    if path.suffix == ".gz":
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
            yield from f
        return
    with path.open("r", encoding="utf-8", errors="replace") as f:
        yield from f


def _session_payload(session_id: str, commands: List[str], classification_events: List[Dict[str, Any]], closed: bool) -> Dict[str, Any]:
    return {
        "session_id": session_id,
        "commands": commands,
        "classification_events": classification_events,
        "is_ended": bool(closed),
        "status": "closed" if closed else "active",
    }


def _rate(numerator: int, denominator: int) -> float:
    return round(float(numerator) / float(denominator), 4) if denominator else 0.0


def _source_bucket(event: Dict[str, Any]) -> str:
    source = str(event.get("source") or "unknown")
    agreement_status = str(event.get("agreement_status") or "")
    if source == "rule_securebert_disagreement":
        if agreement_status == "tactic_only_disagreement":
            return "both_tactic_disagree"
        return "both_disagree"
    if source == "both":
        bert_ttp = str(event.get("bert_ttp") or "")
        ttp = str(event.get("ttp") or "")
        if bert_ttp and bert_ttp == ttp:
            return "both_agree"
        tactic = str(event.get("tactic") or "").strip()
        bert_tactic = str(event.get("bert_tactic") or "").strip()
        if bert_ttp and tactic and bert_tactic and tactic == bert_tactic:
            return "both_tactic_agree"
        return "both_disagree"
    return source


def _review_record(command: str, reason: str, outputs: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "command": command,
        "command_hash": stable_id("external_seed_command", {"command": command}),
        "reason": reason,
        "classifier_outputs": outputs,
    }


def _load_bert_fn(
    use_securebert: bool,
    bert_fn: Optional[Callable[[str], tuple[Optional[str], float]]],
    securebert_model_path: str,
    securebert_checkpoint_path: str,
    securebert_device: str,
    securebert_max_length: int,
    allow_securebert_unavailable: bool,
) -> tuple[Optional[Callable[[str], tuple[Optional[str], float]]], Dict[str, Any]]:
    if bert_fn is not None:
        return bert_fn, {
            "securebert_used": True,
            "securebert_source": "injected_callable",
            "securebert_available": True,
        }
    if not use_securebert:
        return None, {
            "securebert_used": False,
            "securebert_source": "disabled",
            "securebert_available": False,
        }
    try:
        classifier = SecureBertCommandClassifier(
            model_path=securebert_model_path,
            checkpoint_path=securebert_checkpoint_path,
            device=securebert_device,
            max_length=securebert_max_length,
        )
        return classifier.classify, {
            "securebert_used": True,
            "securebert_source": "SecureBertCommandClassifier",
            "securebert_available": True,
            "securebert_model_path": str(classifier.model_path),
            "securebert_checkpoint_path": str(classifier.checkpoint_path),
            "securebert_device": str(classifier.device),
        }
    except Exception as exc:
        if not allow_securebert_unavailable:
            raise RuntimeError(redact_exception_for_log(exc)) from None
        return None, {
            "securebert_used": False,
            "securebert_source": "unavailable_fallback_to_rules",
            "securebert_available": False,
            "securebert_error": redact_exception_for_log(exc),
        }


def _accepted_classifications(
    command: str,
    classifications: List[Dict[str, Any]],
    stats: Dict[str, Any],
    source_counts: Counter,
    review_records: List[Dict[str, Any]],
    min_label_confidence: float,
    drop_disagreements: bool,
    review_limit: int,
) -> List[Dict[str, Any]]:
    accepted: List[Dict[str, Any]] = []
    skipped_any = False

    for item in classifications:
        if not isinstance(item, dict):
            continue
        source_bucket = _source_bucket(item)
        source_counts[source_bucket] += 1
        source = str(item.get("source") or "")
        if source == "shell_noise":
            skipped_any = True
            stats["noise_commands_skipped"] += 1
            if len(review_records) < review_limit:
                review_records.append(_review_record(command, "shell_noise", classifications))
            continue

        try:
            confidence = float(item.get("confidence") or 0.0)
        except (TypeError, ValueError):
            confidence = 0.0
        ttp = str(item.get("ttp") or "").strip()
        tactic = str(item.get("tactic") or "").strip()
        if ttp and confidence < min_label_confidence:
            skipped_any = True
            stats["low_confidence_commands_skipped"] += 1
            if len(review_records) < review_limit:
                review_records.append(_review_record(command, "low_confidence", classifications))
            continue
        if not ttp or not tactic or tactic == "unknown":
            skipped_any = True
            stats["unknown_commands_skipped"] += 1
            if len(review_records) < review_limit:
                review_records.append(_review_record(command, "unknown", classifications))
            continue
        if confidence < min_label_confidence:
            skipped_any = True
            stats["low_confidence_commands_skipped"] += 1
            if len(review_records) < review_limit:
                review_records.append(_review_record(command, "low_confidence", classifications))
            continue

        if source_bucket in {"both_disagree", "both_tactic_disagree"}:
            skipped_any = True
            stats["disagreement_commands_skipped"] += 1
            if len(review_records) < review_limit:
                review_records.append(_review_record(command, "classifier_disagreement", classifications))
            continue

        event = dict(item)
        event["external_seed_validation"] = {
            "status": "auto_accepted",
            "min_label_confidence": min_label_confidence,
            "source_bucket": source_bucket,
            "validation_source": (
                "auto_rule_securebert_consensus"
                if source_bucket == "both_agree"
                else "auto_rule_securebert_tactic_consensus"
                if source_bucket == "both_tactic_agree"
                else "auto_securebert_high_confidence"
                if source == "securebert"
                else "auto_rule_high_confidence"
            ),
            "technique_disagreement": source_bucket == "both_tactic_agree",
            "review_note": (
                "rule and SecureBERT disagree on technique but agree on tactic; keep tactic-level evidence only"
                if source_bucket == "both_tactic_agree"
                else ""
            ),
        }
        accepted.append(event)

    if accepted:
        return accepted
    if skipped_any:
        return []
    if classifications:
        stats["filtered_known_commands_skipped"] += 1
        reason = "filtered_known"
    else:
        stats["unknown_commands_skipped"] += 1
        reason = "unknown"
    if len(review_records) < review_limit:
        review_records.append(_review_record(command, reason, classifications))
    return []


def _write_json_or_ndjson(path_text: str, payloads: List[Dict[str, Any]], provenance: Dict[str, Any]) -> None:
    if not path_text:
        return
    path = Path(path_text)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.suffix.lower() in {".ndjson", ".jsonl"}:
        with path.open("w", encoding="utf-8") as f:
            for payload in payloads:
                f.write(json.dumps(payload, sort_keys=True) + "\n")
        return
    document = {
        "schema_version": "external_seed_sessions.v1",
        "generated_at": provenance.get("built_at") or utc_now(),
        "provenance": provenance,
        "sessions": payloads,
    }
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_review_records(path_text: str, records: List[Dict[str, Any]], provenance: Dict[str, Any]) -> None:
    if not path_text:
        return
    path = Path(path_text)
    path.parent.mkdir(parents=True, exist_ok=True)
    document = {
        "schema_version": "external_seed_review_queue.v1",
        "generated_at": provenance.get("built_at") or utc_now(),
        "provenance": provenance,
        "review_count": len(records),
        "review_records": records,
    }
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def build_external_seed_model(
    input_root: str,
    output_path: str,
    mitre_cache: str = "data/feeds/mitre_attack_cache.json",
    dataset_handle: str = "nlaha11/global-ssh-and-telnet-honeypot-logs-cowrie",
    source_name: str = "external_cowrie_seed",
    prefix_max_length: int = 3,
    max_files: int = 0,
    max_commands: int = 0,
    use_securebert: bool = False,
    bert_fn: Optional[Callable[[str], tuple[Optional[str], float]]] = None,
    securebert_scope: str = "hybrid",
    securebert_model_path: str = "models/securebert_ttp",
    securebert_checkpoint_path: str = "",
    securebert_device: str = "auto",
    securebert_max_length: int = 128,
    securebert_high_confidence: float = 0.55,
    allow_securebert_unavailable: bool = False,
    min_label_confidence: float = 0.90,
    keep_disagreements: bool = False,
    session_output_path: str = "",
    review_output_path: str = "",
    review_limit: int = 500,
    mitre_db: Any = None,
) -> Dict[str, Any]:
    root = Path(input_root)
    output = Path(output_path)
    paths = _iter_json_paths(root)
    if max_files > 0:
        paths = paths[:max_files]

    mitre_db = mitre_db or load_mitre_attack_db(cache_path=mitre_cache or None, silent=True)
    loaded_bert_fn, securebert_meta = _load_bert_fn(
        use_securebert=use_securebert,
        bert_fn=bert_fn,
        securebert_model_path=securebert_model_path,
        securebert_checkpoint_path=securebert_checkpoint_path,
        securebert_device=securebert_device,
        securebert_max_length=securebert_max_length,
        allow_securebert_unavailable=allow_securebert_unavailable,
    )
    securebert_active = loaded_bert_fn is not None
    rules_classifier = NotebookParityClassifier(
        bert_fn=None,
        mitre_db=mitre_db,
        high_confidence=securebert_high_confidence,
    )
    hybrid_classifier = NotebookParityClassifier(
        bert_fn=loaded_bert_fn,
        mitre_db=mitre_db,
        high_confidence=securebert_high_confidence,
    )
    classification_cache: Dict[str, List[Dict[str, Any]]] = {}

    sessions: Dict[str, Dict[str, Any]] = {}
    review_records: List[Dict[str, Any]] = []
    source_counts: Counter = Counter()
    stats: Dict[str, Any] = {
        "files_scanned": 0,
        "raw_lines": 0,
        "bad_lines": 0,
        "raw_command_events": 0,
        "securebert_invocations": 0,
        "securebert_cache_hits": 0,
        "noise_commands_skipped": 0,
        "unknown_commands_skipped": 0,
        "low_confidence_commands_skipped": 0,
        "disagreement_commands_skipped": 0,
        "filtered_known_commands_skipped": 0,
        "accepted_command_events": 0,
        "accepted_classification_events": 0,
        "known_tactic_commands": 0,
        "closed_sessions": 0,
    }

    for path in paths:
        stats["files_scanned"] += 1
        for line in _open_text(path):
            stats["raw_lines"] += 1
            text = line.strip()
            if not text:
                continue
            try:
                event = json.loads(text)
            except json.JSONDecodeError:
                stats["bad_lines"] += 1
                continue
            if not isinstance(event, dict):
                continue
            session_id = str(event.get("session") or event.get("session_id") or "").strip()
            if not session_id:
                continue
            session = sessions.setdefault(
                session_id,
                {"commands": [], "classification_events": [], "closed": False},
            )
            eventid = str(event.get("eventid") or "")
            if eventid == "cowrie.session.closed":
                session["closed"] = True
                continue
            if eventid != "cowrie.command.input":
                continue
            command = str(event.get("input") or "").strip()
            if not command:
                continue
            if max_commands > 0 and stats["raw_command_events"] >= max_commands:
                break
            stats["raw_command_events"] += 1
            if is_shell_noise(command):
                stats["noise_commands_skipped"] += 1
                if len(review_records) < review_limit:
                    review_records.append(_review_record(command, "shell_noise", []))
                continue

            has_rule = bool(rule_based_ttp(command))
            should_call_securebert = securebert_active and (
                securebert_scope == "hybrid"
                or (securebert_scope == "unknown_only" and not has_rule)
            )
            classifier = hybrid_classifier if should_call_securebert else rules_classifier
            cache_key = f"{'hybrid' if should_call_securebert else 'rules'}:{command}"
            if cache_key in classification_cache:
                classifications = classification_cache[cache_key]
                if should_call_securebert:
                    stats["securebert_cache_hits"] += 1
            else:
                if should_call_securebert:
                    stats["securebert_invocations"] += 1
                classifications = classifier.classify(command)
                classification_cache[cache_key] = classifications
            known = _accepted_classifications(
                command,
                classifications,
                stats,
                source_counts,
                review_records,
                min_label_confidence=min_label_confidence,
                drop_disagreements=not keep_disagreements,
                review_limit=review_limit,
            )
            if not known:
                continue
            session["commands"].append(command)
            session["classification_events"].extend(known)
            stats["accepted_command_events"] += 1
            stats["accepted_classification_events"] += len(known)
            stats["known_tactic_commands"] += len(known)
        if max_commands > 0 and stats["raw_command_events"] >= max_commands:
            break

    payloads = [
        _session_payload(session_id, item["commands"], item["classification_events"], bool(item["closed"]))
        for session_id, item in sessions.items()
    ]
    stats["closed_sessions"] = sum(1 for item in sessions.values() if item.get("closed"))
    model = build_transition_model(payloads, prefix_max_length=prefix_max_length)
    model["schema_version"] = "external_transition_model.v1"
    model["source_type"] = source_name
    model["built_at"] = utc_now()
    classification_quality = {
        "raw_command_events": stats["raw_command_events"],
        "accepted_command_events": stats["accepted_command_events"],
        "accepted_classification_events": stats["accepted_classification_events"],
        "unique_classification_cache_entries": len(classification_cache),
        "securebert_invocations": stats["securebert_invocations"],
        "securebert_cache_hits": stats["securebert_cache_hits"],
        "unknown_commands_skipped": stats["unknown_commands_skipped"],
        "noise_commands_skipped": stats["noise_commands_skipped"],
        "low_confidence_commands_skipped": stats["low_confidence_commands_skipped"],
        "disagreement_commands_skipped": stats["disagreement_commands_skipped"],
        "filtered_known_commands_skipped": stats["filtered_known_commands_skipped"],
        "unknown_rate": _rate(stats["unknown_commands_skipped"], stats["raw_command_events"]),
        "shell_noise_rate": _rate(stats["noise_commands_skipped"], stats["raw_command_events"]),
        "low_confidence_rate": _rate(stats["low_confidence_commands_skipped"], stats["raw_command_events"]),
        "disagreement_rate": _rate(stats["disagreement_commands_skipped"], stats["raw_command_events"]),
        "acceptance_rate": _rate(stats["accepted_command_events"], stats["raw_command_events"]),
        "source_counts": dict(sorted(source_counts.items())),
        "min_label_confidence": min_label_confidence,
        "drop_disagreements": not keep_disagreements,
    }
    provenance = {
        "source_type": source_name,
        "dataset_handle": dataset_handle,
        "input_root": str(root),
        "training_source": (
            "external Cowrie command events classified by production rules, optional SecureBERT, "
            "and MITRE tactic mapping"
        ),
        "classifier": (
            "NotebookParityClassifier rules plus SecureBERT"
            if securebert_active
            else "NotebookParityClassifier rules only"
        ),
        "securebert_scope": securebert_scope if securebert_active else "off",
        "securebert_high_confidence": securebert_high_confidence,
        **securebert_meta,
        "classification_quality": classification_quality,
        "mitre_techniques": getattr(mitre_db, "technique_count", 0),
        "built_at": model["built_at"],
        **stats,
    }
    model["provenance"] = provenance
    model["classification_quality"] = classification_quality
    model["model_id"] = stable_id(
        "externaltransition",
        {
            "source_type": source_name,
            "dataset_handle": dataset_handle,
            "completed_sessions": model.get("completed_sessions"),
            "usable_sessions": model.get("usable_sessions"),
            "transition_count": model.get("transition_count"),
            "prefix_transition_count": model.get("prefix_transition_count"),
            "technique_transition_count": model.get("technique_transition_count"),
            "prefix_max_length": model.get("prefix_max_length"),
        },
    )

    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as f:
        json.dump(model, f, indent=2, sort_keys=True)
    _write_json_or_ndjson(session_output_path, payloads, provenance)
    _write_review_records(review_output_path, review_records, provenance)
    return model


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build an aggregate external Cowrie transition model")
    parser.add_argument("--input-root", required=True, help="Dataset root, logs root, or a single NDJSON file")
    parser.add_argument("--output", required=True, help="Output JSON model path")
    parser.add_argument("--mitre-cache", default="data/feeds/mitre_attack_cache.json")
    parser.add_argument("--dataset-handle", default="nlaha11/global-ssh-and-telnet-honeypot-logs-cowrie")
    parser.add_argument("--source-name", default="external_cowrie_seed")
    parser.add_argument("--prefix-max-length", type=int, default=3)
    parser.add_argument("--max-files", type=int, default=0)
    parser.add_argument("--max-commands", type=int, default=0, help="Stop after this many command events; useful for smoke tests.")
    parser.add_argument("--use-securebert", action="store_true", help="Use SecureBERT together with rules for seed labeling.")
    parser.add_argument("--securebert-scope", choices=["hybrid", "unknown_only"], default="hybrid")
    parser.add_argument("--securebert-path", default="models/securebert_ttp")
    parser.add_argument("--securebert-checkpoint-path", default="")
    parser.add_argument("--securebert-device", default="auto")
    parser.add_argument("--securebert-max-length", type=int, default=128)
    parser.add_argument("--securebert-high-confidence", type=float, default=0.55)
    parser.add_argument("--allow-securebert-unavailable", action="store_true")
    parser.add_argument("--min-label-confidence", type=float, default=0.90)
    parser.add_argument("--keep-disagreements", action="store_true", help="Keep rule/SecureBERT disagreements instead of sending them to review.")
    parser.add_argument("--session-output", default="", help="Optional JSON/NDJSON session payload output for validation.")
    parser.add_argument("--review-output", default="", help="Optional JSON review queue for unknown/low-confidence/disagreement commands.")
    parser.add_argument("--review-limit", type=int, default=500)
    args = parser.parse_args(list(argv) if argv is not None else None)

    model = build_external_seed_model(
        input_root=args.input_root,
        output_path=args.output,
        mitre_cache=args.mitre_cache,
        dataset_handle=args.dataset_handle,
        source_name=args.source_name,
        prefix_max_length=args.prefix_max_length,
        max_files=args.max_files,
        max_commands=args.max_commands,
        use_securebert=args.use_securebert,
        securebert_scope=args.securebert_scope,
        securebert_model_path=args.securebert_path,
        securebert_checkpoint_path=args.securebert_checkpoint_path,
        securebert_device=args.securebert_device,
        securebert_max_length=args.securebert_max_length,
        securebert_high_confidence=args.securebert_high_confidence,
        allow_securebert_unavailable=args.allow_securebert_unavailable,
        min_label_confidence=args.min_label_confidence,
        keep_disagreements=args.keep_disagreements,
        session_output_path=args.session_output,
        review_output_path=args.review_output,
        review_limit=args.review_limit,
    )
    summary = {
        "output": args.output,
        "model_id": model.get("model_id"),
        "usable_sessions": model.get("usable_sessions"),
        "transition_count": model.get("transition_count"),
        "prefix_transition_count": model.get("prefix_transition_count"),
        "technique_transition_count": model.get("technique_transition_count"),
        "classification_quality": model.get("classification_quality", {}),
        "provenance": model.get("provenance", {}),
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
