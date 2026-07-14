"""Compare classifier variants on a reviewed command-consistency artifact.

The evaluator supports researcher/AI-assisted review artifacts, but labels them
explicitly as non-ground-truth. It uses set-valued TTP metrics so compound
commands are not reduced to one arbitrary label.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Set

from production.classification.classification_pipeline import NotebookParityClassifier
from production.classification.trust import is_trusted_classification_event
from production.utils.serialization import utc_now


def _items(document: Any, *keys: str) -> List[Dict[str, Any]]:
    if isinstance(document, list):
        return [dict(item) for item in document if isinstance(item, dict)]
    if isinstance(document, dict):
        for key in keys:
            values = document.get(key)
            if isinstance(values, list):
                return [dict(item) for item in values if isinstance(item, dict)]
    return []


def _clean_labels(values: Iterable[Any]) -> Set[str]:
    return {
        str(value).strip()
        for value in values
        if str(value or "").strip() not in {"", "unknown", "T0000_UNKNOWN"}
    }


def _main_ttps(values: Iterable[Any]) -> List[str]:
    return sorted({label.split(".", 1)[0] for label in _clean_labels(values)})


def _ttp_metrics(rows: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    tp = fp = fn = exact = covered = 0
    unknown_cases = correct_abstentions = 0
    by_ttp: Dict[str, Dict[str, int]] = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})
    for row in rows:
        expected = _clean_labels(row.get("expected_ttps") or [])
        predicted = _clean_labels(row.get("predicted_ttps") or [])
        if predicted:
            covered += 1
        if expected == predicted:
            exact += 1
        if not expected:
            unknown_cases += 1
            if not predicted:
                correct_abstentions += 1
        common = expected & predicted
        only_predicted = predicted - expected
        only_expected = expected - predicted
        tp += len(common)
        fp += len(only_predicted)
        fn += len(only_expected)
        for ttp in common:
            by_ttp[ttp]["tp"] += 1
        for ttp in only_predicted:
            by_ttp[ttp]["fp"] += 1
        for ttp in only_expected:
            by_ttp[ttp]["fn"] += 1

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    micro_f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    per_ttp = {}
    precision_values = []
    recall_values = []
    f1_values = []
    for ttp, counts in sorted(by_ttp.items()):
        item_precision = counts["tp"] / (counts["tp"] + counts["fp"]) if counts["tp"] + counts["fp"] else 0.0
        item_recall = counts["tp"] / (counts["tp"] + counts["fn"]) if counts["tp"] + counts["fn"] else 0.0
        item_f1 = (
            2 * item_precision * item_recall / (item_precision + item_recall)
            if item_precision + item_recall else 0.0
        )
        if counts["tp"] + counts["fn"]:
            precision_values.append(item_precision)
            recall_values.append(item_recall)
            f1_values.append(item_f1)
        per_ttp[ttp] = {
            **counts,
            "precision": round(item_precision, 4),
            "recall": round(item_recall, 4),
            "f1": round(item_f1, 4),
        }
    total = len(rows)
    return {
        "evaluated_commands": total,
        "coverage": round(covered / total, 4) if total else 0.0,
        "exact_set_accuracy": round(exact / total, 4) if total else 0.0,
        "micro_precision": round(precision, 4),
        "micro_recall": round(recall, 4),
        "micro_f1": round(micro_f1, 4),
        "macro_precision": round(sum(precision_values) / len(precision_values), 4) if precision_values else 0.0,
        "macro_recall": round(sum(recall_values) / len(recall_values), 4) if recall_values else 0.0,
        "macro_f1": round(sum(f1_values) / len(f1_values), 4) if f1_values else 0.0,
        "true_positive_labels": tp,
        "false_positive_labels": fp,
        "false_negative_labels": fn,
        "unknown_expected_cases": unknown_cases,
        "correct_abstentions": correct_abstentions,
        "unknown_abstention_accuracy": round(correct_abstentions / unknown_cases, 4) if unknown_cases else None,
        "per_ttp": per_ttp,
    }


def _captured_hybrid(case: Dict[str, Any], *, trusted_only: bool) -> Set[str]:
    outputs = [item for item in case.get("system_mappings") or [] if isinstance(item, dict)]
    if trusted_only:
        outputs = [item for item in outputs if is_trusted_classification_event(item)]
    else:
        outputs = [item for item in outputs if item.get("high_confidence") is not False]
    return _clean_labels(item.get("ttp") for item in outputs)


def _captured_securebert(queue_case: Dict[str, Any], min_confidence: float) -> Set[str]:
    labels: Set[str] = set()
    for output in queue_case.get("classifier_outputs") or []:
        if not isinstance(output, dict):
            continue
        if output.get("bert_ttp"):
            confidence = float(output.get("bert_confidence") or 0.0)
            if confidence >= min_confidence:
                labels.update(_clean_labels([output.get("bert_ttp")]))
        elif str(output.get("source") or "").lower() == "securebert":
            confidence = float(output.get("confidence") or 0.0)
            if confidence >= min_confidence and output.get("high_confidence") is not False:
                labels.update(_clean_labels([output.get("ttp")]))
    return labels


def evaluate_review_artifact(
    review_document: Mapping[str, Any],
    queue_document: Mapping[str, Any],
    classifier: NotebookParityClassifier,
    *,
    securebert_min_confidence: float = 0.55,
) -> Dict[str, Any]:
    review_cases = _items(review_document, "classification_review", "cases", "review_cases")
    queue_cases = _items(queue_document, "cases", "review_cases")
    queue_by_command = {str(item.get("command") or ""): item for item in queue_cases}
    variant_rows: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    strata: Counter[str] = Counter()

    for case in review_cases:
        command = str(case.get("command") or "").strip()
        if not command:
            continue
        queue_case = queue_by_command.get(command, {})
        expected = sorted(_clean_labels(case.get("recommended_ttps") or case.get("reviewed_ttps") or []))
        pattern = str(queue_case.get("command_pattern") or "other")
        strata[pattern] += 1
        predictions = {
            "captured_hybrid_raw": sorted(_captured_hybrid(case, trusted_only=False)),
            "captured_hybrid_trusted": sorted(_captured_hybrid(case, trusted_only=True)),
            "captured_securebert_only": sorted(_captured_securebert(queue_case, securebert_min_confidence)),
            "current_rules_only": sorted(
                _clean_labels(
                    output.get("ttp")
                    for output in classifier.classify(command)
                    if str(output.get("source") or "") in {"rule", "both"}
                )
            ),
        }
        for variant, predicted in predictions.items():
            variant_rows[variant].append(
                {
                    "command": command,
                    "command_pattern": pattern,
                    "expected_ttps": expected,
                    "predicted_ttps": predicted,
                }
            )

    return {
        "schema_version": "classification_consistency_benchmark.v1",
        "generated_at": utc_now(),
        "review_type": review_document.get("review_type") or "reviewed command consistency artifact",
        "validation_status": review_document.get("validation_status") or "not independently validated ground truth",
        "selection_bias": (
            "The current review queue is uncertainty/disagreement-selected. Metrics describe consistency on this queue "
            "and must not be reported as production classification accuracy."
        ),
        "label_semantics": "set-valued command-level candidate ATT&CK mappings; empty set means conservative abstention",
        "case_count": sum(strata.values()),
        "strata": dict(sorted(strata.items())),
        "variants": {
            name: {
                "exact_technique_metrics": _ttp_metrics(rows),
                "parent_technique_metrics": _ttp_metrics([
                    {
                        **row,
                        "expected_ttps": _main_ttps(row.get("expected_ttps") or []),
                        "predicted_ttps": _main_ttps(row.get("predicted_ttps") or []),
                    }
                    for row in rows
                ]),
                "cases": rows,
            }
            for name, rows in sorted(variant_rows.items())
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--review-artifact", required=True)
    parser.add_argument("--queue-artifact", required=True)
    parser.add_argument("--rule-policy", default="configs/classification_rules.trusted.json")
    parser.add_argument("--securebert-min-confidence", type=float, default=0.55)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    review = json.loads(Path(args.review_artifact).read_text(encoding="utf-8"))
    queue = json.loads(Path(args.queue_artifact).read_text(encoding="utf-8"))
    classifier = NotebookParityClassifier(
        bert_fn=None,
        mitre_db=None,
        rule_policy_path=args.rule_policy,
    )
    result = evaluate_review_artifact(
        review,
        queue,
        classifier,
        securebert_min_confidence=max(float(args.securebert_min_confidence), 0.0),
    )
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "case_count": result["case_count"],
        "selection_bias": result["selection_bias"],
        "metrics": {
            name: {
                "exact_technique_metrics": value["exact_technique_metrics"],
                "parent_technique_metrics": value["parent_technique_metrics"],
            }
            for name, value in result["variants"].items()
        },
        "output": str(output_path),
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
