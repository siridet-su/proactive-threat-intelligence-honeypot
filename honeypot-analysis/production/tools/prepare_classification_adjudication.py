"""Prepare a deterministic, stratified command-classification review queue."""

from __future__ import annotations

import argparse
import json
import random
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

from production.classification.classification_evaluation import command_pattern
from production.utils.serialization import utc_now


def _records(document: Any) -> List[Dict[str, Any]]:
    if isinstance(document, list):
        return [dict(item) for item in document if isinstance(item, dict)]
    if isinstance(document, dict):
        return [
            dict(item) for item in document.get("review_records") or []
            if isinstance(item, dict)
        ]
    return []


def prepare_queue(
    records: Iterable[Dict[str, Any]],
    *,
    limit: int = 500,
    seed: int = 20260712,
) -> Dict[str, Any]:
    unique: Dict[str, Dict[str, Any]] = {}
    for record in records:
        command = str(record.get("command") or "").strip()
        if command and command not in unique:
            unique[command] = dict(record)

    groups: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
    for command, record in unique.items():
        reason = str(record.get("reason") or "unspecified")
        pattern = command_pattern(command)
        groups[(reason, pattern)].append(record)

    rng = random.Random(seed)
    for values in groups.values():
        values.sort(key=lambda item: str(item.get("command_hash") or item.get("command") or ""))
        rng.shuffle(values)

    selected: List[Dict[str, Any]] = []
    keys = sorted(groups)
    while keys and len(selected) < max(limit, 0):
        remaining = []
        for key in keys:
            values = groups[key]
            if values and len(selected) < limit:
                record = dict(values.pop())
                record.update(
                    {
                        "command_pattern": key[1],
                        "review_status": "unreviewed",
                        "reviewed_ttp": "",
                        "reviewed_tactic": "",
                        "reviewer": "",
                        "independent_of_classifier": None,
                        "notes": "",
                    }
                )
                selected.append(record)
            if values:
                remaining.append(key)
        keys = remaining

    strata: Dict[str, int] = {}
    for item in selected:
        key = f"{item.get('reason', 'unspecified')}|{item.get('command_pattern', 'other')}"
        strata[key] = strata.get(key, 0) + 1
    return {
        "schema_version": "classification_adjudication_queue.v1",
        "generated_at": utc_now(),
        "seed": seed,
        "requested_limit": limit,
        "source_unique_commands": len(unique),
        "case_count": len(selected),
        "label_status": "unreviewed_not_ground_truth",
        "instructions": [
            "Assign reviewed_ttp and reviewed_tactic from command evidence only.",
            "Use abstain when the command does not support a defensible ATT&CK mapping.",
            "Record reviewer identity and whether review was independent of classifier development.",
            "Do not use these cases for accuracy claims until human adjudication is complete.",
        ],
        "strata": dict(sorted(strata.items())),
        "cases": selected,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--limit", type=int, default=500)
    parser.add_argument("--seed", type=int, default=20260712)
    args = parser.parse_args()
    source = json.loads(Path(args.input).read_text(encoding="utf-8"))
    output = prepare_queue(_records(source), limit=max(args.limit, 0), seed=args.seed)
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({k: output[k] for k in ("schema_version", "case_count", "label_status", "strata")}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
