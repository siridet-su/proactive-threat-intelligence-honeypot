"""Score two rounds of a privacy-minimized single-reviewer hypothesis audit."""

from __future__ import annotations

import argparse
import json
import math
import re
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Sequence


SCHEMA_VERSION = "threat_hypothesis_single_reviewer_audit.v1"
RUBRIC_VERSION = "threat_hypothesis_review_rubric.v1"
CRITERIA = (
    "relationship_links_correct",
    "claims_evidence_grounded",
    "evidence_references_correct",
    "abstention_appropriate",
    "overclaim_present",
)
ALLOWED_LABELS = {"yes", "no", "uncertain", "not_applicable"}
ALLOWED_FIELDS = {"case_id", "review_round", "rubric_version", *CRITERIA}
SAFE_CASE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
IP_LIKE_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def _ratio(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 6) if denominator else None


def _template_row(case_id: str, review_round: int) -> Dict[str, Any]:
    return {
        "case_id": case_id,
        "review_round": review_round,
        "rubric_version": RUBRIC_VERSION,
        **{criterion: None for criterion in CRITERIA},
    }


def build_review_templates(case_count: int = 30) -> Dict[int, List[Dict[str, Any]]]:
    if case_count < 1 or case_count > 200:
        raise ValueError("case_count must be between 1 and 200")
    case_ids = [f"case-{index:03d}" for index in range(1, case_count + 1)]
    return {
        1: [_template_row(case_id, 1) for case_id in case_ids],
        2: [_template_row(case_id, 2) for case_id in reversed(case_ids)],
    }


def write_review_templates(directory: Path, case_count: int = 30) -> List[Path]:
    directory.mkdir(parents=True, exist_ok=True)
    templates = build_review_templates(case_count)
    outputs = []
    for review_round, rows in templates.items():
        path = directory / f"threat_hypothesis_review_round_{review_round}.jsonl"
        path.write_text(
            "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
            encoding="utf-8",
        )
        outputs.append(path)
    return outputs


def _validate_case_id(value: Any) -> str:
    case_id = str(value or "").strip().lower()
    if not SAFE_CASE_ID_RE.fullmatch(case_id):
        raise ValueError(
            "case_id must be a short pseudonym containing lowercase letters, digits, '-' or '_'"
        )
    if IP_LIKE_RE.fullmatch(case_id) or "@" in case_id:
        raise ValueError("case_id must not contain an IP address or email address")
    return case_id


def validate_judgment(row: Mapping[str, Any], *, source: str = "input") -> Dict[str, Any]:
    unknown_fields = set(row) - ALLOWED_FIELDS
    if unknown_fields:
        raise ValueError(
            f"{source}: unsupported fields {sorted(unknown_fields)}; free-form telemetry is not accepted"
        )
    case_id = _validate_case_id(row.get("case_id"))
    try:
        review_round = int(row.get("review_round"))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{source}: review_round must be 1 or 2") from exc
    if review_round not in {1, 2}:
        raise ValueError(f"{source}: review_round must be 1 or 2")
    rubric_version = str(row.get("rubric_version") or "").strip()
    if rubric_version != RUBRIC_VERSION:
        raise ValueError(f"{source}: rubric_version must be {RUBRIC_VERSION}")
    normalized: Dict[str, Any] = {
        "case_id": case_id,
        "review_round": review_round,
        "rubric_version": rubric_version,
    }
    for criterion in CRITERIA:
        label = str(row.get(criterion) or "").strip().lower()
        if label not in ALLOWED_LABELS:
            raise ValueError(
                f"{source}: {criterion} must be one of {sorted(ALLOWED_LABELS)}"
            )
        normalized[criterion] = label
    return normalized


def load_judgments(paths: Sequence[Path]) -> List[Dict[str, Any]]:
    judgments: List[Dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()
    for path in paths:
        with path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, 1):
                if not line.strip():
                    continue
                try:
                    raw = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"{path}:{line_number}: invalid JSON") from exc
                if not isinstance(raw, dict):
                    raise ValueError(f"{path}:{line_number}: each row must be a JSON object")
                row = validate_judgment(raw, source=f"{path}:{line_number}")
                key = (row["case_id"], row["review_round"])
                if key in seen:
                    raise ValueError(
                        f"{path}:{line_number}: duplicate judgment for {row['case_id']} round {row['review_round']}"
                    )
                seen.add(key)
                judgments.append(row)
    if not judgments:
        raise ValueError("No completed judgments were provided")
    return judgments


def _cohen_kappa(first: Iterable[str], second: Iterable[str]) -> Dict[str, Any]:
    pairs = [
        (left, right)
        for left, right in zip(first, second)
        if left in {"yes", "no"} and right in {"yes", "no"}
    ]
    if not pairs:
        return {
            "paired_determinate_count": 0,
            "percent_agreement": None,
            "cohen_kappa": None,
            "kappa_status": "not_estimable_no_paired_determinate_labels",
        }
    observed = sum(left == right for left, right in pairs) / len(pairs)
    first_yes = sum(left == "yes" for left, _ in pairs) / len(pairs)
    second_yes = sum(right == "yes" for _, right in pairs) / len(pairs)
    expected = first_yes * second_yes + (1 - first_yes) * (1 - second_yes)
    if math.isclose(expected, 1.0):
        kappa = None
        status = "not_estimable_degenerate_marginals"
    else:
        kappa = round((observed - expected) / (1 - expected), 6)
        status = "estimated"
    return {
        "paired_determinate_count": len(pairs),
        "percent_agreement": round(observed, 6),
        "cohen_kappa": kappa,
        "kappa_status": status,
    }


def _criterion_summary(rows: Sequence[Mapping[str, Any]], criterion: str) -> Dict[str, Any]:
    counts = Counter(str(row[criterion]) for row in rows)
    determinate = counts["yes"] + counts["no"]
    return {
        "counts": {label: counts[label] for label in sorted(ALLOWED_LABELS)},
        "determinate_count": determinate,
        "yes_rate": _ratio(counts["yes"], determinate),
        "no_rate": _ratio(counts["no"], determinate),
    }


def _quality_rates(summaries: Mapping[str, Mapping[str, Any]]) -> Dict[str, Any]:
    return {
        "relationship_correctness_rate": summaries["relationship_links_correct"]["yes_rate"],
        "claim_grounding_rate": summaries["claims_evidence_grounded"]["yes_rate"],
        "evidence_reference_correctness_rate": summaries["evidence_references_correct"]["yes_rate"],
        "abstention_appropriateness_rate": summaries["abstention_appropriate"]["yes_rate"],
        "overclaim_concern_rate": summaries["overclaim_present"]["yes_rate"],
    }


def score_judgments(judgments: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    normalized = [validate_judgment(row, source="in_memory") for row in judgments]
    keys = [(row["case_id"], row["review_round"]) for row in normalized]
    if len(set(keys)) != len(keys):
        raise ValueError("Duplicate case_id/review_round judgments are not allowed")
    by_round = {
        review_round: [row for row in normalized if row["review_round"] == review_round]
        for review_round in (1, 2)
    }
    indexed = {
        (row["case_id"], row["review_round"]): row
        for row in normalized
    }
    paired_case_ids = sorted(
        case_id
        for case_id in {row["case_id"] for row in normalized}
        if (case_id, 1) in indexed and (case_id, 2) in indexed
    )
    agreement: Dict[str, Any] = {}
    for criterion in CRITERIA:
        agreement[criterion] = _cohen_kappa(
            [indexed[(case_id, 1)][criterion] for case_id in paired_case_ids],
            [indexed[(case_id, 2)][criterion] for case_id in paired_case_ids],
        )

    all_summaries = {
        criterion: _criterion_summary(normalized, criterion)
        for criterion in CRITERIA
    }
    round_summaries = {
        str(review_round): {
            criterion: _criterion_summary(rows, criterion)
            for criterion in CRITERIA
        }
        for review_round, rows in by_round.items()
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "rubric_version": RUBRIC_VERSION,
        "evaluation_type": "structured_single_reviewer_repeat_assessment",
        "validation_status": "not_independent_or_expert_validation",
        "scope": "evidence grounding within Cowrie honeypot-observable SSH telemetry",
        "judgment_count": len(normalized),
        "unique_case_count": len({row["case_id"] for row in normalized}),
        "round_counts": {
            str(review_round): len(rows)
            for review_round, rows in by_round.items()
        },
        "paired_case_count": len(paired_case_ids),
        "criteria": {
            "relationship_links_correct": "yes means every displayed relationship is supported by the visible Cowrie evidence",
            "claims_evidence_grounded": "yes means each claim is bounded by the cited observed evidence",
            "evidence_references_correct": "yes means claim references point to the relevant visible evidence",
            "abstention_appropriate": "yes means generation or abstention is appropriate for available evidence",
            "overclaim_present": "yes means at least one claim asserts unsupported success, causality, intent, attribution, or impact",
        },
        "aggregate_label_summary": all_summaries,
        "round_label_summary": round_summaries,
        "round_quality_rates": {
            review_round: _quality_rates(summaries)
            for review_round, summaries in round_summaries.items()
        },
        "derived_quality_rates": _quality_rates(all_summaries),
        "derived_rate_semantics": (
            "pooled descriptive judgment rates; repeated rounds are not independent observations"
        ),
        "repeat_agreement": agreement,
        "privacy": {
            "case_identifiers_in_output": False,
            "raw_commands_in_output": False,
            "free_form_notes_accepted": False,
            "source_addresses_or_credentials_accepted": False,
        },
        "limitations": [
            "The two rounds are judgments by the same project developer, not independent reviewers.",
            "Repeat agreement measures reviewer consistency and does not establish expert correctness.",
            "Round-specific rates should be reported separately; pooled rates do not double the effective sample size.",
            "Cohen's kappa is omitted when label marginals are degenerate or no determinate pair exists.",
            "Kappa estimates from small paired samples may be unstable and should be accompanied by raw agreement.",
            "Unknown attacker intent and behavior outside Cowrie telemetry are not review targets.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write-template-directory")
    mode.add_argument("--input", action="append")
    parser.add_argument("--case-count", type=int, default=30)
    parser.add_argument("--output")
    args = parser.parse_args()

    if args.write_template_directory:
        outputs = write_review_templates(
            Path(args.write_template_directory),
            case_count=args.case_count,
        )
        print(json.dumps({
            "case_count": args.case_count,
            "rubric_version": RUBRIC_VERSION,
            "outputs": [str(path) for path in outputs],
            "instruction": (
                "Assign selected private sessions to these pseudonymous case IDs outside Git. "
                "Complete round 2 later without consulting round-1 judgments."
            ),
        }, indent=2, sort_keys=True))
        return 0

    if not args.output:
        parser.error("--output is required when --input is used")
    judgments = load_judgments([Path(value) for value in args.input or []])
    document = score_judgments(judgments)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "judgment_count": document["judgment_count"],
        "unique_case_count": document["unique_case_count"],
        "paired_case_count": document["paired_case_count"],
        "derived_quality_rates": document["derived_quality_rates"],
        "output": str(output),
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
