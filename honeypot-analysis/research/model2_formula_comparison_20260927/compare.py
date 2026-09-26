"""Evaluate five advisory-ranking configurations on one controlled row set.

The procedure labels are synthetic controls fixed before inference.  Results
from this module are mechanics/controlled-PoC evidence, never field accuracy.
Raw scores from Model1 and Model2 are deliberately not added together.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import statistics
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from research.model2_unified_session_candidate_20260926 import controlled_poc
from research.model2_unified_session_candidate_20260926.contract import FEATURE_ORDER, LABEL_ORDER


K = 60
W1 = 1.0
W2 = 0.25
VOTE_WEIGHT_MODEL1 = 0.5
VOTE_WEIGHT_MODEL2 = 0.5
WARNING = "CONTROLLED_SYNTHETIC_POC_NOT_REAL_WORLD_ACCURACY"
METHODS = (
    "model1_only",
    "model1_old32_weighted_voting",
    "model1_old32_gated_weighted_reciprocal_rank",
    "model1_new54_weighted_voting",
    "model1_new54_gated_weighted_reciprocal_rank",
)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _time(value: str) -> float:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def _percentile(values: Sequence[float], fraction: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    low, high = math.floor(position), math.ceil(position)
    if low == high:
        return float(ordered[low])
    return float(ordered[low] + (position - low) * (ordered[high] - ordered[low]))


def old32_vector(envelope: Mapping[str, Any]) -> list[float] | None:
    """Materialize the frozen 17 Cowrie + 15 Zeek feature semantics."""
    events = sorted(envelope["cowrie"]["events"], key=lambda row: _time(row["timestamp"]))
    flows = envelope["network"]["flows"]
    # The frozen 32F contract requires at least one complete Zeek flow.  An
    # episode with no flow is unavailable and must fall back to Model1.
    if not flows:
        return None
    timestamps = [_time(row["timestamp"]) for row in events]
    duration = timestamps[-1] - timestamps[0]
    intervals = [right - left for left, right in zip(timestamps, timestamps[1:])]
    auth = [row["eventid"] for row in events if row["eventid"] in {"cowrie.login.failed", "cowrie.login.success"}]
    failures = auth.count("cowrie.login.failed")
    successes = auth.count("cowrie.login.success")
    streak = current = transitions = 0
    previous = None
    for eventid in auth:
        if eventid == "cowrie.login.failed":
            current += 1
            streak = max(streak, current)
        else:
            transitions += previous == "cowrie.login.failed"
            current = 0
        previous = eventid
    buckets: dict[int, int] = {}
    for timestamp in timestamps:
        bucket = int(math.floor(timestamp - timestamps[0]))
        buckets[bucket] = buckets.get(bucket, 0) + 1
    interval_mean = statistics.fmean(intervals) if intervals else 0.0
    c = [
        float(len(auth)), float(failures), float(successes), float(len(auth) / duration),
        float(failures / duration), float(failures / len(auth)) if auth else 0.0,
        float(streak), float(duration), float(statistics.median(intervals)) if intervals else 0.0,
        float(_percentile(intervals, .75) - _percentile(intervals, .25)) if intervals else 0.0,
        float(statistics.pstdev(intervals) / interval_mean) if interval_mean else 0.0,
        float(sum(count >= 2 for count in buckets.values())), 1.0, 1.0 if successes else 0.0,
        float(duration), float(transitions), float(len(events)),
    ]
    ports = [int(row["tuple"]["resp_p"]) for row in flows]
    port_counts = {port: ports.count(port) for port in set(ports)}
    count = len(flows)
    entropy = -sum((n / count) * math.log(n / count) for n in port_counts.values())
    flow_times = sorted(_time(row["ts_utc"]) for row in flows)
    flow_intervals = [right - left for left, right in zip(flow_times, flow_times[1:])]
    flow_mean = statistics.fmean(flow_intervals) if flow_intervals else 0.0
    durations = [float(row["duration"]) for row in flows]
    z = [
        float(count), float(len(port_counts)), float(len(port_counts) / count), float(count / duration),
        float(entropy), float(len({row["tuple"]["proto"] for row in flows})), float(count),
        sum(float(row["orig_bytes"]) for row in flows), sum(float(row["resp_bytes"]) for row in flows),
        sum(float(row["orig_pkts"]) for row in flows), sum(float(row["resp_pkts"]) for row in flows),
        sum(durations), float(statistics.median(durations)),
        sum(row["conn_state"] in {"S0", "REJ", "RSTO", "RSTR", "OTH", "ERR"} for row in flows) / count,
        float(statistics.pstdev(flow_intervals) / flow_mean) if flow_mean else 0.0,
    ]
    return c + z


def infer_old32(vector: Sequence[float], artifact: Mapping[str, Any]) -> dict[str, bool]:
    prep, state = artifact["preprocessing"], artifact["state_dict"]
    transformed = [
        (float(value) - float(center)) / float(scale) * float(block)
        for value, center, scale, block in zip(vector, prep["center"], prep["scale"], prep["block_scales"])
    ]
    return {
        label: math.fsum(float(w) * value for w, value in zip(weights, transformed)) + float(bias) >= float(artifact["threshold"])
        for label, weights, bias in zip(artifact["output_order"], state["weight"], state["bias"])
    }


def infer_new54(vector: Mapping[str, Any], artifact: Mapping[str, Any]) -> dict[str, bool]:
    means, scales = artifact["standardizer"]["means"], artifact["standardizer"]["scales"]
    values = [float(vector[name]) for name in FEATURE_ORDER]
    selected = [(values[index] - float(means[index])) / float(scales[index]) for index in artifact["selected_feature_indices"]]
    output: dict[str, bool] = {}
    for label in LABEL_ORDER:
        head = artifact["heads"][label]
        linear = float(head["bias"]) + math.fsum(float(w) * value for w, value in zip(head["weights"], selected))
        probability = 1.0 / (1.0 + math.exp(-linear))
        output[label] = probability >= float(head["threshold"])
    return output


def model1_events(commands: Sequence[str], predictor: Callable[[str, int], Sequence[Mapping[str, Any]]], top_k: int = 7) -> list[dict[str, Any]]:
    return [
        {"source_event_key": f"command-{index}", "topk": list(predictor(command, top_k))}
        for index, command in enumerate(commands, start=1)
    ]


def model1_scores(events: Sequence[Mapping[str, Any]]) -> dict[str, float]:
    if not events:
        return {}
    scores: dict[str, float] = {}
    for event in events:
        seen: set[str] = set()
        for rank, item in enumerate(event["topk"], start=1):
            label = str(item["technique_id"]).split(".", 1)[0]
            if label in seen:
                continue
            seen.add(label)
            scores[label] = scores.get(label, 0.0) + W1 / len(events) / (K + rank)
    return scores


def eligible_votes(decisions: Mapping[str, bool], vector54: Mapping[str, Any]) -> set[str]:
    """Evidence gates are shared across old/new Model2 and are not labels."""
    votes: set[str] = set()
    if decisions.get("T1105") and float(vector54["transfer_tool_command_count"]) > 0 and float(vector54["network_connection_count"]) > 0:
        votes.add("T1105")
    if decisions.get("T1046") and float(vector54["network_distinct_destination_port_count"]) >= 2:
        votes.add("T1046")
    # A successful login alone is not repeated password guessing.  The raw
    # model result remains in the audit, but cannot vote without repetitions.
    if decisions.get("T1110") and float(vector54["auth_failure_count"]) >= 2 and float(vector54["auth_max_failure_streak"]) >= 2:
        votes.add("T1110")
    return votes


def rank(base: Mapping[str, float], votes: set[str], method: str) -> list[str]:
    candidates = set(base)
    gated = votes & candidates
    if method == "model1":
        scores = dict(base)
    elif method == "weighted":
        scores = {label: VOTE_WEIGHT_MODEL1 + (VOTE_WEIGHT_MODEL2 if label in gated else 0.0) for label in candidates}
    elif method == "gwrre":
        scores = {label: score + (W2 / (K + 1) if label in gated else 0.0) for label, score in base.items()}
    else:
        raise ValueError("unsupported_method")
    return sorted(candidates, key=lambda label: (-scores[label], -base[label], label))


def _ranking_metrics(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    positive = [row for row in rows if row["truth"]]
    hit1 = mrr = ndcg5 = coverage = 0.0
    for row in positive:
        order, truth = row["ranking"], row["truth"]
        coverage += bool(set(order) & truth)
        hit1 += bool(order and order[0] in truth)
        relevant_ranks = [index for index, label in enumerate(order, start=1) if label in truth]
        mrr += 1.0 / min(relevant_ranks) if relevant_ranks else 0.0
        dcg = sum(1.0 / math.log2(index + 1) for index, label in enumerate(order[:5], start=1) if label in truth)
        ideal = sum(1.0 / math.log2(index + 1) for index in range(1, min(5, len(truth)) + 1))
        ndcg5 += dcg / ideal if ideal else 0.0
    denominator = len(positive) or 1
    negatives = [row for row in rows if not row["truth"]]
    return {
        "evaluated_positive_sessions": len(positive),
        "negative_control_sessions": len(negatives),
        "hit_at_1": hit1 / denominator,
        "mrr": mrr / denominator,
        "ndcg_at_5": ndcg5 / denominator,
        "relevant_candidate_coverage": coverage / denominator,
        "negative_control_with_any_model1_candidate": sum(bool(row["ranking"]) for row in negatives),
    }


def evaluate(
    *, model1_predictor: Callable[[str, int], Sequence[Mapping[str, Any]]],
    old_artifact: Mapping[str, Any], new_artifact: Mapping[str, Any], split: str = "SEALED_FINAL",
) -> dict[str, Any]:
    procedures = [procedure for procedure in controlled_poc._procedures() if procedure.split == split]
    result_rows: dict[str, list[dict[str, Any]]] = {method: [] for method in METHODS}
    model2_confusion = {name: {label: {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "unavailable": 0} for label in LABEL_ORDER} for name in ("old32", "new54")}
    t1110_single_success = {"old32_raw_present": 0, "new54_raw_present": 0, "old32_votes": 0, "new54_votes": 0, "rows": 0}
    for procedure in procedures:
        for repetition in range(1, 5):
            envelope, _ = controlled_poc._episode(procedure, repetition)
            extracted = controlled_poc.extract_features(envelope, expected_identity=envelope["cowrie"]["identity"])
            vector54 = extracted["feature_vector"]
            vector32 = old32_vector(envelope)
            old = infer_old32(vector32, old_artifact) if vector32 is not None else {}
            new = infer_new54(vector54, new_artifact)
            truth = {label for index, label in enumerate(LABEL_ORDER) if procedure.labels[index]}
            for name, decisions in (("old32", old), ("new54", new)):
                for label in LABEL_ORDER:
                    if label not in decisions:
                        model2_confusion[name][label]["unavailable"] += 1
                        continue
                    key = "tp" if decisions[label] and label in truth else "fp" if decisions[label] else "fn" if label in truth else "tn"
                    model2_confusion[name][label][key] += 1
            old_votes, new_votes = eligible_votes(old, vector54), eligible_votes(new, vector54)
            if "single_success_t1110_hard_negative" in procedure.tags:
                t1110_single_success["rows"] += 1
                t1110_single_success["old32_raw_present"] += old["T1110"]
                t1110_single_success["new54_raw_present"] += new["T1110"]
                t1110_single_success["old32_votes"] += "T1110" in old_votes
                t1110_single_success["new54_votes"] += "T1110" in new_votes
            events = model1_events(procedure.commands, model1_predictor)
            base = model1_scores(events)
            rankings = {
                METHODS[0]: rank(base, set(), "model1"),
                METHODS[1]: rank(base, old_votes, "weighted"),
                METHODS[2]: rank(base, old_votes, "gwrre"),
                METHODS[3]: rank(base, new_votes, "weighted"),
                METHODS[4]: rank(base, new_votes, "gwrre"),
            }
            for method, ranking in rankings.items():
                result_rows[method].append({"procedure_family": procedure.family, "repetition": repetition, "truth": truth, "ranking": ranking})
    return {
        "warning": WARNING,
        "split": split,
        "paired_rows": len(next(iter(result_rows.values()))),
        "formula_contract": {
            "weighted_voting": "0.5*I(Model1 candidate) + 0.5*I(gated Model2 PRESENT); ties retain Model1 order",
            "gated_weighted_reciprocal_rank": "S(t)=1.0*(1/N)*sum_c I(t in Lc)/(60+r_c(t)) + 0.25*G2(t)/(60+1)",
            "candidate_set": "MODEL1_ONLY",
            "model2_absent_policy": "NO_SUBTRACTION",
            "score_semantics": "RANKING_SCORE_NOT_PROBABILITY_OR_CONFIDENCE",
        },
        "method_metrics": {method: _ranking_metrics(rows) for method, rows in result_rows.items()},
        "model2_raw_confusion": model2_confusion,
        "t1110_single_success_hard_negative": t1110_single_success,
        "limitations": [
            "procedure-defined controlled synthetic labels",
            "not real-world accuracy",
            "same corpus file contains final labels; not independent escrow",
            "Model1 artifact compatibility depends on its pinned sklearn runtime",
        ],
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model1-package", type=Path, required=True)
    parser.add_argument("--old32-artifact", type=Path, required=True)
    parser.add_argument("--new54-artifact", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    from production.classification.s1_advisory_classifier import S1AdvisoryClassifier
    classifier = S1AdvisoryClassifier(args.model1_package)
    old, new = json.loads(args.old32_artifact.read_text()), json.loads(args.new54_artifact.read_text())
    result = evaluate(model1_predictor=lambda command, k: classifier.predict_topk(command, k), old_artifact=old, new_artifact=new)
    result["identities"] = {
        "model1_package_sha256": classifier.package_sha256,
        "old32_artifact_file_sha256": _sha(args.old32_artifact),
        "new54_artifact_file_sha256": _sha(args.new54_artifact),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
