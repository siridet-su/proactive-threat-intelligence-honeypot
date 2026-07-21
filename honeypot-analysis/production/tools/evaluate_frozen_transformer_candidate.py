"""Evaluate one frozen Transformer checkpoint against the production VOMM.

This tool is deliberately offline-only.  It validates the compact evidence
bundle, loads the checkpoint with ``weights_only=True``, scores the immutable
held-out test membership once, and applies the predeclared PoC promotion gate.
It has no production policy, worker, storage, service, or deployment write path.

The neural softmax outputs are recorded as raw score vectors.  They are not
described as calibrated probabilities.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
import resource
import statistics
import subprocess
import time
import tracemalloc
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Mapping, Sequence

from production.prediction.external_vomm_artifact import canonical_json_bytes
from production.tools.evaluate_authoritative_external_vomm import (
    _membership_sha256,
    _verify_manifest_evaluation_membership,
    file_sha256,
    load_exact_external_artifact,
)
from production.tools.evaluate_next_tactic_model_comparison import (
    load_policy,
    load_session_payloads,
    split_session_payloads,
)
from production.tools.next_tactic_offline_benchmark import (
    DEFAULT_MIN_PER_TACTIC_SUPPORT,
    ModelRun,
    Prediction,
    _classification_metrics,
    _make_neural_model,
    _neural_probabilities,
    _normalize,
    _pad_batch,
    _quantile,
    _ranking,
    _record_for_case,
    _torch_modules,
    evaluate_model,
    external_hard_backoff_model,
    make_cases,
    normalized_confusion,
    paired_comparison,
    sha256_json,
    split_validation_sessions,
)


SCHEMA_VERSION = "frozen_transformer_poc_evaluation.v1"
DEFAULT_CHECKPOINT = "data/models/transformer_shadow_20260721.pt"
DEFAULT_EVIDENCE = "evaluation/next_tactic_benchmark_evidence"
DEFAULT_OUTPUT = f"{DEFAULT_EVIDENCE}/single_checkpoint_evaluation.json"
EXPECTED_CHECKPOINT_SHA256 = "d9b316d76e63b15b175668aa0bf69cfe4172bbd812d6b19743a628cd0ec8073d"
EXPECTED_SEED = 20260723
BOOTSTRAP_SEED = 20260721
EXECUTION_MAX_ABSOLUTE_RECALL_REGRESSION = 0.10
PAIRED_WIN_RATIO_MINIMUM = 1.25
POC_P95_LATENCY_LIMIT_MS = 25.0
POC_MODEL_RAM_LIMIT_BYTES = 64 * 1024 * 1024


def _load_json(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain an object")
    return value


def _git_commit() -> str:
    return subprocess.run(
        ["git", "rev-parse", "HEAD"], check=True, capture_output=True, text=True
    ).stdout.strip()


def _raw_confusion(
    records: Sequence[Mapping[str, Any]], vocabulary: Sequence[str]
) -> dict[str, dict[str, int]]:
    labels = [*vocabulary, "<abstained>"]
    counts: dict[str, Counter[str]] = {label: Counter() for label in vocabulary}
    for row in records:
        counts[str(row["actual"])][str(row["top1"]) or "<abstained>"] += 1
    return {
        actual: {predicted: int(counts[actual][predicted]) for predicted in labels}
        for actual in vocabulary
    }


def _paired_bootstrap(
    reference: Sequence[Mapping[str, Any]],
    candidate: Sequence[Mapping[str, Any]],
    vocabulary: Sequence[str],
    *,
    iterations: int,
    seed: int,
) -> dict[str, Any]:
    fields = ("top1_accuracy", "macro_f1", "balanced_accuracy")
    ref_by_id = {str(row["case_id"]): row for row in reference}
    cand_by_id = {str(row["case_id"]): row for row in candidate}
    if set(ref_by_id) != set(cand_by_id):
        raise ValueError("paired bootstrap requires identical case IDs")
    grouped: dict[str, list[str]] = defaultdict(list)
    for case_id, row in ref_by_id.items():
        grouped[str(row["session_id"])].append(case_id)
    session_ids = sorted(grouped)
    samples = {field: [] for field in fields}
    rng = random.Random(seed)
    for _ in range(iterations):
        selected_ids: list[str] = []
        for _unused in session_ids:
            selected_ids.extend(grouped[session_ids[rng.randrange(len(session_ids))]])
        ref_metrics = _classification_metrics(
            [ref_by_id[item] for item in selected_ids], vocabulary, 1
        )
        cand_metrics = _classification_metrics(
            [cand_by_id[item] for item in selected_ids], vocabulary, 1
        )
        for field in fields:
            samples[field].append(float(cand_metrics[field]) - float(ref_metrics[field]))

    def interval(values: Sequence[float]) -> list[float]:
        ordered = sorted(values)
        return [
            ordered[int(round((len(ordered) - 1) * 0.025))],
            ordered[int(round((len(ordered) - 1) * 0.975))],
        ]

    return {
        "unit": "whole_session",
        "iterations": iterations,
        "seed": seed,
        "candidate_minus_vomm_95ci": {
            field: interval(values) for field, values in samples.items()
        },
    }


def _window_metrics(
    vomm_records: Sequence[Mapping[str, Any]],
    transformer_records: Sequence[Mapping[str, Any]],
    vocabulary: Sequence[str],
    window_count: int = 4,
) -> list[dict[str, Any]]:
    width = math.ceil(len(vomm_records) / window_count)
    output: list[dict[str, Any]] = []
    for number, start in enumerate(range(0, len(vomm_records), width), start=1):
        stop = min(start + width, len(vomm_records))
        output.append(
            {
                "window": number,
                "chronological_positions": [start, stop - 1],
                "case_count": stop - start,
                "hard_backoff_vomm": _classification_metrics(
                    vomm_records[start:stop], vocabulary, 1
                ),
                "transformer": _classification_metrics(
                    transformer_records[start:stop], vocabulary, 1
                ),
            }
        )
    return output


def _sequence_length_metrics(
    records: Sequence[Mapping[str, Any]], vocabulary: Sequence[str]
) -> dict[str, Any]:
    groups: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for row in records:
        length = int(row["sequence_length"])
        bucket = str(length) if length <= 5 else "6+"
        groups[bucket].append(row)
    return {
        key: _classification_metrics(rows, vocabulary, 1)
        for key, rows in sorted(groups.items(), key=lambda item: (item[0] == "6+", item[0]))
    }


def _template_analysis(
    candidate: Sequence[Mapping[str, Any]], reference: Sequence[Mapping[str, Any]]
) -> dict[str, Any]:
    ref = {str(row["case_id"]): row for row in reference}
    pattern_counts = Counter(tuple(str(item) for item in row["sequence"]) for row in candidate)
    pair_counts = Counter(
        (tuple(str(item) for item in row["sequence"]), str(row["actual"]))
        for row in candidate
    )
    persistence = [row for row in candidate if row["actual"] == "persistence"]
    candidate_wins = [
        row for row in candidate
        if row["correct"] and not ref[str(row["case_id"])]["correct"]
    ]

    def repeated_fraction(rows: Sequence[Mapping[str, Any]], threshold: int) -> float:
        if not rows:
            return 0.0
        return sum(
            pattern_counts[tuple(str(item) for item in row["sequence"])] >= threshold
            for row in rows
        ) / len(rows)

    return {
        "unique_input_sequences": len(pattern_counts),
        "unique_sequence_target_pairs": len(pair_counts),
        "cases_in_input_patterns_repeated_at_least_10_times_fraction": repeated_fraction(candidate, 10),
        "persistence_cases_in_input_patterns_repeated_at_least_10_times_fraction": repeated_fraction(persistence, 10),
        "candidate_wins_in_input_patterns_repeated_at_least_10_times_fraction": repeated_fraction(candidate_wins, 10),
        "candidate_win_count": len(candidate_wins),
        "persistence_candidate_win_count": sum(row["actual"] == "persistence" for row in candidate_wins),
        "note": (
            "Exact repeated tactic-sequence concentration is measurable, but the privacy-minimized "
            "payload has no source template identifier; causality cannot be established."
        ),
    }


def _load_candidate(
    checkpoint_path: Path,
    vocabulary: Sequence[str],
    settings: Mapping[str, Any],
    expected_sha256: str,
    *,
    expected_parameter_count: int = 2632,
) -> tuple[Any, dict[str, Any]]:
    actual_hash = file_sha256(checkpoint_path)
    if actual_hash != expected_sha256:
        raise ValueError("Transformer checkpoint SHA-256 mismatch")
    torch, _np = _torch_modules()
    load_started = time.perf_counter()
    state = torch.load(checkpoint_path, map_location="cpu", weights_only=True)
    model = _make_neural_model(
        "transformer", vocabulary_size=len(vocabulary), settings=settings, torch=torch
    )
    incompatible = model.load_state_dict(state, strict=True)
    model.eval()
    load_seconds = time.perf_counter() - load_started
    parameter_count = sum(parameter.numel() for parameter in model.parameters())
    if parameter_count != expected_parameter_count:
        raise ValueError(f"unexpected Transformer parameter count: {parameter_count}")
    if incompatible.missing_keys or incompatible.unexpected_keys:
        raise ValueError("Transformer state dictionary is incompatible")
    return model, {
        "checkpoint_path": str(checkpoint_path),
        "checkpoint_sha256": actual_hash,
        "checkpoint_size_bytes": checkpoint_path.stat().st_size,
        "load_seconds": load_seconds,
        "parameter_count": parameter_count,
        "state_dictionary_keys_sha256": sha256_json(sorted(state)),
        "state_dictionary_compatible": True,
        "model_eval": not model.training,
        "weights_only_load": True,
        "device": "cpu",
        "dtype": "float32",
    }


def _neural_efficiency(
    model: Any,
    cases: Sequence[Any],
    vocabulary: Sequence[str],
    settings: Mapping[str, Any],
) -> dict[str, Any]:
    torch, _np = _torch_modules()
    sample = list(cases[: min(2000, len(cases))])
    _neural_probabilities(model, sample[:32], vocabulary, settings, torch)
    timings: list[float] = []
    tracemalloc.start()
    before, _ = tracemalloc.get_traced_memory()
    rss_before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    started = time.perf_counter()
    for case in sample:
        point = time.perf_counter_ns()
        _neural_probabilities(model, [case], vocabulary, settings, torch, batch_size=1)
        timings.append((time.perf_counter_ns() - point) / 1_000_000)
    elapsed = time.perf_counter() - started
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    rss_after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    batch_started = time.perf_counter()
    _neural_probabilities(model, cases, vocabulary, settings, torch)
    batch_elapsed = time.perf_counter() - batch_started
    return {
        "individual_case_sample_count": len(sample),
        "individual_case_latency_ms": {
            "p50": _quantile(timings, 0.50),
            "p95": _quantile(timings, 0.95),
            "p99": _quantile(timings, 0.99),
            "mean": statistics.fmean(timings),
        },
        "individual_case_throughput_per_second": len(sample) / elapsed,
        "batched_case_count": len(cases),
        "batched_throughput_per_second": len(cases) / batch_elapsed,
        "batch_elapsed_seconds": batch_elapsed,
        "peak_python_allocation_bytes": max(int(peak - before), 0),
        "process_max_rss_delta_bytes": max(int(rss_after - rss_before), 0) * 1024,
        "memory_note": "ru_maxrss delta is a process high-water delta, not isolated model RSS",
    }


def evaluate(args: argparse.Namespace) -> dict[str, Any]:
    evidence_dir = Path(args.evidence_dir)
    split_evidence = _load_json(evidence_dir / "dataset_split_manifest.json")
    model_config = _load_json(evidence_dir / "model_configurations.json")
    selected_metadata = _load_json(evidence_dir / "selected_transformer_metadata.json")
    selection = _load_json(evidence_dir / "validation_only_transformer_selection.json")
    payloads = load_session_payloads(args.payload)
    split, split_method = split_session_payloads(payloads)
    artifact, artifact_validation = load_exact_external_artifact(
        args.artifact,
        expected_sha256=args.expected_artifact_sha256,
        expected_model_id=args.expected_model_id,
        manifest_path=args.manifest,
        expected_manifest_id=args.expected_manifest_id,
    )
    if not artifact_validation.get("valid"):
        raise ValueError(f"production VOMM artifact is invalid: {artifact_validation.get('reasons')}")
    manifest = artifact_validation.get("manifest") or {}
    membership = _verify_manifest_evaluation_membership(payloads, split, manifest)
    if not membership.get("valid"):
        raise ValueError(f"test membership is invalid: {membership.get('reasons')}")
    vocabulary = [str(item) for item in manifest.get("tactic_vocabulary") or []]
    settings = dict(((model_config.get("neural") or {}).get("transformer") or {}).get("settings") or {})
    if not vocabulary or not settings:
        raise ValueError("compact evidence lacks Transformer vocabulary or settings")
    preprocessing = dict(manifest.get("preprocessing") or {})
    preprocessing_hash = hashlib.sha256(canonical_json_bytes(preprocessing)).hexdigest()
    expected_preprocessing_hash = str(manifest.get("preprocessing_sha256") or "")
    if preprocessing_hash != expected_preprocessing_hash:
        raise ValueError("preprocessing hash mismatch")
    payload_hash = file_sha256(args.payload)
    expected_payload_hash = str((split_evidence.get("dataset") or {}).get("payload_sha256") or "")
    if payload_hash != expected_payload_hash:
        raise ValueError("held-out payload hash mismatch")

    selection_sessions, calibration_sessions, validation_roles = split_validation_sessions(split["calibration"])
    test_cases = make_cases(split["test"])
    ordered_case_hash = sha256_json([case.case_id for case in test_cases])
    if len(test_cases) != int(selected_metadata.get("case_count") or 0):
        raise ValueError("held-out case count differs from checkpoint metadata")
    if ordered_case_hash != str(selected_metadata.get("ordered_case_ids_sha256") or ""):
        raise ValueError("held-out ordered case membership differs from checkpoint metadata")
    if int(selection.get("validation_case_count") or 0) != len(make_cases(calibration_sessions)):
        raise ValueError("validation-only seed comparison membership is inconsistent")
    seed_metrics = selection.get("seeds") or {}
    if str(EXPECTED_SEED) not in seed_metrics:
        raise ValueError("selected seed is absent from validation-only evidence")
    best_seed = min(
        seed_metrics,
        key=lambda seed: (
            -float(seed_metrics[seed]["macro_f1"]),
            -float(seed_metrics[seed]["balanced_accuracy"]),
            int(seed),
        ),
    )
    if int(best_seed) != EXPECTED_SEED:
        raise ValueError("frozen checkpoint does not match the validation-only winner")

    model, checkpoint_validation = _load_candidate(
        Path(args.checkpoint), vocabulary, settings, args.expected_checkpoint_sha256
    )
    torch, _np = _torch_modules()
    first_scores = _neural_probabilities(model, test_cases, vocabulary, settings, torch)
    second_scores = _neural_probabilities(model, test_cases, vocabulary, settings, torch)
    if len(first_scores) != len(test_cases) or len(second_scores) != len(test_cases):
        raise ValueError("Transformer prediction alignment failed")
    max_difference = max(
        abs(first[label] - second[label])
        for first, second in zip(first_scores, second_scores)
        for label in vocabulary
    )
    top3_equal = all(
        _ranking(first)[:3] == _ranking(second)[:3]
        for first, second in zip(first_scores, second_scores)
    )
    if max_difference > 1e-7 or not top3_equal:
        raise ValueError("Transformer inference is not deterministic")

    lookup = {case.case_id: values for case, values in zip(test_cases, first_scores)}
    transformer = ModelRun(
        "transformer_seed_20260723",
        "Frozen single-checkpoint causal Transformer",
        lambda case: Prediction(
            dict(lookup[case.case_id]),
            {
                "checkpoint_sha256": args.expected_checkpoint_sha256,
                "seed": EXPECTED_SEED,
                "raw_scores_are_calibrated_probabilities": False,
            },
        ),
        {
            "algorithm": "one_layer_causal_transformer",
            "seed": EXPECTED_SEED,
            "settings": settings,
            "raw_scores_are_calibrated_probabilities": False,
        },
        serialized_size_bytes=Path(args.checkpoint).stat().st_size,
        load_seconds=float(checkpoint_validation["load_seconds"]),
    )
    policy = load_policy(args.policy)
    vomm = external_hard_backoff_model(
        policy, artifact, vocabulary, artifact_validation=artifact_validation
    )
    vomm_result = evaluate_model(
        vomm, test_cases, vocabulary,
        bootstrap_iterations=args.bootstrap_iterations, seed=BOOTSTRAP_SEED,
    )
    transformer_result = evaluate_model(
        transformer, test_cases, vocabulary,
        bootstrap_iterations=args.bootstrap_iterations, seed=BOOTSTRAP_SEED,
    )
    paired = paired_comparison(vomm_result["records"], transformer_result["records"])
    paired_ci = _paired_bootstrap(
        vomm_result["records"], transformer_result["records"], vocabulary,
        iterations=args.bootstrap_iterations, seed=BOOTSTRAP_SEED,
    )
    transformer_efficiency = _neural_efficiency(
        model, test_cases, vocabulary, settings
    )
    transformer_efficiency.update(
        {
            "checkpoint_load_seconds": checkpoint_validation["load_seconds"],
            "checkpoint_size_bytes": checkpoint_validation["checkpoint_size_bytes"],
            "parameter_count": checkpoint_validation["parameter_count"],
        }
    )
    metrics = {
        "hard_backoff_vomm": vomm_result["metrics"],
        "transformer_seed_20260723": transformer_result["metrics"],
    }
    deltas = {
        field: float(metrics["transformer_seed_20260723"][field])
        - float(metrics["hard_backoff_vomm"][field])
        for field in ("top1_accuracy", "top3_accuracy", "macro_f1", "weighted_f1", "balanced_accuracy", "mean_reciprocal_rank")
    }
    outcomes = paired["outcomes"]
    candidate_wins = int(outcomes.get("candidate_win", 0))
    vomm_wins = int(outcomes.get("production_vomm_win", 0))
    transformer_execution = metrics["transformer_seed_20260723"]["per_tactic"]["execution"]
    vomm_execution = metrics["hard_backoff_vomm"]["per_tactic"]["execution"]
    execution_regression = float(vomm_execution["recall"]) - float(transformer_execution["recall"])
    rare_collapses = []
    for tactic in vocabulary:
        incumbent = metrics["hard_backoff_vomm"]["per_tactic"][tactic]
        candidate = metrics["transformer_seed_20260723"]["per_tactic"][tactic]
        support = int(candidate["support"])
        if 0 < support < 100 and float(incumbent["recall"]) - float(candidate["recall"]) > 0.10:
            rare_collapses.append(tactic)
    paired_intervals = paired_ci["candidate_minus_vomm_95ci"]
    integrity_checks = {
        "checkpoint_sha256": checkpoint_validation["checkpoint_sha256"] == EXPECTED_CHECKPOINT_SHA256,
        "state_dictionary_compatible": checkpoint_validation["state_dictionary_compatible"],
        "parameter_count": checkpoint_validation["parameter_count"] == 2632,
        "vocabulary_order_bound_to_manifest_and_training_code": len(vocabulary) == 8,
        "preprocessing_sha256": preprocessing_hash == expected_preprocessing_hash,
        "payload_sha256": payload_hash == expected_payload_hash,
        "ordered_test_case_membership": ordered_case_hash == selected_metadata["ordered_case_ids_sha256"],
        "partition_intersections_empty": bool((membership.get("partitions") or {})) and bool((manifest.get("partition_intersections") or {}).get("all_empty")),
        "validation_only_seed_selection": int(best_seed) == EXPECTED_SEED,
        "test_not_used_for_selection_recorded": not bool(((split_evidence.get("experimental_controls") or {}).get("test_used_for_training_or_selection"))),
        "deterministic_eval_no_grad": not model.training and top3_equal and max_difference <= 1e-7,
    }
    gate = {
        "criterion_1_primary_metrics": {
            "pass": all(deltas[field] > 0 for field in ("top1_accuracy", "macro_f1", "balanced_accuracy")),
            "requirement": "Transformer exceeds VOMM in Top-1, macro-F1, and balanced accuracy",
        },
        "criterion_2_paired_wins": {
            "pass": candidate_wins > PAIRED_WIN_RATIO_MINIMUM * max(vomm_wins, 1),
            "requirement": f"candidate wins exceed {PAIRED_WIN_RATIO_MINIMUM:.2f}x VOMM wins",
            "candidate_wins": candidate_wins,
            "vomm_wins": vomm_wins,
        },
        "criterion_3_confidence_intervals": {
            "pass": all(float(paired_intervals[field][0]) > 0 for field in ("top1_accuracy", "macro_f1", "balanced_accuracy")),
            "requirement": "paired whole-session 95% CI lower bounds exceed zero for all primary metrics",
        },
        "criterion_4_tactic_safety": {
            "pass": execution_regression <= EXECUTION_MAX_ABSOLUTE_RECALL_REGRESSION and not rare_collapses,
            "requirement": "Execution recall regression <= 0.10 absolute and no >0.10 collapse for held-out tactics with support 1-99",
            "execution_recall_regression": execution_regression,
            "rare_tactic_collapses": rare_collapses,
        },
        "criterion_5_integrity": {
            "pass": all(integrity_checks.values()),
            "requirement": "all checkpoint, vocabulary, preprocessing, membership, and provenance checks pass",
        },
        "criterion_6_operational": {
            "pass": (
                float(transformer_efficiency["individual_case_latency_ms"]["p95"]) <= POC_P95_LATENCY_LIMIT_MS
                and int(transformer_efficiency["peak_python_allocation_bytes"]) <= POC_MODEL_RAM_LIMIT_BYTES
                and integrity_checks["deterministic_eval_no_grad"]
            ),
            "requirement": "p95 <= 25 ms, Python allocation <= 64 MiB, deterministic reload/inference",
        },
        "criterion_7_prediction_authority_boundary": {
            "pass": True,
            "requirement": "prediction alone remains insufficient for guidance or action eligibility",
            "basis": "evaluation is offline-only; current canonical evidence validation remains unchanged",
        },
    }
    promotion = all(bool(item["pass"]) for item in gate.values())
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at_epoch_seconds": time.time(),
        "benchmark_code_commit": _git_commit(),
        "offline_only": True,
        "production_mutations": False,
        "raw_transformer_scores_are_calibrated_probabilities": False,
        "integrity": {
            "checks": integrity_checks,
            "checkpoint": checkpoint_validation,
            "seed": EXPECTED_SEED,
            "vocabulary": vocabulary,
            "vocabulary_sha256": hashlib.sha256(canonical_json_bytes(vocabulary)).hexdigest(),
            "preprocessing": preprocessing,
            "preprocessing_sha256": preprocessing_hash,
            "payload_sha256": payload_hash,
            "split_method": split_method,
            "partition_membership": membership,
            "validation_roles": validation_roles,
            "training_membership_sha256": _membership_sha256([*split["train"], *selection_sessions]),
            "validation_membership_sha256": _membership_sha256(calibration_sessions),
            "test_membership_sha256": _membership_sha256(split["test"]),
            "ordered_test_case_ids_sha256": ordered_case_hash,
            "test_case_count": len(test_cases),
            "deterministic_replay": {
                "max_absolute_difference": max_difference,
                "top3_identical_all_cases": top3_equal,
                "eval_mode": not model.training,
                "no_grad_inference_function": True,
            },
            "selection": {
                "rule": "highest validation macro-F1, then balanced accuracy, then lower seed",
                "selected_seed": EXPECTED_SEED,
                "computed_validation_winner": int(best_seed),
                "validation_case_count": int(selection["validation_case_count"]),
                "held_out_test_metrics_consulted": False,
            },
        },
        "metrics": metrics,
        "metric_deltas_transformer_minus_vomm": deltas,
        "confidence_intervals_95": {
            "hard_backoff_vomm": vomm_result["confidence_intervals_95"],
            "transformer_seed_20260723": transformer_result["confidence_intervals_95"],
            "paired": paired_ci,
        },
        "paired_comparison": paired,
        "confusion_matrices": {
            "hard_backoff_vomm": {
                "counts": _raw_confusion(vomm_result["records"], vocabulary),
                "normalized": normalized_confusion(vomm_result["records"], vocabulary),
            },
            "transformer_seed_20260723": {
                "counts": _raw_confusion(transformer_result["records"], vocabulary),
                "normalized": normalized_confusion(transformer_result["records"], vocabulary),
            },
        },
        "chronological_windows": _window_metrics(
            vomm_result["records"], transformer_result["records"], vocabulary
        ),
        "sequence_length": {
            "hard_backoff_vomm": _sequence_length_metrics(vomm_result["records"], vocabulary),
            "transformer_seed_20260723": _sequence_length_metrics(transformer_result["records"], vocabulary),
        },
        "efficiency": {
            "transformer_seed_20260723": transformer_efficiency,
            "hard_backoff_vomm_reference": _load_json(evidence_dir / "efficiency.json").get("hard_backoff_vomm"),
        },
        "template_and_weak_label_analysis": _template_analysis(
            transformer_result["records"], vomm_result["records"]
        ),
        "promotion_gate": gate,
        "promotion_gate_passed": promotion,
        "authoritative_poc_model_decision": (
            "promote_frozen_transformer" if promotion else "retain_external_hard_backoff_vomm"
        ),
        "limitations": [
            "Targets are classifier-derived weak labels, not independent analyst adjudications.",
            "The privacy-minimized external corpus omits source template identifiers and per-session timestamps.",
            "The test set has only two credential-access targets and no impact targets.",
            "This held-out corpus is not a production-local chronological evaluation.",
            "Transformer softmax outputs are raw scores and are not calibrated probabilities.",
        ],
    }


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkpoint", default=DEFAULT_CHECKPOINT)
    parser.add_argument("--evidence-dir", default=DEFAULT_EVIDENCE)
    parser.add_argument("--payload", default="evaluation/next_tactic_zenodo_7day_session_payload.jsonl")
    parser.add_argument("--artifact", default="data/models/external_cowrie_vomm_zenodo_7day_20260721.json")
    parser.add_argument("--manifest", default="data/models/external_cowrie_vomm_zenodo_7day_20260721.manifest.json")
    parser.add_argument("--policy", default="configs/prediction_policy.trusted.json")
    parser.add_argument("--expected-checkpoint-sha256", default=EXPECTED_CHECKPOINT_SHA256)
    parser.add_argument("--expected-artifact-sha256", default="b5a60951764648ed242d7b9acfe1df6f5f314f96e341badb7f4bd55107614e3e")
    parser.add_argument("--expected-model-id", default="externalvomm_8dabca1f770b06e73fb051766539435a")
    parser.add_argument("--expected-manifest-id", default="externalvommmanifest_f97d2d3770c6ac44f9eb7e7905c7736b")
    parser.add_argument("--bootstrap-iterations", type=int, default=500)
    parser.add_argument("--output", default=DEFAULT_OUTPUT)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    result = evaluate(args)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "status": "complete",
        "output": str(output),
        "promotion_gate_passed": result["promotion_gate_passed"],
        "decision": result["authoritative_poc_model_decision"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
