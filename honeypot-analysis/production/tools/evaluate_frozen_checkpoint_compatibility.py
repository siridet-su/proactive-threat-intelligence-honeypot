"""Evaluate the frozen Transformer under the corrected current-policy contract.

This command never trains, fine-tunes, recalibrates, or writes source data.  It
reprocesses immutable privacy-safe role sessions, runs three predeclared arms
(old trust, current trust, and current trust with audit counts ablated), and
publishes only privacy-safe corpus artifacts and aggregate receipts.

The sealed ``test`` role may be opened only after this implementation and its
JSON contract have been frozen in Git.  Use ``selection`` with a bounded
session count for implementation preflight.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import shutil
import subprocess
import time
from collections import Counter, defaultdict
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Sequence

from production.prediction.next_behavior_contract import (
    TARGET_CONTRACT_ID,
    TACTIC_VOCABULARY,
    require_valid_next_behavior_session,
)
from production.prediction.next_behavior_model import (
    load_checkpoint,
    require_valid_model_spec,
)
from production.prediction.next_behavior_preprocessing import (
    build_behavior_phases,
    build_next_behavior_examples,
)
from production.prediction.next_behavior_tensor import (
    require_valid_vocabulary,
    tensorize_example,
    vocabulary_sha256,
)
from production.reproduction.next_behavior.calibration import (
    require_valid_calibration_mapping,
)
from production.reproduction.next_behavior.compatibility_evaluation import (
    COMPATIBILITY_CORPUS_SCHEMA_VERSION,
    force_zero_audit_example,
    reprocess_retained_safe_session,
)
from production.reproduction.next_behavior.metrics import (
    align_examples_and_predictions,
    multilabel_tactic_metrics,
    nonterminal_ranking_metrics,
    terminal_and_discrimination_metrics,
)
from production.utils.serialization import stable_json


EVALUATION_SCHEMA_VERSION = (
    "next_behavior_checkpoint_compatibility_evaluation.v1"
)
CONTRACT_SCHEMA_VERSION = (
    "next_behavior_checkpoint_compatibility_contract.v1"
)
_TENSOR_BATCH_FIELDS = (
    "phase_tactic_multi_hot",
    "phase_technique_multi_hot",
    "phase_source_multi_hot",
    "phase_confidence_multi_hot",
    "phase_agreement_multi_hot",
)
_TENSOR_INDEX_FIELDS = (
    "phase_repetition_index",
    "phase_elapsed_time_index",
    "phase_audit_count_index",
)
_CONTEXT_FIELDS = (
    "context_login_outcome_index",
    "context_command_count_index",
    "context_session_age_index",
    "context_confirmed_transfer",
)


class CompatibilityEvaluationError(ValueError):
    """Raised when a frozen compatibility-evaluation gate is violated."""


def _sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(stable_json(value).encode("utf-8")).hexdigest()


def _sha256_json_rows(values: Iterable[Mapping[str, Any]]) -> str:
    digest = hashlib.sha256()
    for value in values:
        digest.update(stable_json(value).encode("utf-8"))
        digest.update(b"\n")
    return digest.hexdigest()


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CompatibilityEvaluationError(
            f"cannot read JSON artifact: {path}"
        ) from exc


def _git_revision(root: Path) -> str:
    try:
        return subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise CompatibilityEvaluationError(
            "evaluator Git revision is unavailable"
        ) from exc


def _require_sha(value: Any, field: str) -> str:
    text = str(value or "").strip().lower()
    if len(text) != 64 or any(character not in "0123456789abcdef" for character in text):
        raise CompatibilityEvaluationError(f"{field} must be a SHA-256 digest")
    return text


def _verify_file(path: Path, expected: Any, label: str) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise CompatibilityEvaluationError(f"{label} is missing or unsafe")
    digest = _sha256_path(path)
    if digest != _require_sha(expected, f"{label}.sha256"):
        raise CompatibilityEvaluationError(f"{label} SHA-256 mismatch")
    return {
        "path": str(path),
        "sha256": digest,
        "size_bytes": path.stat().st_size,
    }


def _load_contract(path: Path, root: Path) -> dict[str, Any]:
    value = _read_json(path)
    if not isinstance(value, dict):
        raise CompatibilityEvaluationError("evaluation contract must be an object")
    if value.get("schema_version") != CONTRACT_SCHEMA_VERSION:
        raise CompatibilityEvaluationError("evaluation contract schema mismatch")
    if value.get("target_contract_id") != TARGET_CONTRACT_ID:
        raise CompatibilityEvaluationError("evaluation target changed")
    if value.get("model_changes_permitted") is not False:
        raise CompatibilityEvaluationError("evaluation contract permits model changes")
    if value.get("final_role_use") != "single_predeclared_compatibility_evaluation":
        raise CompatibilityEvaluationError("final role use is not frozen")
    if value.get("probability_thresholds") != {
        "tactic": 0.5,
        "terminal": 0.5,
    }:
        raise CompatibilityEvaluationError("runtime probability thresholds changed")
    code_hashes = value.get("code_sha256")
    if not isinstance(code_hashes, dict) or not code_hashes:
        raise CompatibilityEvaluationError("evaluation code hashes are missing")
    for relative, expected in sorted(code_hashes.items()):
        _verify_file(root / relative, expected, f"code:{relative}")
    return value


def _minimal_example(example: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "target_contract_id": example["target_contract_id"],
        "example_id": example["example_id"],
        "session_id": example["session_id"],
        "target": deepcopy(example["target"]),
    }


def _audit_bucket(value: int) -> str:
    if value <= 0:
        return "0"
    if value == 1:
        return "1"
    if value <= 5:
        return "2-5"
    return "6+"


def _example_source_bucket(example: Mapping[str, Any]) -> str:
    sources = sorted(
        {
            str(source)
            for phase in example["model_input"]["phase_sequence"]
            for source in phase.get("label_provenance_sources") or []
        }
    )
    return "+".join(sources) if sources else "none"


def _example_audit_bucket(example: Mapping[str, Any]) -> str:
    return _audit_bucket(
        int(
            example["model_input"]["phase_sequence"][-1].get(
                "audit_only_label_count", 0
            )
        )
    )


def _torch_batch(tensors: Sequence[Mapping[str, Any]], torch: Any) -> dict[str, Any]:
    batch: dict[str, Any] = {}
    for field in _TENSOR_BATCH_FIELDS:
        batch[field] = torch.tensor(
            [tensor[field] for tensor in tensors],
            dtype=torch.float32,
            device="cpu",
        )
    batch["attention_mask"] = torch.tensor(
        [tensor["attention_mask"] for tensor in tensors],
        dtype=torch.bool,
        device="cpu",
    )
    for field in _TENSOR_INDEX_FIELDS:
        batch[field] = torch.tensor(
            [tensor[field] for tensor in tensors],
            dtype=torch.long,
            device="cpu",
        )
    for field in _CONTEXT_FIELDS:
        batch[field] = torch.tensor(
            [tensor[field] for tensor in tensors],
            dtype=torch.long,
            device="cpu",
        )
    return batch


def _sigmoid(logit: float, temperature: float) -> float:
    scaled = float(logit) / float(temperature)
    if scaled >= 0:
        return 1.0 / (1.0 + math.exp(-scaled))
    exponential = math.exp(scaled)
    return exponential / (1.0 + exponential)


def _infer_batch(
    model: Any,
    examples: Sequence[Mapping[str, Any]],
    *,
    vocabulary: Mapping[str, Any],
    calibration: Mapping[str, Any],
    torch: Any,
) -> list[dict[str, Any]]:
    if not examples:
        return []
    tensors = [tensorize_example(example, vocabulary) for example in examples]
    model.eval()
    with torch.inference_mode():
        tactic_logits, terminal_logits = model(_torch_batch(tensors, torch))
    tactic_rows = tactic_logits.detach().cpu().tolist()
    terminal_rows = terminal_logits.detach().cpu().tolist()
    tactics = sorted(TACTIC_VOCABULARY)
    output = []
    for example, tensor, raw_tactics, raw_terminal in zip(
        examples,
        tensors,
        tactic_rows,
        terminal_rows,
        strict=True,
    ):
        probabilities = {
            tactic: _sigmoid(score, calibration["tactic_temperature"])
            for tactic, score in zip(tactics, raw_tactics, strict=True)
        }
        terminal_probability = _sigmoid(
            raw_terminal,
            calibration["terminal_temperature"],
        )
        ranked = sorted(
            tactics,
            key=lambda tactic: (-probabilities[tactic], tactic),
        )
        predicted_terminal = terminal_probability >= 0.5
        predicted = (
            []
            if predicted_terminal
            else sorted(
                tactic
                for tactic in tactics
                if probabilities[tactic] >= 0.5
            )
        )
        if not predicted_terminal and not predicted:
            predicted = [ranked[0]]
        output.append(
            {
                "example_id": example["example_id"],
                "session_id": example["session_id"],
                "status": "predicted",
                "ranked_tactics": ranked,
                "predicted_tactics": predicted,
                "predicted_terminal": predicted_terminal,
                "_probabilities": probabilities,
                "_terminal_probability": terminal_probability,
                "_tensor_hash": tensor["tensor_hash"],
                "_prediction_event_order": example["prediction_event_order"],
            }
        )
    return output


def _infer_in_chunks(
    model: Any,
    examples: Sequence[Mapping[str, Any]],
    *,
    vocabulary: Mapping[str, Any],
    calibration: Mapping[str, Any],
    torch: Any,
    batch_size: int,
) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for start in range(0, len(examples), batch_size):
        output.extend(
            _infer_batch(
                model,
                examples[start : start + batch_size],
                vocabulary=vocabulary,
                calibration=calibration,
                torch=torch,
            )
        )
    return output


def _public_prediction(value: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: deepcopy(item)
        for key, item in value.items()
        if not key.startswith("_")
    }


def _compact_metrics(
    examples: Sequence[Mapping[str, Any]],
    predictions: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    public = [_public_prediction(item) for item in predictions]
    rows = align_examples_and_predictions(examples, public)
    multi = multilabel_tactic_metrics(rows)
    terminal = terminal_and_discrimination_metrics(rows)
    ranking = nonterminal_ranking_metrics(rows)
    probability = _probability_metrics(examples, predictions)
    return {
        "example_count": len(rows),
        "session_count": len({row["session_id"] for row in rows}),
        "coverage": sum(row["status"] == "predicted" for row in rows)
        / len(rows),
        "multilabel_tactics": multi,
        "terminal": terminal["terminal"],
        "tactic_vs_end": terminal["tactic_vs_end"],
        "nonterminal_ranking": ranking,
        "set_and_probability": probability,
    }


def _probability_metrics(
    examples: Sequence[Mapping[str, Any]],
    predictions: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    by_id = {item["example_id"]: item for item in predictions}
    labels = sorted(TACTIC_VOCABULARY)
    brier_sum = log_sum = hamming_sum = jaccard_sum = 0.0
    exact = 0
    probability_count = 0
    bins = [
        {"count": 0, "probability_sum": 0.0, "outcome_sum": 0.0}
        for _ in range(10)
    ]
    for example in examples:
        prediction = by_id[example["example_id"]]
        target = example["target"]
        target_terminal = target["outcome_type"] == "session_end"
        target_tactics = set(target["tactics"])
        predicted_tactics = set(prediction["predicted_tactics"])
        predicted_terminal = bool(prediction["predicted_terminal"])
        actual_set = {"session_end"} if target_terminal else target_tactics
        predicted_set = (
            {"session_end"} if predicted_terminal else predicted_tactics
        )
        exact += int(actual_set == predicted_set)
        union = actual_set | predicted_set
        jaccard_sum += (
            len(actual_set & predicted_set) / len(union) if union else 1.0
        )
        outcomes = [
            (prediction["_probabilities"][label], label in target_tactics)
            for label in labels
        ]
        outcomes.append(
            (prediction["_terminal_probability"], target_terminal)
        )
        mismatches = 0
        for probability, actual in outcomes:
            outcome = float(actual)
            clipped = min(max(float(probability), 1e-12), 1.0 - 1e-12)
            brier_sum += (clipped - outcome) ** 2
            log_sum += -(
                outcome * math.log(clipped)
                + (1.0 - outcome) * math.log(1.0 - clipped)
            )
            mismatches += int((clipped >= 0.5) != actual)
            index = min(9, int(clipped * 10))
            bins[index]["count"] += 1
            bins[index]["probability_sum"] += clipped
            bins[index]["outcome_sum"] += outcome
            probability_count += 1
        hamming_sum += mismatches / len(outcomes)
    expected_calibration_error = sum(
        (
            bucket["count"]
            / probability_count
            * abs(
                bucket["probability_sum"] / bucket["count"]
                - bucket["outcome_sum"] / bucket["count"]
            )
        )
        for bucket in bins
        if bucket["count"]
    )
    count = len(examples)
    return {
        "exact_set_accuracy": exact / count,
        "mean_jaccard": jaccard_sum / count,
        "hamming_loss": hamming_sum / count,
        "brier_score": brier_sum / probability_count,
        "log_loss": log_sum / probability_count,
        "expected_calibration_error_10_bin": expected_calibration_error,
        "calibration_scope": (
            "micro_average_over_independent_tactic_and_terminal_sigmoids"
        ),
    }


def _metrics_by_bucket(
    examples: Sequence[Mapping[str, Any]],
    predictions: Sequence[Mapping[str, Any]],
    buckets: Mapping[str, str],
) -> dict[str, Any]:
    predictions_by_id = {item["example_id"]: item for item in predictions}
    output = {}
    for bucket in sorted(set(buckets.values())):
        selected = [
            example
            for example in examples
            if buckets[example["example_id"]] == bucket
        ]
        if selected:
            output[bucket] = _compact_metrics(
                selected,
                [predictions_by_id[item["example_id"]] for item in selected],
            )
    return output


def _comparison(
    left: Sequence[Mapping[str, Any]],
    right: Sequence[Mapping[str, Any]],
    *,
    same_identity: bool,
) -> dict[str, Any]:
    if same_identity:
        left_by = {item["example_id"]: item for item in left}
        right_by = {item["example_id"]: item for item in right}
    else:
        left_by = {
            (item["session_id"], item["_prediction_event_order"]): item
            for item in left
        }
        right_by = {
            (item["session_id"], item["_prediction_event_order"]): item
            for item in right
        }
    common = sorted(set(left_by) & set(right_by), key=str)
    prediction_changes = top1_changes = tensor_changes = 0
    l1_total = l1_max = 0.0
    for key in common:
        first = left_by[key]
        second = right_by[key]
        prediction_changes += int(
            (
                first["predicted_terminal"],
                first["predicted_tactics"],
            )
            != (
                second["predicted_terminal"],
                second["predicted_tactics"],
            )
        )
        top1_changes += int(
            first["ranked_tactics"][0] != second["ranked_tactics"][0]
        )
        tensor_changes += int(
            first["_tensor_hash"] != second["_tensor_hash"]
        )
        differences = [
            abs(
                first["_probabilities"][tactic]
                - second["_probabilities"][tactic]
            )
            for tactic in sorted(TACTIC_VOCABULARY)
        ]
        differences.append(
            abs(
                first["_terminal_probability"]
                - second["_terminal_probability"]
            )
        )
        l1 = sum(differences)
        l1_total += l1
        l1_max = max(l1_max, l1)
    count = len(common)
    return {
        "left_count": len(left_by),
        "right_count": len(right_by),
        "common_count": count,
        "left_only_count": len(set(left_by) - set(right_by)),
        "right_only_count": len(set(right_by) - set(left_by)),
        "tensor_change_count": tensor_changes,
        "tensor_change_rate": tensor_changes / count if count else None,
        "prediction_change_count": prediction_changes,
        "prediction_change_rate": (
            prediction_changes / count if count else None
        ),
        "top1_change_count": top1_changes,
        "top1_change_rate": top1_changes / count if count else None,
        "mean_probability_l1": l1_total / count if count else None,
        "maximum_probability_l1": l1_max if count else None,
    }


def _session_semantics(session: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "end_event_order": phase["end_event_order"],
            "tactics": phase["tactics"],
            "techniques": phase["techniques"],
            "audit_only_label_count": phase["audit_only_label_count"],
        }
        for phase in build_behavior_phases(session)
    ]


def _merge_counts(target: Counter[str], values: Mapping[str, Any]) -> None:
    for key, value in values.items():
        target[str(key)] += int(value)


def _write_json(path: Path, value: Any) -> None:
    path.write_text(stable_json(value) + "\n", encoding="utf-8")


def run_evaluation(
    *,
    root: Path,
    source_root: Path,
    output_dir: Path,
    contract_path: Path,
    role: str,
    maximum_sessions: int | None,
    batch_size: int,
) -> Path:
    contract = _load_contract(contract_path, root)
    if role not in {"selection", "test"}:
        raise CompatibilityEvaluationError("role must be selection or test")
    if role == "test" and maximum_sessions is not None:
        raise CompatibilityEvaluationError(
            "sealed test role cannot be sampled"
        )
    if maximum_sessions is not None and maximum_sessions < 1:
        raise CompatibilityEvaluationError("maximum_sessions must be positive")
    if batch_size < 1 or batch_size > 4096:
        raise CompatibilityEvaluationError("batch_size must be in [1, 4096]")
    if output_dir.exists():
        raise CompatibilityEvaluationError(
            f"refusing to overwrite evaluation output: {output_dir}"
        )

    role_contract = contract["roles"][role]
    experiment_root = source_root / contract["source"]["experiment_directory"]
    role_root = experiment_root / "roles" / role
    safe_sessions_path = role_root / "safe_sessions.jsonl"
    build_receipt_path = role_root / "build_receipt.json"
    source_receipts_path = role_root / "source_receipts.json"
    partition_path = experiment_root / "partition" / "partition_manifest.json"
    verified_sources = {
        "retained_safe_sessions": _verify_file(
            safe_sessions_path,
            role_contract["safe_sessions_sha256"],
            f"{role} retained safe sessions",
        ),
        "build_receipt": _verify_file(
            build_receipt_path,
            role_contract["build_receipt_sha256"],
            f"{role} build receipt",
        ),
        "source_receipts": _verify_file(
            source_receipts_path,
            role_contract["source_receipts_sha256"],
            f"{role} source receipts",
        ),
        "partition_manifest": _verify_file(
            partition_path,
            contract["source"]["partition_manifest_sha256"],
            "partition manifest",
        ),
    }
    build_receipt = _read_json(build_receipt_path)
    if (
        build_receipt["membership"]["session_membership_sha256"]
        != role_contract["session_membership_sha256"]
        or build_receipt["membership"]["example_membership_sha256"]
        != role_contract["example_membership_sha256"]
        or build_receipt["trust_policy_sha256"]
        != contract["policies"]["old_trust_policy_sha256"]
    ):
        raise CompatibilityEvaluationError("retained role membership mismatch")

    artifact_root = source_root / contract["source"]["artifact_directory"]
    checkpoint_path = artifact_root / contract["model"]["checkpoint_relative_path"]
    model_spec_path = artifact_root / contract["model"]["model_spec_relative_path"]
    vocabulary_path = artifact_root / contract["model"]["vocabulary_relative_path"]
    calibration_path = (
        source_root / contract["model"]["calibration_relative_path"]
    )
    artifacts = {
        "checkpoint": _verify_file(
            checkpoint_path,
            contract["model"]["checkpoint_sha256"],
            "frozen checkpoint",
        ),
        "model_spec": _verify_file(
            model_spec_path,
            contract["model"]["model_spec_file_sha256"],
            "model specification",
        ),
        "vocabulary": _verify_file(
            vocabulary_path,
            contract["model"]["vocabulary_file_sha256"],
            "vocabulary",
        ),
        "calibration": _verify_file(
            calibration_path,
            contract["model"]["calibration_file_sha256"],
            "calibration",
        ),
    }
    vocabulary = require_valid_vocabulary(_read_json(vocabulary_path))
    model_spec = require_valid_model_spec(_read_json(model_spec_path))
    calibration = require_valid_calibration_mapping(_read_json(calibration_path))
    if (
        vocabulary_sha256(vocabulary)
        != contract["model"]["vocabulary_sha256"]
        or model_spec["spec_sha256"]
        != contract["model"]["model_spec_sha256"]
        or calibration["mapping_sha256"]
        != contract["model"]["calibration_mapping_sha256"]
        or calibration["fit_partition_membership_sha256"]
        != contract["model"]["calibration_membership_sha256"]
        or calibration["checkpoint_sha256"]
        != contract["model"]["checkpoint_sha256"]
        or calibration["vocabulary_sha256"]
        != contract["model"]["vocabulary_sha256"]
        or calibration["preprocessing_sha256"]
        != contract["policies"]["preprocessing_sha256"]
    ):
        raise CompatibilityEvaluationError("frozen model semantic binding mismatch")

    try:
        import torch
    except ImportError as exc:
        raise CompatibilityEvaluationError(
            "PyTorch is unavailable in the evaluation environment"
        ) from exc
    model, model_metadata = load_checkpoint(
        checkpoint_path,
        expected_spec=model_spec,
        expected_checkpoint_sha256=contract["model"]["checkpoint_sha256"],
    )
    torch.use_deterministic_algorithms(True)

    staging = output_dir.with_name(output_dir.name + ".partial")
    if staging.exists():
        raise CompatibilityEvaluationError(
            f"stale partial output requires review: {staging}"
        )
    staging.mkdir(parents=True)
    started = time.time()
    safe_output_path = staging / "current_policy_safe_sessions.jsonl"
    examples_output_path = staging / "current_policy_examples.jsonl"
    safe_digest = hashlib.sha256()
    examples_digest = hashlib.sha256()
    safe_count = 0
    current_example_count = 0
    old_example_count = 0
    trust_delta: Counter[str] = Counter()
    audit_distribution: Counter[str] = Counter()
    class_support: Counter[str] = Counter()
    source_buckets: dict[str, str] = {}
    audit_buckets: dict[str, str] = {}
    phase_sequence_change_count = 0
    target_change_count = 0
    common_target_count = 0
    old_minimal: list[dict[str, Any]] = []
    current_minimal: list[dict[str, Any]] = []
    old_predictions: list[dict[str, Any]] = []
    current_predictions: list[dict[str, Any]] = []
    ablated_predictions: list[dict[str, Any]] = []
    pending_old: list[dict[str, Any]] = []
    pending_current: list[dict[str, Any]] = []
    pending_ablated: list[dict[str, Any]] = []
    deterministic_replay_examples: list[dict[str, Any]] = []

    def flush(
        pending: list[dict[str, Any]],
        destination: list[dict[str, Any]],
    ) -> None:
        if pending:
            destination.extend(
                _infer_batch(
                    model,
                    pending,
                    vocabulary=vocabulary,
                    calibration=calibration,
                    torch=torch,
                )
            )
            pending.clear()

    try:
        with (
            safe_sessions_path.open("r", encoding="utf-8") as source,
            safe_output_path.open("wb") as safe_output,
            examples_output_path.open("wb") as examples_output,
        ):
            for source_index, raw_line in enumerate(source, start=1):
                if maximum_sessions is not None and source_index > maximum_sessions:
                    break
                retained = require_valid_next_behavior_session(
                    json.loads(raw_line)
                )
                current, delta = reprocess_retained_safe_session(
                    retained,
                    rule_policy_sha256=contract["policies"][
                        "rule_policy_sha256"
                    ],
                    current_trust_policy_sha256=contract["policies"][
                        "current_trust_policy_sha256"
                    ],
                    classifier_checkpoint_sha256=contract["policies"][
                        "classifier_checkpoint_sha256"
                    ],
                )
                _merge_counts(trust_delta, delta)
                old_examples = build_next_behavior_examples(retained)
                old_example_count += len(old_examples)
                for example in old_examples:
                    old_minimal.append(_minimal_example(example))
                    pending_old.append(example)
                    if len(pending_old) >= batch_size:
                        flush(pending_old, old_predictions)
                if current is None:
                    phase_sequence_change_count += 1
                    continue
                safe_count += 1
                current_examples = build_next_behavior_examples(current)
                current_example_count += len(current_examples)
                phase_sequence_change_count += int(
                    _session_semantics(retained) != _session_semantics(current)
                )
                old_targets = {
                    item["prediction_event_order"]: item["target"]
                    for item in old_examples
                }
                current_targets = {
                    item["prediction_event_order"]: item["target"]
                    for item in current_examples
                }
                for event_order in set(old_targets) & set(current_targets):
                    common_target_count += 1
                    target_change_count += int(
                        old_targets[event_order] != current_targets[event_order]
                    )

                safe_line = (stable_json(current) + "\n").encode("utf-8")
                safe_output.write(safe_line)
                safe_digest.update(safe_line)
                for example in current_examples:
                    example_line = (
                        stable_json(example) + "\n"
                    ).encode("utf-8")
                    examples_output.write(example_line)
                    examples_digest.update(example_line)
                    current_minimal.append(_minimal_example(example))
                    source_buckets[example["example_id"]] = (
                        _example_source_bucket(example)
                    )
                    bucket = _example_audit_bucket(example)
                    audit_buckets[example["example_id"]] = bucket
                    audit_distribution[bucket] += 1
                    if example["target"]["outcome_type"] == "session_end":
                        class_support["session_end"] += 1
                    else:
                        class_support.update(example["target"]["tactics"])
                    pending_current.append(example)
                    pending_ablated.append(force_zero_audit_example(example))
                    if len(deterministic_replay_examples) < int(
                        contract["deterministic_replay_sample"]
                    ):
                        deterministic_replay_examples.append(deepcopy(example))
                    if len(pending_current) >= batch_size:
                        flush(pending_current, current_predictions)
                    if len(pending_ablated) >= batch_size:
                        flush(pending_ablated, ablated_predictions)
        flush(pending_old, old_predictions)
        flush(pending_current, current_predictions)
        flush(pending_ablated, ablated_predictions)

        replay = _infer_in_chunks(
            model,
            deterministic_replay_examples,
            vocabulary=vocabulary,
            calibration=calibration,
            torch=torch,
            batch_size=batch_size,
        )
        current_replay = current_predictions[
            : len(deterministic_replay_examples)
        ]
        deterministic_replay_match = replay == current_replay
        if not deterministic_replay_match:
            raise CompatibilityEvaluationError(
                "bounded deterministic inference replay changed"
            )

        current_metrics = _compact_metrics(
            current_minimal, current_predictions
        )
        zero_metrics = _compact_metrics(
            current_minimal, ablated_predictions
        )
        old_metrics = _compact_metrics(old_minimal, old_predictions)
        audit_comparison = _comparison(
            current_predictions,
            ablated_predictions,
            same_identity=True,
        )
        trust_comparison = _comparison(
            old_predictions,
            current_predictions,
            same_identity=False,
        )
        result = {
            "schema_version": EVALUATION_SCHEMA_VERSION,
            "status": "complete",
            "target_contract_id": TARGET_CONTRACT_ID,
            "role": role,
            "bounded_preflight": maximum_sessions is not None,
            "maximum_sessions": maximum_sessions,
            "evaluation_contract": {
                "path": str(contract_path),
                "sha256": _sha256_path(contract_path),
            },
            "evaluator_git_revision": _git_revision(root),
            "source": {
                **verified_sources,
                "source_session_membership_sha256": role_contract[
                    "session_membership_sha256"
                ],
                "previous_example_membership_sha256": role_contract[
                    "example_membership_sha256"
                ],
                "raw_content_emitted": False,
            },
            "policies": deepcopy(contract["policies"]),
            "model": {
                **artifacts,
                "checkpoint_metadata": model_metadata,
                "vocabulary_sha256": vocabulary_sha256(vocabulary),
                "model_spec_sha256": model_spec["spec_sha256"],
                "calibration_mapping_sha256": calibration["mapping_sha256"],
            },
            "corpus": {
                "schema_version": COMPATIBILITY_CORPUS_SCHEMA_VERSION,
                "retained_safe_session_count": (
                    maximum_sessions
                    if maximum_sessions is not None
                    else role_contract["safe_session_count"]
                ),
                "current_safe_session_count": safe_count,
                "excluded_session_count": (
                    (
                        maximum_sessions
                        if maximum_sessions is not None
                        else role_contract["safe_session_count"]
                    )
                    - safe_count
                ),
                "old_example_count": old_example_count,
                "current_example_count": current_example_count,
                "safe_sessions_sha256": safe_digest.hexdigest(),
                "examples_sha256": examples_digest.hexdigest(),
                "class_support": dict(sorted(class_support.items())),
                "audit_count_distribution": dict(
                    sorted(audit_distribution.items())
                ),
                "chronology": {
                    "shared_function": (
                        "production.prediction.next_behavior_chronology."
                        "order_model_chronology"
                    ),
                    "retained_invalid_timestamp_count": 0,
                    "retained_late_timestamp_count": 0,
                    "original_durable_arrival_late_timestamp_count": (
                        "NOT_DETERMINABLE_FROM_PRIVACY_SAFE_ROLE_ARTIFACT"
                    ),
                    "reason": (
                        "retained role records contain source-relative model "
                        "chronology but not original arrival timestamps"
                    ),
                },
                "trust_delta": dict(sorted(trust_delta.items())),
                "phase_sequence_change_count": phase_sequence_change_count,
                "common_target_count": common_target_count,
                "target_change_count": target_change_count,
                "target_change_rate": (
                    target_change_count / common_target_count
                    if common_target_count
                    else None
                ),
            },
            "comparisons": {
                "old_training_trust_policy": {
                    "metrics": old_metrics,
                },
                "corrected_current_policy_real_audit": {
                    "metrics": current_metrics,
                    "metrics_by_audit_count_bucket": _metrics_by_bucket(
                        current_minimal,
                        current_predictions,
                        audit_buckets,
                    ),
                    "metrics_by_trusted_label_source": _metrics_by_bucket(
                        current_minimal,
                        current_predictions,
                        source_buckets,
                    ),
                },
                "corrected_current_policy_zero_audit": {
                    "metrics": zero_metrics,
                },
                "real_audit_vs_zero_audit": audit_comparison,
                "old_trust_vs_current_trust": {
                    **trust_comparison,
                    "phase_sequence_change_count": phase_sequence_change_count,
                    "target_change_count": target_change_count,
                    "target_change_rate": (
                        target_change_count / common_target_count
                        if common_target_count
                        else None
                    ),
                },
            },
            "determinism": {
                "replay_sample_count": len(deterministic_replay_examples),
                "exact_match": deterministic_replay_match,
                "current_prediction_sha256": _sha256_json_rows(
                    current_predictions
                ),
                "zero_audit_prediction_sha256": _sha256_json_rows(
                    ablated_predictions
                ),
                "old_policy_prediction_sha256": _sha256_json_rows(
                    old_predictions
                ),
            },
            "authority": deepcopy(contract["authority"]),
            "runtime": {
                "batch_size": batch_size,
                "elapsed_seconds": time.time() - started,
                "torch_version": str(torch.__version__),
                "device": "cpu",
            },
        }
        result["evaluation_sha256"] = _sha256_json(result)
        _write_json(staging / "evaluation.json", result)
        _write_json(
            staging / "SHA256SUMS.json",
            {
                path.name: _sha256_path(path)
                for path in sorted(staging.iterdir())
                if path.is_file()
            },
        )
        os.replace(staging, output_dir)
        return output_dir
    except Exception:
        if staging.exists():
            shutil.rmtree(staging)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument(
        "--contract",
        type=Path,
        default=Path(
            "configs/next_behavior_checkpoint_compatibility_evaluation.v1.json"
        ),
    )
    parser.add_argument("--role", choices=("selection", "test"), required=True)
    parser.add_argument("--maximum-sessions", type=int)
    parser.add_argument("--batch-size", type=int, default=512)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    destination = run_evaluation(
        root=root,
        source_root=args.source_root.resolve(),
        output_dir=args.output_dir.resolve(),
        contract_path=(root / args.contract).resolve()
        if not args.contract.is_absolute()
        else args.contract.resolve(),
        role=args.role,
        maximum_sessions=args.maximum_sessions,
        batch_size=args.batch_size,
    )
    print(destination)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
