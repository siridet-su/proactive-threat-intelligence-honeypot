#!/usr/bin/env python3
"""Train and freeze the pre-test corrected next-behavior experiment.

This command deliberately has no final-test path or final-evaluation mode.  It
opens the train, model-selection, and calibration roles through the v2
purpose-scoped partition boundary, builds the technique vocabulary from train
inputs only, fits every model on the same train examples, selects one
Transformer seed on the selection role only, and freezes either the allowed
two-temperature mapping or an explicit no-calibration record.

The command writes into a new directory through a sibling staging directory.
It never overwrites an existing accepted bundle.  A seed without its verified
checkpoint, predictions, metrics, and completion marker is not eligible for
selection.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import resource
import shutil
import subprocess
import tempfile
import time
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Mapping, Sequence

from production.prediction.next_behavior_baseline import (
    fit_corrected_target_baselines,
    predict_many as predict_baseline_many,
    require_valid_baseline,
)
from production.prediction.next_behavior_calibration import (
    RAW_SCORE_SEMANTICS,
    fit_temperature_mapping,
    require_valid_calibration_mapping,
)
from production.prediction.next_behavior_contract import (
    EXAMPLE_SCHEMA_VERSION,
    TARGET_CONTRACT_ID,
)
from production.prediction.next_behavior_metrics import (
    evaluate_next_behavior_predictions,
)
from production.prediction.next_behavior_experiment_policy import (
    DECLARED_SEEDS,
    experiment_policy_sha256,
    load_experiment_policy,
)
from production.prediction.next_behavior_model import (
    OUTPUT_TACTICS,
    build_model,
    build_model_spec,
    load_checkpoint,
    predict_next_behavior,
    require_valid_model_spec,
    save_checkpoint,
)
from production.prediction.next_behavior_partitions import (
    PARTITION_SCHEMA_VERSION_V2,
    load_partition_for_purpose_v2,
    membership_sha256,
)
from production.prediction.next_behavior_tensor import (
    build_vocabulary,
    require_valid_vocabulary,
    tensorize_example,
    vocabulary_sha256,
)
from production.utils.serialization import stable_id, stable_json
from production.tools.build_next_behavior_selected_safe_corpus import (
    verify_selected_role_artifacts,
)


TRAINING_BUNDLE_SCHEMA_VERSION = "next_behavior_training_bundle.v1"
SEED_COMPLETION_SCHEMA_VERSION = "next_behavior_seed_completion.v1"
SELECTION_DECISION_SCHEMA_VERSION = "next_behavior_selection_decision.v1"
EXPERIMENT_BINDINGS_SCHEMA_VERSION_V1 = "next_behavior_experiment_bindings.v1"
EXPERIMENT_BINDINGS_SCHEMA_VERSION = "next_behavior_experiment_bindings.v2"
DECISION_FREEZE_BINDINGS_SCHEMA_VERSION = (
    "next_behavior_decision_freeze_bindings.v1"
)
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class NextBehaviorTrainingError(RuntimeError):
    """Raised when a pre-test training bundle cannot be frozen safely."""


def _require_code_commit(value: str) -> str:
    commit = str(value or "").strip().lower()
    if not _COMMIT.fullmatch(commit):
        raise NextBehaviorTrainingError(
            "code_commit must be a full lowercase Git commit hash"
        )
    repository = Path(__file__).resolve().parents[2]
    try:
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repository,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip().lower()
        tracked = subprocess.run(
            ["git", "diff", "--quiet", "HEAD", "--"],
            cwd=repository,
            check=False,
        ).returncode
        untracked = subprocess.run(
            [
                "git",
                "ls-files",
                "--others",
                "--exclude-standard",
                "--",
                "production",
                "configs",
            ],
            cwd=repository,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise NextBehaviorTrainingError(
            "Git provenance cannot be verified"
        ) from exc
    if head != commit:
        raise NextBehaviorTrainingError("code_commit does not match HEAD")
    if tracked != 0 or untracked:
        raise NextBehaviorTrainingError(
            "tracked source or untracked production/config code is not frozen"
        )
    return commit


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_json(value: Any) -> str:
    return _sha256_bytes(stable_json(value).encode("utf-8"))


def build_decision_freeze_bindings(policy: Mapping[str, Any]) -> Dict[str, Any]:
    """Bind every pre-test decision rule to the validated policy bytes.

    The individual digests intentionally remain the manifest's stable
    decision-freeze interface.  The schema marker and aggregate digest make
    it impossible for a manifest merger to silently mix rules from different
    policy revisions.
    """

    bindings = {
        "schema_version": DECISION_FREEZE_BINDINGS_SCHEMA_VERSION,
        "selection_rule_sha256": _sha256_json(policy["selection"]),
        "promotion_rule_sha256": _sha256_json(
            {
                "authority": policy["authority"],
                "abstention": policy["abstention"],
                "runtime_budgets": policy["runtime_budgets"],
            }
        ),
        "feature_rule_sha256": _sha256_json(
            {
                "architecture": policy["architecture"],
                "prediction_decision": policy["prediction_decision"],
            }
        ),
        "seed_rule_sha256": _sha256_json(policy["training"]),
        "calibration_rule_sha256": _sha256_json(policy["calibration"]),
        "frozen_before_test": True,
    }
    bindings["bindings_sha256"] = _sha256_json(bindings)
    return bindings


def require_valid_decision_freeze_bindings(
    value: Any,
    *,
    policy: Mapping[str, Any],
) -> Dict[str, Any]:
    """Fail closed unless decision bindings exactly derive from ``policy``."""

    if not isinstance(value, Mapping):
        raise NextBehaviorTrainingError("decision freeze bindings are invalid")
    expected = build_decision_freeze_bindings(policy)
    if dict(value) != expected:
        raise NextBehaviorTrainingError(
            "decision freeze bindings do not match the frozen experiment policy"
        )
    return deepcopy(expected)


def _ordered_records_sha256(values: Sequence[Mapping[str, Any]]) -> str:
    digest = hashlib.sha256()
    for value in values:
        encoded = stable_json(value).encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def _sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _read_json(path: Path, *, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise NextBehaviorTrainingError(f"{label} is not valid JSON") from exc


def _iter_jsonl_objects(path: Path) -> Iterator[Dict[str, Any]]:
    emitted = 0
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    raise NextBehaviorTrainingError(
                        "partition JSONL contains an empty line"
                    )
                item = json.loads(line)
                if not isinstance(item, dict):
                    raise NextBehaviorTrainingError(
                        f"partition JSONL line {line_number} is not an object"
                    )
                emitted += 1
                yield item
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise NextBehaviorTrainingError(
            "partition artifact is not valid JSONL"
        ) from exc
    if not emitted:
        raise NextBehaviorTrainingError("partition JSONL is empty")


def _read_object_array(path: Path) -> Iterable[Dict[str, Any]]:
    if path.suffix == ".jsonl":
        return _iter_jsonl_objects(path)
    value = _read_json(path, label="partition artifact")
    if not isinstance(value, list) or not all(
        isinstance(item, dict) for item in value
    ):
        raise NextBehaviorTrainingError(
            "partition artifact must be a JSON array or .jsonl object stream"
        )
    return value


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True, allow_nan=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def _role_examples(
    path: Path,
    *,
    purpose: str,
    partition_manifest: Mapping[str, Any],
) -> List[Dict[str, Any]]:
    records = load_partition_for_purpose_v2(
        {
            {
                "fit_model": "train",
                "select_model": "selection",
                "fit_calibration": "calibration",
            }[purpose]: path
        },
        purpose=purpose,
        reader=_read_object_array,
    )
    role = {
        "fit_model": "train",
        "select_model": "selection",
        "fit_calibration": "calibration",
    }[purpose]
    role_manifest = partition_manifest["roles"][role]
    allowed_members = set(role_manifest["source_member_ids"])
    session_ids: List[str] = []
    examples: List[Dict[str, Any]] = []
    for example in records:
        if (
            example.get("schema_version") != EXAMPLE_SCHEMA_VERSION
            or example.get("target_contract_id") != TARGET_CONTRACT_ID
        ):
            raise NextBehaviorTrainingError(
                f"{role} artifact contains an invalid corrected-target example"
            )
        if example.get("source_member_id") not in allowed_members:
            raise NextBehaviorTrainingError(
                f"{role} artifact contains an example from another role"
            )
        session_ids.append(str(example.get("session_id") or "").strip())
        examples.append(dict(example))
    if not session_ids or not examples:
        raise NextBehaviorTrainingError(f"{role} partition is empty")
    if membership_sha256(session_ids) != role_manifest[
        "session_membership_sha256"
    ]:
        raise NextBehaviorTrainingError(
            f"{role} session membership does not match the frozen manifest"
        )
    example_ids = [item["example_id"] for item in examples]
    if len(set(example_ids)) != len(example_ids):
        raise NextBehaviorTrainingError(f"{role} partition repeats an example")
    if membership_sha256(example_ids) != role_manifest[
        "example_membership_sha256"
    ]:
        raise NextBehaviorTrainingError(
            f"{role} example membership does not match the frozen manifest"
        )
    return examples


def load_pre_final_examples(
    *,
    train_path: Path,
    selection_path: Path,
    calibration_path: Path,
    partition_manifest_path: Path,
    expected_payload_sha256: Mapping[str, str],
) -> tuple[Dict[str, List[Dict[str, Any]]], Dict[str, Any]]:
    """Load exactly the three pre-final roles and verify frozen membership."""

    manifest = _read_json(partition_manifest_path, label="partition manifest")
    if (
        not isinstance(manifest, dict)
        or manifest.get("schema_version") != PARTITION_SCHEMA_VERSION_V2
        or manifest.get("status") != "membership_frozen"
        or not isinstance(manifest.get("roles"), dict)
    ):
        raise NextBehaviorTrainingError(
            "partition manifest is not a frozen v2 manifest"
        )
    manifest_identity = deepcopy(manifest)
    manifest_identity.pop("manifest_id", None)
    if manifest.get("manifest_id") != stable_id(
        "nextbehaviorpartition", manifest_identity
    ):
        raise NextBehaviorTrainingError(
            "partition manifest identity does not match its content"
        )
    role_paths = {
        "train": train_path,
        "selection": selection_path,
        "calibration": calibration_path,
    }
    if not isinstance(expected_payload_sha256, Mapping) or set(
        expected_payload_sha256
    ) != set(role_paths):
        raise NextBehaviorTrainingError(
            "exact pre-final payload hashes must define only train, "
            "selection, and calibration"
        )
    for role, path in role_paths.items():
        if _sha256_path(path) != expected_payload_sha256[role]:
            raise NextBehaviorTrainingError(
                f"{role} payload changed after artifact verification"
            )
    examples = {
        "train": _role_examples(
            train_path,
            purpose="fit_model",
            partition_manifest=manifest,
        ),
        "selection": _role_examples(
            selection_path,
            purpose="select_model",
            partition_manifest=manifest,
        ),
        "calibration": _role_examples(
            calibration_path,
            purpose="fit_calibration",
            partition_manifest=manifest,
        ),
    }
    memberships = {
        role: {item["example_id"] for item in values}
        for role, values in examples.items()
    }
    for left, right in (
        ("train", "selection"),
        ("train", "calibration"),
        ("selection", "calibration"),
    ):
        if memberships[left] & memberships[right]:
            raise NextBehaviorTrainingError(
                f"{left} and {right} example membership intersects"
            )
    return examples, manifest


def build_training_vocabulary(
    train_examples: Sequence[Mapping[str, Any]],
    *,
    preprocessing_sha256: str,
    training_membership_sha256: str,
) -> Dict[str, Any]:
    """Build a vocabulary from training model inputs and no other role."""

    return build_vocabulary(
        [item["model_input"] for item in train_examples],
        preprocessing_sha256=preprocessing_sha256,
        training_membership_sha256=training_membership_sha256,
    )


def _torch_module() -> Any:
    try:
        import torch
    except ImportError as exc:  # pragma: no cover - environment dependent.
        raise NextBehaviorTrainingError(
            "PyTorch is required to fit corrected-target Transformer seeds"
        ) from exc
    return torch


def _training_configuration(policy: Mapping[str, Any]) -> Dict[str, Any]:
    """Return the exact validated training and decision choices."""

    return {
        "training": deepcopy(policy["training"]),
        "prediction_decision": deepcopy(policy["prediction_decision"]),
    }


def _batch(
    tensors: Sequence[Mapping[str, Any]],
    *,
    torch: Any,
) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for field in (
        "phase_tactic_multi_hot",
        "phase_technique_multi_hot",
        "phase_source_multi_hot",
        "phase_confidence_multi_hot",
        "phase_agreement_multi_hot",
    ):
        result[field] = torch.tensor(
            [item[field] for item in tensors],
            dtype=torch.float32,
            device="cpu",
        )
    result["attention_mask"] = torch.tensor(
        [item["attention_mask"] for item in tensors],
        dtype=torch.bool,
        device="cpu",
    )
    for field in (
        "phase_repetition_index",
        "phase_elapsed_time_index",
        "phase_audit_count_index",
    ):
        result[field] = torch.tensor(
            [item[field] for item in tensors],
            dtype=torch.long,
            device="cpu",
        )
    for field in (
        "context_login_outcome_index",
        "context_command_count_index",
        "context_session_age_index",
        "context_confirmed_transfer",
    ):
        result[field] = torch.tensor(
            [item[field] for item in tensors],
            dtype=torch.long,
            device="cpu",
        )
    return result


def _targets(
    examples: Sequence[Mapping[str, Any]],
    *,
    torch: Any,
) -> tuple[Any, Any]:
    tactics = []
    terminal = []
    for example in examples:
        target = example["target"]
        selected = set(target["tactics"])
        tactics.append(
            [1.0 if tactic in selected else 0.0 for tactic in OUTPUT_TACTICS]
        )
        terminal.append(float(target["outcome_type"] == "session_end"))
    return (
        torch.tensor(tactics, dtype=torch.float32, device="cpu"),
        torch.tensor(terminal, dtype=torch.float32, device="cpu"),
    )


def _train_seed(
    train_examples: Sequence[Mapping[str, Any]],
    *,
    vocabulary: Mapping[str, Any],
    model_spec: Mapping[str, Any],
    policy: Mapping[str, Any],
    seed: int,
    checkpoint_path: Path,
) -> tuple[Any, Dict[str, Any], Dict[str, Any]]:
    torch = _torch_module()
    training = policy["training"]
    training_started = time.perf_counter()
    rss_before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024
    torch.manual_seed(seed)
    torch.use_deterministic_algorithms(True)
    model = build_model(model_spec, seed=seed)
    model.train()
    optimizer = torch.optim.Adam(
        model.parameters(),
        lr=training["learning_rate"],
        weight_decay=training["weight_decay"],
    )
    tactic_loss_function = torch.nn.BCEWithLogitsLoss()
    terminal_loss_function = torch.nn.BCEWithLogitsLoss()
    tactic_targets, terminal_targets = _targets(train_examples, torch=torch)
    batch_size = int(training["batch_size"])
    history: List[Dict[str, Any]] = []
    for epoch in range(int(training["epochs"])):
        generator = torch.Generator(device="cpu")
        generator.manual_seed(seed * 1_000_003 + epoch)
        order = torch.randperm(len(train_examples), generator=generator).tolist()
        epoch_loss = 0.0
        batch_count = 0
        for start in range(0, len(order), batch_size):
            indices = order[start : start + batch_size]
            inputs = _batch(
                [
                    tensorize_example(train_examples[index], vocabulary)
                    for index in indices
                ],
                torch=torch,
            )
            selected_tactics = tactic_targets[indices]
            selected_terminal = terminal_targets[indices]
            optimizer.zero_grad(set_to_none=True)
            tactic_logits, terminal_logits = model(inputs)
            loss = tactic_loss_function(
                tactic_logits, selected_tactics
            ) + terminal_loss_function(terminal_logits, selected_terminal)
            loss.backward()
            optimizer.step()
            epoch_loss += float(loss.detach().cpu().item())
            batch_count += 1
        history.append(
            {
                "epoch": epoch + 1,
                "mean_batch_loss": epoch_loss / batch_count,
                "batch_count": batch_count,
            }
        )
    model.eval()
    receipt = save_checkpoint(checkpoint_path, model, spec=model_spec)
    load_started = time.perf_counter()
    loaded, loaded_metadata = load_checkpoint(
        checkpoint_path,
        expected_spec=model_spec,
        expected_checkpoint_sha256=receipt["checkpoint_sha256"],
    )
    checkpoint_load_seconds = time.perf_counter() - load_started
    if loaded_metadata["state_dictionary_sha256"] != receipt[
        "state_dictionary_sha256"
    ]:
        raise NextBehaviorTrainingError(
            "reloaded checkpoint changed the state dictionary"
        )
    return loaded, receipt, {
        "configuration": _training_configuration(policy),
        "epochs": history,
        "resources": {
            "training_wall_seconds": time.perf_counter() - training_started,
            "process_peak_rss_before_bytes": rss_before,
            "process_peak_rss_after_bytes": (
                resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024
            ),
            "checkpoint_load_seconds": checkpoint_load_seconds,
            "checkpoint_bytes": checkpoint_path.stat().st_size,
            "torch_version": str(torch.__version__),
            "device": "cpu",
        },
    }


def _prediction_from_raw(
    example: Mapping[str, Any],
    raw: Mapping[str, Any],
) -> Dict[str, Any]:
    scores = {key: float(value) for key, value in raw["tactic_logits"].items()}
    ranked = sorted(scores, key=lambda item: (-scores[item], item))
    predicted_terminal = float(raw["terminal_logit"]) >= 0.0
    predicted = [] if predicted_terminal else sorted(
        tactic for tactic, score in scores.items() if score >= 0.0
    )
    if not predicted_terminal and not predicted:
        predicted = [ranked[0]]
    return {
        "example_id": example["example_id"],
        "session_id": example["session_id"],
        "status": "predicted",
        "ranked_tactics": ranked,
        "predicted_tactics": predicted,
        "predicted_terminal": predicted_terminal,
    }


def _predict_transformer(
    model: Any,
    examples: Sequence[Mapping[str, Any]],
    *,
    vocabulary: Mapping[str, Any],
    model_spec: Mapping[str, Any],
) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]], float]:
    predictions: List[Dict[str, Any]] = []
    raw_rows: List[Dict[str, Any]] = []
    latencies: List[float] = []
    if not examples:
        raise NextBehaviorTrainingError("prediction examples must not be empty")
    # Exclude lazy framework/thread initialization from the frozen warm
    # single-case latency tie-break.
    predict_next_behavior(
        model,
        tensorize_example(examples[0], vocabulary),
        spec=model_spec,
    )
    for example in examples:
        tensor = tensorize_example(example, vocabulary)
        started = time.perf_counter_ns()
        raw = predict_next_behavior(model, tensor, spec=model_spec)
        latencies.append((time.perf_counter_ns() - started) / 1_000_000.0)
        predictions.append(_prediction_from_raw(example, raw))
        raw_rows.append(
            {
                "example_id": example["example_id"],
                "session_id": example["session_id"],
                "model_output": raw,
            }
        )
    ordered = sorted(latencies)
    position = min(
        len(ordered) - 1,
        max(0, math.ceil(0.95 * len(ordered)) - 1),
    )
    return predictions, raw_rows, ordered[position]


def _selection_values(metrics: Mapping[str, Any]) -> Dict[str, float]:
    clustered = metrics["session_cluster_bootstrap"]["metrics"]
    return {
        "macro_f1": float(clustered["macro_f1"]["estimate"]),
        "balanced_accuracy": float(
            clustered["balanced_accuracy"]["estimate"]
        ),
        "terminal_f1": float(clustered["terminal_f1"]["estimate"]),
    }


def assess_selection_candidate(
    *,
    seed: int,
    metrics: Mapping[str, Any],
    baseline_metrics: Mapping[str, Any],
    p95_latency_ms: float,
    selection_policy: Mapping[str, Any],
) -> Dict[str, Any]:
    """Apply the frozen blocker and tie-break policy to one complete seed."""

    reportable = list(metrics["multilabel_tactics"]["reportable_classes"])
    high_consequence = set(selection_policy["high_consequence_tactics"])
    maximum_regression = float(
        selection_policy["maximum_high_consequence_recall_regression"]
    )
    candidate_classes = metrics["multilabel_tactics"]["per_class"]
    baseline_classes = baseline_metrics["multilabel_tactics"]["per_class"]
    regressions = {
        tactic: float(baseline_classes[tactic]["recall"])
        - float(candidate_classes[tactic]["recall"])
        for tactic in reportable
    }
    blockers: List[str] = []
    for tactic in reportable:
        if (
            float(baseline_classes[tactic]["recall"]) > 0.0
            and float(candidate_classes[tactic]["recall"]) == 0.0
        ):
            blockers.append(f"reportable_zero_recall:{tactic}")
    for tactic in sorted(high_consequence.intersection(reportable)):
        if regressions[tactic] > maximum_regression + 1e-12:
            blockers.append(f"high_consequence_recall_regression:{tactic}")
    values = _selection_values(metrics)
    values["worst_reportable_tactic_recall_regression"] = max(
        regressions.values(), default=0.0
    )
    values["p95_single_case_cpu_latency_ms"] = float(p95_latency_ms)
    return {
        "seed": int(seed),
        "eligible": not blockers,
        "blockers": blockers,
        "selection_values": values,
        "reportable_tactics": reportable,
        "recall_regression_vs_hard_backoff_vomm": regressions,
    }


def require_selection_support(
    baseline_metrics: Mapping[str, Any],
    selection_policy: Mapping[str, Any],
) -> List[str]:
    """Require predeclared support before any checkpoint can be selected."""

    reportable = list(
        baseline_metrics["multilabel_tactics"]["reportable_classes"]
    )
    required = set(selection_policy["high_consequence_tactics"])
    if not reportable or not required.issubset(reportable):
        raise NextBehaviorTrainingError(
            "selection partition does not meet the frozen independent "
            "support gate for reportable high-consequence tactics"
        )
    return reportable


def select_completed_seed(
    seed_records: Sequence[Mapping[str, Any]],
) -> Dict[str, Any]:
    """Select exactly one eligible complete seed without test information."""

    complete = [
        deepcopy(dict(record))
        for record in seed_records
        if record.get("status") == "complete"
        and record.get("completion_marker_verified") is True
        and record.get("candidate", {}).get("eligible") is True
    ]
    if not complete:
        raise NextBehaviorTrainingError(
            "no complete seed satisfies the frozen selection blockers"
        )

    def key(record: Mapping[str, Any]) -> tuple[Any, ...]:
        values = record["candidate"]["selection_values"]
        return (
            -float(values["macro_f1"]),
            -float(values["balanced_accuracy"]),
            float(values["worst_reportable_tactic_recall_regression"]),
            -float(values["terminal_f1"]),
            float(values["p95_single_case_cpu_latency_ms"]),
            int(record["seed"]),
        )

    return min(complete, key=key)


def publish_selection_blocked_bundle(
    staging: Path,
    output_dir: Path,
    *,
    seed_records: Sequence[Mapping[str, Any]],
    code_commit: str,
) -> Path:
    """Atomically preserve complete pre-test evidence when selection blocks."""

    destination = output_dir.with_name(f"{output_dir.name}.selection_blocked")
    if destination.exists():
        raise FileExistsError(
            f"refusing to overwrite blocked selection evidence: {destination}"
        )
    candidates = []
    for record in seed_records:
        candidates.append(
            {
                "seed": record.get("seed"),
                "status": record.get("status"),
                "completion_marker_verified": record.get(
                    "completion_marker_verified"
                ),
                "candidate": deepcopy(record.get("candidate")),
                "checkpoint": deepcopy(record.get("checkpoint")),
                "selection_metrics": deepcopy(
                    record.get("selection_metrics")
                ),
                "completion": deepcopy(record.get("completion")),
            }
        )
    artifact_hashes = {
        str(path.relative_to(staging)): _sha256_path(path)
        for path in sorted(staging.rglob("*"))
        if path.is_file()
    }
    receipt = {
        "schema_version": "next_behavior_selection_blocked.v1",
        "status": "selection_blocked_pre_test",
        "reason_code": "no_eligible_complete_seed",
        "test_opened": False,
        "final_test_path_accepted_by_command": False,
        "code_commit": code_commit,
        "declared_seeds": list(DECLARED_SEEDS),
        "seed_candidates": candidates,
        "pre_test_artifact_hashes": artifact_hashes,
    }
    receipt["receipt_sha256"] = _sha256_json(receipt)
    _write_json(staging / "SELECTION_BLOCKED.json", receipt)
    os.replace(staging, destination)
    return destination


def require_all_declared_seeds(
    seed_records: Sequence[Mapping[str, Any]],
) -> None:
    """Refuse to publish or select from a subset of the frozen seeds."""

    if [record.get("seed") for record in seed_records] != list(
        DECLARED_SEEDS
    ):
        raise NextBehaviorTrainingError(
            "seed records do not match the frozen declared seed order"
        )
    incomplete = [
        record
        for record in seed_records
        if record.get("status") != "complete"
        or record.get("completion_marker_verified") is not True
    ]
    if incomplete:
        detail = ", ".join(
            f"{record.get('seed')}:{record.get('error_type', 'incomplete')}"
            for record in incomplete
        )
        raise NextBehaviorTrainingError(
            "every declared seed must complete before selection: " + detail
        )


def _calibration_rows(
    examples: Sequence[Mapping[str, Any]],
    raw_outputs: Sequence[Mapping[str, Any]],
    *,
    checkpoint_sha256: str,
    vocabulary_sha256_value: str,
    preprocessing_sha256: str,
) -> List[Dict[str, Any]]:
    if not examples or len(examples) != len(raw_outputs):
        raise NextBehaviorTrainingError(
            "calibration examples and raw outputs are not exactly aligned"
        )
    rows = []
    for example, raw_record in zip(examples, raw_outputs):
        if (
            raw_record.get("example_id") != example["example_id"]
            or raw_record.get("session_id") != example["session_id"]
            or not isinstance(raw_record.get("model_output"), Mapping)
        ):
            raise NextBehaviorTrainingError(
                "raw output is not aligned to its calibration example"
            )
        raw = raw_record["model_output"]
        target = example["target"]
        rows.append(
            {
                "example_id": example["example_id"],
                "partition_role": "calibration",
                "target_contract_id": TARGET_CONTRACT_ID,
                "score_semantics": RAW_SCORE_SEMANTICS,
                "checkpoint_sha256": checkpoint_sha256,
                "vocabulary_sha256": vocabulary_sha256_value,
                "preprocessing_sha256": preprocessing_sha256,
                "tactic_logits": raw["tactic_logits"],
                "target_tactics": target["tactics"],
                "terminal_logit": raw["terminal_logit"],
                "terminal_target": target["outcome_type"] == "session_end",
            }
        )
    return rows


def _artifact_entry(path: Path, root: Path) -> Dict[str, Any]:
    return {
        "path": str(path.relative_to(root)),
        "sha256": _sha256_path(path),
        "byte_size": path.stat().st_size,
    }


def require_valid_experiment_manifest_bindings(
    value: Any,
    *,
    policy: Mapping[str, Any],
) -> Dict[str, Any]:
    """Validate the v2 hand-off record consumed by the manifest merger.

    This is deliberately a pre-test-only contract: it identifies the sealed
    test role but contains neither a final payload path nor final examples.
    Older v1 records remain readable by historic bundles, but cannot be used
    to construct a new v2 experiment manifest because they did not bind every
    decision-freeze rule.
    """

    if not isinstance(value, Mapping):
        raise NextBehaviorTrainingError("experiment manifest bindings are invalid")
    if value.get("schema_version") != EXPERIMENT_BINDINGS_SCHEMA_VERSION:
        raise NextBehaviorTrainingError(
            "experiment manifest bindings must use the v2 schema"
        )
    allowed = {
        "schema_version",
        "status",
        "target_contract_id",
        "code_commit",
        "test_opened",
        "partition_manifest_id",
        "partition_manifest_sha256",
        "partition_membership_sha256",
        "pre_final_role_artifacts",
        "policies",
        "model",
        "baselines",
        "calibration",
        "decision_freeze",
        "artifact_hashes",
        "artifact_paths_relative_to_bundle",
        "bindings_sha256",
    }
    if set(value) != allowed:
        raise NextBehaviorTrainingError(
            "experiment manifest bindings fields do not match the v2 contract"
        )
    if (
        value.get("status") != "ready_for_v2_experiment_manifest_merge"
        or value.get("target_contract_id") != TARGET_CONTRACT_ID
        or value.get("test_opened") is not False
        or not _COMMIT.fullmatch(str(value.get("code_commit") or ""))
    ):
        raise NextBehaviorTrainingError("experiment manifest bindings are unsafe")
    identity = deepcopy(dict(value))
    bindings_sha256 = identity.pop("bindings_sha256")
    if bindings_sha256 != _sha256_json(identity):
        raise NextBehaviorTrainingError(
            "experiment manifest bindings identity does not match its content"
        )
    memberships = value.get("partition_membership_sha256")
    if not isinstance(memberships, Mapping) or set(memberships) != {
        "train", "selection", "calibration", "test"
    } or any(not _SHA256.fullmatch(str(item or "")) for item in memberships.values()):
        raise NextBehaviorTrainingError(
            "experiment manifest bindings partition memberships are invalid"
        )
    if not _SHA256.fullmatch(str(value.get("partition_manifest_sha256") or "")):
        raise NextBehaviorTrainingError(
            "experiment manifest bindings partition hash is invalid"
        )
    policies = value.get("policies")
    if not isinstance(policies, Mapping) or any(
        not _SHA256.fullmatch(str(policies.get(field) or ""))
        for field in (
            "experiment_policy_artifact_sha256",
            "experiment_policy_sha256",
            "preprocessing_sha256",
            "vocabulary_artifact_sha256",
            "vocabulary_sha256",
            "environment_lock_sha256",
        )
    ):
        raise NextBehaviorTrainingError("experiment manifest policy bindings are invalid")
    if policies["experiment_policy_sha256"] != experiment_policy_sha256(policy):
        raise NextBehaviorTrainingError("experiment manifest policy hash mismatch")
    require_valid_decision_freeze_bindings(
        value.get("decision_freeze"), policy=policy
    )
    return deepcopy(dict(value))


def _verified_bundle_entry(
    root: Path,
    value: Mapping[str, Any],
    *,
    label: str,
) -> Path:
    if not isinstance(value, Mapping) or set(value) != {
        "path",
        "sha256",
        "byte_size",
    }:
        raise NextBehaviorTrainingError(
            f"{label} artifact entry is malformed"
        )
    relative = Path(str(value.get("path") or ""))
    if relative.is_absolute() or ".." in relative.parts or not relative.parts:
        raise NextBehaviorTrainingError(
            f"{label} artifact path escapes the bundle"
        )
    path = root / relative
    if not path.is_file() or path.is_symlink():
        raise NextBehaviorTrainingError(f"{label} artifact is missing or unsafe")
    if (
        path.stat().st_size != value.get("byte_size")
        or _sha256_path(path) != value.get("sha256")
    ):
        raise NextBehaviorTrainingError(f"{label} artifact hash mismatch")
    return path


def _verify_seed_completion(
    root: Path,
    record: Mapping[str, Any],
    *,
    model_spec: Mapping[str, Any],
) -> Dict[str, Any]:
    if (
        not isinstance(record, Mapping)
        or record.get("status") != "complete"
        or record.get("completion_marker_verified") is not True
        or record.get("seed") not in DECLARED_SEEDS
    ):
        raise NextBehaviorTrainingError(
            "frozen bundle contains an incomplete seed"
        )
    checkpoint_path = _verified_bundle_entry(
        root, record.get("checkpoint", {}), label="seed checkpoint"
    )
    completion_path = _verified_bundle_entry(
        root, record.get("completion", {}), label="seed completion"
    )
    _verified_bundle_entry(
        root,
        record.get("selection_metrics", {}),
        label="seed selection metrics",
    )
    completion = _read_json(completion_path, label="seed completion")
    if (
        not isinstance(completion, dict)
        or completion.get("schema_version") != SEED_COMPLETION_SCHEMA_VERSION
        or completion.get("status") != "complete"
        or completion.get("seed") != record["seed"]
    ):
        raise NextBehaviorTrainingError("seed completion marker is invalid")
    completion_identity = deepcopy(completion)
    completion_digest = completion_identity.pop("completion_sha256", None)
    if completion_digest != _sha256_json(completion_identity):
        raise NextBehaviorTrainingError(
            "seed completion identity does not match its content"
        )
    seed_directory = completion_path.parent
    file_hashes = completion.get("files_sha256")
    if not isinstance(file_hashes, dict) or not file_hashes:
        raise NextBehaviorTrainingError(
            "seed completion has no file receipts"
        )
    for relative_text, expected_sha256 in file_hashes.items():
        relative = Path(str(relative_text))
        if (
            relative.is_absolute()
            or ".." in relative.parts
            or not relative.parts
        ):
            raise NextBehaviorTrainingError(
                "seed completion file path escapes its seed directory"
            )
        path = seed_directory / relative
        if (
            not path.is_file()
            or path.is_symlink()
            or _sha256_path(path) != expected_sha256
        ):
            raise NextBehaviorTrainingError(
                "seed completion file receipt mismatch"
            )
    persisted_receipt = _read_json(
        seed_directory / "checkpoint_receipt.json",
        label="checkpoint receipt",
    )
    persisted_candidate = _read_json(
        seed_directory / "selection_candidate.json",
        label="selection candidate",
    )
    checkpoint_receipt = record.get("checkpoint_receipt")
    if not isinstance(checkpoint_receipt, Mapping):
        raise NextBehaviorTrainingError("checkpoint receipt is missing")
    if (
        checkpoint_receipt != persisted_receipt
        or record.get("candidate") != persisted_candidate
        or checkpoint_receipt.get("checkpoint_sha256")
        != record["checkpoint"]["sha256"]
        or checkpoint_receipt.get("checkpoint_sha256")
        != completion.get("checkpoint_sha256")
        or checkpoint_receipt.get("state_dictionary_sha256")
        != completion.get("state_dictionary_sha256")
    ):
        raise NextBehaviorTrainingError(
            "checkpoint and completion receipts disagree"
        )
    _model, metadata = load_checkpoint(
        checkpoint_path,
        expected_spec=model_spec,
        expected_checkpoint_sha256=record["checkpoint"]["sha256"],
    )
    if metadata["state_dictionary_sha256"] != completion[
        "state_dictionary_sha256"
    ]:
        raise NextBehaviorTrainingError(
            "checkpoint replay changed the state dictionary"
        )
    return deepcopy(dict(record))


def require_consistent_role_provenance(
    role_verifications: Mapping[str, Mapping[str, Any]],
    *,
    preprocessing_sha256: str,
) -> str:
    """Require one immutable export provenance across all development roles.

    The export producer commit is deliberately distinct from the clean commit
    executing training.  This permits a reviewed training-driver repair after
    role publication without silently rebinding or rewriting sealed exports.
    Both commits remain independently recorded in the frozen bundle.
    """

    if set(role_verifications) != {"train", "selection", "calibration"}:
        raise NextBehaviorTrainingError(
            "exactly three development role verifications are required"
        )
    provenance_fields = (
        "source_selection_sha256",
        "classifier_manifest_sha256",
        "preprocessing_sha256",
        "label_policy_sha256",
        "trust_policy_sha256",
        "classification_checkpoint_sha256",
    )
    reference = role_verifications["train"]
    export_commit = str(reference.get("code_commit") or "")
    if not _COMMIT.fullmatch(export_commit):
        raise NextBehaviorTrainingError(
            "development role export commit is invalid"
        )
    for role, verification in role_verifications.items():
        if (
            verification.get("code_commit") != export_commit
            or verification.get("preprocessing_sha256")
            != preprocessing_sha256
            or any(
                verification.get(field) != reference.get(field)
                for field in provenance_fields
            )
        ):
            raise NextBehaviorTrainingError(
                f"{role} role provenance differs from the frozen "
                "development cohort"
            )
    return export_commit


def verify_frozen_training_bundle(
    bundle_dir: Path,
    *,
    role_artifact_paths: Mapping[str, Mapping[str, Path]],
    partition_manifest_path: Path,
    preprocessing_config_path: Path,
    experiment_policy_path: Path,
    environment_lock_path: Path,
    expected_code_commit: str | None = None,
) -> Dict[str, Any]:
    """Verify a complete development bundle without accepting a test path."""

    root = bundle_dir
    bundle_path = root / "training_bundle.json"
    bundle = _read_json(bundle_path, label="training bundle")
    if (
        not isinstance(bundle, dict)
        or bundle.get("schema_version") != TRAINING_BUNDLE_SCHEMA_VERSION
        or bundle.get("status") != "frozen_pre_test"
        or bundle.get("test_opened") is not False
        or bundle.get("final_test_path_accepted_by_command") is not False
    ):
        raise NextBehaviorTrainingError(
            "training bundle is not a complete sealed pre-test bundle"
        )
    if (
        expected_code_commit is not None
        and bundle.get("code_commit") != expected_code_commit
    ):
        raise NextBehaviorTrainingError("training bundle code commit mismatch")
    identity = deepcopy(bundle)
    semantic_sha256 = identity.pop("bundle_sha256", None)
    if semantic_sha256 != _sha256_json(identity):
        raise NextBehaviorTrainingError(
            "training bundle identity does not match its content"
        )
    policy = load_experiment_policy(experiment_policy_path)
    policy_binding = bundle.get("experiment_policy")
    if (
        not isinstance(policy_binding, dict)
        or policy_binding.get("policy_id") != policy["policy_id"]
        or policy_binding.get("semantic_sha256")
        != experiment_policy_sha256(policy)
        or policy_binding.get("file_sha256")
        != _sha256_path(experiment_policy_path)
    ):
        raise NextBehaviorTrainingError(
            "training bundle experiment policy binding mismatch"
        )
    if bundle.get("environment_lock_sha256") != _sha256_path(
        environment_lock_path
    ):
        raise NextBehaviorTrainingError(
            "training bundle environment lock binding mismatch"
        )
    partition_binding = bundle.get("partition_manifest")
    partition = _read_json(
        partition_manifest_path, label="partition manifest"
    )
    if (
        not isinstance(partition_binding, dict)
        or not isinstance(partition, dict)
        or partition_binding.get("manifest_id") != partition.get("manifest_id")
        or partition_binding.get("sha256")
        != _sha256_path(partition_manifest_path)
        or partition_binding.get("membership_sha256")
        != {
            role: partition["roles"][role]["example_membership_sha256"]
            for role in ("train", "selection", "calibration", "test")
        }
    ):
        raise NextBehaviorTrainingError(
            "training bundle partition binding mismatch"
        )
    if _sha256_path(preprocessing_config_path) != partition.get(
        "preprocessing_sha256"
    ):
        raise NextBehaviorTrainingError(
            "training bundle preprocessing binding mismatch"
        )
    pre_final = bundle.get("pre_final_role_artifacts")
    if not isinstance(pre_final, dict) or set(pre_final) != {
        "train",
        "selection",
        "calibration",
    }:
        raise NextBehaviorTrainingError(
            "training bundle must contain only pre-final role artifacts"
        )
    expected_role_keys = {
        "build_receipt_path",
        "safe_sessions_path",
        "examples_path",
        "source_receipts_path",
        "corpus_receipt_path",
        "historical_split_evidence_path",
    }
    if (
        not isinstance(role_artifact_paths, Mapping)
        or set(role_artifact_paths) != {"train", "selection", "calibration"}
        or any(
            not isinstance(paths, Mapping)
            or set(paths) != expected_role_keys
            for paths in role_artifact_paths.values()
        )
    ):
        raise NextBehaviorTrainingError(
            "bundle verification accepts exactly three pre-final role bundles"
        )
    purposes = {
        "train": "fit_model",
        "selection": "select_model",
        "calibration": "fit_calibration",
    }
    role_verifications: Dict[str, Dict[str, Any]] = {}
    expected_payload_sha256: Dict[str, str] = {}
    for role, paths in role_artifact_paths.items():
        role_verifications[role] = verify_selected_role_artifacts(
            **paths,
            expected_purpose=purposes[role],
            allow_final=False,
        )
        receipt = _read_json(
            paths["build_receipt_path"],
            label=f"{role} build receipt",
        )
        expected_payload_sha256[role] = receipt["examples"]["sha256"]
        if (
            pre_final[role]["source_file_sha256"]
            != expected_payload_sha256[role]
            or pre_final[role]["verified_role_receipt"]
            != role_verifications[role]
        ):
            raise NextBehaviorTrainingError(
                f"{role} role receipt changed after training"
            )
    examples, loaded_partition = load_pre_final_examples(
        train_path=role_artifact_paths["train"]["examples_path"],
        selection_path=role_artifact_paths["selection"]["examples_path"],
        calibration_path=role_artifact_paths["calibration"]["examples_path"],
        partition_manifest_path=partition_manifest_path,
        expected_payload_sha256=expected_payload_sha256,
    )
    if loaded_partition != partition:
        raise NextBehaviorTrainingError(
            "partition changed during bundle verification"
        )

    vocabulary_path = _verified_bundle_entry(
        root, bundle.get("vocabulary", {}), label="vocabulary"
    )
    vocabulary = require_valid_vocabulary(
        _read_json(vocabulary_path, label="vocabulary")
    )
    if (
        vocabulary["training_membership_sha256"]
        != partition_binding["membership_sha256"]["train"]
        or vocabulary["preprocessing_sha256"]
        != partition["preprocessing_sha256"]
    ):
        raise NextBehaviorTrainingError(
            "training vocabulary role binding mismatch"
        )
    model_spec_path = _verified_bundle_entry(
        root, bundle.get("model_spec", {}), label="model spec"
    )
    model_spec = require_valid_model_spec(
        _read_json(model_spec_path, label="model spec")
    )
    if model_spec["vocabulary_sha256"] != vocabulary_sha256(vocabulary):
        raise NextBehaviorTrainingError(
            "model spec vocabulary binding mismatch"
        )

    seed_records = bundle.get("seed_runs")
    if (
        not isinstance(seed_records, list)
        or [item.get("seed") for item in seed_records] != list(DECLARED_SEEDS)
    ):
        raise NextBehaviorTrainingError(
            "training bundle does not contain every declared seed in order"
        )
    verified_seeds = [
        _verify_seed_completion(root, item, model_spec=model_spec)
        for item in seed_records
    ]
    selection_path = _verified_bundle_entry(
        root,
        bundle.get("selection_decision", {}),
        label="selection decision",
    )
    selection = _read_json(selection_path, label="selection decision")
    if not isinstance(selection, dict):
        raise NextBehaviorTrainingError("selection decision is invalid")
    selection_identity = deepcopy(selection)
    decision_sha256 = selection_identity.pop("decision_sha256", None)
    selected = select_completed_seed(verified_seeds)
    if (
        decision_sha256 != _sha256_json(selection_identity)
        or selection.get("test_opened") is not False
        or selection.get("declared_seeds") != list(DECLARED_SEEDS)
        or selection.get("complete_seeds") != list(DECLARED_SEEDS)
        or selection.get("incomplete_seeds") != []
        or selection.get("selected_seed") != selected["seed"]
        or selection.get("selected_checkpoint_sha256")
        != selected["checkpoint"]["sha256"]
        or selection.get("training_membership_sha256")
        != partition_binding["membership_sha256"]["train"]
        or selection.get("selection_membership_sha256")
        != partition_binding["membership_sha256"]["selection"]
    ):
        raise NextBehaviorTrainingError(
            "selection decision does not reproduce from complete seeds"
        )

    baselines = bundle.get("baselines")
    if not isinstance(baselines, dict) or set(baselines) != set(
        policy["baselines"]["families"]
    ):
        raise NextBehaviorTrainingError("baseline bundle is incomplete")
    verified_baseline_metrics: Dict[str, Dict[str, Any]] = {}
    for family, entry in baselines.items():
        artifact_path = _verified_bundle_entry(
            root, entry.get("artifact", {}), label=f"baseline {family}"
        )
        metrics_path = _verified_bundle_entry(
            root,
            entry.get("selection_metrics", {}),
            label=f"baseline {family} selection metrics",
        )
        artifact = require_valid_baseline(
            _read_json(artifact_path, label=f"baseline {family}")
        )
        if (
            artifact["family"] != family
            or entry.get("model_id") != artifact["model_id"]
            or membership_sha256(artifact["training_example_ids"])
            != partition_binding["membership_sha256"]["train"]
            or entry.get("training_membership_sha256")
            != partition_binding["membership_sha256"]["train"]
            or entry.get("selection_membership_sha256")
            != partition_binding["membership_sha256"]["selection"]
        ):
            raise NextBehaviorTrainingError(
                f"baseline {family} role binding mismatch"
            )
        recalculated = evaluate_next_behavior_predictions(
            examples["selection"],
            predict_baseline_many(artifact, examples["selection"]),
            minimum_target_sessions=policy["selection"][
                "minimum_independent_target_sessions"
            ],
            minimum_targets=policy["selection"]["minimum_targets"],
            bootstrap_samples=1,
        )
        if _read_json(
            metrics_path, label=f"baseline {family} selection metrics"
        ) != recalculated:
            raise NextBehaviorTrainingError(
                f"baseline {family} selection metrics do not reproduce"
            )
        verified_baseline_metrics[family] = recalculated
    _verified_bundle_entry(
        root,
        bundle.get("baselines_manifest", {}),
        label="baseline manifest",
    )

    for record in verified_seeds:
        seed_directory = (root / record["checkpoint"]["path"]).parent
        persisted_predictions = _read_json(
            seed_directory / "selection_predictions.json",
            label="seed selection predictions",
        )
        persisted_metrics = _read_json(
            seed_directory / "selection_metrics.json",
            label="seed selection metrics",
        )
        recalculated = evaluate_next_behavior_predictions(
            examples["selection"],
            persisted_predictions,
            minimum_target_sessions=policy["selection"][
                "minimum_independent_target_sessions"
            ],
            minimum_targets=policy["selection"]["minimum_targets"],
            bootstrap_samples=1,
        )
        if persisted_metrics != recalculated:
            raise NextBehaviorTrainingError(
                "seed selection metrics do not reproduce"
            )
        candidate = assess_selection_candidate(
            seed=record["seed"],
            metrics=recalculated,
            baseline_metrics=verified_baseline_metrics[
                "hard_backoff_vomm"
            ],
            p95_latency_ms=record["candidate"]["selection_values"][
                "p95_single_case_cpu_latency_ms"
            ],
            selection_policy=policy["selection"],
        )
        if candidate != record["candidate"]:
            raise NextBehaviorTrainingError(
                "seed selection candidate does not reproduce"
            )

    calibration_path = _verified_bundle_entry(
        root, bundle.get("calibration", {}), label="calibration"
    )
    calibration_raw_path = _verified_bundle_entry(
        root,
        bundle.get("calibration_raw_outputs", {}),
        label="calibration raw outputs",
    )
    _verified_bundle_entry(
        root,
        bundle.get("calibration_predictions", {}),
        label="calibration predictions",
    )
    calibration = require_valid_calibration_mapping(
        _read_json(calibration_path, label="calibration")
    )
    if (
        calibration["fit_partition_membership_sha256"]
        != partition_binding["membership_sha256"]["calibration"]
        or calibration["checkpoint_sha256"]
        != selected["checkpoint"]["sha256"]
        or calibration["vocabulary_sha256"]
        != vocabulary_sha256(vocabulary)
        or calibration["preprocessing_sha256"]
        != partition["preprocessing_sha256"]
    ):
        raise NextBehaviorTrainingError(
            "calibration role or artifact binding mismatch"
        )
    calibration_raw = _read_json(
        calibration_raw_path, label="calibration raw outputs"
    )
    refitted_calibration = fit_temperature_mapping(
        _calibration_rows(
            examples["calibration"],
            calibration_raw,
            checkpoint_sha256=selected["checkpoint"]["sha256"],
            vocabulary_sha256_value=vocabulary_sha256(vocabulary),
            preprocessing_sha256=partition["preprocessing_sha256"],
        ),
        calibration_example_ids=[
            item["example_id"] for item in examples["calibration"]
        ],
        fit_partition_membership_sha256=partition_binding[
            "membership_sha256"
        ]["calibration"],
        checkpoint_sha256=selected["checkpoint"]["sha256"],
        vocabulary_sha256=vocabulary_sha256(vocabulary),
        preprocessing_sha256=partition["preprocessing_sha256"],
    )
    if refitted_calibration != calibration:
        raise NextBehaviorTrainingError(
            "calibration mapping does not reproduce from its frozen role"
        )
    bindings_path = _verified_bundle_entry(
        root,
        bundle.get("experiment_manifest_bindings", {}),
        label="experiment manifest bindings",
    )
    binding_value = _read_json(bindings_path, label="experiment manifest bindings")
    # Accepted v1 bundles predate the complete decision-freeze hand-off.
    # Keep their historical verification behavior intact; only v2 records may
    # feed the new manifest merger.
    if isinstance(binding_value, Mapping) and binding_value.get(
        "schema_version"
    ) == EXPERIMENT_BINDINGS_SCHEMA_VERSION:
        require_valid_experiment_manifest_bindings(binding_value, policy=policy)
    elif not isinstance(binding_value, Mapping) or binding_value.get(
        "schema_version"
    ) != EXPERIMENT_BINDINGS_SCHEMA_VERSION_V1:
        raise NextBehaviorTrainingError("experiment manifest bindings are invalid")
    return {
        "status": "frozen_pre_test",
        "test_opened": False,
        "code_commit": bundle["code_commit"],
        "training_bundle_sha256": _sha256_path(bundle_path),
    }


def run_training_experiment(
    *,
    train_path: Path,
    train_safe_sessions_path: Path,
    train_build_receipt_path: Path,
    train_source_receipts_path: Path,
    train_corpus_receipt_path: Path,
    train_historical_split_evidence_path: Path,
    selection_path: Path,
    selection_safe_sessions_path: Path,
    selection_build_receipt_path: Path,
    selection_source_receipts_path: Path,
    selection_corpus_receipt_path: Path,
    selection_historical_split_evidence_path: Path,
    calibration_path: Path,
    calibration_safe_sessions_path: Path,
    calibration_build_receipt_path: Path,
    calibration_source_receipts_path: Path,
    calibration_corpus_receipt_path: Path,
    calibration_historical_split_evidence_path: Path,
    partition_manifest_path: Path,
    preprocessing_config_path: Path,
    experiment_policy_path: Path,
    environment_lock_path: Path,
    output_dir: Path,
    code_commit: str,
) -> Dict[str, Any]:
    """Run all pre-final fitting stages and atomically freeze their outputs."""

    if output_dir.exists():
        raise FileExistsError(f"refusing to overwrite existing bundle: {output_dir}")
    policy = load_experiment_policy(experiment_policy_path)
    normalized_seeds = tuple(policy["training"]["seeds"])
    verified_commit = _require_code_commit(code_commit)

    output_dir.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(
        tempfile.mkdtemp(prefix=f".{output_dir.name}.", dir=output_dir.parent)
    )
    try:
        role_verification_inputs = {
            "train": {
                "purpose": "fit_model",
                "build_receipt_path": train_build_receipt_path,
                "safe_sessions_path": train_safe_sessions_path,
                "examples_path": train_path,
                "source_receipts_path": train_source_receipts_path,
                "corpus_receipt_path": train_corpus_receipt_path,
                "historical_split_evidence_path": (
                    train_historical_split_evidence_path
                ),
            },
            "selection": {
                "purpose": "select_model",
                "build_receipt_path": selection_build_receipt_path,
                "safe_sessions_path": selection_safe_sessions_path,
                "examples_path": selection_path,
                "source_receipts_path": selection_source_receipts_path,
                "corpus_receipt_path": selection_corpus_receipt_path,
                "historical_split_evidence_path": (
                    selection_historical_split_evidence_path
                ),
            },
            "calibration": {
                "purpose": "fit_calibration",
                "build_receipt_path": calibration_build_receipt_path,
                "safe_sessions_path": calibration_safe_sessions_path,
                "examples_path": calibration_path,
                "source_receipts_path": calibration_source_receipts_path,
                "corpus_receipt_path": calibration_corpus_receipt_path,
                "historical_split_evidence_path": (
                    calibration_historical_split_evidence_path
                ),
            },
        }
        role_verifications: Dict[str, Dict[str, Any]] = {}
        expected_payload_sha256: Dict[str, str] = {}
        for role, inputs in role_verification_inputs.items():
            role_verifications[role] = verify_selected_role_artifacts(
                build_receipt_path=inputs["build_receipt_path"],
                safe_sessions_path=inputs["safe_sessions_path"],
                examples_path=inputs["examples_path"],
                source_receipts_path=inputs["source_receipts_path"],
                corpus_receipt_path=inputs["corpus_receipt_path"],
                historical_split_evidence_path=inputs[
                    "historical_split_evidence_path"
                ],
                expected_purpose=inputs["purpose"],
                allow_final=False,
            )
            build_receipt = _read_json(
                inputs["build_receipt_path"],
                label=f"{role} build receipt",
            )
            expected_payload_sha256[role] = build_receipt["examples"][
                "sha256"
            ]
        examples, partition_manifest = load_pre_final_examples(
            train_path=train_path,
            selection_path=selection_path,
            calibration_path=calibration_path,
            partition_manifest_path=partition_manifest_path,
            expected_payload_sha256=expected_payload_sha256,
        )
        preprocessing_sha256 = _sha256_path(preprocessing_config_path)
        if preprocessing_sha256 != partition_manifest["preprocessing_sha256"]:
            raise NextBehaviorTrainingError(
                "preprocessing bytes do not match the partition manifest"
            )
        if partition_manifest.get("max_sequence_length") != policy[
            "architecture"
        ]["maximum_sequence_length"]:
            raise NextBehaviorTrainingError(
                "partition sequence length does not match experiment policy"
            )
        require_consistent_role_provenance(
            role_verifications,
            preprocessing_sha256=preprocessing_sha256,
        )
        for role, verification in role_verifications.items():
            role_manifest = partition_manifest["roles"][role]
            membership = verification["membership"]
            if (
                membership["source_member_count"]
                != role_manifest["source_member_count"]
                or membership["source_member_membership_sha256"]
                != role_manifest["source_member_membership_sha256"]
                or membership["session_membership_sha256"]
                != role_manifest["session_membership_sha256"]
                or membership["example_membership_sha256"]
                != role_manifest["example_membership_sha256"]
            ):
                raise NextBehaviorTrainingError(
                    f"{role} verified payload does not match the frozen "
                    "partition role"
                )
        policy_semantic_sha256 = experiment_policy_sha256(policy)
        policy_file_sha256 = _sha256_path(experiment_policy_path)
        environment_lock_sha256 = _sha256_path(environment_lock_path)
        role_memberships = {
            role: partition_manifest["roles"][role][
                "example_membership_sha256"
            ]
            for role in ("train", "selection", "calibration", "test")
        }
        role_paths = {
            "train": train_path,
            "selection": selection_path,
            "calibration": calibration_path,
        }
        model_input_ids = {
            role: [item["model_input"]["input_hash"] for item in values]
            for role, values in examples.items()
        }
        for left, right in (
            ("train", "selection"),
            ("train", "calibration"),
            ("selection", "calibration"),
        ):
            overlap = set(model_input_ids[left]).intersection(
                model_input_ids[right]
            )
            if overlap:
                raise NextBehaviorTrainingError(
                    f"{left} and {right} model-input membership intersects"
                )
        role_artifacts = {
            role: {
                "source_file_sha256": _sha256_path(role_paths[role]),
                "source_file_byte_size": role_paths[role].stat().st_size,
                "ordered_examples_sha256": _ordered_records_sha256(values),
                "example_membership_sha256": role_memberships[role],
                "model_input_membership_sha256": membership_sha256(
                    model_input_ids[role]
                ),
                "verified_role_receipt": role_verifications[role],
            }
            for role, values in examples.items()
        }
        vocabulary = build_training_vocabulary(
            examples["train"],
            preprocessing_sha256=preprocessing_sha256,
            training_membership_sha256=role_memberships["train"],
        )
        vocabulary_path = staging / "vocabulary.json"
        _write_json(vocabulary_path, vocabulary)
        model_spec = build_model_spec(vocabulary)
        model_spec_path = staging / "model_spec.json"
        _write_json(model_spec_path, model_spec)

        baseline_policy = policy["baselines"]
        baselines = fit_corrected_target_baselines(
            examples["train"],
            maximum_order=baseline_policy["maximum_order"],
            interpolation_decay=baseline_policy["interpolation_decay"],
            include_zero_order=baseline_policy["include_zero_order"],
        )
        baseline_entries: Dict[str, Any] = {}
        baseline_metrics: Dict[str, Any] = {}
        for family, artifact in baselines.items():
            path = staging / "baselines" / f"{family}.json"
            _write_json(path, artifact)
            predictions = predict_baseline_many(artifact, examples["selection"])
            metrics = evaluate_next_behavior_predictions(
                examples["selection"],
                predictions,
                minimum_target_sessions=policy["selection"][
                    "minimum_independent_target_sessions"
                ],
                minimum_targets=policy["selection"]["minimum_targets"],
                bootstrap_samples=1,
            )
            metrics_path = staging / "baselines" / f"{family}.selection_metrics.json"
            _write_json(metrics_path, metrics)
            baseline_metrics[family] = metrics
            baseline_entries[family] = {
                "model_id": artifact["model_id"],
                "artifact": _artifact_entry(path, staging),
                "selection_metrics": _artifact_entry(metrics_path, staging),
                "training_membership_sha256": role_memberships["train"],
                "selection_membership_sha256": role_memberships["selection"],
            }
        require_selection_support(
            baseline_metrics["hard_backoff_vomm"],
            policy["selection"],
        )
        baselines_manifest = {
            "schema_version": "next_behavior_baseline_bundle.v1",
            "target_contract_id": TARGET_CONTRACT_ID,
            "experiment_policy_sha256": policy_semantic_sha256,
            "training_membership_sha256": role_memberships["train"],
            "selection_membership_sha256": role_memberships["selection"],
            "configuration": deepcopy(baseline_policy),
            "artifacts": {
                family: {
                    "model_id": entry["model_id"],
                    "artifact_sha256": entry["artifact"]["sha256"],
                    "selection_metrics_sha256": entry["selection_metrics"][
                        "sha256"
                    ],
                }
                for family, entry in sorted(baseline_entries.items())
            },
        }
        baselines_manifest["manifest_sha256"] = _sha256_json(
            baselines_manifest
        )
        baselines_manifest_path = staging / "baselines" / "manifest.json"
        _write_json(baselines_manifest_path, baselines_manifest)

        seed_records: List[Dict[str, Any]] = []
        for seed in normalized_seeds:
            seed_dir = staging / "seed_runs" / f"transformer_seed_{seed}"
            seed_dir.mkdir(parents=True)
            checkpoint_path = seed_dir / "checkpoint.pt"
            try:
                model, checkpoint_receipt, training_log = _train_seed(
                    examples["train"],
                    vocabulary=vocabulary,
                    model_spec=model_spec,
                    policy=policy,
                    seed=seed,
                    checkpoint_path=checkpoint_path,
                )
                predictions, raw_outputs, p95_latency = _predict_transformer(
                    model,
                    examples["selection"],
                    vocabulary=vocabulary,
                    model_spec=model_spec,
                )
                repeat_predictions, repeat_raw, _unused_latency = _predict_transformer(
                    model,
                    examples["selection"],
                    vocabulary=vocabulary,
                    model_spec=model_spec,
                )
                if predictions != repeat_predictions or raw_outputs != repeat_raw:
                    raise NextBehaviorTrainingError(
                        "seed inference is not deterministically replayable"
                    )
                metrics = evaluate_next_behavior_predictions(
                    examples["selection"],
                    predictions,
                    minimum_target_sessions=policy["selection"][
                        "minimum_independent_target_sessions"
                    ],
                    minimum_targets=policy["selection"]["minimum_targets"],
                    bootstrap_samples=1,
                )
                candidate = assess_selection_candidate(
                    seed=seed,
                    metrics=metrics,
                    baseline_metrics=baseline_metrics["hard_backoff_vomm"],
                    p95_latency_ms=p95_latency,
                    selection_policy=policy["selection"],
                )
                receipt_path = seed_dir / "checkpoint_receipt.json"
                training_path = seed_dir / "training_log.json"
                prediction_path = seed_dir / "selection_predictions.json"
                raw_path = seed_dir / "selection_raw_outputs.json"
                metrics_path = seed_dir / "selection_metrics.json"
                candidate_path = seed_dir / "selection_candidate.json"
                _write_json(receipt_path, checkpoint_receipt)
                _write_json(training_path, training_log)
                _write_json(prediction_path, predictions)
                _write_json(raw_path, raw_outputs)
                _write_json(metrics_path, metrics)
                _write_json(candidate_path, candidate)
                completion = {
                    "schema_version": SEED_COMPLETION_SCHEMA_VERSION,
                    "status": "complete",
                    "seed": seed,
                    "training_membership_sha256": role_memberships["train"],
                    "selection_membership_sha256": role_memberships["selection"],
                    "checkpoint_sha256": checkpoint_receipt["checkpoint_sha256"],
                    "state_dictionary_sha256": checkpoint_receipt[
                        "state_dictionary_sha256"
                    ],
                    "selection_prediction_count": len(predictions),
                    "selection_example_membership_sha256": membership_sha256(
                        item["example_id"] for item in predictions
                    ),
                    "files_sha256": {
                        str(path.relative_to(seed_dir)): _sha256_path(path)
                        for path in (
                            checkpoint_path,
                            receipt_path,
                            training_path,
                            prediction_path,
                            raw_path,
                            metrics_path,
                            candidate_path,
                        )
                    },
                }
                completion["completion_sha256"] = _sha256_json(completion)
                completion_path = seed_dir / "completion.json"
                _write_json(completion_path, completion)
                seed_records.append(
                    {
                        "seed": seed,
                        "status": "complete",
                        "completion_marker_verified": (
                            _read_json(completion_path, label="seed completion")
                            == completion
                        ),
                        "candidate": candidate,
                        "checkpoint": _artifact_entry(checkpoint_path, staging),
                        "checkpoint_receipt": checkpoint_receipt,
                        "selection_metrics": _artifact_entry(metrics_path, staging),
                        "completion": _artifact_entry(completion_path, staging),
                    }
                )
            except Exception as exc:
                seed_records.append(
                    {
                        "seed": seed,
                        "status": "incomplete",
                        "completion_marker_verified": False,
                        "error_type": type(exc).__name__,
                        "error_message": str(exc),
                    }
                )

        require_all_declared_seeds(seed_records)
        try:
            selected = select_completed_seed(seed_records)
        except NextBehaviorTrainingError:
            publish_selection_blocked_bundle(
                staging,
                output_dir,
                seed_records=seed_records,
                code_commit=verified_commit,
            )
            raise
        selected_seed = int(selected["seed"])
        selected_checkpoint_path = staging / selected["checkpoint"]["path"]
        selected_model, selected_metadata = load_checkpoint(
            selected_checkpoint_path,
            expected_spec=model_spec,
            expected_checkpoint_sha256=selected["checkpoint"]["sha256"],
        )
        calibration_predictions, calibration_raw, _ = _predict_transformer(
            selected_model,
            examples["calibration"],
            vocabulary=vocabulary,
            model_spec=model_spec,
        )
        calibration = fit_temperature_mapping(
            _calibration_rows(
                examples["calibration"],
                calibration_raw,
                checkpoint_sha256=selected["checkpoint"]["sha256"],
                vocabulary_sha256_value=vocabulary_sha256(vocabulary),
                preprocessing_sha256=preprocessing_sha256,
            ),
            calibration_example_ids=[
                item["example_id"] for item in examples["calibration"]
            ],
            fit_partition_membership_sha256=role_memberships["calibration"],
            checkpoint_sha256=selected["checkpoint"]["sha256"],
            vocabulary_sha256=vocabulary_sha256(vocabulary),
            preprocessing_sha256=preprocessing_sha256,
        )
        calibration_path_out = staging / "calibration.json"
        _write_json(calibration_path_out, calibration)
        calibration_raw_path = staging / "calibration_raw_outputs.json"
        _write_json(calibration_raw_path, calibration_raw)
        calibration_predictions_path = staging / "calibration_predictions.json"
        _write_json(calibration_predictions_path, calibration_predictions)

        selection_decision = {
            "schema_version": SELECTION_DECISION_SCHEMA_VERSION,
            "target_contract_id": TARGET_CONTRACT_ID,
            "selected_on_partition": "selection",
            "test_opened": False,
            "selection_rule": policy["selection"],
            "selection_rule_sha256": _sha256_json(policy["selection"]),
            "declared_seeds": list(DECLARED_SEEDS),
            "complete_seeds": [
                item["seed"] for item in seed_records if item["status"] == "complete"
            ],
            "incomplete_seeds": [
                item["seed"]
                for item in seed_records
                if item["status"] != "complete"
            ],
            "selected_seed": selected_seed,
            "selected_checkpoint_sha256": selected["checkpoint"]["sha256"],
            "selected_state_dictionary_sha256": selected[
                "checkpoint_receipt"
            ]["state_dictionary_sha256"],
            "training_membership_sha256": role_memberships["train"],
            "selection_membership_sha256": role_memberships["selection"],
            "candidates": [
                item["candidate"]
                for item in seed_records
                if item["status"] == "complete"
            ],
        }
        selection_decision["decision_sha256"] = _sha256_json(
            selection_decision
        )
        selection_path_out = staging / "selection_decision.json"
        _write_json(selection_path_out, selection_decision)

        partition_sha256 = _sha256_path(partition_manifest_path)
        experiment_bindings = {
            "schema_version": EXPERIMENT_BINDINGS_SCHEMA_VERSION,
            "status": "ready_for_v2_experiment_manifest_merge",
            "target_contract_id": TARGET_CONTRACT_ID,
            "code_commit": verified_commit,
            "test_opened": False,
            "partition_manifest_id": partition_manifest["manifest_id"],
            "partition_manifest_sha256": partition_sha256,
            "partition_membership_sha256": role_memberships,
            "pre_final_role_artifacts": role_artifacts,
            "policies": {
                "experiment_policy_artifact_sha256": policy_file_sha256,
                "experiment_policy_sha256": policy_semantic_sha256,
                "preprocessing_sha256": preprocessing_sha256,
                "vocabulary_artifact_sha256": _sha256_path(vocabulary_path),
                "vocabulary_sha256": vocabulary_sha256(vocabulary),
                "environment_lock_sha256": environment_lock_sha256,
            },
            "model": {
                "family": "small_causal_transformer",
                "model_id": model_spec["spec_id"],
                "architecture_sha256": model_spec["architecture_sha256"],
                "parameter_count": selected_metadata["parameter_count"],
                "checkpoint_sha256": selected["checkpoint"]["sha256"],
                "model_spec_artifact_sha256": _sha256_path(model_spec_path),
                "model_spec_sha256": model_spec["spec_sha256"],
                "state_dictionary_sha256": selected_metadata[
                    "state_dictionary_sha256"
                ],
                "training_seed": selected_seed,
                "training_membership_sha256": role_memberships["train"],
                "selection_membership_sha256": role_memberships["selection"],
                "selected_on_partition": "selection",
                "deterministic_replay_verified": True,
            },
            "baselines": {
                "manifest_sha256": _sha256_path(baselines_manifest_path),
                "training_membership_sha256": role_memberships["train"],
                "families": {
                    family: {
                        "model_id": entry["model_id"],
                        "artifact_sha256": entry["artifact"]["sha256"],
                        "training_membership_sha256": role_memberships[
                            "train"
                        ],
                        "selection_membership_sha256": role_memberships[
                            "selection"
                        ],
                    }
                    for family, entry in sorted(baseline_entries.items())
                },
            },
            "calibration": {
                "artifact_sha256": _sha256_path(calibration_path_out),
                "status": calibration["status"],
                "method": calibration["method"],
                "mapping_sha256": calibration["mapping_sha256"],
                "fit_partition_membership_sha256": role_memberships[
                    "calibration"
                ],
            },
            "decision_freeze": build_decision_freeze_bindings(policy),
            "artifact_hashes": {
                "experiment_policy": policy_file_sha256,
                "preprocessing": preprocessing_sha256,
                "vocabulary": _sha256_path(vocabulary_path),
                "partition_manifest": partition_sha256,
                "environment_lock": environment_lock_sha256,
                "checkpoint": selected["checkpoint"]["sha256"],
                "model_spec": _sha256_path(model_spec_path),
                "calibration": _sha256_path(calibration_path_out),
                "baseline_manifest": _sha256_path(
                    baselines_manifest_path
                ),
                **{
                    f"baseline_{family}": entry["artifact"]["sha256"]
                    for family, entry in sorted(baseline_entries.items())
                },
            },
            "artifact_paths_relative_to_bundle": {
                "vocabulary": str(vocabulary_path.relative_to(staging)),
                "checkpoint": selected["checkpoint"]["path"],
                "model_spec": str(model_spec_path.relative_to(staging)),
                "calibration": str(calibration_path_out.relative_to(staging)),
                "baseline_manifest": str(
                    baselines_manifest_path.relative_to(staging)
                ),
                **{
                    f"baseline_{family}": entry["artifact"]["path"]
                    for family, entry in sorted(baseline_entries.items())
                },
            },
        }
        experiment_bindings["bindings_sha256"] = _sha256_json(
            experiment_bindings
        )
        bindings_path = staging / "experiment_manifest_bindings.json"
        _write_json(bindings_path, experiment_bindings)

        bundle = {
            "schema_version": TRAINING_BUNDLE_SCHEMA_VERSION,
            "status": (
                "frozen_pre_test"
                if all(item["status"] == "complete" for item in seed_records)
                else "incomplete_declared_seeds"
            ),
            "target_contract_id": TARGET_CONTRACT_ID,
            "code_commit": verified_commit,
            "test_opened": False,
            "final_test_path_accepted_by_command": False,
            "partition_manifest": {
                "manifest_id": partition_manifest["manifest_id"],
                "sha256": partition_sha256,
                "membership_sha256": role_memberships,
            },
            "pre_final_role_artifacts": role_artifacts,
            "role_counts": {
                role: {
                    "examples": len(values),
                    "sessions": len({item["session_id"] for item in values}),
                }
                for role, values in examples.items()
            },
            "experiment_policy": {
                "policy_id": policy["policy_id"],
                "semantic_sha256": policy_semantic_sha256,
                "file_sha256": policy_file_sha256,
            },
            "environment_lock_sha256": environment_lock_sha256,
            "training_configuration": _training_configuration(policy),
            "training_configuration_sha256": _sha256_json(
                _training_configuration(policy)
            ),
            "vocabulary": _artifact_entry(vocabulary_path, staging),
            "model_spec": _artifact_entry(model_spec_path, staging),
            "baselines": baseline_entries,
            "baselines_manifest": _artifact_entry(
                baselines_manifest_path, staging
            ),
            "seed_runs": seed_records,
            "selection_decision": _artifact_entry(selection_path_out, staging),
            "calibration": _artifact_entry(calibration_path_out, staging),
            "calibration_raw_outputs": _artifact_entry(
                calibration_raw_path, staging
            ),
            "calibration_predictions": _artifact_entry(
                calibration_predictions_path, staging
            ),
            "experiment_manifest_bindings": _artifact_entry(
                bindings_path, staging
            ),
        }
        bundle["bundle_sha256"] = _sha256_json(bundle)
        _write_json(staging / "training_bundle.json", bundle)
        verification = verify_frozen_training_bundle(
            staging,
            role_artifact_paths={
                role: {
                    key: value
                    for key, value in inputs.items()
                    if key != "purpose"
                }
                for role, inputs in role_verification_inputs.items()
            },
            partition_manifest_path=partition_manifest_path,
            preprocessing_config_path=preprocessing_config_path,
            experiment_policy_path=experiment_policy_path,
            environment_lock_path=environment_lock_path,
            expected_code_commit=verified_commit,
        )
        _write_json(
            staging / "training_bundle_verification.json",
            verification,
        )
        if output_dir.exists():
            raise FileExistsError(
                f"refusing to overwrite existing bundle: {output_dir}"
            )
        os.replace(staging, output_dir)
        return bundle
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--train", type=Path, required=True)
    parser.add_argument("--train-safe-sessions", type=Path, required=True)
    parser.add_argument("--train-build-receipt", type=Path, required=True)
    parser.add_argument("--train-source-receipts", type=Path, required=True)
    parser.add_argument("--train-corpus-receipt", type=Path, required=True)
    parser.add_argument(
        "--train-historical-split-evidence", type=Path, required=True
    )
    parser.add_argument("--selection", type=Path, required=True)
    parser.add_argument("--selection-safe-sessions", type=Path, required=True)
    parser.add_argument(
        "--selection-build-receipt", type=Path, required=True
    )
    parser.add_argument(
        "--selection-source-receipts", type=Path, required=True
    )
    parser.add_argument(
        "--selection-corpus-receipt", type=Path, required=True
    )
    parser.add_argument(
        "--selection-historical-split-evidence", type=Path, required=True
    )
    parser.add_argument("--calibration", type=Path, required=True)
    parser.add_argument(
        "--calibration-safe-sessions", type=Path, required=True
    )
    parser.add_argument(
        "--calibration-build-receipt", type=Path, required=True
    )
    parser.add_argument(
        "--calibration-source-receipts", type=Path, required=True
    )
    parser.add_argument(
        "--calibration-corpus-receipt", type=Path, required=True
    )
    parser.add_argument(
        "--calibration-historical-split-evidence", type=Path, required=True
    )
    parser.add_argument("--partition-manifest", type=Path, required=True)
    parser.add_argument("--preprocessing-config", type=Path, required=True)
    parser.add_argument("--experiment-policy", type=Path, required=True)
    parser.add_argument("--environment-lock", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--code-commit", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    bundle = run_training_experiment(
        train_path=args.train,
        train_safe_sessions_path=args.train_safe_sessions,
        train_build_receipt_path=args.train_build_receipt,
        train_source_receipts_path=args.train_source_receipts,
        train_corpus_receipt_path=args.train_corpus_receipt,
        train_historical_split_evidence_path=(
            args.train_historical_split_evidence
        ),
        selection_path=args.selection,
        selection_safe_sessions_path=args.selection_safe_sessions,
        selection_build_receipt_path=args.selection_build_receipt,
        selection_source_receipts_path=args.selection_source_receipts,
        selection_corpus_receipt_path=args.selection_corpus_receipt,
        selection_historical_split_evidence_path=(
            args.selection_historical_split_evidence
        ),
        calibration_path=args.calibration,
        calibration_safe_sessions_path=args.calibration_safe_sessions,
        calibration_build_receipt_path=args.calibration_build_receipt,
        calibration_source_receipts_path=args.calibration_source_receipts,
        calibration_corpus_receipt_path=args.calibration_corpus_receipt,
        calibration_historical_split_evidence_path=(
            args.calibration_historical_split_evidence
        ),
        partition_manifest_path=args.partition_manifest,
        preprocessing_config_path=args.preprocessing_config,
        experiment_policy_path=args.experiment_policy,
        environment_lock_path=args.environment_lock,
        output_dir=args.output_dir,
        code_commit=args.code_commit,
    )
    print(
        json.dumps(
            {
                "output": str(args.output_dir),
                "status": bundle["status"],
                "test_opened": bundle["test_opened"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
