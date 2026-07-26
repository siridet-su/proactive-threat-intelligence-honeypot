#!/usr/bin/env python3
"""Freeze a separate professor-approved corrected-target PoC pre-test bundle.

It consumes the immutable ``training.selection_blocked`` evidence read-only.
It never alters that directory or opens the Final Test role.  The resulting
bundle is intentionally separate and carries an approval decision explaining
why the original ``BLOCKED_AT_SELECTION`` conclusion remains true.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from copy import deepcopy
from pathlib import Path
from typing import Any, Mapping, Sequence

from production.prediction.next_behavior_calibration import fit_temperature_mapping
from production.prediction.next_behavior_model import load_checkpoint, predict_next_behavior
from production.prediction.next_behavior_partitions import membership_sha256
from production.prediction.next_behavior_professor_approved import (
    build_professor_approved_decision,
)
from production.prediction.next_behavior_tensor import tensorize_example, vocabulary_sha256
from production.tools.train_next_behavior_experiment import _calibration_rows
from production.utils.serialization import stable_json


class ProfessorApprovedPreparationError(ValueError):
    pass


def _sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ProfessorApprovedPreparationError(f"invalid JSON: {path}") from exc


def _jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ProfessorApprovedPreparationError(
                    f"invalid JSONL {path}:{number}"
                ) from exc
            if not isinstance(row, dict):
                raise ProfessorApprovedPreparationError("JSONL row is not an object")
            rows.append(row)
    return rows


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(stable_json(value) + "\n", encoding="utf-8")


def _verify_blocked_files(blocked: Path, receipt: Mapping[str, Any]) -> None:
    for relative, expected in receipt.get("pre_test_artifact_hashes", {}).items():
        path = blocked / relative
        if not path.is_file() or _sha(path) != expected:
            raise ProfessorApprovedPreparationError(
                f"immutable blocked artifact failed verification: {relative}"
            )


def _selection_raw_outputs(
    examples: Sequence[Mapping[str, Any]], *, model: Any, spec: Mapping[str, Any], vocabulary: Mapping[str, Any]
) -> list[dict[str, Any]]:
    result = []
    for example in examples:
        result.append({
            "example_id": example["example_id"],
            "session_id": example["session_id"],
            "model_output": predict_next_behavior(
                model, tensorize_example(example, vocabulary), spec=spec
            ),
        })
    return result


def prepare(
    *,
    experiment_root: Path,
    output_root: Path,
    code_commit: str,
) -> dict[str, Any]:
    """Create an atomic calibration/pre-test bundle without reading Final data."""
    blocked = experiment_root / "training.selection_blocked"
    receipt_path = blocked / "SELECTION_BLOCKED.json"
    if output_root.exists():
        raise FileExistsError(f"refusing to overwrite PoC bundle: {output_root}")
    receipt = _json(receipt_path)
    if not isinstance(receipt, dict):
        raise ProfessorApprovedPreparationError("blocked receipt is not an object")
    _verify_blocked_files(blocked, receipt)
    decision = build_professor_approved_decision(
        receipt,
        selection_blocked_receipt_sha256=_sha(receipt_path),
        source_code_commit=code_commit,
    )
    selected_seed = int(decision["selection"]["selected_seed"])
    selected_dir = blocked / "seed_runs" / f"transformer_seed_{selected_seed}"
    checkpoint = selected_dir / "checkpoint.pt"
    spec_path = blocked / "model_spec.json"
    vocabulary_path = blocked / "vocabulary.json"
    spec, vocabulary = _json(spec_path), _json(vocabulary_path)
    selected_hash = decision["selection"]["selected_checkpoint_sha256"]
    model, metadata = load_checkpoint(
        checkpoint, expected_spec=spec, expected_checkpoint_sha256=selected_hash
    )
    if metadata["checkpoint_sha256"] != selected_hash:
        raise ProfessorApprovedPreparationError("selected checkpoint replay mismatch")

    calibration_examples_path = experiment_root / "roles" / "calibration" / "examples.jsonl"
    calibration_examples = _jsonl(calibration_examples_path)
    calibration_raw = _selection_raw_outputs(
        calibration_examples, model=model, spec=spec, vocabulary=vocabulary
    )
    calibration_membership = membership_sha256(
        [row["example_id"] for row in calibration_examples]
    )
    calibration = fit_temperature_mapping(
        _calibration_rows(
            calibration_examples, calibration_raw,
            checkpoint_sha256=selected_hash,
            vocabulary_sha256_value=vocabulary_sha256(vocabulary),
            preprocessing_sha256=spec["preprocessing_sha256"],
        ),
        calibration_example_ids=[row["example_id"] for row in calibration_examples],
        fit_partition_membership_sha256=calibration_membership,
        checkpoint_sha256=selected_hash,
        vocabulary_sha256=vocabulary_sha256(vocabulary),
        preprocessing_sha256=spec["preprocessing_sha256"],
    )
    decision_policy = {
        "schema_version": "next_behavior_professor_approved_decision_policy.v1",
        "status": "frozen_pre_test",
        "score_semantics": "global_temperature_sigmoid_probabilities",
        "tactic_threshold": 0.5,
        "terminal_threshold": 0.5,
        "terminal_precedence": True,
        "empty_nonterminal_rule": "highest_ranked_tactic",
        "abstention": {"score_based": False, "asset_or_schema_failure": True, "fallback_model": None},
        "objective": "calibration_binary_log_loss_only; thresholds_fixed_by_probability_semantics",
    }
    decision_policy["sha256"] = hashlib.sha256(stable_json(decision_policy).encode()).hexdigest()
    staging = Path(tempfile.mkdtemp(prefix=f".{output_root.name}.", dir=output_root.parent))
    try:
        _write_json(staging / "PROFESSOR_APPROVED_DECISION.json", decision)
        _write_json(staging / "calibration.json", calibration)
        _write_json(staging / "calibration_raw_outputs.json", calibration_raw)
        _write_json(staging / "decision_policy.json", decision_policy)
        inventory = {
            "schema_version": "next_behavior_professor_approved_pretest_inventory.v1",
            "status": "prepared_pre_test_not_opened",
            "code_commit": code_commit,
            "original_selection_blocked_path": str(blocked),
            "original_selection_blocked_sha256": _sha(receipt_path),
            "selected_seed": selected_seed,
            "selected_checkpoint": {"path": str(checkpoint), "sha256": selected_hash, "metadata": metadata},
            "vocabulary": {"path": str(vocabulary_path), "sha256": _sha(vocabulary_path), "semantic_sha256": vocabulary_sha256(vocabulary)},
            "model_spec": {"path": str(spec_path), "sha256": _sha(spec_path), "spec_sha256": spec["spec_sha256"]},
            "calibration_examples": {"path": str(calibration_examples_path), "count": len(calibration_examples), "membership_sha256": calibration_membership},
            "authority": decision["approval_basis"],
            "final_test_opened": False,
        }
        inventory["inventory_sha256"] = hashlib.sha256(stable_json(inventory).encode()).hexdigest()
        _write_json(staging / "PRETEST_INVENTORY.json", inventory)
        hashes = {str(p.relative_to(staging)): _sha(p) for p in sorted(staging.rglob("*")) if p.is_file()}
        _write_json(staging / "SHA256SUMS.json", {"files": hashes})
        os.replace(staging, output_root)
    except BaseException:
        import shutil
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return _json(output_root / "PRETEST_INVENTORY.json")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--experiment-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--code-commit", required=True)
    args = parser.parse_args(argv)
    prepare(experiment_root=args.experiment_root, output_root=args.output_root, code_commit=args.code_commit)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
