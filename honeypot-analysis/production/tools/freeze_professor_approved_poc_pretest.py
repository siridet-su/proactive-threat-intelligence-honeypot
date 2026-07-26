#!/usr/bin/env python3
"""Freeze and verify the additive professor-approved PoC manifest.

This tool reads only development/Calibration artifacts and Final *metadata*.
It deliberately does not parse or hash Final examples; the recorded example
digest is taken from the immutable Final build receipt and is verified only
after the separate one-time evaluation ledger has been claimed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Mapping, Sequence

from production.prediction.next_behavior_professor_approved import (
    build_professor_approved_pretest_manifest,
    verify_professor_approved_pretest_artifacts,
)
from production.prediction.next_behavior_tensor import vocabulary_sha256
from production.utils.serialization import stable_json


class ProfessorApprovedFreezeError(ValueError):
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
        raise ProfessorApprovedFreezeError(f"invalid JSON: {path}") from exc


def _descriptor(path: Path, **extra: Any) -> dict[str, Any]:
    if not path.is_file():
        raise ProfessorApprovedFreezeError(f"required artifact missing: {path}")
    return {"path": str(path), "sha256": _sha(path), **extra}


def freeze(*, experiment_root: Path, preparation_root: Path, output_root: Path, code_commit: str, repository_root: Path) -> dict[str, Any]:
    if output_root.exists():
        raise FileExistsError(f"refusing to overwrite frozen manifest: {output_root}")
    blocked = experiment_root / "training.selection_blocked"
    final_receipt_path = experiment_root / "roles" / "test" / "build_receipt.json"
    final_receipt = _json(final_receipt_path)
    if final_receipt.get("role") != "test" or final_receipt.get("purpose") != "final_evaluation":
        raise ProfessorApprovedFreezeError("Final Test metadata is not sealed final role")
    examples = final_receipt.get("examples")
    membership = final_receipt.get("membership")
    if not isinstance(examples, Mapping) or not isinstance(membership, Mapping):
        raise ProfessorApprovedFreezeError("Final Test receipt is incomplete")
    final_examples = experiment_root / "roles" / "test" / "examples.jsonl"
    # Do not read final_examples here. Its prior receipt supplies the binding.
    final_test = {
        "path": str(final_examples), "sha256": examples.get("sha256"), "role": "test",
        "membership_sha256": membership.get("example_membership_sha256"), "kind": "sealed_examples_jsonl",
    }
    model_spec_path = blocked / "model_spec.json"
    vocabulary_path = blocked / "vocabulary.json"
    vocabulary = _json(vocabulary_path)
    model_spec = _json(model_spec_path)
    preprocessing_path = repository_root / "configs" / "next_behavior_preprocessing.v1.json"
    decision_path = preparation_root / "PROFESSOR_APPROVED_DECISION.json"
    calibration_path = preparation_root / "calibration.json"
    policy_path = preparation_root / "decision_policy.json"
    environment_path = repository_root / "configs" / "next_behavior_classifier_environment.v1.json"
    artifacts = {
        "original_selection_blocked_receipt": _descriptor(blocked / "SELECTION_BLOCKED.json"),
        "selected_checkpoint": _descriptor(
            blocked / "seed_runs" / f"transformer_seed_{_json(decision_path)['selection']['selected_seed']}" / "checkpoint.pt"
        ),
        "model_spec": _descriptor(model_spec_path, semantic_sha256=model_spec["spec_sha256"]),
        "vocabulary": _descriptor(vocabulary_path, semantic_sha256=vocabulary_sha256(vocabulary)),
        "preprocessing_contract": _descriptor(preprocessing_path, semantic_sha256=_sha(preprocessing_path)),
        "hard_backoff_vomm": _descriptor(blocked / "baselines" / "hard_backoff_vomm.json"),
        "partition_manifest": _descriptor(experiment_root / "partition" / "partition_manifest.json"),
        "train_receipt": _descriptor(experiment_root / "roles" / "train" / "build_receipt.json", role="train"),
        "selection_receipt": _descriptor(experiment_root / "roles" / "selection" / "build_receipt.json", role="selection"),
        "calibration_receipt": _descriptor(experiment_root / "roles" / "calibration" / "build_receipt.json", role="calibration"),
        "final_receipt": _descriptor(final_receipt_path),
        "environment_receipt": _descriptor(environment_path),
    }
    environment = {
        "python": "3.12", "torch": "2.13.0+cpu", "cpu": "cpu_only",
        "receipt_sha256": artifacts["environment_receipt"]["sha256"],
    }
    manifest = build_professor_approved_pretest_manifest(
        decision=_json(decision_path), calibration=_json(calibration_path),
        decision_policy=_json(policy_path), code_commit=code_commit, artifacts=artifacts,
        final_test=final_test, environment=environment,
    )
    # This hashes every declared non-final artifact and leaves Final bytes sealed.
    verification = verify_professor_approved_pretest_artifacts(manifest)
    staging = Path(tempfile.mkdtemp(prefix=f".{output_root.name}.", dir=output_root.parent))
    try:
        (staging / "PRETEST_MANIFEST.json").write_text(stable_json(manifest) + "\n", encoding="utf-8")
        (staging / "PRETEST_VERIFICATION.json").write_text(stable_json(verification) + "\n", encoding="utf-8")
        sums = {p.name: _sha(p) for p in sorted(staging.iterdir()) if p.is_file()}
        (staging / "SHA256SUMS.json").write_text(stable_json({"files": sums}) + "\n", encoding="utf-8")
        os.replace(staging, output_root)
    except BaseException:
        import shutil
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return manifest


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--experiment-root", type=Path, required=True)
    parser.add_argument("--preparation-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--repository-root", type=Path, default=Path.cwd())
    parser.add_argument("--code-commit", required=True)
    args = parser.parse_args(argv)
    freeze(**vars(args))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
