"""Create a manifest-bound immutable external hard-backoff VOMM artifact."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence

from production.prediction.external_vomm_artifact import (
    build_external_vomm_artifact,
    sha256_file,
)


def _load_json_object(path: str) -> dict:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--payload", required=True)
    parser.add_argument("--artifact", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--artifact-version", required=True)
    parser.add_argument("--source-start", required=True)
    parser.add_argument("--source-end", required=True)
    parser.add_argument("--classification-policy", required=True)
    parser.add_argument("--trust-policy", required=True)
    parser.add_argument("--classification-policy-sha256", default="")
    parser.add_argument("--securebert-checkpoint-id", required=True)
    parser.add_argument("--securebert-checkpoint-sha256", required=True)
    parser.add_argument("--prefix-max-length", type=int, default=3)
    parser.add_argument("--transition-smoothing", type=float, default=0.05)
    parser.add_argument("--min-transition-count", type=int, default=2)
    parser.add_argument("--code-commit", default="")
    args = parser.parse_args(argv)

    classification = {
        "policy_path": args.classification_policy,
        "sha256": args.classification_policy_sha256 or sha256_file(args.classification_policy),
        "securebert_checkpoint_id": args.securebert_checkpoint_id,
        "securebert_checkpoint_sha256": args.securebert_checkpoint_sha256,
        "label_quality": "classifier_derived_weak_labels",
    }
    trust_policy = {
        "path": args.trust_policy,
        "sha256": sha256_file(args.trust_policy),
    }
    preprocessing = {
        "input_schema": "privacy-minimized whole-session tactic payload",
        "split_requirement": "preassigned chronological whole-session train/validation/test",
        "trusted_label_requirement": "source builder admitted trusted classifier-derived tactic labels only",
        "adjacent_tactic_deduplication": True,
        "prefix_max_length": max(args.prefix_max_length, 1),
        "transition_smoothing": max(args.transition_smoothing, 0.0),
        "min_transition_count": max(args.min_transition_count, 1),
    }
    result = build_external_vomm_artifact(
        payload_path=args.payload,
        artifact_path=args.artifact,
        manifest_path=args.manifest,
        artifact_version=args.artifact_version,
        source_start=args.source_start,
        source_end=args.source_end,
        preprocessing=preprocessing,
        classification=classification,
        trust_policy=trust_policy,
        model_builder_commit=args.code_commit,
    )
    print(json.dumps({
        "artifact_path": args.artifact,
        "manifest_path": args.manifest,
        "artifact_sha256": result["artifact_sha256"],
        "manifest_sha256": result["manifest_sha256"],
        "model_id": result["artifact"]["model_id"],
        "manifest_id": result["manifest"]["manifest_id"],
        "partition_intersections": result["manifest"]["partition_intersections"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
