#!/usr/bin/env python3
"""Build compact preprocessing evidence from a privacy-safe corpus JSONL.

The inventory validates every session, reconstructs every causal example, and
records only aggregate counts and content hashes. It does not write examples,
open a model partition, fit a vocabulary, or expose private event content.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Mapping, Sequence

from production.prediction.next_behavior_contract import (
    TARGET_CONTRACT_ID,
    require_valid_next_behavior_session,
)
from production.prediction.next_behavior_corpus import (
    require_valid_corpus_receipt,
    require_valid_source_member_receipt,
)
from production.prediction.next_behavior_partitions import (
    assign_seven_member_roles,
)
from production.prediction.next_behavior_preprocessing import (
    build_behavior_phases,
    build_next_behavior_examples,
)
from production.utils.serialization import stable_id, stable_json


INVENTORY_SCHEMA_VERSION = "next_behavior_corpus_inventory.v1"
_HISTORICAL_SPLITS = ("train", "calibration", "test")


class NextBehaviorInventoryError(ValueError):
    """Raised when a safe-corpus inventory cannot be trusted."""


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _load_object(path: Path, *, label: str) -> Dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise NextBehaviorInventoryError(f"{label} must be a JSON object")
    return value


def _require_clean_commit(repository_root: Path, expected_commit: str) -> str:
    commit = str(expected_commit or "").strip().lower()
    if len(commit) != 40 or any(character not in "0123456789abcdef" for character in commit):
        raise NextBehaviorInventoryError(
            "inventory code commit must be a full Git hash"
        )
    try:
        actual = subprocess.run(
            ["git", "-C", str(repository_root), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip().lower()
        status = subprocess.run(
            [
                "git",
                "-C",
                str(repository_root),
                "status",
                "--porcelain",
                "--untracked-files=no",
            ],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise NextBehaviorInventoryError(
            "cannot verify inventory repository state"
        ) from exc
    if actual != commit:
        raise NextBehaviorInventoryError(
            "inventory code commit does not match repository HEAD"
        )
    if status:
        raise NextBehaviorInventoryError(
            "tracked repository state must be clean"
        )
    return commit


def _counter(value: Counter[Any]) -> Dict[str, int]:
    return {str(key): int(count) for key, count in sorted(value.items())}


def _empty_role() -> Dict[str, Any]:
    return {
        "session_count": 0,
        "phase_count": 0,
        "example_count": 0,
        "next_behavior_example_count": 0,
        "terminal_example_count": 0,
        "target_tactic_occurrences": Counter(),
        "target_sessions_by_tactic": Counter(),
        "target_set_counts": Counter(),
        "input_sequence_length_counts": Counter(),
    }


def build_corpus_inventory(
    *,
    safe_payload_path: Path,
    source_receipts: Mapping[str, Any],
    corpus_receipt: Mapping[str, Any],
    build_receipt: Mapping[str, Any],
    preprocessing_sha256: str,
    inventory_code_commit: str,
) -> Dict[str, Any]:
    """Stream and verify a real safe corpus without freezing model roles."""

    corpus = require_valid_corpus_receipt(dict(corpus_receipt))
    members_value = source_receipts.get("members")
    if (
        source_receipts.get("schema_version")
        != "next_behavior_source_member_receipts.v1"
        or not isinstance(members_value, list)
    ):
        raise NextBehaviorInventoryError(
            "source-member receipt artifact is invalid"
        )
    members = [
        require_valid_source_member_receipt(member) for member in members_value
    ]
    if len(members) != corpus["source_member_count"]:
        raise NextBehaviorInventoryError(
            "source-member count does not match corpus receipt"
        )
    member_hashes = sorted(
        hashlib.sha256(stable_json(member).encode("utf-8")).hexdigest()
        for member in members
    )
    if hashlib.sha256(stable_json(member_hashes).encode("utf-8")).hexdigest() != (
        corpus["source_member_receipts_sha256"]
    ):
        raise NextBehaviorInventoryError(
            "source-member receipt hashes do not match corpus receipt"
        )
    ordered_members = sorted(members, key=lambda member: member["member_id"])
    if hashlib.sha256(
        stable_json(ordered_members).encode("utf-8")
    ).hexdigest() != corpus["source_member_receipts_artifact_sha256"]:
        raise NextBehaviorInventoryError(
            "source-member receipt artifact does not match corpus receipt"
        )
    if build_receipt.get("schema_version") != (
        "next_behavior_zenodo_build_receipt.v1"
    ) or build_receipt.get("status") != "safe_corpus_built":
        raise NextBehaviorInventoryError("safe build receipt is invalid")
    if (
        build_receipt.get("corpus_receipt_id") != corpus["receipt_id"]
        or build_receipt.get("code_commit") != corpus["code_commit"]
    ):
        raise NextBehaviorInventoryError(
            "safe build and corpus receipts do not match"
        )
    build_safe = build_receipt.get("safe_payload")
    if not isinstance(build_safe, Mapping):
        raise NextBehaviorInventoryError(
            "safe build receipt has no payload identity"
        )
    if build_safe.get("size_bytes") != safe_payload_path.stat().st_size:
        raise NextBehaviorInventoryError(
            "safe payload file size does not match build receipt"
        )
    file_sha256 = _sha256_file(safe_payload_path)
    if file_sha256 != build_safe.get("sha256"):
        raise NextBehaviorInventoryError(
            "safe payload file SHA-256 does not match build receipt"
        )
    if str(preprocessing_sha256).lower() != corpus["preprocessing_sha256"]:
        raise NextBehaviorInventoryError(
            "preprocessing hash does not match corpus receipt"
        )

    roles_by_member = assign_seven_member_roles(members)
    role_counts = {role: _empty_role() for role in set(roles_by_member.values())}
    member_counts = {
        member["member_id"]: {
            "chronological_order": member["chronological_order"],
            "candidate_role": roles_by_member[member["member_id"]],
            **_empty_role(),
        }
        for member in members
    }
    payload_digest = hashlib.sha256(b"[")
    membership_digest = hashlib.sha256(b"[")
    example_digest = hashlib.sha256()
    model_input_digest = hashlib.sha256()
    first = True
    previous_session_id = ""
    session_count = 0
    example_count = 0
    observed_techniques: set[str] = set()

    with safe_payload_path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            try:
                session = require_valid_next_behavior_session(json.loads(line))
            except Exception as exc:
                raise NextBehaviorInventoryError(
                    f"safe payload line {line_number} is invalid"
                ) from exc
            session_id = str(session["session_id"])
            if previous_session_id and session_id <= previous_session_id:
                raise NextBehaviorInventoryError(
                    "safe payload sessions are not strictly ordered"
                )
            previous_session_id = session_id
            member_id = str(session["source_member_id"])
            if member_id not in member_counts:
                raise NextBehaviorInventoryError(
                    "safe session references an unknown source member"
                )
            serialized_session = stable_json(session).encode("utf-8")
            serialized_id = stable_json(session_id).encode("utf-8")
            if not first:
                payload_digest.update(b",")
                membership_digest.update(b",")
            payload_digest.update(serialized_session)
            membership_digest.update(serialized_id)
            first = False

            phases = build_behavior_phases(session)
            examples = build_next_behavior_examples(session)
            session_tactics: set[str] = set()
            member = member_counts[member_id]
            role = role_counts[member["candidate_role"]]
            session_count += 1
            member["session_count"] += 1
            role["session_count"] += 1
            member["phase_count"] += len(phases)
            role["phase_count"] += len(phases)
            for phase in phases:
                observed_techniques.update(phase["techniques"])
            for example in examples:
                example_id = str(example["example_id"])
                example_digest.update(example_id.encode("utf-8") + b"\n")
                model_input_digest.update(
                    str(example["model_input"]["input_hash"]).encode("utf-8")
                    + b"\n"
                )
                target = example["target"]
                tactics = tuple(target["tactics"])
                target_key = (
                    "SESSION_END"
                    if target["outcome_type"] == "session_end"
                    else "+".join(tactics)
                )
                for target_counts in (member, role):
                    target_counts["example_count"] += 1
                    target_counts["target_set_counts"][target_key] += 1
                    target_counts["input_sequence_length_counts"][
                        len(example["model_input"]["phase_sequence"])
                    ] += 1
                    if target["outcome_type"] == "session_end":
                        target_counts["terminal_example_count"] += 1
                    else:
                        target_counts["next_behavior_example_count"] += 1
                        target_counts["target_tactic_occurrences"].update(
                            tactics
                        )
                session_tactics.update(tactics)
                example_count += 1
            for tactic in session_tactics:
                member["target_sessions_by_tactic"][tactic] += 1
                role["target_sessions_by_tactic"][tactic] += 1

    payload_digest.update(b"]")
    membership_digest.update(b"]")
    if session_count != corpus["safe_session_count"]:
        raise NextBehaviorInventoryError(
            "safe payload session count does not match corpus receipt"
        )
    if session_count != build_safe.get("line_count"):
        raise NextBehaviorInventoryError(
            "safe payload line count does not match build receipt"
        )
    if payload_digest.hexdigest() != corpus["safe_payload_sha256"]:
        raise NextBehaviorInventoryError(
            "safe payload semantic hash does not match corpus receipt"
        )
    if (
        membership_digest.hexdigest()
        != corpus["safe_session_membership_sha256"]
    ):
        raise NextBehaviorInventoryError(
            "safe payload membership hash does not match corpus receipt"
        )

    def finalize(counts: Mapping[str, Any]) -> Dict[str, Any]:
        return {
            key: (
                _counter(value) if isinstance(value, Counter) else value
            )
            for key, value in sorted(counts.items())
        }

    historical = build_receipt.get("historical_membership")
    overlap_by_split = (
        historical.get("overlap_by_historical_split")
        if isinstance(historical, Mapping)
        else None
    )
    if not isinstance(overlap_by_split, Mapping):
        raise NextBehaviorInventoryError(
            "safe build has no historical overlap evidence"
        )
    if set(overlap_by_split) != {*_HISTORICAL_SPLITS, "not_present"}:
        raise NextBehaviorInventoryError(
            "historical overlap splits are incomplete"
        )
    for split, count in overlap_by_split.items():
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise NextBehaviorInventoryError(
                f"historical overlap count for {split} is invalid"
            )
    accepted_count = historical.get("accepted_payload_session_count")
    if (
        isinstance(accepted_count, bool)
        or not isinstance(accepted_count, int)
        or accepted_count < 1
    ):
        raise NextBehaviorInventoryError(
            "accepted historical membership count is invalid"
        )
    if sum(overlap_by_split.values()) != corpus["private_session_count"]:
        raise NextBehaviorInventoryError(
            "historical overlap counts do not reconcile"
        )
    overlap_count = sum(
        overlap_by_split[split] for split in _HISTORICAL_SPLITS
    )
    if overlap_count > accepted_count:
        raise NextBehaviorInventoryError(
            "historical overlap exceeds accepted membership"
        )
    result: Dict[str, Any] = {
        "schema_version": INVENTORY_SCHEMA_VERSION,
        "status": "preprocessing_inventory_complete",
        "target_contract_id": TARGET_CONTRACT_ID,
        "inventory_code_commit": inventory_code_commit,
        "corpus_build_code_commit": corpus["code_commit"],
        "preprocessing_sha256": corpus["preprocessing_sha256"],
        "safe_payload_file_sha256": file_sha256,
        "safe_payload_semantic_sha256": corpus["safe_payload_sha256"],
        "safe_session_membership_sha256": corpus[
            "safe_session_membership_sha256"
        ],
        "source_member_count": len(members),
        "session_count": session_count,
        "example_count": example_count,
        "ordered_example_id_sha256": example_digest.hexdigest(),
        "ordered_model_input_sha256": model_input_digest.hexdigest(),
        "hash_algorithms": {
            "ordered_example_id_sha256": "sha256(example_id + newline in safe-session/phase order)",
            "ordered_model_input_sha256": "sha256(input_hash + newline in safe-session/phase order)",
        },
        "observed_techniques": sorted(observed_techniques),
        "candidate_roles": {
            role: finalize(counts)
            for role, counts in sorted(role_counts.items())
        },
        "source_members": {
            member_id: finalize(counts)
            for member_id, counts in sorted(member_counts.items())
        },
        "historical_membership": {
            "overlap_count": overlap_count,
            "overlap_by_historical_split": {
                str(key): int(value)
                for key, value in sorted(overlap_by_split.items())
            },
            "partition_freeze_status": (
                "blocked_historical_overlap"
                if overlap_count
                else "eligible_for_partition_preflight"
            ),
        },
        "training_vocabulary_frozen": False,
        "model_fitting_authorized": False,
        "final_test_opened": False,
    }
    result["inventory_id"] = stable_id("nextbehaviorinventory", result)
    return result


def _atomic_create(path: Path, value: Mapping[str, Any]) -> None:
    if path.exists():
        raise FileExistsError(f"refusing to overwrite existing inventory: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
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
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--safe-payload", type=Path, required=True)
    parser.add_argument("--source-receipts", type=Path, required=True)
    parser.add_argument("--corpus-receipt", type=Path, required=True)
    parser.add_argument("--build-receipt", type=Path, required=True)
    parser.add_argument("--preprocessing-config", type=Path, required=True)
    parser.add_argument("--repository-root", type=Path, default=Path("."))
    parser.add_argument("--code-commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    commit = _require_clean_commit(args.repository_root, args.code_commit)
    result = build_corpus_inventory(
        safe_payload_path=args.safe_payload,
        source_receipts=_load_object(
            args.source_receipts,
            label="source receipts",
        ),
        corpus_receipt=_load_object(
            args.corpus_receipt,
            label="corpus receipt",
        ),
        build_receipt=_load_object(
            args.build_receipt,
            label="build receipt",
        ),
        preprocessing_sha256=_sha256_file(args.preprocessing_config),
        inventory_code_commit=commit,
    )
    _atomic_create(args.output, result)
    print(
        json.dumps(
            {
                "inventory_id": result["inventory_id"],
                "output": str(args.output),
                "status": result["status"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
