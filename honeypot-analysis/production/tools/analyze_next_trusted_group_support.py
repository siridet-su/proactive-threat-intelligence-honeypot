#!/usr/bin/env python3
"""Run the frozen successor target support analysis on development roles only."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import resource
import subprocess
import time
from pathlib import Path

from production.prediction.next_trusted_group_target import (
    DEVELOPMENT_ROLES,
    load_next_trusted_group_target_policy,
    target_policy_file_sha256,
)
from production.reproduction.next_behavior.group_target_support import (
    attach_operational_observations,
    build_group_target_support_receipt,
    validate_group_target_support_receipt,
)
from production.reproduction.next_behavior.source_selection_v2 import (
    require_valid_successor_member_inventory,
)
from production.reproduction.next_behavior.support_preflight import (
    iter_development_safe_sessions,
    require_complete_support_store_classification,
    require_valid_historical_test_session_membership,
    require_valid_support_preflight_receipt,
)
from production.utils.serialization import stable_json


DESIGN_COMMIT = "a7b07f36563e78c7ed87bbe415480fe023dbd049"
DESIGN_TREE = "ff63c4e92eee89a06f74210154e65889335e670d"


class SupportAnalysisCliError(ValueError):
    pass


def _json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SupportAnalysisCliError(f"cannot read {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise SupportAnalysisCliError(f"{path} must contain an object")
    return value


def _sha256_json(value) -> str:
    return hashlib.sha256(stable_json(value).encode("utf-8")).hexdigest()


def _git(repository: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _verify_design_freeze(repository: Path, policy_path: Path) -> tuple[str, str]:
    if _git(repository, "status", "--porcelain", "--untracked-files=no"):
        raise SupportAnalysisCliError("tracked worktree must be clean")
    if _git(repository, "merge-base", "--is-ancestor", DESIGN_COMMIT, "HEAD"):
        raise SupportAnalysisCliError("design commit ancestry check returned output")
    if _git(repository, "rev-parse", f"{DESIGN_COMMIT}^{{tree}}") != DESIGN_TREE:
        raise SupportAnalysisCliError("frozen design tree is inconsistent")
    relative = policy_path.resolve().relative_to(repository.resolve())
    frozen_bytes = subprocess.run(
        ["git", "-C", str(repository), "show", f"{DESIGN_COMMIT}:{relative}"],
        check=True,
        capture_output=True,
    ).stdout
    if frozen_bytes != policy_path.read_bytes():
        raise SupportAnalysisCliError("target policy bytes changed after design freeze")
    load_next_trusted_group_target_policy(policy_path)
    return DESIGN_COMMIT, DESIGN_TREE


def _atomic_write(path: Path, value: dict) -> None:
    if path.exists() or path.is_symlink():
        raise SupportAnalysisCliError("support receipt output already exists")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    if temporary.exists() or temporary.is_symlink():
        raise SupportAnalysisCliError("support receipt temporary path already exists")
    encoded = (stable_json(value) + "\n").encode("utf-8")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except Exception:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise


def _checked_role_stream(selected_role: str, source):
    """Bind one role eagerly and reject rather than filter cross-role output."""

    if selected_role not in DEVELOPMENT_ROLES:
        raise SupportAnalysisCliError("support stream role is invalid")
    for returned_role, session in source:
        if returned_role != selected_role:
            raise SupportAnalysisCliError("safe-session iterator returned a wrong role")
        yield session


def run(args: argparse.Namespace) -> dict:
    repository = args.repository.resolve()
    design_commit, design_tree = _verify_design_freeze(repository, args.policy)
    policy_sha256 = target_policy_file_sha256(args.policy)

    prior = require_valid_support_preflight_receipt(_json(args.prior_support_receipt))
    inventory = require_valid_successor_member_inventory(_json(args.inventory))
    inventory_sha256 = _sha256_json(inventory)
    if (
        prior["successor_inventory_id"] != inventory["inventory_id"]
        or prior["successor_inventory_sha256"] != inventory_sha256
        or prior["source_selection_sha256"] != inventory["source_selection_sha256"]
    ):
        raise SupportAnalysisCliError("prior support and frozen inventory differ")

    key_path = args.pseudonymization_key
    if key_path.is_symlink() or not key_path.is_file():
        raise SupportAnalysisCliError("pseudonymization key path is missing or unsafe")
    key = key_path.read_bytes()
    key_fingerprint = hashlib.sha256(key).hexdigest()
    expected_key_id = "next-behavior-hmac-" + key_fingerprint[:16]
    if args.pseudonymization_key_id != expected_key_id:
        raise SupportAnalysisCliError("pseudonymization key identity is inconsistent")

    historical = require_valid_historical_test_session_membership(
        _json(args.historical_membership_receipt)
    )
    historical_sha256 = _sha256_json(historical)
    if (
        historical["source_selection_sha256"] != inventory["source_selection_sha256"]
        or historical["pseudonymization_key_id"] != expected_key_id
        or historical["pseudonymization_key_fingerprint_sha256"] != key_fingerprint
        or historical["test_metrics_included"] is not False
        or historical["raw_content_emitted"] is not False
    ):
        raise SupportAnalysisCliError(
            "historical sealed-test membership lineage is inconsistent"
        )

    require_complete_support_store_classification(
        private_database_path=args.database,
        expected_receipt_sha256=prior["classification_receipt_sha256"],
        source_selection_sha256=inventory["source_selection_sha256"],
        frozen_semantics=prior["frozen_semantics"],
        successor_inventory=inventory,
        inventory_validator=require_valid_successor_member_inventory,
    )

    started_wall = time.monotonic()
    started_cpu = time.process_time()
    streams = {
        role: _checked_role_stream(
            role,
            iter_development_safe_sessions(
                private_database_path=args.database,
                pseudonymization_key=key,
                pseudonymization_key_id=expected_key_id,
                role=role,
            ),
        )
        for role in DEVELOPMENT_ROLES
    }
    receipt = build_group_target_support_receipt(
        safe_sessions_by_role=streams,
        target_policy_sha256=policy_sha256,
        design_commit=design_commit,
        design_tree=design_tree,
        source_selection_sha256=inventory["source_selection_sha256"],
        successor_inventory_id=inventory["inventory_id"],
        successor_inventory_sha256=inventory_sha256,
        classification_receipt_sha256=prior["classification_receipt_sha256"],
        pseudonymization_key_id=expected_key_id,
        pseudonymization_key_fingerprint_sha256=key_fingerprint,
        historical_test_membership_receipt_sha256=historical_sha256,
    )
    observations = {
        "elapsed_seconds": f"{time.monotonic() - started_wall:.6f}",
        "cpu_seconds": f"{time.process_time() - started_cpu:.6f}",
        "peak_rss_kib": int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss),
        "python_version": f"{os.sys.version_info.major}.{os.sys.version_info.minor}.{os.sys.version_info.micro}",
        "database_size_bytes": args.database.stat().st_size,
    }
    receipt = attach_operational_observations(receipt, observations)
    errors = validate_group_target_support_receipt(receipt)
    if errors:
        raise SupportAnalysisCliError("; ".join(errors))
    _atomic_write(args.output, receipt)
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--prior-support-receipt", type=Path, required=True)
    parser.add_argument("--historical-membership-receipt", type=Path, required=True)
    parser.add_argument("--pseudonymization-key", type=Path, required=True)
    parser.add_argument("--pseudonymization-key-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    receipt = run(args)
    print(stable_json({
        "status": receipt["status"],
        "receipt_id": receipt["receipt_id"],
        "semantic_support_sha256": receipt["semantic_support_sha256"],
        "output": str(args.output),
        "sealed_test_behavioral_content_accessed": False,
        "training_performed": False,
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
