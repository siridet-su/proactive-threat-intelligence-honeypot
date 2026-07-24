#!/usr/bin/env python3
"""Ingest the frozen 13-member corrected-target source selection safely.

This module is additive to ``build_next_behavior_zenodo_corpus``.  The
historical seven-member builder remains byte-for-byte compatible, while this
path binds every private event to its frozen development/final cohort and
train/selection/calibration/test role.

The store contains private session identifiers and command text and therefore
must remain outside version control.  Public outputs are aggregate,
content-hashed inventories containing only HMAC-pseudonymous membership.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import hmac
import json
import os
import re
import sqlite3
import subprocess
import tempfile
import zlib
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, Mapping, Sequence

from production.prediction.next_behavior_contract import TARGET_CONTRACT_ID
from production.prediction.next_behavior_source_selection import (
    require_completed_source_selection,
)
from production.tools.verify_next_behavior_classifier_assets import (
    load_classifier_manifest,
)
from production.utils.serialization import stable_id, stable_json


STORE_SCHEMA_VERSION = "next_behavior_selected_private_store.v1"
INGEST_RECEIPT_SCHEMA_VERSION = "next_behavior_selected_ingest_receipt.v1"
ROLE_INVENTORY_SCHEMA_VERSION = "next_behavior_role_inventory.v1"
CLASSIFICATION_CACHE_RECEIPT_SCHEMA_VERSION = (
    "next_behavior_classification_cache_import.v1"
)
PURPOSE_TO_ROLE = {
    "fit_model": "train",
    "select_model": "selection",
    "fit_calibration": "calibration",
    "final_evaluation": "test",
}
ROLE_TO_COHORT = {
    "train": "development",
    "selection": "development",
    "calibration": "development",
    "test": "final",
}
_DEVELOPMENT_ROLE_BY_ORDER = {
    1: "train",
    2: "train",
    3: "train",
    4: "train",
    5: "selection",
    6: "calibration",
}
_RELEVANT_EVENTS = frozenset(
    {
        "cowrie.session.connect",
        "cowrie.command.input",
        "cowrie.session.closed",
        "cowrie.login.success",
        "cowrie.login.failed",
        "cowrie.session.file_download",
        "cowrie.session.file_upload",
    }
)
_CONTEXT_EVENTS = frozenset(
    {
        "cowrie.login.success",
        "cowrie.login.failed",
        "cowrie.session.file_download",
        "cowrie.session.file_upload",
    }
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_KEY_ID = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_BLOCK_SIZE = 8 * 1024 * 1024
FINAL_PREPARATION_SCHEMA_VERSION = (
    "next_behavior_final_corpus_preparation.v1"
)
FINAL_PREPARATION_FIELDS = frozenset(
    {
        "schema_version",
        "receipt_id",
        "status",
        "purpose",
        "evaluation_opened",
        "code_commit",
        "source_selection_id",
        "source_selection_sha256",
        "final_source_member_count",
        "final_source_member_receipts_sha256",
        "classifier_manifest_sha256",
        "classifier_adapter_sha256",
        "classification_pipeline_sha256",
        "preprocessing_sha256",
        "environment_lock_sha256",
        "label_policy_sha256",
        "trust_policy_sha256",
        "mitre_cache_sha256",
        "classification_checkpoint_sha256",
        "pseudonymization_key_id",
    }
)
FINAL_PREPARATION_GENERATION_SCHEMA_VERSION = (
    "next_behavior_final_corpus_preparation_generation.v1"
)
FINAL_PREPARATION_GENERATION_LEDGER_SCHEMA_VERSION = (
    "next_behavior_final_corpus_preparation_generation_ledger.v1"
)
FINAL_PREPARATION_GENERATION_FIELDS = frozenset(
    {
        "schema_version",
        "generation_id",
        "generation_number",
        "status",
        "purpose",
        "target_safe_build_schema_version",
        "code_commit",
        "predecessor_generation_id",
        "predecessor_build_receipt_id",
        "predecessor_build_receipt_sha256",
        "predecessor_build_schema_version",
        "legacy_preparation_receipt_id",
        "legacy_preparation_receipt_sha256",
        "preparation_receipt_id",
        "preparation_receipt_sha256",
        "source_selection_sha256",
        "final_source_member_receipts_sha256",
        "classifier_manifest_sha256",
        "preprocessing_sha256",
        "label_policy_sha256",
        "trust_policy_sha256",
        "classification_checkpoint_sha256",
        "pseudonymization_key_id",
        "max_sequence_length",
        "membership",
        "store_snapshot_hmac_sha256",
        "authorized_output_paths",
        "authorized_output_paths_sha256",
    }
)
_FINAL_PREPARATION_GENERATION_HEAD_KEY = (
    "final_corpus_preparation_generation_id"
)
_FINAL_PREPARATION_LEDGER_SCHEMA_KEY = (
    "final_corpus_preparation_generation_ledger_schema_version"
)


class SelectedCorpusBuildError(ValueError):
    """Raised when selected-source ingestion or role access is unsafe."""


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(_BLOCK_SIZE), b""):
            digest.update(block)
    return digest.hexdigest()


def _file_identity(path: Path) -> tuple[int, str, str]:
    digest = hashlib.sha256()
    crc32 = 0
    size = 0
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(_BLOCK_SIZE), b""):
            size += len(block)
            crc32 = zlib.crc32(block, crc32)
            digest.update(block)
    return size, f"{crc32 & 0xFFFFFFFF:08x}", digest.hexdigest()


def _require_repository_commit(
    *,
    repository_root: Path,
    expected_commit: str,
) -> str:
    """Bind generated private evidence to the exact clean tracked tree."""

    commit = _clean(expected_commit).lower()
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise SelectedCorpusBuildError("code_commit must be a full Git hash")
    try:
        head = subprocess.run(
            ["git", "-C", str(repository_root), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip().lower()
        tracked_status = subprocess.run(
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
        raise SelectedCorpusBuildError(
            "repository state cannot be verified for final preparation"
        ) from exc
    if head != commit:
        raise SelectedCorpusBuildError(
            "code_commit does not match repository HEAD"
        )
    if tracked_status:
        raise SelectedCorpusBuildError(
            "tracked repository state must be clean before final preparation"
        )
    return commit


def _final_member_receipt_basis(
    members: Sequence[Mapping[str, Any]],
) -> list[Dict[str, Any]]:
    """Return the canonical public identity of the seven frozen final members."""

    final = [
        {
            "filename": _clean(member.get("filename")),
            "source_sha256": _clean(
                member.get("source_sha256") or member.get("sha256")
            ).lower(),
            "source_size_bytes": member.get(
                "source_size_bytes", member.get("size_bytes")
            ),
            "archive_crc32": _clean(member.get("archive_crc32")).lower(),
            "chronological_order": member.get("chronological_order"),
            "source_cohort": _clean(
                member.get("source_cohort") or member.get("role")
            ),
            "experiment_role": _clean(
                member.get("experiment_role") or "test"
            ),
        }
        for member in members
        if _clean(member.get("source_cohort") or member.get("role")) == "final"
        or _clean(member.get("experiment_role")) == "test"
    ]
    final.sort(key=lambda item: int(item["chronological_order"] or 0))
    if (
        len(final) != 7
        or [item["chronological_order"] for item in final]
        != list(range(7, 14))
        or any(
            not item["filename"]
            or not _SHA256.fullmatch(item["source_sha256"])
            or isinstance(item["source_size_bytes"], bool)
            or not isinstance(item["source_size_bytes"], int)
            or item["source_size_bytes"] < 1
            or not re.fullmatch(r"[0-9a-f]{8}", item["archive_crc32"])
            or item["source_cohort"] != "final"
            or item["experiment_role"] != "test"
            for item in final
        )
    ):
        raise SelectedCorpusBuildError(
            "final source member receipts are incomplete or inconsistent"
        )
    return final


def final_member_receipts_sha256(
    members: Sequence[Mapping[str, Any]],
) -> str:
    """Hash exact final member identities without opening their content."""

    return hashlib.sha256(
        stable_json(_final_member_receipt_basis(members)).encode("utf-8")
    ).hexdigest()


def _preparation_receipt_basis(
    *,
    completed_selection_path: Path,
    classifier_manifest_path: Path,
    preprocessing_manifest_path: Path,
    repository_root: Path,
    code_commit: str,
    pseudonymization_key_id: str,
) -> Dict[str, Any]:
    selection, source_selection_sha256 = _load_completed_selection(
        completed_selection_path
    )
    members = normalized_selected_members(selection)
    try:
        classifier = load_classifier_manifest(classifier_manifest_path)
    except ValueError as exc:
        raise SelectedCorpusBuildError(str(exc)) from exc
    key_id = _clean(pseudonymization_key_id)
    if not _KEY_ID.fullmatch(key_id):
        raise SelectedCorpusBuildError("pseudonymization key ID is invalid")
    dependency_lock = classifier["dependency_lock"]
    environment_lock_path = repository_root / dependency_lock["path"]
    policy = classifier["classification_policy"]
    for path, expected, label in (
        (
            environment_lock_path,
            dependency_lock["sha256"],
            "environment lock",
        ),
        (
            repository_root
            / "production/classification/securebert_classifier.py",
            classifier["classifier"]["adapter_sha256"],
            "classifier adapter",
        ),
        (
            repository_root
            / "production/classification/classification_pipeline.py",
            classifier["classifier"]["pipeline_sha256"],
            "classification pipeline",
        ),
        (
            repository_root / policy["rule_policy_path"],
            policy["rule_policy_sha256"],
            "label policy",
        ),
        (
            repository_root / policy["trust_policy_path"],
            policy["trust_policy_sha256"],
            "trust policy",
        ),
        (
            repository_root / policy["mitre_cache_path"],
            policy["mitre_cache_sha256"],
            "MITRE cache",
        ),
    ):
        if not path.is_file() or _sha256_file(path) != expected:
            raise SelectedCorpusBuildError(f"{label} SHA-256 mismatch")
    if not preprocessing_manifest_path.is_file():
        raise SelectedCorpusBuildError("preprocessing manifest is missing")
    return {
        "schema_version": FINAL_PREPARATION_SCHEMA_VERSION,
        "status": "frozen_for_blinded_preparation",
        "purpose": "prepare_final_corpus",
        "evaluation_opened": False,
        "code_commit": code_commit,
        "source_selection_id": selection["selection_id"],
        "source_selection_sha256": source_selection_sha256,
        "final_source_member_count": 7,
        "final_source_member_receipts_sha256": final_member_receipts_sha256(
            members
        ),
        "classifier_manifest_sha256": _sha256_file(
            classifier_manifest_path
        ),
        "classifier_adapter_sha256": classifier["classifier"][
            "adapter_sha256"
        ],
        "classification_pipeline_sha256": classifier["classifier"][
            "pipeline_sha256"
        ],
        "preprocessing_sha256": _sha256_file(preprocessing_manifest_path),
        "environment_lock_sha256": dependency_lock["sha256"],
        "label_policy_sha256": policy["rule_policy_sha256"],
        "trust_policy_sha256": policy["trust_policy_sha256"],
        "mitre_cache_sha256": policy["mitre_cache_sha256"],
        "classification_checkpoint_sha256": classifier["classifier"][
            "checkpoint_sha256"
        ],
        "pseudonymization_key_id": key_id,
    }


def build_final_corpus_preparation_receipt(
    *,
    completed_selection_path: Path,
    classifier_manifest_path: Path,
    preprocessing_manifest_path: Path,
    repository_root: Path,
    code_commit: str,
    pseudonymization_key_id: str,
    output_path: Path | None = None,
) -> Dict[str, Any]:
    """Freeze the blinded data-preparation inputs before final ingestion."""

    commit = _require_repository_commit(
        repository_root=repository_root,
        expected_commit=code_commit,
    )
    receipt = _preparation_receipt_basis(
        completed_selection_path=completed_selection_path,
        classifier_manifest_path=classifier_manifest_path,
        preprocessing_manifest_path=preprocessing_manifest_path,
        repository_root=repository_root,
        code_commit=commit,
        pseudonymization_key_id=pseudonymization_key_id,
    )
    receipt["receipt_id"] = stable_id(
        "nextbehaviorfinalpreparation", receipt
    )
    if output_path is not None:
        _atomic_write_new(
            output_path,
            (stable_json(receipt) + "\n").encode("utf-8"),
        )
    return receipt


def require_final_corpus_preparation_receipt(
    value: Any,
    *,
    completed_selection_path: Path,
    classifier_manifest_path: Path,
    preprocessing_manifest_path: Path,
    repository_root: Path,
    code_commit: str,
    pseudonymization_key_id: str,
) -> Dict[str, Any]:
    """Validate a preparation receipt against authoritative current bytes."""

    if not isinstance(value, Mapping) or set(value) != (
        FINAL_PREPARATION_FIELDS
    ):
        raise SelectedCorpusBuildError(
            "final corpus preparation receipt fields are invalid"
        )
    expected = _preparation_receipt_basis(
        completed_selection_path=completed_selection_path,
        classifier_manifest_path=classifier_manifest_path,
        preprocessing_manifest_path=preprocessing_manifest_path,
        repository_root=repository_root,
        code_commit=code_commit,
        pseudonymization_key_id=pseudonymization_key_id,
    )
    expected["receipt_id"] = stable_id(
        "nextbehaviorfinalpreparation", expected
    )
    if dict(value) != expected:
        raise SelectedCorpusBuildError(
            "final corpus preparation receipt does not match frozen inputs"
        )
    return expected


def _pseudonymization_key_id(path: Path) -> str:
    """Derive the public key identity without exposing the private key."""

    if not path.is_file() or path.is_symlink():
        raise SelectedCorpusBuildError(
            "pseudonymization key is missing or unsafe"
        )
    if path.stat().st_mode & 0o077:
        raise SelectedCorpusBuildError(
            "pseudonymization key permissions are too broad"
        )
    key = path.read_bytes()
    if len(key) != 32:
        raise SelectedCorpusBuildError(
            "pseudonymization key must contain exactly 32 bytes"
        )
    return "next-behavior-hmac-" + hashlib.sha256(key).hexdigest()[:16]


def _load_completed_selection(path: Path) -> tuple[Dict[str, Any], str]:
    try:
        raw = path.read_bytes()
        value = json.loads(raw)
        selection = require_completed_source_selection(value)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        raise SelectedCorpusBuildError(
            f"completed source selection is invalid: {exc}"
        ) from exc
    return selection, hashlib.sha256(raw).hexdigest()


def _experiment_role(member: Mapping[str, Any]) -> str:
    cohort = _clean(member.get("role"))
    order = member.get("chronological_order")
    if cohort == "final" and isinstance(order, int) and 7 <= order <= 13:
        return "test"
    if cohort == "development" and order in _DEVELOPMENT_ROLE_BY_ORDER:
        return _DEVELOPMENT_ROLE_BY_ORDER[int(order)]
    raise SelectedCorpusBuildError("source member has no frozen experiment role")


def normalized_selected_members(
    selection: Mapping[str, Any],
) -> list[Dict[str, Any]]:
    """Bind selection declarations to exact completed archive receipts."""

    try:
        completed = require_completed_source_selection(dict(selection))
    except ValueError as exc:
        raise SelectedCorpusBuildError(str(exc)) from exc
    receipts = {
        receipt["filename"]: receipt
        for receipt in completed["verification"]["member_receipts"]
    }
    output: list[Dict[str, Any]] = []
    for member in completed["members"]:
        receipt = receipts[member["filename"]]
        output.append(
            {
                **dict(member),
                "source_cohort": member["role"],
                "experiment_role": _experiment_role(member),
                "size_bytes": receipt["size_bytes"],
                "archive_compressed_bytes": receipt[
                    "archive_compressed_bytes"
                ],
                "archive_crc32": receipt["archive_crc32"],
                "sha256": receipt["sha256"],
            }
        )
    return output


def _verify_member_files(
    members: Sequence[Mapping[str, Any]],
    raw_directory: Path,
) -> Dict[str, Path]:
    """Verify every requested input before creating or changing the store."""

    verified: Dict[str, Path] = {}
    for member in members:
        filename = _clean(member.get("filename"))
        path = raw_directory / filename
        if not path.is_file() or path.is_symlink():
            raise SelectedCorpusBuildError(
                f"missing or unsafe source member: {filename}"
            )
        try:
            size, crc32, sha256 = _file_identity(path)
        except OSError as exc:
            raise SelectedCorpusBuildError(
                f"cannot read source member: {filename}"
            ) from exc
        if (
            size != member["size_bytes"]
            or crc32 != member["archive_crc32"]
            or sha256 != member["sha256"]
        ):
            raise SelectedCorpusBuildError(
                f"source member identity mismatch: {filename}"
            )
        try:
            with gzip.open(path, "rb") as handle:
                for _block in iter(lambda: handle.read(_BLOCK_SIZE), b""):
                    pass
        except (OSError, EOFError, zlib.error) as exc:
            raise SelectedCorpusBuildError(
                f"source member gzip integrity failed: {filename}"
            ) from exc
        verified[filename] = path
    return verified


def _normalize_timestamp(value: Any) -> str:
    text = _clean(value)
    if not text:
        return ""
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return ""
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def open_selected_database(path: Path) -> sqlite3.Connection:
    """Open a private selected-source store with an exact additive schema."""

    path.parent.mkdir(parents=True, exist_ok=True)
    database = sqlite3.connect(path)
    database.execute("PRAGMA foreign_keys=ON")
    database.execute("PRAGMA journal_mode=WAL")
    database.execute("PRAGMA synchronous=NORMAL")
    database.execute("PRAGMA temp_store=MEMORY")
    database.executescript(
        """
        CREATE TABLE IF NOT EXISTS metadata (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS source_members (
            filename TEXT PRIMARY KEY,
            source_sha256 TEXT NOT NULL,
            source_size_bytes INTEGER NOT NULL,
            archive_crc32 TEXT NOT NULL,
            chronological_order INTEGER NOT NULL UNIQUE,
            source_cohort TEXT NOT NULL,
            experiment_role TEXT NOT NULL,
            collection_start TEXT NOT NULL,
            collection_end TEXT NOT NULL,
            stats_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions (
            raw_session_id TEXT PRIMARY KEY,
            source_member TEXT NOT NULL,
            source_cohort TEXT NOT NULL,
            experiment_role TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            protocol TEXT NOT NULL,
            configuration TEXT NOT NULL,
            connected INTEGER NOT NULL DEFAULT 0,
            closed INTEGER NOT NULL DEFAULT 0,
            cross_member INTEGER NOT NULL DEFAULT 0,
            cross_role INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_selected_sessions_role
            ON sessions(experiment_role, first_seen, raw_session_id);
        CREATE TABLE IF NOT EXISTS session_sources (
            raw_session_id TEXT NOT NULL,
            source_member TEXT NOT NULL,
            source_cohort TEXT NOT NULL,
            experiment_role TEXT NOT NULL,
            chronological_order INTEGER NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            protocol TEXT NOT NULL,
            configuration TEXT NOT NULL,
            connected INTEGER NOT NULL DEFAULT 0,
            closed INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY(raw_session_id, source_member)
        );
        CREATE TABLE IF NOT EXISTS command_events (
            source_member TEXT NOT NULL,
            source_line INTEGER NOT NULL,
            raw_session_id TEXT NOT NULL,
            event_time TEXT NOT NULL,
            command TEXT NOT NULL,
            PRIMARY KEY(source_member, source_line)
        );
        CREATE INDEX IF NOT EXISTS idx_selected_commands_session
            ON command_events(raw_session_id, event_time, source_line);
        CREATE TABLE IF NOT EXISTS context_events (
            source_member TEXT NOT NULL,
            source_line INTEGER NOT NULL,
            raw_session_id TEXT NOT NULL,
            event_time TEXT NOT NULL,
            event_type TEXT NOT NULL,
            PRIMARY KEY(source_member, source_line)
        );
        CREATE INDEX IF NOT EXISTS idx_selected_context_session
            ON context_events(raw_session_id, event_time, source_line);
        CREATE TABLE IF NOT EXISTS quarantined_sessions (
            raw_session_id TEXT PRIMARY KEY,
            reason TEXT NOT NULL,
            source_members_json TEXT NOT NULL,
            experiment_roles_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS command_labels (
            command TEXT PRIMARY KEY,
            labels_json TEXT NOT NULL,
            unrepresented_json TEXT NOT NULL,
            cache_receipt_id TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS classification_cache_receipts (
            cache_receipt_id TEXT PRIMARY KEY,
            receipt_json TEXT NOT NULL
        );
        """
    )
    existing = database.execute(
        "SELECT value FROM metadata WHERE key = 'store_schema_version'"
    ).fetchone()
    if existing is not None and str(existing[0]) != STORE_SCHEMA_VERSION:
        database.close()
        raise SelectedCorpusBuildError(
            "private database belongs to another schema"
        )
    database.execute(
        "INSERT OR IGNORE INTO metadata(key, value) VALUES (?, ?)",
        ("store_schema_version", STORE_SCHEMA_VERSION),
    )
    database.commit()
    return database


def _generation_receipt_sha256(receipt: Mapping[str, Any]) -> str:
    return hashlib.sha256(stable_json(dict(receipt)).encode()).hexdigest()


def require_final_preparation_generation_receipt(
    value: Any,
) -> Dict[str, Any]:
    """Validate the immutable shape and identity of a migration generation."""

    if not isinstance(value, Mapping) or set(value) != (
        FINAL_PREPARATION_GENERATION_FIELDS
    ):
        raise SelectedCorpusBuildError(
            "final preparation generation fields are invalid"
        )
    receipt = dict(value)
    generation_number = receipt.get("generation_number")
    if (
        receipt.get("schema_version")
        != FINAL_PREPARATION_GENERATION_SCHEMA_VERSION
        or receipt.get("status") != "compatible_generation_recorded"
        or receipt.get("purpose") != "authorize_selected_safe_build_v3"
        or receipt.get("target_safe_build_schema_version")
        != "next_behavior_selected_safe_build.v3"
        or isinstance(generation_number, bool)
        or not isinstance(generation_number, int)
        or generation_number < 1
    ):
        raise SelectedCorpusBuildError(
            "final preparation generation is invalid"
        )
    predecessor = receipt.get("predecessor_generation_id")
    if generation_number == 1:
        if predecessor is not None:
            raise SelectedCorpusBuildError(
                "first preparation generation cannot name a predecessor "
                "generation"
            )
    elif not _clean(predecessor):
        raise SelectedCorpusBuildError(
            "preparation generation predecessor is missing"
        )
    for field in (
        "predecessor_build_receipt_sha256",
        "legacy_preparation_receipt_sha256",
        "preparation_receipt_sha256",
        "source_selection_sha256",
        "final_source_member_receipts_sha256",
        "classifier_manifest_sha256",
        "preprocessing_sha256",
        "label_policy_sha256",
        "trust_policy_sha256",
        "classification_checkpoint_sha256",
        "store_snapshot_hmac_sha256",
        "authorized_output_paths_sha256",
    ):
        if not _SHA256.fullmatch(_clean(receipt.get(field)).lower()):
            raise SelectedCorpusBuildError(
                f"final preparation generation {field} is invalid"
            )
    if not re.fullmatch(r"[0-9a-f]{40}", _clean(receipt.get("code_commit"))):
        raise SelectedCorpusBuildError(
            "final preparation generation code commit is invalid"
        )
    if not _KEY_ID.fullmatch(_clean(receipt.get("pseudonymization_key_id"))):
        raise SelectedCorpusBuildError(
            "final preparation generation key ID is invalid"
        )
    if (
        not _clean(receipt.get("predecessor_build_receipt_id"))
        or not _clean(receipt.get("legacy_preparation_receipt_id"))
        or not _clean(receipt.get("preparation_receipt_id"))
        or isinstance(receipt.get("max_sequence_length"), bool)
        or not isinstance(receipt.get("max_sequence_length"), int)
        or receipt["max_sequence_length"] < 1
    ):
        raise SelectedCorpusBuildError(
            "final preparation generation receipt binding is invalid"
        )
    membership = receipt.get("membership")
    if (
        not isinstance(membership, Mapping)
        or set(membership)
        != {
            "source_member_count",
            "source_member_membership_sha256",
            "session_count",
            "session_membership_sha256",
            "example_count",
            "example_membership_sha256",
            "input_count",
            "input_membership_sha256",
        }
        or any(
            isinstance(membership.get(field), bool)
            or not isinstance(membership.get(field), int)
            or membership[field] < 0
            for field in (
                "source_member_count",
                "session_count",
                "example_count",
                "input_count",
            )
        )
        or any(
            not _SHA256.fullmatch(_clean(membership.get(field)).lower())
            for field in (
                "source_member_membership_sha256",
                "session_membership_sha256",
                "example_membership_sha256",
                "input_membership_sha256",
            )
        )
    ):
        raise SelectedCorpusBuildError(
            "final preparation generation membership is invalid"
        )
    paths = receipt.get("authorized_output_paths")
    if (
        not isinstance(paths, Mapping)
        or not paths
        or any(not _clean(path) for path in paths.values())
        or hashlib.sha256(stable_json(dict(paths)).encode()).hexdigest()
        != receipt["authorized_output_paths_sha256"]
    ):
        raise SelectedCorpusBuildError(
            "final preparation generation output authorization is invalid"
        )
    identity = dict(receipt)
    generation_id = identity.pop("generation_id", None)
    if generation_id != stable_id(
        "nextbehaviorfinalpreparationgeneration", identity
    ):
        raise SelectedCorpusBuildError(
            "final preparation generation identity is invalid"
        )
    return receipt


def _preparation_generation_table_exists(database: sqlite3.Connection) -> bool:
    return database.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' "
        "AND name = 'final_preparation_generations'"
    ).fetchone() is not None


def _require_preparation_generation_ledger_state(
    database: sqlite3.Connection,
    *,
    allow_absent: bool,
) -> bool:
    """Validate ledger schema presence without changing an existing store."""

    table_exists = _preparation_generation_table_exists(database)
    schema = database.execute(
        "SELECT value FROM metadata WHERE key = ?",
        (_FINAL_PREPARATION_LEDGER_SCHEMA_KEY,),
    ).fetchone()
    head = database.execute(
        "SELECT value FROM metadata WHERE key = ?",
        (_FINAL_PREPARATION_GENERATION_HEAD_KEY,),
    ).fetchone()
    if not table_exists:
        if schema is not None or head is not None:
            raise SelectedCorpusBuildError(
                "preparation-generation ledger is partially initialized"
            )
        if allow_absent:
            return False
        raise SelectedCorpusBuildError("preparation-generation ledger is missing")
    if (
        schema is None
        or str(schema[0]) != FINAL_PREPARATION_GENERATION_LEDGER_SCHEMA_VERSION
    ):
        raise SelectedCorpusBuildError(
            "private database preparation-generation ledger schema is invalid"
        )
    return True


def _initialize_preparation_generation_ledger(
    database: sqlite3.Connection,
) -> None:
    """Create the additive ledger only inside an explicit migration write."""

    if _preparation_generation_table_exists(database):
        _require_preparation_generation_ledger_state(
            database, allow_absent=False
        )
        return
    _require_preparation_generation_ledger_state(database, allow_absent=True)
    database.execute(
        """
        CREATE TABLE final_preparation_generations (
            generation_id TEXT PRIMARY KEY,
            generation_number INTEGER NOT NULL UNIQUE,
            predecessor_generation_id TEXT,
            predecessor_build_receipt_id TEXT NOT NULL,
            receipt_sha256 TEXT NOT NULL,
            receipt_json TEXT NOT NULL
        )
        """
    )
    database.execute(
        "INSERT INTO metadata(key, value) VALUES (?, ?)",
        (
            _FINAL_PREPARATION_LEDGER_SCHEMA_KEY,
            FINAL_PREPARATION_GENERATION_LEDGER_SCHEMA_VERSION,
        ),
    )


def _legacy_preparation_marker(
    database: sqlite3.Connection,
) -> Dict[str, Any]:
    """Load the original marker without upgrading or rewriting it."""

    metadata = dict(
        database.execute(
            "SELECT key, value FROM metadata WHERE key IN "
            "('final_corpus_prepared_at', "
            "'final_corpus_preparation_receipt_id', "
            "'final_corpus_preparation_receipt_id_pending', "
            "'final_corpus_preparation_receipt_json')"
        )
    )
    if (
        "final_corpus_prepared_at" not in metadata
        or "final_corpus_preparation_receipt_id_pending" in metadata
        or "final_corpus_preparation_receipt_id" not in metadata
        or "final_corpus_preparation_receipt_json" not in metadata
    ):
        raise SelectedCorpusBuildError(
            "completed legacy preparation predecessor is missing"
        )
    try:
        receipt = json.loads(metadata["final_corpus_preparation_receipt_json"])
    except json.JSONDecodeError as exc:
        raise SelectedCorpusBuildError(
            "legacy preparation marker receipt is invalid"
        ) from exc
    if (
        not isinstance(receipt, Mapping)
        or set(receipt) != FINAL_PREPARATION_FIELDS
        or receipt.get("schema_version") != FINAL_PREPARATION_SCHEMA_VERSION
        or receipt.get("receipt_id")
        != metadata["final_corpus_preparation_receipt_id"]
        or stable_json(receipt)
        != metadata["final_corpus_preparation_receipt_json"]
    ):
        raise SelectedCorpusBuildError(
            "legacy preparation marker history is invalid"
        )
    identity = dict(receipt)
    receipt_id = identity.pop("receipt_id", None)
    if receipt_id != stable_id("nextbehaviorfinalpreparation", identity):
        raise SelectedCorpusBuildError(
            "legacy preparation marker identity is invalid"
        )
    return dict(receipt)


def _validated_generation_history(
    database: sqlite3.Connection,
) -> list[Dict[str, Any]]:
    """Validate every append-only row and its predecessor link."""

    if not _require_preparation_generation_ledger_state(
        database, allow_absent=True
    ):
        return []
    generations: list[Dict[str, Any]] = []
    previous_id: str | None = None
    rows = database.execute(
        """
        SELECT generation_id, generation_number, predecessor_generation_id,
               predecessor_build_receipt_id, receipt_sha256, receipt_json
        FROM final_preparation_generations
        ORDER BY generation_number
        """
    )
    for expected_number, row in enumerate(rows, start=1):
        try:
            value = json.loads(str(row[5]))
        except json.JSONDecodeError as exc:
            raise SelectedCorpusBuildError(
                "preparation-generation ledger receipt is invalid"
            ) from exc
        receipt = require_final_preparation_generation_receipt(value)
        if (
            int(row[1]) != expected_number
            or receipt["generation_number"] != expected_number
            or str(row[0]) != receipt["generation_id"]
            or (
                None if row[2] is None else str(row[2])
            )
            != receipt["predecessor_generation_id"]
            or receipt["predecessor_generation_id"] != previous_id
            or str(row[3]) != receipt["predecessor_build_receipt_id"]
            or str(row[4]) != _generation_receipt_sha256(receipt)
            or str(row[5]) != stable_json(receipt)
        ):
            raise SelectedCorpusBuildError(
                "preparation-generation ledger history is inconsistent"
            )
        generations.append(receipt)
        previous_id = receipt["generation_id"]
    return generations


def require_final_preparation_generation_marker(
    database: sqlite3.Connection,
    value: Any,
) -> Dict[str, Any]:
    """Require an exact ledger row, head marker, and preserved legacy marker."""

    receipt = require_final_preparation_generation_receipt(value)
    _require_preparation_generation_ledger_state(database, allow_absent=False)
    legacy = _legacy_preparation_marker(database)
    if (
        legacy["receipt_id"] != receipt["legacy_preparation_receipt_id"]
        or hashlib.sha256(stable_json(legacy).encode()).hexdigest()
        != receipt["legacy_preparation_receipt_sha256"]
    ):
        raise SelectedCorpusBuildError(
            "preparation generation legacy predecessor is inconsistent"
        )
    history = _validated_generation_history(database)
    head = database.execute(
        "SELECT value FROM metadata WHERE key = ?",
        (_FINAL_PREPARATION_GENERATION_HEAD_KEY,),
    ).fetchone()
    if (
        not history
        or head is None
        or str(head[0]) != history[-1]["generation_id"]
        or history[-1] != receipt
    ):
        raise SelectedCorpusBuildError(
            "preparation generation marker or history is inconsistent"
        )
    return receipt


def record_final_preparation_generation(
    *,
    private_database_path: Path,
    generation_receipt: Mapping[str, Any],
) -> Dict[str, Any]:
    """Append one generation atomically, or recover its missing head marker."""

    receipt = require_final_preparation_generation_receipt(
        generation_receipt
    )
    database = open_selected_database(private_database_path)
    try:
        database.execute("BEGIN IMMEDIATE")
        _initialize_preparation_generation_ledger(database)
        legacy = _legacy_preparation_marker(database)
        if (
            legacy["receipt_id"] != receipt["legacy_preparation_receipt_id"]
            or hashlib.sha256(stable_json(legacy).encode()).hexdigest()
            != receipt["legacy_preparation_receipt_sha256"]
        ):
            raise SelectedCorpusBuildError(
                "preparation generation legacy predecessor is inconsistent"
            )
        history = _validated_generation_history(database)
        head = database.execute(
            "SELECT value FROM metadata WHERE key = ?",
            (_FINAL_PREPARATION_GENERATION_HEAD_KEY,),
        ).fetchone()
        existing = next(
            (
                item
                for item in history
                if item["generation_id"] == receipt["generation_id"]
            ),
            None,
        )
        if existing is not None:
            if existing != receipt or history[-1] != receipt:
                raise SelectedCorpusBuildError(
                    "preparation generation cannot rebind ledger history"
                )
            if head is not None and str(head[0]) != receipt["generation_id"]:
                raise SelectedCorpusBuildError(
                    "preparation generation head cannot be rebound"
                )
            status = "generation_already_recorded"
            if head is None:
                database.execute(
                    "INSERT INTO metadata(key, value) VALUES (?, ?)",
                    (
                        _FINAL_PREPARATION_GENERATION_HEAD_KEY,
                        receipt["generation_id"],
                    ),
                )
                status = "generation_head_recovered"
            database.commit()
            return {
                "status": status,
                "generation_id": receipt["generation_id"],
                "generation_number": receipt["generation_number"],
                "receipt_sha256": _generation_receipt_sha256(receipt),
            }
        if head is not None and (
            not history or str(head[0]) != history[-1]["generation_id"]
        ):
            raise SelectedCorpusBuildError(
                "preparation generation head cannot be rebound"
            )
        expected_number = len(history) + 1
        expected_predecessor = (
            history[-1]["generation_id"] if history else None
        )
        if (
            receipt["generation_number"] != expected_number
            or receipt["predecessor_generation_id"] != expected_predecessor
        ):
            raise SelectedCorpusBuildError(
                "preparation generation predecessor linkage is invalid"
            )
        database.execute(
            """
            INSERT INTO final_preparation_generations(
                generation_id, generation_number,
                predecessor_generation_id, predecessor_build_receipt_id,
                receipt_sha256, receipt_json
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                receipt["generation_id"],
                receipt["generation_number"],
                receipt["predecessor_generation_id"],
                receipt["predecessor_build_receipt_id"],
                _generation_receipt_sha256(receipt),
                stable_json(receipt),
            ),
        )
        if head is None:
            database.execute(
                "INSERT INTO metadata(key, value) VALUES (?, ?)",
                (
                    _FINAL_PREPARATION_GENERATION_HEAD_KEY,
                    receipt["generation_id"],
                ),
            )
        else:
            database.execute(
                "UPDATE metadata SET value = ? WHERE key = ?",
                (receipt["generation_id"], _FINAL_PREPARATION_GENERATION_HEAD_KEY),
            )
        database.commit()
        return {
            "status": "generation_recorded",
            "generation_id": receipt["generation_id"],
            "generation_number": receipt["generation_number"],
            "receipt_sha256": _generation_receipt_sha256(receipt),
        }
    except (sqlite3.Error, SelectedCorpusBuildError):
        database.rollback()
        raise
    finally:
        database.close()


def _clear_partial_member(
    database: sqlite3.Connection,
    filename: str,
) -> None:
    database.execute(
        "DELETE FROM command_events WHERE source_member = ?", (filename,)
    )
    database.execute(
        "DELETE FROM context_events WHERE source_member = ?", (filename,)
    )
    database.execute(
        "DELETE FROM session_sources WHERE source_member = ?", (filename,)
    )
    _rebuild_sessions(database)
    database.commit()


_SESSION_SOURCE_UPSERT = """
INSERT INTO session_sources(
    raw_session_id, source_member, source_cohort, experiment_role,
    chronological_order, first_seen, last_seen, protocol, configuration,
    connected, closed
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(raw_session_id, source_member) DO UPDATE SET
    first_seen = MIN(session_sources.first_seen, excluded.first_seen),
    last_seen = MAX(session_sources.last_seen, excluded.last_seen),
    protocol = CASE WHEN excluded.protocol != '' THEN excluded.protocol
                    ELSE session_sources.protocol END,
    configuration = CASE WHEN excluded.configuration != ''
                         THEN excluded.configuration
                         ELSE session_sources.configuration END,
    connected = MAX(session_sources.connected, excluded.connected),
    closed = MAX(session_sources.closed, excluded.closed)
"""


def _rebuild_sessions(database: sqlite3.Connection) -> None:
    """Rebuild aggregate flags from resumable per-member observations."""

    database.execute("DELETE FROM sessions")
    database.execute(
        """
        INSERT INTO sessions(
            raw_session_id, source_member, source_cohort, experiment_role,
            first_seen, last_seen, protocol, configuration, connected, closed,
            cross_member, cross_role
        )
        SELECT
            first.raw_session_id,
            first.source_member,
            first.source_cohort,
            first.experiment_role,
            aggregate.first_seen,
            aggregate.last_seen,
            COALESCE(
                NULLIF(MAX(first.protocol), ''),
                NULLIF(MAX(any_source.protocol), ''),
                ''
            ),
            COALESCE(
                NULLIF(MAX(first.configuration), ''),
                NULLIF(MAX(any_source.configuration), ''),
                ''
            ),
            aggregate.connected,
            aggregate.closed,
            CASE WHEN aggregate.member_count > 1 THEN 1 ELSE 0 END,
            CASE WHEN aggregate.role_count > 1 THEN 1 ELSE 0 END
        FROM (
            SELECT raw_session_id,
                   MIN(first_seen) AS first_seen,
                   MAX(last_seen) AS last_seen,
                   MAX(connected) AS connected,
                   MAX(closed) AS closed,
                   COUNT(DISTINCT source_member) AS member_count,
                   COUNT(DISTINCT experiment_role) AS role_count,
                   MIN(chronological_order) AS first_order
            FROM session_sources
            GROUP BY raw_session_id
        ) AS aggregate
        JOIN session_sources AS first
          ON first.raw_session_id = aggregate.raw_session_id
         AND first.chronological_order = aggregate.first_order
        JOIN session_sources AS any_source
          ON any_source.raw_session_id = aggregate.raw_session_id
        GROUP BY first.raw_session_id
        """
    )


def _ingest_one_member(
    database: sqlite3.Connection,
    member: Mapping[str, Any],
    path: Path,
    *,
    flush_size: int,
) -> Dict[str, Any]:
    filename = member["filename"]
    stored = database.execute(
        """
        SELECT source_sha256, source_size_bytes, archive_crc32,
               chronological_order, source_cohort, experiment_role,
               collection_start, collection_end, stats_json
        FROM source_members WHERE filename = ?
        """,
        (filename,),
    ).fetchone()
    if stored is not None:
        expected = (
            member["sha256"],
            member["size_bytes"],
            member["archive_crc32"],
            member["chronological_order"],
            member["source_cohort"],
            member["experiment_role"],
        )
        if tuple(stored[:6]) != expected:
            raise SelectedCorpusBuildError(
                f"stored source member receipt mismatch: {filename}"
            )
        return {
            "status": "already_ingested",
            "filename": filename,
            "collection_start": str(stored[6]),
            "collection_end": str(stored[7]),
            "stats": json.loads(str(stored[8])),
        }

    _clear_partial_member(database, filename)
    stats: Counter[str] = Counter()
    event_ids: Counter[str] = Counter()
    collection_start = ""
    collection_end = ""
    source_rows: list[tuple[Any, ...]] = []
    command_rows: list[tuple[Any, ...]] = []
    context_rows: list[tuple[Any, ...]] = []

    def flush() -> None:
        if source_rows:
            database.executemany(
                _SESSION_SOURCE_UPSERT,
                source_rows,
            )
            source_rows.clear()
        if command_rows:
            database.executemany(
                """
                INSERT INTO command_events(
                    source_member, source_line, raw_session_id,
                    event_time, command
                ) VALUES (?, ?, ?, ?, ?)
                """,
                command_rows,
            )
            command_rows.clear()
        if context_rows:
            database.executemany(
                """
                INSERT INTO context_events(
                    source_member, source_line, raw_session_id,
                    event_time, event_type
                ) VALUES (?, ?, ?, ?, ?)
                """,
                context_rows,
            )
            context_rows.clear()
        database.commit()

    try:
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as handle:
            for source_line, line in enumerate(handle, start=1):
                stats["raw_event_records"] += 1
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    stats["malformed_records"] += 1
                    continue
                if not isinstance(event, dict):
                    stats["non_object_records"] += 1
                    continue
                event_id = _clean(event.get("eventid"))
                event_ids[event_id or "missing"] += 1
                timestamp = _normalize_timestamp(event.get("ts"))
                if _clean(event.get("ts")) and not timestamp:
                    stats["invalid_timestamps"] += 1
                if timestamp:
                    collection_start = (
                        timestamp
                        if not collection_start
                        else min(collection_start, timestamp)
                    )
                    collection_end = max(collection_end, timestamp)
                if event_id not in _RELEVANT_EVENTS:
                    continue
                session_id = _clean(event.get("session"))
                if not session_id or not timestamp:
                    stats["relevant_events_missing_session_or_time"] += 1
                    continue
                stats["relevant_session_events"] += 1
                source_rows.append(
                    (
                        session_id,
                        filename,
                        member["source_cohort"],
                        member["experiment_role"],
                        member["chronological_order"],
                        timestamp,
                        timestamp,
                        _clean(event.get("protocol")).lower(),
                        _clean(event.get("group")),
                        int(event_id == "cowrie.session.connect"),
                        int(event_id == "cowrie.session.closed"),
                    )
                )
                if event_id == "cowrie.command.input":
                    stats["raw_command_input_events"] += 1
                    command = _clean(event.get("input"))
                    if command:
                        stats["nonempty_command_events"] += 1
                        command_rows.append(
                            (
                                filename,
                                source_line,
                                session_id,
                                timestamp,
                                command,
                            )
                        )
                    else:
                        stats["empty_command_input_events"] += 1
                elif event_id in _CONTEXT_EVENTS:
                    stats["context_events"] += 1
                    context_rows.append(
                        (
                            filename,
                            source_line,
                            session_id,
                            timestamp,
                            event_id,
                        )
                    )
                if len(source_rows) >= flush_size:
                    flush()
        flush()
    except (OSError, EOFError, sqlite3.Error) as exc:
        database.rollback()
        _clear_partial_member(database, filename)
        raise SelectedCorpusBuildError(
            f"source member ingestion failed: {filename}: "
            f"{type(exc).__name__}"
        ) from exc
    if not collection_start or not collection_end:
        _clear_partial_member(database, filename)
        raise SelectedCorpusBuildError(
            f"source member has no usable timestamps: {filename}"
        )
    summary = {
        **dict(sorted(stats.items())),
        "event_id_counts": dict(sorted(event_ids.items())),
        "complete_session_rule": (
            "both cowrie.session.connect and cowrie.session.closed required"
        ),
    }
    database.execute(
        """
        INSERT INTO source_members(
            filename, source_sha256, source_size_bytes, archive_crc32,
            chronological_order, source_cohort, experiment_role,
            collection_start, collection_end, stats_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            filename,
            member["sha256"],
            member["size_bytes"],
            member["archive_crc32"],
            member["chronological_order"],
            member["source_cohort"],
            member["experiment_role"],
            collection_start,
            collection_end,
            stable_json(summary),
        ),
    )
    _rebuild_sessions(database)
    database.commit()
    return {
        "status": "ingested",
        "filename": filename,
        "collection_start": collection_start,
        "collection_end": collection_end,
        "stats": summary,
    }


def _refresh_quarantine(database: sqlite3.Connection) -> None:
    database.execute("DELETE FROM quarantined_sessions")
    rows = database.execute(
        """
        SELECT s.raw_session_id, s.connected, s.closed, s.cross_member,
               s.cross_role,
               GROUP_CONCAT(DISTINCT ss.source_member),
               GROUP_CONCAT(DISTINCT ss.experiment_role)
        FROM sessions AS s
        JOIN session_sources AS ss
          ON ss.raw_session_id = s.raw_session_id
        GROUP BY s.raw_session_id
        """
    )
    quarantined: list[tuple[str, str, str, str]] = []
    for row in rows:
        reasons: list[str] = []
        if int(row[4]):
            reasons.append("cross_role")
        elif int(row[3]):
            reasons.append("cross_member")
        if not int(row[1]) or not int(row[2]):
            reasons.append("incomplete_connection_or_close")
        if not reasons:
            continue
        members = sorted(filter(None, str(row[5] or "").split(",")))
        roles = sorted(filter(None, str(row[6] or "").split(",")))
        quarantined.append(
            (
                str(row[0]),
                "+".join(reasons),
                stable_json(members),
                stable_json(roles),
            )
        )
    database.executemany(
        """
        INSERT INTO quarantined_sessions(
            raw_session_id, reason, source_members_json,
            experiment_roles_json
        ) VALUES (?, ?, ?, ?)
        """,
        quarantined,
    )
    database.commit()


def _database_counts(database: sqlite3.Connection) -> Dict[str, Any]:
    by_reason = {
        str(reason): int(count)
        for reason, count in database.execute(
            """
            SELECT reason, COUNT(*) FROM quarantined_sessions
            GROUP BY reason ORDER BY reason
            """
        )
    }
    role_counts: Dict[str, Dict[str, int]] = {}
    for role in PURPOSE_TO_ROLE.values():
        role_counts[role] = {
            "members": int(
                database.execute(
                    "SELECT COUNT(*) FROM source_members "
                    "WHERE experiment_role = ?",
                    (role,),
                ).fetchone()[0]
            ),
            "sessions": int(
                database.execute(
                    "SELECT COUNT(*) FROM sessions WHERE experiment_role = ?",
                    (role,),
                ).fetchone()[0]
            ),
            "eligible_complete_sessions": int(
                database.execute(
                    """
                    SELECT COUNT(*) FROM sessions AS s
                    WHERE s.experiment_role = ?
                      AND s.protocol = 'ssh'
                      AND s.connected = 1
                      AND s.closed = 1
                      AND NOT EXISTS (
                          SELECT 1 FROM quarantined_sessions AS q
                          WHERE q.raw_session_id = s.raw_session_id
                      )
                    """,
                    (role,),
                ).fetchone()[0]
            ),
        }
    return {
        "processed_members": int(
            database.execute("SELECT COUNT(*) FROM source_members").fetchone()[0]
        ),
        "sessions": int(
            database.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
        ),
        "command_events": int(
            database.execute("SELECT COUNT(*) FROM command_events").fetchone()[0]
        ),
        "context_events": int(
            database.execute("SELECT COUNT(*) FROM context_events").fetchone()[0]
        ),
        "classified_unique_commands": int(
            database.execute("SELECT COUNT(*) FROM command_labels").fetchone()[0]
        ),
        "quarantined_sessions": sum(by_reason.values()),
        "quarantine_by_reason": by_reason,
        "by_role": role_counts,
    }


def _require_canonical_cached_row(
    labels_json: str,
    unrepresented_json: str,
    *,
    rule_policy_sha256: str,
    trust_policy_sha256: str,
    checkpoint_sha256: str,
) -> None:
    try:
        labels = json.loads(labels_json)
        unrepresented = json.loads(unrepresented_json)
    except json.JSONDecodeError as exc:
        raise SelectedCorpusBuildError(
            "cached classification row contains malformed JSON"
        ) from exc
    if stable_json(labels) != labels_json or stable_json(unrepresented) != (
        unrepresented_json
    ):
        raise SelectedCorpusBuildError(
            "cached classification row is not canonically serialized"
        )
    if not isinstance(labels, list) or not isinstance(unrepresented, dict):
        raise SelectedCorpusBuildError(
            "cached classification row has invalid value types"
        )
    for reason, count in unrepresented.items():
        if (
            not _clean(reason)
            or isinstance(count, bool)
            or not isinstance(count, int)
            or count < 0
        ):
            raise SelectedCorpusBuildError(
                "cached unrepresented counts are invalid"
            )
    for label in labels:
        if not isinstance(label, dict):
            raise SelectedCorpusBuildError(
                "cached classification label is not an object"
            )
        if label.get("policy_sha256") != rule_policy_sha256:
            raise SelectedCorpusBuildError(
                "cached label rule-policy provenance is inconsistent"
            )
        if label.get("trust_policy_sha256") != trust_policy_sha256:
            raise SelectedCorpusBuildError(
                "cached label trust-policy provenance is inconsistent"
            )
        source = _clean(label.get("source"))
        if source in {"securebert", "rule_model_agreement"}:
            if label.get("checkpoint_sha256") != checkpoint_sha256:
                raise SelectedCorpusBuildError(
                    "cached label checkpoint provenance is inconsistent"
                )
        elif source == "reviewed_rule":
            if _clean(label.get("checkpoint_sha256")):
                raise SelectedCorpusBuildError(
                    "rule-only cached label has model provenance"
                )
        else:
            raise SelectedCorpusBuildError(
                "cached label source is outside the central policy"
            )
        if label.get("trust_tier") not in {
            "trusted_observation",
            "audit_only_candidate",
            "excluded",
        }:
            raise SelectedCorpusBuildError(
                "cached label trust tier is outside the central policy"
            )


def _require_cache_donor_receipts(
    donor: sqlite3.Connection,
    *,
    selection: Mapping[str, Any],
    classifier_manifest: Mapping[str, Any],
    classifier_manifest_sha256: str,
    repository_root: Path,
) -> Dict[str, Any]:
    try:
        row = donor.execute(
            """
            SELECT receipt_json FROM build_stage_receipts
            WHERE stage_id = 'next_behavior_zenodo_classification.v1'
            """
        ).fetchone()
    except sqlite3.Error as exc:
        raise SelectedCorpusBuildError(
            "classification cache donor schema is invalid"
        ) from exc
    if row is None:
        raise SelectedCorpusBuildError(
            "classification cache donor has no completed receipt"
        )
    try:
        receipt = json.loads(str(row[0]))
    except json.JSONDecodeError as exc:
        raise SelectedCorpusBuildError(
            "classification cache donor receipt is malformed"
        ) from exc
    policy = classifier_manifest["classification_policy"]
    expected = {
        "schema_version": "next_behavior_zenodo_classification.v1",
        "status": "classified",
        "source_manifest_sha256": selection["preserved_source_manifest"][
            "sha256"
        ],
        "classifier_manifest_sha256": classifier_manifest_sha256,
        "checkpoint_sha256": classifier_manifest["classifier"][
            "checkpoint_sha256"
        ],
        "rule_policy_sha256": policy["rule_policy_sha256"],
        "trust_policy_sha256": policy["trust_policy_sha256"],
        "trusted_model_only_threshold": policy[
            "trusted_model_only_threshold"
        ],
        "drop_rule_securebert_disagreements": policy[
            "drop_rule_securebert_disagreements"
        ],
        "label_adapter_sha256": _sha256_file(
            repository_root
            / "production/prediction/next_behavior_label_policy.py"
        ),
        "corpus_builder_sha256": _sha256_file(
            repository_root
            / "production/tools/build_next_behavior_zenodo_corpus.py"
        ),
    }
    for field, value in expected.items():
        if receipt.get(field) != value:
            raise SelectedCorpusBuildError(
                f"classification cache donor {field} receipt mismatch"
            )

    normalized = normalized_selected_members(selection)
    development = {
        member["filename"]: member
        for member in normalized
        if member["source_cohort"] == "development"
    }
    try:
        stored = {
            str(row[0]): {
                "sha256": str(row[1]),
                "size_bytes": int(row[2]),
                "chronological_order": int(row[3]),
            }
            for row in donor.execute(
                """
                SELECT source_member, source_sha256, source_size_bytes,
                       chronological_order
                FROM processed_members
                """
            )
        }
    except sqlite3.Error as exc:
        raise SelectedCorpusBuildError(
            "classification cache donor source receipts are unavailable"
        ) from exc
    for filename, member in development.items():
        if stored.get(filename) != {
            "sha256": member["sha256"],
            "size_bytes": member["size_bytes"],
            "chronological_order": member["chronological_order"],
        }:
            raise SelectedCorpusBuildError(
                f"classification cache donor source receipt mismatch: "
                f"{filename}"
            )
    return receipt


def import_verified_classification_cache(
    *,
    completed_selection_path: Path,
    classifier_manifest_path: Path,
    repository_root: Path,
    donor_database_path: Path,
    private_database_path: Path,
) -> Dict[str, Any]:
    """Reuse only exact commands from a provenance-equivalent private cache.

    Every matching row is validated before the transaction commits.  The
    returned missing count is the only command set a later classifier stage
    may process.
    """

    selection, selection_sha256 = _load_completed_selection(
        completed_selection_path
    )
    try:
        classifier_manifest = load_classifier_manifest(
            classifier_manifest_path
        )
    except ValueError as exc:
        raise SelectedCorpusBuildError(
            f"classifier manifest is invalid: {exc}"
        ) from exc
    classifier_manifest_sha256 = _sha256_file(classifier_manifest_path)
    if not donor_database_path.is_file():
        raise SelectedCorpusBuildError(
            "classification cache donor database is missing"
        )
    if any(
        Path(str(donor_database_path) + suffix).exists()
        for suffix in ("-wal", "-journal")
    ):
        raise SelectedCorpusBuildError(
            "classification cache donor has uncheckpointed side files"
        )
    donor_uri = (
        f"file:{donor_database_path.resolve().as_posix()}"
        "?mode=ro&immutable=1"
    )
    try:
        donor = sqlite3.connect(donor_uri, uri=True)
    except sqlite3.Error as exc:
        raise SelectedCorpusBuildError(
            "cannot open classification cache donor read-only"
        ) from exc
    try:
        donor_receipt = _require_cache_donor_receipts(
            donor,
            selection=selection,
            classifier_manifest=classifier_manifest,
            classifier_manifest_sha256=classifier_manifest_sha256,
            repository_root=repository_root,
        )
    except Exception:
        donor.close()
        raise

    database = open_selected_database(private_database_path)
    try:
        stored_selection = database.execute(
            "SELECT value FROM metadata "
            "WHERE key = 'source_selection_sha256'"
        ).fetchone()
        if (
            stored_selection is None
            or str(stored_selection[0]) != selection_sha256
        ):
            raise SelectedCorpusBuildError(
                "target private database selection receipt is inconsistent"
            )
        exact_command_count = int(
            database.execute(
                "SELECT COUNT(DISTINCT command) FROM command_events"
            ).fetchone()[0]
        )
        receipt_basis = {
            "schema_version": CLASSIFICATION_CACHE_RECEIPT_SCHEMA_VERSION,
            "source_selection_sha256": selection_sha256,
            "classifier_manifest_sha256": classifier_manifest_sha256,
            "donor_classification_receipt_sha256": hashlib.sha256(
                stable_json(donor_receipt).encode()
            ).hexdigest(),
            "donor_source_manifest_sha256": donor_receipt[
                "source_manifest_sha256"
            ],
        }
        cache_receipt_id = stable_id(
            "nextbehaviorclassificationcache",
            receipt_basis,
        )
        existing = database.execute(
            """
            SELECT receipt_json FROM classification_cache_receipts
            WHERE cache_receipt_id = ?
            """,
            (cache_receipt_id,),
        ).fetchone()
        if existing is not None:
            return {
                **json.loads(str(existing[0])),
                "status": "already_imported",
            }

        database.execute("BEGIN IMMEDIATE")
        imported = 0
        policy = classifier_manifest["classification_policy"]
        target_cursor = database.execute(
            "SELECT DISTINCT command FROM command_events ORDER BY command"
        )
        while True:
            batch = [str(row[0]) for row in target_cursor.fetchmany(500)]
            if not batch:
                break
            placeholders = ",".join("?" for _item in batch)
            donor_rows = donor.execute(
                "SELECT command, labels_json, unrepresented_json "
                f"FROM command_labels WHERE command IN ({placeholders}) "
                "ORDER BY command",
                batch,
            )
            for command, labels_json, unrepresented_json in donor_rows:
                _require_canonical_cached_row(
                    str(labels_json),
                    str(unrepresented_json),
                    rule_policy_sha256=policy["rule_policy_sha256"],
                    trust_policy_sha256=policy["trust_policy_sha256"],
                    checkpoint_sha256=classifier_manifest["classifier"][
                        "checkpoint_sha256"
                    ],
                )
                database.execute(
                    """
                    INSERT INTO command_labels(
                        command, labels_json, unrepresented_json,
                        cache_receipt_id
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (
                        str(command),
                        str(labels_json),
                        str(unrepresented_json),
                        cache_receipt_id,
                    ),
                )
                imported += 1
        missing = exact_command_count - imported
        receipt = {
            **receipt_basis,
            "status": "verified_exact_command_cache_imported",
            "cache_receipt_id": cache_receipt_id,
            "target_unique_command_count": exact_command_count,
            "imported_exact_command_count": imported,
            "missing_unique_command_count": missing,
            "row_serialization": "byte-identical-canonical-json",
            "only_missing_commands_require_classification": True,
            "raw_content_emitted": False,
        }
        database.execute(
            """
            INSERT INTO classification_cache_receipts(
                cache_receipt_id, receipt_json
            ) VALUES (?, ?)
            """,
            (cache_receipt_id, stable_json(receipt)),
        )
        database.commit()
        return receipt
    except (sqlite3.Error, SelectedCorpusBuildError):
        database.rollback()
        raise
    finally:
        database.close()
        donor.close()


def iter_missing_classification_commands(
    private_database_path: Path,
) -> Iterator[str]:
    """Yield only unique commands absent from the verified private cache."""

    database = open_selected_database(private_database_path)
    try:
        cursor = database.execute(
            """
            SELECT DISTINCT events.command
            FROM command_events AS events
            LEFT JOIN command_labels AS labels
              ON labels.command = events.command
            WHERE labels.command IS NULL
            ORDER BY events.command
            """
        )
        for row in cursor:
            yield str(row[0])
    finally:
        database.close()


def ingest_selected_members(
    *,
    completed_selection_path: Path,
    raw_directory: Path,
    private_database_path: Path,
    cohort: str,
    prepare_final_corpus: bool = False,
    final_preparation_receipt_path: Path | None = None,
    classifier_manifest_path: Path | None = None,
    preprocessing_manifest_path: Path | None = None,
    pseudonymization_key_id: str | None = None,
    repository_root: Path | None = None,
    code_commit: str | None = None,
    selected_members: Iterable[str] = (),
    flush_size: int = 20_000,
    receipt_output_path: Path | None = None,
) -> Dict[str, Any]:
    """Verify then ingest one frozen cohort without leaking raw content.

    ``final`` ingestion is blinded preparation, not evaluation access. It
    requires an exact preparation receipt frozen before ingestion. Merely
    downloading or verifying final member bytes does not prepare the corpus,
    and this function never opens the final payload for model evaluation.
    """

    if cohort not in {"development", "final"}:
        raise SelectedCorpusBuildError("cohort must be development or final")
    if cohort == "final" and not prepare_final_corpus:
        raise SelectedCorpusBuildError(
            "final cohort remains sealed; --prepare-final-corpus is required"
        )
    final_gate: Dict[str, Any] | None = None
    if cohort == "final":
        if (
            final_preparation_receipt_path is None
            or classifier_manifest_path is None
            or preprocessing_manifest_path is None
            or pseudonymization_key_id is None
            or code_commit is None
        ):
            raise SelectedCorpusBuildError(
                "final cohort requires a frozen blinded-preparation receipt"
            )
        root = (
            repository_root
            if repository_root is not None
            else Path(__file__).resolve().parents[2]
        )
        commit = _require_repository_commit(
            repository_root=root,
            expected_commit=code_commit,
        )
        try:
            preparation_value = json.loads(
                final_preparation_receipt_path.read_text(encoding="utf-8")
            )
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise SelectedCorpusBuildError(
                "final corpus preparation receipt is unreadable"
            ) from exc
        final_gate = require_final_corpus_preparation_receipt(
            preparation_value,
            completed_selection_path=completed_selection_path,
            classifier_manifest_path=classifier_manifest_path,
            preprocessing_manifest_path=preprocessing_manifest_path,
            repository_root=root,
            code_commit=commit,
            pseudonymization_key_id=pseudonymization_key_id,
        )
    if flush_size < 1:
        raise SelectedCorpusBuildError("flush_size must be positive")
    selection, selection_sha256 = _load_completed_selection(
        completed_selection_path
    )
    all_members = normalized_selected_members(selection)
    cohort_members = [
        member for member in all_members
        if member["source_cohort"] == cohort
    ]
    requested_names = [
        _clean(value) for value in selected_members if _clean(value)
    ]
    if len(requested_names) != len(set(requested_names)):
        raise SelectedCorpusBuildError("selected member list is duplicated")
    allowed = {member["filename"] for member in cohort_members}
    if requested_names:
        unknown = sorted(set(requested_names) - allowed)
        if unknown:
            raise SelectedCorpusBuildError(
                "selected members are outside the requested frozen cohort"
            )
        members = [
            member for member in cohort_members
            if member["filename"] in set(requested_names)
        ]
    else:
        members = cohort_members
    paths = _verify_member_files(members, raw_directory)

    database = open_selected_database(private_database_path)
    try:
        if cohort == "final":
            legacy_open = database.execute(
                "SELECT 1 FROM metadata WHERE key = 'final_test_opened_at'"
            ).fetchone()
            if legacy_open is not None:
                raise SelectedCorpusBuildError(
                    "legacy final-test-open state cannot authorize blinded "
                    "preparation"
                )
            existing_gate = database.execute(
                "SELECT value FROM metadata WHERE key IN "
                "('final_corpus_preparation_receipt_id', "
                "'final_corpus_preparation_receipt_id_pending') "
                "ORDER BY key"
            ).fetchall()
            if any(
                str(row[0]) != final_gate["receipt_id"]
                for row in existing_gate
            ):
                raise SelectedCorpusBuildError(
                    "private store is bound to another final preparation"
                )
            existing_receipt = database.execute(
                "SELECT value FROM metadata "
                "WHERE key = 'final_corpus_preparation_receipt_json'"
            ).fetchone()
            if (
                existing_receipt is not None
                and str(existing_receipt[0]) != stable_json(final_gate)
            ):
                raise SelectedCorpusBuildError(
                    "private store final preparation provenance changed"
                )
        stored_hash = database.execute(
            "SELECT value FROM metadata "
            "WHERE key = 'source_selection_sha256'"
        ).fetchone()
        if stored_hash is not None and str(stored_hash[0]) != selection_sha256:
            raise SelectedCorpusBuildError(
                "private database source-selection hash mismatch"
            )
        database.execute(
            "INSERT OR IGNORE INTO metadata(key, value) VALUES (?, ?)",
            ("source_selection_sha256", selection_sha256),
        )
        if cohort == "final":
            database.execute(
                "INSERT OR IGNORE INTO metadata(key, value) VALUES (?, ?)",
                (
                    "final_corpus_preparation_receipt_id_pending",
                    final_gate["receipt_id"],
                ),
            )
        database.commit()
        receipts = [
            _ingest_one_member(
                database,
                member,
                paths[member["filename"]],
                flush_size=flush_size,
            )
            for member in members
        ]
        _refresh_quarantine(database)
        if cohort == "final":
            database.execute(
                "INSERT OR IGNORE INTO metadata(key, value) VALUES (?, ?)",
                (
                    "final_corpus_prepared_at",
                    datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                ),
            )
            database.execute(
                "INSERT OR IGNORE INTO metadata(key, value) VALUES (?, ?)",
                (
                    "final_corpus_preparation_receipt_id",
                    final_gate["receipt_id"],
                ),
            )
            database.execute(
                "INSERT OR IGNORE INTO metadata(key, value) VALUES (?, ?)",
                (
                    "final_corpus_preparation_receipt_json",
                    stable_json(final_gate),
                ),
            )
            database.execute(
                "DELETE FROM metadata "
                "WHERE key = 'final_corpus_preparation_receipt_id_pending'"
            )
            database.commit()
        counts = _database_counts(database)
    finally:
        database.close()
    receipt = {
        "schema_version": INGEST_RECEIPT_SCHEMA_VERSION,
        "status": "cohort_ingested",
        "source_selection_sha256": selection_sha256,
        "cohort": cohort,
        "final_corpus_prepared": cohort == "final",
        "evaluation_opened": False,
        "final_preparation_gate": final_gate,
        "requested_member_count": len(members),
        "member_receipts": receipts,
        "counts": counts,
        "raw_content_emitted": False,
    }
    if receipt_output_path is not None:
        _atomic_write_new(
            receipt_output_path,
            (stable_json(receipt) + "\n").encode(),
        )
    return receipt


def _require_hmac_key(key: bytes, key_id: str) -> tuple[bytes, str]:
    if not isinstance(key, bytes) or len(key) < 32:
        raise SelectedCorpusBuildError(
            "pseudonymization key must contain at least 32 bytes"
        )
    clean_id = _clean(key_id)
    if not _KEY_ID.fullmatch(clean_id):
        raise SelectedCorpusBuildError("pseudonymization key ID is invalid")
    return key, clean_id


def _pseudonymous_session_id(raw_session_id: str, key: bytes) -> str:
    digest = hmac.new(
        key,
        f"next-behavior:session:{raw_session_id}".encode(),
        hashlib.sha256,
    ).hexdigest()
    return f"nbsession_{digest}"


def _atomic_write_new(path: Path, payload: bytes) -> None:
    if path.exists():
        raise SelectedCorpusBuildError(
            f"refusing to overwrite role inventory: {path}"
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError as exc:
            raise SelectedCorpusBuildError(
                f"refusing to overwrite role inventory: {path}"
            ) from exc
    finally:
        temporary.unlink(missing_ok=True)


def build_role_inventory(
    *,
    private_database_path: Path,
    purpose: str,
    pseudonymization_key: bytes,
    pseudonymization_key_id: str,
    output_path: Path | None = None,
) -> Dict[str, Any]:
    """Freeze one role's eligible, complete private-session membership.

    This is a privacy-safe pre-classification inventory.  The later safe-corpus
    builder must reuse the same HMAC key and membership; this receipt does not
    replace label classification or the strict safe-session corpus contract.
    """

    role = PURPOSE_TO_ROLE.get(purpose)
    if role is None:
        raise SelectedCorpusBuildError("purpose is not recognized")
    key, key_id = _require_hmac_key(
        pseudonymization_key,
        pseudonymization_key_id,
    )
    database = open_selected_database(private_database_path)
    try:
        selection_row = database.execute(
            "SELECT value FROM metadata "
            "WHERE key = 'source_selection_sha256'"
        ).fetchone()
        if selection_row is None or not _SHA256.fullmatch(str(selection_row[0])):
            raise SelectedCorpusBuildError(
                "private database is not bound to a completed selection"
            )
        if role == "test" and database.execute(
            "SELECT 1 FROM metadata WHERE key = 'final_corpus_prepared_at'"
        ).fetchone() is None:
            raise SelectedCorpusBuildError(
                "final corpus has not completed blinded preparation"
            )
        expected_member_count = 4 if role == "train" else (7 if role == "test" else 1)
        member_rows = list(
            database.execute(
                """
                SELECT filename, source_sha256, chronological_order,
                       source_cohort
                FROM source_members WHERE experiment_role = ?
                ORDER BY chronological_order
                """,
                (role,),
            )
        )
        if len(member_rows) != expected_member_count:
            raise SelectedCorpusBuildError(
                f"all frozen {role} members must be ingested before inventory"
            )
        raw_session_ids = [
            str(row[0])
            for row in database.execute(
                """
                SELECT s.raw_session_id
                FROM sessions AS s
                WHERE s.experiment_role = ?
                  AND s.source_cohort = ?
                  AND s.protocol = 'ssh'
                  AND s.connected = 1
                  AND s.closed = 1
                  AND NOT EXISTS (
                      SELECT 1 FROM quarantined_sessions AS q
                      WHERE q.raw_session_id = s.raw_session_id
                  )
                ORDER BY s.raw_session_id
                """,
                (role, ROLE_TO_COHORT[role]),
            )
        ]
        session_ids = sorted(
            _pseudonymous_session_id(value, key) for value in raw_session_ids
        )
        quarantine_count = int(
            database.execute(
                """
                SELECT COUNT(DISTINCT q.raw_session_id)
                FROM quarantined_sessions AS q
                JOIN session_sources AS ss
                  ON ss.raw_session_id = q.raw_session_id
                WHERE ss.experiment_role = ?
                """,
                (role,),
            ).fetchone()[0]
        )
        member_receipts = [
            {
                "source_sha256": str(row[1]),
                "chronological_order": int(row[2]),
                "source_cohort": str(row[3]),
            }
            for row in member_rows
        ]
        inventory: Dict[str, Any] = {
            "schema_version": ROLE_INVENTORY_SCHEMA_VERSION,
            "status": "role_membership_frozen",
            "target_contract_id": TARGET_CONTRACT_ID,
            "purpose": purpose,
            "role": role,
            "source_cohort": ROLE_TO_COHORT[role],
            "source_selection_sha256": str(selection_row[0]),
            "pseudonymization_scheme": "hmac-sha256-v1",
            "pseudonymization_key_id": key_id,
            "source_member_count": len(member_rows),
            "source_members_sha256": hashlib.sha256(
                stable_json(member_receipts).encode()
            ).hexdigest(),
            "eligible_complete_session_count": len(session_ids),
            "session_membership_sha256": hashlib.sha256(
                stable_json(session_ids).encode()
            ).hexdigest(),
            "quarantined_session_count": quarantine_count,
            "partial_sessions_can_emit_terminal_target": False,
            "raw_content_emitted": False,
        }
        inventory["inventory_id"] = stable_id(
            "nextbehaviorroleinventory",
            inventory,
        )
    finally:
        database.close()
    if output_path is not None:
        _atomic_write_new(
            output_path,
            (stable_json(inventory) + "\n").encode(),
        )
    return inventory


def iter_role_private_sessions(
    *,
    private_database_path: Path,
    purpose: str,
) -> Iterator[Dict[str, Any]]:
    """Yield complete private sessions to the declared downstream stage.

    The iterator deliberately yields no labels.  Classification must use the
    frozen classifier/label adapter before calling the existing
    ``build_privacy_safe_session`` contract. Final sessions are inaccessible
    until the blinded-preparation marker exists; this iterator does not grant
    model-evaluation access.
    """

    role = PURPOSE_TO_ROLE.get(purpose)
    if role is None:
        raise SelectedCorpusBuildError("purpose is not recognized")
    database = open_selected_database(private_database_path)
    try:
        if role == "test" and database.execute(
            "SELECT 1 FROM metadata WHERE key = 'final_corpus_prepared_at'"
        ).fetchone() is None:
            raise SelectedCorpusBuildError(
                "final corpus has not completed blinded preparation"
            )
        rows = database.execute(
            """
            SELECT s.raw_session_id, s.source_member, s.first_seen,
                   s.last_seen, s.protocol, s.configuration
            FROM sessions AS s
            WHERE s.experiment_role = ?
              AND s.source_cohort = ?
              AND s.connected = 1
              AND s.closed = 1
              AND NOT EXISTS (
                  SELECT 1 FROM quarantined_sessions AS q
                  WHERE q.raw_session_id = s.raw_session_id
              )
            ORDER BY s.first_seen, s.raw_session_id
            """,
            (role, ROLE_TO_COHORT[role]),
        )
        for row in rows:
            commands = [
                {
                    "source_line": int(item[0]),
                    "observed_at": str(item[1]),
                    "command": str(item[2]),
                }
                for item in database.execute(
                    """
                    SELECT source_line, event_time, command
                    FROM command_events WHERE raw_session_id = ?
                    ORDER BY event_time, source_line
                    """,
                    (str(row[0]),),
                )
            ]
            yield {
                "session_id": str(row[0]),
                "source_member": str(row[1]),
                "experiment_role": role,
                "first_seen": str(row[2]),
                "last_seen": str(row[3]),
                "protocol": str(row[4]),
                "configuration": str(row[5]),
                "connected": True,
                "closed": True,
                "commands": commands,
            }
    finally:
        database.close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    prepare = subparsers.add_parser("freeze-final-preparation")
    prepare.add_argument("--completed-selection", type=Path, required=True)
    prepare.add_argument("--classifier-manifest", type=Path, required=True)
    prepare.add_argument("--preprocessing-manifest", type=Path, required=True)
    prepare.add_argument("--pseudonymization-key", type=Path, required=True)
    prepare.add_argument("--repository-root", type=Path, required=True)
    prepare.add_argument("--code-commit", required=True)
    prepare.add_argument("--receipt-output", type=Path, required=True)
    ingest = subparsers.add_parser("ingest")
    ingest.add_argument("--completed-selection", type=Path, required=True)
    ingest.add_argument("--raw-directory", type=Path, required=True)
    ingest.add_argument("--private-database", type=Path, required=True)
    ingest.add_argument(
        "--cohort", choices=("development", "final"), required=True
    )
    ingest.add_argument("--prepare-final-corpus", action="store_true")
    ingest.add_argument("--final-preparation-receipt", type=Path)
    ingest.add_argument("--classifier-manifest", type=Path)
    ingest.add_argument("--preprocessing-manifest", type=Path)
    ingest.add_argument("--pseudonymization-key", type=Path)
    ingest.add_argument("--repository-root", type=Path)
    ingest.add_argument("--code-commit")
    ingest.add_argument("--member", action="append", default=[])
    ingest.add_argument("--flush-size", type=int, default=20_000)
    ingest.add_argument("--receipt-output", type=Path, required=True)
    cache = subparsers.add_parser("import-classification-cache")
    cache.add_argument("--completed-selection", type=Path, required=True)
    cache.add_argument("--classifier-manifest", type=Path, required=True)
    cache.add_argument("--repository-root", type=Path, required=True)
    cache.add_argument("--donor-database", type=Path, required=True)
    cache.add_argument("--private-database", type=Path, required=True)
    cache.add_argument("--receipt-output", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "freeze-final-preparation":
        receipt = build_final_corpus_preparation_receipt(
            completed_selection_path=args.completed_selection,
            classifier_manifest_path=args.classifier_manifest,
            preprocessing_manifest_path=args.preprocessing_manifest,
            repository_root=args.repository_root,
            code_commit=args.code_commit,
            pseudonymization_key_id=_pseudonymization_key_id(
                args.pseudonymization_key
            ),
            output_path=args.receipt_output,
        )
        print(stable_json(receipt))
        return 0
    if args.command == "ingest":
        key_id = (
            _pseudonymization_key_id(args.pseudonymization_key)
            if args.pseudonymization_key is not None
            else None
        )
        receipt = ingest_selected_members(
            completed_selection_path=args.completed_selection,
            raw_directory=args.raw_directory,
            private_database_path=args.private_database,
            cohort=args.cohort,
            prepare_final_corpus=args.prepare_final_corpus,
            final_preparation_receipt_path=args.final_preparation_receipt,
            classifier_manifest_path=args.classifier_manifest,
            preprocessing_manifest_path=args.preprocessing_manifest,
            pseudonymization_key_id=key_id,
            repository_root=args.repository_root,
            code_commit=args.code_commit,
            selected_members=args.member,
            flush_size=args.flush_size,
            receipt_output_path=args.receipt_output,
        )
        print(stable_json(receipt))
        return 0
    if args.command == "import-classification-cache":
        receipt = import_verified_classification_cache(
            completed_selection_path=args.completed_selection,
            classifier_manifest_path=args.classifier_manifest,
            repository_root=args.repository_root,
            donor_database_path=args.donor_database,
            private_database_path=args.private_database,
        )
        _atomic_write_new(
            args.receipt_output,
            (stable_json(receipt) + "\n").encode(),
        )
        print(stable_json(receipt))
        return 0
    raise SelectedCorpusBuildError("unsupported command")


if __name__ == "__main__":
    raise SystemExit(main())
