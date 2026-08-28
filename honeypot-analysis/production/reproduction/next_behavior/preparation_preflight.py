"""Fail-closed static preflight for a next-behavior corpus preparation.

This module deliberately stops before opening a corpus database or reading a
source archive.  It binds the code, policies, frozen input-receipt bytes, and
host capacity that a later preparation command is allowed to use.  Passing
this preflight is evidence of *readiness only*; it is not evidence that ingest,
classification, training, or evaluation ran.

The request is a small local protocol rather than an import of the successor
corpus implementation.  That keeps this boundary usable while successor
contracts are reviewed independently, without accepting unpinned inputs.
"""

from __future__ import annotations

import ast
import hashlib
import importlib.metadata
import json
import os
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import urllib.error
import urllib.request
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, Mapping, Sequence

from production.reproduction.next_behavior.classifier_assets import (
    ClassifierAssetError,
    load_classifier_manifest,
    verify_classifier_assets,
    verify_classifier_source_identity,
)
from production.reproduction.next_behavior.experiment_policy import (
    NextBehaviorExperimentPolicyError,
    require_valid_experiment_policy,
)
from production.reproduction.next_behavior.support_preflight import (
    SUPPORT_PREFLIGHT_ROOT,
    SupportPreflightError,
    _verify_historical_test_membership_artifact,
    require_valid_historical_test_session_membership,
)
from production.utils.serialization import stable_id, stable_json


REQUEST_SCHEMA_VERSION = "next_behavior_preparation_static_preflight_request.v1"
RECEIPT_SCHEMA_VERSION = "next_behavior_preparation_static_preflight.v1"
SOURCE_SELECTION_SCHEMA_VERSION = "next_behavior_source_selection.v2"
MEMBER_INVENTORY_SCHEMA_VERSION = "next_behavior_successor_member_inventory.v1"
MODEL_ROOT_BINDING_SCHEMA_VERSION = "next_behavior_classifier_model_root_binding.v1"
PREPROCESSING_SCHEMA_VERSION = "next_behavior_preprocessing.v2"
PREPROCESSING_PATH = "configs/next_behavior_preprocessing.v2.json"
EXPERIMENT_POLICY_SCHEMA_VERSION = "next_behavior_experiment_policy.v2"
TARGET_CONTRACT_ID = "next_distinct_trusted_behavior_phase_or_session_end.v2"
TRUSTED_HISTORY_SCHEMA_VERSION = "prediction_trusted_history_manifest.v3"
MAXIMUM_PHASES = 8
SUCCESSOR_ROLE_COUNTS = {"train": 10, "selection": 7, "calibration": 7, "test": 7}
REVIEWED_OUTPUT_ROOT = Path("/mnt/honeypot-data/next-behavior-successor")
SAME_FILESYSTEM_MINIMUM_FREE_BYTES = 60 * 1024**3
MINIMUM_MEM_AVAILABLE_BYTES = 10 * 1024**3
MINIMUM_SWAP_FREE_BYTES = 6 * 1024**3

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_CRC32 = re.compile(r"^[0-9a-f]{8}$")
_GIT_OBJECT = re.compile(r"^[0-9a-f]{40}$")
_MODULE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$")

_REQUEST_FIELDS = frozenset(
    {
        "schema_version",
        "repository",
        "provenance",
        "classifier_environment",
        "classifier_model",
        "preprocessing",
        "frozen_inputs",
        "experiment_policy",
        "runtime",
        "capacity",
        "output_workspace",
    }
)
_RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "status",
        "scope",
        "request_sha256",
        "repository",
        "provenance",
        "classifier_environment",
        "classifier_model",
        "preprocessing",
        "frozen_inputs",
        "experiment_policy",
        "runtime",
        "output_workspace",
        "capacity",
        "receipt_sha256",
    }
)
_REPOSITORY_FIELDS = frozenset({"commit", "tree"})
_PROVENANCE_FIELDS = frozenset({"required_files", "import_bindings"})
_FILE_FIELDS = frozenset({"path", "sha256"})
_IMPORT_FIELDS = frozenset({"module", "source_path", "importer_path"})
_PIN_FIELDS = frozenset({"path", "artifact_byte_sha256", "schema_version"})
_EXTERNAL_PIN_FIELDS = _PIN_FIELDS | frozenset({"contract_sha256"})
_CLASSIFIER_MODEL_FIELDS = frozenset({"model_root", "binding_receipt"})
_PRE_STAGING_CLASSIFIER_MODEL_FIELDS = frozenset({"stage", "status"})
_MODEL_ROOT_RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "status",
        "model_root",
        "classifier_environment_artifact_byte_sha256",
        "checkpoint_id",
        "checkpoint_sha256",
        "files",
    }
)
_PREPROCESSING_FIELDS = _PIN_FIELDS | frozenset(
    {"target_contract_id", "trusted_history_schema_version", "maximum_phases"}
)
_FROZEN_INPUT_FIELDS = frozenset({"source_selection", "member_inventory"})
_PRE_STAGING_FROZEN_INPUT_FIELDS = frozenset(
    {
        "stage",
        "source_selection",
        "source_archive_availability",
        "historical_test_membership",
    }
)
_PRE_STAGING_ARCHIVE_FIELDS = frozenset(
    {"schema_version", "url", "expected_size_bytes", "expected_md5"}
)
_PRE_STAGING_MEMBERSHIP_FIELDS = frozenset(
    {
        "receipt_path",
        "receipt_byte_sha256",
        "artifact_path",
        "artifact_byte_sha256",
        "role_inventory_session_count",
        "role_inventory_session_membership_sha256",
    }
)
PRE_STAGING_STAGE = "pre_staging"
POST_STAGING_STAGE = "post_staging"
HISTORICAL_TEST_SESSION_COUNT = 5_334_841
HISTORICAL_TEST_SESSION_MEMBERSHIP_SHA256 = (
    "628b5105b3a4210e9c1f4e14b51a18478d554ac009f172816b7447ecf15a9346"
)
HISTORICAL_SOURCE_SELECTION_SHA256 = (
    "078a0d2185f95a13c4642b15a5f8da69bc80df6093dc4d8435f181ff93702487"
)
HISTORICAL_PSEUDONYMIZATION_KEY_ID = "next-behavior-hmac-d664dad99120377f"
HISTORICAL_PSEUDONYMIZATION_KEY_FINGERPRINT_SHA256 = (
    "d664dad99120377fd7e08fe2128b3ed76107eb82e39873a864bd414503b3173c"
)
SOURCE_ARCHIVE_AVAILABILITY_SCHEMA_VERSION = (
    "next_behavior_source_archive_availability.v1"
)
_RUNTIME_FIELDS = frozenset(
    {
        "python_implementation",
        "python_version",
        "sqlite_minimum_version",
        "dependencies",
    }
)
_DEPENDENCY_FIELDS = frozenset({"distribution", "version"})
_CAPACITY_FIELDS = frozenset(
    {
        "minimum_free_bytes",
        "minimum_mem_available_bytes",
        "minimum_swap_free_bytes",
    }
)
_SELECTION_FIELDS = frozenset(
    {
        "schema_version",
        "selection_id",
        "preserved_source_selection",
        "source",
        "archive",
        "policy",
        "members",
        "verification",
    }
)
_SELECTION_MEMBER_FIELDS = frozenset(
    {
        "filename",
        "archive_path",
        "collection_date",
        "chronological_order",
        "cohort",
        "role",
        "sealed",
    }
)
_MEMBER_RECEIPT_FIELDS = _SELECTION_MEMBER_FIELDS | frozenset(
    {"size_bytes", "archive_compressed_bytes", "archive_crc32", "sha256"}
)
_INVENTORY_FIELDS = frozenset(
    {
        "schema_version",
        "inventory_id",
        "status",
        "source_selection_id",
        "source_selection_sha256",
        "member_count",
        "role_counts",
        "test_members_sealed",
        "ordered_member_receipts_sha256",
        "members",
    }
)
_SUCCESSOR_DATES_BY_ROLE = {
    "train": (
        "2025-07-03",
        "2025-07-10",
        "2025-07-17",
        "2025-07-18",
        "2025-07-19",
        "2025-07-20",
        "2025-07-21",
        "2025-07-22",
        "2025-07-23",
        "2025-07-24",
    ),
    "selection": tuple(f"2025-07-{day:02d}" for day in range(25, 32)),
    "calibration": tuple(f"2025-08-{day:02d}" for day in range(1, 8)),
    "test": (
        "2025-08-09",
        "2025-08-10",
        "2025-08-11",
        "2025-08-12",
        "2025-08-13",
        "2025-08-15",
        "2025-08-16",
    ),
}
_SUCCESSOR_SELECTION_ID = "successor_calendar_blocks_10_7_7_7.v1"
_EXPECTED_PRESERVED_SELECTION = {
    "path": "configs/next_behavior_source_selection.v1.json",
    "schema_version": "next_behavior_source_selection.v1",
    "sha256": "f453502df46a79c5e934eb3377287d47815605f240d51a305ec89645b2f8f514",
}
_EXPECTED_SOURCE = {
    "zenodo_record_id": 21260400,
    "doi": "10.5281/zenodo.21260400",
}
_EXPECTED_ARCHIVE = {
    "filename": "data_all.zip",
    "size_bytes": 19372965772,
    "checksum": "md5:5b6d6e77e5f7247ac400d2318cef7adb",
    "download_url": "https://zenodo.org/api/records/21260400/files/data_all.zip/content",
}
_EXPECTED_SELECTION_POLICY = {
    "selection_basis": "collection_date_only_complete_calendar_blocks",
    "labels_used": False,
    "member_sizes_used": False,
    "test_metrics_used": False,
    "substitution_allowed": False,
    "train_rule": (
        "fixed_anchors_2025-07-03_2025-07-10_2025-07-17_plus_"
        "all_daily_members_2025-07-18_through_2025-07-24"
    ),
    "selection_window_start_date": "2025-07-25",
    "selection_window_end_date": "2025-07-31",
    "calibration_window_start_date": "2025-08-01",
    "development_cutoff_date": "2025-08-07",
    "embargo_dates": ["2025-08-08"],
    "final_window_start_date": "2025-08-09",
    "final_window_end_date": "2025-08-16",
    "excluded_dates": ["2025-08-14"],
    "test_access": "sealed_until_one_final_evaluation",
}

# These are the complete reviewed Python import edges reachable from the
# successor-preparation entry points.  The caller supplies hashes, but cannot
# choose which files or import edges count as provenance.  Updating an entry
# point or one of these edges therefore requires a reviewed preflight-contract
# change rather than silently shrinking/substituting the receipt inventory.
MANDATORY_SUCCESSOR_PREPARATION_IMPORT_BINDINGS = (
    (
        "production/reproduction/next_behavior/preparation_preflight.py",
        "production.reproduction.next_behavior.classifier_assets",
        "production/reproduction/next_behavior/classifier_assets.py",
    ),
    (
        "production/reproduction/next_behavior/preparation_preflight.py",
        "production.reproduction.next_behavior.experiment_policy",
        "production/reproduction/next_behavior/experiment_policy.py",
    ),
    (
        "production/reproduction/next_behavior/preparation_preflight.py",
        "production.reproduction.next_behavior.support_preflight",
        "production/reproduction/next_behavior/support_preflight.py",
    ),
    (
        "production/reproduction/next_behavior/preparation_preflight.py",
        "production.utils.serialization",
        "production/utils/serialization.py",
    ),
    (
        "production/tools/preflight_next_behavior_preparation.py",
        "production.reproduction.next_behavior.preparation_preflight",
        "production/reproduction/next_behavior/preparation_preflight.py",
    ),
    (
        "production/tools/preflight_next_behavior_preparation.py",
        "production.utils.serialization",
        "production/utils/serialization.py",
    ),
    (
        "production/reproduction/next_behavior/support_preflight.py",
        "production.prediction.next_behavior_contract",
        "production/prediction/next_behavior_contract.py",
    ),
    (
        "production/reproduction/next_behavior/support_preflight.py",
        "production.prediction.next_behavior_preprocessing",
        "production/prediction/next_behavior_preprocessing.py",
    ),
    (
        "production/reproduction/next_behavior/support_preflight.py",
        "production.prediction.evidence_cutoff",
        "production/prediction/evidence_cutoff.py",
    ),
    (
        "production/reproduction/next_behavior/support_preflight.py",
        "production.prediction.trusted_history",
        "production/prediction/trusted_history.py",
    ),
    (
        "production/reproduction/next_behavior/support_preflight.py",
        "production.reproduction.next_behavior.corpus",
        "production/reproduction/next_behavior/corpus.py",
    ),
    (
        "production/reproduction/next_behavior/support_preflight.py",
        "production.reproduction.next_behavior.safe_export",
        "production/reproduction/next_behavior/safe_export.py",
    ),
    (
        "production/reproduction/next_behavior/support_preflight.py",
        "production.reproduction.next_behavior.selected_store",
        "production/reproduction/next_behavior/selected_store.py",
    ),
    (
        "production/reproduction/next_behavior/support_preflight.py",
        "production.reproduction.next_behavior.source_selection_v2",
        "production/reproduction/next_behavior/source_selection_v2.py",
    ),
    (
        "production/reproduction/next_behavior/support_preflight.py",
        "production.utils.serialization",
        "production/utils/serialization.py",
    ),
    (
        "production/reproduction/next_behavior/safe_export.py",
        "production.classification.classification_pipeline",
        "production/classification/classification_pipeline.py",
    ),
    (
        "production/reproduction/next_behavior/safe_export.py",
        "production.classification.securebert_classifier",
        "production/classification/securebert_classifier.py",
    ),
    (
        "production/reproduction/next_behavior/safe_export.py",
        "production.enrichment.mitre_attack_loader",
        "production/enrichment/mitre_attack_loader.py",
    ),
    (
        "production/reproduction/next_behavior/safe_export.py",
        "production.reproduction.next_behavior.corpus",
        "production/reproduction/next_behavior/corpus.py",
    ),
    (
        "production/reproduction/next_behavior/safe_export.py",
        "production.prediction.next_behavior_contract",
        "production/prediction/next_behavior_contract.py",
    ),
    (
        "production/reproduction/next_behavior/safe_export.py",
        "production.prediction.next_behavior_label_policy",
        "production/prediction/next_behavior_label_policy.py",
    ),
    (
        "production/reproduction/next_behavior/safe_export.py",
        "production.prediction.next_behavior_preprocessing",
        "production/prediction/next_behavior_preprocessing.py",
    ),
    (
        "production/reproduction/next_behavior/safe_export.py",
        "production.reproduction.next_behavior.selected_store",
        "production/reproduction/next_behavior/selected_store.py",
    ),
    (
        "production/reproduction/next_behavior/safe_export.py",
        "production.reproduction.next_behavior.zenodo_corpus",
        "production/reproduction/next_behavior/zenodo_corpus.py",
    ),
    (
        "production/reproduction/next_behavior/safe_export.py",
        "production.reproduction.next_behavior.classifier_assets",
        "production/reproduction/next_behavior/classifier_assets.py",
    ),
    (
        "production/reproduction/next_behavior/safe_export.py",
        "production.utils.serialization",
        "production/utils/serialization.py",
    ),
    (
        "production/reproduction/next_behavior/selected_store.py",
        "production.prediction.next_behavior_contract",
        "production/prediction/next_behavior_contract.py",
    ),
    (
        "production/reproduction/next_behavior/selected_store.py",
        "production.reproduction.next_behavior.source_selection",
        "production/reproduction/next_behavior/source_selection.py",
    ),
    (
        "production/reproduction/next_behavior/selected_store.py",
        "production.reproduction.next_behavior.classifier_assets",
        "production/reproduction/next_behavior/classifier_assets.py",
    ),
    (
        "production/reproduction/next_behavior/selected_store.py",
        "production.utils.serialization",
        "production/utils/serialization.py",
    ),
    (
        "production/reproduction/next_behavior/source_selection_v2.py",
        "production.utils.serialization",
        "production/utils/serialization.py",
    ),
    (
        "production/reproduction/next_behavior/experiment_policy.py",
        "production.prediction.next_behavior_contract",
        "production/prediction/next_behavior_contract.py",
    ),
    (
        "production/reproduction/next_behavior/experiment_policy.py",
        "production.prediction.next_behavior_model",
        "production/prediction/next_behavior_model.py",
    ),
    (
        "production/reproduction/next_behavior/experiment_policy.py",
        "production.utils.serialization",
        "production/utils/serialization.py",
    ),
    (
        "production/reproduction/next_behavior/corpus.py",
        "production.prediction.next_behavior_contract",
        "production/prediction/next_behavior_contract.py",
    ),
    (
        "production/reproduction/next_behavior/corpus.py",
        "production.prediction.next_behavior_chronology",
        "production/prediction/next_behavior_chronology.py",
    ),
    (
        "production/reproduction/next_behavior/corpus.py",
        "production.utils.serialization",
        "production/utils/serialization.py",
    ),
    (
        "production/reproduction/next_behavior/zenodo_corpus.py",
        "production.classification.classification_pipeline",
        "production/classification/classification_pipeline.py",
    ),
    (
        "production/reproduction/next_behavior/zenodo_corpus.py",
        "production.classification.securebert_classifier",
        "production/classification/securebert_classifier.py",
    ),
    (
        "production/reproduction/next_behavior/zenodo_corpus.py",
        "production.enrichment.mitre_attack_loader",
        "production/enrichment/mitre_attack_loader.py",
    ),
    (
        "production/reproduction/next_behavior/zenodo_corpus.py",
        "production.reproduction.next_behavior.corpus",
        "production/reproduction/next_behavior/corpus.py",
    ),
    (
        "production/reproduction/next_behavior/zenodo_corpus.py",
        "production.prediction.next_behavior_label_policy",
        "production/prediction/next_behavior_label_policy.py",
    ),
    (
        "production/reproduction/next_behavior/zenodo_corpus.py",
        "production.utils.serialization",
        "production/utils/serialization.py",
    ),
    (
        "production/reproduction/next_behavior/zenodo_corpus.py",
        "production.reproduction.next_behavior.zenodo_members",
        "production/reproduction/next_behavior/zenodo_members.py",
    ),
    (
        "production/reproduction/next_behavior/zenodo_corpus.py",
        "production.reproduction.next_behavior.classifier_assets",
        "production/reproduction/next_behavior/classifier_assets.py",
    ),
    (
        "production/reproduction/next_behavior/successor_contracts.py",
        "production.reproduction.next_behavior.source_selection_v2",
        "production/reproduction/next_behavior/source_selection_v2.py",
    ),
    (
        "production/reproduction/next_behavior/successor_contracts.py",
        "production.prediction.next_behavior_contract",
        "production/prediction/next_behavior_contract.py",
    ),
    (
        "production/reproduction/next_behavior/successor_contracts.py",
        "production.prediction.next_behavior_preprocessing",
        "production/prediction/next_behavior_preprocessing.py",
    ),
    (
        "production/reproduction/next_behavior/successor_contracts.py",
        "production.reproduction.next_behavior.safe_export",
        "production/reproduction/next_behavior/safe_export.py",
    ),
    (
        "production/reproduction/next_behavior/successor_contracts.py",
        "production.reproduction.next_behavior.support_preflight",
        "production/reproduction/next_behavior/support_preflight.py",
    ),
    (
        "production/reproduction/next_behavior/successor_contracts.py",
        "production.utils.serialization",
        "production/utils/serialization.py",
    ),
    (
        "production/reproduction/next_behavior/successor_members.py",
        "production.reproduction.next_behavior.selected_store",
        "production/reproduction/next_behavior/selected_store.py",
    ),
    (
        "production/reproduction/next_behavior/successor_members.py",
        "production.reproduction.next_behavior.source_selection_v2",
        "production/reproduction/next_behavior/source_selection_v2.py",
    ),
    (
        "production/reproduction/next_behavior/successor_members.py",
        "production.reproduction.next_behavior.zenodo_members",
        "production/reproduction/next_behavior/zenodo_members.py",
    ),
    (
        "production/reproduction/next_behavior/successor_members.py",
        "production.utils.serialization",
        "production/utils/serialization.py",
    ),
    (
        "production/tools/finalize_next_behavior_successor_inventory.py",
        "production.reproduction.next_behavior.successor_members",
        "production/reproduction/next_behavior/successor_members.py",
    ),
    (
        "production/tools/prepare_next_behavior_successor_members.py",
        "production.reproduction.next_behavior.successor_members",
        "production/reproduction/next_behavior/successor_members.py",
    ),
)
MANDATORY_SUCCESSOR_PREPARATION_SOURCE_PATHS = tuple(
    sorted(
        {
            path
            for importer_path, _module, source_path in (
                MANDATORY_SUCCESSOR_PREPARATION_IMPORT_BINDINGS
            )
            for path in (importer_path, source_path)
        }
    )
)


def _expected_successor_members() -> list[Dict[str, Any]]:
    members: list[Dict[str, Any]] = []
    for role in ("train", "selection", "calibration", "test"):
        for collection_date in _SUCCESSOR_DATES_BY_ROLE[role]:
            filename = f"{collection_date}.json.gz"
            members.append(
                {
                    "filename": filename,
                    "archive_path": f"../logs_by_day/{filename}",
                    "collection_date": collection_date,
                    "chronological_order": len(members) + 1,
                    "cohort": "final" if role == "test" else "development",
                    "role": role,
                    "sealed": role == "test",
                }
            )
    return members


class NextBehaviorPreparationPreflightError(RuntimeError):
    """Raised when static preparation readiness cannot be proven."""


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_json(value: Any) -> str:
    return _sha256_bytes(stable_json(value).encode("utf-8"))


def _require_mapping(value: Any, fields: frozenset[str], path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise NextBehaviorPreparationPreflightError(f"{path} fields are invalid")
    return value


def _require_sha256(value: Any, path: str) -> str:
    digest = str(value or "").strip().lower()
    if not _SHA256.fullmatch(digest):
        raise NextBehaviorPreparationPreflightError(f"{path} is not a SHA-256")
    return digest


def _require_git_object(value: Any, path: str) -> str:
    identity = str(value or "").strip().lower()
    if not _GIT_OBJECT.fullmatch(identity):
        raise NextBehaviorPreparationPreflightError(f"{path} is not a Git object ID")
    return identity


def _require_nonnegative_integer(value: Any, path: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise NextBehaviorPreparationPreflightError(
            f"{path} must be a non-negative integer"
        )
    return value


def _relative_regular_file(repository_root: Path, value: Any, path: str) -> tuple[str, Path]:
    relative = str(value or "").strip()
    candidate = Path(relative)
    if not relative or candidate.is_absolute() or ".." in candidate.parts:
        raise NextBehaviorPreparationPreflightError(f"{path} is not a safe relative path")
    resolved = repository_root / candidate
    current = repository_root
    for component in candidate.parts:
        current = current / component
        try:
            component_metadata = current.lstat()
        except OSError as exc:
            raise NextBehaviorPreparationPreflightError(
                f"required provenance input is missing: {relative}"
            ) from exc
        if stat.S_ISLNK(component_metadata.st_mode):
            raise NextBehaviorPreparationPreflightError(
                f"required provenance input traverses a symlink: {relative}"
            )
    try:
        metadata = resolved.lstat()
    except OSError as exc:
        raise NextBehaviorPreparationPreflightError(
            f"required provenance input is missing: {relative}"
        ) from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise NextBehaviorPreparationPreflightError(
            f"required provenance input is not a regular file: {relative}"
        )
    return candidate.as_posix(), resolved


def _external_regular_file(value: Any, path: str) -> Path:
    candidate = Path(str(value or "").strip()).expanduser()
    if not candidate.is_absolute() or ".." in candidate.parts:
        raise NextBehaviorPreparationPreflightError(
            f"{path} must be an absolute external-artifact path"
        )
    reviewed_root = REVIEWED_OUTPUT_ROOT
    if reviewed_root.is_symlink() or not reviewed_root.is_dir():
        raise NextBehaviorPreparationPreflightError(
            "reviewed successor workspace root is unavailable or unsafe"
        )
    try:
        candidate.relative_to(reviewed_root)
    except ValueError as exc:
        raise NextBehaviorPreparationPreflightError(
            f"{path} escapes the reviewed successor workspace"
        ) from exc
    current = reviewed_root
    for component in candidate.relative_to(reviewed_root).parts:
        current = current / component
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise NextBehaviorPreparationPreflightError(
                f"external artifact is missing: {candidate}"
            ) from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise NextBehaviorPreparationPreflightError(
                f"external artifact traverses a symlink: {candidate}"
            )
    if not stat.S_ISREG(candidate.lstat().st_mode):
        raise NextBehaviorPreparationPreflightError(
            f"external artifact is not a regular file: {candidate}"
        )
    return candidate


def _read_json_regular(path: Path, label: str) -> Dict[str, Any]:
    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> Dict[str, Any]:
        output: Dict[str, Any] = {}
        for key, item in pairs:
            if key in output:
                raise NextBehaviorPreparationPreflightError(
                    f"{label} contains duplicate key: {key}"
                )
            output[key] = item
        return output

    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicate_keys,
        )
    except NextBehaviorPreparationPreflightError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise NextBehaviorPreparationPreflightError(f"cannot read {label}") from exc
    if not isinstance(value, dict):
        raise NextBehaviorPreparationPreflightError(f"{label} must be an object")
    return value


def _verify_pinned_json(
    repository_root: Path,
    binding: Any,
    *,
    label: str,
    expected_schema: str,
    fields: frozenset[str] = _PIN_FIELDS,
) -> tuple[Dict[str, Any], Dict[str, Any]]:
    pin = _require_mapping(binding, fields, label)
    relative, path = _relative_regular_file(repository_root, pin["path"], f"{label}.path")
    expected_hash = _require_sha256(
        pin["artifact_byte_sha256"], f"{label}.artifact_byte_sha256"
    )
    actual_hash = _sha256_bytes(path.read_bytes())
    if actual_hash != expected_hash:
        raise NextBehaviorPreparationPreflightError(f"{label} SHA-256 mismatch")
    if pin["schema_version"] != expected_schema:
        raise NextBehaviorPreparationPreflightError(
            f"{label} binding schema_version is incompatible"
        )
    value = _read_json_regular(path, label)
    if value.get("schema_version") != expected_schema:
        raise NextBehaviorPreparationPreflightError(
            f"{label} content schema_version is incompatible"
        )
    evidence = {
        "path": relative,
        "schema_version": expected_schema,
        "artifact_byte_sha256": actual_hash,
        "size_bytes": path.stat().st_size,
    }
    return value, evidence


def _verify_external_pinned_json(
    binding: Any,
    *,
    label: str,
    expected_schema: str,
) -> tuple[Dict[str, Any], Dict[str, Any]]:
    pin = _require_mapping(binding, _EXTERNAL_PIN_FIELDS, label)
    path = _external_regular_file(pin["path"], f"{label}.path")
    expected_byte_hash = _require_sha256(
        pin["artifact_byte_sha256"], f"{label}.artifact_byte_sha256"
    )
    expected_contract_hash = _require_sha256(
        pin["contract_sha256"], f"{label}.contract_sha256"
    )
    actual_byte_hash = _sha256_bytes(path.read_bytes())
    if actual_byte_hash != expected_byte_hash:
        raise NextBehaviorPreparationPreflightError(
            f"{label} artifact byte SHA-256 mismatch"
        )
    if pin["schema_version"] != expected_schema:
        raise NextBehaviorPreparationPreflightError(
            f"{label} binding schema_version is incompatible"
        )
    value = _read_json_regular(path, label)
    if value.get("schema_version") != expected_schema:
        raise NextBehaviorPreparationPreflightError(
            f"{label} content schema_version is incompatible"
        )
    actual_contract_hash = _sha256_json(value)
    if actual_contract_hash != expected_contract_hash:
        raise NextBehaviorPreparationPreflightError(
            f"{label} canonical contract SHA-256 mismatch"
        )
    return value, {
        "path": str(path),
        "schema_version": expected_schema,
        "artifact_byte_sha256": actual_byte_hash,
        "contract_sha256": actual_contract_hash,
        "size_bytes": path.stat().st_size,
    }


def _run_git(repository_root: Path, arguments: Sequence[str]) -> str:
    try:
        completed = subprocess.run(
            ["git", *arguments],
            cwd=repository_root,
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise NextBehaviorPreparationPreflightError(
            "Git repository provenance cannot be verified"
        ) from exc
    return completed.stdout.strip()


def _verify_repository(repository_root: Path, value: Any) -> Dict[str, Any]:
    binding = _require_mapping(value, _REPOSITORY_FIELDS, "repository")
    expected_commit = _require_git_object(binding["commit"], "repository.commit")
    expected_tree = _require_git_object(binding["tree"], "repository.tree")
    actual_commit = _run_git(repository_root, ["rev-parse", "HEAD"]).lower()
    actual_tree = _run_git(repository_root, ["rev-parse", "HEAD^{tree}"]).lower()
    if actual_commit != expected_commit:
        raise NextBehaviorPreparationPreflightError("repository commit mismatch")
    if actual_tree != expected_tree:
        raise NextBehaviorPreparationPreflightError("repository tree mismatch")
    status = _run_git(
        repository_root,
        ["status", "--porcelain=v1", "--untracked-files=all"],
    )
    if status:
        raise NextBehaviorPreparationPreflightError("repository is not clean")
    return {"commit": actual_commit, "tree": actual_tree, "clean": True}


def _module_source(module: str) -> str:
    if not _MODULE.fullmatch(module):
        raise NextBehaviorPreparationPreflightError("import module is invalid")
    return module.replace(".", "/") + ".py"


def _importer_references_module(importer: Path, module: str) -> bool:
    try:
        tree = ast.parse(importer.read_text(encoding="utf-8"), filename=str(importer))
    except (OSError, UnicodeError, SyntaxError) as exc:
        raise NextBehaviorPreparationPreflightError(
            "importer cannot be parsed for provenance"
        ) from exc
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            if any(alias.name == module for alias in node.names):
                return True
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module == module:
                return True
    return False


def _actual_production_import_bindings(
    repository_root: Path,
    importer_paths: Sequence[str],
) -> set[tuple[str, str, str]]:
    bindings: set[tuple[str, str, str]] = set()
    for importer_relative in importer_paths:
        _, importer = _relative_regular_file(
            repository_root,
            importer_relative,
            "mandatory import graph importer",
        )
        try:
            tree = ast.parse(
                importer.read_text(encoding="utf-8"), filename=str(importer)
            )
        except (OSError, UnicodeError, SyntaxError) as exc:
            raise NextBehaviorPreparationPreflightError(
                "mandatory import graph cannot be parsed"
            ) from exc
        modules: list[str] = []
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.ImportFrom)
                and node.level == 0
                and node.module
                and node.module.startswith("production.")
            ):
                modules.append(node.module)
            elif isinstance(node, ast.Import):
                modules.extend(
                    alias.name
                    for alias in node.names
                    if alias.name.startswith("production.")
                )
        for module in modules:
            source_relative = _module_source(module)
            _relative_regular_file(
                repository_root,
                source_relative,
                f"mandatory imported module {module}",
            )
            bindings.add((importer_relative, module, source_relative))
    return bindings


def _verify_provenance(repository_root: Path, value: Any) -> Dict[str, Any]:
    provenance = _require_mapping(value, _PROVENANCE_FIELDS, "provenance")
    raw_files = provenance["required_files"]
    raw_imports = provenance["import_bindings"]
    if not isinstance(raw_files, list) or not raw_files:
        raise NextBehaviorPreparationPreflightError(
            "provenance.required_files must not be empty"
        )
    if not isinstance(raw_imports, list) or not raw_imports:
        raise NextBehaviorPreparationPreflightError(
            "provenance.import_bindings must not be empty"
        )

    declared_paths: list[str] = []
    for index, raw in enumerate(raw_files):
        item = _require_mapping(raw, _FILE_FIELDS, f"required_files[{index}]")
        declared = str(item["path"] or "").strip()
        candidate = Path(declared)
        if not declared or candidate.is_absolute() or ".." in candidate.parts:
            raise NextBehaviorPreparationPreflightError(
                f"required_files[{index}].path is not a safe relative path"
            )
        declared_paths.append(candidate.as_posix())
    if (
        len(declared_paths) != len(set(declared_paths))
        or tuple(sorted(declared_paths))
        != MANDATORY_SUCCESSOR_PREPARATION_SOURCE_PATHS
    ):
        raise NextBehaviorPreparationPreflightError(
            "mandatory successor-preparation source inventory mismatch"
        )

    declared_imports: list[tuple[str, str, str]] = []
    for index, raw in enumerate(raw_imports):
        item = _require_mapping(raw, _IMPORT_FIELDS, f"import_bindings[{index}]")
        declared_imports.append(
            (
                str(item["importer_path"] or "").strip(),
                str(item["module"] or "").strip(),
                str(item["source_path"] or "").strip(),
            )
        )
    if (
        len(declared_imports) != len(set(declared_imports))
        or tuple(sorted(declared_imports))
        != tuple(sorted(MANDATORY_SUCCESSOR_PREPARATION_IMPORT_BINDINGS))
    ):
        raise NextBehaviorPreparationPreflightError(
            "mandatory successor-preparation import-binding inventory mismatch"
        )

    files: list[Dict[str, Any]] = []
    seen_paths: set[str] = set()
    for index, raw in enumerate(raw_files):
        item = _require_mapping(raw, _FILE_FIELDS, f"required_files[{index}]")
        relative, path = _relative_regular_file(
            repository_root, item["path"], f"required_files[{index}].path"
        )
        if relative in seen_paths:
            raise NextBehaviorPreparationPreflightError(
                "provenance required-file paths must be unique"
            )
        seen_paths.add(relative)
        expected = _require_sha256(item["sha256"], f"required_files[{index}].sha256")
        actual = _sha256_bytes(path.read_bytes())
        if actual != expected:
            raise NextBehaviorPreparationPreflightError(
                f"provenance SHA-256 mismatch: {relative}"
            )
        files.append({"path": relative, "sha256": actual, "size_bytes": path.stat().st_size})

    mandatory_importers = sorted(
        {item[0] for item in MANDATORY_SUCCESSOR_PREPARATION_IMPORT_BINDINGS}
    )
    actual_import_graph = _actual_production_import_bindings(
        repository_root,
        mandatory_importers,
    )
    if actual_import_graph != set(MANDATORY_SUCCESSOR_PREPARATION_IMPORT_BINDINGS):
        raise NextBehaviorPreparationPreflightError(
            "actual AST import graph does not match mandatory bindings"
        )

    imports: list[Dict[str, Any]] = []
    seen_bindings: set[tuple[str, str, str]] = set()
    for index, raw in enumerate(raw_imports):
        item = _require_mapping(raw, _IMPORT_FIELDS, f"import_bindings[{index}]")
        module = str(item["module"] or "").strip()
        expected_source = _module_source(module)
        source_relative, _ = _relative_regular_file(
            repository_root, item["source_path"], f"import_bindings[{index}].source_path"
        )
        if source_relative != expected_source:
            raise NextBehaviorPreparationPreflightError(
                f"imported module path mismatch: {module} resolves to {expected_source}"
            )
        importer_relative, importer = _relative_regular_file(
            repository_root,
            item["importer_path"],
            f"import_bindings[{index}].importer_path",
        )
        if not _importer_references_module(importer, module):
            raise NextBehaviorPreparationPreflightError(
                f"importer does not bind the declared module: {module}"
            )
        binding_identity = (importer_relative, module, source_relative)
        if binding_identity in seen_bindings:
            raise NextBehaviorPreparationPreflightError(
                "provenance import bindings must be unique"
            )
        seen_bindings.add(binding_identity)
        imports.append(
            {"module": module, "source_path": source_relative, "importer_path": importer_relative}
        )

    files.sort(key=lambda item: item["path"])
    imports.sort(key=lambda item: (item["module"], item["importer_path"]))
    return {
        "required_files": files,
        "import_bindings": imports,
        "provenance_sha256": _sha256_json(
            {"required_files": files, "import_bindings": imports}
        ),
    }


def _verify_classifier_environment(
    repository_root: Path, value: Any
) -> Dict[str, Any]:
    pin = _require_mapping(value, _PIN_FIELDS, "classifier_environment")
    relative, path = _relative_regular_file(
        repository_root, pin["path"], "classifier_environment.path"
    )
    expected_hash = _require_sha256(
        pin["artifact_byte_sha256"],
        "classifier_environment.artifact_byte_sha256",
    )
    actual_hash = _sha256_bytes(path.read_bytes())
    if actual_hash != expected_hash:
        raise NextBehaviorPreparationPreflightError(
            "classifier environment SHA-256 mismatch"
        )
    if pin["schema_version"] != "next_behavior_classifier_environment.v4":
        raise NextBehaviorPreparationPreflightError(
            "classifier environment binding schema_version is incompatible"
        )
    try:
        manifest = load_classifier_manifest(path)
        source_identity = verify_classifier_source_identity(
            manifest, repository_root=repository_root
        )
    except ClassifierAssetError as exc:
        raise NextBehaviorPreparationPreflightError(str(exc)) from exc
    if source_identity is None:
        raise NextBehaviorPreparationPreflightError(
            "classifier source identity is not available"
        )

    dependency_relative, dependency_path = _relative_regular_file(
        repository_root,
        manifest["dependency_lock"]["path"],
        "classifier_environment.dependency_lock.path",
    )
    dependency_hash = _sha256_bytes(dependency_path.read_bytes())
    if dependency_hash != manifest["dependency_lock"]["sha256"]:
        raise NextBehaviorPreparationPreflightError(
            "classifier dependency lock SHA-256 mismatch"
        )
    dependency_pins: list[Dict[str, str]] = []
    try:
        lock_lines = dependency_path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise NextBehaviorPreparationPreflightError(
            "classifier dependency lock cannot be read"
        ) from exc
    for line_number, raw_line in enumerate(lock_lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.count("==") != 1:
            raise NextBehaviorPreparationPreflightError(
                f"dependency lock line {line_number} is not an exact pin"
            )
        distribution, version = (item.strip() for item in line.split("==", 1))
        if not distribution or not version:
            raise NextBehaviorPreparationPreflightError(
                f"dependency lock line {line_number} is invalid"
            )
        dependency_pins.append({"distribution": distribution, "version": version})
    if not dependency_pins:
        raise NextBehaviorPreparationPreflightError("classifier dependency lock is empty")

    policy = manifest["classification_policy"]
    verified_policy_files: list[Dict[str, Any]] = []
    for path_field, hash_field in (
        ("rule_policy_path", "rule_policy_sha256"),
        ("mitre_cache_path", "mitre_cache_sha256"),
        ("trust_policy_path", "trust_policy_sha256"),
        ("trusted_history_builder_path", "trusted_history_builder_sha256"),
        ("trusted_history_runtime_path", "trusted_history_runtime_sha256"),
        ("preprocessing_contract_path", "preprocessing_contract_sha256"),
    ):
        relative_policy, policy_path = _relative_regular_file(
            repository_root, policy[path_field], f"classification_policy.{path_field}"
        )
        expected = _require_sha256(
            policy[hash_field], f"classification_policy.{hash_field}"
        )
        actual = _sha256_bytes(policy_path.read_bytes())
        if actual != expected:
            raise NextBehaviorPreparationPreflightError(
                f"classifier policy SHA-256 mismatch: {relative_policy}"
            )
        verified_policy_files.append({"path": relative_policy, "sha256": actual})

    if policy.get("target_contract_id") != TARGET_CONTRACT_ID:
        raise NextBehaviorPreparationPreflightError(
            "classifier target contract is incompatible"
        )
    if policy.get("trusted_history_schema_version") != TRUSTED_HISTORY_SCHEMA_VERSION:
        raise NextBehaviorPreparationPreflightError(
            "classifier trusted-history schema is incompatible"
        )
    if policy.get("trusted_history_maximum_phases") != MAXIMUM_PHASES:
        raise NextBehaviorPreparationPreflightError(
            "classifier trusted-history maximum is incompatible"
        )
    return {
        "path": relative,
        "schema_version": manifest["schema_version"],
        "artifact_byte_sha256": actual_hash,
        "source_identity_sha256": source_identity["sha256"],
        "python": {
            "implementation": manifest["python"]["implementation"],
            "version": manifest["python"]["version"],
        },
        "dependency_lock": {
            "path": dependency_relative,
            "sha256": dependency_hash,
            "pins": dependency_pins,
        },
        "classification_policy": {
            "rule_policy_id": policy["rule_policy_id"],
            "rule_policy_version": policy["rule_policy_version"],
            "target_contract_id": policy["target_contract_id"],
            "trusted_history_schema_version": policy["trusted_history_schema_version"],
            "trusted_history_maximum_phases": policy["trusted_history_maximum_phases"],
            "files": sorted(verified_policy_files, key=lambda item: item["path"]),
        },
    }


def _verify_classifier_model(
    repository_root: Path,
    classifier_environment_binding: Mapping[str, Any],
    classifier_environment_evidence: Mapping[str, Any],
    value: Any,
) -> Dict[str, Any]:
    model_binding = _require_mapping(value, _CLASSIFIER_MODEL_FIELDS, "classifier_model")
    model_root = Path(str(model_binding["model_root"] or "")).expanduser()
    if (
        not model_root.is_absolute()
        or model_root.is_symlink()
        or not model_root.is_dir()
    ):
        raise NextBehaviorPreparationPreflightError(
            "classifier model_root must be an existing non-symlink absolute directory"
        )
    model_root = model_root.resolve()
    receipt, receipt_evidence = _verify_external_pinned_json(
        model_binding["binding_receipt"],
        label="classifier_model.binding_receipt",
        expected_schema=MODEL_ROOT_BINDING_SCHEMA_VERSION,
    )
    if set(receipt) != _MODEL_ROOT_RECEIPT_FIELDS:
        raise NextBehaviorPreparationPreflightError(
            "classifier model-root binding receipt fields are invalid"
        )
    environment_relative, environment_path = _relative_regular_file(
        repository_root,
        classifier_environment_binding["path"],
        "classifier_environment.path",
    )
    try:
        manifest = load_classifier_manifest(environment_path)
    except ClassifierAssetError as exc:
        raise NextBehaviorPreparationPreflightError(str(exc)) from exc
    classifier = manifest["classifier"]
    if (
        receipt.get("status") != "model_root_frozen"
        or receipt.get("model_root") != str(model_root)
        or receipt.get("classifier_environment_artifact_byte_sha256")
        != classifier_environment_evidence["artifact_byte_sha256"]
        or receipt.get("checkpoint_id") != classifier["checkpoint_id"]
        or receipt.get("checkpoint_sha256") != classifier["checkpoint_sha256"]
        or receipt.get("files") != classifier["files"]
    ):
        raise NextBehaviorPreparationPreflightError(
            "classifier model-root receipt does not match the classifier environment"
        )

    verified_files: Dict[str, Dict[str, Any]] = {}
    for relative, expected in classifier["files"].items():
        relative_path = Path(relative)
        if relative_path.is_absolute() or ".." in relative_path.parts:
            raise NextBehaviorPreparationPreflightError(
                "classifier manifest contains an unsafe model path"
            )
        asset = model_root / relative_path
        try:
            metadata = asset.lstat()
        except OSError as exc:
            raise NextBehaviorPreparationPreflightError(
                f"missing classifier model asset: {relative}"
            ) from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise NextBehaviorPreparationPreflightError(
                f"classifier model asset is not a regular file: {relative}"
            )
        actual = _sha256_bytes(asset.read_bytes())
        if actual != expected:
            raise NextBehaviorPreparationPreflightError(
                f"classifier model asset SHA-256 mismatch: {relative}"
            )
        verified_files[relative] = {
            "sha256": actual,
            "size_bytes": metadata.st_size,
        }
    try:
        full_verification = verify_classifier_assets(
            manifest,
            repository_root=repository_root,
            model_root=model_root,
        )
    except ClassifierAssetError as exc:
        raise NextBehaviorPreparationPreflightError(str(exc)) from exc
    return {
        "model_root": str(model_root),
        "binding_receipt": receipt_evidence,
        "classifier_environment_path": environment_relative,
        "adapter_sha256": classifier["adapter_sha256"],
        "pipeline_sha256": classifier["pipeline_sha256"],
        "operation_parser_sha256": classifier["operation_parser_sha256"],
        "splitter_sha256": classifier["splitter_sha256"],
        "checkpoint_id": classifier["checkpoint_id"],
        "checkpoint_sha256": classifier["checkpoint_sha256"],
        "model_files": verified_files,
        "full_asset_verification_status": full_verification["status"],
    }


def _defer_classifier_model_for_pre_staging(value: Any) -> Dict[str, Any]:
    binding = _require_mapping(
        value, _PRE_STAGING_CLASSIFIER_MODEL_FIELDS, "classifier_model"
    )
    if binding != {
        "stage": PRE_STAGING_STAGE,
        "status": "deferred_to_post_staging_model_gate",
    }:
        raise NextBehaviorPreparationPreflightError(
            "pre-staging classifier model gate must be explicitly deferred"
        )
    return dict(binding)


def _verify_preprocessing(
    repository_root: Path, value: Any, classifier: Mapping[str, Any]
) -> Dict[str, Any]:
    contract, evidence = _verify_pinned_json(
        repository_root,
        value,
        label="preprocessing",
        expected_schema=PREPROCESSING_SCHEMA_VERSION,
        fields=_PREPROCESSING_FIELDS,
    )
    if evidence["path"] != PREPROCESSING_PATH:
        raise NextBehaviorPreparationPreflightError(
            f"preprocessing path must be {PREPROCESSING_PATH}"
        )
    binding = value
    expected = {
        "target_contract_id": TARGET_CONTRACT_ID,
        "trusted_history_schema_version": TRUSTED_HISTORY_SCHEMA_VERSION,
        "maximum_phases": MAXIMUM_PHASES,
    }
    if any(binding.get(key) != item for key, item in expected.items()):
        raise NextBehaviorPreparationPreflightError(
            "preprocessing binding is incompatible"
        )
    if contract.get("target_contract_id") != TARGET_CONTRACT_ID:
        raise NextBehaviorPreparationPreflightError(
            "preprocessing target contract is incompatible"
        )
    construction = contract.get("phase_construction")
    if not isinstance(construction, Mapping) or construction.get(
        "maximum_sequence_length"
    ) != MAXIMUM_PHASES:
        raise NextBehaviorPreparationPreflightError(
            "preprocessing maximum sequence length is incompatible"
        )
    classifier_policy = classifier["classification_policy"]
    if classifier_policy["target_contract_id"] != contract["target_contract_id"]:
        raise NextBehaviorPreparationPreflightError(
            "classifier/preprocessing target mismatch"
        )
    classifier_preprocessing = next(
        (
            item
            for item in classifier_policy["files"]
            if item["path"] == evidence["path"]
        ),
        None,
    )
    if (
        not classifier_preprocessing
        or classifier_preprocessing["sha256"]
        != evidence["artifact_byte_sha256"]
    ):
        raise NextBehaviorPreparationPreflightError(
            "classifier environment does not bind the exact preprocessing bytes"
        )
    evidence.update(expected)
    return evidence


def _verify_frozen_inputs(repository_root: Path, value: Any) -> Dict[str, Any]:
    if isinstance(value, Mapping) and value.get("stage") == PRE_STAGING_STAGE:
        return _verify_pre_staging_frozen_inputs(repository_root, value)
    del repository_root  # External immutable artifacts must not dirty the repository.
    inputs = _require_mapping(value, _FROZEN_INPUT_FIELDS, "frozen_inputs")
    selection, selection_evidence = _verify_external_pinned_json(
        inputs["source_selection"],
        label="source_selection",
        expected_schema=SOURCE_SELECTION_SCHEMA_VERSION,
    )
    inventory, inventory_evidence = _verify_external_pinned_json(
        inputs["member_inventory"],
        label="member_inventory",
        expected_schema=MEMBER_INVENTORY_SCHEMA_VERSION,
    )
    if set(selection) != _SELECTION_FIELDS:
        raise NextBehaviorPreparationPreflightError(
            "source selection contract fields are invalid"
        )
    if set(inventory) != _INVENTORY_FIELDS:
        raise NextBehaviorPreparationPreflightError(
            "member inventory contract fields are invalid"
        )
    policy = selection.get("policy")
    if (
        selection.get("selection_id") != _SUCCESSOR_SELECTION_ID
        or selection.get("preserved_source_selection")
        != _EXPECTED_PRESERVED_SELECTION
        or selection.get("source") != _EXPECTED_SOURCE
        or selection.get("archive") != _EXPECTED_ARCHIVE
        or policy != _EXPECTED_SELECTION_POLICY
    ):
        raise NextBehaviorPreparationPreflightError(
            "source selection is not the frozen label-blind/test-sealed protocol"
        )
    verification = selection.get("verification")
    if (
        not isinstance(verification, Mapping)
        or verification.get("status") != "archive_members_verified"
        or not isinstance(verification.get("member_receipts"), list)
    ):
        raise NextBehaviorPreparationPreflightError(
            "source selection archive-member receipts are incomplete"
        )
    if (
        inventory.get("status") != "member_inventory_frozen"
        or inventory.get("test_members_sealed") is not True
    ):
        raise NextBehaviorPreparationPreflightError(
            "successor member inventory is not frozen/test-sealed"
        )
    selection_members = selection.get("members")
    inventory_members = inventory.get("members")
    if not isinstance(selection_members, list) or not selection_members:
        raise NextBehaviorPreparationPreflightError(
            "source selection has no frozen members"
        )
    if not isinstance(inventory_members, list) or not inventory_members:
        raise NextBehaviorPreparationPreflightError(
            "member inventory has no frozen members"
        )
    expected_members = _expected_successor_members()
    if selection_members != expected_members:
        raise NextBehaviorPreparationPreflightError(
            "source selection does not match the frozen 10/7/7/7 calendar protocol"
        )
    selection_names = [
        str(member.get("filename") or "").strip()
        for member in selection_members
        if isinstance(member, Mapping)
    ]
    inventory_names = [
        str(member.get("filename") or "").strip()
        for member in inventory_members
        if isinstance(member, Mapping)
    ]
    if (
        len(selection_names) != len(selection_members)
        or len(inventory_names) != len(inventory_members)
        or not all(selection_names)
        or not all(inventory_names)
        or len(set(selection_names)) != len(selection_names)
        or len(set(inventory_names)) != len(inventory_names)
    ):
        raise NextBehaviorPreparationPreflightError(
            "frozen input member identities are invalid"
        )
    if selection_names != inventory_names:
        raise NextBehaviorPreparationPreflightError(
            "source selection/member inventory membership mismatch"
        )
    verified_members = verification["member_receipts"]
    if verified_members != inventory_members:
        raise NextBehaviorPreparationPreflightError(
            "member inventory does not match completed source-selection receipts"
        )
    if inventory.get("source_selection_id") != selection.get("selection_id"):
        raise NextBehaviorPreparationPreflightError(
            "member inventory source-selection identity mismatch"
        )
    if inventory.get("source_selection_sha256") != _sha256_json(selection):
        raise NextBehaviorPreparationPreflightError(
            "member inventory source-selection hash mismatch"
        )
    if inventory.get("member_count") != len(inventory_members):
        raise NextBehaviorPreparationPreflightError(
            "member inventory count mismatch"
        )
    if len(inventory_members) != sum(SUCCESSOR_ROLE_COUNTS.values()):
        raise NextBehaviorPreparationPreflightError(
            "successor member inventory does not contain exactly 31 members"
        )
    actual_role_counts = {
        role: sum(
            isinstance(member, Mapping) and member.get("role") == role
            for member in inventory_members
        )
        for role in SUCCESSOR_ROLE_COUNTS
    }
    if (
        actual_role_counts != SUCCESSOR_ROLE_COUNTS
        or inventory.get("role_counts") != SUCCESSOR_ROLE_COUNTS
    ):
        raise NextBehaviorPreparationPreflightError(
            "successor member inventory role counts are invalid"
        )
    if inventory.get("ordered_member_receipts_sha256") != _sha256_json(
        inventory_members
    ):
        raise NextBehaviorPreparationPreflightError(
            "successor member inventory ordered receipt hash mismatch"
        )
    inventory_id_basis = {
        key: item for key, item in inventory.items() if key != "inventory_id"
    }
    if inventory.get("inventory_id") != stable_id(
        "nextbehaviorsuccessorinventory", inventory_id_basis
    ):
        raise NextBehaviorPreparationPreflightError(
            "successor member inventory identity mismatch"
        )
    for index, member in enumerate(inventory_members):
        if not isinstance(member, Mapping):
            raise NextBehaviorPreparationPreflightError(
                f"member inventory entry {index} is invalid"
            )
        if set(member) != _MEMBER_RECEIPT_FIELDS:
            raise NextBehaviorPreparationPreflightError(
                f"member_inventory.members[{index}] fields are invalid"
            )
        _require_sha256(member.get("sha256"), f"member_inventory.members[{index}].sha256")
        size = member.get("size_bytes")
        if isinstance(size, bool) or not isinstance(size, int) or size <= 0:
            raise NextBehaviorPreparationPreflightError(
                f"member_inventory.members[{index}].size_bytes is invalid"
            )
        compressed = member.get("archive_compressed_bytes")
        if (
            isinstance(compressed, bool)
            or not isinstance(compressed, int)
            or compressed <= 0
        ):
            raise NextBehaviorPreparationPreflightError(
                f"member_inventory.members[{index}].archive_compressed_bytes is invalid"
            )
        if not _CRC32.fullmatch(str(member.get("archive_crc32") or "").lower()):
            raise NextBehaviorPreparationPreflightError(
                f"member_inventory.members[{index}].archive_crc32 is invalid"
            )
        role = str(member.get("role") or "").strip()
        sealed = member.get("sealed")
        if role not in {"train", "selection", "calibration", "test"}:
            raise NextBehaviorPreparationPreflightError(
                f"member_inventory.members[{index}].role is invalid"
            )
        if sealed is not (role == "test"):
            raise NextBehaviorPreparationPreflightError(
                f"member_inventory.members[{index}] test seal is invalid"
            )
        declaration = selection_members[index]
        for field in (
            "filename",
            "archive_path",
            "collection_date",
            "chronological_order",
            "cohort",
            "role",
            "sealed",
        ):
            if declaration.get(field) != member.get(field):
                raise NextBehaviorPreparationPreflightError(
                    "source-selection declaration/member receipt mismatch"
                )
    return {
        "stage": POST_STAGING_STAGE,
        "source_selection": selection_evidence,
        "member_inventory": inventory_evidence,
        "member_count": len(selection_names),
        "ordered_member_names_sha256": _sha256_json(selection_names),
    }


def _head_source_archive(url: str) -> Dict[str, Any]:
    """Read only archive availability probe used by Stage A.

    A HEAD request proves that the declared source endpoint currently exposes
    the reviewed archive size without opening or downloading archive content.
    The response is evidence only; member bytes remain a Stage B concern.
    """

    request = urllib.request.Request(
        url,
        headers={"User-Agent": "honeypot-next-behavior-preflight/1"},
        method="HEAD",
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            headers = response.headers
            content_length = headers.get("Content-Length")
            return {
                "http_status": int(response.status),
                "content_length_bytes": int(content_length or 0),
                "accept_ranges": str(headers.get("Accept-Ranges") or "").lower(),
            }
    except (OSError, ValueError, urllib.error.URLError) as exc:
        raise NextBehaviorPreparationPreflightError(
            f"source archive availability HEAD request failed: {exc}"
        ) from exc


def _verify_source_archive_availability(value: Any) -> Dict[str, Any]:
    expected = {
        "schema_version": SOURCE_ARCHIVE_AVAILABILITY_SCHEMA_VERSION,
        "url": _EXPECTED_ARCHIVE["download_url"],
        "expected_size_bytes": _EXPECTED_ARCHIVE["size_bytes"],
        "expected_md5": _EXPECTED_ARCHIVE["checksum"].removeprefix("md5:"),
    }
    binding = _require_mapping(
        value, _PRE_STAGING_ARCHIVE_FIELDS, "pre_staging.source_archive_availability"
    )
    if binding != expected:
        raise NextBehaviorPreparationPreflightError(
            "pre-staging source archive availability declaration changed"
        )
    observed = _head_source_archive(binding["url"])
    status = observed["http_status"]
    if not 200 <= status < 400:
        raise NextBehaviorPreparationPreflightError(
            f"source archive availability returned HTTP {status}"
        )
    if observed["content_length_bytes"] != binding["expected_size_bytes"]:
        raise NextBehaviorPreparationPreflightError(
            "source archive availability content length differs from the reviewed archive"
        )
    return {
        "schema_version": binding["schema_version"],
        "url": binding["url"],
        "expected_size_bytes": binding["expected_size_bytes"],
        "expected_md5": binding["expected_md5"],
        "http_status": status,
        "content_length_bytes": observed["content_length_bytes"],
        "accept_ranges": observed["accept_ranges"],
        "member_content_opened": False,
    }


def _verify_pre_staging_frozen_inputs(
    repository_root: Path, value: Mapping[str, Any]
) -> Dict[str, Any]:
    """Verify only declarations that can exist before member staging.

    Stage A intentionally does not accept a member inventory or content hashes.
    The completed inventory path above is Stage B and remains the only input
    accepted by later support/preparation gates.
    """

    inputs = _require_mapping(
        value, _PRE_STAGING_FROZEN_INPUT_FIELDS, "frozen_inputs"
    )
    selection, selection_evidence = _verify_pinned_json(
        repository_root,
        inputs["source_selection"],
        label="pre_staging.source_selection",
        expected_schema=SOURCE_SELECTION_SCHEMA_VERSION,
    )
    if (
        selection.get("selection_id") != _SUCCESSOR_SELECTION_ID
        or selection.get("preserved_source_selection")
        != _EXPECTED_PRESERVED_SELECTION
        or selection.get("source") != _EXPECTED_SOURCE
        or selection.get("archive") != _EXPECTED_ARCHIVE
        or selection.get("policy") != _EXPECTED_SELECTION_POLICY
    ):
        raise NextBehaviorPreparationPreflightError(
            "pre-staging source selection is not the frozen label-blind protocol"
        )
    declarations = selection.get("members")
    if declarations != _expected_successor_members():
        raise NextBehaviorPreparationPreflightError(
            "pre-staging source selection does not match the frozen 10/7/7/7 calendar"
        )
    verification = selection.get("verification")
    if (
        not isinstance(verification, Mapping)
        or verification.get("status") != "pending_archive_verification"
        or verification.get("member_receipts") != []
    ):
        raise NextBehaviorPreparationPreflightError(
            "pre-staging source selection must not contain member content receipts"
        )
    archive_availability = _verify_source_archive_availability(
        inputs["source_archive_availability"]
    )

    membership_binding = _require_mapping(
        inputs["historical_test_membership"],
        _PRE_STAGING_MEMBERSHIP_FIELDS,
        "pre_staging.historical_test_membership",
    )
    count = membership_binding["role_inventory_session_count"]
    if count != HISTORICAL_TEST_SESSION_COUNT:
        raise NextBehaviorPreparationPreflightError(
            "historical role-inventory session count is incompatible"
        )
    if (
        _require_sha256(
            membership_binding["role_inventory_session_membership_sha256"],
            "historical role-inventory session membership SHA-256",
        )
        != HISTORICAL_TEST_SESSION_MEMBERSHIP_SHA256
    ):
        raise NextBehaviorPreparationPreflightError(
            "historical role-inventory membership is incompatible"
        )
    receipt_path = _external_regular_file(
        membership_binding["receipt_path"],
        "pre_staging.historical_test_membership.receipt_path",
    )
    artifact_path = _external_regular_file(
        membership_binding["artifact_path"],
        "pre_staging.historical_test_membership.artifact_path",
    )
    receipt_byte_sha256 = _require_sha256(
        membership_binding["receipt_byte_sha256"],
        "pre_staging.historical_test_membership.receipt_byte_sha256",
    )
    artifact_byte_sha256 = _require_sha256(
        membership_binding["artifact_byte_sha256"],
        "pre_staging.historical_test_membership.artifact_byte_sha256",
    )
    if _sha256_bytes(receipt_path.read_bytes()) != receipt_byte_sha256:
        raise NextBehaviorPreparationPreflightError(
            "historical membership receipt byte SHA-256 mismatch"
        )
    if _sha256_bytes(artifact_path.read_bytes()) != artifact_byte_sha256:
        raise NextBehaviorPreparationPreflightError(
            "historical membership artifact byte SHA-256 mismatch"
        )
    membership_receipt = _read_json_regular(
        receipt_path, "historical test-session membership receipt"
    )
    try:
        checked_membership = require_valid_historical_test_session_membership(
            membership_receipt
        )
    except SupportPreflightError as exc:
        raise NextBehaviorPreparationPreflightError(
            f"historical membership receipt is invalid: {exc}"
        ) from exc
    if (
        checked_membership["artifact_sha256"] != artifact_byte_sha256
        or checked_membership["session_count"] != count
        or checked_membership["sorted_unique_membership_sha256"] == ""
        or checked_membership["source_selection_sha256"]
        != HISTORICAL_SOURCE_SELECTION_SHA256
        or checked_membership["pseudonymization_key_id"]
        != HISTORICAL_PSEUDONYMIZATION_KEY_ID
        or checked_membership["pseudonymization_key_fingerprint_sha256"]
        != HISTORICAL_PSEUDONYMIZATION_KEY_FINGERPRINT_SHA256
    ):
        raise NextBehaviorPreparationPreflightError(
            "historical membership receipt does not bind the declared artifact"
        )
    try:
        _verify_historical_test_membership_artifact(
            receipt=checked_membership,
            artifact_path=artifact_path,
            development_membership=set(),
            source_selection_sha256=checked_membership["source_selection_sha256"],
            test_source_member_membership_sha256=checked_membership[
                "test_source_member_membership_sha256"
            ],
            pseudonymization_key_id=checked_membership[
                "pseudonymization_key_id"
            ],
            pseudonymization_key_fingerprint_sha256=checked_membership[
                "pseudonymization_key_fingerprint_sha256"
            ],
            reviewed_root=SUPPORT_PREFLIGHT_ROOT,
            mount_probe=None,
        )
    except SupportPreflightError as exc:
        raise NextBehaviorPreparationPreflightError(
            f"historical membership artifact is invalid: {exc}"
        ) from exc
    return {
        "stage": PRE_STAGING_STAGE,
        "source_selection": selection_evidence,
        "source_archive_availability": archive_availability,
        "source_selection_status": "label_blind_declaration_verified",
        "declared_member_count": len(declarations),
        "declared_role_counts": dict(SUCCESSOR_ROLE_COUNTS),
        "historical_test_membership": {
            "receipt_path": str(receipt_path),
            "receipt_byte_sha256": receipt_byte_sha256,
            "artifact_path": str(artifact_path),
            "artifact_byte_sha256": artifact_byte_sha256,
            "session_count": checked_membership["session_count"],
            "role_inventory_session_membership_sha256": (
                HISTORICAL_TEST_SESSION_MEMBERSHIP_SHA256
            ),
            "verified_zero_intersection_with_pre_staging_empty_set": True,
        },
    }


def _verify_experiment_policy(
    repository_root: Path,
    value: Any,
    preprocessing: Mapping[str, Any],
) -> Dict[str, Any]:
    policy, evidence = _verify_pinned_json(
        repository_root,
        value,
        label="experiment_policy",
        expected_schema=EXPERIMENT_POLICY_SCHEMA_VERSION,
    )
    try:
        policy = require_valid_experiment_policy(policy)
    except NextBehaviorExperimentPolicyError as exc:
        raise NextBehaviorPreparationPreflightError(
            f"experiment policy is invalid: {exc}"
        ) from exc
    if policy.get("target_contract_id") != TARGET_CONTRACT_ID:
        raise NextBehaviorPreparationPreflightError(
            "experiment policy target contract is incompatible"
        )
    architecture = policy.get("architecture")
    if not isinstance(architecture, Mapping) or architecture.get(
        "maximum_sequence_length"
    ) != MAXIMUM_PHASES:
        raise NextBehaviorPreparationPreflightError(
            "experiment policy maximum sequence length is incompatible"
        )
    selection = policy.get("selection")
    authority = policy.get("authority")
    if not isinstance(selection, Mapping) or selection.get("test_metrics_used") is not False:
        raise NextBehaviorPreparationPreflightError(
            "experiment policy does not seal final/test metrics"
        )
    if (
        not isinstance(authority, Mapping)
        or authority.get("offline_experiment_only") is not True
        or authority.get("production_change_allowed") is not False
        or authority.get(
            "prediction_can_authorize_alerts_guidance_recommendations_or_actions"
        )
        is not False
    ):
        raise NextBehaviorPreparationPreflightError(
            "experiment policy authority boundary is incompatible"
        )
    if preprocessing["target_contract_id"] != policy["target_contract_id"]:
        raise NextBehaviorPreparationPreflightError(
            "experiment/preprocessing target mismatch"
        )
    evidence.update(
        {
            "target_contract_id": policy["target_contract_id"],
            "trusted_history_schema_version": preprocessing[
                "trusted_history_schema_version"
            ],
            "maximum_phases": architecture["maximum_sequence_length"],
            "test_metrics_used": False,
            "offline_experiment_only": True,
        }
    )
    return evidence


def _version_tuple(value: str, path: str) -> tuple[int, ...]:
    if not re.fullmatch(r"[0-9]+(?:\.[0-9]+)*", value):
        raise NextBehaviorPreparationPreflightError(f"{path} is not a numeric version")
    return tuple(int(item) for item in value.split("."))


def _read_meminfo(path: Path) -> Dict[str, int]:
    values: Dict[str, int] = {}
    try:
        for line in path.read_text(encoding="ascii").splitlines():
            match = re.fullmatch(r"([A-Za-z_()]+):\s+([0-9]+)\s+kB", line)
            if match:
                values[match.group(1)] = int(match.group(2)) * 1024
    except (OSError, UnicodeError) as exc:
        raise NextBehaviorPreparationPreflightError(
            "host memory capacity cannot be read"
        ) from exc
    if "MemAvailable" not in values or "SwapFree" not in values:
        raise NextBehaviorPreparationPreflightError(
            "host memory capacity is incomplete"
        )
    return values


def _verify_runtime(
    value: Any,
    *,
    required_dependencies: Sequence[Mapping[str, str]] | None = None,
    required_python: Mapping[str, str] | None = None,
) -> Dict[str, Any]:
    runtime = _require_mapping(value, _RUNTIME_FIELDS, "runtime")
    implementation = str(runtime["python_implementation"] or "").strip()
    version = str(runtime["python_version"] or "").strip()
    actual_implementation = sys.implementation.name
    actual_implementation = (
        "CPython" if actual_implementation == "cpython" else actual_implementation
    )
    actual_version = ".".join(str(item) for item in sys.version_info[:3])
    if implementation != actual_implementation or version != actual_version:
        raise NextBehaviorPreparationPreflightError(
            "Python runtime does not match the frozen requirement"
        )
    if required_python is not None:
        if set(required_python) != {"implementation", "version"}:
            raise NextBehaviorPreparationPreflightError(
                "classifier Python runtime binding is invalid"
            )
        if (
            implementation != str(required_python["implementation"]).strip()
            or version != str(required_python["version"]).strip()
        ):
            raise NextBehaviorPreparationPreflightError(
                "Python runtime does not match the classifier environment"
            )
    minimum_sqlite = str(runtime["sqlite_minimum_version"] or "").strip()
    if _version_tuple(sqlite3.sqlite_version, "sqlite runtime version") < _version_tuple(
        minimum_sqlite, "runtime.sqlite_minimum_version"
    ):
        raise NextBehaviorPreparationPreflightError(
            "SQLite runtime is older than the frozen minimum"
        )
    raw_dependencies = runtime["dependencies"]
    if not isinstance(raw_dependencies, list):
        raise NextBehaviorPreparationPreflightError("runtime.dependencies must be an array")
    dependencies: list[Dict[str, str]] = []
    names: set[str] = set()
    def normalize_distribution(name: str) -> str:
        return re.sub(r"[-_.]+", "-", name).casefold()
    for index, raw in enumerate(raw_dependencies):
        item = _require_mapping(raw, _DEPENDENCY_FIELDS, f"runtime.dependencies[{index}]")
        distribution = str(item["distribution"] or "").strip()
        expected_version = str(item["version"] or "").strip()
        normalized_distribution = normalize_distribution(distribution)
        if not distribution or not expected_version or normalized_distribution in names:
            raise NextBehaviorPreparationPreflightError(
                "runtime dependency identities are invalid"
            )
        names.add(normalized_distribution)
        try:
            actual_version_dependency = importlib.metadata.version(distribution)
        except importlib.metadata.PackageNotFoundError as exc:
            raise NextBehaviorPreparationPreflightError(
                f"required runtime dependency is missing: {distribution}"
            ) from exc
        if actual_version_dependency != expected_version:
            raise NextBehaviorPreparationPreflightError(
                f"runtime dependency version mismatch: {distribution}"
            )
        dependencies.append(
            {"distribution": distribution, "version": actual_version_dependency}
        )
    dependencies.sort(key=lambda item: item["distribution"].casefold())
    if required_dependencies is not None:
        requested = {
            normalize_distribution(item["distribution"]): item["version"]
            for item in dependencies
        }
        required = {
            normalize_distribution(str(item["distribution"])): str(item["version"])
            for item in required_dependencies
        }
        if requested != required:
            raise NextBehaviorPreparationPreflightError(
                "runtime dependencies do not exactly match the frozen dependency lock"
            )
    return {
        "python_implementation": actual_implementation,
        "python_version": actual_version,
        "python_executable": str(Path(sys.executable).resolve()),
        "sqlite_version": sqlite3.sqlite_version,
        "sqlite_minimum_version": minimum_sqlite,
        "dependencies": dependencies,
    }


def _probe_workspace(path: Path) -> None:
    try:
        mode = path.stat().st_mode
    except OSError as exc:
        raise NextBehaviorPreparationPreflightError(
            "output workspace cannot be inspected"
        ) from exc
    if mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH) == 0:
        raise NextBehaviorPreparationPreflightError("output workspace is not writable")
    statvfs = os.statvfs(path)
    if hasattr(os, "ST_RDONLY") and statvfs.f_flag & os.ST_RDONLY:
        raise NextBehaviorPreparationPreflightError("output workspace is read-only")
    probe = path / f".next-behavior-preflight-{os.getpid()}"
    descriptor: int | None = None
    try:
        descriptor = os.open(probe, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.write(descriptor, b"static-preflight\n")
        os.fsync(descriptor)
    except OSError as exc:
        raise NextBehaviorPreparationPreflightError(
            "output workspace write probe failed"
        ) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            probe.unlink()
        except FileNotFoundError:
            pass


def _reviewed_workspace(value: Any) -> tuple[Path, Path]:
    workspace = Path(str(value or "")).expanduser()
    if not workspace.is_absolute():
        raise NextBehaviorPreparationPreflightError(
            "output_workspace must be an absolute path"
        )
    if not workspace.is_dir() or workspace.is_symlink():
        raise NextBehaviorPreparationPreflightError(
            "output_workspace must be an existing non-symlink directory"
        )
    workspace = workspace.resolve()
    reviewed_root = REVIEWED_OUTPUT_ROOT
    if reviewed_root.is_symlink() or not reviewed_root.is_dir():
        raise NextBehaviorPreparationPreflightError(
            "reviewed successor workspace root is unavailable or unsafe"
        )
    reviewed_root = reviewed_root.resolve()
    try:
        workspace.relative_to(reviewed_root)
    except ValueError as exc:
        raise NextBehaviorPreparationPreflightError(
            "output_workspace is outside the reviewed successor workspace"
        ) from exc
    return workspace, reviewed_root


def _mount_identity(path: Path) -> Dict[str, Any]:
    try:
        completed = subprocess.run(
            [
                "findmnt",
                "-J",
                "-T",
                str(path),
                "-o",
                "TARGET,SOURCE,FSTYPE,OPTIONS,MAJ:MIN",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        document = json.loads(completed.stdout)
        filesystems = document.get("filesystems")
    except (OSError, subprocess.CalledProcessError, json.JSONDecodeError) as exc:
        raise NextBehaviorPreparationPreflightError(
            "output workspace mount identity cannot be verified"
        ) from exc
    if not isinstance(filesystems, list) or len(filesystems) != 1:
        raise NextBehaviorPreparationPreflightError(
            "output workspace mount identity is ambiguous"
        )
    filesystem = filesystems[0]
    if not isinstance(filesystem, Mapping):
        raise NextBehaviorPreparationPreflightError(
            "output workspace mount identity is invalid"
        )
    options = str(filesystem.get("options") or "").split(",")
    if filesystem.get("fstype") != "ext4":
        raise NextBehaviorPreparationPreflightError(
            "output workspace filesystem must be ext4"
        )
    if "ro" in options or "rw" not in options:
        raise NextBehaviorPreparationPreflightError(
            "output workspace mount must be writable"
        )
    if str(filesystem.get("target") or "") != "/mnt/honeypot-data":
        raise NextBehaviorPreparationPreflightError(
            "output workspace must use the dedicated /mnt/honeypot-data mount"
        )
    if not str(filesystem.get("source") or "").startswith("/dev/"):
        raise NextBehaviorPreparationPreflightError(
            "output workspace mount source must be a block device"
        )
    device_number = path.stat().st_dev
    observed_major_minor = f"{os.major(device_number)}:{os.minor(device_number)}"
    if str(filesystem.get("maj:min") or "") != observed_major_minor:
        raise NextBehaviorPreparationPreflightError(
            "output workspace mount device identity mismatch"
        )
    return {
        "target": str(filesystem.get("target") or ""),
        "source": str(filesystem.get("source") or ""),
        "filesystem_type": "ext4",
        "options": sorted(set(options)),
        "device_major_minor": observed_major_minor,
        "st_dev": device_number,
    }


def _verify_capacity(
    workspace: Path,
    value: Any,
    *,
    meminfo_path: Path,
) -> Dict[str, Any]:
    capacity = _require_mapping(value, _CAPACITY_FIELDS, "capacity")
    minimum_free = _require_nonnegative_integer(
        capacity["minimum_free_bytes"], "capacity.minimum_free_bytes"
    )
    minimum_memory = _require_nonnegative_integer(
        capacity["minimum_mem_available_bytes"],
        "capacity.minimum_mem_available_bytes",
    )
    minimum_swap = _require_nonnegative_integer(
        capacity["minimum_swap_free_bytes"], "capacity.minimum_swap_free_bytes"
    )
    if minimum_free < SAME_FILESYSTEM_MINIMUM_FREE_BYTES:
        raise NextBehaviorPreparationPreflightError(
            "same-filesystem staging free-space floor cannot be lowered below 60 GiB"
        )
    if minimum_memory < MINIMUM_MEM_AVAILABLE_BYTES:
        raise NextBehaviorPreparationPreflightError(
            "available-memory floor cannot be lowered below 10 GiB"
        )
    if minimum_swap < MINIMUM_SWAP_FREE_BYTES:
        raise NextBehaviorPreparationPreflightError(
            "free-swap floor cannot be lowered below 6 GiB"
        )
    mount = _mount_identity(workspace)
    reviewed_root = REVIEWED_OUTPUT_ROOT.resolve()
    if workspace.stat().st_dev != reviewed_root.stat().st_dev:
        raise NextBehaviorPreparationPreflightError(
            "output workspace and reviewed root are not on the same filesystem"
        )
    disk = shutil.disk_usage(workspace)
    memory = _read_meminfo(meminfo_path)
    if disk.free < minimum_free:
        raise NextBehaviorPreparationPreflightError(
            "output filesystem has insufficient free space"
        )
    if memory["MemAvailable"] < minimum_memory:
        raise NextBehaviorPreparationPreflightError("host has insufficient available memory")
    if memory["SwapFree"] < minimum_swap:
        raise NextBehaviorPreparationPreflightError("host has insufficient free swap")
    return {
        "filesystem": {
            "total_bytes": disk.total,
            "used_bytes": disk.used,
            "free_bytes": disk.free,
            "minimum_free_bytes": minimum_free,
            "raw_source_staging_layout": "same_filesystem",
            "mount": mount,
        },
        "memory": {
            "mem_available_bytes": memory["MemAvailable"],
            "minimum_mem_available_bytes": minimum_memory,
            "swap_free_bytes": memory["SwapFree"],
            "minimum_swap_free_bytes": minimum_swap,
        },
    }


def run_static_preflight(
    request: Mapping[str, Any],
    *,
    repository_root: Path,
    meminfo_path: Path = Path("/proc/meminfo"),
) -> Dict[str, Any]:
    """Validate static readiness and return a deterministic evidence receipt."""

    root = _require_mapping(request, _REQUEST_FIELDS, "$request")
    if root["schema_version"] != REQUEST_SCHEMA_VERSION:
        raise NextBehaviorPreparationPreflightError("request schema_version is invalid")
    repository_root = repository_root.resolve()
    if not repository_root.is_dir() or repository_root.is_symlink():
        raise NextBehaviorPreparationPreflightError("repository root is invalid")

    repository = _verify_repository(repository_root, root["repository"])
    provenance = _verify_provenance(repository_root, root["provenance"])
    classifier = _verify_classifier_environment(
        repository_root, root["classifier_environment"]
    )
    pre_staging = (
        isinstance(root["frozen_inputs"], Mapping)
        and root["frozen_inputs"].get("stage") == PRE_STAGING_STAGE
    )
    classifier_model = (
        _defer_classifier_model_for_pre_staging(root["classifier_model"])
        if pre_staging
        else _verify_classifier_model(
            repository_root,
            root["classifier_environment"],
            classifier,
            root["classifier_model"],
        )
    )
    preprocessing = _verify_preprocessing(
        repository_root, root["preprocessing"], classifier
    )
    frozen_inputs = _verify_frozen_inputs(repository_root, root["frozen_inputs"])
    experiment_policy = _verify_experiment_policy(
        repository_root, root["experiment_policy"], preprocessing
    )
    runtime = _verify_runtime(
        root["runtime"],
        required_dependencies=classifier["dependency_lock"]["pins"],
        required_python=classifier["python"],
    )

    workspace, reviewed_root = _reviewed_workspace(root["output_workspace"])
    _probe_workspace(workspace)
    capacity = _verify_capacity(workspace, root["capacity"], meminfo_path=meminfo_path)

    request_sha256 = _sha256_json(root)
    receipt: Dict[str, Any] = {
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "status": "static_preflight_passed",
        "scope": {
            "corpus_database_opened": False,
            "source_archive_opened": False,
            "source_members_ingested": 0,
            "commands_classified": 0,
            "model_trained": False,
            "model_evaluated": False,
            "preparation_authorized": False,
        },
        "request_sha256": request_sha256,
        "repository": repository,
        "provenance": provenance,
        "classifier_environment": classifier,
        "classifier_model": classifier_model,
        "preprocessing": preprocessing,
        "frozen_inputs": frozen_inputs,
        "experiment_policy": experiment_policy,
        "runtime": runtime,
        "output_workspace": {
            "path": str(workspace),
            "reviewed_root": str(reviewed_root),
            "writable": True,
            "read_only_mount": False,
        },
        "capacity": capacity,
    }
    receipt["receipt_sha256"] = _sha256_json(receipt)
    return deepcopy(receipt)


def load_preflight_request(path: Path) -> Dict[str, Any]:
    """Load a request without accepting symlinks, duplicate keys, or non-objects."""

    if path.is_symlink() or not path.is_file():
        raise NextBehaviorPreparationPreflightError(
            "static preflight request must be a regular file"
        )
    return _read_json_regular(path, "static preflight request")


def verify_static_preflight_receipt(
    value: Any,
    *,
    request: Mapping[str, Any],
    repository_root: Path,
    meminfo_path: Path = Path("/proc/meminfo"),
) -> Dict[str, Any]:
    """Fully rerun the static gate and require exact nested receipt evidence."""

    if not isinstance(value, Mapping):
        raise NextBehaviorPreparationPreflightError("preflight receipt must be an object")
    if set(value) != _RECEIPT_FIELDS:
        raise NextBehaviorPreparationPreflightError(
            "preflight receipt fields are invalid"
        )
    receipt = deepcopy(dict(value))
    digest = _require_sha256(receipt.pop("receipt_sha256", None), "receipt_sha256")
    if receipt.get("schema_version") != RECEIPT_SCHEMA_VERSION:
        raise NextBehaviorPreparationPreflightError("preflight receipt schema is invalid")
    if receipt.get("status") != "static_preflight_passed":
        raise NextBehaviorPreparationPreflightError("preflight receipt status is invalid")
    _require_sha256(receipt.get("request_sha256"), "request_sha256")
    repository = receipt.get("repository")
    if (
        not isinstance(repository, Mapping)
        or set(repository) != {"commit", "tree", "clean"}
        or repository.get("clean") is not True
    ):
        raise NextBehaviorPreparationPreflightError(
            "preflight receipt repository evidence is invalid"
        )
    _require_git_object(repository.get("commit"), "repository.commit")
    _require_git_object(repository.get("tree"), "repository.tree")
    expected_scope = {
        "corpus_database_opened": False,
        "source_archive_opened": False,
        "source_members_ingested": 0,
        "commands_classified": 0,
        "model_trained": False,
        "model_evaluated": False,
        "preparation_authorized": False,
    }
    if receipt.get("scope") != expected_scope:
        raise NextBehaviorPreparationPreflightError(
            "preflight receipt contains non-static runtime claims"
        )
    if _sha256_json(receipt) != digest:
        raise NextBehaviorPreparationPreflightError("preflight receipt SHA-256 mismatch")
    if receipt.get("request_sha256") != _sha256_json(request):
        raise NextBehaviorPreparationPreflightError(
            "preflight receipt does not bind the supplied original request"
        )
    expected = run_static_preflight(
        request,
        repository_root=repository_root,
        meminfo_path=meminfo_path,
    )
    supplied = deepcopy(receipt)
    supplied["receipt_sha256"] = digest
    supplied_capacity = supplied.get("capacity")
    expected_capacity = expected.get("capacity")
    if not isinstance(supplied_capacity, Mapping) or not isinstance(
        expected_capacity, Mapping
    ):
        raise NextBehaviorPreparationPreflightError(
            "preflight receipt nested evidence is invalid"
        )
    supplied_filesystem = supplied_capacity.get("filesystem")
    supplied_memory = supplied_capacity.get("memory")
    expected_filesystem = expected_capacity.get("filesystem")
    expected_memory = expected_capacity.get("memory")
    if not all(
        isinstance(item, Mapping)
        for item in (
            supplied_filesystem,
            supplied_memory,
            expected_filesystem,
            expected_memory,
        )
        ):
            raise NextBehaviorPreparationPreflightError(
                "preflight receipt nested evidence is invalid"
            )
    for observed, required, label in (
        (
            supplied_filesystem["free_bytes"],
            supplied_filesystem["minimum_free_bytes"],
            "capacity.filesystem.free_bytes",
        ),
        (
            supplied_memory["mem_available_bytes"],
            supplied_memory["minimum_mem_available_bytes"],
            "capacity.memory.mem_available_bytes",
        ),
        (
            supplied_memory["swap_free_bytes"],
            supplied_memory["minimum_swap_free_bytes"],
            "capacity.memory.swap_free_bytes",
        ),
    ):
        if not isinstance(observed, int) or not isinstance(required, int) or observed < required:
            raise NextBehaviorPreparationPreflightError(
                f"{label} is below its reviewed floor"
            )
    if supplied_filesystem["total_bytes"] < supplied_filesystem["used_bytes"]:
        raise NextBehaviorPreparationPreflightError(
            "capacity.filesystem total/used values are invalid"
        )
    comparison_supplied = deepcopy(supplied)
    comparison_expected = deepcopy(expected)
    for mapping, dynamic_keys in (
        (
            comparison_supplied["capacity"]["filesystem"],
            {"total_bytes", "used_bytes", "free_bytes"},
        ),
        (
            comparison_supplied["capacity"]["memory"],
            {"mem_available_bytes", "swap_free_bytes"},
        ),
        (
            comparison_expected["capacity"]["filesystem"],
            {"total_bytes", "used_bytes", "free_bytes"},
        ),
        (
            comparison_expected["capacity"]["memory"],
            {"mem_available_bytes", "swap_free_bytes"},
        ),
    ):
        for key in dynamic_keys:
            mapping.pop(key, None)
    if (
        isinstance(supplied["frozen_inputs"], Mapping)
        and supplied["frozen_inputs"].get("stage") == PRE_STAGING_STAGE
    ):
        supplied_archive = comparison_supplied["frozen_inputs"].get(
            "source_archive_availability"
        )
        expected_archive = comparison_expected["frozen_inputs"].get(
            "source_archive_availability"
        )
        if not isinstance(supplied_archive, Mapping) or not isinstance(
            expected_archive, Mapping
        ):
            raise NextBehaviorPreparationPreflightError(
                "preflight receipt source archive evidence is invalid"
            )
        for mapping in (supplied_archive, expected_archive):
            mapping.pop("http_status", None)
            mapping.pop("accept_ranges", None)
    comparison_supplied.pop("receipt_sha256", None)
    comparison_expected.pop("receipt_sha256", None)
    if comparison_supplied != comparison_expected:
        raise NextBehaviorPreparationPreflightError(
            "preflight receipt nested evidence does not match full revalidation"
        )
    # Return the persisted point-in-time receipt.  Host counters are dynamic;
    # revalidation proves their reviewed floors and static bindings without
    # replacing the original evidence with a new measurement.
    return supplied
