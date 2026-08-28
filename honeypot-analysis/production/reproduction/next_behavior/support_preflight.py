"""Development-only support preflight for a frozen successor selection.

This module deliberately does not implement source selection.  Its caller must
first pass a completed ``next_behavior_successor_member_inventory.v1`` through
the reviewed inventory validator and supply that validator here.  The split is
important: support observations must never influence which members are frozen.

The preflight may copy the six preserved *development* members from a verified
read-only selected-store donor and ingest newly admitted development gzip
members into a separate private SQLite store.  Test members are never accepted
as paths, donor members, sessions, or metrics.  Public output is an aggregate,
content-addressed ``next_behavior_support_preflight.v1`` receipt; raw commands
and private session identifiers remain in the private store.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Iterator, Mapping, Sequence

from production.prediction.next_behavior_contract import (
    TACTIC_VOCABULARY,
    TARGET_CONTRACT_ID,
    require_valid_next_behavior_session,
)
from production.prediction.next_behavior_preprocessing import (
    build_behavior_phases,
    build_model_input,
    build_model_input_from_trusted_history_manifest,
    build_next_behavior_examples,
)
from production.prediction.evidence_cutoff import make_evidence_cutoff
from production.prediction.trusted_history import (
    SCHEMA_VERSION as HISTORY_SCHEMA,
    build_prediction_trusted_history_manifest,
    validate_prediction_trusted_history_manifest,
)
from production.reproduction.next_behavior.corpus import (
    build_source_member_receipt,
)
from production.reproduction.next_behavior.safe_export import (
    _private_session_result,
)
from production.reproduction.next_behavior.source_selection_v2 import (
    require_valid_successor_member_inventory,
)
from production.reproduction.next_behavior.selected_store import (
    SelectedCorpusBuildError,
    _ingest_one_member,
    _rebuild_sessions_reference,
    _refresh_quarantine,
    _require_canonical_cached_row,
    _verify_member_files,
    open_selected_database,
)
from production.utils.serialization import stable_id, stable_json


INVENTORY_SCHEMA_VERSION = "next_behavior_successor_member_inventory.v1"
SUPPORT_PREFLIGHT_SCHEMA_VERSION = "next_behavior_support_preflight.v1"
DONOR_AUTHORIZATION_SCHEMA_VERSION = (
    "next_behavior_support_preflight_development_donor.v1"
)
DONOR_IMPORT_SCHEMA_VERSION = (
    "next_behavior_support_preflight_development_donor_import.v1"
)
DONOR_SEMANTICS_BINDING_SCHEMA_VERSION = (
    "next_behavior_support_preflight_donor_semantics_binding.v1"
)
HISTORICAL_TEST_MEMBERSHIP_SCHEMA_VERSION = (
    "historical_test_session_membership.v1"
)
SUPPORT_STORE_PURPOSE = "development_only_support_preflight"
SUPPORT_STORAGE_MOUNT = Path("/mnt/honeypot-data")
SUPPORT_PREFLIGHT_ROOT = (
    SUPPORT_STORAGE_MOUNT / "next-behavior-successor" / "support-preflight"
)
SUPPORT_MINIMUM_AVAILABLE_BYTES = 60 * 1024**3
DEVELOPMENT_ROLES = ("train", "selection", "calibration")
FORBIDDEN_ROLES = frozenset({"test", "final", "evaluation"})
MAX_TRUSTED_PHASES = 8
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PSEUDONYMOUS_SESSION_ID = re.compile(r"^nbsession_[0-9a-f]{64}$")
_FROZEN_SEMANTICS_SHA256_FIELDS = (
    "classifier_manifest_sha256",
    "classifier_source_identity_sha256",
    "classifier_environment_sha256",
    "environment_lock_sha256",
    "classifier_adapter_sha256",
    "classification_pipeline_sha256",
    "rule_policy_sha256",
    "trust_policy_sha256",
    "mitre_cache_sha256",
    "checkpoint_sha256",
    "preprocessing_sha256",
    "label_adapter_sha256",
    "source_member_inventory_sha256",
)
_FROZEN_SEMANTICS_FIELDS = frozenset(
    {
        *_FROZEN_SEMANTICS_SHA256_FIELDS,
        "target_contract_id",
        "trusted_history_schema_version",
        "max_trusted_phases",
    }
)


class SupportPreflightError(ValueError):
    """Raised before or during a support check that cannot be trusted."""


def _decode_mount_field(value: str) -> str:
    return (
        value.replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
    )


def _default_support_mount_probe(mountpoint: Path) -> Dict[str, Any]:
    try:
        lines = Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise SupportPreflightError("cannot inspect support storage mount") from exc
    for line in lines:
        fields = line.split()
        try:
            separator = fields.index("-")
        except ValueError:
            continue
        if _decode_mount_field(fields[4]) != str(mountpoint):
            continue
        statvfs = os.statvfs(mountpoint)
        return {
            "mount_target": str(mountpoint),
            "source": _decode_mount_field(fields[separator + 2]),
            "fstype": fields[separator + 1],
            "mount_options": sorted(set(fields[5].split(","))),
            "available_bytes": statvfs.f_bavail * statvfs.f_frsize,
            "writable": os.access(mountpoint, os.W_OK),
        }
    raise SupportPreflightError(
        "reviewed support storage is not a distinct mounted filesystem"
    )


def _require_support_target_storage(
    path: Path,
    *,
    reviewed_root: Path = SUPPORT_PREFLIGHT_ROOT,
    mount_probe: Callable[[Path], Mapping[str, Any]] | None = None,
) -> Dict[str, Any]:
    """Fail before target creation or private/source access on unsafe storage."""

    if reviewed_root.is_symlink() or not reviewed_root.is_dir():
        raise SupportPreflightError("reviewed support-preflight root is unavailable")
    resolved_root = reviewed_root.resolve(strict=True)
    if reviewed_root == SUPPORT_PREFLIGHT_ROOT:
        mountpoint = SUPPORT_STORAGE_MOUNT
    else:
        if mount_probe is None:
            raise SupportPreflightError(
                "non-production support root requires an explicit mount probe"
            )
        mountpoint = resolved_root
    resolved_path = path.resolve(strict=False)
    try:
        relative = resolved_path.relative_to(resolved_root)
    except ValueError as exc:
        raise SupportPreflightError(
            "support target is outside the reviewed support-preflight root"
        ) from exc
    if not relative.parts:
        raise SupportPreflightError("support target cannot be the reviewed root")
    current = resolved_root
    for part in relative.parts[:-1]:
        current = current / part
        if current.exists() or current.is_symlink():
            if current.is_symlink() or not current.is_dir():
                raise SupportPreflightError("support target path component is unsafe")
    probe = dict((mount_probe or _default_support_mount_probe)(mountpoint))
    if set(probe) != {
        "mount_target",
        "source",
        "fstype",
        "mount_options",
        "available_bytes",
        "writable",
    }:
        raise SupportPreflightError("support storage probe fields are invalid")
    options = probe["mount_options"]
    available = probe["available_bytes"]
    if (
        probe["mount_target"] != str(mountpoint)
        or not _clean(probe["source"])
        or probe["fstype"] != "ext4"
        or not isinstance(options, list)
        or "rw" not in options
        or "ro" in options
        or probe["writable"] is not True
        or isinstance(available, bool)
        or not isinstance(available, int)
        or available < SUPPORT_MINIMUM_AVAILABLE_BYTES
    ):
        raise SupportPreflightError(
            "reviewed ext4 support storage is read-only or below capacity"
        )
    return {
        "schema_version": "next_behavior_support_preflight_storage.v1",
        "status": "verified_before_private_or_source_access",
        "reviewed_root": str(resolved_root),
        "target_path": str(resolved_path),
        "mount_target": probe["mount_target"],
        "source": probe["source"],
        "fstype": "ext4",
        "mount_options": options,
        "available_bytes": available,
        "minimum_available_bytes": SUPPORT_MINIMUM_AVAILABLE_BYTES,
        "writable": True,
    }


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _sha256(value: Any, label: str) -> str:
    digest = _clean(value).lower()
    if not _SHA256.fullmatch(digest):
        raise SupportPreflightError(f"{label} must be a SHA-256 digest")
    return digest


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(stable_json(value).encode("utf-8")).hexdigest()


def _positive_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise SupportPreflightError(f"{label} must be a positive integer")
    return value


def _nonnegative_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise SupportPreflightError(f"{label} must be a non-negative integer")
    return value


def _require_frozen_semantics(value: Any, *, label: str) -> Dict[str, Any]:
    """Validate the complete, explicitly versioned support semantic identity."""

    if not isinstance(value, Mapping) or set(value) != _FROZEN_SEMANTICS_FIELDS:
        raise SupportPreflightError(f"{label} fields are invalid")
    semantics = dict(value)
    for field in _FROZEN_SEMANTICS_SHA256_FIELDS:
        semantics[field] = _sha256(semantics[field], f"{label}.{field}")
    if semantics["target_contract_id"] != TARGET_CONTRACT_ID:
        raise SupportPreflightError(f"{label} target contract is not frozen v2")
    if semantics["trusted_history_schema_version"] != HISTORY_SCHEMA:
        raise SupportPreflightError(f"{label} trusted-history schema is not v3")
    if semantics["max_trusted_phases"] != MAX_TRUSTED_PHASES:
        raise SupportPreflightError(f"{label} trusted-phase window is not eight")
    return semantics


def _require_pseudonymization_binding(
    *, key_id: Any, key_fingerprint_sha256: Any
) -> tuple[str, str]:
    fingerprint = _sha256(
        key_fingerprint_sha256, "pseudonymization_key_fingerprint_sha256"
    )
    expected_id = "next-behavior-hmac-" + fingerprint[:16]
    if _clean(key_id) != expected_id:
        raise SupportPreflightError(
            "pseudonymization key ID does not match its key fingerprint"
        )
    return expected_id, fingerprint


def _member_role(member: Mapping[str, Any]) -> str:
    return _clean(member.get("experiment_role") or member.get("role")).lower()


def _member_sha(member: Mapping[str, Any]) -> str:
    return _sha256(
        member.get("source_sha256") or member.get("sha256"),
        "source member SHA-256",
    )


def _normalized_member(member: Mapping[str, Any]) -> Dict[str, Any]:
    """Return the exact shape consumed by the canonical selected-store parser."""

    filename = _clean(member.get("filename"))
    if not filename or Path(filename).name != filename:
        raise SupportPreflightError("source member filename is unsafe")
    role = _member_role(member)
    cohort = _clean(member.get("source_cohort") or member.get("cohort")).lower()
    if role not in DEVELOPMENT_ROLES or cohort not in {"", "development"}:
        raise SupportPreflightError(
            f"support preflight forbids non-development member: {filename}"
        )
    size = member.get("source_size_bytes", member.get("size_bytes"))
    crc32 = _clean(member.get("archive_crc32")).lower()
    if not re.fullmatch(r"[0-9a-f]{8}", crc32):
        raise SupportPreflightError("source member CRC32 is invalid")
    return {
        "filename": filename,
        "sha256": _member_sha(member),
        "size_bytes": _positive_int(size, "source member size"),
        "archive_crc32": crc32,
        "chronological_order": _positive_int(
            member.get("chronological_order"), "chronological order"
        ),
        "source_cohort": "development",
        "experiment_role": role,
        "collection_date": _clean(member.get("collection_date")),
    }


def require_validated_successor_inventory(
    value: Any,
    *,
    inventory_validator: Callable[[Any], Mapping[str, Any]],
) -> Dict[str, Any]:
    """Require the external reviewed validator; never self-approve membership."""

    if not callable(inventory_validator):
        raise SupportPreflightError(
            "a reviewed successor inventory validator is required"
        )
    try:
        validated = inventory_validator(value)
    except Exception as exc:
        raise SupportPreflightError(
            f"successor inventory validation failed: {type(exc).__name__}"
        ) from exc
    if not isinstance(validated, Mapping):
        raise SupportPreflightError("successor inventory validator returned no object")
    inventory = dict(validated)
    if stable_json(inventory) != stable_json(value):
        raise SupportPreflightError(
            "successor inventory validator output differs from its input"
        )
    try:
        inventory = require_valid_successor_member_inventory(inventory)
    except Exception as exc:
        raise SupportPreflightError(
            f"canonical successor inventory validation failed: {type(exc).__name__}"
        ) from exc
    members = inventory.get("members")
    if not isinstance(members, list) or not members:
        raise SupportPreflightError("successor inventory members are unavailable")
    _sha256(
        inventory.get("source_selection_sha256"),
        "successor inventory source_selection_sha256",
    )
    filenames: set[str] = set()
    orders: set[int] = set()
    for raw in members:
        if not isinstance(raw, Mapping):
            raise SupportPreflightError("successor inventory member is invalid")
        filename = _clean(raw.get("filename"))
        order = _positive_int(raw.get("chronological_order"), "chronological order")
        _member_sha(raw)
        if not filename or Path(filename).name != filename:
            raise SupportPreflightError("successor inventory filename is unsafe")
        if filename in filenames or order in orders:
            raise SupportPreflightError("successor inventory membership is duplicated")
        role = _member_role(raw)
        if role not in {*DEVELOPMENT_ROLES, "test"}:
            raise SupportPreflightError("successor inventory role is unknown")
        filenames.add(filename)
        orders.add(order)
    return inventory


def _inventory_identity(inventory: Mapping[str, Any]) -> tuple[str, str]:
    inventory_id = _clean(
        inventory.get("inventory_id") or inventory.get("receipt_id")
    )
    if not inventory_id:
        raise SupportPreflightError("successor inventory identity is missing")
    return inventory_id, _sha256_json(dict(inventory))


def _inventory_development_members(
    inventory: Mapping[str, Any],
) -> Dict[str, Dict[str, Any]]:
    output: Dict[str, Dict[str, Any]] = {}
    for raw in inventory["members"]:
        if _member_role(raw) == "test":
            continue
        member = _normalized_member(raw)
        output[member["filename"]] = member
    return output


def _require_safe_immutable_side_files(path: Path) -> Dict[str, Any]:
    """Allow only a clean zero-WAL immutable donor snapshot.

    SQLite can leave a zero-length WAL and its shared-memory index behind
    after a clean close.  Those files contain no uncheckpointed transaction.
    A non-empty WAL, any rollback journal, a side-file symlink, or an SHM file
    without the corresponding zero-byte WAL remains fail-closed.  This check
    is read-only and never checkpoints or removes donor files.
    """

    if not path.is_file() or path.is_symlink():
        raise SupportPreflightError("development donor database is missing or unsafe")
    side_paths = {
        "wal": Path(str(path) + "-wal"),
        "shm": Path(str(path) + "-shm"),
        "rollback_journal": Path(str(path) + "-journal"),
    }
    side: Dict[str, tuple[bool, int]] = {}
    for name, side_path in side_paths.items():
        if side_path.is_symlink():
            raise SupportPreflightError(
                f"development donor {name} side file is unsafe"
            )
        exists = side_path.exists()
        size = side_path.stat().st_size if exists else 0
        side[name] = (exists, size)
    wal_exists, wal_size = side["wal"]
    shm_exists, shm_size = side["shm"]
    journal_exists, _journal_size = side["rollback_journal"]
    if wal_exists and wal_size != 0:
        raise SupportPreflightError(
            "development donor has a non-empty uncheckpointed WAL"
        )
    if journal_exists:
        raise SupportPreflightError(
            "development donor has a rollback journal"
        )
    if shm_exists and (not wal_exists or wal_size != 0):
        raise SupportPreflightError(
            "development donor SHM is not paired with an empty WAL"
        )
    return {
        "main_database_size_bytes": path.stat().st_size,
        "wal_exists": wal_exists,
        "wal_size_bytes": wal_size,
        "shm_exists": shm_exists,
        "shm_size_bytes": shm_size,
        "rollback_journal_exists": False,
        "immutable_main_database_quick_check": "pending",
    }


def require_valid_development_donor_semantics_binding(
    value: Any,
) -> Dict[str, Any]:
    """Validate the separately reviewed binding for legacy donor provenance.

    Historical classification/preparation receipts predate some identities in
    the frozen successor tuple.  Those identities must be stated explicitly in
    this content-addressed receipt; the importer never infers them from a path,
    commit, or related-but-different environment digest.
    """

    fields = {
        "schema_version",
        "receipt_id",
        "status",
        "donor_source_selection_sha256",
        "donor_preparation_receipt_sha256",
        "donor_classification_receipt_sha256",
        "frozen_semantics",
        "test_members_accessed",
        "raw_content_emitted",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise SupportPreflightError("donor semantics-binding fields are invalid")
    receipt = dict(value)
    if (
        receipt["schema_version"] != DONOR_SEMANTICS_BINDING_SCHEMA_VERSION
        or receipt["status"] != "reviewed_immutable_semantics_binding"
        or receipt["test_members_accessed"] is not False
        or receipt["raw_content_emitted"] is not False
    ):
        raise SupportPreflightError("donor semantics-binding state is invalid")
    for field in (
        "donor_source_selection_sha256",
        "donor_preparation_receipt_sha256",
        "donor_classification_receipt_sha256",
    ):
        receipt[field] = _sha256(receipt[field], field)
    receipt["frozen_semantics"] = _require_frozen_semantics(
        receipt["frozen_semantics"], label="donor_semantics_binding.frozen_semantics"
    )
    basis = dict(receipt)
    receipt_id = basis.pop("receipt_id")
    if receipt_id != stable_id("nextbehaviorsupportdonorsemantics", basis):
        raise SupportPreflightError("donor semantics-binding identity is invalid")
    return receipt


def build_development_donor_semantics_binding(
    *,
    donor_source_selection_sha256: str,
    donor_preparation_receipt_sha256: str,
    donor_classification_receipt_sha256: str,
    frozen_semantics: Mapping[str, Any],
) -> Dict[str, Any]:
    """Build the immutable semantics assertion reviewed before donor import."""

    receipt: Dict[str, Any] = {
        "schema_version": DONOR_SEMANTICS_BINDING_SCHEMA_VERSION,
        "status": "reviewed_immutable_semantics_binding",
        "donor_source_selection_sha256": _sha256(
            donor_source_selection_sha256, "donor_source_selection_sha256"
        ),
        "donor_preparation_receipt_sha256": _sha256(
            donor_preparation_receipt_sha256,
            "donor_preparation_receipt_sha256",
        ),
        "donor_classification_receipt_sha256": _sha256(
            donor_classification_receipt_sha256,
            "donor_classification_receipt_sha256",
        ),
        "frozen_semantics": _require_frozen_semantics(
            frozen_semantics, label="frozen_semantics"
        ),
        "test_members_accessed": False,
        "raw_content_emitted": False,
    }
    receipt["receipt_id"] = stable_id(
        "nextbehaviorsupportdonorsemantics", receipt
    )
    return require_valid_development_donor_semantics_binding(receipt)


def _load_donor_authorization(value: Any) -> Dict[str, Any]:
    fields = {
        "schema_version",
        "authorization_id",
        "donor_source_selection_sha256",
        "donor_preparation_receipt_id",
        "donor_preparation_receipt_sha256",
        "donor_classification_receipt_sha256",
        "donor_semantics_binding_receipt_sha256",
        "allowed_development_members",
        "frozen_semantics",
        "test_members_authorized",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise SupportPreflightError("development donor authorization fields are invalid")
    authorization = dict(value)
    if authorization["schema_version"] != DONOR_AUTHORIZATION_SCHEMA_VERSION:
        raise SupportPreflightError("development donor authorization schema is invalid")
    if authorization["test_members_authorized"] is not False:
        raise SupportPreflightError("test members cannot be authorized for preflight")
    for field in (
        "donor_source_selection_sha256",
        "donor_preparation_receipt_sha256",
        "donor_classification_receipt_sha256",
        "donor_semantics_binding_receipt_sha256",
    ):
        _sha256(authorization[field], field)
    members = authorization["allowed_development_members"]
    if (
        not isinstance(members, list)
        or len(members) != 6
        or len(set(members)) != 6
        or any(not _clean(name) or Path(_clean(name)).name != _clean(name) for name in members)
    ):
        raise SupportPreflightError(
            "donor authorization must name exactly six development members"
        )
    authorization["frozen_semantics"] = _require_frozen_semantics(
        authorization["frozen_semantics"], label="frozen_semantics"
    )
    basis = dict(authorization)
    authorization_id = basis.pop("authorization_id")
    if authorization_id != stable_id("nextbehaviorsupportdonor", basis):
        raise SupportPreflightError("development donor authorization identity is invalid")
    return authorization


def build_development_donor_authorization(
    *,
    donor_source_selection_sha256: str,
    donor_preparation_receipt_id: str,
    donor_preparation_receipt_sha256: str,
    donor_classification_receipt_sha256: str,
    donor_semantics_binding_receipt_sha256: str,
    allowed_development_members: Sequence[str],
    frozen_semantics: Mapping[str, Any],
) -> Dict[str, Any]:
    """Create the content-addressed authorization consumed by donor import."""

    basis: Dict[str, Any] = {
        "schema_version": DONOR_AUTHORIZATION_SCHEMA_VERSION,
        "donor_source_selection_sha256": _sha256(
            donor_source_selection_sha256, "donor_source_selection_sha256"
        ),
        "donor_preparation_receipt_id": _clean(donor_preparation_receipt_id),
        "donor_preparation_receipt_sha256": _sha256(
            donor_preparation_receipt_sha256,
            "donor_preparation_receipt_sha256",
        ),
        "donor_classification_receipt_sha256": _sha256(
            donor_classification_receipt_sha256,
            "donor_classification_receipt_sha256",
        ),
        "donor_semantics_binding_receipt_sha256": _sha256(
            donor_semantics_binding_receipt_sha256,
            "donor_semantics_binding_receipt_sha256",
        ),
        "allowed_development_members": sorted(
            _clean(item) for item in allowed_development_members
        ),
        "frozen_semantics": dict(frozen_semantics),
        "test_members_authorized": False,
    }
    if not basis["donor_preparation_receipt_id"]:
        raise SupportPreflightError("donor preparation receipt ID is required")
    value = {
        **basis,
        "authorization_id": stable_id("nextbehaviorsupportdonor", basis),
    }
    return _load_donor_authorization(value)


def require_valid_development_donor_import(value: Any) -> Dict[str, Any]:
    fields = {
        "schema_version",
        "import_id",
        "status",
        "authorization_id",
        "source_member_count",
        "source_members_sha256",
        "unique_commands_imported",
        "donor_semantics_binding_receipt_sha256",
        "donor_side_files",
        "query_isolation",
        "test_members_accessed",
        "test_metrics_used",
        "raw_content_emitted",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise SupportPreflightError("development donor import fields are invalid")
    document = dict(value)
    if (
        document["schema_version"] != DONOR_IMPORT_SCHEMA_VERSION
        or document["status"] != "verified_development_only_import"
        or not _clean(document["authorization_id"])
        or document["source_member_count"] != 6
        or not _SHA256.fullmatch(_clean(document["source_members_sha256"]))
        or not _SHA256.fullmatch(
            _clean(document["donor_semantics_binding_receipt_sha256"])
        )
        or isinstance(document["unique_commands_imported"], bool)
        or not isinstance(document["unique_commands_imported"], int)
        or document["unique_commands_imported"] < 0
        or document["test_members_accessed"] is not False
        or document["test_metrics_used"] is not False
        or document["raw_content_emitted"] is not False
    ):
        raise SupportPreflightError("development donor import is invalid")
    side = document["donor_side_files"]
    if (
        not isinstance(side, Mapping)
        or set(side)
        != {
            "main_database_size_bytes",
            "wal_exists",
            "wal_size_bytes",
            "shm_exists",
            "shm_size_bytes",
            "rollback_journal_exists",
            "immutable_main_database_quick_check",
        }
        or isinstance(side.get("main_database_size_bytes"), bool)
        or not isinstance(side.get("main_database_size_bytes"), int)
        or side.get("main_database_size_bytes", 0) < 1
        or type(side.get("wal_exists")) is not bool
        or isinstance(side.get("wal_size_bytes"), bool)
        or not isinstance(side.get("wal_size_bytes"), int)
        or side.get("wal_size_bytes", -1) != 0
        or type(side.get("shm_exists")) is not bool
        or isinstance(side.get("shm_size_bytes"), bool)
        or not isinstance(side.get("shm_size_bytes"), int)
        or side.get("shm_size_bytes", -1) < 0
        or side.get("rollback_journal_exists") is not False
        or side.get("immutable_main_database_quick_check") != "ok"
        or (side.get("shm_exists") is True and side.get("wal_exists") is not True)
    ):
        raise SupportPreflightError("development donor side-file evidence is invalid")
    isolation = document["query_isolation"]
    if (
        not isinstance(isolation, Mapping)
        or set(isolation)
        != {
            "selection_scope",
            "authorized_development_members",
            "session_sources_copied",
            "command_events_copied",
            "context_events_copied",
            "command_labels_copied",
            "test_rows_selected",
        }
        or isolation.get("selection_scope")
        != "authorized_development_members_and_roles_only"
        or isolation.get("authorized_development_members") != 6
        or any(
            isinstance(isolation.get(field), bool)
            or not isinstance(isolation.get(field), int)
            or isolation.get(field, -1) < 0
            for field in (
                "session_sources_copied",
                "command_events_copied",
                "context_events_copied",
                "command_labels_copied",
            )
        )
        or isolation.get("test_rows_selected") != 0
        or isolation.get("command_labels_copied")
        != document["unique_commands_imported"]
    ):
        raise SupportPreflightError("development donor query isolation is invalid")
    basis = dict(document)
    import_id = basis.pop("import_id")
    if import_id != stable_id("nextbehaviorsupportdonorimport", basis):
        raise SupportPreflightError("development donor import identity is invalid")
    return document


def _receipt_by_sha(
    database: sqlite3.Connection,
    table: str,
    column: str,
    expected_sha256: str,
) -> Dict[str, Any]:
    try:
        rows = database.execute(f"SELECT {column} FROM {table}")
    except sqlite3.Error as exc:
        raise SupportPreflightError(f"donor {table} is unavailable") from exc
    matches: list[Dict[str, Any]] = []
    for row in rows:
        try:
            receipt = json.loads(str(row[0]))
        except json.JSONDecodeError as exc:
            raise SupportPreflightError(f"donor {table} receipt is malformed") from exc
        if _sha256_json(receipt) == expected_sha256:
            matches.append(receipt)
    if len(matches) != 1:
        raise SupportPreflightError(f"donor {table} receipt identity is unavailable")
    return matches[0]


def import_verified_development_donor(
    *,
    donor_database_path: Path,
    target_database_path: Path,
    successor_inventory: Mapping[str, Any],
    inventory_validator: Callable[[Any], Mapping[str, Any]],
    donor_authorization: Mapping[str, Any],
    donor_semantics_binding_receipt: Mapping[str, Any],
    reviewed_root: Path = SUPPORT_PREFLIGHT_ROOT,
    mount_probe: Callable[[Path], Mapping[str, Any]] | None = None,
) -> Dict[str, Any]:
    """Copy only six authorized development members from an immutable donor.

    No query references a test member or a test role.  Classification rows are
    fetched only after the exact development command membership has been copied
    into the target store.
    """

    inventory = require_validated_successor_inventory(
        successor_inventory, inventory_validator=inventory_validator
    )
    development = _inventory_development_members(inventory)
    authorization = _load_donor_authorization(donor_authorization)
    semantics_binding = require_valid_development_donor_semantics_binding(
        donor_semantics_binding_receipt
    )
    semantics_binding_sha256 = _sha256_json(semantics_binding)
    if (
        semantics_binding_sha256
        != authorization["donor_semantics_binding_receipt_sha256"]
        or semantics_binding["donor_source_selection_sha256"]
        != authorization["donor_source_selection_sha256"]
        or semantics_binding["donor_preparation_receipt_sha256"]
        != authorization["donor_preparation_receipt_sha256"]
        or semantics_binding["donor_classification_receipt_sha256"]
        != authorization["donor_classification_receipt_sha256"]
        or semantics_binding["frozen_semantics"]
        != authorization["frozen_semantics"]
    ):
        raise SupportPreflightError(
            "donor semantics binding is not authorized"
        )
    allowed_names = sorted(_clean(item) for item in authorization["allowed_development_members"])
    if any(name not in development for name in allowed_names):
        raise SupportPreflightError("donor member is absent from successor inventory")
    _require_support_target_storage(
        target_database_path,
        reviewed_root=reviewed_root,
        mount_probe=mount_probe,
    )
    if target_database_path.is_symlink():
        raise SupportPreflightError("support target database cannot be a symlink")
    donor_resolved = donor_database_path.resolve(strict=False)
    target_resolved = target_database_path.resolve(strict=False)
    if donor_resolved == target_resolved:
        raise SupportPreflightError("development donor and support target are identical")
    if target_database_path.exists():
        try:
            if os.path.samefile(donor_database_path, target_database_path):
                raise SupportPreflightError(
                    "development donor and support target are the same inode"
                )
        except OSError as exc:
            raise SupportPreflightError(
                "cannot prove donor/target filesystem separation"
            ) from exc
        raise SupportPreflightError(
            "support target must be absent before donor import"
        )
    side_file_evidence = _require_safe_immutable_side_files(donor_database_path)
    donor = sqlite3.connect(
        f"file:{donor_database_path.resolve().as_posix()}?mode=ro&immutable=1",
        uri=True,
    )
    target = open_selected_database(target_database_path)
    try:
        quick = _clean(donor.execute("PRAGMA quick_check").fetchone()[0])
        if quick != "ok":
            raise SupportPreflightError("development donor SQLite quick_check failed")
        side_file_evidence["immutable_main_database_quick_check"] = "ok"
        metadata = dict(
            donor.execute(
                "SELECT key, value FROM metadata WHERE key IN "
                "('source_selection_sha256', "
                "'final_corpus_preparation_receipt_id', "
                "'final_corpus_preparation_receipt_json')"
            )
        )
        if metadata.get("source_selection_sha256") != authorization[
            "donor_source_selection_sha256"
        ]:
            raise SupportPreflightError("donor source-selection binding is inconsistent")
        try:
            preparation = json.loads(metadata["final_corpus_preparation_receipt_json"])
        except (KeyError, json.JSONDecodeError) as exc:
            raise SupportPreflightError("donor preparation receipt is unavailable") from exc
        if (
            metadata.get("final_corpus_preparation_receipt_id")
            != authorization["donor_preparation_receipt_id"]
            or _sha256_json(preparation)
            != authorization["donor_preparation_receipt_sha256"]
        ):
            raise SupportPreflightError("donor preparation receipt is inconsistent")
        classification = _receipt_by_sha(
            donor,
            "classification_cache_receipts",
            "receipt_json",
            authorization["donor_classification_receipt_sha256"],
        )
        semantics = authorization["frozen_semantics"]
        for receipt_field, semantic_field in (
            ("classifier_manifest_sha256", "classifier_manifest_sha256"),
            ("checkpoint_sha256", "checkpoint_sha256"),
            ("rule_policy_sha256", "rule_policy_sha256"),
            ("trust_policy_sha256", "trust_policy_sha256"),
            ("label_adapter_sha256", "label_adapter_sha256"),
            ("ingested_source_members_sha256", "source_member_inventory_sha256"),
        ):
            if not _clean(classification.get(receipt_field)):
                raise SupportPreflightError(
                    f"donor classification {receipt_field} is missing"
                )
            if classification[receipt_field] != semantics[semantic_field]:
                raise SupportPreflightError(
                    f"donor classification {receipt_field} is inconsistent"
                )
        for receipt_field, semantic_field in (
            ("classifier_manifest_sha256", "classifier_manifest_sha256"),
            ("classifier_adapter_sha256", "classifier_adapter_sha256"),
            ("classification_pipeline_sha256", "classification_pipeline_sha256"),
            ("preprocessing_sha256", "preprocessing_sha256"),
            ("environment_lock_sha256", "environment_lock_sha256"),
            ("label_policy_sha256", "rule_policy_sha256"),
            ("trust_policy_sha256", "trust_policy_sha256"),
            ("mitre_cache_sha256", "mitre_cache_sha256"),
            ("classification_checkpoint_sha256", "checkpoint_sha256"),
        ):
            if not _clean(preparation.get(receipt_field)):
                raise SupportPreflightError(
                    f"donor preparation {receipt_field} is missing"
                )
            if preparation[receipt_field] != semantics[semantic_field]:
                raise SupportPreflightError(
                    f"donor preparation {receipt_field} is inconsistent"
                )
        if (
            classification.get("source_selection_sha256")
            != authorization["donor_source_selection_sha256"]
            or classification.get("raw_content_emitted") is not False
            or not _clean(classification.get("cache_receipt_id"))
        ):
            raise SupportPreflightError(
                "donor classification receipt safety binding is inconsistent"
            )

        placeholders = ",".join("?" for _ in allowed_names)
        rows = list(
            donor.execute(
                "SELECT filename, source_sha256, source_size_bytes, "
                "archive_crc32, chronological_order, source_cohort, "
                "experiment_role, collection_start, collection_end, stats_json "
                f"FROM source_members WHERE filename IN ({placeholders}) "
                "AND source_cohort = 'development' "
                "AND experiment_role IN ('train', 'selection', 'calibration') "
                "ORDER BY chronological_order",
                allowed_names,
            )
        )
        if len(rows) != 6 or sorted(str(row[0]) for row in rows) != allowed_names:
            raise SupportPreflightError("donor development membership is incomplete")
        successor_rows: list[tuple[Any, ...]] = []
        for row in rows:
            expected = development[str(row[0])]
            if (
                str(row[1]) != expected["sha256"]
                or int(row[2]) != expected["size_bytes"]
                or str(row[3]) != expected["archive_crc32"]
                or str(row[5]) != "development"
                or str(row[6]) != expected["experiment_role"]
            ):
                raise SupportPreflightError(
                    f"donor source receipt mismatch: {row[0]}"
                )
            # The six preserved members keep their bytes and semantic roles,
            # while their ordinal positions legitimately change when the
            # label-blind calendar blocks are inserted around them.
            successor_rows.append(
                (*row[:4], expected["chronological_order"], *row[5:])
            )

        target.execute("BEGIN IMMEDIATE")
        if target.execute("SELECT COUNT(*) FROM source_members").fetchone()[0]:
            raise SupportPreflightError("support target must be empty before donor import")
        target.execute(
            "INSERT OR REPLACE INTO metadata(key, value) VALUES (?, ?)",
            (
                "source_selection_sha256",
                inventory["source_selection_sha256"],
            ),
        )
        target.execute(
            "INSERT OR REPLACE INTO metadata(key, value) VALUES (?, ?)",
            ("store_purpose", SUPPORT_STORE_PURPOSE),
        )
        target.executemany(
            "INSERT INTO source_members VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            successor_rows,
        )
        copy_counts: Counter[str] = Counter()
        for table, columns in (
            (
                "session_sources",
                "raw_session_id, source_member, source_cohort, experiment_role, "
                "chronological_order, first_seen, last_seen, protocol, configuration, "
                "connected, closed",
            ),
            (
                "command_events",
                "source_member, source_line, raw_session_id, event_time, command",
            ),
            (
                "context_events",
                "source_member, source_line, raw_session_id, event_time, event_type",
            ),
        ):
            direct_role_predicate = (
                "AND records.source_cohort = 'development' "
                "AND records.experiment_role IN "
                "('train', 'selection', 'calibration') "
                if table == "session_sources"
                else ""
            )
            donor_cursor = donor.execute(
                f"SELECT {columns} FROM {table} AS records "
                f"WHERE records.source_member IN ({placeholders}) "
                "AND EXISTS (SELECT 1 FROM source_members AS allowed_member "
                " WHERE allowed_member.filename = records.source_member "
                "   AND allowed_member.source_cohort = 'development' "
                "   AND allowed_member.experiment_role IN "
                "       ('train', 'selection', 'calibration')) "
                f"{direct_role_predicate}",
                allowed_names,
            )
            width = len(columns.split(","))
            insert_sql = f"INSERT INTO {table}({columns}) VALUES ({','.join('?' for _ in range(width))})"
            while True:
                batch = donor_cursor.fetchmany(1_000)
                if not batch:
                    break
                if table == "session_sources":
                    batch = [
                        (
                            *row[:4],
                            development[str(row[1])]["chronological_order"],
                            *row[5:],
                        )
                        for row in batch
                    ]
                target.executemany(insert_sql, batch)
                copy_counts[table] += len(batch)

        target_leakage = target.execute(
            "SELECT "
            "(SELECT COUNT(*) FROM source_members "
            "  WHERE source_cohort != 'development' OR experiment_role NOT IN "
            "  ('train', 'selection', 'calibration')), "
            "(SELECT COUNT(*) FROM session_sources "
            "  WHERE source_cohort != 'development' OR experiment_role NOT IN "
            "  ('train', 'selection', 'calibration') "
            f"  OR source_member NOT IN ({placeholders})), "
            "(SELECT COUNT(*) FROM command_events "
            f"  WHERE source_member NOT IN ({placeholders})), "
            "(SELECT COUNT(*) FROM context_events "
            f"  WHERE source_member NOT IN ({placeholders}))",
            (*allowed_names, *allowed_names, *allowed_names),
        ).fetchone()
        if target_leakage is None or any(int(value) for value in target_leakage):
            raise SupportPreflightError(
                "development donor query selected a forbidden row"
            )

        commands = [
            str(row[0])
            for row in target.execute(
                "SELECT DISTINCT command FROM command_events ORDER BY command"
            )
        ]
        imported_labels = 0
        for offset in range(0, len(commands), 500):
            batch = commands[offset : offset + 500]
            marks = ",".join("?" for _ in batch)
            label_rows = list(
                donor.execute(
                    "SELECT command, labels_json, unrepresented_json, cache_receipt_id "
                    f"FROM command_labels WHERE command IN ({marks}) ORDER BY command",
                    batch,
                )
            )
            for row in label_rows:
                _require_canonical_cached_row(
                    str(row[1]),
                    str(row[2]),
                    rule_policy_sha256=semantics["rule_policy_sha256"],
                    trust_policy_sha256=semantics["trust_policy_sha256"],
                    checkpoint_sha256=semantics["checkpoint_sha256"],
                )
            target.executemany(
                "INSERT INTO command_labels(command, labels_json, "
                "unrepresented_json, cache_receipt_id) VALUES (?, ?, ?, ?)",
                label_rows,
            )
            imported_labels += len(label_rows)
        target.execute(
            "INSERT INTO classification_cache_receipts(cache_receipt_id, receipt_json) "
            "VALUES (?, ?)",
            (_clean(classification.get("cache_receipt_id")), stable_json(classification)),
        )
        _rebuild_sessions_reference(target)
        _refresh_quarantine(target)
        result: Dict[str, Any] = {
            "schema_version": DONOR_IMPORT_SCHEMA_VERSION,
            "status": "verified_development_only_import",
            "authorization_id": authorization["authorization_id"],
            "source_member_count": 6,
            "source_members_sha256": _sha256_json(allowed_names),
            "unique_commands_imported": imported_labels,
            "donor_semantics_binding_receipt_sha256": semantics_binding_sha256,
            "donor_side_files": side_file_evidence,
            "query_isolation": {
                "selection_scope": "authorized_development_members_and_roles_only",
                "authorized_development_members": 6,
                "session_sources_copied": copy_counts["session_sources"],
                "command_events_copied": copy_counts["command_events"],
                "context_events_copied": copy_counts["context_events"],
                "command_labels_copied": imported_labels,
                "test_rows_selected": 0,
            },
            "test_members_accessed": False,
            "test_metrics_used": False,
            "raw_content_emitted": False,
        }
        result["import_id"] = stable_id("nextbehaviorsupportdonorimport", result)
        checked_result = require_valid_development_donor_import(result)
        target.execute(
            "INSERT OR REPLACE INTO metadata(key, value) VALUES (?, ?)",
            ("support_donor_import_receipt_json", stable_json(checked_result)),
        )
        target.execute(
            "INSERT OR REPLACE INTO metadata(key, value) VALUES (?, ?)",
            ("support_donor_import_receipt_sha256", _sha256_json(checked_result)),
        )
        target.commit()
        return checked_result
    except (sqlite3.Error, ValueError) as exc:
        target.rollback()
        if isinstance(exc, SupportPreflightError):
            raise
        raise SupportPreflightError(str(exc)) from exc
    finally:
        target.close()
        donor.close()


def ingest_new_development_members(
    *,
    private_database_path: Path,
    raw_directory: Path,
    successor_inventory: Mapping[str, Any],
    inventory_validator: Callable[[Any], Mapping[str, Any]],
    new_member_names: Sequence[str],
    source_selection_sha256: str,
    flush_size: int = 10_000,
    reviewed_root: Path = SUPPORT_PREFLIGHT_ROOT,
    mount_probe: Callable[[Path], Mapping[str, Any]] | None = None,
) -> Dict[str, Any]:
    """Ingest exactly the predeclared new development members, never test data."""

    inventory = require_validated_successor_inventory(
        successor_inventory, inventory_validator=inventory_validator
    )
    development = _inventory_development_members(inventory)
    names = [_clean(name) for name in new_member_names]
    if len(names) != len(set(names)) or not names:
        raise SupportPreflightError("new development membership is empty or duplicated")
    if any(name not in development for name in names):
        # Fail before resolving or opening any path.
        raise SupportPreflightError("new member list contains a test or unknown member")
    _require_support_target_storage(
        private_database_path,
        reviewed_root=reviewed_root,
        mount_probe=mount_probe,
    )
    members = [development[name] for name in names]
    if private_database_path.is_symlink():
        raise SupportPreflightError("support store path cannot be a symlink")
    database = open_selected_database(private_database_path)
    try:
        donor_metadata = dict(
            database.execute(
                "SELECT key, value FROM metadata WHERE key IN "
                "('support_donor_import_receipt_json', "
                "'support_donor_import_receipt_sha256', 'store_purpose')"
            )
        )
        try:
            donor_import = require_valid_development_donor_import(
                json.loads(donor_metadata["support_donor_import_receipt_json"])
            )
        except (KeyError, json.JSONDecodeError) as exc:
            raise SupportPreflightError(
                "support store has no verified donor-import lineage"
            ) from exc
        donor_import_sha256 = _sha256_json(donor_import)
        if (
            donor_metadata.get("support_donor_import_receipt_sha256")
            != donor_import_sha256
            or donor_metadata.get("store_purpose") != SUPPORT_STORE_PURPOSE
        ):
            raise SupportPreflightError(
                "support donor-import lineage is inconsistent"
            )
        existing_development = {
            str(row[0])
            for row in database.execute(
                "SELECT filename FROM source_members WHERE experiment_role IN "
                "('train', 'selection', 'calibration')"
            )
        }
        if existing_development & set(names):
            raise SupportPreflightError(
                "new development membership overlaps the prepared donor"
            )
        if existing_development | set(names) != set(development):
            raise SupportPreflightError(
                "donor plus new members do not cover the frozen development inventory"
            )
        authorized_donor_names = sorted(existing_development)
        if (
            len(authorized_donor_names) != donor_import["source_member_count"]
            or _sha256_json(authorized_donor_names)
            != donor_import["source_members_sha256"]
        ):
            raise SupportPreflightError(
                "support donor source membership differs from its import receipt"
            )
        existing_rows = list(
            database.execute(
                "SELECT filename, source_sha256, source_size_bytes, archive_crc32, "
                "chronological_order, source_cohort, experiment_role "
                "FROM source_members ORDER BY chronological_order"
            )
        )
        if len(existing_rows) != len(authorized_donor_names):
            raise SupportPreflightError(
                "support store contains a source member outside donor authorization"
            )
        for row in existing_rows:
            expected = development.get(str(row[0]))
            if expected is None or (
                str(row[1]) != expected["sha256"]
                or int(row[2]) != expected["size_bytes"]
                or str(row[3]) != expected["archive_crc32"]
                or int(row[4]) != expected["chronological_order"]
                or str(row[5]) != "development"
                or str(row[6]) != expected["experiment_role"]
            ):
                raise SupportPreflightError(
                    f"support donor source receipt mismatch: {row[0]}"
                )
        placeholders_existing = ",".join("?" for _ in authorized_donor_names)
        leakage = database.execute(
            "SELECT "
            "(SELECT COUNT(*) FROM session_sources WHERE source_member NOT IN ("
            + placeholders_existing
            + ")), "
            "(SELECT COUNT(*) FROM command_events WHERE source_member NOT IN ("
            + placeholders_existing
            + ")), "
            "(SELECT COUNT(*) FROM context_events WHERE source_member NOT IN ("
            + placeholders_existing
            + "))",
            (*authorized_donor_names, *authorized_donor_names, *authorized_donor_names),
        ).fetchone()
        if leakage is None or any(int(value) for value in leakage):
            raise SupportPreflightError(
                "support donor store contains rows outside its authorized members"
            )
        try:
            verified = _verify_member_files(members, raw_directory)
        except SelectedCorpusBuildError as exc:
            raise SupportPreflightError(str(exc)) from exc
        selection_hash = _sha256(source_selection_sha256, "source_selection_sha256")
        if selection_hash != inventory["source_selection_sha256"]:
            raise SupportPreflightError(
                "support store selection does not match successor inventory"
            )
        existing = database.execute(
            "SELECT value FROM metadata WHERE key = 'source_selection_sha256'"
        ).fetchone()
        if existing is None:
            database.execute(
                "INSERT INTO metadata(key, value) VALUES (?, ?)",
                ("source_selection_sha256", selection_hash),
            )
            database.execute(
                "INSERT INTO metadata(key, value) VALUES (?, ?)",
                ("store_purpose", SUPPORT_STORE_PURPOSE),
            )
            database.commit()
        elif str(existing[0]) != selection_hash:
            raise SupportPreflightError("support store selection binding changed")
        if database.execute(
            "SELECT COUNT(*) FROM source_members WHERE experiment_role = 'test'"
        ).fetchone()[0]:
            raise SupportPreflightError("support store contains forbidden test members")
        results = []
        instrumentation: Counter[str] = Counter()
        for member in members:
            results.append(
                _ingest_one_member(
                    database,
                    member,
                    verified[member["filename"]],
                    flush_size=flush_size,
                    instrumentation=instrumentation,
                )
            )
        _refresh_quarantine(database)
        return {
            "status": "development_members_ingested",
            "member_count": len(results),
            "member_results": results,
            "instrumentation": dict(sorted(instrumentation.items())),
            "test_members_accessed": False,
            "test_metrics_used": False,
            "raw_content_emitted": False,
        }
    except (sqlite3.Error, ValueError) as exc:
        database.rollback()
        if isinstance(exc, SupportPreflightError):
            raise
        raise SupportPreflightError(str(exc)) from exc
    finally:
        database.close()


def iter_development_safe_sessions(
    *,
    private_database_path: Path,
    pseudonymization_key: bytes,
    pseudonymization_key_id: str,
    role: str | None = None,
    reviewed_root: Path = SUPPORT_PREFLIGHT_ROOT,
    mount_probe: Callable[[Path], Mapping[str, Any]] | None = None,
) -> Iterator[tuple[str, Dict[str, Any]]]:
    """Run the canonical privacy adapter for development roles only."""

    if role is not None and role not in DEVELOPMENT_ROLES:
        raise SupportPreflightError("safe-session iterator forbids non-development role")
    _require_support_target_storage(
        private_database_path,
        reviewed_root=reviewed_root,
        mount_probe=mount_probe,
    )
    database = open_selected_database(private_database_path)
    try:
        if database.execute(
            "SELECT COUNT(*) FROM source_members WHERE experiment_role = 'test'"
        ).fetchone()[0]:
            raise SupportPreflightError("support store contains forbidden test members")
        role_predicate = (
            "s.experiment_role = ?" if role is not None else
            "s.experiment_role IN ('train', 'selection', 'calibration')"
        )
        parameters: tuple[str, ...] = (role,) if role is not None else ()
        rows = database.execute(
            "SELECT s.raw_session_id, s.source_member, s.first_seen, s.last_seen, "
            "s.protocol, s.configuration, s.experiment_role "
            f"FROM sessions AS s WHERE {role_predicate} "
            "AND s.source_cohort = 'development' AND s.protocol = 'ssh' "
            "AND s.connected = 1 AND s.closed = 1 AND NOT EXISTS "
            "(SELECT 1 FROM quarantined_sessions AS q "
            " WHERE q.raw_session_id = s.raw_session_id) "
            "ORDER BY s.first_seen, s.raw_session_id",
            parameters,
        )
        for row in rows:
            member = database.execute(
                "SELECT source_sha256, source_size_bytes, chronological_order, "
                "collection_start, collection_end FROM source_members "
                "WHERE filename = ? AND experiment_role = ?",
                (str(row[1]), str(row[6])),
            ).fetchone()
            if member is None:
                raise SupportPreflightError("session source receipt cannot be resolved")
            receipt = build_source_member_receipt(
                private_member_identifier=str(row[1]),
                source_sha256=str(member[0]),
                byte_size=int(member[1]),
                chronological_order=int(member[2]),
                collection_start=str(member[3]),
                collection_end=str(member[4]),
                pseudonymization_key=pseudonymization_key,
                pseudonymization_key_id=pseudonymization_key_id,
            )
            result = _private_session_result(
                database,
                row[:6],
                source_receipt=receipt,
                key=pseudonymization_key,
                key_id=pseudonymization_key_id,
            )
            safe = result["safe_session"]
            if safe is not None:
                yield str(row[6]), require_valid_next_behavior_session(safe)
    except (sqlite3.Error, ValueError) as exc:
        if isinstance(exc, SupportPreflightError):
            raise
        raise SupportPreflightError(str(exc)) from exc
    finally:
        database.close()


def _empty_role_metrics() -> Dict[str, Any]:
    return {
        "sessions": 0,
        "trusted_groups": 0,
        "trusted_labels": 0,
        "trusted_history_manifests": 0,
        "trusted_history_membership_sha256": _sha256_json([]),
        "distinct_behavior_phases": 0,
        "examples": 0,
        "nonterminal_targets": 0,
        "terminal_targets": 0,
        "target_tactics": {},
        "target_techniques": {},
        "target_tactic_technique_pairs": {},
        "phase_tactics": {},
        "phase_techniques": {},
        "distinct_session_support": {
            "terminal": 0,
            "nonterminal": 0,
            "by_tactic": {},
            "by_technique": {},
        },
        "terminal_to_nonterminal_ratio": None,
    }


def _finalize_role_metrics(
    counter: Counter[str],
    maps: Mapping[str, Counter[str]],
    session_sets: Mapping[str, set[str]],
    history_manifest_hashes: Sequence[str],
) -> Dict[str, Any]:
    nonterminal = counter["nonterminal_targets"]
    terminal = counter["terminal_targets"]
    ratio = None
    if nonterminal:
        ratio = str((Decimal(terminal) / Decimal(nonterminal)).quantize(Decimal("0.000001")))
    return {
        key: int(counter[key])
        for key in (
            "sessions",
            "trusted_groups",
            "trusted_labels",
            "trusted_history_manifests",
            "distinct_behavior_phases",
            "examples",
            "nonterminal_targets",
            "terminal_targets",
        )
    } | {
        "trusted_history_membership_sha256": _sha256_json(
            sorted(history_manifest_hashes)
        ),
        "target_tactics": dict(sorted(maps["target_tactics"].items())),
        "target_techniques": dict(sorted(maps["target_techniques"].items())),
        "target_tactic_technique_pairs": dict(
            sorted(maps["target_pairs"].items())
        ),
        "phase_tactics": dict(sorted(maps["phase_tactics"].items())),
        "phase_techniques": dict(sorted(maps["phase_techniques"].items())),
        "distinct_session_support": {
            "terminal": len(session_sets["terminal"]),
            "nonterminal": len(session_sets["nonterminal"]),
            "by_tactic": {
                key.removeprefix("tactic:"): len(value)
                for key, value in sorted(
                    (item for item in session_sets.items() if item[0].startswith("tactic:"))
                )
            },
            "by_technique": {
                key.removeprefix("technique:"): len(value)
                for key, value in sorted(
                    (item for item in session_sets.items() if item[0].startswith("technique:"))
                )
            },
        },
        "terminal_to_nonterminal_ratio": ratio,
    }


def _v3_history_for_safe_session(
    session: Mapping[str, Any],
    phases: Sequence[Mapping[str, Any]],
    *,
    classifier_environment_sha256: str,
) -> Dict[str, Any]:
    """Exercise v3 history using privacy-safe relative chronology.

    The preflight never emits these per-session manifests.  A fixed UTC origin
    converts already privacy-safe relative times into timestamps required by
    the v3 integrity contract without reintroducing source collection times.
    """

    origin = datetime(2000, 1, 1, tzinfo=timezone.utc)

    def timestamp(value: Any, fallback: int) -> str:
        milliseconds = fallback if value is None else int(float(value))
        return (origin + timedelta(milliseconds=milliseconds)).isoformat().replace(
            "+00:00", "Z"
        )

    history_phases = []
    for phase in phases:
        labels = [dict(item) for item in phase.get("labels") or []]
        history_phases.append(
            {
                "start_command_index": int(phase["start_event_order"]) - 1,
                "end_command_index": int(phase["end_event_order"]) - 1,
                "event_id": _clean(phase["phase_id"]),
                "start_timestamp": timestamp(
                    phase.get("start_relative_time_ms"),
                    int(phase["start_event_order"]) - 1,
                ),
                "end_timestamp": timestamp(
                    phase.get("end_relative_time_ms"),
                    int(phase["end_event_order"]) - 1,
                ),
                "observation_count": int(phase["observation_count"]),
                "labels": labels,
                "audit_only_label_count": int(
                    phase.get("audit_only_label_count") or 0
                ),
                "evidence_refs": list(phase.get("evidence_refs") or []),
            }
        )
    manifest = build_prediction_trusted_history_manifest(
        phases=history_phases,
        evidence_cutoff=make_evidence_cutoff(
            origin.isoformat().replace("+00:00", "Z"),
            _clean(session["session_id"]),
        ),
        classifier_environment={
            "environment_sha256": classifier_environment_sha256
        },
        original_command_count=len(session["observation_groups"]),
        original_trusted_label_count=sum(
            len(group["label_provenance"])
            for group in session["observation_groups"]
        ),
        audit_only_label_count=sum(
            len(group.get("audit_only_labels") or [])
            for group in session["observation_groups"]
        ),
    )
    errors = validate_prediction_trusted_history_manifest(
        manifest, expected_phases=history_phases
    )
    if errors:
        raise SupportPreflightError(
            "canonical v3 trusted history rejected: " + "; ".join(errors)
        )
    direct_input = build_model_input(phases, max_sequence_length=MAX_TRUSTED_PHASES)
    history_input = build_model_input_from_trusted_history_manifest(
        manifest,
        session_context=dict(
            (session["observation_groups"][-1].get("session_context") or {})
        ),
    )
    for field in (
        "target_contract_id",
        "max_sequence_length",
        "truncated",
        "original_phase_count",
        "selected_phase_count",
        "omitted_prefix_phase_count",
        "upstream_truncated",
        "phase_sequence",
        "session_context",
        "input_evidence_refs",
    ):
        if history_input[field] != direct_input[field]:
            raise SupportPreflightError(
                f"v3 history and canonical v2 preprocessing diverged at {field}"
            )
    return manifest


def _role_support(
    sessions: Iterable[Mapping[str, Any]],
    *,
    classifier_environment_sha256: str,
) -> tuple[Dict[str, Any], set[str]]:
    counter: Counter[str] = Counter()
    maps = {
        name: Counter()
        for name in (
            "target_tactics",
            "target_techniques",
            "target_pairs",
            "phase_tactics",
            "phase_techniques",
        )
    }
    session_sets: defaultdict[str, set[str]] = defaultdict(set)
    membership: set[str] = set()
    history_manifest_hashes: list[str] = []
    for raw in sessions:
        try:
            session = require_valid_next_behavior_session(dict(raw))
        except ValueError as exc:
            raise SupportPreflightError(
                f"privacy-safe session is invalid: {exc}"
            ) from exc
        session_id = _clean(session["session_id"])
        if session_id in membership:
            raise SupportPreflightError("privacy-safe session is duplicated")
        membership.add(session_id)
        counter["sessions"] += 1
        groups = session["observation_groups"]
        counter["trusted_groups"] += len(groups)
        counter["trusted_labels"] += sum(
            len(group["label_provenance"]) for group in groups
        )
        phases = build_behavior_phases(session)
        history_manifest = _v3_history_for_safe_session(
            session,
            phases,
            classifier_environment_sha256=classifier_environment_sha256,
        )
        counter["trusted_history_manifests"] += 1
        history_manifest_hashes.append(history_manifest["history_manifest_sha256"])
        examples = build_next_behavior_examples(
            session, max_sequence_length=MAX_TRUSTED_PHASES
        )
        if len(examples) != len(phases):
            raise SupportPreflightError("canonical phase/example counts diverged")
        counter["distinct_behavior_phases"] += len(phases)
        counter["examples"] += len(examples)
        for phase in phases:
            maps["phase_tactics"].update(phase["tactics"])
            maps["phase_techniques"].update(phase["techniques"])
        for index, example in enumerate(examples):
            target = example["target"]
            if target["outcome_type"] == "session_end":
                counter["terminal_targets"] += 1
                session_sets["terminal"].add(session_id)
                continue
            if target["outcome_type"] != "next_behavior_phase" or index + 1 >= len(phases):
                raise SupportPreflightError("canonical next-phase target is inconsistent")
            target_phase = phases[index + 1]
            if target["tactics"] != target_phase["tactics"] or target["techniques"] != target_phase["techniques"]:
                raise SupportPreflightError("canonical target lost phase labels")
            counter["nonterminal_targets"] += 1
            session_sets["nonterminal"].add(session_id)
            for tactic in target["tactics"]:
                if tactic not in TACTIC_VOCABULARY:
                    raise SupportPreflightError("unknown target tactic")
                maps["target_tactics"][tactic] += 1
                session_sets[f"tactic:{tactic}"].add(session_id)
            for technique in target["techniques"]:
                maps["target_techniques"][technique] += 1
                session_sets[f"technique:{technique}"].add(session_id)
            for label in target_phase["labels"]:
                pair = f"{label['tactic']}|{label['technique']}"
                maps["target_pairs"][pair] += 1
    return (
        _finalize_role_metrics(
            counter, maps, session_sets, history_manifest_hashes
        ),
        membership,
    )


def _gate_result(
    roles: Mapping[str, Mapping[str, Any]],
    *,
    require_selection_discovery: bool,
) -> Dict[str, Any]:
    requirements = {
        "train.execution": ("train", "execution", 30),
        "train.discovery": ("train", "discovery", 30),
        "selection.execution": ("selection", "execution", 30),
        "selection.terminal": ("selection", "terminal", 30),
        "calibration.terminal": ("calibration", "terminal", 30),
        "calibration.nonterminal": ("calibration", "nonterminal", 30),
    }
    if require_selection_discovery:
        requirements["selection.discovery"] = ("selection", "discovery", 30)
    results: Dict[str, Any] = {}
    for name, (role, label, minimum) in sorted(requirements.items()):
        metrics = roles[role]
        if label == "terminal":
            targets = metrics["terminal_targets"]
            sessions = metrics["distinct_session_support"]["terminal"]
        elif label == "nonterminal":
            targets = metrics["nonterminal_targets"]
            sessions = metrics["distinct_session_support"]["nonterminal"]
        else:
            targets = metrics["target_tactics"].get(label, 0)
            sessions = metrics["distinct_session_support"]["by_tactic"].get(label, 0)
        results[name] = {
            "minimum_targets": minimum,
            "minimum_distinct_sessions": minimum,
            "observed_targets": targets,
            "observed_distinct_sessions": sessions,
            "passed": targets >= minimum and sessions >= minimum,
        }
    return {
        "selection_discovery_required": require_selection_discovery,
        "requirements": results,
        "passed": all(item["passed"] for item in results.values()),
    }


def _source_member_partition_evidence(
    inventory: Mapping[str, Any],
) -> Dict[str, Any]:
    """Prove development/test separation from frozen member metadata only.

    This deliberately does not open test gzip members, database rows, safe
    sessions, or metrics.  Session-level collision claims therefore remain
    outside this cheap preflight.
    """

    development: list[Dict[str, str]] = []
    test: list[Dict[str, str]] = []
    for raw in inventory["members"]:
        row = {
            "filename": _clean(raw.get("filename")),
            "source_sha256": _member_sha(raw),
            "experiment_role": _member_role(raw),
        }
        (test if row["experiment_role"] == "test" else development).append(row)
    if not development or not test:
        raise SupportPreflightError(
            "successor inventory must contain sealed development and test partitions"
        )
    development_names = {row["filename"] for row in development}
    test_names = {row["filename"] for row in test}
    development_content = {row["source_sha256"] for row in development}
    test_content = {row["source_sha256"] for row in test}
    filename_intersection = development_names & test_names
    content_intersection = development_content & test_content
    if filename_intersection or content_intersection:
        raise SupportPreflightError(
            "successor source-member development/test partitions overlap"
        )
    return {
        "status": "verified_disjoint_from_validated_inventory",
        "identity_basis": "filename_and_source_sha256",
        "development_member_count": len(development),
        "test_member_count": len(test),
        "development_membership_sha256": _sha256_json(
            sorted(development, key=lambda row: (row["filename"], row["source_sha256"]))
        ),
        "test_membership_sha256": _sha256_json(
            sorted(test, key=lambda row: (row["filename"], row["source_sha256"]))
        ),
        "filename_intersection_count": 0,
        "content_sha256_intersection_count": 0,
    }


def require_valid_historical_test_session_membership(
    value: Any,
) -> Dict[str, Any]:
    """Validate metadata for a sealed, private, sorted membership artifact."""

    fields = {
        "schema_version",
        "receipt_id",
        "status",
        "source_selection_sha256",
        "test_source_member_membership_sha256",
        "pseudonymization_key_id",
        "pseudonymization_key_fingerprint_sha256",
        "artifact_format",
        "artifact_sha256",
        "artifact_size_bytes",
        "session_count",
        "sorted_unique_membership_sha256",
        "raw_content_emitted",
        "test_metrics_included",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise SupportPreflightError(
            "historical test-session membership receipt fields are invalid"
        )
    receipt = dict(value)
    if (
        receipt["schema_version"] != HISTORICAL_TEST_MEMBERSHIP_SCHEMA_VERSION
        or receipt["status"] != "sealed_pseudonymous_membership_frozen"
        or receipt["artifact_format"]
        != "sorted_unique_nbsession_sha256_lines.v1"
        or receipt["raw_content_emitted"] is not False
        or receipt["test_metrics_included"] is not False
    ):
        raise SupportPreflightError(
            "historical test-session membership receipt state is invalid"
        )
    for field in (
        "source_selection_sha256",
        "test_source_member_membership_sha256",
        "pseudonymization_key_fingerprint_sha256",
        "artifact_sha256",
        "sorted_unique_membership_sha256",
    ):
        receipt[field] = _sha256(receipt[field], field)
    _require_pseudonymization_binding(
        key_id=receipt["pseudonymization_key_id"],
        key_fingerprint_sha256=receipt[
            "pseudonymization_key_fingerprint_sha256"
        ],
    )
    if (
        isinstance(receipt["artifact_size_bytes"], bool)
        or not isinstance(receipt["artifact_size_bytes"], int)
        or receipt["artifact_size_bytes"] < 1
        or isinstance(receipt["session_count"], bool)
        or not isinstance(receipt["session_count"], int)
        or receipt["session_count"] < 1
    ):
        raise SupportPreflightError(
            "historical test-session membership artifact cannot be empty"
        )
    basis = dict(receipt)
    receipt_id = basis.pop("receipt_id")
    if receipt_id != stable_id("historicaltestsessionmembership", basis):
        raise SupportPreflightError(
            "historical test-session membership receipt identity is invalid"
        )
    return receipt


def _verify_historical_test_membership_artifact(
    *,
    receipt: Mapping[str, Any],
    artifact_path: Path,
    development_membership: set[str],
    source_selection_sha256: str,
    test_source_member_membership_sha256: str,
    pseudonymization_key_id: str,
    pseudonymization_key_fingerprint_sha256: str,
    reviewed_root: Path,
    mount_probe: Callable[[Path], Mapping[str, Any]] | None,
) -> Dict[str, Any]:
    checked = require_valid_historical_test_session_membership(receipt)
    _require_support_target_storage(
        artifact_path, reviewed_root=reviewed_root, mount_probe=mount_probe
    )
    if artifact_path.is_symlink() or not artifact_path.is_file():
        raise SupportPreflightError(
            "historical test-session membership artifact is missing or unsafe"
        )
    expected_id, expected_fingerprint = _require_pseudonymization_binding(
        key_id=pseudonymization_key_id,
        key_fingerprint_sha256=pseudonymization_key_fingerprint_sha256,
    )
    if (
        checked["source_selection_sha256"] != source_selection_sha256
        or checked["test_source_member_membership_sha256"]
        != test_source_member_membership_sha256
        or checked["pseudonymization_key_id"] != expected_id
        or checked["pseudonymization_key_fingerprint_sha256"]
        != expected_fingerprint
    ):
        raise SupportPreflightError(
            "historical test-session membership lineage is inconsistent"
        )
    byte_digest = hashlib.sha256()
    membership_digest = hashlib.sha256()
    count = 0
    intersection = 0
    previous = ""
    size = 0
    try:
        with artifact_path.open("rb") as handle:
            for raw_line in handle:
                size += len(raw_line)
                byte_digest.update(raw_line)
                if not raw_line.endswith(b"\n"):
                    raise SupportPreflightError(
                        "historical membership artifact has an unterminated line"
                    )
                try:
                    session_id = raw_line[:-1].decode("ascii")
                except UnicodeDecodeError as exc:
                    raise SupportPreflightError(
                        "historical membership artifact is not ASCII"
                    ) from exc
                if not _PSEUDONYMOUS_SESSION_ID.fullmatch(session_id):
                    raise SupportPreflightError(
                        "historical membership artifact contains an invalid identity"
                    )
                if previous and session_id <= previous:
                    raise SupportPreflightError(
                        "historical membership artifact is not sorted unique"
                    )
                previous = session_id
                encoded = session_id.encode("ascii")
                membership_digest.update(len(encoded).to_bytes(4, "big"))
                membership_digest.update(encoded)
                count += 1
                intersection += int(session_id in development_membership)
    except OSError as exc:
        raise SupportPreflightError(
            "historical membership artifact cannot be read"
        ) from exc
    if (
        size != checked["artifact_size_bytes"]
        or count != checked["session_count"]
        or byte_digest.hexdigest() != checked["artifact_sha256"]
        or membership_digest.hexdigest()
        != checked["sorted_unique_membership_sha256"]
    ):
        raise SupportPreflightError(
            "historical membership artifact does not match its receipt"
        )
    if intersection:
        raise SupportPreflightError(
            "development sessions overlap sealed historical test membership"
        )
    return {
        "status": "verified_zero_intersection",
        "receipt_id": checked["receipt_id"],
        "receipt_sha256": _sha256_json(checked),
        "artifact_sha256": checked["artifact_sha256"],
        "session_count": count,
        "intersection_count": 0,
    }


def build_support_preflight_receipt(
    *,
    safe_sessions_by_role: Mapping[str, Iterable[Mapping[str, Any]]],
    successor_inventory: Mapping[str, Any],
    inventory_validator: Callable[[Any], Mapping[str, Any]],
    source_selection_sha256: str,
    frozen_semantics: Mapping[str, Any],
    classification_receipt_sha256: str,
    donor_import_receipt_sha256: str | None,
    pseudonymization_key_id: str,
    pseudonymization_key_fingerprint_sha256: str,
    historical_test_membership_receipt: Mapping[str, Any],
    historical_test_membership_artifact_path: Path,
    require_selection_discovery: bool,
    reviewed_root: Path = SUPPORT_PREFLIGHT_ROOT,
    mount_probe: Callable[[Path], Mapping[str, Any]] | None = None,
) -> Dict[str, Any]:
    """Build the deterministic aggregate receipt using canonical v3/v2 code."""

    if set(safe_sessions_by_role) != set(DEVELOPMENT_ROLES):
        raise SupportPreflightError("support inputs must contain development roles only")
    inventory = require_validated_successor_inventory(
        successor_inventory, inventory_validator=inventory_validator
    )
    inventory_id, inventory_sha = _inventory_identity(inventory)
    selection_hash = _sha256(source_selection_sha256, "source_selection_sha256")
    if selection_hash != inventory["source_selection_sha256"]:
        raise SupportPreflightError(
            "support receipt selection does not match successor inventory"
        )
    semantics = _require_frozen_semantics(
        frozen_semantics, label="frozen_semantics"
    )
    key_id, key_fingerprint = _require_pseudonymization_binding(
        key_id=pseudonymization_key_id,
        key_fingerprint_sha256=pseudonymization_key_fingerprint_sha256,
    )

    roles: Dict[str, Dict[str, Any]] = {}
    memberships: Dict[str, set[str]] = {}
    for role in DEVELOPMENT_ROLES:
        roles[role], memberships[role] = _role_support(
            safe_sessions_by_role[role],
            classifier_environment_sha256=semantics[
                "classifier_environment_sha256"
            ],
        )
    intersections = {
        "train_selection": len(memberships["train"] & memberships["selection"]),
        "train_calibration": len(memberships["train"] & memberships["calibration"]),
        "selection_calibration": len(memberships["selection"] & memberships["calibration"]),
    }
    if any(intersections.values()):
        raise SupportPreflightError("development role session memberships overlap")
    source_partition = _source_member_partition_evidence(inventory)
    development_membership = set().union(*memberships.values())
    historical_membership = _verify_historical_test_membership_artifact(
        receipt=historical_test_membership_receipt,
        artifact_path=historical_test_membership_artifact_path,
        development_membership=development_membership,
        source_selection_sha256=selection_hash,
        test_source_member_membership_sha256=source_partition[
            "test_membership_sha256"
        ],
        pseudonymization_key_id=key_id,
        pseudonymization_key_fingerprint_sha256=key_fingerprint,
        reviewed_root=reviewed_root,
        mount_probe=mount_probe,
    )
    gate = _gate_result(
        roles, require_selection_discovery=require_selection_discovery
    )
    protections = {
        "test_members_accessed": False,
        "test_metrics_used": False,
        "raw_content_emitted": False,
        "unknown_or_unresolved_labels": 0,
        "role_membership_intersections": intersections,
        "source_member_partition_isolation": source_partition,
        "historical_test_session_membership": historical_membership,
    }
    receipt: Dict[str, Any] = {
        "schema_version": SUPPORT_PREFLIGHT_SCHEMA_VERSION,
        "status": "support_gate_passed" if gate["passed"] else "support_gate_failed",
        "purpose": SUPPORT_STORE_PURPOSE,
        "target_contract_id": TARGET_CONTRACT_ID,
        "trusted_history_schema_version": HISTORY_SCHEMA,
        "max_trusted_phases": MAX_TRUSTED_PHASES,
        "successor_inventory_id": inventory_id,
        "successor_inventory_sha256": inventory_sha,
        "source_selection_sha256": selection_hash,
        "classification_receipt_sha256": _sha256(
            classification_receipt_sha256, "classification_receipt_sha256"
        ),
        "donor_import_receipt_sha256": (
            _sha256(donor_import_receipt_sha256, "donor_import_receipt_sha256")
            if donor_import_receipt_sha256
            else None
        ),
        "pseudonymization_key_id": key_id,
        "pseudonymization_key_fingerprint_sha256": key_fingerprint,
        "frozen_semantics": semantics,
        "roles": roles,
        "aggregate_support_sha256": _sha256_json(roles),
        "gate": gate,
        "protections": protections,
    }
    receipt["receipt_id"] = stable_id("nextbehaviorsupportpreflight", receipt)
    require_valid_support_preflight_receipt(receipt)
    return receipt


def _validate_role_metrics(role: str, value: Any) -> list[str]:
    errors: list[str] = []
    expected = {
        "sessions",
        "trusted_groups",
        "trusted_labels",
        "trusted_history_manifests",
        "trusted_history_membership_sha256",
        "distinct_behavior_phases",
        "examples",
        "nonterminal_targets",
        "terminal_targets",
        "target_tactics",
        "target_techniques",
        "target_tactic_technique_pairs",
        "phase_tactics",
        "phase_techniques",
        "distinct_session_support",
        "terminal_to_nonterminal_ratio",
    }
    if not isinstance(value, Mapping) or set(value) != expected:
        return [f"roles.{role} fields are invalid"]
    for field in (
        "sessions",
        "trusted_groups",
        "trusted_labels",
        "trusted_history_manifests",
        "distinct_behavior_phases",
        "examples",
        "nonterminal_targets",
        "terminal_targets",
    ):
        try:
            _nonnegative_int(value.get(field), f"roles.{role}.{field}")
        except SupportPreflightError as exc:
            errors.append(str(exc))
    if not _SHA256.fullmatch(
        _clean(value.get("trusted_history_membership_sha256")).lower()
    ):
        errors.append(f"roles.{role}.trusted_history_membership_sha256 is invalid")
    if value.get("trusted_history_manifests") != value.get("sessions"):
        errors.append(f"roles.{role} trusted-history counts do not reconcile")
    if (
        isinstance(value.get("examples"), int)
        and value.get("examples")
        != value.get("nonterminal_targets", -1) + value.get("terminal_targets", -1)
    ):
        errors.append(f"roles.{role} example targets do not reconcile")
    if value.get("sessions") != value.get("terminal_targets"):
        errors.append(f"roles.{role} closed-session terminal counts do not reconcile")
    if isinstance(value.get("distinct_behavior_phases"), int) and isinstance(
        value.get("trusted_groups"), int
    ) and value["distinct_behavior_phases"] > value["trusted_groups"]:
        errors.append(f"roles.{role} phase count exceeds trusted groups")
    for field in (
        "target_tactics",
        "target_techniques",
        "target_tactic_technique_pairs",
        "phase_tactics",
        "phase_techniques",
    ):
        counts = value.get(field)
        if not isinstance(counts, Mapping):
            errors.append(f"roles.{role}.{field} must be an object")
            continue
        for label, count in counts.items():
            if not _clean(label) or isinstance(count, bool) or not isinstance(count, int) or count < 0:
                errors.append(f"roles.{role}.{field} contains an invalid count")
        if field in {"target_tactics", "phase_tactics"} and any(
            label not in TACTIC_VOCABULARY for label in counts
        ):
            errors.append(f"roles.{role}.{field} contains an unknown tactic")
        if field in {"target_techniques", "phase_techniques"} and any(
            not re.fullmatch(r"T[0-9]{4}(?:\.[0-9]{3})?", _clean(label))
            for label in counts
        ):
            errors.append(f"roles.{role}.{field} contains an invalid technique")
        if field == "target_tactic_technique_pairs":
            for label in counts:
                parts = _clean(label).split("|", 1)
                if (
                    len(parts) != 2
                    or parts[0] not in TACTIC_VOCABULARY
                    or not re.fullmatch(r"T[0-9]{4}(?:\.[0-9]{3})?", parts[1])
                ):
                    errors.append(f"roles.{role}.{field} contains an invalid pair")
    support = value.get("distinct_session_support")
    if not isinstance(support, Mapping) or set(support) != {
        "terminal",
        "nonterminal",
        "by_tactic",
        "by_technique",
    }:
        errors.append(f"roles.{role}.distinct_session_support is invalid")
    else:
        for field, maximum in (
            ("terminal", value.get("terminal_targets")),
            ("nonterminal", value.get("nonterminal_targets")),
        ):
            count = support.get(field)
            if (
                isinstance(count, bool)
                or not isinstance(count, int)
                or count < 0
                or not isinstance(maximum, int)
                or count > maximum
            ):
                errors.append(
                    f"roles.{role}.distinct_session_support.{field} is invalid"
                )
        for field, target_field in (
            ("by_tactic", "target_tactics"),
            ("by_technique", "target_techniques"),
        ):
            counts = support.get(field)
            if not isinstance(counts, Mapping):
                errors.append(f"roles.{role}.distinct_session_support.{field} is invalid")
                continue
            if set(counts) != set(value.get(target_field, {})):
                errors.append(
                    f"roles.{role}.distinct_session_support.{field} labels differ"
                )
            for label, count in counts.items():
                maximum = value.get(target_field, {}).get(label, -1)
                if (
                    isinstance(count, bool)
                    or not isinstance(count, int)
                    or count < 0
                    or count > maximum
                ):
                    errors.append(
                        f"roles.{role}.distinct_session_support.{field} count is invalid"
                    )
    nonterminal = value.get("nonterminal_targets")
    terminal = value.get("terminal_targets")
    expected_ratio = None
    if (
        isinstance(nonterminal, int)
        and not isinstance(nonterminal, bool)
        and nonterminal > 0
        and isinstance(terminal, int)
        and not isinstance(terminal, bool)
    ):
        expected_ratio = str(
            (Decimal(terminal) / Decimal(nonterminal)).quantize(Decimal("0.000001"))
        )
    if value.get("terminal_to_nonterminal_ratio") != expected_ratio:
        errors.append(f"roles.{role} terminal/nonterminal ratio is inconsistent")
    return errors


def validate_support_preflight_receipt(value: Any) -> list[str]:
    """Validate deterministic identity, safety flags, metrics, and 30/30 gates."""

    if not isinstance(value, Mapping):
        return ["support preflight receipt must be an object"]
    errors: list[str] = []
    expected = {
        "schema_version",
        "status",
        "purpose",
        "target_contract_id",
        "trusted_history_schema_version",
        "max_trusted_phases",
        "successor_inventory_id",
        "successor_inventory_sha256",
        "source_selection_sha256",
        "classification_receipt_sha256",
        "donor_import_receipt_sha256",
        "pseudonymization_key_id",
        "pseudonymization_key_fingerprint_sha256",
        "frozen_semantics",
        "roles",
        "aggregate_support_sha256",
        "gate",
        "protections",
        "receipt_id",
    }
    if set(value) != expected:
        errors.append("support preflight receipt fields are invalid")
    if value.get("schema_version") != SUPPORT_PREFLIGHT_SCHEMA_VERSION:
        errors.append("support preflight schema is invalid")
    if value.get("purpose") != SUPPORT_STORE_PURPOSE:
        errors.append("support preflight purpose is invalid")
    if value.get("target_contract_id") != TARGET_CONTRACT_ID:
        errors.append("support preflight target is invalid")
    if value.get("trusted_history_schema_version") != HISTORY_SCHEMA:
        errors.append("support preflight history schema is invalid")
    if value.get("max_trusted_phases") != MAX_TRUSTED_PHASES:
        errors.append("support preflight phase window is invalid")
    for field in (
        "successor_inventory_sha256",
        "source_selection_sha256",
        "classification_receipt_sha256",
        "aggregate_support_sha256",
    ):
        if not _SHA256.fullmatch(_clean(value.get(field)).lower()):
            errors.append(f"{field} is invalid")
    donor = value.get("donor_import_receipt_sha256")
    if donor is not None and not _SHA256.fullmatch(_clean(donor).lower()):
        errors.append("donor import receipt SHA-256 is invalid")
    try:
        _require_pseudonymization_binding(
            key_id=value.get("pseudonymization_key_id"),
            key_fingerprint_sha256=value.get(
                "pseudonymization_key_fingerprint_sha256"
            ),
        )
    except SupportPreflightError as exc:
        errors.append(str(exc))
    roles = value.get("roles")
    if not isinstance(roles, Mapping) or set(roles) != set(DEVELOPMENT_ROLES):
        errors.append("support roles are invalid")
    else:
        for role in DEVELOPMENT_ROLES:
            errors.extend(_validate_role_metrics(role, roles[role]))
        if _sha256_json(dict(roles)) != value.get("aggregate_support_sha256"):
            errors.append("aggregate support hash is inconsistent")
    semantics = value.get("frozen_semantics")
    if not isinstance(semantics, Mapping) or set(semantics) != _FROZEN_SEMANTICS_FIELDS:
        errors.append("frozen semantics are invalid")
    else:
        if semantics.get("target_contract_id") != TARGET_CONTRACT_ID:
            errors.append("frozen semantics target is invalid")
        if semantics.get("trusted_history_schema_version") != HISTORY_SCHEMA:
            errors.append("frozen semantics history schema is invalid")
        if semantics.get("max_trusted_phases") != MAX_TRUSTED_PHASES:
            errors.append("frozen semantics phase window is invalid")
        for field in _FROZEN_SEMANTICS_SHA256_FIELDS:
            if not _SHA256.fullmatch(_clean(semantics.get(field)).lower()):
                errors.append(f"frozen_semantics.{field} is invalid")
    protections = value.get("protections")
    if (
        not isinstance(protections, Mapping)
        or set(protections)
        != {
            "test_members_accessed",
            "test_metrics_used",
            "raw_content_emitted",
            "unknown_or_unresolved_labels",
            "role_membership_intersections",
            "source_member_partition_isolation",
            "historical_test_session_membership",
        }
    ):
        errors.append("support protections are invalid")
    if isinstance(protections, Mapping):
        for field in ("test_members_accessed", "test_metrics_used", "raw_content_emitted"):
            if protections.get(field) is not False:
                errors.append(f"protections.{field} must be false")
        if protections.get("unknown_or_unresolved_labels") != 0:
            errors.append("unknown/unresolved label count must be zero")
        intersections = protections.get("role_membership_intersections")
        if (
            not isinstance(intersections, Mapping)
            or set(intersections)
            != {"train_selection", "train_calibration", "selection_calibration"}
            or any(
            not isinstance(count, int) or isinstance(count, bool) or count != 0
            for count in (intersections or {}).values()
            )
        ):
            errors.append("role membership intersections must be zero")
        partition = protections.get("source_member_partition_isolation")
        if (
            not isinstance(partition, Mapping)
            or set(partition)
            != {
                "status",
                "identity_basis",
                "development_member_count",
                "test_member_count",
                "development_membership_sha256",
                "test_membership_sha256",
                "filename_intersection_count",
                "content_sha256_intersection_count",
            }
            or partition.get("status")
            != "verified_disjoint_from_validated_inventory"
            or partition.get("identity_basis") != "filename_and_source_sha256"
            or any(
                isinstance(partition.get(field), bool)
                or not isinstance(partition.get(field), int)
                or partition.get(field, 0) < 1
                for field in ("development_member_count", "test_member_count")
            )
            or not _SHA256.fullmatch(
                _clean(partition.get("development_membership_sha256"))
            )
            or not _SHA256.fullmatch(
                _clean(partition.get("test_membership_sha256"))
            )
            or partition.get("filename_intersection_count") != 0
            or partition.get("content_sha256_intersection_count") != 0
        ):
            errors.append("source-member partition isolation is invalid")
        collision = protections.get("historical_test_session_membership")
        if (
            not isinstance(collision, Mapping)
            or set(collision)
            != {
                "status",
                "receipt_id",
                "receipt_sha256",
                "artifact_sha256",
                "session_count",
                "intersection_count",
            }
            or collision.get("status") != "verified_zero_intersection"
            or not _clean(collision.get("receipt_id"))
            or not _SHA256.fullmatch(_clean(collision.get("receipt_sha256")))
            or not _SHA256.fullmatch(_clean(collision.get("artifact_sha256")))
            or isinstance(collision.get("session_count"), bool)
            or not isinstance(collision.get("session_count"), int)
            or collision.get("session_count", 0) < 1
            or collision.get("intersection_count") != 0
        ):
            errors.append("historical test-session membership proof is invalid")
    gate = value.get("gate")
    if not isinstance(gate, Mapping) or not isinstance(roles, Mapping):
        errors.append("support gate is invalid")
    else:
        try:
            expected_gate = _gate_result(
                roles,
                require_selection_discovery=bool(
                    gate.get("selection_discovery_required")
                ),
            )
            if dict(gate) != expected_gate:
                errors.append("support gate does not match aggregate support")
            expected_status = (
                "support_gate_passed" if expected_gate["passed"] else "support_gate_failed"
            )
            if value.get("status") != expected_status:
                errors.append("support status does not match the gate")
        except (KeyError, TypeError, ValueError):
            errors.append("support gate cannot be recomputed")
    identity = dict(value)
    receipt_id = identity.pop("receipt_id", None)
    if receipt_id != stable_id("nextbehaviorsupportpreflight", identity):
        errors.append("support preflight receipt identity is invalid")
    return errors


def require_valid_support_preflight_receipt(value: Any) -> Dict[str, Any]:
    errors = validate_support_preflight_receipt(value)
    if errors:
        raise SupportPreflightError("; ".join(errors))
    return dict(value)


def run_support_preflight_from_store(
    *,
    private_database_path: Path,
    pseudonymization_key: bytes,
    pseudonymization_key_id: str,
    successor_inventory: Mapping[str, Any],
    inventory_validator: Callable[[Any], Mapping[str, Any]],
    source_selection_sha256: str,
    frozen_semantics: Mapping[str, Any],
    classification_receipt_sha256: str,
    donor_import_receipt_sha256: str | None,
    historical_test_membership_receipt: Mapping[str, Any],
    historical_test_membership_artifact_path: Path,
    require_selection_discovery: bool,
    reviewed_root: Path = SUPPORT_PREFLIGHT_ROOT,
    mount_probe: Callable[[Path], Mapping[str, Any]] | None = None,
) -> Dict[str, Any]:
    """Stream each development role from the private store into aggregation."""

    supplied_donor_hash = _sha256(
        donor_import_receipt_sha256,
        "donor_import_receipt_sha256",
    )
    _require_support_target_storage(
        private_database_path,
        reviewed_root=reviewed_root,
        mount_probe=mount_probe,
    )
    lineage_database = open_selected_database(private_database_path)
    try:
        lineage = dict(
            lineage_database.execute(
                "SELECT key, value FROM metadata WHERE key IN "
                "('support_donor_import_receipt_json', "
                "'support_donor_import_receipt_sha256')"
            )
        )
        try:
            donor_import = require_valid_development_donor_import(
                json.loads(lineage["support_donor_import_receipt_json"])
            )
        except (KeyError, json.JSONDecodeError) as exc:
            raise SupportPreflightError(
                "support store has no verified donor-import lineage"
            ) from exc
        stored_donor_hash = _sha256_json(donor_import)
        if (
            lineage.get("support_donor_import_receipt_sha256")
            != stored_donor_hash
            or supplied_donor_hash != stored_donor_hash
        ):
            raise SupportPreflightError(
                "support preflight donor-import binding mismatch"
            )
    finally:
        lineage_database.close()

    require_complete_support_store_classification(
        private_database_path=private_database_path,
        expected_receipt_sha256=classification_receipt_sha256,
        source_selection_sha256=source_selection_sha256,
        frozen_semantics=frozen_semantics,
        successor_inventory=successor_inventory,
        inventory_validator=inventory_validator,
        reviewed_root=reviewed_root,
        mount_probe=mount_probe,
    )

    def stream_role(selected_role: str) -> Iterator[Dict[str, Any]]:
        for returned_role, session in iter_development_safe_sessions(
            private_database_path=private_database_path,
            pseudonymization_key=pseudonymization_key,
            pseudonymization_key_id=pseudonymization_key_id,
            role=selected_role,
            reviewed_root=reviewed_root,
            mount_probe=mount_probe,
        ):
            if returned_role != selected_role:
                raise SupportPreflightError("safe-session role isolation failed")
            yield session

    sessions_by_role = {role: stream_role(role) for role in DEVELOPMENT_ROLES}
    if not isinstance(pseudonymization_key, bytes) or len(pseudonymization_key) != 32:
        raise SupportPreflightError("pseudonymization key must be exactly 32 bytes")
    key_fingerprint = hashlib.sha256(pseudonymization_key).hexdigest()
    _require_pseudonymization_binding(
        key_id=pseudonymization_key_id,
        key_fingerprint_sha256=key_fingerprint,
    )
    return build_support_preflight_receipt(
        safe_sessions_by_role=sessions_by_role,
        successor_inventory=successor_inventory,
        inventory_validator=inventory_validator,
        source_selection_sha256=source_selection_sha256,
        frozen_semantics=frozen_semantics,
        classification_receipt_sha256=classification_receipt_sha256,
        donor_import_receipt_sha256=stored_donor_hash,
        pseudonymization_key_id=pseudonymization_key_id,
        pseudonymization_key_fingerprint_sha256=key_fingerprint,
        historical_test_membership_receipt=historical_test_membership_receipt,
        historical_test_membership_artifact_path=(
            historical_test_membership_artifact_path
        ),
        require_selection_discovery=require_selection_discovery,
        reviewed_root=reviewed_root,
        mount_probe=mount_probe,
    )


def require_complete_support_store_classification(
    *,
    private_database_path: Path,
    expected_receipt_sha256: str,
    source_selection_sha256: str,
    frozen_semantics: Mapping[str, Any],
    successor_inventory: Mapping[str, Any],
    inventory_validator: Callable[[Any], Mapping[str, Any]],
    reviewed_root: Path = SUPPORT_PREFLIGHT_ROOT,
    mount_probe: Callable[[Path], Mapping[str, Any]] | None = None,
) -> Dict[str, Any]:
    """Reject partial/stale classification before any support aggregation."""

    expected_hash = _sha256(
        expected_receipt_sha256, "classification_receipt_sha256"
    )
    selection_hash = _sha256(source_selection_sha256, "source_selection_sha256")
    inventory = require_validated_successor_inventory(
        successor_inventory, inventory_validator=inventory_validator
    )
    if selection_hash != inventory["source_selection_sha256"]:
        raise SupportPreflightError(
            "classification selection does not match canonical successor inventory"
        )
    _require_support_target_storage(
        private_database_path,
        reviewed_root=reviewed_root,
        mount_probe=mount_probe,
    )
    semantics = _require_frozen_semantics(
        frozen_semantics, label="frozen_semantics"
    )
    database = open_selected_database(private_database_path)
    try:
        if database.execute(
            "SELECT COUNT(*) FROM source_members WHERE experiment_role = 'test'"
        ).fetchone()[0]:
            raise SupportPreflightError("support store contains forbidden test members")
        selection = database.execute(
            "SELECT value FROM metadata WHERE key = 'source_selection_sha256'"
        ).fetchone()
        if selection is None or str(selection[0]) != selection_hash:
            raise SupportPreflightError("support classification selection is inconsistent")
        commands = [
            str(row[0])
            for row in database.execute(
                "SELECT DISTINCT command FROM command_events ORDER BY command"
            )
        ]
        missing = int(
            database.execute(
                "SELECT COUNT(DISTINCT events.command) FROM command_events AS events "
                "WHERE NOT EXISTS (SELECT 1 FROM command_labels AS labels "
                " WHERE labels.command = events.command)"
            ).fetchone()[0]
        )
        if missing:
            raise SupportPreflightError(
                "support store classification coverage is incomplete"
            )
        for labels_json, unrepresented_json in database.execute(
            "SELECT labels.labels_json, labels.unrepresented_json "
            "FROM command_labels AS labels "
            "WHERE EXISTS (SELECT 1 FROM command_events AS events "
            " WHERE events.command = labels.command) ORDER BY labels.command"
        ):
            _require_canonical_cached_row(
                str(labels_json),
                str(unrepresented_json),
                rule_policy_sha256=semantics["rule_policy_sha256"],
                trust_policy_sha256=semantics["trust_policy_sha256"],
                checkpoint_sha256=semantics["checkpoint_sha256"],
            )
        receipt = _receipt_by_sha(
            database,
            "classification_cache_receipts",
            "receipt_json",
            expected_hash,
        )
        if (
            receipt.get("status") != "classification_complete"
            or receipt.get("source_selection_sha256") != selection_hash
            or receipt.get("classifier_manifest_sha256")
            != semantics["classifier_manifest_sha256"]
            or receipt.get("checkpoint_sha256") != semantics["checkpoint_sha256"]
            or receipt.get("rule_policy_sha256") != semantics["rule_policy_sha256"]
            or receipt.get("trust_policy_sha256") != semantics["trust_policy_sha256"]
            or receipt.get("label_adapter_sha256")
            != semantics["label_adapter_sha256"]
            or receipt.get("ingested_source_members_sha256")
            != semantics["source_member_inventory_sha256"]
            or receipt.get("unique_command_count") != len(commands)
            or receipt.get("exact_command_membership_sha256")
            != _sha256_json(commands)
            or receipt.get("raw_content_emitted") is not False
        ):
            raise SupportPreflightError(
                "support classification receipt does not bind exact command coverage"
            )
        return receipt
    except (sqlite3.Error, ValueError) as exc:
        if isinstance(exc, SupportPreflightError):
            raise
        raise SupportPreflightError(str(exc)) from exc
    finally:
        database.close()


def write_support_preflight_receipt(
    path: Path,
    receipt: Mapping[str, Any],
    *,
    reviewed_root: Path = SUPPORT_PREFLIGHT_ROOT,
    mount_probe: Callable[[Path], Mapping[str, Any]] | None = None,
) -> str:
    """Write one validated immutable receipt without overwriting evidence."""

    _require_support_target_storage(
        path, reviewed_root=reviewed_root, mount_probe=mount_probe
    )
    document = require_valid_support_preflight_receipt(receipt)
    payload = (stable_json(document) + "\n").encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise SupportPreflightError("support receipt path cannot be a symlink")
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except FileExistsError as exc:
        raise SupportPreflightError("support receipt already exists") from exc
    return hashlib.sha256(payload).hexdigest()
