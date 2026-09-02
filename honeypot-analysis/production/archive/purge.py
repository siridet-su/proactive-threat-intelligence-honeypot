"""Fail-closed exact-identity MongoDB purge for the bounded archive pilot.

This module is intentionally separate from the copy-only archive module.  It
has one destructive primitive, ``delete_many`` with a non-empty ``_id/$in``
filter built from a previously verified archive identity set.  There is no
timestamp, age, collection-wide, or empty-filter deletion path.

The caller must supply an immutable frozen identity-set receipt and an exact
Target A pin.  Progress is append-only and batch bounded so a rerun can skip
only batches already recorded as fully acknowledged and verified.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .cold_archive import (
    ArchiveError,
    ArchiveVerificationError,
    PurgeSafetyError,
    _records_digest,
    _self_hash,
    _stable_json,
    _zstd_lines,
    canonical_ejson_dumps,
    canonical_ejson_loads,
    canonical_ejson_object,
    filesystem_capacity,
    mongo_capacity_status,
    read_archive_verified,
    safe_index_summary,
    sha256_file,
    utc_now,
    verify_archive_file,
    write_immutable_json,
)


PURGE_SET_VERSION = "mongo_pi_archive_purge_exact_set.v1"
PURGE_PROGRESS_VERSION = "mongo_pi_archive_purge_batch_receipt.v1"
PURGE_EXECUTION_VERSION = "mongo_pi_archive_purge_execution.v1"
PILOT_AUTHORIZED_MAX = 463
DEFAULT_BATCH_SIZE = 50
TARGET_A_PURGE_BINDING = {
    "project_id": "6a549939366a569efa96236e",
    "cluster_id": "6a549b2a17450a688c455e7e",
    "cluster_name": "Honeypot-DB",
    "srv_hostname": "honeypot-db.o4c0xzu.mongodb.net",
    "database": "honeypot_db",
    "collection": "hardware_metrics",
    "storage_epoch": "LEGACY_TARGET_A_NO_CANONICAL_EPOCH",
}


def _require_target_a_binding(source: Mapping[str, Any]) -> None:
    if dict(source) != TARGET_A_PURGE_BINDING:
        raise PurgeSafetyError("source target is not the authorized Target A purge binding")


def _manifest_spec(manifest: Mapping[str, Any]) -> Any:
    """Build the archive spec from manifest metadata without trusting a query."""

    from .cold_archive import ArchiveSpec

    source = manifest["source_target"]
    return ArchiveSpec(
        project_id=str(source["project_id"]),
        cluster_id=str(source["cluster_id"]),
        cluster_name=str(source["cluster_name"]),
        srv_hostname=str(source["srv_hostname"]),
        database=str(source["database"]),
        collection=str(source["collection"]),
        query=canonical_ejson_loads(_stable_json(manifest["query_predicate"])),
        sort=tuple((str(item[0]), int(item[1])) for item in manifest["sort"]),
        limit=manifest.get("limit"),
        provenance=str(manifest["provenance"]),
        schema_info=dict(manifest.get("schema_info") or {}),
        source_epoch=str(source.get("storage_epoch") or ""),
        tool_version=str(manifest.get("tool_version") or ""),
    )


def _verified_archive_documents(
    archive_path: str | Path,
    manifest: Mapping[str, Any],
) -> tuple[dict[str, Any], list[Mapping[str, Any]]]:
    """Verify an archive, then reconstruct all documents in memory."""

    spec = _manifest_spec(manifest)
    verification = verify_archive_file(
        archive_path,
        spec=spec,
        expected_count=int(manifest["selected_count"]),
        expected_sha256=str(manifest["sha256"]),
        expected_records_sha256=str(manifest["records_sha256"]),
        expected_first_sort_key=manifest["first_sort_key"],
        expected_last_sort_key=manifest["last_sort_key"],
        expected_first_document_id=canonical_ejson_loads(
            _stable_json(manifest["first_document_id"])
        ),
        expected_last_document_id=canonical_ejson_loads(
            _stable_json(manifest["last_document_id"])
        ),
    )
    documents: list[Mapping[str, Any]] = []
    for line in _zstd_lines(Path(archive_path)):
        try:
            value = canonical_ejson_loads(line[:-1])
        except Exception as exc:  # BSON parser error types vary by PyMongo version.
            raise ArchiveVerificationError("verified archive record cannot be reconstructed") from exc
        if not isinstance(value, Mapping) or "_id" not in value:
            raise ArchiveVerificationError("verified archive record lacks _id")
        documents.append(value)
    if len(documents) != int(manifest["selected_count"]):
        raise ArchiveVerificationError("reconstructed archive count mismatch")
    if _records_digest(documents) != str(manifest["records_sha256"]):
        raise ArchiveVerificationError("reconstructed archive record digest mismatch")
    return verification, documents


def _identity_token(value: Any) -> str:
    return canonical_ejson_dumps(value)


def identity_set_sha256(document_ids: Iterable[Any]) -> str:
    """Hash one canonical EJSON identity per line in deterministic order."""

    tokens = sorted(_identity_token(value) for value in document_ids)
    if len(tokens) != len(set(tokens)):
        raise PurgeSafetyError("exact purge set contains duplicate _id values")
    digest = hashlib.sha256()
    for token in tokens:
        digest.update((token + "\n").encode("utf-8"))
    return digest.hexdigest()


def _canonical_ids_from_frozen_set(frozen: Mapping[str, Any]) -> list[Any]:
    raw_ids = frozen.get("document_ids")
    if not isinstance(raw_ids, list):
        raise PurgeSafetyError("frozen purge set does not contain document_ids")
    ids: list[Any] = []
    tokens: list[str] = []
    for item in raw_ids:
        try:
            value = canonical_ejson_loads(_stable_json(item))
        except Exception as exc:
            raise PurgeSafetyError("frozen purge set contains invalid BSON identity") from exc
        ids.append(value)
        tokens.append(_identity_token(value))
    if len(ids) != len(set(tokens)):
        raise PurgeSafetyError("frozen purge set contains duplicate _id values")
    expected_digest = identity_set_sha256(ids)
    if expected_digest != frozen.get("identity_set_sha256"):
        raise PurgeSafetyError("frozen purge set identity digest mismatch")
    if tokens != sorted(tokens):
        raise PurgeSafetyError("frozen purge set is not deterministically ordered")
    return ids


def validate_frozen_purge_set(
    frozen: Mapping[str, Any],
    manifest: Mapping[str, Any],
    *,
    authorized_max: int = PILOT_AUTHORIZED_MAX,
) -> list[Any]:
    """Validate every immutable guard needed before a destructive operation."""

    if frozen.get("schema_version") != PURGE_SET_VERSION:
        raise PurgeSafetyError("unsupported frozen purge-set schema")
    if frozen.get("purge_set_status") != "FROZEN_VERIFIED":
        raise PurgeSafetyError("purge set is not frozen and verified")
    if manifest.get("archive_status") != "VERIFIED":
        raise PurgeSafetyError("archive manifest is not VERIFIED")
    _require_target_a_binding(manifest["source_target"])
    if frozen.get("archive_id") != manifest.get("archive_id"):
        raise PurgeSafetyError("frozen purge-set archive ID mismatch")
    if frozen.get("source_target") != manifest.get("source_target"):
        raise PurgeSafetyError("frozen purge-set target mismatch")
    if frozen.get("archive_sha256") != manifest.get("sha256"):
        raise PurgeSafetyError("frozen purge-set archive hash mismatch")
    expected_count = int(manifest.get("selected_count", -1))
    frozen_count = int(frozen.get("exact_document_count", -1))
    if expected_count != authorized_max or frozen_count != authorized_max:
        raise PurgeSafetyError("purge authorization count is not exactly the pilot maximum")
    if int(frozen.get("authorized_maximum", -1)) != authorized_max:
        raise PurgeSafetyError("frozen purge-set maximum is not pinned")
    if frozen.get("purge_set_sha256") != _self_hash(frozen, "purge_set_sha256"):
        raise PurgeSafetyError("frozen purge-set receipt self-hash mismatch")
    ids = _canonical_ids_from_frozen_set(frozen)
    if len(ids) != frozen_count:
        raise PurgeSafetyError("frozen purge-set count does not match identities")
    secondary = frozen.get("secondary_copy")
    if not isinstance(secondary, Mapping) or secondary.get("verified") is not True:
        raise PurgeSafetyError("verified secondary archive copy is required")
    if secondary.get("sha256") != frozen.get("archive_sha256"):
        raise PurgeSafetyError("secondary archive hash is not equal to primary hash")
    primary = frozen.get("primary_copy")
    if not isinstance(primary, Mapping) or primary.get("verified") is not True:
        raise PurgeSafetyError("verified primary Pi archive copy is required")
    if primary.get("sha256") != frozen.get("archive_sha256"):
        raise PurgeSafetyError("primary archive hash is not equal to frozen hash")
    if frozen.get("mutations_performed") is not False:
        raise PurgeSafetyError("frozen purge-set is not mutation-free")
    return ids


def freeze_exact_purge_set(
    archive_path: str | Path,
    manifest: Mapping[str, Any],
    *,
    secondary_archive_path: str | Path,
    secondary_verification: Mapping[str, Any],
    output_path: str | Path,
    primary_recorded_path: str | Path | None = None,
    authorized_max: int = PILOT_AUTHORIZED_MAX,
) -> dict[str, Any]:
    """Verify both copies and freeze exactly the archived BSON identities."""

    if manifest.get("archive_status") != "VERIFIED":
        raise PurgeSafetyError("cannot freeze IDs from an unverified archive")
    if int(manifest.get("selected_count", -1)) != authorized_max:
        raise PurgeSafetyError("archive count is outside the authorized pilot")
    if manifest.get("source_target", {}).get("database") != "honeypot_db":
        raise PurgeSafetyError("frozen source database is not honeypot_db")
    if manifest.get("source_target", {}).get("collection") != "hardware_metrics":
        raise PurgeSafetyError("frozen source collection is not hardware_metrics")
    _require_target_a_binding(manifest["source_target"])
    primary_verification, primary_documents = _verified_archive_documents(archive_path, manifest)
    secondary_verification_result, secondary_documents = _verified_archive_documents(
        secondary_archive_path, manifest
    )
    primary_sha = str(primary_verification["sha256"])
    secondary_sha = str(secondary_verification_result["sha256"])
    expected_sha = str(manifest["sha256"])
    if primary_sha != expected_sha or secondary_sha != expected_sha:
        raise PurgeSafetyError("primary or secondary archive hash differs from manifest")
    if primary_verification["records_sha256"] != secondary_verification_result["records_sha256"]:
        raise PurgeSafetyError("primary and secondary archive record digests differ")
    if secondary_verification.get("success") is not True and secondary_verification.get("verified") is not True:
        raise PurgeSafetyError("secondary copy has no independent verification receipt")
    secondary_receipt_sha = secondary_verification.get(
        "archive_sha256", secondary_verification.get("sha256")
    )
    if secondary_receipt_sha != expected_sha:
        raise PurgeSafetyError("secondary verification receipt hash mismatch")
    if int(secondary_verification.get("record_count", -1)) != authorized_max:
        raise PurgeSafetyError("secondary verification receipt count mismatch")
    if len(primary_documents) != len(secondary_documents):
        raise PurgeSafetyError("primary and secondary archive counts differ")
    primary_ids = [_identity_token(document["_id"]) for document in primary_documents]
    secondary_ids = [_identity_token(document["_id"]) for document in secondary_documents]
    if sorted(primary_ids) != sorted(secondary_ids):
        raise PurgeSafetyError("primary and secondary identity sets differ")
    if len(primary_ids) != len(set(primary_ids)):
        raise PurgeSafetyError("archive contains duplicate identities")
    ids = sorted(
        (document["_id"] for document in primary_documents),
        key=_identity_token,
    )
    frozen: dict[str, Any] = {
        "schema_version": PURGE_SET_VERSION,
        "purge_set_status": "FROZEN_VERIFIED",
        "archive_id": manifest["archive_id"],
        "source_target": dict(manifest["source_target"]),
        "archive_sha256": expected_sha,
        "records_sha256": manifest["records_sha256"],
        "exact_document_count": len(ids),
        "authorized_maximum": authorized_max,
        "identity_order": "canonical_extended_json_id_ascending",
        "identity_set_sha256": identity_set_sha256(ids),
        "document_ids": [canonical_ejson_object(value) for value in ids],
        "primary_copy": {
            "role": "PI_COLD_ARCHIVE",
            "path": str(primary_recorded_path or archive_path),
            "verification_path": str(archive_path),
            "sha256": primary_sha,
            "verified": True,
            "record_count": primary_verification["record_count"],
        },
        "secondary_copy": {
            "role": "LOCAL_PERSISTENT_WORKSTATION",
            "path": str(secondary_archive_path),
            "sha256": secondary_sha,
            "verified": True,
            "record_count": secondary_verification_result["record_count"],
            "verification_receipt_sha256": secondary_verification.get("receipt_sha256"),
        },
        "serialization": manifest.get("serialization"),
        "compression": manifest.get("compression"),
        "provenance": "LEGACY_TARGET_A_ARCHIVE_PURGE_PILOT",
        "frozen_at": utc_now(),
        "mutations_performed": False,
        "purge_set_sha256": "",
    }
    frozen["purge_set_sha256"] = _self_hash(frozen, "purge_set_sha256")
    write_immutable_json(output_path, frozen)
    return frozen


def build_exact_delete_filter(
    document_ids: Sequence[Any],
    *,
    authorized_remaining: int,
    authorized_max: int = PILOT_AUTHORIZED_MAX,
) -> dict[str, Any]:
    """Build the only destructive filter permitted by this module."""

    if not document_ids:
        raise PurgeSafetyError("destructive filter cannot contain an empty identity set")
    if len(document_ids) > authorized_max:
        raise PurgeSafetyError("destructive filter exceeds authorized maximum")
    if len(document_ids) > int(authorized_remaining):
        raise PurgeSafetyError("destructive filter exceeds authorized remaining set")
    tokens = [_identity_token(value) for value in document_ids]
    if len(tokens) != len(set(tokens)):
        raise PurgeSafetyError("destructive filter contains duplicate identities")
    return {"_id": {"$in": list(document_ids)}}


def _fetch_exact_documents(collection: Any, document_ids: Sequence[Any]) -> tuple[int, list[Mapping[str, Any]], int]:
    query = build_exact_delete_filter(
        document_ids,
        authorized_remaining=len(document_ids),
    )
    count = int(collection.count_documents(query))
    documents = list(collection.find(query))
    if len(documents) != count:
        raise PurgeSafetyError("exact source query count and returned document count differ")
    by_id: dict[str, Mapping[str, Any]] = {}
    for document in documents:
        if not isinstance(document, Mapping) or "_id" not in document:
            raise PurgeSafetyError("exact source query returned a document without _id")
        token = _identity_token(document["_id"])
        if token in by_id:
            raise PurgeSafetyError("exact source query returned a duplicate _id")
        by_id[token] = document
    ordered: list[Mapping[str, Any]] = []
    missing = 0
    for document_id in document_ids:
        value = by_id.get(_identity_token(document_id))
        if value is None:
            missing += 1
        else:
            ordered.append(value)
    return count, ordered, missing


def reconcile_exact_source(
    collection: Any,
    document_ids: Sequence[Any],
    *,
    expected_records_sha256: str | None = None,
) -> dict[str, Any]:
    """Read-only exact-ID reconciliation in frozen identity order."""

    count, documents, missing = _fetch_exact_documents(collection, document_ids)
    records_sha = _records_digest(documents) if missing == 0 else None
    content_drift = (
        expected_records_sha256 is not None
        and records_sha is not None
        and records_sha != expected_records_sha256
    )
    return {
        "exact_id_query": "_id in frozen exact purge set",
        "exact_id_count_requested": len(document_ids),
        "exact_id_count_present": count,
        "missing_id_count": missing,
        "duplicate_id_count": 0,
        "source_records_sha256": records_sha,
        "expected_records_sha256": expected_records_sha256,
        "content_drift_detected": bool(content_drift),
        "passed": count == len(document_ids) and missing == 0 and not content_drift,
        "broad_predicate_used": False,
        "mutations_performed": False,
    }


def _sentinel_metadata(document: Mapping[str, Any], role: str) -> dict[str, Any]:
    return {
        "role": role,
        "document_id": canonical_ejson_object(document["_id"]),
        "timestamp": canonical_ejson_object(document.get("timestamp"))
        if "timestamp" in document
        else None,
        "document_sha256": hashlib.sha256(
            (canonical_ejson_dumps(document) + "\n").encode("utf-8")
        ).hexdigest(),
    }


def capture_out_of_scope_sentinels(collection: Any, manifest: Mapping[str, Any]) -> dict[str, Any]:
    """Capture at most one safe metadata-only sentinel on each range side."""

    query = canonical_ejson_loads(_stable_json(manifest["query_predicate"]))
    timestamp = query.get("timestamp") if isinstance(query, Mapping) else None
    if not isinstance(timestamp, Mapping) or "$gte" not in timestamp or "$lt" not in timestamp:
        return {
            "status": "TIMESTAMP_BOUNDARY_UNAVAILABLE",
            "sentinels": [],
            "mutations_performed": False,
        }
    start = timestamp["$gte"]
    end = timestamp["$lt"]
    before = list(
        collection.find({"timestamp": {"$lt": start}})
        .sort([["timestamp", -1], ["_id", -1]])
        .limit(1)
    )
    after = list(
        collection.find({"timestamp": {"$gte": end}})
        .sort([["timestamp", 1], ["_id", 1]])
        .limit(1)
    )
    sentinels = []
    if before:
        sentinels.append(_sentinel_metadata(before[0], "BEFORE_ARCHIVE_RANGE"))
    if after:
        sentinels.append(_sentinel_metadata(after[0], "AFTER_ARCHIVE_RANGE"))
    return {
        "status": "CAPTURED" if sentinels else "NO_SENTINEL_AVAILABLE",
        "sentinels": sentinels,
        "mutations_performed": False,
    }


def verify_out_of_scope_sentinels(collection: Any, snapshot: Mapping[str, Any]) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    for sentinel in snapshot.get("sentinels", []):
        document_id = canonical_ejson_loads(_stable_json(sentinel["document_id"]))
        query = build_exact_delete_filter([document_id], authorized_remaining=1)
        documents = list(collection.find(query))
        if len(documents) != 1:
            checks.append({"role": sentinel.get("role"), "preserved": False, "reason": "missing"})
            continue
        actual = _sentinel_metadata(documents[0], str(sentinel.get("role")))
        checks.append(
            {
                "role": sentinel.get("role"),
                "preserved": actual["document_sha256"] == sentinel.get("document_sha256"),
                "document_sha256_before": sentinel.get("document_sha256"),
                "document_sha256_after": actual["document_sha256"],
            }
        )
    return {
        "status": "PASS" if all(item["preserved"] for item in checks) else "FAIL",
        "sentinel_count": len(checks),
        "checks": checks,
        "broad_delete_issued": False,
        "mutations_performed": False,
    }


def capture_storage_metrics(database: Any, *, tier_limit_bytes: int | None = None) -> dict[str, Any]:
    """Capture database and index metadata without changing MongoDB."""

    status = mongo_capacity_status(database, tier_limit_bytes=tier_limit_bytes)
    names = sorted(database.list_collection_names())
    status["indexes"] = safe_index_summary(database, names)
    status["index_status"] = "READ_ONLY_CAPTURED"
    status["mutations_performed"] = False
    return status


def _read_json(path: str | Path) -> dict[str, Any]:
    selected = Path(path)
    metadata = selected.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise PurgeSafetyError("receipt must be a regular non-symlink file")
    value = json.loads(selected.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise PurgeSafetyError("receipt must contain a JSON object")
    return value


def _append_progress(path: str | Path, receipt: Mapping[str, Any]) -> None:
    selected = Path(path)
    selected.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    selected.parent.chmod(0o700)
    if selected.exists() and selected.is_symlink():
        raise PurgeSafetyError("progress receipt must not be a symlink")
    encoded = (_stable_json(dict(receipt)) + "\n").encode("utf-8")
    descriptor = os.open(
        selected,
        os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW,
        0o600,
    )
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "ab") as handle:
            descriptor = -1
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        if descriptor != -1:
            os.close(descriptor)
    try:
        directory = os.open(selected.parent, os.O_RDONLY | os.O_DIRECTORY)
    except OSError:
        return
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _read_progress(path: str | Path) -> list[dict[str, Any]]:
    selected = Path(path)
    if not selected.exists():
        return []
    if selected.is_symlink() or not selected.is_file():
        raise PurgeSafetyError("progress receipt is not a regular file")
    result: list[dict[str, Any]] = []
    for line in selected.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise PurgeSafetyError("progress receipt line is not an object")
        result.append(value)
    return result


def _completed_batches(
    progress: Sequence[Mapping[str, Any]],
    frozen_ids: Sequence[Any],
    *,
    batch_size: int,
) -> tuple[set[int], int]:
    completed: set[int] = set()
    total_ack = 0
    for item in progress:
        if item.get("schema_version") != PURGE_PROGRESS_VERSION:
            raise PurgeSafetyError("unsupported purge progress receipt")
        index = int(item.get("batch_index", -1))
        if index < 0:
            raise PurgeSafetyError("purge progress batch index is outside frozen set")
        expected = list(frozen_ids[index * batch_size : (index + 1) * batch_size])
        if not expected:
            raise PurgeSafetyError("purge progress batch index is outside frozen set")
        if item.get("status") != "COMPLETED":
            raise PurgeSafetyError("purge progress contains a non-completed batch")
        if int(item.get("expected_count", -1)) != len(expected):
            raise PurgeSafetyError("purge progress expected count mismatch")
        if item.get("identity_set_sha256") != identity_set_sha256(expected):
            raise PurgeSafetyError("purge progress identity digest mismatch")
        if int(item.get("acknowledged_deleted_count", -1)) != len(expected):
            raise PurgeSafetyError("purge progress acknowledged count mismatch")
        if index in completed:
            raise PurgeSafetyError("duplicate completed purge batch")
        completed.add(index)
        total_ack += len(expected)
    return completed, total_ack


def build_predelete_verification(
    collection: Any,
    frozen: Mapping[str, Any],
    manifest: Mapping[str, Any],
    *,
    target: Mapping[str, Any],
    storage_before: Mapping[str, Any] | None,
    pi_capacity: Mapping[str, Any] | None,
    secondary_capacity: Mapping[str, Any] | None,
    sentinels: Mapping[str, Any] | None,
    bson_tests_passed: bool,
    recovery_procedure_written: bool,
    explicit_confirmation: bool,
    reconciliation_ids: Sequence[Any] | None = None,
    reconciliation_records_sha256: str | None = None,
    completed_batch_count: int = 0,
    authorized_max: int = PILOT_AUTHORIZED_MAX,
) -> dict[str, Any]:
    """Build the durable pre-delete GO/NO-GO table from current read-only data."""

    ids = validate_frozen_purge_set(frozen, manifest, authorized_max=authorized_max)
    ids_to_reconcile = list(ids if reconciliation_ids is None else reconciliation_ids)
    expected_reconciliation_digest = reconciliation_records_sha256
    if expected_reconciliation_digest is None and completed_batch_count == 0:
        expected_reconciliation_digest = str(frozen["records_sha256"])
    source = manifest["source_target"]
    if dict(target) != dict(source):
        raise PurgeSafetyError("current target does not exactly match frozen Target A")
    if getattr(collection, "name", None) != source["collection"]:
        raise PurgeSafetyError("current collection does not match frozen Target A")
    if ids_to_reconcile:
        reconciliation = reconcile_exact_source(
            collection,
            ids_to_reconcile,
            expected_records_sha256=expected_reconciliation_digest,
        )
    else:
        reconciliation = {
            "exact_id_query": "no remaining IDs; all frozen batches already completed",
            "exact_id_count_requested": 0,
            "exact_id_count_present": 0,
            "missing_id_count": 0,
            "duplicate_id_count": 0,
            "source_records_sha256": None,
            "expected_records_sha256": expected_reconciliation_digest,
            "content_drift_detected": False,
            "passed": True,
            "broad_predicate_used": False,
            "mutations_performed": False,
        }
    gate = {
        "correct_target_identity": True,
        "correct_database": source["database"] == "honeypot_db",
        "correct_collection": source["collection"] == "hardware_metrics",
        "original_archive_verified": manifest.get("archive_status") == "VERIFIED",
        "original_archive_sha_matches": frozen.get("archive_sha256") == manifest.get("sha256"),
        "original_archive_count_463": int(frozen.get("exact_document_count", -1)) == authorized_max,
        "bson_applicable_tests_passed": bson_tests_passed,
        "pi_archive_restore_read_passed": bool(frozen.get("primary_copy", {}).get("verified")),
        "secondary_copy_exists": bool(frozen.get("secondary_copy", {}).get("path")),
        "secondary_sha_matches": bool(frozen.get("secondary_copy", {}).get("sha256") == frozen.get("archive_sha256")),
        "secondary_restore_read_passed": bool(frozen.get("secondary_copy", {}).get("verified")),
        "exact_id_set_463_unique": len(ids) == authorized_max,
        "exact_id_set_hash_frozen": bool(frozen.get("identity_set_sha256")),
        "exact_ids_currently_exist": reconciliation["exact_id_count_present"] == len(ids_to_reconcile)
        and (completed_batch_count > 0 or len(ids_to_reconcile) == authorized_max),
        "source_archive_reconciliation_passed": reconciliation["passed"],
        "purge_authorization_max_463": authorized_max == PILOT_AUTHORIZED_MAX,
        "destructive_filter_cannot_widen": True,
        "recovery_procedure_written": recovery_procedure_written,
        "prepurge_capacity_metrics_captured": storage_before is not None,
        "explicit_confirmation": explicit_confirmation,
    }
    all_required_gates = all(
        value for key, value in gate.items() if key != "explicit_confirmation"
    )
    status = (
        "GO"
        if all_required_gates and explicit_confirmation
        else "READY"
        if all_required_gates and not explicit_confirmation
        else "NO_GO"
    )
    return {
        "schema_version": "mongo_pi_archive_purge_predelete_verification.v1",
        "status": status,
        "go_no_go": gate,
        "archive_id": frozen["archive_id"],
        "source_target": dict(source),
        "archive_sha256": frozen["archive_sha256"],
        "identity_set_sha256": frozen["identity_set_sha256"],
        "exact_document_count": len(ids),
        "reconciliation_document_count": len(ids_to_reconcile),
        "completed_batch_count": completed_batch_count,
        "reconciliation": reconciliation,
        "storage_before": dict(storage_before or {}),
        "pi_capacity": dict(pi_capacity or {}),
        "secondary_capacity": dict(secondary_capacity or {}),
        "out_of_scope_sentinels": dict(sentinels or {}),
        "delete_filter_shape": "{_id: {$in: frozen_exact_ids}}",
        "broad_predicate_used": False,
        "target_b_collection_mutated": False,
        "created_at": utc_now(),
        "mutations_performed": False,
    }


def execute_exact_purge(
    collection: Any,
    frozen: Mapping[str, Any],
    manifest: Mapping[str, Any],
    *,
    target: Mapping[str, Any],
    predelete_receipt_path: str | Path,
    progress_path: str | Path,
    execution_receipt_path: str | Path,
    batch_size: int = DEFAULT_BATCH_SIZE,
    authorized_max: int = PILOT_AUTHORIZED_MAX,
    explicit_confirmation: bool = False,
    storage_before: Mapping[str, Any] | None = None,
    pi_capacity: Mapping[str, Any] | None = None,
    secondary_capacity: Mapping[str, Any] | None = None,
    sentinels: Mapping[str, Any] | None = None,
    bson_tests_passed: bool = False,
    recovery_procedure_written: bool = False,
) -> dict[str, Any]:
    """Execute only the frozen set, with durable exact-ID batch receipts."""

    if not explicit_confirmation:
        raise PurgeSafetyError("explicit purge confirmation is required")
    if batch_size <= 0 or batch_size > authorized_max:
        raise PurgeSafetyError("invalid purge batch size")
    ids = validate_frozen_purge_set(frozen, manifest, authorized_max=authorized_max)
    progress = _read_progress(progress_path)
    completed, total_ack = _completed_batches(progress, ids, batch_size=batch_size)
    total_batches = (len(ids) + batch_size - 1) // batch_size
    if any(index >= total_batches for index in completed):
        raise PurgeSafetyError("purge progress batch index is outside the frozen batch plan")
    for index in completed:
        completed_batch = ids[index * batch_size : (index + 1) * batch_size]
        completed_query = build_exact_delete_filter(
            completed_batch,
            authorized_remaining=len(ids),
            authorized_max=authorized_max,
        )
        if int(collection.count_documents(completed_query)) != 0:
            raise PurgeSafetyError("completed purge batch is not absent from source")
    remaining_ids = [
        document_id
        for index in range(total_batches)
        if index not in completed
        for document_id in ids[index * batch_size : (index + 1) * batch_size]
    ]
    predelete = build_predelete_verification(
        collection,
        frozen,
        manifest,
        target=target,
        storage_before=storage_before,
        pi_capacity=pi_capacity,
        secondary_capacity=secondary_capacity,
        sentinels=sentinels,
        bson_tests_passed=bson_tests_passed,
        recovery_procedure_written=recovery_procedure_written,
        explicit_confirmation=explicit_confirmation,
        reconciliation_ids=remaining_ids,
        completed_batch_count=len(completed),
        authorized_max=authorized_max,
    )
    write_immutable_json(predelete_receipt_path, predelete)
    if predelete["status"] != "GO":
        raise PurgeSafetyError("pre-delete GO/NO-GO gate is NO_GO")

    for index in range(total_batches):
        batch = ids[index * batch_size : (index + 1) * batch_size]
        if index in completed:
            continue
        query = build_exact_delete_filter(
            batch,
            authorized_remaining=len(ids) - total_ack,
            authorized_max=authorized_max,
        )
        before_count = int(collection.count_documents(query))
        if before_count == 0:
            raise PurgeSafetyError(
                "unreceipted batch is already absent; refusing to infer acknowledged deletion"
            )
        if before_count != len(batch):
            failure = {
                "schema_version": PURGE_PROGRESS_VERSION,
                "status": "SOURCE_COUNT_MISMATCH_STOPPED",
                "batch_index": index,
                "expected_count": len(batch),
                "observed_count": before_count,
                "identity_set_sha256": identity_set_sha256(batch),
                "recorded_at": utc_now(),
                "mutations_performed": False,
            }
            _append_progress(progress_path, failure)
            raise PurgeSafetyError("exact batch source count mismatch before delete")
        result = collection.delete_many(query)
        acknowledged = bool(getattr(result, "acknowledged", False))
        deleted_count = int(getattr(result, "deleted_count", -1))
        after_count = int(collection.count_documents(query))
        if not acknowledged or deleted_count != len(batch) or after_count != 0:
            failure = {
                "schema_version": PURGE_PROGRESS_VERSION,
                "status": "PARTIAL_DELETE_STOPPED",
                "batch_index": index,
                "expected_count": len(batch),
                "pre_delete_count": before_count,
                "acknowledged": acknowledged,
                "acknowledged_deleted_count": deleted_count,
                "post_delete_remaining": after_count,
                "identity_set_sha256": identity_set_sha256(batch),
                "recorded_at": utc_now(),
                "mutations_performed": acknowledged and deleted_count > 0,
            }
            _append_progress(progress_path, failure)
            raise PurgeSafetyError("purge batch acknowledgement or absence verification failed")
        receipt = {
            "schema_version": PURGE_PROGRESS_VERSION,
            "status": "COMPLETED",
            "batch_index": index,
            "batch_count_total": total_batches,
            "expected_count": len(batch),
            "pre_delete_count": before_count,
            "acknowledged": acknowledged,
            "acknowledged_deleted_count": deleted_count,
            "post_delete_remaining": after_count,
            "identity_set_sha256": identity_set_sha256(batch),
            "filter_shape": "{_id: {$in: frozen_exact_ids}}",
            "broad_predicate_used": False,
            "recorded_at": utc_now(),
            "mutations_performed": True,
        }
        _append_progress(progress_path, receipt)
        total_ack += deleted_count
        completed.add(index)

    final_query = build_exact_delete_filter(
        ids,
        authorized_remaining=len(ids),
        authorized_max=authorized_max,
    )
    remaining = int(collection.count_documents(final_query))
    if remaining != 0 or total_ack != authorized_max:
        raise PurgeSafetyError("final exact purge verification failed")
    source = manifest["source_target"]
    execution = {
        "schema_version": PURGE_EXECUTION_VERSION,
        "status": "COMPLETED",
        "archive_id": frozen["archive_id"],
        "source_target": dict(source),
        "identity_set_sha256": frozen["identity_set_sha256"],
        "authorized_maximum": authorized_max,
        "batch_size": batch_size,
        "batch_count": total_batches,
        "acknowledged_deleted_total": total_ack,
        "remaining_archived_ids": remaining,
        "out_of_scope_delete_operation": False,
        "target_b_mutated": False,
        "pi_spool_modified": False,
        "services_restarted": False,
        "credentials_exposed": False,
        "completed_at": utc_now(),
        "mutations_performed": True,
    }
    write_immutable_json(execution_receipt_path, execution)
    return execution


def verify_postdelete_exact_set(
    collection: Any,
    frozen: Mapping[str, Any],
    manifest: Mapping[str, Any],
    *,
    target: Mapping[str, Any],
    sentinels: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Prove frozen IDs are absent and sentinels remain preserved."""

    ids = validate_frozen_purge_set(frozen, manifest)
    if dict(target) != dict(manifest["source_target"]):
        raise PurgeSafetyError("post-delete target identity mismatch")
    query = build_exact_delete_filter(ids, authorized_remaining=len(ids))
    remaining = int(collection.count_documents(query))
    sentinel_result = (
        verify_out_of_scope_sentinels(collection, sentinels)
        if sentinels is not None
        else {"status": "NOT_CAPTURED", "sentinel_count": 0, "checks": []}
    )
    return {
        "schema_version": "mongo_pi_archive_purge_postdelete_verification.v1",
        "status": "PASS" if remaining == 0 and sentinel_result["status"] in {"PASS", "NOT_CAPTURED"} else "FAIL",
        "archive_id": frozen["archive_id"],
        "source_target": dict(manifest["source_target"]),
        "identity_set_sha256": frozen["identity_set_sha256"],
        "exact_ids_expected": len(ids),
        "exact_ids_remaining": remaining,
        "acknowledged_deleted_total": PILOT_AUTHORIZED_MAX,
        "out_of_scope_sentinel_verification": sentinel_result,
        "broad_delete_issued": False,
        "mutations_performed": False,
        "verified_at": utc_now(),
    }
