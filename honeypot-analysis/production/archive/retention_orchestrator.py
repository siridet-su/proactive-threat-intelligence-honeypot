"""Bounded, resumable archive/verify/secondary/purge orchestration.

The default path is a read-only plan.  Mongo deletion is reachable only from
an explicit manual execution call with a frozen exact identity set and both
archive copies independently verified.  Automatic purge is never inferred
from configuration defaults.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping, Protocol

from .cold_archive import (
    ArchiveError,
    ArchiveIDConflict,
    ArchiveSpec,
    PurgeSafetyError,
    _copy_fsync,
    _self_hash,
    _stable_json,
    archive_paths,
    canonical_ejson_dumps,
    canonical_ejson_loads,
    ensure_archive_root,
    export_archive,
    filesystem_capacity,
    mongo_capacity_status,
    pi_capacity_gate,
    read_archive_verified,
    sha256_file,
    utc_now,
    write_immutable_json,
)
from .purge import (
    PURGE_PROGRESS_VERSION,
    _append_progress,
    _completed_batches,
    _read_progress,
    build_exact_delete_filter,
    identity_set_sha256,
    reconcile_exact_source,
    _verified_archive_documents,
)
from .retention_planner import RetentionPlan, plan_retention
from .retention_policy import CollectionPolicy, RetentionConfig, lifecycle_query


RETENTION_RECEIPT_VERSION = "mongo_pi_retention_receipt.v1"
RETENTION_STAGE_VERSION = "mongo_pi_retention_stage.v1"
RETENTION_INDEX_VERSION = "mongo_pi_retention_archive_index_event.v1"
RETENTION_FROZEN_SET_VERSION = "mongo_pi_retention_exact_set.v1"


class RetentionExecutionError(RuntimeError):
    pass


class SecondaryBackend(Protocol):
    name: str

    def capacity(self) -> dict[str, Any]: ...

    def replicate(self, archive_path: str | Path, manifest: Mapping[str, Any]) -> dict[str, Any]: ...


def _private_regular(path: Path) -> None:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise RetentionExecutionError("archive path must be a regular non-symlink file")
    if metadata.st_mode & 0o077:
        raise RetentionExecutionError("archive path grants group or other permissions")


def _capacity_gate(
    capacity: Mapping[str, Any],
    required_bytes: int,
    *,
    reserve_bytes: int,
    max_used_ratio: float,
) -> dict[str, Any]:
    free = int(capacity["free_bytes"])
    total = int(capacity["total_bytes"])
    used = int(capacity["used_bytes"])
    projected_used = used + int(required_bytes)
    projected_ratio = projected_used / total if total else 1.0
    passed = free - required_bytes >= reserve_bytes and projected_ratio <= max_used_ratio
    return {
        "passed": passed,
        "free_before_bytes": free,
        "required_bytes": int(required_bytes),
        "reserve_bytes": reserve_bytes,
        "free_after_bytes": free - int(required_bytes),
        "projected_used_ratio": round(projected_ratio, 8),
        "max_used_ratio": max_used_ratio,
        "reason": "PASS" if passed else "CAPACITY_INSUFFICIENT",
    }


class FilesystemSecondaryBackend:
    """Independent filesystem copy backend; replaceable by a future backend."""

    name = "filesystem"

    def __init__(self, root: str | Path, *, reserve_bytes: int, max_used_ratio: float) -> None:
        selected = Path(root)
        if not selected.is_absolute():
            raise RetentionExecutionError("secondary root must be absolute")
        if selected.exists() and selected.is_symlink():
            raise RetentionExecutionError("secondary root must not be a symlink")
        self.root = selected
        self.reserve_bytes = int(reserve_bytes)
        self.max_used_ratio = float(max_used_ratio)

    def capacity(self) -> dict[str, Any]:
        probe = self.root if self.root.exists() else self.root.parent
        if not probe.exists():
            raise RetentionExecutionError("secondary capacity path is unavailable")
        return {
            **filesystem_capacity(probe),
            "configured_root": str(self.root),
            "capacity_probe_path": str(probe),
        }

    def _destination(self, archive_id: str) -> Path:
        if not archive_id or any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-" for char in archive_id):
            raise RetentionExecutionError("archive ID contains unsafe path characters")
        return self.root / "archives" / f"{archive_id}.ejsonl.zst"

    def replicate(self, archive_path: str | Path, manifest: Mapping[str, Any]) -> dict[str, Any]:
        source = Path(archive_path)
        _private_regular(source)
        archive_id = str(manifest.get("archive_id") or "")
        destination = self._destination(archive_id)
        expected_sha = str(manifest.get("sha256") or "")
        expected_count = int(manifest.get("selected_count", -1))
        capacity = self.capacity()
        gate = _capacity_gate(
            capacity,
            source.stat().st_size,
            reserve_bytes=self.reserve_bytes,
            max_used_ratio=self.max_used_ratio,
        )
        if not gate["passed"]:
            raise RetentionExecutionError("secondary capacity gate failed")
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        destination.parent.chmod(0o700)
        if destination.exists():
            _private_regular(destination)
            if sha256_file(destination) != expected_sha:
                raise ArchiveIDConflict("secondary archive ID exists with a conflicting hash")
            verification = read_archive_verified(destination, manifest=manifest)
            if verification["record_count"] != expected_count:
                raise RetentionExecutionError("secondary existing archive count mismatch")
            return {
                "status": "ALREADY_VERIFIED",
                "backend": self.name,
                "path": str(destination),
                "sha256": verification["sha256"],
                "record_count": verification["record_count"],
                "records_sha256": verification["records_sha256"],
                "verified": True,
                "capacity_gate": gate,
            }
        partial = destination.with_suffix(destination.suffix + ".partial")
        if partial.exists():
            raise ArchiveIDConflict("secondary partial archive exists; quarantine/review is required")
        _copy_fsync(source, partial)
        try:
            if sha256_file(partial) != expected_sha:
                raise RetentionExecutionError("secondary copied archive hash mismatch")
            os.replace(partial, destination)
            os.chmod(destination, 0o600)
        finally:
            if partial.exists():
                partial.unlink()
        verification = read_archive_verified(destination, manifest=manifest)
        if verification["record_count"] != expected_count:
            raise RetentionExecutionError("secondary copied archive count mismatch")
        return {
            "status": "VERIFIED",
            "backend": self.name,
            "path": str(destination),
            "sha256": verification["sha256"],
            "record_count": verification["record_count"],
            "records_sha256": verification["records_sha256"],
            "verified": True,
            "capacity_gate": gate,
        }


def _append_jsonl_event(path: Path, event: Mapping[str, Any]) -> bool:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.parent.chmod(0o700)
    if path.exists() and path.is_symlink():
        raise RetentionExecutionError("retention archive index must not be a symlink")
    event_id = str(event.get("event_id") or "")
    encoded = (_stable_json(dict(event)) + "\n").encode("utf-8")
    try:
        import fcntl
    except ImportError:  # pragma: no cover
        fcntl = None
    with path.open("a+b") as handle:
        if fcntl is not None:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            handle.seek(0)
            for line in handle:
                if not line.strip():
                    continue
                prior = json.loads(line)
                if prior.get("event_id") == event_id:
                    prior_comparable = dict(prior)
                    event_comparable = dict(event)
                    prior_comparable.pop("recorded_at", None)
                    event_comparable.pop("recorded_at", None)
                    if prior_comparable != event_comparable:
                        raise RetentionExecutionError("retention index event ID conflict")
                    return False
            handle.seek(0, os.SEEK_END)
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        finally:
            if fcntl is not None:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    return True


def _read_json(path: str | Path) -> dict[str, Any]:
    selected = Path(path)
    if selected.is_symlink() or not selected.is_file():
        raise RetentionExecutionError("retention receipt is not a regular file")
    value = json.loads(selected.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RetentionExecutionError("retention receipt must contain an object")
    return value


def _write_stage(run_dir: Path, stage: str, payload: Mapping[str, Any]) -> dict[str, Any]:
    event = {
        "schema_version": RETENTION_STAGE_VERSION,
        "stage": stage,
        "recorded_at": utc_now(),
        **dict(payload),
    }
    path = run_dir / "stages.jsonl"
    event_id = hashlib.sha256(
        _stable_json({"schema_version": RETENTION_STAGE_VERSION, "stage": stage, **dict(payload)}).encode()
    ).hexdigest()
    _append_jsonl_event(path, {"event_id": event_id, **event})
    return event


def _filesystem_capacity_or_unavailable(path: str | Path) -> dict[str, Any]:
    selected = Path(path)
    probe = selected if selected.exists() else selected.parent
    if not probe.exists():
        return {"status": "UNAVAILABLE", "path": str(selected)}
    try:
        return {"status": "READ_ONLY_CAPTURED", **filesystem_capacity(probe)}
    except OSError:
        return {"status": "UNAVAILABLE", "path": str(selected)}


def freeze_retention_purge_set(
    primary_archive_path: str | Path,
    secondary_archive_path: str | Path,
    manifest: Mapping[str, Any],
    secondary_verification: Mapping[str, Any],
    *,
    output_path: str | Path,
    run_id: str,
    authorized_maximum: int,
) -> dict[str, Any]:
    """Freeze the exact IDs from two independently verified archive copies."""

    selected_output = Path(output_path)
    if selected_output.exists():
        existing = _read_json(selected_output)
        if (
            existing.get("schema_version") == RETENTION_FROZEN_SET_VERSION
            and existing.get("purge_set_status") == "FROZEN_VERIFIED"
            and existing.get("archive_id") == manifest.get("archive_id")
            and existing.get("archive_sha256") == manifest.get("sha256")
            and existing.get("source_target") == manifest.get("source_target")
            and existing.get("purge_set_sha256") == _self_hash(existing, "purge_set_sha256")
        ):
            return existing
        raise ArchiveIDConflict("retention frozen-set path conflicts with the archive binding")

    if manifest.get("archive_status") != "VERIFIED":
        raise PurgeSafetyError("retention purge set requires a verified primary archive")
    if secondary_verification.get("verified") is not True:
        raise PurgeSafetyError("retention purge set requires an independently verified secondary copy")
    count = int(manifest.get("selected_count", -1))
    if count <= 0 or count > int(authorized_maximum):
        raise PurgeSafetyError("retention archive count exceeds the configured cycle bound")
    primary_verification, primary_documents = _verified_archive_documents(primary_archive_path, manifest)
    secondary_verification_result, secondary_documents = _verified_archive_documents(
        secondary_archive_path, manifest
    )
    expected_sha = str(manifest.get("sha256"))
    if primary_verification["sha256"] != expected_sha or secondary_verification_result["sha256"] != expected_sha:
        raise PurgeSafetyError("retention archive copy hash mismatch")
    if int(secondary_verification.get("record_count", -1)) != count:
        raise PurgeSafetyError("secondary verification receipt count mismatch")
    receipt_sha = secondary_verification.get("sha256", secondary_verification.get("archive_sha256"))
    if receipt_sha != expected_sha:
        raise PurgeSafetyError("secondary verification receipt hash mismatch")
    primary_tokens = [_id_token(document["_id"]) for document in primary_documents]
    secondary_tokens = [_id_token(document["_id"]) for document in secondary_documents]
    if sorted(primary_tokens) != sorted(secondary_tokens) or len(primary_tokens) != len(set(primary_tokens)):
        raise PurgeSafetyError("primary and secondary exact identity sets differ")
    ids = sorted((document["_id"] for document in primary_documents), key=_id_token)
    frozen: dict[str, Any] = {
        "schema_version": RETENTION_FROZEN_SET_VERSION,
        "purge_set_status": "FROZEN_VERIFIED",
        "run_id": run_id,
        "archive_id": manifest["archive_id"],
        "source_target": dict(manifest["source_target"]),
        "archive_sha256": expected_sha,
        "records_sha256": manifest["records_sha256"],
        "exact_document_count": len(ids),
        "authorized_maximum": int(authorized_maximum),
        "identity_order": "canonical_extended_json_id_ascending",
        "identity_set_sha256": identity_set_sha256(ids),
        "document_ids": [
            json.loads(canonical_ejson_dumps(value)) for value in ids
        ],
        "primary_copy": {
            "role": "PI_COLD_ARCHIVE",
            "path": str(primary_archive_path),
            "sha256": primary_verification["sha256"],
            "record_count": primary_verification["record_count"],
            "verified": True,
        },
        "secondary_copy": {
            "role": str(secondary_verification.get("backend") or "INDEPENDENT_SECONDARY"),
            "path": str(secondary_archive_path),
            "sha256": secondary_verification_result["sha256"],
            "record_count": secondary_verification_result["record_count"],
            "verification_receipt_sha256": secondary_verification.get("receipt_sha256"),
            "verified": True,
        },
        "provenance": "RETENTION_ORCHESTRATOR",
        "mutations_performed": False,
        "frozen_at": utc_now(),
        "purge_set_sha256": "",
    }
    frozen["purge_set_sha256"] = _self_hash(frozen, "purge_set_sha256")
    write_immutable_json(output_path, frozen)
    return frozen


def _id_token(value: Any) -> str:
    return canonical_ejson_dumps(value)


def _validate_retention_frozen_set(
    frozen: Mapping[str, Any],
    manifest: Mapping[str, Any],
    config: RetentionConfig,
) -> list[Any]:
    if frozen.get("schema_version") != RETENTION_FROZEN_SET_VERSION:
        raise PurgeSafetyError("unsupported retention frozen-set schema")
    if frozen.get("purge_set_status") != "FROZEN_VERIFIED":
        raise PurgeSafetyError("retention purge set is not frozen and verified")
    if manifest.get("archive_status") != "VERIFIED":
        raise PurgeSafetyError("retention manifest is not verified")
    expected_target = manifest.get("source_target")
    if not isinstance(expected_target, Mapping) or not expected_target.get("collection"):
        raise PurgeSafetyError("retention manifest source target is invalid")
    if dict(expected_target) != config.target.source_target(str(expected_target["collection"])):
        raise PurgeSafetyError("retention manifest target does not match configured target")
    if frozen.get("source_target") != expected_target:
        raise PurgeSafetyError("retention frozen-set target mismatch")
    if frozen.get("archive_id") != manifest.get("archive_id") or frozen.get("archive_sha256") != manifest.get("sha256"):
        raise PurgeSafetyError("retention frozen-set archive binding mismatch")
    count = int(frozen.get("exact_document_count", -1))
    if count <= 0 or count > config.capacity.max_documents_per_cycle:
        raise PurgeSafetyError("retention frozen-set count exceeds cycle bound")
    if int(frozen.get("authorized_maximum", -1)) != config.capacity.max_documents_per_cycle:
        raise PurgeSafetyError("retention frozen-set maximum is not the configured cycle bound")
    if frozen.get("purge_set_sha256") != _self_hash(frozen, "purge_set_sha256"):
        raise PurgeSafetyError("retention frozen-set self-hash mismatch")
    raw_ids = frozen.get("document_ids")
    if not isinstance(raw_ids, list) or len(raw_ids) != count:
        raise PurgeSafetyError("retention frozen-set identities are invalid")
    ids = [canonical_ejson_loads(_stable_json(value)) for value in raw_ids]
    tokens = [_id_token(value) for value in ids]
    if len(tokens) != len(set(tokens)) or tokens != sorted(tokens):
        raise PurgeSafetyError("retention frozen-set identities are not unique and ordered")
    if identity_set_sha256(ids) != frozen.get("identity_set_sha256"):
        raise PurgeSafetyError("retention frozen-set identity hash mismatch")
    for key in ("primary_copy", "secondary_copy"):
        copy = frozen.get(key)
        if not isinstance(copy, Mapping) or copy.get("verified") is not True or copy.get("sha256") != frozen.get("archive_sha256"):
            raise PurgeSafetyError("both verified archive copies are required")
    if frozen.get("mutations_performed") is not False:
        raise PurgeSafetyError("retention frozen-set is not mutation-free")
    return ids


def execute_retention_exact_purge(
    collection: Any,
    frozen: Mapping[str, Any],
    manifest: Mapping[str, Any],
    config: RetentionConfig,
    *,
    run_dir: str | Path,
    explicit_confirmation: bool,
    dependency_safety_verified: bool = False,
) -> dict[str, Any]:
    """Execute/resume only the frozen retention identity set."""

    if not explicit_confirmation:
        raise PurgeSafetyError("explicit purge confirmation is required")
    policy = config.policy_for(str(manifest["source_target"]["collection"]))
    if policy is None or not policy.purge_eligible:
        raise PurgeSafetyError("collection policy does not permit purge")
    if policy.dependencies and not dependency_safety_verified:
        raise PurgeSafetyError("dependent collection requires an independent dependency-safety receipt")
    ids = _validate_retention_frozen_set(frozen, manifest, config)
    run_path = Path(run_dir)
    run_path.mkdir(parents=True, exist_ok=True, mode=0o700)
    progress_path = run_path / "purge_progress.jsonl"
    execution_path = run_path / "purge_execution.json"
    if execution_path.exists():
        existing = _read_json(execution_path)
        if (
            existing.get("status") != "COMPLETED"
            or existing.get("archive_id") != frozen.get("archive_id")
            or existing.get("identity_set_sha256") != frozen.get("identity_set_sha256")
        ):
            raise PurgeSafetyError("existing retention execution receipt conflicts")
        if int(collection.count_documents(build_exact_delete_filter(ids, authorized_remaining=len(ids), authorized_max=len(ids)))) != 0:
            raise PurgeSafetyError("completed retention receipt is not consistent with source absence")
        return {**existing, "status": "ALREADY_PURGED", "mutations_performed": False}
    batch_size = min(config.capacity.batch_size_documents, len(ids))
    total_batches = (len(ids) + batch_size - 1) // batch_size
    if total_batches > config.capacity.max_batches_per_run:
        raise PurgeSafetyError("retention batch count exceeds configured maximum")
    progress = _read_progress(progress_path)
    completed, total_ack = _completed_batches(progress, ids, batch_size=batch_size)
    for index in completed:
        batch = ids[index * batch_size : (index + 1) * batch_size]
        if collection.count_documents(
            build_exact_delete_filter(batch, authorized_remaining=len(ids), authorized_max=len(ids))
        ) != 0:
            raise PurgeSafetyError("receipted retention batch is still present")
    remaining_ids = [
        value
        for index in range(total_batches)
        if index not in completed
        for value in ids[index * batch_size : (index + 1) * batch_size]
    ]
    if remaining_ids:
        reconciliation = reconcile_exact_source(
            collection,
            remaining_ids,
            expected_records_sha256=(str(frozen["records_sha256"]) if not completed else None),
        )
        if not reconciliation["passed"]:
            raise PurgeSafetyError("retention pre-delete reconciliation failed")
    predelete = {
        "schema_version": "mongo_pi_retention_predelete.v1",
        "status": "READY",
        "run_id": frozen.get("run_id"),
        "archive_id": frozen["archive_id"],
        "source_target": dict(manifest["source_target"]),
        "identity_set_sha256": frozen["identity_set_sha256"],
        "exact_document_count": len(ids),
        "remaining_document_count": len(remaining_ids),
        "completed_batch_count": len(completed),
        "reconciliation": reconciliation if remaining_ids else {"passed": True, "requested": 0},
        "delete_filter_shape": "{_id: {$in: frozen_exact_ids}}",
        "broad_predicate_used": False,
        "mutations_performed": False,
        "created_at": utc_now(),
        "predelete_sha256": "",
    }
    predelete["predelete_sha256"] = _self_hash(predelete, "predelete_sha256")
    predelete_path = run_path / "predelete.json"
    if predelete_path.exists():
        prior = _read_json(predelete_path)
        if prior.get("archive_id") != predelete["archive_id"] or prior.get("identity_set_sha256") != predelete["identity_set_sha256"]:
            raise PurgeSafetyError("existing retention pre-delete receipt conflicts")
        if prior.get("predelete_sha256") != _self_hash(prior, "predelete_sha256"):
            raise PurgeSafetyError("existing retention pre-delete receipt self-hash mismatch")
    else:
        write_immutable_json(predelete_path, predelete)
    for index in range(total_batches):
        if index in completed:
            continue
        batch = ids[index * batch_size : (index + 1) * batch_size]
        query = build_exact_delete_filter(
            batch,
            authorized_remaining=len(ids) - total_ack,
            authorized_max=len(ids),
        )
        before = int(collection.count_documents(query))
        if before != len(batch):
            failure = {
                "schema_version": PURGE_PROGRESS_VERSION,
                "status": "SOURCE_COUNT_MISMATCH_STOPPED",
                "batch_index": index,
                "expected_count": len(batch),
                "observed_count": before,
                "identity_set_sha256": identity_set_sha256(batch),
                "recorded_at": utc_now(),
                "mutations_performed": False,
            }
            _append_progress(progress_path, failure)
            raise PurgeSafetyError("retention batch count mismatch before delete")
        result = collection.delete_many(query)
        acknowledged = bool(getattr(result, "acknowledged", False))
        deleted = int(getattr(result, "deleted_count", -1))
        after = int(collection.count_documents(query))
        if not acknowledged or deleted != len(batch) or after != 0:
            _append_progress(
                progress_path,
                {
                    "schema_version": PURGE_PROGRESS_VERSION,
                    "status": "PARTIAL_DELETE_STOPPED",
                    "batch_index": index,
                    "expected_count": len(batch),
                    "pre_delete_count": before,
                    "acknowledged": acknowledged,
                    "acknowledged_deleted_count": deleted,
                    "post_delete_remaining": after,
                    "identity_set_sha256": identity_set_sha256(batch),
                    "recorded_at": utc_now(),
                    "mutations_performed": acknowledged and deleted > 0,
                },
            )
            raise PurgeSafetyError("retention batch acknowledgement/absence verification failed")
        _append_progress(
            progress_path,
            {
                "schema_version": PURGE_PROGRESS_VERSION,
                "status": "COMPLETED",
                "batch_index": index,
                "batch_count_total": total_batches,
                "expected_count": len(batch),
                "pre_delete_count": before,
                "acknowledged": acknowledged,
                "acknowledged_deleted_count": deleted,
                "post_delete_remaining": after,
                "identity_set_sha256": identity_set_sha256(batch),
                "filter_shape": "{_id: {$in: frozen_exact_ids}}",
                "broad_predicate_used": False,
                "recorded_at": utc_now(),
                "mutations_performed": True,
            },
        )
        total_ack += deleted
    remaining = int(
        collection.count_documents(
            build_exact_delete_filter(ids, authorized_remaining=len(ids), authorized_max=len(ids))
        )
    )
    if remaining != 0 or total_ack != len(ids):
        raise PurgeSafetyError("retention final exact absence/count check failed")
    execution = {
        "schema_version": "mongo_pi_retention_purge_execution.v1",
        "status": "COMPLETED",
        "run_id": frozen.get("run_id"),
        "archive_id": frozen["archive_id"],
        "source_target": dict(manifest["source_target"]),
        "identity_set_sha256": frozen["identity_set_sha256"],
        "authorized_maximum": config.capacity.max_documents_per_cycle,
        "batch_size": batch_size,
        "batch_count": total_batches,
        "acknowledged_deleted_total": total_ack,
        "remaining_archived_ids": remaining,
        "broad_predicate_used": False,
        "target_b_mutated": False,
        "pi_spool_modified": False,
        "services_restarted": False,
        "credentials_exposed": False,
        "mutations_performed": True,
        "completed_at": utc_now(),
        "execution_sha256": "",
    }
    execution["execution_sha256"] = _self_hash(execution, "execution_sha256")
    write_immutable_json(execution_path, execution)
    return execution


class RetentionOrchestrator:
    """Run plan-only, archive-only, or explicitly authorized purge cycles."""

    def __init__(
        self,
        database: Any,
        config: RetentionConfig,
        *,
        primary_archive_root: str | Path | None = None,
        secondary_backend: SecondaryBackend | None = None,
        run_root: str | Path | None = None,
    ) -> None:
        self.database = database
        self.config = config
        self.primary_archive_root = Path(primary_archive_root or config.pi["archive_root"])
        self.secondary_backend = secondary_backend or FilesystemSecondaryBackend(
            config.secondary["root"],
            reserve_bytes=int(config.secondary["minimum_reserved_bytes"]),
            max_used_ratio=float(config.secondary["max_used_ratio_after_archive"]),
        )
        self.run_root = Path(run_root or self.primary_archive_root / "retention_runs")

    def plan(self, *, now: datetime | None = None) -> RetentionPlan:
        return plan_retention(self.database, self.config, now=now)

    def run(
        self,
        *,
        now: datetime | None = None,
        execute_archive: bool = False,
        execute_purge: bool = False,
        confirm_purge: bool = False,
        automation: bool = False,
    ) -> dict[str, Any]:
        if automation:
            if execute_archive or execute_purge or confirm_purge:
                raise RetentionExecutionError(
                    "automation mode cannot be combined with manual execution flags"
                )
            execute_archive = self.config.automatic_archive or self.config.automatic_purge
            execute_purge = self.config.automatic_purge
            confirm_purge = execute_purge
        if execute_purge and not confirm_purge:
            raise PurgeSafetyError("--confirm-purge is required for retention deletion")
        plan = self.plan(now=now)
        base = plan.as_dict()
        base["automatic_purge"] = self.config.automatic_purge
        base["automatic_archive"] = self.config.automatic_archive
        base["mutations_performed"] = False
        base["automation_requested"] = automation
        if not execute_archive and not execute_purge:
            return base
        if plan.status not in {"ACTIONABLE_PLAN"} or not plan.selected_by_collection:
            return {**base, "status": "NO_ACTION", "mutations_performed": False}
        if execute_purge:
            blocked = sorted(
                name
                for name in plan.selected_by_collection
                if not (
                    self.config.policy_for(name)
                    and self.config.policy_for(name).purge_eligible
                    and (not automation or self.config.policy_for(name).auto_purge_eligible)
                )
            )
            if blocked:
                raise PurgeSafetyError(
                    "retention plan includes archive-only or unresolved collections: "
                    + ",".join(blocked)
                )
        cycle_run_id = f"{plan.run_id}_{'purge' if execute_purge else 'archive'}"
        run_dir = self.run_root / cycle_run_id
        final_path = run_dir / "retention_receipt.json"
        if final_path.exists():
            existing = _read_json(final_path)
            if existing.get("receipt_sha256") != _self_hash(existing, "receipt_sha256"):
                raise RetentionExecutionError("completed retention receipt self-hash mismatch")
            return existing
        run_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        observed_now = now or datetime.fromisoformat(str(plan.payload["observed_at_utc"]))
        if observed_now.tzinfo is None:
            observed_now = observed_now.replace(tzinfo=timezone.utc)
        primary_before = _filesystem_capacity_or_unavailable(self.primary_archive_root)
        secondary_before = self.secondary_backend.capacity()
        capacity_before = dict(base.get("capacity_before") or {})
        _write_stage(
            run_dir,
            "capacity-status",
            {
                "capacity_state": plan.payload.get("capacity_state"),
                "instantaneous_capacity_state": plan.payload.get("instantaneous_capacity_state"),
                "capacity_before": capacity_before,
                "pi_capacity_before": primary_before,
                "secondary_capacity_before": secondary_before,
            },
        )
        _write_stage(
            run_dir,
            "retention-plan",
            {
                "plan_run_id": plan.run_id,
                "cycle_run_id": cycle_run_id,
                "recommended_document_count": plan.payload.get("recommended_document_count"),
                "estimated_selected_archive_bytes": plan.payload.get("estimated_selected_archive_bytes"),
                "selection_preview": plan.payload.get("selection_preview", []),
            },
        )
        results: list[dict[str, Any]] = []
        for name, selections in plan.selected_by_collection.items():
            policy = self.config.policy_for(name)
            if policy is None:
                raise RetentionExecutionError("selected collection has no policy")
            if execute_purge and not policy.purge_eligible:
                raise PurgeSafetyError(f"{name} is archive-only and cannot be purged")
            if not policy.primary_time_field:
                raise RetentionExecutionError(f"{name} has no primary time field")
            query = lifecycle_query(
                policy,
                cutoff=(
                    observed_now.astimezone(timezone.utc)
                    - timedelta(days=int(policy.hot_window_days or 0))
                ),
            )
            if query is None:
                raise RetentionExecutionError(f"{name} lifecycle query is unresolved")
            serialized_query = next(
                (
                    item.get("selection_query")
                    for item in plan.payload.get("collection_plans", [])
                    if item.get("collection") == name
                ),
                None,
            )
            spec = ArchiveSpec(
                project_id=self.config.target.project_id,
                cluster_id=self.config.target.cluster_id,
                cluster_name=self.config.target.cluster_name,
                srv_hostname=self.config.target.srv_hostname,
                database=self.config.target.database,
                collection=name,
                query=query,
                sort=((policy.primary_time_field, 1), ("_id", 1)),
                limit=len(selections),
                provenance="RETENTION_ORCHESTRATOR",
                schema_info={"policy_id": self.config.policy_id, "policy_sha256": self.config.policy_sha256},
                source_epoch=self.config.target.storage_epoch,
            )
            collection = self.database[name]
            ensure_archive_root(self.primary_archive_root)
            estimated_bytes = sum(int(item["estimated_bytes"]) for item in selections)
            pi_gate = pi_capacity_gate(
                filesystem_capacity(self.primary_archive_root),
                estimated_bytes,
                reserve_bytes=int(self.config.pi["minimum_reserved_bytes"]),
                max_used_ratio=float(self.config.pi["max_used_ratio_after_archive"]),
            )
            _write_stage(
                run_dir,
                "archive",
                {
                    "collection": name,
                    "estimated_uncompressed_bytes": estimated_bytes,
                    "selected_count": len(selections),
                    "pi_capacity_gate": pi_gate,
                    "selection_query": serialized_query,
                },
            )
            primary = export_archive(collection, spec, self.primary_archive_root)
            _write_stage(
                run_dir,
                "verify-primary",
                {"collection": name, "archive_id": primary["archive_id"], "sha256": primary["verification"]["sha256"], "verified": True},
            )
            _write_stage(
                run_dir,
                "replicate-secondary",
                {"collection": name, "archive_id": primary["archive_id"]},
            )
            secondary_before_item = self.secondary_backend.capacity()
            secondary = self.secondary_backend.replicate(primary["paths"]["archive"], primary["manifest"])
            if secondary.get("verified") is not True:
                raise RetentionExecutionError("secondary backend did not return a verified copy")
            secondary_receipt_path = run_dir / f"{name}.secondary_verification.json"
            secondary_receipt = {
                "schema_version": "mongo_pi_retention_secondary_verification.v1",
                "backend": secondary.get("backend"),
                "archive_id": primary["archive_id"],
                "sha256": secondary["sha256"],
                "record_count": secondary["record_count"],
                "verified": True,
                "success": True,
                "path": secondary["path"],
                "mutations_performed": False,
            }
            secondary_receipt["receipt_sha256"] = _self_hash(secondary_receipt, "receipt_sha256")
            write_immutable_json(secondary_receipt_path, secondary_receipt)
            _write_stage(
                run_dir,
                "verify-secondary",
                {"collection": name, "archive_id": primary["archive_id"], "sha256": secondary["sha256"], "verified": True},
            )
            item: dict[str, Any] = {
                "collection": name,
                "archive_id": primary["archive_id"],
                "primary": primary["verification"],
                "secondary": secondary,
                "secondary_capacity_before": secondary_before_item,
                "purged": False,
            }
            if execute_purge:
                frozen_path = run_dir / f"{name}.frozen_set.json"
                frozen = freeze_retention_purge_set(
                    primary["paths"]["archive"],
                    secondary["path"],
                    primary["manifest"],
                    secondary_receipt,
                    output_path=frozen_path,
                    run_id=cycle_run_id,
                    authorized_maximum=self.config.capacity.max_documents_per_cycle,
                )
                _write_stage(run_dir, "freeze-purge-set", {"collection": name, "archive_id": primary["archive_id"], "identity_set_sha256": frozen["identity_set_sha256"]})
                _write_stage(
                    run_dir,
                    "predelete-reconcile",
                    {
                        "collection": name,
                        "archive_id": primary["archive_id"],
                        "identity_set_sha256": frozen["identity_set_sha256"],
                        "status": "STARTED",
                    },
                )
                execution = execute_retention_exact_purge(
                    collection,
                    frozen,
                    primary["manifest"],
                    self.config,
                    run_dir=run_dir / name,
                    explicit_confirmation=True,
                )
                post = {
                    "exact_ids_remaining": int(
                        collection.count_documents(
                            build_exact_delete_filter(
                                [canonical_ejson_loads(_stable_json(value)) for value in frozen["document_ids"]],
                                authorized_remaining=len(frozen["document_ids"]),
                                authorized_max=len(frozen["document_ids"]),
                            )
                        )
                    ),
                    "archive_reverified": read_archive_verified(primary["paths"]["archive"], manifest=primary["manifest"]),
                    "mutations_performed": False,
                }
                if post["exact_ids_remaining"] != 0:
                    raise PurgeSafetyError("retention post-delete exact-ID verification failed")
                _write_stage(
                    run_dir,
                    "postdelete-verify",
                    {
                        "collection": name,
                        "archive_id": primary["archive_id"],
                        "exact_ids_remaining": post["exact_ids_remaining"],
                        "status": "PASS",
                    },
                )
                item.update(
                    {
                        "frozen": {
                            "status": frozen["purge_set_status"],
                            "archive_id": frozen["archive_id"],
                            "exact_document_count": frozen["exact_document_count"],
                            "identity_set_sha256": frozen["identity_set_sha256"],
                            "primary_copy_verified": frozen["primary_copy"]["verified"],
                            "secondary_copy_verified": frozen["secondary_copy"]["verified"],
                        },
                        "execution": execution,
                        "postdelete": post,
                        "purged": True,
                    }
                )
            archive_reverify = read_archive_verified(
                primary["paths"]["archive"], manifest=primary["manifest"]
            )
            _write_stage(
                run_dir,
                "archive-reverify",
                {"collection": name, "archive_id": primary["archive_id"], "verified": True},
            )
            item["archive_reverify"] = archive_reverify
            event = {
                "schema_version": RETENTION_INDEX_VERSION,
                "event_id": hashlib.sha256(
                    f"{cycle_run_id}:{name}:{primary['archive_id']}".encode("utf-8")
                ).hexdigest(),
                "event_type": "PURGED" if item["purged"] else "ARCHIVE_VERIFIED",
                "run_id": cycle_run_id,
                "target": self.config.target.as_dict(),
                "database": self.config.target.database,
                "epoch": self.config.target.storage_epoch,
                "collection": name,
                "archive_id": primary["archive_id"],
                "record_count": primary["manifest"]["selected_count"],
                "archive_logical_bytes": primary["manifest"]["uncompressed_bytes"],
                "compressed_bytes": primary["manifest"]["compressed_bytes"],
                "primary_archive": {"backend": "pi", "path": primary["paths"]["archive"], "sha256": primary["verification"]["sha256"], "verified": True},
                "secondary_archive": {"backend": secondary["backend"], "path": secondary["path"], "sha256": secondary["sha256"], "verified": True},
                "source_purged": item["purged"],
                "restorable": True,
                "public_url": None,
                "path_visibility": "operator_only",
                "mutations_performed": item["purged"],
                "recorded_at": utc_now(),
            }
            _append_jsonl_event(run_dir / "archive_index.jsonl", event)
            _append_jsonl_event(self.primary_archive_root / "retention_catalog.jsonl", event)
            results.append(item)
        capacity_after = mongo_capacity_status(
            self.database,
            tier_limit_bytes=self.config.capacity.quota_bytes,
            policy_thresholds={
                "warning": self.config.capacity.warning_ratio,
                "critical": self.config.capacity.high_ratio,
                "emergency": self.config.capacity.critical_ratio,
            },
        )
        primary_after = _filesystem_capacity_or_unavailable(self.primary_archive_root)
        secondary_after = self.secondary_backend.capacity()
        _write_stage(
            run_dir,
            "capacity-remeasure",
            {
                "capacity_after": capacity_after,
                "pi_capacity_after": primary_after,
                "secondary_capacity_after": secondary_after,
            },
        )
        exact_archive_count = sum(int(item["primary"].get("record_count", 0)) for item in results)
        archive_logical_bytes = sum(
            int(item["primary"].get("uncompressed_bytes", 0)) for item in results
        )
        compressed_bytes = sum(
            int(item["primary"].get("compressed_bytes", 0)) for item in results
        )
        deleted_count = sum(
            int(item.get("execution", {}).get("acknowledged_deleted_total", 0)) for item in results
        )
        selection_predicates = {
            str(item.get("collection")): next(
                (
                    plan_item.get("selection_query")
                    for plan_item in plan.payload.get("collection_plans", [])
                    if plan_item.get("collection") == item.get("collection")
                ),
                None,
            )
            for item in results
        }
        final = {
            **base,
            "receipt_version": RETENTION_RECEIPT_VERSION,
            "status": "COMPLETED",
            "run_id": cycle_run_id,
            "plan_run_id": plan.run_id,
            "target": self.config.target.as_dict(),
            "database": self.config.target.database,
            "epoch": self.config.target.storage_epoch,
            "capacity_before": capacity_before,
            "capacity_after": capacity_after,
            "pi_capacity_before": primary_before,
            "pi_capacity_after": primary_after,
            "secondary_capacity_before": secondary_before,
            "secondary_capacity_after": secondary_after,
            "policy_state": plan.payload.get("capacity_state"),
            "execution_mode": "AUTOMATION" if automation else "MANUAL",
            "selection_predicates": selection_predicates,
            "exact_archive_count": exact_archive_count,
            "archive_logical_bytes": archive_logical_bytes,
            "compressed_bytes": compressed_bytes,
            "primary_archive_hashes": {
                item["collection"]: item["primary"]["sha256"] for item in results
            },
            "secondary_archive_hashes": {
                item["collection"]: item["secondary"]["sha256"] for item in results
            },
            "exact_id_set_hashes": {
                item["collection"]: item.get("frozen", {}).get("identity_set_sha256")
                for item in results
                if item.get("frozen")
            },
            "deleted_count": deleted_count,
            "verification_state": {
                "primary_archives_verified": all(bool(item["primary"]) for item in results),
                "secondary_archives_verified": all(
                    item["secondary"].get("verified") is True for item in results
                ),
                "archive_reverification_passed": all(
                    item.get("archive_reverify", {}).get("success") is True
                    for item in results
                ),
                "exact_id_postcheck_passed": all(
                    item.get("postdelete", {}).get("exact_ids_remaining", 0) == 0
                    for item in results
                ),
                "two_copy_delete_invariant": not execute_purge
                or all(item.get("frozen") for item in results),
            },
            "failure_state": None,
            "results": results,
            "mutations_performed": any(
                bool(item.get("execution", {}).get("mutations_performed")) for item in results
            ),
            "automatic_purge": self.config.automatic_purge,
            "automation_requested": automation,
            "credential_exposure": False,
            "services_changed": False,
            "target_b_mutated": False,
            "completed_at": utc_now(),
        }
        final["receipt_sha256"] = _self_hash(final, "receipt_sha256")
        _write_stage(run_dir, "receipt", {"status": "READY", "receipt_path": str(final_path)})
        write_immutable_json(final_path, final)
        return final


__all__ = [
    "FilesystemSecondaryBackend",
    "RETENTION_FROZEN_SET_VERSION",
    "RETENTION_INDEX_VERSION",
    "RETENTION_RECEIPT_VERSION",
    "RetentionExecutionError",
    "RetentionOrchestrator",
    "execute_retention_exact_purge",
    "freeze_retention_purge_set",
]
