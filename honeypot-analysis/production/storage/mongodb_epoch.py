"""Fail-closed MongoDB epoch, capacity, and rollback-mirror runtime boundary."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from urllib.parse import urlsplit
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from production.storage.canonical_event import CanonicalEventRecord
from production.storage.mongodb_identity import load_mongodb_runtime_identity
from production.storage.mongodb_manifest import load_mongodb_schema_manifest
from production.storage.mongodb_shadow import MongoSQLiteRollbackMirror
from production.storage.rollback_mirror_identity import (
    validate_rollback_mirror_identity,
    verify_rollback_mirror,
)
from production.utils.serialization import stable_json, utc_now


EPOCH_SCHEMA = "canonical_storage_epoch.v2"
CAPACITY_SCHEMA = "mongodb_capacity_policy.v1"
M0_CAPACITY_BYTES = 512 * 1024 * 1024
CANONICAL_DATABASE = "honeypot_canonical_v1"
SCHEMA_MANIFEST_ID = load_mongodb_schema_manifest().sha256
RUNTIME_ROLE_ID = load_mongodb_runtime_identity().sha256
POLICY_BINDING_FIELDS = {
    "classification_rules_file_sha256",
    "classification_trust_policy_file_sha256",
    "classifier_environment_file_sha256",
    "prediction_policy_file_sha256",
}


def _digest(document: Dict[str, Any], hash_field: str) -> str:
    payload = {key: value for key, value in document.items() if key != hash_field}
    return hashlib.sha256(stable_json(payload).encode("utf-8")).hexdigest()


def _require_sha256(value: Any, name: str) -> str:
    selected = str(value or "")
    if len(selected) != 64 or any(character not in "0123456789abcdef" for character in selected):
        raise ValueError(f"{name} must be a lowercase SHA-256")
    return selected


def _require_hex_id(value: Any, name: str) -> str:
    selected = str(value or "")
    if len(selected) != 24 or any(character not in "0123456789abcdef" for character in selected):
        raise ValueError(f"{name} must be a 24-character lowercase hexadecimal ID")
    return selected


def _require_nonempty(value: Any, name: str) -> str:
    selected = str(value or "").strip()
    if not selected or len(selected) > 255 or any(ord(character) < 0x20 for character in selected):
        raise ValueError(f"{name} must be a bounded non-empty string")
    return selected


def _require_utc(value: Any, name: str) -> str:
    selected = str(value or "").strip()
    try:
        parsed = datetime.fromisoformat(selected.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{name} must be an ISO-8601 UTC timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{name} must include a UTC offset")
    if parsed.utcoffset().total_seconds() != 0:
        raise ValueError(f"{name} must be UTC")
    return selected


def _utc_datetime(value: Any, name: str) -> datetime:
    selected = _require_utc(value, name)
    return datetime.fromisoformat(selected.replace("Z", "+00:00")).astimezone(
        timezone.utc
    )


def load_storage_epoch(path: str | Path) -> Dict[str, Any]:
    selected = Path(path)
    info = selected.lstat()
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise ValueError("storage epoch receipt must be a regular non-symlink file")
    if info.st_mode & 0o022:
        raise ValueError("storage epoch receipt must not be group/other writable")
    document = json.loads(selected.read_text(encoding="utf-8"))
    required = {
        "schema_version", "epoch_id", "backend", "deployment_identity",
        "database", "start_time", "first_eligible_event_cutoff",
        "previous_sqlite_archive", "reviewed_release_sha",
        "reviewed_release_tree", "release_manifest_sha256",
        "schema_manifest_identity", "runtime_role_identity",
        "classifier_policy_environment_bindings",
        "failed_predecessor", "provenance_rules",
        "rollback_mirror", "capacity_policy", "receipt_sha256",
    }
    if not isinstance(document, dict) or set(document) != required:
        raise ValueError("storage epoch receipt fields are not exact")
    if document["schema_version"] != EPOCH_SCHEMA or document["backend"] != "mongodb":
        raise ValueError("storage epoch receipt selects an unsupported contract")
    if document["receipt_sha256"] != _digest(document, "receipt_sha256"):
        raise ValueError("storage epoch receipt hash mismatch")
    if document["database"] != CANONICAL_DATABASE:
        raise ValueError("storage epoch database is invalid")
    deployment = document["deployment_identity"]
    if not isinstance(deployment, dict) or set(deployment) != {
        "atlas_org_id", "atlas_project_id", "atlas_cluster_id",
        "atlas_cluster_name", "provider", "region", "srv_hostname",
        "replica_set_name", "mongodb_server_version",
    }:
        raise ValueError("storage epoch deployment identity fields are not exact")
    for key in ("atlas_org_id", "atlas_project_id", "atlas_cluster_id"):
        _require_hex_id(deployment[key], f"deployment_identity.{key}")
    for key in ("atlas_cluster_name", "region", "replica_set_name", "mongodb_server_version"):
        _require_nonempty(deployment[key], f"deployment_identity.{key}")
    if deployment["provider"] not in {"AWS", "AZURE", "GCP"}:
        raise ValueError("storage epoch deployment provider is invalid")
    srv_hostname = _require_nonempty(deployment["srv_hostname"], "deployment_identity.srv_hostname").lower()
    if srv_hostname != deployment["srv_hostname"] or not srv_hostname.endswith(".mongodb.net"):
        raise ValueError("storage epoch Atlas SRV hostname is invalid")
    if document["schema_manifest_identity"] != SCHEMA_MANIFEST_ID:
        raise ValueError("storage epoch schema manifest binding is invalid")
    if document["runtime_role_identity"] != RUNTIME_ROLE_ID:
        raise ValueError("storage epoch runtime role binding is invalid")
    _require_sha256(document["release_manifest_sha256"], "release_manifest_sha256")
    release_tree = str(document["reviewed_release_tree"] or "")
    if len(release_tree) != 40 or any(character not in "0123456789abcdef" for character in release_tree):
        raise ValueError("reviewed_release_tree must be a lowercase Git SHA-1")
    predecessor = document["failed_predecessor"]
    if not isinstance(predecessor, dict) or set(predecessor) != {
        "epoch_id", "preservation_receipt_sha256", "authority"
    } or predecessor["authority"] != "non_authoritative_failed_software_validation_evidence":
        raise ValueError("failed predecessor binding is invalid")
    _require_nonempty(predecessor["epoch_id"], "failed_predecessor.epoch_id")
    _require_sha256(predecessor["preservation_receipt_sha256"], "failed_predecessor.preservation_receipt_sha256")
    if document["provenance_rules"] != {
        "synthetic_session_source": "e2e_test",
        "exclude_from": [
            "empirical_calibration", "attacker_prevalence", "command_frequency",
            "thesis_ground_truth", "model_quality_evaluation",
        ],
        "attacker_command_markers_authoritative": False,
    }:
        raise ValueError("storage epoch provenance rules are invalid")
    if document["capacity_policy"] != capacity_policy():
        raise ValueError("storage epoch capacity policy is invalid")
    start_time = _utc_datetime(document["start_time"], "start_time")
    cutoff = document["first_eligible_event_cutoff"]
    if not isinstance(cutoff, dict) or set(cutoff) != {"received_at", "event_id"}:
        raise ValueError("storage epoch cutoff fields are not exact")
    cutoff_time = _utc_datetime(
        cutoff["received_at"], "first_eligible_event_cutoff.received_at"
    )
    if start_time < cutoff_time:
        raise ValueError("storage epoch start precedes the historical cutoff")
    if not isinstance(cutoff["event_id"], str):
        raise ValueError("storage epoch cutoff event_id must be a string")
    release_sha = str(document["reviewed_release_sha"] or "")
    if len(release_sha) != 40 or any(character not in "0123456789abcdef" for character in release_sha):
        raise ValueError("reviewed_release_sha must be a lowercase Git SHA-1")
    bindings = document["classifier_policy_environment_bindings"]
    if not isinstance(bindings, dict) or set(bindings) != POLICY_BINDING_FIELDS:
        raise ValueError("classifier/policy/environment binding fields are not exact")
    for key, value in bindings.items():
        _require_sha256(value, key)
    mirror_identity = validate_rollback_mirror_identity(
        document["rollback_mirror"], epoch_id=str(document["epoch_id"])
    )
    mirror_path = Path(mirror_identity["path"])
    archive = document["previous_sqlite_archive"]
    if not isinstance(archive, dict) or set(archive) != {
        "path", "sha256", "schema_version", "cutoff", "counts",
        "final_timestamp", "release_sha", "policy_environment_bindings",
    }:
        raise ValueError("historical SQLite archive identity is incomplete")
    if not Path(str(archive["path"] or "")).is_absolute():
        raise ValueError("historical SQLite archive path must be absolute")
    if Path(str(archive["path"])).resolve(strict=False) == mirror_path.resolve(strict=False):
        raise ValueError("historical archive and rollback mirror must be separate")
    _require_sha256(archive["sha256"], "previous_sqlite_archive.sha256")
    _require_utc(archive["final_timestamp"], "previous_sqlite_archive.final_timestamp")
    if archive["schema_version"] != 3:
        raise ValueError("historical SQLite archive schema version is invalid")
    archive_release = str(archive["release_sha"] or "")
    if len(archive_release) != 40 or any(
        character not in "0123456789abcdef" for character in archive_release
    ):
        raise ValueError("historical SQLite release SHA is invalid")
    if not isinstance(archive["counts"], dict) or not archive["counts"]:
        raise ValueError("historical SQLite archive counts are incomplete")
    if archive["cutoff"] != cutoff:
        raise ValueError("historical SQLite cutoff and epoch cutoff disagree")
    archive_bindings = archive["policy_environment_bindings"]
    if not isinstance(archive_bindings, dict) or set(archive_bindings) != POLICY_BINDING_FIELDS:
        raise ValueError("historical SQLite policy/environment bindings are incomplete")
    for key, value in archive_bindings.items():
        _require_sha256(value, f"previous_sqlite_archive.{key}")
    return document


def verify_runtime_deployment(
    receipt: Dict[str, Any],
    uri: str,
    mongo: Any,
    *,
    runtime_metadata: Dict[str, str] | None = None,
) -> Dict[str, str]:
    """Prove the protected URI and connected server match the receipt identity."""

    deployment = receipt["deployment_identity"]
    metadata = runtime_metadata or {
        "atlas_org_id": str(os.getenv("ATLAS_ORG_ID") or "").strip(),
        "atlas_project_id": str(os.getenv("ATLAS_PROJECT_ID") or "").strip(),
        "atlas_cluster_id": str(os.getenv("ATLAS_CLUSTER_ID") or "").strip(),
        "atlas_cluster_name": str(os.getenv("ATLAS_CLUSTER_NAME") or "").strip(),
        "provider": str(os.getenv("ATLAS_PROVIDER") or "").strip(),
        "region": str(os.getenv("ATLAS_REGION") or "").strip(),
    }
    expected_metadata = {key: deployment[key] for key in metadata}
    if metadata != expected_metadata:
        raise ValueError("configured Atlas deployment metadata disagrees with storage epoch receipt")
    parsed = urlsplit(uri)
    if parsed.scheme.lower() != "mongodb+srv" or not parsed.hostname:
        raise ValueError("canonical Atlas runtime requires an exact mongodb+srv URI")
    if parsed.hostname.lower().rstrip(".") != deployment["srv_hostname"]:
        raise ValueError("MongoDB URI endpoint disagrees with storage epoch receipt")
    uri_database = parsed.path.lstrip("/").split("/", 1)[0]
    if uri_database and uri_database != receipt["database"]:
        raise ValueError("MongoDB URI database disagrees with storage epoch receipt")
    hello = mongo.database.command("hello")
    if not bool(hello.get("isWritablePrimary")):
        raise ValueError("MongoDB deployment is not writable primary")
    if str(hello.get("setName") or "") != deployment["replica_set_name"]:
        raise ValueError("MongoDB replica-set identity disagrees with storage epoch receipt")
    version = str(mongo.client.server_info().get("version") or "")
    if version != deployment["mongodb_server_version"]:
        raise ValueError("MongoDB server version disagrees with storage epoch receipt")
    return {
        "srv_hostname": parsed.hostname.lower().rstrip("."),
        "replica_set_name": str(hello["setName"]),
        "mongodb_server_version": version,
    }


def require_active_release(receipt: Dict[str, Any]) -> str:
    configured = str(os.getenv("DEPLOYED_COMMIT") or "").strip()
    candidates = [configured] if configured else []
    for root in (Path.cwd(), Path(__file__).resolve().parents[2]):
        try:
            candidates.append((root / "DEPLOYED_COMMIT").read_text(encoding="utf-8").strip())
        except OSError:
            pass
    expected = str(receipt["reviewed_release_sha"])
    if expected not in candidates:
        raise ValueError("storage epoch receipt does not bind the active release")
    expected_tree = str(receipt["reviewed_release_tree"])
    configured_tree = str(os.getenv("DEPLOYED_TREE") or "").strip()
    tree_candidates = [configured_tree] if configured_tree else []
    expected_manifest = str(receipt["release_manifest_sha256"])
    configured_manifest = str(os.getenv("RELEASE_MANIFEST_SHA256") or "").strip()
    manifest_candidates = [configured_manifest] if configured_manifest else []
    for root in (Path.cwd(), Path(__file__).resolve().parents[2]):
        for name, target in (
            ("DEPLOYED_TREE", tree_candidates),
            ("RELEASE_MANIFEST_SHA256", manifest_candidates),
        ):
            try:
                target.append((root / name).read_text(encoding="utf-8").strip())
            except OSError:
                pass
    if expected_tree not in tree_candidates:
        raise ValueError("storage epoch receipt does not bind the active release tree")
    if expected_manifest not in manifest_candidates:
        raise ValueError("storage epoch receipt does not bind the active release manifest")
    return expected


def capacity_policy() -> Dict[str, Any]:
    return {
        "schema_version": CAPACITY_SCHEMA,
        "capacity_bytes": M0_CAPACITY_BYTES,
        "warning_percent": 60,
        "high_percent": 75,
        "fail_safe_percent": 85,
        "automatic_deletion": False,
        "automatic_upgrade": False,
    }


@dataclass
class MongoCapacityGuard:
    mongo: Any

    def status(self) -> Dict[str, Any]:
        stats = self.mongo.database.command("dbStats", scale=1)
        data = int(stats.get("storageSize", 0))
        indexes = int(stats.get("indexSize", 0))
        used = max(data + indexes, 0)
        percent = (used * 100.0) / M0_CAPACITY_BYTES
        state = (
            "fail_safe" if used * 100 >= M0_CAPACITY_BYTES * 85
            else "high" if used * 100 >= M0_CAPACITY_BYTES * 75
            else "warning" if used * 100 >= M0_CAPACITY_BYTES * 60
            else "normal"
        )
        return {
            "schema_version": "mongodb_capacity_status.v1",
            "data_storage_bytes": data,
            "index_bytes": indexes,
            "used_bytes": used,
            "capacity_bytes": M0_CAPACITY_BYTES,
            "used_percent": round(percent, 6),
            "state": state,
            "checked_at": utc_now(),
        }

    def require_write_capacity(self) -> Dict[str, Any]:
        status = self.status()
        if status["state"] == "fail_safe":
            raise RuntimeError("MongoDB canonical capacity is in fail-safe state")
        return status


class MongoEpochStorage:
    """Delegate runtime state to MongoDB while dual-durably ACKing events."""

    def __init__(self, mongo: Any, mirror_sqlite: Any, receipt: Dict[str, Any]) -> None:
        self.mongo = mongo
        self.mirror_sqlite = mirror_sqlite
        self.receipt = receipt
        self.mirror = MongoSQLiteRollbackMirror(mongo, mirror_sqlite)
        self.capacity = MongoCapacityGuard(mongo)
        self.mirror_verification = verify_rollback_mirror(
            self.receipt["rollback_mirror"], phase="auto"
        )
        self._verify_epoch_boundaries()

    def _verify_epoch_boundaries(self) -> None:
        cutoff = self.receipt["first_eligible_event_cutoff"]
        boundary = (str(cutoff["received_at"]), str(cutoff["event_id"]))
        mongo_first = self.mongo.database.events.find_one(
            {}, {"received_at": 1, "event_id": 1}, sort=[("received_at", 1), ("event_id", 1)]
        )
        if mongo_first is not None and (
            str(mongo_first.get("received_at") or ""),
            str(mongo_first.get("event_id") or ""),
        ) <= boundary:
            raise RuntimeError("MongoDB contains an event outside the canonical epoch")
        with self.mirror_sqlite.connection() as connection:
            mirror_first = connection.execute(
                "SELECT received_at, event_id FROM events "
                "ORDER BY received_at, event_id LIMIT 1"
            ).fetchone()
        if mirror_first is not None and (
            str(mirror_first["received_at"]), str(mirror_first["event_id"])
        ) <= boundary:
            raise RuntimeError("rollback mirror contains an event outside the canonical epoch")

    def __getattr__(self, name: str) -> Any:
        return getattr(self.mongo, name)

    def store_event(self, sensor_id: str, event: Dict[str, Any]) -> tuple[str, bool]:
        record = CanonicalEventRecord.create(sensor_id, event)
        existing = self.mongo.get_event(record.event_id)
        if existing is None:
            self.capacity.require_write_capacity()
        elif (
            existing.get("sensor_id") == record.sensor_id
            and existing.get("payload_json") == record.payload_json
        ):
            # An at-least-once replay receives a fresh local clock value.  The
            # first canonical MongoDB write owns received_at; rebuild the exact
            # record from that durable value so a missing rollback-mirror copy
            # can be repaired without changing durable-prefix ordering.
            record = CanonicalEventRecord.create(
                sensor_id,
                event,
                received_at=str(existing.get("received_at") or ""),
            )
        result = self.mirror.persist_for_ack(record)
        if not result.get("ack_eligible"):
            raise RuntimeError("canonical event is not dual-durable for acknowledgement")
        return record.event_id, existing is None

    def operational_metrics(self, *, now: Any = None) -> Dict[str, Any]:
        metrics = self.mongo.operational_metrics(now=now)
        metrics["canonical_storage_epoch_id"] = self.receipt["epoch_id"]
        metrics["capacity"] = self.capacity.status()
        metrics["rollback_mirror_path"] = str(self.mirror_sqlite.path)
        metrics["rollback_mirror_identity_id"] = self.receipt["rollback_mirror"]["identity_id"]
        return metrics
