from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from production.storage.backend import StorageError
from production.storage.canonical_event import CanonicalEventRecord
from production.storage.mongodb_manifest import (
    MongoDBSchemaManifest,
    collection_validator,
    load_mongodb_schema_manifest,
)
from production.storage.mongodb_operations import MongoDBRuntimeOperations
from production.storage.session_provenance import (
    SESSION_SOURCE_UNKNOWN_LEGACY,
    is_external_source_ip,
    normalize_session_source,
)
from production.utils.serialization import stable_json, utc_now


MONGODB_BACKEND = "mongodb"
MONGODB_DOCUMENT_LIMIT = 16 * 1024 * 1024
MONGODB_EVENT_SCHEMA = "mongodb_canonical_event.v1"
MONGODB_SESSION_SCHEMA = "mongodb_canonical_session.v1"
MONGODB_WORKER_LEASE_SCHEMA = "mongodb_worker_lease.v1"


def _pymongo() -> Dict[str, Any]:
    try:
        from bson import BSON
        from pymongo import ASCENDING, IndexModel, MongoClient, ReadPreference
        from pymongo.errors import DuplicateKeyError, PyMongoError
        from pymongo.read_concern import ReadConcern
        from pymongo.write_concern import WriteConcern
    except ImportError as exc:  # pragma: no cover - depends on optional extra
        raise StorageError("PyMongo is required for MongoDB storage") from exc
    return {
        "ASCENDING": ASCENDING,
        "BSON": BSON,
        "DuplicateKeyError": DuplicateKeyError,
        "IndexModel": IndexModel,
        "MongoClient": MongoClient,
        "PyMongoError": PyMongoError,
        "ReadConcern": ReadConcern,
        "ReadPreference": ReadPreference,
        "WriteConcern": WriteConcern,
    }


def _bounded_document(document: Dict[str, Any]) -> None:
    encoded = _pymongo()["BSON"].encode(document)
    if len(encoded) >= MONGODB_DOCUMENT_LIMIT:
        raise StorageError("canonical MongoDB document exceeds BSON size limit")


def _utc_timestamp(value: Any = None) -> str:
    if value is None:
        return utc_now()
    if isinstance(value, datetime):
        parsed = value
    else:
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("timestamp must be ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp must include a UTC offset")
    return parsed.astimezone(timezone.utc).isoformat()


def _future_timestamp(now: str, seconds: float) -> str:
    try:
        duration = float(seconds)
    except (TypeError, ValueError) as exc:
        raise ValueError("lease_seconds must be numeric") from exc
    if duration <= 0:
        raise ValueError("lease_seconds must be positive")
    base = datetime.fromisoformat(now.replace("Z", "+00:00"))
    return (base + timedelta(seconds=duration)).isoformat()


def _required(value: str, field: str) -> str:
    normalized = str(value or "").strip()
    if not normalized:
        raise ValueError(f"{field} must be non-empty")
    return normalized


def _uuid_token(value: str, field: str) -> str:
    normalized = _required(value, field)
    try:
        return str(uuid.UUID(normalized))
    except (ValueError, AttributeError) as exc:
        raise ValueError(f"{field} must be a UUID fencing token") from exc


def install_mongodb_schema(
    client: Any,
    manifest: MongoDBSchemaManifest | None = None,
) -> str:
    """Install validators and indexes with a deployment identity.

    The runtime identity deliberately does not call this function and therefore
    does not need collection, validator, or index administration privileges.
    """

    selected = manifest or load_mongodb_schema_manifest()
    pymongo = _pymongo()
    database = client.get_database(selected.database)
    existing = set(database.list_collection_names())
    for declaration in selected.collections:
        name = declaration["name"]
        validator = collection_validator(declaration)
        if name not in existing:
            database.create_collection(
                name,
                validator=validator,
                validationLevel="strict",
                validationAction="error",
            )
        else:
            database.command(
                "collMod",
                name,
                validator=validator,
                validationLevel="strict",
                validationAction="error",
            )
        models = []
        for index in declaration["indexes"]:
            models.append(
                pymongo["IndexModel"](
                    [(field, direction) for field, direction in index["keys"]],
                    name=index["name"],
                    unique=bool(index.get("unique", False)),
                )
            )
        if models:
            database[name].create_indexes(models)
    manifest_record = {
        "_id": selected.sha256,
        "schema_version": selected.document["schema_version"],
        "manifest_sha256": selected.sha256,
        "payload_json": stable_json(selected.document),
        "installed_at": utc_now(),
    }
    _bounded_document(manifest_record)
    database["schema_manifests"].replace_one(
        {"_id": selected.sha256}, manifest_record, upsert=True
    )
    return selected.sha256


class MongoDBStorageBackend(MongoDBRuntimeOperations):
    """Canonical MongoDB adapter selected only through a reviewed epoch gate.

    Direct construction remains useful for isolated parity tests. Production
    selection is fail-closed in ``open_storage`` behind the protected URI,
    exact storage-epoch receipt, installed schema manifest, and synchronous
    SQLite rollback mirror.
    """

    def __init__(
        self,
        uri: str | None = None,
        *,
        client: Any = None,
        database_name: str = "honeypot_canonical_v1",
        timeout_ms: int = 5_000,
    ) -> None:
        if database_name != "honeypot_canonical_v1":
            raise StorageError("canonical MongoDB database name is fixed")
        pymongo = _pymongo()
        if client is None:
            if not uri:
                raise StorageError("MongoDB URI is required")
            client = pymongo["MongoClient"](
                uri,
                retryWrites=True,
                serverSelectionTimeoutMS=timeout_ms,
                connectTimeoutMS=timeout_ms,
                socketTimeoutMS=timeout_ms,
            )
        self.client = client
        self.manifest = load_mongodb_schema_manifest()
        base = client.get_database(database_name)
        self.database = base.with_options(
            write_concern=pymongo["WriteConcern"]("majority", j=True),
            read_concern=pymongo["ReadConcern"]("majority"),
            read_preference=pymongo["ReadPreference"].PRIMARY,
        )

    def health_check(self) -> Dict[str, Any]:
        try:
            hello = self.database.command("hello")
            if not bool(hello.get("isWritablePrimary")):
                return {"ok": False, "backend": MONGODB_BACKEND}
        except Exception:
            return {"ok": False, "backend": MONGODB_BACKEND}
        return {"ok": True, "backend": MONGODB_BACKEND}

    def initialize(self) -> None:
        self.verify_existing_schema()

    def verify_existing_schema(self) -> None:
        record = self.database["schema_manifests"].find_one(
            {"_id": self.manifest.sha256},
            {"manifest_sha256": 1, "payload_json": 1},
        )
        if not record:
            raise StorageError("canonical MongoDB schema manifest is not installed")
        if (
            record.get("manifest_sha256") != self.manifest.sha256
            or record.get("payload_json") != stable_json(self.manifest.document)
        ):
            raise StorageError("canonical MongoDB schema manifest integrity mismatch")
        existing = set(self.database.list_collection_names())
        required = {item["name"] for item in self.manifest.collections}
        if not required.issubset(existing):
            missing = ",".join(sorted(required - existing))
            raise StorageError(
                f"canonical MongoDB collections are incomplete: missing={missing}"
            )
        for declaration in self.manifest.collections:
            info = self.database.command(
                "listCollections", filter={"name": declaration["name"]}
            )
            batches = info.get("cursor", {}).get("firstBatch", [])
            if len(batches) != 1 or (
                batches[0].get("options", {}).get("validator")
                != collection_validator(declaration)
            ):
                raise StorageError(
                    "canonical MongoDB collection validator mismatch: "
                    f"collection={declaration['name']}"
                )
            actual = {
                item["name"]: item
                for item in self.database[declaration["name"]].list_indexes()
            }
            expected_names = {"_id_", *[item["name"] for item in declaration["indexes"]]}
            if set(actual) != expected_names:
                missing = sorted(expected_names - set(actual))
                unexpected = sorted(set(actual) - expected_names)
                raise StorageError(
                    "canonical MongoDB index inventory mismatch: "
                    f"collection={declaration['name']} missing={missing} "
                    f"unexpected={unexpected}"
                )
            for index in declaration["indexes"]:
                if index["name"] not in actual:
                    raise StorageError(
                        "canonical MongoDB index manifest is incomplete: "
                        f"collection={declaration['name']} index={index['name']}"
                    )
                observed = list(actual[index["name"]]["key"].items())
                expected = [(field, direction) for field, direction in index["keys"]]
                if observed != expected or bool(actual[index["name"]].get("unique", False)) != bool(index.get("unique", False)):
                    raise StorageError(
                        "canonical MongoDB index manifest mismatch: "
                        f"collection={declaration['name']} index={index['name']}"
                    )

    def operational_metrics(self, *, now: Any = None) -> Dict[str, Any]:
        checked_at = _utc_timestamp(now)
        counts = {
            declaration["name"]: self.database[declaration["name"]].estimated_document_count()
            for declaration in self.manifest.collections
        }
        return {
            "backend": MONGODB_BACKEND,
            "backend_connectivity": self.health_check(),
            "collection_counts": counts,
            "checked_at": checked_at,
        }

    def store_event(self, sensor_id: str, event: Dict[str, Any]) -> tuple[str, bool]:
        record = CanonicalEventRecord.create(sensor_id, event)
        try:
            return self.store_canonical_event(record)
        except StorageError:
            existing = self.get_event(record.event_id)
            if (
                existing is not None
                and existing.get("sensor_id") == record.sensor_id
                and existing.get("payload_json") == record.payload_json
            ):
                return record.event_id, False
            raise

    def store_canonical_event(
        self,
        record: CanonicalEventRecord,
    ) -> tuple[str, bool]:
        try:
            record.verify()
        except ValueError as exc:
            raise StorageError("canonical event record failed integrity validation") from exc
        document = {
            "_id": record.event_id,
            "schema_version": MONGODB_EVENT_SCHEMA,
            "event_id": record.event_id,
            "sensor_id": record.sensor_id,
            "session_id": record.session_id,
            "src_ip": str(record.event.get("src_ip", "unknown")),
            "eventid": str(record.event.get("eventid", "")),
            "timestamp": record.event.get("timestamp"),
            "payload_json": record.payload_json,
            "payload_sha256": record.payload_sha256,
            "received_at": record.received_at,
            "processed": False,
            "attempts": 0,
            "next_retry_at": None,
            "claim_owner": None,
            "claim_token": None,
            "claim_expires_at": None,
        }
        _bounded_document(document)
        duplicate_error = _pymongo()["DuplicateKeyError"]
        try:
            self.database.events.insert_one(document)
            return record.event_id, True
        except duplicate_error:
            existing = self.database.events.find_one({"_id": record.event_id})
            comparison = (
                "event_id",
                "sensor_id",
                "session_id",
                "received_at",
                "payload_json",
                "payload_sha256",
            )
            if not existing or any(existing.get(key) != document.get(key) for key in comparison):
                raise StorageError("conflicting duplicate canonical event ID")
            return record.event_id, False

    @staticmethod
    def _event_result(document: Dict[str, Any]) -> Dict[str, Any]:
        try:
            event = json.loads(document["payload_json"])
        except (KeyError, TypeError, json.JSONDecodeError) as exc:
            raise StorageError("canonical MongoDB event contains invalid JSON") from exc
        if not isinstance(event, dict):
            raise StorageError("canonical MongoDB event must be an object")
        return {
            "event_id": document["event_id"],
            "sensor_id": document["sensor_id"],
            "event": event,
            "payload_json": document["payload_json"],
            "processed": bool(document.get("processed", False)),
            "received_at": document["received_at"],
        }

    def fetch_unprocessed_events(self, limit: int) -> List[Dict[str, Any]]:
        return [
            self._event_result(item)
            for item in self.database.events.find({"processed": False}).sort(
                [("received_at", 1), ("event_id", 1)]
            ).limit(max(0, int(limit)))
        ]

    def get_event(self, event_id: str) -> Optional[Dict[str, Any]]:
        document = self.database.events.find_one(
            {"_id": _required(event_id, "event_id")}
        )
        return self._event_result(document) if document is not None else None

    def fetch_events(
        self,
        limit: int = 1000,
        processed: Optional[bool] = None,
    ) -> List[Dict[str, Any]]:
        query: Dict[str, Any] = {}
        if processed is not None:
            query["processed"] = bool(processed)
        return [
            self._event_result(item)
            for item in self.database.events.find(query).sort(
                [("received_at", 1), ("event_id", 1)]
            ).limit(max(0, int(limit)))
        ]

    def load_session_event_snapshot(
        self,
        session_id: str,
        through_event_id: str,
        max_events: int,
    ) -> Dict[str, Any]:
        selected_session = _required(session_id, "session_id")
        watermark = _required(through_event_id, "through_event_id")
        if isinstance(max_events, bool) or not isinstance(max_events, int) or max_events < 1:
            raise ValueError("max_events must be a positive integer")
        events: List[Dict[str, Any]] = []
        entries: List[Dict[str, str]] = []
        found = False
        cursor = self.database.events.find({"session_id": selected_session}).sort(
            [("received_at", 1), ("event_id", 1)]
        )
        for document in cursor:
            if len(events) >= max_events:
                raise StorageError("canonical session evidence exceeds configured event limit")
            item = self._event_result(document)
            digest = hashlib.sha256(item["payload_json"].encode("utf-8")).hexdigest()
            if digest != document.get("payload_sha256"):
                raise StorageError("canonical MongoDB event payload hash mismatch")
            events.append(item["event"])
            entries.append({"event_id": item["event_id"], "payload_sha256": digest})
            if item["event_id"] == watermark:
                found = True
                break
        if not found:
            raise StorageError("canonical session evidence watermark is unavailable")
        basis = {
            "schema_version": "durable_session_event_manifest.v1",
            "session_id": selected_session,
            "through_event_id": watermark,
            "event_entries": entries,
        }
        return {
            **basis,
            "event_count": len(events),
            "manifest_sha256": hashlib.sha256(stable_json(basis).encode("utf-8")).hexdigest(),
            "events": events,
        }

    def mark_event_processed(self, event_id: str) -> None:
        self.database.events.update_one(
            {"_id": _required(event_id, "event_id")},
            {
                "$set": {
                    "processed": True,
                    "processing_outcome": "succeeded",
                    "processed_at": utc_now(),
                    "effect_summary_json": None,
                },
                "$unset": {
                    "claim_owner": "",
                    "claim_token": "",
                    "claim_leader_scope": "",
                    "claim_leader_token": "",
                    "claim_expires_at": "",
                    "next_retry_at": "",
                    "last_error_code": "",
                    "last_error_type": "",
                    "last_error_at": "",
                },
            },
        )

    def acquire_worker_lease(
        self,
        scope: str,
        owner: str,
        token: str,
        lease_seconds: float,
        *,
        now: Any = None,
    ) -> bool:
        current = _utc_timestamp(now)
        expires = _future_timestamp(current, lease_seconds)
        identity = _required(scope, "scope")
        lease_owner = _required(owner, "owner")
        lease_token = _uuid_token(token, "token")
        conflicting_claim = self.database.events.count_documents(
            {
                "processed": False,
                "claim_leader_scope": identity,
                "claim_expires_at": {"$gt": current},
                "$or": [
                    {"claim_owner": {"$ne": lease_owner}},
                    {"claim_leader_token": {"$ne": lease_token}},
                ],
            },
            limit=1,
        )
        if conflicting_claim:
            return False
        query = {
            "_id": identity,
            "$or": [
                {"expires_at": {"$lte": current}},
                {"owner": lease_owner, "token": lease_token},
            ],
        }
        update = {
            "$set": {
                "schema_version": MONGODB_WORKER_LEASE_SCHEMA,
                "scope": identity,
                "owner": lease_owner,
                "token": lease_token,
                "expires_at": expires,
                "updated_at": current,
            }
        }
        try:
            result = self.database.worker_leases.update_one(query, update, upsert=True)
        except _pymongo()["DuplicateKeyError"]:
            return False
        return bool(result.matched_count or result.upserted_id)

    def renew_worker_lease(
        self,
        scope: str,
        owner: str,
        token: str,
        lease_seconds: float,
        *,
        now: Any = None,
    ) -> bool:
        current = _utc_timestamp(now)
        result = self.database.worker_leases.update_one(
            {
                "_id": _required(scope, "scope"),
                "owner": _required(owner, "owner"),
                "token": _uuid_token(token, "token"),
                "expires_at": {"$gt": current},
            },
            {"$set": {"expires_at": _future_timestamp(current, lease_seconds), "updated_at": current}},
        )
        return result.modified_count == 1

    def release_worker_lease(
        self,
        scope: str,
        owner: str,
        token: str,
        *,
        now: Any = None,
    ) -> bool:
        current = _utc_timestamp(now)
        result = self.database.worker_leases.delete_one(
            {
                "_id": _required(scope, "scope"),
                "owner": _required(owner, "owner"),
                "token": _uuid_token(token, "token"),
                "expires_at": {"$gt": current},
            }
        )
        return result.deleted_count == 1

    def save_session(self, session_payload: Dict[str, Any]) -> None:
        payload = dict(session_payload)
        session_id = _required(str(payload.get("session_id") or ""), "session_id")
        source = normalize_session_source(
            payload.get("session_source"), SESSION_SOURCE_UNKNOWN_LEGACY
        )
        external = is_external_source_ip(payload.get("src_ip"))
        payload["session_source"] = source
        payload["is_external_source"] = external
        now = utc_now()
        protected = {
            "analysis_status", "analysis_updated_at", "analysis_job_id",
            "analysis_error", "analysis_skip_reason", "report_id",
        }
        duplicate_error = _pymongo()["DuplicateKeyError"]
        for _ in range(8):
            candidate = dict(payload)
            existing = self.database.sessions.find_one({"_id": session_id})
            if existing:
                stored_payload = json.loads(existing["payload_json"])
                for key in protected:
                    if key in stored_payload:
                        candidate[key] = stored_payload[key]
                    else:
                        candidate.pop(key, None)
            document = {
                "schema_version": MONGODB_SESSION_SCHEMA,
                "session_id": session_id,
                "src_ip": str(candidate.get("src_ip", "unknown")),
                "start_time": candidate.get("start_time", ""),
                "ended": bool(candidate.get("is_ended")),
                "session_source": source,
                "is_external_source": external,
                "payload_json": stable_json(candidate),
                "updated_at": now,
            }
            if existing is None:
                insert = {"_id": session_id, "revision": 1, **document}
                _bounded_document(insert)
                try:
                    self.database.sessions.insert_one(insert)
                    return
                except duplicate_error:
                    continue
            revision = int(existing.get("revision", 0))
            _bounded_document({"_id": session_id, "revision": revision + 1, **document})
            result = self.database.sessions.update_one(
                {"_id": session_id, "revision": revision},
                {"$set": document, "$inc": {"revision": 1}},
            )
            if result.modified_count == 1:
                return
        raise StorageError("session revision changed repeatedly")

    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        if not session_id:
            return None
        document = self.database.sessions.find_one({"_id": session_id})
        if not document:
            return None
        result = {key: value for key, value in document.items() if key != "_id"}
        result["payload"] = json.loads(result["payload_json"])
        return result
