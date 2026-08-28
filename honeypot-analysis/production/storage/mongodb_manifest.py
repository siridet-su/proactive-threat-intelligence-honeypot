from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Tuple

from production.utils.serialization import stable_json


MONGODB_SCHEMA_MANIFEST_VERSION = "mongodb_canonical_schema_manifest.v1"
DEFAULT_MONGODB_SCHEMA_MANIFEST = (
    Path(__file__).resolve().parents[2] / "configs/mongodb_canonical_schema.v1.json"
)


class MongoDBManifestError(ValueError):
    pass


@dataclass(frozen=True)
class MongoDBSchemaManifest:
    document: Dict[str, Any]
    sha256: str

    @property
    def database(self) -> str:
        return str(self.document["database"])

    @property
    def collections(self) -> Tuple[Dict[str, Any], ...]:
        return tuple(self.document["collections"])


def _validate_keys(keys: Any, *, collection: str, index: str) -> None:
    if not isinstance(keys, list) or not keys:
        raise MongoDBManifestError(f"{collection}.{index} index keys must be non-empty")
    seen = set()
    for item in keys:
        if (
            not isinstance(item, list)
            or len(item) != 2
            or not isinstance(item[0], str)
            or not item[0]
            or item[1] not in (-1, 1)
        ):
            raise MongoDBManifestError(f"{collection}.{index} has invalid index keys")
        if item[0] in seen:
            raise MongoDBManifestError(f"{collection}.{index} repeats an index key")
        seen.add(item[0])


def _validate_collection(collection: Any) -> None:
    if not isinstance(collection, dict):
        raise MongoDBManifestError("collection declarations must be objects")
    name = collection.get("name")
    if not isinstance(name, str) or not name or not name.replace("_", "").isalnum():
        raise MongoDBManifestError("collection name is invalid")
    required = collection.get("required_fields")
    if not isinstance(required, list) or not required or len(set(required)) != len(required):
        raise MongoDBManifestError(f"{name} required_fields must be unique")
    if "_id" not in required or "schema_version" not in required:
        raise MongoDBManifestError(f"{name} must require _id and schema_version")
    canonical_key = collection.get("canonical_key")
    if not isinstance(canonical_key, str) or canonical_key not in required:
        raise MongoDBManifestError(
            f"{name} canonical_key must name a required field"
        )
    for field in ("authority", "retention"):
        if not isinstance(collection.get(field), str) or not collection[field]:
            raise MongoDBManifestError(f"{name} {field} is required")
    indexes = collection.get("indexes")
    if not isinstance(indexes, list):
        raise MongoDBManifestError(f"{name} indexes must be a list")
    index_names = set()
    for index in indexes:
        if not isinstance(index, dict) or not isinstance(index.get("name"), str):
            raise MongoDBManifestError(f"{name} index declaration is invalid")
        index_name = index["name"]
        if index_name in index_names:
            raise MongoDBManifestError(f"{name} repeats index {index_name}")
        index_names.add(index_name)
        if "expireAfterSeconds" in index:
            raise MongoDBManifestError("TTL indexes are forbidden on canonical collections")
        _validate_keys(index.get("keys"), collection=name, index=index_name)


def load_mongodb_schema_manifest(
    path: str | Path = DEFAULT_MONGODB_SCHEMA_MANIFEST,
) -> MongoDBSchemaManifest:
    selected = Path(path)
    try:
        raw = selected.read_bytes()
        document = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        raise MongoDBManifestError("MongoDB schema manifest is unreadable") from exc
    if not isinstance(document, dict):
        raise MongoDBManifestError("MongoDB schema manifest must be an object")
    if document.get("schema_version") != MONGODB_SCHEMA_MANIFEST_VERSION:
        raise MongoDBManifestError("unsupported MongoDB schema manifest version")
    if document.get("database") != "honeypot_canonical_v1":
        raise MongoDBManifestError("canonical MongoDB database name is fixed")
    if document.get("canonical_event_order") != ["received_at", "event_id"]:
        raise MongoDBManifestError("canonical MongoDB event order is invalid")
    if document.get("write_concern") != {"w": "majority", "j": True}:
        raise MongoDBManifestError("canonical MongoDB write concern is invalid")
    if document.get("read_concern") != "majority":
        raise MongoDBManifestError("canonical MongoDB read concern is invalid")
    if document.get("authoritative_ttl_indexes_allowed") is not False:
        raise MongoDBManifestError("canonical MongoDB TTL policy must fail closed")
    prohibited = document.get("prohibited_top_level_fields")
    expected_prohibited = [
        "authorization",
        "credentials",
        "password",
        "private_key",
        "raw_event",
        "raw_payload",
        "refresh_token",
    ]
    if prohibited != expected_prohibited:
        raise MongoDBManifestError("MongoDB prohibited-field policy is invalid")
    collections = document.get("collections")
    if not isinstance(collections, list) or not collections:
        raise MongoDBManifestError("MongoDB manifest collections are missing")
    names = []
    for collection in collections:
        _validate_collection(collection)
        names.append(collection["name"])
    if len(names) != len(set(names)):
        raise MongoDBManifestError("MongoDB manifest repeats a collection")
    required_names = {
        "events", "sessions", "analysis_jobs", "canonical_assessments", "reports",
        "prediction_outbox", "prediction_snapshots", "ai_advisory_outbox",
        "ai_advisories", "schema_manifests", "lifecycle_ledger",
        "migration_receipts", "reconciliation_cursors", "worker_leases",
    }
    if not required_names.issubset(names):
        raise MongoDBManifestError("MongoDB manifest omits required collections")
    return MongoDBSchemaManifest(
        document=document,
        sha256=hashlib.sha256(stable_json(document).encode("utf-8")).hexdigest(),
    )


def collection_validator(collection: Dict[str, Any]) -> Dict[str, Any]:
    required = list(collection["required_fields"])
    return {
        "$and": [{
            "$jsonSchema": {
            "bsonType": "object",
            "required": required,
            "properties": {
                "_id": {"bsonType": "string"},
                "schema_version": {"bsonType": "string"},
            },
            }
        }, {
            "$nor": [
                {field: {"$exists": True}}
                for field in (
                    "authorization",
                    "credentials",
                    "password",
                    "private_key",
                    "raw_event",
                    "raw_payload",
                    "refresh_token",
                )
            ]
        }]
    }


def iter_manifest_indexes(
    manifest: MongoDBSchemaManifest,
) -> Iterable[tuple[str, Dict[str, Any]]]:
    for collection in manifest.collections:
        for index in collection["indexes"]:
            yield collection["name"], index
