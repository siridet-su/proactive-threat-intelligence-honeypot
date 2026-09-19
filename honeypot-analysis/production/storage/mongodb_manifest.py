from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Tuple

from production.utils.serialization import stable_json


MONGODB_SCHEMA_MANIFEST_VERSION = "mongodb_canonical_schema_manifest.v1"
DEFAULT_MONGODB_SCHEMA_MANIFEST = (
    Path(__file__).resolve().parents[2] / "configs/mongodb_canonical_schema.v1.json"
)


class MongoDBManifestError(ValueError):
    pass


COMPATIBLE_OPTIONAL_PERFORMANCE_INDEX = (
    "COMPATIBLE_OPTIONAL_PERFORMANCE_INDEX"
)


@dataclass(frozen=True)
class MongoDBSchemaCompatibility:
    """Semantic compatibility result for a candidate manifest and live schema.

    ``schema_identity`` remains the content address of the declared manifest.
    This result deliberately answers a different question: whether the live
    schema satisfies the candidate's required persistence contract.
    """

    missing_collections: Tuple[str, ...] = ()
    validator_mismatches: Tuple[str, ...] = ()
    missing_required_indexes: Tuple[Dict[str, str], ...] = ()
    required_index_mismatches: Tuple[Dict[str, Any], ...] = ()
    compatible_optional_extras: Tuple[Dict[str, Any], ...] = ()
    rejected_extra_indexes: Tuple[Dict[str, Any], ...] = ()

    @property
    def required_schema_match(self) -> bool:
        return not (
            self.missing_collections
            or self.validator_mismatches
            or self.missing_required_indexes
            or self.required_index_mismatches
        )

    @property
    def schema_compatible(self) -> bool:
        return self.required_schema_match and not self.rejected_extra_indexes

    def failure_message(self) -> str:
        failures = []
        if self.missing_collections:
            failures.append(
                "missing collections=" + ",".join(self.missing_collections)
            )
        if self.validator_mismatches:
            failures.append(
                "validator mismatches=" + ",".join(self.validator_mismatches)
            )
        if self.missing_required_indexes:
            failures.append(
                "missing required indexes="
                + ",".join(
                    f"{item['collection']}.{item['index']}"
                    for item in self.missing_required_indexes
                )
            )
        if self.required_index_mismatches:
            failures.append(
                "required index mismatches="
                + ",".join(
                    f"{item['collection']}.{item['index']}"
                    for item in self.required_index_mismatches
                )
            )
        if self.rejected_extra_indexes:
            failures.append(
                "rejected extra indexes="
                + ",".join(
                    f"{item['collection']}.{item['index']}"
                    for item in self.rejected_extra_indexes
                )
            )
        return "canonical MongoDB schema compatibility failed: " + "; ".join(
            failures or ["unknown incompatibility"]
        )


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


def _validated_manifest(document: Any) -> MongoDBSchemaManifest:
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


def load_mongodb_schema_manifest_payload(
    payload_json: str,
    *,
    expected_sha256: str = "",
) -> MongoDBSchemaManifest:
    """Load and verify a content-addressed manifest payload from MongoDB."""

    if not isinstance(payload_json, str):
        raise MongoDBManifestError("MongoDB schema manifest payload must be text")
    try:
        document = json.loads(payload_json)
    except json.JSONDecodeError as exc:
        raise MongoDBManifestError("MongoDB schema manifest payload is unreadable") from exc
    if stable_json(document) != payload_json:
        raise MongoDBManifestError("MongoDB schema manifest payload is not canonical")
    manifest = _validated_manifest(document)
    if expected_sha256 and manifest.sha256 != expected_sha256:
        raise MongoDBManifestError("MongoDB schema manifest payload hash mismatch")
    return manifest


def load_mongodb_schema_manifest(
    path: str | Path = DEFAULT_MONGODB_SCHEMA_MANIFEST,
) -> MongoDBSchemaManifest:
    selected = Path(path)
    try:
        raw = selected.read_bytes()
        document = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        raise MongoDBManifestError("MongoDB schema manifest is unreadable") from exc
    return _validated_manifest(document)


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


_INDEX_METADATA_FIELDS = frozenset(
    {"name", "key", "keys", "unique", "v", "ns", "hidden"}
)


def _index_key_pairs(index: Mapping[str, Any]) -> Tuple[Tuple[str, Any], ...] | None:
    raw_keys = index.get("key", index.get("keys"))
    if isinstance(raw_keys, Mapping):
        return tuple((str(field), direction) for field, direction in raw_keys.items())
    if isinstance(raw_keys, (list, tuple)):
        pairs = []
        for item in raw_keys:
            if not isinstance(item, (list, tuple)) or len(item) != 2:
                return None
            pairs.append((str(item[0]), item[1]))
        return tuple(pairs)
    return None


def _index_semantic_violations(
    index: Mapping[str, Any], *, reject_unique: bool
) -> Tuple[str, ...]:
    """Return index options that could affect persistence correctness."""

    violations = []
    keys = _index_key_pairs(index)
    if not keys or any(
        not field or field == "$**" or direction not in (-1, 1)
        for field, direction in keys
    ):
        violations.append("unsupported_key_pattern")
    if reject_unique and bool(index.get("unique", False)):
        violations.append("unexpected_unique")
    if "expireAfterSeconds" in index:
        violations.append("unexpected_ttl")
    if "partialFilterExpression" in index:
        violations.append("incompatible_partial_index")
    if "collation" in index:
        violations.append("incompatible_collation")
    if "sparse" in index:
        violations.append("incompatible_sparse_index")
    unknown = sorted(set(index) - _INDEX_METADATA_FIELDS)
    if unknown:
        violations.append("unsupported_index_options:" + ",".join(unknown))
    return tuple(violations)


def _index_definition_is_ordinary(index: Mapping[str, Any]) -> Tuple[str, ...]:
    """Return safety violations for an index that is not manifest-required."""

    return _index_semantic_violations(index, reject_unique=True)


def _required_index_mismatch(
    expected: Mapping[str, Any], actual: Mapping[str, Any]
) -> Tuple[str, ...]:
    violations = []
    if _index_key_pairs(expected) != _index_key_pairs(actual):
        violations.append("keys")
    if bool(expected.get("unique", False)) != bool(actual.get("unique", False)):
        violations.append("unique")
    violations.extend(_index_semantic_violations(actual, reject_unique=False))
    return tuple(dict.fromkeys(violations))


def compare_mongodb_schema_compatibility(
    manifest: MongoDBSchemaManifest,
    *,
    existing_collections: Iterable[str],
    validators: Mapping[str, Any],
    indexes: Mapping[str, Mapping[str, Mapping[str, Any]]],
) -> MongoDBSchemaCompatibility:
    """Compare installed Mongo structures against required manifest semantics.

    The input is deliberately a read-side snapshot.  This helper performs no
    MongoDB operations and does not compare content-addressed identities.
    Additional indexes are accepted only when they are ordinary, non-unique,
    non-TTL B-tree indexes with no semantic options that could change query
    correctness.
    """

    existing = set(existing_collections)
    required_collections = {item["name"] for item in manifest.collections}
    missing_collections = tuple(sorted(required_collections - existing))
    validator_mismatches = []
    missing_required_indexes = []
    required_index_mismatches = []
    compatible_optional_extras = []
    rejected_extra_indexes = []

    for declaration in manifest.collections:
        collection = declaration["name"]
        if collection in existing and validators.get(collection) != collection_validator(
            declaration
        ):
            validator_mismatches.append(collection)

        actual = dict(indexes.get(collection, {}))
        expected = {
            "_id_": {"name": "_id_", "keys": [["_id", 1]], "unique": False}
        }
        expected.update(
            {
                item["name"]: item
                for item in declaration.get("indexes", [])
            }
        )
        for index_name, expected_index in expected.items():
            observed = actual.get(index_name)
            if observed is None:
                missing_required_indexes.append(
                    {"collection": collection, "index": index_name}
                )
                continue
            if index_name == "_id_":
                if _index_key_pairs(observed) != (("_id", 1),):
                    required_index_mismatches.append(
                        {
                            "collection": collection,
                            "index": index_name,
                            "reasons": ["keys"],
                        }
                    )
                continue
            reasons = _required_index_mismatch(expected_index, observed)
            if reasons:
                required_index_mismatches.append(
                    {
                        "collection": collection,
                        "index": index_name,
                        "reasons": list(reasons),
                    }
                )

        for index_name, observed in actual.items():
            if index_name in expected:
                continue
            reasons = _index_definition_is_ordinary(observed)
            item = {
                "collection": collection,
                "index": index_name,
                "keys": list(_index_key_pairs(observed) or ()),
                "unique": bool(observed.get("unique", False)),
            }
            if reasons:
                rejected_extra_indexes.append({**item, "reasons": list(reasons)})
            else:
                compatible_optional_extras.append(
                    {
                        **item,
                        "classification": COMPATIBLE_OPTIONAL_PERFORMANCE_INDEX,
                    }
                )

    return MongoDBSchemaCompatibility(
        missing_collections=missing_collections,
        validator_mismatches=tuple(sorted(set(validator_mismatches))),
        missing_required_indexes=tuple(
            sorted(
                missing_required_indexes,
                key=lambda item: (item["collection"], item["index"]),
            )
        ),
        required_index_mismatches=tuple(
            sorted(
                required_index_mismatches,
                key=lambda item: (item["collection"], item["index"]),
            )
        ),
        compatible_optional_extras=tuple(
            sorted(
                compatible_optional_extras,
                key=lambda item: (item["collection"], item["index"]),
            )
        ),
        rejected_extra_indexes=tuple(
            sorted(
                rejected_extra_indexes,
                key=lambda item: (item["collection"], item["index"]),
            )
        ),
    )


def iter_manifest_indexes(
    manifest: MongoDBSchemaManifest,
) -> Iterable[tuple[str, Dict[str, Any]]]:
    for collection in manifest.collections:
        for index in collection["indexes"]:
            yield collection["name"], index
