"""Content-addressed least-privilege MongoDB runtime identity manifest."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict

from production.utils.serialization import stable_json


MONGODB_RUNTIME_IDENTITY_SCHEMA = "mongodb_runtime_identity.v2"
DEFAULT_MONGODB_RUNTIME_IDENTITY = Path(
    __file__
).resolve().parents[2] / "configs/mongodb_runtime_identity.v2.json"
RUNTIME_ACTIONS = frozenset(
    {
        "find",
        "insert",
        "update",
        "remove",
        "listCollections",
        "listIndexes",
        "collStats",
        "dbStats",
    }
)
PROHIBITED_ROLES = frozenset(
    {"atlasAdmin", "clusterAdmin", "userAdmin", "dbAdmin", "readWriteAnyDatabase"}
)
PROHIBITED_ACTIONS = frozenset(
    {
        "bypassDocumentValidation",
        "createCollection",
        "createIndex",
        "dropCollection",
        "dropDatabase",
        "dropIndex",
        "collMod",
    }
)


@dataclass(frozen=True)
class MongoDBRuntimeIdentityManifest:
    document: Dict[str, Any]
    sha256: str


def load_mongodb_runtime_identity(
    path: str | Path = DEFAULT_MONGODB_RUNTIME_IDENTITY,
) -> MongoDBRuntimeIdentityManifest:
    try:
        document = json.loads(Path(path).read_bytes())
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("MongoDB runtime identity manifest is unreadable") from exc
    if not isinstance(document, dict):
        raise ValueError("MongoDB runtime identity manifest must be an object")
    expected_scalars = {
        "schema_version": MONGODB_RUNTIME_IDENTITY_SCHEMA,
        "username": "10k",
        "authentication": "SCRAM-SHA-256",
        "database": "honeypot_canonical_v1",
        "cluster_scope": "epoch_receipt",
        "credential_delivery": "owner_only_systemd_credential_file",
        "secret_material_present": False,
    }
    if any(document.get(key) != value for key, value in expected_scalars.items()):
        raise ValueError("MongoDB runtime identity binding is invalid")
    role = document.get("custom_role")
    if not isinstance(role, dict) or role.get("name") != "honeypotCanonicalRuntimeV1":
        raise ValueError("MongoDB runtime custom role is invalid")
    if set(role.get("privileges") or []) != RUNTIME_ACTIONS:
        raise ValueError("MongoDB runtime action inventory is invalid")
    if role.get("resource") != {
        "database": "honeypot_canonical_v1",
        "collection": "",
    }:
        raise ValueError("MongoDB runtime role resource is invalid")
    if set(document.get("prohibited_roles") or []) != PROHIBITED_ROLES:
        raise ValueError("MongoDB prohibited role inventory is invalid")
    if set(document.get("prohibited_actions") or []) != PROHIBITED_ACTIONS:
        raise ValueError("MongoDB prohibited action inventory is invalid")
    if RUNTIME_ACTIONS & PROHIBITED_ACTIONS:
        raise ValueError("MongoDB runtime role admits a prohibited action")
    encoded = stable_json(document).encode("utf-8")
    return MongoDBRuntimeIdentityManifest(
        document=document,
        sha256=hashlib.sha256(encoded).hexdigest(),
    )
