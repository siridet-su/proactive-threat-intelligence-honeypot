"""Install or read-only verify the canonical MongoDB schema manifest.

The connection URI is accepted only through an owner-only regular file named
by ``MONGODB_URI_FILE``. This avoids placing credentials in argv, repository
configuration, receipts, or diagnostic output. The install action requires a
separate deployment identity; the runtime identity is intentionally unable to
perform it.
"""

from __future__ import annotations

import argparse
import os
from typing import Sequence

from production.ai_advisory.security import read_mongodb_uri
from production.storage.mongodb_backend import (
    MongoDBStorageBackend,
    install_mongodb_schema,
)
from production.storage.mongodb_manifest import load_mongodb_schema_manifest
from production.utils.serialization import stable_json


def _client() -> object:
    from pymongo import MongoClient

    uri_file = os.getenv("MONGODB_URI_FILE", "").strip()
    if not uri_file:
        raise ValueError("MONGODB_URI_FILE is required")
    uri = read_mongodb_uri(uri_file, max_bytes=65_536)
    return MongoClient(
        uri,
        retryWrites=True,
        serverSelectionTimeoutMS=5_000,
        connectTimeoutMS=5_000,
        socketTimeoutMS=5_000,
    )


def run(action: str) -> dict[str, object]:
    manifest = load_mongodb_schema_manifest()
    client = _client()
    try:
        if action == "install":
            installed = install_mongodb_schema(client, manifest)
            if installed != manifest.sha256:
                raise RuntimeError("installed MongoDB manifest identity changed")
        storage = MongoDBStorageBackend(client=client)
        storage.verify_existing_schema()
        return {
            "schema_version": "mongodb_schema_admin_result.v1",
            "action": action,
            "database": manifest.database,
            "manifest_sha256": manifest.sha256,
            "collection_count": len(manifest.collections),
            "verified": True,
        }
    finally:
        client.close()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("install", "verify"))
    args = parser.parse_args(argv)
    print(stable_json(run(args.action)))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
