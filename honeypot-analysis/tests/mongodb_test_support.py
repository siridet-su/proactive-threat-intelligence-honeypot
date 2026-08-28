from __future__ import annotations

import os
from typing import Any

from production.storage import install_mongodb_schema


def preserve_installed_schema() -> bool:
    return os.getenv("MONGODB_TEST_PRESERVE_SCHEMA", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def clear_canonical_documents(client: Any) -> None:
    """Clear synthetic rows without requiring database/schema administration."""

    database = client["honeypot_canonical_v1"]
    for name in database.list_collection_names():
        if name != "schema_manifests":
            database[name].delete_many({})


def prepare_canonical_test_database(client: Any) -> None:
    if preserve_installed_schema():
        clear_canonical_documents(client)
    else:
        client.drop_database("honeypot_canonical_v1")
        install_mongodb_schema(client)


def cleanup_canonical_test_database(client: Any) -> None:
    if preserve_installed_schema():
        clear_canonical_documents(client)
    else:
        client.drop_database("honeypot_canonical_v1")
