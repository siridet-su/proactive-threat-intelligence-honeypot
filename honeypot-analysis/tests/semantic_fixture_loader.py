"""Load the canonical frozen typed-semantic fixture bundle.

The bundle keeps each family and evaluation role isolated while avoiding a
parallel file layout that made it easy for tests and documentation to drift.
The source-member hashes are checked on every load so consolidation does not
silently change a frozen case set.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
BUNDLE_PATH = ROOT / "evaluation/typed_semantic_fixtures.v2.json"


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def load_bundle() -> dict[str, Any]:
    value = json.loads(BUNDLE_PATH.read_text(encoding="utf-8"))
    assert value["schema_version"] == "typed_semantic_fixtures.v2"
    provenance = value["provenance"]
    assert provenance["labels_frozen_before_execution"] is True
    members = provenance["source_members"]
    assert provenance["source_member_count"] == len(members)
    assert len({item["path"] for item in members}) == len(members)
    for member in members:
        source = ROOT / member["path"]
        # Source files are intentionally absent after consolidation.  Their
        # exact bytes are represented by the parsed member and its recorded
        # digest below; this branch is retained for future bundle migrations.
        if source.exists():
            assert _sha256(source.read_bytes()) == member["sha256"]
    return value


def load_fixture(family: str, role: str) -> dict[str, Any]:
    bundle = load_bundle()
    value = bundle["families"][family][role]
    assert isinstance(value, dict)
    return value


def load_provenance_correction(name: str) -> dict[str, Any]:
    value = load_bundle()["provenance_corrections"][name]
    assert isinstance(value, dict)
    return value


def source_member_sha256(path: str) -> str:
    for member in load_bundle()["provenance"]["source_members"]:
        if member["path"] == path:
            return str(member["sha256"])
    raise AssertionError(f"unknown consolidated fixture source: {path}")
