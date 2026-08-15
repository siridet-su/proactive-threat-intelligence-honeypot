from __future__ import annotations

import datetime as dt
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).parents[1]


def _load(name: str) -> dict:
    return json.loads((ROOT / "configs" / name).read_text(encoding="utf-8"))


def test_official_inventory_is_canonical_and_label_blind() -> None:
    inventory = _load("cyberlab_external_source_inventory.v1.json")
    protocol = _load("cyberlab_external_temporal_protocol.v1.json")
    files = inventory["files"]
    assert len(files) == 113
    assert inventory["source_file_count"] == 293
    assert inventory["checksum_algorithm"] == "official MD5"
    assert hashlib.sha256(
        json.dumps(files, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest() == inventory["official_file_inventory_sha256"]
    assert protocol["selection_is_label_blind"] is True
    assert protocol["behavioral_inspection_before_freeze"] is False
    assert protocol["date_selection_basis"] == "filename_date_only"
    assert protocol["substitution_allowed"] is False
    assert protocol["sealed_test"]["behavioral_contents_opened"] is False
    assert protocol["sealed_test"]["downloaded_in_development_preparation"] is False

    expected_roles = {
        "train": (dt.date(2019, 11, 9), dt.date(2020, 1, 15)),
        "selection": (dt.date(2020, 1, 16), dt.date(2020, 2, 7)),
        "calibration": (dt.date(2020, 2, 8), dt.date(2020, 2, 18)),
        "external_sealed_test": (dt.date(2020, 2, 19), dt.date(2020, 2, 29)),
    }
    for role, (start, end) in expected_roles.items():
        role_files = [item for item in files if item["role"] == role]
        assert len(role_files) == protocol["role_counts"][role]
        assert sum(item["size_bytes"] for item in role_files) == protocol[
            "role_compressed_bytes"
        ][role]
        for item in role_files:
            date = dt.date.fromisoformat(item["date"])
            assert start <= date <= end
            assert item["filename"].endswith(".json.gz")
            assert item["md5"].startswith("md5:")

    development = [
        item for item in files if item["role"] in {"train", "selection", "calibration"}
    ]
    assert len(development) == 102
    assert sum(item["size_bytes"] for item in development) == 4_796_081_688
    assert protocol["role_compressed_bytes"]["development_total"] == 4_796_081_688
    assert protocol["role_compressed_bytes"]["all_candidate_total"] == sum(
        item["size_bytes"] for item in files
    )
