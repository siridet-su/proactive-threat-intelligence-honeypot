from __future__ import annotations

import json
import sqlite3
from copy import deepcopy
from pathlib import Path

import pytest

from production.prediction.evidence_cutoff import make_evidence_cutoff
from production.prediction.prediction_snapshot_contract import (
    PredictionSnapshotIntegrityError,
    finalize_prediction_snapshot,
    validate_prediction_snapshot_integrity,
)
from production.storage import open_storage
from production.utils.serialization import stable_json


def _snapshot(
    *,
    event_id: str = "event-immutable",
    received_at: str = "2026-07-31T00:00:01Z",
) -> dict:
    return finalize_prediction_snapshot(
        {
            "schema_version": "prediction_snapshot.v3",
            "session_id": "immutable-session",
            "event_id": event_id,
            "session_status": "active",
            "generated_at": "2026-07-31T00:00:02Z",
            "prediction_status": "predicted",
            "prediction": ["discovery"],
            "evidence_cutoff": make_evidence_cutoff(received_at, event_id),
            "runtime": {
                "model_load_time_ms": 1.0,
                "inference_latency_ms": 2.0,
            },
        }
    )


def test_exact_retry_is_idempotent_and_preserves_original_storage_record(
    tmp_path: Path,
) -> None:
    storage = open_storage(f"sqlite:///{tmp_path / 'exact.sqlite3'}")
    storage.initialize()
    snapshot = _snapshot()
    storage.save_prediction_snapshot(snapshot)
    before = storage.get_prediction_snapshot(snapshot["snapshot_id"])
    assert before is not None
    storage.save_prediction_snapshot(deepcopy(snapshot))
    after = storage.get_prediction_snapshot(snapshot["snapshot_id"])
    assert after is not None
    assert after["payload_json"] == before["payload_json"]
    assert after["created_at"] == before["created_at"]
    assert after["integrity_errors"] == []


def test_noncanonical_retry_timing_does_not_replace_first_valid_write(
    tmp_path: Path,
) -> None:
    storage = open_storage(f"sqlite:///{tmp_path / 'timing.sqlite3'}")
    storage.initialize()
    original = _snapshot()
    storage.save_prediction_snapshot(original)
    retry = deepcopy(original)
    retry["generated_at"] = "2026-07-31T01:00:00Z"
    retry["runtime"]["model_load_time_ms"] = 99.0
    retry["runtime"]["inference_latency_ms"] = 88.0
    assert validate_prediction_snapshot_integrity(retry) == []
    storage.save_prediction_snapshot(retry)
    stored = storage.get_prediction_snapshot(original["snapshot_id"])
    assert stored is not None
    assert stored["payload"]["generated_at"] == original["generated_at"]
    assert stored["payload"]["runtime"] == original["runtime"]
    assert stored["created_at"] == original["generated_at"]


@pytest.mark.parametrize(
    ("mutation", "match"),
    [
        (lambda value: value.update(prediction=["execution"]), "snapshot_sha256"),
        (
            lambda value: value.update(
                evidence_cutoff=make_evidence_cutoff(
                    "2026-07-31T00:00:03Z",
                    "event-immutable",
                )
            ),
            "snapshot_sha256",
        ),
        (lambda value: value.update(snapshot_id="prediction_corrupt"), "snapshot_id"),
        (lambda value: value.update(snapshot_sha256="0" * 64), "snapshot_sha256"),
    ],
)
def test_changed_canonical_content_or_identity_is_rejected_without_rewrite(
    tmp_path: Path,
    mutation,
    match: str,
) -> None:
    storage = open_storage(f"sqlite:///{tmp_path / (match + '.sqlite3')}")
    storage.initialize()
    original = _snapshot()
    storage.save_prediction_snapshot(original)
    changed = deepcopy(original)
    mutation(changed)
    with pytest.raises(PredictionSnapshotIntegrityError, match=match):
        storage.save_prediction_snapshot(changed)
    stored = storage.get_prediction_snapshot(original["snapshot_id"])
    assert stored is not None
    assert stored["payload_json"] == stable_json(original)
    assert stored["integrity_errors"] == []


def test_historical_valid_v3_without_cutoff_remains_readable_and_current(
    tmp_path: Path,
) -> None:
    storage = open_storage(f"sqlite:///{tmp_path / 'historical.sqlite3'}")
    storage.initialize()
    historical = finalize_prediction_snapshot(
        {
            "schema_version": "prediction_snapshot.v3",
            "session_id": "historical-session",
            "event_id": "historical-event",
            "session_status": "closed",
            "generated_at": "2026-07-01T00:00:00Z",
            "prediction_status": "predicted",
            "prediction": ["discovery"],
        }
    )
    storage.save_prediction_snapshot(historical)
    direct = storage.get_prediction_snapshot(historical["snapshot_id"])
    current = storage.get_current_prediction_snapshot("historical-session")
    assert direct is not None and current is not None
    assert direct["integrity_errors"] == []
    assert current["snapshot_id"] == historical["snapshot_id"]


def test_corrupt_stored_v3_is_readable_for_audit_but_never_current(
    tmp_path: Path,
) -> None:
    database = tmp_path / "corrupt.sqlite3"
    storage = open_storage(f"sqlite:///{database}")
    storage.initialize()
    valid_legacy = {
        "schema_version": "prediction_snapshot.v2",
        "snapshot_id": "legacy-valid",
        "session_id": "corrupt-session",
        "event_id": "legacy-event",
        "session_status": "active",
        "generated_at": "2026-07-01T00:00:00Z",
        "prediction": ["legacy"],
    }
    storage.save_prediction_snapshot(valid_legacy)
    corrupt = _snapshot(event_id="corrupt-event")
    corrupt["session_id"] = "corrupt-session"
    corrupt["prediction"] = ["execution"]
    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            INSERT INTO prediction_snapshots
            (snapshot_id, session_id, src_ip, session_status, event_id,
             features_hash, payload_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                corrupt["snapshot_id"],
                "corrupt-session",
                "unknown",
                "active",
                "corrupt-event",
                "",
                json.dumps(corrupt, sort_keys=True, separators=(",", ":")),
                "2026-07-31T23:59:59Z",
            ),
        )
    direct = storage.get_prediction_snapshot(corrupt["snapshot_id"])
    current = storage.get_current_prediction_snapshot("corrupt-session")
    assert direct is not None
    assert direct["integrity_errors"]
    assert current is not None
    assert current["snapshot_id"] == "legacy-valid"
