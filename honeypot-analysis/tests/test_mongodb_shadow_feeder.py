from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from production.prediction_next_distinct_poc import mongodb_shadow_feeder as feeder_module
from production.prediction_next_distinct_poc.mongodb_shadow_feeder import (
    FeederReject,
    MongoShadowFeeder,
)


FIXTURE = (
    Path(__file__).parent
    / "fixtures/prediction_next_distinct/mongodb_shadow_feeder_golden.json"
)


def predictor(_endpoint, observations, _timeout):
    return {
        "authority": "non_authoritative",
        "canonical_write_allowed": False,
        "task": "next_observed_distinct_tactic",
        "model_identifier": "finalf_refined_v1_prediction_only",
        "checkpoint_sha256": "16506e962432f9921d18a514c3a31686a20f9734385ec49439ad2651e4cdd283",
        "top1": "execution",
        "top3": ["execution", "persistence", "privilege-escalation"],
        "probabilities": [0.01, 0.01, 0.01, 0.01, 0.80, 0.10, 0.07],
        "calibration": {
            "method": "temperature_scaled_softmax.v1",
            "temperature": 0.6990670591704266,
        },
        "received_observations": list(observations),
    }


def config(root: Path) -> dict:
    return {
        "schema_version": "gcp_cowrie_shadow_mongo_feeder_config.v1",
        "deployment_id": "test-v3-mongo",
        "mongo_database": "honeypot_canonical_v1",
        "mongo_collection": "sessions",
        "endpoint": "http://127.0.0.1:18082/predict",
        "shadow_root": str(root),
        "expected_checkpoint_sha256": "16506e962432f9921d18a514c3a31686a20f9734385ec49439ad2651e4cdd283",
        "expected_temperature": 0.6990670591704266,
    }


def test_fixture_round_trip_and_idempotency(tmp_path: Path) -> None:
    feeder = MongoShadowFeeder(config(tmp_path))
    with patch.object(feeder_module, "_request", side_effect=predictor) as request:
        metrics = feeder.run_fixture(FIXTURE)
        assert metrics["predictions_emitted"] == 1
        assert request.call_count == 1
    replay = MongoShadowFeeder(config(tmp_path))
    with patch.object(feeder_module, "_request", side_effect=predictor) as request:
        metrics = replay.run_fixture(FIXTURE)
        assert metrics["duplicate_rows"] == 1
        assert request.call_count == 0
    assert len((tmp_path / "records.jsonl").read_text().splitlines()) == 1


def test_v2_manifest_fails_closed(tmp_path: Path) -> None:
    feeder = MongoShadowFeeder(config(tmp_path))
    row = json.loads(FIXTURE.read_text())
    row["payload"]["prediction_trusted_history_manifest"]["schema_version"] = (
        "prediction_trusted_history_manifest.v2"
    )
    row["updated_at"] = "2026-08-23T00:00:01+00:00"
    row["revision"] = 3
    with pytest.raises(FeederReject):
        feeder.process_row(row)


def test_source_contains_no_mongo_mutation_methods() -> None:
    source = Path(feeder_module.__file__).read_text()
    for token in (
        "insert_one",
        "insert_many",
        "update_one",
        "update_many",
        "delete_one",
        "delete_many",
        "replace_one",
        "bulk_write",
    ):
        assert token not in source
