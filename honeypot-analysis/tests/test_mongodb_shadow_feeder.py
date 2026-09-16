from __future__ import annotations

import json
from copy import deepcopy
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


def row_from_fixture(*, session_id: str = "session_v1_44444444444444444444444444444444", ended: bool = False) -> dict:
    row = deepcopy(json.loads(FIXTURE.read_text()))
    row["session_id"] = session_id
    row["ended"] = ended
    row["updated_at"] = "2026-08-23T00:00:01+00:00"
    row["revision"] = 1
    return row


def rebind_manifest(row: dict, *, received_at: str | None = None, phases: list[dict] | None = None) -> None:
    manifest = row["payload"]["prediction_trusted_history_manifest"]
    if received_at is not None:
        manifest["evidence_cutoff"]["received_at"] = received_at
    if phases is not None:
        manifest["ordered_trusted_phases"] = phases
        manifest["original_distinct_phase_count"] = len(phases)
        manifest["selected_distinct_phase_count"] = len(phases)
        manifest["omitted_prefix_phase_count"] = 0
        manifest["truncated"] = False
        manifest["ordered_trusted_phases_sha256"] = feeder_module.digest(phases)
        row["payload"]["prediction_trusted_history_revision"] = len(phases)
        row["payload"]["prediction_trusted_phase_count"] = len(phases)
    manifest.pop("history_manifest_sha256", None)
    manifest["history_manifest_sha256"] = feeder_module.digest(manifest)


def append_phase(row: dict, tactic: str = "execution") -> None:
    manifest = row["payload"]["prediction_trusted_history_manifest"]
    phases = deepcopy(manifest["ordered_trusted_phases"])
    previous = phases[-1]
    phase = deepcopy(previous)
    phase["phase_index"] = len(phases)
    phase["start_command_index"] = int(previous["end_command_index"]) + 1
    phase["end_command_index"] = int(previous["end_command_index"]) + 2
    phase["start_timestamp"] = "2026-08-23T00:00:10+00:00"
    phase["end_timestamp"] = "2026-08-23T00:00:11+00:00"
    phase["tactics"] = [tactic]
    for label in phase["labels"]:
        label["tactic"] = tactic
    phase.pop("phase_sha256", None)
    phase["phase_sha256"] = feeder_module.digest(phase)
    phases.append(phase)
    rebind_manifest(row, phases=phases)


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


def test_state_fingerprint_controls_reemission_and_session_isolation(tmp_path: Path) -> None:
    feeder = MongoShadowFeeder(config(tmp_path))
    base = row_from_fixture(ended=False)
    with patch.object(feeder_module, "_request", side_effect=predictor) as request:
        assert feeder.process_row(base) == "EMITTED"

        unrelated_revision = deepcopy(base)
        unrelated_revision["revision"] = 2
        assert feeder.process_row(unrelated_revision) == "DUPLICATE"

        changed_manifest = deepcopy(base)
        changed_manifest["revision"] = 3
        rebind_manifest(changed_manifest, received_at="2026-08-23T00:00:03+00:00")
        assert feeder.process_row(changed_manifest) == "EMITTED"

        ended_transition = deepcopy(changed_manifest)
        ended_transition["revision"] = 4
        ended_transition["ended"] = True
        assert feeder.process_row(ended_transition) == "EMITTED"

        same_ended_state = deepcopy(ended_transition)
        same_ended_state["revision"] = 5
        assert feeder.process_row(same_ended_state) == "DUPLICATE"

        higher_progression = deepcopy(ended_transition)
        higher_progression["revision"] = 6
        append_phase(higher_progression)
        assert feeder.process_row(higher_progression) == "EMITTED"

        progression_and_manifest = deepcopy(higher_progression)
        progression_and_manifest["revision"] = 7
        rebind_manifest(progression_and_manifest, received_at="2026-08-23T00:00:07+00:00")
        assert feeder.process_row(progression_and_manifest) == "EMITTED"

        other_session = row_from_fixture(
            session_id="session_v1_55555555555555555555555555555555",
            ended=False,
        )
        assert feeder.process_row(other_session) == "EMITTED"

    assert request.call_count == 6
    assert feeder.metrics["duplicate_rows"] == 2
    records = [json.loads(line) for line in (tmp_path / "records.jsonl").read_text().splitlines()]
    assert len(records) == 6
    assert records[0]["sequence_id"] == base["session_id"]
    assert records[0]["session_ended"] is False
    assert records[-1]["sequence_id"] == other_session["session_id"]
    final = next(record for record in records if record["revision"] == 7)
    current_manifest = progression_and_manifest["payload"]["prediction_trusted_history_manifest"]
    assert final["history_manifest_sha256"] == current_manifest["history_manifest_sha256"]
    assert final["session_ended"] is True
    assert len({record["prediction_id"] for record in records}) == len(records)


def test_legacy_state_reconciles_once_then_is_idempotent(tmp_path: Path) -> None:
    feeder = MongoShadowFeeder(config(tmp_path))
    row = row_from_fixture(ended=False)
    manifest_hash = row["payload"]["prediction_trusted_history_manifest"]["history_manifest_sha256"]
    feeder.state["sessions"][row["session_id"]] = {
        "last_progression": row["payload"]["prediction_trusted_history_revision"],
        "last_cursor": {
            "updated_at": row["updated_at"],
            "session_id": row["session_id"],
            "revision": row["revision"],
        },
        "ended": False,
        "manifest_hash": manifest_hash,
    }
    with patch.object(feeder_module, "_request", side_effect=predictor) as request:
        assert feeder.process_row(row) == "EMITTED"
        reconciled = feeder.state["sessions"][row["session_id"]]
        assert reconciled["last_history_manifest_hash"] == manifest_hash
        assert reconciled["last_ended"] is False
        row["revision"] = 2
        assert feeder.process_row(row) == "DUPLICATE"
    assert request.call_count == 1
    assert len((tmp_path / "records.jsonl").read_text().splitlines()) == 1


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
