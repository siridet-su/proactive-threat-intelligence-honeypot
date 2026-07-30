from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path

from production.utils.serialization import stable_json


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / "evaluation/next_tactic_correction_baseline_20260731.json"


def test_pre_correction_baseline_receipt_is_integrity_bound_and_privacy_safe() -> None:
    value = json.loads(RECEIPT.read_text(encoding="utf-8"))
    recorded = value["receipt_sha256"]
    canonical = deepcopy(value)
    canonical.pop("receipt_sha256")
    assert hashlib.sha256(stable_json(canonical).encode("utf-8")).hexdigest() == (
        recorded
    )
    assert value["source_revision"] == (
        "0d60af2ca2e1689b8d76da76b6118257c0cf207b"
    )
    assert value["privacy"] == {
        "raw_commands_emitted": False,
        "credentials_emitted": False,
        "source_ips_emitted": False,
        "reversible_session_ids_emitted": False,
    }


def test_pre_correction_baseline_records_every_required_failure_mode() -> None:
    value = json.loads(RECEIPT.read_text(encoding="utf-8"))
    selection = value["selection"]
    assert selection["delayed_completion_order"] == ["event-new", "event-old"]
    assert selection["durable_evidence_order"] == ["event-old", "event-new"]
    assert selection["api_selected_trigger_event_id"] == "event-old"
    assert selection["session_detail_selected_trigger_event_id"] == "event-old"
    assert selection["outbox_tasks_have_evidence_cutoff"] is False
    assert selection["equal_timestamp_api_selected_snapshot_id"]
    assert selection["equal_timestamp_detail_selected_snapshot_id"]

    immutability = value["immutability"]
    assert immutability["same_canonical_retry_replaced_generated_at"] is True
    assert immutability["divergent_canonical_write_accepted"] is True
    assert immutability["divergent_integrity_errors"]

    runtime = value["runtime"]
    assert runtime["trusted_plus_audit_runtime_count"] == 0
    assert runtime["audit_only_observation_result"] == (
        "no_trusted_behavior_phase"
    )
    assert runtime["late_source_timestamp"]["prediction_status"] == (
        "model_unavailable"
    )
    assert runtime["real_audit_model_view"]["tensor_hash"] != (
        runtime["forced_zero_model_view"]["tensor_hash"]
    )
    assert runtime["runtime_audit_prediction"]["probabilities"] == (
        runtime["forced_zero_model_view"]["prediction_probabilities"]
    )
