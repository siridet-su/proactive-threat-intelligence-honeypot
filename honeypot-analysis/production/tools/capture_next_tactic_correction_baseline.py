"""Capture the pre-correction next-tactic behavior with isolated fixtures.

This module intentionally records behavior at a named Git revision.  It never
opens production storage and emits no raw command, credential, address, or
reversible session identifier.  The committed receipt is reproducible by
checking out its source revision and running this module with the frozen local
artifacts named in the receipt.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
from copy import deepcopy
from pathlib import Path
from typing import Any, Mapping

from production.prediction.next_behavior_contract import (
    require_valid_next_behavior_session,
)
from production.prediction.next_behavior_model import predict_next_behavior
from production.prediction.next_behavior_preprocessing import (
    build_live_model_input,
)
from production.prediction.next_behavior_runtime import (
    FrozenTransformerPocPredictor,
    _apply_frozen_calibration,
    build_live_next_behavior_session,
    finalize_prediction_snapshot,
    validate_prediction_snapshot_integrity,
)
from production.prediction.next_behavior_tensor import tensorize_model_input
from production.storage import open_storage
from production.utils.serialization import stable_json


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _policy(root: Path, artifact_root: Path, securebert_checkpoint: Path) -> dict:
    document = json.loads(
        (root / "configs/prediction_policy.transformer_poc.trusted.json").read_text(
            encoding="utf-8"
        )
    )
    policy = document["policy"]
    training = artifact_root / "experiment_20260724_v3_generation_dde7495" / (
        "training.selection_blocked"
    )
    policy.update(
        {
            "transformer_checkpoint_path": str(
                training / "seed_runs/transformer_seed_20260721/checkpoint.pt"
            ),
            "transformer_model_spec_path": str(training / "model_spec.json"),
            "transformer_vocabulary_path": str(training / "vocabulary.json"),
            "transformer_preprocessing_path": str(
                root / "configs/next_behavior_preprocessing.v1.json"
            ),
            "transformer_calibration_path": str(
                artifact_root
                / "professor_approved_poc_evaluation_73b902e"
                / "calibration.json"
            ),
            "runtime_rule_policy_path": str(
                root / "configs/classification_rules.trusted.json"
            ),
            "runtime_trust_policy_path": str(
                root / "production/classification/trust.py"
            ),
            "runtime_classifier_checkpoint_path": str(securebert_checkpoint),
        }
    )
    return policy


def _classification(
    *,
    timestamp: str,
    technique: str,
    tactic: str,
    source: str = "rule",
    confidence: float = 1.0,
    agreement_status: str = "rule_only",
) -> dict:
    return {
        "cowrie_eventid": "cowrie.command.input",
        "event_timestamp": timestamp,
        "compound_command_index": 0,
        "ttp": technique,
        "tactic": tactic,
        "source": source,
        "confidence": confidence,
        "high_confidence": confidence >= 0.90,
        "agreement_status": agreement_status,
    }


def _payload(events: list[dict]) -> dict:
    return {
        "session_id": "fixture-session",
        "start_time": "2026-07-31T00:00:00Z",
        "protocol": "ssh",
        "status": "active",
        "is_ended": False,
        "login_success": True,
        "login_attempts": 1,
        "commands": ["[redacted]"] * len(events),
        "classification_events": events,
        "raw_events": [],
    }


def _snapshot(
    session_id: str,
    event_id: str,
    generated_at: str,
    prediction: list[str],
) -> dict:
    return {
        "schema_version": "prediction_snapshot.v2",
        "snapshot_id": f"snapshot-{event_id}",
        "session_id": session_id,
        "event_id": event_id,
        "generated_at": generated_at,
        "session_status": "active",
        "prediction": prediction,
    }


def _selection_fixture(database: Path) -> dict:
    storage = open_storage(f"sqlite:///{database}")
    storage.initialize()
    old_task = {
        "schema_version": "prediction_outbox_task.v1",
        "event_id": "event-old",
        "session_id": "selection-session",
        "prediction_mode": "fixture",
        "session_payload": {"session_id": "selection-session"},
    }
    new_task = {
        **old_task,
        "event_id": "event-new",
        "session_payload": {"session_id": "selection-session", "prefix_size": 2},
    }
    old_outbox = storage.enqueue_prediction_outbox(old_task)
    claimed_old = storage.claim_prediction_outbox(
        "fixture-worker",
        1,
        30,
        3,
        now="2026-07-31T00:00:00+00:00",
    )[0]
    storage.fail_prediction_outbox(
        old_outbox,
        "fixture-worker",
        claimed_old["claim_token"],
        "fixture_retry",
        "RuntimeError",
        True,
        3,
        10,
        now="2026-07-31T00:00:01+00:00",
    )
    new_outbox = storage.enqueue_prediction_outbox(new_task)
    claimed_new = storage.claim_prediction_outbox(
        "fixture-worker",
        1,
        30,
        3,
        now="2026-07-31T00:00:05+00:00",
    )[0]
    new_snapshot = _snapshot(
        "selection-session",
        "event-new",
        "2026-07-31T00:00:06+00:00",
        ["execution"],
    )
    storage.save_prediction_snapshot(new_snapshot)
    storage.complete_prediction_outbox(
        new_outbox,
        "fixture-worker",
        claimed_new["claim_token"],
        new_snapshot["snapshot_id"],
        now="2026-07-31T00:00:06+00:00",
    )
    claimed_retry = storage.claim_prediction_outbox(
        "fixture-worker",
        1,
        30,
        3,
        now="2026-07-31T00:00:11+00:00",
    )[0]
    old_snapshot = _snapshot(
        "selection-session",
        "event-old",
        "2026-07-31T00:00:12+00:00",
        ["discovery"],
    )
    storage.save_prediction_snapshot(old_snapshot)
    storage.complete_prediction_outbox(
        old_outbox,
        "fixture-worker",
        claimed_retry["claim_token"],
        old_snapshot["snapshot_id"],
        now="2026-07-31T00:00:12+00:00",
    )
    api_row = storage.get_latest_prediction_snapshot("selection-session")
    detail_rows = storage.list_rows_for_session(
        "prediction_snapshots", "selection-session", 10
    )

    storage.save_prediction_snapshot(
        _snapshot(
            "equal-time-session",
            "a",
            "2026-07-31T00:01:00+00:00",
            ["discovery"],
        )
    )
    storage.save_prediction_snapshot(
        _snapshot(
            "equal-time-session",
            "z",
            "2026-07-31T00:01:00+00:00",
            ["execution"],
        )
    )
    equal_api = storage.get_latest_prediction_snapshot("equal-time-session")
    equal_detail = storage.list_rows_for_session(
        "prediction_snapshots", "equal-time-session", 10
    )
    return {
        "delayed_completion_order": ["event-new", "event-old"],
        "durable_evidence_order": ["event-old", "event-new"],
        "api_selector": "created_at_desc",
        "api_selected_snapshot_id": api_row["snapshot_id"],
        "api_selected_trigger_event_id": api_row["event_id"],
        "session_detail_selector": "rowid_desc",
        "session_detail_selected_snapshot_id": detail_rows[0]["snapshot_id"],
        "session_detail_selected_trigger_event_id": detail_rows[0]["event_id"],
        "equal_timestamp_api_selected_snapshot_id": equal_api["snapshot_id"],
        "equal_timestamp_detail_selected_snapshot_id": equal_detail[0][
            "snapshot_id"
        ],
        "outbox_tasks_have_evidence_cutoff": all(
            "evidence_cutoff" in task for task in (old_task, new_task)
        ),
    }


def _immutability_fixture(database: Path) -> dict:
    storage = open_storage(f"sqlite:///{database}")
    storage.initialize()
    base = finalize_prediction_snapshot(
        {
            "schema_version": "prediction_snapshot.v3",
            "session_id": "immutability-session",
            "event_id": "event-retry",
            "session_status": "active",
            "generated_at": "2026-07-31T00:02:00+00:00",
            "prediction_status": "predicted",
            "prediction": ["discovery"],
            "runtime": {
                "model_load_time_ms": 1.0,
                "inference_latency_ms": 2.0,
            },
        }
    )
    storage.save_prediction_snapshot(base)
    retry = deepcopy(base)
    retry["generated_at"] = "2026-07-31T00:02:05+00:00"
    retry["runtime"]["model_load_time_ms"] = 9.0
    retry["runtime"]["inference_latency_ms"] = 8.0
    storage.save_prediction_snapshot(retry)
    stored_retry = storage.get_prediction_snapshot(base["snapshot_id"])

    divergent = deepcopy(base)
    divergent["prediction"] = ["execution"]
    divergent["generated_at"] = "2026-07-31T00:02:10+00:00"
    storage.save_prediction_snapshot(divergent)
    stored_divergent = storage.get_prediction_snapshot(base["snapshot_id"])
    return {
        "original_snapshot_id": base["snapshot_id"],
        "original_integrity_errors": validate_prediction_snapshot_integrity(base),
        "same_canonical_retry_accepted": True,
        "same_canonical_retry_replaced_generated_at": (
            stored_retry["payload"]["generated_at"] != base["generated_at"]
        ),
        "same_canonical_retry_integrity_errors": (
            validate_prediction_snapshot_integrity(stored_retry["payload"])
        ),
        "divergent_canonical_write_accepted": True,
        "divergent_stored_prediction": stored_divergent["payload"]["prediction"],
        "divergent_integrity_errors": validate_prediction_snapshot_integrity(
            stored_divergent["payload"]
        ),
    }


def _prediction_view(predictor: FrozenTransformerPocPredictor, safe: Mapping[str, Any]) -> dict:
    model_input = build_live_model_input(
        safe,
        max_sequence_length=int(
            predictor.spec["architecture"]["maximum_sequence_length"]
        ),
    )
    tensor = tensorize_model_input(model_input, predictor.vocabulary)
    raw = predict_next_behavior(predictor.model, tensor, spec=predictor.spec)
    calibrated = _apply_frozen_calibration(
        raw,
        predictor.calibration,
        predictor.policy,
        predictor.vocabulary_hash,
    )
    return {
        "input_hash": model_input["input_hash"],
        "tensor_hash": tensor["tensor_hash"],
        "trusted_phase_sequence": [
            {
                "tactics": phase["tactics"],
                "techniques": phase["techniques"],
                "audit_only_label_count": phase["audit_only_label_count"],
            }
            for phase in model_input["phase_sequence"]
        ],
        "audit_count_indices": tensor["phase_audit_count_index"],
        "prediction_probabilities": {
            item["tactic"]: item["calibrated_probability"]
            for item in calibrated["ranked_tactics"]
        },
        "prediction_ranking": [
            item["tactic"] for item in calibrated["ranked_tactics"]
        ],
        "terminal_probability": calibrated["terminal_outcome"][
            "calibrated_probability"
        ],
    }


def _runtime_fixture(
    root: Path,
    artifact_root: Path,
    securebert_checkpoint: Path,
) -> dict:
    policy = _policy(root, artifact_root, securebert_checkpoint)
    predictor = FrozenTransformerPocPredictor(policy)
    if predictor.load_error or predictor.model is None:
        raise RuntimeError(
            f"frozen checkpoint unavailable: {predictor.load_error or 'unknown'}"
        )
    trusted = _classification(
        timestamp="2026-07-31T00:00:10Z",
        technique="T1059",
        tactic="execution",
    )
    audit = _classification(
        timestamp="2026-07-31T00:00:10Z",
        technique="T1003",
        tactic="credential-access",
        source="securebert_low_confidence",
        confidence=0.60,
        agreement_status="model_only",
    )
    trusted_only = build_live_next_behavior_session(
        _payload([trusted]),
        rule_policy_sha256=policy["runtime_rule_policy_sha256"],
        trust_policy_sha256=policy["runtime_trust_policy_sha256"],
        classifier_checkpoint_sha256=policy[
            "runtime_classifier_checkpoint_sha256"
        ],
    )
    trusted_and_audit = build_live_next_behavior_session(
        _payload([trusted, audit]),
        rule_policy_sha256=policy["runtime_rule_policy_sha256"],
        trust_policy_sha256=policy["runtime_trust_policy_sha256"],
        classifier_checkpoint_sha256=policy[
            "runtime_classifier_checkpoint_sha256"
        ],
    )
    audit_only = build_live_next_behavior_session(
        _payload([audit]),
        rule_policy_sha256=policy["runtime_rule_policy_sha256"],
        trust_policy_sha256=policy["runtime_trust_policy_sha256"],
        classifier_checkpoint_sha256=policy[
            "runtime_classifier_checkpoint_sha256"
        ],
    )
    assert trusted_only is not None and trusted_and_audit is not None

    real_audit = deepcopy(trusted_and_audit)
    real_audit["observation_groups"][0]["audit_only_labels"] = [
        {
            "tactic": "credential-access",
            "technique": "T1003",
            "source": "securebert",
            "trust_tier": "audit_only_candidate",
            "policy_sha256": policy["runtime_rule_policy_sha256"],
            "trust_policy_sha256": policy["runtime_trust_policy_sha256"],
            "checkpoint_sha256": policy[
                "runtime_classifier_checkpoint_sha256"
            ],
            "confidence": 0.6,
            "confidence_bucket": "medium",
            "agreement_status": "model_only",
            "evidence_ref": "nbevidence_" + ("a" * 64),
            "exclusion_reason": "below_trusted_threshold",
        }
    ]
    real_audit["audit_summary"] = {
        "total": 1,
        "by_reason": {"below_trusted_threshold": 1},
    }
    real_audit = require_valid_next_behavior_session(real_audit)
    forced_zero = deepcopy(real_audit)
    forced_zero["observation_groups"][0]["audit_only_labels"] = []
    forced_zero["audit_summary"] = {"total": 0, "by_reason": {}}
    forced_zero = require_valid_next_behavior_session(forced_zero)

    late_payload = _payload(
        [
            _classification(
                timestamp="2026-07-31T00:00:10Z",
                technique="T1059",
                tactic="execution",
            ),
            _classification(
                timestamp="2026-07-31T00:00:05Z",
                technique="T1082",
                tactic="discovery",
            ),
        ]
    )
    late_build_error = ""
    try:
        build_live_next_behavior_session(
            late_payload,
            rule_policy_sha256=policy["runtime_rule_policy_sha256"],
            trust_policy_sha256=policy["runtime_trust_policy_sha256"],
            classifier_checkpoint_sha256=policy[
                "runtime_classifier_checkpoint_sha256"
            ],
        )
    except Exception as exc:
        late_build_error = type(exc).__name__
    late_snapshot = predictor.predict_session(late_payload, event_id="event-late")
    runtime_with_audit = predictor.predict_session(
        _payload([trusted, audit]),
        event_id="event-audit",
    )
    return {
        "artifact_hashes": {
            "checkpoint_sha256": _sha256(
                Path(policy["transformer_checkpoint_path"])
            ),
            "model_spec_sha256": _sha256(
                Path(policy["transformer_model_spec_path"])
            ),
            "vocabulary_file_sha256": _sha256(
                Path(policy["transformer_vocabulary_path"])
            ),
            "calibration_file_sha256": _sha256(
                Path(policy["transformer_calibration_path"])
            ),
        },
        "zero_audit_trusted_tactics": trusted_only["observation_groups"][0][
            "tactics"
        ],
        "zero_audit_runtime_count": len(
            trusted_only["observation_groups"][0]["audit_only_labels"]
        ),
        "trusted_plus_audit_trusted_tactics": trusted_and_audit[
            "observation_groups"
        ][0]["tactics"],
        "trusted_plus_audit_runtime_count": len(
            trusted_and_audit["observation_groups"][0]["audit_only_labels"]
        ),
        "audit_only_observation_result": (
            "no_trusted_behavior_phase" if audit_only is None else "phase_created"
        ),
        "runtime_audit_prediction": {
            "snapshot_id": runtime_with_audit["snapshot_id"],
            "snapshot_integrity_errors": validate_prediction_snapshot_integrity(
                runtime_with_audit
            ),
            "prediction_status": runtime_with_audit["prediction_status"],
            "prediction_status_reason": runtime_with_audit[
                "prediction_status_reason"
            ],
            "prediction": runtime_with_audit["prediction"],
            "ranking": [
                item["tactic"]
                for item in runtime_with_audit["next_behavior_output"][
                    "ranked_tactics"
                ]
            ],
            "probabilities": {
                item["tactic"]: item["calibrated_probability"]
                for item in runtime_with_audit["next_behavior_output"][
                    "ranked_tactics"
                ]
            },
        },
        "real_audit_model_view": _prediction_view(predictor, real_audit),
        "forced_zero_model_view": _prediction_view(predictor, forced_zero),
        "late_source_timestamp": {
            "durable_event_order": [1, 2],
            "source_chronology_ms_before_failure": [10_000, 5_000],
            "safe_session_build_error": late_build_error,
            "trusted_phase_sequence_before_failure": [
                ["execution"],
                ["discovery"],
            ],
            "prediction_status": late_snapshot["prediction_status"],
            "prediction_status_reason": late_snapshot[
                "prediction_status_reason"
            ],
            "snapshot_integrity_errors": validate_prediction_snapshot_integrity(
                late_snapshot
            ),
        },
    }


def capture(
    *,
    root: Path,
    artifact_root: Path,
    securebert_checkpoint: Path,
    source_revision: str,
) -> dict:
    with tempfile.TemporaryDirectory(prefix="next-tactic-baseline-") as directory:
        temporary = Path(directory)
        receipt = {
            "schema_version": "next_tactic_correction_baseline.v1",
            "source_revision": source_revision,
            "scope": "isolated_local_fixtures_only",
            "target_contract_id": (
                "next_distinct_command_behavior_phase_or_session_end.v1"
            ),
            "selection": _selection_fixture(temporary / "selection.sqlite3"),
            "immutability": _immutability_fixture(
                temporary / "immutability.sqlite3"
            ),
            "runtime": _runtime_fixture(
                root, artifact_root, securebert_checkpoint
            ),
            "privacy": {
                "raw_commands_emitted": False,
                "credentials_emitted": False,
                "source_ips_emitted": False,
                "reversible_session_ids_emitted": False,
            },
        }
    receipt["receipt_sha256"] = hashlib.sha256(
        stable_json(receipt).encode("utf-8")
    ).hexdigest()
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--securebert-checkpoint", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    receipt = capture(
        root=root,
        artifact_root=args.artifact_root.resolve(),
        securebert_checkpoint=args.securebert_checkpoint.resolve(),
        source_revision=args.source_revision,
    )
    print(stable_json(receipt))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
