from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from production.prediction.next_behavior_contract import SESSION_SCHEMA_VERSION
from production.prediction.next_behavior_corpus import (
    build_corpus_receipt,
    build_source_member_receipt,
)
from production.tools.build_next_behavior_corpus_inventory import (
    NextBehaviorInventoryError,
    build_corpus_inventory,
)
from production.utils.serialization import stable_json


HASH_A = "a" * 64
HASH_B = "b" * 64
KEY = b"k" * 32
KEY_ID = "fixture-key"


def _member(index: int) -> dict:
    return build_source_member_receipt(
        private_member_identifier=f"member-{index}",
        source_sha256=hashlib.sha256(f"member-{index}".encode()).hexdigest(),
        byte_size=100 + index,
        chronological_order=index,
        collection_start=f"2026-01-{index:02d}T00:00:00Z",
        collection_end=f"2026-01-{index:02d}T23:59:59Z",
        pseudonymization_key=KEY,
        pseudonymization_key_id=KEY_ID,
    )


def _group(session_index: int, index: int, tactic: str) -> dict:
    digest = hashlib.sha256(f"{session_index}:{index}".encode()).hexdigest()
    evidence = f"nbevidence_{digest}"
    return {
        "group_id": f"nbgroup_{digest}",
        "event_order": index,
        "relative_time_ms": (index - 1) * 1000,
        "tactics": [tactic],
        "techniques": ["T1082" if index == 1 else "T1059.004"],
        "evidence_refs": [evidence],
        "label_provenance": [
            {
                "tactic": tactic,
                "technique": "T1082" if index == 1 else "T1059.004",
                "source": "reviewed_rule",
                "trust_tier": "trusted_observation",
                "policy_sha256": HASH_A,
                "trust_policy_sha256": HASH_B,
                "checkpoint_sha256": "",
                "confidence": 1.0,
                "confidence_bucket": "high",
                "agreement_status": "rule_only",
                "evidence_ref": evidence,
            }
        ],
        "session_context": {
            "login_outcome": "success",
            "command_count_bucket": "1" if index == 1 else "2-5",
            "session_age_bucket": "under_10s",
            "confirmed_transfer_observed": False,
        },
    }


def _session(member: dict, index: int) -> dict:
    return {
        "schema_version": SESSION_SCHEMA_VERSION,
        "session_id": (
            "nbsession_"
            + hashlib.sha256(f"session-{index}".encode()).hexdigest()
        ),
        "source_member_id": member["member_id"],
        "source_member_sha256": member["sha256"],
        "protocol": "ssh",
        "status": "closed",
        "observation_groups": [
            _group(index, 1, "discovery"),
            _group(index, 2, "execution"),
        ],
    }


def _fixture(tmp_path: Path, *, overlap: bool = True) -> dict:
    tmp_path.mkdir(parents=True, exist_ok=True)
    members = [_member(index) for index in range(1, 8)]
    sessions = sorted(
        (_session(member, index) for index, member in enumerate(members, 1)),
        key=lambda session: session["session_id"],
    )
    payload = tmp_path / "safe.jsonl"
    payload.write_text(
        "".join(stable_json(session) + "\n" for session in sessions),
        encoding="utf-8",
    )
    build_results = [
        {
            "safe_session": session,
            "reconciliation": {
                "private_group_count": 2,
                "safe_trusted_group_count": 2,
                "audit_only_group_count": 0,
                "private_label_count": 2,
                "trusted_label_count": 2,
                "audit_only_label_count": 0,
            },
        }
        for session in sessions
    ]
    corpus = build_corpus_receipt(
        build_results,
        members,
        code_commit="corpus-commit",
        preprocessing_sha256=HASH_A,
        label_policy_sha256=HASH_A,
        trust_policy_sha256=HASH_B,
        classification_checkpoint_sha256=HASH_B,
    )
    file_hash = hashlib.sha256(payload.read_bytes()).hexdigest()
    build = {
        "schema_version": "next_behavior_zenodo_build_receipt.v1",
        "status": "safe_corpus_built",
        "code_commit": corpus["code_commit"],
        "corpus_receipt_id": corpus["receipt_id"],
        "safe_payload": {
            "sha256": file_hash,
            "size_bytes": payload.stat().st_size,
            "line_count": 7,
        },
        "historical_membership": {
            "accepted_payload_session_count": 50,
            "overlap_by_historical_split": {
                "train": 4 if overlap else 0,
                "calibration": 1 if overlap else 0,
                "test": 2 if overlap else 0,
                "not_present": 0 if overlap else 7,
            }
        },
    }
    return {
        "payload": payload,
        "source_receipts": {
            "schema_version": "next_behavior_source_member_receipts.v1",
            "members": members,
        },
        "corpus_receipt": corpus,
        "build_receipt": build,
    }


def test_real_corpus_inventory_is_deterministic_and_records_targets(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)

    first = build_corpus_inventory(
        safe_payload_path=fixture["payload"],
        source_receipts=fixture["source_receipts"],
        corpus_receipt=fixture["corpus_receipt"],
        build_receipt=fixture["build_receipt"],
        preprocessing_sha256=HASH_A,
        inventory_code_commit="inventory-commit",
    )
    second = build_corpus_inventory(
        safe_payload_path=fixture["payload"],
        source_receipts=fixture["source_receipts"],
        corpus_receipt=fixture["corpus_receipt"],
        build_receipt=fixture["build_receipt"],
        preprocessing_sha256=HASH_A,
        inventory_code_commit="inventory-commit",
    )

    assert first == second
    assert first["session_count"] == 7
    assert first["example_count"] == 14
    assert first["candidate_roles"]["train"]["session_count"] == 4
    assert first["candidate_roles"]["train"]["example_count"] == 8
    assert first["candidate_roles"]["test"]["terminal_example_count"] == 1
    assert first["candidate_roles"]["test"]["target_tactic_occurrences"] == {
        "execution": 1
    }
    assert first["historical_membership"]["overlap_count"] == 7
    assert first["historical_membership"]["partition_freeze_status"] == (
        "blocked_historical_overlap"
    )
    assert first["training_vocabulary_frozen"] is False
    assert first["final_test_opened"] is False


def test_zero_overlap_inventory_is_only_eligible_for_partition_preflight(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path, overlap=False)

    result = build_corpus_inventory(
        safe_payload_path=fixture["payload"],
        source_receipts=fixture["source_receipts"],
        corpus_receipt=fixture["corpus_receipt"],
        build_receipt=fixture["build_receipt"],
        preprocessing_sha256=HASH_A,
        inventory_code_commit="inventory-commit",
    )

    assert result["historical_membership"]["partition_freeze_status"] == (
        "eligible_for_partition_preflight"
    )
    assert result["model_fitting_authorized"] is False


def test_inventory_rejects_payload_or_receipt_drift(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    fixture["payload"].write_text(
        fixture["payload"].read_text(encoding="utf-8") + "{}\n",
        encoding="utf-8",
    )

    with pytest.raises(
        NextBehaviorInventoryError,
        match=r"file (size|SHA-256)",
    ):
        build_corpus_inventory(
            safe_payload_path=fixture["payload"],
            source_receipts=fixture["source_receipts"],
            corpus_receipt=fixture["corpus_receipt"],
            build_receipt=fixture["build_receipt"],
            preprocessing_sha256=HASH_A,
            inventory_code_commit="inventory-commit",
        )

    fixture = _fixture(tmp_path / "second")
    fixture["build_receipt"]["corpus_receipt_id"] = "forged"
    with pytest.raises(NextBehaviorInventoryError, match="do not match"):
        build_corpus_inventory(
            safe_payload_path=fixture["payload"],
            source_receipts=fixture["source_receipts"],
            corpus_receipt=fixture["corpus_receipt"],
            build_receipt=fixture["build_receipt"],
            preprocessing_sha256=HASH_A,
            inventory_code_commit="inventory-commit",
        )
