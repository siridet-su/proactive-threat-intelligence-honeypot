from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import production.tools.assemble_next_behavior_partition_inputs as assembler
from production.prediction.next_behavior_contract import SESSION_SCHEMA_VERSION
from production.prediction.next_behavior_corpus import build_source_member_receipt
from production.utils.serialization import stable_json


HASH_A = "a" * 64
HASH_B = "b" * 64
COMMIT = "c" * 40
SELECTION_SHA = "d" * 64


def _member(index: int) -> dict:
    day = index if index <= 6 else index + 2
    return build_source_member_receipt(
        private_member_identifier=f"member-{index}",
        source_sha256=hashlib.sha256(f"member-{index}".encode()).hexdigest(),
        byte_size=100 + index,
        chronological_order=index,
        collection_start=f"2025-08-{day:02d}T00:00:00Z",
        collection_end=f"2025-08-{day:02d}T23:59:59Z",
        pseudonymization_key=b"k" * 32,
        pseudonymization_key_id="fixture-key",
    )


def _session(member: dict, index: int) -> dict:
    def group(order: int, tactic: str) -> dict:
        evidence_ref = "nbevidence_" + hashlib.sha256(
            f"{index}-{order}".encode()
        ).hexdigest()
        return {
            "group_id": "nbgroup_" + hashlib.sha256(
                f"{index}-{order}".encode()
            ).hexdigest(),
            "event_order": order,
            "relative_time_ms": (order - 1) * 1000,
            "tactics": [tactic],
            "techniques": ["T1082"],
            "evidence_refs": [evidence_ref],
            "label_provenance": [
                {
                    "tactic": tactic,
                    "technique": "T1082",
                    "source": "reviewed_rule",
                    "trust_tier": "trusted_observation",
                    "policy_sha256": HASH_A,
                    "trust_policy_sha256": HASH_B,
                    "checkpoint_sha256": "",
                    "confidence": 1.0,
                    "confidence_bucket": "high",
                    "agreement_status": "rule_only",
                    "evidence_ref": evidence_ref,
                }
            ],
            "session_context": {
                "login_outcome": "success",
                "command_count_bucket": "1",
                "session_age_bucket": "under_10s",
                "confirmed_transfer_observed": False,
            },
        }

    return {
        "schema_version": SESSION_SCHEMA_VERSION,
        "session_id": "nbsession_" + hashlib.sha256(
            f"session-{index}".encode()
        ).hexdigest(),
        "source_member_id": member["member_id"],
        "source_member_sha256": member["sha256"],
        "protocol": "ssh",
        "status": "closed",
        "observation_groups": [group(1, "discovery"), group(2, "execution")],
    }


def _role_for(index: int) -> str:
    if index <= 4:
        return "train"
    if index == 5:
        return "selection"
    if index == 6:
        return "calibration"
    return "test"


def _bundle(tmp_path: Path, role: str, rows: list[tuple[int, dict, dict]]) -> assembler.RoleBundle:
    directory = tmp_path / role
    directory.mkdir()
    paths = {}
    for name, filename in assembler.ROLE_BUNDLE_FILENAMES.items():
        path = directory / filename
        path.write_text("{}\n", encoding="utf-8")
        paths[name] = path
    members = tuple(row[1] for row in rows)
    sessions = tuple(row[2] for row in rows)
    evidence = {
        session["session_id"]: (
            "train" if index <= 4 else "calibration" if index <= 6 else "not_present"
        )
        for index, _member, session in rows
    }
    receipt = {
        "build_receipt_id": f"nextbehaviorselectedsafebuild_{role}",
        "code_commit": COMMIT,
        "source_selection_sha256": SELECTION_SHA,
        "pseudonymization_key_id": "fixture-key",
        "max_sequence_length": 8,
        "preprocessing_sha256": HASH_A,
        "label_policy_sha256": HASH_A,
        "trust_policy_sha256": HASH_B,
        "classification_checkpoint_sha256": HASH_B,
    }
    return assembler.RoleBundle(
        role=role,
        paths=paths,
        build_receipt=receipt,
        corpus_receipt={"receipt_id": f"nextbehaviorcorpus_{role}"},
        inventory={},
        source_members=members,
        sessions=sessions,
        historical_split_by_session=evidence,
    )


def test_assembly_publishes_canonical_frozen_v2_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rows = [(index, _member(index), _session(_member(index), index)) for index in range(1, 14)]
    bundles = {
        role: _bundle(tmp_path, role, [row for row in rows if _role_for(row[0]) == role])
        for role in assembler.MEMBER_ROLES
    }
    monkeypatch.setattr(assembler, "_load_role_bundle", lambda role, _path: bundles[role])
    output = tmp_path / "assembled"

    receipt = assembler.assemble_partition_inputs(
        role_bundle_directories={role: tmp_path / role for role in assembler.MEMBER_ROLES},
        output_directory=output,
    )

    manifest = json.loads((output / "partition_manifest.json").read_text())
    persisted_receipt = json.loads((output / "assembly_receipt.json").read_text())
    assert manifest["protocol"] == "thirteen_member_chronological_4_1_1_7_with_embargo.v1"
    assert manifest["roles"]["train"]["source_member_count"] == 4
    assert manifest["roles"]["test"]["source_member_count"] == 7
    assert receipt == persisted_receipt
    assert receipt["manifest_id"] == manifest["manifest_id"]
    assert receipt["test_opened"] is False
    test_payload = json.loads(
        (output / "safe_payloads" / "test.json").read_text()
    )
    assert len(test_payload) == 7
    assert receipt["role_artifacts"]["test"][
        "canonical_safe_payload_sha256"
    ] == hashlib.sha256(
        (stable_json(test_payload) + "\n").encode("utf-8")
    ).hexdigest()

    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        assembler.assemble_partition_inputs(
            role_bundle_directories={role: tmp_path / role for role in assembler.MEMBER_ROLES},
            output_directory=output,
        )


def test_historical_sidecar_requires_canonical_exact_safe_session_binding(
    tmp_path: Path,
) -> None:
    member = _member(1)
    session = _session(member, 1)
    evidence_path = tmp_path / "evidence.json"
    payload = {
        "schema_version": assembler.HISTORICAL_EVIDENCE_SCHEMA_VERSION,
        "status": "historical_split_evidence_complete",
        "selected_safe_corpus_receipt_id": "nextbehaviorcorpus_fixture",
        "source_selection_sha256": SELECTION_SHA,
        "records": [
            {
                "session_id": session["session_id"],
                "source_member_id": session["source_member_id"],
                "source_member_sha256": HASH_B,
                "historical_split": "train",
            }
        ],
    }
    evidence_path.write_text(stable_json(payload) + "\n", encoding="utf-8")

    with pytest.raises(assembler.PartitionInputAssemblyError, match="not canonical or bound"):
        assembler._load_historical_evidence(
            evidence_path,
            corpus_receipt_id="nextbehaviorcorpus_fixture",
            source_selection_sha256=SELECTION_SHA,
            sessions=[session],
        )


def test_assembly_requires_all_four_role_bundles(tmp_path: Path) -> None:
    with pytest.raises(assembler.PartitionInputAssemblyError, match="must define"):
        assembler.assemble_partition_inputs(
            role_bundle_directories={"train": tmp_path},
            output_directory=tmp_path / "out",
        )


def test_role_bundle_verification_binds_exact_historical_sidecar(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory = tmp_path / "train"
    directory.mkdir()
    paths = {
        name: directory / filename
        for name, filename in assembler.ROLE_BUNDLE_FILENAMES.items()
    }
    for path in paths.values():
        path.write_text("{}\n", encoding="utf-8")
    captured: dict[str, Path] = {}

    def fake_verify(
        *,
        historical_split_evidence_path: Path,
        **_kwargs: object,
    ) -> dict[str, object]:
        captured["path"] = historical_split_evidence_path
        raise ValueError("verification boundary reached")

    monkeypatch.setattr(
        assembler, "verify_selected_role_artifacts", fake_verify
    )
    with pytest.raises(
        assembler.PartitionInputAssemblyError,
        match="verification boundary reached",
    ):
        assembler._load_role_bundle("train", directory)
    assert captured["path"] == paths["historical_split_evidence"]
