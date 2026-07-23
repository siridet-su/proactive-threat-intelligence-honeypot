from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from production.prediction.next_behavior_contract import SESSION_SCHEMA_VERSION
from production.prediction.next_behavior_partitions import (
    MEMBER_ROLES,
    NextBehaviorPartitionError,
    assign_seven_member_roles,
    build_partition_manifest,
    membership_sha256,
    load_partition_for_purpose,
    records_for_purpose,
)
from production.tools.build_next_behavior_split_manifest import main as build_manifest


HASH_A = "a" * 64
HASH_B = "b" * 64
ROOT = Path(__file__).resolve().parents[1]
PREPROCESSING_PATH = ROOT / "configs" / "next_behavior_preprocessing.v1.json"


def _members() -> list[dict]:
    return [
        {
            "member_id": (
                "nbmember_"
                + hashlib.sha256(f"member-{index}".encode()).hexdigest()
            ),
            "sha256": hashlib.sha256(f"member-{index}".encode()).hexdigest(),
            "chronological_order": index,
            "collection_start": f"2026-01-{index:02d}T00:00:00Z",
            "collection_end": f"2026-01-{index:02d}T23:59:59Z",
        }
        for index in range(1, 8)
    ]


def _session(member: dict, index: int) -> dict:
    policy_sha = hashlib.sha256(b"policy").hexdigest()

    def group(group_index: int, tactic: str) -> dict:
        evidence_ref = (
            "nbevidence_"
            + hashlib.sha256(
                f"evidence-{index}-{group_index}".encode()
            ).hexdigest()
        )
        return {
            "group_id": (
                "nbgroup_"
                + hashlib.sha256(
                    f"group-{index}-{group_index}".encode()
                ).hexdigest()
            ),
            "event_order": group_index,
            "relative_time_ms": (group_index - 1) * 1000,
            "tactics": [tactic],
            "techniques": ["T1082"],
            "evidence_refs": [evidence_ref],
            "label_provenance": [
                {
                    "tactic": tactic,
                    "technique": "T1082",
                    "source": "reviewed_rule",
                    "trust_tier": "trusted_observation",
                    "policy_sha256": policy_sha,
                    "trust_policy_sha256": policy_sha,
                    "checkpoint_sha256": "",
                    "confidence": 1.0,
                    "confidence_bucket": "high",
                    "agreement_status": "rule_only",
                    "evidence_ref": evidence_ref,
                }
            ],
            "session_context": {
                "login_outcome": "success",
                "command_count_bucket": "1" if group_index == 1 else "2-5",
                "session_age_bucket": "under_10s",
                "confirmed_transfer_observed": False,
            },
        }

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
            group(1, "discovery"),
            group(2, "execution"),
        ],
    }


def _records(members: list[dict]) -> list[dict]:
    return [_session(member, index) for index, member in enumerate(members, 1)]


def _session_id(index: int) -> str:
    return "nbsession_" + hashlib.sha256(f"session-{index}".encode()).hexdigest()


def _manifest(records: list[dict], members: list[dict], **kwargs) -> dict:
    preprocessing_sha = hashlib.sha256(PREPROCESSING_PATH.read_bytes()).hexdigest()
    kwargs.setdefault(
        "forbidden_historical_session_ids",
        {"accepted-historical-session"},
    )
    return build_partition_manifest(
        records,
        members,
        preprocessing_sha256=preprocessing_sha,
        label_policy_sha256=HASH_A,
        trust_policy_sha256=HASH_B,
        code_commit="test-commit",
        **kwargs,
    )


def test_frozen_preprocessing_configuration_matches_contract() -> None:
    payload = json.loads(PREPROCESSING_PATH.read_text(encoding="utf-8"))

    assert payload["target_contract_id"] == (
        "next_distinct_command_behavior_phase_or_session_end.v1"
    )
    assert payload["phase_construction"]["simultaneous_tactics"] == "unordered_set"
    assert payload["phase_construction"]["maximum_sequence_length"] == 8
    assert payload["score_semantics"] == "raw_model_scores_not_probabilities"


def test_seven_member_roles_are_chronological_and_frozen() -> None:
    members = _members()

    roles = assign_seven_member_roles(members)

    assert [roles[_members()[index - 1]["member_id"]] for index in range(1, 8)] == [
        "train",
        "train",
        "train",
        "train",
        "selection",
        "calibration",
        "test",
    ]


def test_manifest_has_disjoint_membership_and_deterministic_hashes() -> None:
    members = _members()
    records = _records(members)

    first = _manifest(records, members)
    second = _manifest(list(reversed(records)), members)

    assert first == second
    assert first["intersection_proofs"]["sessions"]["all_empty"] is True
    assert first["intersection_proofs"]["examples"]["all_empty"] is True
    assert set(first["roles"]) == set(MEMBER_ROLES)
    assert first["roles"]["train"]["session_count"] == 4
    assert first["roles"]["train"]["example_count"] == 8
    assert first["roles"]["test"]["session_count"] == 1
    assert first["roles"]["test"]["example_count"] == 2
    assert first["manifest_id"].startswith("nextbehaviorpartition_")


def test_member_reuse_and_receipt_mismatch_fail_closed() -> None:
    members = _members()
    reused = copy.deepcopy(members)
    reused[-1]["member_id"] = reused[0]["member_id"]
    with pytest.raises(NextBehaviorPartitionError, match="unique"):
        assign_seven_member_roles(reused)

    records = _records(members)
    records[0]["source_member_sha256"] = HASH_A
    with pytest.raises(NextBehaviorPartitionError, match="does not match"):
        _manifest(records, members)


def test_nonchronological_or_undefined_member_metadata_is_rejected() -> None:
    members = _members()
    members[2]["chronological_order"] = 1
    with pytest.raises(NextBehaviorPartitionError, match="chronological"):
        assign_seven_member_roles(members)

    members = _members()
    members[0]["unexpected"] = "not allowed"
    with pytest.raises(NextBehaviorPartitionError, match="undefined fields"):
        assign_seven_member_roles(members)


def test_historical_membership_guard_rejects_any_overlap() -> None:
    members = _members()
    records = _records(members)

    with pytest.raises(NextBehaviorPartitionError, match="historical corpus"):
        _manifest(
            records,
            members,
            forbidden_historical_session_ids={_session_id(7), "historical-only"},
        )

    manifest = _manifest(
        records,
        members,
        forbidden_historical_session_ids={"historical-only"},
    )
    exclusion = manifest["accepted_historical_membership_exclusion"]
    assert exclusion["forbidden_session_count"] == 1
    assert exclusion["intersection_count"] == 0


@pytest.mark.parametrize(
    ("purpose", "expected_session"),
    [
        ("fit_model", _session_id(1)),
        ("select_model", _session_id(5)),
        ("fit_calibration", _session_id(6)),
        ("final_evaluation", _session_id(7)),
    ],
)
def test_purpose_scoped_loader_exposes_only_its_role(
    purpose: str,
    expected_session: str,
) -> None:
    members = _members()
    selected = records_for_purpose(
        _records(members),
        members,
        purpose=purpose,
    )

    assert expected_session in {record["session_id"] for record in selected}
    if purpose != "fit_model":
        assert len(selected) == 1


def test_training_and_selection_cannot_load_final_test() -> None:
    members = _members()
    records = _records(members)

    train = records_for_purpose(records, members, purpose="fit_model")
    selection = records_for_purpose(records, members, purpose="select_model")

    assert _session_id(7) not in {record["session_id"] for record in train}
    assert _session_id(7) not in {record["session_id"] for record in selection}
    with pytest.raises(NextBehaviorPartitionError, match="unknown"):
        records_for_purpose(records, members, purpose="train_and_test")


def test_purpose_loader_never_opens_another_role_artifact() -> None:
    opened: list[str] = []
    paths = {
        "train": "private/train.jsonl",
        "selection": "private/selection.jsonl",
        "calibration": "private/calibration.jsonl",
        "test": "private/test.jsonl",
    }

    def reader(path: str) -> str:
        opened.append(path)
        return path

    selected = load_partition_for_purpose(
        paths,
        purpose="select_model",
        reader=reader,
    )

    assert selected == "private/selection.jsonl"
    assert opened == ["private/selection.jsonl"]
    assert "private/test.jsonl" not in opened


def test_membership_hash_is_order_invariant_and_duplicate_free() -> None:
    assert membership_sha256(["b", "a", "a"]) == membership_sha256(["a", "b"])


def test_manifest_cli_writes_once_and_refuses_overwrite(tmp_path: Path) -> None:
    members = _members()
    sessions_path = tmp_path / "sessions.json"
    members_path = tmp_path / "members.json"
    historical_path = tmp_path / "historical.json"
    label_policy_path = tmp_path / "label-policy.json"
    trust_policy_path = tmp_path / "trust-policy.json"
    output_path = tmp_path / "manifest.json"
    sessions_path.write_text(json.dumps(_records(members)), encoding="utf-8")
    members_path.write_text(json.dumps(members), encoding="utf-8")
    historical_path.write_text(
        json.dumps(["accepted-historical-session"]),
        encoding="utf-8",
    )
    label_policy_path.write_text('{"version": 1}\n', encoding="utf-8")
    trust_policy_path.write_text('{"version": 1}\n', encoding="utf-8")
    arguments = [
        "--sessions",
        str(sessions_path),
        "--source-members",
        str(members_path),
        "--historical-session-ids",
        str(historical_path),
        "--preprocessing-config",
        str(PREPROCESSING_PATH),
        "--label-policy",
        str(label_policy_path),
        "--trust-policy",
        str(trust_policy_path),
        "--code-commit",
        "test-commit",
        "--output",
        str(output_path),
    ]

    assert build_manifest(arguments) == 0
    manifest = json.loads(output_path.read_text(encoding="utf-8"))
    assert manifest["status"] == "membership_frozen"

    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        build_manifest(arguments)
