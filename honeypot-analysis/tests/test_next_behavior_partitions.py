from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from production.prediction.next_behavior_contract import SESSION_SCHEMA_VERSION
from production.prediction.next_behavior_partitions import (
    MEMBER_ROLES,
    PARTITION_SCHEMA_VERSION,
    PARTITION_SCHEMA_VERSION_V2,
    V2_DEVELOPMENT_CUTOFF,
    V2_EMBARGO_DATE,
    V2_FINAL_WINDOW_START,
    NextBehaviorPartitionError,
    assign_seven_member_roles,
    assign_thirteen_member_cohorts,
    assign_thirteen_member_roles,
    build_partition_manifest,
    build_partition_manifest_v2,
    load_partition_for_purpose_v2,
    membership_sha256,
    load_partition_for_purpose,
    records_for_purpose,
    records_for_purpose_v2,
    require_historical_membership_independence,
)
from production.prediction.next_behavior_corpus import (
    build_corpus_receipt,
    build_privacy_safe_session,
    build_source_member_receipt,
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


def _members_v2() -> list[dict]:
    members = []
    for index in range(1, 14):
        day = index if index <= 6 else index + 2
        members.append(
            {
                "member_id": (
                    "nbmember_"
                    + hashlib.sha256(f"v2-member-{index}".encode()).hexdigest()
                ),
                "sha256": hashlib.sha256(
                    f"v2-member-{index}".encode()
                ).hexdigest(),
                "chronological_order": index,
                "collection_start": f"2025-08-{day:02d}T00:00:00Z",
                "collection_end": f"2025-08-{day:02d}T23:59:59Z",
            }
        )
    return members


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


def _corpus_and_build_receipts(
    *,
    overlap: dict[str, int],
) -> tuple[dict, dict]:
    members = _members()
    records = _records(members)
    key = b"k" * 32

    source_receipts = [
        build_source_member_receipt(
            private_member_identifier=str(index),
            source_sha256=member["sha256"],
            byte_size=100 + index,
            chronological_order=index,
            collection_start=member["collection_start"],
            collection_end=member["collection_end"],
            pseudonymization_key=key,
            pseudonymization_key_id="fixture-key",
        )
        for index, member in enumerate(members, 1)
    ]
    build_results = []
    for index, record in enumerate(records, 1):
        source_receipt = source_receipts[index - 1]
        build_results.append(
            build_privacy_safe_session(
                {
                    "session_id": record["session_id"],
                    "source_member_id": str(index),
                    "protocol": "ssh",
                    "status": "closed",
                    "observation_groups": [
                        {
                            **record["observation_groups"][0],
                            "labels": record["observation_groups"][0][
                                "label_provenance"
                            ],
                        }
                    ],
                },
                source_receipt,
                pseudonymization_key=key,
                pseudonymization_key_id="fixture-key",
            )
        )
    corpus = build_corpus_receipt(
        build_results,
        source_receipts,
        code_commit="fixture-commit",
        preprocessing_sha256=HASH_A,
        label_policy_sha256=HASH_A,
        trust_policy_sha256=HASH_B,
        classification_checkpoint_sha256=HASH_B,
    )
    build = {
        "schema_version": "next_behavior_zenodo_build_receipt.v1",
        "status": "safe_corpus_built",
        "code_commit": corpus["code_commit"],
        "corpus_receipt_id": corpus["receipt_id"],
        "historical_payload_sha256": HASH_A,
        "safe_payload": {"line_count": corpus["safe_session_count"]},
        "pipeline_reconciliation": {
            "private_sessions_entering_safe_adapter": corpus[
                "private_session_count"
            ],
        },
        "historical_membership": {
            "accepted_payload_session_count": 50,
            "overlap_by_historical_split": overlap,
        },
    }
    return corpus, build


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


def _historical_evidence_v2(records: list[dict]) -> dict[str, str]:
    split_by_session = {
        _session_id(index): (
            "train"
            if index <= 4
            else "calibration"
            if index <= 6
            else "not_present"
        )
        for index in range(1, 14)
    }
    return {
        record["session_id"]: split_by_session[record["session_id"]]
        for record in records
    }


def _manifest_v2(records: list[dict], members: list[dict], **kwargs) -> dict:
    preprocessing_sha = hashlib.sha256(PREPROCESSING_PATH.read_bytes()).hexdigest()
    kwargs.setdefault(
        "historical_split_by_session",
        _historical_evidence_v2(records),
    )
    kwargs.setdefault("development_cutoff", V2_DEVELOPMENT_CUTOFF)
    kwargs.setdefault("final_window_start", V2_FINAL_WINDOW_START)
    return build_partition_manifest_v2(
        records,
        members,
        preprocessing_sha256=preprocessing_sha,
        label_policy_sha256=HASH_A,
        trust_policy_sha256=HASH_B,
        code_commit="test-v2-commit",
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


def test_thirteen_member_roles_and_cohorts_are_additive_and_frozen() -> None:
    members = _members_v2()

    roles = assign_thirteen_member_roles(members)
    cohorts = assign_thirteen_member_cohorts(members)

    assert [roles[member["member_id"]] for member in members] == [
        "train",
        "train",
        "train",
        "train",
        "selection",
        "calibration",
        "test",
        "test",
        "test",
        "test",
        "test",
        "test",
        "test",
    ]
    assert [cohorts[member["member_id"]] for member in members] == [
        *(["development"] * 6),
        *(["final"] * 7),
    ]


def test_v2_manifest_is_deterministic_with_exact_disjoint_membership() -> None:
    members = _members_v2()
    records = _records(members)

    first = _manifest_v2(records, members)
    second = _manifest_v2(list(reversed(records)), members)

    assert first == second
    assert first["schema_version"] == PARTITION_SCHEMA_VERSION_V2
    assert first["protocol"] == (
        "thirteen_member_chronological_4_1_1_7_with_embargo.v1"
    )
    assert first["temporal_policy"]["development_cutoff"] == "2025-08-07"
    assert first["temporal_policy"]["embargo_date"] == V2_EMBARGO_DATE
    assert first["temporal_policy"]["final_window_start"] == "2025-08-09"
    assert first["roles"]["train"]["source_member_count"] == 4
    assert first["roles"]["test"]["source_member_count"] == 7
    assert first["roles"]["test"]["session_count"] == 7
    assert first["roles"]["test"]["example_count"] == 14
    assert first["cohorts"]["development"]["session_count"] == 6
    assert first["cohorts"]["final"]["session_count"] == 7
    for scope in ("roles", "cohorts"):
        for membership in ("source_members", "sessions", "examples"):
            assert (
                first["intersection_proofs"][scope][membership]["all_empty"]
                is True
            )
    assert all(
        len(digest) == 64 for digest in first["input_hashes"].values()
    )


def test_v2_historical_policy_rejects_test_in_development_and_any_final_overlap(
) -> None:
    members = _members_v2()
    records = _records(members)
    evidence = _historical_evidence_v2(records)
    evidence[records[4]["session_id"]] = "test"

    with pytest.raises(
        NextBehaviorPartitionError,
        match="development cohort.*historical test",
    ):
        _manifest_v2(
            records,
            members,
            historical_split_by_session=evidence,
        )

    evidence = _historical_evidence_v2(records)
    evidence[records[6]["session_id"]] = "calibration"
    with pytest.raises(
        NextBehaviorPartitionError,
        match=r"final cohort.*historical split \(calibration\)",
    ):
        _manifest_v2(
            records,
            members,
            historical_split_by_session=evidence,
        )


def test_v2_discloses_permitted_development_historical_reuse() -> None:
    members = _members_v2()
    records = _records(members)

    manifest = _manifest_v2(records, members)

    disclosure = manifest["historical_membership_policy"]["development"][
        "disclosure"
    ]
    assert disclosure["train"]["session_count"] == 4
    assert disclosure["calibration"]["session_count"] == 2
    assert disclosure["test"]["session_count"] == 0
    assert (
        manifest["historical_membership_policy"]["final"]["disclosure"][
            "not_present"
        ]["session_count"]
        == 7
    )


def test_v2_requires_exact_temporal_cutoff_and_embargo() -> None:
    members = _members_v2()
    records = _records(members)

    with pytest.raises(NextBehaviorPartitionError, match="development_cutoff"):
        _manifest_v2(records, members, development_cutoff="2025-08-06")

    members[6]["collection_start"] = "2025-08-08T23:59:59Z"
    with pytest.raises(NextBehaviorPartitionError, match="final window boundary"):
        _manifest_v2(records, members)


def test_v1_manifest_and_role_assignment_remain_compatible() -> None:
    members = _members()
    manifest = _manifest(_records(members), members)

    assert manifest["schema_version"] == PARTITION_SCHEMA_VERSION
    assert manifest["protocol"] == "seven_member_chronological_4_1_1_1.v1"
    assert assign_seven_member_roles(members)[members[-1]["member_id"]] == "test"
    assert "cohorts" not in manifest


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


def test_private_historical_receipt_rejects_overlap_despite_new_safe_ids() -> None:
    corpus, build = _corpus_and_build_receipts(
        overlap={"train": 3, "calibration": 1, "test": 2, "not_present": 1},
    )

    with pytest.raises(
        NextBehaviorPartitionError,
        match=r"6 sessions; train=3, calibration=1, test=2",
    ):
        require_historical_membership_independence(build, corpus)


def test_private_historical_receipt_accepts_reconciled_zero_overlap() -> None:
    corpus, build = _corpus_and_build_receipts(
        overlap={"train": 0, "calibration": 0, "test": 0, "not_present": 7},
    )

    result = require_historical_membership_independence(build, corpus)

    assert result["status"] == "historical_membership_independent"
    assert result["overlap_count"] == 0
    assert result["candidate_private_session_count"] == 7


def test_private_historical_receipt_rejects_forged_or_incomplete_counts() -> None:
    corpus, build = _corpus_and_build_receipts(
        overlap={"train": 0, "calibration": 0, "test": 0, "not_present": 7},
    )
    build["historical_membership"]["overlap_by_historical_split"][
        "not_present"
    ] = 6
    with pytest.raises(NextBehaviorPartitionError, match="do not reconcile"):
        require_historical_membership_independence(build, corpus)

    corpus, build = _corpus_and_build_receipts(
        overlap={"train": 0, "calibration": 0, "test": 0, "not_present": 7},
    )
    build["corpus_receipt_id"] = "copied-but-wrong"
    with pytest.raises(NextBehaviorPartitionError, match="identities"):
        require_historical_membership_independence(build, corpus)

    corpus, build = _corpus_and_build_receipts(
        overlap={"train": 0, "calibration": 0, "test": 0, "not_present": 7},
    )
    build["historical_payload_sha256"] = "not-a-digest"
    with pytest.raises(NextBehaviorPartitionError, match="SHA-256"):
        require_historical_membership_independence(build, corpus)


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


@pytest.mark.parametrize(
    ("purpose", "expected_count"),
    [
        ("fit_model", 4),
        ("select_model", 1),
        ("fit_calibration", 1),
        ("final_evaluation", 7),
    ],
)
def test_v2_record_access_is_role_and_purpose_scoped(
    purpose: str,
    expected_count: int,
) -> None:
    members = _members_v2()

    selected = records_for_purpose_v2(
        _records(members),
        members,
        purpose=purpose,
    )

    assert len(selected) == expected_count
    if purpose != "final_evaluation":
        final_member_ids = {
            member["member_id"] for member in members[6:]
        }
        assert not final_member_ids.intersection(
            record["source_member_id"] for record in selected
        )


@pytest.mark.parametrize(
    ("purpose", "role"),
    [
        ("fit_model", "train"),
        ("select_model", "selection"),
        ("fit_calibration", "calibration"),
    ],
)
def test_v2_nonfinal_loader_rejects_any_test_path(
    purpose: str,
    role: str,
) -> None:
    opened: list[str] = []

    with pytest.raises(NextBehaviorPartitionError, match=f"only {role}"):
        load_partition_for_purpose_v2(
            {
                role: f"private/{role}.jsonl",
                "test": "private/test.jsonl",
            },
            purpose=purpose,
            reader=opened.append,
        )

    assert opened == []
    selected = load_partition_for_purpose_v2(
        {role: f"private/{role}.jsonl"},
        purpose=purpose,
        reader=lambda path: path,
    )
    assert selected == f"private/{role}.jsonl"


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


def test_manifest_cli_builds_explicit_v2_protocol(tmp_path: Path) -> None:
    members = _members_v2()
    records = _records(members)
    sessions_path = tmp_path / "sessions.json"
    members_path = tmp_path / "members.json"
    evidence_path = tmp_path / "historical-split-evidence.json"
    label_policy_path = tmp_path / "label-policy.json"
    trust_policy_path = tmp_path / "trust-policy.json"
    output_path = tmp_path / "manifest-v2.json"
    sessions_path.write_text(json.dumps(records), encoding="utf-8")
    members_path.write_text(json.dumps(members), encoding="utf-8")
    evidence_path.write_text(
        json.dumps(_historical_evidence_v2(records)),
        encoding="utf-8",
    )
    label_policy_path.write_text('{"version": 2}\n', encoding="utf-8")
    trust_policy_path.write_text('{"version": 2}\n', encoding="utf-8")

    assert (
        build_manifest(
            [
                "--protocol-version",
                "v2",
                "--sessions",
                str(sessions_path),
                "--source-members",
                str(members_path),
                "--historical-split-evidence",
                str(evidence_path),
                "--development-cutoff",
                V2_DEVELOPMENT_CUTOFF,
                "--final-window-start",
                V2_FINAL_WINDOW_START,
                "--preprocessing-config",
                str(PREPROCESSING_PATH),
                "--label-policy",
                str(label_policy_path),
                "--trust-policy",
                str(trust_policy_path),
                "--code-commit",
                "test-v2-commit",
                "--output",
                str(output_path),
            ]
        )
        == 0
    )
    manifest = json.loads(output_path.read_text(encoding="utf-8"))
    assert manifest["schema_version"] == PARTITION_SCHEMA_VERSION_V2
    assert manifest["roles"]["test"]["source_member_count"] == 7


def test_manifest_cli_runs_private_historical_preflight_before_writing(
    tmp_path: Path,
) -> None:
    corpus, build = _corpus_and_build_receipts(
        overlap={"train": 3, "calibration": 1, "test": 2, "not_present": 1},
    )
    corpus_path = tmp_path / "corpus-receipt.json"
    build_path = tmp_path / "build-receipt.json"
    output_path = tmp_path / "must-not-exist.json"
    corpus_path.write_text(json.dumps(corpus), encoding="utf-8")
    build_path.write_text(json.dumps(build), encoding="utf-8")

    with pytest.raises(NextBehaviorPartitionError, match="6 sessions"):
        build_manifest(
            [
                "--sessions",
                str(tmp_path / "sessions-do-not-need-to-exist.json"),
                "--source-members",
                str(tmp_path / "members-do-not-need-to-exist.json"),
                "--historical-session-ids",
                str(tmp_path / "ids-do-not-need-to-exist.json"),
                "--corpus-receipt",
                str(corpus_path),
                "--build-receipt",
                str(build_path),
                "--preprocessing-config",
                str(PREPROCESSING_PATH),
                "--label-policy",
                str(tmp_path / "label-policy-does-not-need-to-exist.json"),
                "--trust-policy",
                str(tmp_path / "trust-policy-does-not-need-to-exist.py"),
                "--code-commit",
                "fixture-commit",
                "--output",
                str(output_path),
            ]
        )

    assert not output_path.exists()
