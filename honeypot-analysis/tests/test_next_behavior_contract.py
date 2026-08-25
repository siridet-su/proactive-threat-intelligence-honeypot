from __future__ import annotations

import copy
import hashlib

import pytest

from production.prediction.evidence_cutoff import make_evidence_cutoff
from production.prediction.next_behavior_contract import (
    MODEL_INPUT_SCHEMA_VERSION,
    SESSION_SCHEMA_VERSION,
    TARGET_CONTRACT_ID,
    TERMINAL_OUTCOME,
    NextBehaviorContractError,
    normalize_label_source,
    validate_next_behavior_session,
)
from production.prediction.next_behavior_preprocessing import (
    build_behavior_phases,
    build_live_model_input,
    build_next_behavior_examples,
)
from production.prediction.trusted_history import (
    build_prediction_trusted_history_manifest,
    normalize_trusted_phases,
    phase_sha256,
    validate_prediction_trusted_history_manifest,
)
from production.utils.serialization import stable_json


HASH_A = "a" * 64
HASH_B = "b" * 64


def _opaque(kind: str, value: str) -> str:
    return f"nb{kind}_{hashlib.sha256(value.encode()).hexdigest()}"


def _context(command_count: str = "1", age: str = "under_10s") -> dict:
    if command_count.isdigit():
        count = int(command_count)
        if count == 0:
            command_count = "0"
        elif count == 1:
            command_count = "1"
        elif count <= 5:
            command_count = "2-5"
        elif count <= 20:
            command_count = "6-20"
        else:
            command_count = "21+"
    return {
        "login_outcome": "success",
        "command_count_bucket": command_count,
        "session_age_bucket": age,
        "confirmed_transfer_observed": False,
    }


def _provenance(
    evidence_ref: str,
    *,
    source: str = "reviewed_rule",
    tactic: str = "discovery",
    technique: str = "T1082",
) -> dict:
    if not evidence_ref.startswith("nbevidence_"):
        evidence_ref = _opaque("evidence", evidence_ref)
    return {
        "tactic": tactic,
        "technique": technique,
        "source": source,
        "trust_tier": "trusted_observation",
        "policy_sha256": HASH_A,
        "trust_policy_sha256": HASH_A,
        "checkpoint_sha256": HASH_B if source != "reviewed_rule" else "",
        "confidence": 1.0,
        "confidence_bucket": "high",
        "agreement_status": "rule_only" if source == "reviewed_rule" else "agreed",
        "evidence_ref": evidence_ref,
    }


def _group(
    group_id: str,
    order: int,
    time_ms: int,
    tactics: list[str],
    *,
    techniques: list[str] | None = None,
    command_count: str = "1",
    provenance: list[dict] | None = None,
) -> dict:
    safe_group_id = _opaque("group", group_id)
    refs = [
        _opaque("evidence", f"{group_id}-{index}") for index in range(len(tactics))
    ]
    resolved_techniques = techniques or ["T1082"]
    label_provenance = provenance or [
        _provenance(
            ref,
            tactic=tactic,
            technique=resolved_techniques[min(index, len(resolved_techniques) - 1)],
        )
        for index, (ref, tactic) in enumerate(zip(refs, tactics))
    ]
    return {
        "group_id": safe_group_id,
        "event_order": order,
        "relative_time_ms": time_ms,
        "tactics": tactics,
        "techniques": resolved_techniques,
        "evidence_refs": [
            str(item["evidence_ref"]) for item in label_provenance
        ],
        "label_provenance": label_provenance,
        "session_context": _context(command_count),
    }


def _session(groups: list[dict], *, status: str = "closed") -> dict:
    return {
        "schema_version": SESSION_SCHEMA_VERSION,
        "session_id": _opaque("session", "safe-session"),
        "source_member_id": _opaque("member", "member-week-1"),
        "source_member_sha256": HASH_A,
        "protocol": "ssh",
        "status": status,
        "observation_groups": groups,
    }


def test_simultaneous_label_order_does_not_change_phases_or_examples() -> None:
    first_provenance = [
        _provenance("evidence-one", tactic="execution"),
        _provenance("evidence-two", tactic="discovery"),
    ]
    first = _group(
        "one",
        1,
        0,
        ["execution", "discovery"],
        provenance=first_provenance,
    )
    second = _group("two", 2, 1000, ["persistence"], command_count="2")
    original = _session([first, second])
    permuted = copy.deepcopy(original)
    permuted["observation_groups"][0]["tactics"].reverse()
    permuted["observation_groups"][0]["label_provenance"].reverse()
    permuted["observation_groups"][0]["evidence_refs"].reverse()

    assert build_behavior_phases(original) == build_behavior_phases(permuted)
    assert build_next_behavior_examples(original) == build_next_behavior_examples(
        permuted
    )


def test_repeated_tactic_sets_form_one_phase_without_losing_run_information() -> None:
    record = _session(
        [
            _group("one", 1, 0, ["discovery"]),
            _group("two", 2, 900, ["discovery"], command_count="2"),
            _group("three", 3, 12_000, ["execution"], command_count="3"),
        ]
    )

    phases = build_behavior_phases(record)

    assert len(phases) == 2
    assert phases[0]["tactics"] == ["discovery"]
    assert phases[0]["observation_count"] == 2
    assert phases[0]["repetition_bucket"] == "2"
    assert phases[0]["duration_ms"] == 900.0
    assert phases[0]["elapsed_time_bucket"] == "under_1s"
    assert phases[0]["session_context"]["command_count_bucket"] == "2-5"
    assert len(phases[0]["evidence_refs"]) == 2
    assert phases[0]["label_agreement_statuses"] == ["rule_only"]
    assert phases[0]["audit_only_label_count"] == 0


def test_v3_duplicate_semantic_labels_fail_closed_at_next_behavior_boundary() -> None:
    """The producer collapses duplicates; a malformed boundary record still rejects them."""

    manifest = build_prediction_trusted_history_manifest(
        phases=[
            {
                "command_index": 0,
                "event_id": "event-one",
                "event_timestamp": "2026-08-13T00:00:00Z",
                "labels": [
                    {
                        "tactic": "discovery",
                        "technique": "T1033",
                        "source": "reviewed_rule",
                        "classification_evidence_id": "event-one",
                    }
                ],
            }
        ],
        evidence_cutoff=make_evidence_cutoff(
            "2026-08-13T00:00:00Z", "event-one"
        ),
        classifier_environment={"environment_sha256": "a" * 64},
    )
    phase = copy.deepcopy(manifest["ordered_trusted_phases"][0])
    phase["labels"].append(copy.deepcopy(phase["labels"][0]))
    phase["phase_sha256"] = phase_sha256(phase)
    manifest["ordered_trusted_phases"] = [phase]
    manifest["ordered_trusted_phases_sha256"] = hashlib.sha256(
        stable_json(manifest["ordered_trusted_phases"]).encode("utf-8")
    ).hexdigest()
    basis = copy.deepcopy(manifest)
    basis.pop("history_manifest_sha256")
    manifest["history_manifest_sha256"] = hashlib.sha256(
        stable_json(basis).encode("utf-8")
    ).hexdigest()

    assert validate_prediction_trusted_history_manifest(manifest) == []
    record = _session([_group("one", 1, 0, ["discovery"])])
    record["prediction_trusted_history_manifest"] = manifest
    errors = validate_next_behavior_session(record)
    assert "prediction trusted history phase 0 labels are duplicated" in errors


def test_v3_producer_collapses_semantic_duplicates_and_retains_all_evidence() -> None:
    phases = normalize_trusted_phases(
        [
            {
                "command_index": 0,
                "event_id": "event-id",
                "event_timestamp": "2026-08-13T00:00:00Z",
                "labels": [
                    {
                        "tactic": "discovery",
                        "technique": "T1033",
                        "source": "reviewed_rule",
                        "classification_evidence_id": "event-id",
                    },
                    {
                        "tactic": "discovery",
                        "technique": "T1033",
                        "source": "reviewed_rule",
                        "classification_evidence_id": "event-whoami",
                    },
                ],
            }
        ],
        cap=None,
    )

    assert len(phases) == 1
    assert [(item["tactic"], item["technique"]) for item in phases[0]["labels"]] == [
        ("discovery", "T1033")
    ]
    assert phases[0]["evidence_refs"] == ["event-id", "event-whoami"]


def test_closed_session_emits_next_phase_and_terminal_examples() -> None:
    examples = build_next_behavior_examples(
        _session(
            [
                _group("one", 1, 0, ["discovery"]),
                _group("two", 2, 1000, ["execution"], command_count="2"),
            ]
        )
    )

    assert len(examples) == 2
    assert examples[0]["target"] == {
        "outcome_type": "next_behavior_phase",
        "tactics": ["execution"],
        "techniques": ["T1082"],
        "terminal_outcome": "",
        "target_evidence_refs": [_opaque("evidence", "two-0")],
    }
    assert examples[1]["target"] == {
        "outcome_type": "session_end",
        "tactics": [],
        "techniques": [],
        "terminal_outcome": TERMINAL_OUTCOME,
        "target_evidence_refs": [],
    }
    assert all(
        item["target_contract_id"] == TARGET_CONTRACT_ID for item in examples
    )


def test_active_session_does_not_fabricate_terminal_ground_truth() -> None:
    record = _session([_group("one", 1, 0, ["discovery"])], status="active")

    assert build_behavior_phases(record)
    assert build_next_behavior_examples(record) == []


def test_future_target_mutation_cannot_change_earlier_model_input() -> None:
    record = _session(
        [
            _group("one", 1, 0, ["discovery"]),
            _group("two", 2, 1000, ["execution"], command_count="2"),
        ]
    )
    before = build_next_behavior_examples(record)[0]["model_input"]
    changed = copy.deepcopy(record)
    changed["observation_groups"][1] = _group(
        "future-mutated",
        2,
        55_000,
        ["persistence"],
        techniques=["T1098"],
        command_count="21+",
    )
    after = build_next_behavior_examples(changed)[0]["model_input"]

    assert before == after
    assert "persistence" not in str(after)
    assert "future-mutated" not in str(after)


def test_training_example_and_live_prefix_use_identical_model_input() -> None:
    closed = _session(
        [
            _group("one", 1, 0, ["discovery"]),
            _group("two", 2, 1000, ["execution"], command_count="2"),
        ]
    )
    live_prefix = _session(
        [copy.deepcopy(closed["observation_groups"][0])],
        status="active",
    )

    offline = build_next_behavior_examples(closed)[0]["model_input"]
    live = build_live_model_input(live_prefix)

    assert offline == live
    assert live["schema_version"] == MODEL_INPUT_SCHEMA_VERSION


def test_context_truncation_is_explicit_and_uses_most_recent_phases() -> None:
    tactics = [
        "discovery",
        "execution",
        "persistence",
        "defense-evasion",
        "command-and-control",
    ]
    groups = [
        _group(
            f"group-{index}",
            index,
            index * 1000,
            [tactic],
            command_count="6-20",
        )
        for index, tactic in enumerate(tactics, start=1)
    ]

    value = build_live_model_input(_session(groups, status="active"), max_sequence_length=3)

    assert value["truncated"] is True
    assert [item["tactics"] for item in value["phase_sequence"]] == [
        ["persistence"],
        ["defense-evasion"],
        ["command-and-control"],
    ]


@pytest.mark.parametrize(
    "mutation, expected",
    [
        (lambda row: row.update({"commands": ["sensitive"]}), "forbidden"),
        (
            lambda row: row["observation_groups"][0]["label_provenance"][0].update(
                {"source": "securebert_low_confidence"}
            ),
            "not approved",
        ),
        (
            lambda row: row["observation_groups"][0]["label_provenance"][0].update(
                {"trust_tier": "audit_only_candidate"}
            ),
            "trusted_observation",
        ),
        (
            lambda row: row["observation_groups"][0].update({"event_order": 0}),
            "strictly increasing",
        ),
    ],
)
def test_malformed_or_unsafe_session_contract_is_rejected(
    mutation,
    expected: str,
) -> None:
    record = _session([_group("one", 1, 0, ["discovery"])])
    mutation(record)

    errors = validate_next_behavior_session(record)

    assert any(expected in error for error in errors)
    with pytest.raises(NextBehaviorContractError):
        build_behavior_phases(record)


@pytest.mark.parametrize(
    "field, value, expected",
    [
        ("event_order", True, "must be an integer"),
        ("event_order", 1.5, "must be an integer"),
        ("relative_time_ms", float("nan"), "must be non-negative"),
        ("relative_time_ms", float("inf"), "must be non-negative"),
    ],
)
def test_noncanonical_order_and_time_values_are_rejected(
    field: str,
    value,
    expected: str,
) -> None:
    record = _session([_group("one", 1, 0, ["discovery"])])
    record["observation_groups"][0][field] = value

    assert any(
        expected in error for error in validate_next_behavior_session(record)
    )


def test_nonfinite_confidence_and_unknown_fields_are_rejected() -> None:
    record = _session([_group("one", 1, 0, ["discovery"])])
    provenance = record["observation_groups"][0]["label_provenance"][0]
    provenance["confidence"] = float("nan")
    record["observation_groups"][0]["geo"] = {"country": "example"}

    errors = validate_next_behavior_session(record)

    assert any("confidence must be in [0, 1]" in error for error in errors)
    assert any("geo is not defined by the contract" in error for error in errors)


def test_raw_identifiers_and_unregistered_tactics_are_rejected() -> None:
    record = _session([_group("one", 1, 0, ["discovery"])])
    record["session_id"] = "private-session-id"
    record["observation_groups"][0]["tactics"] = ["secret-shaped-tactic"]

    errors = validate_next_behavior_session(record)

    assert any("pseudonymous session ID" in error for error in errors)
    assert any("unknown tactic" in error for error in errors)


def test_audit_only_labels_are_retained_but_never_become_targets() -> None:
    record = _session(
        [
            _group("one", 1, 0, ["discovery"]),
            _group("two", 2, 1000, ["execution"], command_count="2"),
        ]
    )
    record["observation_groups"][0]["audit_only_labels"] = [
        {
            **_provenance(
                "audit-evidence",
                source="securebert",
                tactic="persistence",
            ),
            "trust_tier": "audit_only_candidate",
            "confidence": 0.2,
            "confidence_bucket": "medium",
            "agreement_status": "model_only",
            "exclusion_reason": "below_trusted_threshold",
        }
    ]

    examples = build_next_behavior_examples(record)

    assert examples[0]["model_input"]["phase_sequence"][0][
        "audit_only_label_count"
    ] == 1
    assert examples[0]["target"]["tactics"] == ["execution"]
    assert "persistence" not in examples[0]["target"]["tactics"]


def test_legacy_source_mapping_is_explicit_and_validator_remains_canonical() -> None:
    assert normalize_label_source("rule") == "reviewed_rule"
    assert normalize_label_source("both") == "rule_model_agreement"
    assert normalize_label_source("model") == "securebert"

    record = _session([_group("one", 1, 0, ["discovery"])])
    record["observation_groups"][0]["label_provenance"][0]["source"] = "rule"
    assert any(
        "not approved" in error for error in validate_next_behavior_session(record)
    )
