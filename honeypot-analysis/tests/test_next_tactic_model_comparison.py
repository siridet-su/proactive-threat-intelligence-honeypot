from __future__ import annotations

import json
from argparse import Namespace
from pathlib import Path

import pytest

from production.prediction.realtime_prediction import build_transition_model
from production.prediction.session_features import build_session_features
from production.tools.evaluate_next_tactic_model_comparison import (
    EvaluationCase,
    Predictor,
    build_result,
    build_cases,
    empirical_bayes_probabilities,
    evaluate_scope,
    filter_local_production_payloads,
    load_session_payloads,
    payload_input_summary,
    split_session_payloads,
    summarize_predictions,
    trusted_tactic_sequence,
)
from production.tools.prepare_next_tactic_external_payload import (
    SCHEMA_VERSION,
    build_safe_payloads,
)
from production.tools.primary_transition_evaluation import chronological_split
from production.tools.evaluate_zenodo_tuned_next_tactic import (
    build_count_model,
    configuration_aware_probabilities,
    configuration_hard_backoff_probabilities,
    hard_backoff_probabilities,
    interpolated_probabilities,
)


def _payload(
    index: int,
    tactics: list[str] | None = None,
) -> dict:
    sequence = tactics or ["discovery", "execution", "persistence"]
    return {
        "session_id": f"comparison-{index:03d}",
        "start_time": f"2026-01-{(index % 28) + 1:02d}T{index % 24:02d}:00:00Z",
        "status": "closed",
        "is_ended": True,
        "classification_events": [
            {
                "command": f"command-{event_index}",
                "tactic": tactic,
                "ttp": f"T{1000 + event_index}",
                "source": "rule",
                "confidence": 1.0,
            }
            for event_index, tactic in enumerate(sequence)
        ],
    }


def _policy() -> dict:
    document = json.loads(Path("configs/prediction_policy.trusted.json").read_text())
    policy = document["policy"]
    policy["min_sessions_for_local"] = 1
    policy["external_min_sessions"] = 1
    policy["min_transition_count"] = 1
    policy["min_prefix_transition_count"] = 1
    policy["min_technique_transition_count"] = 1
    policy["min_tactic_transition_count"] = 1
    policy["external_min_transition_count"] = 1
    return policy


def _case(prefix: list[str], configuration: str = "1") -> EvaluationCase:
    return EvaluationCase(
        "case",
        "execution",
        {
            "tactic_sequence": prefix,
            "last_tactic": prefix[-1],
            "honeypot_configuration": configuration,
        },
    )


def test_tuned_evaluator_uses_longest_supported_context() -> None:
    payloads = [
        _payload(1, ["discovery", "persistence", "execution"]),
        _payload(2, ["discovery", "persistence", "execution"]),
        _payload(3, ["execution", "persistence", "discovery"]),
    ]
    model = build_count_model(payloads, max_order=3)

    probabilities = hard_backoff_probabilities(
        model,
        _case(["discovery", "persistence"]),
        ["discovery", "execution"],
        max_context=3,
        min_support=2,
        alpha=0.0,
    )

    assert probabilities == {"discovery": 0.0, "execution": 1.0}


def test_interpolated_model_shrinks_sparse_context_toward_lower_order() -> None:
    payloads = [
        _payload(1, ["discovery", "execution"]),
        _payload(2, ["discovery", "execution"]),
        _payload(3, ["persistence", "discovery"]),
    ]
    model = build_count_model(payloads, max_order=2)

    probabilities = interpolated_probabilities(
        model,
        _case(["discovery"]),
        ["discovery", "execution"],
        max_context=2,
        min_support=1,
        alpha=0.1,
        kappa=20.0,
    )

    assert 0.0 < probabilities["discovery"] < probabilities["execution"] < 1.0
    assert sum(probabilities.values()) == pytest.approx(1.0)


def test_configuration_aware_model_uses_only_matching_configuration() -> None:
    payloads = [
        {**_payload(1, ["discovery", "execution"]), "honeypot_configuration": "1"},
        {**_payload(2, ["discovery", "execution"]), "honeypot_configuration": "1"},
        {**_payload(3, ["discovery", "persistence"]), "honeypot_configuration": "2"},
        {**_payload(4, ["discovery", "persistence"]), "honeypot_configuration": "2"},
    ]
    model = build_count_model(payloads, max_order=2)
    vocabulary = ["execution", "persistence"]

    config_one = configuration_aware_probabilities(
        model,
        _case(["discovery"], "1"),
        vocabulary,
        max_context=2,
        min_support=1,
        alpha=0.1,
        kappa=1.0,
    )
    config_two = configuration_aware_probabilities(
        model,
        _case(["discovery"], "2"),
        vocabulary,
        max_context=2,
        min_support=1,
        alpha=0.1,
        kappa=1.0,
    )

    assert config_one["execution"] > config_one["persistence"]
    assert config_two["persistence"] > config_two["execution"]


def test_configuration_hard_backoff_uses_global_context_when_config_is_unseen() -> None:
    payloads = [
        {**_payload(1, ["discovery", "execution"]), "honeypot_configuration": "1"},
        {**_payload(2, ["discovery", "execution"]), "honeypot_configuration": "1"},
    ]
    model = build_count_model(payloads, max_order=2)

    probabilities = configuration_hard_backoff_probabilities(
        model,
        _case(["discovery"], "unseen"),
        ["execution", "persistence"],
        max_context=2,
        min_support=1,
        alpha=0.0,
    )

    assert probabilities == {"execution": 1.0, "persistence": 0.0}


def test_trusted_sequence_excludes_audit_only_labels_and_deduplicates() -> None:
    payload = _payload(1, ["discovery"])
    payload["classification_events"] = [
        {"command": "whoami", "tactic": "discovery", "ttp": "T1033", "source": "rule"},
        {
            "command": "opaque",
            "tactic": "defense-evasion",
            "ttp": "T1562",
            "source": "securebert_low_confidence",
            "confidence": 0.40,
            "high_confidence": False,
        },
        {"command": "uname -a", "tactic": "discovery", "ttp": "T1082", "source": "rule"},
        {"command": "noise", "tactic": "execution", "ttp": "T1059", "source": "shell_noise"},
        {
            "command": "cat /etc/passwd",
            "tactic": "credential-access",
            "ttp": "T1003",
            "source": "rule",
        },
    ]

    assert trusted_tactic_sequence(payload) == ["discovery", "credential-access"]


def test_evaluation_case_prefix_uses_the_same_adjacent_deduplication() -> None:
    payload = _payload(4)
    payload["classification_events"].insert(
        1,
        {
            "command": "uname -a",
            "tactic": "discovery",
            "ttp": "T1082",
            "source": "rule",
            "confidence": 1.0,
        },
    )

    cases = build_cases([payload])

    assert [case.actual for case in cases] == ["execution", "persistence"]
    assert cases[0].features["tactic_sequence"] == ["discovery"]
    assert cases[1].features["tactic_sequence"] == ["discovery", "execution"]


def test_chronological_split_keeps_whole_sessions_disjoint() -> None:
    payloads = [_payload(index) for index in range(20)]
    split = chronological_split(payloads)

    assert {key: len(value) for key, value in split.items()} == {
        "train": 14,
        "calibration": 3,
        "test": 3,
    }
    ids = {
        key: {str(payload["session_id"]) for payload in values}
        for key, values in split.items()
    }
    assert ids["train"].isdisjoint(ids["calibration"])
    assert ids["train"].isdisjoint(ids["test"])
    assert ids["calibration"].isdisjoint(ids["test"])


def test_abstention_counts_as_all_case_failure_but_not_selective_failure() -> None:
    cases = [
        EvaluationCase("covered", "execution", {"last_tactic": "discovery"}),
        EvaluationCase("abstained", "persistence", {"last_tactic": "execution"}),
    ]
    predictor = Predictor(
        predict=lambda case: {"execution": 1.0} if case.session_id == "covered" else {},
        metadata={},
    )

    metrics = summarize_predictions(
        cases,
        predictor,
        bootstrap_iterations=0,
        seed=20260714,
        min_per_tactic_support=1,
    )

    assert metrics["coverage"] == 0.5
    assert metrics["abstention_rate"] == 0.5
    assert metrics["top1_accuracy"] == 0.5
    assert metrics["all_case_accuracy"] == 0.5
    assert metrics["selective_top1_accuracy"] == 1.0
    assert metrics["brier_score"] == 0.5
    assert metrics["normalized_multiclass_brier_score"] == 0.25


def test_macro_and_per_tactic_metrics_flag_low_and_zero_support() -> None:
    cases = [
        EvaluationCase("e1", "execution", {"last_tactic": "discovery"}),
        EvaluationCase("e2", "execution", {"last_tactic": "discovery"}),
        EvaluationCase("p1", "persistence", {"last_tactic": "execution"}),
        EvaluationCase(
            "pe1",
            "privilege-escalation",
            {"last_tactic": "execution"},
        ),
    ]
    predictions = {
        "e1": {"execution": 1.0},
        "e2": {"persistence": 1.0},
        "p1": {"persistence": 1.0},
        "pe1": {"execution": 1.0},
    }
    predictor = Predictor(
        predict=lambda case: predictions[case.session_id],
        metadata={},
    )

    metrics = summarize_predictions(
        cases,
        predictor,
        bootstrap_iterations=0,
        seed=20260714,
        min_per_tactic_support=2,
        target_vocabulary=[
            "credential-access",
            "execution",
            "persistence",
            "privilege-escalation",
        ],
    )

    assert metrics["macro_top1_accuracy"] == 0.5
    assert metrics["balanced_accuracy"] == 0.5
    assert metrics["macro_recall"] == 0.5
    assert metrics["macro_top1_accuracy_sufficient_support"] == 0.5
    assert metrics["per_tactic"]["execution"]["top1_accuracy"] == 0.5
    assert metrics["per_tactic"]["execution"]["mean_reciprocal_rank"] == 0.5
    assert metrics["per_tactic"]["persistence"]["top1_accuracy"] is None
    assert metrics["per_tactic"]["persistence"]["descriptive_only"][
        "top1_accuracy"
    ] == 1.0
    assert metrics["per_tactic"]["privilege-escalation"]["support_status"] == (
        "low_support_descriptive_only"
    )
    assert metrics["per_tactic"]["credential-access"]["support_status"] == (
        "no_heldout_support"
    )
    assert metrics["tactic_support_summary"]["low_support_tactics"] == [
        "persistence",
        "privilege-escalation",
    ]
    assert metrics["tactic_support_summary"]["zero_support_tactics"] == [
        "credential-access"
    ]


def test_empirical_bayes_combines_external_prior_and_local_counts() -> None:
    external_model = build_transition_model(
        [_payload(1, ["discovery", "execution"]), _payload(2, ["discovery", "execution"])]
    )
    local_model = build_transition_model(
        [_payload(3, ["discovery", "credential-access"])]
    )
    features = build_session_features(
        {
            "session_id": "active",
            "classification_events": [
                {"tactic": "discovery", "ttp": "T1033", "source": "rule"}
            ],
        }
    )

    probabilities = empirical_bayes_probabilities(
        features,
        external_model,
        local_model,
        ["credential-access", "execution"],
        alpha=0.0,
        kappa=2.0,
        prefix_max_length=3,
        min_support=1,
    )

    assert probabilities["execution"] == pytest.approx(2 / 3)
    assert probabilities["credential-access"] == pytest.approx(1 / 3)


def test_scope_models_share_identical_heldout_cases() -> None:
    payloads = [
        _payload(
            index,
            ["discovery", "execution", "persistence"]
            if index % 2 == 0
            else ["discovery", "credential-access", "command-and-control"],
        )
        for index in range(40)
    ]
    result = evaluate_scope(
        scope="external",
        payloads=payloads,
        policy=_policy(),
        selected_external_model=build_transition_model([]),
        alpha=0.05,
        kappa_grid=[1.0, 10.0],
        min_calibration_cases=2,
        min_evaluation_examples=30,
        min_per_tactic_support=1,
        bootstrap_iterations=20,
        seed=20260714,
    )

    assert result["heldout_cases"] == 12
    evaluated = [row for row in result["rows"] if row["status"] == "evaluated"]
    assert evaluated
    assert {
        int(row["metrics"]["evaluated_examples"])
        for row in evaluated
    } == {result["heldout_cases"]}
    assert len(result["identical_heldout_case_ids"]) == result["heldout_cases"]


def test_missing_payload_scope_reports_insufficient_data_without_metrics() -> None:
    result = evaluate_scope(
        scope="local",
        payloads=[],
        policy=_policy(),
        selected_external_model=build_transition_model([]),
        alpha=0.05,
        kappa_grid=[1.0],
        min_calibration_cases=10,
        min_evaluation_examples=30,
        min_per_tactic_support=5,
        bootstrap_iterations=0,
        seed=20260714,
    )

    assert result["status"] == "not_evaluated"
    assert result["heldout_cases"] == 0
    assert all(row["status"] == "skipped" for row in result["rows"])
    assert all(row["metrics"] is None for row in result["rows"])


def test_local_scope_requires_production_and_external_provenance() -> None:
    accepted = _payload(1)
    accepted["session_source"] = "production_live"
    accepted["is_external_source"] = True
    fixture = _payload(2)
    fixture["session_source"] = "demo_fixture"
    fixture["is_external_source"] = True
    internal = _payload(3)
    internal["session_source"] = "production_live"
    internal["is_external_source"] = False

    payloads, summary = filter_local_production_payloads([accepted, fixture, internal])

    assert [payload["session_id"] for payload in payloads] == [accepted["session_id"]]
    assert summary["accepted_payloads"] == 1
    assert summary["excluded_reasons"] == {
        "is_external_source_not_true": 1,
        "session_source_not_production_live": 1,
    }


def test_jsonl_loader_and_recorded_split_are_whole_session_safe(tmp_path: Path) -> None:
    payloads = [_payload(index) for index in range(6)]
    for index, payload in enumerate(payloads):
        payload["split"] = ("train", "calibration", "test")[index // 2]
    path = tmp_path / "payloads.jsonl"
    path.write_text(
        "".join(json.dumps(payload, sort_keys=True) + "\n" for payload in payloads),
        encoding="utf-8",
    )

    loaded = load_session_payloads(str(path))
    split, method = split_session_payloads(loaded)

    assert method == "preassigned_whole_session_split"
    assert {name: len(items) for name, items in split.items()} == {
        "train": 2,
        "calibration": 2,
        "test": 2,
    }
    assert payload_input_summary(loaded)["transition_cases"] == 12


def test_safe_external_payload_strips_raw_fields_and_hashes_ids() -> None:
    source_payloads = []
    for index in range(20):
        payload = _payload(
            index,
            ["discovery", "execution", "persistence"]
            if index % 2 == 0
            else ["discovery", "credential-access", "command-and-control"],
        )
        payload["session_id"] = f"raw-session-{index}"
        payload["src_ip"] = "198.51.100.25"
        payload["username"] = "private-user"
        payload["commands"] = ["curl https://sensitive.invalid/payload"]
        source_payloads.append(payload)

    safe, summary = build_safe_payloads(source_payloads)

    serialized = "\n".join(json.dumps(payload, sort_keys=True) for payload in safe)
    assert summary["eligible_transition_sessions"] == 20
    assert summary["adjacent_deduplicated_tactic_transitions"] == 40
    assert sum(summary["split_sessions"].values()) == 20
    assert all(payload["schema_version"] == SCHEMA_VERSION for payload in safe)
    assert all(payload["session_id"].startswith("external-") for payload in safe)
    assert all(payload["protocol"] == "ssh_telnet_mixed_or_unknown" for payload in safe)
    assert "raw-session" not in serialized
    assert "198.51.100.25" not in serialized
    assert "private-user" not in serialized
    assert "sensitive.invalid" not in serialized
    assert '"commands"' not in serialized


def test_safe_external_payload_keeps_single_tactic_training_context() -> None:
    transition_session = _payload(1, ["discovery", "execution"])
    single_tactic_session = _payload(2, ["discovery"])

    safe, summary = build_safe_payloads([transition_session, single_tactic_session])

    assert len(safe) == 2
    assert summary["safe_usable_completed_sessions"] == 2
    assert summary["eligible_transition_sessions"] == 1
    assert summary["adjacent_deduplicated_tactic_transitions"] == 1
    single_tactic_safe = next(payload for payload in safe if not payload["transition_examples"])
    assert single_tactic_safe["split"] == "train"


def test_safe_external_payload_preserves_trusted_technique_order() -> None:
    payload = _payload(1, ["discovery"])
    payload["classification_events"] = [
        {"tactic": "discovery", "ttp": "T1033", "source": "rule"},
        {"tactic": "discovery", "ttp": "T1082", "source": "rule"},
        {"tactic": "execution", "ttp": "T1059", "source": "rule"},
    ]

    safe, _summary = build_safe_payloads([payload])
    model = build_transition_model(safe, prefix_max_length=3)

    assert safe[0]["trusted_technique_sequence"] == ["T1033", "T1082", "T1059"]
    assert safe[0]["adjacent_deduplicated_tactic_sequence"] == [
        "discovery",
        "execution",
    ]
    assert model["transition_count"] == 1.0
    assert model["technique_transition_count"] == 2.0


def test_recorded_split_rejects_partially_labeled_payloads() -> None:
    payloads = [_payload(1), _payload(2)]
    payloads[0]["split"] = "train"

    with pytest.raises(ValueError, match="every session"):
        split_session_payloads(payloads)


def test_partial_zenodo_sample_remains_additional_validation(tmp_path: Path) -> None:
    summary_path = tmp_path / "summary.json"
    summary_path.write_text(
        json.dumps(
            {
                "dataset_source": "zenodo:21260400:COW160x4:500mb_sample",
                "sample_scope": "two_time_spread_daily_members_approximately_500mb",
                "selected_members": [
                    {"member": "day-a.json.gz"},
                    {"member": "day-b.json.gz"},
                ],
            }
        ),
        encoding="utf-8",
    )
    args = Namespace(
        policy="configs/prediction_policy.trusted.json",
        external_payload_json=None,
        local_payload_json=None,
        external_model="not-used.json",
        dataset_summary_json=str(summary_path),
        historical_evidence=str(tmp_path / "not-supplied.json"),
        alpha=0.05,
        kappa_grid=[1.0],
        min_calibration_cases=10,
        min_evaluation_examples=30,
        min_per_tactic_support=5,
        bootstrap_iterations=0,
        seed=20260714,
    )

    result = build_result(args)
    interpretation = result["reporting_interpretation"]

    assert interpretation["replacement_decision"] == (
        "additional_external_validation_not_replacement"
    )
    assert interpretation["replacement_reason"].startswith(
        "Only 2 of 52 daily members"
    )
    assert interpretation["full_52_member_processing_plan"]
