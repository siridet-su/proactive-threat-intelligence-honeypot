from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from production.classification.classification_pipeline import (
    NotebookParityClassifier,
)
from production.tools.stabilization_semantic_evaluation import (
    CLASSIFICATION_POLICY,
    EvaluationContractError,
    _case_outputs,
    _git_revision,
    _semantic_projection,
    _set_metric,
    load_frozen_spec,
)


def test_frozen_stabilization_spec_has_exact_recorded_hash() -> None:
    spec, digest = load_frozen_spec()

    assert digest == (
        "5fa0bdb5d6fcebf021a1b122e04f52c873e1f17f494c18d07dc26d9a449f3ac7"
    )
    assert len(spec["cases"]) == 40
    assert len({item["case_id"] for item in spec["cases"]}) == 40
    assert spec["labels_frozen_before_execution"] is True
    assert (
        spec["authoring_record"][
            "final_holdout_may_be_used_for_tuning"
        ]
        is False
    )


def test_frozen_stabilization_spec_rejects_hash_mismatch(
    tmp_path: Path,
) -> None:
    spec_path = tmp_path / "spec.json"
    hash_path = tmp_path / "spec.sha256"
    spec_path.write_text('{"schema_version":"changed"}', encoding="utf-8")
    hash_path.write_text("0" * 64 + "  spec.json\n", encoding="utf-8")

    with pytest.raises(
        EvaluationContractError,
        match="SHA-256 mismatch",
    ):
        load_frozen_spec(spec_path, hash_path)


def test_metric_contract_counts_exact_case_label_decisions() -> None:
    metric = _set_metric(
        {
            "a": {"T1", "T2"},
            "b": set(),
            "c": {"T2"},
        },
        {
            "a": {"T1"},
            "b": {"T3"},
            "c": {"T2"},
        },
    )

    assert metric["micro"] == {
        "tp": 2,
        "fp": 1,
        "fn": 1,
        "precision": 2 / 3,
        "recall": 2 / 3,
        "f1": 2 / 3,
    }
    assert metric["per_label"]["T3"]["fp"] == 1


def test_non_authoritative_context_case_cannot_select_a_family() -> None:
    spec, _digest = load_frozen_spec()
    case = next(
        item for item in spec["cases"] if item["case_id"] == "SE36"
    )
    classifier = NotebookParityClassifier(
        bert_fn=None,
        rule_policy_path=str(CLASSIFICATION_POLICY),
    )

    payload, fact_set, report = _case_outputs(
        case,
        classifier,
        _git_revision(),
    )

    assert hashlib.sha256(
        CLASSIFICATION_POLICY.read_bytes()
    ).hexdigest() == fact_set["provenance"][
        "classification_policy_sha256"
    ]
    assert payload["classification_events"][-1]["source"] == (
        "securebert_unavailable"
    )
    assert report["behavioral_findings"] == []
    assert report["hypothesis_sets"] == []
    assert all(
        not item.get("semantic_family")
        for item in report["response_guidance_v3"]["advisory_actions"]
    )
    assert report["authority"]["predictions_authoritative"] is False
    assert report["authority"]["enrichment_authoritative"] is False
    assert report["authority"]["automatic_alerts_authorized"] is False


def test_repeatability_projection_excludes_only_rendering_time() -> None:
    report = {
        "response_guidance_v3": {
            "generated_at": "first",
            "guidance_id": "guidance-stable",
            "safety": {"automatic_execution": False},
        },
        "assessment_id": "assessment-stable",
        "status": "assessed",
        "canonical_evidence": {},
        "behavioral_findings": [],
        "hypothesis_sets": [],
        "provenance": {},
        "authority": {},
        "non_authoritative_context": {},
    }
    first = _semantic_projection({}, report)
    report["response_guidance_v3"]["generated_at"] = "second"
    second = _semantic_projection({}, report)

    assert first == second
    assert first["response_guidance_v3"]["guidance_id"] == (
        "guidance-stable"
    )
    assert "generated_at" not in first["response_guidance_v3"]
