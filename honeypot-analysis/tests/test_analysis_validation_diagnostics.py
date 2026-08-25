from __future__ import annotations

import json

import pytest

from production.reporting.session_assessment_v4 import (
    SessionAssessmentV4Error,
    validate_session_assessment_v4,
)
from production.utils.validation_diagnostics import (
    build_validation_diagnostic,
    diagnostic_from_exception,
)


SENTINELS = (
    "synthetic-secret-marker",
    "cat /private/credential",
    "192.0.2.123",
)


def _assert_private_values_absent(value: object) -> None:
    rendered = json.dumps(value, sort_keys=True)
    for sentinel in SENTINELS:
        assert sentinel not in rendered


def test_v4_diagnostic_reports_only_structural_fields() -> None:
    value = {
        "schema_version": "session_assessment.v4",
        "canonical_evidence": {
            "command": SENTINELS[1],
            "source_ip": SENTINELS[2],
            "credential": SENTINELS[0],
            "evidence_sha256": "0" * 64,
        },
        "provenance": {
            "evidence_sha256": "1" * 64,
            "evaluator_git_revision": "a" * 40,
        },
        "response_guidance_v3": [],
    }

    with pytest.raises(SessionAssessmentV4Error) as captured:
        validate_session_assessment_v4(value, raise_on_error=True)

    diagnostic = build_validation_diagnostic(captured.value)

    assert diagnostic is not None
    assert diagnostic["schema_version"] == (
        "analysis_validation_diagnostic.v1"
    )
    assert diagnostic["contract_name"] == "session_assessment.v4"
    paths = {
        item["field_path"] for item in diagnostic["errors"]
    }
    assert "canonical_evidence.evidence_sha256" in paths
    assert "response_guidance_v3" in paths
    _assert_private_values_absent(diagnostic)


def test_arbitrary_exception_text_never_becomes_a_diagnostic() -> None:
    error = ValueError(" ".join(SENTINELS))

    assert build_validation_diagnostic(error) is None
    assert diagnostic_from_exception(
        error,
        job_id="analysis_job_1",
        retry_attempt=1,
    ) is None


def test_unknown_validator_message_is_reduced_to_generic_structure() -> None:
    error = SessionAssessmentV4Error(
        " ".join(SENTINELS),
        validation_errors=[" ".join(SENTINELS)],
        source_revision="b" * 40,
    )

    diagnostic = build_validation_diagnostic(error)

    assert diagnostic is not None
    assert diagnostic["errors"] == [
        {
            "error_category": "malformed",
            "field_path": "canonical_record",
            "constraint": "contract_constraint",
            "received_type": "not_recorded",
            "state": "malformed",
        }
    ]
    _assert_private_values_absent(diagnostic)


def test_propagated_pipeline_diagnostic_gets_bounded_job_context() -> None:
    source = SessionAssessmentV4Error(
        "assessment_id mismatch",
        validation_errors=["assessment_id mismatch"],
        source_revision="c" * 40,
    )
    failure = RuntimeError("operation_failed")
    failure.validation_diagnostic = build_validation_diagnostic(source)

    diagnostic = diagnostic_from_exception(
        failure,
        job_id="analysis_job-safe_123",
        retry_attempt=999,
    )

    assert diagnostic is not None
    assert diagnostic["job_id"] == "analysis_job-safe_123"
    assert diagnostic["retry_attempt"] == 100
    assert diagnostic["errors"][0]["field_path"] == "assessment_id"
    _assert_private_values_absent(diagnostic)
