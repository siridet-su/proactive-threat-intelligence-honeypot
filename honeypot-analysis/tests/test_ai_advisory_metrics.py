from production.tools.ai_advisory_metrics import summarize_ai_advisory_metrics


def test_metrics_are_aggregate_and_do_not_export_sensitive_rows() -> None:
    result = summarize_ai_advisory_metrics(
        [
            {
                "session_id": "must-not-export",
                "provider_id": "fixture",
                "model_id": "fixture-model",
                "status": "accepted",
                "metrics": {
                    "schema_valid": True,
                    "validator_accepted": True,
                    "abstained": False,
                    "cache_hit": False,
                    "selected_finding_count": 2,
                    "selected_relationship_count": 1,
                    "selected_action_count": 1,
                    "shadow_candidate_count": 1,
                    "shadow_evidence_reference_count": 2,
                },
            },
            {
                "session_id": "also-must-not-export",
                "provider_id": "fixture",
                "model_id": "fixture-model",
                "status": "rejected",
                "metrics": {
                    "schema_valid": False,
                    "validator_accepted": False,
                    "validator_reason_code": "invented_reference",
                },
            },
        ],
        [
            {"status": "succeeded", "completion_code": "accepted"},
            {"status": "succeeded", "completion_code": "cache_replayed"},
            {"status": "failed", "last_error_code": "ai_provider_unavailable"},
        ],
    )

    assert result["record_count"] == 2
    assert result["rates"]["validator_accept_rate"] == 0.5
    assert result["rates"]["invented_reference_rate"] == 0.5
    assert result["rates"]["cache_hit_rate"] == 0.5
    assert result["outbox_failure_code_counts"] == {"ai_provider_unavailable": 1}
    assert result["selection_totals"]["findings"] == 2
    assert "must-not-export" not in str(result)
