"""Historical and experimental Model2 spool compatibility checks."""

from __future__ import annotations

from production.ensemble.evidence import (
    MODEL2_BACKEND_POC_ARTIFACT_SHA256, MODEL2_BACKEND_POC_PROJECTION_SHA256,
    MODEL2_BACKEND_POC_VERSION, MODEL2_V5_ARTIFACT_SHA256,
    MODEL2_V5_FEATURE_CONTRACT_SHA256,
)
from production.ensemble.model2_result_bridge import BINDING_SHA256, _valid_result


def _result() -> dict:
    return {
        "schema_version": "model2_v5_style_unified_production_native_shadow_result.v1",
        "status": "VALID_SHADOW", "availability": "AVAILABLE",
        "authority": "NON_AUTHORITATIVE_SHADOW_ONLY",
        "model_version": "MODEL2_V5_STYLE_UNIFIED_PRODUCTION_NATIVE_20260915_32F_V4",
        "model_artifact_sha256": MODEL2_V5_ARTIFACT_SHA256,
        "feature_contract_sha256": MODEL2_V5_FEATURE_CONTRACT_SHA256,
        "output_order": ["T1105", "T1046", "T1110"],
        "one_model": True, "one_inference_call": True,
        "independent_binary_heads": False, "argmax_used": False,
        "canonical_write_authority": False,
        "session_id": "session-a", "run_id": "run-a",
        "measurement_id": "measurement-a", "episode_id": "episode-a",
        "pcap_binding": "PASS", "zeek_binding": "PASS",
        "feature_materialization": "PASS", "source_binding": "PASS",
        "session_binding": "PASS", "run_id_binding": "PASS",
        "feature_count": 32, "source_feature_count": 32,
        "zero_fill": False, "source_ip_only_binding": False,
        "cross_session_contamination": "NO", "binding_contract_sha256": BINDING_SHA256,
        "outputs": {name: {"availability": "AVAILABLE", "decision": "ABSENT", "raw_score": -1.0}
                    for name in ("T1105", "T1046", "T1110")},
    }


def test_old_result_remains_readable() -> None:
    assert _valid_result(_result(), session_id="session-a", run_id="run-a")


def test_poc_result_requires_exact_projection_identity() -> None:
    result = _result()
    result.update({"model_version": MODEL2_BACKEND_POC_VERSION,
                   "model_artifact_sha256": MODEL2_BACKEND_POC_ARTIFACT_SHA256,
                   "quality_status": "EXPERIMENTAL_POC_UNVALIDATED",
                   "input_projection_contract_sha256": MODEL2_BACKEND_POC_PROJECTION_SHA256,
                   "source_feature_contract_sha256": MODEL2_V5_FEATURE_CONTRACT_SHA256})
    assert _valid_result(result, session_id="session-a", run_id="run-a")
    result.pop("input_projection_contract_sha256")
    assert not _valid_result(result, session_id="session-a", run_id="run-a")


def test_poc_result_cannot_claim_an_old_artifact() -> None:
    result = _result()
    result.update({"model_version": MODEL2_BACKEND_POC_VERSION,
                   "quality_status": "EXPERIMENTAL_POC_UNVALIDATED",
                   "input_projection_contract_sha256": MODEL2_BACKEND_POC_PROJECTION_SHA256,
                   "source_feature_contract_sha256": MODEL2_V5_FEATURE_CONTRACT_SHA256})
    assert not _valid_result(result, session_id="session-a", run_id="run-a")
