"""Historical and experimental Model2 spool compatibility checks."""

from __future__ import annotations

import json

from production.ensemble import model2_result_bridge as bridge
from production.ensemble.evidence import (
    MODEL2_BACKEND_POC_ARTIFACT_SHA256, MODEL2_BACKEND_POC_PROJECTION_SHA256,
    MODEL2_BACKEND_POC_VERSION, MODEL2_V5_ARTIFACT_SHA256,
    MODEL2_V5_FEATURE_CONTRACT_SHA256, MODEL2_UNIFIED54_ARTIFACT_SHA256,
    MODEL2_UNIFIED54_FEATURE_CONTRACT_SHA256, MODEL2_UNIFIED54_VERSION,
)
from production.ensemble.model2_result_bridge import (
    BINDING_SHA256, _ResultIndex, _find_result, _valid_result,
)


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


def test_unified54_accepts_exact_supported_capture_contracts_only() -> None:
    result = _result()
    result.update({
        "schema_version": "model2_unified_54f_experimental_shadow_result.v1",
        "model_version": MODEL2_UNIFIED54_VERSION,
        "model_artifact_sha256": MODEL2_UNIFIED54_ARTIFACT_SHA256,
        "feature_contract_sha256": MODEL2_UNIFIED54_FEATURE_CONTRACT_SHA256,
        "source_feature_contract_sha256": MODEL2_UNIFIED54_FEATURE_CONTRACT_SHA256,
        "quality_status": "CONTROLLED_SYNTHETIC_POC_NOT_REAL_WORLD_ACCURACY",
        "independent_binary_heads": True,
        "feature_count": 54,
        "source_feature_count": 54,
    })
    for contract in (
        "OUTCOME_INDEPENDENT_FIXED_SESSION_WINDOW_V1",
        "OUTCOME_INDEPENDENT_SESSION_SOCKET_V2",
    ):
        result["capture_selection"] = contract
        assert _valid_result(result, session_id="session-a", run_id="run-a")
    result["capture_selection"] = "FILE_DOWNLOAD_SELECTED_FLOW"
    assert not _valid_result(result, session_id="session-a", run_id="run-a")


def test_result_index_keeps_exact_session_and_detects_changes(tmp_path) -> None:
    root = tmp_path / "results"
    root.mkdir()
    first = root / "first.json"
    second = root / "second.json"
    first.write_text(json.dumps(_result()), encoding="utf-8")
    other = _result()
    other.update({"session_id": "session-b", "run_id": "run-b"})
    second.write_text(json.dumps(other), encoding="utf-8")
    index = _ResultIndex(root)
    assert _find_result(root, session_id="session-a", run_id="run-a", index=index)[0] == "AVAILABLE"
    assert index.paths_for("session-a") == [first]
    assert index.paths_for("session-b") == [second]
    second.write_text(json.dumps(_result()), encoding="utf-8")
    assert _find_result(root, session_id="session-a", run_id="run-a", index=index)[0] == "UNAVAILABLE"
    second.unlink()
    assert _find_result(root, session_id="session-a", run_id="run-a", index=index)[0] == "AVAILABLE"


def test_result_index_rejects_symlinked_result(tmp_path) -> None:
    root = tmp_path / "results"
    root.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text(json.dumps(_result()), encoding="utf-8")
    (root / "alias.json").symlink_to(outside)
    index = _ResultIndex(root)
    assert _find_result(root, session_id="session-a", run_id="run-a", index=index)[0] == "UNAVAILABLE"


def test_result_index_keeps_a_hard_file_count_bound(tmp_path, monkeypatch) -> None:
    root = tmp_path / "results"
    root.mkdir()
    (root / "first.json").write_text(json.dumps(_result()), encoding="utf-8")
    (root / "second.json").write_text(json.dumps(_result()), encoding="utf-8")
    monkeypatch.setattr(bridge, "MAX_RESULT_FILES", 1)
    assert _find_result(root, session_id="session-a", run_id="run-a")[0] == "UNAVAILABLE"
