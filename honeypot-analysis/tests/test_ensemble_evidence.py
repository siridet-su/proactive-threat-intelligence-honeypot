from __future__ import annotations

import pytest

import production.ensemble.evidence as evidence_module
from production.ensemble.evidence import (
    CrossSessionEvidenceError,
    EnsembleContractError,
    MODEL2_SHADOW_STATUS,
    TECHNIQUE_GRANULARITY,
    build_ensemble_from_bound_v5_result,
    build_ensemble_from_session_payload,
    compute_ensemble_evidence,
    normalize_model2_completed_run_evidence,
    normalize_model2_v5_shadow_result,
)
from production.utils.sensor_identity import canonical_session_id


def _model1(
    *,
    session_id: str = "session-a",
    applicable: bool = True,
    present: dict[str, float] | None = None,
    model1_only: list[dict] | None = None,
) -> dict:
    present = present or {}
    shared = {
        label: {
            "technique_id": label,
            "applicable": applicable,
            "result": "PRESENT" if label in present else ("ABSENT" if applicable else None),
            "decision_score": present.get(label),
            "score_type": "linear_svc_decision_margin" if label in present else None,
            "observed_at": "2026-09-09T00:00:01Z",
        }
        for label in ("T1105", "T1046", "T1110")
    }
    return {
        "session_id": session_id,
        "run_id": "run-a",
        "applicable": applicable,
        "observed_at": "2026-09-09T00:00:01Z",
        "shared": shared,
        "model1_only_labels": model1_only or [],
    }


def test_model2_ensemble_is_parent_technique_only() -> None:
    assert TECHNIQUE_GRANULARITY == "PARENT_TECHNIQUE_ONLY"
    assert evidence_module._technique("T1087.001") == "T1087"


def _model2(
    *,
    session_id: str = "session-a",
    outputs: dict[str, dict] | None = None,
    available: bool = True,
    status: str = MODEL2_SHADOW_STATUS,
) -> dict:
    return {
        "session_id": session_id,
        "run_id": "run-a",
        "available": available,
        "status": status,
        "available_at": "2026-09-09T00:00:02Z",
        "outputs": outputs or {},
        "artifact_sha256": "a" * 64,
        "feature_contract_sha256": "b" * 64,
    }


def _result(model1: dict, model2: dict, label: str = "T1105") -> dict:
    value = compute_ensemble_evidence(
        session_id="session-a",
        run_id="run-a",
        model1=model1,
        model2=model2,
        computed_at="2026-09-09T00:00:03Z",
    )
    return next(row for row in value["results"] if row["technique_id"] == label)


def test_a_present_in_both_is_agree() -> None:
    row = _result(
        _model1(present={"T1105": 2.5}),
        _model2(outputs={"T1105": {"result": "PRESENT", "score": 0.9}}),
    )
    assert row["evidence_state"] == "AGREE"
    assert row["primary_source"] == "MODEL1"
    assert row["model2_relation"] == "CORROBORATES"


def test_b_model1_present_model2_absent_is_disagree() -> None:
    row = _result(
        _model1(present={"T1105": 2.5}),
        _model2(outputs={"T1105": {"result": "ABSENT", "score": -0.2}}),
    )
    assert row["evidence_state"] == "DISAGREE"
    assert row["model2_relation"] == "CONTRADICTS"


def test_c_model1_absent_model2_present_is_model2_only() -> None:
    row = _result(
        _model1(),
        _model2(outputs={"T1105": {"result": True, "score": 0.7}}),
    )
    assert row["evidence_state"] == "MODEL2_ONLY"
    assert row["primary_source"] == "MODEL1"


def test_d_model1_not_applicable_retains_model2_context_without_fallback() -> None:
    row = _result(
        _model1(applicable=False),
        _model2(outputs={"T1105": {"result": "PRESENT", "score": 0.7}}),
    )
    assert row["evidence_state"] == "MODEL1_NOT_APPLICABLE"
    assert row["model2_relation"] == "MODEL2_ONLY"
    assert row["primary_source"] == "NONE"


def test_e_model1_only_label_is_preserved_without_model2_vote() -> None:
    model1 = _model1(
        present={"T1105": 2.5},
        model1_only=[
            {
                "technique_id": "T1033",
                "result": "PRESENT",
                "decision_score": 1.8,
                "score_type": "linear_svc_decision_margin",
            }
        ],
    )
    value = compute_ensemble_evidence(
        session_id="session-a",
        run_id="run-a",
        model1=model1,
        model2=_model2(outputs={"T1105": {"result": "PRESENT", "score": 0.7}}),
    )
    assert value["model1_only_labels"][0]["technique_id"] == "T1033"
    assert value["model1_only_labels"][0]["evidence_state"] == "MODEL1_ONLY"
    assert value["model1_only_labels"][0]["model2_supported"] is False
    assert all(row["technique_id"] != "T1033" for row in value["results"])


def test_f_model2_unavailable_keeps_model1_usable() -> None:
    row = _result(
        _model1(present={"T1105": 2.5}),
        _model2(available=False),
    )
    assert row["evidence_state"] == "MODEL2_UNAVAILABLE"
    assert row["model1_result"] == "PRESENT"
    assert row["model2_result"] is None


def test_g_experimental_model2_status_is_retained() -> None:
    value = compute_ensemble_evidence(
        session_id="session-a",
        run_id="run-a",
        model1=_model1(present={"T1105": 2.5}),
        model2=_model2(
            outputs={"T1105": {"result": "PRESENT", "score": 0.7}},
            status=MODEL2_SHADOW_STATUS,
        ),
    )
    assert value["model2"]["status"] == MODEL2_SHADOW_STATUS
    assert value["model2"]["authority"] == "ADVISORY_ONLY"
    assert value["trusted_eligible"] is False


def test_h_exact_session_isolation_is_required() -> None:
    with pytest.raises(CrossSessionEvidenceError):
        normalize_model2_completed_run_evidence(
            _model2(session_id="session-other", outputs={"T1105": {"result": True}}),
            session_id="session-a",
            run_id="run-a",
        )


def test_i_s1_margin_is_never_a_probability() -> None:
    row = _result(
        _model1(present={"T1105": 4.2}),
        _model2(outputs={"T1105": {"result": "PRESENT", "score": 0.8}}),
    )
    assert row["model1_margin"] == 4.2
    assert row["model1_calibrated_probability"] is None
    assert row["model2_calibrated_probability"] is None


def test_j_no_numeric_score_fusion_is_emitted() -> None:
    value = compute_ensemble_evidence(
        session_id="session-a",
        run_id="run-a",
        model1=_model1(present={"T1105": 4.2}),
        model2=_model2(outputs={"T1105": {"result": "PRESENT", "score": 0.8}}),
    )
    assert value["fused_score"] is None
    assert value["no_numeric_score_fusion"] is True
    assert value["results"][0]["fused_score"] is None


def test_session_payload_builder_uses_unavailable_model2_without_cross_session_data() -> None:
    value = build_ensemble_from_session_payload(
        {
            "session_id": "session-a",
            "classification_events": [
                {
                    "session_id": "session-a",
                    "event_timestamp": "2026-09-09T00:00:01Z",
                    "s1_advisory": {
                        "status": "loaded",
                        "predicted_technique": "T1105",
                        "decision_score": 1.2,
                        "score_type": "linear_svc_decision_margin",
                        "topk": [],
                    },
                }
            ],
        },
        computed_at="2026-09-09T00:00:03Z",
    )
    assert value["session_id"] == "session-a"
    assert value["results"][0]["evidence_state"] == "AGREE" or value["results"][0]["evidence_state"] == "MODEL2_UNAVAILABLE"
    assert all(row["evidence_state"] == "MODEL2_UNAVAILABLE" for row in value["results"])


def test_session_payload_builder_rebinds_v5_through_authenticated_sensor_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sensor_id = "sensor-a"
    sensor_session_id = "cowrie-session-a"
    canonical_id = canonical_session_id(sensor_id, sensor_session_id)
    source_result = normalize_model2_v5_shadow_result(
        _v5_result(session_id=sensor_session_id),
        binding={
            "session_id": sensor_session_id,
            "run_id": "run-a",
            "measurement_id": "measurement-a",
            "episode_id": "episode-a",
        },
        expected_model_sha256="c" * 64,
        expected_feature_contract_sha256="d" * 64,
    )
    calls: list[tuple[str, str]] = []

    def _load(*, session_id: str, run_id: str = "", result_root=None):
        del result_root
        calls.append((session_id, run_id))
        return source_result if session_id == sensor_session_id else None

    monkeypatch.setattr(evidence_module, "load_bound_model2_v5_result", _load)
    value = evidence_module.build_ensemble_from_session_payload(
        {
            "session_id": canonical_id,
            "sensor": sensor_id,
            "sensor_session_id": sensor_session_id,
            "classification_events": [],
        },
        computed_at="2026-09-09T00:00:03Z",
    )

    assert calls == [(canonical_id, ""), (sensor_session_id, "")]
    assert value["session_id"] == canonical_id
    assert value["run_id"] == "run-a"
    assert value["model2"]["available"] is True
    assert value["model2"]["source_session_id"] == sensor_session_id
    assert value["model2"]["measurement_id"] == "measurement-a"
    assert value["model2"]["episode_id"] == "episode-a"
    assert value["model2"]["binding"]["session_id"] == canonical_id
    assert value["model2"]["binding"]["source_session_id"] == sensor_session_id


def test_session_payload_builder_does_not_use_source_ip_as_model2_alias(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    def _load(*, session_id: str, run_id: str = "", result_root=None):
        del run_id, result_root
        calls.append(session_id)
        return None

    monkeypatch.setattr(evidence_module, "load_bound_model2_v5_result", _load)
    value = evidence_module.build_ensemble_from_session_payload(
        {
            "session_id": "session-canonical",
            "sensor": "sensor-a",
            "sensor_session_id": "not-the-session-that-hashes-to-canonical",
            "src_ip": "202.28.41.152",
            "classification_events": [],
        }
    )

    assert calls == ["session-canonical"]
    assert all(row["model2_available"] is False for row in value["results"])


def _v5_result(*, session_id: str = "session-a", run_id: str = "run-a") -> dict:
    return {
        "schema_version": "model2_v5_style_unified_production_native_shadow_result.v1",
        "status": "VALID_SHADOW",
        "availability": "AVAILABLE",
        "authority": "NON_AUTHORITATIVE_SHADOW_ONLY",
        "model_version": "MODEL2_V5_STYLE_UNIFIED_PRODUCTION_NATIVE_20260915_32F_V4",
        "model_artifact_sha256": "c" * 64,
        "feature_contract_sha256": "d" * 64,
        "output_order": ["T1105", "T1046", "T1110"],
        "one_model": True,
        "one_inference_call": True,
        "independent_binary_heads": False,
        "argmax_used": False,
        "canonical_write_authority": False,
        "session_id": session_id,
        "run_id": run_id,
        "measurement_id": "measurement-a",
        "episode_id": "episode-a",
        "outputs": {
            "T1105": {"availability": "AVAILABLE", "decision": "PRESENT", "raw_score": 1.0},
            "T1046": {"availability": "AVAILABLE", "decision": "ABSENT", "raw_score": -1.0},
            "T1110": {"availability": "AVAILABLE", "decision": "ABSENT", "raw_score": -2.0},
        },
    }


def test_v5_result_requires_exact_measurement_binding_and_preserves_one_model() -> None:
    normalized = normalize_model2_v5_shadow_result(
        _v5_result(),
        binding={
            "session_id": "session-a",
            "run_id": "run-a",
            "measurement_id": "measurement-a",
            "episode_id": "episode-a",
        },
        expected_model_sha256="c" * 64,
        expected_feature_contract_sha256="d" * 64,
    )
    value = compute_ensemble_evidence(
        session_id="session-a",
        run_id="run-a",
        model1=_model1(present={"T1105": 1.2}),
        model2=normalized,
    )
    assert normalized["measurement_id"] == "measurement-a"
    assert normalized["one_model"] is True
    assert normalized["independent_binary_heads"] is False
    assert normalized["one_model"] is True
    assert normalized["one_inference_call"] is True
    assert normalized["argmax_used"] is False
    assert value["results"][0]["evidence_state"] == "AGREE"
    assert value["fused_score"] is None
    assert value["no_numeric_score_fusion"] is True


def test_v5_result_rejects_cross_session_identity() -> None:
    with pytest.raises(CrossSessionEvidenceError):
        normalize_model2_v5_shadow_result(
            _v5_result(session_id="session-other"),
            binding={
                "session_id": "session-a",
                "run_id": "run-a",
                "measurement_id": "measurement-a",
                "episode_id": "episode-a",
            },
            expected_model_sha256="c" * 64,
            expected_feature_contract_sha256="d" * 64,
        )


def test_v5_result_rejects_partial_outputs() -> None:
    result = _v5_result()
    result["outputs"].pop("T1110")
    with pytest.raises(EnsembleContractError):
        normalize_model2_v5_shadow_result(
            result,
            binding={
                "session_id": "session-a",
                "run_id": "run-a",
                "measurement_id": "measurement-a",
                "episode_id": "episode-a",
            },
            expected_model_sha256="c" * 64,
            expected_feature_contract_sha256="d" * 64,
        )


def test_bound_v5_builder_requires_all_production_identities() -> None:
    value = build_ensemble_from_bound_v5_result(
        {
            "session_id": "session-a",
            "run_id": "run-a",
            "measurement_id": "measurement-a",
            "episode_id": "episode-a",
            "classification_events": [],
        },
        _v5_result(),
        expected_model_sha256="c" * 64,
        expected_feature_contract_sha256="d" * 64,
    )
    assert value["session_id"] == "session-a"
    assert value["run_id"] == "run-a"
    assert value["model2"]["measurement_id"] == "measurement-a"
    assert value["model2"]["episode_id"] == "episode-a"
    assert value["ensemble_authority"] == "ADVISORY_ONLY"
    assert value["fused_score"] is None
