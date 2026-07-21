from __future__ import annotations

import json
from pathlib import Path

from production.prediction.realtime_prediction import build_transition_model
from production.prediction.external_vomm_artifact import (
    build_external_vomm_artifact,
    sha256_file,
)
from production.tools.evaluate_authoritative_external_vomm import (
    evaluate_authoritative_external_vomm,
    file_sha256,
    load_exact_external_artifact,
    validate_external_transition_artifact,
    write_evaluation_outputs,
)


def _payload(index: int, split: str, tactics: list[str]) -> dict:
    technique_by_tactic = {
        "discovery": "T1082",
        "execution": "T1059",
        "impact": "T1486",
        "persistence": "T1547",
    }
    return {
        "schema_version": "next_tactic_test.v1",
        "session_id": f"session-{index:03d}",
        "split": split,
        "start_time": f"2026-01-{index + 1:02d}T00:00:00Z",
        "is_ended": True,
        "status": "closed",
        "protocol": "ssh",
        "classification_events": [
            {
                "tactic": tactic,
                "ttp": technique_by_tactic[tactic],
                "source": "rule",
                "confidence": 1.0,
            }
            for position, tactic in enumerate(tactics)
        ],
    }


def _policy() -> dict:
    policy = json.loads(Path("configs/prediction_policy.trusted.json").read_text(encoding="utf-8"))["policy"]
    policy.update({
        "min_sessions_for_local": 1,
        "external_min_sessions": 1,
        "min_transition_count": 1,
        "min_prefix_transition_count": 1,
        "min_technique_transition_count": 1,
        "min_tactic_transition_count": 1,
        "external_min_transition_count": 1,
        "external_min_prefix_transition_count": 1,
        "external_min_technique_transition_count": 1,
        "external_min_tactic_transition_count": 1,
        "transition_history_limit": 100,
        "recency_decay_half_life_sessions": 0,
    })
    return {"schema_version": "prediction_policy.v1", "policy": policy}


def _artifact() -> dict:
    model = build_transition_model(
        [_payload(100, "train", ["discovery", "execution"])],
        source_name="external_seed_transition",
    )
    model.update({
        "schema_version": "external_transition_model.v1",
        "model_id": "external-test-model",
        "built_at": "2026-01-01T00:00:00Z",
        "provenance": {
            "dataset_handle": "unit-test/external",
            "classifier": "deterministic fixture",
            "classification_rule_policy_sha256": "rule-fixture",
            "securebert_checkpoint_sha256": "checkpoint-fixture",
        },
    })
    return model


def _write_fixture_inputs(tmp_path: Path) -> tuple[Path, Path, Path]:
    policy_path = tmp_path / "policy.json"
    artifact_path = tmp_path / "artifact.json"
    payload_path = tmp_path / "payloads.jsonl"
    policy_path.write_text(json.dumps(_policy(), sort_keys=True), encoding="utf-8")
    artifact_path.write_text(json.dumps(_artifact(), sort_keys=True), encoding="utf-8")
    payloads = [
        _payload(1, "train", ["discovery", "execution"]),
        _payload(2, "train", ["impact", "persistence"]),
        _payload(3, "calibration", ["discovery", "execution"]),
        _payload(4, "calibration", ["impact", "persistence"]),
        _payload(5, "test", ["discovery", "execution"]),
        _payload(6, "test", ["impact", "persistence"]),
        _payload(7, "test", ["discovery", "execution"]),
        _payload(8, "test", ["impact", "persistence"]),
    ]
    payload_path.write_text(
        "".join(json.dumps(payload, sort_keys=True) + "\n" for payload in payloads),
        encoding="utf-8",
    )
    return policy_path, artifact_path, payload_path


def _write_manifest_bound_fixture_inputs(tmp_path: Path) -> tuple[Path, Path, Path, Path, dict]:
    policy_path, _legacy_artifact_path, payload_path = _write_fixture_inputs(tmp_path)
    payloads = [json.loads(line) for line in payload_path.read_text(encoding="utf-8").splitlines()]
    for payload in payloads:
        payload["dataset_source"] = "unit-test:manifest-bound-external-corpus"
    payload_path.write_text(
        "".join(json.dumps(payload, sort_keys=True) + "\n" for payload in payloads),
        encoding="utf-8",
    )
    artifact_path = tmp_path / "external-vomm.json"
    manifest_path = tmp_path / "external-vomm.manifest.json"
    built = build_external_vomm_artifact(
        payload_path=payload_path,
        artifact_path=artifact_path,
        manifest_path=manifest_path,
        artifact_version="unit-test-v1",
        source_start="2026-01-01",
        source_end="2026-01-08",
        preprocessing={"prefix_max_length": 3, "transition_smoothing": 0.0, "min_transition_count": 1},
        classification={
            "sha256": "classification-fixture-sha",
            "classifier": "deterministic fixture",
            "securebert_checkpoint_id": "fixture-checkpoint",
            "securebert_checkpoint_sha256": "checkpoint-fixture-sha",
        },
        trust_policy={"sha256": "trust-policy-fixture-sha"},
        model_builder_commit="unit-test",
    )
    return policy_path, artifact_path, manifest_path, payload_path, built


def test_artifact_validation_is_fail_closed_for_bad_identity_or_malformed_data(tmp_path: Path) -> None:
    artifact = _artifact()
    valid = validate_external_transition_artifact(
        artifact,
        actual_sha256="a" * 64,
        expected_sha256="a" * 64,
        expected_model_id="external-test-model",
    )
    assert valid["valid"] is True

    mismatched = validate_external_transition_artifact(
        artifact,
        actual_sha256="a" * 64,
        expected_sha256="b" * 64,
    )
    assert mismatched["status"] == "unavailable"
    assert "artifact_sha256_mismatch" in mismatched["reasons"]

    malformed = dict(artifact)
    malformed["transitions"] = []
    invalid = validate_external_transition_artifact(malformed)
    assert invalid["valid"] is False
    assert "missing_or_malformed_transitions" in invalid["reasons"]

    missing_model, missing = load_exact_external_artifact(tmp_path / "missing.json")
    assert missing_model == {}
    assert missing["status"] == "unavailable"
    assert "artifact_path_missing" in missing["reasons"]

    malformed_path = tmp_path / "malformed.json"
    malformed_path.write_text("{not valid json", encoding="utf-8")
    malformed_model, malformed_result = load_exact_external_artifact(malformed_path)
    assert malformed_model == {}
    assert malformed_result["status"] == "unavailable"
    assert malformed_result["path"] == str(malformed_path)
    assert malformed_result["artifact_size_bytes"] == malformed_path.stat().st_size
    assert "artifact_json_malformed" in malformed_result["reasons"]


def test_exact_artifact_experiment_uses_identical_cases_and_writes_review_outputs(tmp_path: Path) -> None:
    policy_path, artifact_path, payload_path = _write_fixture_inputs(tmp_path)
    digest = file_sha256(artifact_path)

    result = evaluate_authoritative_external_vomm(
        payload_path=str(payload_path),
        policy_path=str(policy_path),
        artifact_path=str(artifact_path),
        expected_artifact_sha256=digest,
        expected_model_id="external-test-model",
        window_count=2,
        bootstrap_iterations=0,
        min_per_tactic_support=1,
    )

    assert result["status"] == "evaluated_external_proxy_only"
    assert result["artifact"]["actual_sha256"] == digest
    assert result["dataset"]["split_method"] == "preassigned_whole_session_split"
    assert result["experiment_parameters"] == {
        "window_count": 2,
        "bootstrap_iterations": 0,
        "min_per_tactic_support": 1,
        "seed": 20260721,
        "memory_profile_case_limit": 250,
        "external_only_authority": False,
        "min_external_coverage": 0.8,
        "max_all_case_regression": 0.15,
    }
    assert result["promotion_gate"]["status"] == "not_supported_for_production_change"
    assert "no_clean_local_production_chronological_evidence" in result["promotion_gate"]["reasons"]
    assert "external_artifact_training_data_manifest_missing_no_overlap_proof" in result["promotion_gate"]["reasons"]
    assert result["reproducibility"]["external_training_data"]["overlap_proof"] == "not_available"
    assert len(result["windows"]) == 2
    assert result["local_authority"]["local_override_summary"]["override_count"] >= 1
    assert result["abstention_vs_heuristic"]["unsupported_external_context_cases"] >= 1
    assert result["abstention_vs_heuristic"]["guidance_effect"]["expected_actions_created_from_prediction_only"] == 0

    summaries = {item["model_id"]: item for item in result["model_summaries"]}
    assert summaries["external_authoritative_abstain"]["coverage"] < 1.0
    assert summaries["external_then_heuristic"]["coverage"] == 1.0
    assert set(result["models"]) == {
        "current_local_first_cascade",
        "external_authoritative_abstain",
        "external_then_heuristic",
        "heuristic_only",
        "local_shadow_only",
    }

    paths = write_evaluation_outputs(result, tmp_path / "outputs")
    assert Path(paths["json"]).is_file()
    assert Path(paths["csv"]).is_file()
    assert Path(paths["markdown"]).is_file()
    tables = [Path(item) for item in paths["tables"].split(",")]
    assert len(tables) == 4
    assert all(path.is_file() for path in tables)
    figures = [Path(item) for item in paths["figures"].split(",")]
    assert len(figures) == 12
    assert all(path.is_file() and "<svg" in path.read_text(encoding="utf-8") for path in figures)


def test_hash_mismatch_blocks_experiment_without_ranking(tmp_path: Path) -> None:
    policy_path, artifact_path, payload_path = _write_fixture_inputs(tmp_path)

    result = evaluate_authoritative_external_vomm(
        payload_path=str(payload_path),
        policy_path=str(policy_path),
        artifact_path=str(artifact_path),
        expected_artifact_sha256="0" * 64,
        window_count=1,
        bootstrap_iterations=0,
    )

    assert result["status"] == "blocked_invalid_external_artifact"
    assert "models" not in result
    assert "artifact_sha256_mismatch" in result["artifact"]["reasons"]


def test_manifest_bound_external_only_experiment_requires_exact_dataset_membership(tmp_path: Path) -> None:
    policy_path, artifact_path, manifest_path, payload_path, built = _write_manifest_bound_fixture_inputs(tmp_path)

    result = evaluate_authoritative_external_vomm(
        payload_path=str(payload_path),
        policy_path=str(policy_path),
        artifact_path=str(artifact_path),
        manifest_path=str(manifest_path),
        expected_artifact_sha256=sha256_file(artifact_path),
        expected_model_id=built["artifact"]["model_id"],
        expected_manifest_id=built["manifest"]["manifest_id"],
        external_only_authority=True,
        min_external_coverage=0.0,
        max_all_case_regression=1.0,
        window_count=2,
        bootstrap_iterations=0,
        min_per_tactic_support=1,
    )

    assert result["status"] == "evaluated_external_proxy_only"
    assert result["artifact"]["manifest_bound"] is True
    assert result["artifact"]["manifest_sha256"] == sha256_file(manifest_path)
    assert result["exact_split_proof"]["valid"] is True
    assert result["promotion_gate"]["architecture"] == "external_only_authority"
    assert "no_clean_local_production_chronological_evidence" not in result["promotion_gate"]["reasons"]

    changed = [json.loads(line) for line in payload_path.read_text(encoding="utf-8").splitlines()]
    changed[-1]["session_id"] = "different-test-session"
    payload_path.write_text(
        "".join(json.dumps(payload, sort_keys=True) + "\n" for payload in changed),
        encoding="utf-8",
    )
    blocked = evaluate_authoritative_external_vomm(
        payload_path=str(payload_path),
        policy_path=str(policy_path),
        artifact_path=str(artifact_path),
        manifest_path=str(manifest_path),
        expected_artifact_sha256=sha256_file(artifact_path),
        expected_model_id=built["artifact"]["model_id"],
        expected_manifest_id=built["manifest"]["manifest_id"],
        external_only_authority=True,
        window_count=1,
        bootstrap_iterations=0,
    )
    assert blocked["status"] == "blocked_manifest_evaluation_membership_mismatch"
    assert "evaluation_test_membership_mismatch" in blocked["exact_split_proof"]["reasons"]
