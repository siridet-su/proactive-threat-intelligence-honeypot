from __future__ import annotations

import json
from pathlib import Path

import pytest

from production.prediction.external_vomm_artifact import (
    build_external_vomm_artifact,
    load_external_vomm_artifact,
)


def _payload(session_id: str, split: str, tactics: list[str]) -> dict:
    return {
        "schema_version": "next_tactic_fixture.v1",
        "session_id": session_id,
        "split": split,
        "dataset_source": "fixture/external-cowrie",
        "status": "closed",
        "is_ended": True,
        "tactics": tactics,
    }


def _build(tmp_path: Path, name: str = "model") -> dict:
    payload_path = tmp_path / "payloads.jsonl"
    if not payload_path.exists():
        payloads = [
            _payload("train-1", "train", ["discovery", "execution"]),
            _payload("train-2", "train", ["execution", "persistence"]),
            _payload("validation-1", "calibration", ["persistence", "impact"]),
            _payload("test-1", "test", ["impact", "collection"]),
        ]
        payload_path.write_text(
            "".join(json.dumps(item, sort_keys=True) + "\n" for item in payloads),
            encoding="utf-8",
        )
    return build_external_vomm_artifact(
        payload_path=payload_path,
        artifact_path=tmp_path / f"{name}.json",
        manifest_path=tmp_path / f"{name}.manifest.json",
        artifact_version="2026-07-21-fixture-v1",
        source_start="2025-07-03",
        source_end="2025-08-14",
        preprocessing={
            "prefix_max_length": 3,
            "transition_smoothing": 0.05,
            "min_transition_count": 1,
            "adjacent_tactic_deduplication": True,
        },
        classification={
            "sha256": "classification-fixture-sha",
            "securebert_checkpoint_id": "securebert-fixture",
            "securebert_checkpoint_sha256": "checkpoint-fixture-sha",
        },
        trust_policy={"sha256": "trust-fixture-sha"},
        model_builder_commit="fixture-commit",
    )


def test_manifest_bound_artifact_is_deterministic_and_excludes_test_partition(tmp_path: Path) -> None:
    first = _build(tmp_path, "first")
    second = _build(tmp_path, "second")

    assert first["artifact_sha256"] == second["artifact_sha256"]
    assert first["manifest_sha256"] == second["manifest_sha256"]
    assert first["manifest"] == second["manifest"]
    assert first["manifest"]["partition_intersections"] == {
        "all_empty": True,
        "counts": {
            "train_test": 0,
            "train_validation": 0,
            "validation_test": 0,
        },
        "intersection_hashes": {
            "train_test": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "train_validation": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "validation_test": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        },
    }
    assert "impact" in first["artifact"]["transitions"]["persistence"]
    assert "collection" not in first["artifact"]["transitions"]
    assert "test-1" not in (tmp_path / "first.json").read_text(encoding="utf-8")
    assert first["manifest"]["temporal_provenance"]["source_collection"] == {
        "start": "2025-07-03",
        "end": "2025-08-14",
        "precision": "selected-source-member-date-range",
    }


def test_manifest_bound_artifact_loads_only_when_hashes_and_membership_match(tmp_path: Path) -> None:
    result = _build(tmp_path)
    artifact_path = tmp_path / "model.json"
    manifest_path = tmp_path / "model.manifest.json"
    model, validation = load_external_vomm_artifact(
        artifact_path,
        manifest_path,
        expected_artifact_sha256=result["artifact_sha256"],
        expected_model_id=result["artifact"]["model_id"],
        expected_manifest_id=result["manifest"]["manifest_id"],
    )
    assert model["model_id"] == result["artifact"]["model_id"]
    assert validation["valid"] is True

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["artifact"]["sha256"] = "0" * 64
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    blocked_model, blocked = load_external_vomm_artifact(artifact_path, manifest_path)
    assert blocked_model == {}
    assert blocked["status"] == "unavailable"
    assert "manifest_artifact_sha256_mismatch" in blocked["reasons"]


def test_builder_rejects_cross_partition_session_membership(tmp_path: Path) -> None:
    payload_path = tmp_path / "overlap.jsonl"
    payload_path.write_text(
        "\n".join([
            json.dumps(_payload("duplicate", "train", ["discovery", "execution"])),
            json.dumps(_payload("duplicate", "test", ["execution", "impact"])),
            json.dumps(_payload("validation", "validation", ["impact", "collection"])),
        ]) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="intersection"):
        build_external_vomm_artifact(
            payload_path=payload_path,
            artifact_path=tmp_path / "artifact.json",
            manifest_path=tmp_path / "manifest.json",
            artifact_version="fixture",
            source_start="2025-07-03",
            source_end="2025-08-14",
            preprocessing={"min_transition_count": 1},
            classification={
                "sha256": "classification",
                "securebert_checkpoint_id": "checkpoint",
                "securebert_checkpoint_sha256": "checkpoint-sha",
            },
            trust_policy={"sha256": "trust"},
            model_builder_commit="fixture",
        )
