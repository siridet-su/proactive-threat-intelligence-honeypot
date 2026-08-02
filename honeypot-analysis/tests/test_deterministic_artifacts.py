from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

from production.prediction.next_behavior_runtime import (
    FrozenTransformerPocPredictor,
    finalize_prediction_snapshot,
    validate_prediction_snapshot_integrity,
)
from production.reporting.artifacts import (
    attach_report_artifacts,
    build_stix_bundle,
    validate_report_artifact_manifest,
    write_markdown_report,
    write_pdf_report,
)
from production.utils.config import ProductionConfig


ROOT = Path(__file__).resolve().parents[1]


def _prediction_policy(tmp_path: Path) -> dict:
    document = json.loads(
        (
            ROOT
            / "configs"
            / "prediction_policy.transformer_poc.trusted.json"
        ).read_text(encoding="utf-8")
    )
    policy = document["policy"]
    missing = tmp_path / "missing-transformer.pt"
    policy["transformer_checkpoint_path"] = str(missing)
    return policy


def _prediction_payload() -> dict:
    return {
        "session_id": "phase2-prediction",
        "is_ended": False,
        "classification_events": [],
        "commands": [],
        "raw_events": [],
    }


def _report_and_session() -> tuple[dict, dict]:
    report = {
        "schema_version": "phase2.artifact.fixture",
        "session_id": "phase2-artifact",
        "generated_at": "2026-07-28T10:11:12.123456+00:00",
        "summary": "Deterministic artifact fixture.",
        "ttps": ["T1033"],
    }
    session = {
        "session_id": "phase2-artifact",
        "src_ip": "192.0.2.80",
        "start_time": "2026-07-28T10:10:00Z",
        "end_time": "2026-07-28T10:11:00Z",
        "commands": ["whoami"],
        "raw_events": [],
    }
    return report, session


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_prediction_id_and_digest_ignore_runtime_clock_and_latency(
    tmp_path: Path,
) -> None:
    predictor = FrozenTransformerPocPredictor(_prediction_policy(tmp_path))

    first = predictor.predict_session(_prediction_payload(), event_id="evt-phase2")
    second = predictor.predict_session(_prediction_payload(), event_id="evt-phase2")

    assert first["generated_at"] != ""
    assert first["snapshot_id"] == second["snapshot_id"]
    assert first["snapshot_sha256"] == second["snapshot_sha256"]
    assert validate_prediction_snapshot_integrity(first) == []
    assert validate_prediction_snapshot_integrity(second) == []


def test_prediction_digest_rejects_canonical_mutation_but_not_runtime_metrics(
    tmp_path: Path,
) -> None:
    predictor = FrozenTransformerPocPredictor(_prediction_policy(tmp_path))
    snapshot = predictor.predict_session(_prediction_payload(), event_id="evt-phase2")

    runtime_only = dict(snapshot)
    runtime_only["runtime"] = dict(snapshot["runtime"])
    runtime_only["runtime"]["model_load_time_ms"] = 999.0
    runtime_only["runtime"]["inference_latency_ms"] = 123.0
    assert finalize_prediction_snapshot(runtime_only)["snapshot_id"] == (
        snapshot["snapshot_id"]
    )

    tampered = dict(snapshot)
    tampered["prediction_status_reason"] = "forged-success"
    assert validate_prediction_snapshot_integrity(tampered) == [
        "snapshot_sha256 mismatch",
        "snapshot_id mismatch",
    ]


def test_stix_and_markdown_are_byte_deterministic(tmp_path: Path) -> None:
    report, session = _report_and_session()

    first_bundle = build_stix_bundle(report, session)
    second_bundle = build_stix_bundle(report, session)
    assert first_bundle == second_bundle
    assert first_bundle["id"].startswith("bundle--")

    first_dir = tmp_path / "first"
    second_dir = tmp_path / "second"
    first_dir.mkdir(mode=0o700)
    second_dir.mkdir(mode=0o700)
    first_markdown = Path(write_markdown_report(report, session, first_dir))
    second_markdown = Path(write_markdown_report(report, session, second_dir))
    assert first_markdown.read_bytes() == second_markdown.read_bytes()
    assert b"2026-07-28T10:11:12Z" in first_markdown.read_bytes()


@pytest.mark.skipif(
    importlib.util.find_spec("reportlab") is None,
    reason="optional ReportLab renderer unavailable",
)
def test_pdf_is_byte_deterministic(tmp_path: Path) -> None:
    report, session = _report_and_session()
    first_dir = tmp_path / "first-pdf"
    second_dir = tmp_path / "second-pdf"
    first_dir.mkdir(mode=0o700)
    second_dir.mkdir(mode=0o700)

    first = Path(write_pdf_report(report, session, first_dir))
    second = Path(write_pdf_report(report, session, second_dir))

    assert first.read_bytes() == second.read_bytes()


def test_integrity_manifest_hash_binds_every_emitted_artifact(
    tmp_path: Path,
) -> None:
    report, session = _report_and_session()
    reports_dir = tmp_path / "reports"
    config = ProductionConfig(
        reports_dir=str(reports_dir),
        enable_artifacts=True,
        enable_stix_export=True,
        enable_pdf_export=True,
    )

    first = attach_report_artifacts(report, session, config)
    first_hashes = {
        kind: _sha256(Path(path))
        for kind, path in first["artifacts"].items()
        if not kind.endswith("_error")
    }
    retry = attach_report_artifacts(report, session, config)
    retry_hashes = {
        kind: _sha256(Path(path))
        for kind, path in retry["artifacts"].items()
        if not kind.endswith("_error")
    }

    assert first["artifacts"] == retry["artifacts"]
    assert first_hashes == retry_hashes
    manifest_path = Path(first["artifacts"]["integrity_manifest"])
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    recorded = {item["kind"]: item for item in manifest["artifacts"]}
    for kind in {"json", "stix", "markdown"}:
        assert recorded[kind]["sha256"] == first_hashes[kind]
        assert recorded[kind]["size_bytes"] == Path(
            first["artifacts"][kind]
        ).stat().st_size
    rendered_digest = _sha256(manifest_path)
    assert manifest_path.stem.endswith(rendered_digest)
    assert validate_report_artifact_manifest(manifest_path) == []

    json_path = Path(first["artifacts"]["json"])
    json_path.write_bytes(json_path.read_bytes() + b"\n")
    assert "artifact SHA-256 mismatch: json" in (
        validate_report_artifact_manifest(manifest_path)
    )
