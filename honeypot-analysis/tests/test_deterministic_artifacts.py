from __future__ import annotations

import hashlib
import importlib.util
import json
import re
from pathlib import Path

import pytest

from production.prediction.next_behavior_runtime import (
    FrozenTransformerPocPredictor,
    finalize_prediction_snapshot,
    validate_prediction_snapshot_integrity,
)
from production.reporting.artifacts import (
    _evidence_reference_summary,
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


@pytest.mark.skipif(
    importlib.util.find_spec("reportlab") is None
    or importlib.util.find_spec("pypdf") is None,
    reason="optional PDF renderer/parser unavailable",
)
def test_pdf_shows_only_exact_session_model2_binding(tmp_path: Path) -> None:
    from pypdf import PdfReader

    report, session = _report_and_session()
    model2 = {
        "available": True,
        "availability": "PARTIAL",
        "status": "MODEL2_V5_STYLE_UNIFIED_PRODUCTION_NATIVE_SHADOW",
        "artifact_sha256": "a" * 64,
        "binding": {
            "session_id": session["session_id"],
            "run_id": "run-fixture-1",
            "measurement_id": "measurement-fixture-1",
            "episode_id": "episode-fixture-1",
        },
        "unavailable_heads": {"T1046": "t1046_not_observed"},
    }
    session["ensemble_evidence"] = {
        "session_id": session["session_id"], "model2": model2,
    }
    bound_dir = tmp_path / "bound"
    bound_dir.mkdir(mode=0o700)
    bound_pdf = Path(write_pdf_report(report, session, bound_dir))
    bound_text = "\n".join(page.extract_text() or "" for page in PdfReader(bound_pdf).pages)
    assert "Model2 exact-session shadow evidence" in bound_text
    assert "PARTIAL" in bound_text
    assert "run-fixture-1" in bound_text
    assert "T1046" in bound_text

    model2["binding"]["session_id"] = "another-session"
    unbound_dir = tmp_path / "unbound"
    unbound_dir.mkdir(mode=0o700)
    unbound_pdf = Path(write_pdf_report(report, session, unbound_dir))
    unbound_text = "\n".join(page.extract_text() or "" for page in PdfReader(unbound_pdf).pages)
    assert "No complete exact-session Model2 binding" in unbound_text
    assert "run-fixture-1" not in unbound_text


@pytest.mark.skipif(
    importlib.util.find_spec("reportlab") is None
    or importlib.util.find_spec("pypdf") is None,
    reason="optional PDF renderer/parser unavailable",
)
def test_pdf_keeps_bounded_cwd_and_otx_pulse_context(tmp_path: Path) -> None:
    from pypdf import PdfReader

    report, session = _report_and_session()
    session["raw_events"] = [{
        "eventid": "cowrie.session.cwd",
        "cwd_from_path": "/home/test",
        "cwd_path": "/tmp",
        "timestamp": "2026-07-28T10:10:30Z",
        "input": "MUST_NOT_APPEAR_IN_PDF",
    }]
    external_ti = {
        "ok": True,
        "status": "TI_AVAILABLE",
        "source_ip_cache": [{
            "provider": "otx",
            "lookup_status": "OK",
            "lookup_at": "2026-07-28T10:10:40Z",
            "policy_binding": "CURRENT_POLICY",
            "normalized_context": {"pulses": [{"name": "Example botnet pulse"}]},
        }],
    }
    output_dir = tmp_path / "cwd-otx-pdf"
    output_dir.mkdir(mode=0o700)
    path = Path(write_pdf_report(report, session, output_dir, external_ti_projection=external_ti))
    text = "\n".join(page.extract_text() or "" for page in PdfReader(path).pages)
    assert "Filesystem Activity / Working Directory" in text
    assert "/home/test" in text
    assert "/tmp" in text
    # ReportLab may wrap this table cell between "Example" and "botnet".
    assert "Example botnet pulse" in re.sub(r"\s+", " ", text)
    assert "MUST_NOT_APPEAR_IN_PDF" not in text


@pytest.mark.skipif(
    importlib.util.find_spec("reportlab") is None
    or importlib.util.find_spec("pypdf") is None,
    reason="optional PDF renderer/parser unavailable",
)
def test_pdf_presents_bounded_ti_ai_and_separates_internal_network_context(
    tmp_path: Path,
) -> None:
    from pypdf import PdfReader

    report, session = _report_and_session()
    session.update(
        login_attempts=1,
        login_success=True,
        observed_account_visibility="REDACTED_BEFORE_PERSISTENCE",
    )
    report["ioc_summary"] = {
        "ips": [
            {"type": "ipv4", "value": "8.8.8.8", "confidence": "high"},
            {"type": "ipv4", "value": "10.58.33.42", "confidence": "high"},
        ]
    }
    external_ti = {
        "ok": True,
        "status": "TI_AVAILABLE",
        "external_ti_summary": {
            "status": "TI_AVAILABLE",
            "eligible_observable_count": 1,
            "eligible_observable_types": ["ip"],
            "records_found": 1,
            "evidence_returned": 1,
            "source_ip_cache_records_found": 1,
            "source_ip_cache_latest_lookup_at": "2026-07-28T10:10:30Z",
            "source_ip_cache_freshness": "FRESH",
            "shared_entity_count": 0,
            "authority": "CONTEXT_ONLY",
        },
        "provider_status": {
            "virustotal": {
                "status": "ok",
                "lookup_status": "OK",
                "finding_state": "CONTEXT_PRESENT",
                "record_count": 1,
                "freshness_state": "FRESH",
            },
            "censys": {
                "status": "ok",
                "lookup_status": "OK",
                "finding_state": "CONTEXT_PRESENT",
                "record_count": 1,
                "freshness_state": "FRESH",
            },
        },
        "freshness": {
            "state": "TI_FRESH",
            "latest_retrieved_at": "2026-07-28T10:09:00Z",
        },
        "source_ip_cache": [
            {
                "provider": "abuseipdb",
                "observable_type": "ip",
                "observable_value": "8.8.8.8",
                "lookup_status": "OK",
                "lookup_at": "2026-07-28T10:10:30Z",
                "policy_binding": "source-ip-policy-v2",
                "normalized_context": {
                    "abuse_confidence_score": 0,
                    "total_reports": 0,
                    "finding_state": "NO_REPORTS",
                },
            }
        ],
        "evidence": [
            {
                "provider": "virustotal",
                "observable_type": "ip",
                "observable_value": "8.8.8.8",
                "lookup_status": "OK",
                "finding_state": "CONTEXT_PRESENT",
                "summary": "Stored provider context is available",
                "freshness_state": "FRESH",
            },
            {
                "provider": "censys",
                "observable_type": "ip",
                "observable_value": "8.8.8.8",
                "lookup_status": "OK",
                "finding_state": "CONTEXT_PRESENT",
                "summary": "Must not be rendered",
                "freshness_state": "FRESH",
            },
        ],
    }
    ai_advisory = {
        "ok": True,
        "status": "accepted",
        "advisory_id": "ai_advisory_fixture",
        "report_id": "report_fixture",
        "assessment_id": "assessment_fixture",
        "advisory": {
            "schema_version": "ai_advisory_record.v1",
            "authority": "non_authoritative_advisory_only",
            "validation": {"status": "accepted"},
            "rendered_advisory": {
                "paragraphs": [{"text": "Review the recorded evidence before action."}],
            },
        },
    }
    output_dir = tmp_path / "bounded-context-pdf"
    output_dir.mkdir(mode=0o700)
    path = Path(write_pdf_report(
        report,
        session,
        output_dir,
        external_ti_projection=external_ti,
        ai_advisory_projection=ai_advisory,
    ))
    reader = PdfReader(path)
    text = "\n".join(page.extract_text() or "" for page in reader.pages)
    first_page_text = reader.pages[0].extract_text() or ""

    assert len(reader.pages) <= 5
    assert "Executive Decision Summary" in first_page_text
    assert "Report map" not in first_page_text
    assert "TI_AVAILABLE" in text
    assert "virustotal" in text
    assert "Review the recorded evidence before action." in text
    assert "Latest provider/cache lookup" in text
    assert "28 Jul 2026, 17:10:30 ICT" in text
    assert "Redacted before persistence" in text
    assert "Internal Infrastructure Context" in text
    assert "10.58.33.42" in text
    assert "Private/reserved network context" in text
    assert "8.8.8.8" in text
    assert "censys" not in text.lower()
    assert "Must not be rendered" not in text


@pytest.mark.skipif(
    importlib.util.find_spec("reportlab") is None
    or importlib.util.find_spec("pypdf") is None,
    reason="optional PDF renderer/parser unavailable",
)
def test_pdf_uses_exact_external_ti_api_status_vocabulary(tmp_path: Path) -> None:
    from pypdf import PdfReader

    report, session = _report_and_session()
    external_ti = {
        "ok": True,
        "status": "TI_PENDING",
        "status_reason": "NO_ELIGIBLE_OBSERVABLE",
        "status_reason_text": "No eligible observable was available.",
        "freshness": {"state": "TI_PENDING"},
        "external_ti_summary": {
            "status": "TI_PENDING",
            "status_reason": "NO_ELIGIBLE_OBSERVABLE",
            "eligible_observable_count": 0,
            "records_found": 0,
            "evidence_returned": 0,
        },
    }
    output_dir = tmp_path / "exact-ti-status-pdf"
    output_dir.mkdir(mode=0o700)
    path = Path(
        write_pdf_report(
            report,
            session,
            output_dir,
            external_ti_projection=external_ti,
        )
    )
    text = "\n".join(page.extract_text() or "" for page in PdfReader(path).pages)

    assert "TI_PENDING" in text
    assert "NO_ELIGIBLE_OBSERVABLE" in text
    assert "NO_ELIGIBLE_DATA" not in text
    assert "LOOKUP_PENDING" not in text


def test_evidence_reference_summary_is_bounded_and_content_addressed() -> None:
    references = [f"evidence_ref_{index:04d}" for index in range(50)]
    summary = _evidence_reference_summary(references)

    assert summary.startswith(
        "50 refs; examples: evidence_ref_0000, evidence_ref_0001, evidence_ref_0002; +47 more"
    )
    assert "set SHA-256:" in summary
    assert "evidence_ref_0049" not in summary
    assert summary == _evidence_reference_summary(list(reversed(references)))


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
