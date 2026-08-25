from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

from production.policies.validate_stix_bundle import validate_stix_bundle_document
from production.reporting.artifact_privacy import sanitize_artifact_boundary
from production.reporting.artifacts import (
    attach_report_artifacts,
    build_stix_bundle,
    validate_report_artifact_manifest,
)
from production.reporting.session_assessment_v4 import (
    build_session_assessment_v4,
    validate_session_assessment_v4,
)
from production.utils.config import ProductionConfig


MARKER = "UNIQUE_ARTIFACT_RAW_COMMAND_MARKER_20260804"


def _assessment() -> dict:
    event = {
        "session": "artifact-privacy-session",
        "timestamp": "2026-08-04T19:43:22Z",
        "eventid": "cowrie.command.input",
        "input": "printf safe",
    }
    payload = {
        "session_id": "artifact-privacy-session",
        "src_ip": "192.0.2.80",
        "commands": ["printf safe"],
        "classification_events": [],
        "raw_events": [event],
    }
    report = build_session_assessment_v4(
        [payload],
        raw_events=[event],
        behavior_policy_path="configs/threat_hypothesis_behavior.trusted.json",
        classification_policy_path="configs/classification_rules.trusted.json",
    )
    report["non_authoritative_context"]["pipeline_compatibility"] = {
        "data_provenance": {"timestamp": "2026-08-04T19:43:22Z"},
        "bpg_list": [
            {
                "session": "shell (PID 12)",
                "chain": [MARKER],
                "chain_str": MARKER,
                "depth": 1,
                "nested": {"renamed_command_text": MARKER},
            }
        ],
        "metadata": {"tactic": "discovery", "count": 1},
    }
    report["non_authoritative_context"]["threat_evidence_layers"] = {
        "audit_only_classification_candidates": {
            "items": [
                {
                    "evidence_id": "audit-1",
                    "command": MARKER,
                    "candidate_tactic": "discovery",
                    "confidence": 0.1,
                }
            ]
        }
    }
    assert validate_session_assessment_v4(report) == []
    session = {
        "session_id": payload["session_id"],
        "src_ip": payload["src_ip"],
        "commands": [MARKER],
        "raw_events": [{**event, "input": MARKER}],
        "classification_events": [{"command": MARKER, "evidence_id": "audit-1"}],
    }
    return report, session


def _contains(path: Path, needle: str) -> bool:
    return needle.encode("utf-8") in path.read_bytes()


def test_boundary_sanitizer_is_recursive_shape_preserving_and_idempotent() -> None:
    value = {
        "items": [{"evidence_id": "evt-1", "command": MARKER}],
        "pipeline_compatibility": {
            "nested": {"raw_command_text": MARKER},
            "timestamp": "2026-08-04T19:43:22Z",
            "count": 2,
        },
    }
    safe = sanitize_artifact_boundary(value)
    assert value["items"][0]["command"] == MARKER
    assert safe["items"][0] == {"evidence_id": "evt-1", "command": "[REDACTED]"}
    assert safe["pipeline_compatibility"]["nested"]["raw_command_text"] == "[REDACTED]"
    assert safe["pipeline_compatibility"]["timestamp"] == value["pipeline_compatibility"]["timestamp"]
    assert safe["pipeline_compatibility"]["count"] == 2
    assert sanitize_artifact_boundary(safe) == safe


def test_unique_command_marker_is_absent_from_all_generated_artifacts(
    tmp_path: Path,
) -> None:
    report, session = _assessment()
    reports_dir = tmp_path / "reports"
    config = ProductionConfig(
        reports_dir=str(reports_dir),
        enable_artifacts=True,
        enable_stix_export=True,
        enable_pdf_export=True,
    )

    bundle = build_stix_bundle(report, session)
    assert validate_stix_bundle_document(bundle) == []
    assert MARKER not in json.dumps(bundle, sort_keys=True)

    rendered = attach_report_artifacts(report, session, config)
    artifacts = rendered["artifacts"]
    manifest = Path(artifacts["integrity_manifest"])
    assert validate_report_artifact_manifest(manifest) == []
    assert rendered["non_authoritative_context"]["pipeline_compatibility"]["bpg_list"][0]["chain"] == [
        "[REDACTED]"
    ]

    for kind, path_text in artifacts.items():
        if kind.endswith("_error"):
            continue
        path = Path(path_text)
        assert not _contains(path, MARKER), f"raw marker leaked into {kind}"

    if "pdf" in artifacts and importlib.util.find_spec("pypdf") is not None:
        from pypdf import PdfReader

        extracted = "\n".join(
            page.extract_text() or ""
            for page in PdfReader(artifacts["pdf"]).pages
        )
        assert MARKER not in extracted

    # The manifest itself is content-addressed and must also remain free of
    # the marker; its recorded hashes still validate every emitted artifact.
    assert MARKER not in manifest.read_text(encoding="utf-8")
    assert hashlib.sha256(manifest.read_bytes()).hexdigest() == manifest.stem.rsplit("_", 1)[-1]
