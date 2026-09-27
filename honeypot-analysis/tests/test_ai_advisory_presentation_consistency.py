"""A stored response-guidance selection is not a canonical behavioral finding."""

from __future__ import annotations

import copy
import importlib.util
import shutil
import subprocess
from pathlib import Path

import pytest

from production.ai_advisory.presentation import advisory_presentation
from production.api.monitor_web import MonitorConfig, load_ai_advisory_detail
from production.reporting.artifacts import write_pdf_report


def _case():
    report = {
        "schema_version": "phase2.artifact.fixture",
        "session_id": "presentation-session",
        "generated_at": "2026-09-23T00:00:03Z",
        "behavioral_findings": [],
        "response_guidance_v3": {
            "findings": [{"finding_id": "response_guidance_finding_abc"}],
        },
    }
    selected = {"selected_finding_ids": ["response_guidance_finding_abc"]}
    rendered = {
        "status": "rendered",
        "render_sha256": "a" * 64,
        "paragraphs": [{
            "template_id": "summarize_selected_findings",
            "finding_ids": ["response_guidance_finding_abc"],
            "text": "AI selected 1 existing canonical finding family/families for analyst review: canonical_finding",
        }],
    }
    return report, selected, rendered


def test_presentation_uses_verified_finding_authority_without_mutating_source():
    report, selected, rendered = _case()
    original = copy.deepcopy(rendered)

    presentation = advisory_presentation(rendered, selected, report)

    assert "0 canonical behavioral finding(s)" in presentation["paragraphs"][0]["text"]
    assert "1 response-guidance finding(s)" in presentation["paragraphs"][0]["text"]
    assert "existing canonical finding family" not in presentation["paragraphs"][0]["text"]
    assert rendered == original


def test_presentation_labels_a_verified_canonical_finding_by_authority():
    report, selected, rendered = _case()
    report["behavioral_findings"] = [{"finding_id": "canonical_abc", "status": "supported"}]
    selected["selected_finding_ids"] = ["canonical_abc"]
    rendered["paragraphs"][0]["finding_ids"] = ["canonical_abc"]

    presentation = advisory_presentation(rendered, selected, report)

    assert "1 canonical behavioral finding(s)" in presentation["paragraphs"][0]["text"]
    assert "0 response-guidance finding(s)" in presentation["paragraphs"][0]["text"]
    assert "existing canonical finding family" not in presentation["paragraphs"][0]["text"]


def test_ai_api_exposes_corrected_display_but_preserves_stored_text(monkeypatch):
    report, selected, rendered = _case()
    report["assessment_id"] = "assessment-test"

    class Storage:
        def get_current_report_for_session(self, session_id):
            assert session_id == "presentation-session"
            return {"report_id": "report-test", "payload": report}

        def get_ai_advisory_for_report(self, report_id, assessment_id):
            assert (report_id, assessment_id) == ("report-test", "assessment-test")
            return {"status": "accepted", "payload": {
                "status": "accepted", "validation": {"status": "accepted"},
                "validated_advisory": selected, "rendered_advisory": rendered,
            }}

        def get_ai_advisory_outbox_for_report(self, report_id, assessment_id):
            return None

        def get_ai_advisory_for_session(self, session_id):
            return None

    monkeypatch.setattr(
        "production.api.monitor_web._complete_report_payload",
        lambda payload, reports_dir: payload,
    )
    config = MonitorConfig(db_path=":memory:", reports_dir="reports")
    result = load_ai_advisory_detail(config, "presentation-session", _storage=Storage())

    assert result["status"] == "accepted"
    assert result["advisory"]["presentation"]["paragraphs"] == advisory_presentation(
        rendered, selected, report,
    )["paragraphs"]
    assert result["advisory"]["rendered_advisory"] == rendered


@pytest.mark.skipif(
    importlib.util.find_spec("reportlab") is None or shutil.which("pdftotext") is None,
    reason="optional PDF renderer or text extractor unavailable",
)
def test_pdf_and_api_presentation_agree_on_guidance_finding(tmp_path: Path):
    report, selected, rendered = _case()
    display = advisory_presentation(rendered, selected, report)
    session = {
        "session_id": "presentation-session", "src_ip": "192.0.2.8",
        "start_time": "2026-09-23T00:00:00Z", "end_time": "2026-09-23T00:00:03Z",
        "commands": [], "raw_events": [], "classification_events": [],
    }
    ai_projection = {
        "status": "accepted",
        "advisory": {
            "validation": {"status": "accepted"},
            "validated_advisory": selected,
            "rendered_advisory": rendered,
            "presentation": display,
        },
    }
    output = tmp_path / "reports"
    output.mkdir(mode=0o700)
    path = write_pdf_report(report, session, output, ai_advisory_projection=ai_projection)
    extracted = subprocess.check_output(["pdftotext", "-layout", str(path), "-"], text=True)

    assert display["paragraphs"][0]["text"] in " ".join(extracted.split())
    assert "existing canonical finding family/families" not in extracted
