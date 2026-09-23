import importlib.util
from pathlib import Path

import pytest

from production.ensemble.session_ttp_advisory import summarize_session_model1_ttp
from production.reporting.artifacts import _safe_artifact_mapping, write_pdf_report


def row(index, technique, *, session="session-a", status="loaded", evidence="class-a"):
    return {
        "session_id": session,
        "compound_command_index": index,
        "evidence_id": evidence,
        "event_timestamp": "2026-09-23T00:00:00Z",
        "s1_advisory": {
            "status": status,
            "predicted_technique": technique,
            "score_type": "linear_svc_decision_margin",
            "topk": [{"technique_id": "T1110"}],
        },
    }


def test_distinct_commands_not_classification_rows_or_topk():
    value = summarize_session_model1_ttp([
        row(0, "T1105", evidence="class-1"),
        row(0, "T1105", evidence="class-2"),
        row(1, "T1033", evidence="class-3"),
        row(2, "T1105", evidence="class-4"),
    ], session_id="session-a")
    assert value["assessed_command_events"] == 3
    assert [(item["technique_id"], item["supporting_command_events"]) for item in value["techniques"]] == [
        ("T1105", 2), ("T1033", 1)
    ]
    assert value["techniques"][0]["evidence_refs"][0]["command_ref"] == "index:0"
    assert value["is_confidence"] is False


def test_cross_session_failed_and_unidentified_rows_are_excluded():
    unidentified = row(3, "T1105")
    unidentified.pop("compound_command_index")
    value = summarize_session_model1_ttp([
        row(0, "T1105", session="other"),
        row(1, "T1105", status="inference_error"),
        unidentified,
        row(2, "T1046"),
    ], session_id="session-a")
    assert value["excluded_classification_rows"] == 3
    assert value["assessed_command_events"] == 1
    assert [item["technique_id"] for item in value["techniques"]] == ["T1046"]


def test_event_identity_fallback_is_deduplicated():
    first = row(0, "T1110")
    first.pop("compound_command_index")
    first["source_event_id"] = "evt-1"
    second = dict(first, evidence_id="class-2")
    value = summarize_session_model1_ttp([first, second], session_id="session-a")
    assert value["assessed_command_events"] == 1
    assert value["techniques"][0]["supporting_command_events"] == 1


def test_pdf_artifact_privacy_projection_preserves_same_counts_without_command_text():
    source = {
        "session_id": "session-a",
        "classification_events": [dict(row(0, "T1105"), command="sensitive input")],
    }
    projected = _safe_artifact_mapping(source, "session")
    assert summarize_session_model1_ttp(source["classification_events"], session_id="session-a") == summarize_session_model1_ttp(
        projected["classification_events"], session_id="session-a"
    )
    assert "sensitive input" not in str(projected)


@pytest.mark.skipif(
    importlib.util.find_spec("reportlab") is None or importlib.util.find_spec("pypdf") is None,
    reason="optional PDF renderer/parser unavailable",
)
def test_rendered_pdf_agrees_with_session_advisory(tmp_path: Path):
    from pypdf import PdfReader

    report = {
        "schema_version": "phase2.artifact.fixture", "session_id": "session-a",
        "generated_at": "2026-09-23T00:00:03Z", "summary": "Test report",
    }
    session = {
        "session_id": "session-a", "src_ip": "192.0.2.8",
        "start_time": "2026-09-23T00:00:00Z", "end_time": "2026-09-23T00:00:03Z",
        "commands": ["private command text"], "raw_events": [],
        "classification_events": [row(0, "T1105")],
    }
    output = tmp_path / "reports"
    output.mkdir(mode=0o700)
    path = write_pdf_report(report, session, output)
    extracted = "\n".join(page.extract_text() for page in PdfReader(path).pages)
    assert "Model1 command-level advisory" in extracted
    assert "T1105" in extracted
    assert "1 distinct command event" in extracted
    assert "index:0" in extracted
    assert "private command text" not in extracted
