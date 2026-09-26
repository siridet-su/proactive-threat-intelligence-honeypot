import importlib.util
import shutil
import subprocess
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


def test_cowrie_outcome_event_does_not_cast_second_model1_vote():
    entered = dict(row(0, "T1059"), cowrie_eventid="cowrie.command.input")
    failed = dict(row(1, "T1059"), cowrie_eventid="cowrie.command.failed")
    value = summarize_session_model1_ttp([entered, failed], session_id="session-a")
    assert value["assessed_command_events"] == 1
    assert value["excluded_classification_rows"] == 1
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


@pytest.mark.skipif(
    importlib.util.find_spec("reportlab") is None or importlib.util.find_spec("pypdf") is None,
    reason="optional PDF renderer/parser unavailable",
)
def test_pdf_distinguishes_model2_inference_from_downstream_rrf(tmp_path: Path):
    from pypdf import PdfReader

    report = {
        "schema_version": "phase2.artifact.fixture", "session_id": "session-a",
        "generated_at": "2026-09-23T00:00:03Z", "summary": "Test report",
    }
    session = {
        "session_id": "session-a", "src_ip": "192.0.2.8", "is_ended": True,
        "start_time": "2026-09-23T00:00:00Z", "end_time": "2026-09-23T00:00:03Z",
        "commands": [], "raw_events": [], "classification_events": [row(0, "T1105")],
    }
    ensemble = {
        "session_id": "session-a",
        "model2": {
            "available": True,
            "availability": "DATA",
            "status": "EXPERIMENTAL_SHADOW",
            "binding": {
                "session_id": "session-a", "run_id": "run-a",
                "measurement_id": "measurement-a", "episode_id": "episode-a",
            },
        },
        "results": [{
            "technique_id": "T1105", "model1_result": "PRESENT",
            "model2_result": "PRESENT", "model2_relation": "CORROBORATES",
        }],
    }
    model1 = summarize_session_model1_ttp(session["classification_events"], session_id="session-a")
    model1["rrf_recommendation"] = {
        "schema_version": "session_ttp_rrf_advisory.v1",
        "session_id": "session-a",
        "formula": "1.0*(1/N)*sum_c I(t in Lc)/(60+r_c(t)) + 0.25*G2(t)/(60+1)",
        "rows": [{
            "technique_id": "T1105", "baseline_rank": 1,
            "recommendation_rank": 1, "model2_support_added": True,
            "rrf_score": 0.020491803,
        }],
    }
    model1["weighted_voting_recommendation"] = {
        "schema_version": "session_ttp_weighted_voting_advisory.v1",
        "session_id": "session-a",
        "formula": "0.5*I(Model1 candidate) + 0.5*I(gated Model2 PRESENT)",
        "rows": [],
    }
    output = tmp_path / "reports"
    output.mkdir(mode=0o700)
    path = write_pdf_report(
        report,
        session,
        output,
        ensemble_projection=ensemble,
        session_ttp_advisory_projection=model1,
    )
    extracted = "\n".join(page.extract_text() or "" for page in PdfReader(path).pages)
    compact = " ".join(extracted.split())
    assert "Advisory recommendation ranking (two retained late-fusion candidates)" in compact
    assert "Model2 does not run RRF internally" in compact
    assert "gated weighted voting" in compact
    assert "PRESENT bonus" in compact
    assert "T1105" in compact


@pytest.mark.skipif(
    importlib.util.find_spec("reportlab") is None or shutil.which("pdftotext") is None,
    reason="optional PDF renderer or text extractor unavailable",
)
def test_pdf_shows_validated_ai_selections_without_rendered_paragraphs(tmp_path: Path):
    report = {
        "schema_version": "phase2.artifact.fixture", "session_id": "session-a",
        "generated_at": "2026-09-23T00:00:03Z", "summary": "Test report",
    }
    session = {
        "session_id": "session-a", "src_ip": "192.0.2.8",
        "start_time": "2026-09-23T00:00:00Z", "end_time": "2026-09-23T00:00:03Z",
        "commands": [], "raw_events": [], "classification_events": [],
    }
    ai_projection = {
        "status": "accepted", "advisory_id": "advisory-test",
        "advisory": {
            "validation": {"status": "accepted"},
            "validated_advisory": {
                "selected_finding_ids": ["finding-test-1"],
                "ranked_action_ids": ["action-test-1"],
                "selected_relationship_ids": ["relationship-test-1"],
                "template_selections": [],
            },
            "rendered_advisory": {"status": "rendered", "paragraphs": []},
        },
    }
    output = tmp_path / "reports"
    output.mkdir(mode=0o700)
    path = write_pdf_report(
        report, session, output, ai_advisory_projection=ai_projection,
    )
    extracted = subprocess.check_output(
        ["pdftotext", "-layout", str(path), "-"], text=True,
    )
    assert "finding-test-1" in extracted
    assert "action-test-1" in extracted
    assert "relationship-test-1" in extracted
    assert "may be newer than" in extracted
