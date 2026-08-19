from __future__ import annotations

import asyncio
import sys
import types
from pathlib import Path

from production.api.monitor_web import _render_report_panel, _report_summary
from production.classification.classification_pipeline import NotebookParityClassifier
from production.reporting.artifacts import (
    build_stix_bundle,
    write_markdown_report,
    write_pdf_report,
)
from production.reporting.canonical_pipeline import CanonicalAssessmentCoordinator
from production.reporting.session_assessment_v4 import build_session_assessment_v4
from production.reporting.session_assessment_v5 import (
    build_session_assessment_v5,
    trusted_behavioral_findings_for_presentation,
    validate_session_assessment_v5,
)
from production.utils.serialization import session_to_payload
from production.workers import analysis_worker
from production.workers.analysis_worker import deterministic_baseline_report
from production.workers.session_monitor import SessionMonitor
from tests.test_cross_family_relationship_evaluation import (
    BEHAVIOR_POLICY,
    CLASSIFICATION_POLICY,
    _payload,
)
from tests.test_phase3_session_assessment_v5 import _Mitre


def _historical_audit_only_report() -> tuple[dict, dict, dict]:
    classifier = NotebookParityClassifier(bert_fn=None, mitre_db=_Mitre())
    monitor = SessionMonitor(
        mitre_db=_Mitre(),
        classification_fn=classifier.classify,
        classification_policy={"strategy": "notebook_merge"},
    )
    event = {
        "eventid": "cowrie.command.success",
        "session": "phase1-historical-authority",
        "src_ip": "203.0.113.30",
        "timestamp": "2026-08-19T00:00:00Z",
        "input": "useradd audithelper",
        "success": 1,
    }
    monitor.on_event(event)
    payload = session_to_payload(monitor.get_session(event["session"]))
    report = build_session_assessment_v4(
        [payload],
        raw_events=[event],
        behavior_policy_path=str(BEHAVIOR_POLICY),
        classification_policy_path=str(CLASSIFICATION_POLICY),
    )
    audit = report["behavioral_findings"][0]
    assert next(
        item
        for item in report["canonical_evidence"]["semantic_graph"]["authority_decisions"]
        if item["candidate_id"] == audit["finding_id"]
    )["decision"] == "audit_only"
    return report, payload, audit


def test_current_producers_use_explicit_v5_contract_and_identity() -> None:
    payload = _payload({
        "case_id": "phase1-producer-parity",
        "events": [("whoami", "success")],
    })
    coordinator = CanonicalAssessmentCoordinator(
        behavior_policy_path=str(BEHAVIOR_POLICY),
        classification_rules_path=str(CLASSIFICATION_POLICY),
    )
    coordinated = asyncio.run(coordinator.analyze(
        {}, {}, [payload], [], raw_events=payload["raw_events"]
    ))
    direct = build_session_assessment_v5(
        [payload],
        raw_events=payload["raw_events"],
        behavior_policy_path=str(BEHAVIOR_POLICY),
        classification_policy_path=str(CLASSIFICATION_POLICY),
    )
    fallback = deterministic_baseline_report(payload, "controlled failure")

    assert coordinated["schema_version"] == "session_assessment.v5"
    assert coordinated["assessment_id"] == direct["assessment_id"]
    assert fallback["schema_version"] == "session_assessment.v5"
    assert validate_session_assessment_v5(coordinated) == []
    assert validate_session_assessment_v5(fallback) == []
    assert not hasattr(analysis_worker, "build_session_assessment_v4")
    assert not hasattr(analysis_worker, "validate_session_assessment_v4")


def test_historical_v4_audit_candidate_is_filtered_from_monitor_markdown_and_stix(
    tmp_path: Path,
) -> None:
    report, payload, audit = _historical_audit_only_report()
    statement = audit["statement"]
    finding_id = audit["finding_id"]

    assert trusted_behavioral_findings_for_presentation(report) == []
    summary = _report_summary(report, {})
    assert summary["schema_version"] == "session_assessment.v4"
    assert summary["evidence_strength_reason"].startswith("0 canonical")
    panel = _render_report_panel(
        {"report_row": {"payload": report}, "job": {"status": "completed"}},
        str(tmp_path),
    )
    assert statement not in panel
    assert finding_id not in panel

    markdown = Path(write_markdown_report(report, payload, tmp_path)).read_text(
        encoding="utf-8"
    )
    assert statement not in markdown
    assert finding_id not in markdown
    bundle = build_stix_bundle(report, payload)
    assert not any(
        item.get("type") == "x-honeypot-behavioral-finding"
        for item in bundle["objects"]
    )


def test_pdf_consumer_uses_the_same_authority_safe_finding_view(
    tmp_path: Path,
    monkeypatch,
) -> None:
    report, payload, audit = _historical_audit_only_report()
    rendered: list[str] = []

    class _Flowable:
        def __init__(self, value="", *args, **kwargs):
            del args, kwargs
            self.value = str(value)
            rendered.append(self.value)

        def setStyle(self, value):
            del value

    class _Document:
        def __init__(self, path, *args, **kwargs):
            del args, kwargs
            self.path = path

        def build(self, story):
            Path(self.path).write_text(
                "\n".join(getattr(item, "value", "") for item in story),
                encoding="utf-8",
            )

    modules = {
        "reportlab": types.ModuleType("reportlab"),
        "reportlab.lib": types.ModuleType("reportlab.lib"),
        "reportlab.lib.colors": types.SimpleNamespace(
            HexColor=lambda value: value, white="white", grey="grey"
        ),
        "reportlab.lib.pagesizes": types.SimpleNamespace(A4="A4"),
        "reportlab.lib.styles": types.SimpleNamespace(
            ParagraphStyle=lambda *args, **kwargs: object(),
            getSampleStyleSheet=lambda: {
                "Title": object(), "Heading2": object(), "Normal": object()
            },
        ),
        "reportlab.lib.units": types.SimpleNamespace(cm=1),
        "reportlab.platypus": types.SimpleNamespace(
            HRFlowable=_Flowable,
            Paragraph=_Flowable,
            SimpleDocTemplate=_Document,
            Spacer=_Flowable,
            Table=_Flowable,
            TableStyle=lambda value: value,
        ),
    }
    for name, module in modules.items():
        monkeypatch.setitem(sys.modules, name, module)

    pdf_path = Path(write_pdf_report(report, payload, tmp_path))
    assert pdf_path.exists()
    assert audit["statement"] not in rendered
    assert audit["finding_id"] not in rendered
