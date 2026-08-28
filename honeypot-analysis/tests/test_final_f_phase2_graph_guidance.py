from __future__ import annotations

import copy
import hashlib
import inspect

import pytest

from production.api.dashboard_api import _current_decision_payload
from production.api.monitor_web import _historical_response_guidance_payload
from production.reporting.canonical_graph_queries import (
    CanonicalGraphQueryError,
    canonical_graph_view,
)
from production.reporting.artifacts import build_stix_bundle
from production.reporting.response_guidance_v4 import (
    build_response_guidance_v4_from_paths,
    validate_response_guidance_v4,
)
from production.reporting.session_assessment_v5 import (
    build_session_assessment_v5,
    validate_session_assessment_v5,
)
from production.reporting.session_assessment_v6 import (
    build_session_assessment_v6,
    refresh_session_assessment_v6_identity,
    validate_session_assessment_v6,
)
from production.utils.config import ProductionConfig
from production.utils.serialization import stable_id, stable_json
from production.storage.mongodb_operations import MongoDBRuntimeOperations
from tests.test_cross_family_relationship_evaluation import (
    BEHAVIOR_POLICY,
    CLASSIFICATION_POLICY,
    _payload,
)


def _assessment(command: str = "cat /etc/shadow") -> dict:
    payload = _payload({
        "case_id": "phase2-" + hashlib.sha256(command.encode()).hexdigest()[:8],
        "events": [(command, "success")],
    })
    return build_session_assessment_v6(
        [payload],
        raw_events=payload["raw_events"],
        behavior_policy_path=str(BEHAVIOR_POLICY),
        classification_policy_path=str(CLASSIFICATION_POLICY),
    )


def _restamp_guidance(guidance: dict) -> None:
    basis = {
        key: copy.deepcopy(value)
        for key, value in guidance.items()
        if key not in {"guidance_id", "content_sha256", "generated_at"}
    }
    digest = hashlib.sha256(stable_json(basis).encode()).hexdigest()
    guidance["content_sha256"] = digest
    guidance["guidance_id"] = stable_id("response_guidance_v4", digest)


def test_guidance_v4_accepts_only_the_validated_graph_query_boundary() -> None:
    report = _assessment()
    graph = report["canonical_evidence"]["semantic_graph"]
    guidance = report["response_guidance_v4"]
    assert validate_response_guidance_v4(guidance, parent_graph=graph) == []
    assert "typed_semantic_fact_set" not in inspect.signature(
        build_response_guidance_v4_from_paths
    ).parameters
    assert guidance["graph_binding"]["graph_sha256"] == graph["graph_sha256"]
    assert all(item["fact_refs"] for item in guidance["findings"] if item["semantic_family"])

    different = _assessment("whoami")["canonical_evidence"]["semantic_graph"]
    assert validate_response_guidance_v4(guidance, parent_graph=different)
    with pytest.raises(CanonicalGraphQueryError):
        canonical_graph_view(
            different,
            expected_graph_sha256=graph["graph_sha256"],
        )


@pytest.mark.parametrize("mutation", ["prose", "evidence", "unknown", "policy"])
def test_closed_guidance_rejects_restamped_content_forgery(mutation: str) -> None:
    report = _assessment()
    guidance = copy.deepcopy(report["response_guidance_v4"])
    if mutation == "prose":
        guidance["advisory_actions"][0]["description"] = "Delete production immediately."
    elif mutation == "evidence":
        unrelated = next(iter(guidance["canonical_graph"]["evidence_nodes"]))["evidence_id"]
        guidance["advisory_actions"][0]["evidence_refs"] = [unrelated]
    elif mutation == "unknown":
        guidance["alerts"] = [{"execute": True}]
    else:
        guidance["provenance"]["policy"]["document"]["finding_rules"][0]["statement"] = "Forged"
        guidance["provenance"]["policy"]["document_sha256"] = hashlib.sha256(
            stable_json(guidance["provenance"]["policy"]["document"]).encode()
        ).hexdigest()
    _restamp_guidance(guidance)
    assert validate_response_guidance_v4(
        guidance,
        parent_graph=report["canonical_evidence"]["semantic_graph"],
    )


def test_v6_complete_authoritative_content_is_hash_bound() -> None:
    report = _assessment()
    assert validate_session_assessment_v6(report) == []
    for path in (
        ("behavioral_findings",),
        ("response_guidance_v4", "triage"),
        ("provenance",),
        ("authority",),
    ):
        changed = copy.deepcopy(report)
        target = changed
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = {} if isinstance(target[path[-1]], dict) else []
        refresh_session_assessment_v6_identity(changed)
        assert validate_session_assessment_v6(changed)
    contextual = copy.deepcopy(report)
    contextual["non_authoritative_context"]["prediction"] = {"tactic": "impact"}
    assert contextual["report_content_sha256"] == report["report_content_sha256"]
    assert validate_session_assessment_v6(contextual) == []


class _ReportStorage:
    def __init__(self, report: dict | None, session: dict | None = None) -> None:
        self.report = report
        self.session = session or {
            "payload": {"session_id": "phase2-current", "commands": ["cat /etc/shadow"]}
        }

    def get_current_report_for_session(self, _session_id: str):
        return {"payload": self.report} if self.report else None

    def get_session(self, _session_id: str):
        return self.session


def test_current_reevaluation_requires_validated_current_report_not_session_fields() -> None:
    config = ProductionConfig(enable_response_guidance=True)
    unavailable = _current_decision_payload(
        config, _ReportStorage(None), "phase2-current", {}
    )
    assert unavailable["status"] == "unavailable"
    assert unavailable["advisory_actions"] == []

    report = _assessment("whoami")
    available = _current_decision_payload(
        config,
        _ReportStorage(report),
        report["canonical_evidence"]["session_id"],
        {"payload": {"prediction": ["impact"]}},
    )
    assert available["schema_version"] == "response_guidance.v4"
    assert available["canonical_graph"] == report["canonical_evidence"]["semantic_graph"]
    assert validate_response_guidance_v4(
        available,
        parent_graph=report["canonical_evidence"]["semantic_graph"],
    ) == []

    stale = copy.deepcopy(report)
    stale["canonical_evidence"]["semantic_graph"]["graph_sha256"] = "0" * 64
    rejected = _current_decision_payload(
        config, _ReportStorage(stale), "phase2-current", {}
    )
    assert rejected["status"] == "unavailable"


def test_historical_v3_guidance_and_v5_assessment_remain_readable() -> None:
    payload = _payload({
        "case_id": "phase2-historical-v5",
        "events": [("whoami", "success")],
    })
    historical = build_session_assessment_v5(
        [payload],
        raw_events=payload["raw_events"],
        behavior_policy_path=str(BEHAVIOR_POLICY),
        classification_policy_path=str(CLASSIFICATION_POLICY),
    )
    assert validate_session_assessment_v5(historical) == []
    guidance = _historical_response_guidance_payload(historical)
    assert guidance["schema_version"] == "response_guidance.v3"
    assert guidance["presentation_semantics"]["historical_record"] is True


def test_v6_rejects_missing_graph_and_separate_graph_substitution() -> None:
    report = _assessment()
    missing = copy.deepcopy(report)
    missing["canonical_evidence"]["semantic_graph"] = {}
    refresh_session_assessment_v6_identity(missing)
    assert validate_session_assessment_v6(missing)

    substituted = copy.deepcopy(report)
    substituted["response_guidance_v4"]["canonical_graph"] = _assessment(
        "whoami"
    )["canonical_evidence"]["semantic_graph"]
    _restamp_guidance(substituted["response_guidance_v4"])
    refresh_session_assessment_v6_identity(substituted)
    assert validate_session_assessment_v6(substituted)


def test_v6_guidance_export_and_storage_identity_remain_graph_bound() -> None:
    report = _assessment()
    session_id = report["canonical_evidence"]["session_id"]
    bundle = build_stix_bundle(report, {"session_id": session_id})
    actions = [
        item for item in bundle["objects"]
        if item.get("type") == "course-of-action"
    ]
    assert actions
    assert all(
        item["x_honeypot_authority"]
        == "deterministic_canonical_graph_policy"
        for item in actions
    )

    report_without_convenience_id = copy.deepcopy(report)
    report_without_convenience_id.pop("session_id", None)
    _report_id, stored_session_id, assessment_id = (
        MongoDBRuntimeOperations._report_identity(
            "phase2-job", report_without_convenience_id
        )
    )
    assert stored_session_id == session_id
    assert assessment_id == report["assessment_id"]
