"""Opt-in one-request Vertex ADC integration test.

This test is skipped unless explicitly requested.  It creates only owner-only
pytest-temporary alias/receipt files; ADC remains under standard discovery.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from production.ai_advisory.contracts import (
    contract_schema_sha256,
    load_ai_advisory_policy,
    provider_output_json_schema,
    sha256_json,
    validate_provider_output,
)
from production.ai_advisory.google_vertex_provider import (
    ADAPTER_REVISION,
    PROVIDER_ID,
    REVIEWED_API_VERSION,
    REVIEWED_ENDPOINT,
    REVIEWED_LOCATION,
    REVIEWED_MODEL_ID,
)
from production.ai_advisory.provider import build_ai_advisory_provider
from production.ai_advisory.security import endpoint_sha256
from production.utils.config import ProductionConfig


pytestmark = pytest.mark.skipif(
    os.getenv("RUN_VERTEX_AI_INTEGRATION") != "1",
    reason="requires explicit one-request Vertex ADC integration opt-in",
)
RECONCILIATION_CUTOFF = {
    "schema_version": "prediction_evidence_cutoff.v1",
    "received_at": "2026-08-08T00:00:00.000000+00:00",
    "event_id": "event-cutoff",
}


def test_one_vertex_adc_request_returns_visible_structured_content(
    tmp_path: Path,
) -> None:
    project = os.environ["VERTEX_AI_TEST_PROJECT"]
    key = tmp_path / "provider-alias.key"
    key.write_bytes(os.urandom(32))
    key.chmod(0o600)
    checked = datetime.now(timezone.utc) - timedelta(seconds=5)
    receipt = tmp_path / "activation-receipt.json"
    receipt.write_text(
        json.dumps(
            {
                "schema_version": "ai_advisory_activation_receipt.v1",
                "status": "ready",
                "provider_id": PROVIDER_ID,
                "model_id": REVIEWED_MODEL_ID,
                "adapter_revision": ADAPTER_REVISION,
                "endpoint_sha256": endpoint_sha256(REVIEWED_ENDPOINT),
                "provider_adapter_reviewed": True,
                "managed_worker_unit": "honeypot-ai-advisory-worker.service",
                "worker_status": "ready",
                "credentials_status": "ready",
                "reconciliation_mode": "new_sessions_only",
                "reconciliation_cutoff": RECONCILIATION_CUTOFF,
                "health_checked_at": checked.isoformat(),
                "expires_at": (checked + timedelta(minutes=15)).isoformat(),
            }
        ),
        encoding="utf-8",
    )
    receipt.chmod(0o600)
    config = ProductionConfig(
        enable_ai_advisory=True,
        ai_advisory_provider=PROVIDER_ID,
        ai_advisory_model=REVIEWED_MODEL_ID,
        ai_advisory_project=project,
        ai_advisory_location=REVIEWED_LOCATION,
        ai_advisory_endpoint=REVIEWED_ENDPOINT,
        ai_advisory_api_version=REVIEWED_API_VERSION,
        ai_advisory_adapter_revision=ADAPTER_REVISION,
        ai_advisory_allowed_hosts=["aiplatform.googleapis.com"],
        ai_advisory_request_options={
            "max_output_tokens": 2048,
            "temperature": 0.0,
            "thinking_budget": 256,
        },
        ai_advisory_alias_key_file=str(key.resolve()),
        ai_advisory_activation_receipt_path=str(receipt.resolve()),
        ai_advisory_reconciliation_cutoff=RECONCILIATION_CUTOFF,
    )
    provider = build_ai_advisory_provider(config)
    policy, policy_sha256, _policy_path = load_ai_advisory_policy()
    schema = provider_output_json_schema(policy)
    projection = {
        "schema_version": "ai_advisory_projection.v1",
        "assessment_id": "assessment_0123456789abcdef0123456789abcdef",
        "evidence_sha256": "c" * 64,
        "projection_sha256": "d" * 64,
        "provenance": {"ai_policy_sha256": policy_sha256},
        "authority": {
            "ai_canonical_authority": False,
            "ai_finding_authority": False,
            "ai_hypothesis_authority": False,
            "ai_guidance_authority": False,
            "ai_alert_authority": False,
            "ai_automatic_execution": False,
        },
        "evidence_index": [],
        "findings": [],
        "relationships": [],
        "hypotheses": [],
        "guidance": {
            "guidance_id": "guidance_0123456789abcdef0123456789abcdef",
            "status": "unavailable",
            "guidance_state": "no_applicable_grounded_action",
            "actions": [],
        },
        "abstention": {
            "abstained": True,
            "reason_code": "insufficient_allowlisted_context",
        },
        "allowed_output": {
            "template_ids": policy["template_ids"],
            "reason_codes": policy["reason_codes"],
            "limitation_codes": policy["limitation_codes"],
            "candidate_types": policy["candidate_types"],
            "missing_evidence_codes": policy["missing_evidence_codes"],
            "falsifier_codes": policy["falsifier_codes"],
        },
    }
    response = provider.generate(
        projection,
        prompt_contract=policy["prompt_contract"],
        response_schema=schema,
        schema_sha256=contract_schema_sha256(policy),
        policy_sha256=policy_sha256,
        timeout_seconds=60.0,
        max_response_bytes=4096,
        idempotency_key="b" * 64,
    )
    assert response.response_sha256 == sha256_json(response.structured_output)
    validated = validate_provider_output(
        response.structured_output,
        projection=projection,
        policy=policy,
        policy_sha256=policy_sha256,
    )
    assert validated["validated_advisory"]["abstained"] is True
    print(
        json.dumps(
            {
                "visible_content": validated["validated_advisory"],
                "model": response.model_id,
                "project": project,
                "usage": response.usage_metadata,
            },
            sort_keys=True,
        )
    )
