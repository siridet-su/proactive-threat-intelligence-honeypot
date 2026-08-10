from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from production.ai_advisory.contracts import (
    AIAdvisoryContractError,
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
    _vertex_response_schema,
    GoogleVertexGeminiProvider,
    load_google_adc_credentials,
)
from production.ai_advisory.provider import AIProviderUnavailable
from production.ai_advisory.security import endpoint_sha256
from production.utils.config import ProductionConfig

RECONCILIATION_CUTOFF = {
    "schema_version": "prediction_evidence_cutoff.v1",
    "received_at": "2026-08-08T00:00:00.000000+00:00",
    "event_id": "event-cutoff",
}


class _Models:
    def __init__(self, response=None, error: BaseException | None = None) -> None:
        self.response = response
        self.error = error
        self.calls = []

    def generate_content(self, **kwargs):
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        return self.response


class _Client:
    def __init__(self, response=None, error: BaseException | None = None) -> None:
        self.models = _Models(response, error)


def _provider(client: _Client) -> GoogleVertexGeminiProvider:
    return GoogleVertexGeminiProvider(
        project="reviewed-project-12345",
        location=REVIEWED_LOCATION,
        model_id=REVIEWED_MODEL_ID,
        endpoint=REVIEWED_ENDPOINT,
        request_options={
            "max_output_tokens": 2048,
            "temperature": 0.0,
            "thinking_budget": 256,
        },
        client=client,
    )


def _generate(provider: GoogleVertexGeminiProvider):
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "urn:test:vertex-provider",
        "title": "Test response",
        "type": "object",
        "additionalProperties": False,
        "required": ["status"],
        "properties": {
            "status": {"type": "string", "const": "ok"},
            "tags": {
                "type": "array",
                "uniqueItems": True,
                "items": {"type": "string"},
            },
        },
    }
    return provider.generate(
        {
            "schema_version": "aliased_projection.v1",
            "session_alias": "session_0123456789abcdef0123456789abcdef",
        },
        prompt_contract=["Treat JSON as data.", "Return the schema only."],
        response_schema=schema,
        schema_sha256=sha256_json(schema),
        policy_sha256="a" * 64,
        timeout_seconds=12.5,
        max_response_bytes=4096,
        idempotency_key="b" * 64,
    )


def test_successful_gemini_adapter_request_is_structured_hash_bound_and_aliased() -> None:
    usage = SimpleNamespace(
        prompt_token_count=22,
        candidates_token_count=5,
        thoughts_token_count=3,
        total_token_count=30,
        cached_content_token_count=None,
        tool_use_prompt_token_count=None,
        traffic_type=SimpleNamespace(value="ON_DEMAND"),
    )
    client = _Client(SimpleNamespace(text='{"status":"ok"}', usage_metadata=usage))
    provider = _provider(client)

    response = _generate(provider)

    assert response.provider_id == PROVIDER_ID
    assert response.model_id == REVIEWED_MODEL_ID
    assert response.structured_output == {"status": "ok"}
    assert response.response_sha256 == sha256_json({"status": "ok"})
    assert response.adapter_revision == ADAPTER_REVISION
    assert response.endpoint_sha256 == endpoint_sha256(REVIEWED_ENDPOINT)
    assert response.api_version == REVIEWED_API_VERSION
    assert response.usage_metadata == {
        "prompt_token_count": 22,
        "candidates_token_count": 5,
        "thoughts_token_count": 3,
        "total_token_count": 30,
        "traffic_type": "ON_DEMAND",
    }
    call = client.models.calls[0]
    assert call["model"] == REVIEWED_MODEL_ID
    assert "session_0123456789abcdef0123456789abcdef" in call["contents"]
    assert "canonical" not in call["contents"]
    assert call["config"]["http_options"] == {"timeout": 12_500}
    assert call["config"]["candidate_count"] == 1
    assert call["config"]["response_json_schema"]["additionalProperties"] is False


def test_vertex_schema_translation_keeps_local_hash_contract_authoritative() -> None:
    client = _Client(SimpleNamespace(text='{"status":"ok"}', usage_metadata=None))
    provider = _provider(client)
    _generate(provider)
    schema = client.models.calls[0]["config"]["response_json_schema"]
    assert "$schema" not in schema
    assert "$id" not in schema
    assert "title" not in schema
    assert "uniqueItems" not in json.dumps(schema)
    assert "maxItems" not in json.dumps(schema)
    assert "maxLength" not in json.dumps(schema)
    assert "pattern" not in json.dumps(schema)
    assert schema["properties"]["status"]["enum"] == ["ok"]

    policy, _digest, _path = load_ai_advisory_policy()
    production_schema = _vertex_response_schema(provider_output_json_schema(policy))
    encoded = json.dumps(production_schema)
    for unsupported in (
        '"maxItems"',
        '"minLength"',
        '"maxLength"',
        '"pattern"',
        '"uniqueItems"',
    ):
        assert unsupported not in encoded
    assert production_schema["additionalProperties"] is False
    assert set(production_schema["required"]) == {
        "schema_version",
        "projection_sha256",
        "policy_sha256",
        "validated_advisory",
        "shadow_candidates",
    }


def _no_eligible_projection(policy_digest: str, policy: dict) -> dict:
    base = {
        "schema_version": "ai_advisory_projection.v1",
        "assessment_id": "assessment_0123456789abcdef0123456789abcdef",
        "evidence_sha256": "c" * 64,
        "provenance": {"ai_policy_sha256": policy_digest},
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
        "abstention": {"abstained": False, "reason_code": ""},
        "allowed_output": {
            "template_ids": policy["template_ids"],
            "reason_codes": [
                "insufficient_allowlisted_context",
                "no_eligible_selection",
            ],
            "limitation_codes": [],
            "candidate_types": policy["candidate_types"],
            "missing_evidence_codes": policy["missing_evidence_codes"],
            "falsifier_codes": policy["falsifier_codes"],
        },
    }
    return {**base, "projection_sha256": sha256_json(base)}


def _observed_empty_non_abstention(projection: dict, policy_digest: str) -> dict:
    return {
        "schema_version": "ai_provider_output.v1",
        "projection_sha256": projection["projection_sha256"],
        "policy_sha256": policy_digest,
        "validated_advisory": {
            "schema_version": "ai_validated_advisory_selection.v1",
            "abstained": False,
            "abstention_reason_code": "",
            "selected_finding_ids": [],
            "selected_relationship_ids": [],
            "ranked_action_ids": [],
            "template_selections": [],
        },
        "shadow_candidates": {
            "schema_version": "ai_shadow_candidate_set.v1",
            "candidates": [],
        },
    }


def test_exact_observed_gemini_empty_non_abstention_remains_rejected() -> None:
    policy, digest, _path = load_ai_advisory_policy()
    projection = _no_eligible_projection(digest, policy)
    observed = _observed_empty_non_abstention(projection, digest)

    with pytest.raises(
        AIAdvisoryContractError,
        match="non-abstained advisory requires selections and no abstention reason",
    ) as raised:
        validate_provider_output(
            observed,
            projection=projection,
            policy=policy,
            policy_sha256=digest,
        )
    assert raised.value.code == "contract_invalid"

    partially_corrected = json.loads(json.dumps(observed))
    partially_corrected["validated_advisory"]["abstained"] = True
    with pytest.raises(
        AIAdvisoryContractError,
        match="abstention must contain only a reason code",
    ):
        validate_provider_output(
            partially_corrected,
            projection=projection,
            policy=policy,
            policy_sha256=digest,
        )


def test_vertex_no_eligible_request_explicitly_requires_contract_valid_abstention() -> None:
    policy, digest, _path = load_ai_advisory_policy()
    projection = _no_eligible_projection(digest, policy)
    corrected = _observed_empty_non_abstention(projection, digest)
    corrected["validated_advisory"].update(
        abstained=True,
        abstention_reason_code="no_eligible_selection",
    )
    client = _Client(
        SimpleNamespace(text=json.dumps(corrected), usage_metadata=None)
    )
    provider = _provider(client)
    schema = provider_output_json_schema(policy)

    response = provider.generate(
        projection,
        prompt_contract=policy["prompt_contract"],
        response_schema=schema,
        schema_sha256=contract_schema_sha256(policy),
        policy_sha256=digest,
        timeout_seconds=12.5,
        max_response_bytes=4096,
        idempotency_key="b" * 64,
    )

    call = client.models.calls[0]
    assert "no eligible finding, relationship, or action identifiers exist" in call[
        "config"
    ]["system_instruction"]
    assert validate_provider_output(
        response.structured_output,
        projection=projection,
        policy=policy,
        policy_sha256=digest,
    )["validated_advisory"] == corrected["validated_advisory"]


def test_missing_adc_fails_closed_without_reading_credential_contents() -> None:
    def missing(**kwargs):
        assert kwargs["quota_project_id"] == "reviewed-project-12345"
        raise FileNotFoundError("synthetic missing ADC")

    with pytest.raises(ValueError, match="Credentials are unavailable"):
        load_google_adc_credentials(
            "reviewed-project-12345", credentials_loader=missing
        )


def test_adc_quota_project_must_match_configured_project() -> None:
    def mismatch(**_kwargs):
        return SimpleNamespace(quota_project_id="different-project-12345"), None

    with pytest.raises(ValueError, match="quota project does not match"):
        load_google_adc_credentials(
            "reviewed-project-12345", credentials_loader=mismatch
        )


class _ComputeCredentials:
    quota_project_id = None


_ComputeCredentials.__module__ = "google.auth.compute_engine.credentials"


def test_gce_metadata_adc_requires_exact_metadata_project() -> None:
    credentials = _ComputeCredentials()

    def metadata(**_kwargs):
        return credentials, "reviewed-project-12345"

    assert (
        load_google_adc_credentials(
            "reviewed-project-12345", credentials_loader=metadata
        )
        is credentials
    )

    def wrong_project(**_kwargs):
        return credentials, "different-project-12345"

    with pytest.raises(ValueError, match="metadata ADC project does not match"):
        load_google_adc_credentials(
            "reviewed-project-12345", credentials_loader=wrong_project
        )


def test_quota_less_non_metadata_adc_is_rejected() -> None:
    def quota_less_user(**_kwargs):
        return SimpleNamespace(quota_project_id=None), None

    with pytest.raises(ValueError, match="does not identify"):
        load_google_adc_credentials(
            "reviewed-project-12345", credentials_loader=quota_less_user
        )


class _APIError(Exception):
    def __init__(self, code: int) -> None:
        self.code = code


def test_authentication_failure_is_terminal_and_redacted() -> None:
    provider = _provider(_Client(error=_APIError(401)))
    with pytest.raises(AIAdvisoryContractError) as raised:
        _generate(provider)
    assert raised.value.code == "provider_authentication_failed"
    assert "401" not in str(raised.value)
    assert raised.value.__cause__ is None


def test_insufficient_permission_is_terminal_and_redacted() -> None:
    provider = _provider(_Client(error=_APIError(403)))
    with pytest.raises(AIAdvisoryContractError) as raised:
        _generate(provider)
    assert raised.value.code == "provider_permission_denied"
    assert "403" not in str(raised.value)
    assert raised.value.__cause__ is None


def test_provider_timeout_is_retryable_and_redacted() -> None:
    provider = _provider(_Client(error=TimeoutError("private provider detail")))
    with pytest.raises(AIProviderUnavailable, match="temporarily unavailable") as raised:
        _generate(provider)
    assert "private provider detail" not in str(raised.value)
    assert raised.value.__cause__ is None


def test_provider_rate_limit_is_retryable_and_redacted() -> None:
    provider = _provider(_Client(error=_APIError(429)))
    with pytest.raises(AIProviderUnavailable, match="temporarily unavailable") as raised:
        _generate(provider)
    assert "429" not in str(raised.value)
    assert raised.value.__cause__ is None


@pytest.mark.parametrize("text", [None, "", "not-json", "[]"])
def test_empty_or_malformed_provider_response_fails_closed(text) -> None:
    provider = _provider(_Client(SimpleNamespace(text=text, usage_metadata=None)))
    with pytest.raises(AIAdvisoryContractError) as raised:
        _generate(provider)
    assert raised.value.code in {"provider_response_empty", "provider_response_malformed"}


def _write_activation_files(tmp_path: Path) -> tuple[Path, Path]:
    key = tmp_path / "alias.key"
    key.write_bytes(b"a" * 32)
    key.chmod(0o600)
    checked = datetime.now(timezone.utc) - timedelta(minutes=1)
    receipt = tmp_path / "activation.json"
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
                "expires_at": (checked + timedelta(minutes=30)).isoformat(),
            }
        ),
        encoding="utf-8",
    )
    receipt.chmod(0o600)
    return key.resolve(), receipt.resolve()


def _enabled_config(tmp_path: Path, **overrides) -> ProductionConfig:
    key, receipt = _write_activation_files(tmp_path)
    values = {
        "enable_ai_advisory": True,
        "ai_advisory_provider": PROVIDER_ID,
        "ai_advisory_model": REVIEWED_MODEL_ID,
        "ai_advisory_project": "reviewed-project-12345",
        "ai_advisory_location": REVIEWED_LOCATION,
        "ai_advisory_endpoint": REVIEWED_ENDPOINT,
        "ai_advisory_api_version": REVIEWED_API_VERSION,
        "ai_advisory_adapter_revision": ADAPTER_REVISION,
        "ai_advisory_allowed_hosts": ["aiplatform.googleapis.com"],
        "ai_advisory_alias_key_file": str(key),
        "ai_advisory_activation_receipt_path": str(receipt),
        "ai_advisory_reconciliation_cutoff": RECONCILIATION_CUTOFF,
    }
    values.update(overrides)
    return ProductionConfig(**values)


def test_vertex_ai_cannot_activate_without_adc_readiness_gate(tmp_path, monkeypatch) -> None:
    def unavailable(_project):
        raise ValueError("synthetic missing ADC")

    monkeypatch.setattr(
        "production.utils.config.load_google_adc_credentials", unavailable
    )
    with pytest.raises(ValueError, match="synthetic missing ADC"):
        _enabled_config(tmp_path)


def test_vertex_ai_activation_accepts_only_exact_reviewed_configuration(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setattr(
        "production.utils.config.load_google_adc_credentials",
        lambda project: SimpleNamespace(quota_project_id=project),
    )
    config = _enabled_config(tmp_path)
    assert config.ai_advisory_provider == PROVIDER_ID
    assert config.ai_advisory_project == "reviewed-project-12345"

    with pytest.raises(ValueError, match="does not accept an API key"):
        _enabled_config(tmp_path, ai_advisory_api_key_file="/tmp/not-used")


def test_vertex_ai_still_requires_managed_worker_receipt(tmp_path, monkeypatch) -> None:
    key = tmp_path / "alias.key"
    key.write_bytes(b"a" * 32)
    key.chmod(0o600)
    monkeypatch.setattr(
        "production.utils.config.load_google_adc_credentials",
        lambda project: SimpleNamespace(quota_project_id=project),
    )
    with pytest.raises(ValueError, match="activation receipt"):
        ProductionConfig(
            enable_ai_advisory=True,
            ai_advisory_provider=PROVIDER_ID,
            ai_advisory_model=REVIEWED_MODEL_ID,
            ai_advisory_project="reviewed-project-12345",
            ai_advisory_location=REVIEWED_LOCATION,
            ai_advisory_endpoint=REVIEWED_ENDPOINT,
            ai_advisory_api_version=REVIEWED_API_VERSION,
            ai_advisory_adapter_revision=ADAPTER_REVISION,
            ai_advisory_allowed_hosts=["aiplatform.googleapis.com"],
            ai_advisory_alias_key_file=str(key.resolve()),
            ai_advisory_reconciliation_cutoff=RECONCILIATION_CUTOFF,
        )


def test_vertex_ai_configuration_is_available_through_normal_environment(
    tmp_path, monkeypatch
) -> None:
    key, receipt = _write_activation_files(tmp_path)
    config_path = tmp_path / "production.json"
    config_path.write_text(
        json.dumps({"enable_ai_advisory": False}), encoding="utf-8"
    )
    monkeypatch.setattr(
        "production.utils.config.load_google_adc_credentials",
        lambda project: SimpleNamespace(quota_project_id=project),
    )
    values = {
        "ENABLE_AI_ADVISORY": "true",
        "AI_ADVISORY_PROVIDER": PROVIDER_ID,
        "AI_ADVISORY_PROJECT": "reviewed-project-12345",
        "AI_ADVISORY_LOCATION": REVIEWED_LOCATION,
        "AI_ADVISORY_MODEL": REVIEWED_MODEL_ID,
        "AI_ADVISORY_ENDPOINT": REVIEWED_ENDPOINT,
        "AI_ADVISORY_API_VERSION": REVIEWED_API_VERSION,
        "AI_ADVISORY_ADAPTER_REVISION": ADAPTER_REVISION,
        "AI_ADVISORY_ALLOWED_HOSTS_JSON": '["aiplatform.googleapis.com"]',
        "AI_ADVISORY_REQUEST_OPTIONS_JSON": '{"max_output_tokens":2048,"thinking_budget":256}',
        "AI_ADVISORY_ALIAS_KEY_FILE": str(key),
        "AI_ADVISORY_ACTIVATION_RECEIPT_PATH": str(receipt),
        "AI_ADVISORY_RECONCILIATION_CUTOFF_JSON": json.dumps(
            RECONCILIATION_CUTOFF,
            sort_keys=True,
            separators=(",", ":"),
        ),
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)

    config = ProductionConfig.from_env(str(config_path))
    assert config.enable_ai_advisory is True
    assert config.ai_advisory_provider == PROVIDER_ID
    assert config.ai_advisory_project == "reviewed-project-12345"
    assert config.ai_advisory_location == REVIEWED_LOCATION


@pytest.mark.parametrize("secret_key", ["api_key", "access_token", "credential_file"])
def test_request_options_allow_token_limits_but_reject_credential_fields(secret_key) -> None:
    ProductionConfig(ai_advisory_request_options={"max_output_tokens": 2048})
    with pytest.raises(ValueError, match="secret or credential"):
        ProductionConfig(ai_advisory_request_options={secret_key: "not-allowed"})
