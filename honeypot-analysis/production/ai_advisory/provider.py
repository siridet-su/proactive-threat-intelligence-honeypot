"""Provider-neutral interface for constrained structured AI output."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Mapping, Protocol, Sequence

from production.ai_advisory.contracts import AIAdvisoryContractError, sha256_json


class AIProviderUnavailable(RuntimeError):
    """A provider could not return a result and may be retried."""


@dataclass(frozen=True)
class AIProviderResponse:
    provider_id: str
    model_id: str
    structured_output: Dict[str, Any]
    response_sha256: str
    # Optional identity echoes are intentionally provider-neutral.  A future
    # adapter must populate them; the offline fixture uses the configured
    # defaults and never performs network I/O.
    adapter_revision: str = ""
    endpoint_sha256: str = ""
    api_version: str = ""
    request_options_sha256: str = ""


class AIAdvisoryProvider(Protocol):
    provider_id: str
    model_id: str
    adapter_revision: str
    endpoint_sha256: str
    api_version: str
    request_options_sha256: str

    def generate(
        self,
        projection: Mapping[str, Any],
        *,
        prompt_contract: Sequence[str],
        response_schema: Mapping[str, Any],
        schema_sha256: str,
        policy_sha256: str,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> AIProviderResponse: ...


class DisabledAIAdvisoryProvider:
    provider_id = "disabled"
    model_id = ""
    adapter_revision = "provider-neutral.v1"
    endpoint_sha256 = ""
    api_version = ""
    request_options_sha256 = ""

    def generate(
        self,
        projection: Mapping[str, Any],
        *,
        prompt_contract: Sequence[str],
        response_schema: Mapping[str, Any],
        schema_sha256: str,
        policy_sha256: str,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> AIProviderResponse:
        raise AIProviderUnavailable("AI advisory provider is disabled")


class FixtureAIAdvisoryProvider:
    """Offline deterministic adapter for tests and research fixtures only."""

    provider_id = "fixture"
    adapter_revision = "fixture.v1"
    endpoint_sha256 = ""
    api_version = ""
    request_options_sha256 = ""

    def __init__(self, path: str | Path, *, model_id: str = "fixture-model") -> None:
        self.path = Path(path)
        self.model_id = str(model_id or "fixture-model")

    def generate(
        self,
        projection: Mapping[str, Any],
        *,
        prompt_contract: Sequence[str],
        response_schema: Mapping[str, Any],
        schema_sha256: str,
        policy_sha256: str,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> AIProviderResponse:
        del (
            projection,
            prompt_contract,
            response_schema,
            schema_sha256,
            policy_sha256,
            timeout_seconds,
        )
        try:
            raw = self.path.read_bytes()
        except OSError as exc:
            raise AIProviderUnavailable("fixture provider response is unavailable") from exc
        if len(raw) > max_response_bytes:
            raise AIAdvisoryContractError("provider response exceeds the configured limit")
        try:
            loaded = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AIAdvisoryContractError("provider response is not valid JSON") from exc
        if not isinstance(loaded, dict):
            raise AIAdvisoryContractError("provider response must be an object")
        return AIProviderResponse(
            provider_id=self.provider_id,
            model_id=self.model_id,
            structured_output=loaded,
            response_sha256=sha256_json(loaded),
            adapter_revision=self.adapter_revision,
            endpoint_sha256=self.endpoint_sha256,
            api_version=self.api_version,
            request_options_sha256=self.request_options_sha256,
        )


def build_ai_advisory_provider(config: Any) -> AIAdvisoryProvider:
    provider = str(getattr(config, "ai_advisory_provider", "disabled") or "disabled").strip().lower()
    if provider == "disabled":
        return DisabledAIAdvisoryProvider()
    if provider == "fixture":
        path = str(getattr(config, "ai_advisory_fixture_response_path", "") or "")
        if not path:
            raise AIProviderUnavailable("fixture response path is not configured")
        return FixtureAIAdvisoryProvider(
            path,
            model_id=str(getattr(config, "ai_advisory_model", "fixture-model") or "fixture-model"),
        )
    raise AIProviderUnavailable(
        "configured hosted AI provider adapter is not installed"
    )
