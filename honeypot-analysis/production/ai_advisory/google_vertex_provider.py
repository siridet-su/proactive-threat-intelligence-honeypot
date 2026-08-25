"""Reviewed Google Gen AI SDK adapter for Vertex AI using ADC.

The adapter is deliberately narrow: it supports one reviewed model, endpoint,
location, API version, and bounded set of generation options.  Authentication
uses ``google.auth.default`` and never accepts an API key or credential value.
"""

from __future__ import annotations

import json
import re
from numbers import Integral, Real
from typing import Any, Callable, Dict, Mapping, Sequence

from production.ai_advisory.contracts import AIAdvisoryContractError, sha256_json
from production.ai_advisory.provider import AIProviderResponse, AIProviderUnavailable
from production.ai_advisory.security import endpoint_sha256
from production.utils.serialization import stable_json


PROVIDER_ID = "google_vertex_gemini"
REVIEWED_MODEL_ID = "gemini-2.5-flash"
REVIEWED_LOCATION = "global"
REVIEWED_ENDPOINT = "https://aiplatform.googleapis.com"
REVIEWED_API_VERSION = "v1"
ADAPTER_REVISION = "google-genai.vertex-adc.v2"
ADC_SCOPE = "https://www.googleapis.com/auth/cloud-platform"

_PROJECT_RE = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")
_OPTION_KEYS = frozenset(
    {"max_output_tokens", "temperature", "thinking_budget", "seed"}
)
_USAGE_INTEGER_FIELDS = (
    "prompt_token_count",
    "candidates_token_count",
    "thoughts_token_count",
    "total_token_count",
    "cached_content_token_count",
    "tool_use_prompt_token_count",
)


def validate_vertex_project(project: Any) -> str:
    value = str(project or "").strip()
    if not _PROJECT_RE.fullmatch(value) or "--" in value:
        raise ValueError("AI advisory Vertex project ID is invalid")
    return value


def normalize_vertex_request_options(value: Any) -> Dict[str, Any]:
    """Return the complete, bounded option set bound into request identity."""

    if not isinstance(value, Mapping):
        raise ValueError("Vertex AI advisory request options must be an object")
    unknown = set(value) - _OPTION_KEYS
    if unknown:
        raise ValueError("Vertex AI advisory request options contain unsupported keys")

    result: Dict[str, Any] = {
        "max_output_tokens": 4096,
        "temperature": 0.0,
        "thinking_budget": 512,
    }
    result.update(dict(value))

    maximum = result["max_output_tokens"]
    if isinstance(maximum, bool) or not isinstance(maximum, Integral):
        raise ValueError("Vertex max_output_tokens must be an integer")
    if not 256 <= int(maximum) <= 8192:
        raise ValueError("Vertex max_output_tokens must be between 256 and 8192")
    result["max_output_tokens"] = int(maximum)

    temperature = result["temperature"]
    if isinstance(temperature, bool) or not isinstance(temperature, Real):
        raise ValueError("Vertex temperature must be numeric")
    if not 0.0 <= float(temperature) <= 1.0:
        raise ValueError("Vertex temperature must be between 0 and 1")
    result["temperature"] = float(temperature)

    thinking_budget = result["thinking_budget"]
    if isinstance(thinking_budget, bool) or not isinstance(thinking_budget, Integral):
        raise ValueError("Vertex thinking_budget must be an integer")
    if not 0 <= int(thinking_budget) <= 2048:
        raise ValueError("Vertex thinking_budget must be between 0 and 2048")
    result["thinking_budget"] = int(thinking_budget)

    if "seed" in result:
        seed = result["seed"]
        if isinstance(seed, bool) or not isinstance(seed, Integral):
            raise ValueError("Vertex seed must be an integer")
        if not 0 <= int(seed) <= 2_147_483_647:
            raise ValueError("Vertex seed is outside the supported range")
        result["seed"] = int(seed)
    return result


def load_google_adc_credentials(
    project: str,
    *,
    credentials_loader: Callable[..., Any] | None = None,
) -> Any:
    """Resolve ADC without refreshing it or reading credential JSON directly."""

    project_id = validate_vertex_project(project)
    if credentials_loader is None:
        try:
            import google.auth
        except ImportError as exc:
            raise ValueError(
                "google-genai with google-auth is required for Vertex AI advisory"
            ) from exc
        credentials_loader = google.auth.default
    try:
        credentials, detected_project = credentials_loader(
            scopes=[ADC_SCOPE],
            quota_project_id=project_id,
        )
    except Exception:
        raise ValueError("Vertex AI Application Default Credentials are unavailable") from None
    if credentials is None:
        raise ValueError("Vertex AI Application Default Credentials are unavailable")
    quota_project = str(getattr(credentials, "quota_project_id", "") or "")
    credential_module = type(credentials).__module__.lower()
    is_gce_metadata = credential_module.startswith("google.auth.compute_engine")
    if quota_project:
        if quota_project != project_id:
            raise ValueError(
                "Vertex AI ADC quota project does not match the configured project"
            )
    elif is_gce_metadata:
        if str(detected_project or "") != project_id:
            raise ValueError(
                "Vertex AI metadata ADC project does not match the configured project"
            )
    else:
        raise ValueError("Vertex AI ADC does not identify the configured quota project")
    return credentials


def _provider_error(exc: BaseException) -> Exception:
    """Classify SDK/auth errors without retaining provider error bodies."""

    code_value = getattr(exc, "code", None)
    if callable(code_value):
        try:
            code_value = code_value()
        except Exception:
            code_value = None
    try:
        code = int(code_value)
    except (TypeError, ValueError):
        try:
            code = int(getattr(exc, "status_code", 0) or 0)
        except (TypeError, ValueError):
            code = 0

    class_name = type(exc).__name__.lower()
    module_name = type(exc).__module__.lower()
    if code == 403:
        return AIAdvisoryContractError(
            "Vertex AI permission was denied",
            code="provider_permission_denied",
        )
    if code == 401 or (
        module_name.startswith("google.auth")
        and class_name in {"refresherror", "defaultcredentialserror"}
    ):
        return AIAdvisoryContractError(
            "Vertex AI authentication failed",
            code="provider_authentication_failed",
        )
    if code in {400, 404}:
        return AIAdvisoryContractError(
            "Vertex AI rejected the reviewed request contract",
            code="provider_request_rejected",
        )
    if code in {408, 409, 429, 500, 502, 503, 504} or any(
        token in class_name for token in ("timeout", "connection", "network")
    ):
        return AIProviderUnavailable("Vertex AI is temporarily unavailable")
    return AIProviderUnavailable("Vertex AI request failed")


def _usage_metadata(response: Any) -> Dict[str, Any]:
    value = getattr(response, "usage_metadata", None)
    result: Dict[str, Any] = {}
    if value is None:
        return result
    for name in _USAGE_INTEGER_FIELDS:
        item = getattr(value, name, None)
        if isinstance(item, Integral) and not isinstance(item, bool) and item >= 0:
            result[name] = int(item)
    traffic = getattr(value, "traffic_type", None)
    if traffic is not None:
        traffic_value = getattr(traffic, "value", traffic)
        traffic_text = str(traffic_value or "").strip()
        if re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", traffic_text):
            result["traffic_type"] = traffic_text
    return result


def _vertex_response_schema(value: Any) -> Any:
    """Translate annotations/keywords not needed at the Vertex boundary.

    The executable local validator remains authoritative.  In particular,
    duplicate selections are rejected locally after ``uniqueItems`` is removed
    from the provider-facing JSON Schema subset.
    """

    if isinstance(value, Mapping):
        result: Dict[str, Any] = {}
        for key, item in value.items():
            if key in {
                "$schema",
                "$id",
                "title",
                "uniqueItems",
                "maxItems",
                "minItems",
                "minLength",
                "maxLength",
                "pattern",
            }:
                continue
            if key == "const":
                result["enum"] = [_vertex_response_schema(item)]
            elif key == "enum" and isinstance(item, list) and len(item) > 1:
                # Closed vocabularies remain present in the aliased projection
                # and are enforced by the exact executable local validator.
                continue
            else:
                result[str(key)] = _vertex_response_schema(item)
        return result
    if isinstance(value, list):
        return [_vertex_response_schema(item) for item in value]
    return value


def _vertex_request_contract_instruction(projection: Mapping[str, Any]) -> str:
    """Return one bounded request-specific abstention/selection instruction."""

    has_selection = bool(
        projection.get("findings")
        or projection.get("relationships")
        or (projection.get("guidance") or {}).get("actions")
    )
    abstention = projection.get("abstention") or {}
    if bool(abstention.get("abstained")):
        reason = str(abstention.get("reason_code") or "policy_requires_abstention")
        return (
            "Request-specific mandatory output: set validated_advisory.abstained "
            f"to true, set abstention_reason_code to {reason}, and return empty "
            "selected_finding_ids, selected_relationship_ids, ranked_action_ids, "
            "and template_selections arrays."
        )
    if not has_selection:
        return (
            "Request-specific mandatory output: no eligible finding, relationship, "
            "or action identifiers exist. Set validated_advisory.abstained to true, "
            "set abstention_reason_code to no_eligible_selection, and return empty "
            "selected_finding_ids, selected_relationship_ids, ranked_action_ids, "
            "and template_selections arrays."
        )
    return (
        "Request-specific output rule: a non-abstained advisory must select at "
        "least one supplied finding, relationship, action, or valid template. If "
        "nothing is selected, set abstained to true, choose one supplied reason "
        "code, and leave every selection and template array empty."
    )


class GoogleVertexGeminiProvider:
    """Constrained Vertex AI Gemini provider using ``google-genai`` and ADC."""

    provider_id = PROVIDER_ID
    adapter_revision = ADAPTER_REVISION
    api_version = REVIEWED_API_VERSION

    def __init__(
        self,
        *,
        project: str,
        location: str,
        model_id: str,
        endpoint: str,
        request_options: Mapping[str, Any],
        client: Any = None,
        credentials: Any = None,
        credentials_loader: Callable[..., Any] | None = None,
    ) -> None:
        self.project = validate_vertex_project(project)
        self.location = str(location or "").strip()
        self.model_id = str(model_id or "").strip()
        self.endpoint = str(endpoint or "").strip().rstrip("/")
        if self.location != REVIEWED_LOCATION:
            raise ValueError("Vertex AI advisory location is not reviewed")
        if self.model_id != REVIEWED_MODEL_ID:
            raise ValueError("Vertex AI advisory model is not reviewed")
        if self.endpoint != REVIEWED_ENDPOINT:
            raise ValueError("Vertex AI advisory endpoint is not reviewed")
        self.request_options = normalize_vertex_request_options(request_options)
        self.endpoint_sha256 = endpoint_sha256(self.endpoint)
        self.request_options_sha256 = sha256_json(self.request_options)
        self.last_usage_metadata: Dict[str, Any] = {}

        if client is None:
            if credentials is None:
                credentials = load_google_adc_credentials(
                    self.project,
                    credentials_loader=credentials_loader,
                )
            try:
                from google import genai
            except ImportError as exc:
                raise AIProviderUnavailable(
                    "google-genai is not installed for Vertex AI advisory"
                ) from exc
            try:
                client = genai.Client(
                    vertexai=True,
                    credentials=credentials,
                    project=self.project,
                    location=self.location,
                    http_options={
                        "base_url": self.endpoint,
                        "api_version": self.api_version,
                    },
                )
            except Exception as exc:
                raise _provider_error(exc) from None
        self._client = client

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
        idempotency_key: str,
    ) -> AIProviderResponse:
        # Vertex generateContent exposes no idempotency-key contract.  The
        # worker still supplies and locally fences the content-addressed key.
        del idempotency_key
        timeout_ms = max(1, int(float(timeout_seconds) * 1000))
        request = {
            "schema_version": "ai_vertex_request.v1",
            "projection": projection,
            "schema_sha256": str(schema_sha256),
            "policy_sha256": str(policy_sha256),
        }
        system_instruction = [
            *(str(item) for item in prompt_contract),
            _vertex_request_contract_instruction(projection),
        ]
        config: Dict[str, Any] = {
            "http_options": {"timeout": timeout_ms},
            "system_instruction": "\n".join(system_instruction),
            "temperature": self.request_options["temperature"],
            "candidate_count": 1,
            "max_output_tokens": self.request_options["max_output_tokens"],
            "response_mime_type": "application/json",
            "response_json_schema": _vertex_response_schema(response_schema),
            "thinking_config": {
                "thinking_budget": self.request_options["thinking_budget"]
            },
        }
        if "seed" in self.request_options:
            config["seed"] = self.request_options["seed"]
        try:
            response = self._client.models.generate_content(
                model=self.model_id,
                contents=stable_json(request),
                config=config,
            )
        except Exception as exc:
            classified = _provider_error(exc)
            raise classified from None

        self.last_usage_metadata = _usage_metadata(response)
        text = getattr(response, "text", None)
        if not isinstance(text, str) or not text.strip():
            raise AIAdvisoryContractError(
                "Vertex AI returned an empty structured response",
                code="provider_response_empty",
            )
        raw = text.encode("utf-8")
        if len(raw) > int(max_response_bytes):
            raise AIAdvisoryContractError(
                "provider response exceeds the configured limit",
                code="provider_response_too_large",
            )
        try:
            loaded = json.loads(text)
        except json.JSONDecodeError as exc:
            raise AIAdvisoryContractError(
                "Vertex AI response is not valid JSON",
                code="provider_response_malformed",
            ) from exc
        if not isinstance(loaded, dict):
            raise AIAdvisoryContractError(
                "Vertex AI response must be an object",
                code="provider_response_malformed",
            )
        return AIProviderResponse(
            provider_id=self.provider_id,
            model_id=self.model_id,
            structured_output=loaded,
            response_sha256=sha256_json(loaded),
            adapter_revision=self.adapter_revision,
            endpoint_sha256=self.endpoint_sha256,
            api_version=self.api_version,
            request_options_sha256=self.request_options_sha256,
            usage_metadata=dict(self.last_usage_metadata),
        )
