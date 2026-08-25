"""Phase-5 integration primitives for the Final-F advisory contract.

The v1 advisory path is intentionally left in its historical modules.  This
module contains only deterministic, provider-neutral v2 dispatch helpers so
the worker can share the existing outbox/lease machinery without allowing a
provider response to become canonical evidence.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from production.ai_advisory.contracts import (
    AIAdvisoryContractError,
    load_ai_advisory_policy,
    sha256_json,
)
from production.ai_advisory.contracts_v2 import load_ai_advisory_policy_v2


V1_POLICY_SCHEMA = "ai_advisory_policy.v1"
V2_POLICY_SCHEMA = "ai_advisory_policy.v2"
V1_TASK_SCHEMA = "ai_advisory_task.v1"
V2_TASK_SCHEMA = "ai_advisory_task.v2"
V1_RECORD_SCHEMA = "ai_advisory_record.v1"
V2_RECORD_SCHEMA = "ai_advisory_record.v2"
V2_REQUEST_SCHEMA = "ai_vertex_request.v2"

_V2_RECORD_KEYS = {
    "schema_version",
    "status",
    "authority",
    "validation",
    "validated_output",
    "rendered_advisory",
    "safety",
    "provenance",
}
_V2_RECORD_VALIDATION_KEYS = {"status", "reason_code"}
_V2_RECORD_SAFETY_KEYS = {
    "requires_manual_approval",
    "safe_to_auto_execute",
    "alerts_authorized",
    "response_actions_authorized",
}
_V2_RECORD_PROVENANCE_KEYS = {
    "report_content_sha256",
    "projection_sha256",
    "evidence_sha256",
    "graph_sha256",
    "typed_fact_set_sha256",
    "guidance_content_sha256",
    "request_sha256",
    "response_sha256",
    "provider_id",
    "model_id",
    "prompt_sha256",
    "schema_sha256",
    "policy_sha256",
    "projection_contract_sha256",
    "provider_identity",
    "request_budget",
}
_V2_RECORD_PROVIDER_IDENTITY_KEYS = {
    "adapter_revision",
    "endpoint_sha256",
    "api_version",
    "request_options_sha256",
}
_V2_RECORD_BUDGET_KEYS = {
    "request_bytes",
    "request_tokens_estimate",
    "max_request_bytes",
    "max_request_tokens",
}
_V2_RECORD_AUTHORITY = {
    "accepted": "non_authoritative_advisory_only",
    "abstained": "non_authoritative_deterministic_abstention",
    "rejected": "non_authoritative_rejected_output",
}


def load_ai_advisory_contract(
    path: str | Path,
) -> tuple[dict[str, Any], str, str, str]:
    """Load exactly one reviewed policy version from its declared bytes.

    Dispatch is based on the policy's own schema version, never on a caller
    supplied version flag.  A v2 policy is explicit opt-in through the
    configured path; the frozen v1 loader remains unchanged for historical
    deployments.
    """

    selected = Path(str(path or ""))
    try:
        value = json.loads(selected.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise AIAdvisoryContractError(
            "AI advisory policy is unavailable", code="policy_unavailable"
        ) from exc
    if not isinstance(value, Mapping):
        raise AIAdvisoryContractError("AI advisory policy must be an object")
    schema = str(value.get("schema_version") or "")
    if schema == V2_POLICY_SCHEMA:
        policy, digest, resolved = load_ai_advisory_policy_v2(selected)
        return policy, digest, resolved, "v2"
    if schema == V1_POLICY_SCHEMA:
        policy, digest, resolved = load_ai_advisory_policy(selected)
        return policy, digest, resolved, "v1"
    raise AIAdvisoryContractError("AI advisory policy schema is unsupported")


def build_ai_vertex_request_v2(
    projection: Mapping[str, Any],
    *,
    schema_sha256: str,
    policy_sha256: str,
    request_options_sha256: str,
) -> dict[str, Any]:
    """Build the closed request envelope sent to a v2 provider adapter."""

    if projection.get("schema_version") != "ai_advisory_projection.v2":
        raise AIAdvisoryContractError("v2 provider request requires projection v2")
    projection_hash = str(projection.get("projection_sha256") or "")
    if len(projection_hash) != 64 or any(
        character not in "0123456789abcdef" for character in projection_hash
    ):
        raise AIAdvisoryContractError("v2 provider request projection hash is invalid")
    for label, value in (
        ("response schema", schema_sha256),
        ("policy", policy_sha256),
        ("request options", request_options_sha256),
    ):
        text = str(value or "")
        if len(text) != 64 or any(
            character not in "0123456789abcdef" for character in text
        ):
            raise AIAdvisoryContractError(
                f"v2 provider request {label} hash is invalid"
            )
    return {
        "schema_version": V2_REQUEST_SCHEMA,
        "projection": dict(projection),
        "projection_sha256": projection_hash,
        "policy_sha256": str(policy_sha256),
        "response_schema_sha256": str(schema_sha256),
        "request_options_sha256": str(request_options_sha256),
    }


def v2_invocation_eligibility(
    projection: Mapping[str, Any],
) -> tuple[bool, str]:
    """Apply the frozen deterministic provider-call rule.

    The rule only counts objects already admitted by the v2 deterministic
    projection.  It does not inspect raw commands, provider output, scores, or
    any denormalized session fields.
    """

    if projection.get("schema_version") != "ai_advisory_projection.v2":
        raise AIAdvisoryContractError("v2 eligibility requires projection v2")
    abstention = projection.get("abstention")
    if not isinstance(abstention, Mapping):
        raise AIAdvisoryContractError("v2 projection abstention is missing")
    if abstention.get("assessment_abstained") is True:
        return False, "canonical_abstention_only"
    chains = [
        item for item in projection.get("chains") or []
        if isinstance(item, Mapping) and item.get("ai_eligible") is True
    ]
    findings = [
        item for item in projection.get("findings") or []
        if isinstance(item, Mapping)
    ]
    hypotheses = [
        item for item in projection.get("hypotheses") or []
        if isinstance(item, Mapping)
    ]
    actions = [
        item for item in projection.get("actions") or []
        if isinstance(item, Mapping)
    ]
    limitations = projection.get("limitations") or []
    evidence_gaps = projection.get("evidence_gaps") or []
    has_primary = bool(chains) or len(findings) >= 2
    has_synthesis_context = bool(
        actions
        or hypotheses
        or len(findings) >= 2
        or len(chains) >= 2
        or limitations
        or evidence_gaps
    )
    if not has_primary or not has_synthesis_context:
        return False, "insufficient_synthesis_context"
    return True, ""


def request_identity_material_v2(
    projection: Mapping[str, Any],
    *,
    provider_identity: Mapping[str, Any],
    prompt_sha256: str,
    schema_sha256: str,
    policy_sha256: str,
    request_bytes: int,
    request_tokens: int,
    request_limits: Mapping[str, int],
) -> dict[str, Any]:
    """Return the content-addressed request material for v2 cache identity."""

    return {
        "contract_version": "v2",
        "projection": projection,
        "provider_identity": dict(provider_identity),
        "prompt_sha256": prompt_sha256,
        "schema_sha256": schema_sha256,
        "policy_sha256": policy_sha256,
        "request_bytes": int(request_bytes),
        "request_tokens": int(request_tokens),
        "request_limits": dict(request_limits),
    }


def v2_record_content_sha256(record: Mapping[str, Any]) -> str:
    """Content digest helper for the persisted, non-authoritative envelope."""

    return sha256_json(dict(record))


def _record_sha(value: Any, label: str) -> str:
    text = str(value or "").lower()
    if len(text) != 64 or any(character not in "0123456789abcdef" for character in text):
        raise AIAdvisoryContractError(f"v2 record {label} must be a SHA-256")
    return text


def _record_text(value: Any, label: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value):
        raise AIAdvisoryContractError(f"v2 record {label} must be a string")
    if len(value) > 256:
        raise AIAdvisoryContractError(f"v2 record {label} is too long")
    return value


def validate_ai_advisory_record_v2(
    value: Any,
    *,
    projection_sha256: str = "",
    policy_sha256: str = "",
) -> dict[str, Any]:
    """Validate the closed persisted v2 advisory envelope.

    This is deliberately context-light: projection and report-bound semantic
    validation happens before persistence in ``contracts_v2``.  The storage
    boundary still needs an exact shape/status/authority/hash check so a
    malformed or tampered cached record cannot be replayed as a valid advisory.
    """

    if not isinstance(value, Mapping) or set(value) != _V2_RECORD_KEYS:
        raise AIAdvisoryContractError(
            "v2 advisory record violates its closed envelope",
            code="record_contract_invalid",
        )
    if value["schema_version"] != V2_RECORD_SCHEMA:
        raise AIAdvisoryContractError("v2 advisory record schema is invalid")
    status = _record_text(value["status"], "status")
    if status not in _V2_RECORD_AUTHORITY:
        raise AIAdvisoryContractError("v2 advisory record status is invalid")
    if value["authority"] != _V2_RECORD_AUTHORITY[status]:
        raise AIAdvisoryContractError("v2 advisory record authority is invalid")

    validation = value["validation"]
    if not isinstance(validation, Mapping) or set(validation) != _V2_RECORD_VALIDATION_KEYS:
        raise AIAdvisoryContractError("v2 advisory validation envelope is invalid")
    validation_status = _record_text(validation["status"], "validation.status")
    if validation_status not in {"accepted", "rejected"}:
        raise AIAdvisoryContractError("v2 advisory validation status is invalid")
    reason = _record_text(
        validation["reason_code"], "validation.reason_code", allow_empty=True
    )
    if status == "rejected" and validation_status != "rejected":
        raise AIAdvisoryContractError("rejected v2 record must have rejected validation")
    if status != "rejected" and validation_status != "accepted":
        raise AIAdvisoryContractError("accepted v2 record must have accepted validation")
    if status == "rejected" and not reason:
        raise AIAdvisoryContractError("rejected v2 record requires a reason")

    validated = value["validated_output"]
    rendered = value["rendered_advisory"]
    if not isinstance(validated, Mapping) or not isinstance(rendered, Mapping):
        raise AIAdvisoryContractError("v2 advisory output envelopes are invalid")
    if status == "rejected":
        if dict(validated) or dict(rendered):
            raise AIAdvisoryContractError("rejected v2 record must contain no output")
    else:
        validated_keys = {
            "schema_version",
            "projection_sha256",
            "policy_sha256",
            "validation_status",
            "selection_origin",
            "synthesis",
            "validated_output_sha256",
        }
        if set(validated) != validated_keys:
            raise AIAdvisoryContractError("v2 validated output envelope is invalid")
        if validated["schema_version"] != "ai_advisory_validated_output.v2":
            raise AIAdvisoryContractError("v2 validated output schema is invalid")
        if validated["validation_status"] != "accepted":
            raise AIAdvisoryContractError("v2 validated output status is invalid")
        if validated["selection_origin"] not in {"provider", "deterministic_no_call"}:
            raise AIAdvisoryContractError("v2 selection origin is invalid")
        _record_sha(validated["projection_sha256"], "validated projection_sha256")
        _record_sha(validated["policy_sha256"], "validated policy_sha256")
        expected_validated = dict(validated)
        recorded_validated_sha = expected_validated.pop("validated_output_sha256")
        if _record_sha(recorded_validated_sha, "validated_output_sha256") != sha256_json(expected_validated):
            raise AIAdvisoryContractError("v2 validated output content hash mismatch")
        rendered_keys = {
            "schema_version",
            "status",
            "abstention_reason_code",
            "sections",
            "review_plan",
            "render_sha256",
        }
        if set(rendered) != rendered_keys or rendered["schema_version"] != "ai_advisory_rendered.v2":
            raise AIAdvisoryContractError("v2 rendered advisory envelope is invalid")
        if rendered["status"] not in {"rendered", "abstained"}:
            raise AIAdvisoryContractError("v2 rendered advisory status is invalid")
        if not isinstance(rendered["sections"], list) or not isinstance(rendered["review_plan"], list):
            raise AIAdvisoryContractError("v2 rendered advisory collections are invalid")
        if status == "abstained" and rendered["status"] != "abstained":
            raise AIAdvisoryContractError("abstained v2 record must render as abstained")
        if status == "accepted" and rendered["status"] != "rendered":
            raise AIAdvisoryContractError("accepted v2 record must render as rendered")
        expected_rendered = dict(rendered)
        recorded_render_sha = expected_rendered.pop("render_sha256")
        if _record_sha(recorded_render_sha, "render_sha256") != sha256_json(expected_rendered):
            raise AIAdvisoryContractError("v2 rendered advisory content hash mismatch")

    safety = value["safety"]
    if not isinstance(safety, Mapping) or set(safety) != _V2_RECORD_SAFETY_KEYS:
        raise AIAdvisoryContractError("v2 advisory safety envelope is invalid")
    if safety != {
        "requires_manual_approval": True,
        "safe_to_auto_execute": False,
        "alerts_authorized": False,
        "response_actions_authorized": False,
    }:
        raise AIAdvisoryContractError("v2 advisory safety policy is invalid")

    provenance = value["provenance"]
    if not isinstance(provenance, Mapping) or set(provenance) != _V2_RECORD_PROVENANCE_KEYS:
        raise AIAdvisoryContractError("v2 advisory provenance envelope is invalid")
    for key in (
        "report_content_sha256", "projection_sha256", "evidence_sha256",
        "graph_sha256", "typed_fact_set_sha256", "guidance_content_sha256",
        "request_sha256", "response_sha256", "prompt_sha256", "schema_sha256",
        "policy_sha256", "projection_contract_sha256",
    ):
        _record_sha(provenance[key], f"provenance.{key}")
    _record_text(provenance["provider_id"], "provenance.provider_id")
    _record_text(provenance["model_id"], "provenance.model_id", allow_empty=True)
    provider_identity = provenance["provider_identity"]
    if not isinstance(provider_identity, Mapping) or set(provider_identity) != _V2_RECORD_PROVIDER_IDENTITY_KEYS:
        raise AIAdvisoryContractError("v2 provider identity is invalid")
    _record_text(provider_identity["adapter_revision"], "provider_identity.adapter_revision")
    _record_sha(provider_identity["endpoint_sha256"], "provider_identity.endpoint_sha256")
    _record_text(provider_identity["api_version"], "provider_identity.api_version")
    _record_sha(provider_identity["request_options_sha256"], "provider_identity.request_options_sha256")
    budget = provenance["request_budget"]
    if not isinstance(budget, Mapping) or set(budget) != _V2_RECORD_BUDGET_KEYS:
        raise AIAdvisoryContractError("v2 request budget is invalid")
    if any(type(budget[key]) is not int or budget[key] < 0 for key in _V2_RECORD_BUDGET_KEYS):
        raise AIAdvisoryContractError("v2 request budget values are invalid")

    if projection_sha256 and provenance["projection_sha256"] != projection_sha256:
        raise AIAdvisoryContractError("v2 record projection identity mismatch")
    if policy_sha256 and provenance["policy_sha256"] != policy_sha256:
        raise AIAdvisoryContractError("v2 record policy identity mismatch")
    return dict(value)


__all__ = [
    "V1_POLICY_SCHEMA",
    "V2_POLICY_SCHEMA",
    "V1_TASK_SCHEMA",
    "V2_TASK_SCHEMA",
    "V1_RECORD_SCHEMA",
    "V2_RECORD_SCHEMA",
    "V2_REQUEST_SCHEMA",
    "build_ai_vertex_request_v2",
    "load_ai_advisory_contract",
    "request_identity_material_v2",
    "validate_ai_advisory_record_v2",
    "v2_invocation_eligibility",
    "v2_record_content_sha256",
]
