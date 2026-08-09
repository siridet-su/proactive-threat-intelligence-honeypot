"""Strict contracts for the separate, non-authoritative AI advisory path."""

from __future__ import annotations

import hashlib
import json
import re
import string
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Sequence, Tuple

from production.utils.serialization import stable_id, stable_json


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_POLICY_PATH = PROJECT_ROOT / "configs" / "ai_advisory_policy.v1.json"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SAFE_ID_RE = re.compile(r"^[a-z][a-z0-9_]*_[0-9a-f]{16,64}$")
SAFE_CODE_RE = re.compile(r"^[a-z][a-z0-9_]{0,127}$")

POLICY_KEYS = {
    "schema_version",
    "policy_id",
    "version",
    "authority",
    "prompt_contract",
    "template_ids",
    "reason_codes",
    "limitation_codes",
    "candidate_types",
    "missing_evidence_codes",
    "falsifier_codes",
    "templates",
    "limits",
}
AUTHORITY_KEYS = {
    "canonical_authority",
    "finding_authority",
    "hypothesis_authority",
    "guidance_authority",
    "alert_authority",
    "automatic_execution",
}
LIMIT_KEYS = {
    "max_findings",
    "max_relationships",
    "max_actions",
    "max_templates",
    "max_shadow_candidates",
    "max_references_per_item",
    "max_response_bytes",
    "max_request_bytes",
    "max_request_tokens",
}
PROVIDER_OUTPUT_KEYS = {
    "schema_version",
    "projection_sha256",
    "policy_sha256",
    "validated_advisory",
    "shadow_candidates",
}
ADVISORY_KEYS = {
    "schema_version",
    "abstained",
    "abstention_reason_code",
    "selected_finding_ids",
    "selected_relationship_ids",
    "ranked_action_ids",
    "template_selections",
}
TEMPLATE_SELECTION_KEYS = {
    "template_id",
    "finding_ids",
    "relationship_ids",
    "action_ids",
    "limitation_codes",
    "reason_codes",
}
SHADOW_SET_KEYS = {"schema_version", "candidates"}
SHADOW_CANDIDATE_KEYS = {
    "candidate_type",
    "status",
    "premise_finding_ids",
    "premise_relationship_ids",
    "premise_evidence_refs",
    "reason_codes",
    "missing_evidence_codes",
    "falsifier_codes",
}
PROHIBITED_OUTPUT_KEYS = {
    "action",
    "actions",
    "alert",
    "alerts",
    "attck",
    "attack",
    "automatic_execution",
    "command",
    "confidence",
    "credential",
    "entity_value",
    "finding",
    "findings",
    "free_text",
    "guidance",
    "hypothesis",
    "intent",
    "objective",
    "payload",
    "prose",
    "response_action",
    "severity",
    "source_ip",
    "statement",
    "url",
    "username",
}
ALLOWED_TEMPLATE_FIELDS = {
    "finding_count",
    "finding_types",
    "action_descriptions",
    "relationship_count",
    "limitation_labels",
}


class AIAdvisoryContractError(ValueError):
    """Raised when an AI policy, projection, or response fails closed."""

    def __init__(self, message: str, *, code: str = "contract_invalid") -> None:
        super().__init__(message)
        self.code = code


def sha256_json(value: Any) -> str:
    return hashlib.sha256(stable_json(value).encode("utf-8")).hexdigest()


def provider_output_json_schema(policy: Mapping[str, Any]) -> Dict[str, Any]:
    """Build the exact strict schema supplied to a structured-output provider.

    Dynamic reference membership still requires the executable validator because
    JSON Schema cannot prove that a returned identifier occurred in the request.
    """

    limits = policy["limits"]

    def string_array(maximum: int, *, enum: Sequence[str] | None = None) -> Dict[str, Any]:
        item: Dict[str, Any] = {"type": "string", "minLength": 1, "maxLength": 256}
        if enum is not None:
            item["enum"] = list(enum)
        return {
            "type": "array",
            "maxItems": maximum,
            "uniqueItems": True,
            "items": item,
        }

    reference_limit = int(limits["max_references_per_item"])
    template_selection = {
        "type": "object",
        "additionalProperties": False,
        "required": sorted(TEMPLATE_SELECTION_KEYS),
        "properties": {
            "template_id": {"type": "string", "enum": list(policy["template_ids"])},
            "finding_ids": string_array(reference_limit),
            "relationship_ids": string_array(reference_limit),
            "action_ids": string_array(reference_limit),
            "limitation_codes": string_array(reference_limit, enum=policy["limitation_codes"]),
            "reason_codes": string_array(reference_limit, enum=policy["reason_codes"]),
        },
    }
    candidate = {
        "type": "object",
        "additionalProperties": False,
        "required": sorted(SHADOW_CANDIDATE_KEYS),
        "properties": {
            "candidate_type": {"type": "string", "enum": list(policy["candidate_types"])},
            "status": {"const": "unverified_ai_candidate"},
            "premise_finding_ids": string_array(reference_limit),
            "premise_relationship_ids": string_array(reference_limit),
            "premise_evidence_refs": string_array(reference_limit),
            "reason_codes": string_array(reference_limit, enum=policy["reason_codes"]),
            "missing_evidence_codes": string_array(reference_limit, enum=policy["missing_evidence_codes"]),
            "falsifier_codes": string_array(reference_limit, enum=policy["falsifier_codes"]),
        },
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "urn:honeypot-analysis:ai-provider-output:v1",
        "title": "Constrained non-authoritative AI provider output",
        "type": "object",
        "additionalProperties": False,
        "required": sorted(PROVIDER_OUTPUT_KEYS),
        "properties": {
            "schema_version": {"const": "ai_provider_output.v1"},
            "projection_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "policy_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "validated_advisory": {
                "type": "object",
                "additionalProperties": False,
                "required": sorted(ADVISORY_KEYS),
                "properties": {
                    "schema_version": {"const": "ai_validated_advisory_selection.v1"},
                    "abstained": {"type": "boolean"},
                    "abstention_reason_code": {
                        "type": "string",
                        "maxLength": 128,
                        "enum": ["", *policy["reason_codes"]],
                    },
                    "selected_finding_ids": string_array(int(limits["max_findings"])),
                    "selected_relationship_ids": string_array(int(limits["max_relationships"])),
                    "ranked_action_ids": string_array(int(limits["max_actions"])),
                    "template_selections": {
                        "type": "array",
                        "maxItems": int(limits["max_templates"]),
                        "items": template_selection,
                    },
                },
            },
            "shadow_candidates": {
                "type": "object",
                "additionalProperties": False,
                "required": sorted(SHADOW_SET_KEYS),
                "properties": {
                    "schema_version": {"const": "ai_shadow_candidate_set.v1"},
                    "candidates": {
                        "type": "array",
                        "maxItems": int(limits["max_shadow_candidates"]),
                        "items": candidate,
                    },
                },
            },
        },
    }


def contract_schema_sha256(policy: Mapping[str, Any]) -> str:
    """Hash the exact structured-output schema used for the request."""

    return sha256_json(provider_output_json_schema(policy))


def _exact_keys(value: Any, expected: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise AIAdvisoryContractError(f"{label} must be an object")
    actual = set(value)
    if actual != expected:
        extra = sorted(actual - expected)
        missing = sorted(expected - actual)
        raise AIAdvisoryContractError(
            f"{label} has invalid keys; missing={missing}, extra={extra}",
            code="additional_or_missing_property",
        )
    return value


def _string(value: Any, label: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value):
        raise AIAdvisoryContractError(f"{label} must be a string")
    if len(value) > 256:
        raise AIAdvisoryContractError(f"{label} is too long")
    return value


def _sha256(value: Any, label: str) -> str:
    text = _string(value, label).lower()
    if not SHA256_RE.fullmatch(text):
        raise AIAdvisoryContractError(f"{label} must be a SHA-256")
    return text


def _code(value: Any, label: str) -> str:
    text = _string(value, label)
    if not SAFE_CODE_RE.fullmatch(text):
        raise AIAdvisoryContractError(f"{label} is not a safe code")
    return text


def _unique_strings(
    value: Any,
    label: str,
    *,
    maximum: int,
    allowed: Iterable[str] | None = None,
) -> list[str]:
    if not isinstance(value, list) or len(value) > maximum:
        raise AIAdvisoryContractError(f"{label} must be a bounded array")
    output = [_string(item, f"{label}[]") for item in value]
    if len(output) != len(set(output)):
        raise AIAdvisoryContractError(f"{label} contains duplicates")
    if allowed is not None:
        unknown = set(output) - set(allowed)
        if unknown:
            raise AIAdvisoryContractError(
                f"{label} contains unknown values",
                code="invented_reference",
            )
    return output


def _walk_keys(value: Any) -> Iterable[str]:
    if isinstance(value, Mapping):
        for key, item in value.items():
            yield str(key).lower()
            yield from _walk_keys(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk_keys(item)


def _reject_prohibited_output_keys(value: Any) -> None:
    prohibited = set(_walk_keys(value)) & PROHIBITED_OUTPUT_KEYS
    if prohibited:
        raise AIAdvisoryContractError(
            "provider output contains prohibited claim or authority fields",
            code="prohibited_field",
        )


def load_ai_advisory_policy(path: str | Path = "") -> Tuple[Dict[str, Any], str, str]:
    selected = Path(path) if str(path) else DEFAULT_POLICY_PATH
    try:
        raw = selected.read_bytes()
        value = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AIAdvisoryContractError(
            "AI advisory policy is missing or invalid",
            code="policy_unavailable",
        ) from exc
    document = dict(_exact_keys(value, POLICY_KEYS, "AI advisory policy"))
    if document["schema_version"] != "ai_advisory_policy.v1":
        raise AIAdvisoryContractError("AI advisory policy schema is invalid")
    _code(document["policy_id"].replace("-", "_"), "policy_id")
    _string(document["version"], "version")
    authority = _exact_keys(document["authority"], AUTHORITY_KEYS, "authority")
    if any(authority.get(key) is not False for key in AUTHORITY_KEYS):
        raise AIAdvisoryContractError("AI advisory policy grants authority")
    prompt = document["prompt_contract"]
    if not isinstance(prompt, list) or not prompt or any(
        not isinstance(item, str) or not item or len(item) > 512 for item in prompt
    ):
        raise AIAdvisoryContractError("prompt_contract is invalid")
    vocab_names = (
        "template_ids",
        "reason_codes",
        "limitation_codes",
        "candidate_types",
        "missing_evidence_codes",
        "falsifier_codes",
    )
    for name in vocab_names:
        _unique_strings(document[name], name, maximum=128)
        if any(not SAFE_CODE_RE.fullmatch(item) for item in document[name]):
            raise AIAdvisoryContractError(f"{name} contains an invalid code")
    templates = document["templates"]
    if not isinstance(templates, Mapping) or set(templates) != set(document["template_ids"]):
        raise AIAdvisoryContractError("templates must exactly match template_ids")
    if any(not isinstance(value, str) or not value or len(value) > 1024 for value in templates.values()):
        raise AIAdvisoryContractError("templates contain invalid text")
    for template in templates.values():
        try:
            fields = {
                field_name
                for _literal, field_name, _format_spec, _conversion in string.Formatter().parse(template)
                if field_name is not None
            }
        except ValueError as exc:
            raise AIAdvisoryContractError("templates contain invalid formatting") from exc
        if fields - ALLOWED_TEMPLATE_FIELDS:
            raise AIAdvisoryContractError("templates contain an unapproved field")
    limits = _exact_keys(document["limits"], LIMIT_KEYS, "limits")
    if any(type(limits[key]) is not int or not 1 <= limits[key] <= 65536 for key in LIMIT_KEYS):
        raise AIAdvisoryContractError("policy limits are invalid")
    return deepcopy(document), hashlib.sha256(raw).hexdigest(), str(selected.resolve())


def _projection_sets(projection: Mapping[str, Any]) -> Dict[str, set[str]]:
    return {
        "finding_ids": {
            str(item.get("finding_id")) for item in projection.get("findings", [])
            if isinstance(item, Mapping)
        },
        "relationship_ids": {
            str(item.get("relationship_id")) for item in projection.get("relationships", [])
            if isinstance(item, Mapping)
        },
        "action_ids": {
            str(item.get("action_id")) for item in (projection.get("guidance") or {}).get("actions", [])
            if isinstance(item, Mapping)
        },
        "evidence_refs": {
            str(item.get("evidence_id")) for item in projection.get("evidence_index", [])
            if isinstance(item, Mapping)
        },
    }


def _validate_template_selection(
    value: Any,
    *,
    index: int,
    policy: Mapping[str, Any],
    refs: Mapping[str, set[str]],
    allowed_output: Mapping[str, Any],
) -> Dict[str, Any]:
    item = _exact_keys(value, TEMPLATE_SELECTION_KEYS, f"template_selections[{index}]")
    limit = int(policy["limits"]["max_references_per_item"])
    result = {
        "template_id": _string(item["template_id"], "template_id"),
        "finding_ids": _unique_strings(item["finding_ids"], "finding_ids", maximum=limit, allowed=refs["finding_ids"]),
        "relationship_ids": _unique_strings(item["relationship_ids"], "relationship_ids", maximum=limit, allowed=refs["relationship_ids"]),
        "action_ids": _unique_strings(item["action_ids"], "action_ids", maximum=limit, allowed=refs["action_ids"]),
        "limitation_codes": _unique_strings(item["limitation_codes"], "limitation_codes", maximum=limit, allowed=allowed_output["limitation_codes"]),
        "reason_codes": _unique_strings(item["reason_codes"], "reason_codes", maximum=limit, allowed=allowed_output["reason_codes"]),
    }
    if result["template_id"] not in set(policy["template_ids"]):
        raise AIAdvisoryContractError("unknown template_id", code="invented_reference")
    requirements = {
        "summarize_selected_findings": bool(result["finding_ids"]),
        "rank_existing_actions": bool(result["action_ids"]),
        "explain_supported_relationships": bool(result["relationship_ids"]),
        "explain_canonical_limitations": bool(result["limitation_codes"]),
    }
    if not requirements.get(result["template_id"], False):
        raise AIAdvisoryContractError("template selection lacks required references")
    return result


def validate_provider_output(
    value: Any,
    *,
    projection: Mapping[str, Any],
    policy: Mapping[str, Any],
    policy_sha256: str,
) -> Dict[str, Any]:
    """Fail closed and return the normalized, separately persisted AI result."""

    _reject_prohibited_output_keys(value)
    root = _exact_keys(value, PROVIDER_OUTPUT_KEYS, "provider output")
    if root["schema_version"] != "ai_provider_output.v1":
        raise AIAdvisoryContractError("provider output schema is invalid")
    if _sha256(root["projection_sha256"], "projection_sha256") != projection.get("projection_sha256"):
        raise AIAdvisoryContractError("projection hash mismatch", code="hash_mismatch")
    if _sha256(root["policy_sha256"], "policy_sha256") != policy_sha256:
        raise AIAdvisoryContractError("policy hash mismatch", code="hash_mismatch")
    refs = _projection_sets(projection)
    limits = policy["limits"]
    allowed_output = projection.get("allowed_output") or {}

    advisory = _exact_keys(root["validated_advisory"], ADVISORY_KEYS, "validated_advisory")
    if advisory["schema_version"] != "ai_validated_advisory_selection.v1":
        raise AIAdvisoryContractError("validated advisory schema is invalid")
    if type(advisory["abstained"]) is not bool:
        raise AIAdvisoryContractError("abstained must be boolean")
    abstention_code = _string(
        advisory["abstention_reason_code"],
        "abstention_reason_code",
        allow_empty=True,
    )
    if abstention_code and abstention_code not in set(allowed_output.get("reason_codes") or []):
        raise AIAdvisoryContractError("unknown abstention reason", code="invented_reference")
    normalized_advisory = {
        "schema_version": "ai_validated_advisory_selection.v1",
        "abstained": advisory["abstained"],
        "abstention_reason_code": abstention_code,
        "selected_finding_ids": _unique_strings(advisory["selected_finding_ids"], "selected_finding_ids", maximum=limits["max_findings"], allowed=refs["finding_ids"]),
        "selected_relationship_ids": _unique_strings(advisory["selected_relationship_ids"], "selected_relationship_ids", maximum=limits["max_relationships"], allowed=refs["relationship_ids"]),
        "ranked_action_ids": _unique_strings(advisory["ranked_action_ids"], "ranked_action_ids", maximum=limits["max_actions"], allowed=refs["action_ids"]),
        "template_selections": [],
    }
    templates = advisory["template_selections"]
    if not isinstance(templates, list) or len(templates) > limits["max_templates"]:
        raise AIAdvisoryContractError("template_selections must be a bounded array")
    normalized_advisory["template_selections"] = [
        _validate_template_selection(
            item,
            index=index,
            policy=policy,
            refs=refs,
            allowed_output=allowed_output,
        )
        for index, item in enumerate(templates)
    ]
    selected_from_templates = {
        "selected_finding_ids": {ref for item in normalized_advisory["template_selections"] for ref in item["finding_ids"]},
        "selected_relationship_ids": {ref for item in normalized_advisory["template_selections"] for ref in item["relationship_ids"]},
        "ranked_action_ids": {ref for item in normalized_advisory["template_selections"] for ref in item["action_ids"]},
    }
    for key, template_refs in selected_from_templates.items():
        if not template_refs <= set(normalized_advisory[key]):
            raise AIAdvisoryContractError("template references are not selected")
    has_selection = any(
        normalized_advisory[key]
        for key in ("selected_finding_ids", "selected_relationship_ids", "ranked_action_ids", "template_selections")
    )
    if normalized_advisory["abstained"]:
        if has_selection or not abstention_code:
            raise AIAdvisoryContractError("abstention must contain only a reason code")
    elif not has_selection or abstention_code:
        raise AIAdvisoryContractError("non-abstained advisory requires selections and no abstention reason")

    shadow = _exact_keys(root["shadow_candidates"], SHADOW_SET_KEYS, "shadow_candidates")
    if shadow["schema_version"] != "ai_shadow_candidate_set.v1":
        raise AIAdvisoryContractError("shadow candidate schema is invalid")
    candidates = shadow["candidates"]
    if not isinstance(candidates, list) or len(candidates) > limits["max_shadow_candidates"]:
        raise AIAdvisoryContractError("shadow candidates must be a bounded array")
    normalized_candidates = []
    for index, raw_candidate in enumerate(candidates):
        candidate = _exact_keys(raw_candidate, SHADOW_CANDIDATE_KEYS, f"candidates[{index}]")
        if candidate["status"] != "unverified_ai_candidate":
            raise AIAdvisoryContractError("shadow candidate status is invalid")
        normalized = {
            "candidate_type": _string(candidate["candidate_type"], "candidate_type"),
            "status": "unverified_ai_candidate",
            "premise_finding_ids": _unique_strings(candidate["premise_finding_ids"], "premise_finding_ids", maximum=limits["max_references_per_item"], allowed=refs["finding_ids"]),
            "premise_relationship_ids": _unique_strings(candidate["premise_relationship_ids"], "premise_relationship_ids", maximum=limits["max_references_per_item"], allowed=refs["relationship_ids"]),
            "premise_evidence_refs": _unique_strings(candidate["premise_evidence_refs"], "premise_evidence_refs", maximum=limits["max_references_per_item"], allowed=refs["evidence_refs"]),
            "reason_codes": _unique_strings(candidate["reason_codes"], "reason_codes", maximum=limits["max_references_per_item"], allowed=allowed_output.get("reason_codes") or []),
            "missing_evidence_codes": _unique_strings(candidate["missing_evidence_codes"], "missing_evidence_codes", maximum=limits["max_references_per_item"], allowed=policy["missing_evidence_codes"]),
            "falsifier_codes": _unique_strings(candidate["falsifier_codes"], "falsifier_codes", maximum=limits["max_references_per_item"], allowed=policy["falsifier_codes"]),
        }
        if normalized["candidate_type"] not in set(policy["candidate_types"]):
            raise AIAdvisoryContractError("unknown candidate type", code="invented_reference")
        if not (
            normalized["premise_finding_ids"]
            or normalized["premise_relationship_ids"]
            or normalized["premise_evidence_refs"]
        ):
            raise AIAdvisoryContractError("shadow candidate lacks an evidence premise")
        premise_count = sum(
            len(normalized[key])
            for key in (
                "premise_finding_ids",
                "premise_relationship_ids",
                "premise_evidence_refs",
            )
        )
        if (
            normalized["candidate_type"]
            in {
                "possible_existing_evidence_relationship",
                "possible_behavioral_pattern",
            }
            and premise_count < 2
        ):
            raise AIAdvisoryContractError(
                "relationship or pattern candidate requires multiple premises"
            )
        if not normalized["falsifier_codes"]:
            raise AIAdvisoryContractError("shadow candidate is not falsifiable")
        if (
            "none_identified" in normalized["missing_evidence_codes"]
            and len(normalized["missing_evidence_codes"]) != 1
        ):
            raise AIAdvisoryContractError(
                "none_identified cannot accompany another missing-evidence code"
            )
        normalized["candidate_id"] = stable_id(
            "ai_candidate",
            {
                "projection_sha256": projection["projection_sha256"],
                **normalized,
            },
        )
        normalized_candidates.append(normalized)

    return {
        "schema_version": "ai_advisory_validated_output.v1",
        "projection_sha256": projection["projection_sha256"],
        "policy_sha256": policy_sha256,
        "validated_advisory": normalized_advisory,
        "shadow_candidates": {
            "schema_version": "ai_shadow_candidate_set.v1",
            "candidates": normalized_candidates,
        },
    }
