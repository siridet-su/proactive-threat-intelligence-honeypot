"""Strict Final-F selection-only AI advisory contracts.

This module is additive. Historical v1 contracts remain implemented by
``production.ai_advisory.contracts`` and are not reinterpreted here.
"""

from __future__ import annotations

import hashlib
import json
import re
from copy import deepcopy
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from production.ai_advisory.contracts import (
    AIAdvisoryContractError,
    sha256_json,
)
from production.ai_advisory.projection import validate_ai_advisory_projection_v2
from production.ai_advisory.security import AssessmentAliasScope


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_POLICY_PATH = PROJECT_ROOT / "configs" / "ai_advisory_policy.v2.json"
DEFAULT_PROJECTION_CONTRACT_PATH = (
    PROJECT_ROOT / "evaluation" / "final_f_contract_bundle.v1.json"
)
FROZEN_POLICY_SHA256 = (
    "521d6222f7bfaddb5617a93a03d22a490770dbbcd57c1fc7310496403e3be115"
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ALIAS_RE = re.compile(r"^a_[0-9a-f]{32}$")
SAFE_CODE_RE = re.compile(r"^[a-z][a-z0-9_]{0,127}$")

POLICY_KEYS = {
    "schema_version", "policy_id", "version", "status", "authority",
    "prompt_contract", "step_types", "anchor_types",
    "abstention_reason_codes", "limitation_codes", "evidence_gap_codes",
    "falsifier_codes", "analyst_question_templates",
    "explanation_templates", "limits",
}
AUTHORITY_KEYS = {
    "canonical_authority", "finding_authority", "hypothesis_authority",
    "guidance_authority", "alert_authority", "prediction_authority",
    "automatic_execution",
}
LIMIT_KEYS = {
    "max_chains", "max_relationships", "max_findings", "max_hypotheses",
    "max_actions", "max_limitations", "max_evidence_gaps",
    "max_question_selections", "max_explanation_selections",
    "max_review_plan_steps", "max_references_per_item",
    "max_response_bytes", "max_request_bytes", "max_request_tokens",
}
PROVIDER_OUTPUT_KEYS = {
    "schema_version", "projection_sha256", "policy_sha256", "synthesis",
}
SYNTHESIS_KEYS = {
    "schema_version", "abstained", "abstention_reason_code",
    "selected_chain_ids", "selected_relationship_ids",
    "ranked_finding_ids", "selected_hypothesis_ids", "ranked_action_ids",
    "selected_limitation_codes", "selected_evidence_gap_codes",
    "analyst_question_selections", "explanation_template_selections",
    "review_plan",
}
TEMPLATE_SELECTION_KEYS = {"template_id", "anchor_type", "anchor_id"}
REVIEW_PLAN_KEYS = {
    "order", "step_type", "anchor_type", "anchor_id",
    "related_chain_ids", "related_finding_ids", "related_hypothesis_ids",
    "related_action_ids", "limitation_codes", "evidence_gap_codes",
    "analyst_question_template_ids", "explanation_template_id",
}
VALIDATED_OUTPUT_KEYS = {
    "schema_version", "projection_sha256", "policy_sha256",
    "validation_status", "selection_origin", "synthesis",
    "validated_output_sha256",
}
PROHIBITED_OUTPUT_KEYS = {
    "action", "alerts", "attck", "command", "confidence", "credential",
    "description", "entity_value", "evidence", "finding", "free_text",
    "guidance", "hypothesis", "intent", "objective", "payload", "prose",
    "rationale", "response_action", "severity", "source_ip", "statement",
    "url", "username", "shadow_candidates", "candidate", "candidates",
}
STEP_ANCHOR_TYPES = {
    "review_chain": "chain",
    "review_finding": "finding",
    "test_existing_hypothesis": "hypothesis",
    "perform_manual_check": "action",
    "resolve_evidence_gap": "evidence_gap",
}
EXPLANATION_ANCHOR_TYPES = {
    "explain_chain_and_limits": "chain",
    "explain_finding_priority": "finding",
    "explain_hypothesis_test": "hypothesis",
    "explain_manual_checks": "action",
    "explain_evidence_gaps": "evidence_gap",
}
QUESTION_GAP_TYPES = {
    "ask_for_execution_corroboration": "execution_observation_missing",
    "ask_for_transfer_corroboration": "direct_transfer_event_missing",
    "ask_to_resolve_entity_identity": "resolved_entity_link_missing",
    "ask_to_verify_reported_outcome": "reported_outcome_missing",
}


def _exact(value: Any, keys: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise AIAdvisoryContractError(
            f"{label} violates additionalProperties=false",
            code="additional_or_missing_property",
        )
    return value


def _string(value: Any, label: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value):
        raise AIAdvisoryContractError(f"{label} must be a string")
    if len(value) > 256:
        raise AIAdvisoryContractError(f"{label} is too long")
    return value


def _sha(value: Any, label: str) -> str:
    text = _string(value, label).lower()
    if not SHA256_RE.fullmatch(text):
        raise AIAdvisoryContractError(f"{label} must be a SHA-256")
    return text


def _unique_strings(
    value: Any,
    label: str,
    *,
    maximum: int,
    allowed: Iterable[str] | None = None,
    aliases: bool = False,
) -> list[str]:
    if not isinstance(value, list) or len(value) > maximum:
        raise AIAdvisoryContractError(f"{label} must be a bounded array")
    output = [_string(item, f"{label}[]") for item in value]
    if len(output) != len(set(output)):
        raise AIAdvisoryContractError(
            f"{label} contains duplicates", code="duplicate_output"
        )
    if aliases and any(not ALIAS_RE.fullmatch(item) for item in output):
        raise AIAdvisoryContractError(f"{label} contains an invalid alias")
    if allowed is not None and set(output) - set(allowed):
        raise AIAdvisoryContractError(
            f"{label} contains an invented reference", code="invented_reference"
        )
    return output


def _walk_keys(value: Any):
    if isinstance(value, Mapping):
        for key, item in value.items():
            yield str(key).lower()
            yield from _walk_keys(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk_keys(item)


def _reject_prohibited(value: Any) -> None:
    found = set(_walk_keys(value)).intersection(PROHIBITED_OUTPUT_KEYS)
    if found:
        raise AIAdvisoryContractError(
            f"provider output contains prohibited fields: {sorted(found)}",
            code="prohibited_field",
        )


def load_ai_advisory_policy_v2(
    path: str | Path = "",
) -> tuple[dict[str, Any], str, str]:
    selected = Path(path) if str(path) else DEFAULT_POLICY_PATH
    try:
        raw = selected.read_bytes()
        value = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise AIAdvisoryContractError(
            "AI advisory policy v2 is unavailable", code="policy_unavailable"
        ) from exc
    sha = hashlib.sha256(raw).hexdigest()
    if sha != FROZEN_POLICY_SHA256:
        raise AIAdvisoryContractError("AI advisory policy v2 identity mismatch")
    policy = dict(_exact(value, POLICY_KEYS, "AI advisory policy v2"))
    if (
        policy["schema_version"] != "ai_advisory_policy.v2"
        or policy["policy_id"] != "cowrie-chronological-graph-synthesis"
        or policy["version"] != "2.0.0-proposed-phase0"
        or policy["status"] != "proposed_not_runtime_active"
    ):
        raise AIAdvisoryContractError("AI advisory policy v2 metadata is invalid")
    authority = _exact(policy["authority"], AUTHORITY_KEYS, "policy authority")
    if any(authority[key] is not False for key in AUTHORITY_KEYS):
        raise AIAdvisoryContractError("AI advisory policy v2 grants authority")
    prompts = policy["prompt_contract"]
    if (
        not isinstance(prompts, list)
        or not prompts
        or len(prompts) != len(set(prompts))
        or any(not isinstance(item, str) or not item or len(item) > 512 for item in prompts)
    ):
        raise AIAdvisoryContractError("AI advisory prompt contract is invalid")
    for key in (
        "step_types", "anchor_types", "abstention_reason_codes",
        "limitation_codes", "evidence_gap_codes", "falsifier_codes",
    ):
        values = _unique_strings(policy[key], key, maximum=128)
        if any(not SAFE_CODE_RE.fullmatch(item) for item in values):
            raise AIAdvisoryContractError(f"AI policy {key} contains an invalid code")
    if policy["step_types"] != list(STEP_ANCHOR_TYPES):
        raise AIAdvisoryContractError("AI policy step types are invalid")
    if set(policy["anchor_types"]) != set(STEP_ANCHOR_TYPES.values()):
        raise AIAdvisoryContractError("AI policy anchor types are invalid")
    for key in ("analyst_question_templates", "explanation_templates"):
        templates = policy[key]
        if (
            not isinstance(templates, Mapping)
            or not templates
            or any(
                not SAFE_CODE_RE.fullmatch(str(template_id))
                or not isinstance(text, str)
                or not text
                or len(text) > 1024
                for template_id, text in templates.items()
            )
        ):
            raise AIAdvisoryContractError(f"AI policy {key} is invalid")
    if set(policy["analyst_question_templates"]) != set(QUESTION_GAP_TYPES):
        raise AIAdvisoryContractError("AI policy question catalog is invalid")
    if set(policy["explanation_templates"]) != set(EXPLANATION_ANCHOR_TYPES):
        raise AIAdvisoryContractError("AI policy explanation catalog is invalid")
    limits = _exact(policy["limits"], LIMIT_KEYS, "AI policy limits")
    if any(type(limits[key]) is not int or not 1 <= limits[key] <= 65536 for key in LIMIT_KEYS):
        raise AIAdvisoryContractError("AI policy limits are invalid")
    return deepcopy(policy), sha, str(selected.resolve())


def _string_array_schema(
    maximum: int,
    *,
    enum: Sequence[str] | None = None,
    aliases: bool = False,
) -> dict[str, Any]:
    item: dict[str, Any] = {"type": "string", "minLength": 1, "maxLength": 256}
    if enum is not None:
        item["enum"] = list(enum)
    if aliases:
        item["pattern"] = "^a_[0-9a-f]{32}$"
    return {
        "type": "array", "maxItems": maximum, "uniqueItems": True,
        "items": item,
    }


def provider_output_json_schema_v2(policy: Mapping[str, Any]) -> dict[str, Any]:
    limits = policy["limits"]
    reference_limit = int(limits["max_references_per_item"])
    alias_array = lambda maximum: _string_array_schema(maximum, aliases=True)
    code_array = lambda maximum, values: _string_array_schema(maximum, enum=values)
    selection = {
        "type": "object", "additionalProperties": False,
        "required": sorted(TEMPLATE_SELECTION_KEYS),
        "properties": {
            "template_id": {"type": "string"},
            "anchor_type": {"type": "string", "enum": policy["anchor_types"]},
            "anchor_id": {"type": "string", "minLength": 1, "maxLength": 256},
        },
    }
    plan_item = {
        "type": "object", "additionalProperties": False,
        "required": sorted(REVIEW_PLAN_KEYS),
        "properties": {
            "order": {"type": "integer", "minimum": 1},
            "step_type": {"type": "string", "enum": policy["step_types"]},
            "anchor_type": {"type": "string", "enum": policy["anchor_types"]},
            "anchor_id": {"type": "string", "minLength": 1, "maxLength": 256},
            "related_chain_ids": alias_array(reference_limit),
            "related_finding_ids": alias_array(reference_limit),
            "related_hypothesis_ids": alias_array(reference_limit),
            "related_action_ids": alias_array(reference_limit),
            "limitation_codes": code_array(reference_limit, policy["limitation_codes"]),
            "evidence_gap_codes": code_array(reference_limit, policy["evidence_gap_codes"]),
            "analyst_question_template_ids": code_array(
                reference_limit, list(policy["analyst_question_templates"])
            ),
            "explanation_template_id": {
                "type": "string", "enum": ["", *policy["explanation_templates"]]
            },
        },
    }
    synthesis = {
        "type": "object", "additionalProperties": False,
        "required": sorted(SYNTHESIS_KEYS),
        "properties": {
            "schema_version": {"const": "ai_advisory_synthesis_selection.v2"},
            "abstained": {"type": "boolean"},
            "abstention_reason_code": {
                "type": "string", "enum": ["", *policy["abstention_reason_codes"]]
            },
            "selected_chain_ids": alias_array(int(limits["max_chains"])),
            "selected_relationship_ids": alias_array(int(limits["max_relationships"])),
            "ranked_finding_ids": alias_array(int(limits["max_findings"])),
            "selected_hypothesis_ids": alias_array(int(limits["max_hypotheses"])),
            "ranked_action_ids": alias_array(int(limits["max_actions"])),
            "selected_limitation_codes": code_array(
                int(limits["max_limitations"]), policy["limitation_codes"]
            ),
            "selected_evidence_gap_codes": code_array(
                int(limits["max_evidence_gaps"]), policy["evidence_gap_codes"]
            ),
            "analyst_question_selections": {
                "type": "array", "maxItems": limits["max_question_selections"],
                "items": selection,
            },
            "explanation_template_selections": {
                "type": "array", "maxItems": limits["max_explanation_selections"],
                "items": selection,
            },
            "review_plan": {
                "type": "array", "maxItems": limits["max_review_plan_steps"],
                "items": plan_item,
            },
        },
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "urn:honeypot-analysis:ai-provider-output:v2",
        "title": "Selection-only chronological graph synthesis output",
        "type": "object", "additionalProperties": False,
        "required": sorted(PROVIDER_OUTPUT_KEYS),
        "properties": {
            "schema_version": {"const": "ai_provider_output.v2"},
            "projection_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "policy_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "synthesis": synthesis,
        },
    }


def contract_schema_sha256_v2(policy: Mapping[str, Any]) -> str:
    return sha256_json(provider_output_json_schema_v2(policy))


def _validated_projection(
    projection: Mapping[str, Any],
    *,
    report: Mapping[str, Any],
    alias_scope: AssessmentAliasScope,
    policy_path: str | Path,
    projection_contract_path: str | Path,
) -> dict[str, Any]:
    return validate_ai_advisory_projection_v2(
        projection,
        report=report,
        alias_scope=alias_scope,
        ai_policy_path=str(policy_path),
        projection_contract_path=str(projection_contract_path),
    )


def _projection_indexes(projection: Mapping[str, Any]) -> dict[str, Any]:
    indexes = {
        name: {item[id_key]: item for item in projection[name]}
        for name, id_key in (
            ("chains", "chain_id"), ("relationships", "relationship_id"),
            ("findings", "finding_id"), ("hypotheses", "hypothesis_id"),
            ("actions", "action_id"),
        )
    }
    return indexes


def _anchor_domains(
    selected: Mapping[str, list[str]],
) -> dict[str, set[str]]:
    return {
        "chain": set(selected["selected_chain_ids"]),
        "finding": set(selected["ranked_finding_ids"]),
        "hypothesis": set(selected["selected_hypothesis_ids"]),
        "action": set(selected["ranked_action_ids"]),
        "evidence_gap": set(selected["selected_evidence_gap_codes"]),
    }


def _object_codes(item: Mapping[str, Any]) -> tuple[set[str], set[str]]:
    return set(item.get("limitation_codes") or []), set(
        item.get("evidence_gap_codes") or []
    )


def _object_tokens(kind: str, item: Mapping[str, Any]) -> set[str]:
    fields = {
        "chain": ("chain_id", "fact_ids", "relationship_ids", "evidence_ids"),
        "finding": ("finding_id", "chain_ids", "relationship_ids", "evidence_ids"),
        "hypothesis": (
            "hypothesis_id", "chain_ids", "relationship_ids", "fact_ids",
            "evidence_ids",
        ),
        "action": ("action_id", "finding_ids", "evidence_ids"),
    }[kind]
    tokens = {f"{kind}:{item[fields[0]]}"}
    for field in fields[1:]:
        token_kind = field.removesuffix("_ids")
        tokens.update(f"{token_kind}:{ref}" for ref in item.get(field) or [])
    return tokens


def _validate_selection_grounding(
    selected: Mapping[str, list[str]],
    indexes: Mapping[str, Mapping[str, Mapping[str, Any]]],
) -> tuple[set[str], set[str]]:
    chains = [indexes["chains"][item] for item in selected["selected_chain_ids"]]
    relationships = [
        indexes["relationships"][item]
        for item in selected["selected_relationship_ids"]
    ]
    findings = [indexes["findings"][item] for item in selected["ranked_finding_ids"]]
    hypotheses = [
        indexes["hypotheses"][item]
        for item in selected["selected_hypothesis_ids"]
    ]
    actions = [indexes["actions"][item] for item in selected["ranked_action_ids"]]
    selected_chains = set(selected["selected_chain_ids"])
    selected_relationships = set(selected["selected_relationship_ids"])
    selected_findings = set(selected["ranked_finding_ids"])

    if any(not item["ai_eligible"] for item in chains):
        raise AIAdvisoryContractError("selected chain is not AI-eligible")
    grounded_relationships = {
        ref for item in [*chains, *findings, *hypotheses]
        for ref in item.get("relationship_ids") or []
    }
    if selected_relationships - grounded_relationships:
        raise AIAdvisoryContractError("selected relationship is not grounded")
    if selected_chains:
        for finding in findings:
            if finding["chain_ids"] and not selected_chains.intersection(
                finding["chain_ids"]
            ):
                raise AIAdvisoryContractError("selected finding is unrelated to chain")
    for hypothesis in hypotheses:
        if not (
            selected_chains.intersection(hypothesis["chain_ids"])
            or selected_relationships.intersection(hypothesis["relationship_ids"])
        ):
            raise AIAdvisoryContractError("selected hypothesis is not graph-grounded")
    for action in actions:
        if not selected_findings.intersection(action["finding_ids"]):
            raise AIAdvisoryContractError("selected action is not finding-grounded")

    limitations: set[str] = set()
    gaps: set[str] = set()
    for item in [*chains, *relationships, *findings, *hypotheses]:
        item_limitations, item_gaps = _object_codes(item)
        limitations.update(item_limitations)
        gaps.update(item_gaps)
    if set(selected["selected_limitation_codes"]) - limitations:
        raise AIAdvisoryContractError("selected limitation is not object-grounded")
    if set(selected["selected_evidence_gap_codes"]) - gaps:
        raise AIAdvisoryContractError("selected evidence gap is not object-grounded")
    return limitations, gaps


def _validate_template_selections(
    raw: Any,
    *,
    label: str,
    maximum: int,
    templates: Mapping[str, str],
    selected_anchors: Mapping[str, set[str]],
    explanation: bool,
) -> list[dict[str, str]]:
    if not isinstance(raw, list) or len(raw) > maximum:
        raise AIAdvisoryContractError(f"{label} must be a bounded array")
    output = []
    seen = set()
    for index, raw_item in enumerate(raw):
        item = _exact(raw_item, TEMPLATE_SELECTION_KEYS, f"{label}[{index}]")
        template_id = _string(item["template_id"], f"{label}.template_id")
        anchor_type = _string(item["anchor_type"], f"{label}.anchor_type")
        anchor_id = _string(item["anchor_id"], f"{label}.anchor_id")
        if template_id not in templates:
            raise AIAdvisoryContractError(
                f"{label} uses an unreviewed template", code="invented_reference"
            )
        if anchor_type not in selected_anchors or anchor_id not in selected_anchors[anchor_type]:
            raise AIAdvisoryContractError(f"{label} anchor is not selected")
        if explanation:
            if EXPLANATION_ANCHOR_TYPES.get(template_id) != anchor_type:
                raise AIAdvisoryContractError("explanation template anchor is invalid")
        else:
            expected_gap = QUESTION_GAP_TYPES.get(template_id)
            if anchor_type == "evidence_gap":
                if anchor_id != expected_gap:
                    raise AIAdvisoryContractError("question gap anchor is invalid")
            elif anchor_type == "hypothesis":
                pass
            else:
                raise AIAdvisoryContractError("question anchor type is invalid")
        identity = (template_id, anchor_type, anchor_id)
        if identity in seen:
            raise AIAdvisoryContractError(
                f"{label} contains duplicates", code="duplicate_output"
            )
        seen.add(identity)
        output.append({
            "template_id": template_id,
            "anchor_type": anchor_type,
            "anchor_id": anchor_id,
        })
    return output


def _validate_review_plan(
    raw: Any,
    *,
    policy: Mapping[str, Any],
    selected: Mapping[str, list[str]],
    question_selections: list[dict[str, str]],
    explanation_selections: list[dict[str, str]],
) -> list[dict[str, Any]]:
    if not isinstance(raw, list) or len(raw) > policy["limits"]["max_review_plan_steps"]:
        raise AIAdvisoryContractError("review plan must be a bounded array")
    if [item.get("order") for item in raw if isinstance(item, Mapping)] != list(
        range(1, len(raw) + 1)
    ):
        raise AIAdvisoryContractError("review plan order must be contiguous")
    anchors = _anchor_domains(selected)
    related_domains = {
        "related_chain_ids": anchors["chain"],
        "related_finding_ids": anchors["finding"],
        "related_hypothesis_ids": anchors["hypothesis"],
        "related_action_ids": anchors["action"],
        "limitation_codes": set(selected["selected_limitation_codes"]),
        "evidence_gap_codes": anchors["evidence_gap"],
    }
    question_ids = {item["template_id"] for item in question_selections}
    explanations = {
        (item["template_id"], item["anchor_type"], item["anchor_id"])
        for item in explanation_selections
    }
    output = []
    reference_limit = policy["limits"]["max_references_per_item"]
    for index, raw_item in enumerate(raw):
        item = _exact(raw_item, REVIEW_PLAN_KEYS, f"review_plan[{index}]")
        step_type = _string(item["step_type"], "review plan step_type")
        anchor_type = _string(item["anchor_type"], "review plan anchor_type")
        anchor_id = _string(item["anchor_id"], "review plan anchor_id")
        if STEP_ANCHOR_TYPES.get(step_type) != anchor_type:
            raise AIAdvisoryContractError("review plan step/anchor types mismatch")
        if anchor_id not in anchors.get(anchor_type, set()):
            raise AIAdvisoryContractError("review plan anchor is not selected")
        normalized: dict[str, Any] = {
            "order": item["order"], "step_type": step_type,
            "anchor_type": anchor_type, "anchor_id": anchor_id,
        }
        for key, domain in related_domains.items():
            normalized[key] = _unique_strings(
                item[key], f"review_plan[{index}].{key}", maximum=reference_limit,
                allowed=domain, aliases=key.startswith("related_"),
            )
        anchor_field = {
            "chain": "related_chain_ids", "finding": "related_finding_ids",
            "hypothesis": "related_hypothesis_ids", "action": "related_action_ids",
            "evidence_gap": "evidence_gap_codes",
        }[anchor_type]
        if anchor_id not in normalized[anchor_field]:
            raise AIAdvisoryContractError("review plan does not include its anchor")
        normalized["analyst_question_template_ids"] = _unique_strings(
            item["analyst_question_template_ids"],
            f"review_plan[{index}].analyst_question_template_ids",
            maximum=reference_limit, allowed=question_ids,
        )
        explanation_id = _string(
            item["explanation_template_id"],
            f"review_plan[{index}].explanation_template_id", allow_empty=True,
        )
        if explanation_id and (explanation_id, anchor_type, anchor_id) not in explanations:
            raise AIAdvisoryContractError("review plan explanation is not grounded")
        normalized["explanation_template_id"] = explanation_id
        output.append(normalized)
    return output


def _validate_plan_object_grounding(
    plan: Sequence[Mapping[str, Any]],
    indexes: Mapping[str, Mapping[str, Mapping[str, Any]]],
) -> None:
    names = {
        "chain": "chains", "finding": "findings",
        "hypothesis": "hypotheses", "action": "actions",
    }
    related = {
        "related_chain_ids": "chain", "related_finding_ids": "finding",
        "related_hypothesis_ids": "hypothesis", "related_action_ids": "action",
    }
    for index, step in enumerate(plan):
        anchor_type = step["anchor_type"]
        associated = []
        if anchor_type != "evidence_gap":
            anchor = indexes[names[anchor_type]][step["anchor_id"]]
            anchor_tokens = _object_tokens(anchor_type, anchor)
        else:
            anchor = None
            anchor_tokens = set()
        for field, kind in related.items():
            for ref in step[field]:
                item = indexes[names[kind]][ref]
                associated.append(item)
                if anchor is not None and ref != step["anchor_id"]:
                    if not anchor_tokens.intersection(_object_tokens(kind, item)):
                        raise AIAdvisoryContractError(
                            f"review plan item {index} contains an unrelated object"
                        )
        objects = ([anchor] if anchor is not None else []) + associated
        limitation_domain = {
            code for item in objects if item is not None
            for code in item.get("limitation_codes") or []
        }
        gap_domain = {
            code for item in objects if item is not None
            for code in item.get("evidence_gap_codes") or []
        }
        if anchor_type == "evidence_gap":
            gap_domain.add(step["anchor_id"])
        if set(step["limitation_codes"]) - limitation_domain:
            raise AIAdvisoryContractError(
                f"review plan item {index} limitation is not grounded"
            )
        if set(step["evidence_gap_codes"]) - gap_domain:
            raise AIAdvisoryContractError(
                f"review plan item {index} evidence gap is not grounded"
            )


def _require_plan_coverage(
    selected: Mapping[str, list[str]],
    plan: Sequence[Mapping[str, Any]],
    questions: Sequence[Mapping[str, str]],
    explanations: Sequence[Mapping[str, str]],
) -> None:
    covered = {
        "selected_chain_ids": {
            ref for item in plan for ref in item["related_chain_ids"]
        },
        "ranked_finding_ids": {
            ref for item in plan for ref in item["related_finding_ids"]
        },
        "selected_hypothesis_ids": {
            ref for item in plan for ref in item["related_hypothesis_ids"]
        },
        "ranked_action_ids": {
            ref for item in plan for ref in item["related_action_ids"]
        },
        "selected_limitation_codes": {
            ref for item in plan for ref in item["limitation_codes"]
        },
        "selected_evidence_gap_codes": {
            ref for item in plan for ref in item["evidence_gap_codes"]
        },
    }
    for key, values in covered.items():
        if set(selected[key]) - values:
            raise AIAdvisoryContractError(f"review plan omits selected {key}")
    used_questions = {
        template for item in plan for template in item["analyst_question_template_ids"]
    }
    if {item["template_id"] for item in questions} - used_questions:
        raise AIAdvisoryContractError("review plan omits a question selection")
    used_explanations = {
        item["explanation_template_id"] for item in plan
        if item["explanation_template_id"]
    }
    if {item["template_id"] for item in explanations} - used_explanations:
        raise AIAdvisoryContractError("review plan omits an explanation selection")


def _normalize_synthesis(
    raw: Any,
    *,
    projection: Mapping[str, Any],
    policy: Mapping[str, Any],
) -> dict[str, Any]:
    synthesis = _exact(raw, SYNTHESIS_KEYS, "provider synthesis")
    if synthesis["schema_version"] != "ai_advisory_synthesis_selection.v2":
        raise AIAdvisoryContractError("provider synthesis schema is invalid")
    if type(synthesis["abstained"]) is not bool:
        raise AIAdvisoryContractError("synthesis.abstained must be boolean")
    limits = policy["limits"]
    allowed = projection["allowed_output"]
    fields = {
        "selected_chain_ids": ("chain_ids", "max_chains", True),
        "selected_relationship_ids": ("relationship_ids", "max_relationships", True),
        "ranked_finding_ids": ("finding_ids", "max_findings", True),
        "selected_hypothesis_ids": ("hypothesis_ids", "max_hypotheses", True),
        "ranked_action_ids": ("action_ids", "max_actions", True),
        "selected_limitation_codes": ("limitation_codes", "max_limitations", False),
        "selected_evidence_gap_codes": ("evidence_gap_codes", "max_evidence_gaps", False),
    }
    selected = {
        key: _unique_strings(
            synthesis[key], key, maximum=limits[limit_key],
            allowed=allowed[domain], aliases=aliases,
        )
        for key, (domain, limit_key, aliases) in fields.items()
    }
    reason = _string(
        synthesis["abstention_reason_code"], "abstention_reason_code",
        allow_empty=True,
    )
    selected_anchors = _anchor_domains(selected)
    indexes = _projection_indexes(projection)
    questions = _validate_template_selections(
        synthesis["analyst_question_selections"],
        label="analyst_question_selections",
        maximum=limits["max_question_selections"],
        templates=policy["analyst_question_templates"],
        selected_anchors=selected_anchors,
        explanation=False,
    )
    explanations = _validate_template_selections(
        synthesis["explanation_template_selections"],
        label="explanation_template_selections",
        maximum=limits["max_explanation_selections"],
        templates=policy["explanation_templates"],
        selected_anchors=selected_anchors,
        explanation=True,
    )
    for item in questions:
        if item["anchor_type"] != "hypothesis":
            continue
        expected_gap = QUESTION_GAP_TYPES[item["template_id"]]
        hypothesis = indexes["hypotheses"][item["anchor_id"]]
        if expected_gap not in set(hypothesis["evidence_gap_codes"]):
            raise AIAdvisoryContractError(
                "question is unrelated to the selected hypothesis"
            )
    plan = _validate_review_plan(
        synthesis["review_plan"], policy=policy, selected=selected,
        question_selections=questions, explanation_selections=explanations,
    )
    if synthesis["abstained"]:
        if reason not in allowed["abstention_reason_codes"]:
            raise AIAdvisoryContractError("abstention reason is not allowed")
        if any(selected.values()) or questions or explanations or plan:
            raise AIAdvisoryContractError("abstention must contain no selections")
    else:
        if reason:
            raise AIAdvisoryContractError("non-abstention must have no reason")
        if not (selected["selected_chain_ids"] or len(selected["ranked_finding_ids"]) >= 2):
            raise AIAdvisoryContractError("synthesis lacks primary context")
        if not plan:
            raise AIAdvisoryContractError("non-abstention requires a review plan")
        _validate_selection_grounding(selected, indexes)
        _validate_plan_object_grounding(plan, indexes)
        _require_plan_coverage(selected, plan, questions, explanations)
    return {
        "schema_version": "ai_advisory_synthesis_selection.v2",
        "abstained": synthesis["abstained"],
        "abstention_reason_code": reason,
        **selected,
        "analyst_question_selections": questions,
        "explanation_template_selections": explanations,
        "review_plan": plan,
    }


def _validated_output(
    *,
    projection_sha256: str,
    policy_sha256: str,
    origin: str,
    synthesis: Mapping[str, Any],
) -> dict[str, Any]:
    base = {
        "schema_version": "ai_advisory_validated_output.v2",
        "projection_sha256": projection_sha256,
        "policy_sha256": policy_sha256,
        "validation_status": "accepted",
        "selection_origin": origin,
        "synthesis": deepcopy(dict(synthesis)),
    }
    return {**base, "validated_output_sha256": sha256_json(base)}


def validate_provider_output_v2(
    value: Any,
    *,
    projection: Mapping[str, Any],
    report: Mapping[str, Any],
    alias_scope: AssessmentAliasScope,
    policy_path: str | Path = DEFAULT_POLICY_PATH,
    projection_contract_path: str | Path = DEFAULT_PROJECTION_CONTRACT_PATH,
) -> dict[str, Any]:
    """Validate provider selection and return a content-bound local result."""

    policy, policy_sha, _ = load_ai_advisory_policy_v2(policy_path)
    current = _validated_projection(
        projection, report=report, alias_scope=alias_scope,
        policy_path=policy_path,
        projection_contract_path=projection_contract_path,
    )
    try:
        response_bytes = json.dumps(value, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise AIAdvisoryContractError("provider output is not JSON") from exc
    if len(response_bytes) > policy["limits"]["max_response_bytes"]:
        raise AIAdvisoryContractError("provider output exceeds response limit")
    _reject_prohibited(value)
    root = _exact(value, PROVIDER_OUTPUT_KEYS, "provider output v2")
    if root["schema_version"] != "ai_provider_output.v2":
        raise AIAdvisoryContractError("provider output v2 schema is invalid")
    if _sha(root["projection_sha256"], "projection_sha256") != current["projection_sha256"]:
        raise AIAdvisoryContractError("projection hash mismatch", code="hash_mismatch")
    if _sha(root["policy_sha256"], "policy_sha256") != policy_sha:
        raise AIAdvisoryContractError("policy hash mismatch", code="hash_mismatch")
    synthesis = _normalize_synthesis(root["synthesis"], projection=current, policy=policy)
    return _validated_output(
        projection_sha256=current["projection_sha256"],
        policy_sha256=policy_sha,
        origin="provider",
        synthesis=synthesis,
    )


def build_deterministic_abstention_v2(
    *,
    projection: Mapping[str, Any],
    report: Mapping[str, Any],
    alias_scope: AssessmentAliasScope,
    reason_code: str,
    policy_path: str | Path = DEFAULT_POLICY_PATH,
    projection_contract_path: str | Path = DEFAULT_PROJECTION_CONTRACT_PATH,
) -> dict[str, Any]:
    """Build the local no-provider abstention defined by the frozen policy."""

    policy, policy_sha, _ = load_ai_advisory_policy_v2(policy_path)
    current = _validated_projection(
        projection, report=report, alias_scope=alias_scope,
        policy_path=policy_path,
        projection_contract_path=projection_contract_path,
    )
    raw = {
        "schema_version": "ai_advisory_synthesis_selection.v2",
        "abstained": True,
        "abstention_reason_code": reason_code,
        "selected_chain_ids": [], "selected_relationship_ids": [],
        "ranked_finding_ids": [], "selected_hypothesis_ids": [],
        "ranked_action_ids": [], "selected_limitation_codes": [],
        "selected_evidence_gap_codes": [], "analyst_question_selections": [],
        "explanation_template_selections": [], "review_plan": [],
    }
    synthesis = _normalize_synthesis(raw, projection=current, policy=policy)
    return _validated_output(
        projection_sha256=current["projection_sha256"],
        policy_sha256=policy_sha,
        origin="deterministic_no_call",
        synthesis=synthesis,
    )


def validate_validated_output_v2(
    value: Any,
    *,
    projection: Mapping[str, Any],
    report: Mapping[str, Any],
    alias_scope: AssessmentAliasScope,
    policy_path: str | Path = DEFAULT_POLICY_PATH,
    projection_contract_path: str | Path = DEFAULT_PROJECTION_CONTRACT_PATH,
) -> dict[str, Any]:
    policy, policy_sha, _ = load_ai_advisory_policy_v2(policy_path)
    current = _validated_projection(
        projection, report=report, alias_scope=alias_scope,
        policy_path=policy_path,
        projection_contract_path=projection_contract_path,
    )
    root = _exact(value, VALIDATED_OUTPUT_KEYS, "validated output v2")
    if (
        root["schema_version"] != "ai_advisory_validated_output.v2"
        or root["validation_status"] != "accepted"
        or root["selection_origin"] not in {"provider", "deterministic_no_call"}
        or root["projection_sha256"] != current["projection_sha256"]
        or root["policy_sha256"] != policy_sha
    ):
        raise AIAdvisoryContractError("validated output v2 identity is invalid")
    synthesis = _normalize_synthesis(root["synthesis"], projection=current, policy=policy)
    if root["selection_origin"] == "deterministic_no_call" and not synthesis["abstained"]:
        raise AIAdvisoryContractError("deterministic output must abstain")
    expected = _validated_output(
        projection_sha256=current["projection_sha256"],
        policy_sha256=policy_sha,
        origin=root["selection_origin"],
        synthesis=synthesis,
    )
    if dict(root) != expected:
        raise AIAdvisoryContractError("validated output v2 content hash mismatch")
    return expected


__all__ = [
    "DEFAULT_POLICY_PATH", "DEFAULT_PROJECTION_CONTRACT_PATH",
    "FROZEN_POLICY_SHA256", "build_deterministic_abstention_v2",
    "contract_schema_sha256_v2", "load_ai_advisory_policy_v2",
    "provider_output_json_schema_v2", "validate_provider_output_v2",
    "validate_validated_output_v2",
]
