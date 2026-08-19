"""Deterministic server-side prose for accepted identifier selections."""

from __future__ import annotations

from typing import Any, Dict, Mapping

from production.ai_advisory.contracts import AIAdvisoryContractError, sha256_json
from production.utils.sensitive_data import redact_for_api
from production.utils.serialization import stable_json


def _validate_rendered_privacy(value: Mapping[str, Any]) -> None:
    """Reject rendered text that the central public privacy policy would redact.

    Canonical statements are already trusted for deterministic analysis, but
    they can contain context values that must not unexpectedly appear in a
    separately persisted AI advisory.  Comparing against the central redactor
    makes this boundary fail closed without changing the canonical report.
    """
    redacted = redact_for_api(value)
    if stable_json(redacted) != stable_json(value):
        raise AIAdvisoryContractError(
            "rendered advisory contains privacy-sensitive content",
            code="rendered_privacy_violation",
        )


def _index(values: Any, key: str) -> Dict[str, Mapping[str, Any]]:
    return {
        str(item.get(key)): item
        for item in values or []
        if isinstance(item, Mapping) and item.get(key)
    }


def render_validated_advisory(
    validated_output: Mapping[str, Any],
    *,
    report: Mapping[str, Any],
    policy: Mapping[str, Any],
) -> Dict[str, Any]:
    """Render policy-authored prose; provider prose is never accepted."""

    advisory = validated_output.get("validated_advisory") or {}
    if advisory.get("abstained") is True:
        result = {
            "schema_version": "ai_advisory_rendered.v1",
            "status": "abstained",
            "abstention_reason_code": str(advisory.get("abstention_reason_code") or ""),
            "paragraphs": [],
        }
        _validate_rendered_privacy(result)
        return {**result, "render_sha256": sha256_json(result)}

    findings = _index(report.get("behavioral_findings"), "finding_id")
    guidance = report.get("response_guidance_v3") or {}
    findings.update(_index(guidance.get("findings"), "finding_id"))
    actions = _index(guidance.get("advisory_actions"), "action_id")
    templates = policy.get("templates") or {}
    paragraphs = []
    for selection in advisory.get("template_selections") or []:
        template_id = str(selection.get("template_id") or "")
        template = templates.get(template_id)
        if not isinstance(template, str):
            raise AIAdvisoryContractError("accepted template is unavailable")
        finding_types = [
            str(findings[item].get("finding_type") or "canonical_finding")
            for item in selection.get("finding_ids") or []
            if item in findings
        ]
        action_descriptions = [
            # Action descriptions can contain deployment-specific values such
            # as source IPs.  Render the already approved stable action ID;
            # the existing canonical guidance remains the detail source.
            str(actions[item].get("action_id") or item)
            for item in selection.get("action_ids") or []
            if item in actions
        ]
        substitutions = {
            "finding_count": len(finding_types),
            # Only the validated, stable semantic family is substituted.  Do
            # not render canonical statements or evidence values: those may
            # contain attacker-controlled commands or deployment context.
            "finding_types": "; ".join(finding_types) or "none",
            "action_descriptions": "; ".join(action_descriptions) or "none",
            # Relationship labels are canonical context, not a closed
            # vocabulary.  Render only the count so an unexpected value can
            # never cross the advisory output boundary.
            "relationship_count": len(selection.get("relationship_ids") or []),
            "limitation_labels": ", ".join(selection.get("limitation_codes") or []) or "none",
        }
        try:
            text = template.format(**substitutions)
        except (KeyError, ValueError) as exc:
            raise AIAdvisoryContractError("policy template cannot be rendered") from exc
        paragraphs.append(
            {
                "template_id": template_id,
                "text": text,
                "finding_ids": list(selection.get("finding_ids") or []),
                "relationship_ids": list(selection.get("relationship_ids") or []),
                "action_ids": list(selection.get("action_ids") or []),
                "limitation_codes": list(selection.get("limitation_codes") or []),
                "reason_codes": list(selection.get("reason_codes") or []),
            }
        )
    result = {
        "schema_version": "ai_advisory_rendered.v1",
        "status": "rendered",
        "abstention_reason_code": "",
        "paragraphs": paragraphs,
    }
    _validate_rendered_privacy(result)
    return {**result, "render_sha256": sha256_json(result)}


V2_RENDERED_SCHEMA = "ai_advisory_rendered.v2"
_V2_SECTION_HEADINGS = {
    "chains": "AI-selected deterministic chains",
    "findings": "AI-selected canonical findings",
    "hypotheses": "Existing bounded hypotheses to test",
    "actions": "Policy-approved manual analyst checks",
    "limitations": "Recorded deterministic limitations",
    "evidence_gaps": "Recorded evidence gaps",
    "questions": "Suggested analyst questions",
}


def _v2_policy_text(
    policy: Mapping[str, Any],
    template_id: str,
    *,
    question: bool = False,
) -> str:
    catalog_key = "analyst_question_templates" if question else "explanation_templates"
    catalog = policy.get(catalog_key)
    if not isinstance(catalog, Mapping) or template_id not in catalog:
        raise AIAdvisoryContractError("v2 renderer template is unavailable")
    text = catalog[template_id]
    if not isinstance(text, str) or not text:
        raise AIAdvisoryContractError("v2 renderer template is invalid")
    return text


def _v2_item(object_type: str, object_id: str, *, label: str = "") -> dict[str, str]:
    # IDs are assessment-scoped HMAC aliases, and labels are fixed vocabulary
    # words.  No report statement/entity/command is copied into the rendering.
    return {
        "object_type": object_type,
        "object_id": str(object_id),
        "label": label or object_type,
    }


def render_validated_advisory_v2(
    validated_output: Mapping[str, Any],
    *,
    projection: Mapping[str, Any],
    policy: Mapping[str, Any],
) -> Dict[str, Any]:
    """Render v2 selections using only policy-owned text and opaque aliases."""

    if validated_output.get("schema_version") != "ai_advisory_validated_output.v2":
        raise AIAdvisoryContractError("v2 renderer requires validated output v2")
    synthesis = validated_output.get("synthesis")
    if not isinstance(synthesis, Mapping):
        raise AIAdvisoryContractError("v2 validated synthesis is missing")
    if projection.get("projection_sha256") != validated_output.get("projection_sha256"):
        raise AIAdvisoryContractError("v2 rendered projection identity mismatch")

    if synthesis.get("abstained") is True:
        result: Dict[str, Any] = {
            "schema_version": V2_RENDERED_SCHEMA,
            "status": "abstained",
            "abstention_reason_code": str(
                synthesis.get("abstention_reason_code") or ""
            ),
            "sections": [],
            "review_plan": [],
        }
        _validate_rendered_privacy(result)
        return {**result, "render_sha256": sha256_json(result)}

    sections: list[dict[str, Any]] = []
    collections = (
        ("chains", "selected_chain_ids", "chain"),
        ("findings", "ranked_finding_ids", "finding"),
        ("hypotheses", "selected_hypothesis_ids", "hypothesis"),
        ("actions", "ranked_action_ids", "action"),
        ("limitations", "selected_limitation_codes", "limitation"),
        ("evidence_gaps", "selected_evidence_gap_codes", "evidence_gap"),
    )
    for section_id, field, object_type in collections:
        values = synthesis.get(field) or []
        if not values:
            continue
        sections.append(
            {
                "section_id": section_id,
                "heading": _V2_SECTION_HEADINGS[section_id],
                "items": [
                    _v2_item(object_type, value, label=object_type)
                    for value in values
                ],
            }
        )

    question_text = {
        item["template_id"]: _v2_policy_text(
            policy, item["template_id"], question=True
        )
        for item in synthesis.get("analyst_question_selections") or []
    }
    if question_text:
        sections.append(
            {
                "section_id": "questions",
                "heading": _V2_SECTION_HEADINGS["questions"],
                "items": [
                    {
                        "template_id": template_id,
                        "anchor_type": next(
                            item["anchor_type"]
                            for item in synthesis["analyst_question_selections"]
                            if item["template_id"] == template_id
                        ),
                        # The text is a reviewed policy template, not provider
                        # prose or a report-derived statement.
                        "text": text,
                    }
                    for template_id, text in sorted(question_text.items())
                ],
            }
        )

    explanation_text = {
        item["template_id"]: _v2_policy_text(
            policy, item["template_id"], question=False
        )
        for item in synthesis.get("explanation_template_selections") or []
    }
    if explanation_text:
        sections.append(
            {
                "section_id": "explanations",
                "heading": "Policy-owned explanation templates",
                "items": [
                    {"template_id": key, "text": value}
                    for key, value in sorted(explanation_text.items())
                ],
            }
        )

    plan = []
    for item in synthesis.get("review_plan") or []:
        plan_item = {
            "order": item["order"],
            "step_type": item["step_type"],
            "anchor_type": item["anchor_type"],
            "anchor_id": item["anchor_id"],
            "related_chain_ids": list(item["related_chain_ids"]),
            "related_finding_ids": list(item["related_finding_ids"]),
            "related_hypothesis_ids": list(item["related_hypothesis_ids"]),
            "related_action_ids": list(item["related_action_ids"]),
            "limitation_codes": list(item["limitation_codes"]),
            "evidence_gap_codes": list(item["evidence_gap_codes"]),
            "analyst_questions": [
                question_text[template]
                for template in item["analyst_question_template_ids"]
                if template in question_text
            ],
            "explanation": (
                _v2_policy_text(policy, item["explanation_template_id"])
                if item["explanation_template_id"]
                else ""
            ),
        }
        plan.append(plan_item)

    result = {
        "schema_version": V2_RENDERED_SCHEMA,
        "status": "rendered",
        "abstention_reason_code": "",
        "sections": sections,
        "review_plan": plan,
    }
    _validate_rendered_privacy(result)
    return {**result, "render_sha256": sha256_json(result)}


__all__ = [
    "render_validated_advisory",
    "render_validated_advisory_v2",
]
