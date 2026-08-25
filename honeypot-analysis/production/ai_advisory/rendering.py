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
