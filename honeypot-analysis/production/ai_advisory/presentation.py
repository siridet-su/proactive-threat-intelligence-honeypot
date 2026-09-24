"""Evidence-checked display text for immutable AI advisory selections.

The provider selection and policy-rendered text remain stored unchanged. This
read model prevents an older template from calling a response-guidance finding
canonical when the linked assessment contains no canonical behavioral finding.
"""

from __future__ import annotations

from typing import Any, Mapping


def _records(value: Any, key: str) -> set[str]:
    return {
        str(item[key])
        for item in value or []
        if isinstance(item, Mapping) and isinstance(item.get(key), str)
    }


def advisory_presentation(
    rendered: Mapping[str, Any],
    selected: Mapping[str, Any],
    report: Mapping[str, Any],
) -> dict[str, Any]:
    """Return display paragraphs without changing the signed stored narrative."""

    canonical = _records(
        [
            item
            for item in report.get("behavioral_findings") or []
            if isinstance(item, Mapping) and item.get("status") == "supported"
        ],
        "finding_id",
    )
    guidance = report.get("response_guidance_v3") or {}
    guidance_ids = _records(
        guidance.get("findings") if isinstance(guidance, Mapping) else [],
        "finding_id",
    ) - canonical
    allowed = {
        value for value in selected.get("selected_finding_ids") or []
        if isinstance(value, str)
    }
    paragraphs: list[dict[str, str]] = []
    for item in rendered.get("paragraphs") or []:
        if not isinstance(item, Mapping):
            continue
        text = str(item.get("text") or "").strip()
        template_id = str(item.get("template_id") or "")
        ids = {
            value for value in item.get("finding_ids") or []
            if isinstance(value, str) and value in allowed
        }
        if (
            template_id == "summarize_selected_findings"
            and "canonical finding" in text.lower()
            and (not ids or ids - canonical)
        ):
            if not ids:
                text = (
                    "AI finding selection could not be verified against the current "
                    "report; no canonical behavioral finding is inferred."
                )
                paragraphs.append({"template_id": template_id, "text": text})
                continue
            canonical_count = len(ids & canonical)
            guidance_count = len(ids & guidance_ids)
            unresolved = len(ids - canonical - guidance_ids)
            text = (
                "AI selected existing evidence for analyst review: "
                f"{canonical_count} canonical behavioral finding(s), "
                f"{guidance_count} response-guidance finding(s)"
                + (f", {unresolved} unresolved reference(s)" if unresolved else "")
                + ". This selection does not create a new trusted finding."
            )
        if text:
            paragraphs.append({"template_id": template_id, "text": text})
    return {
        "schema_version": "ai_advisory_presentation.v1",
        "source": "verified_selection_and_immutable_report",
        "paragraphs": paragraphs[:3],
    }
