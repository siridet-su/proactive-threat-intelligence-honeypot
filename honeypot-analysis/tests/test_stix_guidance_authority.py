from __future__ import annotations

from copy import deepcopy

from production.policies.validate_stix_bundle import validate_stix_bundle_document


def _bundle() -> dict:
    report_id = "report--11111111-1111-4111-8111-111111111111"
    action_id = "course-of-action--22222222-2222-4222-8222-222222222222"
    return {
        "type": "bundle",
        "id": "bundle--33333333-3333-4333-8333-333333333333",
        "objects": [
            {
                "type": "report",
                "spec_version": "2.1",
                "id": report_id,
                "created": "2026-07-28T00:00:00Z",
                "modified": "2026-07-28T00:00:00Z",
                "published": "2026-07-28T00:00:00Z",
                "name": "Canonical v3 guidance",
                "report_types": ["threat-report"],
                "object_refs": [action_id],
            },
            {
                "type": "course-of-action",
                "spec_version": "2.1",
                "id": action_id,
                "created": "2026-07-28T00:00:00Z",
                "modified": "2026-07-28T00:00:00Z",
                "name": "Manually review observed behavior",
                "x_honeypot_authority": "deterministic_observed_evidence_policy",
                "x_honeypot_evidence_refs": ["cowrie_evidence_1"],
                "x_honeypot_evidence_scope": ["observed_behavior"],
                "x_honeypot_requires_manual_approval": True,
                "x_honeypot_safe_to_auto_execute": False,
            },
        ],
    }


def test_canonical_v3_guidance_stix_authority_validates() -> None:
    assert validate_stix_bundle_document(_bundle()) == []


def test_canonical_v3_guidance_stix_rejects_unsafe_or_ungrounded_actions() -> None:
    bundle = deepcopy(_bundle())
    action = bundle["objects"][1]
    action["x_honeypot_evidence_refs"] = []
    action["x_honeypot_evidence_scope"] = ["prediction"]
    action["x_honeypot_requires_manual_approval"] = False
    action["x_honeypot_safe_to_auto_execute"] = True

    errors = validate_stix_bundle_document(bundle)

    assert any("requires observed evidence refs" in error for error in errors)
    assert any("invalid evidence scope" in error for error in errors)
    assert any("must require manual approval" in error for error in errors)
    assert any("must prohibit automatic execution" in error for error in errors)
