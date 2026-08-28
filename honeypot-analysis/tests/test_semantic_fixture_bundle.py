from __future__ import annotations

from tests.semantic_fixture_loader import (
    load_bundle,
    load_fixture,
    load_provenance_correction,
    source_member_sha256,
)


def test_canonical_fixture_bundle_preserves_family_roles_and_case_counts() -> None:
    bundle = load_bundle()
    assert bundle["schema_version"] == "typed_semantic_fixtures.v2"
    expected_roles = {
        "collection": {"independent", "holdout"},
        "command_transfer_attempt": {"independent", "holdout"},
        "cross_family_relationship": {"independent", "holdout"},
        "execution_attempt": {"independent", "holdout"},
        "filesystem_change": {"independent", "holdout"},
        "inspection": {"independent", "holdout"},
        "scheduled_task": {"independent", "holdout"},
        "sensitive_read": {"replay", "holdout"},
        "service": {"independent", "holdout"},
        "transfer": {"independent", "holdout"},
        "transformation": {"independent", "holdout"},
        "typed_semantic_poc_combined": {"combined"},
    }
    assert {
        family: set(roles)
        for family, roles in bundle["families"].items()
    } == expected_roles
    expected_counts = {
        ("collection", "independent"): 12,
        ("collection", "holdout"): 6,
        ("command_transfer_attempt", "independent"): 24,
        ("command_transfer_attempt", "holdout"): 14,
        ("cross_family_relationship", "independent"): 8,
        ("cross_family_relationship", "holdout"): 4,
        ("execution_attempt", "independent"): 24,
        ("execution_attempt", "holdout"): 12,
        ("filesystem_change", "independent"): 24,
        ("filesystem_change", "holdout"): 16,
        ("inspection", "independent"): 45,
        ("inspection", "holdout"): 34,
        ("scheduled_task", "independent"): 12,
        ("scheduled_task", "holdout"): 6,
        ("sensitive_read", "replay"): 50,
        ("sensitive_read", "holdout"): 24,
        ("service", "independent"): 12,
        ("service", "holdout"): 6,
        ("transfer", "independent"): 34,
        ("transfer", "holdout"): 21,
        ("transformation", "independent"): 12,
        ("transformation", "holdout"): 6,
        ("typed_semantic_poc_combined", "combined"): 18,
    }
    for key, count in expected_counts.items():
        assert len(load_fixture(*key)["cases"]) == count
    correction = load_provenance_correction("inspection_holdout")
    assert correction["schema_version"] == "evaluation_provenance_correction.v1"
    assert source_member_sha256(
        "evaluation/inspection_family_holdout_frozen.v1.json"
    ) == correction["target_sha256"]
