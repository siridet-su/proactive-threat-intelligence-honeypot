import json
from copy import deepcopy
from pathlib import Path

from production.policies.validate_remediation_contract_lineage import (
    load_and_validate,
    validate_remediation_contract_lineage,
)


ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "configs" / "remediation_contract_lineage.v1.json"


def test_reviewed_lineage_registry_is_valid_and_has_explicit_dispositions() -> None:
    document = load_and_validate(REGISTRY)
    assert document["baseline"]["commit"] == "49f9b74fbe31c938d37767675d51ff863ce6902d"
    assert all(item["historical_disposition"].startswith("readable") for item in document["contracts"])
    assert {item["planned_phase"] for item in document["contracts"]} >= {1, 2, 3, 4, 5, 9}


def test_duplicate_family_is_rejected() -> None:
    document = json.loads(REGISTRY.read_text(encoding="utf-8"))
    document["contracts"].append(deepcopy(document["contracts"][0]))
    assert any("duplicate contract_family" in error for error in validate_remediation_contract_lineage(document))


def test_ambiguous_schema_owner_is_rejected() -> None:
    document = json.loads(REGISTRY.read_text(encoding="utf-8"))
    document["contracts"][1]["planned_schema"] = document["contracts"][0]["planned_schema"]
    assert any("ambiguous schema owner" in error for error in validate_remediation_contract_lineage(document))


def test_historical_v1_v2_v3_v4_versions_are_not_marked_for_silent_upgrade() -> None:
    document = load_and_validate(REGISTRY)
    dispositions = {
        item["historical_schema"]: item["historical_disposition"]
        for item in document["contracts"]
    }
    assert dispositions["classification_rule_policy.v3"] == "readable_immutable_not_reinterpreted"
    assert dispositions["prediction_trusted_history_manifest.v2"] == "readable_display_only_not_v3_inference_eligible"
    assert dispositions["prediction_snapshot.v3"] == "readable_immutable_display_only"
    assert dispositions["session_assessment.v4"] == "readable_immutable_display_only"
