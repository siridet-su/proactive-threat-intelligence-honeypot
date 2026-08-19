from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

import pytest

from production.tools.validate_final_f_contract_freeze import (
    ABSTENTION_PATH,
    BUNDLE_PATH,
    OUTPUT_PATH,
    POLICY_PATH,
    PROJECTION_PATH,
    RECEIPT_PATH,
    FinalFContractError,
    sha256_json,
    validate_bundle,
    validate_freeze_receipt,
    validate_phase0_artifacts,
    validate_policy,
    validate_projection,
    validate_provider_output,
)


ROOT = Path(__file__).resolve().parents[1]


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.fixture
def artifacts() -> tuple[dict, dict, dict, dict, dict]:
    return (
        _load(BUNDLE_PATH),
        _load(POLICY_PATH),
        _load(PROJECTION_PATH),
        _load(OUTPUT_PATH),
        _load(ABSTENTION_PATH),
    )


def _restamp_projection(value: dict) -> None:
    basis = deepcopy(value)
    basis.pop("projection_sha256", None)
    value["projection_sha256"] = sha256_json(basis)


def test_phase0_known_answers_validate() -> None:
    hashes = validate_phase0_artifacts()
    assert set(hashes) == {
        BUNDLE_PATH.name,
        POLICY_PATH.name,
        PROJECTION_PATH.name,
        OUTPUT_PATH.name,
        ABSTENTION_PATH.name,
    }
    assert all(len(value) == 64 for value in hashes.values())


def test_contract_freezes_authority_chronology_compatibility_and_evaluation(
    artifacts: tuple[dict, dict, dict, dict, dict],
) -> None:
    bundle, policy, _, _, _ = artifacts
    validate_bundle(bundle)
    validate_policy(policy, bundle)
    assert all(value is False for value in policy["authority"].values())
    assert bundle["chronology"]["chain_fact_list_is_chronology"] is False
    assert bundle["chronology"]["classification_only_missing_sequence_creates_step"] is False
    assert bundle["compatibility"]["historical_rewrite"] is False
    assert bundle["compatibility"]["database_migration_required"] is False
    assert bundle["compatibility"]["prediction_contract_changed"] is False
    assert bundle["enum_bindings"]["review_plan_step_type"] == policy["step_types"]
    assert bundle["enum_bindings"]["review_plan_anchor_type"] == policy["anchor_types"]
    assert bundle["enum_bindings"]["finding_status"] == ["supported"]
    assert bundle["enum_bindings"]["completion_code"][-1] == "deterministic_abstention"
    assert bundle["evaluation_protocol"]["case_count"] == 40
    assert bundle["evaluation_protocol"]["independent_reviewers_required_for_analyst_claims"] == 2


def test_projection_rejects_unknown_private_field_even_when_restamped(
    artifacts: tuple[dict, dict, dict, dict, dict],
) -> None:
    bundle, policy, projection, _, _ = artifacts
    projection["raw_command"] = "attacker supplied text"
    _restamp_projection(projection)
    with pytest.raises(FinalFContractError, match="projection keys differ"):
        validate_projection(projection, bundle, policy)


def test_projection_rejects_reversed_causal_relationship_even_when_restamped(
    artifacts: tuple[dict, dict, dict, dict, dict],
) -> None:
    bundle, policy, projection, _, _ = artifacts
    relationship = projection["relationships"][0]
    relationship["source_fact_id"], relationship["target_fact_id"] = (
        relationship["target_fact_id"], relationship["source_fact_id"]
    )
    _restamp_projection(projection)
    with pytest.raises(FinalFContractError, match="contradicts causal order"):
        validate_projection(projection, bundle, policy)


def test_provider_output_rejects_invented_reference(
    artifacts: tuple[dict, dict, dict, dict, dict],
) -> None:
    bundle, policy, projection, output, _ = artifacts
    output["synthesis"]["ranked_finding_ids"].append(
        "a_dddddddddddddddddddddddddddddddd"
    )
    with pytest.raises(FinalFContractError, match="invented reference"):
        validate_provider_output(output, projection, bundle, policy)


def test_provider_output_rejects_free_text_key(
    artifacts: tuple[dict, dict, dict, dict, dict],
) -> None:
    bundle, policy, projection, output, _ = artifacts
    output["synthesis"]["free_text"] = "invented claim"
    with pytest.raises(FinalFContractError, match="prohibited keys"):
        validate_provider_output(output, projection, bundle, policy)


def test_provider_output_rejects_stale_projection_hash(
    artifacts: tuple[dict, dict, dict, dict, dict],
) -> None:
    bundle, policy, projection, output, _ = artifacts
    output["projection_sha256"] = "f" * 64
    with pytest.raises(FinalFContractError, match="stale"):
        validate_provider_output(output, projection, bundle, policy)


def test_abstention_rejects_any_selection(
    artifacts: tuple[dict, dict, dict, dict, dict],
) -> None:
    bundle, policy, projection, _, abstention = artifacts
    abstention["synthesis"]["selected_chain_ids"] = projection["allowed_output"]["chain_ids"]
    with pytest.raises(FinalFContractError, match="abstention must not contain selections"):
        validate_provider_output(abstention, projection, bundle, policy)


def test_phase0_validator_is_not_imported_by_runtime_modules() -> None:
    offenders = []
    for path in (ROOT / "production").rglob("*.py"):
        if path == ROOT / "production" / "tools" / "validate_final_f_contract_freeze.py":
            continue
        if "validate_final_f_contract_freeze" in path.read_text(encoding="utf-8"):
            offenders.append(path.relative_to(ROOT).as_posix())
    assert offenders == []


def test_freeze_receipt_when_present() -> None:
    if RECEIPT_PATH.exists():
        validate_freeze_receipt(_load(RECEIPT_PATH))
