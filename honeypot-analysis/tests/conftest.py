"""Separate superseded PoC contracts from current-runtime acceptance.

The files remain in the repository as historical evidence.  They import APIs
that are absent from the current runtime and can be collected explicitly with
``--include-historical-contracts`` when auditing/restoring those experiments.
"""

from pathlib import Path


HISTORICAL_CONTRACT_FILES = frozenset({
    "test_final_f_phase1_authority.py",
    "test_final_f_phase2_graph_guidance.py",
    "test_final_f_phase3_projection_v2.py",
    "test_final_f_phase4_contract_v2.py",
    "test_next_behavior_preparation_preflight.py",
    "test_next_behavior_provenance.py",
    "test_next_behavior_selected_store_performance.py",
    "test_next_behavior_successor_contracts.py",
    "test_next_behavior_support_preflight.py",
    "test_next_trusted_group_support.py",
    "test_phase4_prediction_contracts.py",
    "test_phase4a_authority_adversarial.py",
    "test_phase4a2_authority_remediation.py",
    "test_phase7_attack_tactic_context.py",
    "test_phase5_ai_integration_v2.py",
    "test_phase6_ai_advisory_presentation.py",
})


def pytest_addoption(parser):
    parser.addoption(
        "--include-historical-contracts",
        action="store_true",
        default=False,
        help="Collect superseded PoC tests, including their known import failures.",
    )


def pytest_ignore_collect(collection_path: Path, config):
    if config.getoption("--include-historical-contracts"):
        return None
    if collection_path.parent.name == "tests" and collection_path.name in HISTORICAL_CONTRACT_FILES:
        return True
    return None
