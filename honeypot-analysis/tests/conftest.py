"""Default pytest collection for the currently supported runtime.

These modules preserve tests for retired experimental contracts.  Their source
remains in the repository as historical evidence, but they import APIs that the
current v4 assessment/v3 guidance and Next-Distinct runtime no longer expose.
Keeping the exclusion explicit prevents stale contracts from blocking the
supported-runtime suite or being mistaken for production coverage.
"""

collect_ignore = [
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
    "test_phase5_ai_integration_v2.py",
    "test_phase6_ai_advisory_presentation.py",
]
