# Completed remediation phases

## Phase 0 — Freeze the remediation baseline and version map

- Completion timestamp: `2026-08-13T05:44:23+07:00`
- Findings addressed: missing immutable remediation baseline; ambiguous ownership/disposition for planned and historical behavioral contracts.
- Exact implementation:
  - recorded baseline commit/tree, tracked-tree inventory digest, reviewed-plan digest, release/model/config evidence hashes, and deterministic baseline fingerprint;
  - added `remediation_contract_lineage.v1` with one owner, producer, consumers, planned phase, and explicit historical disposition for every planned contract family;
  - added a fail-closed lineage validator for duplicate families, ambiguous schema ownership, invalid dispositions, missing ownership, and malformed baseline identities.
- Files/functions/contracts changed:
  - `docs/REMEDIATION_BASELINE.md`;
  - `configs/remediation_contract_lineage.v1.json`;
  - `production/policies/validate_remediation_contract_lineage.py` (`validate_remediation_contract_lineage`, `load_and_validate`);
  - `tests/test_remediation_contract_lineage.py`;
  - initial reviewed `docs/REMEDIATION_PLAN.md` and `docs/REMEDIATION_COMPLETED.md` tracking.
- Contract version introduced: evidence-only `remediation_contract_lineage.v1`; no runtime behavioral contract changed.
- Implementation commit SHA: `f82352fa24f84c4be39f8b54cddf7a05222b15a9`
- Implementation tree SHA: `aac9b13f3caa048e4828b55a0ebd90478f0f33e7`
- Tests and exact results: `pytest -q tests/test_remediation_contract_lineage.py tests/test_classifier_environment_receipt.py tests/test_prediction_snapshot_immutability.py` → `26 passed`; only unrelated pytest `/tmp` cleanup warnings.
- Acceptance criteria:
  - exact source commit/tree and configuration/release identities recorded: PASS;
  - baseline fingerprint reproducible: PASS (`9c0e870f464f355f90f0b856f1441ceeef34ba263d59d31bc40aedf6b26ca801`);
  - each proposed contract has one producer and explicit consumers: PASS;
  - historical versions have explicit readable/display/inference dispositions: PASS;
  - duplicate or ambiguous contract ownership fails validation: PASS.
- Compatibility/historical-data impact: documentation/evidence only; no database, report, prediction, or historical record changed or reinterpreted.
- Model/checkpoint impact: none; the baseline checkpoint and bundle are preserved as immutable historical evidence, and compatibility remains undecided pending Phase 7 and the deterministic-semantics freeze.
- Remaining limitations: planned producers do not exist until their assigned implementation phases; the registry describes ownership and compatibility intent, not runtime activation.

## Phase 1 — Correct command authority and trusted ATT&CK promotion

- Completion timestamp: `2026-08-13T05:52:18+07:00`
- Findings addressed: lexical regex promotion from inert text/searches; read-only promotion of persistence/modification mappings; unproven `&&`/`||` fragments entering trusted ATT&CK state and prediction history; missing operation-context provenance on trusted regex fallback.
- Exact implementation: introduced an operation-context authority gate binding regex matches to the parsed executable, read/write operand, redirection target, mutation-capable command family, and fragment execution status. Conditional RHS fragments without fragment-scoped execution proof remain audit-only. SecureBERT-only candidates and rule/model disagreements remain audit-only.
- Files/functions/contracts changed: `configs/classification_rules.trusted.json`; `configs/next_behavior_classifier_environment.v1.json`; `configs/prediction_policy.transformer_poc.trusted.json`; `production/classification/authority.py`; `production/classification/classification_pipeline.py`; `production/classification/trust.py`; `production/policies/validate_classification_rules.py`; `production/reporting/session_assessment_v4.py`; `production/reproduction/next_behavior/classifier_assets.py`; `tests/test_session_monitor_behavior.py`; `tests/test_phase1_command_authority_v2.py`.
- Contract versions introduced: `classification_rule_policy.v4`, `command_authority_decision.v2`, `classification_event.v3`.
- Implementation commit SHA: `45d48c21f90c7d39aae64e87bce87e63dd81f101`
- Implementation tree SHA: `633a678d5fc95dbc68626d590856d03688c4017f`
- Tests and exact results: phase-focused authority/session/replay/environment/runtime group → `53 passed, 2 skipped` (private frozen Transformer runtime/checkpoint unavailable); behavioral/semantic/stabilization/privacy group → `109 passed`; classification and prediction policy validators PASS; `git diff --check` PASS.
- Acceptance criteria: PASS. Inert mentions/searches cannot create trusted labels; reads cannot satisfy mutation/persistence mappings; unproven conditional fragments do not enter trusted state/history; every trusted regex fallback resolves to the reviewed operation-context class; representative direct unambiguous invocations and structurally proven writes remain trusted.
- Compatibility/historical-data impact: existing classification events/reports are not rewritten or backfilled. Historical v2 events/v1 authority decisions remain readable under their original identities. New classification uses new policy/environment identity.
- Model/checkpoint impact: SecureBERT and Transformer checkpoint bytes unchanged. Transformer compatibility/retraining remains deliberately undecided until Phase 7 and the deterministic-semantics freeze gate.
- Remaining limitations: contextual tactic choice, direction-sensitive transfer mappings, parent/sub-technique policy, and other trusted ATT&CK cleanup remain in Phase 7. No compatibility, retraining, or recalibration decision was made.
