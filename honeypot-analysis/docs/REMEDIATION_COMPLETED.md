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

## Phase 2 — Fix durable replay and typed chain/context correctness

- Completion timestamp: `2026-08-13T06:00:57+07:00`
- Findings addressed: command-index-zero replay splitting; invalid replay cutoff lacking `received_at`; greedy failed-first chain selection; relative transfer/permission/execution chains losing confirmed cwd.
- Exact implementation: canonical storage snapshots now expose each event's existing `received_at` and the exact through-watermark; replay uses explicit zero-safe grouping, constructs a canonical cutoff, and immediately validates its history manifest. Chain selection v3 uses deterministic bounded dynamic programming over successful same-entity transitions. Command observations propagate only observed or confirmed cwd, clearing it after failed/ambiguous directory changes.
- Files/functions/contracts changed: `production/classification/durable_replay.py`; `production/correlation/session_behavior_relationships.py`; `production/reporting/threat_hypothesis.py`; `production/reporting/typed_semantic_chain_selection.py`; `production/reporting/typed_semantic_facts.py`; `production/storage/backend.py`; `production/storage/mongodb_backend.py`; `tests/test_cross_layer_consistency.py`; `tests/test_phase2_replay_chain_context.py`.
- Contract version introduced: `typed_semantic_chain_selection.v3`. No database schema or index changed.
- Implementation commit SHA: `0893efc0acef183ce7a7fe1b587294d977927aa4`
- Implementation tree SHA: `c87c4f3e4d30b20d4e06bc38feda3963938784d7`
- Tests and exact results: replay/chain/cwd/typed/storage/semantic focused group → `93 passed, 13 skipped`; skips are opt-in external MongoDB integration/failure-injection cases; `git diff --check` PASS.
- Acceptance criteria: PASS. Realtime/replay first-command multi-label manifests match exactly; all replay cutoffs validate; a later successful retry forms the complete chain; failed/unreplaced, mismatched, variable, and ambiguous cases abstain; multiple runs over a 203-command retry fixture are byte-identical; search state is bounded by required-depth × chain-fact count.
- Compatibility/historical-data impact: historical v2 selections and assessments are not rewritten. New v3 selection identities may differ. Snapshot payloads expose already-stored ordering metadata only; SQLite/Mongo persistence schemas remain unchanged.
- Model/checkpoint impact: no checkpoint/model bytes changed and no compatibility decision was made. Corrected grouping can affect future sequence fingerprints and remains part of the post-Phase-7 gate.
- Remaining limitations: prediction history still uses v2 representation until Phase 4; mapping/tactic semantics remain scheduled for Phase 7.

## Phase 3 — Restore canonical authority and create an integrity-bound hypothesis contract

- Completion timestamp: `2026-08-13T06:14:51+07:00`
- Findings addressed: audit-only behavioral candidates leaking into canonical findings; hypothesis meaning and status not integrity-bound; unresolved and conflated evidence/fact/entity/relationship/chain reference domains; missing v5 consumer compatibility.
- Exact implementation: introduced a current v5 assessment producer that partitions v4-derived candidates strictly by validated graph authority, retains demoted candidates only in `audit_only_behavioral_candidates`, derives bounded hypotheses solely from incomplete canonical graph chains, content-addresses every hypothesis field and alternative, validates exact reference domains and unique authority IDs, and routes storage, artifacts, monitor, analysis, and AI projection through version-aware validation. Historical v4 construction and validation remain unchanged.
- Files/functions/contracts changed: `production/reporting/session_assessment_v5.py` (`build_session_assessment_v5`, `validate_session_assessment_v5`, `validate_threat_hypothesis_set_v2`, `canonical_assessment_id`); `production/ai_advisory/projection.py`; `production/api/monitor_web.py`; `production/reporting/artifacts.py`; `production/storage/backend.py`; `production/storage/mongodb_operations.py`; `production/workers/analysis_worker.py`; `production/workers/session_monitor.py`; `tests/test_phase3_session_assessment_v5.py`; `tests/test_authority_containment.py`; `tests/test_report_secret_containment.py`.
- Contract versions introduced: `session_assessment.v5`, `threat_hypothesis_set.v2`, `threat_hypothesis_alternative.v2`. `canonical_semantic_graph.v1` was sufficient and was not redefined.
- Implementation commit SHA: `82a400fa86f425d5e2dc5bd527799f7406a6b0df`
- Implementation tree SHA: `7bce876b11f1b3293dc6dc3df265b0f203149390`
- Tests and exact results: phase-focused authority/hypothesis/AI/artifact/runtime/semantic group → `153 passed, 1 skipped`; the skip is an optional ReportLab PDF test; `python -m compileall -q production tests/test_phase3_session_assessment_v5.py` PASS; `git diff --check` PASS.
- Acceptance criteria: PASS. Canonical findings resolve to one trusted decision; audit-only candidates remain separately visible; full hypothesis content and all five reference domains fail closed on tamper; an incomplete-chain hypothesis survives validated non-authoritative AI projection; a completed chain has no stale hypothesis; non-authoritative context cannot change the v5 identity; historical v4 remains readable without v5 adaptation.
- Compatibility/historical-data impact: historical `session_assessment.v4` records retain their original producer, validator, IDs, and read-only adapter. New reports use v5 and new IDs. No report, database record, or production session was backfilled or reinterpreted.
- Model/checkpoint impact: none. Findings and hypotheses remain excluded from trusted prediction history; Transformer checkpoint compatibility/retraining remains deliberately undecided until Phase 7 and the deterministic-semantics freeze.
- Remaining limitations: response-guidance graph unification remains Phase 5; campaign/STIX terminology remains Phase 9; expanded evidence-layer presentation remains Phase 10.

## Phase 4 — Correct prediction history, live model input, target boundary, and evaluation

- Completion timestamp: `2026-08-13T06:53:46+07:00`
- Findings addressed: command-tail rather than distinct-phase truncation; fabricated manifest timestamps and provenance; loss of audit/outcome/count metadata; live/offline tensor skew; forecasts created without a new trusted phase and at session close; invalid automatic next-target labels; current-snapshot integrity gaps; implicit late-arrival behavior.
- Exact implementation:
  - introduced a content-addressed distinct-phase history that collapses consecutive equal trusted tactic sets before retaining the newest eight, while preserving canonical timestamps, exact tactic-technique labels, source/confidence/agreement provenance, command outcomes, fragment execution state, evidence references, audit-only counts, original/selected/omitted counts, and upstream truncation;
  - made the manifest adapter and offline causal adapter share one v2 model-input/tensor path and removed fabricated epoch timestamps and rule-only provenance;
  - made prediction triggers revision-bound to new trusted distinct phases, removed login/close defaults, and made close resolve only the last pre-close target;
  - replaced auto-evidence resolution with cutoff/prefix-bound next-distinct multi-label-or-terminal feedback and made all automatic rows weight-ineligible pending the model gate;
  - made current v4 snapshots fail closed on integrity errors while retaining content-addressed v3 snapshots as historical readable objects in SQLite and MongoDB readers;
  - bound the new preprocessing, runtime, contracts, policy, and source inventory into a v4 classifier-environment receipt with explicit `pending_phase7_deterministic_semantics_freeze` checkpoint status.
- Files/functions/contracts changed: `configs/next_behavior_classifier_environment.v1.json`; `configs/next_behavior_preprocessing.v2.json`; `configs/prediction_policy.transformer_poc.trusted.json`; `configs/production_config.example.json`; `production/api/dashboard_api.py`; `production/api/monitor_web.py`; `production/classification/durable_replay.py`; `production/classification/environment.py`; `production/policies/validate_prediction_policy.py`; `production/prediction/next_behavior_contract.py`; `production/prediction/next_behavior_forecast_contract.py`; `production/prediction/next_behavior_preprocessing.py`; `production/prediction/next_behavior_runtime.py`; `production/prediction/next_behavior_tensor.py`; `production/prediction/prediction_snapshot_contract.py`; `production/prediction/trusted_history.py`; `production/reproduction/next_behavior/classifier_assets.py`; `production/reproduction/next_behavior/experiment_policy.py`; `production/storage/backend.py`; `production/storage/mongodb_operations.py`; `production/utils/feedback.py`; `production/workers/session_monitor.py`; `production/workers/session_worker.py`; and the focused prediction, replay, storage, lifecycle, close, and end-to-end regression tests committed with the phase.
- Contract versions introduced: `prediction_trusted_history_manifest.v3`; `next_distinct_trusted_behavior_phase_or_session_end.v2`; `next_behavior_session.v2`; `next_behavior_phase.v2`; `next_behavior_example.v2`; `next_behavior_input.v2`; `next_behavior_vocabulary.v2`; `next_behavior_tensor_input.v2`; `next_behavior_target_tensor.v2`; `prediction_snapshot.v4`; `prediction_feedback.v2`; `next_behavior_classifier_environment.v4`; preprocessing contract v2. Historical v1/v2 contracts were not redefined.
- Implementation commit SHA: `bcc9e25a0d92ee1cbf226f6ae6e1e19c151a52da`
- Implementation tree SHA: `43508043df9144aeec61d8643edbceb5bc44439c`
- Bound identities: classifier source identity `169a7706874da58757eef3d658be11199b76bb0eb9efbedeb4d88ce3d19c9052`; classifier-environment file SHA-256 `ecc1d6ac0e311e3906f041781585e90064b5993a4b1c7e62c32995230fc6dc72`; derived environment identity `850995efd7e885810bca395d77f3b6fd3209171c7c028b77af2da8da56a0091b`; preprocessing v2 SHA-256 `77c35f705dab415cad233d451b10a1fa96329ad7aae8b1ac59a808eaca2fd8b1`; prediction policy SHA-256 `c00727d5241dadc067808a2eb8173299dd4f03f4f6a5d7960f79d0452ae5a2b2`.
- Tests and exact results:
  - focused history/input/runtime/snapshot/feedback/worker group: `122 passed, 2 skipped`;
  - complete prediction, replay, lifecycle, compatibility, and classifier-environment group: `287 passed, 6 skipped`;
  - SQLite storage contract plus opt-in MongoDB parity group: `23 passed, 25 skipped` (no isolated `MONGODB_TEST_URI` configured; no production database contacted);
  - full repository suite with loopback integration enabled: `1577 passed, 57 skipped`;
  - `python -m compileall -q production tests`, prediction-policy validation, classifier source-identity verification, `git diff --check`, and `python -m pip check`: PASS.
- Acceptance criteria: PASS for Phase 4 implementation. Offline and manifest paths produce identical input hashes/tensors on bound fixtures; timestamps/provenance are preserved; sequence length eight means distinct trusted tactic-set phases; truncation and upstream omission are explicit; audit-only labels cannot evict trusted phases; no login/close forecast is created without a new phase; close is terminal-resolution-only; feedback is prefix/cutoff-bound and never weight-eligible; corrupt current snapshots fail closed; historical content-addressed v3 snapshots remain readable.
- Compatibility/historical-data impact: history v1/v2, snapshot v3, and experiment target v1 remain immutable historical/read-only evidence and are not silently upgraded for v2 inference. Existing prediction and feedback IDs are unchanged; legacy auto-feedback remains stored but ineligible. No historical session was replayed, resent, backfilled, or re-predicted. No SQLite or MongoDB schema/index/data migration occurred.
- Model/checkpoint impact: Transformer architecture, sequence length eight, vocabulary design, checkpoint bytes, weights, thresholds, calibration, scoring, and SecureBERT behavior were not modified. Compatibility, preservation, retraining, recalibration, and thesis-metric decisions were **not** made or performed. Runtime prediction remains fail-closed with `checkpoint_compatibility_status=pending_phase7_deterministic_semantics_freeze` until Phase 7 and the deterministic-semantics freeze gate complete.
- Remaining limitations: four PyTorch unit tests and two exact private-checkpoint/runtime tests were skipped because PyTorch/private reviewed assets are unavailable on this host; they belong to the deferred formal gate. Opt-in MongoDB parity tests require an isolated replica-set URI. Phase 7 may still change trusted technique/tactic sequences, so no checkpoint compatibility conclusion is valid yet.

## Phase 7 — Complete ATT&CK mapping and tactic-context cleanup

- Completion timestamp: `2026-08-13T08:45:29+07:00`
- Findings addressed: list-order tactic selection; inconsistent parent/sub-technique identity; direction-ambiguous SCP/rsync ingress claims; `known_hosts` classified as credentials; service inspection classified as process discovery; read-only sudoers promotion; structural-first suppression of independent exact evidence; archive-completion wording; outcome-ambiguous trusted labels; unchecked trusted-rule allowlist and unresolved tactic metadata; legacy VOMM enabled by an unconfigured default.
- Exact implementation: added reviewed per-rule tactic and submitted-attempt semantics bound to the pinned ATT&CK 14.1 cache; made rule tactics authoritative only when the selected tactic belongs to the exact technique; added closed structural transfer-direction and service/metadata rules; preserved exact sub-technique IDs through canonical graph/report/history consumers; merged independently supported structural and regex evidence deterministically; made allowlist/cache/tactic validation fail closed; and made unconfigured prediction disabled instead of activating the rollback VOMM path.
- Files/functions/contracts changed: `configs/classification_rules.trusted.json`; `configs/next_behavior_classifier_environment.v1.json`; `configs/prediction_policy.transformer_poc.trusted.json`; `production/classification/authority.py`; `production/classification/classification_pipeline.py`; `production/correlation/session_ttp_knowledge.py`; `production/policies/validate_classification_rules.py`; `production/semantics/command_operations.py`; `production/utils/config.py`; `production/workers/session_monitor.py`; `tests/test_phase7_attack_tactic_context.py`.
- Contract versions introduced: none. `classification_rule_policy.v4`, `command_authority_decision.v2`, `classification_event.v3`, `prediction_trusted_history_manifest.v3`, and the exact sub-technique representation were completed without redefining historical contract versions.
- Implementation commit SHA: `0d8d4d14c8820bc807654c76486da1bb8defb36d`
- Implementation tree SHA: `6b9c960daff7f0ab808fa4396f2b43d3ef1aa012`
- Bound identities: classification policy `51cfae25ff39238bbb48ee7143fda675dcb22a2be369b3c558970759799f89ee`; classifier-environment file `ce07d63754cd7fbe0d01d99ff5a9f707e10b12a1fbf62b35ba7f68fcad87b991`; derived classifier-environment identity `4b562b873ee1a4220001fca2585a5f3949193ffb35ac0ddf688736eb64efe6bd`; classifier source identity `fbbf3c60caa2d0650cdaba1254fec6a650cfb985a52a4be93d2ce4eb2bd49ffe`; prediction policy `bba6048cca02d7a22c24f8f5f044482e35a00510bcba62c3fa8fe539b9aebb95`; MITRE cache `33af47bb0a3475cda60c2bea83ce305244bd747021f9e999652dc21520e4e35c`.
- Tests and exact results: Phase 7 focused classifier/replay/history/graph/runtime group `161 passed, 2 skipped`; final focused corrected-mapping/default/recovery/E2E group `9 passed`; full repository suite with loopback access `1584 passed, 57 skipped`; policy validators, classifier source/environment verification, `compileall`, `git diff --check`, and `pip check` PASS. The skips remain opt-in private model/runtime, MongoDB failure-injection/integration, Vertex, and optional PDF gates.
- Acceptance criteria: PASS. Tactics are reviewed evidence-context bindings rather than MITRE list order; exact sub-technique identity is consistent end to end; inbound and outbound transfer attempts differ; credential/service/sudoers semantics are bounded; independent evidence survives structural matching; archive labels explicitly denote submitted attempts; every trusted allowlist entry is unique, present, reviewed, regex-typed, and authority-compatible; invalid cache/tactic bindings fail before trusted state/history; no trusted `unknown` tactic is produced.
- Compatibility/historical-data impact: new policy/source/environment identities affect only newly classified evidence. Historical reports, predictions, IDs, and stored classifications remain immutable and are not reinterpreted or backfilled. SQLite and MongoDB schemas/data were unchanged.
- Model/checkpoint impact: trusted tactic/technique sequences changed materially and are now frozen for the mandatory checkpoint gate. Checkpoint preservation/retraining/recalibration was not decided in Phase 7. Prediction remains fail closed with `checkpoint_compatibility_status=pending_phase7_deterministic_semantics_freeze`.
- Remaining limitations: exact private Transformer checkpoint/runtime evidence and the original bound training corpus must be located and compared before the checkpoint gate can be resolved. Phase 5 has not started.
