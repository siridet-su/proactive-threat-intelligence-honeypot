# Ordered plan to finalize the prediction subsystem

The plan preserves every accepted historical artifact. No phase silently rewrites stored reports or prediction snapshots.

## Phase 0 — Design freeze

**Objective:** approve one target, label, input, metric, authority, and compatibility contract before touching data or model code.

**Tasks**

- Approve `next_distinct_command_behavior_phase_or_session_end.v1`.
- Approve unordered per-command tactic sets, run-length phase construction, terminal outcome, and score semantics.
- Freeze fields in `runtime_output_contract.json`.
- Predeclare selection metric, high-consequence classes, minimum supports, partitions, seeds, calibration/abstention method, and operational budgets.
- Mark the current payload/checkpoint/benchmark as immutable historical schema.

**Likely files:** new versioned schema/policy documents; no active policy switch.

**Artifacts:** design decision record and hash; target/input/label schemas; evaluation protocol.

**Tests:** schema validation; historical fixture readability; policy rejects undefined authority.

**Risk/rollback:** documentation-only and additive; rollback is deletion of the unapproved proposal.

**Acceptance:** every later phase can point to a frozen hash; no decision depends on final-test results.

**Production change:** none.

## Phase 1 — Provenance-preserving private-to-safe data contract

**Objective:** make raw-to-example transformation auditable without storing raw commands in Git.

**Tasks**

- Pin source member SHA-256 values and the complete preparation environment.
- Retain pseudonymous member, session, event-group, event order, relative time, configuration, and optional template-family IDs.
- Retain per-label rule/model/checkpoint/policy/confidence/agreement/trust metadata.
- Preserve excluded/audit-only label counts and reasons.
- Generate privacy-safe phase records with tactic/technique sets, repetition, and time buckets.
- Produce count reconciliation from raw events to final examples.

**Likely files:** `production/tools/evaluate_zenodo_seven_day.py`; classification/trust serializers; new schema validators; artifact policy.

**Artifacts:** private raw receipt; public-safe phase payload; provenance manifest; redaction report.

**Tests:** malformed event handling; label-list order permutation; deterministic rebuild; raw/hash checks; secret scanning; command text absence; count reconciliation.

**Dependencies:** Phase 0 and authorized raw corpus access.

**Risk/rollback:** privacy leakage is the main risk. Build to a new path and never overwrite the accepted payload.

**Acceptance:** identical source and commit rebuild byte-identical safe payload; every target traces to a private evidence receipt.

**Historical results:** preserved.

**Production change:** none.

## Phase 2 — Example builder and preprocessing parity

**Objective:** generate causal examples for next phase set or terminal outcome and guarantee live/offline equivalence.

**Tasks**

- Group simultaneous labels.
- Collapse identical consecutive tactic sets into phase records while retaining run length/duration.
- Emit a target for every eligible prefix, including terminal prefixes.
- Define missing-time and missing-provenance tokens.
- Implement one shared pure preprocessing adapter used by training, replay, and runtime.
- Ensure only evidence at or before the prediction timestamp enters a tensor.

**Likely files:** new shared module under `production/prediction/`; benchmark builders; `session_features.py`.

**Artifacts:** preprocessing manifest/hash; vocabulary; ordered example membership hashes.

**Tests:** golden cross-path tensor parity; future-field counterfactual tests; terminal examples; multi-label ordering invariance; truncation/padding/mask behavior; unknown/missing input; historical adapter compatibility.

**Dependencies:** Phase 1.

**Risk/rollback:** target count and distribution will change materially. Keep all code additive behind v3 schema.

**Acceptance:** same prefix produces byte-identical normalized model input offline and live; no future leakage.

**Production change:** none.

## Phase 3 — Fresh partition and evidence generation

**Objective:** create independent train, selection, calibration, frozen test, and prospective roles.

**Tasks**

- Assign whole source members/time blocks according to `evaluation_protocol.md`.
- Prove all session/member/example intersections empty.
- Record class, terminal, configuration, pattern, and member distributions before training.
- Freeze test membership and make the training command incapable of loading it.
- Create a blinded human-adjudication sample.

**Likely files:** split builder and validators; no existing accepted manifest changes.

**Artifacts:** split manifest, membership hashes, boundary receipt, distribution report.

**Tests:** role reuse rejection; monotonic boundary; intersection proofs; deterministic split; test-loader denial during selection.

**Dependencies:** Phase 2 and enough new members/support.

**Risk/rollback:** insufficient rare-class support. Response is more data or narrower claim, not repartitioning after looking at test outcomes.

**Acceptance:** roles are disjoint and independently auditable; minimum support decision is recorded before model fitting.

**Production change:** none.

## Phase 4 — Baselines and Small Causal Transformer retraining

**Objective:** determine whether the small causal Transformer remains best under the corrected task.

**Tasks**

- Rebuild majority, first-order, hard-backoff VOMM, interpolated VOMM, Transformer, and optional GRU on identical data.
- Keep the Transformer small and CPU-oriented; adapt input embeddings/output heads for tactic sets and terminal outcome.
- Run predeclared feature ablations on model-selection data only.
- Train declared seeds; select one checkpoint using the frozen rule.
- Record resources, environment, state dictionary, hashes, and deterministic replay.

**Likely files:** offline benchmark and a versioned model module; requirements lock.

**Artifacts:** per-seed checkpoints/metrics, selected checkpoint, model card, resource report.

**Tests:** deterministic seeds; state replay; corrupted checkpoint; incomplete seed exclusion; vocabulary/preprocessing mismatch; baseline parity.

**Dependencies:** Phase 3.

**Risk/rollback:** the Transformer may not win. Accept the predeclared winner; do not change rules after results.

**Acceptance:** one validation-selected checkpoint and one same-target VOMM baseline are frozen without test access.

**Production change:** none.

## Phase 5 — Calibration and abstention freeze

**Objective:** either establish valid uncertainty semantics or explicitly retain raw scores.

**Tasks**

- Decide before reading calibration outcomes whether probability display is required.
- If required, fit the predeclared mapping and prediction-set/OOD thresholds on calibration only.
- Otherwise record `calibration.status=not_implemented` and display raw rank scores.
- Freeze the calibration mapping and coverage policy hashes.

**Likely files:** offline calibration tool; output-schema validator.

**Artifacts:** calibration report/mapping or explicit no-calibration record.

**Tests:** calibration membership; mapping hash; missing mapping; score/probability UI semantics; abstention determinism.

**Dependencies:** Phase 4.

**Risk/rollback:** weak rare-class calibration. Default rollback is raw scores with explicit semantics.

**Acceptance:** calibration partition was not used for model selection and test remains unopened.

**Production change:** none.

## Phase 6 — One-time frozen evaluation

**Objective:** evaluate the exact frozen checkpoint and VOMM on the untouched final historical test.

**Tasks**

- Verify all manifests/hashes before inference.
- Run primary, secondary, diagnostic, cluster-bootstrap, chronological/member/configuration, ambiguity, and efficiency analyses.
- Run the blinded human-label sensitivity audit.
- Apply only predeclared promotion criteria.
- Publish favorable and unfavorable results.

**Likely files:** evaluator and compact evidence generator.

**Artifacts:** accepted immutable result bundle, figures actually cited, final decision.

**Tests:** exact membership; no test access by training; deterministic rerun; case-level VOMM/Transformer alignment.

**Dependencies:** Phases 3–5.

**Risk/rollback:** failed criteria. Preserve results and stop; do not tune on the test.

**Acceptance:** evaluator reproduces metrics from frozen artifacts and records one decision.

**Production change:** none.

## Phase 7 — Additive shadow-only runtime integration

**Objective:** execute the frozen Transformer safely on live prefixes while VOMM remains authoritative.

**Tasks**

- Implement a manifest-bound Transformer loader and shared preprocessing adapter.
- Store v3 forecasts separately or as an additive immutable schema.
- Leave v2 VOMM snapshots and current APIs unchanged.
- Display Transformer output only on an explicitly experimental panel.
- Disable v3 forecast influence on alerts, enrichment escalation, assessment claims, guidance, recommendations, actions, and priority.
- Fail shadow-only on any error without interrupting VOMM/session processing.

**Likely files:** new prediction module; `session_worker.py`; storage contract/backends; API/report/dashboard adapters; config schema.

**Artifacts:** deployment manifest, future-only start timestamp, rollback package.

**Tests:** VOMM byte-equivalence enabled/disabled; zero authority under hostile policy overlays; invalid checkpoint isolation; historical schemas; API/report/UI parity; storage retention.

**Dependencies:** successful Phase 6, operational package, local full suite.

**Risk/rollback:** worker resource or compatibility failure. Feature flag defaults off; rollback disables v3 and removes no historical rows.

**Acceptance:** controlled event proves separate storage and zero authority; VOMM remains sole production authority.

**Production change:** shadow computation/storage only.

## Phase 8 — Prospective shadow validation

**Objective:** obtain production-local evidence without changing authority.

**Tasks**

- Freeze start time and include only new sessions.
- Collect later observed outcomes and label provenance.
- Monitor coverage, terminal rate, class/pattern drift, VOMM disagreement, missing-score rate, latency, memory, and errors.
- Conduct periodic blinded label review.
- Keep checkpoint and thresholds fixed.

**Likely files:** evaluator/monitoring queries and dashboard diagnostics; no action policy.

**Artifacts:** immutable prospective cohort manifest and periodic reports.

**Tests:** post-freeze inclusion; checkpoint immutability; no backfill mixing; delayed-ground-truth alignment.

**Dependencies:** Phase 7.

**Risk/rollback:** insufficient meaningful traffic. Report as limitation; do not manufacture a promotion claim.

**Acceptance:** predeclared sample/duration reached or study explicitly closed as underpowered.

**Production change:** observational only.

## Phase 9 — Documentation and final acceptance

**Objective:** state exactly what is final and what is not.

**Tasks**

- Update thesis, model card, artifact policy, operator docs, API schema, and rollback guide.
- Preserve accepted historical benchmark wording and add the redesigned result separately.
- Record whether status is experimental PoC, shadow-validated, or operationally validated.

**Artifacts:** final evidence index and signed acceptance checklist.

**Tests:** documentation links, schema examples, artifact restoration, clean rebuild.

**Dependencies:** Phase 6 for experimental finality; Phase 8 for prospective claims.

**Acceptance:** all criteria in `acceptance_criteria.md` are classified with evidence.

## Scope boundaries

Required before calling the **experimental subsystem final**: Phases 0–6 and 9.

Required before **shadow deployment**: Phases 0–7, complete local tests, backup/rollback verification, and explicit deployment authorization.

Required before **production-generalization claims**: Phase 8 plus independent label/member/time evidence.

Optional future research: learned phase segmentation, raw-command language models, survival/time-to-event modeling, score fusion, tactic routing, automatic response, and continual online retraining.
