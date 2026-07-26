# Final prediction subsystem implementation status

Status date: 2026-07-26

Initial implementation HEAD before source recovery:
`69a6cf82a056ededbdc36f730c25037722afeab1`

Latest corrected-target closure commit:
`720a793646bf0010713400565b1ca22ff70b1c33`

Production deployment status: not deployed; the deployed prediction policy and model were not changed.

## 2026-07-26 corrected-target Selection update

**Formal status: `BLOCKED_AT_SELECTION`.** This generation is complete as a
pre-test blocked experiment. It is not a paused training run: no retraining,
policy amendment, Calibration, or Final Test access is authorized under its
frozen protocol.

The independent 13-member v3 experiment advanced through verified role
exports, disjoint partition assembly, Train-only vocabulary construction,
same-target baselines, and all five declared Transformer seeds. The frozen
Selection gate rejected every seed because `defense-evasion` is reportable
(44 targets in 44 sessions), the hard-backoff VOMM has nonzero recall
(`0.1363636364`), and every Transformer seed has zero recall.

No checkpoint was selected. The selected checkpoint, Calibration, merged
pre-test manifest, Final Test evaluation, final metrics, confidence intervals,
error analysis, and selected-checkpoint runtime measurements are
`NOT_DETERMINABLE`, not zero-valued or failed Final-Test results. Final Test
remains sealed and no evaluation-access ledger exists.

The compact result and interpretation are:

- `corrected_target_selection_blocked.json`
- `CORRECTED_TARGET_SELECTION_STATUS.md`
- `CORRECTED_TARGET_SELECTION_TABLE.md`
- `corrected_target_selection_gate.svg`

The complete private evidence is an atomic
`training.selection_blocked/` bundle whose receipt SHA-256 is
`1845249166196898fd2f50a15bcc2e828b584b61189a526ef97c56e7bf12b379`.
The receipt file SHA-256 is
`fea344c71e9757a8f6794f7e7e0290f24ac80d9ccefebd0dbded917a5ae75da8`.
This later evidence supersedes the older Phase 3–6 “source unavailable”
status below; the historical narrative is retained rather than rewritten.

The thesis conclusion is intentionally two-sided: the Transformer seeds exceed
the VOMM baseline on aggregate Selection macro-F1 and balanced accuracy, but
all five fail the frozen reportable-class defense-evasion recall gate. The
aggregate advantage is preserved and does not override the predeclared safety
criterion.

## Source-recovery update

The earlier statement that the source corpus, event mapping, classifier
checkpoint, and environment lock were unavailable is no longer true.

- Zenodo record: `21260400`, DOI `10.5281/zenodo.21260400`.
- Seven exact selected members were recovered from the official
  `data_all.zip` archive into a local non-repository cache and verified by
  filename, expanded byte size, ZIP compressed size, CRC-32, SHA-256, and
  `gzip -t`.
- The SecureBERT `checkpoint-6765` weights were recovered locally and match
  SHA-256
  `dc3a4e2a57a70c4c7cb5f769b6399f32b2b51f0245025653e0b72f6d025a759b`.
  Configuration, tokenizer, label mapping, architecture, 149,755,588
  parameters, 196 labels, and deterministic CPU replay were verified.
- A Python 3.12.13 environment was pinned in
  `requirements-next-behavior-corpus.lock.txt` with lock SHA-256
  `468db1f2f4dad879b6cd4cc60402117f8ec77bce6d0b64266760e5ce0e4d5ace`.
- The seven source members yielded 30,083,833 raw events, 5,405,789
  sessions, 1,015,068 command-input events (349 empty), 1,014,719 non-empty
  command events, and 5,595,627 causal context events. There were zero
  cross-member sessions and zero non-UTC session timestamps after explicit
  UTC normalization.
- Strict offline classification covered 59,002 classifiable fragments and
  57,955 unique commands. The MITRE cache remained byte-identical to its
  pinned SHA-256.
- The safe corpus contains 219,336 sessions and 351,197 causal examples.
  Its JSONL file SHA-256 is
  `81736363154cf485b0fec98fe8ba41e03f1440860564aa843a1de2739aacf375`.
  A second complete build was byte-identical for the payload and all receipts.
- All 219,336 safe sessions and seven source receipts passed strict schema
  validation; the secret-shaped-field scan was clean.

The recovery exposed a different, decisive blocker: all 219,336 emitted safe
sessions overlap the accepted historical corpus (153,535 historical train,
32,900 historical calibration, and 32,901 historical test). A changed HMAC
key does not create independent membership. Commit `99b78ec` makes the split
builder reject this condition before reading or writing partition artifacts.
No training vocabulary was frozen, no model was fitted, and no redesigned
final test was opened.

This record classifies the implementation against `implementation_plan.md` and
`acceptance_criteria.md`. A validator or synthetic fixture is not treated as
proof that a missing private artifact exists. The accepted 2026-07-21
benchmark, its checkpoint, and all historical snapshots remain historical
evidence for the old target and are not relabeled as evidence for
`next_distinct_command_behavior_phase_or_session_end.v1`.

## Frozen design receipts

| Artifact | SHA-256 |
|---|---|
| `FINAL_DESIGN_REVIEW.md` | `1b2e3c26b3b7f2629cc1fb64435a3618451c648189dab064ffbcc25d72574612` |
| `acceptance_criteria.md` | `a70f27435ee484509f0a156c3b07b737c8a710072960374f44f2bceb3ac1b5c3` |
| `evaluation_protocol.md` | `0248d3f779d6d5549fc413cb283b4606e6ea4a5101e7e33d6ce505503011cf33` |
| `implementation_plan.md` | `6c9925716a99313ca2227136d2311a64eec2e7182bef75c51a6951f5407f2c99` |
| `runtime_output_contract.json` | `7639f55c00f7b9e459898e9629140516a2fc7d2eaa3b98984bccabe23daa2a85` |
| `target_definition_analysis.md` | `a932c37e26165fb4ae5dd946c6cd6d97d3ccc0260d67d3fd174c7091ff168ba9` |
| `configs/next_behavior_preprocessing.v1.json` | `890569a4597df2f300d7c885a2cf0bd34a9fd9fbdd0ab0938141a8f13f4a25c1` |

## Completed implementation units

| Commit | Unit | Result |
|---|---|---|
| `e204334` | Design freeze | Added the reviewed target, pipeline map, protocol, contracts, plan, and criteria without changing runtime authority. |
| `ec6ff9e` | Phase and example contracts | Added strict phase/example/input validation and deterministic phase construction, terminal examples, and causal preprocessing. |
| `5eabbc3` | Partition-role enforcement | Added the fixed seven-member chronological role policy, disjointness proofs, purpose-scoped loaders, hashes, and a no-overwrite split-manifest builder. |
| `b784a84` | Private-to-safe corpus adapter | Added HMAC-pseudonymous safe records, trusted/audit-only provenance, reconciliation receipts, strict source receipts, and secret-shaped-field rejection. |
| `6b4fb3c` | Forecast boundary | Added strict additive `next_behavior_forecast.v3` validation with raw-score semantics and an all-false authority block. |
| `504ebee` | Corrected-target artifact gate | Added a frozen experiment-manifest gate that validates hashes and semantics and rejects old-target artifacts and incomplete provenance. |
| `26d7cc9` | Shared tensor adapter | Added byte-stable offline/live tensor construction, training-only technique vocabulary, unknown handling, masks, multilabel targets, and a separate terminal target. |
| `3781f42` | Vocabulary binding | Bound the experiment manifest semantically to the exact tensor vocabulary rather than trusting a copied hash. |
| `69a6cf8` | Prediction-only side-effect prohibition | Removed active prediction-only alert persistence and enrichment escalation while preserving the legacy evaluator for historical diagnostics and reproducibility. |
| `e3de17c` | Verified Zenodo source manifest | Pinned the official record, archive, seven selected source members, byte sizes, CRCs, and recovered SHA-256 values. |
| `aae0fd3` | Classifier environment freeze | Pinned and verified the recovered SecureBERT assets and complete Python environment lock. |
| `70a1d3a` | Label-provenance normalization | Aligned real classifier output with trusted/audit-only central policy and a strict model-only threshold. |
| `2cc39a6` | Private event mapping | Added resumable source ingestion with event order/time/context preservation and cross-member rejection. |
| `5cd8be7` | Streaming corpus receipts | Added bounded-memory safe-corpus receipt construction equivalent to the in-memory contract. |
| `b54ab62` | Provenance-safe corpus build | Added HMAC-safe export, causal context construction, count reconciliation, and historical membership mapping. |
| `c38fba6` | Offline cache integrity | Made classification fail closed on MITRE cache drift and prevented stale-cache network refresh. |
| `3ce5f24` | Clean-HEAD artifact binding | Bound generated corpus artifacts to the exact clean Git HEAD. |
| `cdb871b` | Recovered corpus evidence | Preserved compact source, classification, reconciliation, and safe-corpus receipts without raw content. |
| `99b78ec` | Historical-overlap preflight | Rejects accepted historical session reuse despite changed safe identifiers. |
| `5566778` | Real-corpus preprocessing inventory | Validates and inventories every real causal example without opening model partitions. |

## Historical pre-amendment phase status (superseded)

The following Phase 0–9 table records the earlier seven-member source-recovery
attempt. It is retained for audit history only. The 2026-07-26
`BLOCKED_AT_SELECTION` record above is the authoritative status for the
corrected 13-member v3 experiment and supersedes these earlier availability
claims.

| Phase | Status | Evidence and exact boundary |
|---|---|---|
| 0 — Design freeze | **COMPLETE** | The target, inputs, output semantics, partitions, selection rule, promotion blockers, raw-score policy, authority limits, and historical compatibility are frozen and content hashed. |
| 1 — Private-to-safe data contract | **COMPLETE AND VERIFIED LOCALLY** | Exact source/checkpoint/environment receipts, private event mapping, per-label provenance, count reconciliation, HMAC-safe output, two byte-identical builds, full strict validation, and a clean secret-field scan now exist. Raw/private artifacts remain outside Git. |
| 2 — Example builder and parity | **PARTIAL; REAL PREPROCESSING VERIFIED** | The recovered safe corpus produces 351,197 validated causal examples with ordered example/input hashes and real member/role/target distributions. Shared offline/live parity remains green. A training-only vocabulary is intentionally not frozen because no independent partition may be authorized. |
| 3 — Fresh partition and evidence generation | **BLOCKED BY PROVEN HISTORICAL OVERLAP** | All 219,336 safe sessions belong to the accepted historical corpus. The real receipt-bound preflight rejects the corpus before any partition output. New, independently selected source members and a predeclared amended split are required; re-HMACing these sessions is not sufficient. |
| 4 — Baselines and Transformer retraining | **BLOCKED** | Correct training requires an independent Phase 3 partition and training-only vocabulary. No checkpoint was retrained, selected, or fabricated from the overlapping corpus. |
| 5 — Calibration and abstention | **BLOCKED** | Depends on the validation-selected Phase 4 checkpoint and independent calibration membership. The v3 contract safely supports `not_implemented`, but no calibration decision is claimed for a nonexistent model. |
| 6 — One-time frozen evaluation | **BLOCKED** | No test evaluation was run because Phases 3–5 have not produced frozen artifacts. The accepted historical benchmark was not opened or reused as the redesigned final test. |
| 7 — Shadow-only integration | **BLOCKED AND NOT IMPLEMENTED** | The plan requires a successful Phase 6 checkpoint, operational package, and explicit deployment authorization. No v3 model loader, storage writer, API field, UI panel, service, timer, or runtime feature flag was introduced. |
| 8 — Prospective shadow validation | **BLOCKED** | Depends on Phase 7 and future production-local observations. No cohort, timestamp, backfill, or production claim was created. |
| 9 — Documentation and final acceptance | **PARTIAL** | This record classifies all criteria and preserves the historical/new-target distinction. A final model card, redesigned evidence index, accepted model decision, restoration rehearsal, and prospective claim remain impossible until the blocked phases complete. |

## Historical pre-amendment acceptance classification (superseded)

The classifications below describe the same earlier source-overlap attempt and
must not be read as the status of the completed 13-member v3 preparation and
Selection run. The current experiment's unavailable downstream outputs are
`NOT_DETERMINABLE` because the frozen Selection gate blocked the generation
before Final Test access.

### A. Experimental subsystem final

| # | Criterion | Status | Evidence or blocker |
|---:|---|---|---|
| A1 | Frozen next-phase-set-or-terminal target | **PASS — DESIGN/CONTRACT** | Frozen design plus strict target constant and validators. |
| A2 | Simultaneous labels are unordered | **PASS — LOCAL** | Canonical set construction and permutation regression tests. |
| A3 | Compression retains repetition/time | **PASS — LOCAL** | Phase builder and strict phase schema tests. |
| A4 | Every eligible prefix has phase or terminal target | **PASS — LOCAL** | Builder emits transition and terminal examples; tests cover both. |
| A5 | Shared live/offline preprocessing and golden tensor parity | **PASS — LOCAL** | One tensor adapter and byte-stable parity tests. |
| A6 | Every real trusted target retains complete provenance | **PASS — REAL ARTIFACT** | All 219,336 safe sessions were rebuilt from the verified private mapping with per-label rule/model/checkpoint/policy/confidence/agreement/evidence provenance and passed strict validation. |
| A7 | Untrusted categories are audit-only | **PASS — LOCAL POLICY** | Corpus validator separates trusted and audit-only labels and reasons. |
| A8 | Real source receipts and safe identities | **PASS — REAL ARTIFACT** | Seven verified SHA-256 source receipts, private mapping, HMAC-safe identities, reconciliation, deterministic rebuild, and redaction scan exist. |
| A9 | Real whole-session role intersections are empty | **BLOCKED — HISTORICAL REUSE** | Candidate member roles are internally disjoint, but every candidate session overlaps the accepted historical corpus; the partition preflight correctly refuses a manifest. |
| A10 | Selection and calibration uses are independently enforced | **PASS — LOCAL CONTROL** | Purpose-specific manifest loading denies role reuse. |
| A11 | Accepted historical test excluded from tuning | **BLOCKED — RECOVERED SOURCE IS HISTORICAL** | No redesigned training occurred, but the recovered seven-member corpus cannot satisfy independent historical exclusion. |
| A12 | All model decisions fixed before final test | **BLOCKED** | No independent experiment manifest can be issued; no final test was opened. |
| A13 | Validation-only checkpoint selection/replay | **BLOCKED — PHASE 4** | No corrected-target checkpoint exists. |
| A14 | Same-target VOMM and baselines | **BLOCKED — PHASE 4** | No corrected-target training corpus exists. |
| A15 | Clustered final intervals and sensitivity | **BLOCKED — PHASE 6** | No corrected-target frozen evaluation exists. |
| A16 | Unsupported tactic reporting | **PARTIAL — DESCRIPTIVE SUPPORT KNOWN** | Candidate support is now inventoried, but reportable support cannot be frozen for an invalid overlapping partition. |
| A17 | Raw scores are not probabilities | **PASS — LOCAL CONTRACT** | Forecast validation rejects probability semantics without a valid independent calibration mapping. |
| A18 | All real artifact hashes verify | **PARTIAL** | Source, environment, checkpoint, policies, cache, safe payload, receipts, memberships, and real example/input hashes verify. Model/vocabulary/partition/checkpoint hashes remain unavailable because Phase 3 is blocked. |
| A19 | Focused and feasible repository tests pass | **PASS** | See exact test record below. |
| A20 | Historical records/evidence remain unchanged and readable | **PASS — LOCAL** | Additive v3 schemas only; compatibility regressions pass; accepted evidence was not rewritten. |
| A21 | Final thesis/model card states narrow claim and adverse findings | **BLOCKED — PHASE 6/9** | No corrected-target result exists from which to make a final claim. |

Section A overall: **BLOCKED**. Local contracts and safeguards do not substitute
for the missing private corpus, model, and one-time evaluation.

### B. Shadow deployment ready

Section B overall: **BLOCKED** because Section A is incomplete and no
corrected-target checkpoint exists. The strict forecast schema and experiment
gate are prerequisites only. No loader, inference path, separate persistence,
API/report/UI presentation, freeze timestamp, resource measurement, backup,
rollback rehearsal, controlled event, or deployment authorization is claimed.

### C. Production-generalization claim ready

Section C overall: **BLOCKED**. No shadow deployment or future-only cohort
exists, no independent production-local target counts exist, and no blinded
human-adjudicated evidence exists. No production-generalization claim is made.

### D. Never-authorized behavior

| Invariant | Status |
|---|---|
| Prediction cannot establish observed behavior or intent | **PASS — CONTRACT/REGRESSION** |
| Prediction alone cannot create an alert or enrichment escalation | **PASS — ACTIVE LOCAL CODE/ADVERSARIAL REGRESSION** |
| Prediction alone cannot select guidance or recommendations | **PASS — CONTRACT/REGRESSION** |
| Prediction alone cannot authorize or execute an action | **PASS — CONTRACT/REGRESSION** |
| No test-derived ensemble or tactic router | **PASS — NONE INTRODUCED** |
| Historical snapshots are not recomputed | **PASS — ADDITIVE DESIGN/REGRESSION** |
| Uncalibrated scores are not probabilities | **PASS — STRICT VALIDATOR** |

The alert/enrichment safeguard is committed locally but has not been deployed.
The deployed service was not inspected or changed during this work.

## Test and validation record

Focused tests were run after each implementation unit. Material checkpoints:

- Contract and affected behavior: `51 passed`.
- Partition and contract tests: `32 passed`.
- Corpus, security, and affected regressions: `198 passed`.
- Forecast and affected regressions: `258 passed`.
- Experiment/contracts: `69 passed`.
- Tensor/contracts: `40 passed`.
- Experiment/tensor semantic binding: `19 passed`.
- Prediction-only alert tests: `7 passed, 179 deselected`.
- Downstream authority, report, and guidance regressions: `52 passed`.
- Complete session-worker module:
  `pytest -q tests/test_production_services.py` → `186 passed`.
- Initial sandboxed full run:
  `pytest -q tests` → `943 passed, 8 failed, 7 skipped`; all eight failures were
  local-socket `PermissionError` failures in ingest/E2E setup, not assertion
  failures.
- Socket-enabled confirmation:
  `pytest -q tests/test_ingest_api_security.py tests/test_production_e2e.py`
  → `15 passed`.
- Final feasible full suite with localhost socket permission:
  `pytest -q tests` → **`951 passed, 7 skipped in 77.09s`**.
- Source-recovery/corpus focused suite:
  `pytest -q tests/test_next_behavior_zenodo_corpus_builder.py
  tests/test_next_behavior_label_policy.py tests/test_next_behavior_corpus.py
  tests/test_next_behavior_contract.py tests/test_next_behavior_zenodo_source.py
  tests/test_next_behavior_classifier_assets.py` → **`69 passed`**.
- Historical preflight and affected contracts/experiment/tensor suite:
  **`68 passed`**.
- Real-corpus inventory and affected preprocessing/partition/tensor suite:
  **`59 passed`**.
- Current sandboxed full run:
  `pytest -q tests` → **`990 passed, 8 failed, 7 skipped`**; all eight failures
  were localhost-socket `PermissionError` failures in ingest/E2E setup.
- Current socket-enabled full confirmation:
  `pytest -q tests` → **`998 passed, 7 skipped in 24.75s`**.

The seven skips are environment/dependency gates: four neural tests require
PyTorch, two figure tests require Matplotlib, and one MongoDB integration test
requires `MONGODB_TEST_URI`. MongoDB migration or deployment is outside this
plan and was not attempted.

## Exact blockers and first safe continuation

The seven expected source members, private event/time mapping, label
provenance, classification checkpoint, and complete environment lock are no
longer missing. Their compact evidence is in `corrected_target_corpus/`; the
bulk safe payload remains ignored and reproducible locally.

The remaining blocker is independent membership. The recovered safe corpus is
not a fresh experiment: all 219,336 emitted sessions are already present in
the accepted historical payload. Candidate 4/1/1/1 role distributions are
descriptive only. No training-only vocabulary, checkpoint, calibration, or
final evaluation may be produced from them under the frozen protocol.

The first safe continuation is a documented design amendment, made before
classification or model access, selecting additional Zenodo source members
that are provably absent from all accepted historical membership. Those exact
members must be content-receipted and rebuilt through the same private-to-safe
pipeline. The historical-overlap preflight must return zero before Phase 3 may
freeze membership or Phase 4 may fit any model. The old Transformer checkpoint
still answers a different target and remains ineligible for relabeling.

## Preserved untracked audit evidence

The following pre-existing, unrelated audit bundles were intentionally left
untracked and unchanged:

- `evaluation/next_tactic_benchmark_evidence/data_preparation_training_audit/`
  (approximately 164 KiB)
- `evaluation/next_tactic_benchmark_evidence/execution_persistence_investigation/`
  (approximately 196 KiB)
- `evaluation/next_tactic_benchmark_evidence/gru_transformer_runtime_comparison/`
  (approximately 48 KiB)

Nothing was pushed, deployed, migrated, restarted, or changed in production.
