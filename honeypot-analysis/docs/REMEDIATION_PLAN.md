# Remediation implementation plan

The plan preserves the existing architecture: sanitized canonical evidence, MongoDB durable ordering, exact-prefix reconstruction, typed abstention, deterministic semantic graphs, manual-only guidance, and non-authoritative prediction/AI.

No database migration or wholesale redesign is required. New contract versions should coexist with historical records; existing reports and predictions must remain read-only and must not be silently reinterpreted.

## Contract-version strategy

| Current contract | Proposed new contract | Reason |
|---|---|---|
| `classification_rule_policy.v3` | `classification_rule_policy.v4` | Operation-context predicates and reviewed tactic binding |
| `command_authority_decision.v1` | `command_authority_decision.v2` | Fragment execution/conditional and operation-context authority |
| `classification_event.v2` | `classification_event.v3` | Explicit fragment/outcome/attempt semantics |
| `typed_semantic_chain_selection.v2` | `typed_semantic_chain_selection.v3` | Retry-aware deterministic subsequence selection |
| `session_assessment.v4` | `session_assessment.v5` | Trusted-only canonical findings and new hypothesis contract |
| Existing hypothesis objects | `threat_hypothesis_set.v2` | Full-content identity and resolved reference domains |
| `prediction_trusted_history_manifest.v2` | `prediction_trusted_history_manifest.v3` | Real timestamps, provenance, outcomes, phase counts, and truncation |
| Prediction target v1 | `next_distinct_trusted_behavior_phase_or_session_end.v2` | Explicit attempted/submitted behavior and conditional-fragment rules |
| Prediction snapshot v3 | Prediction snapshot v4 | New input/target/history contracts and close-event semantics |
| `response_guidance.v3` | `response_guidance.v4` | Exact graph/policy/content/reference integrity |
| Campaign/similarity v1 | Behavioral similarity cluster v2 | Remove attribution/campaign overclaim |

`canonical_semantic_graph.v1`, `typed_semantic_coverage.v1`, and `canonical_evidence_snapshot.v3` can remain unchanged if their shapes are sufficient. Their consumers must become version-aware, but these contracts should not be silently redefined.

## Approved execution-order constraint

The Transformer checkpoint compatibility, preservation, retraining, and recalibration decision is deferred until all deterministic semantics capable of changing trusted technique, tactic, phase, history, input, or target sequences have been implemented, validated, and frozen.

For traceability, the original phase IDs and meanings are preserved. Phase 7 remains Phase 7, but it must execute after the Phase 4 prediction-contract implementation and before the Transformer checkpoint gate. The gate therefore evaluates the final deterministic semantics from Phases 1, 2, 4, and 7 together rather than an intermediate classifier/history state.

The two previously optional Phase 12 items that could change whether a trusted history is admitted—strict trusted-rule allowlist validation and fail-closed behavior when a reviewed TTP tactic cannot be resolved—are explicitly promoted into Phase 7. The remaining Phase 12 work stays optional and post-gate.

---

# 1. MUST FIX before thesis evaluation

## Phase 0 — Freeze the remediation baseline and version map

### What will be fixed

Establish an immutable baseline for implementation and document which new producer consumes which contract version.

### Why

Several changes alter IDs, hashes, policy identities, and prediction eligibility. A baseline prevents new work from being confused with previously reviewed behavior.

### Main areas affected

- Git candidate fingerprint and inventory
- Classifier environment receipt
- Policy/configuration hashes
- Model compatibility receipt
- Release-manifest inputs
- A new contract-lineage/compatibility document

### Tests

- Baseline fingerprint reproducibility
- Clean-worktree/inventory check
- Contract registry rejects duplicate or ambiguous schema IDs
- Historical fixture versions remain recognized

### Acceptance criteria

- Exact source commit/tree and configuration hashes recorded.
- Every proposed contract version has one producer and explicit consumers.
- Historical versions have a documented disposition: readable, display-only, inference-eligible, or rejected.

### Contract change

No runtime contract change yet; this phase records the change plan.

### Transformer impact

None.

### Historical compatibility

No data is rewritten.

---

## Phase 1 — Correct command authority and trusted ATT&CK promotion

### What will be fixed

1. Replace lexical “clean parse + allowlisted regex” trust with a reusable operation-context authority rule.
2. Require trusted regexes to prove, as appropriate:

   - executable position;
   - relevant source/destination operand;
   - read versus write/modify action;
   - transfer direction;
   - conditional-fragment eligibility;
   - reviewed tactic binding.

3. Immediately correct high-risk cases:

   - inert `echo`/`printf`/`grep` mentions;
   - authorized-keys reads versus writes;
   - reads of service/startup files;
   - miner-token searches;
   - cron/NOPASSWD mentions;
   - skipped `&&`/`||` branches.

4. Preserve unresolved, ambiguous, and unproven fragments as audit-only candidates.
5. Keep SecureBERT-only and rule/model disagreement audit-only.

### Why

These defects contaminate trusted TTP summaries and prediction history even when the typed graph later abstains.

### Main files/functions/contracts

- [classification_pipeline.py](/home/rubchek/Desktop/teammate-repo/honeypot-analysis/production/classification/classification_pipeline.py)
  - compound splitting
  - `_classify_single`
  - structural/regex selection
- [authority.py](/home/rubchek/Desktop/teammate-repo/honeypot-analysis/production/classification/authority.py)
  - `command_authority_decision`
  - `candidate_authority_decision`
- [trust.py](/home/rubchek/Desktop/teammate-repo/honeypot-analysis/production/classification/trust.py)
- [command_operations.py](/home/rubchek/Desktop/teammate-repo/honeypot-analysis/production/semantics/command_operations.py)
- [session_monitor.py](/home/rubchek/Desktop/teammate-repo/honeypot-analysis/production/workers/session_monitor.py)
- [classification_rules.trusted.json](/home/rubchek/Desktop/teammate-repo/honeypot-analysis/configs/classification_rules.trusted.json)
- Classification policy validator
- Classifier environment receipt and hashes

### Required tests

- `echo whoami` does not trust T1033.
- `printf 'wget ...'` does not trust T1105.
- `grep xmrig ...` does not trust T1496.
- `cat /home/x/.ssh/authorized_keys` does not trust T1098.
- authorized-keys destination writes can be trusted when structurally proven.
- `cat /etc/systemd/system/x.service` does not trust T1543.
- startup-file reads do not trust persistence/event-triggered execution.
- direct reviewed modification operations still pass.
- `true || /tmp/a.sh` excludes the RHS from trusted state/history.
- `false && /tmp/a.sh` excludes the RHS.
- ambiguous conditional branches remain audit-only.
- variables, globs, and substitutions continue to abstain.
- SecureBERT-only/disagreement behavior is unchanged.
- Trusted candidate cannot be created without a loaded, reviewed, hash-bound policy.

### Acceptance criteria

- No trusted label can arise from a token merely appearing in inert text.
- Read-only operations cannot satisfy modification/persistence rules.
- A conditional fragment without execution proof cannot enter trusted TTP state or prediction history.
- Every trusted regex rule has an explicit reviewed safety/operation class.
- All current direct, unambiguous mappings continue to work.

### Contract/version change

Introduce:

- `classification_rule_policy.v4`
- `command_authority_decision.v2`
- `classification_event.v3`

Regenerate classifier-environment and dependent policy hashes.

### Transformer checkpoint

The checkpoint bytes must be preserved as an immutable historical artifact. However, these changes can alter trusted phases and targets.

The existing checkpoint must not automatically be declared compatible. After corrected corpus generation:

1. compare old and new phase/input/target fingerprints;
2. if identical for the bound training corpus, re-evaluation may be sufficient;
3. if any trusted labels, phase boundaries, or targets change, retraining and recalibration are required.

Material changes are likely, so planning should assume a new checkpoint while retaining the old checkpoint for reproducibility.

### Historical compatibility

- Historical classification events remain readable under their original policy/environment identity.
- Do not reclassify or backfill old sessions automatically.
- New sessions use v4/v3 contracts.
- Any explicitly requested historical replay must produce a new assessment identity under the new policy, alongside—not over—the historical record.

---

## Phase 2 — Fix durable replay and typed chain/context correctness

### What will be fixed

1. Correct command-index-zero grouping in durable replay.
2. Carry the complete durable watermark `(received_at,event_id)`.
3. Require replay-created history manifests to validate immediately.
4. Replace greedy first-match chain selection with deterministic bounded search for the earliest valid successful subsequence.
5. Propagate confirmed cwd into relative-path identity resolution.
6. Preserve existing failure, ambiguity, chronology, and same-entity abstention.

### Why

Replay currently disagrees with realtime grouping, can construct an invalid cutoff, and misses valid chains after an earlier failed attempt.

### Main files/functions/contracts

- [durable_replay.py](/home/rubchek/Desktop/teammate-repo/honeypot-analysis/production/classification/durable_replay.py)
- [evidence_cutoff.py](/home/rubchek/Desktop/teammate-repo/honeypot-analysis/production/prediction/evidence_cutoff.py)
- [trusted_history.py](/home/rubchek/Desktop/teammate-repo/honeypot-analysis/production/prediction/trusted_history.py)
- SQLite/Mongo session snapshot loaders
- [typed_semantic_chain_selection.py](/home/rubchek/Desktop/teammate-repo/honeypot-analysis/production/reporting/typed_semantic_chain_selection.py)
- [session_behavior_relationships.py](/home/rubchek/Desktop/teammate-repo/honeypot-analysis/production/correlation/session_behavior_relationships.py)
- [typed_semantic_facts.py](/home/rubchek/Desktop/teammate-repo/honeypot-analysis/production/reporting/typed_semantic_facts.py)

### Required tests

- First command with two trusted labels remains one phase in realtime and replay.
- Replay manifest contains canonical `received_at` and `event_id`.
- Replay manifest passes its strict validator.
- Realtime and replay history hashes match for the same exact prefix.
- Failed transfer followed by successful transfer→chmod→execution yields a complete later chain.
- Failed prerequisite without later successful replacement still abstains.
- Successful `cd /tmp` plus relative transfer→chmod→execute resolves to one entity.
- Failed or ambiguous `cd` does not resolve later paths.
- Mismatched paths and unresolved variables continue to abstain.
- Long-session replay stays deterministic and memory-bounded.

### Acceptance criteria

- Same durable prefix produces identical phase grouping, hashes, and graph output in realtime replay.
- All constructed cutoffs are canonical and valid.
- Valid later retries are found without linking unrelated attempts.
- Selection remains deterministic if several valid subsequences exist.
- No combinatorial/unbounded chain search is introduced.

### Contract/version change

Introduce `typed_semantic_chain_selection.v3`.

The storage schema and database indexes do not need to change. Snapshot payloads must expose the existing `received_at` already held by canonical event records.

### Transformer checkpoint

Replay/cutoff corrections alone do not require retraining. If corrected grouping changes model-visible phase sequences, the checkpoint requires compatibility re-evaluation and may require retraining in combination with Phase 1.

### Historical compatibility

- Historical v2 chain selections remain readable.
- New v3 selection IDs may differ.
- Historical assessments must not be rewritten.
- New explicit replay outputs get new identities and provenance.

---

## Phase 3 — Restore canonical authority and create an integrity-bound hypothesis contract

### What will be fixed

1. Keep `behavioral_findings` trusted-only.
2. Keep demoted candidates solely in a clearly named audit collection/graph section.
3. Require every canonical finding to resolve to a trusted authority decision.
4. Introduce a strict hypothesis contract binding:

   - question and scope;
   - status;
   - statement;
   - evidence, fact, entity, relationship, and chain references;
   - chronological ordering;
   - evidence strength;
   - gaps and limitations;
   - falsification/disconfirming conditions;
   - exhaustive/mutually-exclusive flags;
   - semantic coverage;
   - selector and policy provenance.

5. Separate `chain_refs` from `relationship_refs`.
6. Require every reference to resolve through the canonical graph.
7. Preserve selector-v3 provenance.

### Why

Current canonical findings contain audit-only candidates, and hypothesis meaning can be changed into a confirmed-compromise claim without changing the assessment identity.

### Main files/functions/contracts

- [session_assessment_v4.py](/home/rubchek/Desktop/teammate-repo/honeypot-analysis/production/reporting/session_assessment_v4.py)
  - authority application
  - `_hypothesis_sets`
  - validator and assessment identity
- [behavioral_authority.py](/home/rubchek/Desktop/teammate-repo/honeypot-analysis/production/reporting/behavioral_authority.py)
- [threat_hypothesis.py](/home/rubchek/Desktop/teammate-repo/honeypot-analysis/production/reporting/threat_hypothesis.py)
- [canonical_semantic_graph.py](/home/rubchek/Desktop/teammate-repo/honeypot-analysis/production/reporting/canonical_semantic_graph.py)
- Monitor/dashboard/artifact consumers
- AI projection reference validator

### Required tests

- Audit-only finding absent from canonical findings.
- Audit-only finding remains visible in the explicit audit collection.
- Every canonical finding has one trusted authority decision.
- Unknown, audit-only, or conflicting authority reference is rejected.
- Tampering with each hypothesis field changes the ID or fails validation.
- Unknown entity/fact/evidence/relationship/chain reference fails.
- `chain_refs` resolve only to chains; `relationship_refs` only to relationships.
- Incomplete-chain hypothesis survives AI projection validation.
- Full chain has a canonical finding but no stale incomplete-chain hypothesis.
- Prediction, enrichment, campaign, guidance, and AI still cannot affect hypothesis identity.
- Historical v4 fixtures remain readable.

### Acceptance criteria

- No audit-only candidate appears as a canonical finding.
- A hypothesis cannot be converted into an observation or real-host claim without invalidating the report.
- Every hypothesis is fully evidence-grounded and falsifiable.
- Assessment identity covers the complete canonical hypothesis content.
- Old reports are displayed as historical v4, not silently validated as v5.

### Contract/version change

Introduce:

- `threat_hypothesis_set.v2`
- `session_assessment.v5`

`canonical_semantic_graph.v1` may remain if it already contains all required node/reference domains. Otherwise introduce graph v2 rather than changing v1 silently.

### Transformer checkpoint

None. Hypotheses and findings remain excluded from trusted prediction history.

### Historical compatibility

- Historical v4 reports remain immutable and readable.
- No automatic backfill.
- Existing IDs remain historical IDs.
- New v5 assessments receive new IDs.
- UI must label legacy v4 authority/hypothesis semantics rather than adapting them silently.

---

## Phase 4 — Correct prediction history, live model input, target boundary, and evaluation

### What will be fixed

1. Build distinct behavior phases before truncating to eight.
2. Store the last eight distinct phases, not eight commands.
3. Preserve:

   - actual canonical timestamps;
   - duration/elapsed buckets;
   - label provenance;
   - confidence/agreement semantics;
   - audit-only counts;
   - outcome/attempt semantics;
   - original command, label, and phase counts;
   - selected and omitted counts;
   - upstream truncation state.

4. Remove fabricated 1970 timestamps and synthetic rule-only provenance.
5. Version the target to explicitly define:

   - submitted/attempted trusted behavior;
   - failed command handling;
   - skipped conditional exclusion;
   - terminal outcome;
   - multi-label set semantics.

6. Stop creating forecasts after `session.closed`.
7. Use close only to resolve/evaluate the last pre-close forecast.
8. Align runtime triggers with trusted distinct-phase boundaries.
9. Disable weight-eligible automatic feedback until a target-aware evaluator exists.
10. Replace feedback with prefix/cutoff-aware, next-distinct, multi-label evaluation.
11. Fail closed on corrupt/integrity-invalid current prediction snapshots.
12. Define canonical handling of late arrivals.

### Why

The deployed adapter currently does not reproduce the frozen training representation, truncates at the wrong layer, and evaluates the wrong target.

### Main files/functions/contracts

- [session_monitor.py](/home/rubchek/Desktop/teammate-repo/honeypot-analysis/production/workers/session_monitor.py)
- [trusted_history.py](/home/rubchek/Desktop/teammate-repo/honeypot-analysis/production/prediction/trusted_history.py)
- [next_behavior_runtime.py](/home/rubchek/Desktop/teammate-repo/honeypot-analysis/production/prediction/next_behavior_runtime.py)
- [next_behavior_preprocessing.py](/home/rubchek/Desktop/teammate-repo/honeypot-analysis/production/prediction/next_behavior_preprocessing.py)
- [next_behavior_tensor.py](/home/rubchek/Desktop/teammate-repo/honeypot-analysis/production/prediction/next_behavior_tensor.py)
- [session_worker.py](/home/rubchek/Desktop/teammate-repo/honeypot-analysis/production/workers/session_worker.py)
- [feedback.py](/home/rubchek/Desktop/teammate-repo/honeypot-analysis/production/utils/feedback.py)
- Prediction snapshot contract and storage readers
- Prediction policy/model/environment receipts

### Required tests

- Direct offline causal input and live manifest input have identical model-input hashes/tensors.
- Rule+model agreement, confidence, and provenance survive history serialization.
- Five-minute repeated phase remains `over_60s`.
- execution→persistence→discovery×9 produces three distinct phases, not one.
- More than eight distinct phases retain the newest eight in order.
- Manifest and model input both report truncation.
- Audit-only labels never evict trusted phases.
- Failed attempts follow the exact v2 target definition.
- Skipped conditional branches never create phases.
- Login or audit-only events without a history change do not create forecasts.
- Session close creates no new forecast.
- Last pre-close forecast is matched to terminal outcome.
- Auto feedback skips repeated identical phases and supports multi-label targets.
- Wrong cutoff/prefix prevents evaluation eligibility.
- Late arrivals cannot rewrite prior forecast evidence boundaries.
- Integrity-invalid current snapshot is rejected by API/dashboard consumers.
- Exact CPython/PyTorch/private-checkpoint deterministic inference test.
- Measured latency and memory against the reviewed runtime.

### Acceptance criteria

- Offline and live tensors are byte-for-byte identical for bound fixtures.
- No synthetic timestamps or provenance exist.
- Sequence length eight means eight distinct behavior phases.
- Terminal outcome is never predicted after it is already known.
- No old invalid auto-evidence row is eligible for thesis metrics.
- Current snapshots fail closed on integrity errors.
- Runtime prediction boundaries match training-example boundaries.

### Contract/version change

Introduce:

- `prediction_trusted_history_manifest.v3`
- `next_distinct_trusted_behavior_phase_or_session_end.v2`
- corresponding model-input/tensor schema version
- prediction snapshot v4
- target-aware feedback/evaluation contract v2

Update prediction policy, classifier-environment binding, model bundle, compatibility receipt, and release inputs.

### Transformer checkpoint

Preserve the current checkpoint bytes but do not assume compatibility.

Do not run the formal compatibility/retraining gate as part of Phase 4 completion. Phase 4 first implements and validates the corrected history, model-input, target-boundary, and evaluation contracts. The checkpoint decision remains blocked until Phase 7 has completed and the deterministic-semantics freeze has been recorded.

Deferred formal gate, after Phase 7:

1. Reconstruct the corrected corpus under the new classifier/history/target contracts.
2. Compare input and target fingerprints with the original training receipt.
3. If unchanged, re-run full evaluation and calibration on the existing checkpoint.
4. If changed, retrain, recalibrate, and issue a new model-bundle/checkpoint receipt.

Given the classifier authority and target changes, retraining is the expected outcome. Architecture, sequence length eight, vocabulary design, thresholds, and model family should remain unchanged unless evaluation independently demonstrates a need.

### Historical compatibility

- History v1/v2 and snapshot v3 remain readable/display-only.
- Because v2 lacks timestamps/provenance, it must not be silently upgraded for v2 inference.
- Existing auto-feedback rows remain stored but are excluded from corrected metrics.
- Old predictions retain original IDs and calibration provenance.
- No historical production session is resent or re-predicted automatically.

---

## Phase 5 — Enforce one canonical graph consumer for guidance

### What will be fixed

1. Add one shared, validated graph-query abstraction for report, guidance, AI projection, monitor, and dashboard.
2. Make current-policy guidance use either:

   - a validated stored v5 assessment/graph; or
   - an exact durable-prefix reconstruction through the canonical coordinator.

3. Fail closed if exact evidence/graph is unavailable.
4. Remove session-only denormalized-command reevaluation from production APIs.
5. Add exact-key guidance schemas.
6. Bind every output field to:

   - exact policy bytes/hash;
   - policy rule/action definition;
   - graph facts and authority decisions;
   - exact matched predicate/semantic trace;
   - appropriate evidence references.

7. Reject unknown action, alert, execution, and authority fields recursively.
8. Add a complete guidance content digest.
9. Retain manual-only and no-execution invariants.

### Why

Normal builder output is conservative, but consumers can generate or validate guidance outside the claimed canonical evidence boundary.

### Main files/functions/contracts

- [response_guidance_v3.py](/home/rubchek/Desktop/teammate-repo/honeypot-analysis/production/reporting/response_guidance_v3.py)
- [dashboard_api.py](/home/rubchek/Desktop/teammate-repo/honeypot-analysis/production/api/dashboard_api.py)
- [monitor_web.py](/home/rubchek/Desktop/teammate-repo/honeypot-analysis/production/api/monitor_web.py)
- Canonical graph query/resolver module
- Response guidance policy validator
- Artifacts/STIX consumers
- AI projection consumer

### Required tests

- Session payload with commands but no durable evidence produces unavailable guidance.
- Missing, extra, or stale denormalized commands cannot change guidance.
- Unknown fields at every nesting level fail validation.
- `alerts`, `response_actions`, execution-like fields fail.
- Changed prose/rationale fails unless it exactly matches reviewed policy content.
- Policy hash must match actual policy bytes.
- Canonical-but-unrelated evidence reference fails.
- Action refs exactly match successful predicate/trace refs.
- Empty/different graph plus separate fact set cannot select guidance.
- Audit-only evidence cannot trigger guidance.
- `/etc/passwd` versus `/etc/shadow` remains correct.
- Transfer attempt versus confirmed direct transfer remains correct.
- Every action remains manual-only and unsafe for auto-execution.
- Prediction/enrichment/AI/hypothesis context remains selection-inert.

### Acceptance criteria

- Every displayed action can be traced through one shared graph resolver to trusted canonical evidence.
- Current-policy reevaluation cannot bypass exact-prefix semantics.
- Validator-approved prose and actions are exactly policy-authored.
- No unrecognized field can imply execution, authority, or alerts.
- Assessment/guidance hashes are reproducible.

### Contract/version change

Introduce `response_guidance.v4`.

If policy selectors or templates change, create a new guidance-policy version rather than modifying v3 in place.

### Transformer checkpoint

None.

### Historical compatibility

- Historical guidance v3 remains readable.
- Stored historical guidance is never recomputed automatically.
- Current-policy reevaluation, when requested, creates a separate v4 object with explicit new provenance.
- Old v3 guidance is not retroactively validated under v4 rules.

---

## Phase 6 — Integrated must-fix regression and authority re-audit

### What will be fixed

This is the acceptance gate for all mandatory remediation, not a new feature phase.

### Required test layers

1. Classifier and parser
2. Realtime/durable replay parity
3. Typed facts, relationships, and chains
4. Canonical graph/authority
5. Assessment/hypothesis integrity
6. Prediction input/target/evaluation
7. Guidance graph/policy integrity
8. UI/API authority containment
9. AI/prediction non-authority
10. MongoDB/SQLite storage-contract parity where applicable

### Acceptance criteria

- Every critical/high audit reproduction now fails closed or produces the expected bounded output.
- Full repository suite passes.
- Exact private runtime/model tests pass or the model remains disabled.
- No audit-only candidate appears in canonical findings/history/guidance.
- No future/terminal leakage.
- No graph/reference/content tampering passes.
- Historical fixtures remain readable without reinterpretation.
- No database schema migration was introduced.
- No automatic response path exists.
- A new independent read-only behavioral audit returns no critical/high semantic defect.

### Contract/version change

Regenerate:

- policy/environment receipts;
- prediction/model compatibility evidence;
- schema/contract registries;
- release-manifest inputs;
- documentation hashes.

### Transformer checkpoint

The corrected model must pass the final compatibility/retraining gate before prediction is included in thesis evaluation. Deterministic analysis may be thesis-ready independently while prediction remains disabled or explicitly excluded.

### Historical compatibility

No backfill, mutation, or replacement of historical artifacts.

---

# 2. SHOULD FIX

These are not allowed to block deterministic remediation, but should be completed before using the affected dashboard/export/model surfaces in the thesis. If a surface is part of the evaluated demonstration, its corresponding item becomes mandatory.

## Phase 7 — Complete ATT&CK mapping and tactic-context cleanup

### What will be fixed

- Add reviewed per-rule tactic binding.
- Validate each selected tactic against the pinned ATT&CK technique.
- Resolve parent/sub-technique semantics.
- Correct:

  - SCP ingress/egress direction;
  - `known_hosts` versus credential material;
  - `systemctl status` semantics;
  - sudoers boundary matching;
  - structural-first suppression of independent evidence;
  - archive invocation versus completed collection wording;
  - failed-attempt terminology.
- Strengthen the trusted-rule allowlist validator so every entry is unique, exists, is reviewed, has the expected rule type, and agrees with per-rule authority metadata.
- Fail classifier readiness when the pinned MITRE cache cannot resolve a reviewed trusted TTP tactic; do not emit a trusted `unknown` tactic or silently drop it during history normalization.

### Files/contracts

- Classification policy v4
- MITRE cache loader/validator
- Rule-policy validator
- Session TTP knowledge/correlation modules
- Reporting and history consumers

### Tests

- One case per corrected mapping.
- Exact sub-technique parity across classifier, graph, report, and history.
- Tactic binding cannot name a tactic absent from the pinned MITRE entry.
- Multiple independent operations can emit multiple exact candidates.
- Every trusted allowlist entry resolves uniquely to a reviewed authority-compatible rule.
- Missing/unresolvable tactic metadata fails readiness before any trusted state or history is produced.

### Acceptance criteria

- Tactic is evidence-context-bound, not list-order-derived.
- Parent/sub-technique handling is consistent end to end.
- Transfer direction and credential-material semantics are explicit.
- The complete deterministic technique/tactic/history semantics are frozen and fingerprinted for the subsequent checkpoint compatibility/retraining gate.

### Transformer impact

Any changed trusted tactic/technique sequence triggers the same compatibility/retraining gate described in Phase 4. Phase 7 must complete before that gate begins; no checkpoint preservation, retraining, recalibration, or compatibility conclusion may be made from the intermediate Phase 4 state.

### Historical impact

New policy identity and new outputs only; no historical rewrite.

---

## Phase 8 — Correct research/UI terminology and evaluation provenance

### What will be fixed

- Replace singular “Next-Tactic” with the exact target description.
- Display terminal outcome.
- Display calibrated marginal probability only where supported.
- Remove fabricated high/medium/low confidence categories.
- Show forced-top fallback and truncation explicitly.
- Separate weak/developer-label agreement from human-adjudicated accuracy.
- Bind displayed metrics to checkpoint, target, dataset split, label origin, support, and gate state.
- Rename “heuristic probability” wording for categorical evidence.

### Files

- Static monitor dashboard
- Server-rendered monitor
- Evaluation API payloads
- Classification evaluation reports
- Model/evaluation documentation

### Tests

- `confidence=not_applicable` is not rendered as low confidence.
- Terminal forecast renders correctly.
- Mixed-label metrics display “agreement,” not “accuracy.”
- Accuracy is suppressed when independent human support is zero.
- Metrics for another checkpoint cannot appear as active-model metrics.

### Acceptance criteria

No UI term overstates target, confidence, label independence, or model authority.

### Transformer impact

None, beyond binding the correct checkpoint evidence.

### Historical impact

Historical metrics remain available with explicit legacy provenance.

---

## Phase 9 — Replace campaign/attribution and STIX overclaims

### What will be fixed

- Rename campaigns to behavioral similarity clusters.
- Rename attribution confidence to reviewed fingerprint match score.
- First cluster member uses N/A, not 1.0 confidence.
- Reserve STIX Campaign for separately reviewed multi-session evidence.
- Replace strong Indicator/malicious-activity semantics with extracted observable/candidate indicator semantics unless independently supported.
- Replace threat-actor-activity report types and `mitigates` relationships for manual review tasks.
- Keep clustering non-authoritative.

### Files/contracts

- Campaign clustering module
- Monitor/dashboard campaign panels
- STIX/artifact builders
- Campaign/cluster storage payload contract
- Artifact documentation

### Tests

- One session cannot produce attribution confidence.
- Cluster membership cannot affect canonical findings/hypotheses/history.
- Extracted observable is not automatically malicious.
- Manual guidance is not exported as an executed mitigation.
- STIX output uses the reviewed custom/observed-data semantics.

### Acceptance criteria

No UI/export implies actor identity, campaign attribution, maliciousness, or response execution from similarity alone.

### Contract/version change

Introduce behavioral-similarity-cluster v2 and a new artifact/STIX profile version.

### Transformer impact

None.

### Historical impact

Historical campaign objects remain read-only legacy exports. Do not relabel stored historical objects in place.

---

## Phase 10 — Preserve full hypothesis provenance and evidence-layer presentation

### What will be fixed

- Retain evidence gaps, limitations, strength, chronology, disconfirming evidence, and abstention reason in v2 hypotheses.
- Correct nested `non_authoritative_context.threat_evidence_layers` consumption.
- Clearly show observed, attempted, inferred, audit-only, predicted, and hypothesized states.

### Tests

- Every hypothesis renders supporting and missing evidence.
- Audit-only and predicted context cannot appear as observation.
- Nested evidence-layer panel displays the same facts as the assessment.
- No new data becomes authoritative through presentation.

### Acceptance criteria

An evaluator can trace each hypothesis and clearly distinguish it from observed facts.

### Transformer impact

None.

### Historical impact

Legacy hypotheses display with a “legacy reduced provenance” label rather than inferred missing data.

---

## Phase 11 — Reconcile methodology and deployment documentation

### What will be fixed

- Current MongoDB canonical architecture documentation.
- Current active release/model/checkpoint identities.
- ATT&CK cache/version limitations.
- Exact classifier and prediction terminology.
- Explicit lack of empirical command-level accuracy.
- Explicit lack of actor intent, real-host impact, attribution, guidance-effectiveness, and automated-response claims.
- Separate SecureBERT and Transformer offline evaluations.

### Tests/validators

- Documentation references valid files/contracts.
- Current architecture docs agree on storage backend and active release.
- Model/checkpoint references resolve to exact receipts.
- No prohibited research claim appears in canonical thesis-facing documentation.

### Acceptance criteria

The methodology chapter and application surfaces describe the same contracts and limitations.

---

# 3. OPTIONAL improvements

## Phase 12 — Presentation and maintenance cleanup

### Items

- Split path-based and inline-execution guidance templates so inline commands do not render `: not observed`.
- Show all guidance findings rather than only the strongest.
- Preserve external references in STIX guidance.
- Remove dead legacy guidance helpers.
- Correct stale preprocessing comments.
- Improve display of omitted/truncated evidence counts.

The trusted-rule allowlist and unresolved-tactic readiness items originally listed in this phase were promoted to Phase 7 because they can affect trusted technique/tactic/history admission and must be frozen before the Transformer checkpoint decision.

### Tests

- Inline execution produces bounded, grammatical guidance.
- External references survive export.
- Dead paths are unreferenced.
- Unknown-tactic trusted history is impossible.
- All allowlist entries resolve uniquely to reviewed rules.

### Contract impact

Mostly none. Any artifact shape change should use the new artifact profile created in Phase 9.

### Transformer impact

None, except unknown-tactic fail-closed behavior may exclude previously invalid phases and should be covered by compatibility evaluation.

### Historical impact

None.

---

# Recommended execution order

1. **Phase 0** — Freeze the remediation baseline and approve the contract-version matrix.
2. **Phase 1** — Implement operation-context classifier authority, trusted ATT&CK promotion, and conditional-fragment containment.
3. **Phase 2** — Correct durable replay grouping/cutoffs, retry-aware chain selection, and cwd-aware entity resolution.
4. **Phase 3** — Introduce trusted-only canonical findings, `session_assessment.v5`, and the full-content `threat_hypothesis_set.v2`.
5. **Phase 4 implementation only** — Implement prediction-history v3, exact offline/live tensor parity, corrected trigger/terminal boundaries, and target-aware evaluation safeguards. Do not decide checkpoint compatibility or retraining yet.
6. **Phase 7** — Complete every ATT&CK mapping/tactic cleanup capable of changing trusted sequences, including contextual tactic binding, parent/sub-technique handling, transfer direction, credential-material/service/sudoers semantics, independent-evidence handling, allowlist integrity, and unresolved-tactic fail-closed readiness.
7. **Deterministic-semantics freeze gate** — Re-run classifier, replay, history, target-construction, policy, and exact sequence-fingerprint validation. Record that all trusted technique/tactic/history semantics from Phases 1, 2, 4, and 7 are frozen. No model decision is permitted before this gate passes.
8. **Transformer checkpoint compatibility gate** — Reconstruct the corrected corpus and compare exact input/target fingerprints against the original training receipt.
9. **Transformer decision** — Preserve and fully re-evaluate/recalibrate the existing checkpoint only if compatibility is proven; otherwise retrain, recalibrate, and issue a new model-bundle/checkpoint receipt. Preserve the prior checkpoint as immutable historical evidence.
10. **Phase 5** — Implement graph-only `response_guidance.v4` and exact-prefix current-policy reevaluation.
11. **Phase 6** — Run the integrated must-fix regression suite and repeat the independent read-only behavioral-authority audit.
12. **Phase 8** — Correct prediction/evaluation UI terminology and provenance.
13. **Phase 9** — Replace campaign/attribution/STIX overclaims with bounded behavioral-similarity and observable semantics.
14. **Phase 10** — Complete hypothesis provenance and evidence-layer presentation.
15. **Phase 11** — Reconcile methodology, architecture, model, release, and limitation documentation.
16. **Phase 12** — Apply remaining optional presentation and maintenance cleanup; no trusted-sequence-affecting work remains in this phase.
17. Run the full repository suite, exact private runtime/model validation, policy/schema validators, replay parity, deterministic secret scan, and release-review checks.
18. Only after a clean separate review, prepare a new thesis-evaluation release.
19. Deployment, historical replay, and production activation remain separate explicitly authorized workflows.

The first remaining implementation phase is **Phase 0 — Freeze the remediation baseline and version map**. Each phase must be completed, validated, recorded in `REMEDIATION_COMPLETED.md`, removed from this remaining plan without renumbering later phases, and followed by a stop for explicit authorization before the next phase begins.

No implementation, commit, deployment, service action, or production mutation was performed.

**PLAN READY FOR IMPLEMENTATION**
