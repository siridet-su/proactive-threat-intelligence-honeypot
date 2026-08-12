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

3. **Phase 7** — Complete every ATT&CK mapping/tactic cleanup capable of changing trusted sequences, including contextual tactic binding, parent/sub-technique handling, transfer direction, credential-material/service/sudoers semantics, independent-evidence handling, allowlist integrity, and unresolved-tactic fail-closed readiness.
5. **Deterministic-semantics freeze gate** — Re-run classifier, replay, history, target-construction, policy, and exact sequence-fingerprint validation. Record that all trusted technique/tactic/history semantics from Phases 1, 2, 4, and 7 are frozen. No model decision is permitted before this gate passes.
6. **Transformer checkpoint compatibility gate** — Reconstruct the corrected corpus and compare exact input/target fingerprints against the original training receipt.
7. **Transformer decision** — Preserve and fully re-evaluate/recalibrate the existing checkpoint only if compatibility is proven; otherwise retrain, recalibrate, and issue a new model-bundle/checkpoint receipt. Preserve the prior checkpoint as immutable historical evidence.
8. **Phase 5** — Implement graph-only `response_guidance.v4` and exact-prefix current-policy reevaluation.
9. **Phase 6** — Run the integrated must-fix regression suite and repeat the independent read-only behavioral-authority audit.
10. **Phase 8** — Correct prediction/evaluation UI terminology and provenance.
11. **Phase 9** — Replace campaign/attribution/STIX overclaims with bounded behavioral-similarity and observable semantics.
12. **Phase 10** — Complete hypothesis provenance and evidence-layer presentation.
13. **Phase 11** — Reconcile methodology, architecture, model, release, and limitation documentation.
14. **Phase 12** — Apply remaining optional presentation and maintenance cleanup; no trusted-sequence-affecting work remains in this phase.
15. Run the full repository suite, exact private runtime/model validation, policy/schema validators, replay parity, deterministic secret scan, and release-review checks.
16. Only after a clean separate review, prepare a new thesis-evaluation release.
17. Deployment, historical replay, and production activation remain separate explicitly authorized workflows.

The first remaining implementation phase is **Phase 7 — Complete ATT&CK mapping and tactic-context cleanup**. Each phase must be completed, validated, recorded in `REMEDIATION_COMPLETED.md`, removed from this remaining plan without renumbering later phases, and followed by a stop for explicit authorization before the next phase begins.

Completed phases and their immutable commit/test evidence are recorded in `REMEDIATION_COMPLETED.md`. No deployment, service action, or production mutation is authorized by this remaining plan.

**PLAN READY FOR IMPLEMENTATION**
