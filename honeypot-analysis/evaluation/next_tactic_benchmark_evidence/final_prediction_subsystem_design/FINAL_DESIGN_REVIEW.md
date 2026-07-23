# Final design review: next-tactic prediction subsystem

## Executive decision

The existing subsystem is a reproducible **historical next-distinct-single-tactic experiment** and a separate **production external hard-backoff VOMM runtime**. It is not yet a final end-to-end experimental subsystem because the current target:

- flattens simultaneous command labels into an artificial order;
- removes repetition and duration;
- excludes session termination and every session without a transition;
- cannot reproduce live contextual inputs;
- relies entirely on weak labels with incomplete retained provenance;
- reuses the evidenced second validation half for both seed-selection and calibration diagnostics.

The final PoC should forecast the next observable command-derived behavior-phase outcome: an unordered tactic set or `session_end_no_further_trusted_behavior`. Consecutive identical sets should form a phase, with run length and time retained. The Small Causal Transformer remains the preferred **architecture candidate**, but the current checkpoint cannot answer this corrected problem and must not be relabeled as if it could. A new dataset and checkpoint are required. VOMM should remain an interpretable same-target baseline and disagreement reference, not fallback authority, ensemble component, or test-derived router.

No accepted model, benchmark, production policy, or historical record was changed by this review.

## Evidence classification

### Verified facts

- HEAD is `cd199d1606dbb7b5dbf7330553fb220a85c1e151`.
- Active trusted policy uses only the immutable external hard-backoff VOMM and explicitly abstains or reports model unavailable; local VOMM is shadow-only and heuristic progression is a score-free prior.
- The selected Transformer checkpoint is offline only and hash-bound to `d9b316d76e63b15b175668aa0bf69cfe4172bbd812d6b19743a628cd0ec8073d`.
- Accepted payload membership is session-disjoint. The payload has 219,336 sessions and 178,922 current-task cases; test has 12,235 cases.
- Test cases reduce to 45 input histories and 56 input-target pairs.
- Current target labels are classifier-derived weak labels. Raw commands, timestamps, command grouping, source member, and per-label provenance are absent from the public payload.
- Selected Transformer historical results: Top-1 0.886555, Top-3 0.995995, macro-F1 0.509713, balanced accuracy 0.511315.
- VOMM historical results: Top-1 0.800817, Top-3 0.998774, macro-F1 0.396874, balanced accuracy 0.399616.
- Transformer improves 1,887 cases uniquely and VOMM improves 838; Transformer Execution recall is 0.711775 versus VOMM 0.949736, while Transformer Persistence recall is 1.0 versus 0.040223.
- The selected model uses one causal Transformer layer, 16-dimensional embeddings, 32-dimensional feed-forward layer, four heads, dropout 0.1, maximum length 8, and 2,632 parameters.
- Raw VOMM and Transformer scores are not calibrated probabilities.
- Response Guidance v2 requires canonical observed-behavior scope and references; prediction-only evidence is rejected.

### Interpretations

- High nominal case count materially overstates independent predictive diversity.
- The current task is easier and narrower than live next-outcome forecasting because it conditions on a later distinct tactic existing.
- Flattening multiple labels from one command can create transitions that never occurred temporally.
- The Transformer’s accepted advantage supports its architecture as a candidate, not the current checkpoint as a final model under a different target.
- The Execution/Persistence trade-off is evidence of target ambiguity and repeated-pattern sensitivity, not proof that either architecture models attacker intent.

### Unresolved uncertainties

- Exact label-source proportions and error rates.
- Chronological monotonicity and boundary ties from the privacy-minimized payload alone.
- Member/template overlap and whether repeated histories reflect attack templates.
- Performance on future members, live sensors, or organic traffic.
- Whether additional causal inputs improve generalization rather than memorization.
- Whether a calibrated uncertainty mapping is supportable for rare tactics.

## Current architecture assessment

The source-to-runtime trace is in `current_pipeline_map.md`. In compact form:

```text
historical raw Cowrie members
  -> closed SSH sessions and command.input events
  -> reviewed rules + SecureBERT weak labels
  -> flattened command labels
  -> adjacent tactic deduplication
  -> whole-session 70/15/15 split
  -> prefix -> next distinct tactic cases
  -> small Transformer / VOMM evaluation

live Cowrie event
  -> SessionMonitor and trusted classifications
  -> session_features.v1
  -> manifest-bound external VOMM
  -> v2 immutable prediction snapshot
  -> separate report forecast and validated guidance
  -> API/dashboard historical dual-read
```

### Current strengths

- Strong artifact hashes, deterministic checkpoint replay, session-level membership separation, and additive historical compatibility.
- Production VOMM fails closed and has no heuristic fallback.
- Predictions are clearly separated from canonical observations in Session Assessment v3.
- Guidance validation rejects prediction-only action grounding.
- CPU and artifact footprint are small.
- The benchmark preserves adverse per-tactic results rather than reporting only aggregate accuracy.

### Current weaknesses

- Target semantics do not match live continuation uncertainty.
- Event grouping and same-command simultaneity are lost.
- Training/runtime feature parity is absent.
- Weak-label provenance cannot be independently audited.
- Test diversity and rare-class support are low.
- Selection/calibration independence is not supported by the retained evidence.
- Predictive alert and enrichment escalation code still exists, although current policy suppresses external-only forecasts.
- Legacy report wording such as `predicted_next_action` can be confused with the statistical forecast.

## Final target and adjacent-duplicate decision

The recommended target and alternatives are detailed in `target_definition_analysis.md`.

Adjacent duplicate removal should **change**, not simply remain or disappear. Consecutive identical tactic sets should be represented as one behavior phase with:

- repetition count;
- command/event count;
- elapsed duration or missing-time marker;
- merged label provenance;
- evidence references.

This retains the phase-transition value of deduplication without erasing persistence. The next target is the next distinct phase set or terminal session outcome.

## Final inputs

Required:

- causal sequence of tactic sets;
- technique sets when provenance is complete;
- phase run-length bucket;
- phase time-gap/duration bucket;
- label source and confidence bucket;
- conflict/audit-only summary;
- command/labeled-command count bucket;
- session age bucket;
- login outcome;
- confirmed transfer state when identically available offline and live.

Monitoring/stratification only:

- sensor and configuration;
- protocol;
- member/template/family cluster;
- source/campaign fingerprint;
- enrichment and reputation.

Excluded from the minimal model:

- source IP and location;
- raw commands;
- future close status as an input;
- threat-intelligence enrichment;
- post-prediction correlations.

Every field must pass prefix-cutoff counterfactual tests and cross-path tensor parity.

## Label policy

Reviewed deterministic rules and rule/model agreement may enter all experimental roles when their version and provenance are retained. High-confidence SecureBERT-only labels may enter as explicitly weak labels if checkpoint/policy hashes are frozen and conflict is absent. Low-confidence, disagreement, emergency, and unreviewed output remains audit-only.

The final test must report results by provenance and include a blinded human-adjudicated subset. Human review does not silently replace corpus labels; it measures label error and sensitivity.

Prediction remains non-authoritative. Even a highly scored prediction cannot establish an observed tactic, attacker intent, alert, guidance, recommendation, or action.

## Dataset suitability

The current dataset is reasonable only for:

> Historical performance on the frozen classifier-derived Cowrie corpus for the next distinct tactic conditional on another distinct tactic occurring.

It is not sufficient for:

- a corrected phase-or-end task;
- future members or time periods;
- current live telemetry;
- rare-class claims;
- attacker intent or general attacker behavior.

A regenerated corpus is required because the accepted payload irreversibly discarded the fields needed for the final target. More data is required if rare-class and future-period claims are desired.

## Split and evaluation decision

Use whole source members and chronological blocks:

- earliest development members for training;
- next member/block for model and seed selection;
- next member/block for calibration and abstention only;
- latest untouched member/block for a one-time frozen test;
- post-checkpoint sessions for prospective shadow evaluation.

Do not reuse the accepted historical test for any redesigned decision. Use session-clustered primary metrics and member/template/chronological sensitivity. Exact rules are in `evaluation_protocol.md`.

## Model architecture decision

| Model | Role in final design | Reason |
|---|---|---|
| Majority/terminal baseline | Required baseline | Quantifies class and end-outcome prevalence |
| First-order Markov | Required baseline | Simplest interpretable transition model |
| Hard-backoff VOMM | Required interpretable baseline and disagreement reference | Deterministic, efficient, auditable, strong Execution recall historically |
| Interpolated VOMM | Offline comparison | Tests whether hard backoff is too brittle |
| Small Causal Transformer | Preferred primary candidate | Best accepted single-checkpoint aggregate metrics, small CPU footprint, causal sequence model |
| GRU | Secondary experimental comparator | Similar aggregate behavior; no reason to add runtime complexity unless it wins the frozen rule |
| Score blend or tactic routing | Excluded | No independent evidence and high risk of test-derived policy |

The Transformer remains suitable in architecture: causal masking, compact capacity, deterministic CPU replay, and low latency fit the PoC. Its input and output heads must change for phase sets and terminal outcome. The new evaluation may select another model; the architecture is not guaranteed promotion.

## Metrics and promotion

Primary selection uses session-clustered macro-F1 and balanced accuracy over reportable tactic labels plus terminal outcome. Terminal F1 and high-consequence tactic recall are predeclared blockers. Top-1, Top-3, weighted-F1, MRR, confusion matrices, and raw score diagnostics are secondary. Calibration metrics are meaningful only if probability semantics are attempted.

Current case-level bootstrap intervals should not be treated as fully independent because repeated histories and sessions cluster observations. The final design uses session, member, and template/chronological blocks.

## Runtime integration

The v3 schema in `runtime_output_contract.json` is additive:

- current v1/v2 snapshots remain immutable and dual-readable;
- v3 stores target semantics, hashes, redacted input evidence, tactic rankings, terminal outcome, abstention, baseline, disagreement, and explicit authority;
- raw scores are never rendered as percentages;
- reevaluation creates a linked new record and never replaces history;
- missing/mismatched Transformer assets disable v3 only.

For the thesis PoC, integrate only in shadow mode after the redesigned frozen evaluation passes. VOMM remains the production authority during prospective evaluation.

## Authority boundaries

| Consumer | Permitted use |
|---|---|
| Session assessment/threat hypothesis | Separate forecast section only; never supporting evidence for a claim |
| Alerts | No security alert from prediction alone |
| Enrichment jobs | No escalation from prediction alone |
| Guidance/recommendations | No action selection; canonical observed evidence remains mandatory |
| Automated action | Never |
| Analyst prioritization | Not during experimental shadow; later only as explicitly supporting context with observed-evidence priority |
| Dashboard | Display rank, terminal outcome, abstention, baseline disagreement, provenance, and limitations |
| Monitoring | May record drift, failures, latency, and disagreement |

Current configuration suppresses external-only predictive alerts, but final v3 should enforce this in code so a policy overlay cannot accidentally widen authority.

## Monitoring and lifecycle

Prospective shadow monitoring must record:

- future-only cohort membership;
- checkpoint/preprocessing/vocabulary identity;
- tactic and terminal distribution drift;
- phase-pattern and unknown-history drift;
- VOMM disagreement;
- abstention and missing-score rate;
- per-class and chronological performance after ground truth;
- label-source mix and human-audit results;
- inference latency, memory, load failures, and worker isolation.

Retraining is triggered for investigation—not automatic promotion—by sustained drift, support changes, label-policy changes, model failures, or a predeclared performance breach. Every retrain creates a new dataset/model version and restarts validation. No online learning is recommended.

## Gap classification and implementation

`gap_analysis.csv` classifies 20 gaps. The first five priorities are:

1. remove fabricated within-command ordering;
2. add terminal outcomes;
3. retain repetition/time as phase features;
4. preserve label provenance;
5. align or explicitly map historical/runtime trust policy.

The ordered phases, rollback, tests, and acceptance criteria are in `implementation_plan.md` and `acceptance_criteria.md`.

## Direct answers

1. **What should be predicted?** The next distinct command-derived behavior phase as an unordered tactic set, or session end with no further trusted behavior.
2. **Should adjacent duplicate removal remain?** As phase compression only; retain run length, event count, duration, and provenance.
3. **Is tactic history alone sufficient?** No for the final live-aligned task; yes only as the accepted historical baseline.
4. **What inputs should be used?** Tactic/technique phase sequence, repetition/time, provenance/confidence/conflict, session maturity, login state, and confirmed transfer state. Sensor/configuration and enrichment remain monitoring-only.
5. **What labels are acceptable?** Reviewed rules, rule/model agreement, and explicitly weak high-confidence frozen SecureBERT labels without conflict. Audit-only and unresolved labels are excluded. A human-adjudicated audit subset is required.
6. **Is the current dataset reasonable for the final claim?** No. It is reasonable for the narrow accepted historical conditional task only.
7. **What claim is currently defensible?** Historical performance on the frozen weak-labeled Cowrie corpus for next distinct tactic conditional on another distinct tactic.
8. **What claim is not defensible?** Future/live generalization, rare-class reliability, attacker intent, exact next command, or response necessity.
9. **Does the Small Causal Transformer remain correct?** It remains the preferred experimental architecture candidate, but the current checkpoint is not a final model for the corrected task.
10. **What role should VOMM have?** Same-target interpretable baseline, rollback reference, and disagreement diagnostic; no hidden fallback, blend, or routing.
11. **Critical gaps?** Simultaneous-label ordering, missing terminal target, lost repetition/time, missing provenance, trust-policy mismatch, non-independent selection/calibration, weak diversity, and no runtime Transformer adapter.
12. **Must dataset/model be regenerated?** Yes for the final design; both must be versioned separately.
13. **Must historical results be replaced?** No. Preserve them unchanged and label their original target and limitations.
14. **Minimum final experimental PoC?** Phases 0–6 and documentation: frozen contracts, regenerated auditable dataset, independent roles, one validation-selected checkpoint, same-target baselines, one untouched test, clustered metrics, and immutable evidence.
15. **Additional evidence before production use?** Prospective post-freeze sessions, member/time validation, sufficient per-class support, blinded label audit, drift/failure/latency evidence, and rollback rehearsal.
16. **Exact next work?** Approve the target/input/label/metric contract; regain authorized raw corpus and hashes; build the provenance-preserving phase payload; freeze independent member/time splits; retrain same-target baselines and Transformer; calibrate or explicitly decline calibration; run one untouched evaluation; only then add disabled-by-default shadow integration.

## Final boundary

The accepted Transformer’s strong aggregate benchmark result and its Execution regression both remain visible. The final recommendation neither promotes the old checkpoint under new semantics nor discards its evidence. It treats it as the best current indication that a small causal Transformer is worth carrying forward into a scientifically corrected experiment.
