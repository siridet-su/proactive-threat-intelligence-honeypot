# Final experimental and prospective evaluation protocol

## Principles

1. Split whole sessions before generating examples.
2. Preserve event groups; never assign labels from one session to different roles.
3. Freeze preprocessing, label, vocabulary, split, model, and decision rules before opening the final test.
4. Never select a checkpoint, threshold, tactic policy, or routing rule from final-test errors.
5. Treat repeated examples from one session/template/member as correlated.
6. Present raw model scores as scores unless a separate calibration procedure establishes probability semantics.
7. Preserve the accepted historical test as historical evidence; do not reuse it as the final redesigned test.

## Required source partitions

The regenerated corpus must preserve content-hashed source-member identity, pseudonymous session identity, configuration, event time, and optional template/family cluster identity.

| Role | Recommended construction | Allowed use | Forbidden use |
|---|---|---|---|
| Development train | Earliest whole source members/time blocks, approximately 60% | Fit weights for every declared seed | Threshold selection, final claims |
| Model-selection validation | Next whole member/time block, approximately 15% | Architecture, epoch, seed, feature ablation, primary metric selection | Calibration and final reporting |
| Calibration/abstention validation | Next whole member/time block, approximately 10% | Score mapping, prediction-set threshold, OOD/abstention threshold only | Model/feature/seed selection |
| Frozen historical test | Latest untouched whole member/time block, approximately 15% | One final evaluation after all decisions freeze | Any tuning or post-hoc routing |
| Prospective shadow set | Sessions beginning after checkpoint and manifest freeze | External-validity and drift evidence | Retraining or threshold changes during the window |
| Human-adjudicated audit subset | Stratified sample drawn and labeled under a blinded protocol | Label-quality and weak-label sensitivity | Replacing corpus labels silently |

With only seven weekly members, use four earliest members for training, the fifth for model selection, the sixth for calibration, and the seventh for frozen test, subject to a pre-run minimum-support check. If minimum support is inadequate, collect more members rather than moving test examples backward. Configuration is not an input feature; report leave-one-configuration-out or per-configuration diagnostics.

Template/family cluster identity should be used for diagnostics and cluster intervals. If a robust pre-model clustering method is available, add a separate template-family holdout. Do not invent clusters from final-test model errors.

## Frozen artifacts and receipts

Before training, create a signed or content-hashed manifest containing:

- source dataset name, license, member names, byte sizes, and SHA-256 hashes;
- collection range and configuration coverage;
- raw-to-safe event counts and exclusion reasons;
- safe session membership hash for every partition;
- empty intersection proofs;
- event-group and phase-construction policy hash;
- classification rule, trust policy, SecureBERT identity, and checkpoint hashes;
- vocabulary and `SESSION_END` contract;
- preprocessing code commit and environment lock hash;
- feature schema and normalization/bucket boundaries;
- random seeds, architecture search space, epoch rule, optimizer, and loss;
- selection metric and all promotion blockers;
- calibration method or an explicit `not_implemented`;
- ordered example membership hashes;
- output artifact/checkpoint hashes.

Historical raw commands need not be put in the repository. The manifest must be sufficient to verify authorized private artifacts without exposing them.

## Model-selection rule

Primary metric: session-clustered macro-F1 over reportable tactic labels plus the terminal outcome, computed on the model-selection partition.

Tie-breakers, in order:

1. session-clustered balanced accuracy;
2. lower worst reportable-class recall regression relative to the predeclared VOMM baseline;
3. higher terminal-outcome F1;
4. lower p95 real single-case CPU inference latency;
5. lower seed.

A class is reportable only with at least 30 independent target sessions and at least 30 targets. Unsupported classes stay in the confusion matrix and are marked descriptive.

Predeclared selection blockers:

- any session/member/template membership overlap;
- label or feature values created after the prediction point;
- malformed or provenance-incomplete trusted labels;
- collapse of a reportable class to zero recall when the baseline recall is nonzero;
- greater than 0.10 absolute recall regression for a predeclared high-consequence reportable tactic such as Execution, unless the design freeze explicitly assigns a different cost before test access;
- nondeterministic replay or checkpoint/proprocessing hash failure.

These blockers are design-time rules, not policies derived from the accepted test errors.

## Calibration and abstention

If only ranked scores are displayed, do not calibrate and set `calibration.status=not_implemented`.

If probabilities or a prediction set are required:

- fit one predeclared method on the calibration partition only;
- consider temperature scaling for the single-label terminal head and classwise or vector calibration only if support permits;
- for multilabel tactic marginals, report Brier/log loss and reliability per reportable class;
- select set thresholds only on calibration data;
- freeze the mapping hash with the checkpoint;
- verify calibration on the untouched test without refitting.

Abstention should be triggered by model unavailability, schema/hash mismatch, missing required features, or a predeclared OOD/uncertainty rule. It must not be silently replaced by VOMM or a heuristic. Coverage and selective performance must be reported together.

## Metrics

### Primary

- session-clustered macro-F1 across reportable tactic labels and terminal outcome;
- session-clustered balanced accuracy;
- terminal-outcome F1 and tactic-versus-end discrimination.

### Secondary

- per-tactic precision, recall, and F1;
- micro- and weighted-F1;
- Top-1 and Top-3 tactic accuracy for examples whose next outcome contains a tactic;
- multilabel precision@k, recall@k, and exact-set accuracy;
- MRR over true next-tactic members;
- coverage, abstention rate, and selective primary metrics;
- Brier score, log loss, reliability curves, and ECE only with correctly defined score semantics.

### Promotion blockers

- split/provenance/hash failures;
- material predeclared high-consequence recall regression;
- model/checkpoint nondeterminism;
- inability to fail closed;
- historical record rewriting;
- prediction affecting claims, alerts, guidance, recommendations, or actions without canonical evidence;
- p95 CPU latency or memory above predeclared deployment budgets.

### Diagnostic

- confusion matrices;
- performance by context length, phase run length, session age, support, label source, confidence bucket, configuration, member, and chronological window;
- rare-class support;
- Transformer/VOMM disagreement;
- terminal prevalence;
- unknown-history and missing-feature rates;
- pattern/template concentration;
- class and sequence drift.

Low-support metrics must display numerator, denominator, and interval and must not enter the primary aggregate as if stable.

## Confidence intervals and dependence

Do not bootstrap individual transition rows as independent observations. Use:

- whole-session cluster bootstrap as the default interval;
- source-member block bootstrap/sensitivity where member count permits;
- template/family cluster bootstrap when a pre-model cluster ID exists;
- chronological block intervals for drift;
- paired cluster bootstrap for Transformer versus VOMM differences.

For only seven source members, member-block confidence intervals are coarse; report all leave-one-member-out results rather than hiding instability behind a nominal 95% interval.

## Model comparison

Train and evaluate these baselines on the exact regenerated target and inputs:

- majority/terminal prevalence;
- first-order Markov over phase states;
- hard-backoff VOMM;
- interpolated VOMM;
- selected small causal Transformer family;
- GRU as retained experimental context if resources permit.

VOMM should be rebuilt under the new target contract and used as an interpretable baseline/disagreement reference. It must not serve as a hidden fallback. Do not blend scores or route by tactic unless the scheme is specified before final-test access and validated independently.

## Runtime performance measurement

Measure checkpoint load, warm single-case latency, p50/p95/p99, batch throughput, process RSS delta, isolated model memory where feasible, artifact size, and failure recovery on the intended CPU host. Do not substitute dictionary lookup or saved-prediction access timing for inference timing.

## Prospective shadow protocol

Freeze checkpoint, code commit, preprocessing, vocabulary, label policy, calibration, and start timestamp. Accept only sessions whose first event is after the timestamp. Store authoritative VOMM and Transformer outputs separately, but neither model may change observed-evidence decisions during the evaluation.

Minimum evidence before any stronger operational claim:

- a predeclared duration and sample requirement;
- enough independent reportable targets per important tactic;
- no checkpoint or threshold change mid-window;
- prospective per-class, terminal, disagreement, abstention, latency, and failure results;
- label audit on a blinded sample;
- documented drift and missing-score rates;
- rollback rehearsal.
