# Final acceptance criteria

## A. Experimental subsystem final

Every item is mandatory.

- [ ] Target is frozen as next distinct command-derived behavior-phase tactic set or terminal session outcome.
- [ ] Simultaneous labels are unordered; label-list order cannot change an example.
- [ ] Adjacent phase compression retains run length and available elapsed time.
- [ ] Every eligible prefix has a next-phase or terminal target.
- [ ] Training and live preprocessing share one versioned implementation and pass golden tensor parity.
- [ ] Every trusted target retains rule/model/checkpoint/policy/confidence/conflict/evidence provenance.
- [ ] Low-confidence, disagreement, emergency, and unreviewed labels are audit-only.
- [ ] Source members have SHA-256 receipts and privacy-safe member/session/event-group identities.
- [ ] Whole-session train, selection, calibration, and final-test roles are disjoint.
- [ ] Selection and calibration partitions are independently used and enforced by code.
- [ ] The accepted 2026-07-21 historical test is not used to select or tune the redesigned model.
- [ ] Model, feature, epoch, seed, threshold, calibration, and promotion rules were fixed before opening the final test.
- [ ] One checkpoint is selected on validation only and deterministically replays.
- [ ] VOMM and other baselines use the same target, examples, and test cases.
- [ ] Final metrics use session-clustered intervals and report member/configuration/time sensitivity.
- [ ] Unsupported tactics are explicitly descriptive or unavailable.
- [ ] Raw scores are not presented as probabilities.
- [ ] Artifact, manifest, checkpoint, vocabulary, preprocessing, membership, and code hashes verify.
- [ ] Full focused and feasible repository tests pass.
- [ ] Historical snapshots, reports, APIs, and accepted benchmark evidence remain unchanged and readable.
- [ ] Thesis/model card state the narrow Cowrie weak-label claim and all adverse findings.

## B. Shadow deployment ready

Requires all Section A items plus:

- [ ] Transformer loader validates exact hash, architecture, parameter count, state dictionary, vocabulary, preprocessing, and manifest.
- [ ] Missing or invalid Transformer assets disable shadow scoring only.
- [ ] Enabling shadow scoring leaves authoritative VOMM snapshot bytes unchanged for identical inputs.
- [ ] Transformer results use a separate schema/storage field and explicit experimental authority.
- [ ] No Transformer field can alter alerts, enrichment jobs, assessment claims, guidance, recommendations, action eligibility, automatic action, or analyst priority.
- [ ] Policy-overlay and forged-payload adversarial tests prove zero authority.
- [ ] API, reports, and UI label target semantics, raw scores, terminal outcome, abstention, and disagreement consistently.
- [ ] Future-only start timestamp and checkpoint freeze manifest exist.
- [ ] Backfill cannot enter the prospective cohort.
- [ ] Storage growth, retention, CPU latency, memory, and worker failure isolation meet frozen budgets.
- [ ] Backup, rollback, and controlled-event procedures are rehearsed.
- [ ] Explicit deployment authorization has been given.

## C. Production-generalization claim ready

Requires Sections A and B plus:

- [ ] Prospective post-freeze cohort reaches predeclared duration and independent target counts.
- [ ] At least 30 independent target sessions exist for every tactic included in stable claims; higher thresholds should be used when feasible.
- [ ] Member/time/configuration and sequence-pattern drift are reported.
- [ ] Unknown-history, abstention, missing-score, model-error, and disagreement rates are acceptable under predeclared limits.
- [ ] A blinded human-adjudicated subset quantifies weak-label precision and inter-rater agreement.
- [ ] Performance survives session/member/template clustered uncertainty analysis.
- [ ] No unexplained material regression exists for predeclared high-consequence reportable tactics.
- [ ] Operational latency, memory, model-load integrity, and rollback are validated on the intended host.
- [ ] The claim is limited to observed Cowrie behavior; attacker intent and real-host outcome remain excluded.

## D. Never-authorized behavior

Regardless of evaluation status:

- prediction alone must not establish observed behavior or attacker intent;
- prediction alone must not create a security alert or enrichment escalation;
- prediction alone must not select response guidance or recommendations;
- prediction alone must not authorize or execute an action;
- a VOMM/Transformer ensemble or tactic router must not be introduced from held-out-test error inspection;
- old snapshots must not be silently recomputed under a new model;
- uncalibrated scores must not be labeled probabilities.

## Current status at HEAD

| Gate | Status | Reason |
|---|---|---|
| Accepted historical experiment computationally reproducible | Pass with limitations | Frozen payload/checkpoint/test hashes and deterministic replay validate |
| Correct final target/data contract | Not implemented | Terminal outcomes, grouped labels, repetition, time, and provenance are absent |
| Independent selection/calibration roles | Fail | Both evidenced records use the same second validation half |
| Final redesigned model | Not trained | Existing checkpoint answers the old target |
| Shadow deployment ready | Fail | No Transformer runtime path exists |
| Production-generalization evidence | Fail | No prospective cohort or human-adjudicated truth set |
