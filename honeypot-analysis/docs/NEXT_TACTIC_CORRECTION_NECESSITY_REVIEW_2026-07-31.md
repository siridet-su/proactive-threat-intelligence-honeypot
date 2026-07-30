# Next-tactic correction-necessity adjudication — 2026-07-31

This is an independent, read-only adjudication. No prediction code, policy,
model, training data, database, service, deployment, or historical record was
changed. Disposable SQLite fixtures were created under the operating system
temporary directory and removed automatically.

## 1. Executive decision

There is no `P0_BLOCKER`. The prediction path remains safe because it is
advisory-only and has no authority for findings, hypotheses, guidance, alerts,
recommendations, or actions.

The earlier list nevertheless mixed four different kinds of concern:

| Issue | Adjudicated result | Severity | Required correction |
| --- | --- | --- | --- |
| A. creation-time “latest” | Reachable correctness defect; not present in the current production rows | `P1_REQUIRED` before a live PoC or analyst use; `P2_RECOMMENDED` for the restricted thesis demonstration | Select by a monotonic durable evidence cutoff, not completion/generation time |
| B. late source timestamp | Reachable session-local prediction failure; normal single-Pi forwarding makes it unlikely but does not make it impossible | `P1_REQUIRED` before a live PoC or analyst use; `P2_RECOMMENDED` for the restricted thesis demonstration | Deterministically rebuild source chronology or explicitly handle late evidence without poisoning later forecasts |
| C. failed/unknown command outcome | Intentional attempt-observation semantics, not proof of effect | `NOT_A_DEFECT` | Terminology only; changing the input would require retraining |
| D. transfer command versus direct transfer | Intentional distinction between a classified attempt phase and a directly observed context bit | `ACCEPTED_LIMITATION` | Document; a proof-scoped phase redesign would require retraining |
| E. compound command grouping | Intentional and scientifically safer than inventing within-command chronology | `NOT_A_DEFECT` | Document; do not split the current target |
| F. trust-policy mismatch | Real, quantitatively small in aggregate, concentrated in rare labels; not evidence of target leakage | `P2_RECOMMENDED` | Publish the semantic/quantitative delta; retrain only if exact train/serve trust alignment becomes a claim |
| G1. runtime audit feature | Real train/serve preprocessing defect: runtime forces a trained feature to zero | `P1_REQUIRED` before claiming evaluated live-input equivalence or redeploying as a live PoC | Preserve representable audit-only labels/counts in live phases and reevaluate; the existing model already supports the feature |
| G2. replay fields | Evidence cutoff is required for A; tensor/phase identity is valuable audit evidence; unchanged-history reason is optional | cutoff `P1_REQUIRED`; tensor/phase identity `P2_RECOMMENDED`; unchanged reason `P3_OPTIONAL` | Additive observability except for the cutoff |
| H. snapshot upsert | Latent immutability defect; legitimate retries can change noncanonical bytes, and storage accepts unchecked canonical tampering | `P2_RECOMMENDED` | First-write-wins or exact canonical-match storage plus read/write integrity validation |
| I. API/detail ordering | Latent correctness/presentation defect; zero current production mismatches | `P2_RECOMMENDED` | One shared evidence-order selector |
| J. terminology | Current warnings are safe, but “next tactic,” “phase,” “primary,” and generic confidence displays can still overstate the target | `P1_REQUIRED` before demonstration/submission as a presentation correction | Use the exact vocabulary in section 11 |

The current subsystem is worth keeping as a **secondary experimental PoC**.
It should not be a primary thesis contribution or an operational predictor.

Under the restricted claim supplied for this review, a controlled thesis
demonstration does not require an emergency code change if it uses ordered,
non-retrying synthetic evidence and explicitly verifies the selected
snapshot's trigger event. It does require terminology and limitation
corrections. A live candidate redeployment should wait for the minimal
runtime corrections in section 9.

## 2. Verified implementation and evidence

### Revision and deployment state

| Item | Independently verified value | Method |
| --- | --- | --- |
| Branch | `professor-approved-poc-evaluation` | local Git |
| Starting HEAD | `cf37f0e22eeefe685b6fde553797d2a3c2671aaa` | local Git |
| Starting worktree | clean | `git status --short --branch` |
| Active GCP release | `19afabd0bb7ed82ac93767301bb0cb1024d0b92e` | read-only private/Tailscale SSH; `/opt/honeypot` and `DEPLOYED_COMMIT` agree |
| Staged candidate | `6964d54326ba59a51cffb2f0d13d9a5b1bd858f2` | release directory and marker present |
| Previous release | `325d136a35f4e9b6cf197cc05565a0798f7b3e14` | release directory and marker present |
| Pi sanitizer | `7f764ab471e8dac555d06277b4613237299aee69` | active Cowrie-output link and manifest agree |
| Live health | no failed GCP unit; ingest/dashboard/monitor health `ok`; Cowrie and forwarder active | read-only SSH |

The first public-address GCP SSH attempt timed out. The same host was then
reached through its previously verified private/Tailscale address. No remote
write was performed.

### Runtime and target contract

The verified data flow is:

```text
Cowrie NDJSON
  -> privacy sanitizer
  -> FIFO disk spool
  -> authenticated ingest
  -> SQLite event (received_at,event_id)
  -> per-session head-of-line worker
  -> reviewed rule/SecureBERT classification
  -> trust adapter
  -> unordered command-level tactic groups
  -> adjacent-equal tactic-set phases
  -> bounded tensor
  -> frozen Transformer
  -> advisory prediction_snapshot.v3
```

Concrete implementation evidence:

- `production/workers/sensor_forwarder.py:176-428` reads complete physical
  log records and handles rotation; `:431-531` appends and consumes a FIFO
  durable spool.
- `production/storage/backend.py:953-975` deduplicates ingested events;
  `:1079-1203` claims them in `received_at,event_id` order with per-session
  head-of-line exclusion.
- `production/workers/session_monitor.py:573-664` classifies input, success,
  and failure events and records `command_outcome`, but outcome is not a trust
  gate.
- `production/prediction/next_behavior_runtime.py:268-385` groups classifier
  outputs, constructs source-relative times, and hard-codes audit labels/counts
  to empty/zero.
- `production/prediction/next_behavior_preprocessing.py:129-150` compresses
  only adjacent equal tactic sets; `:153-213` constructs the bounded model
  input.
- `production/prediction/next_behavior_tensor.py:287-359` includes tactic,
  technique, provenance, repetition, elapsed-time, audit-count, and session
  context features and creates a tensor hash.
- `production/prediction/next_behavior_runtime.py:568-690` converts any
  inference/build exception to a persisted `model_unavailable` snapshot.
- `production/workers/session_worker.py:885-1019` enqueues a captured session
  payload, immediately drains one claim, and completes or retries the outbox.
- `production/storage/backend.py:3736-3782` upserts snapshots and selects
  “latest” by `created_at`; `:4124-4142` lists session rows by `rowid`.

The design record
`evaluation/next_tactic_benchmark_evidence/final_prediction_subsystem_design/target_definition_analysis.md`
explicitly rejects treating multiple labels attached to one command as a
temporal sequence. Its target is the next **unordered tactic set** on the next
distinct command-derived behavior phase, or session end. ATT&CK tactics are
labels in that target, not states in a formal attack-state machine.

### Current production observations

A read-only query of `/var/lib/honeypot/production_pilot.db` found:

- 21,817 total snapshots; 94 are `prediction_snapshot.v3`;
- 7,198 sessions have at least one snapshot;
- all 60 prediction-outbox rows are `completed`, all with exactly one attempt;
- zero tied per-session `created_at` values;
- zero sessions where `created_at DESC` and `rowid DESC` choose different
  snapshots;
- 7,439 stored sessions, 214 with retained classification events;
- zero retained classification timestamp regressions and zero live-builder
  contract failures across those stored session payloads.

These observations show that A, B, and I are not occurring in the current
stored state. They do not prove that the allowed transitions cannot occur.

## 3. Independent reproduction of A–J

### A. Latest prediction selected by creation time

**Reproduced.** A disposable SQLite outbox used two tasks for one session:

1. older evidence was claimed, failed retryably, and received a future
   `next_retry_at`;
2. newer evidence was therefore claimable and completed first;
3. the older task became due and completed second.

Completion order was `event-new`, then `event-old`.
`get_latest_prediction_snapshot()` returned `event-old`, whose fixture
evidence sequence was 1 rather than 2.

Per-session event head-of-line processing does not prevent this. It serializes
event application and initial task creation, but a retry-delayed prediction
task is skipped while a newer queued task is due
(`production/storage/backend.py:3533-3549`). Each task contains a fixed session
payload, so the older task remains valid but stale. Its content-derived ID is
different from the newer task's ID; content identity deduplicates the same
content and does not establish recency.

**Decision:** real latent correctness defect. Current production has no
observed instance because every present outbox row completed on attempt one.
A durable event cutoff—at minimum the triggering event's
`(received_at,event_id)` ordering identity—is required before live/analyst use.

### B. Late-event ordering

**Reproduced.** Two trusted groups retained in arrival order with source times
`00:00:10Z`, then `00:00:05Z`, produced:

```text
NextBehaviorContractError:
observation_groups[1].relative_time_ms must be non-decreasing
```

The predictor catches that exception and returns `model_unavailable`; it does
not raise to the outbox retry handler. Therefore:

- the event and outbox task complete;
- the canonical session continues to be stored;
- the previous valid prediction remains in history;
- the new current row is an unavailable forecast;
- later triggers continue to fail while the regressing group remains in the
  bounded session state.

The single Pi's physical log reader, FIFO spool, front-of-queue
acknowledgement, restart offset, and rotation recovery preserve physical
record order. A network retry does not normally reorder that stream. They do
not prove monotonic timestamps: clock adjustment, a source that appends an
older record, independent sensors, replay/import, or a same-session identity
collision can still violate it. No current production session exhibited the
condition.

Training safe export orders commands by source `event_time,source_line`
(`production/reproduction/next_behavior/safe_export.py:819-840`), while live
construction retains arrival/list order. For this model contract,
deterministically source-sorting the currently available session prefix, with
a stable evidence-order tie-break and explicit invalid-time handling, is more
train-aligned than declaring the model unavailable. Arrival order should
remain the durable evidence/cutoff order; it need not be the model's
source-chronology order.

**Decision:** real latent prediction-availability defect, not canonical
evidence corruption. It is not a blocker for a controlled monotonic demo, but
must be corrected before accepting arbitrary live traffic.

### C. Failed or unknown-outcome commands

**Reproduced.** A reviewed T1082/Discovery classification attached to
`cowrie.command.failed` produced a trusted Discovery observation group. The
trust predicate does not inspect `command_outcome`.

This matches the target's attempt-observation semantics. Cowrie command input,
success, and failure all prove that a command string was observed at the
honeypot. They do not prove a real-host effect. Even
`cowrie_reported_success` is an emulated-honeypot outcome, not confirmation of
system discovery, execution, persistence, or compromise.

**Decision:** `NOT_A_DEFECT` under an attempt-derived label-transition target.
Excluding failure/unknown outcomes, adding outcome as a learned feature, or
predicting effect-confirmed tactics would change input/target distributions
and require retraining and full reevaluation. Terminology is sufficient now.

### D. Transfer attempt versus direct transfer

**Reproduced.**

- A payload containing only `cowrie.session.file_download` produced no
  command-derived phase and therefore no model history.
- With an existing T1105/Command-and-Control command-derived phase, the same
  direct event set `confirmed_transfer_observed=true`.

This is the exact training input design: transfer observation is a context
feature, while a reviewed `wget`/`curl` mapping is an attempt-derived ATT&CK
label. The asymmetry is semantically awkward but intentional and
provenance-distinguishable.

**Decision:** defensible `ACCEPTED_LIMITATION`. A direct transfer may remain
stronger proof-scoped context. Making it a T1105 phase or a new proof-scoped
target changes the phase sequence and requires dataset regeneration,
retraining, and independent evaluation.

### E. Compound-command ordering

**Reproduced and confirmed intentional.** Three trusted fragments for
Discovery, Command-and-Control, and Execution sharing one Cowrie command
index/timestamp became one group:

```text
{command-and-control, discovery, execution}
```

`compound_command_index` is the index of the original Cowrie command in the
session, not the classifier's subcommand index
(`production/workers/session_monitor.py:578-625`). The target design explicitly
requires this grouping because shell separators, conditional execution, pipes,
wrappers, malformed syntax, and emulator outcome do not prove that fragments
executed sequentially.

**Decision:** `NOT_A_DEFECT`. Splitting fragments would manufacture chronology
the evidence does not establish. It would also change the target and require
retraining/full reevaluation.

### F. Train/serve trust-policy mismatch

**Semantic difference verified.** Training trust SHA-256
`1e3518583516a200fc5198ba65cbf10a3f056e4006baa27fc7b5fc6aa835eecd`
is the file at commit `f8a28349…`. Runtime trust SHA-256
`e4fcf976a18e079a493fcab0472bb220d42e42512a8ae78dc9ccb52799c38b39`
is the file at commit `1e506e28…` and current HEAD. The only semantic code
addition is:

```python
if source == "securebert":
    if event.get("model_authority") != "reviewed_trusted_model_only":
        return "audit_only_candidate"
```

The normal classifier does not emit that authority. Runtime is therefore
strictly narrower: model-only SecureBERT labels that previously passed the
0.90 prediction adapter threshold can no longer be trusted. Rule-only and
rule/model-agreement semantics are unchanged.

The immutable build receipt contains 546 trusted model-only SecureBERT labels
among 137,628 trusted classified labels (0.397%). Occurrence-level inspection
of the retained non-final roles found:

| Role | Model-only trusted occurrences | Sessions | Groups with no other trusted label | Mixed groups | Examples directly referencing affected evidence |
| --- | ---: | ---: | ---: | ---: | ---: |
| Train | 775 | 690 / 109,068 | 339 | 436 | 1,302 / 188,968 (0.689%) |
| Selection | 107 | 105 | 94 | 12 | 168 / 58,721 (0.286%) |
| Calibration | 115 | 106 | 89 | 18 | 179 / 54,756 (0.327%) |

In Train, 174 targets directly reference such evidence. The occurrences are
concentrated in Credential Access and Defense Evasion, with smaller Impact and
Persistence counts. Small aggregate prevalence therefore does not prove
negligible rare-class effect. Exact regenerated phase/tensor/metric deltas are
`NOT_DETERMINABLE` without rebuilding under the current policy. The frozen
Final result was not reopened or rescored in this adjudication.

This is distribution/provenance drift, not target leakage: the old label was
derived from evidence available at prediction time and did not use the future.

**Decision:** `P2_RECOMMENDED`, not a hash-only retraining mandate. The frozen
model remains valid as an experiment trained/evaluated under the recorded old
trust policy while serving under a stricter policy. It cannot be presented as
an exact current-policy train/serve evaluation. Exact alignment would require
new training and independent evaluation; disclosure and a fresh
current-policy evaluation of the frozen checkpoint do not themselves require
retraining.

### G. Snapshot replay and observability

The proposed fields do not have equal necessity:

| Field/gap | Finding | Necessity |
| --- | --- | --- |
| monotonic evidence cutoff | Required to prevent A and to identify what “current” means | `P1_REQUIRED` before live/analyst use |
| audit-only evidence/count | Not merely display metadata: it is a trained tensor feature | `P1_REQUIRED` before claiming live-input evaluation equivalence |
| tensor hash | Tensorizer already creates it, but snapshots omit it | `P2_RECOMMENDED` for replay/debug/thesis evidence |
| bounded phase identity | `model_input.input_hash` binds the phase content, and outbox payload supports replay, but the snapshot cannot display or independently compare it | `P2_RECOMMENDED`; a hash/summary is sufficient |
| unchanged-history/tensor reason | Inference is deliberately rerun even when learned input is unchanged | `P3_OPTIONAL` |
| unsupported/audit delta | Needed to explain why a trigger did not add a trusted phase; the current builder hides it | `P2_RECOMMENDED` for audit display in addition to the required tensor count |

The audit feature discrepancy is quantitatively material:

| Role | Examples with at least one nonzero audit-count phase |
| --- | ---: |
| Train | 127,347 / 188,968 (67.39%) |
| Selection | 46,862 / 58,721 (79.81%) |
| Calibration | 31,466 / 54,756 (57.46%) |
| Live adapter | 0 by construction |

`next_behavior_preprocessing.py:84-86,153-169` carries audit counts into model
input, and `next_behavior_tensor.py:315-319` maps them into the audit embedding.
The live adapter instead emits `audit_only_labels=[]` and
`audit_summary.total=0` at
`next_behavior_runtime.py:324-383`.

**Decision:** preserving the audit count is a preprocessing correction, not
optional observability. The model already trained on this vocabulary and
feature, so restoring it does not intrinsically require retraining, but it
changes live tensors and requires full focused and independent reevaluation.

### H. Snapshot mutability

**Reproduced.**

- Two v3 snapshots with identical canonical prediction content but different
  `generated_at`, model-load time, and inference latency had the same
  `snapshot_id` and `snapshot_sha256`.
- Both passed `validate_prediction_snapshot_integrity`.
- Their serialized bytes differed.
- Saving the second replaced the first payload and `created_at`.
- Storage also accepted a deliberately changed canonical reason under the old
  ID; the integrity validator detected both ID and SHA mismatch, but storage
  and API read paths do not call that validator.

This distinction is intentional in
`prediction_snapshot_hash_input()`:
generation/load/inference timing is excluded to keep retry identity stable.
Consequently `snapshot_sha256` is a canonical-content digest, not a byte digest.
The defect is the mutable row and absent enforcement, not the exclusion itself.

Normal v3 worker retries recompute IDs and should produce a different ID if
canonical model output changes. A retry of identical canonical content may
still overwrite the historical generated time/latency. That can also affect
creation-time selection.

**Decision:** latent `P2_RECOMMENDED` immutability defect. Current production
has no retried outbox row. For a historical point-in-time contract, retain the
first valid row for a canonical ID, reject canonical mismatch, and keep retry
timing in the outbox/operational record.

### I. Dashboard/API ordering inconsistency

**Reproduced in an allowed local table state.** Inserting a row with
`created_at=02:00:10` first and one with `created_at=02:00:05` second produced:

- current API choice: first row (`created_at DESC`);
- session-detail choice: second row (`rowid DESC`).

The current production query found zero such sessions and zero timestamp ties.
Ordinary first-attempt completion usually makes insertion and generation order
agree. Backfill/import or a same-ID retry that preserves rowid while updating
`created_at` can break that agreement.

**Decision:** latent correctness/presentation defect, not a proven current-data
failure. Standardize both paths on the same evidence cutoff and deterministic
tie-break.

### J. Terminology

The corrected Transformer panel already says “Experimental PoC,” “advisory /
non-authoritative,” and displays the exact target contract. Those safeguards
are real.

Remaining misleading or ambiguous terms include:

- “Statistical Next-Tactic Forecast” and “Non-Authoritative Next-Tactic
  Forecast”;
- `primary_experimental_poc_predictor` / “primary experimental PoC forecast”;
- generic static-dashboard “Top Prediction,” confidence badges, and percent
  bars that do not always distinguish calibrated model probability from
  factual confidence;
- “phase” without defining it as an adjacent run of equal labels;
- “real-time” where processing is event-driven but user-visible refresh and
  outbox retry are not continuous or strictly current.

Terminology alone is sufficient for C, D, and E. It cannot correct stale
selection, late-history failure, the audit-feature mismatch, mutable storage,
or inconsistent selectors.

## 4. Defect versus limitation classification

| Issue | Primary class | Why |
| --- | --- | --- |
| A | correctness defect | Can present older evidence as current |
| B | reliability/preprocessing defect | One late trusted timestamp can make all later forecasts for a session unavailable |
| C | documented target semantics | Observed attempt is the modeled evidence; no effect is claimed |
| D | model-design limitation | Attempt-derived phase and direct proof-scoped context are deliberately different features |
| E | documented target semantics | Unordered grouping avoids fabricated shell chronology |
| F | scientific-validity/provenance limitation | Runtime trust is stricter than training; small aggregate, rare-class-concentrated delta |
| G1 audit | train/serve preprocessing defect | A trained input channel is constant-zero at runtime |
| G2 hashes/reason | observability/auditability gap | Inference still functions; replay evidence is harder to inspect |
| H | storage integrity/auditability defect | Same row is mutable; integrity exists but is unenforced |
| I | API/UI consistency defect | Two supported read paths define latest differently |
| J | terminology/presentation defect | Can overstate label, outcome, authority, and timeliness semantics |

None of these corrupts canonical Cowrie evidence, grants unsafe authority, or
causes automatic response.

## 5. Use-case-specific necessity matrix

Legend:

- `N`: no correction required for that bounded use;
- `T`: terminology/disclosure or a preflight constraint is required, not a
  behavior change;
- `R`: correction and its tests are required;
- `R*`: correction is necessary but still insufficient for operational
  authority;
- `PROHIBITED`: this predictor must not be used for the purpose.

| Issue | Local testing | Controlled thesis demo | Thesis submission under restricted claim | Isolated deployment test | Live PoC deployment | Analyst use | Operational decisions | Automatic response |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| A latest | N | T: verify trigger/cutoff | T: disclose | N for bounded ordered fixture | R | R | R* plus independent validation | PROHIBITED |
| B late time | N | T: monotonic controlled fixture | T: disclose | N for bounded fixture | R | R | R* plus independent validation | PROHIBITED |
| C outcome | N | T | T | T | T | T | R* if target semantics were ever changed | PROHIBITED |
| D transfer | N | T | T | T | T | T | R* if proof-scoped phases were required | PROHIBITED |
| E compound | N | T | T | T | T | T | R* for a different target | PROHIBITED |
| F trust | N | T | T and quantitative evidence; R only for exact alignment claim | T | T; R for aligned-performance claim | T | R* and fresh validation | PROHIBITED |
| G1 audit input | N | T if no live-performance claim | R for evaluated-live-equivalence claim | R for representative runtime test | R | R | R* and fresh validation | PROHIBITED |
| G2 replay fields | N | N except cutoff preflight | T | N | cutoff R; hashes recommended | cutoff R; hashes recommended | R* | PROHIBITED |
| H mutability | N | N with fixture validation | T | N | R | R | R* | PROHIBITED |
| I read ordering | N | N with explicit current-event check | T | N | R | R | R* | PROHIBITED |
| J terminology | N | T | T | T | T | T | T but still non-authoritative | PROHIBITED |

“Required before automatic response” is deliberately not a fix checklist.
Automatic response remains outside the contract even if every issue is fixed.

## 6. Retraining-impact matrix

| Proposed change | Model/target effect | Retraining | Reevaluation |
| --- | --- | --- | --- |
| A evidence-aware current selection | Storage/API only | No | Runtime ordering/integration tests |
| B source-chronology rebuild and late-event handling within existing schema/vocabulary | Runtime preprocessing; aligns with source-time training order | No by itself | Yes, focused plus fresh representative holdout |
| C exclude failed/unknown commands or add outcome feature | Changes input population/features and possibly targets | Yes | Full new experiment |
| D make direct transfer a tactic phase | Changes phases, context, and targets | Yes | Full new experiment |
| E split compound fragments into ordered phases | Changes target definition | Yes | Full new experiment |
| F train under current trust policy | Changes training examples/labels/phases | Yes | Full independent experiment |
| F disclose/quantify or evaluate frozen model on current-policy data | No checkpoint change | No | Yes; cannot rewrite the immutable old result |
| G preserve audit-only count in live input | Restores an already trained feature/vocabulary | No by itself | Full focused runtime and independent semantic/performance evaluation |
| G add cutoff/phase/tensor hashes or unchanged reason | Additive envelope only | No | Integrity/replay tests |
| H immutable storage enforcement | Storage only | No | Migration/compatibility/integrity tests |
| I shared selector | API/storage only | No | API/UI consistency tests |
| J terminology | Presentation only | No | Contract/UI wording tests |
| Replace tactics with techniques or typed semantic operations | New target/input/architecture choice | Yes | Full new experiment |

No retraining should be ordered merely because two hashes differ. Retraining is
necessary only when the evidence population, features, phase construction, or
target changes and exact alignment is required.

## 7. Thesis-claim assessment

Proposed restricted claim:

> An experimental, event-driven advisory Transformer forecast of the next
> distinct trusted ATT&CK-derived tactic-set observation or session end,
> evaluated on classifier-derived weak labels, with no authority for alerts or
> response.

**Decision: supported after terminology corrections and explicit limitation
disclosure, but not as a claim of exact deployed-runtime performance.**

The claim is true at the model-contract level:

- target and output are next distinct unordered tactic set or terminal;
- inputs/targets are classifier-derived weak labels;
- the model is event-triggered;
- authority fields prohibit alerts and response.

The thesis must additionally disclose:

1. “trusted” is a policy disposition for a classifier-derived label, not
   ground truth;
2. command mappings describe observed attempts, even on failure;
3. “phase” is a compressed adjacent run of equal tactic sets, not ATT&CK
   progress or completion;
4. direct transfer is proof-scoped context, not a phase;
5. training used trust SHA `1e351858…`, while serving uses stricter
   `e4fcf976…`;
6. runtime currently zeros the audit-count channel used by most non-final
   evaluation examples;
7. no current production ordering failure was observed, but retry/late-event
   fixtures prove latent failure modes;
8. rare/absent tactic performance and independent live validation remain
   limited;
9. the immutable old evaluation is not rewritten as current-policy evidence.

Adjacent identical tactic-set compression is correct for this target because
repetition count/duration remain features and a transition is defined as a
different set. It must not be described as a finite-state ATT&CK phase model.

Tactic labels are a defensible coarse PoC target: the available classifier
labels and small model provide enough support for a bounded aggregate
experiment, while technique or typed-operation targets would be substantially
sparser and require a new study. Tactics are not precise enough for response,
intent, or operational claims.

The most accurate short name is:

> **attempt-derived ATT&CK tactic-set transition forecast**

or, when space permits:

> **advisory forecast of the next distinct trusted classifier-derived ATT&CK
> tactic set or session end**

## 8. Options 1–4

| Option | Benefits | Risks | Size | Retraining | Evaluation | Thesis/deployment impact | Recommendation |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1. No runtime correction | Preserves frozen behavior and artifacts; smallest immediate scope | Leaves stale-current, late-session, audit-feature, immutability, and selector gaps | Documentation/UI only | No | Wording/preflight only | Acceptable for a controlled secondary demo; not for a live candidate redeploy or exact runtime-performance claim | Conditional fallback only |
| 2. Minimal correctness correction | Fixes currentness, late evidence, trained audit feature, immutability, and consistent reads without changing target | Changes some live tensors/outputs; needs careful historical adapters and deployment testing | Small-to-medium modular change across runtime, storage/API, contracts, and tests | No by design | Focused/full tests plus fresh representative evaluation | Best balance; preserves checkpoint and thesis scope | **Recommended** |
| 3. Scientific input-contract correction | Could distinguish outcomes/proof and adopt current trust everywhere | Large new target/data decision; fewer labels; rare classes may worsen; post-hoc redesign risk | Large experiment generation | Yes | New preregistered train/select/calibrate/test cycle | Delays thesis and invalidates comparability with frozen result | Defer; not justified by present evidence |
| 4. Appendix-only Transformer | Maximally honest if correction/evaluation time is unavailable; deterministic v4/v3 remains primary | Reduces prediction contribution and demonstration prominence | Small writing/UX change | No | Preserve old experiment unchanged | Strongest fallback for submission; no live predictor claim | Use if Option 2 cannot be independently validated |

Option 2 is not an architecture change. It should preserve
`prediction_snapshot.v3` historical readers, the checkpoint, target,
advisory-only authority, and deterministic canonical evidence.

## 9. Smallest recommended correction scope

### Immediate thesis/demo scope without model-behavior change

1. Adopt section 11 terminology everywhere the corrected-target model is
   presented.
2. Publish the trust-policy and audit-channel deltas in the thesis/model card.
3. For a controlled demonstration, require:
   - monotonic synthetic source timestamps;
   - zero pending/retry outbox rows;
   - selected snapshot event ID equals the last demonstrated trigger;
   - snapshot integrity validates;
   - no prediction-created alert/guidance/action.

This is sufficient for the restricted secondary-PoC claim.

### Before a live candidate redeployment

1. **Evidence currentness:** bind every task/snapshot to the durable trigger
   cutoff `(received_at,event_id)` or an equivalent monotonic session sequence;
   select and supersede by cutoff, then deterministic ID.
2. **Late evidence:** build the model history from deterministic source
   chronology within the captured causal prefix, with stable evidence-order
   tie-breaks and explicit invalid/ambiguous timestamp abstention. A late
   record must not permanently poison later predictions.
3. **Audit feature:** retain representable audit-only candidates on groups that
   contain trusted labels, populate phase audit counts, and expose aggregate
   excluded-evidence reasons without promoting them.
4. **Immutable snapshot rows:** validate v3 integrity on write/read; retain the
   first valid payload for a content ID; reject canonical mismatch; keep retry
   timing operationally separate.
5. **One selector:** use the same evidence-aware ordering in current API,
   monitor detail, recovery cache, feedback selection, and retention logic.
6. **Additive replay evidence:** persist tensor hash and a privacy-safe bounded
   phase-sequence hash/summary. An unchanged-tensor reason may be added but is
   not a gate.
7. Run late/retry/restart/backfill/tie/history-compatibility tests and a fresh
   independent, non-authoritative evaluation. Do not alter the frozen Final
   result.

If this scope cannot be completed and independently evaluated, use Option 4
rather than changing the target hurriedly.

## 10. Issues explicitly deferred

The following should not be changed in the present correction:

- failed/unknown command inclusion in an attempt-derived target;
- direct transfer as context rather than a tactic phase;
- unordered same-command labels;
- adjacent identical-set compression;
- tactic target replacement with techniques or typed semantic operations;
- architecture, class weighting, calibration, thresholds, or OOD policy;
- retraining solely to erase the trust hash difference;
- VOMM substitution or fallback;
- prediction authority, alerts, guidance, or automatic response;
- immutable historical snapshot/model/evaluation rewriting.

Future research may define a proof-scoped typed-operation forecast or an
outcome-aware model, but that is a separate target and experiment.

## 11. Exact terminology required when issues are deferred

Use:

- “event-driven advisory forecast,” not “real-time continuous prediction”;
- “next distinct trusted classifier-derived ATT&CK tactic-set observation or
  session end,” not “next attacker action” or unqualified “next tactic”;
- “attempt-derived ATT&CK label” for command classifications;
- “Cowrie-reported command success/failure,” not “action succeeded/failed on
  the host”;
- “Cowrie-observed direct transfer” for upload/download events;
- “adjacent run of equal tactic-set labels” when defining a behavior phase;
- “calibrated model probability under the frozen weak-label experiment,” not
  “confidence that the attacker will do this”;
- “secondary experimental PoC predictor,” not “primary system authority”;
- “current by durable evidence cutoff” only after A/I are fixed; before then,
  say “most recently generated stored snapshot”;
- “no alert, hypothesis, guidance, recommendation, or action authority.”

Required display disclaimer:

> This secondary experimental model forecasts the next distinct
> classifier-derived ATT&CK tactic set, or no further trusted behavior, from
> attempt-derived Cowrie observations. It does not predict a literal command,
> prove tactic completion or real-host effect, establish intent, or authorize
> alerts or response.

## 12. Final go/no-go decisions

1. **Before the thesis demonstration:** **GO WITH CONDITIONS.** No prediction
   code correction is mandatory for a bounded, monotonic, no-retry
   demonstration under the restricted claim. Terminology, disclosures, event
   binding, integrity, and prohibited-authority checks are mandatory.
2. **Before thesis submission:** **GO only as a secondary experimental PoC.**
   Correct terminology and quantitative train/serve disclosures are required.
   If the thesis claims that frozen metrics validate the deployed live-input
   path, it is **NO-GO** until G1 is corrected and a fresh aligned evaluation
   is completed.
3. **Before redeploying the candidate as a live PoC:** **NO-GO pending Option
   2.** A, B, G1, H, and I should be corrected and tested. The separate
   activation-health/fallback gates in
   `STABILIZATION_RECOVERY_ACTIVATION_BLOCKER_HANDOFF_2026-07-30.md` also
   remain mandatory.
4. **Documented limitations that may remain:** C, D, E, the small F mismatch
   under explicitly old-policy training semantics, rare/absent tactic
   performance, weak labels, lack of external validation, and no OOD
   abstention after valid inference.
5. **Changes requiring retraining:** outcome/proof filtering or features,
   direct-transfer phases, ordered compound fragments, exact current-policy
   training alignment, tactic-to-technique/typed-operation targets, or any
   target/architecture change. A/B/G runtime restoration/H/I/J do not
   intrinsically require retraining but do require reevaluation.
6. **Keep the subsystem:** **YES.** It provides a bounded, reproducible
   experimental comparison and a useful advisory demonstration.
7. **Primary or secondary claim:** **SECONDARY.** Canonical deterministic
   evidence, `session_assessment.v4`, and `response_guidance.v3` remain the
   defensible primary system contribution.
8. **Smallest rational plan:** terminology/disclosure immediately; Option 2
   before live redeployment; fresh aligned evaluation; retrain only if a
   separately approved scientific target/alignment claim requires it.
9. **Do not change now:** the attempt-derived target, unordered compound
   grouping, adjacent-set compression, model architecture/artifacts,
   classifier rules, thresholds, VOMM mode, historical records, or
   advisory-only/no-response authority.

Final adjudication: **correction is necessary for representative live
redeployment and exact runtime-evaluation claims, but a wholesale scientific
redesign or immediate retraining is not justified.**
