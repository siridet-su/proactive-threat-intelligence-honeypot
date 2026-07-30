# Existing next-tactic checkpoint compatibility review

Date: 2026-07-31

Branch: `professor-approved-poc-evaluation`

Frozen evaluator revision: `638f51e77331bf1d7875e228830da7f6862f90a4`

Decision: `COMPATIBLE_WITH_DISCLOSED_LIMITATIONS`

## Scope and immutable decision

This review evaluates whether the existing frozen Transformer checkpoint remains
compatible after the smallest evidence-based runtime corrections. It does not
retrain, recalibrate, replace, or download a model. It does not alter the
classification rules, target definition, training partitions, production data,
services, or deployment.

The checkpoint is compatible with the corrected runtime and current trust policy.
Retraining is **not required for this correction**. The corrected current-policy
replay has no material aggregate regression from the exactly reproduced
old-policy reference, and the restored audit feature is representable by the
existing vocabulary and model architecture. The remaining class-coverage and
rare-class recall limitations must be disclosed; they are not repaired by this
runtime change.

## Corrections assessed

The implementation is split into reviewable rollback boundaries:

| Commit | Correction |
|---|---|
| `5a0f2d5` | Recorded the immutable starting state, policy and artifact hashes, target contract, and deployment observations. |
| `936892a` | Bound predictions to a durable `(received_at, event_id)` evidence cutoff and made every consumer use the same canonical snapshot selector. |
| `bb2b425` | Enforced strict v3 snapshot integrity, first-valid-write-wins immutability, idempotent exact retries, and rejection of conflicting writes. |
| `e39b2d1` | Shared deterministic source chronology between corpus and runtime and replaced timestamp clamping/permanent poisoning with bounded explicit abstention. |
| `d683a71` | Restored the training-time audit-context feature without promoting audit-only candidates into trusted phases; added tensor provenance. |
| `638f51e` | Added the frozen current-policy compatibility corpus and three-arm checkpoint evaluator. |

The target remains exactly
`next_distinct_command_behavior_phase_or_session_end.v1`: the next distinct
trusted, classifier-derived ATT&CK tactic set, or session end. ATT&CK candidates
that do not satisfy the current reviewed trust policy are audit context only.
They cannot create observations, targets, findings, guidance, or alerts.

## Artifact and policy identity

The evaluation verified content, not filenames:

| Item | SHA-256 |
|---|---|
| Frozen checkpoint | `7fbd73c4bd071336fa52a589bf41e39f5a3122a67aee398dfb8e6dd9cfdfb04a` |
| Model specification file | `2f4ea5531ce08adbd78f53832d7a6e23ba34617549c56aa50f04d069dee6ccc6` |
| Model specification identity | `82b1a15ec96f5165878ee03639daa61e319f06c4376e0a9a8018f3e1a2b3e512` |
| Vocabulary file | `1b46db302d2a92f80f1385e63fa01968cc23a9ce50cb77ef24f20ce8a9e494e9` |
| Vocabulary identity | `527a65c6d6cee94a3bbb0af6d5df95981a6438cf703e053484c9e7e116f0306f` |
| Calibration file | `528bdd8f21d7e0a5f4446657639ccbc994b9d469876e8f026eb716e9a8d7cc9` |
| Calibration identity | `aa27813af96eaa2674b07d76f41565e71835bfa1a5bba8a3232eaa0a396a4e2d` |
| SecureBERT checkpoint | `dc3a4e2a57a70c4c7cb5f769b6399f32b2b51f0245025653e0b72f6d025a759b` |
| Reviewed classification rules | `33f332946c53578f2e609a3a039dda712355b9e209721bcc073c61a623d6342b` |
| MITRE cache | `33af47bb0a3475cda60c2bea83ce305244bd747021f9e999652dc21520e4e35c` |
| Preprocessing contract | `890569a4597df2f300d7c885a2cf0bd34a9fd9fbdd0ab0938141a8f13f4a25c1` |

Checkpoint metadata also verified parameter count `3,951`, initialization seed
`20260721`, state-dictionary SHA-256
`f6fd0f3b9dbbb11a5d9d222dbee56fc38b06da087829a88b524e825f84a109ce`,
and PyTorch `2.13.0+cpu`.

## Frozen evaluation protocol

The implementation, thresholds, three evaluation arms, role, and prohibition on
post-final adaptation were committed before the test role was opened. The final
role was then evaluated once on CPU:

- contract:
  `configs/next_behavior_checkpoint_compatibility_evaluation.v1.json`
  (`34e2e9fbe19d66041ce2c951fdb870eaf116c28166efdaa9a82bf66422997dad`)
- evaluator revision:
  `638f51e77331bf1d7875e228830da7f6862f90a4`
- role: `test`
- elapsed time: `2949.055872` seconds
- batch size: `512`
- logical evaluation SHA-256:
  `0c0569962857de73184f613b5704da9f6fd3e1bb2d2b8d8d8104235bac608d15`
- `evaluation.json` SHA-256:
  `20d50e17d9797747a08e9e1f43b0ad48b0de98232922d83461f425511f506e87`
- deterministic replay: exact match for the fixed 1,024-example sample

The evaluator reprocessed the immutable privacy-safe test-role membership under
the exact current trust policy. It emitted no raw command content. The original
old-policy arm reproduced the retained final evaluation metrics exactly, which
is an independent check that the checkpoint, calibration, role membership, and
metric implementation were reconstructed correctly.

The source contained 237,514 retained sessions and 336,089 old-policy examples.
The current policy retained 237,117 sessions and 335,293 examples. It demoted
1,183 formerly trusted model-only labels, removed 763 groups, changed 932 phase
sequences, and changed 291 targets (`0.086790%`). The current safe-session and
example hashes are:

- `c2c1b66c67eeca5b9649142b3743e017025ce727f7f747f440e45b9033a11d3e`
- `4b81000e29e3e382815ed37c660a27e94a6464a841cff18135f174fdaf28ae53`

## Results

### Corrected current policy with real audit context

| Metric | Result |
|---|---:|
| Examples / coverage | 335,293 / 100% |
| Top-1 accuracy | 0.993838 |
| Top-3 accuracy | 0.995865 |
| MRR | 0.995239 |
| Exact-set accuracy | 0.805937 |
| Mean Jaccard | 0.806034 |
| Hamming loss | 0.025891 |
| Brier score | 0.009192 |
| Log loss | 0.026938 |
| ECE, 10 bins | 0.009177 |
| Weighted tactic F1 | 0.778873 |
| All-class macro tactic F1 | 0.188284 |
| Terminal F1 | 0.842118 |
| Terminal recall | 0.728645 |

The aligned old/current comparison changed 616 input tensors (`0.183720%`), 54
thresholded predictions (`0.016105%`), and 56 Top-1 outputs (`0.016702%`) across
335,293 common examples. Relative to the reproduced old-policy aggregate, the
current run improved Top-1 by 0.003404, Top-3 by 0.002763, MRR by 0.002810,
weighted F1 by 0.002917, exact-set accuracy by 0.000451, Brier by 0.000103, and
log loss by 0.000727. ECE worsened by only 0.000107; all-class macro balanced
accuracy was effectively unchanged.

These small differences are consistent with correcting target authority rather
than changing the model task. In particular, the 60 former
credential-access targets were removed because current policy identifies them
as unsupported model-only labels. Their disappearance is target cleaning, not
evidence of improved credential-access recall.

### Audit-context ablation

Forcing the representable audit feature to zero changed 197,488 tensors
(`58.900126%`), 86,685 thresholded decisions (`25.853507%`), and 24,898 Top-1
outputs (`7.425744%`). It also worsened log loss from `0.026938` to `0.045655`.
Some zero-audit aggregate threshold metrics improve because this counterfactual
substantially shifts the terminal/tactic operating point; it is not a calibrated
replacement runtime.

This ablation establishes that audit context is a material trained feature. The
correct fix is to restore the bounded training-time feature while retaining its
audit-only authority, not to silently zero it or retrain around the runtime bug.

## Limitations and failure analysis

- Defense-evasion (209 targets) and privilege-escalation (224 targets) meet the
  declared reporting thresholds but have zero recall. They remain disclosed
  frozen-model limitations.
- Eight tactic classes have no target support under the current test role.
  Command-and-control has only 28 targets and is non-reportable under the
  predeclared minimum of 30.
- Discovery recall is high (`0.995909`) but precision is only `0.482626`; this
  known imbalance must be visible whenever tactic-level results are presented.
- Performance varies substantially by audit-count stratum. The one-audit-label
  stratum has Top-1 `0.252874` over 572 examples; the 2–5 stratum has high
  ranking accuracy but low exact-set accuracy (`0.271558`). Aggregate metrics
  must not hide these strata.
- The retained privacy-safe role records preserve source-relative chronology but
  do not contain original durable arrival timestamps. Consequently, the number
  of originally late arrivals is
  `NOT_DETERMINABLE_FROM_PRIVACY_SAFE_ROLE_ARTIFACT`.
- This is a compatibility evaluation, not independent external model
  validation, a new semantic benchmark, long-term production observation, or
  authorization to deploy.

The limitations are primarily sparse/imbalanced target support and frozen-model
behavior, not a failure of the correction implementation. Retraining would be
justified only after a separately approved target/corpus change and a new
independent evaluation protocol. It is not supported merely by the runtime
corrections assessed here.

## Verification

Focused results:

- cutoff, snapshot, retry, chronology, audit, compatibility, privacy, storage,
  and contract tests: `109 passed`
- compatibility-focused tests: `34 passed, 6 skipped`
- audit-runtime tests and exact checkpoint smoke coverage: `65 passed, 2 skipped`
- deterministic standalone checkpoint smoke: passed

Full local suite:

- sandbox run: `1037 passed, 7 skipped, 8 failed`
- all eight failures were local-socket `PermissionError` failures in
  `test_ingest_api_security.py` and `test_production_e2e.py`
- exact out-of-sandbox rerun of those tests: `15 passed`

Validators:

- prediction policy: passed
- classification rules: passed
- `response_guidance.v3`: passed
- threat-hypothesis behavior: passed
- Python compilation: passed
- `git diff --check`: passed
- final `SHA256SUMS.json`: all entries verified

No tests, frozen expected labels, classification trust rules, calibration, or
authority assertions were weakened.

## Readiness gates

| Gate | Decision | Reason |
|---|---|---|
| Controlled local demonstration | `READY` | Deterministic checkpoint inference and corrected authority path are verified locally. |
| Thesis secondary experimental PoC | `READY_WITH_DISCLOSED_LIMITATIONS` | Aggregate compatibility is strong, but rare/unsupported class and audit-stratum limitations must be disclosed. |
| Isolated deployment test | `READY` | The correction is committed, hash-bound, and locally validated; an isolated environment is the next safe boundary. |
| Live candidate redeployment | `BLOCKED` | Separate backup, manifest, artifact installation, startup, recovery, and rollback gates have not been executed for this revision. |

Read-only deployment observation during the baseline found GCP active revision
`19afabd0bb7ed82ac93767301bb0cb1024d0b92e`, a staged revision beginning
`6964d543`, and Raspberry Pi revision beginning `7f764ab`. This work did not
modify either host. Local corrections are not deployed.

## Rollback and next action

Each correction can be reverted at its own commit boundary in reverse order.
The complete pre-correction boundary is
`0d60af2ca2e1689b8d76da76b6118257c0cf207b`. Generated compatibility artifacts
are evidence only and are not runtime inputs.

The smallest justified next action is an isolated, manifest-bound deployment
test of the committed correction, using the existing frozen artifacts and a
verified rollback package. A live candidate must remain blocked unless database
backup, capacity, artifact-hash, service-startup, recovery, and rollback gates
all pass. No retraining or recalibration step is warranted by this evaluation.

The compact machine-readable decision receipt is
`evaluation/next_tactic_checkpoint_compatibility_20260731.json`.
