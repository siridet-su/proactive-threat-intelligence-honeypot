# Corrected-target seven-member final-evaluation amendment

Status: approved before source-member retrieval, classification, training, or
final-test access.

This amendment is additive. It does not rewrite the accepted historical
benchmark or change the target, preprocessing, label, trust, authority, or
production contracts frozen by the original design.

## Scientific scope

The experiment measures chronological generalization to later, previously
unused daily members from the same Zenodo collection. It is not external
validation: development and final members share the collection deployment,
sensor population, configurations, deterministic rules, SecureBERT
checkpoint, and weak-label policy. Claims must remain limited to the frozen
corpus and later members of the same collection process.

## Development roles

The existing verified corrected-target corpus supplies development data:

| Role | Members |
|---|---|
| Train | `2025-07-03.json.gz`, `2025-07-10.json.gz`, `2025-07-17.json.gz`, `2025-07-24.json.gz` |
| Model selection | `2025-07-31.json.gz` |
| Calibration only | `2025-08-07.json.gz` |

`2025-08-14.json.gz` is excluded as a whole member because it contains the
entire accepted historical test membership. Development reuse of accepted
historical train or calibration membership must be disclosed per role.
Accepted historical test membership is forbidden from every redesigned role.

## Cutoff, embargo, and final-member rule

- Development collection cutoff: `2025-08-07`.
- Exact observed development end:
  `2025-08-07T23:59:59.974898Z`.
- Purge/embargo member: `2025-08-08.json.gz`.
- Earliest permitted final-test date: `2025-08-09`.

The final member selection algorithm is fixed before inspecting new member
content:

1. Enumerate only canonical `YYYY-MM-DD.json.gz` entries from the exact
   Zenodo `data_all.zip` receipt.
2. Exclude every historically forbidden member below.
3. Exclude dates on or before the development cutoff.
4. Reserve `2025-08-08.json.gz` as an unused embargo member.
5. Sort remaining entries by collection date.
6. Select the first seven without consulting byte volume, commands, labels,
   tactic support, classification output, or model output.
7. Stop if any rule-selected entry is absent or unverifiable. Do not replace a
   member after viewing labels or results.

The rule-selected members are:

- `2025-08-09.json.gz`
- `2025-08-10.json.gz`
- `2025-08-11.json.gz`
- `2025-08-12.json.gz`
- `2025-08-13.json.gz`
- `2025-08-15.json.gz`
- `2025-08-16.json.gz`

Their size, compressed size, CRC-32, and SHA-256 receipts must come from the
exact archive metadata and downloaded member bytes. Values must never be
inferred or fabricated.

## Historical forbidden members

The following members are forbidden from the redesigned final test:

- `2025-06-27.json.gz`
- `2025-06-29.json.gz`
- `2025-07-03.json.gz`
- `2025-07-10.json.gz`
- `2025-07-17.json.gz`
- `2025-07-24.json.gz`
- `2025-07-31.json.gz`
- `2025-08-07.json.gz`
- `2025-08-14.json.gz`
- `2025-08-17.json.gz`

The first six development members are allowed only in their declared
development roles. `2025-08-14.json.gz` is forbidden from every redesigned
role. The embargo member is unused in this experiment.

## Partition and access contract

The amended partition is `4 train / 1 selection / 1 calibration / 7 test`
across thirteen role-bearing source members. Development and final corpora may
have separate receipts, but one partition manifest must bind both.

Before model fitting, the manifest must prove:

- empty source-member, safe-session, example, and model-input intersections
  across roles;
- zero accepted historical-test membership in development;
- zero accepted historical train, calibration, or test membership in final;
- deterministic, content-hashed membership for every role;
- a training-only technique vocabulary with unknown handling;
- purpose-scoped loaders that cannot expose the final-test path to fitting,
  selection, or calibration code;
- unchanged HMAC identity semantics across development and final corpora.

Whole-session membership is mandatory. Sessions lacking both connection and
close evidence, sessions truncated at a selected-member boundary, and sessions
crossing experimental roles must not create terminal targets. They must be
rejected or deterministically quarantined with aggregate and membership
receipts. Same-role cross-member retention is permitted only if complete
multi-member provenance is represented by the data contract; otherwise it is
quarantined.

## Training, selection, and calibration freeze

The corrected target and shared tensor adapter remain authoritative. Majority,
first-order Markov, hard-backoff VOMM, interpolated VOMM, and the Small Causal
Transformer must use identical role-scoped examples. GRU is optional
experimental context.

Checkpoint selection uses only the selection role and the existing frozen
metric/tie-break order. The calibration role cannot change architecture,
features, epoch, seed, or model family.

If calibrated probabilities are required, fit only:

- one positive global temperature for tactic logits; and
- one positive global temperature for the terminal head.

Both mappings use calibration membership only. Class-specific calibration is
not permitted under weak rare-class support. If the preregistered calibration
criteria fail, record `calibration.status=not_implemented` and retain raw-score
semantics. Test data is never used to fit or choose a mapping.

## Final-test and evidence gate

The seven-member final payload remains unopened by training and model-selection
code. Before one-time evaluation, freeze and verify:

- exact source, corpus, split, vocabulary, policy, environment, baseline,
  checkpoint, state-dictionary, calibration, selection-rule, and code hashes;
- one validation-selected checkpoint;
- deterministic checkpoint reload;
- the same-target VOMM baseline;
- all promotion blockers and runtime budgets;
- `test_opened=false`.

The final evaluator may then open the exact test membership once. A failed
criterion, weak tactic support, or unfavorable result is reported rather than
repaired by repartitioning, retraining, routing, or threshold changes.

## Additional acceptance criteria

- The seven final members satisfy the frozen metadata-only selection rule.
- No already verified member is downloaded again.
- The full `data_all.zip` is not downloaded.
- The embargo member contributes no training, selection, calibration, or test
  example.
- Development prior use is disclosed and accepted historical test use is zero.
- The final cohort has zero historical and development session overlap.
- Partial/cross-role sessions cannot create `SESSION_END`.
- Final-test support cannot alter member selection or reportability rules.
- Member/session/template dependence is reported with clustered sensitivity.
- Historical evidence and production behavior remain unchanged.
