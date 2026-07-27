# Historical next-tactic audit conclusions

Status: canonical consolidation of three previously untracked working bundles.
These findings concern the superseded single-label, next-distinct-tactic
experiment. They do not redefine the current corrected-target Transformer,
its Final evaluation, or production behavior.

## Data preparation and training-data audit

The frozen public payload and accepted manifests support the narrow claim of
predicting the next distinct ATT&CK tactic in a classifier-derived Cowrie SSH
corpus. They prove safe-session-disjoint roles and reconcile 219,336 sessions
and 178,922 examples:

| Role | Sessions | Transition-bearing sessions | Examples |
|---|---:|---:|---:|
| Train | 153,535 | 42,586 | 151,822 |
| Validation selection | 16,450 | 1,695 | 6,654 |
| Calibration | 16,450 | 2,090 | 8,211 |
| Held-out test | 32,901 | 3,342 | 12,235 |

The held-out cases contain only 45 model-visible histories; 99.6322% repeat an
input history. Targets are weak classifier labels after adjacent tactic
deduplication, not independently adjudicated attacker intent. Raw commands,
timestamps, per-command label provenance, private classifier weights, member
lineage, and template-family identity were absent from the public payload, so
chronology and template independence were manifest-bound rather than
independently auditable. Claims about future collections or real attacker
intent were therefore unsupported.

Original working-report SHA-256:
`57fb65e9da89b0a985d773eb0ab4e83cc7cac687c6f943bac57ebd6f82c380c8`.
Original summary SHA-256:
`5f3a22aa3cfc071d5140756981843c37208edb23179a1579dff0b78f3b9e0fd4`.
Original reproducibility-manifest SHA-256:
`6ccd9cac39bc91e78678f74c937457765d44ee9aaae5429b8ec38ec05eb1b13e`.

The current authoritative replacement for dataset limitations and design
consequences is
`evaluation/next_tactic_benchmark_evidence/final_prediction_subsystem_design/data_and_label_assessment.md`.

## Execution-to-Persistence investigation

The accepted single-checkpoint evaluation contains 819 actual Execution cases
classified as Persistence. The investigation found:

- 810 cases use the identical input `[persistence, discovery]`, which maps to
  both targets and is Persistence-majority in train, validation, and test.
- Eight use `[discovery, persistence, discovery]`; one uses `[discovery]`.
- There were three distinct visible patterns, no recorded cross-role session
  overlap, and no vocabulary, padding, masking, truncation, checkpoint-load,
  or output-index defect.
- The VOMM made the opposing dominant error: 1,718 actual Persistence cases
  were classified as Execution. The models resolved an ambiguous repeated
  context differently.
- Raw behavioral evidence was unavailable, so the audit did not adjudicate or
  relabel any individual weak label.

This supports repeated-pattern and weak-label ambiguity within that corpus. It
does not prove source-template leakage or prove any label incorrect. Selecting
routing or thresholds from those held-out errors would have been test-set
overfitting.

Original working-report SHA-256:
`86a488aec0479c4053651c67662da83f01d791a5811f9432796c5583adef88b9`.
Original machine-readable summary SHA-256:
`68e0a94ffd68ecae7c88afbd662b20980d3cf7c2fef6ffd189c289524508bd22`.
The authoritative confusion counts remain in
`evaluation/next_tactic_benchmark_evidence/single_checkpoint_evaluation.json`.

## GRU–Transformer runtime comparison

The requested paired runtime comparison was not performed. None of the five
exact accepted GRU checkpoint state dictionaries remained available. The
selected Transformer checkpoint was present, but measuring it alone or
retraining substitute GRUs would not produce a valid paired comparison.

Consequently latency, throughput, process-memory, and checkpoint-size
comparisons were `NOT_DETERMINABLE`. The accepted five-seed aggregate
predictive results still showed a small Transformer advantage (Top-1
`+0.002452`, macro-F1 `+0.010384`), but do not establish a runtime advantage.
Latency must not be cited as a model-selection reason.

Original working-report SHA-256:
`12984ca4c09ad19d8f0b041ab795e449914b022b787722a4b2ccefd06a8f2e84`.
Original blocked-benchmark manifest SHA-256:
`a02f00591c1f64934ceccfa57a34e95325f0a569faf79ae83db566a4ea91fc06`.

## Preservation decision

The original untracked bundles consisted of intermediate CSV/JSON tables,
case listings, environment snapshots, blank measurement tables, and these
reports. The unique defensible conclusions and provenance hashes are retained
here. Their raw/intermediate files were not authoritative inputs to the
current reproduction or runtime, contained no model weights or source data,
and were removed rather than committed as a second historical working tree.
Git history and the already committed benchmark evidence remain the recovery
and audit sources.
