# Next-tactic benchmark artifact policy

`next_tactic_benchmark_evidence/` is the compact, version-controlled evidence
bundle for the corrected external-corpus benchmark. It preserves machine-
readable metrics, per-tactic metrics, paired comparisons, bootstrap intervals,
confusion matrices, split/manifest hashes, model configuration, calibration and
efficiency results, and the validation-only Transformer selection record.

The selected Transformer checkpoint is retained locally at
`data/models/transformer_shadow_20260721.pt`; its SHA-256 and frozen metadata
are recorded here. The legacy `shadow` filename does not imply that any shadow
runtime is active. Restore it only from trusted local artifact storage, then
verify from the repository root with:

```text
sha256sum -c evaluation/next_tactic_benchmark_evidence/selected_transformer_checkpoint.sha256
```

`single_checkpoint_evaluation.json` is the authoritative final promotion-gate
record for that exact checkpoint. It was generated once with the committed,
offline-only evaluator:

```text
PYTHONPATH=. python -m production.tools.evaluate_frozen_transformer_candidate
```

The record retains the external hard-backoff VOMM as the PoC authority because
the frozen Transformer failed the predeclared tactic-safety criterion. It does
not replace or alter the earlier five-seed aggregate evidence.

Bulk run directories `evaluation/next_tactic_offline_benchmark_*/` are ignored:
they contain raw case predictions, seed duplicates, logs, stage dumps, caches,
and duplicate figures. Regenerate them with
`python -m production.tools.next_tactic_offline_benchmark`; never use the
superseded 20260721 run, whose VOMM adapter omitted required manifest
validation and therefore abstained on every case.
