# Model and evaluation (canonical summary)

## Frozen runtime identity

The active policy is `configs/prediction_policy.transformer_poc.trusted.json`.
It selects the professor-approved corrected-target Transformer, seed `20260721`,
CPU float32, one causal layer, `d_model=16`, four heads, feed-forward 32,
maximum sequence length 8, and 3,951 parameters. The policy binds exact hashes
for the checkpoint, model specification, vocabulary, preprocessing,
calibration, rule policy, trust policy, and classifier artifact. Missing or
mismatched artifacts produce explicit unavailable/abstained prediction state;
there is no runtime model fallback.

The external VOMM bundle is retained as an explicit operator-selected rollback
and reference artifact. It is not blended into Transformer output and cannot be
selected implicitly.

## Retained benchmark evidence

`evaluation/next_tactic_benchmark_evidence/` is the reproducibility bundle. Its
historical seed-20260723 Transformer comparison over 12,235 held-out examples
records Top-1 `0.886555`, Top-3 `0.995995`, MRR `0.941600`, macro-F1 `0.509713`,
balanced accuracy `0.511315`, and weighted-F1 `0.868128`; the hard-backoff VOMM
reference records Top-1 `0.800817`, Top-3 `0.998774`, MRR `0.893328`, macro-F1
`0.396874`, balanced accuracy `0.399616`, and weighted-F1 `0.736824`.
The benchmark is explicitly offline and not a claim that the active seed-20260721
runtime has independent external validation. Execution and rare-class
limitations remain visible in the per-tactic results and post-analysis.

The exact Transformer policy still records the original selection status
`BLOCKED_AT_SELECTION`; the later controlled PoC activation did not rewrite that
scientific result. Do not train, recalibrate, relabel, or promote the model from
these artifacts without a new frozen evaluation and promotion gate.

## Authority and reproducibility

Prediction snapshots are content-addressed, provenance-bound, and contain no
recommendations. `prediction_only_alerts`, `prediction_only_hypotheses`,
`prediction_only_guidance`, and `prediction_only_actions` are prohibited.
Canonical v4/v3 outputs use immutable observed evidence, exact policy hashes,
artifact hashes, and evaluator Git revision. Deterministic replay and artifact
validators are part of the focused and full test suites.

See [`FROZEN_MODEL_BUNDLE.md`](FROZEN_MODEL_BUNDLE.md),
[`GCP_TRANSFORMER_POC_DEPLOYMENT_20260727.md`](GCP_TRANSFORMER_POC_DEPLOYMENT_20260727.md),
[`SESSION_ASSESSMENT_V4.md`](SESSION_ASSESSMENT_V4.md),
[`RESPONSE_GUIDANCE_V3.md`](RESPONSE_GUIDANCE_V3.md), and the machine-readable
files under `evaluation/next_tactic_benchmark_evidence/`.
