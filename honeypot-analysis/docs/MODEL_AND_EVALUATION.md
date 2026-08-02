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

`evaluation/canonical_final_evaluation.json` is the claim-to-artifact index for
the retained evidence set. It records stable claim IDs, exact source hashes,
dataset and policy identities, metric definitions and values, generation
commands, limitations, and superseded-artifact decisions. The authoritative
historical comparison remains
`evaluation/next_tactic_benchmark_evidence/single_checkpoint_evaluation.json`;
its source record contains the full aggregate, per-tactic, paired, confidence,
confusion, efficiency, and promotion-gate values used by the final figures.
Raw per-case predictions, stage dumps, logs, caches, seed duplicates, and
intermediate candidate-selection receipts are not evidence authorities and are
not retained in this checkout.

The current PoC policy instead identifies the externally managed
`data/models/corrected_target_transformer_seed_20260721.pt` checkpoint with
SHA-256 `7fbd73c4bd071336fa52a589bf41e39f5a3122a67aee398dfb8e6dd9cfdfb04a`.
Its specification, vocabulary, calibration, and classifier environment are
also hash-bound by that policy and the retained current-policy compatibility
receipt. Those private bytes are intentionally absent from this checkout and
must be restored only through the verified frozen-model bundle procedure in
[`DEPLOYMENT_AND_RECOVERY.md`](DEPLOYMENT_AND_RECOVERY.md).

Separately, the historical benchmark's locally named
`data/models/transformer_shadow_20260721.pt` checkpoint has SHA-256
`d9b316d76e63b15b175668aa0bf69cfe4172bbd812d6b19743a628cd0ec8073d` and
seed `20260723`; it is not the active runtime model. If that historical asset
is restored from trusted artifact storage, verify it from the repository root
against `evaluation/next_tactic_benchmark_evidence/selected_transformer_checkpoint.sha256`
before using the benchmark evaluator.

`single_checkpoint_evaluation.json` is the authoritative original promotion
gate for the historical benchmark checkpoint. It is an immutable recorded
result of the retired offline evaluator, not a supported command-line interface
in this checkout. It retained the external hard-backoff VOMM as the gate's PoC
authority because the Transformer failed the predeclared tactic-safety
criterion; it neither replaces the earlier five-seed aggregate nor conflicts
with the later explicitly approved, bounded experimental activation. That
activation did not rewrite the gate.

The historical seed-20260723 Transformer comparison over 12,235 held-out examples
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

Bulk benchmark runs are intentionally not reproduced by a supported final-gate
CLI in this checkout. The only supported prediction-experiment entry point is
`production.tools.reproduce_next_behavior_experiment`; it prepares and freezes
pre-test experiment inputs and must not be used to replace the recorded final
promotion gate. Any future benchmark must use a newly reviewed, versioned
evaluation procedure rather than the superseded 20260721 run whose VOMM adapter
omitted required manifest validation and consequently abstained on every case.

The compact blocked-selection summary and its final status/table/gate
derivatives preserve the original `BLOCKED_AT_SELECTION` claim without keeping
the private corpus-build receipt chain. The checkpoint compatibility receipt
remains because it is current model-identity evidence. The retained seven-day
session payload and authoritative external-VOMM evaluation support the explicit
rollback/reference claim. The superseded seven-day comparison projection,
intermediate calibration/configuration projections, and duplicate checksum
wrappers are indexed as superseded in the canonical aggregate. CSV and
image-format duplicates are not evidence authorities.

## Typed-semantic evaluation

Current generalized regression fixtures are retained because tests load their
exact paths. They cover sensitive reads, inspection, direct transfers,
filesystem changes, transfer and execution attempts, deferred transformation,
scheduled-task, service and collection families, and cross-family relations.
Only the activation states defined in
[`SYSTEM_ARCHITECTURE.md`](SYSTEM_ARCHITECTURE.md) can affect v4/v3 evaluation.
Frozen shadow or holdout data does not activate a family. The combined PoC
fixture and stabilization result preserve prediction, enrichment, ATT&CK-only,
reference-resolution, contradiction, and abstention checks.

## Authority and reproducibility

Prediction snapshots are content-addressed, provenance-bound, and contain no
recommendations. `prediction_only_alerts`, `prediction_only_hypotheses`,
`prediction_only_guidance`, and `prediction_only_actions` are prohibited.
Canonical v4/v3 outputs use immutable observed evidence, exact policy hashes,
artifact hashes, and evaluator Git revision. Deterministic replay and artifact
validators are part of the focused and full test suites.

## Deterministic artifact integrity

`prediction_snapshot.v3` derives `snapshot_id` and `snapshot_sha256` after
inference from canonical prediction content: event, target contract,
policy-bound provenance, model-input hash, status, output, and the deterministic
trigger record. Wall-clock generation/model-load time and inference latency are
diagnostics excluded from identity. Integrity validation recomputes both values
without inference; mutation of prediction, status, input, authority, or
provenance invalidates them. Historical snapshots are readable without being
rewritten.

JSON, Markdown, PDF (when ReportLab is installed), and STIX exports share one
content-addressed artifact version. Renderer times come from the source record,
STIX identifiers are deterministic UUIDv5 values, and invariant PDF rendering
makes identical inputs byte-stable. V4 STIX time comes from canonical evidence
or deterministic session times; retry-only runtime context is excluded from
the source-report digest represented by STIX.

Each run writes `report_artifact_manifest.v1`, naming the artifact version,
exact source report/session SHA-256 values, and each file's name, media type,
length, and SHA-256. The manifest filename itself contains the manifest-byte
SHA-256. Verify that name/digest before verifying its entries. Validated report
files remain mode `0600` in an owner-only directory. These hashes establish
reproducibility and tamper evidence only: they do not establish accuracy or
authorize an analytical claim, alert, guidance, or response.

Frozen-bundle installation and recovery are specified in
[`DEPLOYMENT_AND_RECOVERY.md`](DEPLOYMENT_AND_RECOVERY.md); assessment,
guidance, and typed-semantic authority are specified in
[`SYSTEM_ARCHITECTURE.md`](SYSTEM_ARCHITECTURE.md). Machine-readable benchmark
evidence remains under `evaluation/next_tactic_benchmark_evidence/`. The core
figure package retains PDF as its single export format; source metrics and
hashes remain machine-readable.
