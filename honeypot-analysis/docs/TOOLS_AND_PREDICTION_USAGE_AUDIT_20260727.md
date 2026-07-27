# Tools and prediction usage audit — 2026-07-27

Pre-cleanup HEAD: `da1367d8f78f82d2ec52e02f8635b6144189bedf`.
Recovery tag: `pre-tools-prediction-cleanup-20260727`.

The audit used Python AST imports, `git grep`, project CLI entrypoints,
systemd `ExecStart`, configs, tests, documentation, manifests, receipts, the
deployment handoff, and file history. A test-only reference did not by itself
make an unsupported executable design current. Historical conclusions remain
in Git/evaluation evidence even when their one-time runner is removed.

## Current reachability

```text
session_worker
  -> next_behavior_runtime
  -> next_behavior_model + tensor + preprocessing + label/forecast contracts
  -> frozen Transformer artifact validation and advisory output

manual VOMM rollback
  -> session_worker
  -> external_vomm_artifact + realtime_prediction
  -> frozen VOMM artifact/manifest

corrected-target reproduction
  -> source selection and safe corpus builders
  -> partitions / experiment policy / Train-only vocabulary
  -> train_next_behavior_experiment
  -> Selection / Calibration / frozen professor-approved evaluator ledger
```

Prediction snapshots remain advisory. Removing offline runners does not change
the prediction, alert, hypothesis, guidance, recommendation, or action
authority boundary.

## Prediction modules

| File | References and role | Classification / replacement |
|---|---|---|
| `__init__.py` | Package marker | `CURRENT_RUNTIME_REQUIRED` |
| `next_behavior_runtime.py` | Session-worker production predictor | `CURRENT_RUNTIME_REQUIRED` |
| `next_behavior_model.py` | Strict checkpoint construction/loading | `CURRENT_RUNTIME_REQUIRED` |
| `next_behavior_tensor.py` | Canonical tensorization | `CURRENT_RUNTIME_REQUIRED` |
| `next_behavior_preprocessing.py` | Frozen preprocessing contract | `CURRENT_RUNTIME_REQUIRED` |
| `next_behavior_label_policy.py` | Runtime classifier/label admission | `CURRENT_RUNTIME_REQUIRED` |
| `next_behavior_contract.py` | Corrected-target schemas and IDs | `CURRENT_RUNTIME_REQUIRED` |
| `next_behavior_forecast_contract.py` | Forecast normalization/authority contract | `CURRENT_RUNTIME_REQUIRED` |
| `predictive_alerts.py` | Explicit alert boundary used by worker/reporting | `CURRENT_RUNTIME_REQUIRED` |
| `prune_prediction_snapshots.py` | Deployed dry-run retention timer | `CURRENT_RUNTIME_REQUIRED` |
| `external_vomm_artifact.py` | Manual rollback artifact validation and inference adapter | `CURRENT_RUNTIME_REQUIRED` |
| `realtime_prediction.py` | Manual VOMM rollback engine and historical snapshot compatibility | `CURRENT_RUNTIME_REQUIRED`; old scorers remain embedded and need a separate internal refactor |
| `session_features.py` | Session-worker features and VOMM engine | `CURRENT_RUNTIME_REQUIRED` |
| `behavior_regime.py` | Imported by session features/VOMM engine | `CURRENT_RUNTIME_REQUIRED` |
| `external_seed_health.py` | Dashboard/monitor rollback-model health | `CURRENT_RUNTIME_REQUIRED` |
| `prediction_backtest.py` | Deployed diagnostic timer; no automatic policy update | `CURRENT_DEVELOPMENT_OR_TEST_REQUIRED` |
| `weight_fitting.py` | Backtest/calibration diagnostic dependency | `CURRENT_DEVELOPMENT_OR_TEST_REQUIRED`; no Transformer authority |
| `next_behavior_baseline.py` | Same-target VOMM/Markov baselines in frozen experiment | `THESIS_OR_REPRODUCIBILITY_REQUIRED` |
| `next_behavior_calibration.py` | Independent Calibration-role logic | `THESIS_OR_REPRODUCIBILITY_REQUIRED` |
| `next_behavior_corpus.py` | Canonical corpus construction | `THESIS_OR_REPRODUCIBILITY_REQUIRED` |
| `next_behavior_experiment.py` | Frozen experiment manifest/gates | `THESIS_OR_REPRODUCIBILITY_REQUIRED` |
| `next_behavior_experiment_policy.py` | Frozen architecture/metric/decision policy | `THESIS_OR_REPRODUCIBILITY_REQUIRED` |
| `next_behavior_metrics.py` | Current multi-label and terminal metrics | `THESIS_OR_REPRODUCIBILITY_REQUIRED` |
| `next_behavior_partitions.py` | Role isolation and Final sealing | `THESIS_OR_REPRODUCIBILITY_REQUIRED` |
| `next_behavior_professor_approved.py` | Professor-approved protocol/ledger | `THESIS_OR_REPRODUCIBILITY_REQUIRED` |
| `next_behavior_source_selection.py` | Source-membership freeze | `THESIS_OR_REPRODUCIBILITY_REQUIRED` |
| `domain_shift.py` | Only imported by an old monolithic service test; no runtime, CLI, unit, config, or current evidence consumer | `LEGACY_SAFE_TO_REMOVE`; conclusions retained in post-analysis |
| `external_seed_validation.py` | Only direct importer is a legacy regression test; current VOMM uses `external_vomm_artifact.py` | `LEGACY_SAFE_TO_REMOVE` |

## Tool modules retained

| Files | Reason |
|---|---|
| `analyze_professor_approved_poc.py`, `prepare_professor_approved_poc_evaluation.py`, `freeze_professor_approved_poc_pretest.py`, `evaluate_professor_approved_poc.py`, `report_professor_approved_poc.py`, `benchmark_professor_approved_poc_runtime.py` | Immutable approved protocol, calibration, one-time ledger, reports, and real runtime evidence |
| `assemble_next_behavior_partition_inputs.py`, `build_next_behavior_*`, `fetch_next_behavior_*`, `merge_next_behavior_experiment_manifest.py`, `train_next_behavior_experiment.py`, `evaluate_next_behavior_frozen.py`, `benchmark_next_behavior_runtime.py`, `verify_next_behavior_*` | Minimum corrected-target reproducibility chain |
| `build_authoritative_external_vomm.py`, `evaluate_authoritative_external_vomm.py` | Explicit VOMM rollback artifact construction/validation |
| `evaluate_next_tactic_model_comparison.py` | `AMBIGUOUS_DO_NOT_REMOVE`: current VOMM evaluator imports its stable case/metric primitives; extraction is required before safe deletion |
| `backfill_session_source.py`, `migrate_sqlite_to_mongodb.py` | Supported installation upgrade and disabled MongoDB future boundary |
| classification, coverage, feedback, job, session-correlation, threat-hypothesis, and knowledge-pack tools | Current maintenance, review, UI, or evidence evaluation |
| `__init__.py` | Package marker |

## Tool modules removed

| File | Evidence | Replacement / history |
|---|---|---|
| `audit_local_transition_provenance.py` | No importer, CLI entrypoint, unit, or current manifest; local authority is unsupported | Current Transformer provenance receipts; Git history |
| `external_seed_weight_fit.py`, `external_seed_weight_sweep.py` | Weighted multi-source design is not a runtime or rollback mode; only old tests/tools reference it | Frozen Transformer calibration and same-target baselines |
| `primary_transition_evaluation.py` | Historical local-first/weighted evaluator | Immutable benchmark results and current professor-approved evaluator |
| `prepare_next_tactic_external_payload.py` | Pre-corrected-target v1 payload exporter, used only by removed old tests | Canonical v3 safe corpus builder |
| `evaluate_zenodo_tuned_next_tactic.py` | Heuristic/tuned old next-tactic task | Corrected-target experiment and explicit VOMM rollback |
| `evaluate_zenodo_seven_day.py` | One-time raw-to-old-target runner; frozen seven-day payload/model/manifest retained | `build_authoritative_external_vomm.py`; Git history |
| `build_external_seed_model.py` | Pre-VOMM external-seed builder only used by removed runner/tests | Immutable external VOMM artifact and builder |
| `next_tactic_offline_benchmark.py` | Superseded aggregate neural benchmark | Corrected-target experiment evidence |
| `evaluate_frozen_transformer_candidate.py` | Old single-label Transformer candidate | Corrected-target Transformer runtime/evaluator |
| `generate_next_tactic_decision_figures.py`, `generate_final_model_selection_figures.py` | One-time figure generators; authoritative figures retained | Preserved evidence and Git history |

## Tests removed with unsupported code

- `test_next_tactic_offline_benchmark.py`
- `test_frozen_transformer_candidate_evaluation.py`
- `test_final_model_selection_figures.py`
- `test_next_tactic_decision_figures.py`
- `test_external_seed_weight_fit.py`
- old model-comparison portions of `test_next_tactic_model_comparison.py`
- legacy evaluation-consistency tests that only exercise the removed
  local-first/weighted tool chain
- direct tests for removed `domain_shift.py` and
  `external_seed_validation.py`

Current Transformer, VOMM artifact/runtime, historical-read compatibility,
fail-closed, report/guidance, and authority tests remain.

## Evaluation/config artifacts

The old external, early-Zenodo, and 500-MiB payloads/results become
`LEGACY_SAFE_TO_REMOVE` once their executable consumers above are removed.
The exact seven-day payload remains because the VOMM manifest binds its path
and SHA-256. Immutable benchmark reports, figures, hashes, selected-checkpoint
evidence, blocker evidence, and professor-approved results remain unchanged.

`configs/prediction_policy.transformer_poc.trusted.json` is current.
`configs/prediction_policy.trusted.json` is explicit VOMM rollback.
Old weighted/example modes are not deployment policies.

## Ambiguous boundary

- `evaluate_next_tactic_model_comparison.py` cannot yet be removed without
  extracting primitives used by the retained VOMM evaluator.
- Legacy scorer internals in `realtime_prediction.py` and diagnostic
  `weight_fitting.py` are intertwined with a deployed backtest timer and
  historical snapshot compatibility. They are not production authority, but
  deleting them in this cleanup would be a behavioral refactor.
- One-time database migration/backfill tools remain because supported upgrade
  floors have not been raised past their schemas.

