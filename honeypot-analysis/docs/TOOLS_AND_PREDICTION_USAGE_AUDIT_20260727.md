# Tools and prediction usage audit — 2026-07-27

Pre-cleanup HEAD: `da1367d8f78f82d2ec52e02f8635b6144189bedf`.
Recovery tag: `pre-aggressive-prediction-cleanup-20260727`.

This audit followed systemd `ExecStart` commands, worker/report/API/dashboard
imports, trusted policies, deployment documentation, tests, manifests,
receipts, and Git history recursively. Test-only and historical-document
references were not treated as runtime reachability.

## Supported graph

```text
session_worker
  -> next_behavior_runtime
  -> preprocessing -> tensor -> model
  -> contract + label/forecast contracts
  -> advisory snapshot (no response authority)

explicit operator policy change
  -> session_worker
  -> vomm_rollback -> external_vomm_artifact
  -> validated hard-backoff prediction or fail-closed abstention

reproduce_next_behavior_experiment CLI
  -> production.reproduction.next_behavior
  -> canonical corpus/partition/train/selection/calibration verification
```

There is no automatic fallback between these paths.

## Every retained prediction module

| Module | Supported caller | Classification |
|---|---|---|
| `__init__.py` | Python package | `ACTIVE_RUNTIME_REACHABLE` |
| `next_behavior_runtime.py` | `session_worker` | Frozen Transformer runtime |
| `next_behavior_model.py` | runtime and reproduction CLI | Strict model/checkpoint loader |
| `next_behavior_tensor.py` | runtime and reproduction CLI | Frozen tensor contract |
| `next_behavior_preprocessing.py` | runtime and reproduction CLI | Frozen preprocessing |
| `next_behavior_contract.py` | runtime, reporting, reproduction | Corrected-target schema |
| `next_behavior_forecast_contract.py` | reporting/API/assessment boundaries | Advisory forecast normalization |
| `next_behavior_label_policy.py` | runtime and reproduction | Trusted classifier-output admission |
| `session_features.py` | `vomm_rollback` only | Minimal canonical tactic context |
| `external_vomm_artifact.py` | `session_worker` rollback loader | Hash/manifest verification and immutable transition builder |
| `vomm_rollback.py` | explicit rollback branch in `session_worker` | Sole VOMM inference implementation |
| `prediction_health.py` | dashboard and monitor APIs | Compatibility-shaped current artifact availability |

No retained file exists only for an obsolete test. Offline experiment modules
were moved to `production/reproduction/next_behavior/`; they are reachable
from the single reproduction CLI. The large selected-store and safe-export
libraries also contain completed migration verification primitives. They
remain because current canonical artifact verification calls them transitively;
splitting those security-sensitive receipts is `AMBIGUOUS_DO_NOT_REMOVE`.

## Removed prediction modules and test replacement

| Removed module/subsystem | Tests removed | Retained replacement |
|---|---|---|
| `realtime_prediction.py`: weighted scorers, local transition, heuristic progression, cascade, routing | monolithic service tests and old cascade/evaluation tests | `test_external_only_prediction_runtime.py`, `test_next_behavior_runtime.py` |
| `weight_fitting.py`, `prediction_backtest.py`, calibration worker | backtest/calibration service portions and superseded evaluation-consistency tests | canonical calibration/metrics/experiment tests and immutable evidence |
| `predictive_alerts.py` | legacy predictive-alert service assertions | response-guidance and forecast authority tests |
| `behavior_regime.py` | legacy regime/scorer assertions | not replaced; unsupported feature |
| `external_seed_health.py` | external-seed review/validation assertions | current API security tests and `prediction_health.py` |
| `vomm_evaluation.py` | superseded aggregate VOMM evaluator tests | explicit rollback runtime tests and retained immutable metrics |
| `prune_prediction_snapshots.py` | CLI/unit wiring assertions | storage retention contract tests |
| `next_behavior_professor_approved.py` | one-time professor protocol tool tests | immutable decision, ledger, receipts, and canonical reproduction validation |
| superseded next-tactic, benchmark, figure, source-recovery, partition-assembly and professor runner tools | their implementation-specific tests | compact authoritative evidence plus canonical reproduction suite |
| `test_production_services.py` | file itself (mixed 8,478-line legacy suite) | focused worker lifecycle, runtime, storage, API/report, authority and deployment suites |

Historical report schemas, snapshot readers, database tables, and stored rows
were not deleted or rewritten.

## Retained tools

`production/tools/` now contains one prediction CLI,
`reproduce_next_behavior_experiment.py`. The remaining tools are current
classification, correlation, threat-hypothesis, queue, coverage, source
backfill, or SQLite-to-MongoDB migration utilities. The latter two are
`AMBIGUOUS_DO_NOT_REMOVE`: supported installations have not declared a schema
floor that makes their upgrade paths impossible.

## Configuration and compatibility

- `prediction_policy.transformer_poc.trusted.json` remains byte-preserved as
  the deployed frozen contract.
- `prediction_policy.trusted.json` remains the explicit VOMM rollback contract.
- Inert legacy keys inside these hash-sensitive policies are accepted only
  where required for deployed-policy compatibility; runtime code does not load
  their rules or weights.
- Existing historical backtest/calibration tables and API read routes remain
  readable. No executable producer or scheduled unit remains.
- The monitor’s external-seed field name is a presentation compatibility alias
  populated by current predictor health, not the removed health engine.

## Removed units

The calibration-worker, prediction-backtest, and prediction-retention service
and timer pairs were removed from the deployment templates. Current production
service entrypoints are unchanged.

## Evidence and recovery

Immutable reports, figures, manifests, receipts, hashes, Selection blocker,
professor-approved evaluation, and deployment handoff remain. Removed
implementations are recoverable from the annotated tag
`pre-aggressive-prediction-cleanup-20260727`; they must not be restored merely
because a historical document names them.

Protected untracked audit bundles and external cache artifacts were not read,
modified, staged, or deleted during this cleanup.
