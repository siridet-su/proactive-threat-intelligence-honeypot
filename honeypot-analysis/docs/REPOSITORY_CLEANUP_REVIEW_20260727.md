# Repository cleanup review — 2026-07-27

This is the pre-removal inventory for handoff cleanup. It is bound to
`3fe1482d8047deb9592cf1fb1a52d2cc68df2d18`. Git history and the local tag
`pre-handoff-repository-cleanup-20260727` are the recovery mechanism for
tracked removals. The three untracked audit bundles are user-owned and outside
the cleanup scope.

## Baseline

- Working tree: tracked files clean; three user audit bundles and
  `local_cache_cleanup_review/` untracked.
- Tracked files: 482.
- Tracked lines: 621,147.
- Working-directory apparent size: approximately 2.6 GiB.
- Tracked evaluation material: approximately 228 MiB.
- Ignored `evaluation/generated/`: approximately 2.3 GiB.
- Git object store: approximately 31.9 MiB.

## Supported architecture and entrypoints

```text
Pi Cowrie JSON
  -> production.workers.sensor_forwarder
  -> production.api.ingest_api
  -> SQLite production.storage.backend
  -> production.workers.session_worker / session_monitor
  -> deterministic classification + trust boundary
  -> evidence graph and report-only correlation
  -> frozen Transformer next-behavior runtime
  -> session assessment + threat hypothesis
  -> response guidance (manual approval; forecast has zero authority)
  -> reports/artifacts
  -> dashboard_api and monitor_web
```

Current entrypoints:

| Responsibility | Entrypoint |
|---|---|
| Event ingest | `production.api.ingest_api:main` |
| Sensor forwarding | `production.workers.sensor_forwarder:main` |
| Session processing | `production.workers.session_worker:main` |
| Classification | `production.classification.classification_pipeline` |
| Evidence reconstruction | `production.correlation.session_evidence_graph` and `session_behavior_relationships` |
| Threat assessment | `production.reporting.session_assessment` and `threat_hypothesis` |
| Transformer prediction | `production.prediction.next_behavior_runtime` invoked by `realtime_prediction` |
| Reporting | `production.reporting.reporting_pipeline` and `artifacts` |
| Guidance | `production.reporting.response_guidance` and `smb_decision` |
| API/UI | `production.api.dashboard_api` and `monitor_web` |
| Backup/restore | SQLite online-backup/restore procedure in `docs/GCP_TRANSFORMER_POC_DEPLOYMENT_20260727.md` |
| Deployment | reviewed systemd units under `deployment/systemd/` |
| VOMM rollback | `external_vomm_artifact`, `external_seed_validation`, frozen artifact/manifest, and deployment rollback procedure |
| Offline reproduction | corrected-target builders/train/evaluator tools and frozen evidence under `evaluation/next_tactic_benchmark_evidence/` |

The deployed policy is one frozen Transformer checkpoint. VOMM is explicit
rollback/reference only. SQLite is authoritative. Forecasts are advisory and
cannot independently authorize an alert, claim, recommendation, guidance, or
action.

## Classification inventory

### `CURRENT_RUNTIME_REQUIRED`

- `production/api`, `classification`, `correlation`, `enrichment`, `policies`,
  `reporting`, `storage`, `utils`, and active workers.
- Transformer contracts/runtime plus explicit VOMM validation/rollback code.
- Trusted policies, production example configuration, schemas, static monitor,
  systemd units, public feed caches, and intentionally versioned model data.
- SQLite support. MongoDB remains an isolated, disabled, tested future backend;
  PostgreSQL remains explicit fail-closed compatibility.

### `CURRENT_DEVELOPMENT_OR_TEST_REQUIRED`

- `tests/`, project/requirements files, `.github/workflows`, `demo/`, fixtures,
  validators, operational tools, and deployment templates.
- Corrected-target corpus, partition, training, calibration, evaluation, and
  professor-approved ledger tools.
- Offline VOMM rollback validation and current model-comparison tooling.

### `THESIS_OR_REPRODUCIBILITY_REQUIRED`

- `evaluation/next_tactic_benchmark_evidence/`, corrected-target design and
  closure evidence, current authoritative VOMM evaluation, selected model
  manifest, deployment handoff, and retention/support documentation.
- `evaluation/next_tactic_zenodo_7day_session_payload.jsonl`: its exact hash and
  path are bound by the VOMM manifest and evaluation receipts.
- The three untracked audit bundles:
  `data_preparation_training_audit/`,
  `execution_persistence_investigation/`, and
  `gru_transformer_runtime_comparison/`.

### `SUPPORTED_FUTURE_WORK`

- MongoDB adapter, indexes, migration utility, optional requirement, and tests.
  It is disabled and not production-authoritative, but has a coherent
  configuration boundary and test suite. Promotion still requires private live
  parity, backup, migration, and rollback proof.
- Optional SecureBERT, artifacts, Vertex presentation, and offline evaluation
  extras. All imports must remain lazy and features fail closed when absent.

### `GENERATED_SAFE_TO_REMOVE`

| Path | Approximate size | Evidence |
|---|---:|---|
| `evaluation/generated/` | 2.3 GiB | Ignored deterministic rebuild outputs; two copies; no tracked reference requires exact paths |
| `build/` | 3.4 MiB | Ignored setuptools output |
| `honeypot_analysis.egg-info/` | 60 KiB | Ignored packaging metadata |
| `.pytest_cache/` | 164 KiB | Ignored test cache |
| all `__pycache__/` and `*.pyc` | about 7 MiB | Ignored interpreter/test cache |

### `LEGACY_SAFE_TO_REMOVE` candidates

These require a dedicated removal commit and reference/test update:

| Subsystem/path | Size | Evidence and replacement |
|---|---:|---|
| Pre-Zenodo external session payload and comparison | about 36 MiB plus small result/tool | Superseded by seven-day frozen VOMM and corrected-target experiment; not a runtime input |
| Early Zenodo payload and comparison | about 49 MiB plus result | Superseded by seven-day payload and corrected-target evidence |
| 500 MiB tuned payload/comparisons | about 56 MiB plus results/tool | Superseded; heuristic tuning is not current prediction authority |
| Associated old benchmark-only evaluator tests/docs | small | Remove only with the obsolete tools while retaining current VOMM/corrected-target tests |

The seven-day payload, `next_tactic_offline_benchmark.py`, corrected benchmark
evidence, and all Transformer corrected-target tooling are explicitly excluded
from this candidate set.

### `AMBIGUOUS_DO_NOT_REMOVE`

- Historical threat-hypothesis evaluation matrices and report compatibility
  aliases: currently referenced by tests or thesis evidence.
- Weighted/local prediction implementations: inactive in deployed policy but
  still used by backtest/diagnostic regression paths and historical snapshot
  compatibility.
- Old schema readers and storage migrations: retained until supported upgrade
  floors and historical report/database compatibility are documented.
- `CODEX_REMEDIATION_HANDOFF.md`: ignored local operational history; not
  committed or removed.
- `local_cache_cleanup_review/`: untracked manual cache-review package created
  for the owner; not part of repository simplification.

## Removal safety conditions

Each removal commit must leave:

1. current Transformer strict loading and authority-boundary tests green;
2. VOMM artifact/manifest validation and explicit rollback available;
3. historical stored-report and database compatibility intact;
4. no broken imports, entrypoints, systemd commands, config references, or
   documentation links;
5. authoritative experiment hashes/results unchanged;
6. MongoDB disabled and isolated;
7. production behavior unchanged.

## Completed validation

Final cleanup state:

- tracked files: 469 (baseline 482);
- tracked lines: 616,492 (baseline 621,147);
- tracked blob bytes: 246,920,566 (baseline 247,114,080);
- working-directory apparent size: approximately 238 MiB (baseline 2.6 GiB,
  dominated by ignored generated copies);
- ignored generated data, packaging output, test caches, and bytecode removed;
- superseded pre-provenance `evaluation/authoritative_external_vomm/` removed;
  the exact seven-day replacement remains.

Validation performed:

- full socket-capable suite: `1194 passed, 16 skipped`;
- affected runtime/deployment/storage suite: 218 passed, 2 skipped;
- VOMM-focused regression: 14 passed;
- repository reproducibility documentation suite: 6 passed;
- all current CLI entrypoints accepted `--help`;
- Python compile/import validation passed;
- prediction, classification, and SMB policy validation passed;
- systemd module references and documentation links passed;
- tracked-production private-key/token pattern scan passed;
- VOMM artifact and manifest hashes matched;
- the real frozen Transformer checkpoint loaded strictly in eval mode with
  3,951 parameters using the locked Torch environment.

The old external/early-Zenodo/500-MiB benchmark payloads remain
`AMBIGUOUS_DO_NOT_REMOVE`: current authoritative evaluators and immutable audit
evidence still import or cite their shared tools and exact historical paths.
Removing them safely requires first extracting a stable evaluation-common
module and updating immutable reproducibility documentation; that is future
work, not a safe cleanup shortcut.
