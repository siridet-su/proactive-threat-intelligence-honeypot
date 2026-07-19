# Repository support status

This inventory is authoritative for this repository. “Supported” means covered
by the local automated suite; it does not imply that a component has been
deployed or live-tested on every backend. The status vocabulary matches the
remediation handoff.

## Runtime services

| Component | Status | Scope and caveats |
|---|---|---|
| `production.api.ingest_api` | `COMPLETE_AND_VERIFIED` | Authenticated, sensor-bound bounded ingest; local socket and storage tests pass. |
| `production.api.dashboard_api` | `COMPLETE_AND_VERIFIED` | Authenticated JSON API, readiness/liveness and operational metrics. |
| `production.api.monitor_web` | `COMPLETE_AND_VERIFIED` | Authenticated monitor/API; primary static frontend plus compatibility `/legacy` rendering. |
| Session, analysis, enrichment, threat-hunt and webhook workers | `COMPLETE_AND_VERIFIED` | Durable fenced work on SQLite and MongoDB test backends; optional external services remain configuration-dependent. |
| Sensor forwarder | `COMPLETE_AND_VERIFIED` | Crash-durable local spool/checkpoint semantics; current changes are not deployed to Raspberry Pi. |
| Scheduled feed refresh | `COMPLETE_AND_VERIFIED` | Atomic last-good local implementation; timer is committed but not deployed or network-tested. |
| Prediction backtest/calibration/retention and session-count timers | `COMPLETE_AND_VERIFIED` | Offline/oneshot operations. Retention timer is dry-run only. |

## Storage backends

| Backend | Status | Intended use |
|---|---|---|
| SQLite | `COMPLETE_AND_VERIFIED` | Default local development and emergency fallback. |
| MongoDB | `COMPLETE_NOT_FULLY_VERIFIED` | Intended private production backend; complete mocked adapter/index/migration coverage, but the opt-in authorized live test is skipped locally and production cutover is not performed. |
| PostgreSQL | `INTENTIONALLY_DEFERRED` | Legacy compatibility only. Basic adapter/schema parity remains, but durable job leasing deliberately fails closed and no live endpoint is available. Do not select it for the remediated worker topology. |

`DATABASE_BACKEND` with backend-specific fields is the supported configuration
surface. `DATABASE_URL` is a compatibility input. Plain filesystem paths and
conflicting backend settings fail closed.

## Optional capabilities and dependency groups

| Capability | Requirement/extra | Status |
|---|---|---|
| Core HTTP/feed support | `requirements.txt` / base project | `COMPLETE_AND_VERIFIED` |
| MongoDB | `requirements-mongodb.txt` / `mongodb` | `COMPLETE_NOT_FULLY_VERIFIED` pending authorized live infrastructure |
| PostgreSQL compatibility | `requirements-postgresql.txt` / `postgresql` | `INTENTIONALLY_DEFERRED` |
| SecureBERT inference | `requirements-securebert.txt` / `securebert` | `COMPLETE_NOT_FULLY_VERIFIED`; lazy and disabled in the local core environment |
| SecureBERT training | `requirements-training.txt` / `training` | `INTENTIONALLY_DEFERRED` from production runtime; offline research only |
| Vertex narrative rewrite | `requirements-vertex.txt` / `vertex` | `COMPLETE_NOT_FULLY_VERIFIED`; disabled by default and no live request was authorized |
| PDF and external STIX validation | `requirements-artifacts.txt` / `artifacts` | `COMPLETE_NOT_FULLY_VERIFIED`; HTML/JSON/STIX core paths are tested, optional libraries are not installed locally |
| Model/evaluation tooling | `requirements-evaluation.txt` / `evaluation` | `INTENTIONALLY_DEFERRED` from runtime; offline comparison only |
| Tests | `requirements-dev.txt` / `test` | `COMPLETE_AND_VERIFIED` |

Optional imports must remain lazy. A core-only install must import every
`production` module and show every service `--help` without optional packages.

## Policies, tools, demos, and compatibility paths

- `configs/*.trusted.json` and validators in `production.policies` are
  `COMPLETE_AND_VERIFIED` production policy inputs. Files named `*.example.json`
  are templates, not trusted deployment state.
- Migration, backfill, normalization, job inspection, coverage, review, and
  repository-policy commands under `production.tools` are supported offline
  operational tools when invoked for their documented scope. Migration remains
  dry-run/preflight first and never changes SQLite.
- Evaluation, fitting, benchmark, review-template, Zenodo, and external-seed
  tools under `production.tools` are `INTENTIONALLY_DEFERRED` from runtime.
  Their outputs are research evidence, not active model policy.
- `demo/realtime_pipeline_demo.py` and `data/samples` are `NOT_APPLICABLE` to
  production evidence. They are synthetic demonstrations/fixtures.
- Legacy report aliases, `DATABASE_URL`, old sensor checkpoint parsing, and
  `/legacy` monitor rendering are `COMPLETE_AND_VERIFIED` compatibility paths.
  They must not be used to bypass current trust, secret, or lease contracts.
- PostgreSQL job-lease methods are `STARTED_BUT_BROKEN` for modern worker use by
  design: they raise a clear unsupported error. This explicit failure is safer
  than silent unfenced processing and is why PostgreSQL is not a supported
  production selection.

## Frontend and generated-artifact lifecycle

`production/api/static/monitor.html` is the primary monitor frontend and is
packaged as runtime data. `production.api.monitor_web` owns its authenticated
API and serves the older server-rendered frontend only at `/legacy` or when the
static asset is unavailable. Both paths are regression-tested. The static file
is maintained source, not generated output; changes must be reviewed together
with monitor API/security tests.

The checked-in files under `evaluation/` are historical reviewed outputs and
privacy-minimized payloads. Four JSONL payloads are large (about 35–89 MB each).
They are `INTENTIONALLY_DEFERRED` from Git cleanup in this remediation because
removing tracked research evidence would be destructive and change published
evaluation reproducibility. New evaluation output is ignored by default and
must be deliberately force-added after privacy and claim review.

The checked-in `data/feeds/*_cache.json` files are public last-good bootstrap
caches and remain tracked for offline startup. Runtime refreshes should target
configured writable deployment paths. `data/models/*.json` contains selected
aggregate transition data, not model binaries. `configs/*generated*.json` is a
reviewed historical/generated input; future generated configuration is ignored
unless explicitly promoted.

Databases, logs, spools, reports, downloads, model binaries, credentials,
virtual environments, caches, deployment archives, handoff files, and new
generated evaluation outputs are not committable. See `.gitignore` and
`docs/RETENTION_POLICY.md`. No existing tracked artifact was removed or
rewritten during the reproducibility remediation.
