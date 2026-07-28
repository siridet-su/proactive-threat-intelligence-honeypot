# Legacy removal index

Git history is the archive. Do not create a new `legacy/` source tree.

Recovery baseline: annotated local tag
`pre-handoff-repository-cleanup-20260727`, commit
`3fe1482d8047deb9592cf1fb1a52d2cc68df2d18`.

| Removed item | Reason | Replacement | Recovery |
|---|---|---|---|
| `evaluation/generated/` | 2.3 GiB of ignored deterministic duplicate rebuild output | Retained source receipts, canonical cache artifacts, and committed compact evidence | Regenerate with reviewed evaluation tooling; directory was untracked |
| `build/` and `honeypot_analysis.egg-info/` | Local packaging output | `pyproject.toml` | `python -m build` or editable install |
| `.pytest_cache/` and Python bytecode caches | Interpreter/test-generated | Source and tests | Rerun Python/pytest |
| `evaluation/authoritative_external_vomm/` | Pre-provenance evaluation superseded by the exact Zenodo-seven-day evaluation | `evaluation/authoritative_external_vomm_zenodo7_20260721/` | Commit `744dca3` or the recovery tag |

| Legacy prediction scorers, cascade, heuristic fallback, local transitions, weight fitting, old predictive alerts and backtests | Unsupported by the frozen Transformer runtime and explicit VOMM rollback | `next_behavior_runtime.py` and `vomm_rollback.py` | `pre-aggressive-prediction-cleanup-20260727` |
| Superseded next-tactic and professor-protocol runners | Immutable reports, receipts and manifests are authoritative; duplicate executables obscured the supported path | `production.tools.reproduce_next_behavior_experiment` | `pre-aggressive-prediction-cleanup-20260727` |
| Calibration/backtest/retention timer units | No current production caller; prediction calibration is frozen into the Transformer artifact contract | Current application services and storage retention API | `pre-aggressive-prediction-cleanup-20260727` |
| Monolithic `test_production_services.py` and obsolete experiment tests | Primarily protected removed scorer/backtest/calibration implementations | Focused runtime, authority, report/API, storage, VOMM rollback, and reproduction suites | `pre-aggressive-prediction-cleanup-20260727` |

| Phase 6 canonical-report wrappers | New writes use only `canonical_pipeline.py`, `session_assessment_v4.py`, and `response_guidance_v3.py` | Canonical v4/v3 evaluator plus read-only historical adapters | Commit `d2e047c31fa4ba524ca4bb7b89660d8ae6a87d22` |
| Legacy SMB decision/guidance generators and policies | Unreachable from canonical writes and carried unsupported scoring/action surfaces | `response_guidance.v3` | Commit `d2e047c31fa4ba524ca4bb7b89660d8ae6a87d22` |
| MongoDB/PostgreSQL adapters, schemas, migration tool, dependencies, and backend tests | Neither backend satisfied the current durable leasing/outbox/migration contract | SQLite storage, backup, and restore tooling | Commit `d2e047c31fa4ba524ca4bb7b89660d8ae6a87d22` |
| Vertex narrative client/configuration | Non-authoritative presentation path was unreachable from canonical v4 writes | Deterministic artifact renderers | Commit `d2e047c31fa4ba524ca4bb7b89660d8ae6a87d22` |
| Broken prediction-retention console entrypoint | Target module did not exist; retention remains explicit storage maintenance only | Documented SQLite lifecycle/backup procedures | Commit `d2e047c31fa4ba524ca4bb7b89660d8ae6a87d22` |
| Server-rendered and `/legacy` monitor pages | Duplicated the shipped monitor and could drift from its API contract | `production/api/static/monitor.html` | Commit `d2e047c31fa4ba524ca4bb7b89660d8ae6a87d22` |

MongoDB, PostgreSQL, Vertex, and legacy SMB/report implementations are Git
history only. Their stored historical payloads remain readable through the
current compatibility adapters.

Any later source removal must add its exact paths, replacement, tests, and
recovery commit here.
