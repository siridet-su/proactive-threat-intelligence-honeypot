# Honeypot Threat Intelligence

An evidence-bounded proof of concept for analyzing authorized Cowrie SSH
telemetry. It ingests events, reconstructs trusted behavior, produces advisory
next-behavior forecasts, and generates auditable session assessments and
operator guidance.

This is not an autonomous response system. Predictions cannot independently
authorize alerts, analytical claims, recommendations, guidance, blocking, or
actions.

## Current supported system

```text
Cowrie sensor
  -> authenticated bounded ingest
  -> SQLite
  -> session worker
  -> deterministic classification and trust filtering
  -> evidence graph and report-only correlation
  -> frozen Transformer forecast
  -> canonical session_assessment.v4 findings + falsifiable alternatives
  -> manually approved response guidance
  -> reports, dashboard API, and monitor
```

- SQLite is the authoritative deployed backend.
- Transformer seed `20260721` is the sole active experimental PoC predictor.
- Its checkpoint SHA-256 is
  `7fbd73c4bd071336fa52a589bf41e39f5a3122a67aee398dfb8e6dd9cfdfb04a`.
- The external hard-backoff VOMM is retained only as an explicit rollback and
  interpretable reference model.
- There is no blending, routing, cascade, heuristic fallback, or automatic
  VOMM fallback.
- Missing, malformed, incompatible, or hash-mismatched Transformer artifacts
  fail closed to model-unavailable/abstained forecast semantics.
- SQLite is the only active runtime backend. Removed MongoDB/PostgreSQL
  implementations remain recoverable from Git history, not selectable code.

See the [documentation index](docs/README.md), including the canonical
[architecture](docs/SYSTEM_ARCHITECTURE.md), [security and privacy](docs/SECURITY_AND_PRIVACY.md),
[model/evaluation](docs/MODEL_AND_EVALUATION.md), and
[deployment/recovery](docs/DEPLOYMENT_AND_RECOVERY.md) summaries. The older
architecture, operations, development, and cohort handoff paths remain as
backward-compatible detailed records.

## Scope and safety boundary

The system describes only what Cowrie can observe: connections, authentication
attempts, commands, transfers, and derived candidate ATT&CK mappings. It does
not establish attacker identity or intent, real-host impact, compromise,
malware execution, or unobserved lateral movement.

Deterministic trusted evidence is authoritative. SecureBERT, enrichment,
correlation, forecasts, and presentation text cannot promote weak or
audit-only evidence into fact. All response actions require canonical
behavioral evidence, policy provenance, scope, preconditions, verification,
rollback guidance, and manual approval.

New guidance uses `response_guidance.v3`: an immutable observed-evidence
snapshot plus exact policy/profile SHA-256 values determine its stable ID and
advisory tasks. Forecast and enrichment are display-only context. Guidance is
not written into prediction snapshots, never creates alerts, and has no
execution integration. Historical v1/v2 guidance remains readable only through
a non-authorizing legacy adapter.

New threat assessments use `session_assessment.v4`. They are constructed
directly from one content-addressed Cowrie evidence snapshot, fail closed when
an explicitly selected behavior or classification policy is unavailable, and
keep predictions, enrichment, correlations, and LLM prose outside canonical
authority. See [the v4 contract](docs/SESSION_ASSESSMENT_V4.md).

Never expose Cowrie or administrative services without explicit authorization,
isolation, monitoring, egress controls, and tested recovery. No live secrets,
keys, databases, raw production telemetry, private network configuration, or
cloud credentials belong in this repository.

## Quick start

Python 3.11 or newer:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp configs/production_config.example.json /tmp/honeypot-config.json
```

Replace only local placeholders in `/tmp/honeypot-config.json`; do not commit
the edited file.

Validate the core package:

```bash
python -m compileall -q production
pytest -q
```

Run individual entrypoints with `--help`, for example:

```bash
python -m production.api.ingest_api --help
python -m production.workers.session_worker --help
python -m production.api.dashboard_api --help
```

## Repository map

| Directory | Purpose |
|---|---|
| `production/` | Runtime package and reviewed offline tools |
| `configs/` | Trusted policies and safe configuration templates |
| `deployment/` | Generic systemd units and deployment templates |
| `tests/` | Unit, integration, security, compatibility, and evidence tests |
| `evaluation/` | Intentionally retained reviewed research evidence |
| `data/` | Public feeds, synthetic fixtures, and VOMM rollback model |
| `docs/` | Current operations, architecture, handoff, and immutable deployment evidence |

Reviewed offline bootstrap feeds live under `data/feeds/`; runtime refreshes
must use configured writable deployment paths.

Retained evaluators under `production/tools` support current reproducibility or
review workflows. Superseded hypothesis evaluators remain only as immutable
results under `evaluation/` and in Git history.

## Evidence and deployment status

The original corrected-target experiment remains truthfully recorded as
`BLOCKED_AT_SELECTION`. The later professor-approved PoC evaluation accepted
the known defense-evasion limitation without rewriting that blocker. The Final
partition was opened once under its ledger, and its immutable result and
post-analysis are retained.

The exact validated GCP deployment and rollback rehearsal are indexed by
[DEPLOYMENT_AND_RECOVERY.md](docs/DEPLOYMENT_AND_RECOVERY.md) and the
machine-readable `evaluation/next_tactic_final_production_activation_20260802.json`;
the dated deployment record remains available for full evidence.

## Optional components

Optional dependency groups are separated in `pyproject.toml` and
`requirements-*.txt`. SecureBERT, PDF/STIX artifacts, evaluation, and research
training are not part of the minimal runtime. Optional imports must remain lazy
and fail closed. MongoDB, PostgreSQL, and Vertex dependencies are archived.

For retention rules and generated output policy, see
[RETENTION_POLICY.md](docs/RETENTION_POLICY.md).
