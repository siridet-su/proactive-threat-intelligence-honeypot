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

See the [documentation index](docs/README.md). The retained documentation is a
single canonical set covering architecture, security/privacy, model/evaluation,
deployment/recovery, current repository-recorded production state, and the
historical implementation record. Superseded implementation reports remain
recoverable from Git history.

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
authority. The canonical v4, v3, and typed-semantic contracts are consolidated
in [SYSTEM_ARCHITECTURE.md](docs/SYSTEM_ARCHITECTURE.md).

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
pip install -r requirements-dev.txt
cp configs/production_config.example.json /tmp/honeypot-config.json
```

Replace only local placeholders in `/tmp/honeypot-config.json`; do not commit
the edited file.

Validate the core package:

```bash
python -m compileall -q production
pytest -q
```

For development tooling, also install `requirements-dev.txt`. Use focused
suites first for storage, ingest security, prediction runtime, reporting,
guidance, and authority boundaries; then run the full suite. A loopback-socket
failure in a restricted sandbox must be distinguished from a test assertion
failure.

Validate policy changes explicitly:

```bash
python -m production.policies.validate_prediction_policy \
  --policy configs/prediction_policy.transformer_poc.trusted.json
python -m production.policies.validate_classification_rules \
  --policy configs/classification_rules.trusted.json
python -m production.policies.validate_response_guidance_policy \
  --policy configs/response_guidance_policy.v3.json
python -m production.tools.reproduce_next_behavior_experiment --help
```

That experiment entrypoint is the only supported prediction experiment CLI;
modules below `production.reproduction.next_behavior` are libraries, not
independent command-line interfaces.

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
| `evaluation/` | Current fixtures and final reproducibility/acceptance evidence |
| `data/` | Public feeds, synthetic fixtures, and VOMM rollback model |
| `docs/` | Canonical summaries and current operational/authority contracts |

Reviewed offline bootstrap feeds live under `data/feeds/`; runtime refreshes
must use configured writable deployment paths.

Retained evaluators under `production/tools` support current reproducibility or
review workflows. Superseded hypothesis evaluators remain only as immutable
results under `evaluation/` and in Git history.

## Development safety

- Classifier changes require reviewed provenance, bounded conditions,
  whole-policy validation, and positive, negative, compound-command,
  audit-only, and secret-containment tests. A label is not proof of success or
  impact.
- Model changes require a new immutable artifact and manifest with frozen
  preprocessing, vocabulary, policies, partition membership, selection,
  calibration, metrics, and authority restrictions. Never tune after Final
  access or reinterpret stored snapshots.
- Guidance changes must preserve deterministic v3 identity, immutable observed
  evidence, manual approval, non-executability, and adversarial tests for
  non-authoritative input and policy/hash drift.
- Storage changes must preserve SQLite transactions, migrations, leases,
  backups, and restore semantics. Another backend is a new reviewed design,
  not a compatibility switch.

Caches, databases, checkpoints, logs, benchmark runs, generated reports, local
keys, and environments are not source artifacts. Commit evaluation evidence
only after privacy, provenance, claim, size, and reproducibility review.

## Evidence and deployment status

The original corrected-target experiment remains truthfully recorded as
`BLOCKED_AT_SELECTION`. The later professor-approved PoC evaluation accepted
the known defense-evasion limitation without rewriting that blocker. The Final
partition was opened once under its ledger, and its immutable result and
post-analysis are retained.

The canonical evaluation claim index is
`evaluation/canonical_final_evaluation.json`. The current capstone target and
active release are indexed by
[CURRENT_PRODUCTION_STATE.md](docs/CURRENT_PRODUCTION_STATE.md), while the
deployment and rollback procedure is indexed by
[DEPLOYMENT_AND_RECOVERY.md](docs/DEPLOYMENT_AND_RECOVERY.md). The
machine-readable `evaluation/next_tactic_final_production_activation_20260802.json`
is retained as historical evidence for the former VM, not as the current
target selector; superseded activation narratives remain available in Git
history.

## Optional components

Optional dependency groups are separated in `pyproject.toml` and
`requirements-*.txt`. SecureBERT, PDF/STIX artifacts, evaluation, and research
training are not part of the minimal runtime. Optional imports must remain lazy
and fail closed. MongoDB, PostgreSQL, and Vertex dependencies are archived.

Lifecycle and generated-output rules are consolidated in
[SECURITY_AND_PRIVACY.md](docs/SECURITY_AND_PRIVACY.md).
