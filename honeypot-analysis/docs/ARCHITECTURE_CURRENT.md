# Current architecture

## Runtime data flow

1. `production.workers.sensor_forwarder` durably reads authorized Cowrie JSON
   and sends bounded batches with sensor-bound authentication.
2. `production.api.ingest_api` validates authentication, request limits,
   event schemas, and sensitive-data policy before storing events.
3. `production.storage.backend` owns the authoritative SQLite contract,
   transactions, leases, reports, predictions, and provenance.
4. `production.workers.session_worker` and `session_monitor` reconstruct
   sessions, split compound commands, classify observations, and close work
   through fenced job lifecycle operations.
5. `production.classification.classification_pipeline` applies reviewed rules
   and optionally SecureBERT. `classification.trust` decides what may enter
   canonical evidence; disagreements and weak outputs remain audit-only.
6. Correlation builds occurrence-preserving evidence graphs and report-only
   relationships. It cannot rewrite the trusted tactic sequence.
7. `production.prediction.next_behavior_runtime` verifies and loads the frozen
   Transformer and emits an advisory snapshot separately from factual
   observations. There is no scorer cascade or automatic fallback.
8. `session_assessment.v4` is built directly from one immutable, hashed Cowrie
   evidence snapshot and is the only authority for new threat assessments.
   It separates behavioral findings from falsifiable alternatives and records
   exact evidence, policy, model-provenance, and evaluator Git hashes.
   Historical v2/v3 records remain readable through read-only adapters.
9. `response_guidance.v3` evaluates a SHA-256-bound reviewed policy directly
   against an immutable canonical observed-behaviour snapshot. Its guidance ID
   is derived from the evidence, policy, optional explicitly configured asset
   profile, selected rules, and actions—not timestamps, scores, forecasts, or
   enrichment. Forecast and enrichment may appear only as non-authoritative
   context. V1/v2 payloads remain display-only historical adapters and are
   never promoted into current actions.
10. Reporting writes JSON/Markdown/STIX/PDF artifacts where enabled. Dashboard
    APIs and the single static monitor UI revalidate authority-bearing fields
    at their boundary.

## Prediction policy

The active PoC ranker is one frozen, hash-bound corrected-target Transformer:

- seed `20260721`;
- CPU float32, one causal layer, `d_model=16`, four heads, feed-forward 32,
  maximum sequence length 8, 3,951 parameters;
- checkpoint SHA-256
  `7fbd73c4bd071336fa52a589bf41e39f5a3122a67aee398dfb8e6dd9cfdfb04a`;
- vocabulary, model specification, preprocessing, classifier provenance, and
  calibration are hash-bound and validated before inference.

There is no automatic fallback. An unavailable Transformer produces explicit
unavailable/abstained semantics. Historical snapshots retain their original
model and policy meaning.

The external VOMM artifact and manifest under `data/models/` are an explicit
operator-selected rollback/reference implemented by
`production.prediction.vomm_rollback`. Weighted, local-first, heuristic,
cascade, and predictive-alert implementations have been removed; recover them
only from tag `pre-aggressive-prediction-cleanup-20260727`.

Offline reproduction is isolated under
`production.reproduction.next_behavior` and has one public entrypoint:
`python -m production.tools.reproduce_next_behavior_experiment`.

## Ownership and trust boundaries

| Boundary | Authority |
|---|---|
| Raw Cowrie observation | Immutable ingest provenance |
| ATT&CK evidence | Reviewed deterministic/trusted classifier policy |
| Correlation | Explanation only |
| Forecast | Advisory model output only |
| Enrichment | Context only |
| Finding / hypothesis | Canonical v4 evidence references and whole-contract validator |
| Response guidance | SHA-256-bound v3 policy plus immutable canonical observed evidence |
| Execution | Human operator outside this application |

Secrets pass through centralized redaction and serialization policy. HMAC keys,
credentials, databases, spools, raw telemetry, and private deployment metadata
remain outside Git.

## Storage

SQLite is the only runtime backend. MongoDB and PostgreSQL adapters,
dependencies, schemas, migrations, and backend-specific tests were archived in
Phase 6 because neither met the durable runtime contract. Historical records
are preserved in SQLite and remain readable; no database migration was run.

## Compatibility

Additive schemas and dual readers preserve stored historical reports and
prediction snapshots without recomputation. Compatibility aliases are
presentation/read paths, not an authority bypass. Removal requires a declared
minimum upgrade version and a migration of every supported historical record.
