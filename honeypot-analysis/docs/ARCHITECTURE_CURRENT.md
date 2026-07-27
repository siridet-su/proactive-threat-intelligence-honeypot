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
8. `session_assessment.v3` organizes observations, claims, counterevidence,
   assumptions, limitations, gaps, alternatives, and falsification conditions.
   `threat_hypothesis.v2` remains readable as a compatibility/report contract.
9. `response_guidance.v2` derives finding, triage, and advisory actions from
   validated canonical behavioral evidence and reviewed policy. Forecast or
   enrichment alone is never action eligibility.
10. Reporting writes JSON/HTML/STIX/PDF artifacts where enabled. Dashboard and
    monitor endpoints revalidate authority-bearing fields at their boundary.

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
| Claim | Canonical cited evidence and claim validator |
| Response guidance | Trusted action policy plus canonical behavioral scope |
| Execution | Human operator outside this application |

Secrets pass through centralized redaction and serialization policy. HMAC keys,
credentials, databases, spools, raw telemetry, and private deployment metadata
remain outside Git.

## Storage

SQLite is authoritative in the validated deployment. MongoDB is disabled and
is retained only as tested future work; selecting it requires independent live
parity, indexing, migration, backup, restore, and rollback gates. PostgreSQL is
legacy compatibility and deliberately rejects modern durable leasing.

## Compatibility

Additive schemas and dual readers preserve stored historical reports and
prediction snapshots without recomputation. Compatibility aliases are
presentation/read paths, not an authority bypass. Removal requires a declared
minimum upgrade version and a migration of every supported historical record.
