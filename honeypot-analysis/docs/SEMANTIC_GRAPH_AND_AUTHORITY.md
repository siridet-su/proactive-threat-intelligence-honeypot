# Canonical semantic graph and authority boundaries

New `session_assessment.v4` records retain the historical v1/v2 evidence
snapshot as the `observed_evidence_sha256` input and add a content-addressed
`canonical_evidence_snapshot.v3`. The v3 extension contains:

- `typed_semantic_coverage.v1`, reporting the durable command/transfer
  population, typed fact/entity/relationship/chain counts, omitted count, and
  explicit limit reason; v1 emits only `full` or `unavailable` (a future
  streaming/chunking contract would require a new schema), and silent
  truncation is invalid;
- `canonical_semantic_graph.v1`, deduplicating evidence IDs and resolving
  compatible evidence IDs while rejecting conflicting semantic/status/
  provenance duplicates, and resolving entity, fact, relationship, chain,
  and authority references; and
- `behavioral_authority_decision.v1` records for every trusted or audit-only
  candidate.

Findings, falsifiable hypotheses, manual-only guidance, the monitor/dashboard
summary, and the provider projection consume the same v3 snapshot and graph.
The AI projection receives graph evidence and relationship IDs once; duplicate
legacy collections are not independently promoted.

## Authority rule

Typed semantic selections are the only active promotion source for activated
families. A structural parser abstention remains an abstention: a matching
legacy regex or ATT&CK candidate cannot promote the command. Legacy fallback is
trusted only when a reviewed policy explicitly lists its rule ID in the
authority boundary; the current policy lists none, so unsupported or ambiguous
forms are audit-only. Deferred families such as identity and scheduled-task
semantics remain audit-only until they have typed coverage.

SecureBERT disagreement remains audit context, prediction remains
non-authoritative, and response actions always require human approval with
`safe_to_auto_execute=false`.

## Reproducibility and compatibility

The v3 evidence digest, coverage hash, graph hash, typed fact-set hash, policy
hashes, and classifier-environment binding are recorded together. Existing
v1/v2 reports remain readable and are never silently recomputed. New graph and
coverage fields change new report IDs/digests and downstream AI projection IDs;
the SQLite schema, model weights, sequence length, vocabulary, calibration, and
source event IDs are unchanged.

This is a deterministic evidence-consistency contract, not an empirical
command-level accuracy claim. The retained corpus has no independently
adjudicated command-bearing ground truth.
