# Session Assessment v4

`session_assessment.v4` is the only threat-assessment authority for newly
generated reports. Historical `threat_hypothesis.v2` and
`session_assessment.v3` payloads remain immutable and are exposed only through
read-only compatibility adapters.

## Construction and authority

The evaluator in `production/reporting/session_assessment_v4.py` normalizes one
Cowrie session into `canonical_cowrie_evidence_snapshot.v1`, hashes it, and
rebuilds the evidence relationships without accepting a caller-supplied cached
graph. The derived canonical snapshot contains observations, Cowrie transfer
events, entities, relationships, connected chains, trusted ATT&CK candidates,
and audit-only candidates. Its SHA-256 is the sole evidence boundary.

The canonical output has two analytical collections:

- `behavioral_findings`: supported descriptions of observed behavior and
  relationships, with content-addressed IDs and exact evidence references.
- `hypothesis_sets`: bounded, non-exhaustive alternatives with falsification
  conditions. These are not attacker-intent or exact next-action claims.

Predictions, enrichment, cross-session correlation, and optional LLM prose are
stored only under `non_authoritative_context`. They cannot change canonical
findings, hypotheses, statuses, or IDs.

## Provenance and failure semantics

Every new assessment records the canonical evidence SHA-256, exact behavior
and classification policy file SHA-256 values and effective paths, relevant
model-provenance hashes, evaluator Git revision, and the cache rebuild binding.

An explicitly configured missing, malformed, or invalid policy is never
replaced with a bundled policy. The assessment fails closed to
`observation_only_abstention`, retaining the evidence snapshot while emitting
no findings or hypothesis sets.

New canonical records do not contain intent, objective, predicted-next-action,
global score, mitigation, response-action, or alert authority. Observed
evidence remains authoritative. `response_guidance.v3` remains a separate,
advisory-only sibling contract with manual approval and no execution
integration.

`validate_session_assessment_v4()` validates the whole canonical contract:
evidence hash integrity, policy/evaluator provenance, authority flags, unique
content IDs, evidence references, and prohibited fields.

## Consumers and validation

The production coordinator returns v4 before any legacy generator can run.
Monitor summaries, raw API payloads, JSON, Markdown, PDF, and STIX artifacts
read the same findings, hypothesis sets, evidence references, and provenance.
STIX does not promote hypotheses into indicators, alerts, actors, or response
actions.

Run:

```bash
pytest -q tests/test_session_assessment_v4.py
pytest -q
```

The controlled evaluation is a deterministic developer oracle, not independent
evidence of field accuracy or analyst usefulness.
