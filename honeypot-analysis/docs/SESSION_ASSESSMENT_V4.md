# Session Assessment v4

`session_assessment.v4` is the only threat-assessment authority for newly
generated reports. Historical `threat_hypothesis.v2` and
`session_assessment.v3` payloads remain immutable and are exposed only through
read-only compatibility adapters.

## Construction and authority

The evaluator in `production/reporting/session_assessment_v4.py` normalizes one
Cowrie session and rebuilds its evidence relationships without accepting a
caller-supplied cached graph. It then creates exactly one
`canonical_evidence_snapshot.v1`, consumed unchanged by both the v4 assessment
and its `response_guidance.v3` sibling. The snapshot contains sensor evidence,
observations, Cowrie transfer events, entities, relationships, connected
chains, and trusted ATT&CK candidates. Model-only/audit-only classifier
candidates remain outside the authority snapshot. Classifier confidence,
scores, predictions, and enrichment therefore cannot change its SHA-256 or any
content-addressed assessment or guidance ID.

The runtime classification policy is read once, validated as a whole, hashed
from those exact bytes, and compiled from that same in-memory document.
Explicitly configured missing or invalid rule policies compile no fallback
rules. SecureBERT-only labels remain audit-only context even above a model
score threshold; a score cannot promote model output into observed evidence.

The canonical output has two analytical collections:

- `behavioral_findings`: supported descriptions of observed behavior and
  relationships, with content-addressed IDs and exact evidence references.
- `hypothesis_sets`: bounded, non-exhaustive alternatives with falsification
  conditions. These are not attacker-intent or exact next-action claims.

An incomplete-chain hypothesis is emitted only when the existing relationship
layer provides a resolved artifact identity and no completion observation for
that identity exists elsewhere in the same canonical session. Ambiguous
artifact or relationship identity, and session-wide contradictory completion
evidence, cause deterministic abstention.

Predictions, enrichment, cross-session correlation, and optional LLM prose are
stored only under `non_authoritative_context`. They cannot change canonical
findings, hypotheses, statuses, or IDs.

The evaluator also builds and validates `typed_semantic_fact_set.v2` in
shadow mode. The fact set preserves richer structured semantics for comparison
but is discarded before record construction. It is not an authority input,
canonical field, persisted value, API value, or artifact value. It is bound to
the canonical evidence, derived semantic input, exact behavior,
classification, and semantic-vocabulary policy hashes, and evaluator
revision. See `docs/TYPED_SEMANTIC_FACTS.md`.

## Provenance and failure semantics

Every new assessment records the canonical evidence SHA-256, exact behavior
and classification policy file SHA-256 values and effective paths, the actual
SHA-256 and expected SHA-256 for each configured Transformer/runtime model
artifact, the configured MITRE cache path and actual SHA-256, evaluator Git
revision, and the cache rebuild binding. Missing artifacts and digest
mismatches remain explicit provenance states; metadata never turns a mismatch
into a verified artifact.

An explicitly configured missing, malformed, or invalid behavior,
classification, or MITRE source is never replaced with a bundled source. The
assessment fails closed to
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
