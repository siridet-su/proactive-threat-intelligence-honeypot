# Typed semantic facts

`typed_semantic_fact_set.v1` is an additive, non-authoritative comparison
contract. It is built from the same already-redacted observed-behavior graph
used by `session_assessment.v4`, validated, compared with the source graph, and
discarded.

It is not embedded in v4 or `response_guidance.v3`, written to SQLite, exposed
through an API, rendered in an artifact, or used by a policy. Its content and
digest therefore cannot select or change findings, hypotheses, guidance,
statuses, or canonical IDs. A shadow exception is contained and cannot fail
the authoritative report path.

## Preserved fields

Each `typed_semantic_fact.v1` retains:

- the source observation and exact supporting evidence references;
- all existing literal operation types plus a shadow operation class;
- Cowrie outcome, scope, and relationship-derived action status;
- structured entities without conversion to display strings;
- shell fragments, operators, pipeline and conditional context;
- observed and conservatively derived working-directory context;
- recorded path uncertainty and non-authoritative resolution candidates;
- trusted ATT&CK candidates without promoting them into operation facts.

The fact set also retains exact entity, relationship, and connected-chain IDs.
Its comparison must account for every source observation and preserve those
identities exactly. Unknown commands remain `unknown`. Conditional or
unresolved path candidates remain non-linkable and cannot become canonical
evidence.

## Shadow boundary

`build_session_assessment_v4()` invokes `run_typed_semantic_shadow()` after
rebuilding observed behavior. The returned comparison is intentionally
discarded. Direct test and evaluation callers may inspect the fact set and
comparison result, but production consumers cannot.

No hypothesis or guidance policy reads this contract. A later migration
requires separate approval, compatibility work, and semantic validation.
