# CyberLab external adapter v1

`production.reproduction.cyberlab_adapter` is a separate, external-domain
adapter for Zenodo record 3687527. It does not change the internal
`production.reproduction.next_behavior.zenodo_corpus` parser or any reviewed
classifier, ATT&CK, trust, or prediction semantics.

## Source and eligibility

The source is the public CyberLab daily gzip member format: a top-level JSON
array whose items map one `session_id` to an event array. Every event must
carry `session_id`, `eventid`, a timezone-aware `timestamp`, and `sensor`.
High-interaction eligibility is label-blind and uses only
`sensor == "ubuntu_basic_pool"`; a session with a missing or mixed sensor is
excluded with an explicit reason. Commands, tactics, and external labels are
never used for this decision.

## Boundaries

The parser reads one top-level session object at a time. It canonicalizes event
time to UTC, retains source event order as the durable tie-break, and preserves
explicit `cowrie.session.closed` only. A missing close is `active/unresolved`;
no terminal target is fabricated. Repeated session IDs can be merged with
`merge_cyberlab_private_sessions`, including cross-file provenance. Conflicting
duplicate events fail closed. A cross-file session is not emitted through the
single-member safe receipt boundary until a reviewed multi-member receipt is
available.

`cowrie.command.input` text is taken from an exact `input` field or `CMD:`
message prefix. `cowrie.command.success` and `cowrie.command.failed` are kept
as contextual outcome events. CyberLab does not provide a command-event ID
that proves their association with an input, so the adapter never promotes
them to authoritative command-success/failure semantics. The ephemeral
`build_private_classifier_events` stream gives the existing monitor command
inputs and deliberately omits `input` from outcome records; it must not be
persisted.

## Privacy and provenance

`iter_cyberlab_sessions` emits `cyberlab_canonical_session.v1`: raw session
identifiers and command text are HMAC-protected or removed, while source
member identity/date, sensor provenance, event type/time, and outcome
association status remain auditable. Each record binds the Zenodo record/DOI,
source filename/date, full member SHA-256, official MD5 receipt, adapter hash,
sanitizer version, and deterministic policy hashes. Original source members
remain immutable and are not downloaded by this implementation.

The tracked contract is `configs/cyberlab_external_adapter.v1.json`. It must be
content-addressed and frozen before any real CyberLab development-member
support inspection. Synthetic fixtures in
`tests/test_cyberlab_adapter.py` are the only data used by the adapter tests.
