# Typed collection/archive family decision

Decision date: 2026-07-30

Baseline: `710ffbb`

Disposition: **retain as shadow-only**

## Frozen contract and evidence

A supported `tar` create form records a `file_read` facet for its literal
source operands and an `archive_create` attempt for the literal destination
and sources. It does not establish that every source existed, that data was
successfully read, the archive's bytes or contents, collection intent,
exfiltration, or any real-host effect.

Filesystem search remains an independently activated inspection observation;
it does not become collection merely because an archive command appears later.
Failed, unknown, malformed, extraction-only, missing-source, unsupported-
option, expansion-dependent, wildcard/unresolved, redirected, compound, or
ambiguous operations are ineligible for collection authority.

No retained raw archive command exists in the demonstration telemetry. A
search-to-archive-to-transfer narrative would require exact source,
destination, event-order, outcome, and shared-identity proof that the current
evidence cannot establish safely. The family remains shadow-only.

The frozen evaluation and holdout verify archive/source representation,
conservative unknown handling, deterministic facts, and absence of any
collection-specific v4 finding, hypothesis, v3 finding, or guidance.

