# Typed command-transfer-attempt contract

Decision date: 2026-07-30

Baseline: `a4396b2`

Disposition: **activate only if the frozen evaluation and later holdout pass**

## Authority contract frozen before implementation

Command transfer attempts are distinct from direct Cowrie transfer events.
An eligible command attempt requires the same resolved HTTP(S) URL entity to
be referenced by both `remote_content_access` and `transfer_attempt` in one
parsed, successful, single-fragment `curl` or `wget` fact from the documented
option subset.

An explicit output path is retained when present but is not required: an
option-free downloader still attempts remote content access to stdout. The
output must never say that bytes arrived, a destination was created, an
artifact hash exists, execution occurred, or a real host was affected.
Only a direct `cowrie.session.file_download` or
`cowrie.session.file_upload` event with its separately validated artifact
identity can establish the existing direct-transfer observation.

Failed, unknown, malformed, missing-URL, unsupported-option,
expansion-dependent, ambiguous, conditional, compound, or shell-piped commands
abstain. ATT&CK, prediction, enrichment, correlation, hypothesis output, and
optional prose cannot define the operations or change eligibility.

## Output contract

The exact typed facts independently select one bounded v4 behavioral finding
and one v3 finding. No command-transfer action or hypothesis is authorized.
Guidance remains manual-only globally and direct-transfer behavior remains
unchanged.

## Acceptance

- zero completed-transfer claims from commands;
- zero false-positive eligible selections;
- zero unsupported specialized findings or guidance;
- exact shared URL, operation, outcome, proof-scope, and evidence references;
- deterministic IDs, persistence, and JSON/Markdown/PDF/STIX rendering;
- direct Cowrie transfer and all other activated families unchanged.

