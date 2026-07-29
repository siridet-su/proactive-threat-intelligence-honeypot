# Typed semantic facts

`typed_semantic_fact_set.v2` is a lossless, versioned interpretation contract
built from the same redacted observed-behaviour reconstruction used while
creating `session_assessment.v4`. The complete fact set is validated and
content-addressed before any family-scoped policy evaluation.

Only `sensitive_read` is activated. The complete fact set is not embedded in
v4 or `response_guidance.v3`, written to SQLite, exposed through an API, or
rendered in an artifact. Instead, v4 and v3 independently evaluate the same
validated fact set and retain a bounded content-addressed trace for a matched
sensitive read. All other families remain shadow-only. A typed-evaluation
error fails the selected family closed without promoting legacy credential
matching.

## Bound inputs

Every fact set records:

- the canonical evidence and source-evidence SHA-256 values;
- a SHA-256 over every observed-behaviour field read by the extractor;
- the exact behavior and classification policy SHA-256 values;
- the exact bytes, version, extractor version, and repository-relative source
  of `configs/typed_semantic_vocabulary.v1.json`; and
- the evaluator Git revision.

The builder rejects an observed-behaviour input that does not match the bound
semantic-input digest. A missing, invalid, or substituted vocabulary makes the
family input unavailable. There is no fallback vocabulary.

## Contract

Facts preserve ordered operation facets rather than choosing one primary
operation. Each facet has a closed operation type, family, effect, categorical
proof scope, Cowrie-scoped effect status, entity references, and any exact
literal action emitted by canonical behavior extraction.

The contract separately preserves:

- command parsing and abstention status;
- action outcome and its fragment, compound, unknown, or direct-event scope;
- structured entity values, source entity identity, redaction state, and every
  observed form of a shared entity;
- shell fragments, operators, conditional context, and pipeline context;
- observed, confirmed, conditional, or unknown working-directory context;
- resolved path identities and non-authoritative conditional candidates;
- exact evidence references;
- typed whole-session relationships and connected chains; and
- trusted ATT&CK candidates with an explicit mapping scope.

ATT&CK candidates have `may_define_operations=false`. A label cannot create or
change a literal operation.

All fact, operation, entity, relationship, chain, path, ATT&CK-candidate, fact
set, and shadow-diff identities are deterministic and content-addressed. The
validator checks exact keys, closed semantic values, hashes, reciprocal and
resolvable references, deterministic entity aggregation, and independent
whole-session relationship and chain rebuilds.

## Supported shell subset

This extractor is deliberately not a shell interpreter. It supports:

- shell words and POSIX quoting accepted by `shlex`;
- the upstream canonical splitter's pipe, `&&`, `||`, and explicit sequence
  fragments;
- simple `<`, `>`, and `>>` redirection;
- selected documented options for the reviewed command families; and
- an explicit set of wrapper forms with no ambiguous wrapper options.

It does not interpret aliases, shell functions, variables, glob expansion,
command or process substitution, heredocs, file-descriptor manipulation,
unsupported options, or malformed quoting. Those forms abstain. Missing
operands or targets remain `unknown`. An adjacent numeric IO descriptor such
as `2>` is rejected, while an ordinary numeric utility argument followed by a
separately spaced redirect (for example `head -c 20 < file`) remains
parseable.

General extractors cover:

- host, account, route, process, socket, filesystem, and service inspection;
- file read, overwrite/truncate, append, in-place modification, permission
  modification, delete, move, copy, and directory creation;
- decoding and archive creation;
- scheduled-task inspect, modify, and delete;
- working-directory changes;
- command transfer attempts and direct Cowrie transfer observations; and
- script, inline-program, and shell-pipeline execution attempts.

`file_read` and `file_modify`, `file_write` and `file_append`,
`decode_transform` and its output/consumer facets, and transfer attempt and
direct transfer observation remain distinct. A reported failure never becomes
a completed effect or confirmed working-directory change. A compound outcome
does not become fragment proof.

## Relationships and uncertainty

Relationships are rebuilt across the complete fact set; source graph
relationships are comparison inputs only. Supported relationships require
resolved identity and applicable observed outcome. A shared conditional path
may produce a `partial` diagnostic relationship with no authoritative entity
reference. It cannot become a supported relationship or a supported chain.

A command transfer remains an attempt. Only a direct
`cowrie.session.file_download` or `cowrie.session.file_upload` observation can
create `transfer_observed`, and only matching resolved identity can connect the
attempt to that observation.

## Resource limits

The immutable vocabulary bounds:

- facts: 2,048;
- entities: 8,192;
- relationships: 8,192;
- chains: 2,048;
- one command: 8,192 UTF-8 bytes; and
- aggregate command input: 1 MiB.

Exceeding a limit makes the selected family unavailable and leaves
non-migrated contained behavior unchanged. Empty and incomplete sessions
remain valid observation-only inputs and do not invent facts.

## Review diagnostics and activation

Direct callers may build a deterministic `typed_semantic_shadow_diff.v1` and
render it as Markdown. It contains old literal actions, typed operations,
blocked or partial matches, abstention reasons, and the exact family-scoped
policy impact. The diagnostic itself remains discarded.

The vocabulary records `sensitive_read` and `transfer` as `activated`,
`unknown` as `not_eligible`, and every other operation family as
`not_activated`. A sensitive read requires exactly `file_read` and
`credential_path_read` on the same resolved, linkable credential-path entity,
a parsed fragment, no abstention, and a Cowrie-reported successful fragment
outcome. Additional operations, failures, compound outcomes, conditional
outcomes, unsupported syntax, unresolved identities, and ambiguity abstain.

`credential_path_read` is emitted only when the general parser proves a
same-entity `file_read`; merely mentioning a sensitive path in `echo`, delete,
permission-change, or other non-read syntax does not create it.

Credential sensitivity is matched against the complete, quote-normalized
parsed path operand, never a regex substring from the raw command. The
hash-bound vocabulary names `/etc/passwd`, `/etc/shadow`, AWS credentials,
gcloud application-default credentials, and the reviewed DSA/ECDSA/Ed25519/RSA
private-key basenames. Suffix matching is segment-exact, so public-key,
backup, and whitespace-suffixed paths do not match. A path resolved through an
observed working directory has the same entity identity in `read_paths` and
`credential_paths`. Input-redirection reads are recorded with
`shell_syntax` proof before the derived sensitive-read facet.

Metadata inspection such as `stat` remains outside the reviewed content-reader
subset and therefore stays `unknown`. Unsupported nested syntax cannot create
a credential entity or sensitive-read operation. A raw credential-path mention
may remain audit-only context for other unsupported commands, but it cannot
select the family without a same-entity parsed read.

The selected threat output is a bounded behavioral finding, not an attacker
intent or hypothesis. The selected v3 playbook remains advisory, manually
approved, and non-executable.

For `transfer`, only `transfer_observed` from a direct
`cowrie.session.file_download` or `cowrie.session.file_upload` event is
eligible. It must reference one exact linkable SHA-256, contain no unresolved
entity, carry `event_observed` effect and outcome, and retain only its direct
Cowrie event as supporting evidence. Downloader commands, even when Cowrie
reports command success, remain transfer attempts and abstain. ATT&CK T1105,
prediction, enrichment, and command-to-event relationships cannot create the
literal operation. A supported shared-path confirmation relationship is
contextual evidence linkage, not causality or execution proof.

The transfer family produces a bounded observed-event finding and manual
hash-correlation guidance. It produces no follow-on threat hypothesis while
execution and cross-family relationship semantics remain non-activated.
Both selected playbooks remain manually approved, non-executable, and
incapable of alerts. ATT&CK labels, predictions, enrichment, correlations, and
optional prose cannot create or alter a family match.
