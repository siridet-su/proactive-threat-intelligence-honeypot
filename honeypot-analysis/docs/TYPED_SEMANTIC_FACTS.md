# Typed semantic facts

`typed_semantic_fact_set.v2` is a lossless, versioned, non-authoritative
comparison contract. It is built from the same redacted observed-behaviour
reconstruction used while creating `session_assessment.v4`, validated, compared
with that source, and discarded.

It is not embedded in v4 or `response_guidance.v3`, written to SQLite, exposed
through an API, rendered in a production artifact, or used by a hypothesis or
guidance policy. A shadow exception is contained and cannot fail or change the
authoritative report path.

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
shadow run unavailable. There is no fallback vocabulary.

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
operands or targets remain `unknown`.

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

Exceeding a limit makes only the shadow run unavailable. Empty and incomplete
sessions remain valid observation-only inputs and do not invent facts.

## Review diagnostics and activation

Direct callers may build a deterministic `typed_semantic_shadow_diff.v1` and
render it as Markdown. It contains old literal actions, typed operations,
blocked or partial matches, abstention reasons, and a no-authority policy-impact
summary. The production v4 call discards this data.

The vocabulary records every operation family as `not_activated` (and
`unknown` as `not_eligible`). This metadata is only a boundary for a later,
separately approved family-by-family migration. It grants no hypothesis,
guidance, alert, or response authority.
