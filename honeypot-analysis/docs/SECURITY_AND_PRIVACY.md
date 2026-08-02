# Security and privacy (canonical summary)

This summary consolidates the current security boundary. The dated acceptance
records remain authoritative for exact hashes, receipts, and failure states.

## Collection and persistence

Cowrie output is sanitized before the forwarder reads it. Structured JSON is
the analytical feed; categorical text is diagnostic output with a narrower
closed projection. Credential-bearing historical records are not rewritten by
the application. SQLite, spools, reports, TTY evidence, keys, and deployment
metadata are outside the source release and use owner/group-restricted modes.
Native JSON rotation and categorical rotation have separate mode and durability
contracts. See [`COWRIE_UPSTREAM_CREDENTIAL_PRIVACY_DECISION.md`](COWRIE_UPSTREAM_CREDENTIAL_PRIVACY_DECISION.md),
[`COWRIE_PRIVACY_BLOCKER_HANDOFF_2026-07-30.md`](COWRIE_PRIVACY_BLOCKER_HANDOFF_2026-07-30.md),
and [`PI_COWRIE_PLAINTEXT_LOG_PRIVACY_ACCEPTANCE_2026-08-01.md`](PI_COWRIE_PLAINTEXT_LOG_PRIVACY_ACCEPTANCE_2026-08-01.md).

## Network and access controls

- Sensor batches require sensor-bound authentication and schema validation.
- The public Cowrie dependency is only the intended TCP/2222 path; the final
  correction enabled the existing scoped GCP rule rather than adding a port or
  widening a rule. HAProxy sends the required PROXY header to the Pi backend.
- Ingest and management routes are not public application interfaces.
- Secrets use service-specific credential files and centralized redaction;
  raw credentials, private keys, and source deployment metadata are not Git
  artifacts.
- The lifecycle policy prohibits automatic deletion and unauthorized external
  source-IP sharing. Optional enrichment is fail-closed and non-authoritative.

## Analytical safety

Observed evidence remains authoritative. Predictions, enrichment, ATT&CK-only
context, and optional prose cannot select findings, hypotheses, guidance,
alerts, or actions. New guidance always requires manual approval, is never safe
to auto-execute, and has no response or alert side effects. Historical v1/v2/v3
records remain readable through adapters without rewriting them.

## Residual limitations

The repository contains both successful final activation evidence and earlier
failed privacy/deployment handoffs. Those are intentionally retained so a
reviewer can distinguish a corrected gate from a prior failure. Live state is
not re-verified by this local-only cleanup; any conclusion about current host
contents beyond the committed receipts is
`NOT_DETERMINABLE_FROM_CURRENT_REPOSITORY`.
