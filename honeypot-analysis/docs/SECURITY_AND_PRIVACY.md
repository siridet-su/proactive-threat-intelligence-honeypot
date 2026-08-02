# Security and privacy (canonical summary)

This summary consolidates the current security boundary. The dated acceptance
records remain authoritative for exact hashes, receipts, and failure states.

## Collection and persistence

Cowrie output is sanitized before the forwarder reads it. The repository-owned
observer writes a bounded structured JSON projection; categorical text and
lifecycle diagnostics use closed vocabularies and cannot persist arbitrary
event or exception text. TTY replay is disabled because its shell prompt can
persist attacker-controlled identity data. Credential-bearing historical
records are restricted and receipt-bound but are not rewritten or deleted.

The accepted Pi revision recorded by final production evidence is
`5bb3b97fbe3b9034c70fc6ca2aba0ad9d159bb02`. Its installer uses a closed
manifest inventory, verifies the Cowrie/Python/Twisted binding, stops only
Cowrie, preserves the forwarder process, seals a non-overwriting owner-only
rollback receipt, and rejects release bytecode. Native JSON rotation leaves a
bounded group-readable handoff interval so the unchanged forwarder can drain
the renamed inode before it is sealed owner-only; categorical rotation is a
separate policy. These are repository-recorded acceptance properties, not a
claim about current live files.

SQLite, spools, reports, TTY evidence, keys, and deployment metadata are
outside the source release and use owner/group-restricted modes. The retained
final activation receipt records zero fresh credential-marker findings in the
new pipeline and no packet payload retention.

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

Earlier observer, rollback-receipt, rotation, and marker-scan failures are
summarized in [`HISTORICAL_IMPLEMENTATION_RECORD.md`](HISTORICAL_IMPLEMENTATION_RECORD.md)
and preserved byte-for-byte in Git history. Live state is not re-verified by
this local-only cleanup; any conclusion about current host contents beyond the
committed receipts is
`NOT_DETERMINABLE_FROM_CURRENT_REPOSITORY`.
