# System architecture (canonical summary)

This is the canonical architecture index. Detailed contracts and dated
evidence remain in the linked records; this file is a navigational summary,
not a replacement for their hashes or machine-readable receipts.

## End-to-end flow

```text
Pi Cowrie (sanitized JSON)
  -> sensor_forwarder (bounded durable batches, sensor authentication)
  -> HAProxy/PROXY protocol and ingest_api
  -> SQLite (transactions, deduplication, leases, outbox)
  -> session_worker/session_monitor
  -> reviewed classification and canonical evidence reconstruction
  -> session_assessment.v4 + advisory Transformer snapshot
  -> response_guidance.v3 (manual-only)
  -> JSON/Markdown/PDF/STIX reports, dashboard API, monitor UI
```

The deployed public Cowrie route is TCP/2222. The application ingest route is
private (Tailscale), while the dashboard and monitor health routes are loopback
services. The exact final connectivity evidence is in
[`COWRIE_PUBLIC_CONNECTIVITY_ROOT_CAUSE_2026-08-02.md`](COWRIE_PUBLIC_CONNECTIVITY_ROOT_CAUSE_2026-08-02.md)
and `evaluation/cowrie_public_connectivity_root_cause_20260802.json`.

## Component boundaries

- `production.workers.sensor_forwarder` reads only the authorized sanitized
  Cowrie feed and sends authenticated, bounded batches.
- `production.api.ingest_api` validates authentication, limits, event shape,
  and sensitive-data policy before a transaction reaches SQLite.
- `production.storage.backend` is the authoritative runtime store. SQLite is
  the only active backend; historical adapters are read-only.
- Session workers reconstruct complete sessions, apply reviewed deterministic
  classification, and build occurrence-preserving evidence relationships.
- `session_assessment.v4` owns new factual findings and bounded falsifiable
  hypotheses. `response_guidance.v3` independently evaluates the same immutable
  evidence and is advisory-only.
- The Transformer is a separate, hash-bound prediction context. It cannot
  create findings, hypotheses, guidance, alerts, or actions.
- Reports and APIs revalidate the same v4/v3 contracts at their boundaries.
  STIX is an export, not an authority escalation.

## Trust boundaries

| Data | Authority |
| --- | --- |
| Observed Cowrie events | Canonical evidence, subject to ingest provenance |
| Reviewed rule classifications | Trusted candidate evidence only when policy permits |
| SecureBERT candidates, enrichment, correlations | Audit/context only |
| Transformer/VOMM predictions | Advisory prediction context only |
| Findings and hypotheses | v4 whole-contract evaluator |
| Guidance | v3 policy over immutable canonical evidence |
| Response execution | Outside this application and requires a human |

See [`SESSION_ASSESSMENT_V4.md`](SESSION_ASSESSMENT_V4.md),
[`RESPONSE_GUIDANCE_V3.md`](RESPONSE_GUIDANCE_V3.md), and
[`ARCHITECTURE_CURRENT.md`](ARCHITECTURE_CURRENT.md) for the normative details.
