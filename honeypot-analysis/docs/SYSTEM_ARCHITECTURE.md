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

The last repository-recorded public Cowrie route is TCP/2222. The application
ingest route is private (Tailscale), while the dashboard and monitor health
routes are loopback services. The exact final connectivity evidence is
`evaluation/cowrie_public_connectivity_root_cause_20260802.json`: HAProxy was
already bound correctly and its Pi backend was healthy; the existing scoped
GCP firewall rule was disabled and was re-enabled without adding a listener or
widening its declared source range. Live state is not inferred from that
receipt.

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
[`TYPED_SEMANTIC_FACTS.md`](TYPED_SEMANTIC_FACTS.md) for normative details.

## Deliberate simplifications

SQLite is the only active runtime backend. MongoDB, PostgreSQL, SMB, Vertex,
legacy report generators, duplicate monitor renderers, prediction-only
recommendations, and automatic response paths were removed or archived. The
application remains a modular monolith with separately managed systemd
processes, not a microservice or SOAR platform. Historical records use
read-only compatibility adapters; they are not rewritten into current v4/v3
authority.
