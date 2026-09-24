---
title: Web-corp login pipeline deployment validation
date: 2026-09-24
status: passed with scope limitations
environment: Raspberry Pi development honeypot
---

# Web-corp login pipeline deployment validation

## Result

The web-corp login path is deployed and accepting requests on the Pi's
ZeroTier-bound HTTP listener. A synthetic SQL-injection-shaped login was
rejected by the decoy and flowed through the dedicated spool/Redis/processor
path. This validates the application and Redis projection path; the test did
not use a separate remote ZeroTier peer or independently query MongoDB with a
database shell.

## Checks performed

- `go test ./...` passed for both `agents/collector-agent` and
  `agents/processor-agent`.
- Five web-corp request-path tests passed inside the built container image with
  networking disabled. They cover login rejection, spool persistence and
  permissions, truncation metadata, SQLi indicators, and spool-capacity
  failure behavior.
- The sibling Compose configuration validated, and the updated web-corp image
  built successfully.
- Only `honeypot-collector.service`, `honeypot-processor.service`, and the
  `web-corp` container were restarted/recreated. At final status check, both
  agents were `active` and web-corp was `Up` at `10.58.33.42:80` → container
  port `8080`. Odoo, Deception Core, Redis, and other containers were not
  restarted by this rollout.
- One synthetic `POST /web/login` returned the decoy's HTTP 200 failed-login
  response. The normalized result was `rejected`; the SQLi classifier recorded
  heuristic indicator names only. No input was executed or sent to Odoo or
  PostgreSQL.
- The latest `raw:web-login` entry had the expected event type, source address,
  result, and SQLi indicator names. The check confirmed a password field exists
  without printing its value. The matching `event:canonical` entry retained
  the event context and indicator names while omitting the password field.
- The host spool directory was mode `0700` (`root:root`) and its pending
  directory was empty after collection. `XPENDING raw:web-login processor`
  returned zero. The processor logs its successful enrichment only after the
  MongoDB upsert and canonical Redis write return successfully; MongoDB itself
  was not separately queried during this validation.

## Scope limitations and follow-up

- The request was generated on the Pi and addressed to its own ZeroTier IP;
  the host route resolved locally. No second ZeroTier peer was used, so remote
  overlay reachability is not independently confirmed here.
- MongoDB durability is inferred from the running processor's code path,
  enabled Mongo writer, successful processing log, and raw-stream
  acknowledgement. A direct authorized query should be used for an independent
  database verification.
- This deployment did not verify MongoDB Atlas roles, encryption-at-rest,
  backup expiry, or TTL deletion timing.
- Brute-force attempts are captured for later analysis, but no threshold,
  sliding window, lockout, or derived brute-force finding is implemented.
- Historical credential-bearing Core records created before cutover remain
  untouched and are not migrated.

For current retrieval commands and credential-handling cautions, see the
[web-corp data access guide](../../integrations/web-corp/DATA-ACCESS.md). The
intended system boundaries are in the
[web-login telemetry design](../design/web-login-telemetry.md).

## Follow-up validation after the user login test

A later read-only check traced the user's login by request ID without printing
credential values:

- The raw Redis event was `web_login_attempt`, had result `rejected`, and
  contained all five bounded form keys. No SQLi indicators were recorded for
  this attempt.
- The matching `event:canonical` event existed and omitted the password field.
- A direct read-only lookup of the matching Mongo document in
  `honeypot_db.events` found `source=web-corp` and
  `event_type=web_login_attempt`. The query projected no credential values and
  checked only whether the password/username fields exist; both were present.
- The pending spool was empty, Redis consumer pending count was zero, and the
  raw stream contained two events at that check. The source address differed
  from the sensor address, but the event alone does not prove which client
  interface/path was used.
- The optional `remember` value was empty in the raw event and omitted from
  normalized Mongo/canonical output by the current empty-string compaction.
  This behavior is now documented as a schema-fidelity limitation.

This follow-up supersedes the earlier statement above that MongoDB had not
been independently queried; that statement remains accurate for the original
deployment validation only. No event values were added to this report.
