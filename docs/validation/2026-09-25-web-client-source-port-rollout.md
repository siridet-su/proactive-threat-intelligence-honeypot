---
title: Web-corp client source-port rollout
date: 2026-09-25
environment: Raspberry Pi development honeypot
commit: 60125598
status: deployed; live login-event verification pending
---

# Web-corp client source-port rollout

## Objective

Deploy the optional client TCP source-port field through the existing
web-corp → spool/Redis → processor → MongoDB path after a login record from
05:29 local time showed `network.src_port` was absent.

## Diagnosis

- The running web-corp image was created at 03:03 local time, before commit
  `60125598`; its `/app/main.py` did not contain `_client_port` or emit
  `source_port`.
- `honeypot-collector.service` and `honeypot-processor.service` had started at
  02:14 and 02:15, before the updated binaries existed.
- A Git push does not rebuild or restart these deployed components. The
  missing field was therefore absent upstream, not rejected by a MongoDB
  schema. Existing records cannot be backfilled because the port was not
  captured by the producer.

## Deployment and validation

- `docker compose -f ../decoy-honeypot/docker-compose.yml config --quiet`
  passed.
- Collector and processor `go test ./...` passed. New binaries were built from
  the reviewed source and the old binaries were copied to
  `/tmp/web-source-port-rollout.ycLTz2/` for rollback.
- Rebuilt only the `web-corp` image. The isolated, network-disabled container
  test run passed all 14 Web-corp tests, including direct and trusted-proxy
  source-port cases. The image contains `_client_port` and emits `source_port`.
- Atomically replaced the collector and processor executables. Restarted only
  `honeypot-processor.service` and `honeypot-collector.service`; both are
  `active` (processor entered active at 12:53:46 ICT, collector at 12:54:10
  ICT).
- Recreated only `web-corp` with `--no-deps --force-recreate`. It is running
  image `sha256:90cc6ac2722dade246b81ca7f0ded8be15dce5c2e911848bf51c2e37c8a0b4b0`
  and started at 12:55:06 ICT.
- A non-telemetry `GET /web/login` to `10.58.33.42:80` returned HTTP 200.
- HTTPS, Odoo, Deception Core, PostgreSQL, Cowrie, and unrelated services were
  not restarted. No database migration was made.

## Limitations and follow-up

- No live login POST was submitted during this rollout, so no synthetic
  credential event was written to the spool, Redis, or MongoDB. End-to-end
  persistence of `network.src_port` remains to be confirmed on the next
  authorized login attempt.
- Verify the next event in `honeypot_db.events` using a projection that returns
  `network.src_port` and excludes submitted credentials. A direct ZeroTier
  request should provide the socket peer port; a trusted proxy must overwrite
  `X-Forwarded-Client-Port` and be configured consistently with the app.
- Preserve the rollback binaries under `/tmp/web-source-port-rollout.ycLTz2/`
  until the next event is confirmed; `/tmp` is not durable across reboot.
