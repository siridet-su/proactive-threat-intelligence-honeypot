---
title: Reimaged Azure ARM64 fresh stack activation
date: 2026-09-29
environment: staging
commit: 2341488
status: passed-bounded
---

## Objective

Complete the fresh installer on the reimaged Ubuntu ARM64 VM after the
operator placed private test credentials, and verify the localhost Web-corp,
Cowrie, Zeek, collector, Redis, processor, and MongoDB data paths.

## Procedure

1. Ran the redacting Pi and decoy env checkers without printing private
   values. Used the same reviewed release, bundles, one-host inventory, and
   installer command as in the [preparation record](2026-09-29-azure-arm64-fresh-installer.md).
2. The first activation exposed a missing `NETWORK_SAMPLE_SECONDS` for the
   hardware agent. Fixed the example, filler, and env gate in `1e3f390`, then
   pulled and reran the same installer. The Go rollback had left newly started
   Go units and Redis stopped after the failed attempt.
3. After all core services started, the collector reported that it could not
   traverse the Web-corp login spool. Applied the host-generated non-root
   Web-corp Compose override in `25f1fc6` and reran the same installer.
4. Sent one synthetic login through localhost Web-corp. Checked its HTTP
   response, pending-file removal, Redis stream count, and a count-only MongoDB
   query for its unique synthetic username. No submitted values were printed.
5. Sent bounded loopback SSH banner exchanges to Cowrie. Cowrie logged them,
   but the collector initially could not traverse its log directory; Zeek
   initially wrote ASCII logs. Applied group traversal and Zeek JSON policy
   fixes in `2341488`, then reran the same installer and repeated the exchange.
6. Queried only counts of canonical VM-sensor records by source in the
   operator-configured MongoDB destination. Checked final systemd/container
   states, loopback listeners, and recent error counts.

## Expected result

The fresh stack starts without moving administrator SSH. Web-corp login and
Cowrie/Zeek events reach MongoDB; the Web-corp retry spool drains. B2 backup
stays inactive until a separate owner opt-in.

## Observed result

The final installer run returned `ACTIVE`. Cowrie, Zeek, Redis, the four core
Go units, Docker, PostgreSQL, Deception Core, and Web-corp were active.
Web-corp returned HTTP 200. Its test login drained from the spool into Redis,
and one matching canonical MongoDB event was found. A later Cowrie connection
produced JSON log entries; Cowrie and Zeek connection streams received events,
and count-only MongoDB queries found VM-sensor canonical events from both
sources. The collector could read the Cowrie log and the Web-corp spool.

## Metrics

- Redis after the bounded connection test: `raw:cowrie` length 6 and
  `raw:zeek:conn` length 1.
- MongoDB count-only query scoped to the VM sensor: 6 Cowrie and 1 Zeek
  canonical events; the unique synthetic Web-corp login matched 1 event.
- Final recent five-minute journal check: zero permission-denied, invalid-JSON,
  or MongoDB error messages in the checked Go units.
- Host binds: Cowrie TCP 2222/2223 and Web-corp/Core/PostgreSQL/Redis on
  loopback; administrator SSH remained on TCP 22.
- B2 backup control unit inactive and disabled. Root filesystem about 17% used.

## Limitations

This was a local ARM64 VM with Zeek capture on `lo`; it did not validate Pi
Wi-Fi hardware, external traffic exposure, Dashboard login, or restart after
reboot. MongoDB record counts prove these synthetic writes in the
operator-configured destination, but no broader data quality or retention
audit was performed. B2 upload and restore were not tested. Synthetic records
were left in that destination for audit; no raw payload or credential was
copied into this repository.

## Follow-up

Run a separate clean physical Pi acceptance test using `wlan0`, then verify
service restart, capture filter, and event persistence. Keep backup disabled
until a new owner-controlled write destination passes upload and restore.
