# Stabilization starting evidence — 2026-07-30

This record freezes the read-only state verified before stabilization work.
Commands were run locally and through read-only SSH; no production service,
database, file, unit, network, or release state was changed while collecting it.

## Repository

- HEAD: `ccf0a8db78e0d4d3d6133f642e71d98dc26bb0e1`
- branch: `professor-approved-poc-evaluation`
- worktree: clean
- configured upstream for the branch: none
- deployed revision comparison: 39 commits ahead, 81 files changed,
  21,576 insertions and 235 deletions relative to `bf53edf…`

## GCP release and provenance

- active release:
  `/opt/honeypot-releases/bf53edf640de9f8dbfd8002d91b383e55ceb9187`
- `DEPLOYED_COMMIT`:
  `bf53edf640de9f8dbfd8002d91b383e55ceb9187`
- deployment manifest:
  `/opt/honeypot/DEPLOYMENT_MANIFEST.json`
- manifest SHA-256:
  `d25c459c3f388fedd32048c83115f4af2a6e67beaa65603d5c41846530bd3b5d`
- release-tree SHA-256:
  `bc0e9d6421e91d0112756a7105d38a9d7e309a9ffd525c47344a05a45dafebaf`
- rollback release:
  `/opt/honeypot-releases/7125cd8de64afc1d60cc2920f03eb21e5c8010af`
- frozen model bundle:
  `frozen_model_bundle_4957a700e993c76fd94a95bb569f70b0`
- bundle manifest SHA-256:
  `609ab334bb5c75295eee2851e2b2b6ae103ce8e0dbc6e43219da8bb5221e4419`
- artifact-inventory SHA-256:
  `fb9804a1beb3d62f31bc1fc031a54f031ab3201c062402723b2bf748c80195c7`
- runtime-feed provenance SHA-256:
  `a5c005fa44f92f878621568f38e1e7ccd6e3bdafd3af1b5a120f5ed91736d8e5`
- CISA/Sigma/MITRE receipts were `fresh`; MITRE version was `14.1`.
  All feeds remained `non_authoritative_context_only`.

Effective policy hashes:

| Policy | SHA-256 |
| --- | --- |
| classification | `33f332946c53578f2e609a3a039dda712355b9e209721bcc073c61a623d6342b` |
| threat-hypothesis behavior | `edefc7ee9c85a5fac738f3c763d1b38112c5b33ac1c3670acd62bdcfb22f4269` |
| response guidance | `4d1c5bf249fbbca3229ff7fba89d20cca8855e303ebe41716561c26c7dc7c076` |
| data lifecycle | `5c7d76556310a913879c8a53f509f44d10b823213e0f8189eca32c0fcfa9e7f2` |
| Transformer prediction | `3861d6a6edad4d15e147213cf0c4a5e8fb6c74f2a5f90142526df31492ddd90c` |

## GCP services, timers, listeners, and hardening

The eight application services were active with zero restarts. There were no
failed units. The feed-refresh and session-count timers were active.

An unmanaged `honeypot-prediction-backtest.timer` was enabled and scheduled for
`2026-08-03T00:00:00Z`. Its service invokes the obsolete, database-writing
`production.prediction.prediction_backtest --include-cases --save` entrypoint.

Effective hardening differed from the repository templates:

- ingest, session, enrichment, dashboard, monitor, and threat-hunt used
  `UMask=0022`;
- monitor and threat-hunt had no effective group, `NoNewPrivileges`,
  `PrivateTmp`, `ProtectSystem`, or `ReadWritePaths`;
- analysis and webhook used `UMask=0077` and the expected sandboxing.

Observed listeners:

- `100.122.213.37:8080` ingest;
- `127.0.0.1:8081` dashboard;
- `127.0.0.1:8090` monitor;
- `0.0.0.0:2222` HAProxy Cowrie relay;
- `0.0.0.0:22` administrative SSH;
- loopback SMTP and system resolver listeners.

Host nftables returned no GCP application firewall rules. Cloud firewall state
was not determined from the VM.

## SQLite and operational state

- database: `/var/lib/honeypot/production_pilot.db`
- database bytes: `3,930,820,608`
- WAL bytes: `477,952`
- SHM bytes: `32,768`
- `PRAGMA journal_mode`: `wal`
- `PRAGMA quick_check`: `ok`
- `PRAGMA integrity_check`: `ok`
- schema migrations: versions 1–3 with matching checksums

| Entity | Count |
| --- | ---: |
| events | 49,571 |
| sessions | 7,435 |
| reports / successful analysis jobs | 6,936 |
| prediction snapshots | 21,790 |
| completed prediction outbox | 33 |
| enrichment jobs | 190: 187 succeeded, 3 failed |
| threat-hunt jobs | 13,847 succeeded |
| alerts | 31,611 |
| webhook deliveries | 0 |
| campaigns / memberships | 68 / 7,051 |
| session links | 1,209,687 |

There were zero unprocessed events. Five sessions remained active with last
updates between `2026-05-31` and `2026-07-06`; two are named calibration/smoke
sessions and three have Cowrie-style IDs. Their evidence was not altered.

## Capacity and backups

- root disk: `/dev/sda`, 80 GiB;
- root partition/filesystem: `/dev/sda1`, ext4;
- available bytes: `10,851,819,520` (87% used);
- backups: about 15 GiB;
- retained releases: about 8.3 GiB;
- release packages: about 791 MiB;
- frozen model bundles: about 579 MiB;
- reports: about 312 MiB.

Verified backups:

| Backup | Bytes | SHA-256 | Checks |
| --- | ---: | --- | --- |
| `phase8b-20260729T064717Z` | 3,929,804,800 | `c27d172420903418fcb48b142b5d1f78e8afac3dc2daa070c81eccabb5efb69b` | quick/integrity `ok` |
| `phase8c-20260729T083200Z` | 3,930,181,632 | `4ed779f68ff0ff89ae9fa889cf4e277764c65d6966d056366229da07eaa4ceb7` | quick/integrity `ok` |

Both isolated restored copies remain present. A new database-sized backup,
isolated restore, 1 GiB bounded WAL allowance, 1 GiB release staging allowance,
and 10 GiB safety margin require approximately 20 GiB free. The starting host
has a deficit of approximately 9.2 GiB, so the deployment capacity gate is
closed until the disk and filesystem are expanded or another approved
non-destructive backup target is available.

The instance is `honeypot-gcp-test`, zone `asia-southeast1-c`, boot disk device
`honeypot-gcp-test`. Partition and filesystem expansion must be discovered from
the live system and must not assume a device name.

## Raspberry Pi

- host: `ubuntu-pi-server`
- root available bytes: `86,194,991,104`
- Cowrie and `honeypot-sensor-forwarder` were active;
- forwarder used `UMask=0077`, `NoNewPrivileges=true`, `PrivateTmp=true`,
  `ProtectSystem=full`, and
  `ReadWritePaths=/var/lib/honeypot-forwarder`;
- spool contained no data record, only the private lock and offset files;
- Cowrie listened directly on ports 22/23 and on the Tailscale-only PROXY
  endpoint `100.118.43.30:2224`;
- UFW allowed the PROXY endpoint only from GCP `100.122.213.37`.

Pi deployment evidence:

| Item | SHA-256 |
| --- | --- |
| deployment receipt | `866b427f0cba3e7956d6973452dc82c0d0410bcf22d651a12bef414ec92b5449` |
| rollback archive | `c3049e91871b904de932e23c95854cea7e1bee5a5d4b4dd797ef60e7e0074067` |
| deployed sanitizer/forwarder | `ebe4365e2ee045358758ef941e8cd0be018c89d6b204ebf24f7b5b9e7f15905c` |

The Pi also runs unrelated legacy collector/processor/hardware services, Zeek,
Redis, ZeroTier, a MySQL honeypot, and local model services. They were recorded
but not modified because they are outside this stabilization deployment.

## Starting gates

- repository identity: passed;
- release/rollback identity: passed;
- model/policy/feed provenance: passed;
- database integrity: passed;
- Pi receipt and rollback identity: passed;
- production backup/restore capacity: **failed pending non-destructive capacity
  expansion**;
- alert-authority, fallback reconstruction, managed-unit reconciliation,
  independent evaluation, and deployment gates: pending.
