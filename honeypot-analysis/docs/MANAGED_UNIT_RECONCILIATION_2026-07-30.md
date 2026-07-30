# Managed systemd unit reconciliation

This record was captured read-only on 2026-07-30 before stabilization
deployment. It distinguishes units controlled by this repository from retained
Pi services that have separate ownership.

## GCP finding

The reviewed backend set is the ten enabled units in the `gcp_backend` profile
of `deployment/systemd/managed_units.v1.json`: eight continuously running
services and two active timers. The corresponding feed-refresh and
session-count oneshot services are installed static units.

One unknown enabled timer was present:

- `honeypot-prediction-backtest.timer`, enabled and active, next scheduled for
  `2026-08-03T00:00:00Z`, last triggered `2026-07-27T00:00:05Z`;
- timer file: 178 bytes, root:root mode 0644,
  SHA-256 `f0a5dc48eafc3e2b346ef963372e382a992d2bb430ebb201455e78b7a149ecd7`;
- service file: 452 bytes, root:root mode 0644,
  SHA-256 `9bcf823fce12c2f83e07aadfeef0bb20486770a75f94918ca576ce1d3b777d99`;
- the service invokes the removed active path
  `production.prediction.prediction_backtest --include-cases --save`, which can
  write prediction backtest rows.

Calibration and prediction-retention units were absent. The disabled
`honeypot-sensor-forwarder.service` template was installed on GCP but was not
enabled or active and is not part of the backend managed set.

The backtest pair is confirmed obsolete. It must be archived only after the
deployment backup/capacity gate passes. The reviewed command is:

```bash
sudo /opt/honeypot/deployment/systemd/reconcile-obsolete-units.sh archive \
  /var/backups/honeypot/systemd-units/STABILIZATION_DEPLOYMENT_UTC
```

The destination must not exist. The reconciler records before/after properties,
copies both exact files with owner-only permissions, writes SHA-256 checksums,
disables the timer, removes only the two exact unit paths, and reloads systemd.
Its `restore-files` mode verifies and restores the archived files without
re-enabling the obsolete writer.

## Pi boundary

The repository-managed Pi unit was
`honeypot-sensor-forwarder.service`; it was enabled, active and hardened with
`UMask=0077`, `NoNewPrivileges=yes`, `PrivateTmp=yes`,
`ProtectSystem=full`, and
`ReadWritePaths=/var/lib/honeypot-forwarder`. `cowrie.service` was the required
active external dependency.

The following enabled Pi units were inventoried but remain externally managed
and unchanged:

- `honeypot-collector.service`
- `honeypot-disk-monitor.timer`
- `honeypot-hardware.service`
- `honeypot-local-firewall.service`
- `honeypot-processor.service`

They are enumerated as allowed external units in the Pi profile so any new
enabled `honeypot-*` unit still fails validation. Their presence does not grant
this deployment permission to alter them.

## Fail-closed release boundary

Release-manifest schema v5 requires the managed-unit policy path and exact
SHA-256. A release cannot be built without it. After installation,
`production.tools.managed_systemd_units` fails on:

- a missing managed unit;
- a required unit that is disabled or inactive;
- an unknown enabled unit in the selected profile;
- any installed or active prohibited calibration, backtest, or retention unit.

The policy SHA-256 at the time of this record is
`069abe87e1b249ab9e5c5a62391eeaccce584f817becd90873e8a2a439f92644`.
The release manifest will record the final committed policy hash again.
