# Current production state (repository-recorded)

This file is a last-known-state index, not a live probe. It must be read with
the machine-readable receipt and the final activation narrative; no local
cleanup operation contacts GCP or the Raspberry Pi.

## Last verified records in this checkout

| Boundary | Recorded value |
| --- | --- |
| Repository revision | `3c79ae155021ca4cf0ab6d744211d884c4ee039e` |
| GCP active revision | `3c79ae155021ca4cf0ab6d744211d884c4ee039e` |
| GCP recovery revision | `19afabd0bb7ed82ac93767301bb0cb1024d0b92e` |
| Accepted Pi release | `5bb3b97fbe3b9034c70fc6ca2aba0ad9d159bb02` (recorded unchanged) |
| GCP package / manifest / tree | `c30c4984…` / `c92e4a9…` / `de42745…` |
| Guard state | `ACTIVATION_COMPLETED` |
| Backup | `/var/backups/honeypot/cowrie-connectivity-20260801T231500Z/production_pilot.db` |
| Backup checks | schema 3, quick check `ok`, integrity check `ok`, isolated restore verified |
| Public route | intended TCP/2222 via `allow-cowrie-relay-2222` and HAProxy PROXY protocol |
| Observation | 30/30 healthy samples; zero failed units; SQLite quick check `ok` |

The full values and hashes are in
`evaluation/next_tactic_final_production_activation_20260802.json`.

## Authority and safety state

The recorded final sessions passed v4, v3, STIX, and artifact-integrity
validation; prediction snapshots had no recommendations, predictive alerts were
prohibited, no new alerts/webhooks were produced, and new credential-marker
count was zero. Guidance retained manual approval, automatic execution false,
and no response/alert side effects. Historical v1/v2/v3 records remain
readable and unchanged.

## What this checkout cannot prove

The live GCP marker, current service processes, current disk free space, current
Pi files, and current backup availability are
`NOT_DETERMINABLE_FROM_CURRENT_REPOSITORY`. Re-verify them through the approved
read-only/guarded operational procedure before any future deployment.
