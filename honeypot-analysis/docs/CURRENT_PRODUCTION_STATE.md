# Current production state (repository-recorded)

This file identifies the canonical operational target. It is not a substitute
for release manifests, owner-only migration receipts, or live health checks.
The values below were re-read from the local repository and from a read-only
SSH probe on 2026-08-10.

## Active production target

| Boundary | Recorded value |
| --- | --- |
| VM name / hostname | `capstone` |
| Public management address | `34.142.229.209` |
| Private application address | `100.85.50.74` (Tailscale IPv4) |
| Production ingest endpoint | `http://100.85.50.74:8080/events` |
| SSH alias | `honeypot-gcp` |
| SSH user | `siridet_s_dev` |
| SSH identity | `/home/rubchek/.ssh/honeypot_gcp_ed25519` |
| Repository revision | `c3bd2456e6e4693f669c9e48385a62242209afbc` |
| Active release | `c3bd2456e6e4693f669c9e48385a62242209afbc` |
| Active release link | `/opt/honeypot-releases/c3bd2456e6e4693f669c9e48385a62242209afbc` |

The canonical management command is:

```bash
ssh -i /home/rubchek/.ssh/honeypot_gcp_ed25519 \
  -o IdentitiesOnly=yes \
  siridet_s_dev@34.142.229.209
```

The local operator alias `honeypot-gcp` resolves to that identity. Deployment,
validation, monitoring, database, backup, and service-management work must use
capstone unless a change request explicitly invokes a rollback procedure.

## Preserved rollback/reference VM

The host at Tailscale IPv4 `100.122.213.37` is retained only as a rollback and
historical reference VM. It is not the active deployment, management,
validation, monitoring, database, or default SSH target. The local alias
`honeypot-gcp-old` makes that exceptional role explicit. Do not modify or
decommission it without a separately approved procedure.

The earlier activation receipt
`evaluation/next_tactic_final_production_activation_20260802.json` and the
connectivity receipt
`evaluation/cowrie_public_connectivity_root_cause_20260802.json` remain
immutable historical evidence. Their old addresses and revisions must not be
interpreted as the current operational target.

## Authority and safety state

The VM migration did not change analytical authority. Cowrie evidence and the
canonical evidence snapshot remain authoritative. Predictions and enrichment
remain non-authoritative; `session_assessment.v4` and
`response_guidance.v3` retain their existing contracts; guidance remains
manual-only and non-executable. Hybrid AI advisory remains disabled unless a
separate reviewed activation explicitly enables it.

## Verification boundary

The 2026-08-10 verification confirmed hostname `capstone`, Tailscale IPv4
`100.85.50.74`, `/opt/honeypot` resolving to the release shown above, and an
exactly matching `DEPLOYED_COMMIT`. The eight managed application daemons are
active and enabled under `multi-user.target`; enabling them did not restart the
running processes. Both managed timers are active/enabled, and the repository
managed-unit validator reports `status=valid` for `gcp_backend`.

The same maintenance pass confirmed healthy ingest/dashboard/monitor liveness
responses and left application configuration, SQLite, models, and services
otherwise unchanged. A later read-only pre-activation audit found dashboard
readiness exceeding 15 seconds because the deployed handler repeats SQLite
schema initialization. The repository candidate contains a read-only readiness
fix, but it has not been deployed and no production service was restarted.

Immediately before the approved backup cleanup, the root filesystem was
105,427,566,592 bytes total, 89,255,714,816 bytes used, and 11,759,644,672
bytes available. `/var/backups/honeypot` accounted for 74,753,236,992 bytes.
Only the three superseded full database/WAL/SHM payload sets from the failed
2026-08-09 16:22 cutover were removed; their manifests and diagnostic receipts
were retained. The successful 17:36 incoming/final/pre-promotion rollback chain
was retained and its three database hashes were reverified against the
migration receipts. The latest final backup also passed a fresh read-only
`quick_check`.

After `sync`, `/var/backups/honeypot` was 55,931,482,112 bytes and the root
filesystem had 30,578,216,960 bytes available (28.48 GiB). The cleanup reclaimed
18,821,754,880 bytes (17.53 GiB) from the backup directory and met the 25 GiB
minimum, but not the preferred 30 GiB target. The retained final backup predates
subsequent live writes, so a separately authorized fresh current-state backup
is still required before deployment. No live database/WAL/SHM, release,
runtime/model evidence, application service, or production configuration was
changed.

The Pi was audited read-only. The canonical sanitized sensor forwarder is
active/enabled, but the legacy Redis collector and hardware agents are also
active/enabled. The legacy processor is enabled and repeatedly failing with
automatic restarts; Redis is loopback-only and active, while no local
`mongod.service` is installed. Those services were not stopped or changed.
Their ownership and data-retention purpose must be resolved before any legacy
path is retired or any MongoDB environment is reused.
