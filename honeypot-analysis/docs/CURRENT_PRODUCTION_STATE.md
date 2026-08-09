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

The 2026-08-10 read-only probe verified hostname `capstone`, Tailscale IPv4
`100.85.50.74`, `/opt/honeypot` resolving to the release shown above, and an
exactly matching `DEPLOYED_COMMIT`. Service health, current disk capacity,
backup availability, Raspberry Pi state, and database integrity were not
re-probed for this SSH/reference-only update and are
`NOT_DETERMINABLE_FROM_THIS_REFERENCE_UPDATE`.
