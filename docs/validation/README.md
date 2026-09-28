# Validation evidence

- [2026-09-28 Azure ARM64 Cowrie/Zeek staging](2026-09-28-azure-arm64-cowrie-zeek-staging.md) — pinned dependency staging, loopback listener correction, interrupted-run recovery, and inactive final state.
- [2026-09-28 existing Pi Zeek endpoint filter](2026-09-28-zeek-decoy-endpoint-filter.md) — bounded decoy-port capture and management-port exclusion after restart/reload.

This directory stores concise, reproducible evidence for staging work. Do not
store raw attacker sessions, secrets, malware, full databases, or generated
logs here.

Each evidence note uses this outline:

```md
---
title: <test or staging milestone>
date: YYYY-MM-DD
environment: staging|loopback|synthetic
commit: <commit or uncommitted-worktree note>
status: passed|failed|partial
---

## Objective
## Procedure
## Expected result
## Observed result
## Metrics
## Limitations
## Follow-up
```

An evidence note proves only the stated environment and conditions. Production
approval remains an explicit operational decision.

## Evidence notes

- [Azure ARM64 installer first run — 2026-09-28](2026-09-28-azure-arm64-installer-first-run.md): reviewed Go release preparation, private env skeletons, missing-value pause, and unchanged-file retry on a disposable VM.
- [Session guidance projection closeout — 2026-09-27](2026-09-27-session-guidance-projection-closeout.md): production API text-completeness check, bounded policy projection, and the remaining Model2 API discrepancy.
- [Web-corp login pipeline — 2026-09-24](2026-09-24-web-login-pipeline.md): synthetic deployed event verified in raw/redacted Redis paths; pending spool drained and processor acknowledged it after MongoDB write.
- [Web-corp HTTPS listener — 2026-09-24](2026-09-24-web-corp-https.md): HTTP/HTTPS page parity, TLS 1.3, overlay-only bindings, scheme/port unit coverage, and deployment limitations.
- [Web-login-only scope and service posture — 2026-09-25](2026-09-25-web-login-scope.md): login-only telemetry test, HTTP `:80` deployment, and stopped web-only containers.
- [Odoo/PostgreSQL data inventory — 2026-09-24](2026-09-24-odoo-postgres-data-inventory.md): read-only schema/row-count snapshot and attachment/filestore consistency check.
