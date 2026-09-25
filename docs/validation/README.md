# Validation evidence

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

- [Web-corp login pipeline — 2026-09-24](2026-09-24-web-login-pipeline.md): synthetic deployed event verified in raw/redacted Redis paths; pending spool drained and processor acknowledged it after MongoDB write.
- [Web-corp HTTPS listener — 2026-09-24](2026-09-24-web-corp-https.md): HTTP/HTTPS page parity, TLS 1.3, overlay-only bindings, scheme/port unit coverage, and deployment limitations.
- [Web-login-only scope and service posture — 2026-09-25](2026-09-25-web-login-scope.md): login-only telemetry test, HTTP `:80` deployment, and stopped web-only containers.
- [Odoo/PostgreSQL data inventory — 2026-09-24](2026-09-24-odoo-postgres-data-inventory.md): read-only schema/row-count snapshot and attachment/filestore consistency check.
