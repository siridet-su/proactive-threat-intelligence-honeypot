---
title: Session guidance projection closeout
date: 2026-09-27
environment: production
commit: fix/session-display-operational-closeout-20260927
status: partial
---

## Objective

Verify that compact session detail preserves full policy-authored response guidance while retaining bounded public output. Check associated session services without treating operational smoke checks as model accuracy.

## Procedure

1. Fetched remote branch tips and used an isolated clean worktree based on `origin/release/model2-54f-rrf-closeout-20260926` (`9d9cf7fb0`). The main `staging` worktree was left untouched.
2. Confirmed the deployed backend files matched the release version by SHA-256. Installed the tested `security.py` projection change and a bounded Model2 bridge timeout change in `evidence.py`, compiled them and restarted `honeypot-monitor-web`.
3. Queried the existing canonical session `session_v1_7266073c2cd2f8b7a88ee040ff6e208b` through the loopback session detail API. Checked only lengths, SHA-256 completeness and terminal wording; no command text, credential or provider payload was copied into this note.
4. Checked the PDF, dashboard login and protected detail routes, ETI/AI status, Model2 bridge status and one historical session with a hypothesis. Repeated the current V3 session detail check after the bridge timeout change.

## Expected result

The compact API should retain full finding/action sentences and a complete artifact digest. Model2 and RRF should reflect the exact current binding when a valid result exists.

## Observed result

- Guidance: two findings and two actions. The first finding is 200 characters and the first action is 170 characters; both contain a complete 64-character SHA-256 and end as full sentences. `requires_manual_approval=true`; `safe_to_auto_execute=false`.
- Monitor API `/health`: HTTP 200 after startup warm-up. PDF: HTTP 200, `application/pdf`. Dashboard `/login`: HTTP 200 on loopback and at the existing public tunnel URL; unauthenticated protected detail: HTTP 307.
- The same session's ETI endpoint reported `TI_AVAILABLE`; the AI endpoint reported `accepted`; the session detail enrichment projection reported `completed` while the stored legacy status remained `queued`. These are current versus stored projections, not one shared status field.
- The current V3 Model2 spool includes a `VALID_SHADOW`, `PRESENT` result for the source session. The protected bridge and direct recomputation returned available evidence. Initially the HTTP endpoint intermittently returned Model1-only because its bridge client had a 250 ms timeout against measured 215–250 ms spool lookups. With the bounded 3-second timeout deployed, HTTP `/api/session-detail` returned bound Model2 V3 and `EXPERIMENTAL_RRF`; T1105 moved to first review priority. Two other current V3 sessions returned available Model2 evidence but retained Model1-only ordering where no gated support changed the order.
- The older documented V2 session currently falls back to Model1-only at the HTTP API because the active V3 identity gate does not accept the retired V2 artifact. It still has one hypothesis set and two response-guidance findings/actions. The prior RRF reorder in its historical report remains a record of its original runtime, not evidence of current V3 fusion.

## Metrics

- Regression tests: 128 passed, 3 skipped. These test API contracts and mechanics, not Model2 accuracy.
- Production session guidance completeness: 2/2 sampled long sentences complete, including a full 64-character digest.
- Model1 versus ensemble accuracy/ranking lift: not measured in this operational check.

## Limitations

No authenticated browser screenshot was captured. The temporary owner-only API response and the two upload staging files were removed after validation; the protected rollback backups remain. The active directory's copied release manifest and marker already identify an older backend revision and a different release path; read-only manifest verification therefore fails before checking file hashes. This deployment changed two files in place and does not repair that pre-existing provenance drift. The active public address is backed by an unmanaged Cloudflare quick tunnel; changing its process would rotate the address. The Next Distinct feeder's historical restart count was 46 after a temporary MongoDB primary-selection timeout on 2026-09-25, but the service was active and the count stable during this check.

## Follow-up

Build a clean manifest-bound backend release from the committed revision and promote it using the documented deployment procedure. Verify guidance and the V3 RRF recommendation in an authenticated browser. Keep the existing tunnel address until a stable named tunnel migration is planned.
