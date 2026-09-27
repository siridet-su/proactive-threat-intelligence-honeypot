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

The compact API should retain full finding/action sentences and a complete artifact digest. Model2 and both experimental downstream ranking projections should reflect the exact current binding when a valid result exists. Weighted voting is the primary review order; reciprocal-rank is retained only for comparison.

## Observed result

- Guidance: two findings and two actions. The first finding is 200 characters and the first action is 170 characters; both contain a complete 64-character SHA-256 and end as full sentences. `requires_manual_approval=true`; `safe_to_auto_execute=false`.
- Monitor API `/health`: HTTP 200 after startup warm-up. PDF: HTTP 200, `application/pdf`. Dashboard `/login`: HTTP 200 on loopback and at the existing public tunnel URL; unauthenticated protected detail: HTTP 307.
- The same session's ETI endpoint reported `TI_AVAILABLE`; the AI endpoint reported `accepted`; the session detail enrichment projection reported `completed` while the stored legacy status remained `queued`. These are current versus stored projections, not one shared status field.
- The current V3 Model2 spool includes a `VALID_SHADOW`, `PRESENT` result for the source session. The protected bridge and direct recomputation returned available evidence. Initially the HTTP endpoint intermittently returned Model1-only because its bridge client had a 250 ms timeout against measured 215–250 ms spool lookups. With the bounded 3-second timeout deployed, HTTP `/api/session-detail` returned bound Model2 V3 and both downstream formula projections; T1105 was first in the then-displayed reciprocal-rank order. This follow-up changes the dashboard and PDF primary review order to weighted voting while retaining reciprocal-rank only as a comparator. Two other current V3 sessions returned available Model2 evidence but retained Model1-only ordering where no gated support changed the order.
- The older documented V2 session currently falls back to Model1-only at the HTTP API because the active V3 identity gate does not accept the retired V2 artifact. It still has one hypothesis set and two response-guidance findings/actions. The prior RRF reorder in its historical report remains a record of its original runtime, not evidence of current V3 fusion.
- A further read-only presentation audit of the current V3 session found one canonical behavioral finding but zero hypothesis sets. The assessment reports `effect_status_not_eligible`, `outcome_not_eligible` and `no_fact_for_activated_family` across six semantic families. The zero-set display follows these recorded evidence gates.
- The ETI endpoint reports `TI_AVAILABLE` because two linked provider evidence records and three source-IP cache records exist. Its freshness state is `TI_EXPIRED`, with one stale linked record. The deployed dashboard build contains the provider-detail rows and freshness labels. No new provider lookup was made during this audit.
- The AI endpoint reports `accepted`; session detail reports `current_ai_advisory_status=accepted` and immutable `ai_enriched=false`. The deployed dashboard build explicitly explains that the current AI advisory is stored separately from the earlier immutable assessment. These fields describe different generation times.

## Metrics

- Regression tests: 128 passed, 3 skipped. These test API contracts and mechanics, not Model2 accuracy.
- Production session guidance completeness: 2/2 sampled long sentences complete, including a full 64-character digest.
- Model1 versus ensemble accuracy/ranking lift: not measured in this operational check.

## Limitations

No authenticated browser screenshot was captured. A temporary owner-only PDF was generated for text comparison, but automatic approval review rejected copying that production PDF to the local host because it may contain sensitive observables. The host has no installed PDF text reader, so PDF content parity was not independently checked in this audit; the temporary PDF was removed. The temporary owner-only API response and the two upload staging files were also removed; the protected rollback backups remain. The active directory's copied release manifest and marker already identify an older backend revision and a different release path; read-only manifest verification therefore fails before checking file hashes. This deployment changed two files in place and does not repair that pre-existing provenance drift. The active public address is backed by an unmanaged Cloudflare quick tunnel; changing its process would rotate the address. The Next Distinct feeder's historical restart count was 46 after a temporary MongoDB primary-selection timeout on 2026-09-25, but the service was active and the count stable during this check.

## Follow-up

Build a clean manifest-bound backend release from the committed revision and promote it using the documented deployment procedure. Verify guidance and the V3 weighted-voting primary recommendation in an authenticated browser, with reciprocal-rank shown only as a comparator. Keep the existing tunnel address until a stable named tunnel migration is planned.
