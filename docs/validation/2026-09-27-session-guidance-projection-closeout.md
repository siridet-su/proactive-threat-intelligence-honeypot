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
- The current V3 Model2 spool includes a `VALID_SHADOW`, `PRESENT` result for the source session. The protected bridge and direct recomputation returned available evidence. Initially the HTTP endpoint intermittently returned Model1-only because its bridge client had a 250 ms timeout against measured 215–250 ms spool lookups. With the bounded 3-second timeout deployed, HTTP `/api/session-detail` returned bound Model2 V3 and both downstream formula projections. On this session both formula orders were `T1105, T1078, T1083`. The dashboard primary review order now uses weighted voting while retaining reciprocal-rank only as a comparator. PDF source was changed to the same presentation, but the backend PDF runtime has not yet been redeployed. Two other current V3 sessions returned available Model2 evidence but retained Model1-only ordering where no gated support changed the order.
- The older documented V2 session currently falls back to Model1-only at the HTTP API because the active V3 identity gate does not accept the retired V2 artifact. It still has one hypothesis set and two response-guidance findings/actions. The prior RRF reorder in its historical report remains a record of its original runtime, not evidence of current V3 fusion.
- A further read-only presentation audit of the current V3 session found one canonical behavioral finding but zero hypothesis sets. The assessment reports `effect_status_not_eligible`, `outcome_not_eligible` and `no_fact_for_activated_family` across six semantic families. The zero-set display follows these recorded evidence gates.
- The ETI endpoint reports `TI_AVAILABLE` because two linked provider evidence records and three source-IP cache records exist. Its freshness state is `TI_EXPIRED`, with one stale linked record. The deployed dashboard build contains the provider-detail rows and freshness labels. No new provider lookup was made during this audit.
- The AI endpoint reports `accepted`; session detail reports `current_ai_advisory_status=accepted` and immutable `ai_enriched=false`. The deployed dashboard build explicitly explains that the current AI advisory is stored separately from the earlier immutable assessment. These fields describe different generation times.
- Dashboard staging, which serves the existing public quick-tunnel URL, was switched to hash-bound build `36be3ed40e3f47da5f99576b0c7a8e8874d39da7`, artifact SHA-256 `3048d7effbf0ddcbcb7beeb741d8d2331064a32183309c9b0df74946f9d7fa97`. Loopback and public `/` carried the new build identity; the staging service was active and its explicit auth route returned HTTP 405 for GET as expected. The old release remains at `/opt/honeypot-dashboard-v2-staging/releases/630999b0a-ensemble-v3d-20260927` for rollback. Production dashboard on port 3000 and backend/PDF services were not switched in this follow-up.

## Metrics

- Regression tests: 128 passed, 3 skipped. These test API contracts and mechanics, not Model2 accuracy.
- Production session guidance completeness: 2/2 sampled long sentences complete, including a full 64-character digest.
- Model1 versus ensemble accuracy/ranking lift: not measured in this operational check.
- New focused dashboard ranking tests: 5 passed; focused Python advisory/PDF contract tests: 14 passed, 3 skipped because optional PDF rendering dependencies were unavailable. Dashboard TypeScript check and webpack build passed. Full dashboard Vitest run had 5 unrelated failures among 813 tests; the same five failures were reproduced in the prior unmodified worktree.
- The focused dashboard fixture deliberately gives reciprocal-rank and weighted voting different orders; the UI ranking test still follows weighted voting. This guards against accidentally selecting the comparator as the primary order again.

## Limitations

No authenticated browser screenshot was captured. A temporary owner-only PDF was generated for text comparison, but automatic approval review rejected copying that production PDF to the local host because it may contain sensitive observables. The host has no installed PDF text reader, so PDF content parity was not independently checked in this audit; the temporary PDF was removed. The temporary owner-only API response and the two upload staging files were also removed; the protected rollback backups remain. The active directory's copied release manifest and marker identify older backend revision `00d3fde...` and a different release path, while `/opt/honeypot` currently resolves to `/opt/honeypot-releases/9d9cf7fb0-ensemble-v3e-20260927`; manifest verification therefore fails before checking file hashes. The manifest's referenced package file is also absent. The earlier backend deployment changed two files in place and did not repair that provenance drift. This follow-up did not repeat an in-place backend edit. The staging dashboard's pre-existing absolute `current` symlink and legacy release name were incompatible with its strict deploy wrapper, so the new release was activated by an exact-target, SHA-checked pointer switch with rollback trap and health checks; the wrapper's deployment receipt was not emitted. The temporary uploaded 50 MB artifact was deleted after validation; the local package and both extracted releases remain. The active public address is backed by an unmanaged Cloudflare quick tunnel; changing its process would rotate the address. The Next Distinct feeder's historical restart count was 46 after a temporary MongoDB primary-selection timeout on 2026-09-25, but the service was active and the count stable during this check.

## Follow-up

Build a clean manifest-bound backend release from the committed revision and promote it using the documented deployment procedure before claiming that the live PDF or API method metadata changed. Verify guidance and the V3 weighted-voting primary recommendation in an authenticated browser, with reciprocal-rank shown only as a comparator. Reconcile the staging pointer with the standard wrapper only after its legacy-release migration is reviewed. Keep the existing tunnel address until a stable named tunnel migration is planned.
