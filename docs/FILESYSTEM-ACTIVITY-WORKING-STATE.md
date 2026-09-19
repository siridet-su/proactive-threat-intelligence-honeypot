---
title: Filesystem Activity live working state
status: active
last_updated: 2026-09-20
owner: Dashboard Filesystem workstream
---

# Filesystem Activity live working state

This document is the tactical source of truth for improving the Dashboard
Filesystem Activity experience. Update it in the same change that completes,
blocks, defers, or materially changes any tracked item.

The architectural contract remains in
[`dashboard-v2/docs/REALTIME_CWD_TRACKING.md`](../dashboard-v2/docs/REALTIME_CWD_TRACKING.md).
The canonical corrective-remediation status and detailed acceptance evidence
remain in [`FILESYSTEM-ACTIVITY-AUDIT-FIXES.md`](FILESYSTEM-ACTIVITY-AUDIT-FIXES.md).
Reproducible test results belong in [`validation/`](validation/).

## Working rules

- Keep exactly one item in **In progress** unless tasks are intentionally being
  executed in parallel.
- Do not mark an item **Done** until its acceptance criteria and relevant tests
  pass.
- Record the commit or validation note in the item's Evidence column.
- Add newly discovered work to the backlog before implementing it.
- If scope or data semantics change, update the canonical design/API document
  in the same change.
- Do not place secrets, private management addresses, raw attacker data, or
  credentials in this document.

## Status legend

| Status | Meaning |
| --- | --- |
| `TODO` | Accepted work that has not started. |
| `IN PROGRESS` | Current implementation or validation focus. |
| `PARTIAL` | Some acceptance scope is complete, but a named corrective item or gate remains outstanding. |
| `BLOCKED` | Cannot progress until the recorded dependency is resolved. |
| `DONE` | Acceptance criteria passed and evidence is recorded. |
| `DEFERRED` | Intentionally outside the current workstream. |

## Current focus

**In progress:** `FA-016` — bound retained Audit directory queries and establish truthful MongoDB execution-plan limits.

**Why now:** FA-001 through FA-015 are accepted DONE. FA-016 is the sole active
remediation focus. FS-007 remains PARTIAL until that large-collection work passes
final audit. The outstanding manual response-agent validation remains recorded
as an unrelated gate.

## Historical baseline

The following is historical baseline evidence, not current repository
validation. It was recorded on 2026-09-15 against the then-unmodified working
tree after commit `78ce21c`.

| Check | Historical result |
| --- | --- |
| Filesystem Vitest suites | Passed: 2 files, 9 tests |
| Filesystem-scoped ESLint | Passed |
| Next.js production build | Passed |
| Working tree after review | Clean |

The baseline passing did not close the findings. Its test count and clean-tree
state must not be read as evidence about the current repository.

## Current remediation state

The original FS rows below retain their historical implementation evidence.
Their corrective acceptance and current validation are cross-referenced to the
canonical audit tracker; the final FA-013 audit evidence is recorded there to
avoid duplicating a large evidence block.

### Now — correctness and truthful UI

| ID | Status | Work | Acceptance criteria | Evidence |
| --- | --- | --- | --- | --- |
| `FS-001` | `DONE` | Replace client-inferred Audit filters with complete per-session audit summaries. | `homeOnly` and path-touch results include active and closed history, do not depend on the selected session's loaded page, and have unit/integration coverage. | Historical implementation evidence: server `auditSummary` contract and 15 focused tests. Corrected and accepted by `FA-001` (`d4b96d5`), with final acceptance recorded in the canonical audit tracker. |
| `FS-002` | `DONE` | Make history completeness explicit. | API returns total/completeness metadata; Replay never claims to show all history while earlier pages remain unloaded; hop numbering stays stable as pages load. | Historical implementation evidence: API completeness contract and 18 focused tests. Corrected and accepted by `FA-010` commit chain; final guarded MongoDB validation is recorded in the canonical audit tracker. |
| `FS-003` | `DONE` | Decouple Response and Command tabs from CWD-history state. | An authorized operator can inspect response capability and disconnect any eligible live session even when route history is empty, loading, or unavailable. | Historical implementation evidence: independent sidebar gating and 29-test suite; no FA corrective item mapped to FS-003. |
| `FS-004` | `DONE` | Expose topology render limits. | UI shows rendered versus available sources/paths and offers a clear way to focus or expand omitted data; no limit is silent. | Historical implementation evidence: render-limit indicators and 37 tests; no FA corrective item mapped to FS-004. |
| `FS-005` | `DONE` | Resolve filtered-selection semantics. | A `0/N` result cannot look like a matching topology; either clear the selection into a filter empty state or label the retained item prominently as pinned outside the result set. | Historical implementation evidence: pinned-outside-filter and `0/N` states. Corrected and accepted by `FA-001` (`d4b96d5`); final acceptance is in the canonical audit tracker. |
| `FS-006` | `DONE` | Synchronize Audit navigation state with the URL. | View, session, filters, and selected hop survive reload/share; Back and Forward restore coherent state; expired session links show a specific state instead of silently choosing another session. | Historical implementation evidence: initial URL/popstate implementation. Corrected and accepted by `FA-005` (`ac74c8b`) and `FA-008` accepted chain; final acceptance is in the canonical audit tracker. |

### Next — data flow, scale, and topology behavior

| ID | Status | Work | Acceptance criteria | Evidence |
| --- | --- | --- | --- | --- |
| `FS-007` | `PARTIAL` | Split live topology transport from the closed-session Audit directory. | Live SSE no longer queries and rebroadcasts the full retained closed-session list on every CWD update; Audit sessions are searchable and paginated. | Original transport/search implementation is accepted by `FA-001`, `FA-002`, and `FA-011`. `FA-016` is IN PROGRESS for large-collection summary/cursor index optimization, so this row remains explicitly partial pending final audit. |
| `FS-008` | `DONE` | Define multi-session IP cluster interaction. | A cluster exposes every active session and path without implying that the latest path is the only route; selection behavior is deterministic and keyboard accessible. | Historical implementation evidence: cluster disclosure, multi-route rendering, and 57 tests; no FA corrective item mapped to FS-008. |
| `FS-009` | `DONE` | Replace the fit algorithm with two-dimensional world bounds. | Fit considers X/Y, rendered element sizes, manual positions outside `0..100`, minimap clearance, and compact/fullscreen canvas sizes. | Historical implementation evidence: 2D bounds and 63 tests; no FA corrective item mapped to FS-009. |
| `FS-010` | `DONE` | Correct count semantics. | Labels distinguish unique sources, sessions, exact-path sessions, and descendant-branch sessions; badges and their resulting lists always agree. | Historical implementation evidence: unified count semantics and 68 tests; no FA corrective item mapped to FS-010. |
| `FS-011` | `DONE` | Reduce response-action polling cost. | Pending actions do not perform a Pi health check plus multiple MongoDB reads every second; status propagation has bounded backoff or an event stream and preserves terminal-state feedback. | Historical implementation evidence: cache, single-pass state read, and bounded polling. Corrected and accepted by `FA-003`/`FA-004`; manual live response-agent smoke validation remains an outstanding gate, as recorded canonically. |
| `FS-012` | `DONE` | Add freshness and degraded-state semantics. | Connected transport and fresh data are distinguishable; UI shows last update age, stale threshold, retry actions, and recovery without discarding the last valid snapshot. | Historical implementation evidence: freshness/degraded implementation and 81 tests. Corrected and accepted by `FA-006` (`2098af3`); final acceptance is in the canonical audit tracker. |

### Later — UX, accessibility, and maintainability

| ID | Status | Work | Acceptance criteria | Evidence |
| --- | --- | --- | --- | --- |
| `FS-013` | `DONE` | Consolidate Session and Path selectors on an accessible combobox/popover primitive. | Arrow navigation, typeahead, Escape, focus return, listbox semantics, screen readers, and reduced motion work consistently in both selectors. | Historical implementation evidence: shared combobox primitive and 96 tests. Corrected and accepted by `FA-007`; final component/browser acceptance is recorded under `FA-013` in the canonical audit tracker. |
| `FS-014` | `DONE` | Simplify toolbar hierarchy and responsive behavior. | Global view controls, canvas navigation, layout editing, and replay actions remain visually distinct without wrapping into ambiguous rows at supported breakpoints. | Historical implementation evidence: four toolbar domains and 101 tests. FA-013 adds accepted Chromium responsive/reduced-motion coverage; details are in the canonical audit tracker. |
| `FS-015` | `DONE` | Add density-aware topology modes. | Small sets render fully; medium sets cluster by source/branch; large sets aggregate and expand on focus while preserving visible hidden-item counts. | Historical implementation evidence: density-aware modes and 109 tests; no FA corrective item mapped to FS-015. |
| `FS-016` | `DONE` | Refactor the three oversized feature components. | Streaming, Audit/replay state, URL state, response actions, and layout math are isolated into testable hooks/modules; presentational components do not own unrelated data flow. | Historical implementation evidence: seven modular hooks and 122 tests. Corrected and accepted by `FA-012` commit chain; final ownership evidence is in the canonical audit tracker. |
| `FS-017` | `DONE` | Harden layout persistence. | Blocked/corrupt storage cannot crash rendering; stale entries are pruned or version-migrated; live and per-session Audit layouts remain isolated. | Historical implementation evidence: persistence hardening and 139 tests; no FA corrective item mapped to FS-017. |
| `FS-018` | `DONE` | Expand automated coverage. | Tests cover filter truth, pagination completeness, empty-history Response, URL restoration, topology limits, cluster selection, 2D fit, fullscreen/sidebar behavior, keyboard use, touch gestures, and reduced motion. | Historical implementation evidence: initial 158-test expansion. Corrected and accepted by `FA-007`, `FA-008`, and `FA-013`; final component/browser evidence is in the canonical audit tracker. |

## Product additions after the foundation is correct

These remain product backlog items and are not the active remediation focus.

| ID | Status | Addition | Acceptance criteria | Evidence |
| --- | --- | --- | --- | --- |
| `FS-019` | `DONE` | Time-based replay scrubber. | Shows real event time and gaps, supports jump/step/play, and does not imply uniform attacker timing. | Historical implementation evidence: initial time-aware scrubber and 164 tests. Corrected and accepted by `FA-009`; final component/browser evidence is recorded under `FA-013` in the canonical audit tracker. |
| `FS-020` | `TODO` | Focus controls. | Operator can focus a session or directory branch and return to live/global context in one predictable action. | Backlog; not part of FA-014. |
| `FS-021` | `TODO` | Exact historical transition overlay. | Repeated visits and lateral jumps are represented as actual event transitions rather than only first-visit node badges. | Backlog; not part of FA-014. |
| `FS-022` | `TODO` | Correlated command and file telemetry. | Command/file events are shown only when joined by authoritative identifiers, with provenance and explicit unavailable states. | Backlog; not part of FA-014. |
| `FS-023` | `TODO` | Forensic export and shareable evidence links. | Exported JSON/CSV preserves session, event IDs, timestamps, status, and filter scope; shared links open the same session/hop without embedding sensitive data. | Backlog; not part of FA-014. |

## Deferred outside this workstream

- Returning-attacker virtual filesystem continuity remains governed by
  [`design/returning-attacker-continuity.md`](design/returning-attacker-continuity.md).
- Customer appliance packaging and the outbound WSS gateway remain governed by
  [`HONEYPOT-PORTAL-INSTALLER-GUIDE.md`](HONEYPOT-PORTAL-INSTALLER-GUIDE.md).
- Do not expand the scoped Response surface beyond approved, allow-listed
  operations as part of a Filesystem UI change.

## Current validation and evidence policy

FA-015 was accepted `DONE` on `725102189587477bd9eafe13c8ac2d6e2e97e20c`.
FA-016 is the sole `IN PROGRESS` item, and FS-007 remains `PARTIAL` pending
its final re-audit. The manual response-agent validation remains unrelated.

FA-016 implementation and follow-up re-audit evidence is recorded in
[`validation/FA-016-audit-scale.md`](validation/FA-016-audit-scale.md). The
isolated MongoDB command passed its 1,900-session dashboard and processor
coverage, including v1-to-v2 migration, monotonic interleavings, event-outbox
close races, rejected-observation ownership, old canonical/legacy writers, and
scoped overflow coverage, with separate item/count/summary and retention-repair
execution bounds recorded there. Retention coverage now also includes source
expiry normalization, raw stable repair keysets, resumable orphan cleanup, and
TTL-ordering/source-recreation races. FA-016
remains IN PROGRESS pending final re-audit; FS-007 remains PARTIAL.

The current repository validation is the independent final FA-013 audit dated
2026-09-19 and is recorded in the canonical audit tracker. It ran these
reproducible commands: `cd dashboard-v2 && npm test`,
`cd dashboard-v2 && npm run test:browser`, `cd dashboard-v2 && npm run lint`,
`cd dashboard-v2 && npm run build`, and `go test -count=1 ./...` in each of the
five `agents/*` Go modules. It recorded 22 Vitest files with 460 passing and 2
skipped tests, 6/6 Chromium tests, zero ESLint errors/warnings, a passing
production build, all five Go modules passing, and `git diff --check` passing.
No manual/live validation was performed. The repository had no test-results or
playwright-report artifacts. These are current audit results, not replacement
claims about the 2026-09-15 historical baseline.

## Decision log

| Date | Decision | Reason |
| --- | --- | --- |
| 2026-09-15 | Start with `FS-001`; defer visual additions until Audit filtering is authoritative. | Incorrect result sets would invalidate later selection, count, and topology UX. |
| 2026-09-15 | Keep this tracker separate from design and validation evidence. | Work status changes frequently; architecture and evidence must remain durable and independently reviewable. |
| 2026-09-19 | Accept FA-015 and move the sole remediation focus to FA-016; preserve FS-007 as PARTIAL. | Large-collection optimization is now the only remaining FA item; FS-007 cannot be accepted until FA-016 passes final audit. |

## Update log

| Date | Change | Evidence |
| --- | --- | --- |
| 2026-09-19 | Continued only FA-016: made history projection an event-level durable outbox, separated current-state/history ownership, blocked rejected observed payloads from seeding or clearing readiness, and covered old canonical/legacy writers after the v2 marker. | Clean preflight at audited `60a73c4`; `git fetch origin --prune` succeeded; `origin/main` was already an ancestor; isolated integration passed 12 dashboard tests and executed 9 production FA-016 Mongo tests plus 2 target-safety tests; dashboard execution plans remained bounded and steady-state reconciliation performed zero `cwd_events` reads. Full dashboard tests, lint, build, diff check, and all five Go modules passed. FA-016 remains IN PROGRESS and FS-007 remains PARTIAL pending re-audit. |
| 2026-09-19 | Continued only FA-016: exact cursor-aware overflow composition, generation-owned readiness/CAS with bounded execution evidence, stale/late history crash recovery, padded canonical convergence, and deterministic race barriers. | Clean start at `5aeb4c0`; initial sandbox fetch failure and approved successful retry are recorded in validation evidence; `origin/main` was already an ancestor; dashboard baseline passed; isolated FA-016 integration passed 12 dashboard tests and six processor tests; full dashboard and five-module Go validation passed. FA-016 remains IN PROGRESS and FS-007 remains PARTIAL pending final re-audit. |
| 2026-09-19 | Accepted FA-015 on `725102189587477bd9eafe13c8ac2d6e2e97e20c` and continued FA-016 as the sole current focus; remediation commit `54c872b` was created without rewriting prior history; retained FS-007 as PARTIAL. | FA-015 validation is recorded in [`docs/validation/FA-015-change-hygiene.md`](validation/FA-015-change-hygiene.md); FA-016 remediation evidence is recorded in [`docs/validation/FA-016-audit-scale.md`](validation/FA-016-audit-scale.md) and remains pending final re-audit. |
| 2026-09-19 | Accepted FA-013 and reconciled this tracker to FA-014; qualified FS-007 as partial because FA-016 remains TODO and retained FS-020+ as backlog. | Accepted FA-013 chain and independent final audit evidence are recorded in `FILESYSTEM-ACTIVITY-AUDIT-FIXES.md`; FA-014 remains the sole current focus pending re-audit. |
| 2026-09-16 | Completed `FS-019`; started `FS-020`. | Historical implementation note: 164-test time-based scrubber result; superseded for corrective acceptance by FA-009 and FA-013. |
| 2026-09-16 | Completed `FS-018`; started `FS-019`. | Historical implementation note: 158-test foundation result; the “100% complete” wording and FA-014/FA-015/FA-016 focus state describe that earlier checkpoint and are superseded by the current backlog above. |
| 2026-09-15 | Created the live working state from the Filesystem Activity code/UX/logic review. | Historical baseline recorded above; its clean-tree statement applies only to that review point. |
| 2026-09-19 | Continued only FA-016: replaced the non-atomic source event counter with the indexed event outbox marker, closed failed-upsert/crash/concurrent-reconciler ownership gaps, and added exact dashboard pending-marker plan coverage. | Clean preflight at `7ef06f1`; fetch succeeded; `origin/main` `4390d88` was already an ancestor; implementation commits `53c9cc6` and `bd351b1`; isolated integration passed 12 dashboard tests and executed 11 production FA-016 Mongo tests plus 2 loopback-target safety tests with none skipped; full dashboard validation and all five Go modules passed. FA-016 remains IN PROGRESS and FS-007 remains PARTIAL pending re-audit. |
| 2026-09-19 | Continued only FA-016: made source-state TTL authoritative for projection retention, added bounded resumable repair and source-checked orphan cleanup, and covered projection-first deletion with concurrent reconciliation and exact projection facts. | Clean preflight at `5036d03`; fetch succeeded; `origin/main` `4390d88` was already the merge base; dashboard baseline passed before edits; isolated retention integration passed with no skipped FA-016 cases. FA-016 remains IN PROGRESS and FS-007 remains PARTIAL pending re-audit. |
| 2026-09-20 | Continued only FA-016: normalized eligible source expiry, replaced trimmed repair cursors with raw `(session field, _id)` keysets, and made orphan cleanup resumable with source-recreation rechecks. | Preflight started clean at `e575ede`; fetch succeeded; `origin/main` `4390d88` was already the merge base; dashboard baseline passed; production Mongo coverage passed all required retention/cursor cases with no skips. FA-016 remains IN PROGRESS and FS-007 remains PARTIAL pending re-audit. |
