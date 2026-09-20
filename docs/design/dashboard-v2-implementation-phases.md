# Dashboard v2 implementation phases

## Purpose

This plan sequences the remediation in
[Dashboard v2 UX and information-architecture review](dashboard-v2-ux-review-2026-09-20.md)
so that data correctness is fixed before navigation and component
consolidation. The goal is to keep each change reviewable, reversible, and
testable instead of performing a high-risk dashboard rewrite.

This plan does not replace
[Honeypot dashboard UX](honeypot-dashboard-ux.md). It is the delivery plan for
moving the current repository toward that accepted target.

## Delivery principles

1. **Truth before polish.** Fix fabricated, ambiguous, or overclaimed values
   before reorganizing the pages that display them.
2. **Add, switch, remove.** Add the new contract or route, migrate consumers,
   then remove the legacy path in a later change.
3. **One concern per pull request.** API contract, UI migration, route cutover,
   and cleanup should normally be separate changes.
4. **Keep deep links stable.** Existing `/threat-intel/[id]` links must continue
   to resolve throughout the migration.
5. **No inferred evidence.** Missing fields render as unknown/not recorded;
   they are never reconstructed for visual completeness.
6. **Make scope machine-readable.** APIs should return window, as-of time,
   total, limit/coverage, and truncation instead of relying only on UI copy.
7. **Preserve authority lanes.** Observed evidence, trusted mappings, model
   output, correlation, TI enrichment, and advisory guidance remain separate.
8. **Feature removal is delayed.** Do not delete a legacy route or response
   field in the same change that introduces its replacement.

## Standard pull-request shape

For phases that change a read model or route, prefer this sequence:

1. **Contract PR:** types, API/read model, fixtures, unit/integration tests.
2. **Presentation PR:** new UI consumes the contract behind a route or feature
   boundary; legacy UI remains available.
3. **Cutover PR:** navigation and default links move to the new UI; old paths
   become compatibility aliases or redirects.
4. **Cleanup PR:** remove unused components and endpoints after validation.

This structure gives each phase an obvious rollback point.

## Phase 0 — Baseline and regression harness

### Objective

Freeze current behavior and define the semantic invariants required by later
phases. No navigation or visual redesign occurs here.

### Work

- Add fixtures for:
  - Critical, High, Medium, Low, and missing severity;
  - active and closed sessions;
  - more than 2,000 historical sessions;
  - missing artifact size/hash/session linkage;
  - fresh, stale, partial, empty, and unavailable sources.
- Add unit tests for threat normalization, lifecycle state, summary windows,
  pagination, filter normalization, and export caps.
- Add API tests asserting metadata such as `asOf`, `window`, `total`, `limit`,
  and `truncated` where relevant.
- Add Playwright coverage at desktop and 390 px mobile widths for Dashboard,
  Sessions/Threat Intel, Archives, Malware Vault, System Health, Filesystem,
  and Session Analysis.
- Capture screenshot baselines for ready, empty, stale, and error states.
- Record current route and deep-link behavior.

### Exit gate

- `npm run lint`, `npm test`, `npm run build`, and browser smoke tests pass.
- A failing test demonstrates each P0 concern before its fix, or the invariant
  is otherwise encoded in an automated test.
- No production-visible behavior changes.

### Rollback

Tests and fixtures are additive and can remain even if later phases pause.

## Phase 1 — Data-truth hotfixes

### Objective

Remove misleading or fabricated presentation without restructuring pages.

### Work package 1A: threat/session terminology

- Stop presenting severity-derived values as APT, BOT, or Script Kiddie.
- Prefer observed fields such as severity, lifecycle, sensor, and source IP.
- Rename `Hacker IP` to `Source IP` and `Attacker type` to an evidence-safe
  field, or remove the column.
- Change `Critical threats` to `Critical + High sessions`, or count only
  Critical sessions.
- Rename `Total sessions` to `Latest loaded sessions` until it is backed by a
  full server count.
- Remove the permanently unavailable Detection Latency KPI.

### Work package 1B: artifact truth

- Remove random size generation.
- Render absent size, session, hash, URL, and filename as `Not recorded`.
- Filter the endpoint to records that satisfy a documented artifact/hash
  contract.
- Prevent VirusTotal links when the hash is absent or invalid.
- Rename Malware Vault and correct its description to match the hash-only
  policy.

### Work package 1C: scope disclosure

- Add visible scope and as-of metadata to Dashboard, Threat Intel, Archives,
  and artifact results.
- Label truncated/latest-buffer views explicitly.
- Ensure connection state and data freshness are not represented as the same
  state.

### Exit gate

- No UI value is random or fabricated.
- A severity value alone cannot produce an attacker-type claim.
- Every count/chart under review states its scope.
- Missing evidence is visibly unknown rather than assigned a default fact.
- Existing routes and deep links still work.

### Rollback

This phase should be composed of label/adapter changes and can be reverted per
work package. Do not combine it with route deletion.

## Phase 2 — Unified session query and summary contracts

### Objective

Create one server-side source for session discovery and one internally
consistent Overview aggregation before changing page ownership.

### Session-directory contract

Extend or supersede `/api/threats/directory` with a neutral Sessions contract.
Support:

- page and page size;
- time range/from/to;
- lifecycle status;
- severity;
- sensor/service;
- source IP/session ID search;
- country/region when available;
- deterministic sort;
- server-side CSV export using the same filters.

Every response should include:

```text
items
page
pageSize
total
totalPages
appliedFilters
asOf
truncated / coverage, when applicable
```

Keep the current endpoint as an alias during migration if renaming it.

### Overview-summary contract

Return one documented window containing:

- total sessions;
- distinct sources;
- severity buckets;
- time buckets;
- active/closed counts;
- recent priority sessions;
- top sources;
- generated/as-of timestamp.

All these values must be computed from the same predicate and time window.
The live stream can remain a separate latest buffer but must not be used to
populate the windowed aggregate charts.

### Tests

- More-than-2,000-row pagination and filtering.
- Export count equals the matching server-side query up to the documented cap.
- KPI total equals the sum of severity buckets for the same window.
- Trend buckets and KPI total reconcile under one fixture.
- Stable ordering when timestamps are equal.
- Invalid filter and page values fail safely or normalize predictably.

### Exit gate

- Dashboard aggregates reconcile for a shared window.
- Historical search no longer requires loading the entire bounded snapshot in
  the browser.
- API consumers can migrate without changing the legacy routes yet.

### Rollback

Keep old endpoints and consumers active. The new contracts are additive until
Phase 3 cutover.

## Phase 3 — Consolidate session discovery

### Objective

Make one `Sessions` workspace the owner of live and historical investigation.

### Work package 3A: new Sessions page

- Introduce `/sessions` using the Phase 2 directory contract.
- Provide `Live` and `History` tabs or equivalent URL-backed scopes.
- Put filter state in the URL so searches can be shared and restored.
- Use one table/card component for all scopes.
- Retain links to the existing `/threat-intel/[id]` detail route.
- Provide server-side export with visible matching/exported/truncated counts.

### Work package 3B: Overview reduction

- Replace the complete directory with three to eight recent priority sessions.
- Add `View all sessions` preserving relevant window/severity parameters.
- Remove directory-specific pagination and export code from Dashboard.

### Work package 3C: compatibility cutover

- Change `Threat Intel` navigation to `Sessions`.
- Make `/threat-intel` a compatibility redirect or wrapper for `/sessions`.
- Make `/archives` point to `/sessions?view=history` while preserving bookmarks.
- Keep `/threat-intel/[id]` unchanged in this phase.

### Exit gate

- Search, filtering, pagination, history, and export exist in one implementation.
- No Dashboard mobile view renders a 20-card directory.
- Old list-route URLs resolve to the appropriate Sessions scope.
- Session deep links from old exports/bookmarks remain valid.

### Rollback

Navigation can return to the old pages because they are not removed until the
cleanup phase.

## Phase 4 — Re-scope Overview and System Health

### Objective

Make Overview answer “what needs attention now?” and System Health answer “can
the data path be trusted?”

### Overview work

- Use only the Phase 2 summary for windowed KPIs and charts.
- Keep one page-level feed/data-health indicator.
- Remove duplicate feed-status KPI and repeated summary prose.
- Add recent priority sessions and top sources with direct investigation links.
- Reduce map prominence or aggregate markers by source/country.
- Show previous-window comparison only if the backend supplies a documented
  comparison from complete aggregates.

### System Health work

- Move Live Event Stream and Top Source IPs to Overview or Live Activity.
- Add service/sensor states, last ingestion, ingest lag, queue depth,
  processing errors/retries, provider quota, cache state, and retention/storage
  pressure as available.
- Retain hardware telemetry and its independent freshness state.
- Define overall health from explicit component states; do not infer it from
  the local browser clock or SSE connection alone.

### Exit gate

- Overview values share one explicit window, except a separately labelled live
  stream.
- System Health contains no attacker ranking or investigation directory.
- A disconnected service, stale data source, and empty dataset are visibly
  distinct states.

### Rollback

Move widgets using shared components first. Delete old placements only after
the new locations pass browser tests.

## Phase 5 — Session Analysis progressive disclosure

### Objective

Reduce scanning cost while preserving exact-session evidence boundaries.

### Work package 5A: page state model

- Build an availability summary from the existing capability results.
- Define tab IDs and URL state:
  - `overview`;
  - `evidence`;
  - `analysis`;
  - `intelligence`;
  - `response-reports`.
- Keep data loading independent from tab presentation initially to minimize
  behavioral change.

### Work package 5B: grouped presentation

- Move existing panels into tabs without changing their authority semantics.
- Keep the most important lifecycle and evidence summary above the tabs.
- Group unavailable capability results into a collapsed summary; allow an
  operator to inspect individual reasons on demand.
- Preserve print/export behavior with a print layout that includes all
  relevant sections regardless of the selected screen tab.

### Work package 5C: request optimization

- After presentation parity is proven, evaluate lazy loading for expensive
  inactive tabs.
- Keep exact-session binding, request timeout, stale response, and cancellation
  behavior covered by tests.

### Exit gate

- Operators can reach any evidence lane in one interaction from the tab bar.
- Unavailable services do not produce a long stack of repetitive cards.
- Observed, model, correlation, TI, and advisory lanes remain explicitly
  separated.
- Printing/export includes the intended full report and is not limited to the
  active tab.

### Rollback

The original panel components remain intact during Work package 5B; the tab
container only changes composition. Lazy loading is deferred until parity is
established.

## Phase 6 — Filesystem and responsive refinement

### Objective

Resolve control density and mobile layout after the major page ownership is
stable.

### Filesystem work

- Separate mode tabs from connection/freshness controls.
- Introduce a combined status sentence such as `Connected · data stale` while
  retaining the two underlying fields.
- Keep topology-specific controls inside the canvas header.
- Prevent footer summary and legend collision at common desktop widths.
- Verify keyboard focus, fullscreen behavior, and replay controls after layout
  changes.

### Cross-page responsive work

- Test 390, 768, 1024, 1280, and 1440 px widths.
- Cap Overview preview rows on mobile.
- Ensure tables use either intentional horizontal scrolling or a compact card
  representation, not both simultaneously.
- Keep primary actions visible without duplicating them in every panel.
- Verify page `h1` hierarchy and shell breadcrumb behavior.

### Exit gate

- No page-level horizontal overflow at tested widths.
- Overview mobile no longer has directory-driven excessive length.
- Filesystem controls and legend do not overlap.
- Keyboard, focus trap, reduced-motion, and fullscreen tests pass.

## Phase 7 — Legacy cleanup and documentation

### Objective

Remove only code proven unused after the new routes and contracts have been
validated.

### Work

- Remove duplicate directory, pagination, filter, and CSV implementations.
- Remove obsolete API aliases only if compatibility policy permits; otherwise
  retain documented redirects.
- Delete unused presentation components and legacy field mappings.
- Update:
  - API/OpenAPI documentation;
  - data semantics;
  - navigation and UX design;
  - validation evidence;
  - changelog and operational runbooks.
- Add validation evidence to `docs/validation/`; do not mark a design document
  as deployment proof.

### Exit gate

- Repository search finds no active consumer of removed fields/routes.
- All automated checks and production/staging smoke tests pass.
- Route redirects and export compatibility are documented.
- Validation artifacts record the tested dataset scope and build identity.

## Cross-phase test matrix

Every phase that changes user-visible behavior should cover the applicable
cells below.

| Dimension | Required cases |
| --- | --- |
| Data state | loading, ready, empty, stale, partial error, unavailable |
| Session lifecycle | active, closed, missing/unknown lifecycle |
| Severity | Critical, High, Medium, Low, absent/unrecognized |
| Volume | 0, 1, one page, multiple pages, more than 2,000, export cap |
| Viewport | 390, 768, 1024, 1280, 1440 px |
| Interaction | keyboard, pointer, back/forward URL state, refresh, reconnect |
| Role | Supporter, Admin, unauthenticated/expired session |
| Freshness | live connection/fresh data, live/stale data, disconnected/cached data |
| Export | no rows, filtered rows, Unicode/CSV escaping, truncated export |

Minimum command gate:

```text
npm run lint
npm test
npm run build
npm run test:browser
```

If the complete browser suite is not practical for every small PR, run a
documented affected-route subset and require the complete suite at each phase
exit.

## Dependency order

```text
Phase 0 baseline
  → Phase 1 truth fixes
    → Phase 2 read contracts
      → Phase 3 session consolidation
        → Phase 4 overview/health ownership
        → Phase 5 session-detail grouping
      → Phase 6 responsive/filesystem refinement
        → Phase 7 cleanup and documentation
```

Phase 5 can proceed in parallel with Phase 4 after Phase 2 if it does not
change the shared session directory or summary contracts. Phase 7 must wait for
all route and consumer migrations.

## Recommended first implementation batch

The safest first batch is limited to Phase 0 and Phase 1:

1. encode fixtures and invariants;
2. remove random artifact size;
3. remove severity-derived attacker-type claims;
4. correct KPI labels and remove Detection Latency placeholder;
5. add scope/as-of labels without moving any routes.

This batch resolves the highest-risk truth concerns while leaving navigation,
URLs, and page ownership unchanged.

## Completion definition

The program is complete when:

- every displayed claim is traceable to an authoritative source field or a
  clearly labelled derived/advisory result;
- Overview metrics and charts reconcile within a documented window;
- one Sessions implementation owns live/history discovery and export;
- artifact presentation follows the hash-only security policy;
- System Health represents platform and data-path health;
- Session Analysis is navigable without flattening evidence authority;
- legacy routes and components are removed only after compatibility validation;
- validation evidence exists for desktop, mobile, error states, and data scale.
