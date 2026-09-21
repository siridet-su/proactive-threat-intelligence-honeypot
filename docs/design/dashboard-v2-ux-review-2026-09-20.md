# Dashboard v2 UX and information-architecture review

## Document status

- Review date: 2026-09-20
- Scope: `dashboard-v2` operator workspace
- Review type: read-only code, data-semantics, information-architecture, and rendered-UI review
- Verification: `npm run build` passed; representative pages were rendered at 1440 px desktop and 390 px mobile widths
- Implementation status: findings only; this document is not evidence that remediation has shipped

This review is a current-state companion to
[Honeypot dashboard UX](honeypot-dashboard-ux.md). It does not replace that
target design. It identifies the shortest safe path from the current dashboard
to that target without a large, high-risk rewrite.

## Executive summary

The visual system is coherent: typography, spacing, panels, badges, loading
states, and desktop layout are generally consistent. The largest risks are not
cosmetic. They are data meaning, overlapping page responsibilities, and weak
progressive disclosure.

The most important conclusions are:

1. Several labels imply conclusions that the underlying data does not support.
   In particular, `APT`, `BOT`, and `SCRIPT KIDDIE` are currently derived from
   severity rather than an independent attacker-classification result.
2. The Overview mixes a 24-hour aggregate with a latest-100-session live
   buffer. Counts and charts shown beside one another therefore have different
   denominators.
3. Dashboard, Threat Intel, and Archives each implement a session directory
   with different limits, filters, pagination, and export behavior.
4. Malware Vault is backed by general enrichment records, includes synthetic
   file sizes when data is absent, and describes metadata as retained malware
   payloads. This conflicts with the hash-first handling policy.
5. System Health mixes platform health with attacker/event monitoring.
6. Session Analysis renders up to 17 evidence panels in one vertical flow,
   including repeated unavailable states. The tested page was approximately
   3,879 px tall.
7. The mobile Overview renders all 20 directory results as cards after the
   analytics sections. The tested page was approximately 9,153 px tall.

These issues should be corrected in small, contract-first phases. Do not start
with a navigation rewrite or a large component migration.

## Current page responsibilities

| Page | Current responsibility | Main concern |
| --- | --- | --- |
| Dashboard | 24-hour KPIs, map, live feed, trends, severity, prose insight, full directory, export | Too many jobs; mixed data scopes; very long mobile page |
| Threat Intel | Latest-buffer KPIs, classification chart, paginated live session table | Duplicates the directory and presents severity-derived attacker types |
| Archives | Historical session filters, client pagination, client CSV export | “All” is capped at 2,000 records; duplicates the directory |
| Session Analysis | Metadata, commands, chronology, classifications, model output, TI, guidance, provenance, reports | Seventeen panels in a single flow; repeated empty/unavailable noise |
| Filesystem Activity | Live topology and session audit/replay | Dense global controls; freshness and connection can compete visually |
| Malware Vault | Enrichment-derived artifact table and VirusTotal links | Source records and labels do not reliably mean captured malware |
| System Health | Hardware telemetry, live event stream, top source IPs | Platform health and attacker activity are mixed together |
| User Management / Profile | Operator and access administration | Appropriate responsibility; navigation grouping can improve |

## Findings by priority

### P0 — Data truth and evidence semantics

#### D-01: attacker classification is inferred from severity

`normalizeThreat` maps:

- `Critical` to `APT`;
- `High` to `BOT`;
- every other session to `SCRIPT KIDDIE`.

This derived value is then presented as “Attacker type”, “Automated bots”, and
“Target landscape”. Severity does not establish actor sophistication or
identity. Until a separate, evidence-bounded classifier exists, the field
should be removed or explicitly labelled `Severity-derived category`.

Related wording should also change from `Hacker IP` or `Attacker` to
`Source IP` or `Observed source`. An IP can represent a proxy, NAT gateway,
scanner, relay, or compromised host.

Evidence:

- `dashboard-v2/src/lib/threat-server.ts`, `normalizeThreat`
- `dashboard-v2/src/app/(main)/threat-intel/page.tsx`, summary and chart data
- `dashboard-v2/src/app/(main)/dashboard/page.tsx`, directory columns

#### D-02: Malware Vault contains fabricated or overclaimed values

The API currently reads the first 50 general `enrichment_records`, maps
`observable_value` to `sourceIp`, sets `session` to `N/A`, and creates a random
size when the source record has no size. A non-IP record is labelled
`Malware Payload` regardless of whether the record establishes that meaning.

The page description states that payloads, scripts, and binaries are retained,
while the accepted project policy is hash-first, metadata-only, and
never-execute.

Required correction:

- never synthesize an evidence value;
- show `Not recorded` for absent size or provenance;
- select only records with an appropriate artifact/hash contract;
- display record type, source collection, provider, queried time, and expiry;
- link the originating session when the relationship exists;
- rename the page to `Artifact Intelligence` or `Malware Hash Evidence`;
- state clearly that executable bytes are not retained in Atlas.

Evidence:

- `dashboard-v2/src/app/api/malware/route.ts`
- `dashboard-v2/src/app/(main)/malware-vault/page.tsx`
- `docs/SECURITY-AND-MALWARE-POLICY.md`
- `docs/adr/ADR-0002-hash-only-malware-handling.md`

#### D-03: adjacent dashboard values use different denominators

The situation summary is a 24-hour MongoDB aggregation. The map, live feed,
activity trend, and severity distribution use the latest session buffer, which
is truncated to 100 items. The activity trend then uses the 24-hour window
label while binning only those buffered sessions.

In the reviewed dataset, this produced a visible example of 277 sessions in
the 24-hour summary while a nearby distribution contained 100 sessions. Both
values can be correct, but their presentation makes them appear directly
comparable.

Every data region must expose:

- scope/window, such as `Last 24 hours` or `Latest 100 sessions`;
- generated/as-of time;
- record limit or coverage when truncated;
- stale/partial state independently from connection state.

Prefer one server aggregation for the Overview so the KPI, trend, severity,
top sources, and recent-priority list share the same window.

Evidence:

- `dashboard-v2/src/components/threat/ThreatFeedProvider.tsx`
- `dashboard-v2/src/lib/threat-server.ts`, snapshot and summary limits
- `dashboard-v2/src/app/(main)/dashboard/page.tsx`, activity/severity builders

#### D-04: Archives “All Time” is a bounded client snapshot

`/api/threats?range=all` returns at most 2,000 sessions. Archives then filters,
paginates, counts, and exports that bounded snapshot in the browser. The user
is not told that older matching rows can be absent.

Historical filters and export should use the same server-side directory/query
contract as the primary Sessions page. Response metadata must include total,
page, page size, applied scope, and export truncation.

#### D-05: KPI labels do not match their calculation

The Threat Intel `Critical threats` value includes both Critical and High
severity sessions while its annotation says `Critical severity`.
`Total sessions` means the latest live buffer, not total stored sessions.
`Detection latency` is permanently rendered as not reported.

Fix the label/calculation mismatch and remove placeholders that cannot yet be
populated. Empty capacity should not be presented as a KPI.

### P1 — Duplication and information architecture

#### IA-01: three competing session directories

The following surfaces overlap:

| Capability | Dashboard directory | Threat Intel | Archives |
| --- | --- | --- | --- |
| Session rows | Yes | Yes | Yes |
| Detail navigation | Yes | Yes | Yes |
| Search | Session/IP/sensor | No | Region only |
| Severity filter | Yes | No | Yes |
| Date filter | No | No | Yes |
| Server pagination | Yes | No | No |
| Export | Server, up to documented cap | No | Client, loaded subset |
| Data scope | Full directory | Latest 100 | Latest 2,000 called “all” |

This makes it unclear where an operator should start an investigation and
creates three implementations to maintain.

Recommended ownership:

- one `Sessions` route owns search, filters, pagination, history, and export;
- `Live` and `History` are tabs or saved scopes on that route;
- Dashboard shows only a short priority/recent preview and links to Sessions;
- Archives becomes a compatibility route to `Sessions?view=history`;
- Session deep links remain stable throughout migration.

#### IA-02: feed health is repeated without adding meaning

Feed status appears in the Dashboard header, a KPI tile, the Live Threat Feed,
and the Security Insight panel. Keep one global data-health indicator in the
page header and local status only where a panel has an independent source.

The freed KPI slot should represent an operational question, for example:

- active sessions;
- sessions needing review;
- new high-priority sessions since the previous window;
- ingestion lag, if it is authoritative.

#### IA-03: Security Insight repeats the KPI summary

The current insight paragraph restates observed sessions, unique sources, and
priority sessions. It does not identify a change, anomaly, or recommended
review action.

Either remove it or replace it with a deterministic, traceable finding such as
“12 new sources since the previous 24-hour window” or “3 sessions have
unreviewed Critical evidence”. Do not generate an insight merely to fill the
panel.

#### IA-04: System Health contains attacker/event views

Live Event Stream and Top Source IPs belong to monitoring/investigation, not
platform health. System Health should answer whether the data path can be
trusted:

- sensor, collector, processor, TI worker, database, and stream status;
- last successful ingestion and lag;
- queue depth, retry/error counts, and provider quota;
- Pi CPU, memory, storage, temperature, and retention pressure.

#### IA-05: navigation is a flat list

Near-term navigation should group current capabilities rather than add more
top-level links:

```text
Monitor
  Overview
  Live Activity

Investigate
  Sessions
  Filesystem & Replay
  Intelligence / Artifacts

Operate
  Platform & Sensor Health

Administration
  Operators & Access
  Profile
```

The accepted target design may later promote Attackers and Intelligence as
their own primary workspaces when their entity/read models are complete.

### P1 — Page hierarchy and responsive behavior

#### UX-01: Overview is a dashboard plus a complete application page

The Overview currently includes seven major sections and a full 20-row
directory. A dashboard should help the operator decide where to go next; it
should not contain the complete investigation directory.

Recommended order:

1. global window/sensor filters and data-health state;
2. four authoritative KPIs with the same scope;
3. recent high-priority sessions and top sources;
4. compact trend and severity summary;
5. map as supporting context, not the dominant surface;
6. links to Sessions, Intelligence, and System Health.

On mobile, show no more than three to five session previews. Do not render a
20-card directory below the analytics.

#### UX-02: Session Analysis needs progressive disclosure

The current page exposes 17 panels in one vertical sequence. When the monitor
or a capability is unavailable, each panel repeats a separate unavailable
card, producing a long page with little usable evidence.

Recommended grouping:

| Tab | Content |
| --- | --- |
| Overview | lifecycle, source, destination, timestamps, evidence counts, geography |
| Evidence | timeline, authentication, commands, files/observables |
| Analysis | trusted classification, ATT&CK, ensemble, hypothesis, Next-Distinct |
| Intelligence | external TI, source-IP pivot, related sessions/campaigns |
| Response & Reports | guidance, advisory, provenance, reports |

Preserve the separation between observed evidence, model output, correlation,
and advisory information. Tabs are a navigation mechanism, not permission to
blend authority lanes.

Add an availability summary near the top, for example `5 of 12 evidence
sources available`, and place unavailable sources in a collapsed region.

#### UX-03: Filesystem controls are dense

The page header combines mode tabs, stream connection, telemetry freshness,
reconnect, and refresh controls. At narrower desktop widths these controls
compete with the title; the topology footer legend can also collide with
summary text.

Split the header into:

- title and Live/Audit mode tabs;
- a separate compact status row for connection, data freshness, and refresh;
- canvas-specific view controls inside the canvas header.

Connection and freshness must remain distinct. If the stream is connected but
the last evidence is stale, present `Connected · data stale` as the primary
combined state rather than allowing the green connection badge to dominate.

#### UX-04: page-title hierarchy is inconsistent

Some pages show both a shell title and an `h1`; Threat Intel has no content
`h1` and starts with metric-card `h2` elements. Use the shell header as a
breadcrumb/context bar and retain exactly one meaningful page `h1` in the main
content.

### P2 — Useful improvements after consolidation

- Aggregate map markers by source or country and show count, highest severity,
  and last seen. Multiple sessions from one source should not create
  indistinguishable overlapping markers.
- Add direct pivots from an artifact to its session and source-IP history.
- Add previous-window comparisons only when the backend provides a documented
  aggregation; do not calculate them from a truncated live buffer.
- Standardize loading, stale, partial, empty, and unavailable state wording
  across all pages.
- Keep export semantics visible: applied filters, generated time, total
  matching records, exported count, and truncation.

## Recommended ownership after consolidation

| Information | Authoritative UI owner | Secondary presentation |
| --- | --- | --- |
| Current situation and priorities | Overview | compact badges/links elsewhere |
| Searchable session inventory | Sessions | recent preview on Overview |
| Historical sessions and export | Sessions → History | compatibility redirect from Archives |
| Exact-session evidence and analysis | Session Analysis | links from Sessions/Artifacts |
| Filesystem path evidence and replay | Filesystem & Replay | exact-session deep link |
| IP/hash/provider enrichment | Intelligence | compact context in Session Analysis |
| Platform/sensor/data-path health | System Health | global degraded-health indicator |
| Operator access | Administration | profile menu for current operator |

## Review completion criteria

This review should be considered addressed only when:

- no displayed field is fabricated or assigned a stronger semantic meaning
  than its source supports;
- every aggregate or chart exposes its scope and as-of time;
- the Overview does not contain a complete session directory;
- one server-side query contract owns live and historical session discovery;
- System Health contains platform/data-path health rather than attacker lists;
- Session Analysis supports grouped navigation and collapses unavailable data;
- desktop and mobile test coverage includes loading, ready, empty, stale,
  partial-error, and unavailable states.
