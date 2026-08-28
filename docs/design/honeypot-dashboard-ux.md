# Honeypot dashboard UX and information architecture

## Purpose

This dashboard is an investigation workspace for an educational adaptive
honeypot. It must let an operator move from a high-level alert to the relevant
event and SSH session in two or three interactions. It is not a generic metrics
wall and it must not imply that a VirusTotal `not found` result is safe.

The dashboard reads summarized, redacted data from MongoDB. It never displays
malware binaries, raw provider responses, unredacted credentials, or unlimited
shell transcripts.

## Primary navigation

Keep six top-level areas. More destinations should be tabs or drawers within
these areas, not additions to the main sidebar.

| Area | Primary question | Main data |
|---|---|---|
| Overview | What is happening now? | rollups, recent events, top attackers |
| Live Activity | Which events need attention? | hot `events` |
| Attackers | Who is interacting with the honeypot? | attacker profiles and event history |
| Sessions | What happened in this SSH session? | session summaries and event timeline |
| Intelligence | What do reputation and hash lookups say? | `threat_intel`, artifacts, correlations |
| System Health | Is the data path healthy? | sensor, queue, quota, and Pi metrics |

`Malware Vault` should become **Intelligence → Artifacts**. The default system
stores hash and metadata only; it does not retain or execute malware samples.

## Global interaction model

Every operational page has these shared controls:

- time range;
- sensor/service filter (Cowrie, Zeek, SSH, FTP, HTTP, and so on);
- severity and TI-state filter;
- source-IP or session search;
- a detail drawer that retains the current page context.

The standard investigation route is:

```text
Overview alert → Live event or attacker → Session detail → TI/artifact context
```

An event row therefore needs direct actions for **Open session** and **Open
attacker**, rather than forcing the user to re-search for either entity.

## Page design

### 1. Overview

The landing page answers “what is happening now?” in under a minute.

```text
┌────────────────────────────────────────────────────────────────────┐
│ Time range · sensor · severity · search                             │
├──────────┬──────────┬──────────────┬────────────────────────────────┤
│ Events   │ Unique IP│ High risk IP │ VT-known artifacts             │
├────────────────────────────────────┬───────────────────────────────┤
│ Live event stream                  │ Top attackers                  │
│ recent high-risk activity          │ score, ISP, country, sessions │
├────────────────────────────────────┼───────────────────────────────┤
│ Activity / tactic trend            │ Geographic or campaign view    │
└────────────────────────────────────┴───────────────────────────────┘
```

The map is a supporting visualization, not the dashboard's focal point. A live
stream and attacker/session drill-down provide more investigative value.

### 2. Live Activity

Use a compact event table with a right-hand detail drawer.

- Columns: time, source, service, source IP, session, event type, severity,
  and TI state.
- Drawer: normalized event data, safe payload preview, linked session,
  enrichment summary, and timestamps.
- TI state: `pending`, `complete`, `unknown_to_provider`, `skipped`, or
  `failed`. Do not represent `unknown_to_provider` as a green/safe state.

### 3. Attackers

Treat an IP as an entity rather than a collection of disconnected events.

- Table: IP, country, ISP, AbuseIPDB score, Tor flag, session count, command
  count, first seen, and last seen.
- Detail: chronological activity, related sessions, related hashes, and a
  compact behavioural-risk explanation.
- The score must combine observed behaviour with TI; an AbuseIPDB score alone
  must not determine severity.

### 4. Sessions

This is the principal Cowrie investigation page.

```text
┌───────────────┬────────────────────────────────┬───────────────────┐
│ Session list  │ Redacted command/event timeline │ Context panel     │
│ risk + status │ commands, transfers, outcomes  │ IP, Zeek, TI, AI  │
└───────────────┴────────────────────────────────┴───────────────────┘
```

The transcript must be redacted and bounded. The context panel can later show
the post-session cloud-AI assessment, but live deception/LLM controls do not
belong in this dashboard page.

### 5. Intelligence

Use three tabs:

| Tab | Content |
|---|---|
| IP Reputation | AbuseIPDB score, reports, ISP, country, usage type, and Tor flag |
| Artifacts | SHA-256, observed filename/URL metadata, VirusTotal status, analysis statistics, linked sessions |
| Campaigns | Future correlation across IPs, sessions, hashes, services, and tactics |

Show the provider, query time, result expiry, and data state beside every
enrichment result. The default policy remains hash lookup only; there is no
button to upload a sample to VirusTotal or report an IP to AbuseIPDB.

### 6. System Health

Keep operational health separate from attacker data.

- status of Cowrie, Zeek, collector, processor, Redis, MongoDB Atlas, and the
  TI worker;
- Redis stream depth for raw ingestion and `ti:jobs`;
- provider quota, cache hit rate, pending/retry counts, and skipped lookups;
- Pi CPU, memory, disk, log-retention, and last-data timestamps.

## Threat-intelligence presentation contract

The API adapter maps persistent event data from `event.threat_intel.*` to the
legacy dashboard shapes while the UI is incrementally migrated. New UI work
should prefer the normalized contract below.

```text
event.threat_intel.abuseipdb
  → status, observable, summary, queried_at, expires_at

event.threat_intel.virustotal
  → status, observable, summary, queried_at, expires_at
```

The event receives only a selected summary. The shared detailed cache stays in
the `threat_intel` collection and expires according to provider policy.

## Risk and colour semantics

- Red: critical/high confidence harmful observed behaviour.
- Orange: suspicious or high reputation risk that needs review.
- Blue/teal: system/source identity, not risk.
- Purple: AI-derived assessment, clearly labelled as advisory.
- Grey: pending, unknown, disabled, or unavailable.

Suggested severity inputs, in order of importance:

1. observed honeypot behaviour (authentication success, privilege attempts,
   transfer attempts, destructive command families);
2. session and event recurrence;
3. AbuseIPDB score and Tor context;
4. VirusTotal detection statistics for an observed SHA-256;
5. AI post-session assessment as a labelled advisory signal.

## Incremental delivery plan

### Already implemented or prepared

- API compatibility adapter for asynchronous AbuseIPDB and VirusTotal results.
- Attacker table uses AbuseIPDB risk score and ISP when present.
- Live stream can show AbuseIPDB risk and VirusTotal malware indicators.
- Asynchronous TI worker data contract and provider state are documented.

### Next dashboard iteration

1. Add global time/sensor/severity filters and safe TI-state badges.
2. Add event detail drawer with direct session/attacker navigation.
3. Build the session-detail three-column investigation view.
4. Add System Health queue/quota/cache widgets.
5. Replace legacy UI provider shapes with the normalized `threat_intel`
   contract once all consumers are migrated.

### Later work

- attacker/session correlation graph;
- campaign view;
- cloud-AI post-session advisory panel;
- report/export pages based on rollups rather than raw event scans.

## Data and storage constraints

Dashboard queries should use summaries and rollups first. Do not make the UI
scan raw logs, full shell transcripts, raw provider JSON, or hardware metrics
at native sampling frequency. Apply the retention policy in
[Data ownership and retention](../DATA-OWNERSHIP.md).
