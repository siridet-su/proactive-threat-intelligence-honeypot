# ADR-0008: Attribute Cowrie outbound flows by socket receipt

Date: 2026-09-28
Status: Implemented as a live shadow-path PoC on 2026-09-28; not a model-performance validation

## Context

The V7 observer currently selects every eligible HTTP flow in a Cowrie
session's time window. A live 493-second session generated one successful
download but its exact PCAP also contained 76 other outbound HTTP connections.
The receiver returned `MODEL2_UNAVAILABLE` because it could not validate the
whole flow set. The time window and Pi source address do not identify which
outbound socket belongs to an SSH session. Cowrie recorded 17 session IDs in
that interval, so a single test operator does not imply a single session.
Before the 2026-09-28 capture-only correction, the installed Pi transfer ring
captured only Pi-to-public-HTTP packets; the return direction was missing.
An offline Zeek replay of the long capture
found two incomplete rows for one HTTP tuple despite only one client SYN.

## Decision

Cowrie's per-command HTTP agent should emit a bounded, pre-response
`cowrie.session.outbound_connection` receipt when the TCP connection is made.
The receipt carries only the Cowrie session identity, timestamp, and an
`outbound_*` IPv4 endpoint tuple. It contains no URL, command text, payload,
headers, credentials, or response outcome. The separate field names avoid
misrepresenting the outbound IP as the SSH attacker's origin.

The Pi observer keeps its bounded episode-wide PCAP acquisition. Its
session-flow projection selects only receipts belonging to that Cowrie
session, requiring one exact client SYN within five seconds before each
receipt. Zeek must then return one exact flow per selected tuple. Missing,
duplicated, stale, private-destination, or ambiguous tuples fail closed.
Unattributed packets remain retained as Pi-wide capture context; they are
not silently assigned to the session or used as Model2 features.

The transfer ring must capture both directions of eligible public HTTP while
retaining the existing private-network exclusion. A short temporary capture
on Pi proved 5 outgoing and 4 incoming packets for one Cowrie transfer;
Zeek produced one response-bearing connection. The temporary raw PCAP was
removed after the aggregate check. The bidirectional filter was subsequently
deployed to the Pi capture unit only; Cowrie, observer, receiver and ensemble
remained on V1. In a subsequent short transfer, the ring held 7 outgoing and
5 incoming HTTP packets, but V1 still yielded zero bound episode flows because
another Pi HTTP tuple in the same window was incomplete. This is capture
mechanics evidence, not Model2 accuracy or a successful V2 binding test.

The projection gets a versioned contract distinct from the existing
`OUTCOME_INDEPENDENT_FIXED_SESSION_WINDOW_V1`. The 54-feature model remains
shadow/PoC; changing flow selection changes its input distribution and does
not establish improved accuracy or justify a production vote.

## Validation and rollout gate

1. Unit tests: two concurrent sessions, background flows, duplicate SYN,
   missing receipt, duplicate receipt, invalid endpoint, and missing data.
2. Isolated Pi loopback test: two treq agents must record distinct real local
   source ports without changing request completion.
3. Staged Cowrie integration: no changes to canonical source-IP fields;
   confirm one socket receipt per cleartext connection, including redirects.
4. Staged capture: confirm bidirectional packets and one exact Zeek row per
   tuple under the new filter, including a simultaneous unrelated flow.
5. Staged Model2 integration: exact session/run/measurement/episode, PCAP and
   Zeek binding for two overlapping SSH sessions, one HTTP transfer each,
   plus unrelated Pi HTTP. No cross-session flow may enter either envelope.
6. Long-duration smoke test: at least one several-minute session with its
   bound transfer still observed. Only then consider extending the 120-second
   receiver gate. Model-performance evaluation remains separate.

The Cowrie socket hook, Pi observer, GCP receiver, and backend ensemble
contract reader were subsequently deployed with V2 support. An overlapping
two-session test with unrelated Pi HTTP produced distinct session-bound
socket source ports; each result reported one exact episode flow and PCAP/Zeek
PASS. A fresh post-backend-restart test also returned VALID_SHADOW and one
observed transfer flow. The bridge accepted the V2 result. T1046 raw PRESENT
without an exact scan observation remained excluded by the ensemble
normalizer. These are operational smoke results, not evidence of better model
accuracy. The 120-second receiver limit remains unchanged, so long demo
sessions are not yet proven. Rollback uses the recorded narrow Pi/GCP source
backups and service restarts; the capture-only filter backup is separate.
