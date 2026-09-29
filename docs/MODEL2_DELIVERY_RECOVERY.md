# Model2 delivery recovery (2026-09-29)

Status: Pi queue monitoring and observer backpressure handling deployed on
2026-09-29; **not a network-authority bypass**. The GCP ZeroTier member was
rejoined at the operator's request and later returned to `OK`.

The Pi observer maintains a durable FIFO of sanitized Model2 envelopes. A
running observer/receiver does not prove delivery. If the first envelope is
unacknowledged, later envelopes remain queued. Never delete or reorder queue
files to make a demo result appear: event order and exact session binding
depend on them.

## Confirm the failure boundary

1. Check the Pi observer service and queue-health result. `CRITICAL` with
   `delivery_stalled` means the oldest envelope exceeded two minutes; it does
   not by itself prove why delivery failed.
2. Compare ZeroTier membership status on Pi and GCP. During the 2026-09-29
   outage, the Pi showed `OK` and GCP showed `ACCESS_DENIED`. A requested GCP
   `join` to network `633e31d8a21076ea` returned `200 join OK`; membership
   subsequently returned to `OK` and the queue drained from 105 to zero.
   A `join` response alone is not proof of authorization or connectivity.
   If denial recurs, an authorized network administrator must restore
   membership. Do not use a public raw TCP listener to bypass denial.
3. After the administrator restores membership, test TCP reachability **as
   the observer service account**, since the Pi firewall grants the Model2
   receiver connection to that UID only. Then watch the FIFO count fall and
   verify exact-session results/ACKs. Do not infer health from `active` alone.
4. If delivery stays stuck after connectivity returns, inspect the first
   envelope's metadata and receiver rejection/audit status without printing
   raw contents. A rejected envelope requires a separate, reviewed poison-item
   handling change; do not discard it manually.

The deployed queue-health probe reads file names and modification times only.
It does not parse envelopes or connect to the receiver. Its exit code is 0 for
`OK` or recent `PENDING`, and 2 for `CRITICAL` or `UNAVAILABLE`. The Pi
`model2-v7-pi-queue-health.timer` runs the probe and leaves a local systemd
status/journal signal; it is **not** a remote notification channel. Verify
the timer, last service result, observer service, oldest queue age and queue
depth together. A zero-depth queue does not prove the receiver accepted a
particular exact-session envelope; inspect its ACK/result separately.

The deployed V7 Pi observer rewinds its open Cowrie-log cursor on queue
pressure and retries pending session completion after space returns. It also
resumes eligible closed-session completion after an observer restart. Eight
targeted mechanics tests passed locally and as the Pi `cowrie` account;
systemd unit verification passed on Pi. This is **not** a complete no-loss
guarantee: restart after an unprocessed rotated Cowrie log is not proven
recoverable. Preserve rotated Cowrie logs and queue files during outages.
Do not delete or reorder a rejected FIFO item; a reviewed poison-item
protocol is still missing.

## Verified recovery boundary

- The original raw session `b3f484742c9a` eventually reached the receiver,
  but Model2 returned `MODEL2_UNAVAILABLE` / `episode_window_invalid` because
  its episode lasted about 26 minutes. Draining the queue cannot turn this
  past session into a valid Model2 result.
- A fresh short session `d60991273f5a` after the Pi observer deployment
  returned `VALID_SHADOW`, `AVAILABLE`, with one exact-bound flow and PCAP/Zeek
  binding `PASS`.
- A fresh short combined session `5c3e917ad299` (canonical
  `session_v1_6b8717924cbcfbfa422e80a79b363d99`) also returned
  `VALID_SHADOW` with PCAP/Zeek `PASS`. Its analysis completed with one
  evidence-bounded hypothesis set after transfer and same-path permission
  change. This proves the current short-session path can surface both Model2
  and hypothesis output; it is not a model-accuracy or long-session test.
- The combined session's T1105 was a Model2-only `PRESENT` signal, not a new
  trusted finding or an independently promoted recommendation. T1046 remained
  unavailable without scan evidence; T1110 was `ABSENT`.
- After the receiver ceiling was changed to 360 seconds, raw session
  `8139d4f231c8` (canonical
  `session_v1_cc415f638178ca3b91d04c6d889ef259`) lasted 151.5 seconds,
  downloaded two small HTTP files, and issued permission-change commands for
  each distinct path in Cowrie's simulated shell. It produced two separate
  evidence-bounded hypothesis sets (two
  connected chains) and one `VALID_SHADOW` Model2 result with two bound flows;
  session/run/PCAP/Zeek bindings all reported `PASS`. Both sets use the same
  policy question/template but concern different file paths; they are not
  two independent kinds of attacker intent.
- A near-limit raw session `0719657d6fdb` (canonical
  `session_v1_06f1fd7ffa6402092fb854bac986e41e`) lasted 329.7 seconds.
  Its one public HTTP transfer was observed in a V2 exact-socket episode;
  Model2 returned `VALID_SHADOW` with one flow and session/run/PCAP/Zeek
  bindings all `PASS`. The analysis job succeeded. This verifies a roughly
  5½-minute episode, not the exact 360-second boundary or heavy-traffic ring
  survival.

## Analytical limits that delivery recovery does not remove

The GCP receiver now rejects an episode longer than **360 seconds** (six
minutes), measured from earliest retained event/flow start to latest event/flow
end. The old 26-minute session remains invalid and is not reprocessed by this
change. The Pi public-HTTP ring remains 8 × 8 MiB and direct SSH PCAP metadata
is bounded to 8 MiB. If traffic overwrites the start of a session, the exact
SYN/PCAP/Zeek check fails closed; six minutes is a maximum eligibility window,
not a guarantee under arbitrary packet volume. The 54-feature Model2 artifact
and its controlled-synthetic performance claim have **not** been retrained or
validated for six-minute traffic. Never silently truncate events or claim
field accuracy from the extended window.

To generate two hypothesis sets without changing policy, use two different
artifact paths in one Cowrie session: `wget http://example.org/ -O
/tmp/pti_demo_a.txt`, `chmod 700 /tmp/pti_demo_a.txt`, then the same pair with
`/tmp/pti_demo_b.txt`, and close the session. A direct transfer event and
same-path chronology must actually be recorded for each path. A failed
download, ambiguous path, missing event or observed follow-on execution can
change the result; the system does not force a count of two.

Threat-hypothesis sets are independent of Model2 delivery. A direct Cowrie
transfer finding may exist while a follow-on hypothesis abstains because the
same-entity chronology, outcome or effect evidence is incomplete. Do not
relax this gate to fabricate a hypothesis.
