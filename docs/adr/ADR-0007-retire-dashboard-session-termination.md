---
title: ADR-0007 — Retire Dashboard session termination
status: accepted
date: 2026-09-25
---

# ADR-0007 — Retire Dashboard session termination

## Context

Filesystem Activity exposed an Admin action that asked a Pi-hosted agent to
disconnect one Cowrie transport over Tailscale. Disconnecting a transport does
not prevent the client from reconnecting, while the Dashboard-to-Pi command
path adds service credentials, a host agent, a Cowrie hook, and a tailnet grant
to an evidence-oriented workflow.

## Decision

- Remove the Response tab, session-termination UI, Dashboard terminate API,
  client polling/controller, Pi response-agent, and Cowrie control-socket hook.
- Keep Filesystem Activity read-only, with Route Replay and Evidence as its
  Forensic Studio views.
- Keep Tailscale enabled for SSH/host administration; do not use it as a
  Dashboard-to-Cowrie response transport.
- Preserve existing `session_response_actions` data. Removing the capability
  does not authorize deleting historical action records.
- Treat evidence as source-backed: CWD changes do not prove file reads/writes;
  only show filesystem-operation claims when an authoritative source emits
  those events. Link command evidence to a hop only with exact session and
  timestamp/event provenance.
- Reintroducing a session-control action requires a new decision and a reviewed
  operational design.

## Consequences and rollout state

The Dashboard source no longer includes the terminate endpoint or Response
tab. On `pi-t`, the response-agent unit was stopped and disabled, its runtime
files, credentials, and dedicated service account were removed, and the Cowrie
control drop-in was removed.
Port 8788 was verified to have no listener. Cowrie was not restarted because
active TCP sessions were present; its running process may retain the previous
environment or hook until a later restart. The tailnet ACL was not changed from
the host and must be checked in the Tailscale Admin Console for any old TCP
8788 grant. Tailscale remains enabled for administration. The Dashboard source
change has not been deployed to production; a deployed older version may still
show the former control UI, but the Pi endpoint is unavailable.

The Evidence panel remains a placeholder in this change. The proposed content
and evidence-provenance boundaries are recorded in
[`FILESYSTEM-ACTIVITY-WORKING-STATE.md`](../FILESYSTEM-ACTIVITY-WORKING-STATE.md).

## Alternatives considered

- Keep the one-session disconnect control: rejected because it does not stop
  reconnection and retains an operationally complex control path in the
  evidence workspace.
- Disable all Tailscale access on the Pi: rejected because it would also remove
  the existing host-administration path.
- Delete historical MongoDB action records: rejected because feature retirement
  does not change evidence-retention policy.
