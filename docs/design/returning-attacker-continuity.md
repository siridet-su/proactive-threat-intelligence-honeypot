---
title: Returning-attacker filesystem continuity
status: future
last_verified: 2026-09-15
---

# Returning-attacker filesystem continuity

## Decision

Keep the current reset-per-login Cowrie filesystem as the production default.
Add returning-attacker continuity only as a bounded, feature-flagged overlay
after the prerequisites and acceptance gates in this document pass.

The target is continuity of selected deception state, not persistence of a real
machine. A returning actor may see directories, filenames, current working
directory, and small synthetic text files from an earlier session. The system
must never restore real processes, malware execution, cron jobs, services, or
host filesystem changes.

## Why this remains future work

Continuity may improve deception quality by making a returning attacker believe
they reached the same host. It may also connect behavior across multiple
sessions. Implementing it before actor identity and resource controls are
stable creates larger risks than the added intelligence value:

- Source IP alone is not an actor identity; NAT can merge unrelated users and
  bot infrastructure can change IPs.
- Persisted attacker files can become an unbounded storage or malware-retention
  path.
- State shared with the wrong actor leaks deception history and breaks the
  persona.
- Concurrent sessions can overwrite each other's virtual state.
- Corrupt state must not prevent Cowrie from serving the clean baseline.

## Current behavior

For the active `backend = shell` deployment, each new authenticated avatar
creates a new Cowrie server and loads a fresh virtual filesystem from the
configured pickle image plus `honeyfs` content. Virtual directories and files
created during that login live in the session's in-memory filesystem and are
not serialized on logout.

The following data persists independently and must not be confused with a
persistent virtual filesystem:

- `AuthRandom` authentication state and its bounded credential cache;
- session, command, CWD, and file-transfer telemetry;
- captured upload/download artifacts handled by the existing hash-only
  retention policy.

## Prerequisites

Complete these items before implementing the overlay:

1. **Cowrie runtime ownership invariant**
   - Codify the owner and mode of mutable Cowrie state paths in deployment
     automation.
   - Add a service preflight that fails clearly when the Cowrie service user
     cannot read and write its required state.
   - Add an authentication smoke test covering first failure, second failure,
     third distinct-combination success, and returning credential success.
2. **Version-pinned Cowrie boundary**
   - Convert live customizations into a reviewable patch series against a
     pinned Cowrie version.
   - Pass interactive, exec, disconnect, restart, timeout, and rollback golden
     transcripts on a non-public listener.
3. **Stable session and actor-correlation contract**
   - Define an opaque local continuity namespace that does not use raw IP alone.
   - Never copy plaintext credentials into the overlay store.
   - Prefer a keyed/HMAC-derived identifier from approved normalized signals;
     when confidence is insufficient, start from a clean baseline.
4. **Canonical filesystem telemetry**
   - Preserve session ID, normalized virtual path, operation, timestamp, and
     outcome for create, write, rename, and delete operations.
   - Keep observed operations separate from reconstructed overlay state.
5. **Retention and resource budget**
   - Approve per-actor and global quotas, TTL, cleanup behavior, and disk-full
     failure handling.
   - Keep captured artifact bytes under the existing artifact policy rather
     than duplicating them in the overlay.
6. **Isolation and corruption recovery tests**
   - Prove that two actors cannot see one another's overlays.
   - Fall back to the immutable baseline when an overlay is missing, expired,
     malformed, or from an incompatible schema version.

## Deferred prerequisite backlog

This workstream is paused while the team improves the Dashboard Filesystem
experience. Resume the Pi/control-plane work in this order before implementing
returning-attacker continuity:

1. **Prevent Cowrie state-ownership regressions**
   - Move the live `auth_random.json` owner/mode invariant into versioned
     deployment automation instead of relying on a one-time Pi repair.
   - Add an authentication smoke test covering two rejected distinct
     combinations, third-combination success, returning success, and readable/
     writable state as the Cowrie service user.
2. **Pin and package the Cowrie boundary**
   - Pin the deployed Cowrie version.
   - Convert live source customizations into a reviewable patch series.
3. **Complete golden runtime transcripts**
   - Cover interactive login, SSH exec, disconnect, Ctrl-C, timeout, restart,
     overload, and rollback on a non-public listener.
4. **Stabilize the response-action contract**
   - Separate the allow-listed executor from its Tailscale HTTP transport.
   - Add versioned schemas and durable idempotency before building the outbound
     WSS gateway or packaging the customer appliance.
5. **Define actor identity and filesystem telemetry**
   - Do not use source IP alone as continuity identity.
   - Emit canonical create, write, rename, delete, CWD, and outcome events before
     reconstructing persistent overlays.
6. **Approve retention and resource budgets**
   - Set TTL, per-actor/global quotas, cleanup, disk-full behavior, and artifact
     boundaries before enabling any overlay implementation.

The resume point is item 1. Do not start with the overlay, WSS gateway, or
container packaging while these prerequisites remain open.

## Allowed continuity scope

The first experiment may persist only:

- normalized directory entries below the actor's virtual home;
- normalized filenames and basic synthetic metadata;
- the last valid virtual CWD;
- small UTF-8 text content created through approved emulated commands;
- tombstones for files from the actor's own overlay.

It must not persist:

- process tables, background jobs, shell memory, environment secrets, cron, or
  service state;
- executable payload bytes or captured malware;
- real host paths, file descriptors, device nodes, sockets, or mount state;
- arbitrary `/etc`, `/proc`, `/sys`, or `/dev` mutations;
- data from another tenant, device, actor namespace, or expired overlay.

## Candidate resource limits

These are conservative experiment defaults, not approved production values:

| Limit | Candidate default |
| --- | --- |
| Overlay TTL | 24 hours after last verified session |
| Entries per actor | 128 files/directories |
| Text per file | 32 KiB |
| Total text per actor | 512 KiB |
| Total overlay store | 64 MiB on the Pi |
| Concurrent writers per actor | 1, with explicit conflict handling |

Crossing a limit must produce a believable virtual filesystem error and a
bounded telemetry event. It must not write outside the overlay or affect the
Cowrie service process.

## Proposed state flow

```text
session authentication
  -> resolve high-confidence opaque continuity namespace
  -> load immutable filesystem baseline
  -> validate and apply bounded actor overlay
  -> run isolated virtual session
  -> journal allowed virtual filesystem mutations
  -> atomically commit a versioned overlay on clean/forced disconnect
  -> expire by TTL and global quota policy
```

Use a versioned operation journal or versioned overlay document rather than
serializing Cowrie's entire in-memory object graph. All paths must be
canonicalized as virtual paths before storage. Symlinks must never escape the
virtual namespace.

## Feature flag and failure behavior

- Default: `returning_attacker_continuity = false`.
- Enable only on a non-public staging listener during the first experiment.
- A load/validation/storage failure starts the session with the clean baseline
  and emits a bounded error event.
- Cowrie availability must not depend on the overlay database.
- Disabling the flag immediately returns all new logins to baseline behavior
  without deleting retained evidence.

## Acceptance gates

1. The same test actor sees an allowed directory and small text file after a
   reconnect.
2. A different actor never sees that overlay, including actors behind the same
   NAT address.
3. Expired overlays return to the clean baseline.
4. Path traversal, symlink escape, oversized content, excessive entries, and
   malformed UTF-8 are rejected safely.
5. Uploaded/downloaded artifact bytes are not copied into overlay storage.
6. Concurrent-session conflicts are deterministic and tested.
7. Power loss during commit leaves either the previous valid overlay or the new
   valid overlay, never a partial document.
8. Corrupt or incompatible state does not prevent login.
9. CPU, memory, and disk use remain inside the approved Pi budget.
10. Golden transcripts prove that disabling the flag reproduces the current
    reset-per-login behavior.

## Delivery sequence

1. Record an ADR for actor correlation, storage schema, and retention policy.
2. Implement a deterministic overlay library independent of Cowrie transport.
3. Add unit/property tests for paths, quotas, merging, expiry, and corruption.
4. Integrate behind the disabled feature flag on a non-public Cowrie listener.
5. Run repeat-session and isolation fixtures, then collect deception-quality
   evidence.
6. Promote only if the measured continuity benefit justifies the operational
   and privacy cost.

This work must not block the current control-plane, telemetry, and adaptive
Cowrie production gates.
