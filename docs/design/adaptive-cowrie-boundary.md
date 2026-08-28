---
title: Adaptive Cowrie boundary
status: target
last_verified: 2026-08-25
---

# Adaptive Cowrie boundary

## Decision boundary

Cowrie remains the SSH/Telnet transport, authentication emulator, session
owner, downloader/capture layer, and terminal-facing process. The adaptive
engine owns only synthetic virtual-world state and deterministic command
results.

```text
Cowrie session
  -> raw command gateway
  -> authenticated local adaptive transport
  -> deterministic engine
  -> stdout / stderr / exit status / virtual cwd
  -> Cowrie terminal
```

## Invariants

- No attacker command reaches a real Pi shell or subprocess.
- Persona facts are derived only from virtual world/session state.
- Each Cowrie session receives isolated virtual state and cleanup on disconnect.
- The gateway has a deadline, cancellation path, per-session admission limit,
  and bounded global capacity.
- AI or threat-intelligence output may inform an approved policy only; neither
  is permitted to become terminal output authority or block command execution.

## POC evidence retained elsewhere

The adaptive POC has demonstrated raw command handling, SSH exec behavior,
timeouts, Ctrl-C, idle timeout, backpressure, and a cooperative cancellation
checkpoint on loopback. These results are experiment evidence, not production
approval. Preserve the original POC status and transcript material until it is
migrated to `validation/evidence/`.

## Production acceptance gates

1. Pin the Cowrie version and maintain a reviewable patch series/fork.
2. Replace unauthenticated loopback HTTP with a Unix socket or authenticated,
   least-privilege local transport.
3. Run golden transcript suites for interactive and exec channels.
4. Verify disconnect, Ctrl-C, timeout, idle timeout, overload, and restart
   behavior.
5. Emit privacy-safe engine decision telemetry into the common event contract.
6. Demonstrate rollback to normal Cowrie before any live-listener switch.
