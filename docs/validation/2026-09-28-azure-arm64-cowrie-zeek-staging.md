---
title: Azure ARM64 Cowrie and Zeek dependency staging
date: 2026-09-28
environment: staging
commit: main uncommitted worktree
status: partial
---

## Objective

Prepare Zeek and the pinned Cowrie source on the disposable Ubuntu 24.04
ARM64 VM while keeping the public management SSH available and all honeypot
listeners inactive between tests.

## Procedure and observations

1. Installed the official Ubuntu 24.04 Zeek OBS repository with a
   SHA-256-pinned signing key and exact `zeek-8.0-core`/`zeekctl-8.0`
   version `1:8.0.10-0`. The first manual ZeekControl smoke start used the
   loopback capture interface but exposed Broker port `27760` and metrics
   port `9991` on all interfaces. Zeek was stopped immediately. No external
   traffic or collector integration was used.
2. Set `MetricsPort = 0` and `Env_Vars =
   ZEEK_DEFAULT_LISTEN_ADDRESS=127.0.0.1`, then verified ZeekControl `check`
   and `deploy`. During the second smoke start, `ss -lntp` showed Broker
   only at `127.0.0.1:27760`; no metrics listener was present. A local
   benign HTTP request produced a `conn.log` entry during the earlier
   loopback-capture smoke.
3. Added and applied `prepare-zeek.yml` to stage the exact packages,
   standalone `lo` node, loopback Broker configuration, disabled metrics,
   and a stopped/disabled `zeek.service`. A repeat run reported `changed=0`.
   Starting through systemd reported Zeek running with only loopback Broker;
   the unit was stopped again afterward. The final unit uses Zeek's PID file;
   a further start reported `Type=forking`, a nonzero main PID, and `active`;
   after stop it reported main PID 0 and `inactive`.
4. A clean checkout of Cowrie commit
   `575146bc6b24d70082527d66cd805d9bae0e0db4` exposed a malformed
   existing project CWD patch. The patch was regenerated against that
   exact commit. `git apply --check` and Python compilation of the two
   patched files passed. Two independent builds of the patched source
   archive had the same SHA-256.
5. Applied `prepare-cowrie.yml` with the approved archive SHA-256. It
   staged `/home/cowrie/cowrie`, a Python venv, and a non-login account.
   The first Ansible execution ended during venv preparation without a
   marker because the initial playbook did not write one early enough. The
   archive and two patched source files were hash checked on the VM, a
   `preparing` marker was recorded, and the corrected playbook resumed to
   `prepared`. The final repeat run reported `changed=0`, both patched
   source hashes matched, and `pip check` passed. No Cowrie service was
   created or started.

## Final observed runtime state

- `zeek.service`: inactive and disabled; `cowrie.service`: absent.
- Redis and all five Go sensor units remain inactive from the prior
  blank-configuration pause.
- No Cowrie SSH/Telnet, Zeek Broker, or Zeek metrics listener remains active.
  The management SSH listener remains available.
- The production Pi and Dashboard were not changed by this test.

## Limits and follow-up

Cowrie was staged only. The fresh-host sanitized JSON output boundary,
private configuration, service unit, log permissions, and safe listener
cutover are not implemented. Cowrie's direct Python requirements are pinned
by the source checkout, but the transitive dependency closure is not hash
locked. The VM test did not exercise a Cowrie session, collector/processor
delivery, Docker decoys, Go activation, or a production capture interface.
The first manual Zeek start briefly had public control/metrics listeners;
this exposure was corrected before the final staging and should not be
repeated. Do not apply the staging playbooks to the existing production Pi.
