---
title: Reimaged Azure ARM64 fresh installer rehearsal
date: 2026-09-29
environment: staging
commit: a6bba68
status: partial
---

## Objective

Follow the fresh-install runbook from a clean Ubuntu ARM64 VM and verify that
the full installer prepares every component, pauses for operator credentials,
and can be rerun without opening a service or replacing private env files.

## Procedure

1. Connected to the reimaged Ubuntu 24.04.4 ARM64 VM through administrator
   SSH on TCP 22. Cloned the public repository over HTTPS at `1086c6d`.
2. Ran the read-only `preflight`, `package-audit`, and `plan` checks. Updated
   apt indexes and reviewed exact package candidates.
3. Built the five Go binaries as a reviewed ARM64 release; built the pinned,
   patched Cowrie source archive, matching sanitizer bundle, and decoy source
   bundle outside Git. Stored their SHA-256 values in a private non-secret
   reviewed vars file. Installed Ubuntu `ansible-core` for the VM's local
   controller and used a one-host local inventory with `lo` and TCP 2222/2223.
4. Ran `install_fresh_pi.py` with that inventory, reviewed vars, and
   `--passwordless-sudo`. Two Ansible 2.16 compatibility failures in the
   manifest verification path were fixed in repository commits `bb7cf7e` and
   `a6bba68`; both failures occurred before package or service mutation.
5. Pulled `a6bba68` and reran the same installer. It prepared and audited the
   Go release, staged blank private env skeletons, staged Cowrie, Zeek, and
   Docker/Compose decoys, filled only non-secret host values, and stopped at
   the private env gate. Repeated that command once more.
6. Checked private-file owner/mode, unit states, and listening sockets without
   printing any private env contents.

## Expected result

No fresh service starts before the operator supplies required private values.
The retry preserves the prepared release and filled non-secret env state.
Administrator SSH remains available on TCP 22.

## Observed result

Preparation and audit passed. The env gate reported only the missing
`MONGO_URI` needed by the processor and TI worker; it stopped before the
decoy password gate. The wrapper returned its documented pause exit code 2.
On retry the non-secret env filler reported `FRESH_ENV_UNCHANGED` and the same
pause. Six actual private env files were root-owned regular files with mode
`0600`. Redis, Zeek, Docker, and all five Go units remained inactive; Cowrie
had no installed active listener. SSH was still listening on TCP 22. B2
backup was not enabled.

## Metrics

- Guest: Ubuntu 24.04.4 LTS, ARM64, approximately 4 GiB RAM, 30 GiB root disk.
- Reviewed Go release manifest SHA-256:
  `a4137a22dc85bd98be9395fcac34a3d5bed5c0b3289ccf4afd6cd3d01a1e9c69`.
- Installer tests before the VM run: 39 passed and five subtests.
- Root filesystem after preparation: about 3.8 GiB used of 30 GiB.

## Limitations

No operator credential was supplied or printed. The test therefore did not
activate Cowrie, Zeek, PostgreSQL/Core/Web-corp, Redis, or Go services; it did
not verify Atlas writes, Dashboard reads, telemetry, Wi-Fi capture, public
exposure, or B2 upload/restore. Loopback `lo` is an isolated VM substitute for
the Pi's `wlan0`, not proof of physical network behavior. The retry's full
Ansible recap was not retained; the env filler and post-run service checks
support only the narrower repeatability claims above.

## Follow-up

Have the operator place a test-scoped write-capable Mongo URI and a fresh
PostgreSQL password in the staged private files on the VM. Rerun the same
installer, check immediate service/listener state, then exercise a synthetic
Cowrie-to-Atlas event and localhost Web-corp path. Keep B2 disabled until the
new owner supplies a separate write-capable destination.
