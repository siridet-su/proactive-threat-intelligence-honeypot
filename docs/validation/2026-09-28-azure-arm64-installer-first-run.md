---
title: Azure ARM64 installer first run
date: 2026-09-28
environment: staging
commit: main uncommitted worktree
status: partial
---

## Objective

Exercise the current one-command Pi Go-agent installer on a fresh Ubuntu
24.04 ARM64 guest and verify that missing operator values stop activation and
that a same-release retry preserves private files.

## Procedure

1. Verified Ubuntu 24.04, `aarch64`, 2 vCPU, approximately 4 GiB RAM, 30 GiB root
   filesystem, administrator SSH, and passwordless sudo. Refreshed the Ubuntu
   apt index and reviewed candidates for the four pinned packages.
2. Verified the locally built five-agent ARM64 release and approved manifest
   SHA-256 before installing. The release ID was
   `bootstrap-e2e-20260928`; the manifest SHA-256 was
   `8cc5c480bc6a8be09a5666313eef27c55badd96644e555f1716a9e46bb13deaa`.
3. Ran `python3 scripts/install_pi_sensor.py --inventory <private-inventory>
   --vars <reviewed-vars> --passwordless-sudo` against the disposable VM. The
   local Ansible process needed an approved unsandboxed execution path because
   its RPC server failed to start inside the tool sandbox. The controller's
   unsafe system SSH config include was bypassed with `-F /dev/null` in the
   private inventory.
4. Inspected owner/mode, SHA-256 hashes, and service states without printing
   env file contents. Re-ran the same installer command and repeated those
   checks.
5. Copied the read-only Redis checker into the VM's temporary directory and
   checked `/etc/redis/redis.conf`. Ran `systemd-analyze verify` on the five
   installed unit files without starting the services.

## Expected result

Prepare and audit pass; five examples and five actual blank env files are
created root-owned with mode `0600`; missing values pause activation; same
release and file retry does not replace private files or start services.

## Observed result

The first prepare recap had `changed=10`; the installed release, exact package
versions, units, and prepared marker passed audit. Staging created ten env
files and had `changed=12` including its other state tasks. Activation failed
at the value-redacting required-key check as expected. Redis and all five Go
units were inactive and disabled. On retry, preparation exited at the prepared
marker, audit passed, staging reported `changed=0`, and activation again paused
at the same env gate. All five private-file hashes and owner/mode checks were
unchanged across the retry.
The independent Redis loopback/protected-mode check and systemd unit
verification both passed.

## Metrics

- First run: prepare `ok=36 changed=10`; audit/staging cumulative recap
  `ok=68 changed=12`; activation gate failed before service start.
- Retry: staging cumulative recap `ok=44 changed=0`; activation gate failed
  before service start.
- Five Go units and Redis: inactive and disabled after both runs.

## Limitations

No clean snapshot was verified. No real credentials were supplied. Cowrie,
Zeek, Docker decoys, Dashboard, and any project listener were not installed or
started. Symlink rejection, interrupted preparation, rollback, successful
activation, Mongo/B2 access, telemetry delivery, and backup restore were not
tested. Azure VM sizing and public SSH management differ from an isolated
Raspberry Pi production environment. No private address, key, env contents,
or attacker data are included here.

## Follow-up

Use a fresh snapshot or disposable VM for failure-path tests, then add
versioned Cowrie/Zeek and decoy installers and test full activation with
operator-provisioned nonproduction credentials.
