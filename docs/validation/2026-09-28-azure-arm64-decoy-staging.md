---
title: Azure ARM64 Docker decoy source staging
date: 2026-09-28
environment: disposable Ubuntu 24.04 ARM64 VM
commit: e719c9095c1a918c5801861652ce96bc68426880 source bundle
status: passed for staging and disposable loopback smoke; persistent activation not tested
---

## Objective

Stage Docker/Compose and reviewed decoy source on the clean sensor test VM
without credentials or a public listener, then perform a disposable ARM64
build and loopback smoke check.

## Procedure and observed result

- Built a Git archive from the clean commit's tracked decoy Compose and
  Web-corp/Deception Core contexts. The builder checks for dirty or unsafe
  archive members and emitted a SHA-256 digest. The Ansible playbook checked
  that digest on the controller before changing the VM.
- Verified the VM was Ubuntu 24.04 ARM64 with a completed Pi preparation
  marker and no running Docker/containerd service. Installed exact reviewed
  Ubuntu `docker.io` 29.1.3-0ubuntu3~24.04.2 and `docker-compose-v2`
  2.40.3+ds1-0ubuntu1~24.04.1. APT service-start policy prevented activation; the
  playbook then explicitly stopped and disabled Docker, its socket, and
  containerd.
- Staged root-owned source under a commit-named release directory and wrote
  a non-secret preparation marker. Installed an example and a blank actual
  `/etc/honeypot/decoy.env` owned by root with mode `0600`; no value was read
  or copied into the repository.
- Validated the base and optional public-Web-corp Compose files using
  synthetic placeholder values, without a Docker daemon. First Ansible run
  reported `changed=9`, `failed=0`; same-bundle retry reported `changed=0`,
  `failed=0`.
- Rebuilding the bundle from the same commit produced the same SHA-256.
- After the retry, Docker, Docker socket, and containerd were inactive and
  disabled. No listener was present on the decoy web, app, Core, or database
  ports checked. The private env remained root-owned mode `0600`.
- For a separate bounded build check, started Docker, built the Web-corp and
  Deception Core images from the staged source on ARM64, and inspected both
  images as Linux ARM64. A no-network Web-corp module import passed. A first
  Deception Core import failed because the isolated test omitted its required
  `/data` volume; repeating with a temporary in-container `/data` filesystem
  passed. No service container or host port was started. Docker, its socket,
  and containerd were stopped again after testing.
- A separate loopback-only Compose smoke run with synthetic temporary database
  input started PostgreSQL, Deception Core, and Web-corp. Web-corp login GET
  returned HTTP 200; the Core root route returned HTTP 404 while its container
  remained running. All three host mappings were loopback-only. The test then
  removed the disposable containers, network, and named volumes and stopped
  Docker. No credential-bearing login POST was sent.
- The smoke run revealed that Docker auto-created the empty Web-corp spool
  directory with overly broad default permissions when it was absent. The
  staging playbook now creates the parent and spool as `root:root` mode
  `0700` before any Compose start. Reapplying it changed only that permission;
  the spool was empty and Docker remained inactive afterward.

## Limitations

The images built and passed a short loopback smoke run, but sustained container
health, PostgreSQL data integration, app telemetry, and private credential
validation are untested. The Python base image resolved to a digest during
this test, but the Dockerfile still uses a mutable tag. The staged source belongs to the tested commit;
new commits require a newly reviewed bundle and release transition. This VM
result does not qualify the existing Pi for migration or a customer Pi for
public exposure.
