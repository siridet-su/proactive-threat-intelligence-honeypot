---
title: Installer VM Test Target — Ubuntu Server 24.04 ARM64
status: operator-preparing-test-target
last_verified: 2026-09-25
---

# Installer VM Test Target

This checklist prepares a disposable environment for the current **Pi host-foundation phase**. It is a VM setup specification, not an install script. The goal is to verify the base OS and Pi-side prerequisites before adding honeypot services, databases, or the web decoy.

## 1. Guest requirements

- OS: Ubuntu Server 24.04 LTS, ARM64 (`aarch64` guest). Use a full virtual machine with systemd, not a container.
- Recommended installer image for this generic ARM64 VM: `ubuntu-24.04.5-live-server-arm64.iso` from the [official Ubuntu 24.04.5 release directory](https://cdimages.ubuntu.com/ubuntu/releases/24.04.5/release/). Verify the ISO against `SHA256SUMS` in that directory before booting. This is a generic ARM64 server image; it does not emulate Raspberry Pi firmware or peripherals. The separate Raspberry Pi preinstalled image is for supported Pi hardware, not a generic VM install.
- If the physical VM host is x86-64, use QEMU ARM64 emulation. An x86-64 guest can check generic package-manager behavior, but it cannot validate the ARM64 target profile or ARM64 artifacts.
- Starting functional-test size: 2 vCPU, 4 GiB RAM, and 32 GiB disk. This is only a convenient test allocation; it is not a Raspberry Pi performance or sizing claim.
- Keep a VM console or recovery path available. Create a clean snapshot named `00-ubuntu-24.04-arm64-clean` after the first boot and before installing project dependencies.
- One NAT interface is enough for OS/package-source checks. Do not bridge the VM onto a public or production network. Add a separate isolated host-only interface later if the Zeek packet-capture test needs synthetic traffic.

## 2. Keep the image clean

For the initial baseline test, do not install Docker, Cowrie, Zeek, Redis, PostgreSQL, or project agents yet. Do not join a production ZeroTier network, copy API/database credentials, or reuse any Pi data. Keep the initial package state intact until its inventory is recorded; do not run `full-upgrade` as part of preflight.

The current phase covers:

1. Ubuntu release, architecture, systemd, apt/dpkg, time, disk, and recovery access.
2. A candidate base package set: `ca-certificates`, `curl`, `git`, Python 3, and Python virtual-environment support. Verify the actual package state on the clean VM before deciding what to install.
3. The ZeroTier ARM64 client/package and service/interface behavior, without joining a production network.
4. Proposed service identities, protected configuration paths, release layout, journald behavior, and read-only log access requirements.

The six Go-agent artifacts were cross-built as statically linked Linux ARM64 binaries; the Pi does not need the Go compiler/runtime. Keep Go and its module cache on a controlled build host. The project's Cowrie patch is based on a pinned 2.6.1-derived deployment, so test that exact revision; current Cowrie documentation lists Python 3.10+ and a virtualenv prerequisite but does not replace testing the pinned revision. [Cowrie installation requirements](https://cowrie.readthedocs.io/_/downloads/en/latest/pdf/)

Database and web work is deferred: Redis, MongoDB, PostgreSQL/Deception Core, Docker Compose, and Web-corp are not installed in this phase. Cowrie and Zeek services themselves are also deferred until the host foundation is accepted; only their base runtime/package questions are recorded here.

## 3. Known package and service questions

- ZeroTier's official Snap documentation lists ARM64 support, but the Snap channel refreshes automatically. Validate its service name, interface, and refresh/rollback policy in the VM before adopting it for a reproducible Pi installer. Do not put the network ID or enrollment secret in Git. [ZeroTier Snap documentation](https://docs.zerotier.com/snap/)
- Zeek publishes an Ubuntu 24.04 binary-package repository and marks Ubuntu 24.04 supported. Confirm that the selected repository has the needed ARM64 artifacts before pinning it. The official binary-package instructions install under `/opt/zeek`, whereas the repository's current `systemd-services/zeek.service` assumes `/usr/local/zeek`; do not enable that unit unchanged. [Zeek binary packages](https://github.com/zeek/zeek/wiki/Binary-Packages) and [Zeek OS support matrix](https://github.com/zeek/zeek/wiki/Zeek-Operating-System-Support-Matrix)
- Cowrie's current upstream requirement is Python 3.10+ with virtualenv support. The repository uses a version-pinned, older Cowrie-derived patch, so validate compatibility before fixing the package list or service account.
- Resolve file ownership before hardening the collector: it must read Cowrie and Zeek logs, while it should not need unrestricted root access. Define dedicated non-login identities and narrowly scoped groups/ACLs rather than reusing the development account.

## 4. Initial read-only evidence to send back

After the VM boots, send only the output of these commands. They avoid network IDs, credentials, and application data:

```sh
grep -E '^(ID|VERSION_ID)=' /etc/os-release
uname -m
dpkg --print-architecture
systemctl --version | head -n 1
apt-get --version | head -n 1
dpkg-query --version | head -n 1
timedatectl show -p NTPSynchronized --value
df -h /
df -i /
free -h
```

Then run the repository's read-only check from a clean checkout:

```sh
python3 scripts/pti_install.py preflight --profile deploy/profiles/pi-host-foundation-ubuntu-2404-arm64.json
python3 scripts/pti_install.py package-audit --profile deploy/profiles/pi-host-foundation-ubuntu-2404-arm64.json
python3 scripts/pti_install.py plan --profile deploy/profiles/pi-host-foundation-ubuntu-2404-arm64.json
```

The preflight checks compatibility and basic system tools only. `package-audit` reads installed/not-installed states from dpkg's local database; it does not run apt or decide that a candidate package should be installed. Neither command approves ZeroTier enrollment, Zeek/Cowrie activation, database services, or web exposure.

For the detailed pre-test steps and explicit host-foundation acceptance criteria, see the [Thai Word-ready installation manual](INSTALLATION-MANUAL-WORD-TH.md). Package installation there is for the disposable VM only, after snapshot and package-origin review; it has not yet been qualified on that VM.

## 5. Later acceptance boundary

The VM can validate Ubuntu packages, systemd units, filesystem permissions, ZeroTier client behavior, and ARM64 executables. It does not reproduce Raspberry Pi hardware sensors, physical NIC names, RF/network behavior, thermal readings, or real Pi performance. Those require a separate acceptance run on the selected Pi model after the VM phase passes.
