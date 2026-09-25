# PTI Honeypot Installation Manual

**Word-ready draft — copy this document into Word and apply Word Heading styles to the numbered headings.**

Document status: Pre-test installation draft; host-foundation commands are ready for VM validation, not yet approved for production hardware.

Target profile: Fresh Ubuntu Server 24.04 ARM64 Raspberry Pi sensor node.
Full target profile: `deploy/profiles/pi-sensor-arm64.json`.

Current phase profile: `deploy/profiles/pi-host-foundation-ubuntu-2404-arm64.json`.

Last updated: 25 September 2026.

## 1. Purpose

This manual describes the proposed installation order for the Proactive Threat Intelligence Honeypot modules. It separates the Raspberry Pi sensor from cloud-hosted dashboard and analysis services, distinguishes current services from future work, and identifies prerequisites that must be resolved before installation can be automated.

The current repository does not yet contain a production installer. The accompanying profile planner is read-only. Do not use this draft to replace services on an existing Pi or to make unreviewed firewall, SSH, package, or database changes.

## 2. Scope and Installation Status

The full installation target is a **fresh Ubuntu Server 24.04 ARM64 image** for a Raspberry Pi sensor node. The operator has selected this OS/release/architecture; the exact image build/checksum and supported Raspberry Pi model matrix still need qualification on clean hardware. Existing-device migration is a separate procedure and is not covered by this fresh-install profile.

The active implementation phase is narrower: validate the clean Pi host foundation, base package candidates, ZeroTier client behavior, and service identity/path contract. Web-corp and all database/data services are explicitly deferred until this phase is accepted. The complete ordered installation below is retained as the later target plan, not an instruction to install every module now. See the [VM test-target checklist](INSTALLER-VM-TEST-TARGET.md).

Current modules are not all packaged for independent installation. In particular, the decoy Docker Compose source remains outside this repository; several systemd units contain development-machine paths; and some module versions, host configuration, or secrets are provisioned outside Git. These are release blockers, not steps for the operator to guess.

### 2.1 Status labels

- **Current:** part of the documented live architecture; a fresh-node installation procedure still requires validation.
- **Optional:** supported module enabled only when its data, credentials, and exposure policy are approved.
- **External:** dependency hosted or provisioned outside this repository.
- **Future / excluded:** not installed or activated by the first profile.

## 3. Recommended Installation Order

| Order | Module | Target | Status | Dependency / gate |
|---:|---|---|---|---|
| 1 | Host OS and security baseline | Raspberry Pi | Required | Qualify the exact Ubuntu Server 24.04 ARM64 image build and baseline policy. |
| 2 | Private management network | Raspberry Pi | Required | Operator enrollment and ACL; keep credentials outside Git. |
| 3 | Redis event buffer | Raspberry Pi | Required | Internal-only binding and bounded stream settings. |
| 4 | MongoDB Atlas connection | External dependency | Required | Least-privilege runtime identity and protected URI file. |
| 5 | PostgreSQL and Deception Core | Raspberry Pi | Cowrie support | Internal-only; deployment source is outside this repository. |
| 6 | Zeek | Raspberry Pi | Current | Pin package/release and configure approved interfaces. |
| 7 | Cowrie SSH/Telnet | Raspberry Pi | Current | Pin version and patch series; stage before trap exposure. |
| 8 | Go collector | Raspberry Pi | Current | Requires Redis, Zeek, Cowrie; portable service unit is needed. |
| 9 | Go processor | Raspberry Pi | Current | Requires Redis and MongoDB Atlas; portable service unit is needed. |
| 10 | Web-corp HTTP login decoy | Raspberry Pi | Optional/current | Compose must first be brought under repository control; activate only this service. |
| 11 | TI worker | Raspberry Pi | Optional/current | Provider credentials, quota policy, Redis, and MongoDB Atlas. |
| 12 | Hardware metrics and retained-data backup | Raspberry Pi | Optional/current | Redis/MongoDB plus reviewed B2 policy and protected credentials. |
| 13 | Response agent | Raspberry Pi | Optional | Tailscale identity, ACL, and host firewall approval. |
| 14 | Dashboard and post-session analysis | GCP | Separate deployment | Different host, service identity, secrets, and release lifecycle. |

Install and validate dependencies before enabling their consumers. Do not enable every optional service just because its source or unit file exists.

## 4. Pre-Installation Checklist

1. Select a clean Ubuntu Server 24.04 ARM64 image for a supported Raspberry Pi model and record its exact image build and checksum.
2. Confirm console or other out-of-band recovery access before network or SSH changes.
3. Establish the approved administrative path and verify time synchronization, DNS, storage capacity, and network reachability.
4. Inventory existing listeners, systemd units, containers, data directories, and firewall rules. Stop if the device is not clean; use a separately reviewed migration plan instead.
5. Decide which optional profiles are required. Keep future/excluded modules disabled.
6. Provision database, provider, and archive credentials through the approved secret process. Never paste secrets into this manual, a command argument, or the repository.
7. Run the read-only plan command and review every blocker:

   ```text
   python3 scripts/pti_install.py preflight --profile deploy/profiles/pi-host-foundation-ubuntu-2404-arm64.json
   python3 scripts/pti_install.py package-audit --profile deploy/profiles/pi-host-foundation-ubuntu-2404-arm64.json
   python3 scripts/pti_install.py plan --profile deploy/profiles/pi-host-foundation-ubuntu-2404-arm64.json
   ```

The current preflight, package audit, and planner cannot install or change services. A passing host preflight checks only the selected OS/architecture and basic systemd/apt prerequisites; package audit reads only the local dpkg status database. Neither clears deployment blockers nor authorizes apply mode.

## 5. Module Installation Procedures

### 5.1 Host OS and Security Baseline

**Objective:** Prepare a supported, recoverable sensor host before installing honeypot services.

For the active host-foundation phase, follow the detailed disposable-VM procedure in §5.1.1. Create only the initial non-root administrator during OS installation; do not create application service users, change SSH/firewall policy, or install sensor services until their access and exposure gates have been reviewed.

1. Install the selected Ubuntu Server 24.04 ARM64 image and record its release, guest architecture, and checksum.
2. Verify time synchronization, storage, package-manager tools, failed services, and listeners without changing the host.
3. Audit package candidates on the clean image; install only the explicitly accepted base candidates in the disposable VM after taking a snapshot.
4. Record the service identity/path/log-access contract before creating runtime accounts or directories.
5. Save a sanitized installation receipt before continuing.

**Verification:** Confirm the OS release and architecture, administrative access, time, disk space, and clean service inventory.

**Rollback:** Restore the clean image or use the recorded host backup; do not attempt automatic migration of an existing Pi.

#### 5.1.1 Detailed host-foundation VM procedure — pre-test draft

This is the active phase for the disposable VM. The sequence is written now so it can be exercised as one pass when the VM is ready. The package-changing commands below have **not** yet been run on that VM. Do not use this section to upgrade or migrate the existing Pi.

**A. Image and VM preparation**

1. Use `ubuntu-24.04.5-live-server-arm64.iso` from the [official Ubuntu release directory](https://cdimages.ubuntu.com/ubuntu/releases/24.04.5/release/) and compare its SHA-256 with the directory's `SHA256SUMS` before booting.
2. This is the generic Ubuntu Server ARM64 installer. It validates Ubuntu userspace, apt/dpkg, systemd, and ARM64 packages, but does not reproduce Pi boot firmware or Pi-specific peripherals. Hardware acceptance remains a later step.
3. Create a full VM with 2 vCPU, 4 GiB RAM, and 32 GiB disk for functional tests. These are test allocations, not production sizing.
4. Use NAT for package-source access, keep a VM console/recovery path, and do not bridge to a public or production network. An x86-64 host needs an ARM64-capable emulator; confirm the guest itself boots as AArch64.
5. Install the minimal Ubuntu Server system and create a non-root administrator. Do not select project services or copy Pi data, credentials, ZeroTier identity, or production environment files into the VM.
6. After first boot and before project package changes, create snapshot `00-ubuntu-24.04-arm64-clean`.

**B. Capture the clean baseline (read-only)**

Run from the VM console or approved isolated admin session. Keep evidence outside Git; redact local addresses and MAC addresses before sharing it beyond the operators.

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
systemctl --failed --no-pager
ss -lntup
```

Expected: Ubuntu `24.04`, guest architecture `aarch64`/`arm64`, systemd, apt, and dpkg-query. Stop if the VM booted as AMD64, has no recovery console, or has unexplained failed services/listeners.

**C. Run the repository's read-only assessment**

From a clean checkout of this branch on the VM:

```sh
python3 scripts/pti_install.py preflight --profile deploy/profiles/pi-host-foundation-ubuntu-2404-arm64.json
python3 scripts/pti_install.py package-audit --profile deploy/profiles/pi-host-foundation-ubuntu-2404-arm64.json
python3 scripts/pti_install.py plan --profile deploy/profiles/pi-host-foundation-ubuntu-2404-arm64.json
```

- `preflight` checks OS/release/architecture and basic systemd/apt/dpkg-query availability only.
- `package-audit` reads installed/not-installed status for the profile candidates from the local dpkg database; it does not refresh apt indexes, inspect package origins, or install anything.
- `plan` should show the host-foundation profile. `install_enabled=false` and unresolved blockers are expected at this stage.

Save the output with the VM snapshot and checkout revision. Do not commit machine IDs, addresses, tokens, credentials, or host-specific full interface inventories.

**D. Review and install only the approved base-package candidates**

| Package | Purpose in this phase | State before VM test |
|---|---|---|
| `ca-certificates` | Validate TLS for approved artifact sources | Candidate; audit image and origin |
| `curl` | Bounded download/health checks where required | Candidate; audit image and origin |
| `git` | Retrieve reviewed source if the installation workflow needs it | Candidate; audit image and origin |
| `python3` | Host Python candidate for the pinned Cowrie compatibility test | Candidate; exact interpreter compatibility unverified |
| `python3-venv` | Isolated environment support for Cowrie | Candidate; validate against the pinned dependency lock |

After the clean snapshot and review of the current package state, refresh package indexes and inspect package origin/version:

```sh
sudo apt-get update
apt-cache policy ca-certificates curl git python3 python3-venv
```

If the operator accepts the origins and candidate versions, install only this explicit set in the disposable VM:

```sh
sudo apt-get install --no-install-recommends ca-certificates curl git python3 python3-venv
```

Do not substitute `full-upgrade`, `dist-upgrade`, an unreviewed third-party repository, or a broad `build-essential` bundle. Record what was newly installed; some packages may already be present in the image.

Verify the installed package records and Python venv support:

```sh
dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Status}\n' ca-certificates curl git python3 python3-venv
python3 --version
python3 -m venv --help >/dev/null
```

The clean VM result—not the development host's dpkg state—is the evidence for accepting this package list.

**E. Verify host health and exposure**

```sh
timedatectl show -p NTPSynchronized --value
df -h /
df -i /
systemctl --failed --no-pager
systemctl list-units --type=service --state=running --no-pager
ss -lntup
ip -brief address
ip route
```

Document unexplained failed units, listeners, unsynchronized time, or low disk/inode capacity; do not change SSH or firewall policy just to make output match. Preserve console recovery before investigating network changes.

**F. Dependencies intentionally not installed in this pass**

- **Go:** Keep Go toolchain and module cache on the controlled build host. The Pi is intended to receive reviewed static ARM64 artifacts, not build agents.
- **Cowrie/Python:** Python and venv are candidates only. Do not install Cowrie until the pinned revision, dependency lock, and patch series pass on the VM.
- **Zeek:** Do not install or enable it in this baseline pass. Confirm ARM64 artifacts and reconcile the package prefix with the tracked service unit first.
- **Docker/Compose, Redis, MongoDB, PostgreSQL/Deception Core, Web-corp:** Defer; they are outside the active host-foundation phase, and the complete Compose source is not controlled by this worktree.
- **Node.js/dashboard:** Keep dashboard build/runtime dependencies on the separate cloud/development target, not the Pi foundation profile.
- **Legacy sensor forwarder:** Do not add it to a fresh-node installation; its migration/retirement requires a separate parity decision.

**G. Optional ZeroTier test gate**

Do not install a VPN during the clean-image baseline. Once the baseline passes, the operator may select a ZeroTier client method for a dedicated test. Snap is an ARM64-capable candidate, but its refresh policy must be accepted before it becomes the reproducible installation method. Join and authorize only a disposable test network as an explicit operator action. Keep network IDs, node identity files, credentials, and API tokens out of Git. Record package version, service state, interface, route, and a permitted management-path check; write package-specific commands into the final runbook only after confirming them on the VM.

**H. Service identity and filesystem contract**

Do not create service accounts, change ownership, or apply ACLs until the per-service matrix is reviewed. It must identify the dedicated non-login user/group, root-controlled executable/config paths, owner-only secret files, bounded writable state, exact Cowrie/Zeek log read access, log rotation behavior, and systemd sandbox/restart/resource policy. Current tracked unit files contain deployment-specific paths/accounts and must not be copied unchanged. Record the accepted matrix before writing the Ansible role or enabling a service.

**I. Acceptance and rollback**

Accept host foundation only when the VM target facts, recovery path, baseline checks, package origins/versions, and service inventory are recorded; no broad OS upgrade was performed; any ZeroTier test used a disposable network; and no application/database/decoy/legacy-forwarder service was enabled. Restore the clean VM snapshot if package/network tests leave unclear state. Do not use `apt autoremove` or manual directory deletion as a substitute for snapshot rollback. Preserve a sanitized test receipt without secrets, node identities, raw event data, or unredacted network inventory.

**Not yet tested:** This procedure is prepared for the operator's VM. Record actual command outcomes and any corrections only after the clean VM run.

### 5.2 Private Management Network

**Objective:** Provide approved private access for administration and telemetry without exposing management services to attacker-facing interfaces.

1. Validate the ZeroTier ARM64 client and service with a test identity. Production network enrollment is an operator action and is not part of the clean VM image check.
2. Apply the reviewed network ACL and host firewall rules as separate controls.
3. Confirm administrative access through the intended private path before exposing any decoy port.
4. Store enrollment credentials in the approved system secret store; do not store them in the profile or manual. Tailscale response-control is a separate optional control-plane deployment and is not the Pi management network for this phase.

**Verification:** Confirm the device identity, assigned private interfaces, intended routes, and permitted management connections.

**Rollback:** Revoke the device identity or restore the prior reviewed ACL/firewall snapshot without disturbing unrelated services.

### 5.3 Redis Event Buffer

**Objective:** Provide private, bounded Redis streams for sensor ingestion and downstream workers.

1. Install Redis from the approved package source or approved deployment artifact after that source is selected for the profile.
2. Bind Redis to the approved local interface only; do not publish it to ZeroTier, the public network, or a decoy container network without an explicit reviewed need.
3. Apply stream-length, memory, persistence, and authentication settings from the approved runtime configuration.
4. Start Redis and confirm that it is healthy before installing the collector or processor.

**Verification:** Confirm service readiness, local-only listener, and the required stream configuration without printing event payloads.

**Release gate:** The canonical Redis installation/configuration source is not yet standardized in this repository.

### 5.4 MongoDB Atlas Connection

**Objective:** Allow the processor and explicitly selected workers to persist or read only the data they need.

1. Provision the reviewed least-privilege database identity and network access rule outside the installer.
2. Install the connection URI into a root-protected secret file using the approved secret-management process.
3. Configure only the services authorized to use that identity. Never pass the URI on a command line or include it in a release receipt.
4. Test connectivity using a health/readiness operation that does not print credentials or credential-bearing records.

**Verification:** Confirm TLS, authorized database access, and expected read/write scope.

**Rollback:** Revoke or rotate the runtime identity and restore the previous protected file atomically.

### 5.5 PostgreSQL and Deception Core Support

**Objective:** Provide the internal Cowrie support services documented in the current architecture.

1. Install the approved PostgreSQL and Deception Core artifacts from a versioned deployment source.
2. Bind these services to approved local interfaces only and provision their data/configuration directories separately from the web login telemetry store.
3. Apply the reviewed Cowrie integration configuration and database roles.
4. Start and validate these dependencies before starting Cowrie.

**Important:** Odoo is not part of the web-corp login path and is excluded. PostgreSQL/Deception Core are not substitutes for the Redis-to-MongoDB login telemetry pipeline.

**Release gate:** Their source and full Compose deployment are not yet tracked in this repository.

### 5.6 Zeek Network Sensor

**Objective:** Collect network observations from explicitly approved interfaces.

1. Install a pinned Zeek release whose OS/architecture compatibility is verified.
2. Configure the monitored interfaces and Zeek workers for the actual device; do not copy a development interface list blindly.
3. Install the reviewed Zeek configuration and the repository's systemd unit after its executable path is made portable.
4. Validate the Zeek configuration and deployment in a staging window before enabling the service.

**Verification:** Confirm expected workers are healthy and the collector receives synthetic or benign Zeek events.

**Release gate:** A versioned package source and portable configuration template are not yet part of the Pi install profile.

### 5.7 Cowrie SSH/Telnet Decoy

**Objective:** Present the approved virtual SSH/Telnet environment without executing attacker-controlled content on the host.

1. Obtain the reviewed, version-pinned Cowrie source and patch series.
2. Apply and test project patches only in a clean staging checkout, following `integrations/cowrie/README.md`.
3. Configure the virtual filesystem, event output, management socket, runtime account, and trap ports from reviewed templates.
4. Install a hardened, portable systemd unit and start a non-public staging listener first.
5. Run benign protocol and event-contract tests. Expose trap ports only after validation and a separate firewall review.

**Verification:** Confirm Cowrie events reach the collector, the management socket is private, and the host remains isolated from attacker payloads.

**Rollback:** Return to the previous pinned source/configuration and restore the prior service state; retain telemetry and virtual-world data unless an explicit retention procedure says otherwise.

### 5.8 Go Collector

**Objective:** Validate and forward Cowrie, Zeek, and approved web-login events into Redis.

1. Build the Go sensor release from a clean, reviewed checkout. The helper tests and cross-builds the six Go agents, writes `manifest.json` and `SHA256SUMS`, and does not install or activate them. Go dependency/toolchain downloads are disabled, so the approved toolchain and module cache must already be available. Example release label only:

   ```text
   python3 scripts/build_sensor_release.py --release-id 2026.09.25-rc1 --output-root /var/tmp/pti-release-staging
   ```

2. Review the source commit and every artifact checksum in the manifest. Checksums detect accidental changes but do not authenticate a release; signing and publication are still release gates.
3. Install the approved collector binary into an immutable release directory and install a portable systemd unit using the selected service account and protected environment files.
4. Configure input paths and Redis stream settings without including secrets in the release.
5. Validate the unit and configuration, then start only the collector service.

**Verification:** Check service health and Redis stream counters; do not print raw event payloads during routine verification.

**Release gate:** Current unit files include development-machine paths and require portable templates before clean-host installation.

### 5.9 Go Processor

**Objective:** Normalize Redis events, write canonical MongoDB records, and dispatch eligible TI jobs when explicitly enabled.

1. Use the same reviewed Go sensor release described in §5.8; verify the processor artifact's source commit and checksum before installation.
2. Install the portable service unit and shared/processor-specific protected environment files.
3. Configure MongoDB access, Redis consumer groups, retention, and queue bounds from the reviewed profile.
4. Keep threat-intelligence job production disabled unless the TI worker and its quota policy are configured.
5. Start the processor only after Redis, MongoDB connectivity, and the collector are ready.

**Verification:** Process a synthetic event and confirm the expected normalized record through a non-secret projection. Preserve credentials and raw event values in protected storage; do not paste them into Word or a ticket.

### 5.10 Web-corp HTTP Login Decoy

**Objective:** Serve the fake ERP login page and capture rejected login attempts through the canonical event pipeline.

1. Bring the decoy Compose source and sanitized service definition under repository/release control before automating installation.
2. Build only the `web-corp` image from `integrations/web-corp`; do not start the full Compose stack.
3. Mount the bounded, permission-restricted login spool and configure the collector/processor path.
4. Bind only the approved HTTP interface. Keep the app's internal container port unpublished on the host.
5. Start the HTTP service and verify the login page with a GET request before using synthetic values for a POST.
6. Confirm the event in Redis, MongoDB, and the authorized dashboard projection. Use a projection that omits submitted credentials.

**Verification:** Confirm `network.src_port` where available and validate the dashboard view; this field-level flow has been operator-confirmed in the current deployment.

**Release gate:** The Compose source currently lives outside this repository, and the Pi's direct HTTPS service is stopped. Do not activate HTTPS as part of this module.

### 5.11 Threat-Intelligence Worker (Optional)

**Objective:** Enrich only eligible, validated observables asynchronously.

1. Install the versioned worker artifact and portable systemd unit.
2. Create its private environment file and configure Redis stream/group/consumer values.
3. Add provider keys through the approved secret store; enable only the providers authorized for the account and its quota.
4. Enable processor job dispatch only after confirming worker readiness and queue bounds.

**Verification:** Use a controlled observable and confirm cache/quota behavior without uploading samples or printing keys.

**Disable:** Stop the worker and disable processor dispatch; preserve queued/evidence data according to policy.

### 5.12 Hardware Metrics Agent (Optional)

**Objective:** Publish bounded host metrics to Redis for the processor's live and minute-history projections.

1. Install the versioned ARM64 agent and portable systemd unit.
2. Configure only approved physical interfaces and the sensor identity.
3. Verify Redis stream limits and processor projection before enabling periodic collection.

**Verification:** Confirm a fresh bounded sample and one expected dashboard projection; do not treat raw counters as a durable audit log.

### 5.13 Retained-Data Backup Worker (Optional)

**Objective:** Archive explicitly approved MongoDB retention sources to the private object-storage target.

1. Approve each collection, sensitivity level, retention window, destination prefix, and restore owner.
2. Create a least-privilege upload credential outside the repository; do not grant delete permission to the upload worker.
3. Install the worker and control/scheduled units with private configuration and bounded temporary storage.
4. Run a dry-run or small approved staging archive, verify its manifest/hash, and rehearse restore before enabling the timer.

**Verification:** Review target status, manifest counts, object hash, and retention policy without exposing event payloads. Keep sensitive login data disabled for archival unless separately approved.

### 5.14 Response Agent (Optional)

**Objective:** Permit only the reviewed session-termination action through the private management network.

1. Provision the tagged dashboard and Pi identities and pass the tailnet policy test.
2. Store the service credential in the approved protected file/credential mechanism.
3. Install the hardened unit bound only to the Pi's Tailscale address and the exact approved port.
4. Apply the matching narrow host-firewall rule and run a synthetic-session end-to-end test.

**Verification:** Require a verified action record and the matching Cowrie closure event. The agent must not expose shell, arbitrary command, generic container-control, or Docker-socket access.

### 5.15 Dashboard and Post-Session Analysis (Separate GCP Deployment)

1. Follow the GCP deployment runbook and use a separate cloud inventory and service identity.
2. Install the exact application release, systemd units, environment templates, and credentials for the selected GCP services only.
3. Validate health and authentication boundaries before routing an operator to the dashboard.
4. Validate MongoDB projections and analysis outputs using non-sensitive test data.

Do not install dashboard or analysis services on the Pi profile. Do not copy the Pi's private configuration or secrets to the cloud host.

## 6. Post-Installation Acceptance Checks

1. Confirm the host, network, Redis, Cowrie, Zeek, collector, and processor services match the selected profile.
2. Confirm there are no unexpected listeners and that Redis, PostgreSQL, and Deception Core remain private.
3. Send synthetic Cowrie and Web-corp test events only in the authorized test window.
4. Confirm collector acceptance, processor persistence, and the expected dashboard projection without returning credential-bearing fields.
5. Confirm optional services are enabled only when selected and approved.
6. Save a sanitized receipt containing profile ID, release/build IDs, checksums, enabled modules, validation outcomes, and rollback reference—but no secrets or raw attacker data.

## 7. Rollback and Removal

1. Stop only the service or module being rolled back.
2. Restore its previous versioned release and exact prior unit/configuration from the recorded backup.
3. Revalidate dependent services before restoring traffic.
4. Preserve telemetry, database records, secrets needed for recovery, and Cowrie data by default.
5. Do not delete volumes, purge databases, or reset firewall/SSH configuration automatically. Any purge requires a separate explicit approval and verified backup.

## 8. Future Work — Not Installed by the First Profile

- OpenCanary HTTP: prepared for loopback staging but stopped; local JSONL only and no central event adapter.
- FTP and SMTP: source is tracked, but both are stopped and lack the approved canonical database/dashboard integration.
- Odoo: stopped and not part of login capture.
- Direct Pi HTTPS: stopped; trusted public-VPS HTTPS is a separate future deployment.
- Customer appliance enrollment/outbound gateway: requires the control-plane phases and release-signing gates in the Installer Blueprint.
- Legacy sensor forwarder: do not expand on fresh installs; migration/retirement needs a separate parity plan.

## 9. Repository Gaps Before This Manual Can Become an Automated Installer

1. Qualify the exact Ubuntu Server 24.04 ARM64 image build/checksum and supported Raspberry Pi model matrix on clean hardware.
2. Move the active Docker Compose source and sanitized service definitions into repository control.
3. Replace development-path systemd units with portable templates and explicit service accounts.
4. Pin and publish all required Redis, PostgreSQL/Deception Core, Zeek, and Cowrie artifacts; validate, sign, and publish the Go-agent release bundle.
5. Define module config schemas and secret provisioning without embedding values.
6. Test fresh installation, repeat/idempotent plan, failure rollback, and power-loss behavior on a clean ARM64 device.
7. Only then implement an explicit apply mode and promote this draft to an executable runbook.

## 10. Module References

- Architecture and lifecycle: `docs/CURRENT-ARCHITECTURE.md`, `docs/SERVICE-CATALOG.md`
- Cowrie patch/staging: `integrations/cowrie/README.md`
- Web-corp HTTP and data retrieval: `integrations/web-corp/README.md`, `integrations/web-corp/DATA-ACCESS.md`
- Threat-intelligence worker: `agents/ti-worker/README.md`
- Hardware metrics: `agents/hardware-agent/README.md`
- Retained-data backup: `agents/hardware-backup/README.md`
- Private response control: `integrations/tailscale/README.md`, `agents/response-agent/README.md`
- GCP systemd deployment: `honeypot-analysis/deployment/systemd/README.md`
- Future customer appliance: `docs/HONEYPOT-PORTAL-INSTALLER-GUIDE.md`
