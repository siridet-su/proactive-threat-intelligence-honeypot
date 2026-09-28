# Fresh Pi preparation — first Ansible slice

Status: **first prepare, blank-env pause, and unchanged-file retry passed on a
disposable Ubuntu 24.04 ARM64 VM; not qualified for a production Raspberry Pi**.
The resumable entry point builds a missing
Go release, prepares the host, checks operator configuration and prerequisites,
and activates the five Go units only when its gates pass. It is not a complete
Cowrie, Zeek, decoy, or Dashboard installer.

## One command to resume the current Pi slice

From the build/control host, keep a **non-secret** reviewed vars JSON and a
single-host inventory outside Git. Set the release ID, absolute release path,
and exact Ubuntu package versions as shown in `install-vars.example.json`.
`pti_manifest_sha256` can stay a placeholder for the first build; the command
will build the release, print its SHA-256, and pause. Review the bundle and put
that digest into the vars file. Then run the **same command** again:

```sh
python3 scripts/install_pi_sensor.py \
  --inventory /path/to/private-inventory.ini \
  --vars /path/to/reviewed-install-vars.json
```

The command asks once for the target administrator's `sudo` password when it
reaches Ansible. Use `--passwordless-sudo` only when that account already has
approved passwordless sudo. Ansible still executes target changes with
`become: true`; the password is not stored in the vars file or release.

The command verifies the approved release, calls the existing Ansible prepare
playbook, audits the installed hashes/packages, and places the
[blank examples](env-examples/) on the Pi as
`/etc/honeypot-agent.env.example` and `/etc/honeypot/*.env.example`. It also
creates the matching actual `.env` files from those blank examples **only if
they do not exist**, with `root:root` ownership and mode `0600`. It then checks
the `.env` files and Redis binding, and requires Cowrie and Zeek already
running before starting Redis and the five Go units. Missing values or
prerequisites pause the workflow without enabling Go units. Fill the actual
`.env` files on the Pi with `sudoedit`, then rerun the same command. Existing
actual `.env` contents are never read or replaced by the staging step;
existing example files are preserved on retry. A prepared release
with the same ID and digest is reused, so a retry does not stop running
services or copy the release again. A different release is rejected; upgrades
need their own reviewed procedure. If a new Go unit fails during activation,
units started by that attempt are stopped and disabled. Check service logs and
rerun after fixing the cause.

The Go activation check verifies file shape and immediate process state. It
does not prove Mongo/B2 credentials, telemetry delivery, scheduled backup
execution, or recovery. The clean VM acceptance run must check those before
production use. Cowrie, Zeek, and Docker decoys have separate **staging**
playbooks below; decoy activation and Dashboard installation remain pending.

## Stage Docker decoy source on the ARM64 test sensor

The separate `prepare-decoy.yml` playbook installs reviewed exact Ubuntu
`docker.io` and `docker-compose-v2` versions, copies a SHA-256-approved Git
source bundle, installs `/etc/honeypot/decoy.env.example`, and creates
`/etc/honeypot/decoy.env` from that blank template only if absent. It also
creates the Web-corp login spool with root-only directory permissions before
Docker can create a broad default bind-mount directory. Docker,
its socket, and containerd are left stopped and disabled. Images are not built
and no container or listener is started. It requires a prepared Pi marker and
refuses a running Docker host or an unmarked source release.

On the controller, commit reviewed source first and build the bundle. Record
the reported commit and digest outside Git. On the target, review exact
package versions with `apt-cache policy docker.io docker-compose-v2`. Supply
the bundle path, digest, commit, and versions as non-secret Ansible variables:

```sh
python3 scripts/build_decoy_bundle.py --output /path/to/decoy-source.tar.gz
ansible-playbook -i /path/to/private-inventory.ini \
  deploy/ansible/prepare-decoy.yml \
  -e @/path/to/reviewed-decoy-vars.json
```

The JSON keys are `pti_decoy_archive`, `pti_decoy_sha256`,
`pti_decoy_commit`, `pti_docker_version`, and `pti_compose_version`.
No credential belongs in this vars file. The playbook checks the approved
bundle hash and validates both Compose files with synthetic placeholder
values, without reading the operator env. A same-bundle retry is idempotent;
a different bundle requires a reviewed release transition. On the disposable
Ubuntu 24.04 ARM64 VM, the first staging run passed and the repeat reported
`changed=0`; see [evidence](../../docs/validation/2026-09-28-azure-arm64-decoy-staging.md).
An additional disposable VM check built both application images and started
the three-service Compose stack briefly on loopback with synthetic input;
it was fully stopped and its test volumes removed. This is evidence for
ARM64 build and basic startup, not an activation step in the playbook.

This stage does not build images, prove image base digests, activate Docker,
validate private credentials, or install the Dashboard. The one-command Go
wrapper does not invoke this playbook yet; it still requires Cowrie and Zeek
to be staged separately. Leave public trap ports closed until later
activation and synthetic acceptance checks pass.

## Stage Zeek and Cowrie on a prepared test sensor

The Zeek playbook uses the [official Zeek Ubuntu package repository](https://github.com/zeek/zeek/wiki/Binary-Packages),
checks the signing-key SHA-256, installs the reviewed `1:8.0.10-0` ARM64
Zeek/ZeekControl packages, and writes a single standalone capture interface.
Supply an interface that exists on the target. The disposable VM test used
`lo` for an isolated smoke test; a real Pi needs a reviewed capture interface.
The playbook disables Prometheus metrics and binds the Broker control port to
loopback. It stages `zeek.service` stopped and disabled, refuses to reconfigure
a running Zeek process, and does not modify the host firewall or SSH. The
staged unit follows Zeek's PID file so systemd reports the actual process.

```sh
ansible-playbook -i /path/to/private-inventory.ini \
  -e pti_zeek_interface=lo deploy/ansible/prepare-zeek.yml
```

Use an exact, clean upstream Cowrie checkout at commit
`575146bc6b24d70082527d66cd805d9bae0e0db4`. The builder checks the
revision and clean state, applies the project CWD patch, and emits a
deterministic archive. Review the printed archive digest before passing it to
Ansible. The source archive remains on the controller outside Git.

```sh
python3 scripts/build_cowrie_source.py \
  --checkout /path/to/clean-cowrie-checkout \
  --output /path/to/approved-cowrie-source.tar.gz
ansible-playbook -i /path/to/private-inventory.ini \
  -e pti_cowrie_archive=/path/to/approved-cowrie-source.tar.gz \
  -e pti_cowrie_sha256=REPLACE_WITH_REVIEWED_DIGEST \
  deploy/ansible/prepare-cowrie.yml
```

Cowrie's venv uses the checkout's pinned direct requirements; transitive
Python packages are resolved online and are not yet hash locked. The playbook
verifies the patched source hashes and `pip check`, then leaves Cowrie inactive
without a service or listener. **Do not start Cowrie from this staged source.**
The fresh-install sanitized output bundle, private config, log permissions,
service unit, and safe listener cutover still need an accepted installer.
The existing sanitized-output installer is for a running legacy deployment
and must not be used as a fresh-host shortcut. The one-command Go wrapper
does not invoke either staging playbook yet, so run them separately on the
reviewed test host before attempting Go activation.

The [first ARM64 VM result](../../docs/validation/2026-09-28-azure-arm64-installer-first-run.md)
covers preparation and the expected blank-env pause only. Activation and
the full installer have not been tested. Separate Cowrie/Zeek staging is
recorded in the [dependency VM result](../../docs/validation/2026-09-28-azure-arm64-cowrie-zeek-staging.md).
On that controller, Ansible's
local RPC server could not start inside the tool sandbox, so the run used the
approved unsandboxed execution path. An unrelated unsafe system SSH config
include required `-F /dev/null` in that test inventory's SSH arguments; this
is a controller-specific workaround, not a Pi installer requirement.

The accepted boundary is [ADR-0009](../../docs/adr/ADR-0009-installer-operator-managed-credentials.md).
The prepare playbook installs `ca-certificates`, Python 3 and venv support, and Redis;
uses apt's service-start policy to prevent Redis from starting during package
installation, then leaves it stopped and disabled; creates the dedicated
`pti-agent` identity and
non-secret directories; verifies and copies one local Linux ARM64 release;
and installs five Go service units in the stopped/disabled state. The later
staging playbook creates blank private `.env` skeletons only when absent and
never overwrites or backs up completed files. It does not change
SSH, firewall, trap ports, network membership, or Dashboard services.

## Prepare a disposable target

1. Start with a clean Ubuntu 24.04 ARM64 VM with a recovery console. Validate
   OS, architecture, package source, and administrator SSH separately. Do not
   target the existing `pi-t` host or a customer Pi yet.
2. Build the Go bundle from a clean checkout on a Linux x86-64 or ARM64 build
   host with internet access. The bootstrap script checks base tools, uses
   `sudo apt-get` for missing tools on Ubuntu 24.04, installs checksum-pinned
   Go 1.26.3 under the invoking user's data directory if needed, and downloads
   Go modules. It then invokes the existing builder, which runs each module's
   tests and disables downloads during the release build. Run `--check` first
   to see what this build host needs. No Go toolchain is installed on the Pi.
   Record the printed `Manifest SHA-256` with the reviewed release receipt;
   this digest must come from that trusted build record, not from a changed
   bundle discovered during installation:

   ```sh
   bash scripts/bootstrap_sensor_build.sh --check
   bash scripts/bootstrap_sensor_build.sh --release-id r1 --output-root /tmp/pti-releases
   python3 scripts/verify_sensor_release.py --release-id r1 \
     --release-dir /tmp/pti-releases/r1 --manifest-sha256 'REPLACE_WITH_APPROVED_64_HEX_DIGEST'
   ```

   The Go archive hashes are pinned to the [official Go downloads](https://go.dev/dl/).
   The bootstrap supports non-Ubuntu Linux hosts when the base tools are
   already installed; it never runs a different distribution's package
   manager. Each release ID needs a new output directory entry, because the
   builder refuses to overwrite an existing bundle. A failed network download
   does not produce a release. The bootstrap only prepares the build host;
   `redis-cli`, Cowrie, Zeek, and runtime services belong to later host steps.

3. Copy `inventory.example.ini` to an inventory outside Git and add the VM's
   management address and administrator account. Keep passwords and private
   keys out of the inventory. Copy `install-vars.example.json` to a reviewed
   vars file outside Git. Fill in the absolute release path, release ID,
   approved manifest digest, and exact versions of the four Ubuntu packages.
   Review versions and origins on the clean VM with `apt-cache policy` before
   filling in that file; the playbook refuses placeholders or missing versions.
   This vars file has no credentials.
4. Run Ansible from the build/control host. Review the target and release
   before the second command; no production Pi is an
   approved target yet:

   ```sh
   ansible-playbook -i /path/to/private-inventory.ini deploy/ansible/prepare-pi.yml \
     --syntax-check
   ansible-playbook -i /path/to/private-inventory.ini deploy/ansible/prepare-pi.yml \
     -e @/path/to/reviewed-install-vars.json
   ```

   The playbook fails before mutation if the OS/architecture is wrong, the
   release is missing or modified, an application service is running, or
   unmarked PTI units/private agent config already exist. The playbook checks
   the copied manifest and binary hashes on the target before installing
   units. Re-running an interrupted preparation with the **same** release is
   supported while all relevant services remain stopped and disabled and
   Cowrie/Zeek or other sensor services have not yet been installed. The
   non-secret marker `/var/lib/pti-installer/prepared-release` records the
   release ID, approved manifest digest, and `preparing` or `prepared` state.
   A different bundle under the same release ID is rejected. Once the marker is
   `prepared`, a repeat call with the same approved release exits before any
   package, unit, or service mutation; the wrapper audits the installed files
   before attempting activation.
   The existing `scripts/pti_install.py` remains a read-only planner; it does
   not invoke this Ansible playbook.

5. Run the separate read-only acceptance audit with the **same** reviewed vars
   and inventory. It checks the prepared marker, approved manifest and binary
   hashes, exact host package versions, and that Redis and all five units are
   still stopped and disabled. It does not read private env files or enable
   services:

   ```sh
   ansible-playbook -i /path/to/private-inventory.ini \
     deploy/ansible/audit-prepared-pi.yml \
     -e @/path/to/reviewed-install-vars.json
   ```

   Restore the clean VM snapshot before a destructive retry test. Re-run the
   prepare playbook with the same release to check resumability, then run the
   audit again. Record the VM OS/architecture, package origins and versions,
   release ID and manifest digest, playbook results, and any unexplained
   service or listener state without including credentials or attacker data.

## Operator handoff

The operator supplies private values after preparation. The units refer to
`/etc/honeypot-agent.env` and selected files under `/etc/honeypot/` for the
processor, TI worker, hardware agent, and backup control loop. The operator
owns the values, service access policy, and mode; no value belongs in Git,
Ansible variables, release artifacts, CLI arguments, or installation receipts.

The [blank Pi env examples](env-examples/) list the current Go-unit paths and
settings. The one-command flow installs both examples and missing actual env
files with `root:root` mode `0600`. Edit the actual files on the Pi:

```sh
sudoedit /etc/honeypot-agent.env
sudoedit /etc/honeypot/processor.env
sudoedit /etc/honeypot/ti-worker.env
sudoedit /etc/honeypot/hardware.env
sudoedit /etc/honeypot/backup.env
```

You may instead upload completed files through the private management route.
Never replace an existing private `.env` with a blank example. Do not paste
secret values into Ansible vars, shell arguments, issue comments, or installer
logs. Staging never replaces existing actual private files.

After editing or uploading, run the read-only shape check on the Pi from this checkout:

```sh
sudo python3 scripts/check_pi_env.py --service all
```

Use `--service collector`, `processor`, `ti-worker`, `hardware`, or
`hardware-backup` to check one unit's required files. The checker reports only
missing key names, syntax errors, ownership, and permissions; it never prints
values. A passing result does not prove credentials, dependencies, or network
access work. Confirm Cowrie and Zeek paths, Redis private binding, Mongo and
B2 access, and collector log permissions before a separate activation step.

**Do not manually enable the prepared units.** Cowrie, Zeek, Docker decoys,
PostgreSQL/Deception Core, and Dashboard are outside this first playbook.
The collector's access to Cowrie/Zeek logs, the Redis private binding,
versioned Cowrie/Zeek artifacts, the tracked
[active decoy Compose source](../decoy-honeypot/README.md), and a value-redacting
activation preflight still require VM validation. Dashboard installation belongs to its
separate host and its staging env contract is still pending correction.

Rollback for this VM slice is to restore the clean VM snapshot. Production
rollback and existing-Pi migration have not been qualified.
