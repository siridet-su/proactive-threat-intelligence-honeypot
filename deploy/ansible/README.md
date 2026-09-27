# Fresh Pi preparation — first Ansible slice

Status: **prepared for disposable Ubuntu 24.04 ARM64 VM testing; not qualified
for a production Raspberry Pi**. This playbook prepares Go sensor-agent
artifacts and inactive units. It is not a complete honeypot installer.

The accepted boundary is [ADR-0009](../../docs/adr/ADR-0009-installer-operator-managed-credentials.md).
The playbook installs `ca-certificates`, Python 3 and venv support, and Redis;
uses apt's service-start policy to prevent Redis from starting during package
installation, then leaves it stopped and disabled; creates the dedicated
`pti-agent` identity and
non-secret directories; verifies and copies one local Linux ARM64 release;
and installs five Go service units in the stopped/disabled state. It does not
create, read the contents of, overwrite, or back up private `.env` files. It does not change
SSH, firewall, trap ports, network membership, or Dashboard services.

## Prepare a disposable target

1. Start with a clean Ubuntu 24.04 ARM64 VM with a recovery console. Validate
   OS, architecture, package source, and administrator SSH separately. Do not
   target the existing `pi-t` host or a customer Pi yet.
2. Build the Go bundle from a clean checkout on a build host with cached Go
   modules. The builder runs each module's tests and disables Go downloads:

   ```sh
   python3 scripts/build_sensor_release.py --release-id r1 --output-root /tmp/pti-releases
   python3 scripts/verify_sensor_release.py --release-id r1 --release-dir /tmp/pti-releases/r1
   ```

3. Copy `inventory.example.ini` to a private inventory outside Git and add
   the VM's management address and administrator account. Keep passwords and
   private keys out of the inventory.
4. Run Ansible from the build/control host. Set the release source to an
   **absolute local path** and use the same release ID as the manifest. Review
   the target and release before the second command; no production Pi is an
   approved target yet:

   ```sh
   ansible-playbook -i /path/to/private-inventory.ini deploy/ansible/prepare-pi.yml \
     --syntax-check
   ansible-playbook -i /path/to/private-inventory.ini deploy/ansible/prepare-pi.yml \
     -e '{"pti_release_id":"r1","pti_release_source":"/tmp/pti-releases/r1"}'
   ```

   The playbook fails before mutation if the OS/architecture is wrong, the
   release is missing or modified, an application service is running, or
   unmarked PTI units/private agent config already exist. Re-running a
   prepared, inactive host is supported. The marker is
   `/var/lib/pti-installer/prepared-release` and contains only the release ID.
   The existing `scripts/pti_install.py` remains a read-only planner; it does
   not invoke this Ansible playbook.

## Operator handoff

The operator supplies private files after preparation. The units refer to
`/etc/honeypot-agent.env` and selected files under `/etc/honeypot/` for the
processor, TI worker, hardware agent, and backup control loop. The operator
owns the values, service access policy, and mode; no value belongs in Git,
Ansible variables, release artifacts, CLI arguments, or installation receipts.

**Do not enable the prepared units yet.** Cowrie, Zeek, Docker decoys,
PostgreSQL/Deception Core, and Dashboard are outside this first playbook.
The collector's access to Cowrie/Zeek logs, the Redis private binding,
versioned Cowrie/Zeek and Compose artifacts, and a value-redacting activation
preflight still require VM validation. Dashboard installation belongs to its
separate host and its staging env contract is still pending correction.

Rollback for this VM slice is to restore the clean VM snapshot. Production
rollback and existing-Pi migration have not been qualified.
