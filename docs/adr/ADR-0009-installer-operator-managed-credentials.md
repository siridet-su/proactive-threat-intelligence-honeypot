# ADR-0009: Installer prepares services; operators provision credentials

- Status: Accepted
- Date: 2026-09-28

> File creation policy amended by [ADR-0011](ADR-0011-installer-private-env-skeletons.md):
> the installer may create blank, owner-only `.env` skeletons when absent.
> The decision below records the original boundary; credential values remain
> operator-managed and existing files remain protected.

## Context

The first installation target is a fresh Ubuntu 24.04 ARM64 Raspberry Pi. The
current Pi uses protected environment files for MongoDB, Redis, provider,
backup, and decoy settings. The Dashboard runs on a separate host. A complete
installer must be reproducible without copying the current Pi's private files
or embedding customer credentials in a release artifact.

## Decision

- The installer installs reviewed, version-pinned dependencies, application
  artifacts, service units, directories, and configuration that contains no
  secrets. It records the expected private env-file paths and required key
  names in a separate operator checklist.
- The installer does not create, populate, overwrite, import, print, or back
  up `.env` files, API keys, database passwords, device enrollment credentials,
  or other private settings. An existing private file is left untouched.
- Application services are installed but remain disabled and stopped after
  the preparation phase. The installer reports which operator inputs are still
  needed; preparation success does not claim that the honeypot is operational.
- The operator provisions each private file outside Git and the release tree,
  with the owner and mode required by its service. Dashboard credentials are
  provisioned on the separate Dashboard host. The installer may check path,
  ownership, permissions, required key names, and connectivity without showing
  values. Validation must not write credentials to logs or installation
  receipts.
- Activation is a separate explicit action after operator provisioning and
  validation. It enables only selected services, validates private bindings
  and telemetry on a non-public listener, and exposes trap ports only after
  acceptance checks pass. A missing or invalid private file stops activation
  without changing the prepared release.
- Existing-Pi migration and customer device enrollment remain separate
  procedures. The first installer does not use the old Pi's live checkout or
  private env as input.

## Consequences

- A clean installation has two visible states: **prepared** and **active**.
  Operators can inspect a prepared host before adding credentials.
- The release manifest and rollback receipt cover packages, artifacts, units,
  and non-secret config. Private files remain operator-owned and survive
  upgrade, rollback, and default uninstall.
- The plan-only `feat/appliance-installer` branch needs an apply phase and an
  activation gate before it can meet this contract. Its current commands do
  not install or enable services.
- Dashboard staging bootstrap must use the current application's env contract
  before Dashboard activation can be qualified.
