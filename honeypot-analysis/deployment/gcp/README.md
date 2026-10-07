# Backend VM migration bundle

This directory contains source code and an example runtime plan for building,
verifying, and staging a backend migration package. A verified source package
is not proof that a destination VM is production-ready and does not activate
services by itself.

## Safe-use boundary

- Keep inventories, credentials, database snapshots, rollback data, live
  capture/spool files, and host-specific network identities outside Git.
- Start from a copy of `runtime-plan.example.json`; replace every
  `REPLACE_...` value in a protected, owner-only plan.
- Use only independently verified source inputs and reviewed hashes.
- Review the generated manifest and health report before any staging step.
- Do not place secret values in command-line arguments, environment examples,
  this repository, or generated reports.
- Staging a source package is separate from installing runtime assets, enabling
  services, changing ingress, or accepting live traffic.

Run `python3 backend_vm.py --help` for the local command interface. Tests for
the package builder are in `honeypot-analysis/tests/test_backend_vm_bundle.py`.
No host action or deployment is performed by this repository documentation.
