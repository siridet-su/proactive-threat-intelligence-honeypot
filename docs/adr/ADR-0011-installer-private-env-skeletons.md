# ADR-0011: Create blank private env skeletons during Pi staging

- Status: Accepted; amends the file-creation clause of ADR-0009
- Date: 2026-09-28

## Context

ADR-0009 kept all private env-file creation with the operator. The fresh-Pi
workflow now installs its own units and knows the exact env paths. Requiring
operators to copy five example files manually adds avoidable steps and makes a
resume after missing configuration harder to follow.

## Decision

- After the approved release passes preparation and audit, the installer puts
  non-secret `.env.example` files beside the paths used by the five Go units.
- It also creates the matching actual `.env` files from those blank examples
  **only when absent**, as root-owned regular files with mode `0600`. The
  contents contain no credential values. An existing actual file is never
  opened for reading, overwritten, or reset by staging.
- The operator fills the actual files on the Pi or uploads replacements through
  the private management route. The installer never generates or records
  credentials. Its later read-only gate checks required names and file safety
  without printing values.
- Missing values leave the Go units stopped and disabled. Only the separate
  activation playbook may start them, after its dependency checks pass.

## Consequences

- The operator can run the same installer command, fill the staged files, and
  run it again; repeated staging preserves completed values.
- This changes only ADR-0009's prohibition on creating a blank actual `.env`.
  Its operator ownership of secret values, existing-file protection, and
  separate activation boundary still apply.
- The VM acceptance run must check first creation, owner/mode, missing-value
  pause, unchanged-content retry, and symlink rejection before production use.
