# ADR-0006: Retained-data backup boundaries

- Status: Accepted
- Date: 2026-09-25

## Context

MongoDB retention collections are useful for the dashboard but are not all the
same kind of data. `hardware_metrics_1m` is a compact trend rollup. `events` is
the canonical security-event record and the restricted web-corp login path can
retain submitted passwords in that collection. Filesystem activity has two
authoritative collections, `cwd_events` and `cwd_session_state`, plus a
derived `cwd_audit_projection` read model.

The existing Pi backup worker was hardware-specific. Marking the dashboard's
other source cards active before the worker, B2 key scope, and sensitive-data
policy were ready would report a capability that was not actually deployed.

## Decision

- Keep `hardware_metrics_1m` as the default enabled backup target.
- Add opt-in logical targets: `threat_events` for `events`, and
  `filesystem_audit` for `cwd_events` plus `cwd_session_state`.
- Do not archive `cwd_audit_projection` or
  `cwd_audit_projection_meta`; rebuildable projections and readiness metadata
  are not authoritative evidence.
- Store multi-source archives as gzip Extended JSON Lines with a target header
  and a source-collection field on every record so a restore operator can
  route records without guessing.
- Require `BACKUP_ALLOW_SENSITIVE=true` before the worker can activate
  `threat_events`. The target must use a private bucket, a scoped upload key,
  reviewed encryption settings, and a separate read-only restore key.
- When several B2 prefixes are enabled, use a reviewed bucket-scoped key or
  separate worker/key deployments because a B2 application key has one
  `namePrefix`.
- The upload worker receives `writeFiles` and `listFiles` only. It does not
  receive `deleteFiles`; lifecycle and deletion remain an operator/cloud
  policy decision.
- Publish the enabled target set to `backup_target_status`. The dashboard
  reports a target as active only when the worker has published that state (or
  the existing hardware manifest proves the already-deployed hardware path).

## Consequences

- Repository support and host activation are visibly separate. A new target
  remains Planned until the Pi environment is changed and the worker runs.
- Filesystem restore can rebuild the projection from source records, avoiding
  duplicate backup storage and stale derived data.
- Threat-event archives require stricter handling than hardware archives and
  must not be enabled as a side effect of deploying the generic worker.
- Existing hardware manifests and object names remain readable; newly created
  archives use the versioned target/source envelope.

## Alternatives considered

- Backup every MongoDB collection: rejected because it duplicates derived
  projections and risks copying operational/control data into evidence storage.
- Treat `cwd_audit_projection` as the filesystem archive: rejected because it
  is a derived read model and does not contain the complete authoritative
  transition history.
- Let the dashboard call B2 directly: rejected; B2 credentials remain on the
  Pi and dashboard actions only create audited MongoDB requests.
