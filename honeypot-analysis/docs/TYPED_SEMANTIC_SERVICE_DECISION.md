# Typed service family decision

Decision date: 2026-07-30

Baseline: `cb539ff`

Disposition: **retain as shadow-only**

## Frozen contract and evidence

The documented subset distinguishes selected read-only `systemctl` operations
from selected modification attempts. A literal `status`, `show`,
`is-active`, or list operation is inspection; `start`, `stop`, `restart`,
`reload`, `enable`, `disable`, `mask`, `unmask`, `edit`, or
`daemon-reload` is a modification attempt.

Cowrie command success does not establish a unit's prior state, that a service
transition occurred, persistence, availability impact, attacker intent, or an
effect on a real host. Failed, unknown, malformed, unsupported-option,
incomplete, expansion-dependent, and compound outcomes are ineligible.

There is no retained raw service-management command in the demonstration
telemetry. Activating service findings or guidance therefore adds little
thesis value while creating a substantial effect/availability overclaim risk.
The family remains shadow-only. Its frozen evaluation and holdout verify the
inspect/modify distinction, conservative unknown behavior, deterministic
facts, and absence of v4/v3 or hypothesis authority.

