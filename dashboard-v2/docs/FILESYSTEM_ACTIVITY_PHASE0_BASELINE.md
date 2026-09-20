# Filesystem Activity Phase 0 behavior baseline

Date: 2026-09-20

Scope: `/filesystem-activity` before the production UI refactor

This note records the behavior evidence that later redesign phases must preserve. It complements the redesign plan; it does not prescribe the Phase 2 semantic implementation.

## Preserved contracts

### Audit topology and retained evidence

- `buildAuditSnapshot` materializes every ancestor needed for each verified current or historical path, including branches the attacker later exited.
- A `failed_change` contributes its verified `fromPath`, but its unverified destination must not create typo/destination nodes.
- A retained selection remains a `FilesystemClosedSession` with lifecycle evidence at the source-model boundary. The current canvas adapter places a rendering copy in `snapshot.sessions`; that adapter behavior must not be used to infer that the source session is live.
- History completeness and absolute-hop numbering remain explicit; partial pages must not be presented as complete retained history.

### Independent status dimensions

- SSE connection state describes transport health.
- Telemetry age describes evidence freshness.
- A connected stream may have stale telemetry, and a disconnected stream may retain recently observed telemetry. Neither dimension may overwrite or masquerade as the other.

### State and lifecycle ownership

- `useFilesystemStreaming` / `FilesystemStreamLifecycleManager` owns the single stream lifecycle.
- `useAuditDirectory` and its search manager own the retained-directory/search lifecycle.
- `useSessionCwdHistory` owns retained history loading and pagination.
- `useAuditReplay` owns replay selection and its single autoplay timer.
- `useResponseActionController` owns capability/polling/abort behavior while the Response tab is active.

### Navigation and filtering

- `view`, `sessionId`, `hop`, `hideHome`, and `targetPath` retain their URL/deep-link/back-forward behavior.
- Selected-outside-filter, remote lookup, stale-response suppression, cursor pagination, and deep-hop resolution remain covered by their existing suites.

## Known current semantic defects and risks

These are evidence for later correction, not accepted production semantics:

1. A selected closed session is copied into `snapshot.sessions` so the generic topology renderer can draw it. Generic presentation can therefore call a retained/closed session “active” unless audit context is carried separately.
2. `buildAuditSnapshot.generatedAt` is set with `new Date()` when the client materializes the view. It is view-materialization time, not evidence observation, session closure, or telemetry freshness time.
3. Current page presentation places stream and freshness badges together without naming their different scopes clearly, even though the underlying state model treats them independently.

No executable test intentionally expects incorrect user-facing wording. The defects above are documented so Phase 2 can replace them with explicit audit context and evidence-safe labels without weakening the preserved data contracts.

## Authoritative test evidence

| Contract | Test file |
| --- | --- |
| Phase 0 hierarchy, failed destination, retained lifecycle boundary, independent status dimensions | `tests/filesystem-phase0-baseline.test.ts` |
| Snapshot ingestion, SSE lifecycle, telemetry trust/freshness | `tests/filesystem-freshness.test.ts` |
| Single replay/timer/response/freshness presentation owners | `tests/filesystem-ownership-boundaries.test.tsx` |
| URL transactions, back/forward, lookup races, selection and filter coordination | `tests/filesystem-navigation-history.test.ts` |
| Filter semantics and selected-outside-filter behavior | `tests/filesystem-audit-filter.test.ts` |
| Retained directory search, pagination and stale-response suppression | `tests/filesystem-audit-directory.test.ts` |
| History keyset pagination and completeness metadata | `tests/filesystem-history-pagination.test.ts` |
| Deep-hop lookup and absolute-hop resolution | `tests/filesystem-hop-resolution.test.ts` |

## Commands and Phase 0 acceptance evidence

Run from `dashboard-v2`:

```bash
npx vitest run tests/filesystem-phase0-baseline.test.ts
npx eslint tests/filesystem-phase0-baseline.test.ts
npm test
git diff --check
```

Acceptance evidence for this checkpoint:

- Narrow Phase 0 characterization suite: **passed**, 1 file / 3 tests.
- Targeted ESLint check: **passed**.
- Full Vitest suite: **passed**, 23 files passed and 1 skipped; 466 tests passed and 14 skipped.
- `git diff --check`: **passed**.
- Production files under `src/`: unchanged by this checkpoint.

Visual screenshot capture is tracked as a separate Phase 0 deliverable because it requires a running authenticated browser fixture and viewport/state matrix; it is not claimed by this behavior-baseline checkpoint.
