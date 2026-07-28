# Phase 5 account-switch handoff

This handoff records the state observed on 2026-07-28. Work stopped after
roadmap Phase 5 at the user's request. Phase 6 was not started.

## Completed phases

| Roadmap phase | Commit | Result |
| --- | --- | --- |
| 1. Canonical report authority | `64645a0f7ca5950836d0ca7ab097ea994c1bda61` | Removed active legacy report/next-action authority and required validated v4/v3 output. |
| 2. Canonical evidence provenance | `1e506e28ada8b5882079581cdb9bc52afbdc9336` | Bound one evidence snapshot to exact behavior, classification, MITRE, model, and evaluator provenance. |
| 3. Deterministic predictions/artifacts | `0147d9d08434b6a6caabfbe818efb88aaf6efb8d` | Added retry-stable prediction IDs/digests and deterministic JSON, Markdown, PDF, STIX, and artifact manifests. |
| 4. Durable storage and recovery | `223168a` | Added checksummed SQLite migrations, prediction outbox/retries, lifecycle/privacy policy, backup/restore tooling, and service-specific secret files. |
| 5. Manifest-bound deployment | `7125cd8de64afc1d60cc2920f03eb21e5c8010af` | Added release-manifest tooling, fixed exact Transformer trust provenance, corrected content addressing/redaction, and aligned STIX validation with `response_guidance.v3`. |

The local runtime-code commit and deployed commit are both
`7125cd8de64afc1d60cc2920f03eb21e5c8010af`. The handoff document is a
documentation-only commit after that revision and does not represent a deployed
runtime change.

## Repository and deployment state

- Repository: `/home/rubchek/Desktop/teammate-repo`
- Project: `/home/rubchek/Desktop/teammate-repo/honeypot-analysis`
- Baseline: `5fee45ab0b58ebc810929e4d3b279743cd508819`
- Final deployed release:
  `/opt/honeypot-releases/7125cd8de64afc1d60cc2920f03eb21e5c8010af`
- Live link and `DEPLOYED_COMMIT` were verified as that revision.
- All eight affected GCP services returned `active` immediately after the final
  restart and ran from the final release directory with zero restart count.
- Frozen Transformer and SecureBERT artifacts were linked from the preserved
  `97db7b495d3f4fb8c14286dff873ef5d07d0fb73` release. No retraining,
  recalibration, VOMM switch, database rewrite, or network change was made.
- Effective Transformer policy remained advisory-only: prediction-only alerts,
  guidance, recommendations, actions, and automatic execution were prohibited.

## Tests and validation

| Phase | Focused tests | Full suite |
| --- | --- | --- |
| 1 | 79 passed | 843 passed, 7 skipped |
| 2 | 83 passed, 2 skipped | 847 passed, 7 skipped |
| 3 | 44 passed, 3 skipped | 851 passed, 8 skipped |
| 4 | 77 passed | 861 passed, 8 skipped |
| 5 final | 46 passed, 1 skipped | 868 passed, 8 skipped |

The final full suite required loopback socket permission; an initial sandboxed
run failed only eight socket-creation tests, and the identical unrestricted run
passed all 868 tests.

Final pre-activation checks passed:

- prediction, 111-rule classification, response-guidance, and
  threat-hypothesis policy validators
- frozen Transformer artifact loading and non-persistent inference smoke test
- release package, release-tree, effective-configuration, and model-artifact
  manifest verification
- SQLite `quick_check`

Final controlled Pi-to-GCP session `c4022f691bfb` produced 13 Cowrie events.
The Pi forwarder initially spooled them while GCP was starting, then sent all
13 with zero remaining. GCP persisted and processed all 13 exactly once, closed
the `production_live` session, completed seven prediction outbox entries,
persisted seven prediction snapshots, created three observed/correlation
alerts, and completed analysis job
`job_e2bc4a7c2fa26daeed2c4284f19f63a9` with report
`report_bfcd4accd08fac89ed8fcde559e844a6`.

## Manifest, backup, and rollback

- Manifest:
  `/opt/honeypot-releases/7125cd8de64afc1d60cc2920f03eb21e5c8010af/DEPLOYMENT_MANIFEST.json`
- Manifest SHA-256:
  `ed341968e214d44930e4f660b9041df72fe707987ad635be51d5a8b272533ab6`
- Release tree: 432 files,
  SHA-256 `64ceb1a3fbf47221d42862a765adae1dada9ba6463dae84d4d94acb2198de2e0`
- Package:
  `/opt/honeypot-packages/honeypot-release-7125cd8de64afc1d60cc2920f03eb21e5c8010af.tar`
- Package SHA-256:
  `9102016186cb56288984b59c7c53e5c2740c9edcd1d45d36d759edfe7a3e431d`
- GCP configuration/unit rollback:
  `/var/backups/honeypot/full-roadmap-20260728T140000Z-4e40df3`
- Preserved release rollbacks:
  `/opt/honeypot-releases/97db7b495d3f4fb8c14286dff873ef5d07d0fb73`
  and
  `/opt/honeypot-releases/3e35e037b6d020363434e8f86293b51785087f8c`
- Immediate pre-final candidate, also retained:
  `/opt/honeypot-releases/2a0f20eec51c56a317dc97ed14acd339ad735267`
- Off-host database backup:
  `/tmp/production_pilot.pre-4e40df3.db.gz`
  (volatile location; move it to durable encrypted storage before relying on
  it operationally)
- Source DB SHA-256:
  `bd3b12e41ddebafc06dff2d02a813b2de969db304c621cc7de1e38c323805d3f`
- Gzip SHA-256:
  `2223c62c36f2cf6c6cbb7b87aeb2d0cb5e10d4b534f3c723384b3e70a6f64218`

The off-host restore rehearsal decompressed the backup, matched the source
digest and table counts, and passed SQLite quick/integrity checks. A live
release-pointer rollback rehearsal was not performed.

## Unresolved or intentionally stopped checks

- Per the stop request, no remote check was run after observing the final E2E
  report reach `succeeded`. A new session should strictly validate report
  `report_bfcd4accd08fac89ed8fcde559e844a6`, all v4/v3 hashes and IDs, its
  JSON/Markdown/PDF/STIX artifact manifest, the no-recommendations snapshot
  rule, and the three alerts' non-predictive provenance.
- Dashboard and monitor readiness endpoints were not re-polled after the final
  activation. Earlier candidate startup showed temporary SQLite contention,
  although the final E2E completion proves the ingest/session/analysis/
  prediction path subsequently operated.
- The VM filesystem had approximately 189 MiB free and reported 100% usage
  after staging the final release. Capacity cleanup is an operational blocker.
- The database backup remains under `/tmp`, which is not durable storage.
- No live pointer/config rollback rehearsal was completed.
- Long-duration observation, load testing, independent model validation,
  privacy/compliance review, and external STIX schema validation remain open.
- Roadmap Phase 6 (archiving obsolete generators/backends/configuration,
  broken entrypoints, and duplicate UI paths) was not started.

## Exact next steps for a new Codex session

1. Read this handoff and `docs/RELEASE_DEPLOYMENT.md`; confirm the local
   worktree is clean and distinguish the documentation-only handoff commit from
   deployed runtime commit `7125cd8...`.
2. With fresh authorization, perform only read-only GCP checks first: verify
   the live link, marker, manifest, eight service working directories,
   readiness endpoints, recent error logs, disk capacity, and SQLite
   `quick_check`.
3. Strictly validate final report
   `report_bfcd4accd08fac89ed8fcde559e844a6` and its prediction/alert/artifact
   contracts. Do not create another Cowrie event unless this persisted evidence
   is insufficient.
4. Copy the gzip database backup from `/tmp` to durable encrypted storage and
   verify its recorded digest.
5. Rehearse the documented rollback in a bounded maintenance window, restoring
   the final release afterward and re-verifying the manifest and service
   health.
6. Only after those checks pass, begin Phase 6 as a new, separate commit. Run
   focused and full tests and preserve all historical v1/v2/v3 read adapters.
