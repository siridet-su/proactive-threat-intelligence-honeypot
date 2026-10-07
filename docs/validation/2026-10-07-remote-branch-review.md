---
title: Remote branch review and selective integration
date: 2026-10-07
environment: repository-review
commit: origin/main 89eb8cd141f556bc044ae16e64143283c5eb5ea8
status: passed
---

## Objective

Review the GitHub remote branches against the curated `main`, inspect the
meaning of commits not reachable from `main`, and decide whether any branch
should be merged wholesale or contribute a selective patch.

## Procedure

Fetched `origin` without pruning or changing remote refs. Compared each actual
remote branch head with `origin/main` using commit reachability, then inspected
the unique commits, affected source/tests, and whether equivalent or newer
implementations were already on `main`. The symbolic `origin/HEAD` alias is not
counted as a branch.

## Expected result

Only changes that remain necessary, correct for the current runtime, and
consistent with the reviewed source should be integrated. A branch's ahead
count alone is not evidence that its whole tree is safe to merge.

## Observed result

At this snapshot, `origin/main` was `89eb8cd141f556bc044ae16e64143283c5eb5ea8`.
There were 43 actual remote branch refs including `main`: 11 non-main refs had
one or more commits not reachable from `main`; the other 32 refs (including
`main`) pointed to commits already reachable from `main`. The 11 unique branch
heads were reviewed as follows. Behind/ahead counts are relative to the stated
`origin/main` snapshot.

| Branch head | Behind / ahead | Decision and reason |
|---|---:|---|
| `dashboard-final-poc-staging-validation-20260905` (`8fa427193`) | 671 / 1 | Do not merge. The old prediction adapter can overwrite generic prediction data with a Next-Distinct tactic; current `main` has a newer bounded, exact-session sidecar interface. |
| `eti-report-policy-reconciliation-20260919` (`13710ed57`) | 574 / 1 | No patch needed. The unique commit is patch-equivalent to current code and its policy configuration blob matches `main`. |
| `feat/appliance-installer` (`ddf4f3c89`) | 141 / 1 | Do not merge. Installer scripts/docs are superseded by newer pinned, resumable installer work already on `main`. |
| `feat/service-watchdog-20260928` (`ad2baf0b2`) | 29 / 30 | Do not merge wholesale. It mixes stale changes; the watchdog has URL-validation/redirect and health-reporting problems and targets an obsolete endpoint. The relevant queue-wait correction was selected into current `main` in `3a3b2f8`. |
| `fix/dashboard-staging-ci-types-20260903` (`1e29b5c6e`) | 684 / 1 | No patch needed. It is an older type-safety change against stale Dashboard sources; current source has since changed and its TypeScript check passed in the curation validation. |
| `fix/model2-direct-pi22-20260928` (`3fe3f6422`) | 133 / 1 | Do not merge wholesale. Its fixed historical SSH target and broad direct-Pi capture path do not match the current ingress. The bounded exact-session result bridge was selected into `main`; retain fail-closed validation. |
| `fix/mongodb-prediction-outbox-lifecycle-20260905` (`1335a84b0`) | 671 / 1 | No patch needed. The compaction change and regression test match the implementation already on `main` (`74d28b055`). |
| `hotfix/gcp-retry-guidance-20261001` (`2bde4ac6d`) | 29 / 32 | Do not merge wholesale. Useful session-bound hypotheses/guidance were selectively included in `3a3b2f8`; historical smoke/deployment records and stale or unbound projections were not carried over. |
| `professor-approved-poc-evaluation` (`503085cfb`) | 711 / 1 | Do not merge or publish wholesale. Its resulting tree would add roughly 438 paths and 72,440 lines, including obsolete Dashboard copies, databases, logs, and historical artifacts; it also has multiple merge bases. |
| `release/ttp-rank-production-20260923` (`1539ac9bf`) | 254 / 2 | Do not merge. Its client-side ranking from partial Model1/Model2 signals is superseded by the server-owned exact-session recommendation contract on `main`. |
| `staging` (`e8a135340`) | 29 / 39 | Do not merge wholesale. The backup calendar/coverage work is already present. The remaining source-table patch changes severity/count semantics but does not implement the requested attacker-type tag; defer a separately scoped UI decision. |

The remaining 31 non-main heads already reachable from `main` are:

- `add-honeypot-analysis`, `audit/filesystem-activity-ux-20260920`,
  `dashboard-latest-integration-20260912`, `decoy-1`,
  `design/production-theme-system`, `edit-dashboard`,
  `feat/cwd-filesystem-telemetry`, `feat/filesystem-visualization-semantics`,
  `feat/opencanary-web-login-honeypot`,
  `feature/filesystem-activity-command-evidence-20260928`,
  `fix/dashboard-staging-artifact-symlinks-20260904`,
  `fix/dashboard-staging-postmerge-20260903`,
  `fix/dashboard-staging-runtime-health-20260904`,
  `fix/eti-otx-proof-guard-20260920`,
  `fix/mongodb-prediction-outbox-lifecycle-main-20260905`,
  `fix/observed-attempt-hypothesis-20260923`,
  `fix/session-display-operational-closeout-20260927`,
  `integration/latest-dashboard-to-staging-20260903`,
  `model2-eti-otx-20260920`, `model2-eti-otx-20260920-final`,
  `model2-eti-otx-20260920-final-compat`, `model2-final-release-20260916`,
  `release/eti-otx-main-integration-20260920`,
  `release/integrate-ttp-main-20260924`,
  `release/model2-54f-rrf-closeout-20260926`,
  `release/model2-backend-poc-20260924`,
  `release/runtime-closure-20260920`, `release/runtime-closure-20260923`,
  `release/session-ttp-live-20260923`, `release/web-corp-http-20260925`,
  `report-release-20260918`.

## Metrics

- Remote branch refs: 43 actual refs including `main` (the symbolic `origin/HEAD`
  alias is excluded).
- Non-main refs with unique commits: 11; all reviewed, none approved for a
  wholesale merge.
- Non-main refs already contained by `main`: 31.
- Source/runtime changes from this audit: none. Relevant selected code was
  already published in curation commit `3a3b2f8`.
- No remote branch was deleted, rebased, or repointed. Thus GitHub's branch list
  and behind/ahead counts are expected to remain visible; publishing selected
  code to `main` does not move the source branch refs.

## Limitations

This is a source/history review, not a runtime deployment or authenticated
staging test. Tests cited in the 2026-10-07 publication record belong to that
earlier source curation; they were not rerun for this documentation-only audit.
The full repository history has not received a dedicated secret scan.

## Follow-up

Keep reviewed branch refs intact for traceability. If a branch should be
archived or deleted, make that a separate explicit decision after checking its
open pull request and retention needs. Any new functional change should be
ported as a small, tested commit against current `main`, not by merging a stale
branch tree.
