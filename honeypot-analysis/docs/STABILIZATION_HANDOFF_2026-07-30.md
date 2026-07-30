# Stabilization handoff — 2026-07-30

## Repository checkpoint

- Branch: `professor-approved-poc-evaluation`
- Starting revision:
  `ccf0a8db78e0d4d3d6133f642e71d98dc26bb0e1`
- Final implementation revision before this handoff:
  `f7d0d0525816a1c45f939a8eadbf88e91c890eef`
- Final branch HEAD: the separate commit containing this document. Its exact
  SHA-1 must be resolved with `git rev-parse HEAD` and is recorded in the
  account-switch checkpoint returned with this handoff.
- Worktree immediately before authoring this handoff: clean.
- Expected worktree after committing this handoff: clean.

## Completed stabilization scope

The work completed the already-started stabilization through the independent
classification and typed-semantic evaluation. It did not start storage
capacity recovery, backup creation, release construction, deployment, systemd
reconciliation, operational-state repair, E2E, rollback, load testing, or UI
cleanup.

1. Frozen read-only local/GCP/Pi evidence and the closed deployment-capacity
   gate.
2. Added an explicit alert-authority policy. New prediction, enrichment,
   correlation, threat-hunt, typed-finding, and guidance output cannot
   authorize automatic alerts or webhook delivery. Campaign similarity uses
   neutral correlation language. Historical alert rows remain readable.
3. Changed analysis fallback reporting to reconstruct and verify durable
   SQLite events before both primary and fallback reports, failing closed
   without partial artifacts when canonical evidence is unavailable.
4. Added a manifest-bound exact systemd unit allowlist and a managed,
   reversible reconciliation plan for the confirmed obsolete prediction
   backtest timer. No live unit was changed.
5. Authored and froze an independent 40-case semantic evaluation before
   execution; added a hash-verifying isolated evaluator; ran it through the
   actual classifier, typed-fact builder, six family selectors, v4/v3,
   SQLite persistence, and JSON/Markdown/PDF-or-fallback/STIX validators; and
   committed every discrepancy without policy tuning or label changes.

## Commits created

| Commit | Subject and boundary |
| --- | --- |
| `2576876f0e396ecc5e4ee7f3a7a42d11b4f7de6a` | Record stabilization starting evidence |
| `900fa4faacf055e147515df0e781fd5a42478fb3` | Prohibit automatic alerts and neutralize correlation signals |
| `44084e53171913d81c55433d7992b6da25c407c6` | Reconstruct durable evidence before fallback reporting |
| `ff0e961b6dd92bcbd21dce9ec0349290c59b3100` | Bind releases to an exact managed unit allowlist |
| `1648c68d6209830e694db6e2535a993612636c5c` | Freeze independent stabilization semantic evaluation |
| `4b44ecada626060727d2129ab148dde1f645a1ad` | Add isolated semantic stabilization evaluator |
| `2d42fd092f19bbf5bd283b3eba3937e5f076acb3` | Compare integrity-bound semantic outputs deterministically |
| `f7d0d0525816a1c45f939a8eadbf88e91c890eef` | Record independent semantic stabilization results |
| handoff commit | Separate commit containing this document |

## Root causes and changes

- Alert creation had several implicit producer-specific gates and retained
  actor-identifying campaign terminology. One closed, versioned policy now
  rejects every unapproved automatic producer and external-delivery path.
- Fallback analysis previously accepted bounded job payloads as if they were
  complete durable evidence. The worker now reconstructs the exact SQLite
  event set and validates its manifest before any report path.
- Runtime unit drift could not be compared to an exact release contract. The
  release manifest now binds the reviewed unit/timer allowlist and a
  fail-closed validator reports unknown enabled honeypot units.
- Existing semantic acceptance sets were implementation-adjacent. The new
  specification records partial rather than organizational independence,
  freezes expectations by SHA-256, and preserves failures.
- The evaluator initially treated v3 `generated_at` as semantic content. A
  focused correction excludes only that wall-clock rendering field while
  retaining guidance IDs, evidence, actions, traces, provenance, safety
  fields, and all integrity-bound output in repeatability comparison.

No Transformer, VOMM, model artifact, typed-semantic extractor, activated
family, classification policy, v4/v3 runtime policy, historical reader,
database schema, or automatic-response contract was changed.

## Files and contracts changed

- Alert authority:
  `configs/alert_authority_policy.v1.json`,
  `production/policies/alert_authority_policy.py`, session/campaign/
  threat-hunt/webhook/API integration, configuration example, and boundary
  tests.
- Durable fallback:
  `production/workers/analysis_worker.py` and canonical-runtime regression
  tests.
- Managed units:
  `deployment/systemd/managed_units.v1.json`,
  `deployment/systemd/reconcile-obsolete-units.sh`,
  `production/tools/managed_systemd_units.py`, release-manifest integration,
  documentation, and tests.
- Independent evaluation:
  `evaluation/stabilization_semantic_evaluation.v1.json` plus SHA-256,
  `production/tools/stabilization_semantic_evaluation.py`,
  `evaluation/stabilization_semantic_evaluation_results_2026-07-30.json`
  plus SHA-256, evaluation documentation, and focused tests.

The complete path list is available with:

```bash
git diff --name-status \
  ccf0a8db78e0d4d3d6133f642e71d98dc26bb0e1..f7d0d0525816a1c45f939a8eadbf88e91c890eef
```

## Validation evidence

Focused tests:

- `pytest -q tests/test_stabilization_semantic_evaluation.py`:
  `6 passed`
- Alert, lifecycle, managed-unit, and evaluation focus:
  `39 passed`

Validators:

- Transformer prediction policy: passed.
- Reviewed classification policy: passed.
- Response-guidance policy: passed.
- Threat-hypothesis behavior policy: passed.
- Typed-semantic vocabulary load and validation: `valid`.
- Python compilation for the evaluator and test: passed.
- `git diff --check`: passed before result commit.

Full suite:

```text
980 passed, 7 skipped, 1 failed in 80.29s
```

The sole failure is reproducible:

`tests/test_observability_lifecycle_phase12.py::test_analysis_report_logs_latency_and_preserves_event_correlation`

The test enqueues an analysis payload without durable session events and
expects its mocked `analyze_job` to run. The fail-closed reconstruction added
in `44084e5…` rejects it first with
`canonical_evidence_status=unavailable`, `partial_report_created=false`.
The isolated rerun also failed. This is not caused by the semantic evaluator
and was not changed during the current task.

Independent evaluation:

| Layer | Precision | Recall | F1 |
| --- | ---: | ---: | ---: |
| Classification micro | 0.461538 | 0.342857 | 0.393443 |
| Typed operations micro | 0.803571 | 0.818182 | 0.810811 |
| Eligible families micro | 1.000000 | 0.875000 | 0.933333 |
| Findings micro | 1.000000 | 0.875000 | 0.933333 |
| Guidance micro | 1.000000 | 0.166667 | 0.285714 |

All 40 cases passed required abstention, integrity/reference, persistence,
artifact, and deterministic-repeatability checks. Unsupported specialized
output, contradicted hypotheses, and unfalsifiable hypotheses were all zero.
Thirty-three cases retained at least one exact-label or coverage difference;
the complete per-case evidence is in the committed result.

## Production access and impact

Read-only SSH was used earlier in this stabilization run to freeze GCP and Pi
state. No production file, service, timer, database, release, backup,
configuration, network, firewall, manifest, model, or Pi state was changed.
No production command was run while completing the independent evaluation or
this handoff.

Last verified deployed GCP revision:
`bf53edf640de9f8dbfd8002d91b383e55ceb9187`.
Active release:
`/opt/honeypot-releases/bf53edf640de9f8dbfd8002d91b383e55ceb9187`.
Verified rollback release:
`/opt/honeypot-releases/7125cd8de64afc1d60cc2920f03eb21e5c8010af`.
Manifest SHA-256:
`d25c459c3f388fedd32048c83115f4af2a6e67beaa65603d5c41846530bd3b5d`.

The deployment state after the earlier read-only snapshot is
`NOT_DETERMINABLE` without a new SSH verification. This session made no
production change that could have advanced it.

## Unresolved defects, blockers, and NOT_DETERMINABLE items

1. The full suite is not green because of the reproducible stale
   observability fixture described above. It must be adjudicated without
   weakening fail-closed durable reconstruction.
2. The independent evaluation recorded classification exact-label,
   typed-operation coverage, and specialized-guidance recall gaps. These
   require independent adjudication; the final evaluation must not be used as
   a tuning set.
3. The GCP capacity gate is closed: the last verified free space was about
   10.85 GB, while backup, isolated restore, WAL, staging, and safety margin
   require about 20 GB.
4. The obsolete backtest timer is documented and a reconciliation mechanism
   exists locally, but no live unit was disabled or archived.
5. Current GCP/Pi state after the starting snapshot, cloud firewall policy,
   an external-origin PROXY source-IP proof, and all later deployment/E2E
   acceptance items remain `NOT_DETERMINABLE`.

## Rollback boundaries

All local boundaries are ordinary additive commits. Do not reset or rewrite
history. Revert only the smallest affected boundary, or revert the evaluation
batch in reverse order:

```bash
git revert f7d0d0525816a1c45f939a8eadbf88e91c890eef
git revert 2d42fd092f19bbf5bd283b3eba3937e5f076acb3
git revert 4b44ecada626060727d2129ab148dde1f645a1ad
git revert 1648c68d6209830e694db6e2535a993612636c5c
```

Earlier runtime boundaries are independently revertible:

```bash
git revert ff0e961b6dd92bcbd21dce9ec0349290c59b3100
git revert 44084e53171913d81c55433d7992b6da25c407c6
git revert 900fa4faacf055e147515df0e781fd5a42478fb3
```

No production rollback command is needed because nothing was deployed.

## Exact next stabilization step

Do not begin capacity recovery or deployment yet. First reconcile the one
failing observability test with the fail-closed durable-evidence contract:
construct valid durable session events and a matching canonical manifest in
the test fixture (or, if code inspection proves a runtime regression, make the
smallest fail-closed correction). The test must continue to prove latency and
correlation logging without allowing a bounded job payload to masquerade as
canonical evidence. Then rerun the focused fallback/observability tests and
the entire suite.

Only after the full suite is green should the next plan item begin:
re-verify live GCP state and satisfy the non-destructive capacity and fresh
backup/isolated-restore prerequisites. No cleanup or deployment is authorized
by this handoff.

## First commands for the next account/session

```bash
cd /home/rubchek/Desktop/teammate-repo/honeypot-analysis
git branch --show-current
git rev-parse HEAD
git status --short
git log -10 --oneline
(cd evaluation && sha256sum -c stabilization_semantic_evaluation.v1.sha256)
(cd evaluation && sha256sum -c stabilization_semantic_evaluation_results_2026-07-30.sha256)
pytest -q tests/test_observability_lifecycle_phase12.py::test_analysis_report_logs_latency_and_preserves_event_correlation
pytest -q tests/test_phase7_canonical_runtime.py tests/test_observability_lifecycle_phase12.py
```

Before continuing beyond that test repair, require:

- a clean worktree and exact handoff commit;
- all focused and full tests green;
- frozen evaluation labels and results unchanged;
- no weakening of durable-event, v4/v3, privacy, historical-reader, alert,
  manual-approval, or no-automatic-response boundaries;
- a fresh read-only GCP/Pi state check;
- at least the calculated safe capacity;
- a fresh non-overwriting verified backup and isolated restore;
- exact manifest and rollback gates.
