# Stabilization rollback-blocker handoff — 2026-07-30

## Outcome

Remaining stabilization stopped at the rollback prerequisite. The current
local repository, deployed GCP release, and Raspberry Pi credential-sanitizing
component match the expected revisions. The current GCP release verifies
exactly when the release verifier is run with the privileges required to read
its owner-restricted package and model inputs.

The preserved GCP rollback release
`7125cd8de64afc1d60cc2920f03eb21e5c8010af` does not pass its immutable
release-manifest verification. It also predates authority and deployment
boundaries that are mandatory in the current system. It was therefore not
activated, even in production for a short interval.

No production file, service, timer, database, queue, lease, configuration,
release pointer, network rule, backup, log, model, or Pi state was changed
during this continuation. No restart, rollback, load, recovery, privacy replay,
or new backup was attempted after the rollback gate failed.

The correct operational decision is:

- keep GCP revision `325d136a35f4e9b6cf197cc05565a0798f7b3e14`
  active;
- keep Pi sanitizer revision
  `7f764ab471e8dac555d06277b4613237299aee69` active;
- freeze feature development;
- do not claim final stabilization or production rollback readiness;
- repair and independently validate the rollback boundary before resuming
  operational acceptance.

## Repository checkpoint

- Branch: `professor-approved-poc-evaluation`
- Starting HEAD:
  `064a7866323a64540a76bb9c1e353fb3999f75a4`
- Worktree at preflight: clean
- Local implementation changes in this continuation: none
- Final code revision before this document:
  `064a7866323a64540a76bb9c1e353fb3999f75a4`
- This handoff is committed separately. Resolve its commit with
  `git log -1 --format='%H %s'`.

Frozen evaluation receipts still verify:

```text
stabilization_semantic_evaluation.v1.json: OK
stabilization_semantic_evaluation_results_2026-07-30.json: OK
```

## Fresh GCP baseline

Read-only SSH used the private Tailscale management address after the public
SSH address timed out before authentication. The public timeout made no remote
change.

Verified live state:

- active release:
  `/opt/honeypot-releases/325d136a35f4e9b6cf197cc05565a0798f7b3e14`;
- `DEPLOYED_COMMIT`:
  `325d136a35f4e9b6cf197cc05565a0798f7b3e14`;
- deployment-manifest SHA-256:
  `362a0ea361c0b819dcdb69f2a476d67ac2d54d76fdef84302e0b86feaf950f0e`;
- release-tree SHA-256:
  `96d7f71ddb165cac3825ce6b8d4a7c9cbf618b96936353e9ebde7a519d3f73a1`;
- manifest inventory: 497 files;
- root release verification: passed;
- SQLite bytes: `3932856320`;
- SQLite `quick_check`: `ok`;
- SQLite full `integrity_check`: `ok`;
- SQLite schema `user_version`: `3`;
- WAL and SHM were absent at the observed checkpoint;
- root filesystem free bytes: `18890711040`;
- failed systemd units: none;
- managed-unit validator: valid, with no missing, unknown, or prohibited units;
- obsolete calibration, prediction-backtest, and prediction-retention units:
  absent;
- required application services: active;
- required feed-refresh and session-count timers: enabled and active;
- webhook deliveries: zero;
- prediction outbox: 60 completed, zero pending;
- analysis jobs: 6940 succeeded, zero pending or failed;
- threat-hunt jobs: 13856 succeeded, zero pending or failed.

The eight continuously running application services retain:

```text
User=honeypot
Group=honeypot
UMask=0077
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=full
ReadWritePaths=/var/lib/honeypot
```

The feed-refresh service writes only below `/var/lib/honeypot/feeds`.
Expected listeners remain GCP Tailscale `:8080`, loopback `:8081` and `:8090`,
HAProxy `0.0.0.0:2222`, and management SSH. No listener was changed.

Current immutable configuration hashes observed included:

- prediction policy:
  `0c82941c90d6e36283b638b1554ad700311990df78895b0111131f9658da1c22`;
- reviewed classification policy:
  `33f332946c53578f2e609a3a039dda712355b9e209721bcc073c61a623d6342b`;
- response-guidance v3 policy:
  `91d5241a0c54daefd8e8371cf692cd5838737fcb08a7221fbd77a86f730ec6c7`;
- typed-semantic vocabulary:
  `61032bd6cadbf819290cee9759f7f73b2330c39e6f9d2c2796bef9dc5e6f8ef3`;
- managed-unit policy:
  `069abe87e1b249ab9e5c5a62391eeaccce584f817becd90873e8a2a439f92644`;
- runtime-feed provenance record:
  `a5c005fa44f92f878621568f38e1e7ccd6e3bdafd3af1b5a120f5ed91736d8e5`.

The root release verification re-hashed the current package, effective
configuration, managed-unit policy, frozen-model receipt, and individual
model artifacts. A separate runtime-feed content replay was not reached after
the rollback stop gate.

### Why two initial manifest checks appeared to fail

The first current-release verification was run as the SSH user. It could
enumerate only 220 of 497 owner-restricted manifest entries and reported them
as missing. Running as `honeypot` verified the release tree but could not read
the root-only package. Running the same command as root passed completely:

```json
{
  "git_revision": "325d136a35f4e9b6cf197cc05565a0798f7b3e14",
  "manifest_sha256": "362a0ea361c0b819dcdb69f2a476d67ac2d54d76fdef84302e0b86feaf950f0e",
  "release_file_count": 497,
  "release_tree_sha256": "96d7f71ddb165cac3825ce6b8d4a7c9cbf618b96936353e9ebde7a519d3f73a1",
  "verified": true
}
```

This was an invocation-permission issue, not current-release drift.

## Fresh Pi baseline

Verified read-only:

- active component:
  `/opt/honeypot-cowrie-output/releases/7f764ab471e8dac555d06277b4613237299aee69`;
- component manifest SHA-256:
  `714d04608d7385490000edef2effddbdad948fd065820e35fdebef29ada0f39d`;
- policy SHA-256:
  `439c11f1f88da9873be9ab62ab7f4ae98a7b8a7c73116362a5f4c7a20d47cf76`;
- validator result: `status=valid`;
- installed Cowrie revision:
  `575146bc6b24d70082527d66cd805d9bae0e0db4`;
- Cowrie status entry count: 133;
- stock `jsonlog.py` SHA-256:
  `b25558820d9e8e45cc3c7cb70e0d8233e0cc30e2c438d7590750f4418cfacf65`;
- final receipt:
  `/var/backups/honeypot/cowrie-output-20260730T114805Z`;
- historical hash receipt SHA-256:
  `30390983ebf3695eab78a63b127e6e911d7f1b8da2547b738f0f7a8a3ab11430`;
- Cowrie and sensor forwarder: active;
- Pi failed units: none;
- Pi free bytes: `86191009792`;
- forwarder spool: zero bytes at the observed checkpoint;
- current sanitized JSON: mode `0640`, `cowrie:cowrie`;
- diagnostic and direct legacy credential files: mode `0600`;
- post-fix authentication events with unredacted sensitive fields: zero.

The active configuration has:

```text
[output_jsonlog]
enabled = false

[output_sanitizedjson]
enabled = true
bundle_root = /opt/honeypot-cowrie-output/current
manifest = /opt/honeypot-cowrie-output/current/COWRIE_OUTPUT_MANIFEST.json
policy = /opt/honeypot-cowrie-output/current/configs/cowrie_output_privacy.v1.json
```

### Corrected configuration hash

`docs/COWRIE_PRIVACY_BLOCKER_HANDOFF_2026-07-30.md` recorded
`002932230b85…` as the reviewed post-integration configuration hash. The live
file and authoritative final receipt both record:

```text
22bfdca388f66073601744276c04337404aec935082cec401fdbb4f4336230db
```

The file timestamp is the final installation time. A structural comparison
against `cowrie.cfg.before` showed only the expected inserted
`[output_sanitizedjson]` section and separating newline. The receipt's
`managed-hashes.after.sha256` proves the live hash was the installed hash.
This is a documentation error, not host drift.

## Operational-state reconciliation status

Five sessions remain open:

- two retained seed/demo fixtures from May;
- three retained E2E sessions from July 6.

They were not closed, rewritten, or given fabricated end events.

Five enrichment jobs are failed, all with:

```text
last_error_code=job_attempts_exhausted
last_error_type=LeaseExpired
claim_owner=NULL
claim_expires_at=NULL
next_retry_at=NULL
```

The previous handoff recorded three. The two additional terminal rows are
associated with the most recent privacy-acceptance session IDs
`fc18cbb983b7` and `110c24682935`; they were exhausted at
`2026-07-30T11:29:35Z` and `2026-07-30T11:32:11Z`. No current worker warning
or error was present after `08:00Z`, authoritative queues were drained, and
the current session-worker lease was valid.

This explains the count drift but does not reconcile those rows. Determining
whether they should remain terminal, be operator-reviewed, or receive a
bounded retry is deferred because the rollback prerequisite stopped the
stabilization sequence. No one-off database update was made.

## Rollback blocker

### Manifest evidence

The required preserved rollback release is:

```text
/opt/honeypot-releases/7125cd8de64afc1d60cc2920f03eb21e5c8010af
```

Its v2 manifest expects 432 entries and tree SHA-256:

```text
64ceb1a3fbf47221d42862a765adae1dada9ba6463dae84d4d94acb2198de2e0
```

The current verifier sees 429 entries and tree SHA-256:

```text
90e41a80c1b84b439284870c1bc793f662d0c0f3a7aa8a0e4b0738a66c389a7e
```

There are no changed or unexpected entries. The only missing manifest-bound
entries are:

```text
production/__pycache__/__init__.cpython-311.pyc
production/tools/__pycache__/__init__.cpython-311.pyc
production/tools/__pycache__/release_manifest.cpython-311.pyc
```

Current manifest code correctly treats Python bytecode as reproducible runtime
output, but its legacy-manifest comparison does not normalize bytecode entries
already recorded by a v2 manifest. The old release therefore cannot satisfy
the current verifier without either modifying an immutable release or making a
reviewed, tested compatibility correction.

No missing bytecode was regenerated and the old release and its manifest were
not changed.

### Authority and deployment incompatibility

Even if the bytecode compatibility defect is corrected, production activation
of `7125cd8…` is not currently safe:

- it has no `alert_authority_policy.v1` or global alert-authority validator;
- it has no manifest-bound managed-systemd-unit policy or live allowlist
  validator;
- it predates the current hardened unit templates and explicit writable paths;
- it retains active webhook transport behavior based on configured targets,
  without the current global external-delivery prohibition;
- it predates SQLite-only runtime cleanup and contains unsupported backend
  paths;
- it predates the six-family typed-semantic migration and current v4/v3 policy
  hardening;
- its model receipt points into the older `97db7b…` release rather than the
  separately managed immutable frozen-model bundle;
- its manifest is v2 and has no runtime-feed provenance or managed-unit
  receipt.

The repository diff from `7125cd8…` to `325d136…` spans 201 files. Therefore
the older release cannot be assumed to preserve current authority, privacy,
configuration, reporting, or operational behavior. No production switch was
attempted.

Database read compatibility, private temporary service startup, historical
reader behavior, and round-trip return to the current release remain
`NOT_DETERMINABLE` because isolated rollback rehearsal was correctly not
started after this prerequisite failure.

## Completion matrix

| Stabilization item | Current state | Evidence |
| --- | --- | --- |
| Alert-authority correction | completed and directly verified | Current release exact; full suite passed; v1 policy is manifest-bound. |
| Neutral correlation terminology | completed, supported by current release and tests | No new UI replay was run after the stop. |
| Fail-closed durable reconstruction | completed and directly verified locally | Full suite passed at exact local HEAD. |
| Independent 40-case evaluation | completed and directly verified | Both frozen SHA-256 receipts pass. |
| GCP capacity expansion | completed and directly verified | `18890711040` bytes free. |
| Fresh backup and isolated restore | completed but supported mainly by prior evidence | Files and sizes remain; hash/integrity replay was not reached after stop. |
| Exact GCP deployment | completed and directly verified | Root manifest verification passed for 497 files. |
| Systemd hardening | completed and directly verified | Service properties and managed-unit validator passed. |
| Obsolete timer archival | completed and directly verified | No prohibited unit is installed or active. |
| Pi pre-persistence sanitization | completed and directly verified | Exact revision/manifest/policy; unsafe writer disabled; validator valid. |
| Stale-session reconciliation | partially completed | Five rows classified; evidence unchanged; no resolution policy applied. |
| Failed-job reconciliation | partially completed | Five terminal LeaseExpired rows identified; no unsafe retry or edit. |
| Rollback rehearsal | blocked | Required rollback release fails manifest and current authority compatibility gates. |
| Bounded load/restart/recovery | not started | Prohibited after rollback gate failure. |
| Final privacy/E2E replay | not started | Prohibited after rollback gate failure; prior acceptance remains evidence. |
| Dashboard terminology | completed, supported by deployed revision and local tests | No new UI smoke after stop. |
| Final project freeze | blocked for acceptance; feature freeze recommended | Current system must remain fixed in place pending rollback repair. |

## Tests and validators

Local at exact starting HEAD:

```text
996 passed, 7 skipped in 76.26s
```

An initial sandboxed run produced only the expected eight loopback socket
`PermissionError` failures and otherwise reported `988 passed, 7 skipped`.
The identical unrestricted run passed completely.

Also passed:

- frozen evaluation specification SHA-256 check;
- frozen evaluation result SHA-256 check;
- current GCP release manifest verification;
- GCP managed-unit validation;
- GCP SQLite quick and full integrity checks;
- Pi Cowrie output boundary validation.

Not run after the rollback stop:

- rollback release activation;
- backup tool verification and a new isolated restore;
- frozen-model standalone smoke replay;
- runtime-feed content checksum replay;
- isolated load, lock, WAL, lease, restart, retry, or recovery tests;
- bounded production restarts;
- a new privacy/E2E acceptance session;
- final artifact/API/monitor replay.

## Production-changing commands

None.

All SSH commands in this continuation were read-only inventory, hashing,
validation, SQLite read-only queries, journal reads, and Git/configuration
inspection. No GCP or Pi service was restarted. No backup, temporary remote
file, or database row was created.

## Readiness recalculation

These percentages are weighted readiness judgments, not test-coverage
averages. The "previous documented" column is the state at the earlier
privacy-blocker stop. Improvements credit the completed upstream sanitizer and
green local suite. Reductions retain the newly proven rollback incompatibility
and unperformed recovery acceptance.

| Dimension | Previous documented | Current evidence | Confidence | Limiting evidence |
| --- | ---: | ---: | --- | --- |
| Local implementation completeness | 94% | 96% | high | Privacy boundary is repository-owned and tests pass; legacy manifest compatibility remains defective. |
| Controlled PoC readiness | 84% | 90% | medium-high | Prior real E2E and privacy acceptance pass; final combined replay was not repeated. |
| Thesis presentation readiness | 88% | 92% | medium-high | System boundaries and limitations are demonstrable and auditable; rollback limitation must be disclosed. |
| Isolated deployment readiness | 90% | 84% | medium | Current release verifies, but the required rollback release cannot be verified or safely started. |
| Current deployed-system readiness | 84% | 88% | medium | Current GCP/Pi revisions and integrity pass; five failed enrichments and no final restart/recovery replay. |
| Production acceptance readiness | 70% | 72% | medium-low | Privacy improved materially, but rollback, bounded recovery, soak, independent model validation, and long-term operations remain incomplete. |

Selected subsystem readiness:

| Subsystem | Current readiness |
| --- | ---: |
| Pi collection and sanitized forwarding | 88% |
| GCP ingest and SQLite durability | 91% |
| Canonical reconstruction and classification | 82% |
| Typed semantics and `session_assessment.v4` | 86% |
| Transformer prediction and provenance | 83% |
| `response_guidance.v3` and alert authority | 93% |
| Reports, API, monitor and artifacts | 90% |
| Deployment, backup and manifest operations | 84% |
| Rollback, load and recovery operations | 50% |
| Privacy and retention compliance | 84% |
| Overall controlled system | 84% |

No score reaches 100% because there is no independently verified production
rollback, bounded recovery/load result, long-term production observation,
external model validation, full privacy-compliance assessment, or current
post-replay backup/restore acceptance.

## Supported and unsupported thesis claims

Still supported:

- Cowrie events pass through a pre-persistence credential sanitizer before the
  forwarder and GCP;
- observed evidence remains authoritative;
- predictions and enrichment remain contextual;
- six typed-semantic families are active under deterministic v4/v3 contracts;
- current guidance is manual-only and non-executable;
- current automatic alert and external delivery authority is prohibited;
- current GCP and Pi components are revision- and hash-verifiable;
- the full local suite passes.

Not supported:

- a safe production rollback to `7125cd8…`;
- completed isolated rollback compatibility;
- bounded load, restart, database-lock, lease, spool, or recovery performance;
- long-term production reliability or privacy compliance;
- production-grade classification or model accuracy;
- enterprise readiness;
- absence of credential plaintext from preserved pre-fix historical logs.

## Smallest safe next step

Do not change the active release.

The next session should:

1. Re-read this handoff and verify the local/GCP/Pi revisions are unchanged.
2. Add a local regression proving legacy v2 manifests with only
   manifest-recorded runtime bytecode differences can be normalized without
   ignoring any source, configuration, symlink, package, policy, or artifact
   mismatch.
3. Decide independently whether to:
   - use that compatibility fix only for an isolated, side-effect-disabled
     historical-reader rehearsal; or
   - create a new verified recovery release that preserves the current
     alert-authority, systemd, SQLite, model-bundle, v4/v3, and privacy
     boundaries.
4. Never regenerate files inside or rewrite the manifest of the preserved
   `7125cd8…` release.
5. Keep all webhook/external-delivery paths disabled and do not activate the
   older release in production unless its authority and configuration
   compatibility are independently proven.
6. Only after a rollback target passes exact manifests, database compatibility,
   isolated startup, and no-side-effect gates may stale-state reconciliation
   and bounded recovery acceptance resume.

Initial checks:

```sh
cd /home/rubchek/Desktop/teammate-repo/honeypot-analysis
git branch --show-current
git rev-parse HEAD
git status --short
pytest -q tests/test_release_manifest.py tests/test_alert_authority_boundaries.py
pytest -q
```

Safety condition: any proposed rollback must preserve the current Pi
pre-persistence sanitizer and the current GCP no-alert/no-delivery authority.
If that cannot be proven, retain the current release and accept isolated
reinstallation of the current package—not older runtime activation—as the
controlled-PoC recovery boundary.
