# Final session-links delta reconciliation

Date: 2026-08-25 (Asia/Bangkok)  
Status: **PASS — LEGITIMATE CURRENT OUTPUT / FINAL LIVE VALIDATION COMPLETE**

## Determination

The observed `session_links` delta of **17** for controlled canonical session
`session_v1_c6b95688803b3afd472be748cc432498` was correct current application
output. The validator's fixed expectation of 15 was stale.

The two successful `ThreatHuntWorker` jobs produced nine IP relationships and
eight HASSH relationships. The immediately preceding controlled session
`session_v1_b532d2052253c259311e3824d0a4888c` had become one additional valid
relationship target for both observables. Those two exact additional rows were:

| Link | Observable | Created at | Target |
|---|---|---|---|
| `sessionlink_9be4119d1d64c6fe3f078b1c730b3361` | IP | `2026-08-25T13:06:57.283882+00:00` | `session_v1_b532d2052253c259311e3824d0a4888c` |
| `sessionlink_54b8e17028992f9c70dbb1dcf5594d5c` | HASSH | `2026-08-25T13:06:57.988447+00:00` | `session_v1_b532d2052253c259311e3824d0a4888c` |

All 17 rows had unique deterministic IDs, the controlled session as source,
`shared_observable` type, one of the two controlled-job producers, and creation
times after the bounded pre-cutover measurement. The source session was new,
so all 17 were inserts rather than updates. Historical sessions were legitimate
relationship targets; no historical job or replay produced these writes.

Classification: **A — `LEGITIMATE_CURRENT_OUTPUT`**. This was not an application
duplicate, historical replay, database measurement error, or unresolved delta.
The complete 17-row identity matrix and producer/job evidence are preserved in
`cleanup_audit/session_links_delta_reconciliation_20260825.json`.

## Validation-only repair

`cleanup_audit/remote_live_invariant_validator.py` no longer predicts a constant
link count. It reconstructs the exact deterministic identity set from the
controlled session's successful threat-hunt jobs and the current related-session
contract. It then requires exact expected/actual/window-set equality.

Historical-replay zero and canonical non-interference are checked independently.
An unrelated in-window row or a same-count identity substitution fails closed.
Normal validation failures atomically produce a terminal FAIL receipt. Focused
regressions in `cleanup_audit/test_remote_live_invariant_validator.py` passed:
**9 passed**. The final validator SHA-256 is
`612cdf287fd350ac5bb9ac4562dc1d85070d169e06a94fc0839b1f6c090ff8d9`.

No application, model, policy, network, activation-guard, candidate, or package
byte changed. Candidate `00d7e9594b11505c167f4e03bb3efffd9a90144b` remained
bound to package SHA-256
`4597c15dfbcc69030097d6fa2a0f55ab8f8df366d15f2a60445842dbe9945fae`.

## Preserved-evidence closure

The repaired validator completed a no-cutover run against the preserved failed
session: `PASS_PREFLIGHT`, 50 checks, zero errors, and exact 17/17/17
derived/actual/window link identity sets. Historical replay, bounded canonical
deltas, and canonical non-interference all passed.

Receipt:
`/var/lib/honeypot/validator_io_00d7_final_20260825/session_links_reconciled_preflight_receipt.json`

SHA-256:
`25a62ed66a18e72fd60ab32c66333150177d5b19cb49425ff18931f57c010f0d`

## Final promotion and live validation

The one authorized final attempt reused immutable candidate 00d7, the exact
epoch-bound rollback mirror, service-readable epoch permissions, and the
unchanged 300-second SQLite integrity deadline. The activation guard reached
candidate readiness. Exactly one bounded Cowrie session was generated through
the authoritative endpoint `100.118.43.30:22`.

Canonical session `session_v1_041963689ec3f6684ac0e6d30ea51705` completed
durable analysis, report creation, prediction, and both threat-hunt jobs. Its
dynamically derived link set was 19 (ten IP plus nine HASSH): each new controlled
session legitimately adds one related target for each shared observable. The
validator found exactly 19 expected, 19 actual, 19 in-window, zero missing,
zero unexpected, and zero out-of-contract rows.

The terminal receipt is `PASS`, with 50 true checks and zero errors:

`/var/lib/honeypot/validator_io_00d7_session_links_reconciled_20260825/final_live_invariant_receipt.json`

SHA-256:
`b4cf0da8f5839bf36be22203a220ff48e50cb72541901adc717f77fcba2254c5`

It proves received-at propagation, durable replay, V3 evidence cutoff and
trusted history, repaired semantic-label deduplication with evidence retained,
the V3 next-behavior contract, prediction completion, classifier/environment
binding, shadow non-authority, historical replay zero, bounded canonical
deltas, canonical non-interference, service health, and rollback readiness.

The activation guard finalized as `ACTIVATION_COMPLETED`; its receipt SHA-256 is
`497da5d384f69b6a1445cb93f4d996e19d2bdb43c54089a1708b982f70476dd5`.
The active release is now `00d7e9594b11505c167f4e03bb3efffd9a90144b`.
Release 403c remains intact as the verified recovery target. No rollback was
needed in the successful attempt, and no Git mutation was performed.

V3 DUPLICATE-LABEL DEFECT CLOSED —
SESSION_LINKS DELTA RECONCILED /
FINAL INVARIANT RECEIPT COMPLETED /
NEW IMMUTABLE RELEASE ACTIVE /
403C RETAINED AS RECOVERY
