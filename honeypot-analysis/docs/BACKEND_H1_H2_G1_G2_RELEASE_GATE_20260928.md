# H1/H2/G1/G2 backend release gate — 2026-09-28

Status: **NOT RELEASED**. The operator requires the complete test suite to pass before deployment. No exception has been authorized.

## Candidate and active-host comparison

- The isolated candidate includes H1/H2 hypothesis-only logic and G1/G2 manual guidance from the prior preparation.
- The active GCP release is based on revision `917f0341959d6ee6599d38b8ba50e604302e4e46`. Read-only verification of its v7 release manifest fails: 3 of 917 inventoried files differ. The changed source paths are `production/ensemble/evidence.py`, `production/ensemble/model2_result_bridge.py`, and `production/ensemble/rrf_advisory.py`.
- Those three host changes admit an additional exact outcome-independent capture contract and index Model2 results by exact session with a hard file-count bound. The candidate now preserves their source behavior. No host file was modified while comparing them.
- No candidate release package, new manifest, pointer switch, service restart, MongoDB write, or new session has occurred.

## Validation completed

- New guidance regression: path-bounded actions had an empty legacy semantic-family trace, causing the entire guidance v3 projection to become unavailable. The candidate now retains the typed-fact predicate/evidence trace without claiming a legacy family selection. Frozen cross-family, filesystem, and combined-semantic checks pass again.
- Assessment/API/AI-presentation/ensemble/bounded-guidance/frozen-evaluation targeted group: 98 passed, 1 skipped. A separate Model2 bridge group: 7 passed. Both policy validators and `git diff --check` passed.
- Full `pytest tests -q` **cannot collect**: 13 test modules import symbols that the current source does not provide. These involve V6 controlled-synthetic provenance, AI projection v2, and retired/experimental next-behavior APIs. A prior broad source change removed many of these APIs while the test modules remained; adding no-op symbols would not validate their contracts.
- Running the other tests by explicitly omitting those 13 modules gives **2,129 passed, 77 skipped, 25 failed** after the guidance correction. Failures span missing private model assets, stale worker API assumptions, inactive systemd template assertions, Mongo capacity thresholds, historical policy/hash expectations, chain-selection and ATT&CK semantics, and old prediction paths. This is not a green release gate.

## Required before host activation

1. Decide, with evidence, whether each failing test is an active contract to repair or an obsolete contract that needs a formally reviewed replacement. Do not hide or delete failing tests to manufacture a green result.
2. Correct source/tests and rerun `pytest tests -q` successfully with the required frozen model assets available. Re-run the focused H1/H2/G1/G2 and Model2 bridge tests.
3. Build a clean immutable source archive from one commit containing the three reconciled ensemble paths. Create and verify a v7 release manifest with exact policy/model/dependency identities and a recoverable prior release.
4. Only then switch the GCP release pointer, restart affected units, verify health and report/API/PDF parity, and run one bounded authorized session through the real Pi route. Confirm that H1/H2 remain hypotheses and G1/G2 remain manual guidance with no automatic execution.

The existing out-of-manifest active-host state is not a substitute for a new verified release. No production activation is claimed by this record.

## 2026-09-28 current-runtime test addendum

The project owner selected alignment with the current runtime, not restoration of unsupported V6/AI-v2/next-behavior APIs. ADR-0010 records the boundary. Thirteen non-collecting historical modules are preserved in the research archive; 15 historical assertions remain in the active test files as individually documented strict expected failures. Current-policy tests were corrected for Atlas Flex's 5-GB capacity, managed systemd units, S1's private artifact boundary, and packaged service imports. **`pytest tests -q` exits successfully: 2,140 passed, 77 skipped, 15 strict expected failures, zero failures/collection errors.** Historical expected failures are not evidence of those experiments working. The immutable release, host, model identity, and live report/API/PDF gates remain pending.

## 2026-09-28 GCP staged-release gate addendum

The tested `6be281e2` package was pushed to staging and copied to a new, inactive GCP release. Its v7 manifest and separate CISA/Sigma/MITRE cache hash checks passed. The preserved runtime can import the changed modules but has no `pytest` installed, so the full suite was run in the clean local checkout. No active pointer or service was changed.

The live managed-unit guard then identified five already-enabled but unlisted external units: both Dashboard-v2 units, both Next-Distinct shadow units, and the watchdog timer. A new candidate policy records exactly those existing units as allowed external services. This does **not** enable or alter them. The first staged package is superseded; a fresh commit/package/manifest and full test rerun are required before activation.
