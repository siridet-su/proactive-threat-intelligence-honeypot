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
