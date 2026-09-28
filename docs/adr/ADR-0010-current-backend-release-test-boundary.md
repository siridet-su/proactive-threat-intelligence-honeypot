# ADR-0010: Current backend release test boundary

- Status: Accepted for the H1/H2/G1/G2 backend candidate, 2026-09-28.
- Decision owner: project owner (selected alignment with current runtime rather than restoring experimental APIs).

## Context

The backend's active analysis worker builds `session_assessment.v4` with response guidance v3; the AI worker uses the current projection contract. Thirteen tests imported experimental Final-F V6, AI projection v2, or next-behavior preparation APIs that are absent from current production source. Another 15 historical assertions describe contracts not adopted by the current runtime. Keeping these as ordinary release failures encouraged restoring inactive code or altering frozen evaluation labels just to make a test command green.

## Decision

The release gate is `pytest tests -q` with no collection errors, failures, or unexpected passes. Historical tests that cannot import current source are preserved under `honeypot-analysis/research/historical_contract_tests_20260928/`; they are not release evidence. Historical assertions inside otherwise useful current test modules remain executable and use strict `xfail` with individual reasons. A new unexpected pass fails the suite and forces contract review. Frozen evaluation inputs and labels are not rewritten.

Active release coverage remains in `tests/` for assessment v4, response guidance v3, AI advisory, Model2 exact binding and the Next-Distinct PoC. A passing test suite is necessary but not sufficient: the immutable release manifest, private model identities, host health, and real-session API/PDF smoke must also pass. These checks cannot be waived by archiving an old test.

The current runtime is not changed to implement experimental V6/AI-v2/VOMM APIs. Historical test preservation is not a claim that those contracts are correct or active.

## Consequences

- The normal full-suite command can collect and assess current runtime tests.
- Historical `xfail` and archived modules remain visible research debt, not metrics or release success claims.
- Any proposal to promote an archived feature requires a new accepted contract, implementation, and release tests before enabling it.
- Release notes must report passed, skipped, and expected-failure counts separately.
