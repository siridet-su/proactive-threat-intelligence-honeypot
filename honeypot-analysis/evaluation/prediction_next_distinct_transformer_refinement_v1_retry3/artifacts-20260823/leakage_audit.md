# Leakage-boundary audit

Status: `COMPLETE_VALID`.

This supplemental audit closes the protocol section-38 artifact omission in the
frozen refinement namespace. It binds the exact search and post-selection source
hashes and records the source-line boundary: grouped TRAIN folds are used for
all architecture, loss, optimization, capacity, masking, seed, and candidate
decisions; Selection, Calibration, controlled synthetic, and OOD cohorts are
read only after the candidate is frozen. Sealed data was not accessed.

The original `receipt.json` is preserved byte-for-byte. This document and
`leakage_audit.json` are bound by the supplemental completion receipt and do not
retroactively alter the frozen base receipt's required-artifact set.
