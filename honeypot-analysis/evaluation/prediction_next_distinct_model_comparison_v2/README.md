# Prediction-only Next-Distinct-Tactic model comparison V2

This namespace is a new, isolated reproduction of the frozen V1 comparison.
It reads the V1 dataset shards without changing them and writes only new V2
artifacts.  The prediction remains non-authoritative:

`P(next observed distinct trusted tactic | previous observed distinct trusted tactics)`

V2 adds per-epoch training history, privacy-safe per-case outputs, checkpoint
reload ablations, true deterministic prefix shuffles, and phase timing.  It
does not access sealed data, modify canonical analysis, or load any historical
or prior experimental weights.

The authoritative corrected run is `artifacts-20260823-final/`.  The
earlier `artifacts-20260823/` directory is preserved as a non-authoritative
engineering attempt: its metrics were valid, but its first reproducibility-map
serialization collapsed all seed keys and its first shuffle summary omitted
the changed-case union.  It is not used as V2 evidence.

`artifacts-20260823-corrected/` is also preserved as a superseded corrected
attempt; the final directory adds explicit calibration summaries and
checkpoint-provenance comparisons.
