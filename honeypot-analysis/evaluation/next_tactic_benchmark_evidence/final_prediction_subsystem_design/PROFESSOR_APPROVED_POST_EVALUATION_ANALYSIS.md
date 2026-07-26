# Professor-approved PoC post-evaluation analysis

Status: `DERIVED_FROM_IMMUTABLE_FINAL_OUTPUT`

This analysis is separate from, and does not reinterpret, the original
`BLOCKED_AT_SELECTION` experiment. It uses only the immutable aggregate result
whose SHA-256 is
`3e82ccd46dd1114488e8e8c7cfc45522ded38ed580969f853687b233e5440c08`.
It did not reopen Final source data or execute either model on Final inputs.

The Final cohort contains 237,514 sessions and 336,089 examples. Across all 14
tactics, Transformer macro/micro/weighted F1 are 0.188117/0.747780/0.775956
and balanced accuracy is 0.598416. VOMM values are
0.244289/0.632459/0.568420 and 0.619261. On the six reportable tactics,
Transformer macro-F1 is 0.438940 versus VOMM 0.482706. Transformer has higher
micro and weighted F1 because it performs extremely well on high-support
execution and persistence while nearly saturating recall for discovery. Its
zero recall for credential-access, defense-evasion, and privilege-escalation
reduces macro and balanced results. VOMM detects defense-evasion and
privilege-escalation but entirely misses persistence and overpredicts
execution.

Under an objective prioritizing frequent-behavior aggregate performance, the
Transformer is preferable. Under an objective prioritizing tactic balance and
rare-behavior coverage, VOMM is preferable. Neither is universally superior.

The immutable output did not retain per-example targets, prediction sets,
calibrated probabilities, or input-context fields. Exact-set metrics, Hamming
loss, Jaccard, full-set paired analysis, calibration diagnostics, and context
buckets are therefore
`NOT_DETERMINABLE_FROM_IMMUTABLE_FINAL_OUTPUT`; they must not be reconstructed
by reopening Final Test.

The complete machine-readable derived bundle is local at
`/home/rubchek/.cache/honeypot-analysis/zenodo/21260400/professor_approved_poc_post_analysis_complete_0a15ab3`.
Its analysis JSON SHA-256 is
`6e3ae5ed8f0a1d4b5554f54581d6afa6c469fac730797538dc625d27f42aa7b4`.
The bundle is bound to non-Final Calibration runtime evidence SHA-256
`36f356ec6d194b3e2e4134d301dd58c9171b01e0f8375f3c872142dfaa295de5`.

The Calibration-input benchmark removed the true target before inference.
Transformer p50/p95/p99 latency was 4.520/20.251/25.011 ms at 119.616
inferences/s; checkpoint load was 1107.580 ms and size 27,400 bytes. VOMM
p50/p95/p99 was 0.0231/0.0266/0.0313 ms at 19,077.080 inferences/s; artifact
load was 678.620 ms and size 20,428,241 bytes. These are hardware-specific
non-Final measurements, not evidence of Final predictive performance.

The holdout remains a within-Zenodo temporal split with classifier-derived weak
labels, not external validation. Predictions are advisory and are not evidence
of attacker intent or authority for an operational action.
