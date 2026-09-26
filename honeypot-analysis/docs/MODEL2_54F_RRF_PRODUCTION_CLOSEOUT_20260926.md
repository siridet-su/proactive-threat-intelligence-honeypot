# Model2 54F + evidence-gated RRF production PoC closeout — 2026-09-26

## Decision

The controlled-synthetic unified Model2 candidate is deployed as a non-authoritative shadow PoC. Its qualified `PRESENT` decisions may change only the review order of TTP candidates already emitted by Model1. It cannot create a candidate, trusted finding, canonical write, or response action.

This deployment proves operational mechanics and exact evidence binding. It does not establish real-world accuracy or ranking lift over Model1.

## Deployed identity

- Model version: `MODEL2_UNIFIED_54F_CONTROLLED_SYNTHETIC_POC_20260926_V2`
- Serialized artifact SHA-256: `adff0e76507edfc4f5deadb02922917ff66962c6c2824eb25970ebf40a06b424`
- Feature contract SHA-256: `28cc1a43e59259c5939dacdb889cdbe4e13fbdaa71b197264e27907a071d13c1`
- Runtime model shape: one 54-feature artifact with independent T1105, T1046, and T1110 heads
- Quality status: `CONTROLLED_SYNTHETIC_POC_NOT_REAL_WORLD_ACCURACY`
- Capture contract: `OUTCOME_INDEPENDENT_FIXED_SESSION_WINDOW_V1`

Pi command and authentication inputs are converted to bounded projections before transport. Raw command text and credentials are not added to the Model2 transport contract. The GCP feature extractor accepts the projections and reconstructs the same 54-feature vector used by the controlled candidate.

## Recommendation formula

For each Model1 candidate at rank `r`:

```text
RRF(TTP) = 1 / (60 + r)
         + 0.25 / (60 + 1), only when the matching Model2 head is PRESENT
           and its technique-specific evidence gate passes
```

Properties:

- candidate set is Model1-only;
- Model2 `ABSENT` never subtracts;
- missing, stale, wrong-identity, wrong-binding, or unavailable Model2 preserves exact Model1 order;
- RRF output is an ordinal review score, not probability or confidence;
- raw Model1 margins and Model2 sigmoid decision scores are not numerically combined.

## Technique gates

- T1105 requires a bounded transfer-command projection and at least one exact episode-bound network flow. Its semantics are session-bound transfer activity, not proof that downloaded content executed.
- T1046 requires an exact-bound scan observation from the same session, run, measurement, and episode. Otherwise the head is unavailable.
- T1110 requires exact authentication binding. A Model2-only result still cannot enter the Model1 candidate set.

## End-to-end receipt

The final test used source session `eefa0bd9b0f1`, mapped to canonical session `session_v1_564e672478bcc5033ad0224752dcf3cb`.

- Model2 binding contained matching canonical/source session, run, measurement, and episode identifiers.
- Episode flow count: `1`.
- `t1105_transfer_observed`: `true`.
- Model1 T1105 result: `PRESENT`.
- Model2 T1105 result: `PRESENT` with relation `CORROBORATES`.
- RRF status: `EXPERIMENTAL_RRF`.
- Model2 support count: `1`.
- Model1 baseline order: `T1033, T1078, T1105, T1222`.
- Recommendation order: `T1105, T1033, T1078, T1222`.
- T1105 moved from baseline rank 3 to recommendation rank 1.
- T1105 components: Model1 `0.015873015873015872`, Model2 `0.004098360655737705`, total `0.019971376528753578`.
- T1046 remained unavailable with `t1046_not_observed`.
- A Model2-only T1110 result did not enter the recommendation candidates.
- Threat-hypothesis output remained available for the same session.

The Pi durable active queue drained to zero after the receiver sanitizer recursion was fixed. The runtime now contains one `sanitized_v7_event` wrapper based on one saved V6 sanitizer reference.

## Operational status at closeout

- Cowrie: active
- Pi observer: active
- Pi episode capture: active
- GCP receiver: active
- Model2 ensemble bridge: active
- dashboard API and monitor service: active
- dashboard release: `/opt/honeypot-dashboard-v2/releases/rrf-54f-20260926`
- dashboard rollback target: `/opt/honeypot-dashboard-v2/releases/ca9d7dd0-http-evidence`

## Remaining research limitations

The controlled dataset and sealed-final partition are synthetic and not independently escrowed real-session evidence. T1110 produced a `PRESENT` shadow result in the final single-success-login session, so its field false-positive behavior needs further evaluation. No paired independently adjudicated current-identity corpus exists for estimating Model1-only versus RRF ranking lift. These limitations do not invalidate the operational PoC but must remain explicit in reports and demonstrations.
