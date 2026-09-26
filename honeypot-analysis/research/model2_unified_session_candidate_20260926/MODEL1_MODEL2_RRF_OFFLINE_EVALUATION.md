# Model1 + unified Model2 — offline RRF contract and current result

**RRF performance:** NOT_COMPUTABLE.  
**Implementation status:** RRF mechanics remain research-only. A corrected unified 54F Model2 artifact was trained on controlled synthetic data, but there are no paired real Model1 outputs and no production path.

## 1. Frozen proposed formula

For a technique t that appears in at least one Model1 command ranking:

S(t) = w1 * [(1/N) * Σ_c I(t ∈ L_c)/(k + r_c(t))] + w2 * [G2(t)/(k + 1)]

Initial parameters: k=60, w1=1.0, w2=0.25.

- c is one unique Model1 command event after stable event-key deduplication.
- L_c is that command's ordered Model1 technique list; rank is 1-based.
- N is the count of deduplicated eligible Model1 command events.
- G2(t)=1 only for a fresh, identity/hash/schema-bound, eligible PRESENT from Model2; otherwise zero.
- The Model1 union is the only candidate set. Model2 cannot introduce a label absent from Model1.
- Model2 ABSENT never subtracts from Model1 in this first version.
- An unavailable/stale/misbound Model2 result returns exactly Model1-only RRF ordering.
- Score is an advisory rank score, not probability/confidence or trusted evidence.

The formula is contract-design, not an empirically selected optimum. No weights/thresholds were fit in this task.

## 2. Per-TTP gating

| TTP | Gate in this design |
|---|---|
| T1105 | Hard-blocked by default (`allow_t1105=false`). Valid benign-content retrieval within a Cowrie session is T1105-positive under the corrected semantics. The synthetic candidate still had 4 false positives among 64 no-transfer controls, so controlled and production T1105 gates remain blocked. |
| T1046 | In addition to full model/session/run/measurement/episode binding, require exact PCAP binding, Zeek binding, and complete network observation. |
| T1110 | Require exact full binding, fresh candidate identity, and complete auth-event binding. |

All three require exact expected model SHA, feature-contract SHA, status VALID_SHADOW, NON_AUTHORITATIVE_SHADOW_ONLY, valid generation timestamp within the configured maximum age, and matching session/run/measurement/episode identity. Any failure suppresses Model2 votes. This changes only advisory rank ordering; it does not create trusted findings or response actions.

## 3. Mechanics versus performance

Ten RRF mechanics tests pass: T1105 default block, T1046/T1110 evidence gates, missing/wrong identity/hash/stale fallback, naive-time and invalid-identity fail-closed behavior, ABSENT non-penalty, deterministic ties, command-event dedup and collision rejection, parent-technique normalization, Model1-only candidate-set restriction, and no probability/confidence output field.

The local controlled 54F artifact is not paired with independently labeled real Model1 outputs and is not wired into the existing RRF interface. Its synthetic confusion matrix is not ranking evidence. No exact paired independently labeled real final set exists. Thus top-1, MRR, Recall@K, Precision@K, false/correct promotion, fallback correctness on empirical data, and per-TTP rank-change rates are all NOT_COMPUTABLE.

## 4. Required future evaluation

After the unified candidate independently passes its own evaluation, use same sessions and Model1 outputs to compare (a) Model1-only RRF and (b) Model1 + gated binary Model2 vote. Freeze k/w1/w2, candidate identity, and gates before opening the sealed final. Include each TTP, all hard-negative and unavailable slices, candidate-set invariance, score/rank changes, and fallback counts. Do not tune on final. T1105 remains blocked until its own hard-negative gate passes; T1046/T1110 do not inherit a T1105 decision.
