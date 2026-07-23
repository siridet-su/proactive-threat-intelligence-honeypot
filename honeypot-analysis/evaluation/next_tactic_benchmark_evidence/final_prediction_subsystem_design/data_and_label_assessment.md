# Data, input, and label assessment

## Verified dataset facts

- Payload: 219,336 closed SSH sessions and 178,922 adjacent-deduplicated transition cases.
- Transition-bearing sessions: 49,713.
- Current final Transformer fit: 158,476 transition cases from train plus the first validation half.
- Held-out test: 32,901 sessions, 3,342 transition-bearing sessions, 12,235 cases.
- Held-out diversity: 45 model-visible histories and 56 history-target pairs; 99.6322% of cases share an input history with another case.
- Test ambiguity: 7 of 45 histories map to multiple targets; those histories contain 47.5685% of cases.
- Test support: command-and-control 46, credential-access 2, defense-evasion 235, discovery 6,854, execution 2,845, impact 0, persistence 1,790, privilege-escalation 463.
- All accepted labels are classifier-derived weak labels. No direct safe-session overlap was found across preserved roles.
- Member/template identity and private timestamps are absent, so member-level contribution, template leakage, and chronological monotonicity are not independently testable.

## Current claim suitability

| Claim | Assessment | Basis |
|---|---|---|
| Performance on accepted historical next-distinct-tactic cases | Supported with limitations | Frozen hashes, disjoint safe-session roles, deterministic checkpoint replay |
| Unseen sessions from the same collection process | Partially supported | Session IDs are disjoint, but model-visible histories are extremely concentrated |
| Unseen time periods | Unsupported | No untouched future period and timestamps removed |
| Unseen corpus members | Not verifiable | Member identity removed |
| Live production telemetry | Unsupported | No meaningful production-local evaluation and historical/runtime feature contracts differ |
| General attacker behavior or intent | Unsupported | Cowrie-only observations and classifier-derived weak labels |

## Final input contract

The final model should use only fields that are observable before the forecast, reproducible in training, privacy-safe, and stable enough to survive sensor changes.

| Candidate | Exists live now | Reproducible from accepted payload | Final disposition | Reason |
|---|---:|---:|---|---|
| Ordered tactic phase sets | Yes, after grouping work | No; only flattened tactics survive | Model input, required | Primary sequential signal |
| Technique set per phase | Yes | No | Model input after provenance-preserving regeneration and ablation | Adds behavior specificity without raw commands |
| Phase repetition count | Derivable | No | Model input, bucketed | Restores information lost by deduplication |
| Phase duration/time since last label | Derivable from event times | No | Model input, bucketed, after timestamp retention | Distinguishes burst repetition from persistent phase |
| Trusted label source | Yes | No | Model input or reliability channel | Separates deterministic rule, SecureBERT, and agreement evidence |
| Confidence bucket | Yes | No | Reliability channel; never factual certainty | Helps model/monitor label uncertainty |
| Conflict/audit-only count | Yes | No | Monitoring and possible reliability channel | Unresolved conflict should not become target evidence |
| Command count and labeled-command count | Yes | No | Model input, bucketed | Measures observation maturity |
| Session age | Yes | No | Model input, bucketed | Conditions continuation versus end |
| Login outcome/authentication state | Yes | No | Model input | Stable Cowrie context available before prediction |
| Confirmed file transfer state | Yes | No | Model input only after identical historical extraction | Direct Cowrie observation, not enrichment |
| Coarse deterministic command-behavior category | Partly | No | Optional after a versioned rule contract and ablation | Avoid raw command vocabulary/template memorization |
| Protocol | Yes | Constant SSH in corpus | Monitoring only | No predictive variation in current corpus |
| Sensor/configuration ID | Yes | Configuration exists | Stratification/monitoring only | High shortcut and deployment-specific leakage risk |
| Source IP, ASN, country | Yes | Not retained | Exclude | Privacy, instability, and campaign shortcut risk |
| Threat-intelligence enrichment | Yes | Not retained | Exclude from model; display separately | Not behavior evidence and prone to availability drift |
| Raw command text | Yes | Not retained | Exclude from minimal final PoC | Privacy, memorization, portability, and preprocessing expansion |
| Session/campaign fingerprint | Yes | Not retained | Monitoring only | Can leak template/family identity |
| Future close status or future events | Known only later | N/A | Target construction only | Using it as input is leakage |

Tactic history alone is adequate for the accepted historical baseline, but insufficient for a final claim about live next behavior. The minimum final representation is a causal sequence of tactic-set phases with run length and label reliability, plus pre-prediction session maturity/authentication context.

## Final label contract

Each label must retain:

- event/command group identifier scoped to a pseudonymous session;
- event order and privacy-safe relative time;
- ATT&CK tactic and technique;
- source (`reviewed_rule`, `securebert`, or `rule_model_agreement`);
- source-policy version and hash;
- model checkpoint hash when applicable;
- raw classifier confidence and an explicitly versioned confidence bucket;
- agreement/conflict status;
- trust tier;
- exclusion reason when audit-only;
- the original behavior evidence reference or privacy-safe digest.

### Permitted uses

| Label category | Train | Select/validate | Calibration | Final test | Runtime display | Authoritative decisions |
|---|---:|---:|---:|---:|---:|---:|
| Reviewed deterministic rule, no conflict | Yes | Yes | Yes | Yes | Observed candidate with provenance | Only through existing canonical evidence policy, not prediction |
| Rule/SecureBERT agreement | Yes | Yes | Yes | Yes | Observed candidate with both sources | Same boundary |
| High-confidence SecureBERT-only, frozen hash, no conflict | Yes, separately flagged | Yes, with stratified metrics | Yes | Yes, report separately | Supporting weak label | Never by prediction alone |
| Low-confidence or unresolved conflict | No | No | No | No | Audit-only | Never |
| Emergency/unreviewed fallback | No | No | No | No | Audit-only | Never |
| Human-adjudicated subset | Yes only if adjudicator split is predeclared | Preferred for selection diagnostics | Preferred | Required as an independent quality audit | Gold-review marker | Human evidence remains distinct from model prediction |

Training weights based on label confidence are not recommended initially: classifier confidence is not necessarily label correctness and weighted loss would add another policy to tune. Use provenance-stratified evaluation first. If weighting is later studied, predeclare it and fit it without test access.

## Multiple labels and conflicts

- Labels from the same command/event are an unordered set.
- Exact duplicate tactic/technique labels within a group are removed, but source provenance is merged.
- Conflicting rule/model labels remain audit records and are excluded from trusted target construction.
- A later command with the same tactic set increments phase run length; it does not disappear.
- Different targets for the same input are valid aleatoric ambiguity and must not be resolved using test-set frequency.

## Data-quality deficiencies

1. The accepted public payload cannot reconstruct raw-to-label decisions.
2. No raw-member cryptographic hashes are retained.
3. Source member and template/family identities are absent.
4. Event grouping and simultaneous-label semantics are lost.
5. Repetition, time gaps, and terminal outcomes are lost.
6. Validation seed selection and calibration diagnostics are not independent.
7. Rare and absent tactics prevent broad tactic-balanced claims.
8. Historical training and live feature schemas are not the same.

## Regeneration decision

A new dataset and new model are required before calling the redesigned experimental subsystem final. Regeneration must start from authorized raw Cowrie events because the privacy-minimized accepted payload lacks command grouping, terminal labels, repetition, timing, and provenance. The accepted payload, checkpoint, benchmark, and unfavorable results must remain immutable historical evidence under their original schema and target wording.
