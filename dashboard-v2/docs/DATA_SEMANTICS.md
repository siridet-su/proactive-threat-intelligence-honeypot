# Dashboard v2 data semantics

The dashboard presents several evidence lanes. They are intentionally not interchangeable.

## Evidence and authority lanes

| Lane | Representative fields/routes | Meaning | What it cannot establish |
|---|---|---|---|
| Observed telemetry | `/api/events`, session `events`, `event_id`, `eventid`, timestamps, sensor/source IP | Safe projections of recorded sensor/session observations | A future action, a model conclusion, or an automatic alert |
| Session/workflow state | `/api/sessions`, `/api/session`, `analysis_status`, job/report status | Session identity, timing, processing state, and bounded joins | That analysis is correct or that a session is malicious |
| Trusted observed ATT&CK | `observed_trusted_ttps`, tactics/TTPs | Projected trusted observed technique evidence when present | Correlated hypotheses or model forecasts |
| Model output | `/api/predictions/current`, `/api/prediction-snapshots`, `final_ranking`, `prediction`, `score` | Current or historical scorer output and its coverage/trust metadata | Ground truth, calibrated probability, or automatic action authority |
| Correlation | `correlated_ttp_hypotheses`, `session_links`, `campaigns`, `confidence_semantics` | Derived relationship/hypothesis across events/sessions | Direct observation or probability unless explicitly defined by the producer |
| Advisory/guidance | `/api/ai-advisory`, `/api/decisions/current`, `response_guidance` | Policy- or model-derived presentation guidance | An alert, execution command, authorization, or raw evidence |
| Alert records | `/api/alerts`, `authority_display` | Stored historical/legacy alert records | Current automatic alert authority; the UI labels this legacy |
| Human review | `/api/analyst-feedback`, `/api/feedback-review`, `/api/classification-review-labels` | Analyst/operator feedback and reviewed evaluation labels | Replacement of the underlying event or session record |
| Enrichment | `/api/observables`, `/api/enrichment-records`, sightings | Context around observed indicators and provider freshness | Unqualified truth; stale/provider status must remain visible |
| Health/freshness | health routes, `feed_status`, response `timestamp` | Service/readiness and data-as-of metadata | Proof that the dataset is populated or current |

The UI keeps raw/trusted evidence, model output, correlation, and advisory information in separate visual lanes on the session detail page. That separation is part of the contract.

## Scores, probabilities, and model identity

The current dashboard-v2 source labels model values generically (`score`, `weighted_score`, `prediction`, `final_ranking`) and explicitly states that scores are not calibrated probabilities. The current dashboard source contains no `FINAL_S1` or `LinearSVC` field name. If a backend snapshot includes provenance for a LinearSVC or another margin-based scorer, its raw decision margin remains a score, not a probability or confidence, unless a separately documented calibration field and calibration contract are present.

`prediction_snapshots` may also carry `trust_status`, `coverage`, `evidence_cutoff`, model maturity, calibration status, and scorer disagreement. Those qualifiers should be displayed or preserved when interpreting the result. A ranked tactic is a model selection, not an observed TTP.

The current UI limits the model lane to the first eight ranked entries and displays score values as `score`; it does not silently convert or normalize them. Backtest and calibration endpoints expose run metadata, not a guarantee that the current prediction is calibrated.

## Correlation semantics

Correlation records must carry their producer-defined semantics. The source semantic marker is `developer_defined_heuristic_policy_strength_not_probability`; legacy missing or malformed markers are represented as `legacy_unresolved_correlation_score_semantics`. `confidence`, `strength`, and similarly named values must not be read as probabilities merely because of their names. Session links, campaign membership, and correlated TTP hypotheses are derived hypotheses.

## Freshness and timestamps

Backend responses include a generated `timestamp`; rows may include `timestamp`, `created_at`, `updated_at`, `start_time`, `generated_at`, or `last_seen`. The dashboard’s `isFresh` helper compares an available timestamp with the response `asOf` time and marks a stream current when it is no more than 24 hours old. Invalid or missing timestamps produce an unknown state. Existing documents without a recent timestamp are not evidence that the service is live.

The dashboard page uses `/api/events` for latest-observed context and `/api/sessions` for session-derived activity; the threat-intel page uses session timestamps and snapshot rows. There is no polling or automatic refresh in the current source. A current-looking local browser clock alone is not data freshness.

## Redaction and safe fields

Public session/event views use the backend security projection. Event rows retain identifiers, timestamps, sensor/source metadata, and the `command_event` marker; command-shaped values are redacted. Generic row views expose table-specific metadata and recursively apply `public_payload`. Webhook target URLs are represented by hashes. The private `/api/internal/session-commands` route is outside this application contract.

## Empty, stale, and unavailable states

- Empty: a successful response contains no usable rows or no selected detail. The UI shows a section-specific empty state.
- Stale: a usable timestamp is older than 24 hours relative to the API response time. The UI labels the stream stale.
- Unknown: timestamp is unavailable or invalid; the UI does not call it current.
- Partial error: `Promise.allSettled` reports one or more endpoint failures while other results remain available.
- Detail failure: no usable `/api/session` detail remains after loading; the page shows the failure panel.
- Unavailable advisory/prediction: a valid response can explicitly say the artifact is pending, failed, superseded, unavailable, or abstained. This is different from a transport failure.

## Mutability

The dashboard-v2 BFF has no Mongo/application-data mutation route. `POST /api/auth` and `DELETE /api/auth` write or expire only the browser session cookie. Upstream feedback write routes exist in the broader monitor/dashboard service but are not allowlisted here.
