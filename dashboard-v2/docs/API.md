# Dashboard v2 API

Status: source-backed contract for the current `dashboard-v2` tree, audited 2026-09-01.

This document describes the browser-visible contract. The implementation has 36 explicit method/path contracts: 34 authenticated `GET` paths dispatched by `src/app/api/[...path]/route.ts`, plus `POST` and `DELETE` on `/api/auth`. The catch-all Next route is one handler, not an additional logical endpoint.

## Architecture and authentication

The request path is:

```text
browser page/component
  -> same-origin Next.js BFF (`/api/...`)
  -> allowlisted upstream path
  -> monitor_web (default http://127.0.0.1:8090)
  -> storage adapter and public projection
  -> canonical datastore/artifacts selected by the deployed monitor service
```

The browser never receives a Mongo URI and never connects to MongoDB directly. The BFF reads `DASHBOARD_API_ORIGIN` and the optional server-only `DASHBOARD_API_READ_TOKEN`; it does not accept an origin or credential from the browser. A configured origin must be HTTP(S) and must not contain userinfo. The default monitor origin is the active `monitor_web` service. On the current `127.0.0.1:8090` deployment, the BFF uses the bounded generic table routes first for `/api/sessions`, `/api/session`, and `/api/events` because the corresponding structured routes currently return incompatible responses; other origins retain structured-route probing with compatibility fallback. `dashboard_api` implements the table and semantic dashboard paths but does not implement those four monitor-specific paths; pointing the BFF at it is therefore a deployment compatibility decision, not a second browser contract.

All `GET /api/...` requests require a valid `dashboard_v2_session` cookie before route dispatch. The cookie is an HMAC-SHA256 value derived from server-side operator credentials and `DASHBOARD_V2_SESSION_SECRET`; it is HttpOnly, SameSite=Lax, path-scoped, eight hours on login, and Secure in production. `POST /api/auth` and `DELETE /api/auth` are the only unauthenticated browser methods. The upstream monitor may additionally require a server-owned bearer read token; a loopback monitor with no configured read token can allow anonymous upstream reads, but that does not bypass the BFF cookie.

The BFF forwards only `GET`, sends `Accept: application/json`, disables caching, rejects redirects, applies a 15-second timeout, and caps response bodies at 8 MiB. Unknown query keys and overlong values are dropped. `limit` is capped at 1000 by the BFF, `offset` at 5000, and the upstream applies route-specific bounds. The backend generic table handlers use `limit` only; `offset` and `filter` are accepted by the BFF allowlist but have no generic-table effect. `session_id` is consumed by session-specific routes. `filter` is consumed by feedback review.

Every public backend JSON response passes through a redaction projection. Raw command detail is deliberately excluded from the public session view; `/api/internal/session-commands` is a separate loopback/admin monitor route and is not allowlisted by this BFF.

## Error contract

The BFF returns `401` for a missing/invalid dashboard session, `404` for an unknown allowlist key, `503` for an unsafe origin or unavailable upstream, and `502` for a non-JSON or oversized upstream response. An upstream `401`/`403` is normalized to `dashboard backend authorization failed`; an upstream `404` is normalized to `dashboard data was not found`; other upstream status codes are preserved with `dashboard backend request failed`. Backend route-specific errors below are therefore visible only after the BFF has admitted the request.

Authentication errors are `503` when server auth configuration is incomplete, `400` for malformed JSON, and `401` for invalid operator credentials. A successful login returns `{ "ok": true }` and sets the session cookie. Logout returns `{ "ok": true }` and expires it. Authentication changes only the dashboard session cookie; it does not write MongoDB or application records.

## Endpoint index

| Method | Browser path | Upstream path | Purpose | Data source / response shape | Frontend consumer |
|---|---|---|---|---|---|
| GET | `/api/health` | `/health` | Liveness | `monitor_web`; `{ok,service,timestamp}` | Dashboard fetch; not currently rendered |
| GET | `/api/health/live` | `/health/live` | Liveness | `monitor_web`; `{ok,service,timestamp}` | None |
| GET | `/api/health/ready` | `/health/ready` | Storage readiness | `monitor_web` health check; `{ok,service,timestamp}` | None |
| GET | `/api/live` | `/live` | Liveness alias | `monitor_web`; `{ok,service,timestamp}` | None |
| GET | `/api/ready` | `/ready` | Readiness alias | `monitor_web` health check; `{ok,service,timestamp}` | None |
| GET | `/api/sessions` | `/api/sessions` | Bounded session snapshot | `sessions`, plus bounded jobs/reports/events/evidence joins; `{ok,timestamp,summary,sessions,selected_session_id,error}` | Dashboard, Threat Intel |
| GET | `/api/session` | `/api/session` | One-session detail | `sessions` and bounded related tables; `session_detail_view` projection | Threat Intel session detail |
| GET | `/api/events` | `/api/events` | Global or session event view | `events`; `{ok,timestamp,events,error}` | Dashboard freshness/activity |
| GET | `/api/ai-advisory` | `/api/ai-advisory` | Stored advisory status/detail | advisory/outbox/report records; `{ok,status,advisory,metrics,...}` | Threat Intel session detail |
| GET | `/api/predictions/current` | `/predictions/current` | Current model snapshot and guidance | `prediction_snapshots` plus feedback; `{item,current_prediction,response_guidance,...}` | Threat Intel session detail |
| GET | `/api/decisions/current` | `/decisions/current` | Current response guidance | runtime policy plus optional snapshot; `{response_guidance,session_id,timestamp}` | None |
| GET | `/api/feedback-review` | `/feedback-review` | Feedback review aggregate | `analyst_feedback`; `{filter,items,review,timestamp}` | None |
| GET | `/api/classification-evaluation` | `/classification-evaluation` | Classification evaluation report | `classification_review_labels`; `{report,timestamp}` | None |
| GET | `/api/external-seed-health` | `/external-seed-health` | External seed artifact health | runtime config/artifact metadata; `{external_seed_health,timestamp}` | None |
| GET | `/api/events-table` | `/events` | Generic event rows | `events`; `{items,limit,table,timestamp}` | None |
| GET | `/api/sessions-table` | `/sessions` | Generic session rows | `sessions`; `{items,limit,table,timestamp}` | None |
| GET | `/api/alerts` | `/alerts` | Stored alert rows | `alerts`; generic table response | Dashboard, Threat Intel |
| GET | `/api/jobs` | `/jobs` | Analysis job rows | `analysis_jobs`; generic table response | Dashboard fetch; not currently rendered |
| GET | `/api/reports` | `/reports` | Report rows | `reports`; generic table response | None |
| GET | `/api/feed-status` | `/feed-status` | Feed status rows | `feed_status`; generic table response | None |
| GET | `/api/enrichment-records` | `/enrichment-records` | Enrichment rows | `enrichment_records`; generic table response | None |
| GET | `/api/enrichment-jobs` | `/enrichment-jobs` | Enrichment job rows | `enrichment_jobs`; generic table response | None |
| GET | `/api/prediction-snapshots` | `/prediction-snapshots` | Model snapshot rows | `prediction_snapshots`; generic table response | Threat Intel |
| GET | `/api/prediction-backtests` | `/prediction-backtests` | Backtest run rows | `prediction_backtest_runs`; generic table response | None |
| GET | `/api/prediction-calibrations` | `/prediction-calibrations` | Calibration run rows | `prediction_calibration_runs`; generic table response | None |
| GET | `/api/analyst-feedback` | `/analyst-feedback` | Analyst feedback rows | `analyst_feedback`; generic table response | None |
| GET | `/api/classification-review-labels` | `/classification-review-labels` | Review-label rows | `classification_review_labels`; generic table response | None |
| GET | `/api/observables` | `/observables` | Observable rows | `observables`; generic table response | None |
| GET | `/api/observable-sightings` | `/observable-sightings` | Observable sighting rows | `observable_sightings`; generic table response | None |
| GET | `/api/threat-hunt-jobs` | `/threat-hunt-jobs` | Threat-hunt job rows | `threat_hunt_jobs`; generic table response | None |
| GET | `/api/session-links` | `/session-links` | Session-link rows | `session_links`; generic table response | None |
| GET | `/api/campaigns` | `/campaigns` | Campaign rows | `campaigns`; generic table response | None |
| GET | `/api/campaign-sessions` | `/campaign-sessions` | Campaign membership rows | `campaign_sessions`; generic table response | None |
| GET | `/api/webhooks` | `/webhooks` | Webhook delivery rows | `webhook_deliveries`; generic table response | None |
| POST | `/api/auth` | local BFF | Establish dashboard session | Server-side env comparison; `{ok}` plus Set-Cookie | Login form |
| DELETE | `/api/auth` | local BFF | Expire dashboard session | Cookie deletion only; `{ok}` plus Set-Cookie | Main layout logout |

## Detailed endpoint contracts

The detailed entries below use synthetic examples. They contain no production identifiers, payloads, credentials, or raw commands.

### GET `/api/health`

- Purpose: report monitor liveness.
- Authentication: dashboard session at the BFF; monitor read authorization after forwarding.
- Parameters/body: none; extra query keys are ignored.
- Response: `200` `{ "ok": true, "service": "monitor_web", "timestamp": "2026-08-31T00:00:00Z" }`.
- Important fields and authority: `ok` is transport/service liveness, not evidence freshness or data authority.
- Errors: BFF `401`, unsafe-origin `503`, unavailable upstream `503`, non-JSON/oversized upstream `502`.
- Pagination/filter: none.
- Frontend consumer: `/dashboard` fetches it and stores it, but no current visible section renders the value.
- Source: BFF route map; `production/api/monitor_web.py` liveness branch.

### GET `/api/health/live`

- Purpose: explicit liveness alias.
- Authentication: same BFF and upstream read requirements as `/api/health`.
- Parameters/body: none.
- Response: the same `{ok,service,timestamp}` liveness object; no datastore query.
- Important fields and authority: operational signal only.
- Errors: BFF transport errors; the monitor liveness handler normally returns `200`.
- Pagination/filter: none. Frontend consumer: none.
- Source: `ROUTES.health/live` and `monitor_web.py` liveness set.

### GET `/api/health/ready`

- Purpose: report whether the monitor can open and health-check storage.
- Authentication: same BFF and upstream read requirements as `/api/health`.
- Parameters/body: none.
- Response: `200` with `{ok:true,...}` when ready, or `503` with `{ok:false,...}` when storage is not ready.
- Important fields and authority: readiness is an operational gate, not proof that current events exist.
- Errors: BFF errors; monitor uses `503` for failed storage readiness.
- Pagination/filter: none. Frontend consumer: none.
- Source: `monitor_web.py` readiness branch and storage `health_check()`.

### GET `/api/live`

- Purpose: short liveness alias.
- Authentication: same BFF and upstream read requirements as `/api/health`.
- Parameters/body: none.
- Response: `{ok,service,timestamp}` from monitor liveness.
- Important fields and authority: operational only. Errors: BFF transport errors; pagination/filter: none; frontend consumer: none.
- Source: BFF route map and monitor liveness set.

### GET `/api/ready`

- Purpose: short readiness alias.
- Authentication: same BFF and upstream read requirements as `/api/health/ready`.
- Parameters/body: none.
- Response: `{ok,service,timestamp}` with monitor storage readiness status.
- Important fields and authority: operational readiness only. Errors: BFF errors or monitor `503`; pagination/filter: none; frontend consumer: none.
- Source: BFF route map and monitor readiness set.

### GET `/api/sessions`

- Purpose: provide a bounded session snapshot and dashboard summary.
- Authentication: dashboard session plus upstream read authorization.
- Parameters/body: optional `session_id`; `limit` (monitor default 500, bounded by monitor to 5000 and BFF to 1000); `offset` (non-negative, BFF cap 5000). No body.
- Response: `{ok,timestamp,summary,sessions,selected_session_id,error}`. `summary` includes `total_sessions`, `shown_sessions`, `active_sessions`, `queued_jobs`, `succeeded_reports`, `skipped_no_command_sessions`, and `latest_updated`; session rows include identifiers, source IP/scope, times, status, command count, tactics/TTPs, and safe geography when available.
- Important fields and authority: session/event-derived operational evidence; status is a projection of analysis/job state, not a verdict. Command text is not exposed.
- Errors: `500` when snapshot storage work fails; BFF `401/502/503`; selected missing session does not itself fail the global snapshot.
- Pagination/filter: `limit` and `offset` are applied to the session listing; `filter` is ignored by the monitor session handler.
- Frontend consumers: `/dashboard` (map, activity, status, tactic, table, counts) and `/threat-intel` (status, log, tactic/TTP coverage, map, freshness).
- Source: `monitor_web.py` `/api/sessions`, `load_snapshot()`.

### GET `/api/session`

- Purpose: return one session and bounded related evidence/work products.
- Authentication: dashboard session plus upstream read authorization.
- Parameters/body: required `session_id`; no body.
- Response: public `session_detail_view` with `ok,timestamp,session_id,overview,source_geo,observables,commands,classification_events,observed_trusted_ttps,correlated_ttp_hypotheses,session_ttp_correlations,tactics,ttps,enrichment_status,session,events,events_table_rows,alerts,prediction_snapshots,analyst_feedback,session_links,threat_hunt_jobs,campaigns,enrichment_records,enrichment_jobs,analysis_jobs,reports,report_summary,response_guidance,errors`. The public projection redacts command-shaped sensitive values.
- Important fields and authority: `observed_trusted_ttps` is the trusted observed-evidence lane; correlations are hypotheses with explicit semantics; alerts are historical/legacy; model/advisory fields are not authoritative evidence.
- Errors: `404` for missing `session_id` or unavailable session; per-table errors are reported under `errors` when the detail remains usable; BFF errors also apply.
- Pagination/filter: no client pagination; backend bounds events and related rows (for example, 50 jobs/reports/predictions and a bounded event set).
- Frontend consumer: `/threat-intel/[id]` detail page.
- Source: `monitor_web.py` `load_session_detail()` and `security.py` `session_detail_view()`.

### GET `/api/events`

- Purpose: return safe event metadata globally or for one session.
- Authentication: dashboard session plus upstream read authorization.
- Parameters/body: optional `session_id`; no body.
- Response: `{ok,timestamp,events,error}` and, for the session form, `session_id`. Event views contain safe fields such as `event_id`, `eventid`, `timestamp`, `received_at`, `session_id`, `sensor_id`, `src_ip`, and `command_event`.
- Important fields and authority: events are raw/observed telemetry metadata after public projection; event views do not authorize predictions, alerts, or response guidance.
- Errors: session form returns `404` when the session detail is unavailable; global form returns `500` on snapshot failure; BFF errors apply.
- Pagination/filter: no client pagination; global and session event counts are bounded by monitor constants.
- Frontend consumers: `/dashboard` uses them for latest-observed/freshness/activity context. The detail page gets events through `/api/session`.
- Source: `monitor_web.py` event branch and `security.py` `event_views()`.

### GET `/api/ai-advisory`

- Purpose: expose the stored AI advisory status and safe advisory projection for a session.
- Authentication: dashboard session plus upstream read authorization.
- Parameters/body: required `session_id`; no body.
- Response: `{ok,status,session_id,advisory,metrics,timestamp}`. Advisory fields include schema/status/authority/validation/rendered advisory/shadow candidates/safety/provenance; statuses may be `not_available`, `pending`, `failed`, `superseded`, or `unavailable`.
- Important fields and authority: advisory output is explicitly non-authoritative and must not be treated as observed fact, an alert, or an action authorization.
- Errors: `404` for missing/unavailable advisory/session; BFF errors apply.
- Pagination/filter: none; backend selects bounded current/related advisory records. Frontend consumer: `/threat-intel/[id]` advisory panel.
- Source: `monitor_web.py` `load_ai_advisory_detail()`.

### GET `/api/predictions/current`

- Purpose: return the current model snapshot plus response guidance for one session.
- Authentication: dashboard session plus upstream read authorization.
- Parameters/body: required `session_id`; no body.
- Response: `{item,current_prediction,response_guidance,session_id,timestamp}`. `item` is the projected `prediction_snapshots` row; current prediction may include `prediction`, `final_ranking`, `trust_status`, `coverage`, `evidence_cutoff`, and generic `score`/`weighted_score` fields.
- Important fields and authority: model output is advisory/non-authoritative. Scores are raw model/scorer values and are not calibrated probabilities unless a separately named calibrated field says so. The current dashboard source contains no `FINAL_S1` or `LinearSVC` field contract; any backend provenance for such a model must retain uncalibrated decision-margin semantics.
- Errors: `400` without `session_id`, `404` without a current snapshot, BFF errors apply.
- Pagination/filter: none; feedback lookup is bounded internally. Frontend consumer: `/threat-intel/[id]` model lane.
- Source: `monitor_web.py` prediction branch and `security.py` row projection.

### GET `/api/decisions/current`

- Purpose: return current response guidance derived from runtime policy and an optional model snapshot.
- Authentication: dashboard session plus upstream read authorization.
- Parameters/body: required `session_id`; no body.
- Response: `{response_guidance,session_id,timestamp}`.
- Important fields and authority: guidance is policy/advisory output, not a raw event, trusted ATT&CK observation, automatic alert, or action execution.
- Errors: `400` without `session_id`; storage/backend errors may surface as upstream failures; BFF errors apply.
- Pagination/filter: none. Frontend consumer: none in the current dashboard-v2 tree.
- Source: `monitor_web.py`/`dashboard_api.py` decision branch.

### GET `/api/feedback-review`

- Purpose: summarize analyst feedback and return a bounded review set.
- Authentication: dashboard session plus upstream read authorization.
- Parameters/body: `limit` default 1000, max 5000; `filter` default `all`, normalized to `all`, `wrong`, `useful`, `high_confidence_wrong`, `low_confidence_useful`, `missing_actual`, `classification_error`, `missing_transition_evidence`, `policy_review`, or `needs_review`. No body.
- Response: `{filter,items,review,timestamp}`. `review` is `feedback_review.v1` with counts, failure categories, weak-source indicators, recurring weak predictions, and recommendations.
- Important fields and authority: feedback is an analyst/operator signal and may be a human-reviewed label; it does not rewrite raw evidence. The review report is an evaluation/triage projection.
- Errors: invalid filters normalize to `all`; storage/backend failures and BFF errors apply. Pagination/filter: only the first 100 filtered items are returned, while the aggregate is computed over the bounded input.
- Frontend consumer: none in the current dashboard-v2 tree.
- Source: `monitor_web.py` feedback branch and `reporting/feedback_review.py`.

### GET `/api/classification-evaluation`

- Purpose: return classification evaluation metrics from review labels.
- Authentication: dashboard session plus upstream read authorization.
- Parameters/body: `limit` default 1000, max 5000; no body.
- Response: `{report,timestamp}` where `report.schema_version` is `classification_evaluation.v1` and includes coverage, abstention, tactic/TTP accuracy and macro-F1, confusion, and source/command breakdowns.
- Important fields and authority: reviewed labels are evaluation evidence, not a live command classification authorization. Metrics describe the bounded review sample.
- Errors: invalid limit falls back to default; storage/backend and BFF errors apply. Pagination/filter: bounded by `limit`; no filter.
- Frontend consumer: none in current dashboard-v2.
- Source: `monitor_web.py` classification branch and `classification/classification_evaluation.py`.

### GET `/api/external-seed-health`

- Purpose: expose the health/status of configured external seed artifacts.
- Authentication: dashboard session plus upstream read authorization.
- Parameters/body: none.
- Response: `{external_seed_health,timestamp}` with config/artifact status fields.
- Important fields and authority: artifact health is provenance/operational metadata; it is not proof that a seed prediction is correct or authoritative.
- Errors: backend config/artifact errors are represented by the payload or upstream failure; BFF errors apply. Pagination/filter: none.
- Frontend consumer: none in current dashboard-v2.
- Source: `monitor_web.py` external-seed branch.

### GET `/api/events-table`

- Purpose: generic tabular event rows.
- Authentication: dashboard session plus upstream read authorization.
- Parameters/body: optional `limit` default 100, max 1000; no body. BFF may pass `offset`/`filter`, but the generic backend ignores them.
- Response: `{items,limit,table:"events",timestamp}`. Projected fields include common identifiers/times plus `sensor_id`, `src_ip`, `eventid`, `timestamp`, `received_at`, `processed`, and `command_event`.
- Important fields and authority: raw event metadata projection; no raw command content is guaranteed or intended. Errors: backend/BFF errors; pagination/filter: limit only, bounded.
- Frontend consumer: none. Source: BFF `events-table` map, `dashboard_api.TABLES`, `security.api_row_view()`.

### GET `/api/sessions-table`

- Purpose: generic tabular session rows.
- Authentication: dashboard session plus upstream read authorization.
- Parameters/body: optional `limit` default 100, max 1000; generic backend ignores `offset`/`filter`.
- Response: `{items,limit,table:"sessions",timestamp}` with session identifiers, source IP/scope, start/update times, ended/source flags, derived sensor/command/tactic/TTP/analysis fields.
- Important fields and authority: session records and derived operational state; not a replacement for the structured `/api/sessions` snapshot. Errors: backend/BFF errors; pagination/filter: limit only; frontend consumer: none.
- Source: BFF map, `dashboard_api.TABLES`, `api_row_view()`.

### GET `/api/alerts`

- Purpose: generic stored alert rows.
- Authentication: dashboard session plus upstream read authorization.
- Parameters/body: optional `limit` default 100, max 1000; generic backend ignores `offset`/`filter`.
- Response: `{items,limit,table:"alerts",timestamp}` with identifiers, severity, reason, delivery state, and `authority_display:"historical_legacy_alert"` when projected.
- Important fields and authority: alerts are historical/legacy records and do not represent current automatic alert authority. Errors: backend/BFF errors; pagination/filter: limit only.
- Frontend consumers: `/dashboard` and `/threat-intel` use bounded rows for critical-alert counts. Source: table map and `api_row_view()`.

### GET `/api/jobs`

- Purpose: generic analysis-job rows.
- Authentication: dashboard session plus upstream read authorization.
- Parameters/body: optional `limit` default 100, max 1000; generic backend ignores `offset`/`filter`.
- Response: `{items,limit,table:"analysis_jobs",timestamp}` with job/session/report identifiers, status, retry/priority fields, and errors where available.
- Important fields and authority: operational workflow state, not evidence or model truth. Errors: backend/BFF errors; pagination/filter: limit only.
- Frontend consumer: `/dashboard` fetches this endpoint but current rendering does not use the returned rows (orphan fetch). Source: table map and `api_row_view()`.

### GET `/api/reports`

- Purpose: generic report rows.
- Authentication: dashboard session plus upstream read authorization.
- Parameters/body: optional `limit` default 100, max 1000; generic backend ignores `offset`/`filter`.
- Response: `{items,limit,table:"reports",timestamp}` with report identifiers/times, summary, and confidence when projected.
- Important fields and authority: reports are derived work products; summary/confidence must not be read as raw event facts. Errors: backend/BFF errors; pagination/filter: limit only; frontend consumer: none.
- Source: table map and `api_row_view()`.

### GET `/api/feed-status`

- Purpose: generic feed status rows.
- Authentication: dashboard session plus upstream read authorization.
- Parameters/body: optional bounded `limit`; no body; generic backend ignores `offset`/`filter`.
- Response: `{items,limit,table:"feed_status",timestamp}` with status, last-success, and stale indicators.
- Important fields and authority: operational freshness metadata, not event evidence. Errors: backend/BFF errors; pagination/filter: limit only; frontend consumer: none.
- Source: table map and `api_row_view()`.

### GET `/api/enrichment-records`

- Purpose: generic enrichment records.
- Authentication: dashboard session plus upstream read authorization.
- Parameters/body: optional bounded `limit`; no body; generic backend ignores `offset`/`filter`.
- Response: `{items,limit,table:"enrichment_records",timestamp}` with observable identity, first/last seen, expiry, sighting count, stale, and provider status fields.
- Important fields and authority: enrichment is contextual/third-party derived metadata; stale/provider status must remain visible. Errors: backend/BFF errors; pagination/filter: limit only; frontend consumer: none.
- Source: table map and `api_row_view()`.

### GET `/api/enrichment-jobs`

- Purpose: generic enrichment job rows.
- Authentication: dashboard session plus upstream read authorization.
- Parameters/body: optional bounded `limit`; no body; generic backend ignores `offset`/`filter`.
- Response: `{items,limit,table:"enrichment_jobs",timestamp}` with job status, observable, priority, attempts, retry time, report/error fields.
- Important fields and authority: operational enrichment workflow state, not raw evidence. Errors: backend/BFF errors; pagination/filter: limit only; frontend consumer: none.
- Source: table map and `api_row_view()`.

### GET `/api/prediction-snapshots`

- Purpose: generic model snapshot rows.
- Authentication: dashboard session plus upstream read authorization.
- Parameters/body: optional bounded `limit`; no body; generic backend ignores `offset`/`filter`.
- Response: `{items,limit,table:"prediction_snapshots",timestamp}` with snapshot/session/event identifiers, generated time, prediction/ranking, features hash, trust status, coverage, and evidence cutoff.
- Important fields and authority: model output is advisory/non-authoritative; a score is not automatically a probability. Frontend consumer: `/threat-intel` counts available snapshots. Errors: backend/BFF errors; pagination/filter: limit only.
- Source: table map and `api_row_view()`.

### GET `/api/prediction-backtests`

- Purpose: generic prediction backtest-run rows.
- Authentication: dashboard session plus upstream read authorization.
- Parameters/body: optional bounded `limit`; no body; generic backend ignores `offset`/`filter`.
- Response: `{items,limit,table:"prediction_backtest_runs",timestamp}` with run/generated/metrics fields.
- Important fields and authority: offline evaluation metadata, not a live prediction or event. Errors: backend/BFF errors; pagination/filter: limit only; frontend consumer: none.
- Source: table map and `api_row_view()`.

### GET `/api/prediction-calibrations`

- Purpose: generic prediction calibration-run rows.
- Authentication: dashboard session plus upstream read authorization.
- Parameters/body: optional bounded `limit`; no body; generic backend ignores `offset`/`filter`.
- Response: `{items,limit,table:"prediction_calibration_runs",timestamp}` with run/generated/metrics/applied fields.
- Important fields and authority: calibration metadata is only authoritative for fields explicitly marked calibrated; raw scores remain non-probabilistic. Errors: backend/BFF errors; pagination/filter: limit only; frontend consumer: none.
- Source: table map and `api_row_view()`.

### GET `/api/analyst-feedback`

- Purpose: generic analyst feedback rows.
- Authentication: dashboard session plus upstream read authorization.
- Parameters/body: optional bounded `limit`; no body; generic backend ignores `offset`/`filter`.
- Response: `{items,limit,table:"analyst_feedback",timestamp}` with label/operator signal, evidence origin, eligibility, predicted/actual tactic fields, and status.
- Important fields and authority: human/operator feedback is a review signal; it is not a raw event and does not mutate evidence through this GET route. Errors: backend/BFF errors; pagination/filter: limit only; frontend consumer: none.
- Source: table map and `api_row_view()`.

### GET `/api/classification-review-labels`

- Purpose: generic reviewed classification-label rows.
- Authentication: dashboard session plus upstream read authorization.
- Parameters/body: optional bounded `limit`; no body; generic backend ignores `offset`/`filter`.
- Response: `{items,limit,table:"classification_review_labels",timestamp}` with command index, predicted/reviewed TTP/tactic, source, and confidence fields.
- Important fields and authority: reviewed labels are evaluation evidence, not an automatic live classification decision. Errors: backend/BFF errors; pagination/filter: limit only; frontend consumer: none.
- Source: table map and `api_row_view()`.

### GET `/api/observables`

- Purpose: generic observable rows.
- Authentication: dashboard session plus upstream read authorization.
- Parameters/body: optional bounded `limit`; no body; generic backend ignores `offset`/`filter`.
- Response: `{items,limit,table:"observables",timestamp}` with observable value/type, first/last seen, expiry, sightings, stale, and provider status.
- Important fields and authority: observed/derived observable identity and enrichment state; not a command or authorization. Errors: backend/BFF errors; pagination/filter: limit only; frontend consumer: none.
- Source: table map and `api_row_view()`.

### GET `/api/observable-sightings`

- Purpose: generic observable-sighting rows.
- Authentication: dashboard session plus upstream read authorization.
- Parameters/body: optional bounded `limit`; no body; generic backend ignores `offset`/`filter`.
- Response: `{items,limit,table:"observable_sightings",timestamp}` with observable, sensor, source IP, event ID, role/source, and timestamp.
- Important fields and authority: sighting metadata is an observed linkage projection; it does not make an enrichment claim authoritative. Errors: backend/BFF errors; pagination/filter: limit only; frontend consumer: none.
- Source: table map and `api_row_view()`.

### GET `/api/threat-hunt-jobs`

- Purpose: generic threat-hunt job rows.
- Authentication: dashboard session plus upstream read authorization.
- Parameters/body: optional bounded `limit`; no body; generic backend ignores `offset`/`filter`.
- Response: `{items,limit,table:"threat_hunt_jobs",timestamp}` with job status, observable, priority/attempt/retry, report, and error fields.
- Important fields and authority: operational/analyst workflow state, not proof of a threat. Errors: backend/BFF errors; pagination/filter: limit only; frontend consumer: none.
- Source: table map and `api_row_view()`.

### GET `/api/session-links`

- Purpose: generic session-link rows.
- Authentication: dashboard session plus upstream read authorization.
- Parameters/body: optional bounded `limit`; no body; generic backend ignores `offset`/`filter`.
- Response: `{items,limit,table:"session_links",timestamp}` with paired sessions, link/observable identity, confidence, and `confidence_semantics`.
- Important fields and authority: links are correlation hypotheses; `confidence_semantics` distinguishes heuristic policy strength from probability. Errors: backend/BFF errors; pagination/filter: limit only; frontend consumer: none.
- Source: table map, `api_row_view()`, and correlation semantics.

### GET `/api/campaigns`

- Purpose: generic campaign rows.
- Authentication: dashboard session plus upstream read authorization.
- Parameters/body: optional bounded `limit`; no body; generic backend ignores `offset`/`filter`.
- Response: `{items,limit,table:"campaigns",timestamp}` with primary fingerprint/source IP, session count, time range, severity, and confirmed tactics.
- Important fields and authority: campaign grouping is derived correlation, not raw observation. Errors: backend/BFF errors; pagination/filter: limit only; frontend consumer: none.
- Source: table map and `api_row_view()`.

### GET `/api/campaign-sessions`

- Purpose: generic campaign membership rows.
- Authentication: dashboard session plus upstream read authorization.
- Parameters/body: optional bounded `limit`; no body; generic backend ignores `offset`/`filter`.
- Response: `{items,limit,table:"campaign_sessions",timestamp}` with campaign/session IDs, confidence, match reasons, and confidence semantics.
- Important fields and authority: membership is a derived correlation hypothesis; it is not a direct event fact. Errors: backend/BFF errors; pagination/filter: limit only; frontend consumer: none.
- Source: table map and `api_row_view()`.

### GET `/api/webhooks`

- Purpose: generic webhook delivery rows.
- Authentication: dashboard session plus upstream read authorization.
- Parameters/body: optional bounded `limit`; no body; generic backend ignores `offset`/`filter`.
- Response: `{items,limit,table:"webhook_deliveries",timestamp}` with alert/report IDs, target URL hash, attempts, and last error; raw targets are not exposed.
- Important fields and authority: delivery/workflow metadata only. The current dashboard BFF exposes this read path; it does not expose a webhook write operation. Errors: backend/BFF errors; pagination/filter: limit only; frontend consumer: none.
- Source: table map and `api_row_view()`.

### POST `/api/auth`

- Purpose: authenticate the dashboard operator and establish the browser session cookie.
- Authentication: no existing dashboard cookie required; compares request values to server-only `DASHBOARD_V2_OPERATOR_ID` and `DASHBOARD_V2_ACCESS_KEY` using a timing-safe comparison.
- Parameters/body: JSON object `{operator_id:string,access_key:string}`. No query parameters.
- Response: `200` `{ "ok": true }` plus `Set-Cookie: dashboard_v2_session=...`; the token value must not be copied into documentation or logs.
- Important fields and authority: this is UI session establishment only; it does not identify a Mongo user or authorize application writes.
- Errors: `503` auth configuration incomplete, `400` malformed JSON, `401` invalid credentials.
- Pagination/filter: none. Frontend consumer: `/login` `LoginForm`.
- Source: `src/app/api/auth/route.ts` and `src/lib/dashboardAuth.ts`.

### DELETE `/api/auth`

- Purpose: log out and expire the dashboard session cookie.
- Authentication: no existing cookie required; it is safe to call from the logout control.
- Parameters/body: none.
- Response: `200` `{ "ok": true }` plus an expired `dashboard_v2_session` cookie.
- Important fields and authority: cookie lifecycle only; no application/database mutation.
- Errors: no route-specific error path in the current handler; BFF/browser transport errors may still occur. Pagination/filter: none.
- Frontend consumer: main dashboard layout logout control.
- Source: `src/app/api/auth/route.ts` and `src/lib/dashboardAuth.ts`.

## Implementation references

- BFF allowlist, query filtering, timeout, size cap, and error mapping: `src/app/api/[...path]/route.ts`.
- Cookie/session implementation: `src/app/api/auth/route.ts`, `src/lib/dashboardAuth.ts`.
- Browser client and error conversion: `src/lib/api.ts`.
- Monitor route dispatch and bounded snapshot/detail loading: `production/api/monitor_web.py`.
- Generic table map and semantic handlers: `production/api/dashboard_api.py`.
- Public redaction, row projections, event views, session detail views, and authorization: `production/api/security.py`.
- Correlation semantics: `production/correlation/semantics.py`.
- The machine-readable endpoint list is [`API_ENDPOINT_INVENTORY.csv`](./API_ENDPOINT_INVENTORY.csv); the consistency check is [`verify_endpoint_inventory.mjs`](./verify_endpoint_inventory.mjs).
