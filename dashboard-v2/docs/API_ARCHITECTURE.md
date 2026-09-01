# Dashboard v2 API architecture

This is a read-only dashboard data path with a local browser-session boundary. The current source does not put MongoDB credentials in the Next application and does not allow browser code to choose a database target.

## Request flow

```text
LoginForm --POST /api/auth--> Next auth handler --Set-Cookie--> browser

dashboard page --GET /api/... + cookie--> Next catch-all BFF
                                      |-- route allowlist
                                      |-- query bounds
                                      |-- server-only origin/token
                                      |-- timeout, JSON and size checks
                                      v
                              monitor_web (default :8090)
                                      |-- read authorization
                                      |-- route-specific bounded loaders
                                      v
                         public projection / redaction
                                      v
                         storage adapter / canonical backend
```

The BFF is implemented by `src/app/api/[...path]/route.ts`. Its `ROUTES` object is the source of truth for the 34 browser-visible GET mappings. The route is a dispatch boundary, not a datastore adapter: it forwards JSON and does not interpret Mongo documents.

The auth handler is `src/app/api/auth/route.ts`, with cookie derivation and timing-safe comparison in `src/lib/dashboardAuth.ts`. The browser client in `src/lib/api.ts` is GET-only, uses `cache: "no-store"`, parses JSON, and converts non-2xx responses to `DashboardApiError`.

## Upstream compatibility

The default BFF origin is `http://127.0.0.1:8090`, the existing `monitor_web` service. The active 2026-09-01 monitor deployment returns an incompatible success-with-error response or `404` for `/api/sessions`, `/api/session`, and `/api/events`; its bounded generic table routes are the current working contract. For this exact loopback origin, the BFF therefore uses the measured generic compatibility response first for those three browser keys and only probes the structured route if that compatibility request cannot produce a response. Other origins retain the structured-route probe/fallback behavior. `monitor_web` supplies liveness/readiness, the structured session/event/advisory routes, and the semantic/table routes. `dashboard_api` supplies the semantic/table routes and overlaps the health routes, but it does not implement the monitor-specific `/api/sessions`, `/api/session`, `/api/events`, or `/api/ai-advisory` paths. A deployment that changes `DASHBOARD_API_ORIGIN` must preserve this compatibility or those paths will return an upstream not-found response.

The private `monitor_web` route `/api/internal/session-commands` is intentionally excluded from the BFF allowlist. It requires loopback access and a separate raw-command admin token. The dashboard-v2 public session projection redacts command-shaped values and is not a raw-command viewer.

## Backend and storage layers

`monitor_web.py` routes structured requests to `load_snapshot()`, `load_session_detail()`, `load_ai_advisory_detail()`, or `_dashboard_get_payload()`. The latter maps the 20 generic table paths to the `DASHBOARD_TABLES` collection/table names and calls storage read methods. Public values are passed through `security.py` projections (`api_row_view`, `event_views`, `session_detail_view`, and `public_payload`). The storage backend and its runtime configuration determine whether the deployed service reads MongoDB Atlas, another approved backend, or an unavailable state; this source audit intentionally does not infer deployment state from the local development checkout.

Bounds are deliberate: generic table reads default to 100 and cap at 1000; semantic review endpoints cap at 5000; session snapshots and detail loaders have their own bounded scans/joins; the BFF caps a response at 8 MiB. There is no cursor or page-token contract in dashboard-v2.

## Security boundaries

- Browser authentication is a dashboard session cookie, not a Mongo credential.
- The upstream bearer token, if configured, is server-only and is never placed in `NEXT_PUBLIC_*` variables.
- The BFF rejects credential-bearing upstream origins, redirects, unexpected content types, and oversized bodies.
- The BFF exposes only GET data routes plus local cookie auth. It does not expose upstream `POST /analyst-feedback`, `POST /feedback`, command retrieval, or any Mongo write.
- Logout expires the dashboard cookie. It does not change application data.
- Public JSON uses safe projections and recursively redacts sensitive keys. This is a data-disclosure boundary, not a substitute for backend authorization.

## Failure and UI state relationship

The frontend uses `Promise.allSettled` so one failed endpoint can leave other cards usable. `DashboardApiError` messages are shown in a partial-error banner or a detail failure panel. Loading indicators exist for list/table areas; the detail page has no dedicated skeleton. Empty sections distinguish no returned rows from a request failure. Freshness labels are derived client-side from response timestamps and a 24-hour threshold; absence or invalid timestamps is shown as unknown rather than current.

See [`API.md`](./API.md) for all method/path contracts, [`FRONTEND_API_MAPPING.md`](./FRONTEND_API_MAPPING.md) for page consumers, and [`DATA_SEMANTICS.md`](./DATA_SEMANTICS.md) for authority and score interpretation.
