import { validDashboardSession } from "@/lib/dashboardAuth";

export const runtime = "nodejs";

const ROUTES: Record<string, string> = {
  "health": "/health",
  "health/live": "/health/live",
  "health/ready": "/health/ready",
  "live": "/live",
  "ready": "/ready",
  "sessions": "/api/sessions",
  "session": "/api/session",
  "events": "/api/events",
  "ai-advisory": "/api/ai-advisory",
  "predictions/current": "/predictions/current",
  "decisions/current": "/decisions/current",
  "feedback-review": "/feedback-review",
  "classification-evaluation": "/classification-evaluation",
  "external-seed-health": "/external-seed-health",
  "events-table": "/events",
  "sessions-table": "/sessions",
  "alerts": "/alerts",
  "jobs": "/jobs",
  "reports": "/reports",
  "feed-status": "/feed-status",
  "enrichment-records": "/enrichment-records",
  "enrichment-jobs": "/enrichment-jobs",
  "prediction-snapshots": "/prediction-snapshots",
  "prediction-backtests": "/prediction-backtests",
  "prediction-calibrations": "/prediction-calibrations",
  "analyst-feedback": "/analyst-feedback",
  "classification-review-labels": "/classification-review-labels",
  "observables": "/observables",
  "observable-sightings": "/observable-sightings",
  "threat-hunt-jobs": "/threat-hunt-jobs",
  "session-links": "/session-links",
  "campaigns": "/campaigns",
  "campaign-sessions": "/campaign-sessions",
  "webhooks": "/webhooks",
};

const ALLOWED_QUERY_KEYS = new Set(["session_id", "limit", "offset", "filter"]);
const ALLOWED_FILTERS = new Set(["all", "wrong", "useful", "high_confidence_wrong", "low_confidence_useful", "missing_actual", "classification_error", "missing_transition_evidence", "policy_review", "needs_review"]);
const MAX_QUERY_VALUE_LENGTH = 256;
const MAX_RESPONSE_BYTES = 8 * 1024 * 1024;

type JsonRecord = Record<string, unknown>;

interface UpstreamJson {
  status: number;
  body: unknown;
}

interface TableRowsResult {
  body: JsonRecord;
  rows: JsonRecord[];
}

function isRecord(value: unknown): value is JsonRecord {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

function asRecord(value: unknown): JsonRecord {
  return isRecord(value) ? value : {};
}

function recordText(record: JsonRecord, key: string): string {
  const value = record[key];
  return typeof value === "string" ? value : value === undefined || value === null ? "" : String(value);
}

function pickFields(record: JsonRecord, fields: readonly string[]): JsonRecord {
  const output: JsonRecord = {};
  for (const field of fields) {
    if (record[field] !== undefined) output[field] = record[field];
  }
  return output;
}

function jsonResponse(body: unknown, status = 200): Response {
  const serialized = JSON.stringify(body);
  if (new TextEncoder().encode(serialized).byteLength > MAX_RESPONSE_BYTES) {
    return new Response(JSON.stringify({ error: "dashboard response exceeded the safe limit" }), {
      status: 502,
      headers: {
        "content-type": "application/json; charset=utf-8",
        "cache-control": "no-store",
      },
    });
  }
  return new Response(serialized, {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}

function upstreamError(status: number): Response {
  const message = status === 401 || status === 403
    ? "dashboard backend authorization failed"
    : status === 404
      ? "dashboard data was not found"
      : "dashboard backend request failed";
  const safeStatus = status >= 400 && status <= 599 ? status : 502;
  return jsonResponse({ error: message }, safeStatus);
}

function upstreamOrigin(): URL {
  const configured = process.env.DASHBOARD_API_ORIGIN?.trim() || "http://127.0.0.1:8090";
  const origin = new URL(configured);
  if (!(["http:", "https:"] as string[]).includes(origin.protocol)) {
    throw new Error("DASHBOARD_API_ORIGIN must use http or https");
  }
  if (origin.username || origin.password) {
    throw new Error("DASHBOARD_API_ORIGIN must not contain credentials");
  }
  origin.pathname = origin.pathname.replace(/\/$/, "");
  origin.search = "";
  origin.hash = "";
  return origin;
}

function safeQuery(request: Request): string {
  const incoming = new URL(request.url).searchParams;
  const outgoing = new URLSearchParams();
  for (const [key, value] of incoming.entries()) {
    if (!ALLOWED_QUERY_KEYS.has(key) || value.length > MAX_QUERY_VALUE_LENGTH) {
      continue;
    }
    if (key === "limit") {
      const limit = Number(value);
      if (!Number.isInteger(limit) || limit < 1) continue;
      outgoing.set(key, String(Math.min(limit, 1000)));
      continue;
    }
    if (key === "offset") {
      const offset = Number(value);
      if (!Number.isInteger(offset) || offset < 0) continue;
      outgoing.set(key, String(Math.min(offset, 5000)));
      continue;
    }
    if (key === "filter" && !ALLOWED_FILTERS.has(value)) continue;
    outgoing.set(key, value);
  }
  const encoded = outgoing.toString();
  return encoded ? `?${encoded}` : "";
}

function tableQuery(request: Request, defaultLimit: number): string {
  const encoded = safeQuery(request);
  const query = new URLSearchParams(encoded.slice(1));
  if (!query.has("limit")) query.set("limit", String(defaultLimit));
  return `?${query.toString()}`;
}

async function fetchUpstreamJson(target: URL, headers: Headers): Promise<UpstreamJson> {
  const upstream = await fetch(target, {
    method: "GET",
    headers,
    cache: "no-store",
    redirect: "error",
    signal: AbortSignal.timeout(15_000),
  });
  const contentLength = Number(upstream.headers.get("content-length") || 0);
  if (contentLength > MAX_RESPONSE_BYTES) {
    throw new Error("dashboard backend response exceeded the safe limit");
  }
  const contentType = upstream.headers.get("content-type") || "";
  if (!contentType.toLowerCase().startsWith("application/json")) {
    throw new Error("dashboard backend returned an unexpected content type");
  }
  const body = await upstream.arrayBuffer();
  if (body.byteLength > MAX_RESPONSE_BYTES) {
    throw new Error("dashboard backend response exceeded the safe limit");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(body));
  } catch {
    throw new Error("dashboard backend returned invalid JSON");
  }
  return { status: upstream.status, body: parsed };
}

function rowsFromTable(body: unknown): JsonRecord[] {
  const items = asRecord(body).items;
  return Array.isArray(items) ? items.filter(isRecord) : [];
}

function projectSession(row: JsonRecord): JsonRecord {
  const projected = pickFields(row, [
    "session_id", "src_ip", "src_ip_is_public", "src_ip_scope", "start_time", "updated_at",
    "ended", "is_ended", "session_source", "is_external_source", "sensor_id", "sensor",
    "command_count", "tactics", "ttps", "analysis_status", "job_status", "report_id",
  ]);
  if (projected.sensor_id === undefined && row.sensor !== undefined) projected.sensor_id = row.sensor;
  if (projected.ended === undefined && row.is_ended !== undefined) projected.ended = row.is_ended;
  if (projected.is_ended === undefined && row.ended !== undefined) projected.is_ended = row.ended;
  if (projected.analysis_status === undefined && row.status !== undefined) projected.analysis_status = row.status;
  return projected;
}

function projectEvent(row: JsonRecord): JsonRecord {
  return pickFields(row, [
    "event_id", "session_id", "session", "sensor_id", "sensor", "src_ip", "src_ip_is_public",
    "eventid", "timestamp", "received_at", "processed", "command_event",
  ]);
}

function projectReport(row: JsonRecord): JsonRecord {
  return pickFields(row, ["report_id", "session_id", "status", "created_at", "updated_at", "summary", "confidence"]);
}

function projectSnapshot(row: JsonRecord): JsonRecord {
  return pickFields(row, [
    "snapshot_id", "session_id", "created_at", "updated_at", "generated_at", "src_ip", "session_status",
    "event_id", "features_hash", "prediction", "final_ranking", "trust_status", "coverage", "evidence_cutoff",
  ]);
}

function projectJob(row: JsonRecord): JsonRecord {
  return pickFields(row, ["job_id", "session_id", "status", "created_at", "updated_at", "report_id", "priority", "error"]);
}

function projectAlert(row: JsonRecord): JsonRecord {
  return pickFields(row, ["alert_id", "session_id", "severity", "created_at", "updated_at", "reason", "delivered", "authority_display"]);
}

function belongsToSession(row: JsonRecord, sessionId: string): boolean {
  return recordText(row, "session_id") === sessionId || recordText(row, "session") === sessionId;
}

function latestTimestamp(rows: JsonRecord[], fields: readonly string[]): string | undefined {
  const values = rows
    .flatMap((row) => fields.map((field) => recordText(row, field)))
    .filter(Boolean)
    .sort();
  return values.at(-1);
}

async function fetchTableRows(
  origin: URL,
  headers: Headers,
  path: string,
  query: string,
): Promise<TableRowsResult | null> {
  try {
    const result = await fetchUpstreamJson(new URL(`${path}${query}`, origin), headers);
    if (result.status < 200 || result.status >= 300 || !isRecord(result.body)) return null;
    return { body: result.body, rows: rowsFromTable(result.body) };
  } catch {
    return null;
  }
}

async function fetchCurrentPrediction(origin: URL, headers: Headers, sessionId: string): Promise<JsonRecord | null> {
  const query = new URLSearchParams({ session_id: sessionId }).toString();
  try {
    const result = await fetchUpstreamJson(new URL(`/predictions/current?${query}`, origin), headers);
    if (result.status < 200 || result.status >= 300 || !isRecord(result.body)) return null;
    return result.body;
  } catch {
    return null;
  }
}

function shouldUseCompatibilityFallback(key: string, result: UpstreamJson): boolean {
  if (!["sessions", "events", "session"].includes(key)) return false;
  if (result.status === 401 || result.status === 403) return false;
  if (result.status === 404 || result.status >= 500) return true;
  if (!isRecord(result.body)) return false;
  if (key === "session") return result.body.ok === false || !isRecord(result.body.overview);
  return typeof result.body.error === "string" && result.body.error.length > 0;
}

async function sessionsCompatibilityResponse(origin: URL, headers: Headers, request: Request): Promise<Response | null> {
  const table = await fetchTableRows(origin, headers, "/sessions", tableQuery(request, 100));
  if (!table) return null;
  const sessions = table.rows.map(projectSession);
  const limit = typeof table.body.limit === "number" ? table.body.limit : sessions.length;
  const offset = typeof table.body.offset === "number" ? table.body.offset : 0;
  return jsonResponse({
    ok: true,
    timestamp: typeof table.body.timestamp === "string" ? table.body.timestamp : new Date().toISOString(),
    summary: {
      total_sessions: sessions.length,
      shown_sessions: sessions.length,
      session_limit: limit,
      session_offset: offset,
      latest_updated: latestTimestamp(sessions, ["updated_at", "start_time"]),
    },
    sessions,
    selected_session_id: null,
    error: "",
    compatibility_fallback: "monitor_generic_table_routes",
  });
}

async function eventsCompatibilityResponse(origin: URL, headers: Headers, request: Request): Promise<Response | null> {
  const table = await fetchTableRows(origin, headers, "/events", tableQuery(request, 100));
  if (!table) return null;
  return jsonResponse({
    ok: true,
    timestamp: typeof table.body.timestamp === "string" ? table.body.timestamp : new Date().toISOString(),
    events: table.rows.map(projectEvent),
    error: "",
    compatibility_fallback: "monitor_generic_table_routes",
  });
}

async function sessionCompatibilityResponse(
  origin: URL,
  headers: Headers,
  request: Request,
): Promise<Response> {
  const sessionId = new URL(request.url).searchParams.get("session_id")?.trim() || "";
  if (!sessionId || sessionId.length > MAX_QUERY_VALUE_LENGTH) {
    return jsonResponse({ error: "session_id is required" }, 400);
  }

  const [sessionTable, eventTable, reportTable, snapshotTable, jobTable, alertTable, prediction] = await Promise.all([
    fetchTableRows(origin, headers, "/sessions", "?limit=1000"),
    fetchTableRows(origin, headers, "/events", "?limit=1000"),
    fetchTableRows(origin, headers, "/reports", "?limit=1000"),
    fetchTableRows(origin, headers, "/prediction-snapshots", "?limit=1000"),
    fetchTableRows(origin, headers, "/jobs", "?limit=1000"),
    fetchTableRows(origin, headers, "/alerts", "?limit=1000"),
    fetchCurrentPrediction(origin, headers, sessionId),
  ]);

  if (!sessionTable) return jsonResponse({ error: "dashboard backend is unavailable" }, 503);
  const session = sessionTable.rows.find((row) => belongsToSession(row, sessionId));
  if (!session) {
    return jsonResponse({ ok: false, session_id: sessionId, error: "dashboard data was not found" }, 404);
  }

  const events = (eventTable?.rows || []).filter((row) => belongsToSession(row, sessionId)).map(projectEvent);
  const reports = (reportTable?.rows || []).filter((row) => belongsToSession(row, sessionId)).map(projectReport);
  const snapshots = (snapshotTable?.rows || []).filter((row) => belongsToSession(row, sessionId)).map(projectSnapshot);
  const jobs = (jobTable?.rows || []).filter((row) => belongsToSession(row, sessionId)).map(projectJob);
  const alerts = (alertTable?.rows || []).filter((row) => belongsToSession(row, sessionId)).map(projectAlert);
  const overview = projectSession(session);
  overview.session_id = overview.session_id || sessionId;
  const predictionRecord = asRecord(prediction);
  const responseGuidance = isRecord(predictionRecord.response_guidance) ? predictionRecord.response_guidance : {};
  const reportSummary = reports.length && isRecord(reports[0].summary) ? reports[0].summary : {};
  const timestamp = [
    recordText(sessionTable.body, "timestamp"),
    recordText(eventTable?.body || {}, "timestamp"),
    recordText(reportTable?.body || {}, "timestamp"),
  ].find(Boolean) || new Date().toISOString();

  return jsonResponse({
    ok: true,
    timestamp,
    session_id: sessionId,
    overview,
    source_geo: {},
    source_geo_context: {},
    observables: [],
    commands: [],
    classification_events: [],
    observed_trusted_ttps: [],
    correlated_ttp_hypotheses: [],
    session_ttp_correlations: [],
    session_ttp_correlation_summary: {},
    tactics: Array.isArray(overview.tactics) ? overview.tactics : [],
    ttps: Array.isArray(overview.ttps) ? overview.ttps : [],
    session: {
      session_id: overview.session_id,
      sensor_id: overview.sensor_id,
      src_ip: overview.src_ip,
      start_time: overview.start_time,
      is_ended: overview.is_ended ?? overview.ended,
      command_count: overview.command_count,
      analysis_status: overview.analysis_status || overview.job_status,
    },
    events,
    events_table_rows: events,
    alerts,
    prediction_snapshots: snapshots,
    latest_prediction_snapshot: snapshots[0] || {},
    analysis_jobs: jobs,
    reports,
    report_summary: reportSummary,
    response_guidance: responseGuidance,
    errors: {
      structured_route: "structured monitor route unavailable; generic table compatibility fallback used",
      events: eventTable ? "" : "generic events table unavailable",
      reports: reportTable ? "" : "generic reports table unavailable",
      predictions: snapshotTable ? "" : "generic prediction snapshot table unavailable",
      jobs: jobTable ? "" : "generic analysis jobs table unavailable",
      alerts: alertTable ? "" : "generic alerts table unavailable",
    },
    compatibility_fallback: "monitor_generic_table_routes",
  });
}

export async function GET(
  request: Request,
  context: { params: Promise<{ path: string[] }> },
) {
  if (!validDashboardSession(request)) {
    return jsonResponse({ error: "dashboard session required" }, 401);
  }
  const { path } = await context.params;
  const key = (path || []).join("/");
  const targetPath = ROUTES[key];
  if (!targetPath) {
    return jsonResponse({ error: "dashboard API route is not available" }, 404);
  }

  let origin: URL;
  let target: URL;
  try {
    origin = upstreamOrigin();
    target = new URL(`${targetPath}${safeQuery(request)}`, origin);
  } catch {
    return jsonResponse({ error: "dashboard API origin is not configured safely" }, 503);
  }

  const headers = new Headers({ Accept: "application/json" });
  const readToken = process.env.DASHBOARD_API_READ_TOKEN?.trim();
  if (readToken) headers.set("Authorization", `Bearer ${readToken}`);

  let upstream: UpstreamJson;
  try {
    upstream = await fetchUpstreamJson(target, headers);
  } catch {
    return jsonResponse(
      { error: "dashboard backend is unavailable", route: key },
      503,
    );
  }

  if (shouldUseCompatibilityFallback(key, upstream)) {
    const fallback = key === "sessions"
      ? await sessionsCompatibilityResponse(origin, headers, request)
      : key === "events"
        ? await eventsCompatibilityResponse(origin, headers, request)
        : await sessionCompatibilityResponse(origin, headers, request);
    if (fallback) return fallback;
  }

  if (upstream.status < 200 || upstream.status >= 300) return upstreamError(upstream.status);
  return jsonResponse(upstream.body, upstream.status);
}
