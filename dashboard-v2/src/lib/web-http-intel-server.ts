import "server-only";

import { getMongoClient, getMongoDatabaseName } from "@/lib/mongodb";
import { projectWebHttpEvent, type WebHttpCapturedPayload, type WebHttpHint } from "@/lib/web-http-intel";

const HTTP_EVENT_PROJECTION = {
  _id: 0, source: 1, event_type: 1, event_id: 1, timestamp: 1,
  "network.src_ip": 1, "network.src_port": 1,
  "network.dst_ip": 1, "network.dst_port": 1,
  "network.protocol": 1, "network.service": 1,
  "http.method": 1, "http.path": 1, "http.status_code": 1,
  "analysis.sqli.indicators": 1, "analysis.xss.indicators": 1,
  "correlation.web_session_id": 1, outcome: 1,
} as const;

const HTTP_DETAIL_PROJECTION = {
  ...HTTP_EVENT_PROJECTION,
  "http.raw_path": 1,
  "http.query": 1,
  "http.scheme": 1, "http.host": 1, "http.user_agent": 1,
  "http.referer": 1, "http.origin": 1, "http.accept_language": 1,
  "web_login.database": 1, "web_login.username": 1,
  "web_login.password": 1, "web_login.redirect": 1, "web_login.remember": 1,
  truncated_fields: 1,
} as const;

function object(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
}

function captured(value: unknown, eventId: string): WebHttpCapturedPayload {
  const row = object(value);
  const http = object(row.http);
  const login = object(row.web_login);
  const field = (value: unknown, max: number): string => typeof value === "string" ? value.slice(0, max) : "";
  const isLogin = row.event_type === "web_login_attempt";
  return {
    eventId,
    rawPath: typeof http.raw_path === "string" ? http.raw_path.slice(0, 512)
      : isLogin && typeof http.path === "string" ? http.path.slice(0, 512) : null,
    // The processor may compact empty strings, so null also covers an empty query.
    query: typeof http.query === "string" ? http.query.slice(0, 512) : null,
    scheme: typeof http.scheme === "string" ? http.scheme.slice(0, 16) : null,
    host: typeof http.host === "string" ? http.host.slice(0, 256) : null,
    userAgent: typeof http.user_agent === "string" ? http.user_agent.slice(0, 256) : null,
    referer: typeof http.referer === "string" ? http.referer.slice(0, 256) : null,
    origin: typeof http.origin === "string" ? http.origin.slice(0, 256) : null,
    acceptLanguage: typeof http.accept_language === "string" ? http.accept_language.slice(0, 256) : null,
    form: isLogin ? {
      database: field(login.database, 256), login: field(login.username, 256),
      password: field(login.password, 256), redirect: field(login.redirect, 256),
      remember: field(login.remember, 32),
    } : null,
    truncatedFields: Array.isArray(row.truncated_fields)
      ? row.truncated_fields.filter((name): name is string => typeof name === "string" && /^(http\.(query|host|user_agent|referer|origin|accept_language)|odoo_login\.(database|login|password|redirect|remember))$/.test(name))
      : [],
  };
}

export async function getWebHttpHints(limit = 50): Promise<{ items: WebHttpHint[]; coverage: string }> {
  const safeLimit = Math.max(1, Math.min(100, Math.trunc(limit)));
  const client = await getMongoClient();
  const rows = await client.db(getMongoDatabaseName()).collection("events")
    .find({ source: "web-corp", event_type: { $in: ["web_login_attempt", "web_http_request"] } }, {
      maxTimeMS: 5_000,
      // Explicit allowlist: the Mongo row also contains plaintext password
      // under web_login and raw.payload. They must never reach this read path.
      projection: HTTP_EVENT_PROJECTION,
    })
    .sort({ timestamp: -1, event_id: -1 })
    .limit(safeLimit)
    .toArray();
  return {
    items: rows.map(projectWebHttpEvent).filter((item): item is WebHttpHint => item !== null),
    coverage: "Stored web-corp HTTP requests and login attempts only; legacy events without a session ID remain ungrouped.",
  };
}

/** Exact sensor-issued browser-continuity ID only. Never join by IP or username. */
export async function getWebHttpSession(sessionId: string, includeCapturedPayload = false): Promise<{ items: WebHttpHint[]; payloads: WebHttpCapturedPayload[] } | null> {
  if (!/^[a-f0-9]{32}$/.test(sessionId)) return null;
  const client = await getMongoClient();
  const rows = await client.db(getMongoDatabaseName()).collection("events")
    .find({ source: "web-corp", event_type: { $in: ["web_login_attempt", "web_http_request"] }, "correlation.web_session_id": sessionId }, {
      maxTimeMS: 5_000,
      projection: includeCapturedPayload ? HTTP_DETAIL_PROJECTION : HTTP_EVENT_PROJECTION,
    })
    .sort({ timestamp: 1, event_id: 1 })
    .limit(501)
    .toArray();
  // Do not silently claim a complete chronology when the safe cap is reached.
  if (rows.length > 500) throw new Error("HTTP session exceeds the bounded detail limit");
  const items = rows.map(projectWebHttpEvent).filter((item): item is WebHttpHint => item?.sessionId === sessionId);
  if (!items.length) return null;
  const ids = new Set(items.map((item) => item.eventId));
  return { items, payloads: includeCapturedPayload ? rows.map((row) => {
    const projected = projectWebHttpEvent(row);
    return projected && ids.has(projected.eventId) ? captured(row, projected.eventId) : null;
  }).filter((entry): entry is WebHttpCapturedPayload => entry !== null) : [] };
}
