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

export async function GET(
  request: Request,
  context: { params: Promise<{ path: string[] }> },
) {
  if (!validDashboardSession(request)) {
    return Response.json({ error: "dashboard session required" }, { status: 401 });
  }
  const { path } = await context.params;
  const key = (path || []).join("/");
  const targetPath = ROUTES[key];
  if (!targetPath) {
    return Response.json({ error: "dashboard API route is not available" }, { status: 404 });
  }

  let target: URL;
  try {
    target = new URL(`${targetPath}${safeQuery(request)}`, upstreamOrigin());
  } catch {
    return Response.json({ error: "dashboard API origin is not configured safely" }, { status: 503 });
  }

  const headers = new Headers({ Accept: "application/json" });
  const readToken = process.env.DASHBOARD_API_READ_TOKEN?.trim();
  if (readToken) {
    headers.set("Authorization", `Bearer ${readToken}`);
  }

  try {
    const upstream = await fetch(target, {
      method: "GET",
      headers,
      cache: "no-store",
      redirect: "error",
      signal: AbortSignal.timeout(15_000),
    });
    const contentLength = Number(upstream.headers.get("content-length") || 0);
    if (contentLength > MAX_RESPONSE_BYTES) {
      return Response.json({ error: "dashboard backend response exceeded the safe limit" }, { status: 502 });
    }
    const contentType = upstream.headers.get("content-type") || "";
    if (!contentType.toLowerCase().startsWith("application/json")) {
      return Response.json({ error: "dashboard backend returned an unexpected content type" }, { status: 502 });
    }
    if (!upstream.ok) {
      const message = upstream.status === 401 || upstream.status === 403
        ? "dashboard backend authorization failed"
        : upstream.status === 404
          ? "dashboard data was not found"
          : "dashboard backend request failed";
      return Response.json({ error: message }, { status: upstream.status, headers: { "cache-control": "no-store" } });
    }
    const body = await upstream.arrayBuffer();
    if (body.byteLength > MAX_RESPONSE_BYTES) {
      return Response.json({ error: "dashboard backend response exceeded the safe limit" }, { status: 502 });
    }
    return new Response(body, {
      status: upstream.status,
      headers: {
        "content-type": upstream.headers.get("content-type") || "application/json; charset=utf-8",
        "cache-control": "no-store",
      },
    });
  } catch {
    return Response.json(
      { error: "dashboard backend is unavailable", route: key },
      { status: 503, headers: { "cache-control": "no-store" } },
    );
  }
}
