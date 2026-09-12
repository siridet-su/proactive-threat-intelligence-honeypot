import { NextResponse } from "next/server";

import { getSessionFromRequest } from "@/lib/auth/session";

export const dynamic = "force-dynamic";

const MAX_RESPONSE_BYTES = 1_000_000;
const DEFAULT_UPSTREAM_TIMEOUT_MS = 2_500;
const FULL_DETAIL_UPSTREAM_TIMEOUT_MS = 6_000;
const SESSION_ID_PATTERN = /^[\x20-\x7e]{1,256}$/;
const OBSERVABLE_TYPES = new Set(["ip", "hash"]);

type JsonRecord = Record<string, unknown>;
type Capability =
  | "detail"
  | "commands"
  | "next-distinct"
  | "session-ti"
  | "source-ip-pivot"
  | "observable-ti"
  | "hypothesis"
  | "recommendations"
  | "ai-advisory"
  | "related"
  | "feedback"
  | "reports";

const CAPABILITIES = new Set<Capability>([
  "detail",
  "commands",
  "next-distinct",
  "session-ti",
  "source-ip-pivot",
  "observable-ti",
  "hypothesis",
  "recommendations",
  "ai-advisory",
  "related",
  "feedback",
  "reports",
]);

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function monitorBaseUrl(): string {
  const configured = process.env.DASHBOARD_MONITOR_BASE_URL?.trim();
  return (configured || "http://127.0.0.1:8090").replace(/\/$/, "");
}

function boundedSessionId(searchParams: URLSearchParams): string | null {
  const sessionId = searchParams.get("session_id")?.trim() || "";
  return SESSION_ID_PATTERN.test(sessionId) ? sessionId : null;
}

function upstreamFor(capability: Capability, searchParams: URLSearchParams): URL | null {
  const sessionId = boundedSessionId(searchParams);
  if (!sessionId) return null;
  const routes: Partial<Record<Capability, string>> = {
    // The compact authenticated session projection is the bounded source for
    // the command panel, including the normal persisted Cowrie command
    // projection. Credential-bearing command substrings remain scrubbed by
    // the backend sensitive-data policy.
    detail: "/api/session-detail",
    commands: "/api/session-detail",
    "next-distinct": "/api/next-distinct",
    "session-ti": "/api/session-ti",
    "ai-advisory": "/api/ai-advisory",
  };
  const route = routes[capability] || "/api/session-detail";
  const upstream = new URL(route, monitorBaseUrl());
  upstream.searchParams.set("session_id", sessionId);

  if (capability === "source-ip-pivot") {
    const sourceIp = searchParams.get("source_ip")?.trim() || "";
    if (!sourceIp || sourceIp.length > 64) return null;
    upstream.pathname = "/api/source-ip-pivot";
    upstream.searchParams.delete("session_id");
    upstream.searchParams.set("source_ip", sourceIp);
    upstream.searchParams.set("exclude_session_id", sessionId);
    upstream.searchParams.set("limit", "20");
  }
  if (capability === "observable-ti") {
    const observableType = searchParams.get("observable_type")?.trim().toLowerCase() || "";
    const observableValue = searchParams.get("observable_value")?.trim() || "";
    if (!OBSERVABLE_TYPES.has(observableType) || !observableValue || observableValue.length > 256) return null;
    upstream.pathname = "/api/observable-ti";
    upstream.searchParams.delete("session_id");
    upstream.searchParams.set("observable_type", observableType);
    upstream.searchParams.set("observable_value", observableValue);
    upstream.searchParams.set("limit", "100");
  }
  return upstream;
}

function projectDetail(capability: Capability, payload: JsonRecord): JsonRecord {
  const base = {
    ok: payload.ok === true,
    session_id: payload.session_id,
    timestamp: payload.timestamp,
  };
  if (capability === "hypothesis") {
    return {
      ...base,
      authority: "CONTEXTUAL_NON_AUTHORITATIVE",
      report_summary: payload.report_summary || {},
      correlated_ttp_hypotheses: payload.correlated_ttp_hypotheses || [],
      hypothesis_sets: payload.hypothesis_sets || [],
      reports: payload.reports || [],
      non_claims: [
        "does not establish attacker identity or intent",
        "cannot alter trusted ATT&CK mappings or authorize response",
      ],
    };
  }
  if (capability === "recommendations") {
    return {
      ...base,
      response_guidance: payload.response_guidance || {},
      requires_manual_approval: true,
      safe_to_auto_execute: false,
    };
  }
  if (capability === "ai-advisory") {
    return {
      ...base,
      status: payload.status || "unavailable",
      advisory: payload.advisory || {},
      metrics: payload.metrics || {},
      policy_gap: payload.policy_gap || {},
      authority: "NON_AUTHORITATIVE_ADVISORY_ONLY",
      automatic_policy_mutation: false,
      automatic_response_execution: false,
    };
  }
  if (capability === "related") {
    return {
      ...base,
      authority: "CONTEXTUAL_NON_AUTHORITATIVE",
      session_links: payload.session_links || [],
      campaigns: payload.campaigns || [],
      related_observable_sightings: payload.related_observable_sightings || [],
    };
  }
  if (capability === "feedback") {
    return { ...base, analyst_feedback: payload.analyst_feedback || [], write_enabled: false };
  }
  if (capability === "reports") {
    return { ...base, reports: payload.reports || [], report_summary: payload.report_summary || {} };
  }
  return payload;
}

function projectNextDistinct(payload: JsonRecord, sessionId: string): JsonRecord {
  const nextDistinct = payload.next_distinct_tactic ?? payload.top1 ?? null;
  const hasStoredData = nextDistinct !== null && nextDistinct !== undefined && nextDistinct !== "";
  const freshness = isRecord(payload.freshness) ? payload.freshness : {};
  const predictionStatus = String(payload.prediction_status || "").toUpperCase();
  const freshnessState = String(freshness.state || "").toUpperCase();
  const unavailable = predictionStatus === "UNAVAILABLE" || freshnessState === "UNAVAILABLE";
  const sessionEnded = payload.session_ended === true || payload.is_ended === true;
  const stale = predictionStatus === "STALE" || ["STALE", "EXPIRED"].includes(freshnessState);
  const state = sessionEnded
    ? "SESSION_ENDED"
    : unavailable
      ? "UNAVAILABLE"
      : stale
        ? "STALE"
        : hasStoredData
          ? "DATA"
          : "WAITING_FOR_EVIDENCE";
  return {
    ...payload,
    ok: true,
    session_id: payload.session_id || payload.sequence_id || sessionId,
    source: "NEXT_DISTINCT_POC",
    dashboard_source: "NEXT_DISTINCT_POC",
    read_only: true,
    advisory_only: true,
    state,
    status: state,
    availability: state === "DATA" ? "AVAILABLE" : state,
    next_distinct_tactic: state === "DATA" ? nextDistinct : null,
    ...(state === "SESSION_ENDED"
      ? { prediction_status_reason: "session ended; no session-end prediction is emitted" }
      : {}),
  };
}

export async function GET(
  request: Request,
  context: { params: Promise<{ capability: string }> },
) {
  const dashboardSession = await getSessionFromRequest(request);
  if (!dashboardSession || dashboardSession.mustChangePassword) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }
  const rawCapability = (await context.params).capability;
  if (!CAPABILITIES.has(rawCapability as Capability)) {
    return NextResponse.json({ error: "Unsupported session capability" }, { status: 404 });
  }
  const capability = rawCapability as Capability;
  const upstream = upstreamFor(capability, new URL(request.url).searchParams);
  if (!upstream) {
    return NextResponse.json({ error: "Invalid or missing exact-session query" }, { status: 400 });
  }
  const token = process.env.DASHBOARD_MONITOR_READ_TOKEN?.trim();

  const controller = new AbortController();
  const timeout = setTimeout(
    () => controller.abort(),
    capability === "detail" ? FULL_DETAIL_UPSTREAM_TIMEOUT_MS : DEFAULT_UPSTREAM_TIMEOUT_MS,
  );
  try {
    const headers: Record<string, string> = {};
    if (token) headers.Authorization = `Bearer ${token}`;
    const response = await fetch(upstream, {
      method: "GET",
      cache: "no-store",
      headers,
      signal: controller.signal,
    });
    const text = await response.text();
    if (new TextEncoder().encode(text).byteLength > MAX_RESPONSE_BYTES) {
      return NextResponse.json({ error: "Bounded monitor response exceeded" }, { status: 502 });
    }
    let payload: unknown;
    let monitorJson = true;
    try {
      payload = JSON.parse(text);
    } catch {
      monitorJson = false;
      payload = { error: "Monitor returned a non-JSON response", error_code: "monitor_non_json" };
    }

    if (capability === "next-distinct" && response.status === 503 && monitorJson && isRecord(payload)) {
      const freshness = isRecord(payload.freshness) ? payload.freshness : {};
      if (String(payload.prediction_status || "").toUpperCase() === "UNAVAILABLE"
        || String(freshness.state || "").toUpperCase() === "UNAVAILABLE") {
        return NextResponse.json(projectNextDistinct(payload, boundedSessionId(new URL(request.url).searchParams) || ""), {
          status: 200,
          headers: { "Cache-Control": "private, no-store" },
        });
      }
    }

    const projected = isRecord(payload)
      ? capability === "next-distinct" && response.ok
        ? projectNextDistinct(payload, boundedSessionId(new URL(request.url).searchParams) || "")
        : projectDetail(capability, payload)
      : payload;
    return NextResponse.json(projected, {
      status: response.status,
      headers: { "Cache-Control": "private, no-store" },
    });
  } catch (error: unknown) {
    const message = error instanceof Error && error.name === "AbortError"
      ? "Monitor request timed out"
      : "Monitor request unavailable";
    return NextResponse.json({ error: message }, { status: 503 });
  } finally {
    clearTimeout(timeout);
  }
}
