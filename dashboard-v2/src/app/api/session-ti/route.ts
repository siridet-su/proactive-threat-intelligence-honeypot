import { NextResponse } from "next/server";

import { getSessionFromRequest } from "@/lib/auth/session";

export const dynamic = "force-dynamic";

const MAX_RESPONSE_BYTES = 1_000_000;
const SESSION_ID_PATTERN = /^[\x20-\x7e]{1,256}$/;
const SESSION_TI_UPSTREAM_TIMEOUT_MS = 60_000;

function monitorBaseUrl(): string {
  const configured = process.env.DASHBOARD_MONITOR_BASE_URL?.trim();
  return (configured || "http://127.0.0.1:8090").replace(/\/$/, "");
}

export async function GET(request: Request) {
  const dashboardSession = await getSessionFromRequest(request);
  if (!dashboardSession || dashboardSession.mustChangePassword) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const sessionId = new URL(request.url).searchParams.get("session_id")?.trim() || "";
  if (!SESSION_ID_PATTERN.test(sessionId)) {
    return NextResponse.json({ error: "Invalid or missing exact-session query" }, { status: 400 });
  }

  const upstream = new URL("/api/session-ti", monitorBaseUrl());
  upstream.searchParams.set("session_id", sessionId);
  const token = process.env.DASHBOARD_MONITOR_READ_TOKEN?.trim();
  const headers: Record<string, string> = { Accept: "application/json" };
  if (token) headers.Authorization = `Bearer ${token}`;

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), SESSION_TI_UPSTREAM_TIMEOUT_MS);
  try {
    const response = await fetch(upstream, {
      method: "GET",
      cache: "no-store",
      headers,
      signal: controller.signal,
    });
    const body = await response.arrayBuffer();
    if (body.byteLength > MAX_RESPONSE_BYTES) {
      return NextResponse.json({ error: "Session TI response exceeded the safe limit" }, { status: 502 });
    }
    const contentType = response.headers.get("content-type") || "";
    if (!contentType.toLowerCase().startsWith("application/json")) {
      return NextResponse.json({ error: "Session TI backend returned an unexpected response" }, { status: 502 });
    }
    return new Response(body, {
      status: response.status,
      headers: {
        "content-type": "application/json; charset=utf-8",
        "cache-control": "no-store",
        "x-content-type-options": "nosniff",
      },
    });
  } catch {
    return NextResponse.json({ error: "Session TI backend is unavailable" }, { status: 503 });
  } finally {
    clearTimeout(timeout);
  }
}

export async function HEAD(request: Request) {
  const response = await GET(request);
  return new Response(null, { status: response.status, headers: response.headers });
}

export async function POST() {
  return NextResponse.json({ error: "Session TI route is read-only" }, { status: 405, headers: { allow: "GET, HEAD" } });
}

export async function PUT() {
  return NextResponse.json({ error: "Session TI route is read-only" }, { status: 405, headers: { allow: "GET, HEAD" } });
}

export async function PATCH() {
  return NextResponse.json({ error: "Session TI route is read-only" }, { status: 405, headers: { allow: "GET, HEAD" } });
}

export async function DELETE() {
  return NextResponse.json({ error: "Session TI route is read-only" }, { status: 405, headers: { allow: "GET, HEAD" } });
}
