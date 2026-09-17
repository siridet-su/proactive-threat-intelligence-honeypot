import { NextResponse } from "next/server";

import { getSessionFromRequest } from "@/lib/auth/session";

export const dynamic = "force-dynamic";

const MAX_PDF_BYTES = 16 * 1024 * 1024;
const SESSION_ID_PATTERN = /^[\x20-\x7e]{1,256}$/;

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

  const upstream = new URL("/api/session-report", monitorBaseUrl());
  upstream.searchParams.set("session_id", sessionId);
  const token = process.env.DASHBOARD_MONITOR_READ_TOKEN?.trim();
  const headers: Record<string, string> = {};
  if (token) headers.Authorization = `Bearer ${token}`;

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15_000);
  try {
    const response = await fetch(upstream, {
      method: "GET",
      cache: "no-store",
      headers,
      signal: controller.signal,
    });
    if (!response.ok) {
      return NextResponse.json(
        {
          error: response.status === 404
            ? "No completed report is available for this session"
            : "Session report PDF is unavailable",
        },
        { status: response.status },
      );
    }
    const body = await response.arrayBuffer();
    if (body.byteLength > MAX_PDF_BYTES) {
      return NextResponse.json({ error: "Session report exceeded the safe download limit" }, { status: 502 });
    }
    return new Response(body, {
      status: 200,
      headers: {
        "content-type": "application/pdf",
        "content-disposition": 'attachment; filename="session-threat-report.pdf"',
        "cache-control": "no-store",
        "x-content-type-options": "nosniff",
      },
    });
  } catch {
    return NextResponse.json({ error: "Session report backend is unavailable" }, { status: 503 });
  } finally {
    clearTimeout(timeout);
  }
}
