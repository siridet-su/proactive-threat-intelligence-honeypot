import { NextResponse } from "next/server";

import { getSessionFromRequest, isAdmin } from "@/lib/auth/session";
import { requestSessionTermination, responseControlConfigured, responseControlHealthy } from "@/lib/response-control";
import {
  createTerminateAction,
  getTerminateAction,
  markTerminateActionDelivered,
  markTerminateActionFailed,
  sessionIsActive,
} from "@/lib/session-actions";

export const dynamic = "force-dynamic";

const SESSION_ID_PATTERN = /^[0-9a-f]{12}$/;
const ACTION_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

function sameOrigin(request: Request): boolean {
  const origin = request.headers.get("origin");
  if (!origin) return false;
  try {
    return new URL(origin).origin === new URL(request.url).origin;
  } catch {
    return false;
  }
}

export async function GET(request: Request, { params }: { params: Promise<{ id: string }> }) {
  const dashboardSession = await getSessionFromRequest(request);
  if (!dashboardSession || dashboardSession.mustChangePassword) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  const { id } = await params;
  if (!SESSION_ID_PATTERN.test(id)) return NextResponse.json({ error: "Invalid session ID" }, { status: 400 });
  const administrator = isAdmin(dashboardSession);
  const actionId = new URL(request.url).searchParams.get("actionId") ?? undefined;
  if (actionId && !ACTION_ID_PATTERN.test(actionId)) return NextResponse.json({ error: "Invalid action ID" }, { status: 400 });
  const configured = responseControlConfigured();
  const [action, active, healthy] = await Promise.all([
    administrator ? getTerminateAction(id, actionId) : null,
    sessionIsActive(id),
    administrator && configured ? responseControlHealthy() : false,
  ]);
  return NextResponse.json({
    available: administrator && healthy,
    authorized: administrator,
    configured,
    active,
    action,
  }, { headers: { "Cache-Control": "no-store" } });
}

export async function POST(request: Request, { params }: { params: Promise<{ id: string }> }) {
  const dashboardSession = await getSessionFromRequest(request);
  if (!dashboardSession || dashboardSession.mustChangePassword) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  if (!isAdmin(dashboardSession)) return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  if (!sameOrigin(request)) return NextResponse.json({ error: "Cross-origin request rejected" }, { status: 403 });

  const { id } = await params;
  if (!SESSION_ID_PATTERN.test(id)) return NextResponse.json({ error: "Invalid session ID" }, { status: 400 });
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: "Invalid confirmation" }, { status: 400 });
  }
  if (!body || typeof body !== "object" || Array.isArray(body) || Object.keys(body).length !== 1 || (body as { confirmation?: unknown }).confirmation !== id) {
    return NextResponse.json({ error: "Session confirmation does not match" }, { status: 400 });
  }
  if (!await sessionIsActive(id)) return NextResponse.json({ error: "Session is no longer active" }, { status: 409 });

  const current = await getTerminateAction(id);
  if (current && (current.status === "requested" || current.status === "delivered")) {
    return NextResponse.json({ action: current }, { status: 202 });
  }
  const action = await createTerminateAction(id, dashboardSession.operatorId);
  if (action.status !== "requested") return NextResponse.json({ action }, { status: 202 });
  const result = await requestSessionTermination(id, action.actionId);
  if (result.delivered) {
    return NextResponse.json({ action: await markTerminateActionDelivered(action.actionId) ?? action }, { status: 202 });
  }
  if (result.category === "not_found") {
    const reconciled = await getTerminateAction(id, action.actionId);
    if (reconciled?.status === "verified") return NextResponse.json({ action: reconciled }, { status: 202 });
    // The transport may have closed between the MongoDB liveness check and
    // delivery. Keep the action open briefly so the lifecycle event can catch
    // up instead of recording a false failure.
    return NextResponse.json({ action, reconciling: true }, { status: 202 });
  }
  const failed = await markTerminateActionFailed(action.actionId, result.category);
  const status = result.category === "unconfigured" ? 503 : 502;
  return NextResponse.json({ error: "Terminate request was not delivered", action: failed ?? action }, { status });
}
