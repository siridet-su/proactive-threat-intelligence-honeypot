import { NextResponse } from "next/server";

import { getSessionFromRequest, isAdmin } from "@/lib/auth/session";
import { createHardwareBackupRequest } from "@/lib/hardware-backup";
import type { HardwareBackupRequestAction } from "@/lib/dashboardTypes";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

function isBackupAction(value: unknown): value is HardwareBackupRequestAction {
  return value === "run_missing" || value === "retry_failed";
}

export async function POST(request: Request) {
  const session = await getSessionFromRequest(request);
  if (!session || session.mustChangePassword) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }
  if (!isAdmin(session)) {
    return NextResponse.json({ error: "Administrator access required" }, { status: 403 });
  }

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: "Request body must be valid JSON" }, { status: 400 });
  }

  const action = body && typeof body === "object" && "action" in body
    ? (body as { action?: unknown }).action
    : undefined;
  if (!isBackupAction(action)) {
    return NextResponse.json({ error: "Unsupported backup action" }, { status: 400 });
  }

  try {
    const result = await createHardwareBackupRequest(action, session.operatorId);
    if (result.conflict) {
      return NextResponse.json({
        error: "A hardware backup request is already pending or running",
        request: result.request,
      }, { status: 409 });
    }
    return NextResponse.json({ request: result.request }, {
      status: 202,
      headers: { "Cache-Control": "no-store" },
    });
  } catch (error: unknown) {
    console.error("Failed to create hardware backup request:", error);
    const message = error instanceof Error ? error.message : "Failed to create hardware backup request";
    return NextResponse.json({ error: message }, { status: 503 });
  }
}
