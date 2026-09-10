import { NextResponse } from "next/server";
import { getRecentHardwareMetrics } from "@/lib/hardware-mongo";
import { getSessionFromRequest } from "@/lib/auth/session";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET(request: Request) {
  const session = await getSessionFromRequest(request);
  if (!session || session.mustChangePassword) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  try {
    // hardware_live is the agent-maintained rolling window for the live monitor.
    return NextResponse.json(await getRecentHardwareMetrics());
  } catch (error: unknown) {
    console.error("Failed to fetch hardware metrics:", error);
    const message = error instanceof Error ? error.message : "Failed to fetch metrics";
    return NextResponse.json({ error: message }, { status: 503 });
  }
}
