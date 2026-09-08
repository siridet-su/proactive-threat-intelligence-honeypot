import { NextResponse } from "next/server";

import { getSessionFromRequest } from "@/lib/auth/session";
import { getThreatDashboardSummary } from "@/lib/threat-server";

export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  const session = await getSessionFromRequest(request);
  if (!session || session.mustChangePassword) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  try {
    const summary = await getThreatDashboardSummary();
    return NextResponse.json(summary, {
      headers: { "Cache-Control": "private, max-age=5, stale-while-revalidate=10" },
    });
  } catch (error: unknown) {
    console.error("[THREAT SUMMARY API ERROR]", error);
    return NextResponse.json({ error: "Threat summary unavailable" }, { status: 500 });
  }
}
