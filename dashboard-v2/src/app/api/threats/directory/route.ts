import { NextResponse } from "next/server";

import { getSessionFromRequest } from "@/lib/auth/session";
import { getThreatDirectory } from "@/lib/threat-server";
import type { ThreatSeverityFilter } from "@/lib/dashboardTypes";

export const dynamic = "force-dynamic";

function parsePositiveInteger(value: string | null, fallback: number) {
  if (!value) return fallback;
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

export async function GET(request: Request) {
  const session = await getSessionFromRequest(request);
  if (!session || session.mustChangePassword) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  try {
    const { searchParams } = new URL(request.url);
    const directory = await getThreatDirectory({
      query: searchParams.get("query") ?? "",
      severity: searchParams.get("severity") as ThreatSeverityFilter | null ?? undefined,
      page: parsePositiveInteger(searchParams.get("page"), 1),
      pageSize: parsePositiveInteger(searchParams.get("pageSize"), 20),
    });

    return NextResponse.json(directory, {
      headers: { "Cache-Control": "private, no-store" },
    });
  } catch (error: unknown) {
    console.error("[THREAT DIRECTORY API ERROR]", error);
    return NextResponse.json({ error: "Threat directory unavailable" }, { status: 500 });
  }
}
