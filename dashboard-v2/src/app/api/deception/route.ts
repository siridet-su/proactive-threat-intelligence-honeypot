import { NextResponse } from "next/server";
import { getDeceptionDecisionForSession, getDeceptionDecisions } from "@/lib/deception-server";
import { getSessionFromRequest } from "@/lib/auth/session";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET(request: Request) {
  const session = await getSessionFromRequest(request);
  if (!session || session.mustChangePassword) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const params = new URL(request.url).searchParams;
  const ip = params.get("ip");
  const sessionId = params.get("session_id");

  try {
    if (ip !== null || sessionId !== null) {
      if (!ip?.trim() || !sessionId?.trim()) {
        return NextResponse.json({ error: "Both IP and session_id are required" }, { status: 400 });
      }
      const decision = await getDeceptionDecisionForSession(ip, sessionId);
      if (!decision) {
        return NextResponse.json({ error: "No deception decision for this session and origin IP" }, { status: 404 });
      }
      return NextResponse.json(decision);
    }
    return NextResponse.json(await getDeceptionDecisions());
  } catch (error: unknown) {
    console.error("Failed to fetch deception decisions:", error);
    const message = error instanceof Error ? error.message : "Failed to fetch deception decisions";
    return NextResponse.json({ error: message }, { status: 503 });
  }
}
