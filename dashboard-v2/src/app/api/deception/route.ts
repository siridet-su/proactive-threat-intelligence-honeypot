import { NextResponse } from "next/server";
import { getDeceptionDecisionByIp, getDeceptionDecisions } from "@/lib/deception-server";
import { getSessionFromRequest } from "@/lib/auth/session";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET(request: Request) {
  const session = await getSessionFromRequest(request);
  if (!session || session.mustChangePassword) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const ip = new URL(request.url).searchParams.get("ip");

  try {
    if (ip) {
      const decision = await getDeceptionDecisionByIp(ip);
      if (!decision) {
        return NextResponse.json({ error: "No deception decision for this IP" }, { status: 404 });
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
