import { NextResponse } from "next/server";
import { getSessionFromRequest } from "@/lib/auth/session";
import { getWebHttpSession } from "@/lib/web-http-intel-server";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

const headers = { "Cache-Control": "private, no-store", Vary: "Cookie", "X-Content-Type-Options": "nosniff" };

export async function GET(request: Request, context: { params: Promise<{ id: string }> }) {
  const operator = await getSessionFromRequest(request);
  if (!operator || operator.mustChangePassword) return NextResponse.json({ error: "Unauthorized" }, { status: 401, headers });
  const id = (await context.params).id;
  if (!/^[a-f0-9]{32}$/.test(id)) return NextResponse.json({ error: "Invalid HTTP session ID" }, { status: 400, headers });
  try {
    const items = await getWebHttpSession(id);
    if (!items) return NextResponse.json({ error: "HTTP session not found" }, { status: 404, headers });
    return NextResponse.json({ sessionId: id, items, coverage: "Exact Web-corp cookie session; browser continuity is not verified attacker identity." }, { headers });
  } catch {
    return NextResponse.json({ error: "HTTP session detail unavailable" }, { status: 503, headers });
  }
}
