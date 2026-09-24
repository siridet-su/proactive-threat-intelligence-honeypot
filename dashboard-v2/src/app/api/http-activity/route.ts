import { NextResponse } from "next/server";

import { getSessionFromRequest } from "@/lib/auth/session";
import { getWebHttpHints } from "@/lib/web-http-intel-server";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

const headers = { "Cache-Control": "private, no-store", Vary: "Cookie", "X-Content-Type-Options": "nosniff" };

export async function GET(request: Request) {
  const session = await getSessionFromRequest(request);
  if (!session || session.mustChangePassword) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401, headers });
  }
  try {
    return NextResponse.json(await getWebHttpHints(), { headers });
  } catch {
    // Do not leak Mongo connection details or event payloads.
    return NextResponse.json({ error: "HTTP activity unavailable" }, { status: 503, headers });
  }
}
