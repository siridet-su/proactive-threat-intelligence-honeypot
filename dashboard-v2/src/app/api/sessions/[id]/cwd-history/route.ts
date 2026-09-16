import { NextResponse } from "next/server";

import { getSessionFromRequest } from "@/lib/auth/session";
import { getSessionCwdHistory, getSessionCwdHistoryHop } from "@/lib/filesystem-server";

export const dynamic = "force-dynamic";

export async function GET(request: Request, { params }: { params: Promise<{ id: string }> }) {
  const session = await getSessionFromRequest(request);
  if (!session || session.mustChangePassword) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }
  const { id } = await params;
  try {
    const url = new URL(request.url);
    const hop = url.searchParams.get("hop");
    if (hop) {
      const result = await getSessionCwdHistoryHop(id, hop);
      if (!result.item) {
        return NextResponse.json({ item: null, error: "Hop not found or unavailable" }, { status: 404 });
      }
      return NextResponse.json(result, {
        headers: { "Cache-Control": "no-store" },
      });
    }

    const cursor = url.searchParams.get("cursor");
    return NextResponse.json(await getSessionCwdHistory(id, cursor), {
      headers: { "Cache-Control": "no-store" },
    });
  } catch (error) {
    console.error("[SESSION CWD HISTORY API ERROR]", error);
    return NextResponse.json({ error: "Session history is unavailable" }, { status: 500 });
  }
}
