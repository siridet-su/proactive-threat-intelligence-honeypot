import { NextResponse } from "next/server";

import { getSessionFromRequest } from "@/lib/auth/session";
import { getSessionCwdHistory, getSessionCwdHistoryHop, MAX_CWD_IDENTIFIER_LENGTH } from "@/lib/filesystem-server";

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
    const cursor = url.searchParams.get("cursor");

    if (
      id.length > MAX_CWD_IDENTIFIER_LENGTH ||
      (hop && hop.length > MAX_CWD_IDENTIFIER_LENGTH) ||
      (cursor && cursor.length > MAX_CWD_IDENTIFIER_LENGTH)
    ) {
      return NextResponse.json({ error: "Identifier length exceeds limit" }, { status: 400 });
    }

    if (hop) {
      const result = await getSessionCwdHistoryHop(id, hop);
      if (!result.item) {
        return NextResponse.json({ item: null, error: "Hop not found or unavailable" }, { status: 404 });
      }
      return NextResponse.json(result, {
        headers: { "Cache-Control": "no-store" },
      });
    }

    return NextResponse.json(await getSessionCwdHistory(id, cursor), {
      headers: { "Cache-Control": "no-store" },
    });
  } catch (error) {
    console.error("[SESSION CWD HISTORY API ERROR]", error);
    return NextResponse.json({ error: "Session history is unavailable" }, { status: 500 });
  }
}
