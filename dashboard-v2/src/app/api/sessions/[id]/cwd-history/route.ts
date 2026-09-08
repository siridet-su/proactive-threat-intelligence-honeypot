import { NextResponse } from "next/server";

import { getSessionFromRequest } from "@/lib/auth/session";
import { getSessionCwdHistory } from "@/lib/filesystem-server";

export const dynamic = "force-dynamic";

export async function GET(request: Request, { params }: { params: Promise<{ id: string }> }) {
  const session = await getSessionFromRequest(request);
  if (!session || session.mustChangePassword) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }
  const { id } = await params;
  try {
    const cursor = new URL(request.url).searchParams.get("cursor");
    return NextResponse.json(await getSessionCwdHistory(id, cursor), {
      headers: { "Cache-Control": "no-store" },
    });
  } catch (error) {
    console.error("[SESSION CWD HISTORY API ERROR]", error);
    return NextResponse.json({ error: "Session history is unavailable" }, { status: 500 });
  }
}
