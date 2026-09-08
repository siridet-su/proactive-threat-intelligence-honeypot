import { NextResponse } from "next/server";

import { getSessionFromRequest } from "@/lib/auth/session";
import { getFilesystemTopology } from "@/lib/filesystem-server";

export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  const session = await getSessionFromRequest(request);
  if (!session || session.mustChangePassword) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }
  try {
    return NextResponse.json(await getFilesystemTopology(), {
      headers: { "Cache-Control": "no-store" },
    });
  } catch (error) {
    console.error("[FILESYSTEM TOPOLOGY API ERROR]", error);
    return NextResponse.json({ error: "Filesystem activity is unavailable" }, { status: 500 });
  }
}
