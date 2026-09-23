import { NextResponse } from "next/server";

import { getSessionFromRequest } from "@/lib/auth/session";
import { getHardwareBackupStatus } from "@/lib/hardware-backup";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET(request: Request) {
  const session = await getSessionFromRequest(request);
  if (!session || session.mustChangePassword) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  try {
    return NextResponse.json(await getHardwareBackupStatus(), {
      headers: { "Cache-Control": "no-store" },
    });
  } catch (error: unknown) {
    console.error("Failed to fetch hardware backup status:", error);
    const message = error instanceof Error ? error.message : "Failed to fetch hardware backup status";
    return NextResponse.json({ error: message }, { status: 503 });
  }
}
