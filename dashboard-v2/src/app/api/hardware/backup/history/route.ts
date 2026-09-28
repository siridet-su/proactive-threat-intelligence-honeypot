import { NextResponse } from "next/server";

import { getSessionFromRequest } from "@/lib/auth/session";
import { getHardwareBackupHistory, MAX_BACKUP_HISTORY_PERIOD } from "@/lib/hardware-backup";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET(request: Request) {
  const session = await getSessionFromRequest(request);
  if (!session || session.mustChangePassword) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const rawPeriod = new URL(request.url).searchParams.get("period");
  if (!rawPeriod || !/^[1-9]\d*$/.test(rawPeriod) || Number(rawPeriod) > MAX_BACKUP_HISTORY_PERIOD) {
    return NextResponse.json({ error: "Choose a valid backup history period" }, { status: 400 });
  }

  try {
    return NextResponse.json(await getHardwareBackupHistory(Number(rawPeriod)), {
      headers: { "Cache-Control": "no-store" },
    });
  } catch (error: unknown) {
    console.error("Failed to fetch hardware backup history:", error);
    return NextResponse.json({ error: "Backup history is unavailable" }, { status: 503 });
  }
}
