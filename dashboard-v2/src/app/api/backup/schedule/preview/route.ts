import { NextResponse } from "next/server";

import { getSessionFromRequest, isAdmin } from "@/lib/auth/session";
import { previewBackupScheduleEdit, type BackupScheduleEdit } from "@/lib/backupSchedule";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function POST(request: Request) {
  const session = await getSessionFromRequest(request);
  if (!session || session.mustChangePassword) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  if (!isAdmin(session)) return NextResponse.json({ error: "Administrator access required" }, { status: 403 });
  let edit: BackupScheduleEdit;
  try { edit = (await request.json()) as BackupScheduleEdit; }
  catch { return NextResponse.json({ error: "Invalid JSON" }, { status: 400 }); }
  try {
    return NextResponse.json(await previewBackupScheduleEdit(edit), { headers: { "Cache-Control": "no-store" } });
  } catch (error: unknown) {
    return NextResponse.json({ error: error instanceof Error ? error.message : "Could not preview schedule" }, { status: 400 });
  }
}
