import { NextResponse } from "next/server";

import { getSessionFromRequest, isAdmin } from "@/lib/auth/session";
import { getBackupScheduleView, saveBackupSchedule, type BackupScheduleEdit } from "@/lib/backupSchedule";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

function scheduleEdit(value: unknown): value is BackupScheduleEdit {
  if (!value || typeof value !== "object") return false;
  const item = value as Record<string, unknown>;
  if (item.mode === "clear_override") return true;
  if (item.mode === "permanent") return typeof item.time === "string";
  return item.mode === "temporary" && typeof item.time === "string"
    && typeof item.start_date === "string" && typeof item.days === "number";
}

export async function GET(request: Request) {
  const session = await getSessionFromRequest(request);
  if (!session || session.mustChangePassword) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  try {
    return NextResponse.json(await getBackupScheduleView(isAdmin(session)), { headers: { "Cache-Control": "no-store" } });
  } catch (error: unknown) {
    return NextResponse.json({ error: error instanceof Error ? error.message : "Schedule unavailable" }, { status: 503 });
  }
}

export async function POST(request: Request) {
  const session = await getSessionFromRequest(request);
  if (!session || session.mustChangePassword) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  if (!isAdmin(session)) return NextResponse.json({ error: "Administrator access required" }, { status: 403 });
  let body: unknown;
  try { body = await request.json(); } catch { return NextResponse.json({ error: "Invalid JSON" }, { status: 400 }); }
  if (!body || typeof body !== "object" || !scheduleEdit((body as Record<string, unknown>).edit)
    || typeof (body as Record<string, unknown>).expected_revision !== "string") {
    return NextResponse.json({ error: "Invalid schedule request" }, { status: 400 });
  }
  const input = body as { edit: BackupScheduleEdit; expected_revision: string };
  try {
    const view = await saveBackupSchedule(input.edit, input.expected_revision, session.operatorId);
    return NextResponse.json(view, { headers: { "Cache-Control": "no-store" } });
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : "Could not save schedule";
    const duplicate = Boolean(error && typeof error === "object" && "code" in error && (error as { code?: unknown }).code === 11000);
    const status = duplicate || message.includes("changed") ? 409 : message.includes("not ready") ? 503 : 400;
    return NextResponse.json({ error: duplicate ? "Backup schedule changed; refresh and try again" : message }, { status });
  }
}
