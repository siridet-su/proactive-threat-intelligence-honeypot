import { NextResponse } from "next/server";

import { getSessionFromRequest } from "@/lib/auth/session";

export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  const session = await getSessionFromRequest(request);
  if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  return NextResponse.json({
    operatorId: session.operatorId,
    role: session.role,
    fullName: session.fullName ?? session.operatorId,
    mustChangePassword: session.mustChangePassword,
    expiresAt: session.expiresAt.toISOString(),
  });
}
