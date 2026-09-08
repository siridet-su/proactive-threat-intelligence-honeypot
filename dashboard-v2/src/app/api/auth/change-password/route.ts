import { NextResponse } from "next/server";
import { getMongoClient } from "@/lib/mongodb";
import bcrypt from "bcryptjs";
import { getSessionFromRequest, refreshSessionToken, sessionCookie } from "@/lib/auth/session";

export async function POST(request: Request) {
  try {
    const session = await getSessionFromRequest(request);
    if (!session) return NextResponse.json({ success: false, error: "Unauthorized" }, { status: 401 });
    if (session.operatorId === "admin") {
      return NextResponse.json({ success: false, error: "The built-in Admin access key is managed through PTI_ADMIN_PASSWORD." }, { status: 400 });
    }
    const body: unknown = await request.json();
    const newPassword = body && typeof body === "object" ? (body as { newPassword?: unknown }).newPassword : undefined;
    if (typeof newPassword !== "string" || newPassword.length < 8) {
      return NextResponse.json({ success: false, error: "Access key must contain at least 8 characters." }, { status: 400 });
    }
    const client = await getMongoClient();
    const db = client.db("honeypot_db");

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    await db.collection("users").updateOne(
      { operatorId: session.operatorId },
      { $set: { password: hashedPassword, isFirstLogin: false } }
    );

    const updatedSession = { ...session, mustChangePassword: false };
    const response = NextResponse.json({ success: true });
    response.cookies.set(sessionCookie(await refreshSessionToken(updatedSession), session.expiresAt));
    return response;
  } catch {
    return NextResponse.json({ success: false, error: "Failed to update password" }, { status: 500 });
  }
}
