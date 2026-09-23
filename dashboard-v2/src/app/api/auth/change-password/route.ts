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
    const payload = body && typeof body === "object" ? body as Record<string, unknown> : {};
    
    const currentPassword = payload.currentPassword;
    const newPassword = payload.newPassword;

    // ตรวจสอบว่าส่งรหัสผ่านเดิมมาหรือไม่
    if (typeof currentPassword !== "string" || !currentPassword) {
      return NextResponse.json({ success: false, error: "Please provide your current access key." }, { status: 400 });
    }

    // ตรวจสอบรหัสผ่านใหม่
    if (typeof newPassword !== "string" || newPassword.length < 8) {
      return NextResponse.json({ success: false, error: "Access key must contain at least 8 characters." }, { status: 400 });
    }

    const client = await getMongoClient();
    const db = client.db("honeypot_db");

    // 1. ค้นหาข้อมูลผู้ใช้ในระบบ
    const user = await db.collection("users").findOne({ operatorId: session.operatorId });
    if (!user) {
      return NextResponse.json({ success: false, error: "Operator not found." }, { status: 404 });
    }

    // 2. ตรวจสอบรหัสผ่านปัจจุบันว่าตรงกับในฐานข้อมูลหรือไม่
    const isPasswordValid = await bcrypt.compare(currentPassword, user.password);
    if (!isPasswordValid) {
      return NextResponse.json({ success: false, error: "รหัสผ่านปัจจุบันไม่ถูกต้อง (Current password is incorrect)" }, { status: 401 });
    }

    // 3. เข้ารหัสรหัสผ่านใหม่
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // 4. บันทึกรหัสผ่านใหม่ลงฐานข้อมูล
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
