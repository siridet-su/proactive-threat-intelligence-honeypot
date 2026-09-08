import { NextResponse } from "next/server";
import clientPromise from "@/lib/mongodb";
import { getSessionFromRequest, isAdmin } from "@/lib/auth/session";

export async function GET(request: Request, { params }: { params: Promise<{ operatorId: string }> }) {
  try {
    // 1. แกะค่า params ด้วย await ก่อนนำไปใช้
    const resolvedParams = await params;
    const operatorId = resolvedParams.operatorId;
    const session = await getSessionFromRequest(request);
    if (!session || session.mustChangePassword) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    if (!isAdmin(session) && session.operatorId !== operatorId) {
      return NextResponse.json({ error: "Forbidden" }, { status: 403 });
    }

    const client = await clientPromise;
    const db = client.db("honeypot_db");

    // 2. ใช้ operatorId ที่แกะมาแล้วในการค้นหา
    const user = await db.collection("users").findOne({ operatorId: operatorId });

    if (!user) {
      return NextResponse.json({ error: "User not found" }, { status: 404 });
    }

    // ตัดข้อมูลรหัสผ่านทิ้งก่อนส่งกลับไปที่หน้าเว็บ
    return NextResponse.json({
      operatorId: user.operatorId,
      fullName: user.fullName,
      email: user.email,
      position: user.position,
      role: user.role,
      status: user.status,
      createdAt: user.createdAt,
    });
  } catch {
    return NextResponse.json({ error: "Failed to fetch user profile" }, { status: 500 });
  }
}
