import { NextResponse } from "next/server";
import clientPromise from "@/lib/mongodb";
import bcrypt from "bcryptjs";
import { getSessionFromRequest, isAdmin, revokeOperatorSessions } from "@/lib/auth/session";

function unauthorized() {
  return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
}

function forbidden() {
  return NextResponse.json({ error: "Forbidden" }, { status: 403 });
}

// ดึงข้อมูลผู้ใช้ทั้งหมด
export async function GET(request: Request) {
  const session = await getSessionFromRequest(request);
  if (!session || session.mustChangePassword) return unauthorized();
  if (!isAdmin(session)) return forbidden();
  try {
    const client = await clientPromise;
    const db = client.db("honeypot_db");
    const users = await db.collection("users").find({}).toArray();
    return NextResponse.json(users.map((user) => ({
      operatorId: user.operatorId,
      fullName: user.fullName,
      email: user.email,
      position: user.position,
      role: user.role,
      status: user.status,
      createdAt: user.createdAt,
    })));
  } catch {
    return NextResponse.json({ error: "Failed to fetch users" }, { status: 500 });
  }
}

// เพิ่มผู้ใช้ใหม่
export async function POST(request: Request) {
  const session = await getSessionFromRequest(request);
  if (!session || session.mustChangePassword) return unauthorized();
  if (!isAdmin(session)) return forbidden();
  try {
    const data = await request.json();
    const client = await clientPromise;
    const db = client.db("honeypot_db");

    // สุ่ม Operator ID เช่น OP_4402
    const operatorId = `OP_${Math.floor(1000 + Math.random() * 9000)}`;

    // ตั้งค่ารหัสผ่านเริ่มต้นเป็น default123 และแฮช
    const defaultPassword = await bcrypt.hash("default123", 10);

    const newUser = {
      operatorId,
      fullName: data.fullName,
      email: data.email,
      position: data.position,
      role: data.role,
      password: defaultPassword,
      isFirstLogin: true, // บังคับเปลี่ยนรหัสผ่าน
      status: "Active",
      createdAt: new Date(),
    };

    await db.collection("users").insertOne(newUser);
    return NextResponse.json({ success: true, user: newUser });
  } catch {
    return NextResponse.json({ error: "Failed to create user" }, { status: 500 });
  }
}

// อัปเดตข้อมูลผู้ใช้ (PUT)
export async function PUT(request: Request) {
  const session = await getSessionFromRequest(request);
  if (!session || session.mustChangePassword) return unauthorized();
  try {
    const data = await request.json();
    if (typeof data.operatorId !== "string" || !data.operatorId) {
      return NextResponse.json({ error: "Invalid operator ID" }, { status: 400 });
    }
    const administrator = isAdmin(session);
    if (!administrator && data.operatorId !== session.operatorId) return forbidden();
    const client = await clientPromise;
    const db = client.db("honeypot_db");

    const updateData: Record<string, unknown> = {
      fullName: data.fullName,
      email: data.email,
    };
    if (administrator) {
      updateData.position = data.position;
      updateData.role = data.role === "Admin" ? "Admin" : "Supporter";
    }

    // อัปเดตข้อมูลลงฐานข้อมูล
    await db.collection("users").updateOne(
      { operatorId: data.operatorId },
      { $set: updateData }
    );

    if (administrator && data.operatorId !== session.operatorId) {
      await revokeOperatorSessions(data.operatorId);
    }

    return NextResponse.json({ success: true });
  } catch {
    return NextResponse.json({ error: "Failed to update user" }, { status: 500 });
  }
}

// ลบผู้ใช้ (DELETE)
export async function DELETE(request: Request) {
  const session = await getSessionFromRequest(request);
  if (!session || session.mustChangePassword) return unauthorized();
  if (!isAdmin(session)) return forbidden();
  try {
    const { operatorId } = await request.json();
    if (typeof operatorId !== "string" || !operatorId) {
      return NextResponse.json({ error: "Invalid operator ID" }, { status: 400 });
    }
    if (operatorId === session.operatorId) return NextResponse.json({ error: "You cannot delete your own account" }, { status: 400 });
    const client = await clientPromise;
    const db = client.db("honeypot_db");

    await db.collection("users").deleteOne({ operatorId });
    await revokeOperatorSessions(operatorId);
    return NextResponse.json({ success: true });
  } catch {
    return NextResponse.json({ error: "Failed to delete user" }, { status: 500 });
  }
}
