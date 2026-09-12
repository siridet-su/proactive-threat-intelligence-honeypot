import { NextResponse } from "next/server";
import { getMongoClient } from "@/lib/mongodb";
import bcrypt from "bcryptjs";
import { getSessionFromRequest, isAdmin, revokeOperatorSessions } from "@/lib/auth/session";
import { emailLookup, normalizeEmail } from "@/lib/auth/operator-identity";

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
    const client = await getMongoClient();
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
    const data: unknown = await request.json();
    if (!data || typeof data !== "object" || Array.isArray(data)) {
      return NextResponse.json({ error: "Invalid operator details" }, { status: 400 });
    }

    const candidate = data as Record<string, unknown>;
    const fullName = typeof candidate.fullName === "string" ? candidate.fullName.trim() : "";
    const email = typeof candidate.email === "string" ? normalizeEmail(candidate.email) : null;
    const position = typeof candidate.position === "string" ? candidate.position.trim() : "";
    const role = candidate.role === "Admin" ? "Admin" : candidate.role === "Supporter" ? "Supporter" : "";
    const initialPassword = typeof candidate.initialPassword === "string" ? candidate.initialPassword : "";

    if (!fullName || !email || !position || !role || initialPassword.length < 8) {
      return NextResponse.json({ error: "Enter complete operator details and an access key of at least 8 characters" }, { status: 400 });
    }

    const client = await getMongoClient();
    const db = client.db("honeypot_db");
    const users = db.collection("users");

    const emailInUse = await users.findOne(
      { email: emailLookup(email) },
      { projection: { _id: 1 } },
    );
    if (emailInUse) {
      return NextResponse.json({ error: "An operator already uses this email address" }, { status: 409 });
    }

    let operatorId = "";
    for (let attempt = 0; attempt < 8; attempt += 1) {
      const candidateId = `OP_${Math.floor(1000 + Math.random() * 9000)}`;
      const existing = await users.findOne({ operatorId: candidateId }, { projection: { _id: 1 } });
      if (!existing) {
        operatorId = candidateId;
        break;
      }
    }
    if (!operatorId) return NextResponse.json({ error: "Unable to allocate an operator ID. Please try again." }, { status: 503 });

    const password = await bcrypt.hash(initialPassword, 10);

    const newUser = {
      operatorId,
      fullName,
      email,
      position,
      role,
      password,
      isFirstLogin: true,
      status: "Active",
      createdAt: new Date(),
    };

    await users.insertOne(newUser);
    return NextResponse.json({ success: true, user: {
      operatorId: newUser.operatorId,
      fullName: newUser.fullName,
      email: newUser.email,
      position: newUser.position,
      role: newUser.role,
      status: newUser.status,
      createdAt: newUser.createdAt,
    } });
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
    const client = await getMongoClient();
    const db = client.db("honeypot_db");

    const email = typeof data.email === "string" ? normalizeEmail(data.email) : null;
    if (!email) return NextResponse.json({ error: "Enter a valid email address" }, { status: 400 });

    const users = db.collection("users");
    const emailInUse = await users.findOne(
      { operatorId: { $ne: data.operatorId }, email: emailLookup(email) },
      { projection: { _id: 1 } },
    );
    if (emailInUse) {
      return NextResponse.json({ error: "An operator already uses this email address" }, { status: 409 });
    }

    const updateData: Record<string, unknown> = {
      fullName: data.fullName,
      email,
    };
    if (administrator) {
      updateData.position = data.position;
      updateData.role = data.role === "Admin" ? "Admin" : "Supporter";
    }

    // อัปเดตข้อมูลลงฐานข้อมูล
    await users.updateOne(
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
    const client = await getMongoClient();
    const db = client.db("honeypot_db");

    await db.collection("users").deleteOne({ operatorId });
    await revokeOperatorSessions(operatorId);
    return NextResponse.json({ success: true });
  } catch {
    return NextResponse.json({ error: "Failed to delete user" }, { status: 500 });
  }
}
