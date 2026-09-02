import { NextResponse } from "next/server";
import clientPromise from "@/lib/mongodb";
import bcrypt from "bcryptjs";

// ดึงข้อมูลผู้ใช้ทั้งหมด
export async function GET() {
  try {
    const client = await clientPromise;
    const db = client.db("honeypot_db");
    const users = await db.collection("users").find({}).toArray();
    return NextResponse.json(users);
  } catch (error) {
    return NextResponse.json({ error: "Failed to fetch users" }, { status: 500 });
  }
}

// เพิ่มผู้ใช้ใหม่
export async function POST(request: Request) {
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
  } catch (error) {
    return NextResponse.json({ error: "Failed to create user" }, { status: 500 });
  }
}

// อัปเดตข้อมูลผู้ใช้ (PUT)
export async function PUT(request: Request) {
  try {
    const data = await request.json();
    const client = await clientPromise;
    const db = client.db("honeypot_db");

    // สร้าง object สำหรับอัปเดตข้อมูลทั่วไป
    const updateData: any = {
      fullName: data.fullName,
      email: data.email,
      position: data.position,
      role: data.role,
    };

    // อัปเดตข้อมูลลงฐานข้อมูล
    await db.collection("users").updateOne(
      { operatorId: data.operatorId },
      { $set: updateData }
    );

    return NextResponse.json({ success: true });
  } catch (error) {
    return NextResponse.json({ error: "Failed to update user" }, { status: 500 });
  }
}

// ลบผู้ใช้ (DELETE)
export async function DELETE(request: Request) {
  try {
    const { operatorId } = await request.json();
    const client = await clientPromise;
    const db = client.db("honeypot_db");

    await db.collection("users").deleteOne({ operatorId });
    return NextResponse.json({ success: true });
  } catch (error) {
    return NextResponse.json({ error: "Failed to delete user" }, { status: 500 });
  }
}