import { NextResponse } from "next/server";
import clientPromise from "@/lib/mongodb";
import bcrypt from "bcryptjs";

export async function POST(request: Request) {
  try {
    const { operatorId, password } = await request.json();
    const client = await clientPromise;
    const db = client.db("honeypot_db");

    // กรณี Admin Root ชั่วคราว (เผื่อเข้าไม่ได้)
    if (operatorId === "admin" && password === "admin") {
      return NextResponse.json({ success: true, isFirstLogin: false, role: "Admin" });
    }

    const user = await db.collection("users").findOne({ operatorId });
    if (!user) {
      return NextResponse.json({ success: false, error: "Invalid Operator ID" }, { status: 401 });
    }

    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) {
      return NextResponse.json({ success: false, error: "Invalid Access Key" }, { status: 401 });
    }

    return NextResponse.json({
      success: true,
      isFirstLogin: user.isFirstLogin,
      role: user.role,
      operatorId: user.operatorId
    });
  } catch (error) {
    return NextResponse.json({ success: false, error: "Server Error" }, { status: 500 });
  }
}