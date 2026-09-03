import { NextResponse } from "next/server";
import clientPromise from "@/lib/mongodb";
import bcrypt from "bcryptjs";

export async function POST(request: Request) {
  try {
    const { operatorId, newPassword } = await request.json();
    const client = await clientPromise;
    const db = client.db("honeypot_db");

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    await db.collection("users").updateOne(
      { operatorId },
      { $set: { password: hashedPassword, isFirstLogin: false } }
    );

    return NextResponse.json({ success: true });
  } catch (error) {
    return NextResponse.json({ success: false, error: "Failed to update password" }, { status: 500 });
  }
}