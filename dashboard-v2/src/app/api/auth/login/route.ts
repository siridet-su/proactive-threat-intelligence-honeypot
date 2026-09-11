import { NextResponse } from "next/server";
import { getMongoClient } from "@/lib/mongodb";
import bcrypt from "bcryptjs";
import { createSession, sessionCookie } from "@/lib/auth/session";
import { emailLookup, normalizeEmail } from "@/lib/auth/operator-identity";

export async function POST(request: Request) {
  try {
    const body: unknown = await request.json();
    if (!body || typeof body !== "object") {
      return NextResponse.json({ success: false, error: "Invalid credentials." }, { status: 400 });
    }
    const { identifier, operatorId, password } = body as {
      identifier?: unknown;
      operatorId?: unknown;
      password?: unknown;
    };
    const suppliedIdentifier = typeof identifier === "string" ? identifier : operatorId;
    if (typeof suppliedIdentifier !== "string" || typeof password !== "string" || !suppliedIdentifier.trim() || !password) {
      return NextResponse.json({ success: false, error: "Invalid credentials." }, { status: 400 });
    }
    const client = await getMongoClient();
    const db = client.db("honeypot_db");
    const normalizedIdentifier = suppliedIdentifier.trim();
    const normalizedEmail = normalizeEmail(normalizedIdentifier);

    let authenticatedUser: { operatorId: string; role: "Admin" | "Supporter"; isFirstLogin: boolean } | null = null;

    if (normalizedIdentifier.toLowerCase() === "admin") {
      const configuredPassword = process.env.PTI_ADMIN_PASSWORD;
      const developmentPassword = process.env.NODE_ENV !== "production" ? "admin" : undefined;
      if (password === configuredPassword || password === developmentPassword) {
        authenticatedUser = { operatorId: "admin", role: "Admin", isFirstLogin: false };
      }
    } else {
      const user = await db.collection("users").findOne(
        normalizedEmail
          ? { email: emailLookup(normalizedEmail) }
          : { operatorId: normalizedIdentifier },
      );
      if (user && user.status === "Active" && typeof user.password === "string" && await bcrypt.compare(password, user.password)) {
        authenticatedUser = {
          operatorId: user.operatorId,
          role: user.role === "Admin" ? "Admin" : "Supporter",
          isFirstLogin: Boolean(user.isFirstLogin),
        };
      }
    }

    if (!authenticatedUser) {
      return NextResponse.json({ success: false, error: "Invalid credentials." }, { status: 401 });
    }

    const { token, expiresAt } = await createSession({
      operatorId: authenticatedUser.operatorId,
      role: authenticatedUser.role,
      mustChangePassword: authenticatedUser.isFirstLogin,
    });
    const response = NextResponse.json({
      success: true,
      isFirstLogin: authenticatedUser.isFirstLogin,
      role: authenticatedUser.role,
      operatorId: authenticatedUser.operatorId,
    });
    response.cookies.set(sessionCookie(token, expiresAt));
    return response;
  } catch (error) {
    console.error("[LOGIN ERROR]", error);
    return NextResponse.json({ success: false, error: "Server Error" }, { status: 500 });
  }
}
