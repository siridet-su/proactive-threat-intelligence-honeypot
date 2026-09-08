import "server-only";

import { createHash, randomUUID } from "crypto";

import clientPromise from "@/lib/mongodb";
import {
  SESSION_COOKIE_NAME,
  signSessionToken,
  type SessionRole,
  verifySessionToken,
} from "@/lib/auth/session-token";

const DATABASE_NAME = "honeypot_db";
const SESSIONS_COLLECTION = "auth_sessions";
const SESSION_MAX_AGE_SECONDS = 8 * 60 * 60;

export interface AuthSession {
  sessionId: string;
  operatorId: string;
  role: SessionRole;
  mustChangePassword: boolean;
  expiresAt: Date;
  fullName?: string;
}

function hashSessionId(sessionId: string): string {
  return createHash("sha256").update(sessionId).digest("hex");
}

function cookieOptions(maxAge: number) {
  return {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax" as const,
    path: "/",
    maxAge,
    priority: "high" as const,
  };
}

function readCookie(request: Request, name: string): string | undefined {
  const cookie = request.headers.get("cookie");
  if (!cookie) return undefined;
  return cookie.split(";").map((part) => part.trim()).find((part) => part.startsWith(`${name}=`))?.slice(name.length + 1);
}

let sessionIndexes: Promise<void> | null = null;

async function ensureSessionIndexes() {
  if (sessionIndexes) return sessionIndexes;
  sessionIndexes = (async () => {
    const client = await clientPromise;
    const collection = client.db(DATABASE_NAME).collection(SESSIONS_COLLECTION);
    await Promise.all([
      collection.createIndex({ sessionIdHash: 1 }, { unique: true, name: "session_id_hash_unique" }),
      collection.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0, name: "session_expiry_ttl" }),
      collection.createIndex({ operatorId: 1 }, { name: "session_operator_id" }),
    ]);
  })();
  return sessionIndexes;
}

export async function createSession(input: Omit<AuthSession, "sessionId" | "expiresAt">): Promise<{ token: string; expiresAt: Date }> {
  await ensureSessionIndexes();
  const sessionId = randomUUID();
  const expiresAt = new Date(Date.now() + SESSION_MAX_AGE_SECONDS * 1_000);
  const token = await signSessionToken({
    sessionId,
    operatorId: input.operatorId,
    role: input.role,
    mustChangePassword: input.mustChangePassword,
    expiresAt: expiresAt.getTime(),
  });
  const client = await clientPromise;
  await client.db(DATABASE_NAME).collection(SESSIONS_COLLECTION).insertOne({
    sessionIdHash: hashSessionId(sessionId),
    operatorId: input.operatorId,
    expiresAt,
    createdAt: new Date(),
    lastSeenAt: new Date(),
  });
  return { token, expiresAt };
}

export function sessionCookie(token: string, expiresAt: Date) {
  return {
    name: SESSION_COOKIE_NAME,
    value: token,
    ...cookieOptions(Math.max(0, Math.floor((expiresAt.getTime() - Date.now()) / 1_000))),
    expires: expiresAt,
  };
}

export function clearSessionCookie() {
  return { name: SESSION_COOKIE_NAME, value: "", ...cookieOptions(0), expires: new Date(0) };
}

export async function getSessionFromRequest(request: Request): Promise<AuthSession | null> {
  const payload = await verifySessionToken(readCookie(request, SESSION_COOKIE_NAME));
  if (!payload) return null;

  const client = await clientPromise;
  const db = client.db(DATABASE_NAME);
  const sessionRecord = await db.collection(SESSIONS_COLLECTION).findOne({
    sessionIdHash: hashSessionId(payload.sessionId),
    operatorId: payload.operatorId,
    expiresAt: { $gt: new Date() },
  });
  if (!sessionRecord) return null;

  if (payload.operatorId === "admin") {
    return {
      sessionId: payload.sessionId,
      operatorId: "admin",
      role: "Admin",
      mustChangePassword: false,
      expiresAt: sessionRecord.expiresAt as Date,
      fullName: "Admin",
    };
  }

  const user = await db.collection("users").findOne({ operatorId: payload.operatorId });
  if (!user || user.status !== "Active") return null;
  const role: SessionRole = user.role === "Admin" ? "Admin" : "Supporter";
  const mustChangePassword = Boolean(user.isFirstLogin);

  await db.collection(SESSIONS_COLLECTION).updateOne(
    { _id: sessionRecord._id },
    { $set: { lastSeenAt: new Date() } },
  );

  return {
    sessionId: payload.sessionId,
    operatorId: payload.operatorId,
    role,
    mustChangePassword,
    expiresAt: sessionRecord.expiresAt as Date,
    fullName: typeof user.fullName === "string" ? user.fullName : undefined,
  };
}

export async function refreshSessionToken(session: AuthSession): Promise<string> {
  return signSessionToken({
    sessionId: session.sessionId,
    operatorId: session.operatorId,
    role: session.role,
    mustChangePassword: session.mustChangePassword,
    expiresAt: session.expiresAt.getTime(),
  });
}

export async function destroySessionFromRequest(request: Request): Promise<void> {
  const payload = await verifySessionToken(readCookie(request, SESSION_COOKIE_NAME));
  if (!payload) return;
  const client = await clientPromise;
  await client.db(DATABASE_NAME).collection(SESSIONS_COLLECTION).deleteOne({
    sessionIdHash: hashSessionId(payload.sessionId),
  });
}

export async function revokeOperatorSessions(operatorId: string): Promise<void> {
  const client = await clientPromise;
  await client.db(DATABASE_NAME).collection(SESSIONS_COLLECTION).deleteMany({ operatorId });
}

export function isAdmin(session: AuthSession): boolean {
  return session.role === "Admin";
}
