import { createHmac, timingSafeEqual } from "node:crypto";

export const DASHBOARD_SESSION_COOKIE = "dashboard_v2_session";

function authConfig() {
  return {
    operatorId: process.env.DASHBOARD_V2_OPERATOR_ID?.trim() || "",
    accessKey: process.env.DASHBOARD_V2_ACCESS_KEY || "",
    sessionSecret: process.env.DASHBOARD_V2_SESSION_SECRET || "",
  };
}

export function authenticationConfigured(): boolean {
  const config = authConfig();
  return Boolean(config.operatorId && config.accessKey && config.sessionSecret);
}

export function validDashboardSession(request: Request): boolean {
  if (!authenticationConfigured()) return false;
  const config = authConfig();
  const cookieHeader = request.headers.get("cookie") || "";
  const cookie = cookieHeader
    .split(";")
    .map((part) => part.trim())
    .find((part) => part.startsWith(`${DASHBOARD_SESSION_COOKIE}=`))
    ?.slice(`${DASHBOARD_SESSION_COOKIE}=`.length);
  if (!cookie) return false;
  return safeEqual(cookie, sessionValue(config.operatorId, config.accessKey, config.sessionSecret));
}

export function sessionValue(operatorId: string, accessKey: string, sessionSecret: string): string {
  return createHmac("sha256", sessionSecret).update(`${operatorId}:${accessKey}`).digest("hex");
}

export function safeEqual(left: string, right: string): boolean {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);
  return leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
}

export function authCookie(value: string, maxAge: number): string {
  const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
  return `${DASHBOARD_SESSION_COOKIE}=${value}; Path=/; Max-Age=${maxAge}; HttpOnly; SameSite=Lax${secure}`;
}
