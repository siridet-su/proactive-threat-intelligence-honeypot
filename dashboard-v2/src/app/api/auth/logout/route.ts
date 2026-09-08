import { NextResponse } from "next/server";

import { clearSessionCookie, destroySessionFromRequest } from "@/lib/auth/session";

export async function POST(request: Request) {
  try {
    await destroySessionFromRequest(request);
  } catch {
    // Clear the browser cookie even when database cleanup is temporarily unavailable.
  }
  const response = NextResponse.json({ success: true });
  response.cookies.set(clearSessionCookie());
  return response;
}
