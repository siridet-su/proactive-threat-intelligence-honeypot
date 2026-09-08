import { NextResponse, type NextRequest } from "next/server";

import { SESSION_COOKIE_NAME, verifySessionToken } from "@/lib/auth/session-token";

const protectedPrefixes = [
  "/dashboard",
  "/threat-intel",
  "/archives",
  "/malware-vault",
  "/system-health",
  "/user-management",
  "/profile",
  "/change-password",
];

function isProtectedPath(pathname: string) {
  return protectedPrefixes.some((prefix) => pathname === prefix || pathname.startsWith(`${prefix}/`));
}

export async function proxy(request: NextRequest) {
  const { pathname } = request.nextUrl;
  const session = await verifySessionToken(request.cookies.get(SESSION_COOKIE_NAME)?.value);

  if (pathname === "/login" && session) {
    return NextResponse.redirect(new URL(session.mustChangePassword ? "/change-password" : "/dashboard", request.url));
  }

  if (!isProtectedPath(pathname)) return NextResponse.next();

  if (!session) {
    const destination = new URL("/login", request.url);
    destination.searchParams.set("next", pathname);
    return NextResponse.redirect(destination);
  }

  if (session.mustChangePassword && pathname !== "/change-password") {
    return NextResponse.redirect(new URL("/change-password", request.url));
  }

  if (pathname.startsWith("/user-management") && session.role !== "Admin") {
    return NextResponse.redirect(new URL("/dashboard", request.url));
  }

  return NextResponse.next();
}

export const config = { matcher: ["/dashboard/:path*", "/threat-intel/:path*", "/archives/:path*", "/malware-vault/:path*", "/system-health/:path*", "/user-management/:path*", "/profile/:path*", "/change-password"] };
