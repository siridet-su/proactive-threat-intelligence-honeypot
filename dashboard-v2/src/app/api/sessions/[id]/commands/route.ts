import { NextResponse } from "next/server";

import { getSessionFromRequest, isAdmin } from "@/lib/auth/session";
import {
  loadAdminCowrieCommands,
  loadLocalAdminCowrieCommands,
  resolveCanonicalSessionIdForCommandEvidence,
} from "@/lib/session-command-server";
import { CANONICAL_SESSION_ID_PATTERN, isValidSensorSessionIdentifier } from "@/lib/sensor-session-identity";

export const dynamic = "force-dynamic";
export const revalidate = 0;

const PRIVATE_HEADERS = {
  "Cache-Control": "private, no-store, no-cache, max-age=0, must-revalidate",
  Pragma: "no-cache",
  Vary: "Cookie",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
};

function json(body: Record<string, unknown>, status: number): NextResponse {
  return NextResponse.json(body, { status, headers: PRIVATE_HEADERS });
}

export async function GET(
  request: Request,
  context: { params: Promise<{ id: string }> },
): Promise<NextResponse> {
  try {
    const session = await getSessionFromRequest(request);
    if (!session) return json({ ok: false, error: "Authentication required" }, 401);
    if (!isAdmin(session) || session.mustChangePassword) {
      return json({ ok: false, error: "Administrator access required" }, 403);
    }

    const { id } = await context.params;
    if (!CANONICAL_SESSION_ID_PATTERN.test(id) && !isValidSensorSessionIdentifier(id)) {
      return json({ ok: false, error: "Invalid session identifier" }, 400);
    }

    const localReview = process.env.NODE_ENV === "development"
      && process.env.PTI_LOCAL_ADMIN_COMMANDS_FROM_MONGO === "true";
    if (localReview && !new Set(["127.0.0.1", "localhost", "[::1]"]).has(new URL(request.url).hostname)) {
      return json({ ok: false, error: "Local command review requires loopback access" }, 403);
    }
    const canonicalSessionId = await resolveCanonicalSessionIdForCommandEvidence(id);
    if (!canonicalSessionId) {
      return json({ ok: false, error: "No unique authenticated session binding is available" }, 400);
    }
    const projection = localReview
      ? await loadLocalAdminCowrieCommands(canonicalSessionId)
      : await loadAdminCowrieCommands(canonicalSessionId);
    return json({
      ...projection,
      schema_version: "dashboard.admin_cowrie_commands.v2",
      requested_session_id: id,
    }, 200);
  } catch {
    // Do not log or return command text or event payloads on any failure path.
    return json({ ok: false, error: "Sensitive command evidence is temporarily unavailable" }, 503);
  }
}
