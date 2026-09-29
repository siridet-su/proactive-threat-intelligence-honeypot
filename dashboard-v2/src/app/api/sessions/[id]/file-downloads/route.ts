import { NextResponse } from "next/server";

import { getSessionFromRequest, isAdmin } from "@/lib/auth/session";
import { loadSessionDownloads } from "@/lib/session-download-server";
import { resolveCanonicalSessionIdForCommandEvidence } from "@/lib/session-command-server";
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

export async function GET(request: Request, context: { params: Promise<{ id: string }> }): Promise<NextResponse> {
  try {
    const session = await getSessionFromRequest(request);
    if (!session) return json({ ok: false, error: "Authentication required" }, 401);
    if (!isAdmin(session) || session.mustChangePassword) return json({ ok: false, error: "Administrator access required" }, 403);

    const { id } = await context.params;
    if (!CANONICAL_SESSION_ID_PATTERN.test(id) && !isValidSensorSessionIdentifier(id)) {
      return json({ ok: false, error: "Invalid session identifier" }, 400);
    }
    const canonicalSessionId = await resolveCanonicalSessionIdForCommandEvidence(id);
    if (!canonicalSessionId) return json({ ok: false, error: "No unique authenticated session binding is available" }, 400);

    const projection = await loadSessionDownloads(canonicalSessionId);
    return json({
      ok: true,
      schema_version: "dashboard.session_file_downloads.v1",
      requested_session_id: id,
      session_id: canonicalSessionId,
      ...projection,
    }, 200);
  } catch {
    return json({ ok: false, error: "Download evidence is temporarily unavailable" }, 503);
  }
}
