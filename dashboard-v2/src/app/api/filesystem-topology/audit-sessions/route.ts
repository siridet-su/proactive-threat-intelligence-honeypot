import { getSessionFromRequest } from "@/lib/auth/session";
import { getAuditSessions } from "@/lib/filesystem-server";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET(request: Request) {
  const session = await getSessionFromRequest(request);
  if (!session || session.mustChangePassword) {
    return Response.json({ error: "Unauthorized" }, { status: 401 });
  }

  try {
    const url = new URL(request.url);
    const search = url.searchParams.get("q") ?? url.searchParams.get("search");
    const targetPath = url.searchParams.get("targetPath");
    const hideHomeParam = url.searchParams.get("hideHome");
    const hideHome = hideHomeParam === "1" || hideHomeParam === "true";
    const cursor = url.searchParams.get("cursor");
    const limitParam = url.searchParams.get("limit");
    const limit = limitParam ? parseInt(limitParam, 10) : 25;

    const summaryParam = url.searchParams.get("summary") ?? url.searchParams.get("facets");
    const includeSummary = summaryParam === "1" || summaryParam === "true";

    const fromParam = url.searchParams.get("from");
    const toParam = url.searchParams.get("to");
    const from = fromParam ? parseInt(fromParam, 10) : undefined;
    const to = toParam ? parseInt(toParam, 10) : undefined;

    console.log("[API] /audit-sessions: from=" + from + ", to=" + to + ", cursor=" + cursor + ", hideHome=" + hideHome);
    const page = await getAuditSessions({
      search: search || null,
      targetPath: targetPath || null,
      hideHome,
      cursor: cursor || null,
      limit: Number.isNaN(limit) ? 25 : limit,
      includeSummary,
      from: from && !Number.isNaN(from) ? from : undefined,
      to: to && !Number.isNaN(to) ? to : undefined,
    });

    return Response.json(page, {
      headers: {
        "Cache-Control": "no-store",
      },
    });
  } catch (error) {
    console.error("[AUDIT SESSIONS API ERROR]", error);
    return Response.json({ error: "Failed to fetch audit sessions" }, { status: 500 });
  }
}
