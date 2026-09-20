import { getSessionFromRequest } from "@/lib/auth/session";
import { getAuditDirectorySummary } from "@/lib/filesystem-server";

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

    const fromParam = url.searchParams.get("from");
    const toParam = url.searchParams.get("to");
    const from = fromParam ? parseInt(fromParam, 10) : undefined;
    const to = toParam ? parseInt(toParam, 10) : undefined;

    const summary = await getAuditDirectorySummary({
      search: search || null,
      targetPath: targetPath || null,
      hideHome,
      from: from && !Number.isNaN(from) ? from : undefined,
      to: to && !Number.isNaN(to) ? to : undefined,
    });

    return Response.json(summary, {
      headers: {
        "Cache-Control": "no-store",
      },
    });
  } catch (error) {
    console.error("[AUDIT SUMMARY API ERROR]", error);
    return Response.json({ error: "Failed to fetch audit summary" }, { status: 500 });
  }
}
