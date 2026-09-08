import { getSessionFromRequest } from "@/lib/auth/session";
import { getThreatDirectoryExport, MAX_DIRECTORY_EXPORT } from "@/lib/threat-server";
import type { ThreatSeverityFilter } from "@/lib/dashboardTypes";

export const dynamic = "force-dynamic";

function escapeCsv(value: string) {
  const safeValue = /^[=+\-@]/.test(value) ? `'${value}` : value;
  return `"${safeValue.replace(/"/g, '""')}"`;
}

export async function GET(request: Request) {
  const session = await getSessionFromRequest(request);
  if (!session || session.mustChangePassword) {
    return Response.json({ error: "Unauthorized" }, { status: 401 });
  }

  try {
    const { searchParams } = new URL(request.url);
    const result = await getThreatDirectoryExport({
      query: searchParams.get("query") ?? "",
      severity: searchParams.get("severity") as ThreatSeverityFilter | null ?? undefined,
    });
    const rows = [
      ["Session ID", "Origin IP", "Attacker Type", "Severity", "Date & Time", "Session status"],
      ...result.items.map((session) => [
        session.id,
        session.sourceIp,
        session.classification,
        session.severity,
        `${session.date} ${session.time}`,
        session.duration,
      ]),
    ];
    const filename = `pti-incursion-directory-${new Date().toISOString().slice(0, 10)}.csv`;

    return new Response(rows.map((row) => row.map(escapeCsv).join(",")).join("\n"), {
      headers: {
        "Content-Type": "text/csv; charset=utf-8",
        "Content-Disposition": `attachment; filename="${filename}"`,
        "Cache-Control": "private, no-store",
        "X-PTI-Export-Count": String(result.items.length),
        "X-PTI-Export-Total": String(result.total),
        "X-PTI-Export-Truncated": String(result.truncated),
        "X-PTI-Export-Limit": String(MAX_DIRECTORY_EXPORT),
      },
    });
  } catch (error: unknown) {
    console.error("[THREAT DIRECTORY EXPORT ERROR]", error);
    return Response.json({ error: "Threat directory export unavailable" }, { status: 500 });
  }
}
