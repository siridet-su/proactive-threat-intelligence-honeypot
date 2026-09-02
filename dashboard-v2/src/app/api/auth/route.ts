import { authCookie, authenticationConfigured, safeEqual, sessionValue } from "@/lib/dashboardAuth";

export const runtime = "nodejs";

export async function POST(request: Request) {
  if (!authenticationConfigured()) {
    return Response.json({ error: "dashboard authentication is not configured" }, { status: 503 });
  }

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return Response.json({ error: "invalid authentication request" }, { status: 400 });
  }
  const record = body && typeof body === "object" ? body as Record<string, unknown> : {};
  const operatorId = typeof record.operator_id === "string" ? record.operator_id : "";
  const accessKey = typeof record.access_key === "string" ? record.access_key : "";
  const expectedOperator = process.env.DASHBOARD_V2_OPERATOR_ID?.trim() || "";
  const expectedKey = process.env.DASHBOARD_V2_ACCESS_KEY || "";
  if (!safeEqual(operatorId, expectedOperator) || !safeEqual(accessKey, expectedKey)) {
    return Response.json({ error: "invalid operator credentials" }, { status: 401 });
  }

  const secret = process.env.DASHBOARD_V2_SESSION_SECRET || "";
  const token = sessionValue(expectedOperator, expectedKey, secret);
  return Response.json(
    { ok: true },
    { headers: { "set-cookie": authCookie(token, 8 * 60 * 60) } },
  );
}

export async function DELETE() {
  return Response.json(
    { ok: true },
    { headers: { "set-cookie": authCookie("", 0) } },
  );
}
