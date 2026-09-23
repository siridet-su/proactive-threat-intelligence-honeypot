import { NextResponse } from "next/server";

import { getSessionFromRequest } from "@/lib/auth/session";
import { getHardwareHistory } from "@/lib/hardware-history";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

const RANGE_HOURS: Record<string, number> = {
  "1h": 1,
  "6h": 6,
  "24h": 24,
  "7d": 24 * 7,
  "30d": 24 * 30,
};
const MAX_CUSTOM_RANGE_MS = 30 * 24 * 60 * 60 * 1_000;

export async function GET(request: Request) {
  const session = await getSessionFromRequest(request);
  if (!session || session.mustChangePassword) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const url = new URL(request.url);
  const fromParam = url.searchParams.get("from");
  const toParam = url.searchParams.get("to");
  const range = url.searchParams.get("range") ?? (fromParam || toParam ? "custom" : "24h");

  const sensorID = url.searchParams.get("sensor_id")?.trim() || undefined;
  if (sensorID && sensorID.length > 128) {
    return NextResponse.json({ error: "sensor_id is too long" }, { status: 400 });
  }

  let from: Date;
  let to: Date;
  if (range === "custom") {
    if (!fromParam || !toParam) {
      return NextResponse.json({ error: "Custom history requires from and to" }, { status: 400 });
    }
    from = new Date(fromParam);
    to = new Date(toParam);
    if (!Number.isFinite(from.getTime()) || !Number.isFinite(to.getTime())) {
      return NextResponse.json({ error: "Invalid custom history dates" }, { status: 400 });
    }
    if (to.getTime() <= from.getTime()) {
      return NextResponse.json({ error: "History end must be after start" }, { status: 400 });
    }
    if (to.getTime() - from.getTime() > MAX_CUSTOM_RANGE_MS) {
      return NextResponse.json({ error: "Custom history range is limited to 30 days" }, { status: 400 });
    }
    if (to.getTime() > Date.now()) {
      return NextResponse.json({ error: "History end cannot be in the future" }, { status: 400 });
    }
  } else {
    const hours = RANGE_HOURS[range];
    if (!hours) {
      return NextResponse.json({ error: "Unsupported hardware history range" }, { status: 400 });
    }
    to = new Date();
    from = new Date(to.getTime() - hours * 60 * 60 * 1_000);
  }

  try {
    return NextResponse.json(await getHardwareHistory(from, to, sensorID), {
      headers: { "Cache-Control": "no-store" },
    });
  } catch (error: unknown) {
    console.error("Failed to fetch hardware history:", error);
    const message = error instanceof Error ? error.message : "Failed to fetch hardware history";
    return NextResponse.json({ error: message }, { status: 503 });
  }
}
