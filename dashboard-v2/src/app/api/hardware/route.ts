import { NextResponse } from "next/server";
import type { Db } from "mongodb";
import { getMongoClient } from "@/lib/mongodb";
import { getRecentHardwareMetrics } from "@/lib/hardware-mongo";
import { isHardwareTelemetry } from "@/lib/dashboardTypes";
import type { HardwareTelemetry } from "@/lib/dashboardTypes";
import { getSessionFromRequest } from "@/lib/auth/session";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

async function readRecentMongoMetrics(
  db: Db,
  collectionName: string,
): Promise<HardwareTelemetry[]> {
  const documents = await db
    .collection(collectionName)
    .find({})
    .sort({ timestamp: -1 })
    .limit(30)
    .toArray();
  return documents.filter(isHardwareTelemetry).reverse();
}

const DATABASE_NAME = 'honeypot_db';
const HARDWARE_LIVE_COLLECTION = 'hardware_live';
const HARDWARE_SAMPLE_LIMIT = 30;

export async function GET(request: Request) {
  const session = await getSessionFromRequest(request);
  if (!session || session.mustChangePassword) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  try {
    const client = await getMongoClient();
    const db = client.db(DATABASE_NAME);

    // hardware_live is the agent-maintained rolling window for the live monitor.
    const rawMetrics = await db
      .collection(HARDWARE_LIVE_COLLECTION)
      .find({})
      .sort({ timestamp: -1 })
      .limit(HARDWARE_SAMPLE_LIMIT)
      .toArray();

    // Transitional fallback while the first minute rollup is being created.
    const legacyMetrics = await readRecentMongoMetrics(db, "hardware_metrics");
    return NextResponse.json(legacyMetrics);
  } catch (error: unknown) {
    console.error("Failed to fetch hardware metrics:", error);
    const message = error instanceof Error ? error.message : "Failed to fetch metrics";
    return NextResponse.json({ error: message }, { status: 503 });
  }
}
