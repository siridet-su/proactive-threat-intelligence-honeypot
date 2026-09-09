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

export async function GET(request: Request) {
  const session = await getSessionFromRequest(request);
  if (!session || session.mustChangePassword) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  try {
    const liveMetrics = await getRecentHardwareMetrics(30);
    if (liveMetrics.length > 0) {
      return NextResponse.json(liveMetrics);
    }
  } catch (error) {
    console.warn("Hardware live snapshot unavailable; using MongoDB rollup:", error);
  }

  try {
    const client = await getMongoClient();
    const db = client.db("honeypot_db");
    const rollups = await readRecentMongoMetrics(db, "hardware_metrics_1m");
    if (rollups.length > 0) {
      return NextResponse.json(rollups);
    }

    // Transitional fallback while the first minute rollup is being created.
    const legacyMetrics = await readRecentMongoMetrics(db, "hardware_metrics");
    return NextResponse.json(legacyMetrics);
  } catch (error: unknown) {
    console.error("Failed to fetch hardware metrics:", error);
    const message = error instanceof Error ? error.message : "Failed to fetch metrics";
    return NextResponse.json({ error: message }, { status: 503 });
  }
}
