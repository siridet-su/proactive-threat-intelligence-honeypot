import { NextResponse } from 'next/server';
import { getMongoClient } from '@/lib/mongodb';
import { isHardwareTelemetry } from '@/lib/dashboardTypes';
import { getSessionFromRequest } from "@/lib/auth/session";

export const dynamic = 'force-dynamic';

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

    const metrics = rawMetrics.filter(isHardwareTelemetry);
    return NextResponse.json(metrics.reverse()); // Reverse so the oldest of the 30 is first
  } catch (error: unknown) {
    console.error('Failed to fetch hardware metrics:', error);
    const message = error instanceof Error ? error.message : 'Failed to fetch metrics';
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
