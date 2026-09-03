import { NextResponse } from 'next/server';
import clientPromise from '@/lib/mongodb';
import { isHardwareTelemetry } from '@/lib/dashboardTypes';

export const dynamic = 'force-dynamic';

export async function GET() {
  try {
    const client = await clientPromise;
    // Assuming the database is "honeypot" and collection is "hardware_metrics" or "metrics"
    // Adjust db name and collection name based on what processor-agent inserts
    const db = client.db('honeypot_db');
    
    // Fetch the latest 30 hardware metrics (e.g. for a sparkline or live chart)
    const rawMetrics = await db
      .collection('hardware_metrics')
      .find({})
      .sort({ timestamp: -1 })
      .limit(30)
      .toArray();

    const metrics = rawMetrics.filter(isHardwareTelemetry);
    return NextResponse.json(metrics.reverse()); // Reverse so the oldest of the 30 is first
  } catch (error: unknown) {
    console.error('Failed to fetch hardware metrics:', error);
    const message = error instanceof Error ? error.message : 'Failed to fetch metrics';
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
