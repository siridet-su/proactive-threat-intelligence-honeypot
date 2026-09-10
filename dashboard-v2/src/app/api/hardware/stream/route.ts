import { NextResponse } from 'next/server';
import type { ChangeStreamDocument, Document } from 'mongodb';
import { getMongoClient } from '@/lib/mongodb';
import { isHardwareTelemetry } from '@/lib/dashboardTypes';
import { getSessionFromRequest } from "@/lib/auth/session";

export const dynamic = 'force-dynamic';

const DATABASE_NAME = 'honeypot_db';
const HARDWARE_LIVE_COLLECTION = 'hardware_live';
const HARDWARE_SAMPLE_LIMIT = 30;

export async function GET(req: Request) {
  const session = await getSessionFromRequest(req);
  if (!session || session.mustChangePassword) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }
  try {
    const client = await getMongoClient();
    const db = client.db(DATABASE_NAME);
    const collection = db.collection(HARDWARE_LIVE_COLLECTION);

    const stream = new ReadableStream<string>({
      async start(controller) {
        // 1. Send the rolling live window so the chart isn't empty.
        const initialData = (await collection
          .find({})
          .sort({ timestamp: -1 })
          .limit(HARDWARE_SAMPLE_LIMIT)
          .toArray()).filter(isHardwareTelemetry);

        // Reverse so the oldest of the 30 is first
        const reversed = initialData.reverse();
        controller.enqueue(`data: ${JSON.stringify({ type: 'initial', data: reversed })}\n\n`);

        // 2. The live buffer updates fixed slots, so inserts alone would miss most samples.
        const changeStream = collection.watch(
          [{ $match: { operationType: { $in: ['insert', 'replace', 'update'] } } }],
          { fullDocument: 'updateLookup' },
        );

        changeStream.on('change', (change: ChangeStreamDocument<Document>) => {
          if (
            (change.operationType === 'insert' || change.operationType === 'replace' || change.operationType === 'update')
            && isHardwareTelemetry(change.fullDocument)
          ) {
            controller.enqueue(`data: ${JSON.stringify({ type: 'update', data: change.fullDocument })}\n\n`);
          }
        });

        changeStream.on('error', (err) => {
          console.error("Change stream error:", err);
          controller.close();
        });

        const sessionCheck = setInterval(() => {
          void getSessionFromRequest(req).then((currentSession) => {
            if (!currentSession || currentSession.mustChangePassword) {
              void changeStream.close();
              controller.close();
            }
          }).catch(() => {
            void changeStream.close();
            controller.close();
          });
        }, 60_000);

        // 3. Clean up when the client disconnects (e.g., user closes browser tab)
        req.signal.addEventListener('abort', () => {
          clearInterval(sessionCheck);
          changeStream.close();
          controller.close();
        });
      }
    });

    return new Response(stream, {
      headers: {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache, no-transform',
        'Connection': 'keep-alive',
      },
    });
  } catch (error: unknown) {
    console.error('Failed to initialize SSE stream:', error);
    const message = error instanceof Error ? error.message : 'Failed to start stream';
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
