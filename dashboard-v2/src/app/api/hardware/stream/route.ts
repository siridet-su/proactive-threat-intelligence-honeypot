import { NextResponse } from "next/server";
import { getSessionFromRequest } from "@/lib/auth/session";
import {
  getRecentHardwareMetrics,
  subscribeToHardwareMetrics,
} from "@/lib/hardware-mongo";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

const encoder = new TextEncoder();
const HEARTBEAT_MS = 15_000;
const SESSION_RECHECK_MS = 60_000;

function ssePayload(value: unknown): Uint8Array {
  return encoder.encode(`data: ${JSON.stringify(value)}\n\n`);
}

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

    let cancelStream: (() => void) | undefined;
    let unsubscribe: (() => void) | undefined;
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        let closed = false;
        const timers: Record<string, ReturnType<typeof setInterval>> = {};

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
        };
        cancelStream = () => shutdown(false);

        enqueue({
          type: "initial",
          data: initialMetrics,
        });

        timers.sessionCheck = setInterval(() => {
          void getSessionFromRequest(req).then((currentSession) => {
            if (!currentSession || currentSession.mustChangePassword) {
              shutdown(true);
            }
          }).catch(() => shutdown(true));
        }, SESSION_RECHECK_MS);

        req.signal.addEventListener("abort", () => shutdown(false), { once: true });

        timers.heartbeat = setInterval(() => {
          if (!closed) {
            controller.enqueue(encoder.encode(`: heartbeat ${Date.now()}\n\n`));
          }
        }, HEARTBEAT_MS);
        unsubscribe = subscribeToHardwareMetrics((metric) => {
          enqueue({ type: "update", data: metric });
        });
      },
      cancel() {
        cancelStream?.();
      },
    });

    return new Response(stream, {
      headers: {
        "Content-Type": "text/event-stream; charset=utf-8",
        "Cache-Control": "no-cache, no-transform",
        "Connection": "keep-alive",
        "X-Accel-Buffering": "no",
        "X-Content-Type-Options": "nosniff",
      },
    });
  } catch (error: unknown) {
    console.error("Failed to initialize hardware MongoDB stream:", error);
    const message = error instanceof Error ? error.message : "Failed to start stream";
    return NextResponse.json({ error: message }, { status: 503 });
  }
}
