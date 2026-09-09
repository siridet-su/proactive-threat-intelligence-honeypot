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

export async function GET(req: Request) {
  const session = await getSessionFromRequest(req);
  if (!session || session.mustChangePassword) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  try {
    const initialMetrics = await getRecentHardwareMetrics(30);

    let cancelStream: (() => void) | undefined;
    let unsubscribe: (() => void) | undefined;
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        let closed = false;
        const timers: Record<string, ReturnType<typeof setInterval>> = {};

        const enqueue = (value: unknown) => {
          if (closed) return;
          try {
            controller.enqueue(ssePayload(value));
          } catch {
            closed = true;
          }
        };

        const shutdown = (closeController: boolean) => {
          if (closed) return;
          closed = true;
          if (timers.sessionCheck) clearInterval(timers.sessionCheck);
          if (timers.heartbeat) clearInterval(timers.heartbeat);
          unsubscribe?.();
          if (closeController) {
            try {
              controller.close();
            } catch {
              // The browser may already have canceled the stream.
            }
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
