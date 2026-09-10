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

export async function GET(request: Request) {
  const session = await getSessionFromRequest(request);
  if (!session || session.mustChangePassword) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  let shutdown: (() => void) | undefined;

  const stream = new ReadableStream<Uint8Array>({
    async start(controller) {
      let closed = false;
      const resources: {
        unsubscribe?: () => void;
        heartbeat?: ReturnType<typeof setInterval>;
        sessionCheck?: ReturnType<typeof setInterval>;
      } = {};

      const close = () => {
        if (closed) return;
        closed = true;
        if (resources.heartbeat) clearInterval(resources.heartbeat);
        if (resources.sessionCheck) clearInterval(resources.sessionCheck);
        resources.unsubscribe?.();
        controller.close();
      };

      const enqueue = (value: unknown) => {
        if (!closed) controller.enqueue(ssePayload(value));
      };

      shutdown = close;

      try {
        enqueue({ type: "initial", data: await getRecentHardwareMetrics() });
      } catch (error) {
        console.error("Failed to read initial hardware metrics:", error);
        close();
        return;
      }

      resources.unsubscribe = subscribeToHardwareMetrics((metric) => {
        enqueue({ type: "update", data: metric });
      });

      resources.heartbeat = setInterval(() => {
        if (!closed) controller.enqueue(encoder.encode(`: heartbeat ${Date.now()}\n\n`));
      }, HEARTBEAT_MS);

      resources.sessionCheck = setInterval(() => {
        void getSessionFromRequest(request)
          .then((currentSession) => {
            if (!currentSession || currentSession.mustChangePassword) close();
          })
          .catch(close);
      }, SESSION_RECHECK_MS);

      request.signal.addEventListener("abort", close, { once: true });
    },
    cancel() {
      shutdown?.();
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream; charset=utf-8",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
      "X-Accel-Buffering": "no",
      "X-Content-Type-Options": "nosniff",
    },
  });
}
