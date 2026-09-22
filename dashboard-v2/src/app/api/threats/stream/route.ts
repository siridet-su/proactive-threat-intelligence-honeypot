import { getThreatSnapshot, subscribeThreatUpdates } from "@/lib/threat-server";
import { getSessionFromRequest } from "@/lib/auth/session";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

const encoder = new TextEncoder();
const SNAPSHOT_POLL_MS = 5_000;

function formatEvent(event: string, value: unknown): Uint8Array {
  return encoder.encode(`event: ${event}\ndata: ${JSON.stringify(value)}\n\n`);
}

export async function GET(request: Request) {
  const initialSession = await getSessionFromRequest(request);
  if (!initialSession || initialSession.mustChangePassword) {
    return Response.json({ error: "Unauthorized" }, { status: 401 });
  }
  let unsubscribe: (() => void) | null = null;
  const pending: Uint8Array[] = [];
  let streamController: ReadableStreamDefaultController<Uint8Array> | null = null;
  let streamClosed = false;

  // Start the read without awaiting it.  This lets the response headers and
  // retry instruction reach EventSource even when MongoDB is slow.  A later
  // snapshot (or an empty bounded fallback) is emitted through the stream.
  const initialSnapshot = getThreatSnapshot().catch(() => []);

  unsubscribe = subscribeThreatUpdates((update) => {
    const payload = formatEvent(update.type, update);
    if (streamController && !streamClosed) {
      streamController.enqueue(payload);
    } else {
      pending.push(payload);
    }
  });

  let close = () => undefined;
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      let closed = false;
      let snapshotPublished = false;
      let pollInFlight = false;
      let lastSnapshot = "";
      streamController = controller;

      const heartbeat = setInterval(() => {
        if (!closed) controller.enqueue(formatEvent("heartbeat", { type: "heartbeat", data: { at: new Date().toISOString() } }));
      }, 20_000);
      const snapshotPoll = setInterval(() => {
        if (closed || pollInFlight) return;
        pollInFlight = true;
        void getThreatSnapshot()
          .then((snapshot) => {
            if (closed) return;
            const serialized = JSON.stringify(snapshot);
            if (!snapshotPublished || serialized === lastSnapshot) return;
            lastSnapshot = serialized;
            controller.enqueue(formatEvent("snapshot", { type: "snapshot", data: snapshot }));
          })
          .catch(() => undefined)
          .finally(() => {
            pollInFlight = false;
          });
      }, SNAPSHOT_POLL_MS);
      const sessionCheck = setInterval(() => {
        void getSessionFromRequest(request).then((session) => {
          if (!session || session.mustChangePassword) close();
        }).catch(() => close());
      }, 60_000);

      close = () => {
        if (closed) return;
        closed = true;
        streamClosed = true;
        streamController = null;
        clearInterval(heartbeat);
        clearInterval(snapshotPoll);
        clearInterval(sessionCheck);
        unsubscribe?.();
        unsubscribe = null;
        try {
          controller.close();
        } catch {
          // The client may already have cancelled the stream.
        }
      };

      controller.enqueue(encoder.encode("retry: 5000\n\n"));
      void initialSnapshot.then((snapshot) => {
        if (closed || snapshotPublished) return;
        snapshotPublished = true;
        lastSnapshot = JSON.stringify(snapshot);
        controller.enqueue(formatEvent("snapshot", { type: "snapshot", data: snapshot }));
        for (const update of pending.splice(0)) controller.enqueue(update);
      });
      request.signal.addEventListener("abort", close, { once: true });
    },
    cancel() {
      close();
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream; charset=utf-8",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
      "X-Accel-Buffering": "no",
    },
  });
}
