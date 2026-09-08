import { getThreatSnapshot, subscribeThreatUpdates } from "@/lib/threat-server";
import { getSessionFromRequest } from "@/lib/auth/session";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

const encoder = new TextEncoder();

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

  try {
    // Subscribe first, then obtain the snapshot. Updates in that small window are
    // queued and sent after the snapshot, so a newly connected client cannot miss one.
    unsubscribe = await subscribeThreatUpdates((update) => {
      const payload = formatEvent(update.type, update);
      if (streamController && !streamClosed) {
        streamController.enqueue(payload);
      } else {
        pending.push(payload);
      }
    });
    const snapshot = await getThreatSnapshot();

    let close = () => undefined;
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        let closed = false;
        streamController = controller;
        const heartbeat = setInterval(() => {
          if (!closed) controller.enqueue(formatEvent("heartbeat", { type: "heartbeat", data: { at: new Date().toISOString() } }));
        }, 20_000);
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
        controller.enqueue(formatEvent("snapshot", { type: "snapshot", data: snapshot }));
        for (const update of pending.splice(0)) controller.enqueue(update);
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
  } catch (error: unknown) {
    unsubscribe?.();
    const message = error instanceof Error ? error.message : "Failed to establish live feed";
    return Response.json({ error: message }, { status: 500 });
  }
}
