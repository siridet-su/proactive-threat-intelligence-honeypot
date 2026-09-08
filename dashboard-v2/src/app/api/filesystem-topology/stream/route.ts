import { getSessionFromRequest } from "@/lib/auth/session";
import { getFilesystemTopology, subscribeFilesystemUpdates } from "@/lib/filesystem-server";

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
  let controllerRef: ReadableStreamDefaultController<Uint8Array> | null = null;
  let closed = false;
  const pending: Uint8Array[] = [];

  try {
    unsubscribe = await subscribeFilesystemUpdates(() => {
      void getFilesystemTopology().then((snapshot) => {
        const payload = formatEvent("topology.update", { type: "topology.update", data: snapshot });
        if (controllerRef && !closed) controllerRef.enqueue(payload);
        else pending.push(payload);
      }).catch(() => undefined);
    });
    const snapshot = await getFilesystemTopology();

    let close = () => undefined;
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controllerRef = controller;
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
          controllerRef = null;
          clearInterval(heartbeat);
          clearInterval(sessionCheck);
          unsubscribe?.();
          unsubscribe = null;
          try { controller.close(); } catch { /* client may have disconnected */ }
        };
        controller.enqueue(encoder.encode("retry: 5000\n\n"));
        controller.enqueue(formatEvent("snapshot", { type: "snapshot", data: snapshot }));
        for (const item of pending.splice(0)) controller.enqueue(item);
        request.signal.addEventListener("abort", close, { once: true });
      },
      cancel() { close(); },
    });

    return new Response(stream, {
      headers: {
        "Content-Type": "text/event-stream; charset=utf-8",
        "Cache-Control": "no-cache, no-transform",
        Connection: "keep-alive",
        "X-Accel-Buffering": "no",
      },
    });
  } catch (error) {
    unsubscribe?.();
    console.error("[FILESYSTEM TOPOLOGY STREAM ERROR]", error);
    return Response.json({ error: "Failed to establish filesystem stream" }, { status: 500 });
  }
}
