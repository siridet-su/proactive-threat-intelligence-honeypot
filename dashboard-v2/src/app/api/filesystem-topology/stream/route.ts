import { getSessionFromRequest } from "@/lib/auth/session";
import { getFilesystemTopology, subscribeFilesystemUpdates } from "@/lib/filesystem-server";
import type { FilesystemTopologySnapshot } from "@/lib/dashboardTypes";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

const encoder = new TextEncoder();
const SNAPSHOT_POLL_MS = 5_000;

function formatEvent(event: string, value: unknown): Uint8Array {
  return encoder.encode(`event: ${event}\ndata: ${JSON.stringify(value)}\n\n`);
}

// generatedAt changes on every read, even when the underlying telemetry has not.
function snapshotIdentity(snapshot: FilesystemTopologySnapshot): string {
  return JSON.stringify({
    nodes: snapshot.nodes,
    sessions: snapshot.sessions,
    recentClosedSessions: snapshot.recentClosedSessions,
    truncated: snapshot.truncated,
    latestTelemetryAt: snapshot.latestTelemetryAt,
  });
}

export async function GET(request: Request) {
  const initialSession = await getSessionFromRequest(request);
  if (!initialSession || initialSession.mustChangePassword) {
    return Response.json({ error: "Unauthorized" }, { status: 401 });
  }

  let closed = false;
  let unsubscribe: (() => void) | null = null;
  let heartbeat: ReturnType<typeof setInterval> | null = null;
  let sessionCheck: ReturnType<typeof setInterval> | null = null;
  let snapshotPoll: ReturnType<typeof setInterval> | null = null;
  let pollInFlight = false;
  let changeVersion = 0;
  let lastSnapshotIdentity: string | null = null;
  let subscriptionUnavailable = false;
  let controllerRef: ReadableStreamDefaultController<Uint8Array> | null = null;

  const close = () => {
    if (closed) return;
    closed = true;
    if (heartbeat) clearInterval(heartbeat);
    if (sessionCheck) clearInterval(sessionCheck);
    if (snapshotPoll) clearInterval(snapshotPoll);
    unsubscribe?.();
    unsubscribe = null;
    const controller = controllerRef;
    controllerRef = null;
    try { controller?.close(); } catch { /* client disconnected */ }
  };

  const publishSnapshot = async () => {
    if (closed || pollInFlight) return;
    pollInFlight = true;
    const startedAtChangeVersion = changeVersion;
    try {
      const snapshot = await getFilesystemTopology();
      if (closed || !controllerRef) return;
      // A Change Stream update can arrive while this read is in flight.
      // Never let an older read replace the newer observed transition.
      if (startedAtChangeVersion !== changeVersion) return;
      const identity = snapshotIdentity(snapshot);
      if (identity !== lastSnapshotIdentity) {
        lastSnapshotIdentity = identity;
        controllerRef.enqueue(formatEvent("snapshot", { type: "snapshot", data: snapshot }));
      }
    } catch {
      // Preserve the last verified snapshot. Polling retries without fabricating
      // empty topology data when MongoDB is temporarily unavailable.
    } finally {
      pollInFlight = false;
    }
  };

  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      controllerRef = controller;
      controller.enqueue(encoder.encode("retry: 5000\n\n"));
      heartbeat = setInterval(() => {
        if (!closed) controller.enqueue(formatEvent("heartbeat", { type: "heartbeat", data: { at: new Date().toISOString() } }));
      }, 20_000);
      sessionCheck = setInterval(() => {
        void getSessionFromRequest(request).then((session) => {
          if (!session || session.mustChangePassword) close();
        }).catch(close);
      }, 60_000);
      snapshotPoll = setInterval(() => { void publishSnapshot(); }, SNAPSHOT_POLL_MS);
      void publishSnapshot();

      // Change Stream is an acceleration path, not a prerequisite for headers
      // or the initial snapshot. Polling also covers a silent stream outage.
      void subscribeFilesystemUpdates({
        changed: (snapshot) => {
          if (closed) return;
          changeVersion++;
          lastSnapshotIdentity = snapshotIdentity(snapshot);
          controllerRef?.enqueue(formatEvent("topology.update", { type: "topology.update", data: snapshot }));
        },
        unavailable: () => {
          subscriptionUnavailable = true;
          unsubscribe?.();
          unsubscribe = null;
        },
      }).then((release) => {
        if (closed || subscriptionUnavailable) release();
        else unsubscribe = release;
      }).catch(() => {
        // The independent polling path continues serving verified snapshots.
      });
      request.signal.addEventListener("abort", close, { once: true });
    },
    cancel: close,
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
