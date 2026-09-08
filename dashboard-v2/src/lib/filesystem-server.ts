import "server-only";

import type { ChangeStream, Document } from "mongodb";

import type {
  CwdObservationStatus,
  FilesystemTopologyNode,
  FilesystemTopologySession,
  FilesystemTopologySnapshot,
  SessionCwdHistoryEvent,
  SessionCwdHistoryPage,
  SessionCwdState,
} from "@/lib/dashboardTypes";
import { getMongoClient } from "@/lib/mongodb";

// CWD is operational Cowrie telemetry. It intentionally remains outside the
// still-evolving canonical projection so it can be migrated later as one unit.
const DATABASE_NAME = "honeypot_db";
const SESSIONS_COLLECTION = "cwd_session_state";
const HISTORY_COLLECTION = "cwd_events";
const TOPOLOGY_LIMIT = 500;
const HISTORY_PAGE_SIZE = 80;
const STREAM_RETRY_MS = 5_000;

type TopologySubscriber = () => void;

interface FilesystemRuntime {
  subscribers: Set<TopologySubscriber>;
  stream: ChangeStream<Document> | null;
  opening: Promise<void> | null;
  reconnectTimer: ReturnType<typeof setTimeout> | null;
}

const globalScope = globalThis as typeof globalThis & { __ptiFilesystemRuntime?: FilesystemRuntime };
const runtime: FilesystemRuntime = globalScope.__ptiFilesystemRuntime ?? {
  subscribers: new Set(),
  stream: null,
  opening: null,
  reconnectTimer: null,
};

globalScope.__ptiFilesystemRuntime = runtime;

function asString(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value : null;
}

function asStatus(value: unknown): CwdObservationStatus {
  return value === "observed" || value === "confirmed" || value === "conditional_candidate" || value === "unknown"
    ? value
    : "unknown";
}

function asDateString(value: unknown): string | null {
  if (typeof value !== "string" && !(value instanceof Date)) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

function normalizeCwdState(value: unknown): SessionCwdState | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const record = value as Record<string, unknown>;
  const path = asString(record.path);
  if (!path) return null;
  return {
    path,
    status: asStatus(record.status),
    observedAt: asDateString(record.observedAt),
    sourceEventId: asString(record.sourceEventId),
  };
}

function parentPath(path: string): string | null {
  if (path === "/") return null;
  const segments = path.split("/").filter(Boolean);
  segments.pop();
  return segments.length ? `/${segments.join("/")}` : "/";
}

function pathAncestors(path: string): string[] {
  const segments = path.split("/").filter(Boolean);
  const paths = ["/"];
  let current = "";
  for (const segment of segments) {
    current += `/${segment}`;
    paths.push(current);
  }
  return paths;
}

function toTopologySession(document: Document): FilesystemTopologySession | null {
  const sessionId = asString(document.sessionId);
  const cwdState = normalizeCwdState(document.cwdState);
  if (!sessionId || !cwdState) return null;
  return {
    sessionId,
    sourceIp: asString(document.sourceIp) ?? "Unknown",
    cwdState,
  };
}

/**
 * Materializes only observed paths and their ancestors. It deliberately does not
 * invent a Linux filesystem or infer a path where Cowrie has not emitted one.
 */
export async function getFilesystemTopology(): Promise<FilesystemTopologySnapshot> {
  const client = await getMongoClient();
  const documents = await client.db(DATABASE_NAME).collection<Document>(SESSIONS_COLLECTION)
    .find({ "cwdState.path": { $type: "string", $ne: "" } })
    .sort({ "cwdState.observedAt": -1, start_time: -1 })
    .limit(TOPOLOGY_LIMIT)
    .allowDiskUse(true)
    .toArray();

  const sessions = documents.map(toTopologySession).filter((item): item is FilesystemTopologySession => item !== null);
  const nodes = new Map<string, FilesystemTopologyNode>();

  for (const session of sessions) {
    for (const path of pathAncestors(session.cwdState.path ?? "/")) {
      const existing = nodes.get(path);
      const shouldUpdateTime = !existing?.observedAt || (session.cwdState.observedAt !== null && session.cwdState.observedAt > existing.observedAt);
      if (existing) {
        if (!existing.sessionIds.includes(session.sessionId)) existing.sessionIds.push(session.sessionId);
        if (shouldUpdateTime) existing.observedAt = session.cwdState.observedAt;
        continue;
      }
      nodes.set(path, {
        path,
        parentPath: parentPath(path),
        depth: path === "/" ? 0 : path.split("/").filter(Boolean).length,
        sessionIds: [session.sessionId],
        observedAt: session.cwdState.observedAt,
      });
    }
  }

  return {
    nodes: [...nodes.values()].sort((left, right) => left.path.localeCompare(right.path)),
    sessions,
    generatedAt: new Date().toISOString(),
  };
}

function decodeCursor(cursor: string | null): { at: string; id: string } | null {
  if (!cursor) return null;
  try {
    const decoded = JSON.parse(Buffer.from(cursor, "base64url").toString("utf8")) as { at?: unknown; id?: unknown };
    if (typeof decoded.at !== "string" || typeof decoded.id !== "string") return null;
    return { at: decoded.at, id: decoded.id };
  } catch {
    return null;
  }
}

function encodeCursor(event: SessionCwdHistoryEvent): string {
  return Buffer.from(JSON.stringify({ at: event.at, id: event.id })).toString("base64url");
}

function normalizeHistoryEvent(document: Document): SessionCwdHistoryEvent | null {
  const sessionId = asString(document.sessionId) ?? asString(document.session_id);
  const at = asDateString(document.at) ?? asDateString(document.timestamp);
  const id = asString(document.eventId) ?? asString(document._id?.toString());
  const action = document.action;
  if (!sessionId || !at || !id || (action !== "entered" && action !== "changed" && action !== "failed_change")) return null;
  const sequence = typeof document.sequence === "number" && Number.isFinite(document.sequence) ? document.sequence : null;
  return {
    id,
    sessionId,
    sequence,
    at,
    fromPath: asString(document.fromPath),
    toPath: asString(document.toPath),
    action,
    status: asStatus(document.status),
    sourceEventId: asString(document.sourceEventId),
  };
}

export async function getSessionCwdHistory(sessionId: string, cursor: string | null): Promise<SessionCwdHistoryPage> {
  const sanitizedSessionId = sessionId.trim().slice(0, 300);
  if (!sanitizedSessionId) return { items: [], nextCursor: null };
  const decodedCursor = decodeCursor(cursor);
  const query: Document = { $or: [{ sessionId: sanitizedSessionId }, { session_id: sanitizedSessionId }] };
  if (decodedCursor) {
    // The CWD writer stores observed timestamps. Keep the cursor on the indexed
    // timestamp rather than comparing serialized ObjectIds on the API.
    const cursorAt = new Date(decodedCursor.at);
    if (!Number.isNaN(cursorAt.getTime())) query.$and = [{ at: { $lt: cursorAt } }];
  }

  const client = await getMongoClient();
  const documents = await client.db(DATABASE_NAME).collection<Document>(HISTORY_COLLECTION)
    .find(query)
    .sort({ at: -1, _id: -1 })
    .limit(HISTORY_PAGE_SIZE + 1)
    .allowDiskUse(true)
    .toArray();
  const events = documents.map(normalizeHistoryEvent).filter((item): item is SessionCwdHistoryEvent => item !== null);
  const hasMore = events.length > HISTORY_PAGE_SIZE;
  const items = events.slice(0, HISTORY_PAGE_SIZE);
  return { items, nextCursor: hasMore && items.length ? encodeCursor(items.at(-1)!) : null };
}

function broadcast() {
  for (const subscriber of runtime.subscribers) subscriber();
}

function scheduleReconnect() {
  if (!runtime.subscribers.size || runtime.reconnectTimer) return;
  runtime.reconnectTimer = setTimeout(() => {
    runtime.reconnectTimer = null;
    void ensureFilesystemChangeStream();
  }, STREAM_RETRY_MS);
}

function detachStream(stream: ChangeStream<Document>) {
  if (runtime.stream !== stream) return;
  runtime.stream = null;
  void stream.close().catch(() => undefined);
  scheduleReconnect();
}

async function ensureFilesystemChangeStream(): Promise<void> {
  if (!runtime.subscribers.size || runtime.stream) return;
  if (runtime.opening) return runtime.opening;
  runtime.opening = (async () => {
    const client = await getMongoClient();
    if (!runtime.subscribers.size || runtime.stream) return;
    const stream = client.db(DATABASE_NAME).collection<Document>(SESSIONS_COLLECTION).watch(
      [{ $match: { operationType: { $in: ["insert", "replace", "update"] } } }],
      { fullDocument: "updateLookup" },
    );
    runtime.stream = stream;
    stream.on("change", (change) => {
      if (!("fullDocument" in change) || !change.fullDocument || !normalizeCwdState(change.fullDocument.cwdState)) return;
      broadcast();
    });
    stream.on("error", () => detachStream(stream));
    stream.on("close", () => detachStream(stream));
  })();
  try {
    await runtime.opening;
  } finally {
    runtime.opening = null;
  }
}

export async function subscribeFilesystemUpdates(subscriber: TopologySubscriber): Promise<() => void> {
  runtime.subscribers.add(subscriber);
  try {
    await ensureFilesystemChangeStream();
  } catch (error) {
    runtime.subscribers.delete(subscriber);
    throw error;
  }
  return () => {
    runtime.subscribers.delete(subscriber);
    if (runtime.subscribers.size) return;
    if (runtime.reconnectTimer) clearTimeout(runtime.reconnectTimer);
    runtime.reconnectTimer = null;
    const stream = runtime.stream;
    runtime.stream = null;
    if (stream) void stream.close().catch(() => undefined);
  };
}
