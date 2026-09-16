import "server-only";

import type { ChangeStream, Document } from "mongodb";

import type {
  AuditDirectorySummary,
  AuditSessionsPage,
  FilesystemClosedSession,
  FilesystemTopologyNode,
  FilesystemTopologySession,
  FilesystemTopologySnapshot,
  SessionCwdHistoryEvent,
  SessionCwdHistoryPage,
  SessionCwdState,
} from "@/lib/dashboardTypes";
import {
  asDateString,
  asStatus,
  asString,
  buildAuditSessionsPipeline,
  buildAuditSummaryPipeline,
  buildSessionCwdHistoryQuery,
  encodeAuditSessionCursor,
  encodeHistoryCursor,
  normalizeHistoryEvent,
  normalizeSessionAuditSummary,
} from "@/lib/filesystem-data";
import { getMongoClient } from "@/lib/mongodb";

// CWD is operational Cowrie telemetry. It intentionally remains outside the
// still-evolving canonical projection so it can be migrated later as one unit.
const DATABASE_NAME = "honeypot_db";
const SESSIONS_COLLECTION = "cwd_session_state";
const HISTORY_COLLECTION = "cwd_events";
const TOPOLOGY_LIMIT = 500;
// Live topology SSE broadcast maintains only a small immediate transition buffer
// of recently closed sessions; the complete searchable/paginated closed directory
// is accessed via the dedicated audit sessions API.
const RECENT_CLOSED_BUFFER_LIMIT = 12;
const HISTORY_PAGE_SIZE = 80;
const TOPOLOGY_BROADCAST_DEBOUNCE_MS = 250;

// Closed session audit paths are immutable once closed; cached in-memory
// to avoid querying and aggregating cwd_events on high-frequency live CWD ticks.
const closedAuditPathsCache = new Map<string, AggregatedAuditPaths>();
interface TopologySubscriber {
  changed: (snapshot: FilesystemTopologySnapshot) => void;
  unavailable: () => void;
}

interface FilesystemRuntime {
  subscribers: Set<TopologySubscriber>;
  stream: ChangeStream<Document> | null;
  opening: Promise<void> | null;
  snapshotRequest: Promise<FilesystemTopologySnapshot> | null;
  pendingBroadcast: ReturnType<typeof setTimeout> | null;
  broadcastInFlight: Promise<void> | null;
  topologyDirty: boolean;
}

const globalScope = globalThis as typeof globalThis & { __ptiFilesystemRuntime?: FilesystemRuntime };
const runtime: FilesystemRuntime = globalScope.__ptiFilesystemRuntime ?? {
  subscribers: new Set(),
  stream: null,
  opening: null,
  snapshotRequest: null,
  pendingBroadcast: null,
  broadcastInFlight: null,
  topologyDirty: false,
};

globalScope.__ptiFilesystemRuntime = runtime;

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

interface AggregatedAuditPaths extends Document {
  _id: string;
  fromPaths: unknown[];
  toPaths: unknown[];
  eventCount: number;
}

function toTopologySession(document: Document, auditPaths?: AggregatedAuditPaths): FilesystemTopologySession | null {
  const sessionId = asString(document.sessionId) ?? asString(document.session_id) ?? asString(document.effectiveSessionId);
  const cwdState = normalizeCwdState(document.cwdState);
  if (!sessionId || !cwdState) return null;
  return {
    sessionId,
    sourceIp: asString(document.sourceIp) ?? "Unknown",
    cwdState,
    auditSummary: normalizeSessionAuditSummary(
      cwdState.path,
      auditPaths?.fromPaths,
      auditPaths?.toPaths,
      auditPaths?.eventCount,
    ),
  };
}

function toClosedSession(document: Document, auditPaths?: AggregatedAuditPaths): FilesystemClosedSession | null {
  const session = toTopologySession(document, auditPaths);
  const lifecycle = document.lifecycle;
  if (!session || !lifecycle || typeof lifecycle !== "object" || Array.isArray(lifecycle)) return null;
  const lifecycleRecord = lifecycle as Record<string, unknown>;
  return {
    ...session,
    lifecycle: {
      startedAt: asDateString(lifecycleRecord.startedAt),
      closedAt: asDateString(lifecycleRecord.closedAt),
    },
  };
}

async function aggregateSessionAuditPaths(sessionIds: string[]): Promise<Map<string, AggregatedAuditPaths>> {
  if (!sessionIds.length) return new Map();
  const client = await getMongoClient();
  const rows = await client.db(DATABASE_NAME).collection<Document>(HISTORY_COLLECTION).aggregate<AggregatedAuditPaths>([
    {
      $match: {
        action: { $in: ["entered", "changed", "failed_change"] },
        $or: [
          { sessionId: { $in: sessionIds } },
          { session_id: { $in: sessionIds } },
        ],
      },
    },
    {
      $project: {
        effectiveSessionId: { $ifNull: ["$sessionId", "$session_id"] },
        fromPath: 1,
        successfulToPath: {
          $cond: [{ $eq: ["$action", "failed_change"] }, null, "$toPath"],
        },
      },
    },
    {
      $group: {
        _id: "$effectiveSessionId",
        fromPaths: { $addToSet: "$fromPath" },
        toPaths: { $addToSet: "$successfulToPath" },
        eventCount: { $sum: 1 },
      },
    },
  ]).toArray();
  return new Map(rows.map((row) => [row._id, row]));
}

/**
 * Materializes only observed paths and their ancestors. It deliberately does not
 * invent a Linux filesystem or infer a path where Cowrie has not emitted one.
 */
async function buildFilesystemTopology(): Promise<FilesystemTopologySnapshot> {
  const client = await getMongoClient();
  const states = client.db(DATABASE_NAME).collection<Document>(SESSIONS_COLLECTION);
  const [documents, closedDocuments] = await Promise.all([
    states
    // A missing lifecycle field is legacy state, not evidence that a session is
    // still live. Only the processor's explicit active projection belongs in
    // the real-time map.
    .find({ "lifecycle.status": "active", "cwdState.path": { $type: "string", $ne: "" } })
    .sort({ updatedAt: -1, sessionId: -1 })
    // Read one additional record so a bounded live view never silently claims
    // to represent every active session.
    .limit(TOPOLOGY_LIMIT + 1)
    .allowDiskUse(true)
    .toArray(),
    // Closed sessions are intentionally outside the live topology, but a
    // small immediate buffer remains in the live snapshot for graceful transition.
    states
      .find({ "lifecycle.status": "closed", "cwdState.path": { $type: "string", $ne: "" } })
      .sort({ "lifecycle.closedAt": -1, sessionId: -1 })
      .limit(RECENT_CLOSED_BUFFER_LIMIT)
      .allowDiskUse(true)
      .toArray(),
  ]);

  const truncated = documents.length > TOPOLOGY_LIMIT;
  const liveDocuments = documents.slice(0, TOPOLOGY_LIMIT);
  const liveSessionIds = liveDocuments
    .map((document) => asString(document.sessionId) ?? asString(document.session_id))
    .filter((sessionId): sessionId is string => sessionId !== null);
  const closedSessionIds = closedDocuments
    .map((document) => asString(document.sessionId) ?? asString(document.session_id))
    .filter((sessionId): sessionId is string => sessionId !== null);

  // Closed sessions are immutable; read cached audit summaries and only aggregate
  // active sessions and uncached recent closed sessions.
  const uncachedClosedIds = closedSessionIds.filter((id) => !closedAuditPathsCache.has(id));
  const neededIds = [...liveSessionIds, ...uncachedClosedIds];
  const fetchedAuditPaths = await aggregateSessionAuditPaths(neededIds);

  for (const id of uncachedClosedIds) {
    const row = fetchedAuditPaths.get(id);
    if (row) closedAuditPathsCache.set(id, row);
  }

  const getAuditPaths = (id: string) => fetchedAuditPaths.get(id) ?? closedAuditPathsCache.get(id);

  const sessions = liveDocuments
    .map((document) => toTopologySession(document, getAuditPaths(asString(document.sessionId) ?? asString(document.session_id) ?? "")))
    .filter((item): item is FilesystemTopologySession => item !== null);
  const recentClosedSessions = closedDocuments
    .map((document) => toClosedSession(document, getAuditPaths(asString(document.sessionId) ?? asString(document.session_id) ?? "")))
    .filter((item): item is FilesystemClosedSession => item !== null);
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
    recentClosedSessions,
    truncated,
    generatedAt: new Date().toISOString(),
  };
}

/**
 * Coalesces simultaneous REST, SSE-initialization, and change-stream refreshes
 * into one MongoDB read per Node.js process. The result remains no-store at the
 * HTTP boundary; this is only an in-flight request dedupe.
 */
export async function getFilesystemTopology(): Promise<FilesystemTopologySnapshot> {
  if (!runtime.snapshotRequest) {
    runtime.snapshotRequest = buildFilesystemTopology().finally(() => {
      runtime.snapshotRequest = null;
    });
  }
  return runtime.snapshotRequest;
}

export async function getSessionCwdHistory(sessionId: string, cursor: string | null): Promise<SessionCwdHistoryPage> {
  const sanitizedSessionId = sessionId.trim().slice(0, 300);
  if (!sanitizedSessionId) {
    return { items: [], nextCursor: null, totalItems: 0, totalSuccessfulItems: 0, complete: true };
  }
  const query = buildSessionCwdHistoryQuery(sanitizedSessionId, cursor);
  const sessionQuery = buildSessionCwdHistoryQuery(sanitizedSessionId, null);

  const client = await getMongoClient();
  const collection = client.db(DATABASE_NAME).collection<Document>(HISTORY_COLLECTION);
  const [documents, totalItems, totalSuccessfulItems] = await Promise.all([
    collection
      .find(query)
      .sort({ at: -1, eventId: -1 })
      .limit(HISTORY_PAGE_SIZE + 1)
      .allowDiskUse(true)
      .toArray(),
    collection.countDocuments(sessionQuery),
    collection.countDocuments({ $and: [sessionQuery, { action: { $ne: "failed_change" } }] }),
  ]);
  const events = documents.map(normalizeHistoryEvent).filter((item): item is SessionCwdHistoryEvent => item !== null);
  const hasMore = events.length > HISTORY_PAGE_SIZE;
  const items = events.slice(0, HISTORY_PAGE_SIZE);
  return {
    items,
    nextCursor: hasMore && items.length ? encodeHistoryCursor(items.at(-1)!) : null,
    totalItems,
    totalSuccessfulItems,
    complete: !hasMore,
  };
}

export interface SessionCwdHopResolution {
  item: SessionCwdHistoryEvent | null;
  hopNumber?: number;
  successfulHopNumber?: number;
  totalItems?: number;
}

export async function getSessionCwdHistoryHop(
  sessionId: string,
  eventId: string,
): Promise<SessionCwdHopResolution> {
  const sanitizedSessionId = typeof sessionId === "string" ? sessionId.trim().slice(0, 300) : "";
  const sanitizedEventId = typeof eventId === "string" ? eventId.trim().slice(0, 300) : "";
  if (!sanitizedSessionId || !sanitizedEventId) {
    return { item: null };
  }

  const client = await getMongoClient();
  const collection = client.db(DATABASE_NAME).collection<Document & { _id: string }>(HISTORY_COLLECTION);

  // 1. Primary indexed read: attempt fast primary key lookup on canonical _id_
  let doc = await collection.findOne({ _id: sanitizedEventId });
  if (doc) {
    const docSessionId = asString(doc.sessionId) ?? asString(doc.session_id);
    if (docSessionId !== sanitizedSessionId) {
      // Cross-session: return null to prevent data leakage across sessions
      return { item: null };
    }
  } else {
    // 2. Legacy fallback: check sessionId + eventId
    doc = await collection.findOne({ sessionId: sanitizedSessionId, eventId: sanitizedEventId });
    if (!doc) {
      doc = await collection.findOne({ session_id: sanitizedSessionId, eventId: sanitizedEventId });
    }
    if (!doc) {
      return { item: null };
    }
  }

  const item = normalizeHistoryEvent(doc);
  if (!item) {
    return { item: null };
  }

  // Compute exact chronological hop numbers in MongoDB using the compound index
  const docAt = doc.at instanceof Date ? doc.at : new Date(item.at);
  const docEventId = asString(doc.eventId) ?? asString(doc._id?.toString()) ?? item.id;
  const sessionFilter: Document = { $or: [{ sessionId: sanitizedSessionId }, { session_id: sanitizedSessionId }] };
  const chronologicalFilter: Document = {
    $or: [
      { at: { $lt: docAt } },
      { at: docAt, eventId: { $lte: docEventId } },
    ],
  };

  const [hopNumber, successfulHopNumber, totalItems] = await Promise.all([
    collection.countDocuments({ $and: [sessionFilter, chronologicalFilter] }),
    collection.countDocuments({ $and: [sessionFilter, { action: { $ne: "failed_change" } }, chronologicalFilter] }),
    collection.countDocuments(sessionFilter),
  ]);

  item.hopNumber = hopNumber;
  item.successfulHopNumber = successfulHopNumber;

  return {
    item,
    hopNumber,
    successfulHopNumber,
    totalItems,
  };
}

export interface AuditSessionsQueryOptions {
  search?: string | null;
  targetPath?: string | null;
  hideHome?: boolean;
  cursor?: string | null;
  limit?: number;
  includeSummary?: boolean;
}

function mapDocumentToClosedSession(document: Document): FilesystemClosedSession | null {
  const sessionId = asString(document.effectiveSessionId) ?? asString(document.sessionId) ?? asString(document.session_id);
  const cwdState = normalizeCwdState(document.cwdState);
  const lifecycle = document.lifecycle;
  if (!sessionId || !cwdState || !lifecycle || typeof lifecycle !== "object" || Array.isArray(lifecycle)) {
    return null;
  }
  const lifecycleRecord = lifecycle as Record<string, unknown>;

  const rawVisited = Array.isArray(document.visitedPaths) ? document.visitedPaths : [cwdState.path];
  const visitedSet = new Set<string>();
  for (const p of rawVisited) {
    if (typeof p === "string" && p.startsWith("/")) {
      visitedSet.add(p);
    }
  }
  if (cwdState.path?.startsWith("/")) {
    visitedSet.add(cwdState.path);
  }
  const visitedPaths = [...visitedSet].sort((a, b) => a.localeCompare(b));

  const nonRootPaths = visitedPaths.filter((p) => p !== "/");
  const hasHomePath = nonRootPaths.some((p) => p === "/home" || p.startsWith("/home/"));
  const hasOutsideHomePath = nonRootPaths.some((p) => p !== "/home" && !p.startsWith("/home/"));
  const homeOnly = typeof document.homeOnly === "boolean" ? document.homeOnly : (hasHomePath && !hasOutsideHomePath);

  const eventCount = typeof document.eventCount === "number" && Number.isSafeInteger(document.eventCount) && document.eventCount >= 0
    ? document.eventCount
    : 0;

  return {
    sessionId,
    sourceIp: asString(document.sourceIp) ?? "Unknown",
    cwdState,
    lifecycle: {
      startedAt: asDateString(lifecycleRecord.startedAt),
      closedAt: asDateString(lifecycleRecord.closedAt),
    },
    auditSummary: {
      visitedPaths,
      homeOnly,
      eventCount,
    },
  };
}

export async function getAuditDirectorySummary(options: {
  search?: string | null;
  targetPath?: string | null;
  hideHome?: boolean;
} = {}): Promise<AuditDirectorySummary> {
  const client = await getMongoClient();
  const states = client.db(DATABASE_NAME).collection<Document>(SESSIONS_COLLECTION);
  const pipeline = buildAuditSummaryPipeline({
    search: options.search,
    targetPath: options.targetPath,
    hideHome: options.hideHome,
    historyCollectionName: HISTORY_COLLECTION,
  });

  const result = await states.aggregate<{
    overview: Array<{ totalSessions: number; homeOnlyCount: number; matchingCount: number }>;
    distinctPaths: Array<{ path: string; sessionCount: number }>;
  }>(pipeline, { allowDiskUse: true }).toArray();

  const overview = result[0]?.overview?.[0];
  const totalSessions = overview?.totalSessions ?? 0;
  const homeOnlyCount = overview?.homeOnlyCount ?? 0;
  const hasFilter = Boolean(options.hideHome || options.targetPath || options.search);
  const matchingCount = hasFilter ? (overview?.matchingCount ?? 0) : undefined;
  const distinctPaths = result[0]?.distinctPaths ?? [];

  return {
    totalSessions,
    homeOnlyCount,
    distinctPaths,
    matchingCount,
  };
}

export async function getAuditSessions(options: AuditSessionsQueryOptions = {}): Promise<AuditSessionsPage> {
  const limit = Math.max(1, Math.min(100, options.limit ?? 25));
  const pipeline = buildAuditSessionsPipeline({
    search: options.search,
    targetPath: options.targetPath,
    hideHome: options.hideHome,
    cursor: options.cursor,
    limit,
    historyCollectionName: HISTORY_COLLECTION,
  });

  const client = await getMongoClient();
  const states = client.db(DATABASE_NAME).collection<Document>(SESSIONS_COLLECTION);
  const [aggregationResult, summary] = await Promise.all([
    states.aggregate<{
      total: Array<{ count: number }>;
      items: Document[];
    }>(pipeline, { allowDiskUse: true }).toArray(),
    options.includeSummary
      ? getAuditDirectorySummary({
          search: options.search,
          targetPath: options.targetPath,
          hideHome: options.hideHome,
        })
      : Promise.resolve(undefined),
  ]);

  const facet = aggregationResult[0];
  const totalItems = facet?.total?.[0]?.count ?? 0;
  const rawItems = facet?.items ?? [];

  const hasMore = rawItems.length > limit;
  const pageDocs = rawItems.slice(0, limit);

  const items: FilesystemClosedSession[] = pageDocs
    .map(mapDocumentToClosedSession)
    .filter((item): item is FilesystemClosedSession => item !== null);

  const lastDoc = pageDocs.at(-1);
  const nextCursor = hasMore && lastDoc
    ? encodeAuditSessionCursor(
        asDateString(lastDoc.lifecycle?.closedAt) ?? new Date(0).toISOString(),
        asString(lastDoc.effectiveSessionId) ?? asString(lastDoc.sessionId) ?? asString(lastDoc.session_id) ?? "",
      )
    : null;

  return {
    items,
    totalItems,
    nextCursor,
    summary,
  };
}

async function flushTopologyBroadcast() {
  if (runtime.broadcastInFlight) return runtime.broadcastInFlight;
  runtime.broadcastInFlight = (async () => {
    runtime.topologyDirty = false;
    const snapshot = await getFilesystemTopology();
    for (const subscriber of runtime.subscribers) subscriber.changed(snapshot);
  })();
  try {
    await runtime.broadcastInFlight;
  } finally {
    runtime.broadcastInFlight = null;
    // A second update may arrive while the snapshot query is in flight.
    if (runtime.topologyDirty) scheduleTopologyBroadcast();
  }
}

let broadcastScheduledAt: number | null = null;

function scheduleTopologyBroadcast() {
  if (!runtime.subscribers.size) return;
  runtime.topologyDirty = true;
  const now = Date.now();
  if (broadcastScheduledAt === null) {
    broadcastScheduledAt = now;
  }
  const elapsed = now - broadcastScheduledAt;

  // If already scheduled and within the max latency ceiling (500ms), debounce trailing events.
  // This coalesces rapid two-phase command execution events (e.g. command.input -> session.cwd)
  // into a single smooth snapshot broadcast.
  if (runtime.pendingBroadcast && elapsed < 500) {
    clearTimeout(runtime.pendingBroadcast);
    runtime.pendingBroadcast = null;
  }

  if (runtime.broadcastInFlight) return;
  runtime.pendingBroadcast = setTimeout(() => {
    runtime.pendingBroadcast = null;
    broadcastScheduledAt = null;
    void flushTopologyBroadcast().catch(() => {
      for (const subscriber of [...runtime.subscribers]) subscriber.unavailable();
    });
  }, TOPOLOGY_BROADCAST_DEBOUNCE_MS);
}

function detachStream(stream: ChangeStream<Document>) {
  if (runtime.stream !== stream) return;
  runtime.stream = null;
  if (runtime.pendingBroadcast) clearTimeout(runtime.pendingBroadcast);
  runtime.pendingBroadcast = null;
  runtime.topologyDirty = false;
  void stream.close().catch(() => undefined);
  // Closing every dependent SSE response exposes the outage to EventSource.
  // The browser performs the bounded reconnect and obtains a fresh snapshot,
  // instead of receiving heartbeats from a silently dead MongoDB stream.
  for (const subscriber of [...runtime.subscribers]) subscriber.unavailable();
}

async function ensureFilesystemChangeStream(): Promise<void> {
  if (!runtime.subscribers.size || runtime.stream) return;
  if (runtime.opening) return runtime.opening;
  runtime.opening = (async () => {
    const client = await getMongoClient();
    if (!runtime.subscribers.size || runtime.stream) return;
    const stream = client.db(DATABASE_NAME).collection<Document>(SESSIONS_COLLECTION).watch(
      [{ $match: { operationType: { $in: ["insert", "replace", "update", "delete"] } } }],
      { fullDocument: "updateLookup" },
    );
    runtime.stream = stream;
    stream.on("change", (change) => {
      // TTL deletions must remove stale sessions from an open topology too.
      if (change.operationType === "delete") {
        scheduleTopologyBroadcast();
        return;
      }
      if (!("fullDocument" in change) || !change.fullDocument || !normalizeCwdState(change.fullDocument.cwdState)) return;
      scheduleTopologyBroadcast();
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
    if (runtime.pendingBroadcast) clearTimeout(runtime.pendingBroadcast);
    runtime.pendingBroadcast = null;
    runtime.topologyDirty = false;
    const stream = runtime.stream;
    runtime.stream = null;
    if (stream) void stream.close().catch(() => undefined);
  };
}
