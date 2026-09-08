import "server-only";

import geoip from "geoip-lite";
import type { ChangeStream, Document, Filter } from "mongodb";

import type {
  DashboardThreatEvent,
  ThreatDashboardSummary,
  ThreatDirectoryPage,
  ThreatSeverityFilter,
} from "@/lib/dashboardTypes";
import { getMongoClient } from "@/lib/mongodb";

const DATABASE_NAME = "honeypot_canonical_v1";
const COLLECTION_NAME = "sessions";
const DEFAULT_LIMIT = 100;
const DEFAULT_DIRECTORY_PAGE_SIZE = 20;
const MAX_DIRECTORY_PAGE_SIZE = 100;
export const MAX_DIRECTORY_EXPORT = 10_000;
const SUMMARY_WINDOW_HOURS = 24;
const SNAPSHOT_TTL_MS = 5_000;
const STREAM_RETRY_MS = 5_000;

type ThreatUpdate = { type: "threat.upsert"; data: DashboardThreatEvent };
type ThreatSubscriber = (update: ThreatUpdate) => void;

interface CachedSnapshot {
  value: DashboardThreatEvent[];
  expiresAt: number;
}

interface ThreatRuntime {
  subscribers: Set<ThreatSubscriber>;
  stream: ChangeStream<Document> | null;
  opening: Promise<void> | null;
  reconnectTimer: ReturnType<typeof setTimeout> | null;
  snapshots: Map<string, CachedSnapshot>;
  inflightSnapshots: Map<string, Promise<DashboardThreatEvent[]>>;
}

const globalScope = globalThis as typeof globalThis & { __ptiThreatRuntime?: ThreatRuntime };
const runtime: ThreatRuntime = globalScope.__ptiThreatRuntime ?? {
  subscribers: new Set(),
  stream: null,
  opening: null,
  reconnectTimer: null,
  snapshots: new Map(),
  inflightSnapshots: new Map(),
};

globalScope.__ptiThreatRuntime = runtime;

function queryForRange(range: string | null): Filter<Document> {
  if (range !== "7days") return {};

  const sevenDaysAgo = new Date();
  sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
  return { start_time: { $gte: sevenDaysAgo.toISOString() } };
}

function limitForRange(range: string | null): number {
  return range === "all" ? 2_000 : DEFAULT_LIMIT;
}

export interface ThreatDirectoryFilters {
  query?: string;
  severity?: ThreatSeverityFilter;
  page?: number;
  pageSize?: number;
}

function normalizeDirectoryFilters(filters: ThreatDirectoryFilters) {
  const query = filters.query?.trim().slice(0, 120) ?? "";
  const severity: ThreatSeverityFilter = ["Critical", "High", "Medium", "Low"].includes(filters.severity ?? "")
    ? filters.severity as ThreatSeverityFilter
    : "All";
  const page = Number.isFinite(filters.page) ? Math.max(1, Math.floor(filters.page ?? 1)) : 1;
  const pageSize = Number.isFinite(filters.pageSize)
    ? Math.min(MAX_DIRECTORY_PAGE_SIZE, Math.max(1, Math.floor(filters.pageSize ?? DEFAULT_DIRECTORY_PAGE_SIZE)))
    : DEFAULT_DIRECTORY_PAGE_SIZE;

  return { query, severity, page, pageSize };
}

function escapeRegex(value: string) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function filterForDirectory({ query, severity }: Pick<ReturnType<typeof normalizeDirectoryFilters>, "query" | "severity">): Filter<Document> {
  const conditions: Filter<Document>[] = [];

  if (severity !== "All") {
    if (severity === "Medium") {
      conditions.push({
        $or: [
          { max_confirmed_severity: "Medium" },
          { max_confirmed_severity: { $exists: false } },
          { max_confirmed_severity: "" },
        ],
      });
    } else {
      conditions.push({ max_confirmed_severity: severity });
    }
  }

  if (query) {
    const matcher = new RegExp(escapeRegex(query), "i");
    conditions.push({
      $or: [
        { session_id: matcher },
        { src_ip: matcher },
        { session_source: matcher },
        { max_confirmed_severity: matcher },
      ],
    });
  }

  if (!conditions.length) return {};
  if (conditions.length === 1) return conditions[0];
  return { $and: conditions };
}

function normalizeThreats(sessionDocs: Document[]): DashboardThreatEvent[] {
  const ipCache = new Map<string, { lat: number; lon: number; country: string; city: string }>();

  return sessionDocs.map((session) => normalizeThreat(session, ipCache));
}

function normalizeThreat(
  session: Document,
  ipCache = new Map<string, { lat: number; lon: number; country: string; city: string }>(),
): DashboardThreatEvent {
  let lat = 0;
  let lon = 0;
  let country = "Unknown";
  let city = "Unknown";
  const ip = typeof session.src_ip === "string" && session.src_ip ? session.src_ip : "Unknown";

  if (ip !== "Unknown") {
    const cached = ipCache.get(ip);
    if (cached) {
      ({ lat, lon, country, city } = cached);
    } else {
      const geo = geoip.lookup(ip);
      const location = geo
        ? { lat: geo.ll[0], lon: geo.ll[1], country: geo.country, city: geo.city }
        : { lat: 0, lon: 0, country: "Unknown", city: "Unknown" };
      ipCache.set(ip, location);
      ({ lat, lon, country, city } = location);
    }
  }

  let dateObj = new Date();
  if (session.start_time) {
    const parsed = new Date(String(session.start_time));
    if (!Number.isNaN(parsed.getTime())) dateObj = parsed;
  }

  const severity = typeof session.max_confirmed_severity === "string" && session.max_confirmed_severity
    ? session.max_confirmed_severity
    : "Medium";
  let classification = "SCRIPT KIDDIE";
  let typeColor = "bg-amber-950/40 text-amber-400 border-amber-900/50";

  if (severity === "Critical") {
    classification = "APT";
    typeColor = "bg-red-950/40 text-red-400 border-red-900/50";
  } else if (severity === "High") {
    classification = "BOT";
    typeColor = "bg-slate-800 text-slate-300 border-slate-700";
  }

  return {
    id: typeof session.session_id === "string" && session.session_id
      ? session.session_id
      : session._id?.toString() ?? crypto.randomUUID(),
    timestamp: dateObj.toISOString(),
    date: dateObj.toLocaleDateString("en-GB"),
    time: `${dateObj.toLocaleTimeString("en-US", { hour12: false })} UTC`,
    sensor: typeof session.session_source === "string" && session.session_source ? session.session_source : "Unknown",
    src_ip: ip,
    sourceIp: ip,
    severity,
    classification,
    typeColor,
    duration: "Active",
    geo: { lat, lon, country, city },
  };
}

export async function getThreatSnapshot(range: string | null = null): Promise<DashboardThreatEvent[]> {
  const cacheKey = range ?? "default";
  const cached = runtime.snapshots.get(cacheKey);
  if (cached && cached.expiresAt > Date.now()) return cached.value;

  const inflight = runtime.inflightSnapshots.get(cacheKey);
  if (inflight) return inflight;

  const request = (async () => {
    const client = await getMongoClient();
    const sessions = await client.db(DATABASE_NAME).collection<Document>(COLLECTION_NAME)
      .find(queryForRange(range))
      .sort({ start_time: -1 })
      .limit(limitForRange(range))
      // MongoDB chooses `start_time_desc` automatically when the deployment has
      // it. Disk use keeps the feed available while an index is absent or still
      // being built, rather than failing the entire dashboard at Atlas' sort cap.
      .allowDiskUse(true)
      .toArray();
    const threats = normalizeThreats(sessions);

    // "all" is an archive query and should not keep a large historical cache resident.
    if (range !== "all") {
      runtime.snapshots.set(cacheKey, { value: threats, expiresAt: Date.now() + SNAPSHOT_TTL_MS });
    }
    return threats;
  })();

  runtime.inflightSnapshots.set(cacheKey, request);
  try {
    return await request;
  } finally {
    runtime.inflightSnapshots.delete(cacheKey);
  }
}

export async function getThreatDirectory(filters: ThreatDirectoryFilters = {}): Promise<ThreatDirectoryPage> {
  const normalized = normalizeDirectoryFilters(filters);
  const query = filterForDirectory(normalized);
  const client = await getMongoClient();
  const collection = client.db(DATABASE_NAME).collection<Document>(COLLECTION_NAME);
  const total = await collection.countDocuments(query);
  const totalPages = Math.max(1, Math.ceil(total / normalized.pageSize));
  const page = Math.min(normalized.page, totalPages);
  const sessionDocs = await collection
    .find(query)
    .sort({ start_time: -1 })
    .skip((page - 1) * normalized.pageSize)
    .limit(normalized.pageSize)
    .allowDiskUse(true)
    .toArray();

  return {
    items: normalizeThreats(sessionDocs),
    page,
    pageSize: normalized.pageSize,
    total,
    totalPages,
  };
}

export async function getThreatDirectoryExport(filters: Omit<ThreatDirectoryFilters, "page" | "pageSize"> = {}) {
  const normalized = normalizeDirectoryFilters(filters);
  const query = filterForDirectory(normalized);
  const client = await getMongoClient();
  const collection = client.db(DATABASE_NAME).collection<Document>(COLLECTION_NAME);
  const total = await collection.countDocuments(query);
  const sessionDocs = await collection
    .find(query)
    .sort({ start_time: -1 })
    .limit(MAX_DIRECTORY_EXPORT)
    .allowDiskUse(true)
    .toArray();

  return {
    items: normalizeThreats(sessionDocs),
    total,
    truncated: total > MAX_DIRECTORY_EXPORT,
  };
}

export async function getThreatDashboardSummary(): Promise<ThreatDashboardSummary> {
  const windowStart = new Date(Date.now() - SUMMARY_WINDOW_HOURS * 60 * 60 * 1_000).toISOString();
  const client = await getMongoClient();
  const [summary] = await client.db(DATABASE_NAME).collection<Document>(COLLECTION_NAME).aggregate<{
    sessions: Array<{ count: number }>;
    uniqueSources: Array<{ count: number }>;
    prioritySessions: Array<{ count: number }>;
  }>([
    { $match: { start_time: { $gte: windowStart } } },
    {
      $facet: {
        sessions: [{ $count: "count" }],
        uniqueSources: [
          { $match: { src_ip: { $type: "string", $ne: "" } } },
          { $group: { _id: "$src_ip" } },
          { $count: "count" },
        ],
        prioritySessions: [
          { $match: { max_confirmed_severity: { $in: ["Critical", "High"] } } },
          { $count: "count" },
        ],
      },
    },
  ], { allowDiskUse: true }).toArray();

  return {
    windowHours: SUMMARY_WINDOW_HOURS,
    sessions: summary?.sessions[0]?.count ?? 0,
    uniqueSources: summary?.uniqueSources[0]?.count ?? 0,
    prioritySessions: summary?.prioritySessions[0]?.count ?? 0,
  };
}

function invalidateThreatSnapshots() {
  runtime.snapshots.clear();
}

function broadcast(update: ThreatUpdate) {
  for (const subscriber of runtime.subscribers) subscriber(update);
}

function scheduleReconnect() {
  if (!runtime.subscribers.size || runtime.reconnectTimer) return;
  runtime.reconnectTimer = setTimeout(() => {
    runtime.reconnectTimer = null;
    void ensureThreatChangeStream();
  }, STREAM_RETRY_MS);
}

function detachStream(stream: ChangeStream<Document>) {
  if (runtime.stream !== stream) return;
  runtime.stream = null;
  void stream.close().catch(() => undefined);
  scheduleReconnect();
}

async function ensureThreatChangeStream(): Promise<void> {
  if (!runtime.subscribers.size || runtime.stream) return;
  if (runtime.opening) return runtime.opening;

  runtime.opening = (async () => {
    const client = await getMongoClient();
    if (!runtime.subscribers.size || runtime.stream) return;

    const stream = client.db(DATABASE_NAME).collection<Document>(COLLECTION_NAME).watch(
      [{ $match: { operationType: { $in: ["insert", "replace", "update"] } } }],
      { fullDocument: "updateLookup" },
    );
    runtime.stream = stream;

    stream.on("change", (change) => {
      invalidateThreatSnapshots();
      if (!("fullDocument" in change) || !change.fullDocument) return;
      broadcast({ type: "threat.upsert", data: normalizeThreat(change.fullDocument) });
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

export async function subscribeThreatUpdates(subscriber: ThreatSubscriber): Promise<() => void> {
  runtime.subscribers.add(subscriber);
  try {
    await ensureThreatChangeStream();
  } catch (error) {
    runtime.subscribers.delete(subscriber);
    throw error;
  }

  return () => {
    runtime.subscribers.delete(subscriber);
    if (runtime.subscribers.size) return;
    if (runtime.reconnectTimer) {
      clearTimeout(runtime.reconnectTimer);
      runtime.reconnectTimer = null;
    }
    const stream = runtime.stream;
    runtime.stream = null;
    if (stream) void stream.close().catch(() => undefined);
  };
}
