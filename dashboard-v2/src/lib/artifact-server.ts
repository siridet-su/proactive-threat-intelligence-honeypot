import "server-only";

import type { Db, Document, Filter } from "mongodb";

import type {
  ArtifactIntel,
  ArtifactIntelStatus,
  ArtifactPage,
  ArtifactRecord,
} from "@/lib/artifact-types";

export const DEFAULT_ARTIFACT_PAGE_SIZE = 25;
export const MAX_ARTIFACT_PAGE_SIZE = 50;
export const MAX_ARTIFACT_PAGE = 1_000;

const HASH_PATTERN = /^[a-f0-9]{64}$/i;
const HASH_MONGO_PATTERN = /^[a-f0-9]{64}$/i;
const MAX_EVENT_SCAN = 5_000;
const MAX_EVIDENCE_EVENTS = 2_000;
const MAX_TEXT_LENGTH = 512;

type NormalizedIntel = {
  id: string;
  hash: string;
  intel: ArtifactIntel;
  firstSeen: string | null;
  lastSeen: string | null;
};

type EventEvidence = {
  key: string;
  timestamp: string | null;
  sourceIp: string | null;
  sessionId: string | null;
  filename: string | null;
  url: string | null;
  sizeBytes: number | null;
};

type EventBucket = {
  events: EventEvidence[];
  firstSeen: string | null;
  lastSeen: string | null;
};

const indexPromises = new Map<string, Promise<void>>();

function asRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null;
}

function nestedValue(value: unknown, path: string[]): unknown {
  let current: unknown = value;
  for (const key of path) {
    const record = asRecord(current);
    if (!record) return undefined;
    current = record[key];
  }
  return current;
}

function stringValue(value: unknown, maxLength = MAX_TEXT_LENGTH): string | null {
  if (typeof value !== "string") return null;
  const normalized = value.replace(/[\u0000-\u001f\u007f]/g, " ").trim();
  return normalized ? normalized.slice(0, maxLength) : null;
}

function numberValue(value: unknown): number | null {
  const candidate = typeof value === "number" ? value : typeof value === "string" ? Number(value) : NaN;
  return Number.isFinite(candidate) && candidate >= 0 ? candidate : null;
}

function booleanValue(value: unknown): boolean | null {
  return typeof value === "boolean" ? value : null;
}

export function normalizeSha256(value: unknown): string | null {
  const normalized = stringValue(value, 64)?.toLowerCase();
  return normalized && HASH_PATTERN.test(normalized) ? normalized : null;
}

function dateValue(value: unknown): string | null {
  if (value instanceof Date) {
    return Number.isNaN(value.getTime()) ? null : value.toISOString();
  }
  if (typeof value !== "string" && typeof value !== "number") return null;
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? null : parsed.toISOString();
}

function compareDates(left: string | null, right: string | null): number {
  if (!left) return right ? 1 : 0;
  if (!right) return -1;
  return left.localeCompare(right);
}

function minDate(current: string | null, candidate: string | null): string | null {
  if (!candidate) return current;
  return !current || compareDates(candidate, current) < 0 ? candidate : current;
}

function maxDate(current: string | null, candidate: string | null): string | null {
  if (!candidate) return current;
  return !current || compareDates(candidate, current) > 0 ? candidate : current;
}

function parseObject(value: unknown): Record<string, unknown> | null {
  if (asRecord(value)) return asRecord(value);
  if (typeof value !== "string") return null;
  try {
    return asRecord(JSON.parse(value));
  } catch {
    return null;
  }
}

function recordId(record: Document): string {
  const value = record._id;
  if (typeof value === "string") return value.slice(0, 256);
  if (value && typeof value.toString === "function") return value.toString().slice(0, 256);
  return "unknown";
}

function hashStats(summary: Record<string, unknown>): { detections: number; total: number } {
  const stats = asRecord(summary.analysis_stats) ?? asRecord(summary.last_analysis_stats);
  if (!stats) return { detections: 0, total: 0 };

  let total = 0;
  let detections = 0;
  for (const [key, value] of Object.entries(stats)) {
    const count = numberValue(value) ?? 0;
    total += count;
    if (key === "malicious" || key === "suspicious") detections += count;
  }
  return { detections, total };
}

function detectionRatio(summary: Record<string, unknown>, stats: { detections: number; total: number }): string | null {
  const existing = stringValue(summary.vt_detection_ratio, 32)
    ?? stringValue(summary.detection_ratio, 32);
  if (existing) return existing;
  return stats.total > 0 ? `${stats.detections}/${stats.total}` : null;
}

function intelStatus(
  rawStatus: string | null,
  knownToProvider: boolean | null,
  detections: number,
  expiresAt: string | null,
  now: Date,
): ArtifactIntelStatus {
  if (expiresAt && new Date(expiresAt).getTime() <= now.getTime()) return "stale";

  switch ((rawStatus ?? "").toLowerCase()) {
    case "complete":
    case "ok":
    case "cached":
      if (detections > 0) return "known_malicious";
      if (knownToProvider === true) return "no_malicious_detections";
      return "unknown_to_provider";
    case "not_found":
    case "no_data":
      return "unknown_to_provider";
    case "skipped":
    case "disabled":
    case "unconfigured":
      return "disabled";
    case "error":
    case "failed":
    case "temporary_error":
      return "failed";
    case "deferred":
    case "queued":
    case "pending":
      return "pending";
    default:
      return "pending";
  }
}

function toIntel(
  rawStatus: string | null,
  summary: Record<string, unknown>,
  queriedAt: string | null,
  expiresAt: string | null,
  now: Date,
): ArtifactIntel {
  const stats = hashStats(summary);
  const knownToProvider = booleanValue(summary.known_to_provider);
  const status = intelStatus(rawStatus, knownToProvider, stats.detections, expiresAt, now);
  const malwareFamily = stringValue(summary.meaningful_name)
    ?? stringValue(summary.vt_malware_family)
    ?? stringValue(summary.suggested_threat_label);

  return {
    provider: "virustotal",
    status,
    knownToProvider,
    detectionRatio: detectionRatio(summary, stats),
    malwareFamily,
    queriedAt,
    expiresAt,
  };
}

export function mapThreatIntelRecord(record: Document, now = new Date()): NormalizedIntel | null {
  const hash = normalizeSha256(record.observable ?? record.observable_value);
  if (!hash) return null;

  const summary = asRecord(record.summary) ?? {};
  return {
    id: recordId(record),
    hash,
    intel: toIntel(
      stringValue(record.status, 64),
      summary,
      dateValue(record.queried_at),
      dateValue(record.expires_at),
      now,
    ),
    firstSeen: dateValue(record.first_seen),
    lastSeen: dateValue(record.last_seen),
  };
}

export function mapLegacyEnrichmentRecord(record: Document, now = new Date()): NormalizedIntel | null {
  const observableType = stringValue(record.observable_type, 32)?.toLowerCase();
  if (observableType !== "hash" && observableType !== "sha256") return null;
  const hash = normalizeSha256(record.observable_value ?? record.observable);
  if (!hash) return null;

  const providerStatus = parseObject(record.provider_status_json ?? record.provider_status) ?? {};
  const providerRecord = asRecord(providerStatus.virustotal) ?? providerStatus;
  const summary = asRecord(providerRecord.summary)
    ?? asRecord(providerRecord.provider_evidence)
    ?? providerRecord;
  const fallbackHit = providerRecord.vt_hit === true || summary.vt_hit === true;
  if (fallbackHit && summary.known_to_provider === undefined) summary.known_to_provider = true;
  if (fallbackHit && !summary.vt_detection_ratio && !summary.detection_ratio) summary.vt_detection_ratio = "1/?";

  return {
    id: recordId(record),
    hash,
    intel: toIntel(
      stringValue(providerRecord.status ?? record.status, 64),
      summary,
      dateValue(record.last_seen ?? record.updated_at),
      dateValue(record.expires_at),
      now,
    ),
    firstSeen: dateValue(record.first_seen),
    lastSeen: dateValue(record.last_seen),
  };
}

function safeUrl(value: unknown): string | null {
  const text = stringValue(value, 2_048);
  if (!text) return null;
  try {
    const parsed = new URL(text);
    if (!/^https?:$/.test(parsed.protocol) || parsed.username || parsed.password) return null;
    // Query strings and fragments can carry credentials or one-time download
    // tokens. Keep only stable locator metadata for the dashboard.
    parsed.search = "";
    parsed.hash = "";
    return parsed.toString();
  } catch {
    return null;
  }
}

function eventHashes(event: Document): string[] {
  const candidates = [
    nestedValue(event, ["threat_intel", "virustotal", "observable"]),
    nestedValue(event, ["threat_intel", "virustotal", "observable_value"]),
    nestedValue(event, ["activity", "sha256"]),
    nestedValue(event, ["activity", "sha256_hash"]),
    nestedValue(event, ["activity", "shasum"]),
    nestedValue(event, ["raw", "payload", "sha256"]),
    nestedValue(event, ["raw", "payload", "sha256_hash"]),
    nestedValue(event, ["raw", "payload", "shasum"]),
  ];
  return [...new Set(candidates.map(normalizeSha256).filter((value): value is string => Boolean(value)))];
}

function eventEvidence(event: Document): EventEvidence {
  const timestamp = dateValue(event.timestamp ?? event.ingested_at);
  const sourceIp = stringValue(
    nestedValue(event, ["network", "src_ip"]) ?? event.src_ip,
    64,
  );
  const sessionId = stringValue(
    nestedValue(event, ["session", "id"])
      ?? nestedValue(event, ["cowrie", "session"])
      ?? event.session_id,
    256,
  );
  const activity = asRecord(event.activity) ?? {};
  const filename = stringValue(activity.filename ?? activity.file_name ?? event.filename, 512);
  const url = safeUrl(activity.url ?? activity.uri ?? event.url);
  const sizeBytes = numberValue(
    activity.size_bytes
      ?? activity.file_size
      ?? activity.size
      ?? event.size_bytes,
  );
  const key = stringValue(event._id ?? event.event_id, 256)
    ?? [timestamp, sourceIp, sessionId, filename].filter(Boolean).join("|");

  return { key, timestamp, sourceIp, sessionId, filename, url, sizeBytes };
}

function evidenceProjection(): Document {
  return {
    _id: 1,
    event_id: 1,
    timestamp: 1,
    ingested_at: 1,
    source: 1,
    src_ip: 1,
    session_id: 1,
    filename: 1,
    url: 1,
    size_bytes: 1,
    "network.src_ip": 1,
    "session.id": 1,
    "cowrie.session": 1,
    "activity.filename": 1,
    "activity.file_name": 1,
    "activity.url": 1,
    "activity.uri": 1,
    "activity.size_bytes": 1,
    "activity.file_size": 1,
    "activity.size": 1,
    "activity.sha256": 1,
    "activity.sha256_hash": 1,
    "activity.shasum": 1,
    "threat_intel.virustotal.observable": 1,
    "threat_intel.virustotal.observable_value": 1,
    "raw.payload.sha256": 1,
    "raw.payload.sha256_hash": 1,
    "raw.payload.shasum": 1,
  };
}

function eventFilter(matcher: RegExp): Filter<Document> {
  return {
    $or: [
      { "threat_intel.virustotal.observable": matcher },
      { "threat_intel.virustotal.observable_value": matcher },
      { "activity.sha256": matcher },
      { "activity.sha256_hash": matcher },
      { "activity.shasum": matcher },
      { "raw.payload.sha256": matcher },
      { "raw.payload.sha256_hash": matcher },
      { "raw.payload.shasum": matcher },
    ],
  };
}

async function readEvidence(db: Db, hashes: string[]): Promise<Map<string, EventBucket>> {
  if (!hashes.length) return new Map();
  const hashMatcher = new RegExp(`^(?:${hashes.map(escapeRegex).join("|")})$`, "i");
  const documents = await db.collection<Document>("events")
    .find(eventFilter(hashMatcher), { projection: evidenceProjection() })
    .sort({ timestamp: -1, _id: -1 })
    .limit(MAX_EVIDENCE_EVENTS)
    .maxTimeMS(5_000)
    .toArray();
  return bucketEvents(documents);
}

function bucketEvents(documents: Document[]): Map<string, EventBucket> {
  const buckets = new Map<string, EventBucket>();
  for (const document of documents) {
    const hashes = eventHashes(document);
    if (!hashes.length) continue;
    const evidence = eventEvidence(document);
    for (const hash of hashes) {
      const bucket = buckets.get(hash) ?? { events: [], firstSeen: null, lastSeen: null };
      if (!bucket.events.some((item) => item.key === evidence.key)) {
        bucket.events.push(evidence);
      }
      bucket.firstSeen = minDate(bucket.firstSeen, evidence.timestamp);
      bucket.lastSeen = maxDate(bucket.lastSeen, evidence.timestamp);
      buckets.set(hash, bucket);
    }
  }
  return buckets;
}

function artifactFromIntel(
  normalized: NormalizedIntel,
  evidence: EventBucket | undefined,
): ArtifactRecord {
  const events = evidence?.events ?? [];
  const sourceIps = [...new Set(events.map((event) => event.sourceIp).filter((value): value is string => Boolean(value)))].slice(0, 16);
  const sessionIds = [...new Set(events.map((event) => event.sessionId).filter((value): value is string => Boolean(value)))].slice(0, 16);
  const firstEvent = events.find((event) => event.filename || event.url || event.sizeBytes !== null);

  return {
    id: normalized.id,
    artifactSha256: normalized.hash,
    hashAlgorithm: "sha256",
    firstSeen: evidence?.firstSeen ?? normalized.firstSeen,
    lastSeen: evidence?.lastSeen ?? normalized.lastSeen,
    observedFilename: firstEvent?.filename ?? null,
    observedUrl: firstEvent?.url ?? null,
    sizeBytes: firstEvent?.sizeBytes ?? null,
    sourceIps,
    sessionIds,
    evidenceCount: events.length,
    intel: normalized.intel,
    retention: { bytesRetained: false, mode: "hash_only" },
  };
}

function pendingIntel(): ArtifactIntel {
  return {
    provider: "virustotal",
    status: "pending",
    knownToProvider: null,
    detectionRatio: null,
    malwareFamily: null,
    queriedAt: null,
    expiresAt: null,
  };
}

function artifactFromEvents(hash: string, evidence: EventBucket): ArtifactRecord {
  return artifactFromIntel({
    id: `event-${hash}`,
    hash,
    intel: pendingIntel(),
    firstSeen: null,
    lastSeen: null,
  }, evidence);
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function hashMatcher(query: string): RegExp {
  return query ? new RegExp(escapeRegex(query), "i") : HASH_MONGO_PATTERN;
}

function hashQuery(query: string): string {
  return query.trim().slice(0, 128);
}

async function ensureArtifactIndexes(db: Db): Promise<void> {
  const key = db.databaseName || "default";
  const existing = indexPromises.get(key);
  if (existing) return existing;

  const promise = Promise.all([
    db.collection("threat_intel").createIndex(
      { provider: 1, observable_type: 1, observable: 1, queried_at: -1, _id: -1 },
      { name: "artifact_sha256_identity_v1" },
    ),
    db.collection("enrichment_records").createIndex(
      { observable_type: 1, observable_value: 1, first_seen: -1, _id: -1 },
      { name: "artifact_hash_identity_v1" },
    ),
  ]).then(() => undefined).catch(() => {
    // Index creation must not turn a read-only dashboard view into an outage.
    console.warn("Artifact indexes are unavailable; continuing with bounded reads.");
  });
  indexPromises.set(key, promise);
  return promise;
}

const THREAT_INTEL_PROJECTION = {
  _id: 1,
  provider: 1,
  observable_type: 1,
  observable: 1,
  status: 1,
  summary: 1,
  queried_at: 1,
  expires_at: 1,
};

const LEGACY_PROJECTION = {
  _id: 1,
  observable_type: 1,
  observable_value: 1,
  provider_status_json: 1,
  provider_status: 1,
  status: 1,
  first_seen: 1,
  last_seen: 1,
  updated_at: 1,
  expires_at: 1,
};

async function readEventFallback(
  db: Db,
  query: string,
  page: number,
  limit: number,
  now: Date,
): Promise<ArtifactPage> {
  const documents = await db.collection<Document>("events")
    .find(eventFilter(hashMatcher(query)), { projection: evidenceProjection() })
    .sort({ timestamp: -1, _id: -1 })
    .limit(MAX_EVENT_SCAN + 1)
    .maxTimeMS(5_000)
    .toArray();
  const buckets = bucketEvents(documents.slice(0, MAX_EVENT_SCAN));
  const hashes = [...buckets.keys()];
  const offset = (page - 1) * limit;
  const items = hashes.slice(offset, offset + limit).map((hash) => artifactFromEvents(hash, buckets.get(hash)!));
  const truncated = documents.length > MAX_EVENT_SCAN;

  return {
    success: true,
    items,
    total: buckets.size,
    page,
    limit,
    hasMore: truncated || offset + items.length < buckets.size,
    totalIsApproximate: truncated,
    asOf: now.toISOString(),
    scope: "sha256_observations",
    dataSource: buckets.size ? "events" : "none",
  };
}

export async function getArtifactPage(
  db: Db,
  options: { query?: string; page?: number; limit?: number; now?: Date } = {},
): Promise<ArtifactPage> {
  const query = hashQuery(options.query ?? "");
  const page = Math.min(MAX_ARTIFACT_PAGE, Math.max(1, Math.floor(options.page ?? 1)));
  const limit = Math.min(MAX_ARTIFACT_PAGE_SIZE, Math.max(1, Math.floor(options.limit ?? DEFAULT_ARTIFACT_PAGE_SIZE)));
  const now = options.now ?? new Date();

  await ensureArtifactIndexes(db);

  const threatFilter: Filter<Document> = {
    provider: "virustotal",
    observable_type: "sha256",
    observable: hashMatcher(query),
  };
  const threatHashCount = await db.collection<Document>("threat_intel").countDocuments(
    { provider: "virustotal", observable_type: "sha256", observable: HASH_MONGO_PATTERN },
    { maxTimeMS: 5_000 },
  );

  if (threatHashCount > 0) {
    const total = await db.collection<Document>("threat_intel").countDocuments(threatFilter, { maxTimeMS: 5_000 });
    const records = await db.collection<Document>("threat_intel")
      .find(threatFilter, { projection: THREAT_INTEL_PROJECTION })
      .sort({ queried_at: -1, _id: -1 })
      .skip((page - 1) * limit)
      .limit(limit)
      .maxTimeMS(5_000)
      .toArray();
    const normalized = records.map((record) => mapThreatIntelRecord(record, now)).filter((record): record is NormalizedIntel => Boolean(record));
    const evidence = await readEvidence(db, normalized.map((record) => record.hash));
    return {
      success: true,
      items: normalized.map((record) => artifactFromIntel(record, evidence.get(record.hash))),
      total,
      page,
      limit,
      hasMore: page * limit < total,
      totalIsApproximate: false,
      asOf: now.toISOString(),
      scope: "sha256_observations",
      dataSource: "threat_intel",
    };
  }

  const legacyFilter: Filter<Document> = {
    observable_type: { $in: ["hash", "sha256"] },
    observable_value: hashMatcher(query),
  };
  const legacyHashCount = await db.collection<Document>("enrichment_records").countDocuments(
    { observable_type: { $in: ["hash", "sha256"] }, observable_value: HASH_MONGO_PATTERN },
    { maxTimeMS: 5_000 },
  );

  if (legacyHashCount > 0) {
    const total = await db.collection<Document>("enrichment_records").countDocuments(legacyFilter, { maxTimeMS: 5_000 });
    const records = await db.collection<Document>("enrichment_records")
      .find(legacyFilter, { projection: LEGACY_PROJECTION })
      .sort({ first_seen: -1, _id: -1 })
      .skip((page - 1) * limit)
      .limit(limit)
      .maxTimeMS(5_000)
      .toArray();
    const normalized = records.map((record) => mapLegacyEnrichmentRecord(record, now)).filter((record): record is NormalizedIntel => Boolean(record));
    const evidence = await readEvidence(db, normalized.map((record) => record.hash));
    return {
      success: true,
      items: normalized.map((record) => artifactFromIntel(record, evidence.get(record.hash))),
      total,
      page,
      limit,
      hasMore: page * limit < total,
      totalIsApproximate: false,
      asOf: now.toISOString(),
      scope: "sha256_observations",
      dataSource: "enrichment_records",
    };
  }

  return readEventFallback(db, query, page, limit, now);
}
