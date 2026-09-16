import { Long, type Document } from "mongodb";

import type {
  CwdObservationStatus,
  FilesystemSessionAuditSummary,
  SessionCwdHistoryEvent,
} from "@/lib/dashboardTypes";

export function asString(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value : null;
}

export function asStatus(value: unknown): CwdObservationStatus {
  return value === "observed" || value === "confirmed" || value === "conditional_candidate" || value === "unknown"
    ? value
    : "unknown";
}

export function asDateString(value: unknown): string | null {
  if (typeof value !== "string" && !(value instanceof Date)) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

export function asSequence(value: unknown): string | null {
  if (typeof value === "string" && /^-?\d+$/.test(value)) return value;
  if (typeof value === "bigint") return value.toString();
  if (typeof value === "number" && Number.isSafeInteger(value)) return String(value);
  if (Long.isLong(value)) return value.toString();
  return null;
}

export interface SessionCwdHistoryCursor {
  at: string;
  id: string;
}

export function decodeHistoryCursor(cursor: string | null): SessionCwdHistoryCursor | null {
  if (!cursor) return null;
  try {
    const decoded = JSON.parse(Buffer.from(cursor, "base64url").toString("utf8")) as { at?: unknown; id?: unknown };
    if (typeof decoded.at !== "string" || typeof decoded.id !== "string") return null;
    const at = asDateString(decoded.at);
    return at && decoded.id ? { at, id: decoded.id } : null;
  } catch {
    return null;
  }
}

export function encodeHistoryCursor(event: SessionCwdHistoryEvent): string {
  return Buffer.from(JSON.stringify({ at: event.at, id: event.id })).toString("base64url");
}

export function buildSessionCwdHistoryQuery(sessionId: string, cursor: string | null): Document {
  const sessionScope: Document = {
    $or: [{ sessionId }, { session_id: sessionId }],
  };
  const decoded = decodeHistoryCursor(cursor);
  if (!decoded) return sessionScope;

  const cursorAt = new Date(decoded.at);
  return {
    $and: [
      sessionScope,
      {
        $or: [
          { at: { $lt: cursorAt } },
          { at: cursorAt, eventId: { $lt: decoded.id } },
        ],
      },
    ],
  };
}

export interface AuditSessionCursor {
  closedAt: string;
  sessionId: string;
}

export function decodeAuditSessionCursor(cursor: string | null): AuditSessionCursor | null {
  if (!cursor) return null;
  try {
    const decoded = JSON.parse(Buffer.from(cursor, "base64url").toString("utf8")) as {
      closedAt?: unknown;
      sessionId?: unknown;
    };
    if (typeof decoded.closedAt !== "string" || typeof decoded.sessionId !== "string") return null;
    const closedAt = asDateString(decoded.closedAt);
    return closedAt && decoded.sessionId ? { closedAt, sessionId: decoded.sessionId } : null;
  } catch {
    return null;
  }
}

export function encodeAuditSessionCursor(closedAt: string, sessionId: string): string {
  return Buffer.from(JSON.stringify({ closedAt, sessionId })).toString("base64url");
}

export function buildAuditSessionsQuery(options: {
  search?: string | null;
  cursor?: string | null;
}): Document {
  const conditions: Document[] = [
    { "lifecycle.status": "closed" },
    { "cwdState.path": { $type: "string", $ne: "" } },
  ];

  if (options.search?.trim()) {
    const q = options.search.trim();
    const escaped = q.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const rx = new RegExp(escaped, "i");
    conditions.push({
      $or: [
        { sessionId: { $regex: rx } },
        { sourceIp: { $regex: rx } },
        { "cwdState.path": { $regex: rx } },
      ],
    });
  }

  const decoded = decodeAuditSessionCursor(options.cursor ?? null);
  if (decoded) {
    conditions.push({
      $or: [
        { "lifecycle.closedAt": { $lt: decoded.closedAt } },
        {
          "lifecycle.closedAt": decoded.closedAt,
          sessionId: { $lt: decoded.sessionId },
        },
      ],
    });
  }

  return conditions.length === 1 ? conditions[0] : { $and: conditions };
}

export function normalizeHistoryEvent(document: Document): SessionCwdHistoryEvent | null {
  const sessionId = asString(document.sessionId) ?? asString(document.session_id);
  const at = asDateString(document.at) ?? asDateString(document.timestamp);
  // eventId is the second history sort key, so the public id and cursor use
  // that exact value. _id remains a compatibility fallback for old documents.
  const id = asString(document.eventId) ?? asString(document._id?.toString());
  const action = document.action;
  if (!sessionId || !at || !id || (action !== "entered" && action !== "changed" && action !== "failed_change")) return null;
  return {
    id,
    sessionId,
    sequence: asSequence(document.sequence),
    at,
    fromPath: asString(document.fromPath),
    toPath: asString(document.toPath),
    action,
    status: asStatus(document.status),
    sourceEventId: asString(document.sourceEventId),
  };
}

function canonicalObservedPath(value: unknown): string | null {
  const path = asString(value);
  return path?.startsWith("/") ? path : null;
}

/**
 * Normalizes the result of the MongoDB history aggregation and combines it with
 * the session's current/last CWD. Root is a traversal boundary rather than a
 * home directory, so it does not make an otherwise home-only session unsafe.
 */
export function normalizeSessionAuditSummary(
  currentPath: string | null,
  fromPaths: unknown,
  toPaths: unknown,
  eventCount: unknown,
): FilesystemSessionAuditSummary {
  const visited = new Set<string>();
  const register = (value: unknown) => {
    const path = canonicalObservedPath(value);
    if (path) visited.add(path);
  };

  register(currentPath);
  if (Array.isArray(fromPaths)) fromPaths.forEach(register);
  if (Array.isArray(toPaths)) toPaths.forEach(register);

  const visitedPaths = [...visited].sort((left, right) => left.localeCompare(right));
  const nonRootPaths = visitedPaths.filter((path) => path !== "/");
  const hasHomePath = nonRootPaths.some((path) => path === "/home" || path.startsWith("/home/"));
  const hasOutsideHomePath = nonRootPaths.some((path) => path !== "/home" && !path.startsWith("/home/"));
  const normalizedEventCount = typeof eventCount === "number" && Number.isSafeInteger(eventCount) && eventCount >= 0
    ? eventCount
    : 0;

  return {
    visitedPaths,
    homeOnly: hasHomePath && !hasOutsideHomePath,
    eventCount: normalizedEventCount,
  };
}
