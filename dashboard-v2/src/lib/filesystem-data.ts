import { Long, type Document } from "mongodb";

import type {
  CwdObservationStatus,
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
