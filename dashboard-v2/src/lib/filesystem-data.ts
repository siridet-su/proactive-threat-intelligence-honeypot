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

const SESSION_CWD_HISTORY_ACTIONS = ["entered", "changed", "failed_change"];

function validHistoryStringExpression(field: string): Document {
  return {
    $cond: [
      { $eq: [{ $type: field }, "string"] },
      {
        $cond: [
          { $ne: [{ $trim: { input: field } }, ""] },
          field,
          null,
        ],
      },
      null,
    ],
  };
}

function validHistoryDateExpression(field: string): Document {
  return {
    $cond: [
      { $in: [{ $type: field }, ["date", "string"]] },
      { $convert: { input: field, to: "date", onError: null, onNull: null } },
      null,
    ],
  };
}

function validHistoryIdFallbackExpression(): Document {
  const convertedId = {
    $convert: {
      input: "$_id",
      to: "string",
      onError: null,
      onNull: null,
    },
  };
  return {
    $let: {
      vars: { convertedId },
      in: {
        $cond: [
          { $ne: ["$$convertedId", null] },
          {
            $cond: [
              { $ne: [{ $trim: { input: "$$convertedId" } }, ""] },
              "$$convertedId",
              null,
            ],
          },
          null,
        ],
      },
    },
  };
}

/**
 * Builds the database-side valid-event contract used by history pagination.
 *
 * The contract deliberately mirrors normalizeHistoryEvent: a document is
 * valid only when it has a non-blank session identifier (sessionId or
 * session_id), a parseable at/timestamp (at preferred), a non-blank eventId
 * or _id fallback, and one of the three supported actions. The projection
 * makes those effective values canonical before sorting, cursor comparison,
 * counting, or page limiting.
 */
export function buildSessionCwdHistoryPipeline(
  sessionId: string,
  cursor: string | null,
  pageSize: number,
): Document[] {
  const limit = Math.max(1, Math.floor(pageSize));
  const effectiveSessionId = {
    $let: {
      vars: {
        canonical: validHistoryStringExpression("$sessionId"),
        legacy: validHistoryStringExpression("$session_id"),
      },
      in: { $ifNull: ["$$canonical", "$$legacy"] },
    },
  };
  const effectiveAt = {
    $ifNull: [validHistoryDateExpression("$at"), validHistoryDateExpression("$timestamp")],
  };
  const effectiveEventId = {
    $ifNull: [
      validHistoryStringExpression("$eventId"),
      validHistoryIdFallbackExpression(),
    ],
  };

  const decodedCursor = decodeHistoryCursor(cursor);
  const cursorMatch = decodedCursor
    ? {
        $match: {
          $or: [
            { at: { $lt: new Date(decodedCursor.at) } },
            { at: new Date(decodedCursor.at), eventId: { $lt: decodedCursor.id } },
          ],
        },
      }
    : null;

  const itemsPipeline: Document[] = [];
  if (cursorMatch) itemsPipeline.push(cursorMatch);
  itemsPipeline.push({ $sort: { at: -1, eventId: -1 } }, { $limit: limit + 1 });

  return [
    // This initial OR is indexable on either canonical or legacy session key.
    { $match: { $or: [{ sessionId }, { session_id: sessionId }] } },
    {
      $set: {
        effectiveSessionId,
        effectiveAt,
        effectiveEventId,
      },
    },
    {
      $match: {
        $expr: {
          $and: [
            { $eq: ["$effectiveSessionId", sessionId] },
            { $ne: ["$effectiveAt", null] },
            { $ne: ["$effectiveEventId", null] },
            { $ne: ["$effectiveEventId", ""] },
            { $in: ["$action", SESSION_CWD_HISTORY_ACTIONS] },
          ],
        },
      },
    },
    {
      $project: {
        _id: 0,
        sessionId: "$effectiveSessionId",
        at: "$effectiveAt",
        eventId: "$effectiveEventId",
        sequence: 1,
        fromPath: 1,
        toPath: 1,
        action: 1,
        status: 1,
        sourceEventId: 1,
      },
    },
    {
      $facet: {
        items: itemsPipeline,
        totalItems: [{ $count: "count" }],
        totalSuccessfulItems: [
          { $match: { action: { $ne: "failed_change" } } },
          { $count: "count" },
        ],
      },
    },
  ];
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

export function buildAuditSearchRegexString(search: string | null | undefined): string | null {
  const trimmed = search?.trim();
  if (!trimmed) return null;
  return trimmed.slice(0, 100).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export function normalizeAuditTargetPath(targetPath: string | null | undefined): string | null {
  if (!targetPath) return null;
  let norm = targetPath.trim();
  while (norm.length > 1 && norm.endsWith("/")) {
    norm = norm.slice(0, -1);
  }
  if (!norm || norm === "all") return null;
  return norm;
}

export function buildAuditTargetPathRegexString(targetPath: string | null | undefined): string | null {
  const norm = normalizeAuditTargetPath(targetPath);
  if (!norm || norm === "/") return null;
  const escaped = norm.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return `^${escaped}(/.*)?$`;
}

export function buildAuditSessionsQuery(options: {
  search?: string | null;
  cursor?: string | null;
}): Document {
  const conditions: Document[] = [
    { "lifecycle.status": "closed" },
    { "cwdState.path": { $type: "string", $ne: "" } },
  ];

  const searchRegexStr = buildAuditSearchRegexString(options.search);
  if (searchRegexStr) {
    const rx = new RegExp(searchRegexStr, "i");
    conditions.push({
      $or: [
        { sessionId: { $regex: rx } },
        { session_id: { $regex: rx } },
        { sourceIp: { $regex: rx } },
        { "cwdState.path": { $regex: rx } },
      ],
    });
  }

  if (typeof options.cursor === "string" && options.cursor.trim()) {
    const decoded = decodeAuditSessionCursor(options.cursor);
    if (decoded) {
      const cursorDate = new Date(decoded.closedAt);
      if (!Number.isNaN(cursorDate.getTime()) && decoded.sessionId) {
        conditions.push({
          $or: [
            { "lifecycle.closedAt": { $lt: cursorDate } },
            {
              "lifecycle.closedAt": cursorDate,
              $or: [
                { sessionId: { $lt: decoded.sessionId } },
                { session_id: { $lt: decoded.sessionId } },
              ],
            },
          ],
        });
      } else {
        conditions.push({ $expr: false });
      }
    } else {
      conditions.push({ $expr: false });
    }
  }

  return conditions.length === 1 ? conditions[0] : { $and: conditions };
}

export interface AuditScopingPipelineOptions {
  search?: string | null;
  targetPath?: string | null;
  hideHome?: boolean;
  historyCollectionName?: string;
}

export interface AuditSessionsPipelineOptions extends AuditScopingPipelineOptions {
  cursor?: string | null;
  limit?: number;
}

export function buildAuditScopingStages(options: AuditScopingPipelineOptions): Document[] {
  const historyCollection = options.historyCollectionName ?? "cwd_events";
  const searchRegexStr = buildAuditSearchRegexString(options.search);
  const targetRegexStr = buildAuditTargetPathRegexString(options.targetPath);

  return [
    {
      $match: {
        "lifecycle.status": "closed",
        "cwdState.path": { $type: "string", $ne: "" },
      },
    },
    {
      $addFields: {
        effectiveSessionId: { $ifNull: ["$sessionId", "$session_id"] },
      },
    },
    {
      $lookup: {
        from: historyCollection,
        let: { sid: "$effectiveSessionId" },
        pipeline: [
          {
            $match: {
              $expr: {
                $and: [
                  { $in: ["$action", ["entered", "changed", "failed_change"]] },
                  { $or: [{ $eq: ["$sessionId", "$$sid"] }, { $eq: ["$session_id", "$$sid"] }] },
                ],
              },
            },
          },
          {
            $project: {
              fromPath: 1,
              successfulToPath: {
                $cond: [{ $eq: ["$action", "failed_change"] }, null, "$toPath"],
              },
            },
          },
        ],
        as: "historyEvents",
      },
    },
    {
      $addFields: {
        cwdPath: "$cwdState.path",
        visitedPaths: {
          $filter: {
            input: {
              $setUnion: [
                ["$cwdState.path"],
                "$historyEvents.fromPath",
                "$historyEvents.successfulToPath",
              ],
            },
            as: "p",
            cond: {
              $and: [
                { $ne: ["$$p", null] },
                { $ne: ["$$p", ""] },
                { $regexMatch: { input: "$$p", regex: "^/" } },
              ],
            },
          },
        },
        eventCount: { $size: "$historyEvents" },
      },
    },
    {
      $addFields: {
        nonRootPaths: {
          $filter: {
            input: "$visitedPaths",
            as: "p",
            cond: { $ne: ["$$p", "/"] },
          },
        },
      },
    },
    {
      $addFields: {
        hasHomePath: {
          $anyElementTrue: {
            $map: {
              input: "$nonRootPaths",
              as: "p",
              in: {
                $or: [
                  { $eq: ["$$p", "/home"] },
                  { $regexMatch: { input: "$$p", regex: "^/home/" } },
                ],
              },
            },
          },
        },
        hasOutsideHomePath: {
          $anyElementTrue: {
            $map: {
              input: "$nonRootPaths",
              as: "p",
              in: {
                $and: [
                  { $ne: ["$$p", "/home"] },
                  { $not: { $regexMatch: { input: "$$p", regex: "^/home/" } } },
                ],
              },
            },
          },
        },
      },
    },
    {
      $addFields: {
        homeOnly: {
          $and: ["$hasHomePath", { $not: "$hasOutsideHomePath" }],
        },
        matchesSearch: searchRegexStr
          ? {
              $or: [
                { $regexMatch: { input: "$effectiveSessionId", regex: searchRegexStr, options: "i" } },
                { $regexMatch: { input: { $ifNull: ["$sourceIp", ""] }, regex: searchRegexStr, options: "i" } },
                { $regexMatch: { input: "$cwdPath", regex: searchRegexStr, options: "i" } },
              ],
            }
          : true,
        matchesTarget: targetRegexStr
          ? {
              $anyElementTrue: {
                $map: {
                  input: "$visitedPaths",
                  as: "p",
                  in: { $regexMatch: { input: "$$p", regex: targetRegexStr } },
                },
              },
            }
          : true,
      },
    },
    {
      $addFields: {
        matchesFilter: {
          $and: [
            "$matchesSearch",
            "$matchesTarget",
            options.hideHome ? { $not: "$homeOnly" } : true,
          ],
        },
      },
    },
  ];
}

export function buildAuditSessionsPipeline(options: AuditSessionsPipelineOptions): Document[] {
  const limit = Math.max(1, Math.min(100, options.limit ?? 25));
  const stages = buildAuditScopingStages(options);

  stages.push({
    $match: {
      matchesFilter: true,
    },
  });

  let cursorMatch: Document | null = null;
  if (typeof options.cursor === "string" && options.cursor.trim()) {
    const decoded = decodeAuditSessionCursor(options.cursor);
    if (decoded) {
      const cursorDate = new Date(decoded.closedAt);
      if (!Number.isNaN(cursorDate.getTime()) && decoded.sessionId) {
        cursorMatch = {
          $or: [
            { "lifecycle.closedAt": { $lt: cursorDate } },
            {
              "lifecycle.closedAt": { $eq: cursorDate },
              effectiveSessionId: { $lt: decoded.sessionId },
            },
          ],
        };
      } else {
        cursorMatch = { $expr: false };
      }
    } else {
      cursorMatch = { $expr: false };
    }
  }

  stages.push({
    $facet: {
      total: [
        { $count: "count" },
      ],
      items: [
        ...(cursorMatch ? [{ $match: cursorMatch }] : []),
        {
          $sort: {
            "lifecycle.closedAt": -1,
            effectiveSessionId: -1,
          },
        },
        { $limit: limit + 1 },
      ],
    },
  });

  return stages;
}

export function buildAuditSummaryPipeline(options: AuditScopingPipelineOptions): Document[] {
  const stages = buildAuditScopingStages(options);

  stages.push({
    $facet: {
      overview: [
        {
          $group: {
            _id: null,
            totalSessions: { $sum: 1 },
            homeOnlyCount: { $sum: { $cond: ["$homeOnly", 1, 0] } },
            matchingCount: { $sum: { $cond: ["$matchesFilter", 1, 0] } },
          },
        },
      ],
      distinctPaths: [
        { $unwind: "$nonRootPaths" },
        {
          $group: {
            _id: "$nonRootPaths",
            sessionCount: { $sum: 1 },
          },
        },
        { $sort: { sessionCount: -1, _id: 1 } },
        { $limit: 100 },
        {
          $project: {
            _id: 0,
            path: "$_id",
            sessionCount: 1,
          },
        },
      ],
    },
  });

  return stages;
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
