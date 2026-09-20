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
  sessionIds?: string[];
  projectionOverflow?: "exclude" | "only";
  from?: number;
  to?: number;
}

/** Version written by processor-agent into cwd_audit_projection. */
export const AUDIT_PROJECTION_VERSION = "cwd_audit_projection.v2";

// FA-016 source-row contract. Processor and dashboard both canonicalize the
// first nonblank sessionId/session_id value with surrounding whitespace
// removed, require a closed row with a parseable BSON date/string closedAt,
// and accept only a trimmed absolute cwdState.path. The projection stores the
// resulting canonical sessionId. Invalid rows are outside the retained Audit
// directory and must never hold readiness false.
function trimmedStringExpression(field: string): Document {
  return {
    $cond: [
      { $eq: [{ $type: field }, "string"] },
      { $trim: { input: field } },
      null,
    ],
  };
}

function canonicalAuditSessionIdExpression(): Document {
  return {
    $let: {
      vars: {
        sessionId: trimmedStringExpression("$sessionId"),
        legacySessionId: trimmedStringExpression("$session_id"),
      },
      in: {
        $cond: [
          { $and: [{ $ne: ["$$sessionId", null] }, { $ne: ["$$sessionId", ""] }] },
          "$$sessionId",
          { $cond: [{ $and: [{ $ne: ["$$legacySessionId", null] }, { $ne: ["$$legacySessionId", ""] }] }, "$$legacySessionId", null] },
        ],
      },
    },
  };
}

function auditClosedAtExpression(): Document {
  return {
    $convert: {
      input: "$lifecycle.closedAt",
      to: "date",
      onError: null,
      onNull: null,
    },
  };
}

function auditSourceEligibilityExpression(): Document {
  return {
    $and: [
      { $ne: [canonicalAuditSessionIdExpression(), null] },
      { $ne: [auditClosedAtExpression(), null] },
      { $regexMatch: { input: { $ifNull: [trimmedStringExpression("$cwdState.path"), ""] }, regex: "^/" } },
    ],
  };
}

/**
 * Bounded readiness probe shared by the dashboard and processor contract.
 *
 * The generation branch detects current-protocol work. The separate cutover
 * branch below detects eligible v1/unversioned rows from an old rolling writer
 * that published after the v2 marker and therefore has no pending field.
 */
export function buildAuditProjectionReadinessQuery(options: { includeVersionMigration?: boolean } = {}): Document {
  const pending = { auditProjectionPendingGeneration: { $exists: true } };
  const work = options.includeVersionMigration
    ? { $or: [{ auditProjectionVersion: { $ne: AUDIT_PROJECTION_VERSION } }, pending] }
    : pending;
  return {
    "lifecycle.status": "closed",
    $expr: auditSourceEligibilityExpression(),
    ...work,
  };
}

/** Separate indexed probe for the authoritative event-level outbox. */
export function buildAuditProjectionEventReadinessQuery(): Document {
  return { auditProjectionPending: true };
}

/**
 * Bounded cutover probe for rows written by a pre-v2 rolling writer. Once the
 * marker is published, any eligible row still lacking v2 is reconciliation
 * work; rows that were present before publication were already converged by
 * the processor before it published the marker.
 */
export function buildAuditProjectionCutoverReadinessQuery(): Document {
  return {
    "lifecycle.status": "closed",
    $expr: auditSourceEligibilityExpression(),
    auditProjectionVersion: { $ne: AUDIT_PROJECTION_VERSION },
  };
}

export interface AuditSessionsPipelineOptions extends AuditScopingPipelineOptions {
  cursor?: string | null;
  limit?: number;
}

export function buildAuditScopingStages(options: AuditScopingPipelineOptions): Document[] {
  const historyCollection = options.historyCollectionName ?? "cwd_events";
  const searchRegexStr = buildAuditSearchRegexString(options.search);
  const targetRegexStr = buildAuditTargetPathRegexString(options.targetPath);

  const stages: Document[] = [
    {
      $match: {
        "lifecycle.status": "closed",
        "cwdState.path": { $type: "string", $ne: "" },
      },
    },
    {
      $addFields: {
        effectiveSessionId: canonicalAuditSessionIdExpression(),
        effectiveClosedAt: auditClosedAtExpression(),
        effectiveCwdPath: trimmedStringExpression("$cwdState.path"),
      },
    },
    { $match: { $expr: auditSourceEligibilityExpression() } },
  ];

  if (options.from != null || options.to != null) {
    const timeMatch: Document = {};
    if (options.from != null) timeMatch.$gte = new Date(options.from);
    if (options.to != null) timeMatch.$lte = new Date(options.to);
    stages.push({ $match: { effectiveClosedAt: timeMatch } });
  }

  if (options.sessionIds?.length) {
    stages.push({ $match: { effectiveSessionId: { $in: options.sessionIds } } });
  }

  stages.push({
      $lookup: {
        from: historyCollection,
        let: { sid: "$effectiveSessionId" },
        pipeline: [
          {
            $match: {
              $expr: {
                $and: [
                  { $in: ["$action", ["entered", "changed", "failed_change"]] },
                  { $or: [{ $eq: [trimmedStringExpression("$sessionId"), "$$sid"] }, { $eq: [trimmedStringExpression("$session_id"), "$$sid"] }] },
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
        cwdPath: "$effectiveCwdPath",
        visitedPaths: {
          $filter: {
            input: {
              $setUnion: [
                ["$effectiveCwdPath"],
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
  );
  return stages;
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
            { effectiveClosedAt: { $lt: cursorDate } },
            {
              effectiveClosedAt: { $eq: cursorDate },
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
            effectiveClosedAt: -1,
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

function buildAuditProjectionBaseMatch(options: AuditScopingPipelineOptions = {}): Document {
  const match: Document = {
    "lifecycle.status": "closed",
    "cwdState.path": { $type: "string", $regex: "^/" },
    auditProjectionVersion: AUDIT_PROJECTION_VERSION,
    sessionId: { $type: "string", $ne: "" },
    "lifecycle.closedAt": { $type: "date" },
  };
  if (options.projectionOverflow === "exclude") match.auditPathsOverflow = { $ne: true };
  if (options.projectionOverflow === "only") match.auditPathsOverflow = true;
  return match;
}

function buildAuditProjectionFilterMatch(options: AuditScopingPipelineOptions): Document {
  const match: Document = {};
  const searchRegexStr = buildAuditSearchRegexString(options.search);
  const targetRegexStr = buildAuditTargetPathRegexString(options.targetPath);
  if (searchRegexStr) {
    match.$or = [
      { sessionId: { $regex: searchRegexStr, $options: "i" } },
      { sourceIp: { $regex: searchRegexStr, $options: "i" } },
      { "cwdState.path": { $regex: searchRegexStr, $options: "i" } },
    ];
  }
  if (targetRegexStr) match.auditVisitedPaths = { $elemMatch: { $regex: targetRegexStr } };
  if (options.hideHome) {
    const hideHomeCond = {
      $or: [
        { auditVisitedPaths: { $exists: false } },
        { auditVisitedPaths: { $elemMatch: { $regex: "^(?!/home(/|$))" } } }
      ]
    };
    if (match.$or) {
      match.$and = [{ $or: match.$or }, hideHomeCond];
      delete match.$or;
    } else {
      match.$or = hideHomeCond.$or;
    }
  }
  
  if (options.from != null || options.to != null) {
    match["lifecycle.closedAt"] = match["lifecycle.closedAt"] || {};
    if (options.from != null) Object.assign(match["lifecycle.closedAt"], { $gte: new Date(options.from) });
    if (options.to != null) Object.assign(match["lifecycle.closedAt"], { $lte: new Date(options.to) });
  }

  return match;
}

function buildAuditProjectionFilterExpression(options: AuditScopingPipelineOptions): Document | boolean {
  const searchRegexStr = buildAuditSearchRegexString(options.search);
  const targetRegexStr = buildAuditTargetPathRegexString(options.targetPath);
  const clauses: Document[] = [];
  if (searchRegexStr) {
    clauses.push({
      $or: [
        { $regexMatch: { input: "$sessionId", regex: searchRegexStr, options: "i" } },
        { $regexMatch: { input: { $ifNull: ["$sourceIp", ""] }, regex: searchRegexStr, options: "i" } },
        { $regexMatch: { input: "$cwdState.path", regex: searchRegexStr, options: "i" } },
      ],
    });
  }
  if (targetRegexStr) {
    clauses.push({
      $anyElementTrue: {
        $map: {
          input: { $ifNull: ["$auditVisitedPaths", []] },
          as: "path",
          in: { $regexMatch: { input: "$$path", regex: targetRegexStr } },
        },
      },
    });
  }
  if (options.hideHome) {
    clauses.push({
      $or: [
        { $eq: [{ $type: "$auditVisitedPaths" }, "missing"] },
        {
          $anyElementTrue: {
            $map: {
              input: { $ifNull: ["$auditVisitedPaths", []] },
              as: "path",
              in: { $not: { $regexMatch: { input: "$path", regex: "^/home(/|$)" } } }
            }
          }
        }
      ]
    });
  }
  
  if (options.from != null) clauses.push({ $gte: ["$lifecycle.closedAt", new Date(options.from)] });
  if (options.to != null) clauses.push({ $lte: ["$lifecycle.closedAt", new Date(options.to)] });

  return clauses.length ? { $and: clauses } : true;
}

/**
 * Builds the post-backfill Audit read model path. It deliberately contains no
 * $lookup: every filterable history fact is already owned by the processor's
 * durable projection. The source-state pipeline above remains the explicit
 * migration fallback until the processor writes its completion marker.
 */
function buildAuditProjectionCursorMatch(options: AuditSessionsPipelineOptions): Document | null {
  if (typeof options.cursor !== "string" || !options.cursor.trim()) return null;
  const decoded = decodeAuditSessionCursor(options.cursor);
  if (decoded) {
    const cursorDate = new Date(decoded.closedAt);
    return !Number.isNaN(cursorDate.getTime()) && decoded.sessionId
      ? {
          $or: [
            { "lifecycle.closedAt": { $lt: cursorDate } },
            { "lifecycle.closedAt": cursorDate, sessionId: { $lt: decoded.sessionId } },
          ],
        }
      : { $expr: false };
  }
  return { $expr: false };
}

function buildAuditProjectionBaseStages(options: AuditScopingPipelineOptions): Document[] {
  const stages: Document[] = [{ $match: buildAuditProjectionBaseMatch(options) }];
  const filterMatch = buildAuditProjectionFilterMatch(options);
  if (Object.keys(filterMatch).length) stages.push({ $match: filterMatch });
  return stages;
}

/**
 * The page query is intentionally separate from the exact count query. This
 * keeps cursor/sort/limit before materialization for the common indexed path.
 */
export function buildAuditProjectionItemPipeline(options: AuditSessionsPipelineOptions): Document[] {
  const limit = Math.max(1, Math.min(100, options.limit ?? 25));
  const stages = buildAuditProjectionBaseStages(options);
  const cursorMatch = buildAuditProjectionCursorMatch(options);
  if (cursorMatch) stages.push({ $match: cursorMatch });
  stages.push({ $sort: { "lifecycle.closedAt": -1, sessionId: -1 } }, { $limit: limit + 1 });
  return stages;
}

export function buildAuditProjectionCountPipeline(options: AuditScopingPipelineOptions): Document[] {
  return [...buildAuditProjectionBaseStages(options), { $count: "count" }];
}

function buildAuditProjectionOverflowSourceStages(options: AuditScopingPipelineOptions): Document[] {
  const stages = buildAuditScopingStages({ ...options, projectionOverflow: undefined });
  stages.push(
    { $match: { matchesFilter: true } },
    {
      $lookup: {
        from: "cwd_audit_projection",
        let: { sessionId: "$effectiveSessionId" },
        pipeline: [
          {
            $match: {
              $expr: {
                $and: [
                  { $eq: ["$sessionId", "$$sessionId"] },
                  { $eq: ["$auditProjectionVersion", AUDIT_PROJECTION_VERSION] },
                  { $eq: ["$auditPathsOverflow", true] },
                  { $eq: ["$lifecycle.status", "closed"] },
                ],
              },
            },
          },
          { $project: { _id: 1 } },
        ],
        as: "overflowProjection",
      },
    },
    { $match: { $expr: { $gt: [{ $size: "$overflowProjection" }, 0] } } },
    {
      $set: {
        sessionId: "$effectiveSessionId",
        "lifecycle.closedAt": "$effectiveClosedAt",
        auditVisitedPaths: "$visitedPaths",
        auditHomeOnly: "$homeOnly",
        auditEventCount: "$eventCount",
      },
    },
    { $unset: "overflowProjection" },
  );
  return stages;
}

function buildAuditProjectionOverflowUnionStages(options: AuditSessionsPipelineOptions): Document[] {
  const stages = buildAuditProjectionBaseStages({ ...options, projectionOverflow: "exclude" });
  stages.push({
    $unionWith: {
      coll: "cwd_session_state",
      pipeline: buildAuditProjectionOverflowSourceStages({
        search: options.search,
        targetPath: options.targetPath,
        hideHome: options.hideHome,
        historyCollectionName: options.historyCollectionName,
      }),
    },
  });
  const cursorMatch = buildAuditProjectionCursorMatch(options);
  if (cursorMatch) stages.push({ $match: cursorMatch });
  return stages;
}

/**
 * Exact overflow composition for the exceptional path population. The normal
 * path remains projection-backed; only when an overflow projection exists do
 * we join the bounded projection population to authoritative source rows.
 */
export function buildAuditProjectionOverflowItemPipeline(options: AuditSessionsPipelineOptions): Document[] {
  const limit = Math.max(1, Math.min(100, options.limit ?? 25));
  return [
    ...buildAuditProjectionOverflowUnionStages(options),
    { $sort: { "lifecycle.closedAt": -1, sessionId: -1 } },
    { $limit: limit + 1 },
  ];
}

export function buildAuditProjectionOverflowCountPipeline(options: AuditScopingPipelineOptions): Document[] {
  return [...buildAuditProjectionOverflowUnionStages({ ...options, cursor: null } as AuditSessionsPipelineOptions), { $count: "count" }];
}

// Compatibility name for callers that only need the item plan. Counts are no
// longer combined with this pipeline, so explain output cannot imply that a
// page-sized item query also bounded the exact count.
export const buildAuditProjectionSessionsPipeline = buildAuditProjectionItemPipeline;

export function buildAuditProjectionSummaryPipeline(options: AuditScopingPipelineOptions): Document[] {
  return [
    ...buildAuditProjectionBaseStages({ projectionOverflow: options.projectionOverflow }),
    { $set: { matchesFilter: buildAuditProjectionFilterExpression(options) } },
    {
      $set: {
        nonRootPaths: {
          $filter: {
            input: { $ifNull: ["$auditVisitedPaths", []] },
            as: "path",
            cond: { $ne: ["$$path", "/"] },
          },
        },
      },
    },
    {
      $facet: {
        overview: [
          {
            $group: {
              _id: null,
              totalSessions: { $sum: 1 },
              homeOnlyCount: { $sum: { $cond: ["$auditHomeOnly", 1, 0] } },
              matchingCount: { $sum: { $cond: ["$matchesFilter", 1, 0] } },
            },
          },
        ],
        distinctPaths: [
          { $match: { matchesFilter: true } },
          { $unwind: "$nonRootPaths" },
          { $group: { _id: "$nonRootPaths", sessionCount: { $sum: 1 } } },
          { $sort: { sessionCount: -1, _id: 1 } },
          { $limit: 100 },
          { $project: { _id: 0, path: "$_id", sessionCount: 1 } },
        ],
      },
    },
  ];
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
