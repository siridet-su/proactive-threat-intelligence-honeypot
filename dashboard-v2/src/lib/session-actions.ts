import "server-only";

import { randomUUID } from "crypto";
import { MongoServerError, type Document } from "mongodb";

import type { SessionTerminateAction, SessionTerminateActionStatus } from "@/lib/dashboardTypes";
import { getMongoClient } from "@/lib/mongodb";

const DATABASE_NAME = "honeypot_db";
const ACTIONS_COLLECTION = "session_response_actions";
const SESSION_STATE_COLLECTION = "cwd_session_state";
const VERIFICATION_TIMEOUT_MS = 20_000;

let actionIndexes: Promise<void> | null = null;

async function ensureActionIndexes() {
  if (actionIndexes) return actionIndexes;
  actionIndexes = (async () => {
    const client = await getMongoClient();
    const actions = client.db(DATABASE_NAME).collection(ACTIONS_COLLECTION);
    await Promise.all([
      actions.createIndex({ actionId: 1 }, { unique: true, name: "response_action_id_unique" }),
      actions.createIndex(
        { sessionId: 1, action: 1, open: 1 },
        { unique: true, partialFilterExpression: { open: true }, name: "one_open_response_action_per_session" },
      ),
      actions.createIndex({ sessionId: 1, requestedAt: -1 }, { name: "response_action_session_time" }),
      actions.createIndex({ requestedAt: 1 }, { expireAfterSeconds: 90 * 24 * 60 * 60, name: "response_action_retention" }),
    ]);
  })();
  return actionIndexes;
}

function asDateString(value: unknown): string | null {
  if (value instanceof Date && Number.isFinite(value.getTime())) return value.toISOString();
  if (typeof value === "string") {
    const timestamp = Date.parse(value);
    if (Number.isFinite(timestamp)) return new Date(timestamp).toISOString();
  }
  return null;
}

function asStatus(value: unknown): SessionTerminateActionStatus {
  return value === "requested" || value === "delivered" || value === "verified" || value === "failed" ? value : "failed";
}

function normalizeAction(document: Document): SessionTerminateAction {
  return {
    actionId: String(document.actionId ?? ""),
    sessionId: String(document.sessionId ?? ""),
    action: "terminate_session",
    status: asStatus(document.status),
    requestedBy: String(document.requestedBy ?? ""),
    requestedAt: asDateString(document.requestedAt) ?? new Date(0).toISOString(),
    deliveredAt: asDateString(document.deliveredAt),
    verifiedAt: asDateString(document.verifiedAt),
    failureCategory: typeof document.failureCategory === "string" ? document.failureCategory : null,
  };
}

export async function sessionIsActive(sessionId: string): Promise<boolean> {
  const client = await getMongoClient();
  const state = await client.db(DATABASE_NAME).collection(SESSION_STATE_COLLECTION).findOne(
    { sessionId },
    { projection: { "lifecycle.status": 1 } },
  );
  return state?.lifecycle?.status === "active";
}

export async function createTerminateAction(sessionId: string, requestedBy: string): Promise<SessionTerminateAction> {
  await ensureActionIndexes();
  const client = await getMongoClient();
  const actions = client.db(DATABASE_NAME).collection(ACTIONS_COLLECTION);
  const existing = await actions.findOne({ sessionId, action: "terminate_session", open: true }, { sort: { requestedAt: -1 } });
  if (existing) return normalizeAction(existing);

  const document = {
    actionId: randomUUID(),
    sessionId,
    action: "terminate_session",
    status: "requested" as const,
    requestedBy,
    requestedAt: new Date(),
    deliveredAt: null,
    verifiedAt: null,
    failureCategory: null,
    open: true,
  };
  try {
    await actions.insertOne(document);
  } catch (error) {
    if (!(error instanceof MongoServerError) || error.code !== 11000) throw error;
    const concurrent = await actions.findOne({ sessionId, action: "terminate_session", open: true });
    if (!concurrent) throw error;
    return normalizeAction(concurrent);
  }
  return normalizeAction(document);
}

export async function markTerminateActionDelivered(actionId: string): Promise<SessionTerminateAction | null> {
  const client = await getMongoClient();
  const result = await client.db(DATABASE_NAME).collection(ACTIONS_COLLECTION).findOneAndUpdate(
    { actionId, status: "requested" },
    { $set: { status: "delivered", deliveredAt: new Date(), failureCategory: null } },
    { returnDocument: "after" },
  );
  return result ? normalizeAction(result) : null;
}

export async function markTerminateActionFailed(actionId: string, failureCategory: string): Promise<SessionTerminateAction | null> {
  const client = await getMongoClient();
  const result = await client.db(DATABASE_NAME).collection(ACTIONS_COLLECTION).findOneAndUpdate(
    { actionId, status: { $in: ["requested", "delivered"] } },
    { $set: { status: "failed", failureCategory, open: false } },
    { returnDocument: "after" },
  );
  return result ? normalizeAction(result) : null;
}

export interface TerminateActionWithState {
  action: SessionTerminateAction | null;
  active: boolean;
}

/**
 * Database operations documentation:
 *
 * 1. Pending actionId poll path (normal):
 *    - 1 MongoDB read: Single aggregation pipeline on ACTIONS_COLLECTION matching
 *      { actionId, sessionId, action: "terminate_session" } with $lookup joining
 *      SESSION_STATE_COLLECTION (cwd_session_state) for lifecycle status and closedAt.
 *    - 0 MongoDB writes: When the action remains in "requested" or "delivered" status
 *      and the session is active or not yet verifiably closed.
 *
 * 2. Terminal actionId poll path (already resolved):
 *    - 1 MongoDB read: Same aggregation pipeline returns action already in "verified" or "failed" status.
 *    - 0 MongoDB writes.
 *
 * 3. Terminal reconciliation paths (state transition):
 *    - 1 MongoDB read: Aggregation pipeline reads action and session lifecycle.
 *    - 1 MongoDB write: Atomic findOneAndUpdate on ACTIONS_COLLECTION:
 *      a) Verified: When session lifecycle status is "closed" and closedAt >= requestedAt.
 *      b) Failed: When verification timeout (20s) has elapsed.
 *    - Both transitions match { status: { $in: ["requested", "delivered"] } } ensuring
 *      concurrent reconciliation is idempotent and terminal states cannot regress or duplicate.
 *
 * 4. Initial capability path (without actionId):
 *    - 1 MongoDB read: Aggregation pipeline matching { sessionId, action: "terminate_session" }
 *      sorted by requestedAt descending (limit 1) with $lookup to SESSION_STATE_COLLECTION.
 *    - If no action exists yet for the session, 1 findOne read on SESSION_STATE_COLLECTION for liveness.
 */
export async function getTerminateActionWithState(
  sessionId: string,
  actionId?: string,
): Promise<TerminateActionWithState> {
  await ensureActionIndexes();
  const client = await getMongoClient();
  const db = client.db(DATABASE_NAME);

  const matchFilter: Document = actionId
    ? { actionId, sessionId, action: "terminate_session" }
    : { sessionId, action: "terminate_session" };

  const pipeline: Document[] = [
    { $match: matchFilter },
    { $sort: { requestedAt: -1 } },
    { $limit: 1 },
    {
      $lookup: {
        from: SESSION_STATE_COLLECTION,
        localField: "sessionId",
        foreignField: "sessionId",
        as: "sessionDocs",
      },
    },
    {
      $project: {
        actionId: 1,
        sessionId: 1,
        action: 1,
        status: 1,
        requestedBy: 1,
        requestedAt: 1,
        deliveredAt: 1,
        verifiedAt: 1,
        failureCategory: 1,
        open: 1,
        sessionLifecycle: { $arrayElemAt: ["$sessionDocs.lifecycle", 0] },
      },
    },
  ];

  const [document] = await db.collection(ACTIONS_COLLECTION).aggregate(pipeline).toArray();

  if (!document) {
    const state = await db.collection(SESSION_STATE_COLLECTION).findOne(
      { sessionId },
      { projection: { "lifecycle.status": 1 } },
    );
    return {
      action: null,
      active: state?.lifecycle?.status === "active",
    };
  }

  const active = document.sessionLifecycle?.status === "active";
  const action = normalizeAction(document);

  // If already terminal, return directly without write operations
  if (action.status === "verified") {
    return { action, active: false };
  }
  if (action.status === "failed") {
    return { action, active };
  }

  // Only requested or delivered actions can transition to terminal verified or failed
  const closedAt = asDateString(document.sessionLifecycle?.closedAt);
  const isClosed = document.sessionLifecycle?.status === "closed";
  const isQualifyingClosure = isClosed && closedAt && Date.parse(closedAt) >= Date.parse(action.requestedAt);

  if (isQualifyingClosure) {
    const updated = await db.collection(ACTIONS_COLLECTION).findOneAndUpdate(
      { actionId: action.actionId, sessionId: action.sessionId, status: { $in: ["requested", "delivered"] } },
      { $set: { status: "verified", verifiedAt: new Date(closedAt), failureCategory: null, open: false } },
      { returnDocument: "after" },
    );
    return {
      action: updated ? normalizeAction(updated) : action,
      active: false,
    };
  }

  if (Date.now() - Date.parse(action.requestedAt) > VERIFICATION_TIMEOUT_MS) {
    const failed = await db.collection(ACTIONS_COLLECTION).findOneAndUpdate(
      { actionId: action.actionId, sessionId: action.sessionId, status: { $in: ["requested", "delivered"] } },
      { $set: { status: "failed", failureCategory: "verification_timeout", open: false } },
      { returnDocument: "after" },
    );
    return {
      action: failed ? normalizeAction(failed) : action,
      active,
    };
  }

  return {
    action,
    active,
  };
}

export async function getTerminateAction(sessionId: string, actionId?: string): Promise<SessionTerminateAction | null> {
  const result = await getTerminateActionWithState(sessionId, actionId);
  return result.action;
}
