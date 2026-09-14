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

export async function getTerminateAction(sessionId: string, actionId?: string): Promise<SessionTerminateAction | null> {
  await ensureActionIndexes();
  const client = await getMongoClient();
  const db = client.db(DATABASE_NAME);
  const document = await db.collection(ACTIONS_COLLECTION).findOne(
    actionId ? { actionId, sessionId, action: "terminate_session" } : { sessionId, action: "terminate_session" },
    { sort: { requestedAt: -1 } },
  );
  if (!document) return null;
  const action = normalizeAction(document);
  if (action.status !== "requested" && action.status !== "delivered") return action;

  const state = await db.collection(SESSION_STATE_COLLECTION).findOne(
    { sessionId },
    { projection: { lifecycle: 1 } },
  );
  const closedAt = asDateString(state?.lifecycle?.closedAt);
  if (state?.lifecycle?.status === "closed" && closedAt && Date.parse(closedAt) >= Date.parse(action.requestedAt)) {
    const updated = await db.collection(ACTIONS_COLLECTION).findOneAndUpdate(
      { actionId: action.actionId, status: { $in: ["requested", "delivered"] } },
      { $set: { status: "verified", verifiedAt: new Date(closedAt), failureCategory: null, open: false } },
      { returnDocument: "after" },
    );
    return updated ? normalizeAction(updated) : action;
  }
  if (Date.now() - Date.parse(action.requestedAt) > VERIFICATION_TIMEOUT_MS) {
    return markTerminateActionFailed(action.actionId, "verification_timeout");
  }
  return action;
}
