import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("server-only", () => ({}));

import { GET } from "../src/app/api/sessions/[id]/actions/terminate/route";
import { terminateCapabilityFrom } from "../src/components/filesystem/responseActionTypes";
import {
  getTerminateActionWithState,
} from "../src/lib/session-actions";
import {
  resetResponseControlHealthCache,
} from "../src/lib/response-control";
import * as authSession from "../src/lib/auth/session";
import * as mongo from "../src/lib/mongodb";

const VALID_SESSION_ID = "abcdef123456";
const VALID_ACTION_ID = "123e4567-e89b-12d3-a456-426614174000";

describe("Response action status and capability separation (FA-004)", () => {
  beforeEach(() => {
    resetResponseControlHealthCache();
    process.env.COWRIE_RESPONSE_AGENT_URL = "http://100.118.43.30:8788";
    process.env.COWRIE_RESPONSE_AGENT_TOKEN = "01234567890123456789012345678901";
  });

  afterEach(() => {
    resetResponseControlHealthCache();
    vi.restoreAllMocks();
  });

  it("1. Pending status remains requested/delivered after the health cache expires", async () => {
    // Mock admin session
    vi.spyOn(authSession, "getSessionFromRequest").mockResolvedValue({
      sessionId: "s-1",
      operatorId: "op-1",
      role: "admin",
      mustChangePassword: false,
      expiresAt: new Date(Date.now() + 3600_000),
    });
    vi.spyOn(authSession, "isAdmin").mockReturnValue(true);

    // Mock DB aggregation returning a pending delivered action
    const mockActionDoc = {
      actionId: VALID_ACTION_ID,
      sessionId: VALID_SESSION_ID,
      action: "terminate_session",
      status: "delivered",
      requestedBy: "op-1",
      requestedAt: new Date(Date.now() - 5000),
      deliveredAt: new Date(Date.now() - 4000),
      verifiedAt: null,
      failureCategory: null,
      open: true,
      sessionLifecycle: { status: "active" },
    };

    const aggregateMock = vi.fn().mockReturnValue({
      toArray: vi.fn().mockResolvedValue([mockActionDoc]),
    });

    vi.spyOn(mongo, "getMongoClient").mockResolvedValue({
      db: () => ({
        collection: () => ({
          aggregate: aggregateMock,
          createIndex: vi.fn().mockResolvedValue("index"),
        }),
      }),
    } as unknown as ReturnType<typeof mongo.getMongoClient>);

    // Ensure health cache is expired / empty
    resetResponseControlHealthCache();

    // Call GET route with actionId query parameter
    const request = new Request(`http://localhost/api/sessions/${VALID_SESSION_ID}/actions/terminate?actionId=${VALID_ACTION_ID}`);
    const response = await GET(request, { params: Promise.resolve({ id: VALID_SESSION_ID }) });

    expect(response.status).toBe(200);
    const body = await response.json();

    // Action status remains truthfully delivered
    expect(body.action).not.toBeNull();
    expect(body.action.status).toBe("delivered");
    expect(body.action.actionId).toBe(VALID_ACTION_ID);
    expect(body.authorized).toBe(true);
    expect(body.configured).toBe(true);
    // Explicit response contract: 'available' is omitted from status poll responses
    expect(body.available).toBeUndefined();
    expect("available" in body).toBe(false);
  });

  it("2. Status polling never performs an outbound Pi health request", async () => {
    vi.spyOn(authSession, "getSessionFromRequest").mockResolvedValue({
      sessionId: "s-1",
      operatorId: "op-1",
      role: "admin",
      mustChangePassword: false,
      expiresAt: new Date(Date.now() + 3600_000),
    });
    vi.spyOn(authSession, "isAdmin").mockReturnValue(true);

    const fetchSpy = vi.spyOn(globalThis, "fetch");

    const mockActionDoc = {
      actionId: VALID_ACTION_ID,
      sessionId: VALID_SESSION_ID,
      action: "terminate_session",
      status: "requested",
      requestedBy: "op-1",
      requestedAt: new Date(),
      deliveredAt: null,
      verifiedAt: null,
      failureCategory: null,
      open: true,
      sessionLifecycle: { status: "active" },
    };

    vi.spyOn(mongo, "getMongoClient").mockResolvedValue({
      db: () => ({
        collection: () => ({
          aggregate: () => ({
            toArray: vi.fn().mockResolvedValue([mockActionDoc]),
          }),
          createIndex: vi.fn().mockResolvedValue("index"),
        }),
      }),
    } as unknown as ReturnType<typeof mongo.getMongoClient>);

    const request = new Request(`http://localhost/api/sessions/${VALID_SESSION_ID}/actions/terminate?actionId=${VALID_ACTION_ID}`);
    const response = await GET(request, { params: Promise.resolve({ id: VALID_SESSION_ID }) });

    expect(response.status).toBe(200);
    // Crucial requirement: status polling must NEVER initiate outbound Pi health fetch
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("3. Status-only payload does not overwrite a previously known capability with error", () => {
    const statusPayload = {
      authorized: true,
      configured: true,
      action: {
        actionId: VALID_ACTION_ID,
        sessionId: VALID_SESSION_ID,
        action: "terminate_session" as const,
        status: "delivered" as const,
        requestedBy: "op-1",
        requestedAt: new Date().toISOString(),
        deliveredAt: new Date().toISOString(),
        verifiedAt: null,
        failureCategory: null,
      },
    };

    // When previously known capability was "available", status payload preserves it
    expect(terminateCapabilityFrom(statusPayload, "available")).toBe("available");
    // When previously "loading", preserves "loading"
    expect(terminateCapabilityFrom(statusPayload, "loading")).toBe("loading");
    // When previous capability is undefined, defaults safely to "available" (never "error")
    expect(terminateCapabilityFrom(statusPayload)).toBe("available");

    // Explicit probe failure with available: false still maps truthfully to error
    expect(terminateCapabilityFrom({ available: false, authorized: true, configured: true }, "available")).toBe("error");
    // Explicit forbidden maps to forbidden
    expect(terminateCapabilityFrom({ authorized: false, configured: true }, "available")).toBe("forbidden");
    // Explicit unconfigured maps to unconfigured
    expect(terminateCapabilityFrom({ authorized: true, configured: false }, "available")).toBe("unconfigured");
  });

  it("4. One MongoDB read operation for the ordinary pending actionId path", async () => {
    const aggregateSpy = vi.fn().mockReturnValue({
      toArray: vi.fn().mockResolvedValue([
        {
          actionId: VALID_ACTION_ID,
          sessionId: VALID_SESSION_ID,
          action: "terminate_session",
          status: "delivered",
          requestedBy: "op-1",
          requestedAt: new Date(Date.now() - 2000),
          deliveredAt: new Date(Date.now() - 1000),
          verifiedAt: null,
          failureCategory: null,
          open: true,
          sessionLifecycle: { status: "active" },
        },
      ]),
    });
    const findOneSpy = vi.fn();
    const findOneAndUpdateSpy = vi.fn();

    vi.spyOn(mongo, "getMongoClient").mockResolvedValue({
      db: () => ({
        collection: () => ({
          aggregate: aggregateSpy,
          findOne: findOneSpy,
          findOneAndUpdate: findOneAndUpdateSpy,
          createIndex: vi.fn().mockResolvedValue("index"),
        }),
      }),
    } as unknown as ReturnType<typeof mongo.getMongoClient>);

    const result = await getTerminateActionWithState(VALID_SESSION_ID, VALID_ACTION_ID);

    expect(result.action?.status).toBe("delivered");
    expect(result.active).toBe(true);

    // Exactly one MongoDB read operation (the aggregation pipeline)
    expect(aggregateSpy).toHaveBeenCalledOnce();
    // Zero secondary read operations
    expect(findOneSpy).not.toHaveBeenCalled();
    // Zero write operations for pending action
    expect(findOneAndUpdateSpy).not.toHaveBeenCalled();
  });

  it("5. Verified reconciliation from a qualifying closed lifecycle", async () => {
    const requestedAt = new Date("2026-09-16T12:00:00Z");
    const closedAt = new Date("2026-09-16T12:00:05Z"); // Closed 5 seconds AFTER requestedAt

    const aggregateSpy = vi.fn().mockReturnValue({
      toArray: vi.fn().mockResolvedValue([
        {
          actionId: VALID_ACTION_ID,
          sessionId: VALID_SESSION_ID,
          action: "terminate_session",
          status: "delivered",
          requestedBy: "op-1",
          requestedAt,
          deliveredAt: new Date("2026-09-16T12:00:01Z"),
          verifiedAt: null,
          failureCategory: null,
          open: true,
          sessionLifecycle: {
            status: "closed",
            closedAt,
          },
        },
      ]),
    });

    const findOneAndUpdateSpy = vi.fn().mockResolvedValue({
      actionId: VALID_ACTION_ID,
      sessionId: VALID_SESSION_ID,
      action: "terminate_session",
      status: "verified",
      requestedBy: "op-1",
      requestedAt,
      deliveredAt: new Date("2026-09-16T12:00:01Z"),
      verifiedAt: closedAt,
      failureCategory: null,
      open: false,
    });

    vi.spyOn(mongo, "getMongoClient").mockResolvedValue({
      db: () => ({
        collection: () => ({
          aggregate: aggregateSpy,
          findOneAndUpdate: findOneAndUpdateSpy,
          createIndex: vi.fn().mockResolvedValue("index"),
        }),
      }),
    } as unknown as ReturnType<typeof mongo.getMongoClient>);

    const result = await getTerminateActionWithState(VALID_SESSION_ID, VALID_ACTION_ID);

    expect(result.action?.status).toBe("verified");
    expect(result.action?.verifiedAt).toBe(closedAt.toISOString());
    expect(result.active).toBe(false);

    // 1 read operation + 1 atomic write operation
    expect(aggregateSpy).toHaveBeenCalledOnce();
    expect(findOneAndUpdateSpy).toHaveBeenCalledOnce();
    expect(findOneAndUpdateSpy).toHaveBeenCalledWith(
      { actionId: VALID_ACTION_ID, sessionId: VALID_SESSION_ID, status: { $in: ["requested", "delivered"] } },
      { $set: { status: "verified", verifiedAt: closedAt, failureCategory: null, open: false } },
      { returnDocument: "after" },
    );
  });

  it("6. A closure older than requestedAt does not verify the action", async () => {
    const requestedAt = new Date();
    const oldClosedAt = new Date(Date.now() - 5_000); // Closed BEFORE requestedAt

    const aggregateSpy = vi.fn().mockReturnValue({
      toArray: vi.fn().mockResolvedValue([
        {
          actionId: VALID_ACTION_ID,
          sessionId: VALID_SESSION_ID,
          action: "terminate_session",
          status: "delivered",
          requestedBy: "op-1",
          requestedAt,
          deliveredAt: new Date(),
          verifiedAt: null,
          failureCategory: null,
          open: true,
          sessionLifecycle: {
            status: "closed",
            closedAt: oldClosedAt,
          },
        },
      ]),
    });

    const findOneAndUpdateSpy = vi.fn();

    vi.spyOn(mongo, "getMongoClient").mockResolvedValue({
      db: () => ({
        collection: () => ({
          aggregate: aggregateSpy,
          findOneAndUpdate: findOneAndUpdateSpy,
          createIndex: vi.fn().mockResolvedValue("index"),
        }),
      }),
    } as unknown as ReturnType<typeof mongo.getMongoClient>);

    const result = await getTerminateActionWithState(VALID_SESSION_ID, VALID_ACTION_ID);

    // Must NOT be verified because closure occurred before requestedAt
    expect(result.action?.status).toBe("delivered");
    expect(findOneAndUpdateSpy).not.toHaveBeenCalled();
  });

  it("7. Verification timeout transitions atomically to failed", async () => {
    // Action requested 25 seconds ago (> 20s VERIFICATION_TIMEOUT_MS)
    const requestedAt = new Date(Date.now() - 25_000);

    const aggregateSpy = vi.fn().mockReturnValue({
      toArray: vi.fn().mockResolvedValue([
        {
          actionId: VALID_ACTION_ID,
          sessionId: VALID_SESSION_ID,
          action: "terminate_session",
          status: "delivered",
          requestedBy: "op-1",
          requestedAt,
          deliveredAt: new Date(Date.now() - 24_000),
          verifiedAt: null,
          failureCategory: null,
          open: true,
          sessionLifecycle: { status: "active" },
        },
      ]),
    });

    const findOneAndUpdateSpy = vi.fn().mockResolvedValue({
      actionId: VALID_ACTION_ID,
      sessionId: VALID_SESSION_ID,
      action: "terminate_session",
      status: "failed",
      requestedBy: "op-1",
      requestedAt,
      deliveredAt: new Date(Date.now() - 24_000),
      verifiedAt: null,
      failureCategory: "verification_timeout",
      open: false,
    });

    vi.spyOn(mongo, "getMongoClient").mockResolvedValue({
      db: () => ({
        collection: () => ({
          aggregate: aggregateSpy,
          findOneAndUpdate: findOneAndUpdateSpy,
          createIndex: vi.fn().mockResolvedValue("index"),
        }),
      }),
    } as unknown as ReturnType<typeof mongo.getMongoClient>);

    const result = await getTerminateActionWithState(VALID_SESSION_ID, VALID_ACTION_ID);

    expect(result.action?.status).toBe("failed");
    expect(result.action?.failureCategory).toBe("verification_timeout");
    expect(findOneAndUpdateSpy).toHaveBeenCalledOnce();
    expect(findOneAndUpdateSpy).toHaveBeenCalledWith(
      { actionId: VALID_ACTION_ID, sessionId: VALID_SESSION_ID, status: { $in: ["requested", "delivered"] } },
      { $set: { status: "failed", failureCategory: "verification_timeout", open: false } },
      { returnDocument: "after" },
    );
  });

  it("8. Unknown or cross-session actionId is handled deterministically", async () => {
    const aggregateSpy = vi.fn().mockReturnValue({
      // Aggregation matches actionId AND sessionId, so cross-session returns empty array
      toArray: vi.fn().mockResolvedValue([]),
    });
    const findOneSpy = vi.fn().mockResolvedValue({
      lifecycle: { status: "active" },
    });

    vi.spyOn(mongo, "getMongoClient").mockResolvedValue({
      db: () => ({
        collection: () => ({
          aggregate: aggregateSpy,
          findOne: findOneSpy,
          createIndex: vi.fn().mockResolvedValue("index"),
        }),
      }),
    } as unknown as ReturnType<typeof mongo.getMongoClient>);

    const result = await getTerminateActionWithState(VALID_SESSION_ID, "unknown-or-cross-action-id");

    // Action is null; cannot leak cross-session action details
    expect(result.action).toBeNull();
    expect(result.active).toBe(true);
  });

  it("9. Concurrent reconciliation cannot regress or duplicate terminal state", async () => {
    // Action already terminal verified in MongoDB
    const verifiedDoc = {
      actionId: VALID_ACTION_ID,
      sessionId: VALID_SESSION_ID,
      action: "terminate_session",
      status: "verified",
      requestedBy: "op-1",
      requestedAt: new Date("2026-09-16T12:00:00Z"),
      deliveredAt: new Date("2026-09-16T12:00:01Z"),
      verifiedAt: new Date("2026-09-16T12:00:05Z"),
      failureCategory: null,
      open: false,
      sessionLifecycle: { status: "closed", closedAt: new Date("2026-09-16T12:00:05Z") },
    };

    const aggregateSpy = vi.fn().mockReturnValue({
      toArray: vi.fn().mockResolvedValue([verifiedDoc]),
    });
    const findOneAndUpdateSpy = vi.fn();

    vi.spyOn(mongo, "getMongoClient").mockResolvedValue({
      db: () => ({
        collection: () => ({
          aggregate: aggregateSpy,
          findOneAndUpdate: findOneAndUpdateSpy,
          createIndex: vi.fn().mockResolvedValue("index"),
        }),
      }),
    } as unknown as ReturnType<typeof mongo.getMongoClient>);

    // First call
    const result1 = await getTerminateActionWithState(VALID_SESSION_ID, VALID_ACTION_ID);
    // Second concurrent call
    const result2 = await getTerminateActionWithState(VALID_SESSION_ID, VALID_ACTION_ID);

    expect(result1.action?.status).toBe("verified");
    expect(result2.action?.status).toBe("verified");

    // Neither call writes to the database; terminal state is stable and idempotent
    expect(findOneAndUpdateSpy).not.toHaveBeenCalled();
  });
});
