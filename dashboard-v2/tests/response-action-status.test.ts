import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("server-only", () => ({}));

import { GET } from "../src/app/api/sessions/[id]/actions/terminate/route";
import { terminateCapabilityFrom } from "../src/components/filesystem/responseActionTypes";
import { ResponseActionPollingController } from "../src/components/filesystem/responseActionPoller";
import {
  buildTerminateActionPipeline,
  getTerminateActionWithState,
} from "../src/lib/session-actions";
import {
  resetResponseControlHealthCache,
} from "../src/lib/response-control";
import * as authSession from "../src/lib/auth/session";
import * as mongo from "../src/lib/mongodb";

const VALID_SESSION_ID = "abcdef123456";
const VALID_ACTION_ID = "123e4567-e89b-12d3-a456-426614174000";

const originalUrl = process.env.COWRIE_RESPONSE_AGENT_URL;
const originalToken = process.env.COWRIE_RESPONSE_AGENT_TOKEN;

describe("Response action status and capability separation (FA-004)", () => {
  beforeEach(() => {
    resetResponseControlHealthCache();
    process.env.COWRIE_RESPONSE_AGENT_URL = "http://100.118.43.30:8788";
    process.env.COWRIE_RESPONSE_AGENT_TOKEN = "01234567890123456789012345678901";
  });

  afterEach(() => {
    resetResponseControlHealthCache();
    vi.restoreAllMocks();
    if (originalUrl === undefined) delete process.env.COWRIE_RESPONSE_AGENT_URL;
    else process.env.COWRIE_RESPONSE_AGENT_URL = originalUrl;
    if (originalToken === undefined) delete process.env.COWRIE_RESPONSE_AGENT_TOKEN;
    else process.env.COWRIE_RESPONSE_AGENT_TOKEN = originalToken;
  });

  it("1. Pending status remains requested/delivered after the health cache expires", async () => {
    vi.spyOn(authSession, "getSessionFromRequest").mockResolvedValue({
      sessionId: "s-1",
      operatorId: "op-1",
      role: "admin",
      mustChangePassword: false,
      expiresAt: new Date(Date.now() + 3600_000),
    });
    vi.spyOn(authSession, "isAdmin").mockReturnValue(true);

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

    resetResponseControlHealthCache();

    const request = new Request(`http://localhost/api/sessions/${VALID_SESSION_ID}/actions/terminate?actionId=${VALID_ACTION_ID}`);
    const response = await GET(request, { params: Promise.resolve({ id: VALID_SESSION_ID }) });

    expect(response.status).toBe(200);
    const body = await response.json();

    expect(body.action).not.toBeNull();
    expect(body.action.status).toBe("delivered");
    expect(body.action.actionId).toBe(VALID_ACTION_ID);
    expect(body.authorized).toBe(true);
    expect(body.configured).toBe(true);
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
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("3. Capability preservation fails closed and never defaults unknown capability to available", () => {
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

    // a) available remains available when previously verified
    expect(terminateCapabilityFrom(statusPayload, "available")).toBe("available");

    // b) forbidden/unconfigured/error/loading are preserved appropriately
    expect(terminateCapabilityFrom(statusPayload, "forbidden")).toBe("forbidden");
    expect(terminateCapabilityFrom(statusPayload, "unconfigured")).toBe("unconfigured");
    expect(terminateCapabilityFrom(statusPayload, "error")).toBe("error");
    expect(terminateCapabilityFrom(statusPayload, "loading")).toBe("loading");

    // c) no previous capability never becomes available (fails closed to "loading")
    expect(terminateCapabilityFrom(statusPayload, undefined)).toBe("loading");
    expect(terminateCapabilityFrom(statusPayload)).toBe("loading");

    // ResponseActionPollingController must not initialize unknown capability as available
    const poller = new ResponseActionPollingController({
      sessionId: VALID_SESSION_ID,
      actionId: VALID_ACTION_ID,
      fetchState: vi.fn(),
      onActionUpdate: vi.fn(),
      onTerminal: vi.fn(),
    });
    expect((poller as unknown as { currentCapability: string }).currentCapability).toBe("loading");

    // d) an omitted available field cannot expose the Disconnect control
    // Disconnect button requires capability === "available"; "loading" renders checking state instead
    const unprobedCapability = terminateCapabilityFrom(statusPayload);
    expect(unprobedCapability).not.toBe("available");
    expect(unprobedCapability).toBe("loading");

    // Explicit probe states still map truthfully
    expect(terminateCapabilityFrom({ available: false, authorized: true, configured: true }, "available")).toBe("error");
    expect(terminateCapabilityFrom({ authorized: false, configured: true }, "available")).toBe("forbidden");
    expect(terminateCapabilityFrom({ authorized: true, configured: false }, "available")).toBe("unconfigured");
    expect(terminateCapabilityFrom({ available: true, authorized: true, configured: true }, "loading")).toBe("available");
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

    expect(aggregateSpy).toHaveBeenCalledOnce();
    expect(findOneSpy).not.toHaveBeenCalled();
    expect(findOneAndUpdateSpy).not.toHaveBeenCalled();
  });

  it("5. Pipeline structure proves the lookup targets the index-backed key (_id)", async () => {
    const pipeline = buildTerminateActionPipeline(VALID_SESSION_ID, VALID_ACTION_ID);

    expect(pipeline[0]).toEqual({
      $match: {
        actionId: VALID_ACTION_ID,
        sessionId: VALID_SESSION_ID,
        action: "terminate_session",
      },
    });

    // Lookup stage must join cwd_session_state on foreignField "_id" (primary key index _id_)
    const lookupStage = pipeline.find((stage) => "$lookup" in stage);
    expect(lookupStage).toBeDefined();
    expect(lookupStage?.$lookup).toEqual({
      from: "cwd_session_state",
      localField: "sessionId",
      foreignField: "_id",
      as: "sessionDocs",
    });

    // When no action document is matched, the fallback read must query { _id: sessionId }
    const findOneSpy = vi.fn().mockResolvedValue({
      lifecycle: { status: "active" },
    });
    vi.spyOn(mongo, "getMongoClient").mockResolvedValue({
      db: () => ({
        collection: () => ({
          aggregate: vi.fn().mockReturnValue({ toArray: vi.fn().mockResolvedValue([]) }),
          findOne: findOneSpy,
          createIndex: vi.fn().mockResolvedValue("index"),
        }),
      }),
    } as unknown as ReturnType<typeof mongo.getMongoClient>);

    const result = await getTerminateActionWithState(VALID_SESSION_ID);
    expect(result.action).toBeNull();
    expect(result.active).toBe(true);
    expect(findOneSpy).toHaveBeenCalledWith(
      { _id: VALID_SESSION_ID },
      { projection: { "lifecycle.status": 1 } },
    );
  });

  it("6. Verified reconciliation from a qualifying closed lifecycle", async () => {
    const requestedAt = new Date("2026-09-16T12:00:00Z");
    const closedAt = new Date("2026-09-16T12:00:05Z");

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

    expect(aggregateSpy).toHaveBeenCalledOnce();
    expect(findOneAndUpdateSpy).toHaveBeenCalledOnce();
    expect(findOneAndUpdateSpy).toHaveBeenCalledWith(
      { actionId: VALID_ACTION_ID, sessionId: VALID_SESSION_ID, status: { $in: ["requested", "delivered"] } },
      { $set: { status: "verified", verifiedAt: closedAt, failureCategory: null, open: false } },
      { returnDocument: "after" },
    );
  });

  it("7. A closure older than requestedAt does not verify the action", async () => {
    const requestedAt = new Date();
    const oldClosedAt = new Date(Date.now() - 5_000);

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

    expect(result.action?.status).toBe("delivered");
    expect(findOneAndUpdateSpy).not.toHaveBeenCalled();
  });

  it("8. Verification timeout transitions atomically to failed", async () => {
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

  describe("9. Real concurrent reconciliation race tests", () => {
    it("verified path: losing race performs targeted fallback read and returns authoritative verified document", async () => {
      const requestedAt = new Date("2026-09-16T12:00:00Z");
      const closedAt = new Date("2026-09-16T12:00:05Z");

      // Both concurrent callers first observe the same pending delivered action
      const pendingDoc = {
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
      };

      const verifiedDoc = {
        ...pendingDoc,
        status: "verified",
        verifiedAt: closedAt,
        failureCategory: null,
        open: false,
      };

      // Call 1 wins findOneAndUpdate and receives the updated verifiedDoc
      // Call 2 loses findOneAndUpdate (returns null because status was already transitioned)
      const findOneAndUpdateMock = vi.fn()
        .mockResolvedValueOnce(verifiedDoc)
        .mockResolvedValueOnce(null);

      // Call 2 executes targeted fallback read findOne({ actionId, sessionId }) which returns verifiedDoc
      const findOneMock = vi.fn().mockResolvedValue(verifiedDoc);

      vi.spyOn(mongo, "getMongoClient").mockResolvedValue({
        db: () => ({
          collection: () => ({
            aggregate: () => ({ toArray: vi.fn().mockResolvedValue([pendingDoc]) }),
            findOneAndUpdate: findOneAndUpdateMock,
            findOne: findOneMock,
            createIndex: vi.fn().mockResolvedValue("index"),
          }),
        }),
      } as unknown as ReturnType<typeof mongo.getMongoClient>);

      const [resWinner, resLoser] = await Promise.all([
        getTerminateActionWithState(VALID_SESSION_ID, VALID_ACTION_ID),
        getTerminateActionWithState(VALID_SESSION_ID, VALID_ACTION_ID),
      ]);

      // Both callers receive the authoritative terminal state
      expect(resWinner.action?.status).toBe("verified");
      expect(resLoser.action?.status).toBe("verified");
      expect(resWinner.action?.verifiedAt).toBe(closedAt.toISOString());
      expect(resLoser.action?.verifiedAt).toBe(closedAt.toISOString());

      // Losing caller performed exactly one targeted fallback read under contention
      expect(findOneMock).toHaveBeenCalledOnce();
      expect(findOneMock).toHaveBeenCalledWith({
        actionId: VALID_ACTION_ID,
        sessionId: VALID_SESSION_ID,
      });
      // Neither caller regressed to "delivered"
      expect(resLoser.action?.status).not.toBe("delivered");
    });

    it("verification_timeout path: losing race performs targeted fallback read and returns failed document", async () => {
      const requestedAt = new Date(Date.now() - 25_000);

      const pendingDoc = {
        actionId: VALID_ACTION_ID,
        sessionId: VALID_SESSION_ID,
        action: "terminate_session",
        status: "requested",
        requestedBy: "op-1",
        requestedAt,
        deliveredAt: null,
        verifiedAt: null,
        failureCategory: null,
        open: true,
        sessionLifecycle: { status: "active" },
      };

      const failedDoc = {
        ...pendingDoc,
        status: "failed",
        failureCategory: "verification_timeout",
        open: false,
      };

      const findOneAndUpdateMock = vi.fn()
        .mockResolvedValueOnce(failedDoc)
        .mockResolvedValueOnce(null);

      const findOneMock = vi.fn().mockResolvedValue(failedDoc);

      vi.spyOn(mongo, "getMongoClient").mockResolvedValue({
        db: () => ({
          collection: () => ({
            aggregate: () => ({ toArray: vi.fn().mockResolvedValue([pendingDoc]) }),
            findOneAndUpdate: findOneAndUpdateMock,
            findOne: findOneMock,
            createIndex: vi.fn().mockResolvedValue("index"),
          }),
        }),
      } as unknown as ReturnType<typeof mongo.getMongoClient>);

      const [resWinner, resLoser] = await Promise.all([
        getTerminateActionWithState(VALID_SESSION_ID, VALID_ACTION_ID),
        getTerminateActionWithState(VALID_SESSION_ID, VALID_ACTION_ID),
      ]);

      expect(resWinner.action?.status).toBe("failed");
      expect(resLoser.action?.status).toBe("failed");
      expect(resWinner.action?.failureCategory).toBe("verification_timeout");
      expect(resLoser.action?.failureCategory).toBe("verification_timeout");

      expect(findOneMock).toHaveBeenCalledOnce();
      expect(resLoser.action?.status).not.toBe("requested");
    });
  });

  describe("10. Route-level unknown and cross-session action handling", () => {
    it("handles unknown syntactically valid UUID actionId without leaking data or enabling controls", async () => {
      vi.spyOn(authSession, "getSessionFromRequest").mockResolvedValue({
        sessionId: "s-1",
        operatorId: "op-1",
        role: "admin",
        mustChangePassword: false,
        expiresAt: new Date(Date.now() + 3600_000),
      });
      vi.spyOn(authSession, "isAdmin").mockReturnValue(true);

      const unknownActionId = "99999999-9999-4999-8999-999999999999";

      // Unknown actionId yields no aggregation match; fallback check indicates active session
      vi.spyOn(mongo, "getMongoClient").mockResolvedValue({
        db: () => ({
          collection: () => ({
            aggregate: () => ({ toArray: vi.fn().mockResolvedValue([]) }),
            findOne: vi.fn().mockResolvedValue({ lifecycle: { status: "active" } }),
            createIndex: vi.fn().mockResolvedValue("index"),
          }),
        }),
      } as unknown as ReturnType<typeof mongo.getMongoClient>);

      const request = new Request(`http://localhost/api/sessions/${VALID_SESSION_ID}/actions/terminate?actionId=${unknownActionId}`);
      const response = await GET(request, { params: Promise.resolve({ id: VALID_SESSION_ID }) });

      expect(response.status).toBe(200);
      const body = await response.json();

      expect(body.action).toBeNull();
      expect(body.authorized).toBe(true);
      expect(body.configured).toBe(true);
      expect(body.available).toBeUndefined();
      expect("available" in body).toBe(false);
    });

    it("cross-session actionId does not leak action details across sessions", async () => {
      vi.spyOn(authSession, "getSessionFromRequest").mockResolvedValue({
        sessionId: "s-1",
        operatorId: "op-1",
        role: "admin",
        mustChangePassword: false,
        expiresAt: new Date(Date.now() + 3600_000),
      });
      vi.spyOn(authSession, "isAdmin").mockReturnValue(true);

      const targetSessionId = "111122223333";
      const crossSessionActionId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

      // Aggregation matches { sessionId: targetSessionId, actionId: crossSessionActionId }
      // which produces empty array because crossSessionActionId belongs to a different session
      const aggregateMock = vi.fn().mockReturnValue({ toArray: vi.fn().mockResolvedValue([]) });
      const findOneMock = vi.fn().mockResolvedValue({ lifecycle: { status: "active" } });

      vi.spyOn(mongo, "getMongoClient").mockResolvedValue({
        db: () => ({
          collection: () => ({
            aggregate: aggregateMock,
            findOne: findOneMock,
            createIndex: vi.fn().mockResolvedValue("index"),
          }),
        }),
      } as unknown as ReturnType<typeof mongo.getMongoClient>);

      const request = new Request(`http://localhost/api/sessions/${targetSessionId}/actions/terminate?actionId=${crossSessionActionId}`);
      const response = await GET(request, { params: Promise.resolve({ id: targetSessionId }) });

      expect(response.status).toBe(200);
      const body = await response.json();

      // Cross-session action details are completely inaccessible
      expect(body.action).toBeNull();
      expect(body.available).toBeUndefined();
    });

    it("poller preserves known pending action when poll response omits action", async () => {
      vi.useFakeTimers();
      const clockNow = 1_000_000;
      let currentTime = clockNow;

      const mockPendingAction = {
        actionId: VALID_ACTION_ID,
        sessionId: VALID_SESSION_ID,
        action: "terminate_session" as const,
        status: "delivered" as const,
        requestedBy: "op-1",
        requestedAt: new Date(clockNow).toISOString(),
        deliveredAt: new Date(clockNow).toISOString(),
        verifiedAt: null,
        failureCategory: null,
      };

      // Server returns action: null (e.g. unknown or cross-session status response)
      const fetchState = vi.fn().mockResolvedValue({
        authorized: true,
        configured: true,
        action: null,
      });

      const onActionUpdate = vi.fn();
      const onTerminal = vi.fn();

      const controller = new ResponseActionPollingController({
        sessionId: VALID_SESSION_ID,
        actionId: VALID_ACTION_ID,
        initialAction: mockPendingAction,
        initialCapability: "available",
        sessionIsLive: false,
        fetchState,
        onActionUpdate,
        onTerminal,
        clock: { now: () => currentTime },
        timer: {
          setTimeout: (fn, ms) => setTimeout(fn, ms),
          clearTimeout: (id) => clearTimeout(id as ReturnType<typeof setTimeout>),
        },
        maxDurationMs: 24_000,
      });

      controller.start();

      // Trigger first poll
      await vi.advanceTimersByTimeAsync(100);
      currentTime += 100;

      expect(fetchState).toHaveBeenCalledTimes(1);
      // Poller must preserve the known pending action rather than clearing to null
      expect(onActionUpdate).toHaveBeenCalledWith(mockPendingAction, "available");

      // Advance to deadline without terminal event: poller should timeout gracefully
      await vi.advanceTimersByTimeAsync(25_000);
      currentTime += 25_000;

      expect(onTerminal).toHaveBeenCalledWith(expect.objectContaining({ kind: "timeout" }));

      vi.useRealTimers();
    });
  });
});
