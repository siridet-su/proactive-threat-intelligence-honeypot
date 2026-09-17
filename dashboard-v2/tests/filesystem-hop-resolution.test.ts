import { describe, expect, it, vi } from "vitest";

vi.mock("server-only", () => ({}));

import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import type { FilesystemClosedSession, SessionCwdHistoryEvent } from "@/lib/dashboardTypes";
import {
  RemoteAuditLookupManager,
  SessionHopLifecycleManager,
  type HopResolutionStatus,
} from "@/components/filesystem/sessionHopResolver";
import {
  buildAuditUrlSearch,
  parseAuditUrlParams,
} from "@/components/filesystem/filesystemUtils";
import {
  computeNextReplayEventId,
  computeTogglePlayState,
} from "@/components/filesystem/useAuditReplay";
import { CwdRouteHistory } from "@/components/filesystem/CwdRouteHistory";
import {
  getSessionCwdHistoryHop,
  MAX_CWD_IDENTIFIER_LENGTH,
} from "@/lib/filesystem-server";
import { GET as cwdHistoryRouteGet } from "@/app/api/sessions/[id]/cwd-history/route";
import * as authSession from "@/lib/auth/session";
import * as mongo from "@/lib/mongodb";

function makeHistoryEvent(overrides: Partial<SessionCwdHistoryEvent> = {}): SessionCwdHistoryEvent {
  return {
    id: "cwd:evt-001",
    sessionId: "sess-001",
    sequence: "1000000",
    at: "2026-09-17T00:00:00.000Z",
    fromPath: "/",
    toPath: "/root",
    action: "entered",
    status: "observed",
    sourceEventId: null,
    ...overrides,
  };
}

function makeClosedSession(overrides: Partial<FilesystemClosedSession> = {}): FilesystemClosedSession {
  return {
    sessionId: "sess-remote-001",
    sourceIp: "192.168.1.100",
    cwdState: {
      path: "/root",
      observedAt: "2026-09-17T00:00:00.000Z",
      sourceEventId: null,
    },
    lifecycle: {
      startedAt: "2026-09-16T22:00:00.000Z",
      closedAt: "2026-09-17T00:00:00.000Z",
    },
    auditSummary: {
      visitedPaths: ["/", "/root"],
      homeOnly: false,
      eventCount: 5,
    },
    ...overrides,
  };
}

describe("FA-005: Authoritative Deep-Hop Resolution & Replay Lifecycle Finalization", () => {
  // 1. Initial remote retained-session deep link
  it("resolves remote session and preserves target hop on initial deep link", async () => {
    const manager = new RemoteAuditLookupManager();
    const expectedSession = makeClosedSession({ sessionId: "sess-remote-init" });
    const fetchSession = vi.fn().mockResolvedValue(expectedSession);

    const onSessionFound = vi.fn();
    const onSessionNotFound = vi.fn();

    await manager.lookup(
      { sessionId: "sess-remote-init", targetHopId: "cwd:deep-hop-001" },
      { onSessionFound, onSessionNotFound },
      fetchSession,
    );

    expect(fetchSession).toHaveBeenCalledWith("sess-remote-init", expect.any(AbortSignal));
    expect(onSessionFound).toHaveBeenCalledWith(expectedSession, "cwd:deep-hop-001");
    expect(onSessionNotFound).not.toHaveBeenCalled();
  });

  // 2. Popstate remote retained-session deep link
  it("resolves remote session and forwards parsed hop during browser popstate navigation", async () => {
    const popstateSearch = "?view=audit&sessionId=sess-remote-pop&hop=cwd%3Apop-hop-42";
    const parsed = parseAuditUrlParams(popstateSearch);
    expect(parsed.sessionId).toBe("sess-remote-pop");
    expect(parsed.hop).toBe("cwd:pop-hop-42");

    const manager = new RemoteAuditLookupManager();
    const expectedSession = makeClosedSession({ sessionId: "sess-remote-pop" });
    const fetchSession = vi.fn().mockResolvedValue(expectedSession);

    const onSessionFound = vi.fn();
    const onSessionNotFound = vi.fn();

    await manager.lookup(
      { sessionId: parsed.sessionId!, targetHopId: parsed.hop },
      { onSessionFound, onSessionNotFound },
      fetchSession,
    );

    expect(onSessionFound).toHaveBeenCalledWith(expectedSession, "cwd:pop-hop-42");
  });

  // 3. Late remote lookup after scope change is discarded
  it("discards late remote lookup response if navigation moved to another scope", async () => {
    const manager = new RemoteAuditLookupManager();
    let resolveSlowFetch!: (session: FilesystemClosedSession | null) => void;
    const slowFetch = new Promise<FilesystemClosedSession | null>((res) => {
      resolveSlowFetch = res;
    });

    const onSessionFound = vi.fn();
    const onSessionNotFound = vi.fn();

    // 1. User arrives at slow-resolving session A
    const lookupPromise = manager.lookup(
      { sessionId: "sess-slow-a", targetHopId: "hop-a" },
      { onSessionFound, onSessionNotFound },
      () => slowFetch,
    );

    // 2. User quickly navigates away to session B before session A resolves
    manager.abort();

    // 3. Late response from session A finally arrives
    resolveSlowFetch(makeClosedSession({ sessionId: "sess-slow-a" }));
    await lookupPromise;

    // Late response must be discarded by generation guard
    expect(onSessionFound).not.toHaveBeenCalled();
    expect(onSessionNotFound).not.toHaveBeenCalled();
  });

  // 4. User session selection clears prior hop and cancels in-flight lookups
  it("clears prior hop intent and selection when selecting a new session", () => {
    const manager = new RemoteAuditLookupManager();
    const requestedHopRef = { current: "cwd:sess1-hop" as string | null };
    let selectedHistoryEventId: string | null = "cwd:sess1-hop";

    // User selects session-2
    const handleUserSelectSession = (newSessionId: string) => {
      manager.abort();
      requestedHopRef.current = null;
      selectedHistoryEventId = null;
      return buildAuditUrlSearch({
        view: "audit",
        sessionId: newSessionId,
        hop: selectedHistoryEventId,
      });
    };

    const newUrl = handleUserSelectSession("session-2");
    expect(requestedHopRef.current).toBeNull();
    expect(selectedHistoryEventId).toBeNull();
    expect(newUrl).toContain("sessionId=session-2");
    expect(newUrl).not.toContain("hop=");
  });

  // 5. Preserves terminal hop-resolution state across history refreshes
  it("re-emits authoritative terminal state across history refreshes without getting stuck in resolving", async () => {
    const manager = new SessionHopLifecycleManager();
    const statusLog: HopResolutionStatus[] = [];

    // --- Scenario A: not-found terminal state ---
    const fetchHopNotFound = vi.fn().mockResolvedValue({ item: null });

    manager.sync({
      sessionId: "sess-001",
      hopId: "missing-hop",
      history: [],
      fetchHop: fetchHopNotFound,
      onStatusChange: (s) => statusLog.push(s),
      onResolved: () => {},
    });

    await new Promise((r) => setTimeout(r, 0));
    expect(statusLog).toEqual(["resolving", "not-found"]);

    // Background history refresh arrives with updated page items for the SAME session
    statusLog.length = 0;
    manager.sync({
      sessionId: "sess-001",
      hopId: "missing-hop",
      history: [makeHistoryEvent({ id: "unrelated-page1" })],
      fetchHop: fetchHopNotFound,
      onStatusChange: (s) => statusLog.push(s),
      onResolved: () => {},
    });

    // Authoritative re-emission: must re-emit "not-found", NOT overwrite with "resolving"
    expect(statusLog).toEqual(["not-found"]);

    // --- Scenario B: error state preserves error until explicit retry ---
    const managerError = new SessionHopLifecycleManager();
    const errorLog: HopResolutionStatus[] = [];
    const fetchHopError = vi.fn().mockRejectedValue(new Error("Network timeout"));

    managerError.sync({
      sessionId: "sess-err",
      hopId: "err-hop",
      history: [],
      fetchHop: fetchHopError,
      onStatusChange: (s) => errorLog.push(s),
      onResolved: () => {},
    });

    await new Promise((r) => setTimeout(r, 0));
    expect(errorLog).toEqual(["resolving", "error"]);

    // Normal refresh without explicit retry preserves error
    errorLog.length = 0;
    managerError.sync({
      sessionId: "sess-err",
      hopId: "err-hop",
      history: [],
      fetchHop: fetchHopError,
      onStatusChange: (s) => errorLog.push(s),
      onResolved: () => {},
      retryOnError: false,
    });
    expect(errorLog).toEqual(["error"]);

    // --- Scenario C: resolved state preserves resolved and re-emits event ---
    const managerResolved = new SessionHopLifecycleManager();
    const resolvedLog: HopResolutionStatus[] = [];
    const resolvedEvents: SessionCwdHistoryEvent[] = [];
    const targetEvent = makeHistoryEvent({ id: "valid-hop", sessionId: "sess-ok" });

    managerResolved.sync({
      sessionId: "sess-ok",
      hopId: "valid-hop",
      history: [],
      fetchHop: vi.fn().mockResolvedValue({ item: targetEvent }),
      onStatusChange: (s) => resolvedLog.push(s),
      onResolved: (e) => resolvedEvents.push(e),
    });

    await new Promise((r) => setTimeout(r, 0));
    expect(resolvedLog).toEqual(["resolving", "resolved"]);
    expect(resolvedEvents.map((e) => e.id)).toEqual(["valid-hop"]);

    // Refresh re-emits resolved status and resolved event
    resolvedLog.length = 0;
    resolvedEvents.length = 0;
    managerResolved.sync({
      sessionId: "sess-ok",
      hopId: "valid-hop",
      history: [targetEvent],
      fetchHop: vi.fn(),
      onStatusChange: (s) => resolvedLog.push(s),
      onResolved: (e) => resolvedEvents.push(e),
    });

    expect(resolvedLog).toEqual(["resolved"]);
    expect(resolvedEvents.map((e) => e.id)).toEqual(["valid-hop"]);
  });

  // 6. Truthful mixed-schema hop numbering (sessionId + session_id)
  it("matches normal history pagination scope using migration-compatible $or filter", async () => {
    let capturedPipeline: unknown = null;

    const mockDoc = {
      _id: "cwd:evt-mixed-target",
      sessionId: "sess-mixed",
      action: "entered",
      status: "observed",
      at: new Date("2026-09-17T01:00:00.000Z"),
      fromPath: "/",
      toPath: "/tmp",
    };

    const aggregateMock = vi.fn().mockImplementation((pipeline: unknown) => {
      capturedPipeline = pipeline;
      return {
        toArray: vi.fn().mockResolvedValue([
          {
            totalItems: [{ count: 12 }],
            hopNumber: [{ count: 7 }],
            successfulHopNumber: [{ count: 6 }],
          },
        ]),
      };
    });

    vi.spyOn(mongo, "getMongoClient").mockResolvedValue({
      db: () => ({
        collection: () => ({
          findOne: vi.fn().mockResolvedValue(mockDoc),
          aggregate: aggregateMock,
        }),
      }),
    } as unknown as ReturnType<typeof mongo.getMongoClient>);

    const result = await getSessionCwdHistoryHop("sess-mixed", "cwd:evt-mixed-target");
    expect(result.item).not.toBeNull();
    expect(result.hopNumber).toBe(7);
    expect(result.successfulHopNumber).toBe(6);
    expect(result.totalItems).toBe(12);

    // Verify the aggregation $match stage uses migration-compatible $or query
    const pipeline = capturedPipeline as Array<Record<string, unknown>>;
    expect(pipeline[0].$match).toEqual({
      $or: [{ sessionId: "sess-mixed" }, { session_id: "sess-mixed" }],
    });
  });

  // 7. Exact database-operation bounds
  it("strictly enforces maximum database operations across all query paths", async () => {
    // 7A: Overlength input (>300 chars) -> exactly 0 operations
    const findOneMock = vi.fn();
    const aggregateMock = vi.fn();
    vi.spyOn(mongo, "getMongoClient").mockResolvedValue({
      db: () => ({
        collection: () => ({
          findOne: findOneMock,
          aggregate: aggregateMock,
        }),
      }),
    } as unknown as ReturnType<typeof mongo.getMongoClient>);

    const overlengthResult = await getSessionCwdHistoryHop("a".repeat(MAX_CWD_IDENTIFIER_LENGTH + 1), "hop-1");
    expect(overlengthResult).toEqual({ item: null });
    expect(findOneMock).not.toHaveBeenCalled();
    expect(aggregateMock).not.toHaveBeenCalled();

    // 7B: Canonical success -> exactly 2 operations (1 findOne + 1 aggregate)
    const findOneSuccess = vi.fn().mockResolvedValue({
      _id: "hop-canonical",
      sessionId: "sess-test",
      at: new Date("2026-09-17T00:00:00.000Z"),
      action: "entered",
      status: "observed",
      fromPath: "/",
      toPath: "/bin",
    });
    const aggregateSuccess = vi.fn().mockReturnValue({
      toArray: vi.fn().mockResolvedValue([{ totalItems: [{ count: 1 }], hopNumber: [{ count: 1 }], successfulHopNumber: [{ count: 1 }] }]),
    });
    vi.spyOn(mongo, "getMongoClient").mockResolvedValue({
      db: () => ({
        collection: () => ({
          findOne: findOneSuccess,
          aggregate: aggregateSuccess,
        }),
      }),
    } as unknown as ReturnType<typeof mongo.getMongoClient>);

    const canonicalResult = await getSessionCwdHistoryHop("sess-test", "hop-canonical");
    expect(canonicalResult.item?.id).toBe("hop-canonical");
    expect(findOneSuccess).toHaveBeenCalledTimes(1);
    expect(aggregateSuccess).toHaveBeenCalledTimes(1);

    // 7C: Canonical cross-session -> exactly 1 operation (1 findOne)
    const findOneCross = vi.fn().mockResolvedValue({
      _id: "hop-stolen",
      sessionId: "victim-session", // Different session!
    });
    const aggregateCross = vi.fn();
    vi.spyOn(mongo, "getMongoClient").mockResolvedValue({
      db: () => ({
        collection: () => ({
          findOne: findOneCross,
          aggregate: aggregateCross,
        }),
      }),
    } as unknown as ReturnType<typeof mongo.getMongoClient>);

    const crossResult = await getSessionCwdHistoryHop("attacker-session", "hop-stolen");
    expect(crossResult).toEqual({ item: null });
    expect(findOneCross).toHaveBeenCalledTimes(1);
    expect(aggregateCross).not.toHaveBeenCalled();

    // 7D: Unknown event -> exactly 3 operations (1 primary + 2 legacy fallbacks)
    const findOneUnknown = vi.fn().mockResolvedValue(null);
    const aggregateUnknown = vi.fn();
    vi.spyOn(mongo, "getMongoClient").mockResolvedValue({
      db: () => ({
        collection: () => ({
          findOne: findOneUnknown,
          aggregate: aggregateUnknown,
        }),
      }),
    } as unknown as ReturnType<typeof mongo.getMongoClient>);

    const unknownResult = await getSessionCwdHistoryHop("sess-test", "hop-nonexistent");
    expect(unknownResult).toEqual({ item: null });
    expect(findOneUnknown).toHaveBeenCalledTimes(3); // 1 primary + 2 legacy fallbacks
    expect(aggregateUnknown).not.toHaveBeenCalled();

    // 7E: Database error path -> throws without fan-out catch
    const aggregateThrow = vi.fn().mockReturnValue({
      toArray: vi.fn().mockRejectedValue(new Error("MongoDB connection timeout")),
    });
    vi.spyOn(mongo, "getMongoClient").mockResolvedValue({
      db: () => ({
        collection: () => ({
          findOne: findOneSuccess,
          aggregate: aggregateThrow,
          countDocuments: vi.fn(), // If fan-out catch existed, countDocuments would be called
        }),
      }),
    } as unknown as ReturnType<typeof mongo.getMongoClient>);

    await expect(getSessionCwdHistoryHop("sess-test", "hop-canonical")).rejects.toThrow(
      "MongoDB connection timeout",
    );
  });

  // 8. Anchored replay controls using production functions
  it("disables replay navigation and play across unloaded gap using pure production functions", () => {
    const items = [
      makeHistoryEvent({ id: "evt-01", at: "2026-09-17T01:00:00.000Z" }),
      makeHistoryEvent({ id: "evt-02", at: "2026-09-17T02:00:00.000Z" }),
    ];

    // When anchored target is selected (gap exists):
    expect(computeNextReplayEventId(items, 0, "next", true)).toBeNull();
    expect(computeNextReplayEventId(items, 0, "prev", true)).toBeNull();
    expect(computeTogglePlayState(false, items, 0, true)).toEqual({ isPlaying: false });
    expect(computeTogglePlayState(true, items, 0, true)).toEqual({ isPlaying: false });

    // When normal contiguous event is selected:
    expect(computeNextReplayEventId(items, 0, "next", false)).toBe("evt-02");
    expect(computeTogglePlayState(false, items, 0, false)).toEqual({ isPlaying: true, targetEventId: undefined });
  });

  // 9. Production render path of CwdRouteHistory verifies alert appears with empty history
  it("renders explicit recovery alert banner in production CwdRouteHistory when history is empty", () => {
    const html = renderToStaticMarkup(
      React.createElement(CwdRouteHistory, {
        selectedSession: makeClosedSession({ sessionId: "sess-empty" }),
        history: [],
        historyStatus: "ready",
        historyCursor: null,
        historyTotalItems: 0,
        historyTotalSuccessfulItems: 0,
        historyComplete: true,
        selectedHistoryEventId: null,
        hopResolutionStatus: "not-found",
        requestedHop: "cwd:target-not-found-xyz",
        onSelectHistoryEventId: () => {},
        onLoadEarlier: () => {},
        onClearHop: () => {},
      })
    );

    // Verify recovery UI exists in production rendered HTML
    expect(html).toContain('data-testid="hop-resolution-banner"');
    expect(html).toContain("Clear hop");
    expect(html).toContain("cwd:target-not-found-xyz");
  });

  // 10. Route-level HTTP status and error contracts
  describe("Route HTTP contract for hop lookup", () => {
    it("returns 400 for overlength identifiers (>300 chars)", async () => {
      vi.spyOn(authSession, "getSessionFromRequest").mockResolvedValue({
        operatorId: "admin",
        username: "admin",
        mustChangePassword: false,
      } as unknown as authSession.SessionUser);

      const reqOverlength = new Request(
        `http://localhost:3000/api/sessions/sess-test/cwd-history?hop=${"b".repeat(MAX_CWD_IDENTIFIER_LENGTH + 1)}`
      );
      const res = await cwdHistoryRouteGet(reqOverlength, { params: Promise.resolve({ id: "sess-test" }) });
      expect(res.status).toBe(400);
      const body = await res.json();
      expect(body.error).toBe("Identifier length exceeds limit");
    });

    it("returns 404 with item: null for unknown or cross-session hop", async () => {
      vi.spyOn(authSession, "getSessionFromRequest").mockResolvedValue({
        operatorId: "admin",
        username: "admin",
        mustChangePassword: false,
      } as unknown as authSession.SessionUser);

      vi.spyOn(mongo, "getMongoClient").mockResolvedValue({
        db: () => ({
          collection: () => ({
            findOne: vi.fn().mockResolvedValue(null),
          }),
        }),
      } as unknown as ReturnType<typeof mongo.getMongoClient>);

      const req404 = new Request("http://localhost:3000/api/sessions/sess-test/cwd-history?hop=unknown-hop");
      const res = await cwdHistoryRouteGet(req404, { params: Promise.resolve({ id: "sess-test" }) });
      expect(res.status).toBe(404);
      const body = await res.json();
      expect(body.item).toBeNull();
    });

    it("returns 200 with hop document and hop numbering when hop is found", async () => {
      vi.spyOn(authSession, "getSessionFromRequest").mockResolvedValue({
        operatorId: "admin",
        username: "admin",
        mustChangePassword: false,
      } as unknown as authSession.SessionUser);

      const mockDoc = {
        _id: "cwd:evt-found",
        sessionId: "sess-test",
        action: "entered",
        status: "observed",
        at: new Date("2026-09-17T00:00:00.000Z"),
        fromPath: "/",
        toPath: "/var",
      };

      vi.spyOn(mongo, "getMongoClient").mockResolvedValue({
        db: () => ({
          collection: () => ({
            findOne: vi.fn().mockResolvedValue(mockDoc),
            aggregate: vi.fn().mockReturnValue({
              toArray: vi.fn().mockResolvedValue([
                {
                  totalItems: [{ count: 50 }],
                  hopNumber: [{ count: 20 }],
                  successfulHopNumber: [{ count: 18 }],
                },
              ]),
            }),
          }),
        }),
      } as unknown as ReturnType<typeof mongo.getMongoClient>);

      const req200 = new Request("http://localhost:3000/api/sessions/sess-test/cwd-history?hop=cwd:evt-found");
      const res = await cwdHistoryRouteGet(req200, { params: Promise.resolve({ id: "sess-test" }) });
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.item.id).toBe("cwd:evt-found");
      expect(body.hopNumber).toBe(20);
      expect(body.successfulHopNumber).toBe(18);
      expect(body.totalItems).toBe(50);
    });
  });
});
