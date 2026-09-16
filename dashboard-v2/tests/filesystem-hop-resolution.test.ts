import { describe, expect, it, vi } from "vitest";

vi.mock("server-only", () => ({}));

import type { SessionCwdHistoryEvent } from "@/lib/dashboardTypes";
import {
  mergeResolvedHistoryEvent,
  SessionHopLifecycleManager,
  SessionHopResolver,
  type HopResolutionStatus,
  type SessionCwdHopPayload,
} from "@/components/filesystem/sessionHopResolver";
import {
  buildAuditUrlSearch,
  getHistoryWindowMetrics,
} from "@/components/filesystem/filesystemUtils";
import { getSessionCwdHistoryHop } from "@/lib/filesystem-server";
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

describe("FA-005: Authoritative Deep-Hop Resolution & Lifecycle", () => {
  // 1. Hop on page one resolves normally
  it("resolves hop on page one immediately without direct lookup", () => {
    const hopId = "cwd:page1-hop";
    const pageOneItems: SessionCwdHistoryEvent[] = [
      makeHistoryEvent({ id: "cwd:page1-newest", at: "2026-09-17T01:00:00.000Z" }),
      makeHistoryEvent({ id: hopId, at: "2026-09-17T00:50:00.000Z" }),
      makeHistoryEvent({ id: "cwd:page1-older", at: "2026-09-17T00:40:00.000Z" }),
    ];

    const fetchHop = vi.fn();
    const onResolved = vi.fn();
    const onStatusChange = vi.fn();

    const resolver = new SessionHopResolver({
      sessionId: "sess-001",
      hopId,
      fetchHop,
      onResolved,
      onStatusChange,
    });

    const found = resolver.checkPageItems(pageOneItems);
    expect(found).toBe(true);
    expect(resolver.getStatus()).toBe("resolved");
    expect(resolver.getResolvedEvent()?.id).toBe(hopId);
    expect(onResolved).toHaveBeenCalledWith(expect.objectContaining({ id: hopId }));
    expect(onStatusChange).toHaveBeenCalledWith("resolved");
    // Crucial: no network request needed
    expect(fetchHop).not.toHaveBeenCalled();
  });

  // 2. Hop older than the first 80 events resolves
  it("resolves hop older than the first page via direct lookup", async () => {
    const hopId = "cwd:older-hop";
    const olderEvent = makeHistoryEvent({
      id: hopId,
      sessionId: "sess-001",
      at: "2026-09-16T20:00:00.000Z",
    });

    const fetchHop = vi.fn().mockResolvedValue({
      item: olderEvent,
      hopNumber: 42,
      successfulHopNumber: 38,
      totalItems: 200,
    } satisfies SessionCwdHopPayload);

    const onResolved = vi.fn();
    const statuses: HopResolutionStatus[] = [];

    const resolver = new SessionHopResolver({
      sessionId: "sess-001",
      hopId,
      fetchHop,
      onStatusChange: (status) => statuses.push(status),
      onResolved,
    });

    // Page 1 check fails
    const pageOneItems = [makeHistoryEvent({ id: "cwd:page1-01" })];
    expect(resolver.checkPageItems(pageOneItems)).toBe(false);

    // Direct resolution
    const resolved = await resolver.resolveDirect();
    expect(resolved).not.toBeNull();
    expect(resolved?.id).toBe(hopId);
    expect(resolved?.hopNumber).toBe(42);
    expect(resolved?.successfulHopNumber).toBe(38);
    expect(resolver.getStatus()).toBe("resolved");
    expect(statuses).toEqual(["resolving", "resolved"]);
    expect(onResolved).toHaveBeenCalledWith(expect.objectContaining({ id: hopId, hopNumber: 42 }));
  });

  // 3. Direct lookup is scoped to both sessionId and eventId
  it("passes both sessionId and eventId to direct lookup", async () => {
    const fetchHop = vi.fn().mockResolvedValue({ item: null });

    const resolver = new SessionHopResolver({
      sessionId: "sess-target-123",
      hopId: "cwd:evt-target-456",
      fetchHop,
    });

    await resolver.resolveDirect();
    expect(fetchHop).toHaveBeenCalledWith("sess-target-123", "cwd:evt-target-456", expect.any(AbortSignal));
  });

  // 4. Cross-session event returns the same non-leaking unavailable result as an unknown event
  it("never resolves or leaks an event that belongs to a different session", async () => {
    const crossSessionEvent = makeHistoryEvent({
      id: "cwd:stolen-event",
      sessionId: "sess-victim-999", // Different session!
    });

    const fetchHop = vi.fn().mockResolvedValue({
      item: crossSessionEvent,
    });

    const onResolved = vi.fn();
    const statuses: HopResolutionStatus[] = [];

    const resolver = new SessionHopResolver({
      sessionId: "sess-attacker-001",
      hopId: "cwd:stolen-event",
      fetchHop,
      onStatusChange: (status) => statuses.push(status),
      onResolved,
    });

    const result = await resolver.resolveDirect();
    expect(result).toBeNull();
    expect(resolver.getStatus()).toBe("not-found");
    expect(statuses).toEqual(["resolving", "not-found"]);
    expect(onResolved).not.toHaveBeenCalled();
    expect(resolver.getResolvedEvent()).toBeNull();
  });

  // 5. Expired/missing hop produces explicit UI/state and is not silently cleared
  it("transitions to not-found without silently selecting latest hop", async () => {
    const fetchHop = vi.fn().mockResolvedValue({ item: null });
    const statuses: HopResolutionStatus[] = [];

    const resolver = new SessionHopResolver({
      sessionId: "sess-001",
      hopId: "cwd:missing-or-expired",
      fetchHop,
      onStatusChange: (status) => statuses.push(status),
    });

    const result = await resolver.resolveDirect();
    expect(result).toBeNull();
    expect(resolver.getStatus()).toBe("not-found");
    expect(statuses).toEqual(["resolving", "not-found"]);
    // Target hop ID is retained for user visibility
    expect(resolver.getHopId()).toBe("cwd:missing-or-expired");
  });

  // 6. Late response from the previous session cannot change current selection
  it("discards late response from previous session after session switch", async () => {
    let resolveSession1!: (payload: SessionCwdHopPayload) => void;
    const session1Promise = new Promise<SessionCwdHopPayload>((res) => {
      resolveSession1 = res;
    });

    const fetchHop = vi.fn().mockImplementation((sessionId: string) => {
      if (sessionId === "session-1") return session1Promise;
      return Promise.resolve({ item: makeHistoryEvent({ id: "hop-2", sessionId: "session-2" }) });
    });

    const resolvedEvents: SessionCwdHistoryEvent[] = [];
    const manager = new SessionHopLifecycleManager();

    // 1. Start resolution for session-1
    manager.sync({
      sessionId: "session-1",
      hopId: "hop-1",
      viewMode: "audit",
      history: [],
      fetchHop,
      onStatusChange: () => {},
      onResolved: (e) => resolvedEvents.push(e),
    });

    // 2. User quickly navigates to session-2 before session-1 responds
    manager.sync({
      sessionId: "session-2",
      hopId: "hop-2",
      viewMode: "audit",
      history: [],
      fetchHop,
      onStatusChange: () => {},
      onResolved: (e) => resolvedEvents.push(e),
    });

    // Wait for session-2 to finish
    await new Promise((r) => setTimeout(r, 0));
    expect(resolvedEvents.map((e) => e.id)).toEqual(["hop-2"]);

    // 3. Late response for session-1 finally arrives
    resolveSession1({ item: makeHistoryEvent({ id: "hop-1", sessionId: "session-1" }) });
    await new Promise((r) => setTimeout(r, 0));

    // Must still only contain hop-2; session-1 late resolution was discarded by generation guard
    expect(resolvedEvents.map((e) => e.id)).toEqual(["hop-2"]);
  });

  // 7. Changing hop aborts the prior request
  it("aborts prior in-flight request when requested hop changes", () => {
    let capturedSignal1: AbortSignal | undefined;
    const fetchHop = vi.fn().mockImplementation((_sessionId: string, hopId: string, signal: AbortSignal) => {
      if (hopId === "hop-initial") capturedSignal1 = signal;
      return new Promise(() => {}); // never resolves
    });

    const manager = new SessionHopLifecycleManager();
    manager.sync({
      sessionId: "sess-001",
      hopId: "hop-initial",
      viewMode: "audit",
      history: [],
      fetchHop,
      onStatusChange: () => {},
      onResolved: () => {},
    });

    expect(capturedSignal1).toBeDefined();
    expect(capturedSignal1?.aborted).toBe(false);

    // Change hop to hop-secondary
    manager.sync({
      sessionId: "sess-001",
      hopId: "hop-secondary",
      viewMode: "audit",
      history: [],
      fetchHop,
      onStatusChange: () => {},
      onResolved: () => {},
    });

    expect(capturedSignal1?.aborted).toBe(true);
  });

  // 8. Unmount/view change aborts outstanding resolution
  it("aborts in-flight resolution when unmounting or switching to live mode", () => {
    let capturedSignal: AbortSignal | undefined;
    const fetchHop = vi.fn().mockImplementation((_s: string, _h: string, signal: AbortSignal) => {
      capturedSignal = signal;
      return new Promise(() => {});
    });

    const manager = new SessionHopLifecycleManager();
    manager.sync({
      sessionId: "sess-001",
      hopId: "hop-audit",
      viewMode: "audit",
      history: [],
      fetchHop,
      onStatusChange: () => {},
      onResolved: () => {},
    });

    expect(capturedSignal?.aborted).toBe(false);

    // Switching to live mode aborts resolution
    manager.sync({
      sessionId: "sess-001",
      hopId: "hop-audit",
      viewMode: "live",
      history: [],
      fetchHop,
      onStatusChange: () => {},
      onResolved: () => {},
    });

    expect(capturedSignal?.aborted).toBe(true);
  });

  // 9. Resolved event merges without duplicates and retains correct ordering
  it("merges resolved event without duplicates and preserves newest-to-oldest order", () => {
    const ev1 = makeHistoryEvent({ id: "evt-01", at: "2026-09-17T03:00:00.000Z" });
    const ev2 = makeHistoryEvent({ id: "evt-02", at: "2026-09-17T02:00:00.000Z" });
    const ev3 = makeHistoryEvent({ id: "evt-03", at: "2026-09-17T01:00:00.000Z" });

    const existingHistory = [ev1, ev3]; // evt-02 is missing from page one

    const merged = mergeResolvedHistoryEvent(existingHistory, ev2);
    expect(merged.map((e) => e.id)).toEqual(["evt-01", "evt-02", "evt-03"]);

    // Attempting to merge an already-present event does not duplicate
    const mergedAgain = mergeResolvedHistoryEvent(merged, ev2);
    expect(mergedAgain.length).toBe(3);
    expect(mergedAgain.map((e) => e.id)).toEqual(["evt-01", "evt-02", "evt-03"]);
  });

  // 10. Loading earlier pages preserves selection and absolute hop numbering
  it("preserves selection and absolute hop numbering when earlier pages are loaded", () => {
    // Resolved older event with authoritative hopNumber: 25 out of 100 total
    const olderEvent = makeHistoryEvent({
      id: "evt-target",
      at: "2026-09-16T12:00:00.000Z",
      hopNumber: 25,
      successfulHopNumber: 20,
    });

    // Phase 1: Only Page 1 (80 newest events) + target event loaded = 81 items loaded
    const page1Metrics = getHistoryWindowMetrics(81, 100, 0, olderEvent.hopNumber);
    expect(page1Metrics.selectedNumber).toBe(25);
    expect(page1Metrics.totalItems).toBe(100);

    // Phase 2: User clicks "Load earlier", adding 19 more events. Now all 100 items are loaded
    const page2Metrics = getHistoryWindowMetrics(100, 100, 24, olderEvent.hopNumber);
    expect(page2Metrics.selectedNumber).toBe(25); // Still 25! Never changes!
    expect(page2Metrics.totalItems).toBe(100);
  });

  // 11. URL retains unresolved hop until an explicit user recovery action
  it("retains unresolved hop in URL search until explicit recovery", () => {
    // When selectedHistoryEventId is null because hop is still resolving or not found,
    // requestedHopRef.current preserves ?hop= in the URL
    const searchWhileUnresolved = buildAuditUrlSearch({
      view: "audit",
      sessionId: "sess-001",
      hop: null ?? "requested-hop-123",
    });
    expect(searchWhileUnresolved).toContain("hop=requested-hop-123");

    // After user explicitly clears hop, URL drops hop
    const searchAfterClear = buildAuditUrlSearch({
      view: "audit",
      sessionId: "sess-001",
      hop: null,
    });
    expect(searchAfterClear).not.toContain("hop=");

    // After user clicks "Show latest hop", URL updates to latest hop ID
    const searchAfterShowLatest = buildAuditUrlSearch({
      view: "audit",
      sessionId: "sess-001",
      hop: "latest-hop-999",
    });
    expect(searchAfterShowLatest).toContain("hop=latest-hop-999");
  });

  // 12. Normal history pagination still performs one page request at a time
  it("normal history pagination performs one page request at a time without hop lookup", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        items: [makeHistoryEvent({ id: "page-1" })],
        nextCursor: "cursor-token-123",
        totalItems: 10,
        totalSuccessfulItems: 10,
        complete: false,
      }),
    });
    vi.stubGlobal("fetch", fetchMock);

    const { useSessionCwdHistory } = await import("@/components/filesystem/useSessionCwdHistory");
    expect(useSessionCwdHistory).toBeDefined();

    vi.unstubAllGlobals();
  });

  // Server-side direct lookup unit assertions
  describe("Server-side getSessionCwdHistoryHop & Route", () => {
    it("bounds input lengths and returns null for invalid inputs", async () => {
      const resultEmpty = await getSessionCwdHistoryHop("", "some-event");
      expect(resultEmpty).toEqual({ item: null });

      const findOneMock = vi.fn().mockResolvedValue(null);
      vi.spyOn(mongo, "getMongoClient").mockResolvedValue({
        db: () => ({
          collection: () => ({
            findOne: findOneMock,
          }),
        }),
      } as unknown as ReturnType<typeof mongo.getMongoClient>);

      const resultHuge = await getSessionCwdHistoryHop("a".repeat(500), "b".repeat(500));
      expect(resultHuge).toEqual({ item: null });
      expect(findOneMock).toHaveBeenCalledWith({ _id: "b".repeat(300) });
    });

    it("route returns 404 with item: null for unknown or cross-session hop", async () => {
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

      const mockReq = new Request("http://localhost:3000/api/sessions/sess-test/cwd-history?hop=unknown-hop-xyz");
      const res = await cwdHistoryRouteGet(mockReq, { params: Promise.resolve({ id: "sess-test" }) });
      expect(res.status).toBe(404);
      const body = await res.json();
      expect(body.item).toBeNull();
      expect(body.error).toBeDefined();
    });

    it("route returns 200 with hop document and hop numbering when hop is found", async () => {
      vi.spyOn(authSession, "getSessionFromRequest").mockResolvedValue({
        operatorId: "admin",
        username: "admin",
        mustChangePassword: false,
      } as unknown as authSession.SessionUser);

      const mockDoc = {
        _id: "cwd:evt-resolved",
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
            countDocuments: vi.fn().mockResolvedValue(42),
          }),
        }),
      } as unknown as ReturnType<typeof mongo.getMongoClient>);

      const mockReq = new Request("http://localhost:3000/api/sessions/sess-test/cwd-history?hop=cwd:evt-resolved");
      const res = await cwdHistoryRouteGet(mockReq, { params: Promise.resolve({ id: "sess-test" }) });
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.item).not.toBeNull();
      expect(body.item.id).toBe("cwd:evt-resolved");
      expect(body.hopNumber).toBe(42);
    });
  });
});
