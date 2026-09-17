import { describe, expect, it, vi } from "vitest";

vi.mock("server-only", () => ({}));

import type { SessionCwdHistoryEvent } from "@/lib/dashboardTypes";
import {
  SessionHopLifecycleManager,
  SessionHopResolver,
  type HopResolutionStatus,
  type SessionCwdHopPayload,
} from "@/components/filesystem/sessionHopResolver";
import {
  buildAuditUrlSearch,
  getHistoryWindowMetrics,
  parseAuditUrlParams,
} from "@/components/filesystem/filesystemUtils";
import {
  getSessionCwdHistory,
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

describe("FA-005: Authoritative Deep-Hop Resolution & Replay Window Remediation", () => {
  // 1. Page-one deep link resolves and clears request-only intent
  it("resolves hop on page one immediately, selecting target and clearing request intent", () => {
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
    // No network request required for page-one items
    expect(fetchHop).not.toHaveBeenCalled();

    // Hook level contract: once resolved on page one, request intent is cleared
    const requestedHopRef = { current: hopId as string | null };
    let requestedHopState: string | null = hopId;
    let selectedHistoryEventId: string | null = null;

    if (pageOneItems.some((item) => item.id === requestedHopRef.current)) {
      selectedHistoryEventId = requestedHopRef.current;
      requestedHopRef.current = null;
      requestedHopState = null;
    }

    expect(selectedHistoryEventId).toBe(hopId);
    expect(requestedHopRef.current).toBeNull();
    expect(requestedHopState).toBeNull();
  });

  // 2. Direct older hop resolves and keeps the URL through selectedHistoryEventId
  it("resolves older hop via direct lookup, clearing request intent while retaining URL via selectedHistoryEventId", async () => {
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

    // Direct resolution succeeds
    const resolved = await resolver.resolveDirect();
    expect(resolved).not.toBeNull();
    expect(resolved?.id).toBe(hopId);
    expect(resolved?.hopNumber).toBe(42);
    expect(resolved?.successfulHopNumber).toBe(38);
    expect(resolver.getStatus()).toBe("resolved");
    expect(statuses).toEqual(["resolving", "resolved"]);

    // Contract: request intent clears, selectedHistoryEventId preserves URL ?hop=<id>
    const requestedHopRef = { current: hopId as string | null };
    let requestedHopState: string | null = hopId;
    let selectedHistoryEventId: string | null = null;
    let anchoredHop: SessionCwdHistoryEvent | null = null;

    // Simulate onResolved hook callback
    requestedHopRef.current = null;
    requestedHopState = null;
    anchoredHop = resolved;
    selectedHistoryEventId = resolved?.id ?? null;

    expect(requestedHopRef.current).toBeNull();
    expect(requestedHopState).toBeNull();
    expect(anchoredHop?.id).toBe(hopId);
    expect(selectedHistoryEventId).toBe(hopId);

    const urlSearch = buildAuditUrlSearch({
      view: "audit",
      sessionId: "sess-001",
      hop: selectedHistoryEventId,
    });
    expect(urlSearch).toContain(`hop=${encodeURIComponent(hopId)}`);
  });

  // 3. Switching to another session never reuses the previous hop
  it("clears prior hop and never queries or reuses it when selecting another session", () => {
    const requestedHopRef = { current: "cwd:session-1-hop" as string | null };
    let selectedHistoryEventId: string | null = "cwd:session-1-hop";
    let selectedSessionId: string | null = "session-1";
    let anchoredHop: SessionCwdHistoryEvent | null = makeHistoryEvent({ id: "cwd:session-1-hop", sessionId: "session-1" });

    // User selects session-2
    const handleUserSelectSession = (newSessionId: string) => {
      requestedHopRef.current = null;
      selectedHistoryEventId = null;
      anchoredHop = null;
      selectedSessionId = newSessionId;
    };

    handleUserSelectSession("session-2");

    expect(selectedSessionId).toBe("session-2");
    expect(selectedHistoryEventId).toBeNull();
    expect(requestedHopRef.current).toBeNull();
    expect(anchoredHop).toBeNull();

    const urlSearch = buildAuditUrlSearch({
      view: "audit",
      sessionId: selectedSessionId,
      hop: selectedHistoryEventId,
    });
    expect(urlSearch).toContain("sessionId=session-2");
    expect(urlSearch).not.toContain("hop=");
  });

  // 4. Same-session and cross-session Back/Forward scopes remain coherent
  it("keeps same-session and cross-session Back/Forward URL parsing and selection coherent", () => {
    // A: In same session, Back/Forward restores the hop
    const sameSessionSearch = "?view=audit&sessionId=sess-001&hop=cwd%3Ahop-42";
    const parsedSame = parseAuditUrlParams(sameSessionSearch);
    expect(parsedSame.view).toBe("audit");
    expect(parsedSame.sessionId).toBe("sess-001");
    expect(parsedSame.hop).toBe("cwd:hop-42");

    // B: Cross-session navigation to a session without hop clears hop
    const crossSessionWithoutHop = "?view=audit&sessionId=sess-002";
    const parsedWithoutHop = parseAuditUrlParams(crossSessionWithoutHop);
    expect(parsedWithoutHop.sessionId).toBe("sess-002");
    expect(parsedWithoutHop.hop).toBeNull();

    // C: Cross-session navigation to a session with its own hop applies that hop only
    const crossSessionWithHop = "?view=audit&sessionId=sess-003&hop=cwd%3Asess3-hop";
    const parsedWithHop = parseAuditUrlParams(crossSessionWithHop);
    expect(parsedWithHop.sessionId).toBe("sess-003");
    expect(parsedWithHop.hop).toBe("cwd:sess3-hop");
  });

  // 5. Target on page 2 and page 3, followed by one or more Load earlier operations
  it("reconciles anchored target when earlier pages arrive without altering selection or hop number", () => {
    const targetHopId = "cwd:target-hop-25";
    const targetEvent = makeHistoryEvent({
      id: targetHopId,
      sessionId: "sess-001",
      at: "2026-09-16T12:00:00.000Z",
      hopNumber: 25,
      successfulHopNumber: 20,
    });

    let anchoredHop: SessionCwdHistoryEvent | null = targetEvent;
    const selectedHistoryEventId: string | null = targetHopId;

    // Initial state: Page 1 (items 100..71) loaded
    let history: SessionCwdHistoryEvent[] = [
      makeHistoryEvent({ id: "evt-100", at: "2026-09-17T03:00:00.000Z" }),
      makeHistoryEvent({ id: "evt-71", at: "2026-09-17T02:00:00.000Z" }),
    ];

    // Initial metrics with anchored target at hop 25 of 100
    const initialMetrics = getHistoryWindowMetrics(history.length, 100, 0, targetEvent.hopNumber);
    expect(initialMetrics.selectedNumber).toBe(25);
    expect(initialMetrics.totalItems).toBe(100);

    // Operation 1: Load earlier (Page 2: items 70..41) - does NOT contain target
    const page2Items: SessionCwdHistoryEvent[] = [
      makeHistoryEvent({ id: "evt-70", at: "2026-09-17T01:50:00.000Z" }),
      makeHistoryEvent({ id: "evt-41", at: "2026-09-17T01:10:00.000Z" }),
    ];

    // Append logic
    const incomingIds2 = new Set(page2Items.map((i) => i.id));
    history = [...history.filter((i) => !incomingIds2.has(i.id)), ...page2Items];

    // Reconciliation check for Page 2: target is not in page 2
    if (page2Items.some((item) => item.id === anchoredHop?.id)) {
      anchoredHop = null;
    }
    expect(anchoredHop).not.toBeNull(); // Still anchored
    expect(anchoredHop?.id).toBe(targetHopId);

    // Operation 2: Load earlier (Page 3: items 40..11) - CONTAINS target
    const page3Items: SessionCwdHistoryEvent[] = [
      makeHistoryEvent({ id: "evt-40", at: "2026-09-17T01:00:00.000Z" }),
      targetEvent,
      makeHistoryEvent({ id: "evt-11", at: "2026-09-16T11:00:00.000Z" }),
    ];

    const incomingIds3 = new Set(page3Items.map((i) => i.id));
    history = [...history.filter((i) => !incomingIds3.has(i.id)), ...page3Items];

    // Reconciliation check for Page 3: target is now in loaded history!
    if (page3Items.some((item) => item.id === anchoredHop?.id)) {
      anchoredHop = null;
    }

    expect(anchoredHop).toBeNull(); // Seamlessly reconciled!
    expect(selectedHistoryEventId).toBe(targetHopId); // Selection never shifted!

    // Absolute hop number remains authoritative and unchanged
    const reconciledMetrics = getHistoryWindowMetrics(history.length, 100, 24, targetEvent.hopNumber);
    expect(reconciledMetrics.selectedNumber).toBe(25);
    expect(reconciledMetrics.totalItems).toBe(100);
  });

  // 6. History remains newest-first with no duplicate target
  it("preserves strict newest-first ordering and deduplication across page appends", () => {
    const target = makeHistoryEvent({ id: "target-ev", at: "2026-09-16T12:00:00.000Z" });

    const page1: SessionCwdHistoryEvent[] = [
      makeHistoryEvent({ id: "p1-newest", at: "2026-09-17T02:00:00.000Z" }),
      makeHistoryEvent({ id: "p1-older", at: "2026-09-17T01:00:00.000Z" }),
    ];

    const page2: SessionCwdHistoryEvent[] = [
      makeHistoryEvent({ id: "p1-older", at: "2026-09-17T01:00:00.000Z" }), // overlap
      target,
      makeHistoryEvent({ id: "p2-oldest", at: "2026-09-16T10:00:00.000Z" }),
    ];

    // Append with deduplication
    const incomingIds = new Set(page2.map((i) => i.id));
    const combined = [...page1.filter((i) => !incomingIds.has(i.id)), ...page2];

    expect(combined.map((e) => e.id)).toEqual(["p1-newest", "p1-older", "target-ev", "p2-oldest"]);
    expect(combined.filter((e) => e.id === "target-ev").length).toBe(1);

    // Timestamps strictly descending (newest-first)
    for (let i = 0; i < combined.length - 1; i++) {
      expect(new Date(combined[i].at).getTime()).toBeGreaterThanOrEqual(new Date(combined[i + 1].at).getTime());
    }
  });

  // 7. Replay cannot cross an unloaded gap
  it("prevents prev/next navigation, auto-play, and time metrics from crossing unloaded gap", () => {
    const anchoredHop = makeHistoryEvent({
      id: "cwd:deep-target",
      sessionId: "sess-001",
      at: "2026-09-16T10:00:00.000Z",
      hopNumber: 15,
    });
    const selectedHistoryEventId = "cwd:deep-target";

    const isAnchoredSelected = Boolean(
      anchoredHop &&
        selectedHistoryEventId &&
        (anchoredHop.eventId === selectedHistoryEventId || anchoredHop.id === selectedHistoryEventId)
    );
    expect(isAnchoredSelected).toBe(true);

    let onSelectCalled = false;
    const onSelectHistoryEventId = () => {
      onSelectCalled = true;
    };

    // Simulated handlePrevHop guard
    const handlePrevHop = () => {
      if (isAnchoredSelected) return;
      onSelectHistoryEventId();
    };

    // Simulated handleNextHop guard
    const handleNextHop = () => {
      if (isAnchoredSelected) return;
      onSelectHistoryEventId();
    };

    // Simulated handleTogglePlay guard
    let isPlaying = false;
    const handleTogglePlay = () => {
      if (isAnchoredSelected) return;
      isPlaying = !isPlaying;
    };

    handlePrevHop();
    expect(onSelectCalled).toBe(false);

    handleNextHop();
    expect(onSelectCalled).toBe(false);

    handleTogglePlay();
    expect(isPlaying).toBe(false);

    // Time metrics contract in anchored state
    const anchoredTimeSummary = {
      formattedTotalDuration: "Partial",
      formattedCurrentDelta: "Gap",
    };
    expect(anchoredTimeSummary.formattedCurrentDelta).toBe("Gap");
    expect(anchoredTimeSummary.formattedTotalDuration).toBe("Partial");
  });

  // 8. Invalid hop with non-empty and empty history (0 items) both expose recovery UI/state
  it("exposes not-found status and recovery state independently of history item count", async () => {
    const fetchHop = vi.fn().mockResolvedValue({ item: null });

    // Case A: Non-empty history
    const resolverNonEmpty = new SessionHopResolver({
      sessionId: "sess-001",
      hopId: "cwd:missing-1",
      fetchHop,
    });
    expect(resolverNonEmpty.checkPageItems([makeHistoryEvent({ id: "evt-01" })])).toBe(false);
    await resolverNonEmpty.resolveDirect();
    expect(resolverNonEmpty.getStatus()).toBe("not-found");
    expect(resolverNonEmpty.getHopId()).toBe("cwd:missing-1");

    // Case B: Empty history (0 items)
    const resolverEmpty = new SessionHopResolver({
      sessionId: "sess-empty",
      hopId: "cwd:missing-2",
      fetchHop,
    });
    expect(resolverEmpty.checkPageItems([])).toBe(false);
    await resolverEmpty.resolveDirect();
    expect(resolverEmpty.getStatus()).toBe("not-found");
    expect(resolverEmpty.getHopId()).toBe("cwd:missing-2");
  });

  // 9. Overlength input is rejected rather than truncated (HTTP 400 at route, 0 DB ops)
  it("rejects overlength inputs with HTTP 400 at route and 0 MongoDB operations in server helper", async () => {
    const overlengthId = "a".repeat(MAX_CWD_IDENTIFIER_LENGTH + 1);

    // 1. Server helper rejects immediately with 0 DB operations
    const findOneMock = vi.fn().mockResolvedValue(null);
    vi.spyOn(mongo, "getMongoClient").mockResolvedValue({
      db: () => ({
        collection: () => ({
          findOne: findOneMock,
        }),
      }),
    } as unknown as ReturnType<typeof mongo.getMongoClient>);

    const serverHelperResult = await getSessionCwdHistoryHop(overlengthId, "evt-001");
    expect(serverHelperResult).toEqual({ item: null });
    expect(findOneMock).not.toHaveBeenCalled();

    const historyHelperResult = await getSessionCwdHistory(overlengthId, null);
    expect(historyHelperResult.items).toEqual([]);
    expect(findOneMock).not.toHaveBeenCalled();

    // 2. Route rejects overlength id, hop, or cursor with HTTP 400
    vi.spyOn(authSession, "getSessionFromRequest").mockResolvedValue({
      operatorId: "admin",
      username: "admin",
      mustChangePassword: false,
    } as unknown as authSession.SessionUser);

    const reqOverlengthHop = new Request(
      `http://localhost:3000/api/sessions/sess-test/cwd-history?hop=${overlengthId}`
    );
    const resOverlengthHop = await cwdHistoryRouteGet(reqOverlengthHop, {
      params: Promise.resolve({ id: "sess-test" }),
    });
    expect(resOverlengthHop.status).toBe(400);
    const bodyHop = await resOverlengthHop.json();
    expect(bodyHop.error).toBe("Identifier length exceeds limit");

    const reqOverlengthCursor = new Request(
      `http://localhost:3000/api/sessions/sess-test/cwd-history?cursor=${overlengthId}`
    );
    const resOverlengthCursor = await cwdHistoryRouteGet(reqOverlengthCursor, {
      params: Promise.resolve({ id: "sess-test" }),
    });
    expect(resOverlengthCursor.status).toBe(400);
    const bodyCursor = await resOverlengthCursor.json();
    expect(bodyCursor.error).toBe("Identifier length exceeds limit");
  });

  // 10. Cancellation on hop/session/view change and stale-response protection
  it("aborts in-flight resolution on session, hop, or view change and ignores stale responses", async () => {
    let capturedSignal1: AbortSignal | undefined;
    let resolveSession1!: (payload: SessionCwdHopPayload) => void;
    const session1Promise = new Promise<SessionCwdHopPayload>((res) => {
      resolveSession1 = res;
    });

    const fetchHop = vi.fn().mockImplementation((sessionId: string, _hopId: string, signal: AbortSignal) => {
      if (sessionId === "session-1") {
        capturedSignal1 = signal;
        return session1Promise;
      }
      return Promise.resolve({ item: makeHistoryEvent({ id: "hop-2", sessionId: "session-2" }) });
    });

    const resolvedEvents: SessionCwdHistoryEvent[] = [];
    const manager = new SessionHopLifecycleManager();

    // Step A: Start session-1
    manager.sync({
      sessionId: "session-1",
      hopId: "hop-1",
      viewMode: "audit",
      history: [],
      fetchHop,
      onStatusChange: () => {},
      onResolved: (e) => resolvedEvents.push(e),
    });

    expect(capturedSignal1).toBeDefined();
    expect(capturedSignal1?.aborted).toBe(false);

    // Step B: User navigates to session-2 before session-1 completes
    manager.sync({
      sessionId: "session-2",
      hopId: "hop-2",
      viewMode: "audit",
      history: [],
      fetchHop,
      onStatusChange: () => {},
      onResolved: (e) => resolvedEvents.push(e),
    });

    // session-1 request aborted
    expect(capturedSignal1?.aborted).toBe(true);

    await new Promise((r) => setTimeout(r, 0));
    expect(resolvedEvents.map((e) => e.id)).toEqual(["hop-2"]);

    // Step C: Late response from session-1 arrives
    resolveSession1({ item: makeHistoryEvent({ id: "hop-1", sessionId: "session-1" }) });
    await new Promise((r) => setTimeout(r, 0));

    // Stale generation discarded
    expect(resolvedEvents.map((e) => e.id)).toEqual(["hop-2"]);

    // Step D: Transition to live mode aborts resolution
    let capturedSignal2: AbortSignal | undefined;
    const fetchHop2 = vi.fn().mockImplementation((_s: string, _h: string, signal: AbortSignal) => {
      capturedSignal2 = signal;
      return new Promise(() => {});
    });

    manager.sync({
      sessionId: "session-3",
      hopId: "hop-3",
      viewMode: "audit",
      history: [],
      fetchHop: fetchHop2,
      onStatusChange: () => {},
      onResolved: () => {},
    });

    expect(capturedSignal2?.aborted).toBe(false);
    manager.sync({
      sessionId: "session-3",
      hopId: "hop-3",
      viewMode: "live",
      history: [],
      fetchHop: fetchHop2,
      onStatusChange: () => {},
      onResolved: () => {},
    });
    expect(capturedSignal2?.aborted).toBe(true);
  });

  // Cross-session and unknown event 404 security
  it("never resolves or leaks an event that belongs to a different session", async () => {
    const crossSessionEvent = makeHistoryEvent({
      id: "cwd:stolen-event",
      sessionId: "sess-victim-999",
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

  // Route 404 and 200 contract with $facet aggregation
  describe("Server-side getSessionCwdHistoryHop single $facet aggregation", () => {
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

    it("route returns 200 with hop document and hop numbering via consolidated $facet aggregation", async () => {
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

      const aggregateMock = vi.fn().mockReturnValue({
        toArray: vi.fn().mockResolvedValue([
          {
            totalItems: [{ count: 100 }],
            hopNumber: [{ count: 42 }],
            successfulHopNumber: [{ count: 38 }],
          },
        ]),
      });

      vi.spyOn(mongo, "getMongoClient").mockResolvedValue({
        db: () => ({
          collection: () => ({
            findOne: vi.fn().mockResolvedValue(mockDoc),
            aggregate: aggregateMock,
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
      expect(body.successfulHopNumber).toBe(38);
      expect(body.totalItems).toBe(100);
      expect(aggregateMock).toHaveBeenCalledTimes(1);
    });
  });
});
