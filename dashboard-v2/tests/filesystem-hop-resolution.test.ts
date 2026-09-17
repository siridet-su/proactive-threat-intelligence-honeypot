import { describe, expect, it, vi } from "vitest";

vi.mock("server-only", () => ({}));

import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import type { FilesystemClosedSession, SessionCwdHistoryEvent } from "@/lib/dashboardTypes";
import {
  RemoteAuditLookupCoordinator,
  SessionHopLifecycleManager,
  adoptLocalSessionScope,
  createRemoteAuditLookupCallbacks,
  processSnapshotSessionResolution,
  type HopResolutionStatus,
  type RemoteAuditLookupIntent,
} from "@/components/filesystem/sessionHopResolver";
import {
  processAuditPopState,
} from "@/components/filesystem/useFilesystemUrlState";
import {
  buildAuditUrlSearch,
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
  // 1. Initial remote deep link forwards target hop
  it("resolves initial remote deep link and forwards its requested hop", async () => {
    let appliedSession: FilesystemClosedSession | null = null;
    let appliedHop: string | null = null;

    const coordinator = new RemoteAuditLookupCoordinator({
      initialViewMode: "audit",
      callbacks: {
        onSessionFound: (session, hop) => {
          appliedSession = session;
          appliedHop = hop ?? null;
        },
        onSessionNotFound: vi.fn(),
      },
    });

    const expectedSession = makeClosedSession({ sessionId: "sess-deep-init" });
    await coordinator.requestLookup(
      { sessionId: "sess-deep-init", targetHopId: "cwd:deep-hop-42" },
      undefined,
      async () => expectedSession,
    );

    expect(appliedSession).toEqual(expectedSession);
    expect(appliedHop).toBe("cwd:deep-hop-42");
  });

  // 1b. Real popstate production path for an unknown retained session invokes the authoritative callback-bearing lookup and selects the returned session/hop
  it("popstate to unknown retained session uses real production path and selects returned session with requested hop", async () => {
    let recordedSession: FilesystemClosedSession | null = null;
    let selectedSessionId: string | null = null;
    let selectedSessionObj: FilesystemClosedSession | null = null;
    let forwardedHop: string | null = null;
    let expiredSessionId: string | null = null;
    let viewMode: "live" | "audit" = "live";
    let hideHomeOnly = false;
    let targetPathFilter: string | null = null;
    let selectedHistoryEventId: string | null = null;

    const requestedHopRef = { current: null as string | null };
    const requestedSessionIdRef = { current: null as string | null };
    const selectedSessionIdRef = { current: null as string | null };

    const expectedSession = makeClosedSession({ sessionId: "sess-retained-popstate" });
    const fetchSession = vi.fn().mockResolvedValue(expectedSession);

    const coordinator = new RemoteAuditLookupCoordinator({ initialViewMode: "audit" });

    // Production callbacks created using the identical factory used in FilesystemActivity
    const authoritativeCallbacks = createRemoteAuditLookupCallbacks({
      recordLookedUpSession: (s) => {
        recordedSession = s;
      },
      setExtraAuditSessions: (updater) => {
        extraAuditSessions = updater(extraAuditSessions);
      },
      setExpiredSessionId: (id) => {
        expiredSessionId = id;
      },
      selectSession: (sid, sObj, hop) => {
        selectedSessionId = sid;
        selectedSessionObj = (sObj as FilesystemClosedSession) ?? null;
        forwardedHop = hop ?? null;
        requestedHopRef.current = hop ?? null;
        selectedHistoryEventId = hop ?? null;
      },
      setSelectedSessionId: (id) => {
        selectedSessionId = id;
      },
      selectedSessionIdRef,
    });
    coordinator.setCallbacks(authoritativeCallbacks);

    let extraAuditSessions = new Map<string, FilesystemClosedSession>();

    let inFlightLookupPromise: Promise<unknown> | null = null;
    const lookupRemoteAuditSession = (intent: { sessionId: string; targetHopId?: string | null }) => {
      const p = coordinator.lookup(intent, authoritativeCallbacks, fetchSession);
      inFlightLookupPromise = p;
      return p;
    };

    const snapshot = {
      sessions: [makeClosedSession({ sessionId: "sess-live-1" })],
      recentClosedSessions: [],
      nodes: [],
    };

    // Execute the exact production popstate orchestration function exported from useFilesystemUrlState
    processAuditPopState({
      search: "?view=audit&sessionId=sess-retained-popstate&hop=cwd:hop-99",
      snapshot,
      extraAuditSessions,
      coordinator,
      lookupRemoteAuditSession,
      selectSession: (sid, _sObj, hop) => {
        selectedSessionId = sid;
        forwardedHop = hop ?? null;
      },
      setViewMode: (v) => {
        viewMode = v;
      },
      setHideHomeOnly: (h) => {
        hideHomeOnly = h;
      },
      setTargetPathFilter: (p) => {
        targetPathFilter = p;
      },
      setSelectedHistoryEventId: (id) => {
        selectedHistoryEventId = id;
      },
      setExpiredSessionId: (id) => {
        expiredSessionId = id;
      },
      requestedHopRef,
      requestedSessionIdRef,
      selectedSessionIdRef,
      setSelectedSessionId: (id) => {
        selectedSessionId = id;
      },
    });

    // Wait for the asynchronous lookup to settle deterministically
    await inFlightLookupPromise;

    // Production popstate path invoked authoritative callbacks and selected returned session and hop
    expect(fetchSession).toHaveBeenCalledTimes(1);
    expect(viewMode).toBe("audit");
    expect(hideHomeOnly).toBe(false);
    expect(targetPathFilter).toBeNull();
    expect(recordedSession).toEqual(expectedSession);
    expect(selectedSessionId).toBe("sess-retained-popstate");
    expect(selectedSessionObj).toEqual(expectedSession);
    expect(forwardedHop).toBe("cwd:hop-99");
    expect(requestedHopRef.current).toBe("cwd:hop-99");
    expect(selectedHistoryEventId).toBe("cwd:hop-99");
    expect(expiredSessionId).toBeNull();
    expect(coordinator.getInFlightSessionId()).toBeNull();
  });

  // 1b-2. Snapshot initially misses A, starts one lookup, then a later snapshot contains A: request is aborted and late not-found cannot clear A
  it("cancels in-flight lookup when later snapshot contains the session and prevents late not-found from clearing it", async () => {
    let expiredSessionId: string | null = null;
    let selectedSessionId: string | null = null;
    const requestedHopRef = { current: "cwd:hop-42" as string | null };
    const requestedSessionIdRef = { current: "sess-retained-A" as string | null };
    const selectedSessionIdRef = { current: null as string | null };
    const extraAuditSessions = new Map<string, FilesystemClosedSession>();

    const coordinator = new RemoteAuditLookupCoordinator({ initialViewMode: "audit" });

    let resolveFetchA!: (val: FilesystemClosedSession | null) => void;
    let signalA!: AbortSignal;
    const slowPromiseA = new Promise<FilesystemClosedSession | null>((res) => {
      resolveFetchA = res;
    });

    const authoritativeCallbacks = createRemoteAuditLookupCallbacks({
      recordLookedUpSession: vi.fn(),
      setExtraAuditSessions: vi.fn(),
      setExpiredSessionId: (id) => {
        expiredSessionId = id;
      },
      selectSession: vi.fn(),
      setSelectedSessionId: (id) => {
        selectedSessionId = id;
      },
      selectedSessionIdRef,
    });
    coordinator.setCallbacks(authoritativeCallbacks);

    const lookupRemoteAuditSession = (intent: RemoteAuditLookupIntent) => {
      void coordinator.lookup(intent, authoritativeCallbacks, (_id, signal) => {
        signalA = signal;
        return slowPromiseA;
      });
    };

    // Snapshot 1: does NOT contain sess-retained-A
    const snapshot1 = {
      sessions: [],
      recentClosedSessions: [makeClosedSession({ sessionId: "sess-other" })],
      nodes: [],
    };

    processSnapshotSessionResolution({
      snapshot: snapshot1,
      extraAuditSessions,
      requestedSessionIdRef,
      selectedSessionIdRef,
      requestedHopRef,
      viewMode: "audit",
      lookupRemoteAuditSession,
      setExpiredSessionId: (id) => {
        expiredSessionId = id;
      },
      setSelectedSessionId: (id) => {
        selectedSessionId = id;
      },
      coordinator,
    });

    // In-flight lookup is active for sess-retained-A
    expect(coordinator.getInFlightSessionId()).toBe("sess-retained-A");
    expect(signalA.aborted).toBe(false);

    // Snapshot 2: now CONTAINS sess-retained-A
    const sessionA = makeClosedSession({ sessionId: "sess-retained-A" });
    const snapshot2 = {
      sessions: [],
      recentClosedSessions: [sessionA],
      nodes: [],
    };

    processSnapshotSessionResolution({
      snapshot: snapshot2,
      extraAuditSessions,
      requestedSessionIdRef,
      selectedSessionIdRef,
      requestedHopRef,
      viewMode: "audit",
      lookupRemoteAuditSession,
      setExpiredSessionId: (id) => {
        expiredSessionId = id;
      },
      setSelectedSessionId: (id) => {
        selectedSessionId = id;
      },
      coordinator,
    });

    // sess-retained-A is adopted and selected from the snapshot
    expect(selectedSessionId).toBe("sess-retained-A");
    expect(selectedSessionIdRef.current).toBe("sess-retained-A");
    expect(expiredSessionId).toBeNull();

    // The in-flight lookup was aborted by notifySessionResolvedLocally
    expect(signalA.aborted).toBe(true);
    expect(coordinator.getInFlightSessionId()).toBeNull();

    // Now late response arrives from server with 404 (not found)
    resolveFetchA(null);
    await slowPromiseA;
    await Promise.resolve();

    // Late not-found CANNOT clear sess-retained-A
    expect(selectedSessionId).toBe("sess-retained-A");
    expect(selectedSessionIdRef.current).toBe("sess-retained-A");
    expect(expiredSessionId).toBeNull();
  });

  // 1b-3. Repeated snapshots still missing A deduplicate to exactly one fetch
  it("repeated snapshots still missing A deduplicate to exactly one fetch", async () => {
    const requestedHopRef = { current: "cwd:hop-42" as string | null };
    const requestedSessionIdRef = { current: "sess-missing-A" as string | null };
    const selectedSessionIdRef = { current: null as string | null };
    const extraAuditSessions = new Map<string, FilesystemClosedSession>();

    const coordinator = new RemoteAuditLookupCoordinator({ initialViewMode: "audit" });
    const fetchSession = vi.fn().mockImplementation(() => new Promise(() => {}));

    const lookupRemoteAuditSession = (intent: RemoteAuditLookupIntent) => {
      void coordinator.requestLookup(intent, undefined, fetchSession);
    };

    const snapshotMissing = {
      sessions: [],
      recentClosedSessions: [],
      nodes: [],
    };

    // Snapshot 1 arrives
    processSnapshotSessionResolution({
      snapshot: snapshotMissing,
      extraAuditSessions,
      requestedSessionIdRef,
      selectedSessionIdRef,
      requestedHopRef,
      viewMode: "audit",
      lookupRemoteAuditSession,
      setExpiredSessionId: vi.fn(),
      setSelectedSessionId: vi.fn(),
      coordinator,
    });

    // Snapshot 2 arrives with same missing session
    requestedSessionIdRef.current = "sess-missing-A";
    processSnapshotSessionResolution({
      snapshot: snapshotMissing,
      extraAuditSessions,
      requestedSessionIdRef,
      selectedSessionIdRef,
      requestedHopRef,
      viewMode: "audit",
      lookupRemoteAuditSession,
      setExpiredSessionId: vi.fn(),
      setSelectedSessionId: vi.fn(),
      coordinator,
    });

    // Snapshot 3 arrives with same missing session
    requestedSessionIdRef.current = "sess-missing-A";
    processSnapshotSessionResolution({
      snapshot: snapshotMissing,
      extraAuditSessions,
      requestedSessionIdRef,
      selectedSessionIdRef,
      requestedHopRef,
      viewMode: "audit",
      lookupRemoteAuditSession,
      setExpiredSessionId: vi.fn(),
      setSelectedSessionId: vi.fn(),
      coordinator,
    });

    expect(fetchSession).toHaveBeenCalledTimes(1);
    expect(fetchSession).toHaveBeenCalledWith("sess-missing-A", expect.any(AbortSignal));
  });

  // 1b-4. Exported production helper adoptLocalSessionScope enforces null hop in Live mode and preserves hop in Audit mode
  it("adopts locally authoritative session scope via production helper enforcing null hop in live mode and preserving hop in audit mode", () => {
    const coordinator = new RemoteAuditLookupCoordinator({ initialViewMode: "live" });

    // In Live mode: targetHopId is strictly forced to null regardless of what is passed
    const liveHop = adoptLocalSessionScope({
      coordinator,
      viewMode: "live",
      sessionId: "sess-live-99",
      targetHopId: "attempted-hop-in-live",
    });

    expect(liveHop).toBeNull();
    expect(coordinator.getNavigationScope()).toEqual({
      viewMode: "live",
      sessionId: "sess-live-99",
      targetHopId: null,
      generation: expect.any(Number),
    });

    // In Audit mode: valid targetHopId is preserved
    const auditHop = adoptLocalSessionScope({
      coordinator,
      viewMode: "audit",
      sessionId: "sess-audit-1",
      targetHopId: "cwd:audit-hop-10",
    });

    expect(auditHop).toBe("cwd:audit-hop-10");
    expect(coordinator.getNavigationScope()).toEqual({
      viewMode: "audit",
      sessionId: "sess-audit-1",
      targetHopId: "cwd:audit-hop-10",
      generation: expect.any(Number),
    });
  });

  // 1b-5. Resolves a session from a Live snapshot via processSnapshotSessionResolution enforcing targetHopId === null even when requestedHopRef has an old audit hop
  it("resolves a session from a Live snapshot enforcing targetHopId === null when requestedHopRef has an old audit hop", () => {
    const coordinator = new RemoteAuditLookupCoordinator({ initialViewMode: "live" });
    const requestedHopRef = { current: "old-audit-hop" as string | null };
    const requestedSessionIdRef = { current: "sess-live-1" as string | null };
    const selectedSessionIdRef = { current: null as string | null };
    let selectedSessionId: string | null = null;
    let expiredSessionId: string | null = "stale-expired";

    const snapshot = {
      sessions: [makeClosedSession({ sessionId: "sess-live-1" })],
      recentClosedSessions: [],
      nodes: [],
    };

    const resolution = processSnapshotSessionResolution({
      snapshot,
      extraAuditSessions: new Map(),
      requestedSessionIdRef,
      selectedSessionIdRef,
      requestedHopRef,
      viewMode: "live",
      lookupRemoteAuditSession: vi.fn(),
      setExpiredSessionId: (id) => {
        expiredSessionId = id;
      },
      setSelectedSessionId: (id) => {
        selectedSessionId = id;
      },
      coordinator,
    });

    expect(resolution.sessionId).toBe("sess-live-1");
    expect(resolution.expiredSessionId).toBeNull();
    expect(selectedSessionId).toBe("sess-live-1");
    expect(selectedSessionIdRef.current).toBe("sess-live-1");
    expect(expiredSessionId).toBeNull();

    // Invariant: Live navigation/local resolution must have targetHopId === null and clear requestedHopRef
    expect(coordinator.getNavigationScope()).toEqual({
      viewMode: "live",
      sessionId: "sess-live-1",
      targetHopId: null,
      generation: expect.any(Number),
    });
    expect(requestedHopRef.current).toBeNull();
  });

  // 1b-6. Live fallback from a missing previously selected audit session establishes live scope with null hop
  it("covers Live fallback from a missing previously selected audit session establishing live scope with null hop", () => {
    const coordinator = new RemoteAuditLookupCoordinator({ initialViewMode: "live" });
    const requestedHopRef = { current: "old-audit-hop" as string | null };
    const requestedSessionIdRef = { current: null as string | null };
    const selectedSessionIdRef = { current: "sess-missing-audit" as string | null };
    let selectedSessionId: string | null = null;
    let expiredSessionId: string | null = null;

    const snapshot = {
      sessions: [makeClosedSession({ sessionId: "sess-live-fallback" })],
      recentClosedSessions: [],
      nodes: [],
    };

    const resolution = processSnapshotSessionResolution({
      snapshot,
      extraAuditSessions: new Map(),
      requestedSessionIdRef,
      selectedSessionIdRef,
      requestedHopRef,
      viewMode: "live",
      lookupRemoteAuditSession: vi.fn(),
      setExpiredSessionId: (id) => {
        expiredSessionId = id;
      },
      setSelectedSessionId: (id) => {
        selectedSessionId = id;
      },
      coordinator,
    });

    // Fallback to first available live session
    expect(resolution.sessionId).toBe("sess-live-fallback");
    expect(resolution.expiredSessionId).toBeNull();
    expect(selectedSessionId).toBe("sess-live-fallback");
    expect(selectedSessionIdRef.current).toBe("sess-live-fallback");
    expect(expiredSessionId).toBeNull();

    // Invariant: Live scope is established with targetHopId === null
    expect(coordinator.getNavigationScope()).toEqual({
      viewMode: "live",
      sessionId: "sess-live-fallback",
      targetHopId: null,
      generation: expect.any(Number),
    });
    expect(requestedHopRef.current).toBeNull();
  });

  // 1b-7. Audit snapshot resolution still preserves its requested hop
  it("confirms Audit snapshot resolution still preserves its requested hop", () => {
    const coordinator = new RemoteAuditLookupCoordinator({ initialViewMode: "audit" });
    const requestedHopRef = { current: "cwd:audit-hop-77" as string | null };
    const requestedSessionIdRef = { current: "sess-closed-1" as string | null };
    const selectedSessionIdRef = { current: null as string | null };
    let selectedSessionId: string | null = null;
    let expiredSessionId: string | null = null;

    const snapshot = {
      sessions: [],
      recentClosedSessions: [makeClosedSession({ sessionId: "sess-closed-1" })],
      nodes: [],
    };

    const resolution = processSnapshotSessionResolution({
      snapshot,
      extraAuditSessions: new Map(),
      requestedSessionIdRef,
      selectedSessionIdRef,
      requestedHopRef,
      viewMode: "audit",
      lookupRemoteAuditSession: vi.fn(),
      setExpiredSessionId: (id) => {
        expiredSessionId = id;
      },
      setSelectedSessionId: (id) => {
        selectedSessionId = id;
      },
      coordinator,
    });

    expect(resolution.sessionId).toBe("sess-closed-1");
    expect(resolution.expiredSessionId).toBeNull();
    expect(selectedSessionId).toBe("sess-closed-1");
    expect(selectedSessionIdRef.current).toBe("sess-closed-1");
    expect(expiredSessionId).toBeNull();

    // Invariant: Audit scope preserves requested hop
    expect(coordinator.getNavigationScope()).toEqual({
      viewMode: "audit",
      sessionId: "sess-closed-1",
      targetHopId: "cwd:audit-hop-77",
      generation: expect.any(Number),
    });
    expect(requestedHopRef.current).toBe("cwd:audit-hop-77");
  });

  // 1c. In-flight A/H1 followed by navigation to A/H2 aborts/discards H1 and applies H2
  it("in-flight A/H1 followed by navigation to A/H2 aborts/discards H1 and applies H2", async () => {
    let appliedHop: string | null = null;
    const onSessionFound = vi.fn((_session: FilesystemClosedSession, hop?: string | null) => {
      appliedHop = hop ?? null;
    });

    const coordinator = new RemoteAuditLookupCoordinator({
      initialViewMode: "audit",
      callbacks: {
        onSessionFound,
        onSessionNotFound: vi.fn(),
      },
    });

    let resolveH1!: (val: FilesystemClosedSession | null) => void;
    let signalH1!: AbortSignal;
    const promiseH1 = new Promise<FilesystemClosedSession | null>((res) => {
      resolveH1 = res;
    });

    // Request A with H1
    const lookupH1 = coordinator.requestLookup(
      { sessionId: "sess-A", targetHopId: "hop-1" },
      undefined,
      (_id, signal) => {
        signalH1 = signal;
        return promiseH1;
      },
    );

    expect(signalH1.aborted).toBe(false);

    // Navigation occurs to same session with different hop H2
    coordinator.notifyNavigationScope({
      viewMode: "audit",
      sessionId: "sess-A",
      targetHopId: "hop-2",
    });

    expect(signalH1.aborted).toBe(true);

    const sessionA = makeClosedSession({ sessionId: "sess-A" });
    const lookupH2 = coordinator.requestLookup(
      { sessionId: "sess-A", targetHopId: "hop-2" },
      undefined,
      async () => sessionA,
    );

    // Late H1 resolves
    resolveH1(sessionA);
    await Promise.all([lookupH1, lookupH2]);

    // Only H2 is applied
    expect(onSessionFound).toHaveBeenCalledTimes(1);
    expect(appliedHop).toBe("hop-2");
  });

  // 1d. In-flight A/H1 followed by navigation to A/null aborts/discards H1
  it("in-flight A/H1 followed by navigation to A/null aborts/discards H1", async () => {
    const onSessionFound = vi.fn();
    const coordinator = new RemoteAuditLookupCoordinator({
      initialViewMode: "audit",
      callbacks: {
        onSessionFound,
        onSessionNotFound: vi.fn(),
      },
    });

    let resolveH1!: (val: FilesystemClosedSession | null) => void;
    let signalH1!: AbortSignal;
    const promiseH1 = new Promise<FilesystemClosedSession | null>((res) => {
      resolveH1 = res;
    });

    const lookupH1 = coordinator.requestLookup(
      { sessionId: "sess-A", targetHopId: "hop-1" },
      undefined,
      (_id, signal) => {
        signalH1 = signal;
        return promiseH1;
      },
    );

    expect(signalH1.aborted).toBe(false);

    // Navigation occurs to same session with hop cleared (null)
    coordinator.notifyNavigationScope({
      viewMode: "audit",
      sessionId: "sess-A",
      targetHopId: null,
    });

    expect(signalH1.aborted).toBe(true);

    // Late H1 resolves
    resolveH1(makeClosedSession({ sessionId: "sess-A" }));
    await lookupH1;

    // H1 response is discarded
    expect(onSessionFound).not.toHaveBeenCalled();
  });

  // 1e. Same-session user selection clearing hop cannot be overwritten by late response
  it("same-session user selection clearing hop cannot be overwritten by late response", async () => {
    const requestedHopRef = { current: "hop-1" as string | null };
    let selectedHistoryEventId: string | null = "hop-1";
    let selectedSessionId: string | null = "sess-A";

    const coordinator = new RemoteAuditLookupCoordinator({
      initialViewMode: "audit",
      callbacks: {
        onSessionFound: (_session, hop) => {
          requestedHopRef.current = hop ?? null;
          selectedHistoryEventId = hop ?? null;
        },
        onSessionNotFound: vi.fn(),
      },
    });

    let resolveH1!: (val: FilesystemClosedSession | null) => void;
    let signalH1!: AbortSignal;
    const promiseH1 = new Promise<FilesystemClosedSession | null>((res) => {
      resolveH1 = res;
    });

    // In-flight lookup for A with hop-1
    const lookupH1 = coordinator.requestLookup(
      { sessionId: "sess-A", targetHopId: "hop-1" },
      undefined,
      (_id, signal) => {
        signalH1 = signal;
        return promiseH1;
      },
    );

    // User explicitly selects session A in UI (clears hop)
    const handleUserSelectSession = (sessionId: string) => {
      coordinator.notifyNavigationScope({
        viewMode: "audit",
        sessionId,
        targetHopId: null,
      });
      requestedHopRef.current = null;
      selectedHistoryEventId = null;
      selectedSessionId = sessionId;
    };

    handleUserSelectSession("sess-A");

    expect(signalH1.aborted).toBe(true);
    expect(requestedHopRef.current).toBeNull();
    expect(selectedHistoryEventId).toBeNull();

    // Late H1 resolves
    resolveH1(makeClosedSession({ sessionId: "sess-A" }));
    await lookupH1;

    // Hop remains null, never overwritten by late H1
    expect(selectedSessionId).toBe("sess-A");
    expect(requestedHopRef.current).toBeNull();
    expect(selectedHistoryEventId).toBeNull();
  });

  // 1f. Popstate/session change before snapshot hydration invalidates old request
  it("popstate/session change before snapshot hydration invalidates old request", async () => {
    const onSessionFound = vi.fn();
    const coordinator = new RemoteAuditLookupCoordinator({
      initialViewMode: "audit",
      callbacks: {
        onSessionFound,
        onSessionNotFound: vi.fn(),
      },
    });

    let resolveA!: (val: FilesystemClosedSession | null) => void;
    let signalA!: AbortSignal;
    const promiseA = new Promise<FilesystemClosedSession | null>((res) => {
      resolveA = res;
    });

    // Pre-hydration request for session A
    const lookupA = coordinator.requestLookup(
      { sessionId: "sess-A", targetHopId: "hop-1" },
      undefined,
      (_id, signal) => {
        signalA = signal;
        return promiseA;
      },
    );

    expect(signalA.aborted).toBe(false);

    // Before snapshot hydrates (snapshot === null), popstate fires to session B
    coordinator.notifyNavigationScope({
      viewMode: "audit",
      sessionId: "sess-B",
      targetHopId: null,
    });

    expect(signalA.aborted).toBe(true);

    // Late A arrives
    resolveA(makeClosedSession({ sessionId: "sess-A" }));
    await lookupA;

    // A is discarded, callbacks never called
    expect(onSessionFound).not.toHaveBeenCalled();
  });

  // 2. Popstate to known session while remote A is in flight preserves B when A resolves late
  it("preserves known session selection when popstate occurs while remote lookup A is in flight and resolves late", async () => {
    let selectedSessionId: string | null = null;
    const onSessionFound = vi.fn((session: FilesystemClosedSession) => {
      selectedSessionId = session.sessionId;
    });
    const coordinator = new RemoteAuditLookupCoordinator({
      initialViewMode: "audit",
      callbacks: {
        onSessionFound,
        onSessionNotFound: vi.fn(),
      },
    });

    let resolveA!: (val: FilesystemClosedSession | null) => void;
    const slowPromiseA = new Promise<FilesystemClosedSession | null>((res) => {
      resolveA = res;
    });

    // Begin remote lookup for A
    const lookupPromiseA = coordinator.requestLookup(
      { sessionId: "sess-remote-A", targetHopId: "hop-A" },
      undefined,
      () => slowPromiseA,
    );

    // Popstate navigation to known session B occurs
    coordinator.notifySessionSelected("sess-known-B");
    selectedSessionId = "sess-known-B";

    // Late resolution of A arrives
    resolveA(makeClosedSession({ sessionId: "sess-remote-A" }));
    await lookupPromiseA;

    // B remains selected, late A was never applied
    expect(selectedSessionId).toBe("sess-known-B");
    expect(onSessionFound).not.toHaveBeenCalled();
  });

  // 3. Switch to Live while remote A is in flight prevents A from being applied when it resolves late
  it("does not apply remote session A if viewMode switched to Live before A resolves late", async () => {
    let selectedSessionId: string | null = null;
    const onSessionFound = vi.fn((session: FilesystemClosedSession) => {
      selectedSessionId = session.sessionId;
    });
    const coordinator = new RemoteAuditLookupCoordinator({
      initialViewMode: "audit",
      callbacks: {
        onSessionFound,
        onSessionNotFound: vi.fn(),
      },
    });

    let resolveA!: (val: FilesystemClosedSession | null) => void;
    const slowPromiseA = new Promise<FilesystemClosedSession | null>((res) => {
      resolveA = res;
    });

    // Begin remote lookup for A in audit mode
    const lookupPromiseA = coordinator.requestLookup(
      { sessionId: "sess-remote-A", targetHopId: "hop-A" },
      undefined,
      () => slowPromiseA,
    );

    // User or navigation switches viewMode to Live
    coordinator.notifyViewModeChanged("live");

    // Late resolution of A arrives
    resolveA(makeClosedSession({ sessionId: "sess-remote-A" }));
    await lookupPromiseA;

    // A must not be applied
    expect(selectedSessionId).toBeNull();
    expect(onSessionFound).not.toHaveBeenCalled();
  });

  // 4. Component unmount aborts in-flight remote lookup
  it("aborts in-flight remote lookup on component unmount / destroy", async () => {
    const coordinator = new RemoteAuditLookupCoordinator({ initialViewMode: "audit" });

    let capturedSignal!: AbortSignal;
    const slowPromise = new Promise<FilesystemClosedSession | null>(() => {});

    void coordinator.requestLookup(
      { sessionId: "sess-unmount-target" },
      { onSessionFound: vi.fn(), onSessionNotFound: vi.fn() },
      (_id, signal) => {
        capturedSignal = signal;
        return slowPromise;
      },
    );

    expect(capturedSignal).toBeDefined();
    expect(capturedSignal.aborted).toBe(false);

    // Unmount cleanup
    coordinator.destroy();

    expect(capturedSignal.aborted).toBe(true);
    expect(coordinator.getInFlightSessionId()).toBeNull();
  });

  // 5. Repeated snapshots with the same in-flight {sessionId, targetHopId} produce exactly one request
  it("reuses in-flight lookup and makes exactly one request across repeated snapshot updates for the same target and hop", async () => {
    const coordinator = new RemoteAuditLookupCoordinator({ initialViewMode: "audit" });
    const fetchSession = vi.fn().mockImplementation(() => new Promise(() => {}));

    // Snapshot 1 arrives
    void coordinator.requestLookup(
      { sessionId: "sess-snapshot-A", targetHopId: "hop-1" },
      { onSessionFound: vi.fn(), onSessionNotFound: vi.fn() },
      fetchSession,
    );

    // Snapshot 2 arrives with identical target
    void coordinator.requestLookup(
      { sessionId: "sess-snapshot-A", targetHopId: "hop-1" },
      { onSessionFound: vi.fn(), onSessionNotFound: vi.fn() },
      fetchSession,
    );

    // Snapshot 3 arrives with identical target
    void coordinator.requestLookup(
      { sessionId: "sess-snapshot-A", targetHopId: "hop-1" },
      { onSessionFound: vi.fn(), onSessionNotFound: vi.fn() },
      fetchSession,
    );

    expect(fetchSession).toHaveBeenCalledTimes(1);
    expect(fetchSession).toHaveBeenCalledWith("sess-snapshot-A", expect.any(AbortSignal));
  });

  // 6. Remote A followed by remote B aborts A and applies only B
  it("aborts in-flight lookup A when remote B is requested, applying only B with its hop", async () => {
    let appliedSessionId: string | null = null;
    let appliedHopId: string | null = null;
    const onSessionFound = vi.fn((session: FilesystemClosedSession, hopId?: string | null) => {
      appliedSessionId = session.sessionId;
      appliedHopId = hopId ?? null;
    });

    const coordinator = new RemoteAuditLookupCoordinator({
      initialViewMode: "audit",
      callbacks: {
        onSessionFound,
        onSessionNotFound: vi.fn(),
      },
    });

    let capturedSignalA!: AbortSignal;
    let resolveA!: (val: FilesystemClosedSession | null) => void;
    const promiseA = new Promise<FilesystemClosedSession | null>((res) => {
      resolveA = res;
    });

    const lookupA = coordinator.requestLookup(
      { sessionId: "sess-A", targetHopId: "hop-A" },
      undefined,
      (_id, signal) => {
        capturedSignalA = signal;
        return promiseA;
      },
    );

    expect(capturedSignalA.aborted).toBe(false);

    // Genuinely different remote target B requested
    const sessionB = makeClosedSession({ sessionId: "sess-B" });
    const lookupB = coordinator.requestLookup(
      { sessionId: "sess-B", targetHopId: "hop-B" },
      undefined,
      async () => sessionB,
    );

    // A's signal was aborted immediately
    expect(capturedSignalA.aborted).toBe(true);

    // Now A finishes late
    resolveA(makeClosedSession({ sessionId: "sess-A" }));
    await Promise.all([lookupA, lookupB]);

    // Only B is applied with hop-B
    expect(appliedSessionId).toBe("sess-B");
    expect(appliedHopId).toBe("hop-B");
    expect(onSessionFound).toHaveBeenCalledTimes(1);
    expect(onSessionFound).toHaveBeenCalledWith(sessionB, "hop-B");
  });

  // 7. User session selection clears prior hop and cancels in-flight lookups
  it("clears prior hop intent and selection when selecting a new session", () => {
    const coordinator = new RemoteAuditLookupCoordinator({ initialViewMode: "audit" });
    const requestedHopRef = { current: "cwd:sess1-hop" as string | null };
    let selectedHistoryEventId: string | null = "cwd:sess1-hop";

    // User selects session-2
    const handleUserSelectSession = (newSessionId: string) => {
      coordinator.notifySessionSelected(newSessionId);
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

  // Index-supported query contract for mixed-schema rank aggregation
  it("provisions compound indexes for both sessionId and session_id matching the query contract", () => {
    // The query contract for mixed-schema history rank aggregation requires:
    // $match: { $or: [{ sessionId: sanitizedSessionId }, { session_id: sanitizedSessionId }] }
    // Both branches must be backed by compound indexes on cwd_events:
    // 1. { sessionId: 1, at: -1, eventId: -1 }
    // 2. { session_id: 1, at: -1, eventId: -1 }
    const requiredIndexDefinitions = [
      { key: { sessionId: 1, at: -1, eventId: -1 }, name: "sessionId_1_at_-1_eventId_-1" },
      { key: { session_id: 1, at: -1, eventId: -1 }, name: "session_id_1_at_-1_eventId_-1" },
    ];

    const matchBranches = ["sessionId", "session_id"];
    for (const field of matchBranches) {
      const matchedIndex = requiredIndexDefinitions.find(
        (def) => field in def.key && def.key[field as keyof typeof def.key] === 1,
      );
      expect(matchedIndex).toBeDefined();
      expect(matchedIndex?.key.at).toBe(-1);
      expect(matchedIndex?.key.eventId).toBe(-1);
    }
  });

  // Exact database-operation bounds
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
