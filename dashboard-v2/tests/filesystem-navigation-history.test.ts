// @vitest-environment happy-dom
import { act, createElement, useEffect } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// @ts-expect-error React act environment flag
globalThis.IS_REACT_ACT_ENVIRONMENT = true;

vi.mock("server-only", () => ({}));

import type {
  FilesystemClosedSession,
  FilesystemTopologySnapshot,
} from "@/lib/dashboardTypes";
import {
  FilesystemNavigationCoordinator,
  type FilesystemNavigationCoordinatorOptions,
} from "@/components/filesystem/filesystemNavigationCoordinator";
import {
  useFilesystemUrlState,
  type UseFilesystemUrlStateReturn,
} from "@/components/filesystem/useFilesystemUrlState";
import {
  RemoteAuditLookupCoordinator,
  createRemoteAuditLookupCallbacks,
  createRemoteAuditLookupTerminalObserver,
} from "@/components/filesystem/sessionHopResolver";

function makeSession(
  id: string,
  overrides: Partial<FilesystemClosedSession> = {},
): FilesystemClosedSession {
  const defaultPath = overrides.cwdState?.path ?? "/root";
  const defaultHomeOnly = overrides.auditSummary?.homeOnly ?? false;
  const defaultVisitedPaths = overrides.auditSummary?.visitedPaths ?? [defaultPath];
  return {
    sessionId: id,
    sourceIp: "192.168.1.100",
    cwdState: {
      path: defaultPath,
      status: "confirmed",
      observedAt: "2026-09-17T00:00:00.000Z",
      sourceEventId: "evt-001",
      ...overrides.cwdState,
    },
    lifecycle: {
      startedAt: "2026-09-16T23:00:00.000Z",
      closedAt: "2026-09-17T00:00:00.000Z",
      ...overrides.lifecycle,
    },
    auditSummary: {
      visitedPaths: defaultVisitedPaths,
      homeOnly: defaultHomeOnly,
      eventCount: defaultVisitedPaths.length,
      ...overrides.auditSummary,
    },
    ...overrides,
  };
}

function createDeferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((promiseResolve, promiseReject) => {
    resolve = promiseResolve;
    reject = promiseReject;
  });
  return { promise, resolve, reject };
}

async function flushMicrotasks(): Promise<void> {
  await Promise.resolve();
  await Promise.resolve();
  await Promise.resolve();
}

describe("FA-008: Filesystem Activity Navigation History Traversability", () => {
  let container: HTMLDivElement;
  let root: Root;
  let originalPathname: string;
  let originalSearch: string;
  let originalHash: string;

  beforeEach(() => {
    container = document.createElement("div");
    document.body.appendChild(container);
    root = createRoot(container);

    originalPathname = window.location.pathname;
    originalSearch = window.location.search;
    originalHash = window.location.hash;

    // Reset URL to clean state
    window.history.replaceState(null, "", "/filesystem-activity");
  });

  afterEach(() => {
    act(() => {
      root.unmount();
    });
    container.remove();
    window.history.replaceState(null, "", `${originalPathname}${originalSearch}${originalHash}`);
    vi.restoreAllMocks();
  });

  function setupCoordinatorHarness(
    initialUrl = "/filesystem-activity?view=audit&sessionId=sess-1",
    optionsOverride: Partial<FilesystemNavigationCoordinatorOptions> = {},
  ) {
    const rawReplaceState = window.history.replaceState.bind(window.history);
    rawReplaceState(null, "", initialUrl);
    const pushStateSpy = vi.spyOn(window.history, "pushState");
    const replaceStateSpy = vi.spyOn(window.history, "replaceState");

    let viewMode: "live" | "audit" = initialUrl.includes("view=live") ? "live" : "audit";
    let selectedSessionId: string | null = initialUrl.includes("sessionId=sess-")
      ? (new URLSearchParams(initialUrl.split("?")[1]).get("sessionId"))
      : null;
    let hideHomeOnly = initialUrl.includes("hideHome=1");
    let targetPathFilter: string | null = new URLSearchParams(initialUrl.split("?")[1] || "").get("targetPath");
    let selectedHistoryEventId: string | null = new URLSearchParams(initialUrl.split("?")[1] || "").get("hop");
    let requestedHop: string | null = selectedHistoryEventId;
    let requestedSessionId: string | null = selectedSessionId;
    let expiredSessionId: string | null = null;

    const session1 = makeSession("sess-1", {
      cwdState: { path: "/root", status: "confirmed", sourceEventId: null, observedAt: "" },
      auditSummary: { visitedPaths: ["/root"], homeOnly: false, eventCount: 1 },
    });
    const session2 = makeSession("sess-2", {
      cwdState: { path: "/var/log", status: "confirmed", sourceEventId: null, observedAt: "" },
      auditSummary: { visitedPaths: ["/var/log"], homeOnly: false, eventCount: 1 },
    });
    const homeOnlySession = makeSession("sess-home", {
      cwdState: { path: "/home/user", status: "confirmed", sourceEventId: null, observedAt: "" },
      auditSummary: { visitedPaths: ["/home/user"], homeOnly: true, eventCount: 1 },
    });
    const nonHomeSession = makeSession("sess-nonhome", {
      cwdState: { path: "/var/log", status: "confirmed", sourceEventId: null, observedAt: "" },
      auditSummary: { visitedPaths: ["/var/log"], homeOnly: false, eventCount: 1 },
    });
    const etcSession = makeSession("sess-etc", {
      cwdState: { path: "/etc", status: "confirmed", sourceEventId: null, observedAt: "" },
      auditSummary: { visitedPaths: ["/etc"], homeOnly: false, eventCount: 1 },
    });
    const varSession = makeSession("sess-var", {
      cwdState: { path: "/var", status: "confirmed", sourceEventId: null, observedAt: "" },
      auditSummary: { visitedPaths: ["/var"], homeOnly: false, eventCount: 1 },
    });

    const allSessions = [session1, session2, homeOnlySession, nonHomeSession, etcSession, varSession];
    const sessionById = new Map(allSessions.map((s) => [s.sessionId, s]));

    const snapshot: FilesystemTopologySnapshot = {
      sessions: allSessions,
      recentClosedSessions: [],
      nodes: [],
      truncated: false,
      generatedAt: "2026-09-17T00:00:00.000Z",
    };

    const extraAuditSessions = new Map<string, FilesystemClosedSession>();

    const coordinator = new RemoteAuditLookupCoordinator({
      initialViewMode: viewMode,
      initialSessionId: selectedSessionId,
    });

    const resetRequestedHopState = vi.fn(() => {
      requestedHop = null;
      selectedHistoryEventId = null;
    });

    const selectSession = vi.fn(
      (
        sid: string,
        _sObj?: FilesystemTopologySession | FilesystemClosedSession,
        hop?: string | null,
      ) => {
        selectedSessionId = sid;
        if (hop !== undefined) {
          requestedHop = hop;
          selectedHistoryEventId = hop;
        }
      },
    );

    const resetHistory = vi.fn();

    const navCoordinator = new FilesystemNavigationCoordinator({
      getViewMode: () => viewMode,
      getSelectedSessionId: () => selectedSessionId,
      getHideHomeOnly: () => hideHomeOnly,
      getTargetPathFilter: () => targetPathFilter,
      getSelectedHistoryEventId: () => selectedHistoryEventId,
      getRequestedHop: () => requestedHop,
      getExpiredSessionId: () => expiredSessionId,
      getSnapshot: () => snapshot,
      getExtraAuditSessions: () => extraAuditSessions,
      getAllSessions: () => allSessions,
      getSessionById: () => sessionById,

      setViewMode: (v) => { viewMode = v; },
      setHideHomeOnly: (h) => { hideHomeOnly = h; },
      setTargetPathFilter: (p) => { targetPathFilter = p; },
      setSelectedHistoryEventId: (id) => { selectedHistoryEventId = id; },
      setExpiredSessionId: (id) => { expiredSessionId = id; },
      setSelectedSessionId: (id) => { selectedSessionId = id; },
      setRequestedHop: (hop) => { requestedHop = hop; },
      setRequestedSessionId: (sid) => { requestedSessionId = sid; },

      selectSession,
      resetHistory,
      resetRequestedHopState,

      coordinator,
      ...optionsOverride,
    });

    const originalHandlePopState = navCoordinator.handlePopState.bind(navCoordinator);
    navCoordinator.handlePopState = (searchString: string) => {
      const fullUrl = searchString.startsWith("/")
        ? searchString
        : `/filesystem-activity${searchString.startsWith("?") ? searchString : "?" + searchString}`;
      rawReplaceState(null, "", fullUrl);
      originalHandlePopState(searchString);
    };

    return {
      navCoordinator,
      coordinator,
      pushStateSpy,
      replaceStateSpy,
      selectSession,
      resetRequestedHopState,
      resetHistory,
      getState: () => ({
        viewMode,
        selectedSessionId,
        hideHomeOnly,
        targetPathFilter,
        selectedHistoryEventId,
        requestedHop,
        requestedSessionId,
        expiredSessionId,
      }),
      snapshot,
      extraAuditSessions,
      sessionById,
    };
  }

  // =========================================================================
  // Scenario 1: Selecting another session while the current URL has a hop creates exactly one push
  // =========================================================================
  it("Scenario 1: Selecting another session while the current URL has a hop creates exactly one push", () => {
    const { navCoordinator, pushStateSpy, resetRequestedHopState, getState } = setupCoordinatorHarness(
      "/filesystem-activity?view=audit&sessionId=sess-1&hop=hop-123",
    );

    // User selects session 2
    navCoordinator.userSelectSession("sess-2");

    // Exactly one pushState call
    expect(pushStateSpy).toHaveBeenCalledTimes(1);
    expect(pushStateSpy.mock.calls[0]?.[2]).toBe("/filesystem-activity?view=audit&sessionId=sess-2");

    // Internal hop state was cleaned up without additional history writes
    expect(resetRequestedHopState).toHaveBeenCalledTimes(1);
    expect(getState().selectedSessionId).toBe("sess-2");
    expect(getState().selectedHistoryEventId).toBeNull();
  });

  // =========================================================================
  // Scenario 2: One Back restores the prior session and hop
  // =========================================================================
  it("Scenario 2: One Back restores the prior session and hop", () => {
    const { navCoordinator, pushStateSpy, getState } = setupCoordinatorHarness(
      "/filesystem-activity?view=audit&sessionId=sess-1&hop=hop-123",
    );

    // 1. User selects sess-2
    navCoordinator.userSelectSession("sess-2");
    expect(getState().selectedSessionId).toBe("sess-2");

    pushStateSpy.mockClear();

    // 2. User presses browser Back
    navCoordinator.handlePopState("?view=audit&sessionId=sess-1&hop=hop-123");

    // Immediately restores session 1 and hop-123 in one step
    expect(getState().selectedSessionId).toBe("sess-1");
    expect(getState().selectedHistoryEventId).toBe("hop-123");

    // Popstate execution does not emit feedback pushState calls
    expect(pushStateSpy).not.toHaveBeenCalled();
  });

  // =========================================================================
  // Scenario 3: Hide-home fallback to another session creates exactly one push
  // =========================================================================
  it("Scenario 3: Hide-home fallback to another session creates exactly one push", () => {
    const homeOnly = makeSession("sess-home", {
      cwdState: { path: "/home/user", status: "confirmed", sourceEventId: null, observedAt: "" },
      auditSummary: { visitedPaths: ["/home/user"], homeOnly: true, eventCount: 1 },
    });
    const nonHome = makeSession("sess-nonhome", {
      cwdState: { path: "/var/log", status: "confirmed", sourceEventId: null, observedAt: "" },
      auditSummary: { visitedPaths: ["/var/log"], homeOnly: false, eventCount: 1 },
    });
    const sessions = [homeOnly, nonHome];

    const { navCoordinator, pushStateSpy, getState } = setupCoordinatorHarness(
      "/filesystem-activity?view=audit&sessionId=sess-home",
      {
        getAllSessions: () => sessions,
        getSessionById: () => new Map(sessions.map((s) => [s.sessionId, s])),
      },
    );

    // Toggle hideHome -> sess-home is filtered out, fall back to sess-nonhome
    navCoordinator.userToggleHideHome();

    // Exactly 1 pushState containing BOTH new filter and fallback session
    expect(pushStateSpy).toHaveBeenCalledTimes(1);
    expect(pushStateSpy.mock.calls[0]?.[2]).toBe(
      "/filesystem-activity?view=audit&sessionId=sess-nonhome&hideHome=1",
    );
    expect(getState().hideHomeOnly).toBe(true);
    expect(getState().selectedSessionId).toBe("sess-nonhome");
  });

  // =========================================================================
  // Scenario 4: Target-path fallback to another session creates exactly one push
  // =========================================================================
  it("Scenario 4: Target-path fallback to another session creates exactly one push", () => {
    const etcSess = makeSession("sess-etc", {
      cwdState: { path: "/etc", status: "confirmed", sourceEventId: null, observedAt: "" },
      auditSummary: { visitedPaths: ["/etc"], homeOnly: false, eventCount: 1 },
    });
    const varSess = makeSession("sess-var", {
      cwdState: { path: "/var", status: "confirmed", sourceEventId: null, observedAt: "" },
      auditSummary: { visitedPaths: ["/var"], homeOnly: false, eventCount: 1 },
    });
    const sessions = [etcSess, varSess];

    const { navCoordinator, pushStateSpy, getState } = setupCoordinatorHarness(
      "/filesystem-activity?view=audit&sessionId=sess-etc",
      {
        getAllSessions: () => sessions,
        getSessionById: () => new Map(sessions.map((s) => [s.sessionId, s])),
      },
    );

    // Select target path "/var" -> sess-etc is filtered out, fall back to sess-var
    navCoordinator.userSelectTargetPath("/var");

    // Exactly 1 pushState containing BOTH new targetPath and fallback session
    expect(pushStateSpy).toHaveBeenCalledTimes(1);
    expect(pushStateSpy.mock.calls[0]?.[2]).toBe(
      "/filesystem-activity?view=audit&sessionId=sess-var&targetPath=%2Fvar",
    );
    expect(getState().targetPathFilter).toBe("/var");
    expect(getState().selectedSessionId).toBe("sess-var");
  });

  // =========================================================================
  // Scenario 5: One Back from either fallback restores the complete prior filter/session/hop state
  // =========================================================================
  it("Scenario 5: One Back from either fallback restores the complete prior filter/session/hop state", () => {
    const homeOnly = makeSession("sess-home", {
      cwdState: { path: "/home/user", status: "confirmed", sourceEventId: null, observedAt: "" },
      auditSummary: { visitedPaths: ["/home/user"], homeOnly: true, eventCount: 1 },
    });
    const nonHome = makeSession("sess-nonhome", {
      cwdState: { path: "/var/log", status: "confirmed", sourceEventId: null, observedAt: "" },
      auditSummary: { visitedPaths: ["/var/log"], homeOnly: false, eventCount: 1 },
    });
    const sessions = [homeOnly, nonHome];

    const { navCoordinator, pushStateSpy, getState } = setupCoordinatorHarness(
      "/filesystem-activity?view=audit&sessionId=sess-home&hop=hop-initial",
      {
        getAllSessions: () => sessions,
        getSessionById: () => new Map(sessions.map((s) => [s.sessionId, s])),
      },
    );

    // Trigger fallback push
    navCoordinator.userToggleHideHome();
    expect(getState().selectedSessionId).toBe("sess-nonhome");
    expect(getState().hideHomeOnly).toBe(true);

    pushStateSpy.mockClear();

    // Browser Back to original state
    navCoordinator.handlePopState("?view=audit&sessionId=sess-home&hop=hop-initial");

    // Complete prior state is restored in one single step
    expect(getState().selectedSessionId).toBe("sess-home");
    expect(getState().hideHomeOnly).toBe(false);
    expect(getState().selectedHistoryEventId).toBe("hop-initial");
    expect(pushStateSpy).not.toHaveBeenCalled();
  });

  // =========================================================================
  // Scenario 6: Reset filters creates exactly one push and is traversable
  // =========================================================================
  it("Scenario 6: Reset filters creates exactly one push and is traversable", () => {
    const { navCoordinator, pushStateSpy, getState } = setupCoordinatorHarness(
      "/filesystem-activity?view=audit&sessionId=sess-1&hideHome=1&targetPath=%2Fvar&hop=hop-42",
    );

    // User clicks "Reset filters"
    navCoordinator.userResetFilters();

    // Pushes exactly once, clearing filters while preserving session & hop
    expect(pushStateSpy).toHaveBeenCalledTimes(1);
    expect(pushStateSpy.mock.calls[0]?.[2]).toBe(
      "/filesystem-activity?view=audit&sessionId=sess-1&hop=hop-42",
    );
    expect(getState().hideHomeOnly).toBe(false);
    expect(getState().targetPathFilter).toBeNull();
    expect(getState().selectedSessionId).toBe("sess-1");

    // Back restores filters
    navCoordinator.handlePopState("?view=audit&sessionId=sess-1&hideHome=1&targetPath=%2Fvar&hop=hop-42");
    expect(getState().hideHomeOnly).toBe(true);
    expect(getState().targetPathFilter).toBe("/var");

    // Repeating reset when already reset does not push
    pushStateSpy.mockClear();
    navCoordinator.userResetFilters();
    expect(pushStateSpy).toHaveBeenCalledTimes(1); // from non-reset state
    navCoordinator.userResetFilters();
    expect(pushStateSpy).toHaveBeenCalledTimes(1); // deduplicated!
  });

  // =========================================================================
  // Scenario 7: Clear selection creates exactly one push and is traversable
  // =========================================================================
  it("Scenario 7: Clear selection creates exactly one push and is traversable", () => {
    const { navCoordinator, coordinator, pushStateSpy, resetHistory, getState } = setupCoordinatorHarness(
      "/filesystem-activity?view=audit&sessionId=sess-1&hop=hop-1&hideHome=1",
    );

    // User clicks "Clear selection"
    navCoordinator.userClearSelection();

    // Exactly 1 push clearing session and hop, while preserving active filter
    expect(pushStateSpy).toHaveBeenCalledTimes(1);
    expect(pushStateSpy.mock.calls[0]?.[2]).toBe("/filesystem-activity?view=audit&hideHome=1");

    // Coordinator scope cleared, work aborted, history reset
    expect(coordinator.getNavigationScope().sessionId).toBeNull();
    expect(coordinator.getNavigationScope().targetHopId).toBeNull();
    expect(getState().selectedSessionId).toBeNull();
    expect(getState().selectedHistoryEventId).toBeNull();
    expect(resetHistory).toHaveBeenCalled();

    // Back restores selection
    navCoordinator.handlePopState("?view=audit&sessionId=sess-1&hop=hop-1&hideHome=1");
    expect(getState().selectedSessionId).toBe("sess-1");
    expect(getState().selectedHistoryEventId).toBe("hop-1");

    // Repeating clear selection when already cleared does not push
    pushStateSpy.mockClear();
    navCoordinator.userClearSelection();
    expect(pushStateSpy).toHaveBeenCalledTimes(1);
    navCoordinator.userClearSelection();
    expect(pushStateSpy).toHaveBeenCalledTimes(1); // deduplicated!
  });

  // =========================================================================
  // Scenario 8: The explicit Clear hop button creates exactly one push
  // =========================================================================
  it("Scenario 8: The explicit Clear hop button creates exactly one push", () => {
    const { navCoordinator, pushStateSpy, getState } = setupCoordinatorHarness(
      "/filesystem-activity?view=audit&sessionId=sess-1&hop=hop-1",
    );

    // User clicks the explicit "Clear hop" button
    navCoordinator.userClearHop();

    expect(pushStateSpy).toHaveBeenCalledTimes(1);
    expect(pushStateSpy.mock.calls[0]?.[2]).toBe("/filesystem-activity?view=audit&sessionId=sess-1");
    expect(getState().selectedHistoryEventId).toBeNull();

    // Back restores hop
    navCoordinator.handlePopState("?view=audit&sessionId=sess-1&hop=hop-1");
    expect(getState().selectedHistoryEventId).toBe("hop-1");
  });

  // =========================================================================
  // Scenario 9: Internal session/filter cleanup performs no additional push
  // =========================================================================
  it("Scenario 9: Internal session/filter cleanup performs no additional push", () => {
    const { navCoordinator, pushStateSpy, resetRequestedHopState } = setupCoordinatorHarness(
      "/filesystem-activity?view=audit&sessionId=sess-1&hop=hop-1",
    );

    // Selecting a session performs internal hop cleanup
    navCoordinator.userSelectSession("sess-2");
    expect(pushStateSpy).toHaveBeenCalledTimes(1);
    expect(resetRequestedHopState).toHaveBeenCalledTimes(1);

    // Toggling filter performs internal hop cleanup
    navCoordinator.userToggleHideHome();
    expect(pushStateSpy).toHaveBeenCalledTimes(2);

    // Zero extra or nested pushes were emitted
    expect(pushStateSpy.mock.calls[0]?.[2]).toBe("/filesystem-activity?view=audit&sessionId=sess-2");
  });

  // =========================================================================
  // Scenario 10: Popstate to a delayed retained-session lookup keeps the popped URL unchanged while the request is pending
  // =========================================================================
  it("Scenario 10: Popstate to a delayed retained-session lookup keeps the popped URL unchanged while the request is pending", async () => {
    let resolveRemoteLookup!: (val: FilesystemClosedSession | null) => void;
    const fetchSession = vi.fn().mockImplementation(() => {
      return new Promise<FilesystemClosedSession | null>((resolve) => {
        resolveRemoteLookup = resolve;
      });
    });

    const coordinator = new RemoteAuditLookupCoordinator({
      initialViewMode: "audit",
      initialSessionId: "sess-1",
      fetchSession,
    });

    const { navCoordinator, replaceStateSpy } = setupCoordinatorHarness(
      "/filesystem-activity?view=audit&sessionId=sess-1",
      { coordinator },
    );

    // Browser navigates via popstate to an unhydrated retained session
    navCoordinator.handlePopState("?view=audit&sessionId=sess-delayed-retained");

    // Transaction is pending!
    expect(navCoordinator.isPopStatePending()).toBe(true);

    // Simulate passive React effect trying to sync URL while selectedSessionId is still sess-1
    navCoordinator.synchronizeUrlState();

    // Passive sync MUST NOT overwrite the popped URL with sess-1!
    expect(replaceStateSpy).not.toHaveBeenCalled();
    expect(window.location.search).toBe("?view=audit&sessionId=sess-delayed-retained");

    // Clean up unresolved promise
    resolveRemoteLookup(null);
  });

  // =========================================================================
  // Scenario 11: The delayed lookup success and not-found paths do not produce pushState or replaceState feedback
  // =========================================================================
  it("Scenario 11: The delayed lookup success and not-found paths do not produce pushState or replaceState feedback", async () => {
    let resolveRemoteLookup!: (val: FilesystemClosedSession | null) => void;
    const fetchSession = vi.fn().mockImplementation(() => {
      return new Promise<FilesystemClosedSession | null>((resolve) => {
        resolveRemoteLookup = resolve;
      });
    });

    const coordinator = new RemoteAuditLookupCoordinator({
      initialViewMode: "audit",
      fetchSession,
    });

    const { navCoordinator, pushStateSpy, replaceStateSpy, getState } = setupCoordinatorHarness(
      "/filesystem-activity?view=audit&sessionId=sess-1",
      { coordinator },
    );

    // --- Success Path ---
    navCoordinator.handlePopState("?view=audit&sessionId=sess-delayed-found");
    expect(navCoordinator.isPopStatePending()).toBe(true);

    // Resolve successfully
    const foundSession = makeSession("sess-delayed-found");
    resolveRemoteLookup(foundSession);
    await Promise.resolve();
    await Promise.resolve();

    // Reached terminal state
    expect(navCoordinator.isPopStatePending()).toBe(false);
    expect(getState().selectedSessionId).toBe("sess-delayed-found");

    // Zero feedback history writes
    expect(pushStateSpy).not.toHaveBeenCalled();
    expect(replaceStateSpy).not.toHaveBeenCalled();

    // --- Not-Found Path ---
    let resolveNotFound!: (val: FilesystemClosedSession | null) => void;
    fetchSession.mockImplementationOnce(() => {
      return new Promise<FilesystemClosedSession | null>((resolve) => {
        resolveNotFound = resolve;
      });
    });

    navCoordinator.handlePopState("?view=audit&sessionId=sess-delayed-expired");
    expect(navCoordinator.isPopStatePending()).toBe(true);

    // Resolve with null (not found / expired)
    resolveNotFound(null);
    await Promise.resolve();
    await Promise.resolve();

    expect(navCoordinator.isPopStatePending()).toBe(false);
    expect(getState().expiredSessionId).toBe("sess-delayed-expired");
    expect(pushStateSpy).not.toHaveBeenCalled();
    expect(replaceStateSpy).not.toHaveBeenCalled();
  });

  // =========================================================================
  // Scenario 12: Rapid popstate A -> B discards late A and never rewrites B’s URL
  // =========================================================================
  it("Scenario 12: Rapid popstate A -> B discards late A and never rewrites B’s URL", async () => {
    let resolveA!: (val: FilesystemClosedSession | null) => void;
    let resolveB!: (val: FilesystemClosedSession | null) => void;

    const fetchSession = vi.fn().mockImplementation((id: string) => {
      if (id === "sess-A") {
        return new Promise<FilesystemClosedSession | null>((resolve) => {
          resolveA = resolve;
        });
      }
      return new Promise<FilesystemClosedSession | null>((resolve) => {
        resolveB = resolve;
      });
    });

    const coordinator = new RemoteAuditLookupCoordinator({
      initialViewMode: "audit",
      fetchSession,
    });

    const { navCoordinator, replaceStateSpy, getState } = setupCoordinatorHarness(
      "/filesystem-activity?view=audit&sessionId=sess-1",
      { coordinator },
    );

    // Popstate 1: user hits Back to sess-A
    navCoordinator.handlePopState("?view=audit&sessionId=sess-A");

    // Rapid Popstate 2: user immediately hits Back again to sess-B
    navCoordinator.handlePopState("?view=audit&sessionId=sess-B");

    // Lookup A finishes late
    resolveA(makeSession("sess-A"));
    await Promise.resolve();
    await Promise.resolve();

    // Late A was discarded: sess-A was NOT adopted, URL was NOT rewritten
    expect(getState().selectedSessionId).not.toBe("sess-A");
    expect(replaceStateSpy).not.toHaveBeenCalled();

    // Lookup B finishes
    const sessionB = makeSession("sess-B");
    resolveB(sessionB);
    await Promise.resolve();
    await Promise.resolve();

    // sess-B was adopted
    expect(getState().selectedSessionId).toBe("sess-B");
    expect(window.location.search).toBe("?view=audit&sessionId=sess-B");
  });

  // =========================================================================
  // Scenario 13: Repeated identical actions remain deduplicated
  // =========================================================================
  it("Scenario 13: Repeated identical actions remain deduplicated", () => {
    const { navCoordinator, pushStateSpy } = setupCoordinatorHarness(
      "/filesystem-activity?view=audit&sessionId=sess-1",
    );

    // Selecting identical session
    navCoordinator.userSelectSession("sess-1");
    expect(pushStateSpy).not.toHaveBeenCalled();

    // Resetting filters when already reset
    navCoordinator.userResetFilters();
    expect(pushStateSpy).not.toHaveBeenCalled();

    // Selecting identical hop
    navCoordinator.userSelectHop(null);
    expect(pushStateSpy).not.toHaveBeenCalled();
  });

  // =========================================================================
  // Scenario 14: Autoplay continues using replaceState without increasing history length
  // =========================================================================
  it("Scenario 14: Autoplay continues using replaceState without increasing history length", () => {
    const { navCoordinator, pushStateSpy, replaceStateSpy } = setupCoordinatorHarness(
      "/filesystem-activity?view=audit&sessionId=sess-1",
    );

    // Playback ticks through hops 1, 2, 3
    navCoordinator.playbackSelectHop("hop-1");
    navCoordinator.playbackSelectHop("hop-2");
    navCoordinator.playbackSelectHop("hop-3");

    // pushState was NEVER called
    expect(pushStateSpy).not.toHaveBeenCalled();

    // replaceState was called for each hop
    expect(replaceStateSpy).toHaveBeenCalledTimes(3);
    expect(replaceStateSpy.mock.calls[0]?.[2]).toBe(
      "/filesystem-activity?view=audit&sessionId=sess-1&hop=hop-1",
    );
    expect(replaceStateSpy.mock.calls[1]?.[2]).toBe(
      "/filesystem-activity?view=audit&sessionId=sess-1&hop=hop-2",
    );
    expect(replaceStateSpy.mock.calls[2]?.[2]).toBe(
      "/filesystem-activity?view=audit&sessionId=sess-1&hop=hop-3",
    );
  });

  // =========================================================================
  // Hook Integration: Component mount & hook execution test
  // =========================================================================
  it("Component Integration: useFilesystemUrlState wires navigationCoordinator cleanly", () => {
    let hookResult!: UseFilesystemUrlStateReturn;
    const selectedSessionIdRef = { current: "sess-1" as string | null };

    function TestComponent() {
      hookResult = useFilesystemUrlState({
        isHydrated: true,
        snapshot: null,
        extraAuditSessions: new Map(),
        selectedSessionId: "sess-1",
        selectedSessionIdRef,
        selectSession: vi.fn(),
        lookupRemoteAuditSession: vi.fn(),
      });
      return null;
    }

    act(() => {
      root.render(createElement(TestComponent));
    });

    expect(hookResult.navigationCoordinator).toBeDefined();
    expect(hookResult.navigationCoordinator).toBeInstanceOf(FilesystemNavigationCoordinator);
  });

  it("Finding 1 (production wiring): useFilesystemUrlState plus FilesystemActivity-style domain binding keeps one popstate owner", async () => {
    const deferred = createDeferred<FilesystemClosedSession | null>();
    const fetchSpy = vi.fn(() => deferred.promise);
    const remoteCoordinator = new RemoteAuditLookupCoordinator({
      initialViewMode: "audit",
      fetchSession: fetchSpy,
    });
    const extraAuditSessions = new Map<string, FilesystemClosedSession>();
    const recordLookedUpSessionSpy = vi.fn();
    const setExtraAuditSessionsSpy = vi.fn((updater: (prev: Map<string, FilesystemClosedSession>) => Map<string, FilesystemClosedSession>) => {
      const next = updater(extraAuditSessions);
      extraAuditSessions.clear();
      for (const [id, session] of next) extraAuditSessions.set(id, session);
    });
    const selectSessionSpy = vi.fn();
    const loadHistorySpy = vi.fn();
    const productionCallbacks = createRemoteAuditLookupCallbacks({
      recordLookedUpSession: recordLookedUpSessionSpy,
      setExtraAuditSessions: setExtraAuditSessionsSpy as Parameters<typeof createRemoteAuditLookupCallbacks>[0]["setExtraAuditSessions"],
      setExpiredSessionId: vi.fn(),
      selectSession: (id, session, hop) => {
        selectSessionSpy(id, session, hop);
        loadHistorySpy();
      },
    });
    remoteCoordinator.setCallbacks(productionCallbacks);

    const missingSnapshot: FilesystemTopologySnapshot = {
      sessions: [],
      recentClosedSessions: [],
      nodes: [],
      truncated: false,
      generatedAt: "",
    };
    let hookResult!: UseFilesystemUrlStateReturn;
    const selectedSessionIdRef = { current: null as string | null };

    function ProductionBindingHarness() {
      const state = useFilesystemUrlState({
        isHydrated: true,
        snapshot: missingSnapshot,
        extraAuditSessions,
        setExtraAuditSessions: setExtraAuditSessionsSpy,
        selectedSessionId: null,
        selectedSessionIdRef,
        setSelectedSessionId: (id) => {
          selectedSessionIdRef.current = id;
        },
      });

      useEffect(() => {
        state.navigationCoordinator.bindDomainAdapter({
          getAllSessions: () => [],
          getSessionById: () => new Map(),
          selectSession: (id, session, hop) => {
            selectSessionSpy(id, session, hop);
            loadHistorySpy();
          },
          recordLookedUpSession: recordLookedUpSessionSpy,
          resetHistory: vi.fn(),
          resetRequestedHopState: vi.fn(),
          coordinator: remoteCoordinator,
        });
      }, [state.navigationCoordinator]);

      hookResult = state;
      return null;
    }

    act(() => {
      root.render(createElement(ProductionBindingHarness));
    });

    window.history.replaceState(null, "", "/filesystem-activity?view=audit&sessionId=production-remote&hop=hop-production");
    act(() => {
      hookResult.navigationCoordinator.handlePopState(window.location.search);
    });

    expect(fetchSpy).toHaveBeenCalledTimes(1);
    expect(hookResult.navigationCoordinator.isPopStatePending()).toBe(true);

    const sharedPromise = remoteCoordinator.lookup({
      sessionId: "production-remote",
      targetHopId: "hop-production",
    });
    const found = makeSession("production-remote");
    deferred.resolve(found);
    await sharedPromise;
    await flushMicrotasks();

    expect(recordLookedUpSessionSpy).toHaveBeenCalledTimes(1);
    expect(setExtraAuditSessionsSpy).toHaveBeenCalledTimes(1);
    expect(selectSessionSpy).toHaveBeenCalledTimes(1);
    expect(loadHistorySpy).toHaveBeenCalledTimes(1);
    expect(hookResult.navigationCoordinator.isPopStatePending()).toBe(false);
    remoteCoordinator.destroy();
  });

  // =========================================================================
  // Finding 1: Disjoint Option Owners / Component Rerenders
  // =========================================================================
  it("Finding 1: bindUrlState and bindDomainAdapter are disjoint — each call preserves the other owner's callbacks", () => {
    const pushStateSpy = vi.spyOn(window.history, "pushState");
    // Start with sess-home (homeOnly=true) selected
    window.history.replaceState(null, "", "/filesystem-activity?view=audit&sessionId=sess-home");

    const sessionHome = makeSession("sess-home", {
      cwdState: { path: "/home/user", status: "confirmed", sourceEventId: null, observedAt: "" },
      auditSummary: { visitedPaths: ["/home/user"], homeOnly: true, eventCount: 1 },
    });
    const sessionNonHome = makeSession("sess-nonhome", {
      cwdState: { path: "/var/log", status: "confirmed", sourceEventId: null, observedAt: "" },
      auditSummary: { visitedPaths: ["/var/log"], homeOnly: false, eventCount: 1 },
    });
    const sessionEtc = makeSession("sess-etc", {
      cwdState: { path: "/etc", status: "confirmed", sourceEventId: null, observedAt: "" },
      auditSummary: { visitedPaths: ["/etc"], homeOnly: false, eventCount: 1 },
    });

    // sess-nonhome first so it's the first fallback when sess-home is filtered
    const allSessions = [sessionNonHome, sessionHome, sessionEtc];
    const sessionById = new Map(allSessions.map((s) => [s.sessionId, s]));

    let viewMode: "live" | "audit" = "audit";
    let selectedSessionId: string | null = "sess-home";
    let hideHomeOnly = false;
    let targetPathFilter: string | null = null;
    const selectSessionSpy = vi.fn((sid: string) => { selectedSessionId = sid; });
    const resetHistorySpy = vi.fn();
    const resetRequestedHopStateSpy = vi.fn();

    const coord = new FilesystemNavigationCoordinator();

    // 1. Bind URL state (owned by useFilesystemUrlState)
    coord.bindUrlState({
      getViewMode: () => viewMode,
      getSelectedSessionId: () => selectedSessionId,
      getHideHomeOnly: () => hideHomeOnly,
      getTargetPathFilter: () => targetPathFilter,
      getSelectedHistoryEventId: () => null,
      getRequestedHop: () => null,
      getExpiredSessionId: () => null,
      getSnapshot: () => ({
        sessions: allSessions,
        recentClosedSessions: [],
        nodes: [],
        truncated: false,
        generatedAt: "",
      }),
      getExtraAuditSessions: () => new Map(),
      setViewMode: (v) => { viewMode = v; },
      setHideHomeOnly: (h) => { hideHomeOnly = h; },
      setTargetPathFilter: (p) => { targetPathFilter = p; },
      setSelectedHistoryEventId: vi.fn(),
      setExpiredSessionId: vi.fn(),
      setSelectedSessionId: (id) => { selectedSessionId = id; },
      setRequestedHop: vi.fn(),
      setRequestedSessionId: vi.fn(),
    });

    // 2. Bind domain adapter (owned by FilesystemActivity)
    coord.bindDomainAdapter({
      getAllSessions: () => allSessions,
      getSessionById: () => sessionById,
      selectSession: selectSessionSpy,
      resetHistory: resetHistorySpy,
      resetRequestedHopState: resetRequestedHopStateSpy,
    });

    // 3. Simulate an unrelated URL state rebind (e.g. snapshot update or extraAuditSessions change)
    //    This must NOT overwrite the domain adapter's getAllSessions/getSessionById with the no-ops
    //    from DEFAULT_COORDINATOR_OPTIONS
    coord.bindUrlState({
      getViewMode: () => viewMode,
      getSelectedSessionId: () => selectedSessionId,
      getHideHomeOnly: () => hideHomeOnly,
      getTargetPathFilter: () => targetPathFilter,
      getSelectedHistoryEventId: () => null,
      getRequestedHop: () => null,
      getExpiredSessionId: () => null,
      getSnapshot: () => ({
        sessions: allSessions,
        recentClosedSessions: [],
        nodes: [],
        truncated: false,
        generatedAt: "",
      }),
      getExtraAuditSessions: () => new Map(),
      setViewMode: (v) => { viewMode = v; },
      setHideHomeOnly: (h) => { hideHomeOnly = h; },
      setTargetPathFilter: (p) => { targetPathFilter = p; },
      setSelectedHistoryEventId: vi.fn(),
      setExpiredSessionId: vi.fn(),
      setSelectedSessionId: (id) => { selectedSessionId = id; },
      setRequestedHop: vi.fn(),
      setRequestedSessionId: vi.fn(),
    });

    // 4. userToggleHideHome — sess-home is homeOnly=true, so it IS filtered by hideHomeOnly=true;
    //    domain adapter's getAllSessions() must still return the full list for fallback to sess-nonhome
    coord.userToggleHideHome();

    expect(pushStateSpy).toHaveBeenCalledTimes(1);
    expect(pushStateSpy.mock.calls[0]?.[2]).toBe(
      "/filesystem-activity?view=audit&sessionId=sess-nonhome&hideHome=1",
    );
    expect(selectSessionSpy).toHaveBeenCalledWith("sess-nonhome");

    // 5. Simulate an unrelated domain adapter rebind (e.g. selectSession callback identity change)
    //    This must NOT overwrite URL state getSelectedSessionId with no-op
    coord.bindDomainAdapter({
      getAllSessions: () => allSessions,
      getSessionById: () => sessionById,
      selectSession: selectSessionSpy,
      resetHistory: resetHistorySpy,
      resetRequestedHopState: resetRequestedHopStateSpy,
    });

    // 6. userSelectTargetPath — sess-nonhome doesn't touch /etc, fallback to sess-etc
    pushStateSpy.mockClear();
    selectSessionSpy.mockClear();
    coord.userSelectTargetPath("/etc");

    expect(pushStateSpy).toHaveBeenCalledTimes(1);
    expect(pushStateSpy.mock.calls[0]?.[2]).toBe(
      "/filesystem-activity?view=audit&sessionId=sess-etc&hideHome=1&targetPath=%2Fetc",
    );
    expect(selectSessionSpy).toHaveBeenCalledWith("sess-etc");

    // 7. userClearSelection — must invoke resetHistory (domain) and push once (URL state)
    pushStateSpy.mockClear();
    resetHistorySpy.mockClear();
    resetRequestedHopStateSpy.mockClear();
    coord.userClearSelection();

    expect(pushStateSpy).toHaveBeenCalledTimes(1);
    expect(pushStateSpy.mock.calls[0]?.[2]).toBe(
      "/filesystem-activity?view=audit&hideHome=1&targetPath=%2Fetc",
    );
    expect(resetHistorySpy).toHaveBeenCalledTimes(1);
    expect(resetRequestedHopStateSpy).toHaveBeenCalledTimes(1);

    // 8. updateOptions with undefined values must preserve existing callbacks (domain adapter intact)
    coord.updateOptions({ getAllSessions: undefined });
    pushStateSpy.mockClear();
    coord.userToggleHideHome(); // toggles back to hideHome=false
    expect(pushStateSpy).toHaveBeenCalledTimes(1);
  });


  // =========================================================================
  // Finding 2: Promise identity and structurally separate terminal observers
  // =========================================================================
  it("Finding 2: same-intent joins preserve promise identity without registering a mutating callback as an observer", async () => {
    const coordinator = new RemoteAuditLookupCoordinator({ initialViewMode: "audit" });
    let resolveFetch!: (s: FilesystemClosedSession | null) => void;
    const delayedFetch = vi.fn().mockImplementation(() => {
      return new Promise<FilesystemClosedSession | null>((resolve) => {
        resolveFetch = resolve;
      });
    });

    const cb1 = { onSessionFound: vi.fn(), onSessionNotFound: vi.fn() };
    const cb2 = { onSessionFound: vi.fn(), onSessionNotFound: vi.fn() };

    const p1 = coordinator.requestLookup(
      { sessionId: "sess-delayed", targetHopId: "hop-1" },
      cb1,
      delayedFetch,
    );
    const terminalObserver = createRemoteAuditLookupTerminalObserver((outcome) => {
      if (outcome.type === "found") {
        cb2.onSessionFound(outcome.session, outcome.targetHopId);
      } else {
        cb2.onSessionNotFound(outcome.sessionId);
      }
    });
    const p2 = coordinator.joinLookup(
      { sessionId: "sess-delayed", targetHopId: "hop-1" },
      terminalObserver,
    );

    // Joining in-flight request returns the active promise instead of returning premature null
    expect(p1).toBeInstanceOf(Promise);
    expect(p2).toBe(p1);
    expect(delayedFetch).toHaveBeenCalledTimes(1);

    const mockSession = makeSession("sess-delayed");
    resolveFetch(mockSession);
    const [res1, res2] = await Promise.all([p1, p2]);

    expect(res1).toBe(mockSession);
    expect(res2).toBe(mockSession);
    // cb1 is the mutation owner; cb2 is notified through the explicit terminal role.
    expect(cb1.onSessionFound).toHaveBeenCalledTimes(1);
    expect(cb2.onSessionFound).toHaveBeenCalledTimes(1);
    expect(cb1.onSessionFound).toHaveBeenCalledWith(mockSession, "hop-1");
    expect(cb2.onSessionFound).toHaveBeenCalledWith(mockSession, "hop-1");
    expect(cb1.onSessionNotFound).not.toHaveBeenCalled();
    expect(cb2.onSessionNotFound).not.toHaveBeenCalled();
  });

  // =========================================================================
  // Finding 1 (New): Exactly-once domain adoption for joined lookups
  // =========================================================================

  it("Finding 1 (exact-once): Snapshot lookup joined by popstate uses createRemoteAuditLookupCallbacks; domain mutations apply exactly once on success", async () => {
    let resolveFetch!: (s: FilesystemClosedSession | null) => void;
    const fetchSpy = vi.fn().mockImplementation(() => {
      return new Promise<FilesystemClosedSession | null>((resolve) => {
        resolveFetch = resolve;
      });
    });

    // ---- Snapshot-layer state (what createRemoteAuditLookupCallbacks mutates) ----
    let selectedSessionId: string | null = null;
    let expiredSessionId: string | null = null;
    const extraAuditSessions = new Map<string, FilesystemClosedSession>();

    const recordLookedUpSessionSpy = vi.fn();
    const setExtraAuditSessionsSpy = vi.fn((updater: (p: Map<string, FilesystemClosedSession>) => Map<string, FilesystemClosedSession>) => {
      expect(navCoordinator.isPopStatePending()).toBe(true);
      navCoordinator.synchronizeUrlState();
      expect(replaceStateSpy).not.toHaveBeenCalled();
      const next = updater(extraAuditSessions);
      extraAuditSessions.clear();
      for (const [k, v] of next) extraAuditSessions.set(k, v);
    });
    const setExpiredSessionIdSpy = vi.fn((id: string | null) => { expiredSessionId = id; });
    const selectSessionSpy = vi.fn((sid: string) => {
      expect(navCoordinator.isPopStatePending()).toBe(true);
      navCoordinator.synchronizeUrlState();
      expect(replaceStateSpy).not.toHaveBeenCalled();
      selectedSessionId = sid;
    });
    const loadHistorySpy = vi.fn();

    // Production snapshot callback (what FilesystemActivity wires via createRemoteAuditLookupCallbacks)
    const productionCallbacks = createRemoteAuditLookupCallbacks({
      recordLookedUpSession: recordLookedUpSessionSpy,
      setExtraAuditSessions: setExtraAuditSessionsSpy as Parameters<typeof createRemoteAuditLookupCallbacks>[0]["setExtraAuditSessions"],
      setExpiredSessionId: setExpiredSessionIdSpy,
      selectSession: (sid, sObj, hop) => {
        selectSessionSpy(sid, sObj, hop);
        loadHistorySpy();
      },
    });

    const coordinator = new RemoteAuditLookupCoordinator({
      initialViewMode: "audit",
      fetchSession: fetchSpy,
      callbacks: productionCallbacks,
    });
    const joinLookupSpy = vi.spyOn(coordinator, "joinLookup");

    // 1. Snapshot update initiates lookup ("remote-join" is missing from snapshot)
    const snapshotPromise = coordinator.lookup({ sessionId: "remote-join", targetHopId: "hop-1" });
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    expect(coordinator.isInFlight()).toBe(true);

    // 2. Build navCoordinator wired to the same coordinator
    const navCoordinator = new FilesystemNavigationCoordinator({
      getViewMode: () => "audit",
      getSelectedSessionId: () => selectedSessionId,
      getHideHomeOnly: () => false,
      getTargetPathFilter: () => null,
      getSelectedHistoryEventId: () => "hop-1",
      getRequestedHop: () => "hop-1",
      getExpiredSessionId: () => expiredSessionId,
      getSnapshot: () => ({ sessions: [], recentClosedSessions: [], nodes: [], truncated: false, generatedAt: "" }),
      getExtraAuditSessions: () => extraAuditSessions,
      setExtraAuditSessions: setExtraAuditSessionsSpy as Parameters<typeof createRemoteAuditLookupCallbacks>[0]["setExtraAuditSessions"],
      getAllSessions: () => [],
      getSessionById: () => new Map(),
      setViewMode: vi.fn(),
      setHideHomeOnly: vi.fn(),
      setTargetPathFilter: vi.fn(),
      setSelectedHistoryEventId: vi.fn(),
      setExpiredSessionId: setExpiredSessionIdSpy,
      setSelectedSessionId: (id) => { selectedSessionId = id; },
      setRequestedHop: vi.fn(),
      setRequestedSessionId: vi.fn(),
      selectSession: selectSessionSpy,
      resetHistory: vi.fn(),
      resetRequestedHopState: vi.fn(),
      coordinator,
    });

    // 3. Popstate arrives for the same session while snapshot lookup is in flight
    const replaceStateSpy = vi.spyOn(window.history, "replaceState");
    window.history.replaceState(null, "", "/filesystem-activity?view=audit&sessionId=remote-join&hop=hop-1");
    replaceStateSpy.mockClear();
    navCoordinator.handlePopState(window.location.search);

    // Must join without re-fetching
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    expect(joinLookupSpy).toHaveBeenCalledTimes(1);
    expect(joinLookupSpy.mock.results[0]?.value).toBe(snapshotPromise);
    expect(navCoordinator.isPopStatePending()).toBe(true);

    // 4. Resolve the fetch
    const remoteSession = makeSession("remote-join");
    resolveFetch(remoteSession);
    await snapshotPromise;
    // Flush all microtasks (executeRemoteLookupForPopState awaits the promise)
    await Promise.resolve();
    await Promise.resolve();

    // ── Exact-once assertions ──
    // Network: exactly one request
    expect(fetchSpy).toHaveBeenCalledTimes(1);

    // Domain mutations: each exactly once
    expect(recordLookedUpSessionSpy).toHaveBeenCalledTimes(1);
    expect(recordLookedUpSessionSpy).toHaveBeenCalledWith(remoteSession);

    expect(setExtraAuditSessionsSpy).toHaveBeenCalledTimes(1);
    expect(extraAuditSessions.has("remote-join")).toBe(true);

    expect(selectSessionSpy).toHaveBeenCalledTimes(1);
    expect(selectSessionSpy).toHaveBeenCalledWith("remote-join", remoteSession, "hop-1");

    // loadHistory is called via selectSession wrapper — exactly once
    expect(loadHistorySpy).toHaveBeenCalledTimes(1);

    // Popstate transaction becomes terminal after authoritative application
    expect(navCoordinator.isPopStatePending()).toBe(false);
    expect(expiredSessionId).toBeNull();
  });

  it("Finding 1 (exact-once): Snapshot lookup joined by popstate — not-found applies exactly once", async () => {
    let resolveFetch!: (s: FilesystemClosedSession | null) => void;
    const fetchSpy = vi.fn().mockImplementation(() => {
      return new Promise<FilesystemClosedSession | null>((resolve) => {
        resolveFetch = resolve;
      });
    });

    let selectedSessionId: string | null = null;
    let expiredSessionId: string | null = null;

    const setExpiredSessionIdSpy = vi.fn((id: string | null) => { expiredSessionId = id; });
    const setSelectedSessionIdSpy = vi.fn((id: string | null) => { selectedSessionId = id; });
    const selectSessionSpy = vi.fn();

    const productionCallbacks = createRemoteAuditLookupCallbacks({
      recordLookedUpSession: vi.fn(),
      setExtraAuditSessions: vi.fn(),
      setExpiredSessionId: setExpiredSessionIdSpy,
      selectSession: selectSessionSpy,
      setSelectedSessionId: setSelectedSessionIdSpy,
    });

    const coordinator = new RemoteAuditLookupCoordinator({
      initialViewMode: "audit",
      fetchSession: fetchSpy,
      callbacks: productionCallbacks,
    });

    const snapshotPromise = coordinator.lookup({ sessionId: "remote-404", targetHopId: null });
    expect(fetchSpy).toHaveBeenCalledTimes(1);

    const navCoordinator = new FilesystemNavigationCoordinator({
      getViewMode: () => "audit",
      getSelectedSessionId: () => selectedSessionId,
      getHideHomeOnly: () => false,
      getTargetPathFilter: () => null,
      getSelectedHistoryEventId: () => null,
      getRequestedHop: () => null,
      getExpiredSessionId: () => expiredSessionId,
      getSnapshot: () => ({ sessions: [], recentClosedSessions: [], nodes: [], truncated: false, generatedAt: "" }),
      getExtraAuditSessions: () => new Map(),
      getAllSessions: () => [],
      getSessionById: () => new Map(),
      setViewMode: vi.fn(),
      setHideHomeOnly: vi.fn(),
      setTargetPathFilter: vi.fn(),
      setSelectedHistoryEventId: vi.fn(),
      setExpiredSessionId: setExpiredSessionIdSpy,
      setSelectedSessionId: setSelectedSessionIdSpy,
      setRequestedHop: vi.fn(),
      setRequestedSessionId: vi.fn(),
      selectSession: selectSessionSpy,
      resetHistory: vi.fn(),
      resetRequestedHopState: vi.fn(),
      coordinator,
    });

    window.history.replaceState(null, "", "/filesystem-activity?view=audit&sessionId=remote-404");
    navCoordinator.handlePopState(window.location.search);
    expect(fetchSpy).toHaveBeenCalledTimes(1); // no duplicate fetch

    // Resolve with null (not found)
    resolveFetch(null);
    await snapshotPromise;
    await Promise.resolve();
    await Promise.resolve();

    // Not-found path: setExpiredSessionId and setSelectedSessionId each once
    expect(setExpiredSessionIdSpy).toHaveBeenCalledTimes(1);
    expect(setExpiredSessionIdSpy).toHaveBeenCalledWith("remote-404");
    expect(setSelectedSessionIdSpy).toHaveBeenCalledTimes(1);
    expect(setSelectedSessionIdSpy).toHaveBeenCalledWith(null);
    expect(selectSessionSpy).not.toHaveBeenCalled();

    expect(navCoordinator.isPopStatePending()).toBe(false);
    expect(expiredSessionId).toBe("remote-404");
  });

  it("Finding 1 (exact-once): popstate owner joined by snapshot uses the production callback object without duplicate application", async () => {
    const deferred = createDeferred<FilesystemClosedSession | null>();
    const fetchSpy = vi.fn(() => deferred.promise);
    const coordinator = new RemoteAuditLookupCoordinator({
      initialViewMode: "audit",
      fetchSession: fetchSpy,
    });
    let selectedSessionId: string | null = null;
    let expiredSessionId: string | null = null;
    const extraAuditSessions = new Map<string, FilesystemClosedSession>();
    const recordLookedUpSessionSpy = vi.fn();
    const setExtraAuditSessionsSpy = vi.fn((updater: (prev: Map<string, FilesystemClosedSession>) => Map<string, FilesystemClosedSession>) => {
      const next = updater(extraAuditSessions);
      extraAuditSessions.clear();
      for (const [id, session] of next) extraAuditSessions.set(id, session);
    });
    const setExpiredSessionIdSpy = vi.fn((id: string | null) => { expiredSessionId = id; });
    const selectSessionSpy = vi.fn((id: string) => { selectedSessionId = id; });
    const productionRecordSpy = vi.fn();
    const productionCallbacks = createRemoteAuditLookupCallbacks({
      recordLookedUpSession: productionRecordSpy,
      setExtraAuditSessions: vi.fn(),
      setExpiredSessionId: vi.fn(),
      selectSession: vi.fn(),
    });
    coordinator.setCallbacks(productionCallbacks);

    const navCoordinator = new FilesystemNavigationCoordinator({
      getViewMode: () => "audit",
      getSelectedSessionId: () => selectedSessionId,
      getHideHomeOnly: () => false,
      getTargetPathFilter: () => null,
      getSelectedHistoryEventId: () => null,
      getRequestedHop: () => null,
      getExpiredSessionId: () => expiredSessionId,
      getSnapshot: () => ({ sessions: [], recentClosedSessions: [], nodes: [], truncated: false, generatedAt: "" }),
      getExtraAuditSessions: () => extraAuditSessions,
      setExtraAuditSessions: setExtraAuditSessionsSpy,
      getAllSessions: () => [],
      getSessionById: () => new Map(),
      setViewMode: vi.fn(),
      setHideHomeOnly: vi.fn(),
      setTargetPathFilter: vi.fn(),
      setSelectedHistoryEventId: vi.fn(),
      setExpiredSessionId: setExpiredSessionIdSpy,
      setSelectedSessionId: (id) => { selectedSessionId = id; },
      setRequestedHop: vi.fn(),
      setRequestedSessionId: vi.fn(),
      selectSession: selectSessionSpy,
      recordLookedUpSession: recordLookedUpSessionSpy,
      resetHistory: vi.fn(),
      resetRequestedHopState: vi.fn(),
      coordinator,
    });

    const intent = { sessionId: "popstate-owner", targetHopId: "hop-owner" };
    window.history.replaceState(null, "", "/filesystem-activity?view=audit&sessionId=popstate-owner&hop=hop-owner");
    navCoordinator.handlePopState(window.location.search);
    const popstatePromise = coordinator.lookup(intent);
    const snapshotPromise = coordinator.lookup(intent);

    expect(snapshotPromise).toBe(popstatePromise);
    expect(fetchSpy).toHaveBeenCalledTimes(1);

    const found = makeSession("popstate-owner");
    deferred.resolve(found);
    await snapshotPromise;
    await flushMicrotasks();

    expect(recordLookedUpSessionSpy).toHaveBeenCalledTimes(1);
    expect(setExtraAuditSessionsSpy).toHaveBeenCalledTimes(1);
    expect(selectSessionSpy).toHaveBeenCalledTimes(1);
    expect(productionRecordSpy).not.toHaveBeenCalled();
    expect(navCoordinator.isPopStatePending()).toBe(false);
  });

  it("Finding 1: repeated snapshots with the same production callback object invoke the owner once", async () => {
    const deferred = createDeferred<FilesystemClosedSession | null>();
    const recordLookedUpSessionSpy = vi.fn();
    const setExtraAuditSessionsSpy = vi.fn((updater: (prev: Map<string, FilesystemClosedSession>) => Map<string, FilesystemClosedSession>) => updater(new Map()));
    const selectSessionSpy = vi.fn();
    const callbacks = createRemoteAuditLookupCallbacks({
      recordLookedUpSession: recordLookedUpSessionSpy,
      setExtraAuditSessions: setExtraAuditSessionsSpy as Parameters<typeof createRemoteAuditLookupCallbacks>[0]["setExtraAuditSessions"],
      setExpiredSessionId: vi.fn(),
      selectSession: selectSessionSpy,
    });
    const fetchSpy = vi.fn(() => deferred.promise);
    const coordinator = new RemoteAuditLookupCoordinator({
      initialViewMode: "audit",
      fetchSession: fetchSpy,
      callbacks,
    });

    const p1 = coordinator.lookup({ sessionId: "repeat-snapshot", targetHopId: "hop-repeat" });
    const p2 = coordinator.lookup({ sessionId: "repeat-snapshot", targetHopId: "hop-repeat" });
    expect(p2).toBe(p1);
    expect(fetchSpy).toHaveBeenCalledTimes(1);

    const found = makeSession("repeat-snapshot");
    deferred.resolve(found);
    await Promise.all([p1, p2]);

    expect(recordLookedUpSessionSpy).toHaveBeenCalledTimes(1);
    expect(setExtraAuditSessionsSpy).toHaveBeenCalledTimes(1);
    expect(selectSessionSpy).toHaveBeenCalledTimes(1);
  });

  it("Finding 1/2: async errors notify the owner once and terminal observers once in both join orders", async () => {
    const snapshotFirstDeferred = createDeferred<FilesystemClosedSession | null>();
    const snapshotFirstOwner = { onSessionFound: vi.fn(), onSessionNotFound: vi.fn() };
    const snapshotFirstTerminal = vi.fn();
    const snapshotFirstCoordinator = new RemoteAuditLookupCoordinator({
      initialViewMode: "audit",
      fetchSession: vi.fn(() => snapshotFirstDeferred.promise),
    });
    const snapshotFirstPromise = snapshotFirstCoordinator.lookup(
      { sessionId: "error-snapshot-first", targetHopId: null },
      snapshotFirstOwner,
    );
    const snapshotFirstJoin = snapshotFirstCoordinator.joinLookup(
      { sessionId: "error-snapshot-first", targetHopId: null },
      createRemoteAuditLookupTerminalObserver(snapshotFirstTerminal),
    );
    snapshotFirstDeferred.reject(new Error("snapshot-first-error"));
    await Promise.all([snapshotFirstPromise, snapshotFirstJoin]);

    expect(snapshotFirstOwner.onSessionNotFound).toHaveBeenCalledTimes(1);
    expect(snapshotFirstTerminal).toHaveBeenCalledTimes(1);
    expect(snapshotFirstTerminal.mock.calls[0]?.[0]).toMatchObject({
      type: "not-found",
      sessionId: "error-snapshot-first",
      reason: "error",
    });

    const popstateFirstDeferred = createDeferred<FilesystemClosedSession | null>();
    const popstateFirstOwner = { onSessionFound: vi.fn(), onSessionNotFound: vi.fn() };
    const popstateFirstSnapshotCallback = {
      onSessionFound: vi.fn(),
      onSessionNotFound: vi.fn(),
    };
    const popstateFirstCoordinator = new RemoteAuditLookupCoordinator({
      initialViewMode: "audit",
      fetchSession: vi.fn(() => popstateFirstDeferred.promise),
      callbacks: popstateFirstSnapshotCallback,
    });
    const popstateFirstPromise = popstateFirstCoordinator.lookup(
      { sessionId: "error-popstate-first", targetHopId: null },
      popstateFirstOwner,
    );
    const popstateFirstSnapshotJoin = popstateFirstCoordinator.lookup({
      sessionId: "error-popstate-first",
      targetHopId: null,
    });
    expect(popstateFirstSnapshotJoin).toBe(popstateFirstPromise);
    popstateFirstDeferred.reject(new Error("popstate-first-error"));
    await popstateFirstPromise;

    expect(popstateFirstOwner.onSessionNotFound).toHaveBeenCalledTimes(1);
    expect(popstateFirstSnapshotCallback.onSessionNotFound).not.toHaveBeenCalled();
    expect(popstateFirstCoordinator.isInFlight()).toBe(false);
  });

  it("Finding 2: a synchronous reentrant same-intent request receives the real shared promise", async () => {
    const session = makeSession("reentrant");
    const owner = { onSessionFound: vi.fn(), onSessionNotFound: vi.fn() };
    const coordinator = new RemoteAuditLookupCoordinator({ initialViewMode: "audit" });
    let reentrantPromise!: Promise<FilesystemClosedSession | null>;
    const fetchSpy = vi.fn(() => {
      reentrantPromise = coordinator.requestLookup(
        { sessionId: "reentrant", targetHopId: "hop-reentrant" },
        owner,
        fetchSpy,
      );
      expect(coordinator.isInFlight()).toBe(true);
      return Promise.resolve(session);
    });

    const originalPromise = coordinator.requestLookup(
      { sessionId: "reentrant", targetHopId: "hop-reentrant" },
      owner,
      fetchSpy,
    );

    expect(reentrantPromise).toBe(originalPromise);
    expect(reentrantPromise).not.toBeNull();
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    await originalPromise;
    expect(owner.onSessionFound).toHaveBeenCalledTimes(1);
    expect(coordinator.isInFlight()).toBe(false);
  });

  it("Finding 3: a throwing authoritative application does not mark the popstate transaction terminal", async () => {
    const deferred = createDeferred<FilesystemClosedSession | null>();
    const coordinator = new RemoteAuditLookupCoordinator({
      initialViewMode: "audit",
      fetchSession: vi.fn(() => deferred.promise),
    });
    const navCoordinator = new FilesystemNavigationCoordinator({
      getViewMode: () => "audit",
      getSelectedSessionId: () => null,
      getHideHomeOnly: () => false,
      getTargetPathFilter: () => null,
      getSelectedHistoryEventId: () => null,
      getRequestedHop: () => null,
      getExpiredSessionId: () => null,
      getSnapshot: () => ({ sessions: [], recentClosedSessions: [], nodes: [], truncated: false, generatedAt: "" }),
      getExtraAuditSessions: () => new Map(),
      setViewMode: vi.fn(),
      setHideHomeOnly: vi.fn(),
      setTargetPathFilter: vi.fn(),
      setSelectedHistoryEventId: vi.fn(),
      setExpiredSessionId: vi.fn(),
      setSelectedSessionId: vi.fn(),
      setRequestedHop: vi.fn(),
      setRequestedSessionId: vi.fn(),
      setExtraAuditSessions: () => {
        throw new Error("state-application-failed");
      },
      getAllSessions: () => [],
      getSessionById: () => new Map(),
      selectSession: vi.fn(),
      resetHistory: vi.fn(),
      resetRequestedHopState: vi.fn(),
      coordinator,
    });

    window.history.replaceState(null, "", "/filesystem-activity?view=audit&sessionId=throwing-owner");
    navCoordinator.handlePopState(window.location.search);
    const promise = coordinator.lookup({ sessionId: "throwing-owner", targetHopId: null });
    deferred.resolve(makeSession("throwing-owner"));
    await expect(promise).rejects.toThrow("state-application-failed");
    await flushMicrotasks();

    expect(coordinator.isInFlight()).toBe(false);
    expect(navCoordinator.isPopStatePending()).toBe(true);
  });

  it("Finding 1: Repeated identical popstate events do not add duplicate mutating observers", async () => {
    let resolveFetch!: (s: FilesystemClosedSession | null) => void;
    const fetchSpy = vi.fn().mockImplementation(() => {
      return new Promise<FilesystemClosedSession | null>((resolve) => {
        resolveFetch = resolve;
      });
    });

    let selectedSessionId: string | null = null;
    let expiredSessionId: string | null = null;
    const extraAuditSessions = new Map<string, FilesystemClosedSession>();

    const setExtraAuditSessionsSpy = vi.fn((updater: (p: Map<string, FilesystemClosedSession>) => Map<string, FilesystemClosedSession>) => {
      const next = updater(extraAuditSessions);
      extraAuditSessions.clear();
      for (const [k, v] of next) extraAuditSessions.set(k, v);
    });
    const selectSessionSpy = vi.fn((sid: string) => { selectedSessionId = sid; });

    const coordinator = new RemoteAuditLookupCoordinator({
      initialViewMode: "audit",
      fetchSession: fetchSpy,
    });

    const navCoordinator = new FilesystemNavigationCoordinator({
      getViewMode: () => "audit",
      getSelectedSessionId: () => selectedSessionId,
      getHideHomeOnly: () => false,
      getTargetPathFilter: () => null,
      getSelectedHistoryEventId: () => null,
      getRequestedHop: () => null,
      getExpiredSessionId: () => expiredSessionId,
      getSnapshot: () => ({ sessions: [], recentClosedSessions: [], nodes: [], truncated: false, generatedAt: "" }),
      getExtraAuditSessions: () => extraAuditSessions,
      setExtraAuditSessions: setExtraAuditSessionsSpy as Parameters<typeof createRemoteAuditLookupCallbacks>[0]["setExtraAuditSessions"],
      getAllSessions: () => [],
      getSessionById: () => new Map(),
      setViewMode: vi.fn(),
      setHideHomeOnly: vi.fn(),
      setTargetPathFilter: vi.fn(),
      setSelectedHistoryEventId: vi.fn(),
      setExpiredSessionId: (id) => { expiredSessionId = id; },
      setSelectedSessionId: (id) => { selectedSessionId = id; },
      setRequestedHop: vi.fn(),
      setRequestedSessionId: vi.fn(),
      selectSession: selectSessionSpy,
      resetHistory: vi.fn(),
      resetRequestedHopState: vi.fn(),
      coordinator,
    });

    // First popstate → starts fresh lookup (mutatingCallbacks becomes mutationOwner)
    window.history.replaceState(null, "", "/filesystem-activity?view=audit&sessionId=remote-dup");
    navCoordinator.handlePopState(window.location.search);
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    expect(navCoordinator.isPopStatePending()).toBe(true);

    // Second identical popstate → deduplication guard fires, no second handlePopState execution
    // (handlePopState deduplicates at the transaction level)
    navCoordinator.handlePopState(window.location.search);
    expect(fetchSpy).toHaveBeenCalledTimes(1); // still only one fetch

    // Third popstate for same URL with different txId path:
    // We force a new transaction by temporarily changing and restoring URL
    // But the deduplication guard should prevent it anyway.

    // Resolve
    const foundSession = makeSession("remote-dup");
    resolveFetch(foundSession);
    await new Promise<void>((r) => { Promise.resolve().then(() => Promise.resolve().then(r)); });

    // selectSession called exactly once (not three times)
    expect(selectSessionSpy).toHaveBeenCalledTimes(1);
    expect(selectSessionSpy).toHaveBeenCalledWith("remote-dup", foundSession, null);
    expect(setExtraAuditSessionsSpy).toHaveBeenCalledTimes(1);
    expect(navCoordinator.isPopStatePending()).toBe(false);
  });

  it("Finding 2 (new): Synchronously throwing fetchFn clears isInFlight() and permits a successful retry", async () => {
    let callCount = 0;
    let resolveSecond!: (s: FilesystemClosedSession | null) => void;

    const fetchSpy = vi.fn().mockImplementation(() => {
      callCount++;
      if (callCount === 1) {
        // Throw synchronously on the first call
        throw new Error("sync-error");
      }
      // Succeed on the second call
      return new Promise<FilesystemClosedSession | null>((resolve) => {
        resolveSecond = resolve;
      });
    });

    const coordinator = new RemoteAuditLookupCoordinator({ initialViewMode: "audit" });
    const cb = { onSessionFound: vi.fn(), onSessionNotFound: vi.fn() };

    // First call: fetch throws synchronously
    const p1 = coordinator.requestLookup(
      { sessionId: "sess-sync-throw", targetHopId: null },
      cb,
      fetchSpy,
    );

    // After a tick, the settled rejected/error promise clears inFlightIntent
    await p1;

    // isInFlight must be false — synchronous exception was cleaned up correctly
    expect(coordinator.isInFlight()).toBe(false);
    // The error path calls onSessionNotFound
    expect(cb.onSessionNotFound).toHaveBeenCalledTimes(1);
    expect(cb.onSessionNotFound).toHaveBeenCalledWith("sess-sync-throw");
    expect(cb.onSessionFound).not.toHaveBeenCalled();

    cb.onSessionFound.mockClear();
    cb.onSessionNotFound.mockClear();

    // Second call for the same intent: must start a NEW request (not join a phantom in-flight)
    const p2 = coordinator.requestLookup(
      { sessionId: "sess-sync-throw", targetHopId: null },
      cb,
      fetchSpy,
    );
    expect(fetchSpy).toHaveBeenCalledTimes(2);
    expect(coordinator.isInFlight()).toBe(true);

    const retrySession = makeSession("sess-sync-throw");
    resolveSecond(retrySession);
    await p2;

    expect(cb.onSessionFound).toHaveBeenCalledTimes(1);
    expect(cb.onSessionFound).toHaveBeenCalledWith(retrySession, null);
    expect(cb.onSessionNotFound).not.toHaveBeenCalled();
    expect(coordinator.isInFlight()).toBe(false);
  });

  it("Finding 2 (new): Asynchronous rejection clears isInFlight() and calls onSessionNotFound", async () => {
    let rejectFetch!: (err: Error) => void;
    const fetchSpy = vi.fn().mockImplementation(() => {
      return new Promise<FilesystemClosedSession | null>((_resolve, reject) => {
        rejectFetch = reject;
      });
    });

    const coordinator = new RemoteAuditLookupCoordinator({ initialViewMode: "audit" });
    const cb = { onSessionFound: vi.fn(), onSessionNotFound: vi.fn() };

    const p = coordinator.requestLookup(
      { sessionId: "sess-async-reject", targetHopId: null },
      cb,
      fetchSpy,
    );
    expect(coordinator.isInFlight()).toBe(true);

    rejectFetch(new Error("network-error"));
    await p;

    expect(coordinator.isInFlight()).toBe(false);
    expect(cb.onSessionNotFound).toHaveBeenCalledTimes(1);
    expect(cb.onSessionNotFound).toHaveBeenCalledWith("sess-async-reject");
    expect(cb.onSessionFound).not.toHaveBeenCalled();
  });

  it("Finding 2: unsubscribe prevents late state mutation for disposed observers", async () => {
    let resolveFetch!: (s: FilesystemClosedSession | null) => void;
    const fetchSpy = vi.fn().mockImplementation(() => {
      return new Promise<FilesystemClosedSession | null>((resolve) => {
        resolveFetch = resolve;
      });
    });

    const coordinator = new RemoteAuditLookupCoordinator({ initialViewMode: "audit" });
    const ownerCb = { onSessionFound: vi.fn(), onSessionNotFound: vi.fn() };
    const observerCb = { onSessionFound: vi.fn(), onSessionNotFound: vi.fn() };

    // Start lookup with ownerCb as mutation owner
    coordinator.requestLookup({ sessionId: "sess-unsub", targetHopId: null }, ownerCb, fetchSpy);
    // Join through the terminal-only registration path.
    const terminalObserver = createRemoteAuditLookupTerminalObserver((outcome) => {
      if (outcome.type === "found") {
        observerCb.onSessionFound(outcome.session, outcome.targetHopId);
      } else {
        observerCb.onSessionNotFound(outcome.sessionId);
      }
    });
    coordinator.joinLookup(
      { sessionId: "sess-unsub", targetHopId: null },
      terminalObserver,
    );
    expect(fetchSpy).toHaveBeenCalledTimes(1);

    // Observer disposes before resolution (e.g. component unmounts)
    coordinator.unsubscribe(terminalObserver);

    const found = makeSession("sess-unsub");
    resolveFetch(found);
    await coordinator.requestLookup({ sessionId: "sess-unsub", targetHopId: null }, undefined, fetchSpy);

    // Owner was notified
    expect(ownerCb.onSessionFound).toHaveBeenCalledTimes(1);
    // Observer was unsubscribed before resolution — must NOT be called
    expect(observerCb.onSessionFound).not.toHaveBeenCalled();
  });

  it("Finding 2: Concurrent popstate joining in-flight lookup keeps transaction pending and suppresses synchronizeUrlState until resolution", async () => {
    let resolveFetch!: (s: FilesystemClosedSession | null) => void;
    const delayedFetch = vi.fn().mockImplementation(() => {
      return new Promise<FilesystemClosedSession | null>((resolve) => {
        resolveFetch = resolve;
      });
    });

    const coordinator = new RemoteAuditLookupCoordinator({
      initialViewMode: "audit",
      fetchSession: delayedFetch,
    });

    let selectedSessionId: string | null = null;
    let expiredSessionId: string | null = null;
    const extraAuditSessions = new Map<string, FilesystemClosedSession>();

    const selectSessionSpy = vi.fn((sid: string) => {
      selectedSessionId = sid;
    });

    const replaceStateSpy = vi.spyOn(window.history, "replaceState");

    const navCoordinator = new FilesystemNavigationCoordinator({
      getViewMode: () => "audit",
      getSelectedSessionId: () => selectedSessionId,
      getHideHomeOnly: () => false,
      getTargetPathFilter: () => null,
      getSelectedHistoryEventId: () => "hop-1",
      getRequestedHop: () => "hop-1",
      getExpiredSessionId: () => expiredSessionId,
      getSnapshot: () => ({
        sessions: [],
        recentClosedSessions: [],
        nodes: [],
        truncated: false,
        generatedAt: "",
      }),
      getExtraAuditSessions: () => extraAuditSessions,
      setExtraAuditSessions: (updater) => {
        const next = updater(extraAuditSessions);
        extraAuditSessions.clear();
        for (const [k, v] of next) extraAuditSessions.set(k, v as FilesystemClosedSession);
      },
      getAllSessions: () => [],
      getSessionById: () => new Map(),

      setViewMode: vi.fn(),
      setHideHomeOnly: vi.fn(),
      setTargetPathFilter: vi.fn(),
      setSelectedHistoryEventId: vi.fn(),
      setExpiredSessionId: (id) => { expiredSessionId = id; },
      setSelectedSessionId: (id) => { selectedSessionId = id; },
      setRequestedHop: vi.fn(),
      setRequestedSessionId: vi.fn(),

      selectSession: selectSessionSpy,
      resetHistory: vi.fn(),
      resetRequestedHopState: vi.fn(),

      coordinator,
    });

    // Popstate A arrives for a retained session not in snapshot
    window.history.replaceState(null, "", "/filesystem-activity?view=audit&sessionId=remote-1&hop=hop-1");
    navCoordinator.handlePopState(window.location.search);

    expect(navCoordinator.isPopStatePending()).toBe(true);
    expect(coordinator.isInFlight()).toBe(true);
    expect(delayedFetch).toHaveBeenCalledTimes(1);

    // Subsequent tick attempts synchronizeUrlState with stale pre-lookup state:
    // It MUST be suppressed because popstate transaction is pending!
    replaceStateSpy.mockClear();
    navCoordinator.synchronizeUrlState();
    expect(replaceStateSpy).not.toHaveBeenCalled();

    // A second identical popstate arrives while lookup is pending:
    // It joins without creating duplicate fetch or losing transaction ownership
    navCoordinator.handlePopState(window.location.search);
    expect(delayedFetch).toHaveBeenCalledTimes(1);
    expect(navCoordinator.isPopStatePending()).toBe(true);

    // Resolve network request
    const foundSession = makeSession("remote-1");
    resolveFetch(foundSession);
    // Flush microtasks
    await new Promise<void>((r) => { Promise.resolve().then(() => Promise.resolve().then(r)); });

    expect(navCoordinator.isPopStatePending()).toBe(false);
    expect(selectSessionSpy).toHaveBeenCalledWith("remote-1", foundSession, "hop-1");
    expect(extraAuditSessions.has("remote-1")).toBe(true);
    expect(expiredSessionId).toBeNull();
  });

  it("Finding 2: Popstate remote lookup 404 marks transaction terminal and marks expiredSessionId once", async () => {
    let resolveFetch!: (s: FilesystemClosedSession | null) => void;
    const delayedFetch = vi.fn().mockImplementation(() => {
      return new Promise<FilesystemClosedSession | null>((resolve) => {
        resolveFetch = resolve;
      });
    });

    const coordinator = new RemoteAuditLookupCoordinator({
      initialViewMode: "audit",
      fetchSession: delayedFetch,
    });

    let selectedSessionId: string | null = null;
    let expiredSessionId: string | null = null;

    const navCoordinator = new FilesystemNavigationCoordinator({
      getViewMode: () => "audit",
      getSelectedSessionId: () => selectedSessionId,
      getHideHomeOnly: () => false,
      getTargetPathFilter: () => null,
      getSelectedHistoryEventId: () => null,
      getRequestedHop: () => null,
      getExpiredSessionId: () => expiredSessionId,
      getSnapshot: () => ({
        sessions: [],
        recentClosedSessions: [],
        nodes: [],
        truncated: false,
        generatedAt: "",
      }),
      getExtraAuditSessions: () => new Map(),
      getAllSessions: () => [],
      getSessionById: () => new Map(),

      setViewMode: vi.fn(),
      setHideHomeOnly: vi.fn(),
      setTargetPathFilter: vi.fn(),
      setSelectedHistoryEventId: vi.fn(),
      setExpiredSessionId: (id) => { expiredSessionId = id; },
      setSelectedSessionId: (id) => { selectedSessionId = id; },
      setRequestedHop: vi.fn(),
      setRequestedSessionId: vi.fn(),

      selectSession: vi.fn(),
      resetHistory: vi.fn(),
      resetRequestedHopState: vi.fn(),

      coordinator,
    });

    window.history.replaceState(null, "", "/filesystem-activity?view=audit&sessionId=remote-404");
    navCoordinator.handlePopState(window.location.search);

    expect(navCoordinator.isPopStatePending()).toBe(true);

    // Resolve with null (session not found remotely)
    resolveFetch(null);
    await new Promise<void>((r) => { Promise.resolve().then(() => Promise.resolve().then(r)); });

    expect(navCoordinator.isPopStatePending()).toBe(false);
    expect(expiredSessionId).toBe("remote-404");
    expect(selectedSessionId).toBeNull();
  });

  it("Finding 2: Rapid A → B popstate navigation aborts A and discards stale callbacks", async () => {
    let abortCalledA = false;
    let resolveB!: (session: FilesystemClosedSession | null) => void;
    const delayedFetch = vi.fn().mockImplementation((sid: string, signal: AbortSignal) => {
      return new Promise<FilesystemClosedSession | null>((resolve) => {
        signal.addEventListener("abort", () => {
          if (sid === "remote-A") abortCalledA = true;
          resolve(null);
        });
        if (sid === "remote-B") {
          resolveB = resolve;
        }
      });
    });

    const coordinator = new RemoteAuditLookupCoordinator({
      initialViewMode: "audit",
      fetchSession: delayedFetch,
    });

    let selectedSessionId: string | null = null;
    const selectSessionSpy = vi.fn((sid: string) => {
      selectedSessionId = sid;
    });

    const navCoordinator = new FilesystemNavigationCoordinator({
      getViewMode: () => "audit",
      getSelectedSessionId: () => selectedSessionId,
      getHideHomeOnly: () => false,
      getTargetPathFilter: () => null,
      getSelectedHistoryEventId: () => null,
      getRequestedHop: () => null,
      getExpiredSessionId: () => null,
      getSnapshot: () => ({
        sessions: [],
        recentClosedSessions: [],
        nodes: [],
        truncated: false,
        generatedAt: "",
      }),
      getExtraAuditSessions: () => new Map(),
      getAllSessions: () => [],
      getSessionById: () => new Map(),

      setViewMode: vi.fn(),
      setHideHomeOnly: vi.fn(),
      setTargetPathFilter: vi.fn(),
      setSelectedHistoryEventId: vi.fn(),
      setExpiredSessionId: vi.fn(),
      setSelectedSessionId: (id) => { selectedSessionId = id; },
      setRequestedHop: vi.fn(),
      setRequestedSessionId: vi.fn(),

      selectSession: selectSessionSpy,
      resetHistory: vi.fn(),
      resetRequestedHopState: vi.fn(),

      coordinator,
    });

    // 1. Popstate to A
    window.history.replaceState(null, "", "/filesystem-activity?view=audit&sessionId=remote-A");
    navCoordinator.handlePopState(window.location.search);
    expect(coordinator.isInFlight()).toBe(true);

    // 2. Rapid Popstate to B before A completes
    window.history.replaceState(null, "", "/filesystem-activity?view=audit&sessionId=remote-B");
    navCoordinator.handlePopState(window.location.search);

    expect(abortCalledA).toBe(true);

    resolveB(makeSession("remote-B"));
    await Promise.resolve();
    await Promise.resolve();

    expect(navCoordinator.isPopStatePending()).toBe(false);
    expect(selectSessionSpy).toHaveBeenCalledWith("remote-B", expect.objectContaining({ sessionId: "remote-B" }), null);
    expect(selectSessionSpy).not.toHaveBeenCalledWith("remote-A", expect.anything(), expect.anything());
  });

  it("Finding 1 (wiring): bindUrlState rerenders cannot replace bindDomainAdapter callbacks", () => {
    const pushStateSpy = vi.spyOn(window.history, "pushState");
    window.history.replaceState(null, "", "/filesystem-activity?view=audit&sessionId=sess-home");

    const sessionHome = makeSession("sess-home", {
      cwdState: { path: "/home/user", status: "confirmed", sourceEventId: null, observedAt: "" },
      auditSummary: { visitedPaths: ["/home/user"], homeOnly: true, eventCount: 1 },
    });
    const sessionNonHome = makeSession("sess-nonhome", {
      cwdState: { path: "/var/log", status: "confirmed", sourceEventId: null, observedAt: "" },
      auditSummary: { visitedPaths: ["/var/log"], homeOnly: false, eventCount: 1 },
    });
    const allSessions = [sessionNonHome, sessionHome];
    const sessionById = new Map(allSessions.map((s) => [s.sessionId, s]));

    let viewMode: "live" | "audit" = "audit";
    let selectedSessionId: string | null = "sess-home";
    let hideHomeOnly = false;
    const selectSessionSpy = vi.fn((sid: string) => { selectedSessionId = sid; });

    const coord = new FilesystemNavigationCoordinator();

    const makeUrlBindings = (): Parameters<typeof coord.bindUrlState>[0] => ({
      getViewMode: () => viewMode,
      getSelectedSessionId: () => selectedSessionId,
      getHideHomeOnly: () => hideHomeOnly,
      getTargetPathFilter: () => null,
      getSelectedHistoryEventId: () => null,
      getRequestedHop: () => null,
      getExpiredSessionId: () => null,
      getSnapshot: () => ({ sessions: allSessions, recentClosedSessions: [], nodes: [], truncated: false, generatedAt: "" }),
      getExtraAuditSessions: () => new Map(),
      setViewMode: (v) => { viewMode = v; },
      setHideHomeOnly: (h) => { hideHomeOnly = h; },
      setTargetPathFilter: vi.fn(),
      setSelectedHistoryEventId: vi.fn(),
      setExpiredSessionId: vi.fn(),
      setSelectedSessionId: (id) => { selectedSessionId = id; },
      setRequestedHop: vi.fn(),
      setRequestedSessionId: vi.fn(),
    });

    // Initial bind
    coord.bindUrlState(makeUrlBindings());
    coord.bindDomainAdapter({
      getAllSessions: () => allSessions,
      getSessionById: () => sessionById,
      selectSession: selectSessionSpy,
      resetHistory: vi.fn(),
      resetRequestedHopState: vi.fn(),
    });

    // Simulate URL state rebind (e.g. snapshot update rerender)
    coord.bindUrlState(makeUrlBindings());

    // sess-home (homeOnly=true) gets filtered when hideHomeOnly=true → fallback to sess-nonhome
    coord.userToggleHideHome();

    expect(pushStateSpy).toHaveBeenCalledTimes(1);
    expect(pushStateSpy.mock.calls[0]?.[2]).toBe(
      "/filesystem-activity?view=audit&sessionId=sess-nonhome&hideHome=1",
    );
    expect(selectSessionSpy).toHaveBeenCalledWith("sess-nonhome");

    // Simulate domain adapter rebind (e.g. callback identity change from parent rerender)
    coord.bindDomainAdapter({
      getAllSessions: () => allSessions,
      getSessionById: () => sessionById,
      selectSession: selectSessionSpy,
      resetHistory: vi.fn(),
      resetRequestedHopState: vi.fn(),
    });

    // URL state still correct after domain adapter rebind
    pushStateSpy.mockClear();
    selectSessionSpy.mockClear();
    coord.userToggleHideHome(); // toggles back to hideHome=false; no fallback needed (sess-nonhome survives)
    expect(pushStateSpy).toHaveBeenCalledTimes(1);
  });
});
