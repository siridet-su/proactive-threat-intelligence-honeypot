// @vitest-environment happy-dom
import { act, createElement } from "react";
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
import { RemoteAuditLookupCoordinator } from "@/components/filesystem/sessionHopResolver";

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
  // Finding 2: Same-Intent In-Flight Lookup Join Semantics
  // =========================================================================
  it("Finding 2: RemoteAuditLookupCoordinator.requestLookup joins active promise and delivers results to all subscribers", async () => {
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
    const p2 = coordinator.requestLookup(
      { sessionId: "sess-delayed", targetHopId: "hop-1" },
      cb2,
      delayedFetch,
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
    expect(cb1.onSessionFound).toHaveBeenCalledWith(mockSession, "hop-1");
    expect(cb2.onSessionFound).toHaveBeenCalledWith(mockSession, "hop-1");
    expect(cb1.onSessionNotFound).not.toHaveBeenCalled();
    expect(cb2.onSessionNotFound).not.toHaveBeenCalled();
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
    await new Promise((r) => setTimeout(r, 10));

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
    await new Promise((r) => setTimeout(r, 10));

    expect(navCoordinator.isPopStatePending()).toBe(false);
    expect(expiredSessionId).toBe("remote-404");
    expect(selectedSessionId).toBeNull();
  });

  it("Finding 2: Snapshot-initiated lookup joined by popstate transaction", async () => {
    let resolveFetch!: (s: FilesystemClosedSession | null) => void;
    const delayedFetch = vi.fn().mockImplementation(() => {
      return new Promise<FilesystemClosedSession | null>((resolve) => {
        resolveFetch = resolve;
      });
    });

    const snapshotCallback = { onSessionFound: vi.fn(), onSessionNotFound: vi.fn() };
    const coordinator = new RemoteAuditLookupCoordinator({
      initialViewMode: "audit",
      fetchSession: delayedFetch,
      callbacks: snapshotCallback,
    });

    // 1. Snapshot update initiates lookup for "remote-shared"
    const snapshotPromise = coordinator.lookup({ sessionId: "remote-shared", targetHopId: "hop-1" });
    expect(delayedFetch).toHaveBeenCalledTimes(1);
    expect(coordinator.isInFlight()).toBe(true);

    let selectedSessionId: string | null = null;
    const selectSessionSpy = vi.fn((sid: string) => {
      selectedSessionId = sid;
    });

    const navCoordinator = new FilesystemNavigationCoordinator({
      getViewMode: () => "audit",
      getSelectedSessionId: () => selectedSessionId,
      getHideHomeOnly: () => false,
      getTargetPathFilter: () => null,
      getSelectedHistoryEventId: () => "hop-1",
      getRequestedHop: () => "hop-1",
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

    // 2. Popstate arrives for the same session while snapshot lookup is in flight
    window.history.replaceState(null, "", "/filesystem-activity?view=audit&sessionId=remote-shared&hop=hop-1");
    navCoordinator.handlePopState(window.location.search);

    // Should join the existing in-flight lookup without restarting fetch
    expect(delayedFetch).toHaveBeenCalledTimes(1);
    expect(navCoordinator.isPopStatePending()).toBe(true);

    // Resolve fetch
    const remoteSession = makeSession("remote-shared");
    resolveFetch(remoteSession);
    await snapshotPromise;
    await new Promise((r) => setTimeout(r, 10));

    expect(snapshotCallback.onSessionFound).toHaveBeenCalledWith(remoteSession, "hop-1");
    expect(selectSessionSpy).toHaveBeenCalledWith("remote-shared", remoteSession, "hop-1");
    expect(navCoordinator.isPopStatePending()).toBe(false);
  });

  it("Finding 2: Rapid A -> B popstate navigation aborts A and discards stale callbacks", async () => {
    let abortCalledA = false;
    const delayedFetch = vi.fn().mockImplementation((sid: string, signal: AbortSignal) => {
      return new Promise<FilesystemClosedSession | null>((resolve) => {
        signal.addEventListener("abort", () => {
          if (sid === "remote-A") abortCalledA = true;
          resolve(null);
        });
        if (sid === "remote-B") {
          setTimeout(() => resolve(makeSession("remote-B")), 10);
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

    await new Promise((r) => setTimeout(r, 30));

    expect(navCoordinator.isPopStatePending()).toBe(false);
    expect(selectSessionSpy).toHaveBeenCalledWith("remote-B", expect.objectContaining({ sessionId: "remote-B" }), null);
    expect(selectSessionSpy).not.toHaveBeenCalledWith("remote-A", expect.anything(), expect.anything());
  });
});
