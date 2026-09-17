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
  areAuditUrlParamsEqual,
  buildAuditTargetUrl,
  buildAuditUrlSearch,
  parseAuditUrlParams,
  resolveFilterChangeWithFallback,
} from "@/components/filesystem/filesystemUtils";
import {
  processAuditPopState,
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

  // =========================================================================
  // Scenario 1: User view change pushes 1 entry
  // =========================================================================
  it("Scenario 1: User view change pushes exactly 1 history entry", () => {
    const pushStateSpy = vi.spyOn(window.history, "pushState");
    const coordinator = new RemoteAuditLookupCoordinator();
    const selectedSessionIdRef = { current: "sess-1" as string | null };
    const selectSession = vi.fn();

    let hookResult!: UseFilesystemUrlStateReturn;
    function TestComponent() {
      hookResult = useFilesystemUrlState({
        isHydrated: true,
        snapshot: null,
        extraAuditSessions: new Map(),
        selectedSessionId: "sess-1",
        selectedSessionIdRef,
        selectSession,
        lookupRemoteAuditSession: vi.fn(),
        coordinator,
      });
      return null;
    }

    act(() => {
      root.render(createElement(TestComponent));
    });

    expect(hookResult.viewMode).toBe("live");
    expect(pushStateSpy).not.toHaveBeenCalled();

    // User switches view to audit
    act(() => {
      hookResult.switchViewMode("audit", "sess-1");
    });

    expect(pushStateSpy).toHaveBeenCalledTimes(1);
    expect(pushStateSpy.mock.calls[0]?.[2]).toBe("/filesystem-activity?view=audit&sessionId=sess-1");
    expect(hookResult.viewMode).toBe("audit");

    // User switches view back to live
    act(() => {
      hookResult.switchViewMode("live");
    });

    expect(pushStateSpy).toHaveBeenCalledTimes(2);
    expect(pushStateSpy.mock.calls[1]?.[2]).toBe("/filesystem-activity");
    expect(hookResult.viewMode).toBe("live");
  });

  // =========================================================================
  // Scenario 2: User session selection pushes 1 entry
  // =========================================================================
  it("Scenario 2: User session selection pushes 1 entry with hop cleared", () => {
    window.history.replaceState(null, "", "/filesystem-activity?view=audit&sessionId=sess-1&hop=hop-1");
    const pushStateSpy = vi.spyOn(window.history, "pushState");
    const selectedSessionIdRef = { current: "sess-1" as string | null };

    let hookResult!: UseFilesystemUrlStateReturn;
    function TestComponent() {
      hookResult = useFilesystemUrlState({
        isHydrated: true,
        snapshot: null,
        extraAuditSessions: new Map(),
        selectedSessionId: "sess-1",
        selectedSessionIdRef,
        selectSession: (sid) => {
          selectedSessionIdRef.current = sid;
        },
        lookupRemoteAuditSession: vi.fn(),
      });
      return null;
    }

    act(() => {
      root.render(createElement(TestComponent));
    });

    expect(hookResult.viewMode).toBe("audit");

    // User selects a different session
    act(() => {
      hookResult.commitUserNavigation({
        view: "audit",
        sessionId: "sess-2",
        hop: null,
      });
    });

    expect(pushStateSpy).toHaveBeenCalledTimes(1);
    expect(pushStateSpy.mock.calls[0]?.[2]).toBe("/filesystem-activity?view=audit&sessionId=sess-2");
  });

  // =========================================================================
  // Scenario 3: Hide-home toggle and target-path changes are individually traversable
  // =========================================================================
  it("Scenario 3: Hide-home toggle and target-path changes are individually traversable", () => {
    window.history.replaceState(null, "", "/filesystem-activity?view=audit&sessionId=sess-1");
    const pushStateSpy = vi.spyOn(window.history, "pushState");
    const selectedSessionIdRef = { current: "sess-1" as string | null };

    let hookResult!: UseFilesystemUrlStateReturn;
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

    // 1. User toggles hideHome ON
    act(() => {
      hookResult.commitUserNavigation({ hideHome: true });
      hookResult.setHideHomeOnly(true);
    });

    expect(pushStateSpy).toHaveBeenCalledTimes(1);
    expect(pushStateSpy.mock.calls[0]?.[2]).toBe("/filesystem-activity?view=audit&sessionId=sess-1&hideHome=1");

    // 2. User sets targetPath filter to /etc
    act(() => {
      hookResult.commitUserNavigation({ targetPath: "/etc" });
      hookResult.setTargetPathFilter("/etc");
    });

    expect(pushStateSpy).toHaveBeenCalledTimes(2);
    expect(pushStateSpy.mock.calls[1]?.[2]).toBe("/filesystem-activity?view=audit&sessionId=sess-1&hideHome=1&targetPath=%2Fetc");

    // 3. User clears targetPath filter
    act(() => {
      hookResult.commitUserNavigation({ targetPath: null });
      hookResult.setTargetPathFilter(null);
    });

    expect(pushStateSpy).toHaveBeenCalledTimes(3);
    expect(pushStateSpy.mock.calls[2]?.[2]).toBe("/filesystem-activity?view=audit&sessionId=sess-1&hideHome=1");

    // 4. User toggles hideHome OFF
    act(() => {
      hookResult.commitUserNavigation({ hideHome: false });
      hookResult.setHideHomeOnly(false);
    });

    expect(pushStateSpy).toHaveBeenCalledTimes(4);
    expect(pushStateSpy.mock.calls[3]?.[2]).toBe("/filesystem-activity?view=audit&sessionId=sess-1");
  });

  // =========================================================================
  // Scenario 4: Manual hop selection, clearing, Prev, Next are traversable
  // =========================================================================
  it("Scenario 4: Manual hop selection, clearing, Prev, Next are traversable", () => {
    window.history.replaceState(null, "", "/filesystem-activity?view=audit&sessionId=sess-1");
    const pushStateSpy = vi.spyOn(window.history, "pushState");
    const selectedSessionIdRef = { current: "sess-1" as string | null };

    let hookResult!: UseFilesystemUrlStateReturn;
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

    // 1. User selects hop A
    act(() => {
      hookResult.commitUserNavigation({ hop: "hop-A" });
      hookResult.setSelectedHistoryEventId("hop-A");
    });

    expect(pushStateSpy).toHaveBeenCalledTimes(1);
    expect(pushStateSpy.mock.calls[0]?.[2]).toBe("/filesystem-activity?view=audit&sessionId=sess-1&hop=hop-A");

    // 2. User clicks Next hop -> hop B
    act(() => {
      hookResult.commitUserNavigation({ hop: "hop-B" });
      hookResult.setSelectedHistoryEventId("hop-B");
    });

    expect(pushStateSpy).toHaveBeenCalledTimes(2);
    expect(pushStateSpy.mock.calls[1]?.[2]).toBe("/filesystem-activity?view=audit&sessionId=sess-1&hop=hop-B");

    // 3. User clicks Prev hop -> hop A
    act(() => {
      hookResult.commitUserNavigation({ hop: "hop-A" });
      hookResult.setSelectedHistoryEventId("hop-A");
    });

    expect(pushStateSpy).toHaveBeenCalledTimes(3);
    expect(pushStateSpy.mock.calls[2]?.[2]).toBe("/filesystem-activity?view=audit&sessionId=sess-1&hop=hop-A");

    // 4. User clears hop
    act(() => {
      hookResult.commitUserNavigation({ hop: null });
      hookResult.setSelectedHistoryEventId(null);
    });

    expect(pushStateSpy).toHaveBeenCalledTimes(4);
    expect(pushStateSpy.mock.calls[3]?.[2]).toBe("/filesystem-activity?view=audit&sessionId=sess-1");
  });

  // =========================================================================
  // Scenario 5: Replay autoplay does not increase history length per tick
  // =========================================================================
  it("Scenario 5: Replay autoplay does not increase history length per tick", () => {
    window.history.replaceState(null, "", "/filesystem-activity?view=audit&sessionId=sess-1");
    const pushStateSpy = vi.spyOn(window.history, "pushState");
    const replaceStateSpy = vi.spyOn(window.history, "replaceState");
    const selectedSessionIdRef = { current: "sess-1" as string | null };

    let hookResult!: UseFilesystemUrlStateReturn;
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

    // Tick 1
    act(() => {
      hookResult.commitPlaybackNavigation("hop-1");
      hookResult.setSelectedHistoryEventId("hop-1");
    });

    // Tick 2
    act(() => {
      hookResult.commitPlaybackNavigation("hop-2");
      hookResult.setSelectedHistoryEventId("hop-2");
    });

    // Tick 3
    act(() => {
      hookResult.commitPlaybackNavigation("hop-3");
      hookResult.setSelectedHistoryEventId("hop-3");
    });

    // Crucial invariant: pushState was NEVER called during playback ticks!
    expect(pushStateSpy).not.toHaveBeenCalled();

    // Instead, replaceState kept the URL in sync without growing history length
    expect(replaceStateSpy).toHaveBeenCalledTimes(3);
    expect(replaceStateSpy.mock.calls[0]?.[2]).toBe("/filesystem-activity?view=audit&sessionId=sess-1&hop=hop-1");
    expect(replaceStateSpy.mock.calls[1]?.[2]).toBe("/filesystem-activity?view=audit&sessionId=sess-1&hop=hop-2");
    expect(replaceStateSpy.mock.calls[2]?.[2]).toBe("/filesystem-activity?view=audit&sessionId=sess-1&hop=hop-3");
  });

  // =========================================================================
  // Scenario 6: Back/Forward restores complete view/session/filter/hop state
  // =========================================================================
  it("Scenario 6: Back/Forward restores complete view/session/filter/hop state", () => {
    const popUrl = "?view=audit&sessionId=sess-retained&hideHome=1&targetPath=%2Fvar%2Flog&hop=hop-42";

    let restoredView: string | null = null;
    let restoredHideHome: boolean | null = null;
    let restoredTargetPath: string | null = null;
    let restoredHop: string | null = null;
    let restoredSession: string | null = null;
    const requestedHopRef = { current: null as string | null };
    const requestedSessionIdRef = { current: null as string | null };
    const selectedSessionIdRef = { current: null as string | null };
    const lookupRemoteAuditSession = vi.fn();
    const selectSession = vi.fn((sid) => {
      restoredSession = sid;
    });

    const knownSession = makeSession("sess-retained", {
      cwdState: { path: "/var/log", status: "confirmed", sourceEventId: null, observedAt: "" },
    });
    const snapshot: FilesystemTopologySnapshot = {
      sessions: [knownSession],
      recentClosedSessions: [],
      nodes: [],
      truncated: false,
      generatedAt: "2026-09-17T00:00:00.000Z",
    };

    processAuditPopState({
      search: popUrl,
      snapshot,
      extraAuditSessions: new Map(),
      lookupRemoteAuditSession,
      selectSession,
      setViewMode: (v) => {
        restoredView = v;
      },
      setHideHomeOnly: (h) => {
        restoredHideHome = h;
      },
      setTargetPathFilter: (p) => {
        restoredTargetPath = p;
      },
      setSelectedHistoryEventId: (id) => {
        restoredHop = id;
      },
      setExpiredSessionId: vi.fn(),
      requestedHopRef,
      requestedSessionIdRef,
      selectedSessionIdRef,
    });

    expect(restoredView).toBe("audit");
    expect(restoredHideHome).toBe(true);
    expect(restoredTargetPath).toBe("/var/log");
    expect(restoredHop).toBe("hop-42");
    expect(requestedHopRef.current).toBe("hop-42");
    expect(restoredSession).toBe("sess-retained");
    expect(selectSession).toHaveBeenCalledWith("sess-retained", undefined, "hop-42");
  });

  // =========================================================================
  // Scenario 7: Popstate application performs no feedback loop
  // =========================================================================
  it("Scenario 7: Popstate application performs no feedback loop", async () => {
    window.history.replaceState(null, "", "/filesystem-activity?view=audit&sessionId=sess-1");
    const pushStateSpy = vi.spyOn(window.history, "pushState");
    const replaceStateSpy = vi.spyOn(window.history, "replaceState");

    const selectedSessionIdRef = { current: "sess-1" as string | null };

    function TestComponent() {
      useFilesystemUrlState({
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

    // Reset spy call records after initial mount
    pushStateSpy.mockClear();
    replaceStateSpy.mockClear();

    // Simulate browser popstate event
    window.history.replaceState(null, "", "/filesystem-activity?view=audit&sessionId=sess-2&hideHome=1");
    replaceStateSpy.mockClear();

    act(() => {
      window.dispatchEvent(new PopStateEvent("popstate"));
    });

    // Give any microtasks/effects time to flush
    await act(async () => {
      await Promise.resolve();
    });

    // No pushState or replaceState was fired as a feedback loop from popstate!
    expect(pushStateSpy).not.toHaveBeenCalled();
    expect(replaceStateSpy).not.toHaveBeenCalled();
  });

  // =========================================================================
  // Scenario 8: Rapid Back/Forward discards stale in-flight lookups
  // =========================================================================
  it("Scenario 8: Rapid Back/Forward discards stale in-flight lookups", async () => {
    let resolveLookupA!: (val: FilesystemClosedSession | null) => void;
    let resolveLookupB!: (val: FilesystemClosedSession | null) => void;

    const fetchSession = vi.fn().mockImplementation((id: string) => {
      if (id === "sess-A") {
        return new Promise<FilesystemClosedSession | null>((resolve) => {
          resolveLookupA = resolve;
        });
      }
      return new Promise<FilesystemClosedSession | null>((resolve) => {
        resolveLookupB = resolve;
      });
    });

    const onSessionFound = vi.fn();
    const onSessionNotFound = vi.fn();

    const coordinator = new RemoteAuditLookupCoordinator({
      initialViewMode: "audit",
      fetchSession,
      callbacks: {
        onSessionFound,
        onSessionNotFound,
      },
    });

    // Popstate 1: navigation to sess-A
    coordinator.notifyNavigationScope({
      viewMode: "audit",
      sessionId: "sess-A",
      targetHopId: "hop-A",
    });
    const promiseA = coordinator.lookup({ sessionId: "sess-A", targetHopId: "hop-A" });

    // Rapid Popstate 2: navigation immediately changes to sess-B
    coordinator.notifyNavigationScope({
      viewMode: "audit",
      sessionId: "sess-B",
      targetHopId: "hop-B",
    });
    const promiseB = coordinator.lookup({ sessionId: "sess-B", targetHopId: "hop-B" });

    // Lookup A finishes late
    resolveLookupA(makeSession("sess-A"));
    const resultA = await promiseA;

    // Lookup B finishes
    const sessionB = makeSession("sess-B");
    resolveLookupB(sessionB);
    const resultB = await promiseB;

    // Lookup A was aborted/discarded due to generation change
    expect(resultA).toBeNull();
    // Lookup B succeeded
    expect(resultB).toBe(sessionB);
    // onSessionFound was only called for B
    expect(onSessionFound).toHaveBeenCalledTimes(1);
    expect(onSessionFound).toHaveBeenCalledWith(sessionB, "hop-B");
    // Active scope in coordinator is sess-B
    expect(coordinator.getNavigationScope().sessionId).toBe("sess-B");
  });

  // =========================================================================
  // Scenario 9: Switching to Live clears hop without intermediate entry
  // =========================================================================
  it("Scenario 9: Switching to Live clears hop without intermediate entry", () => {
    window.history.replaceState(null, "", "/filesystem-activity?view=audit&sessionId=sess-1&hop=hop-99");
    const pushStateSpy = vi.spyOn(window.history, "pushState");
    const selectedSessionIdRef = { current: "sess-1" as string | null };

    let hookResult!: UseFilesystemUrlStateReturn;
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

    expect(hookResult.viewMode).toBe("audit");
    expect(hookResult.selectedHistoryEventId).toBe("hop-99");

    // User switches to live mode
    act(() => {
      hookResult.switchViewMode("live");
    });

    // Pushed exactly once to clean live URL
    expect(pushStateSpy).toHaveBeenCalledTimes(1);
    expect(pushStateSpy.mock.calls[0]?.[2]).toBe("/filesystem-activity");

    // Hop state and requested hop ref were cleared synchronously
    expect(hookResult.viewMode).toBe("live");
    expect(hookResult.selectedHistoryEventId).toBeNull();
    expect(hookResult.requestedHopRef.current).toBeNull();
  });

  // =========================================================================
  // Scenario 10: Snapshot-driven fallback and initial hydration do not push entries
  // =========================================================================
  it("Scenario 10: Snapshot-driven fallback and initial hydration do not push entries", () => {
    window.history.replaceState(null, "", "/filesystem-activity?view=live&sessionId=old-closed");
    const pushStateSpy = vi.spyOn(window.history, "pushState");
    const replaceStateSpy = vi.spyOn(window.history, "replaceState");
    const selectedSessionIdRef = { current: "fallback-sess" as string | null };

    function TestComponent() {
      useFilesystemUrlState({
        isHydrated: true,
        snapshot: null,
        extraAuditSessions: new Map(),
        selectedSessionId: "fallback-sess",
        selectedSessionIdRef,
        selectSession: vi.fn(),
        lookupRemoteAuditSession: vi.fn(),
      });
      return null;
    }

    act(() => {
      root.render(createElement(TestComponent));
    });

    // In live mode, canonical URL is clean "/filesystem-activity".
    // Initial canonicalization replaces state, NEVER pushes state!
    expect(pushStateSpy).not.toHaveBeenCalled();
    expect(replaceStateSpy).toHaveBeenCalledWith(null, "", "/filesystem-activity");
  });

  // =========================================================================
  // Scenario 11: Selecting identical canonical state does not create duplicate entries
  // =========================================================================
  it("Scenario 11: Selecting identical canonical state does not create duplicate entries", () => {
    window.history.replaceState(null, "", "/filesystem-activity?view=audit&sessionId=sess-1&hideHome=1");
    const pushStateSpy = vi.spyOn(window.history, "pushState");
    const selectedSessionIdRef = { current: "sess-1" as string | null };

    let hookResult!: UseFilesystemUrlStateReturn;
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

    expect(hookResult.hideHomeOnly).toBe(true);

    // User attempts to commit identical state
    act(() => {
      hookResult.commitUserNavigation({
        view: "audit",
        sessionId: "sess-1",
        hideHome: true,
        targetPath: null,
        hop: null,
      });
    });

    // Identical canonical state does not push
    expect(pushStateSpy).not.toHaveBeenCalled();
  });

  // =========================================================================
  // Scenario 12: Filter change + session fallback produces one atomic history entry
  // =========================================================================
  it("Scenario 12: Filter change + session fallback produces one atomic history entry", () => {
    const homeOnlySession = makeSession("sess-home", {
      cwdState: { path: "/home/user", status: "confirmed", sourceEventId: null, observedAt: "" },
      auditSummary: { visitedPaths: ["/home/user"], homeOnly: true, eventCount: 1 },
    });
    const nonHomeSession = makeSession("sess-nonhome", {
      cwdState: { path: "/var/log", status: "confirmed", sourceEventId: null, observedAt: "" },
      auditSummary: { visitedPaths: ["/var/log"], homeOnly: false, eventCount: 1 },
    });

    const allSessions = [homeOnlySession, nonHomeSession];
    const sessionById = new Map([
      ["sess-home", homeOnlySession],
      ["sess-nonhome", nonHomeSession],
    ]);

    // Test resolveFilterChangeWithFallback pure computation
    const resultHideHome = resolveFilterChangeWithFallback({
      filterType: "hideHome",
      hideHomeOnly: false,
      targetPathFilter: null,
      selectedSessionId: "sess-home",
      allSessions,
      sessionById,
    });

    expect(resultHideHome.nextHideHome).toBe(true);
    expect(resultHideHome.nextSessionId).toBe("sess-nonhome");
    expect(resultHideHome.sessionChanged).toBe(true);

    // Verify commit creates exactly ONE pushState containing both new filter and new session
    window.history.replaceState(null, "", "/filesystem-activity?view=audit&sessionId=sess-home");
    const pushStateSpy = vi.spyOn(window.history, "pushState");
    const selectedSessionIdRef = { current: "sess-home" as string | null };

    let hookResult!: UseFilesystemUrlStateReturn;
    function TestComponent() {
      hookResult = useFilesystemUrlState({
        isHydrated: true,
        snapshot: null,
        extraAuditSessions: new Map(),
        selectedSessionId: "sess-home",
        selectedSessionIdRef,
        selectSession: vi.fn(),
        lookupRemoteAuditSession: vi.fn(),
      });
      return null;
    }

    act(() => {
      root.render(createElement(TestComponent));
    });

    act(() => {
      hookResult.commitUserNavigation({
        view: "audit",
        sessionId: resultHideHome.nextSessionId,
        hideHome: resultHideHome.nextHideHome,
        targetPath: null,
        hop: null,
      });
    });

    expect(pushStateSpy).toHaveBeenCalledTimes(1);
    expect(pushStateSpy.mock.calls[0]?.[2]).toBe("/filesystem-activity?view=audit&sessionId=sess-nonhome&hideHome=1");

    // Test targetPath filter with fallback:
    // Session touching only /etc vs session touching /var
    const etcSession = makeSession("sess-etc", {
      cwdState: { path: "/etc", status: "confirmed", sourceEventId: null, observedAt: "" },
      auditSummary: { visitedPaths: ["/etc"], homeOnly: false, eventCount: 1 },
    });
    const varSession = makeSession("sess-var", {
      cwdState: { path: "/var", status: "confirmed", sourceEventId: null, observedAt: "" },
      auditSummary: { visitedPaths: ["/var"], homeOnly: false, eventCount: 1 },
    });

    const pathSessions = [etcSession, varSession];
    const pathSessionById = new Map([
      ["sess-etc", etcSession],
      ["sess-var", varSession],
    ]);

    const resultTargetPath = resolveFilterChangeWithFallback({
      filterType: "targetPath",
      proposedTargetPath: "/var",
      hideHomeOnly: false,
      targetPathFilter: null,
      selectedSessionId: "sess-etc",
      allSessions: pathSessions,
      sessionById: pathSessionById,
    });

    expect(resultTargetPath.nextTargetPath).toBe("/var");
    expect(resultTargetPath.nextSessionId).toBe("sess-var");
    expect(resultTargetPath.sessionChanged).toBe(true);

    act(() => {
      hookResult.commitUserNavigation({
        view: "audit",
        sessionId: resultTargetPath.nextSessionId,
        hideHome: false,
        targetPath: resultTargetPath.nextTargetPath,
        hop: null,
      });
    });

    expect(pushStateSpy).toHaveBeenCalledTimes(2);
    expect(pushStateSpy.mock.calls[1]?.[2]).toBe("/filesystem-activity?view=audit&sessionId=sess-var&targetPath=%2Fvar");
  });

  // =========================================================================
  // Scenario 13: Encoded and Unicode target paths round-trip correctly
  // =========================================================================
  it("Scenario 13: Encoded and Unicode target paths round-trip correctly", () => {
    const unicodePath = "/var/log/ทดสอบ/ไฟล์.log";
    const spacedPath = "/var/log/my test path/sample.txt";

    // Unicode test
    const unicodeSearch = buildAuditUrlSearch({
      view: "audit",
      sessionId: "sess-unicode",
      targetPath: unicodePath,
    });
    const parsedUnicode = parseAuditUrlParams(unicodeSearch);
    expect(parsedUnicode.targetPath).toBe(unicodePath);

    const targetUrlUnicode = buildAuditTargetUrl({
      view: "audit",
      sessionId: "sess-unicode",
      targetPath: unicodePath,
    }, "/filesystem-activity");

    expect(targetUrlUnicode).toContain("/filesystem-activity?view=audit&sessionId=sess-unicode&targetPath=");

    // Equality check returns true for identical decoded paths regardless of encoding
    expect(
      areAuditUrlParamsEqual(
        { view: "audit", sessionId: "sess-unicode", targetPath: unicodePath },
        parsedUnicode,
      ),
    ).toBe(true);

    // Spaced path test
    const spacedSearch = buildAuditUrlSearch({
      view: "audit",
      sessionId: "sess-space",
      targetPath: spacedPath,
    });
    const parsedSpaced = parseAuditUrlParams(spacedSearch);
    expect(parsedSpaced.targetPath).toBe(spacedPath);

    expect(
      areAuditUrlParamsEqual(
        { view: "audit", sessionId: "sess-space", targetPath: spacedPath },
        parsedSpaced,
      ),
    ).toBe(true);
  });
});
