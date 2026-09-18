// @vitest-environment happy-dom
import { act, createElement, useCallback, useEffect, useRef, useState } from "react";
import { createRoot, type Root } from "react-dom/client";
import { MotionGlobalConfig } from "framer-motion";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type {
  FilesystemClosedSession,
  FilesystemTopologySession,
  SessionCwdHistoryEvent,
  FilesystemTopologySnapshot,
} from "../src/lib/dashboardTypes";
import { AuditFilterControls } from "../src/components/filesystem/AuditFilterControls";
import { AuditSessionSelect } from "../src/components/filesystem/AuditSessionSelect";
import { CwdRouteHistory } from "../src/components/filesystem/CwdRouteHistory";
import { ResponseActionPanel } from "../src/components/filesystem/ResponseActionPanel";
import { TopologyCanvas } from "../src/components/filesystem/TopologyCanvas";
import { useAuditReplay } from "../src/components/filesystem/useAuditReplay";
import { useResponseActionController } from "../src/components/filesystem/ResponseActionController";
import { useSessionCwdHistory } from "../src/components/filesystem/useSessionCwdHistory";
import type { DistinctPathOption } from "../src/components/filesystem/filesystemUtils";

// @ts-expect-error React act environment flag
globalThis.IS_REACT_ACT_ENVIRONMENT = true;

vi.mock("server-only", () => ({}));
MotionGlobalConfig.skipAnimations = true;

const session: FilesystemTopologySession = {
  sessionId: "live-session",
  sourceIp: "192.0.2.10",
  cwdState: {
    path: "/var/log",
    status: "confirmed",
    observedAt: "2026-09-19T00:00:00.000Z",
    sourceEventId: null,
  },
  auditSummary: { visitedPaths: ["/var/log"], homeOnly: false, eventCount: 3 },
};

const emptyClosedSession = (id: string, path = "/var/log"): FilesystemClosedSession => ({
  sessionId: id,
  sourceIp: `198.51.100.${id.slice(-1)}`,
  closedAt: "2026-09-19T00:00:00.000Z",
  cwdState: {
    path,
    status: "confirmed",
    observedAt: "2026-09-19T00:00:00.000Z",
    sourceEventId: null,
  },
  auditSummary: { visitedPaths: [path], homeOnly: path.startsWith("/home"), eventCount: 1 },
});

const event = (id: string, at: string, toPath = `/${id}`): SessionCwdHistoryEvent => ({
  id,
  sessionId: "audit-session",
  fromPath: "/",
  toPath,
  command: `cd ${toPath}`,
  action: "change",
  status: "confirmed",
  at,
});

function jsonResponse(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function fireInputChange(input: HTMLInputElement, value: string): void {
  const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value")?.set;
  setter?.call(input, value);
  input.dispatchEvent(new Event("input", { bubbles: true }));
  input.dispatchEvent(new Event("change", { bubbles: true }));
}

function fireKey(element: HTMLElement, key: string): void {
  element.dispatchEvent(new KeyboardEvent("keydown", { key, bubbles: true, cancelable: true }));
}

function AuditSelectorFilterComposition() {
  const [hideHomeOnly, setHideHomeOnly] = useState(false);
  const [targetPath, setTargetPath] = useState<string | null>(null);
  const [searchResults, setSearchResults] = useState<FilesystemClosedSession[]>([]);
  const [searchHasMore, setSearchHasMore] = useState(false);
  const [searchIsLoading, setSearchIsLoading] = useState(false);
  const [searchIsComplete, setSearchIsComplete] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [cursor, setCursor] = useState<string | null>(null);

  const runSearch = async (query: string, nextCursor: string | null = null) => {
    setSearchIsLoading(true);
    setSearchQuery(query);
    const params = new URLSearchParams({ q: query });
    if (hideHomeOnly) params.set("hideHome", "1");
    if (targetPath) params.set("targetPath", targetPath);
    if (nextCursor) params.set("cursor", nextCursor);
    const response = await fetch(`/api/filesystem-topology/audit-sessions?${params.toString()}`);
    const payload = (await response.json()) as { items: FilesystemClosedSession[]; nextCursor?: string | null };
    setSearchResults((current) => {
      const existing = new Set(current.map((item) => item.sessionId));
      return nextCursor
        ? [...current, ...payload.items.filter((item) => !existing.has(item.sessionId))]
        : payload.items;
    });
    setCursor(payload.nextCursor ?? null);
    setSearchHasMore(Boolean(payload.nextCursor));
    setSearchIsComplete(!payload.nextCursor);
    setSearchIsLoading(false);
  };

  const paths: DistinctPathOption[] = [
    { path: "/var/log", sessionCount: 2 },
    { path: "/home/operator", sessionCount: 1 },
  ];

  return createElement(
    "div",
    null,
    createElement(AuditSessionSelect, {
      sessions: [session],
      recentClosedSessions: [],
      selectedSessionId: null,
      onSelectSession: () => {},
      searchResults,
      searchHasMore,
      searchIsLoading,
      searchIsComplete,
      onSearch: (query) => runSearch(query),
      onLoadMoreSearch: () => (cursor ? runSearch(searchQuery, cursor) : undefined),
      hideHomeOnly,
      targetPathFilter: targetPath,
    }),
    createElement(AuditFilterControls, {
      hideHomeOnly,
      onToggleHideHomeOnly: () => setHideHomeOnly((value) => !value),
      targetPath,
      onSelectTargetPath: setTargetPath,
      distinctPaths: paths,
      homeOnlyCount: 1,
      filteredCount: searchResults.length,
      totalCount: 3,
      onResetFilters: () => {
        setHideHomeOnly(false);
        setTargetPath(null);
      },
    }),
  );
}

function DeepLinkHistoryComposition({ hopId }: { hopId: string }) {
  const requestedHopRef = useRef<string | null>(hopId);
  const [selectedEventId, setSelectedEventId] = useState<string | null>(null);
  const handleHistorySelect = useCallback((id: string | null) => setSelectedEventId(id), []);
  const historyState = useSessionCwdHistory({
    requestedHopRef,
    viewMode: "audit",
    onSelectHistoryEventId: handleHistorySelect,
  });
  const { loadHistory } = historyState;
  useEffect(() => {
    requestedHopRef.current = hopId;
    void loadHistory("audit-session", null);
  }, [loadHistory, hopId]);
  const replay = useAuditReplay({
    viewMode: "audit",
    history: historyState.history,
    anchoredHop: historyState.anchoredHop,
    historyTotalItems: historyState.historyTotalItems,
    historyTotalSuccessfulItems: historyState.historyTotalSuccessfulItems,
    historyComplete: historyState.historyComplete,
    selectedHistoryEventId: selectedEventId,
    onSelectHistoryEventId: (id) => setSelectedEventId(id),
  });

  return createElement(CwdRouteHistory, {
    selectedSession: { ...session, sessionId: "audit-session" },
    history: historyState.history,
    anchoredHop: historyState.anchoredHop,
    historyStatus: historyState.historyStatus,
    historyCursor: historyState.historyCursor,
    historyTotalItems: historyState.historyTotalItems,
    historyTotalSuccessfulItems: historyState.historyTotalSuccessfulItems,
    historyComplete: historyState.historyComplete,
    replay: replay.presentation,
    activeTab: "replay",
    responsePanel: null,
    hopResolutionStatus: historyState.hopResolutionStatus,
    requestedHop: historyState.requestedHop,
    onClearHop: historyState.clearRequestedHop,
    onShowLatestHop: historyState.selectLatestHop,
    onSelectHistoryEventId: (id) => setSelectedEventId(id),
    onLoadEarlier: () => {
      if (historyState.historyCursor) void historyState.loadHistory("audit-session", historyState.historyCursor, true);
    },
  });
}

function ResponseComposition({ enabled }: { enabled: boolean }) {
  const responseAction = useResponseActionController({
    selectedSession: session,
    sessionIsLive: false,
    enabled,
  });
  return createElement(ResponseActionPanel, {
    selectedSession: session,
    sessionIsLive: false,
    visibleTerminateAction: responseAction.visibleTerminateAction,
    visibleTerminateCapability: responseAction.visibleTerminateCapability,
    terminateDialogOpen: responseAction.terminateDialogOpen,
    onTerminateDialogOpenChange: responseAction.setTerminateDialogOpen,
    terminateProcessing: responseAction.terminateProcessing,
    terminateError: responseAction.terminateError,
    onTerminateErrorChange: responseAction.setTerminateError,
    operationToast: responseAction.operationToast,
    onOperationToastChange: responseAction.setOperationToast,
    onTerminateSession: responseAction.handleTerminateSession,
  });
}

describe("FA-013 production component evidence", () => {
  let container: HTMLDivElement;
  let root: Root;

  beforeEach(() => {
    container = document.createElement("div");
    document.body.appendChild(container);
    root = createRoot(container);
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
    act(() => root.unmount());
    container.remove();
  });

  it("A: renders the selector/filter composition with scoped remote page-one/page-two pagination", async () => {
    vi.useFakeTimers();
    const firstPage = {
      items: [emptyClosedSession("closed-1"), emptyClosedSession("closed-2", "/var/log")],
      nextCursor: "page-two",
    };
    const secondPage = {
      items: [emptyClosedSession("closed-2", "/var/log"), emptyClosedSession("closed-3", "/etc")],
      nextCursor: null,
    };
    const fetchMock = vi.fn((url: string) =>
      Promise.resolve(url.includes("cursor=page-two") ? jsonResponse(secondPage) : jsonResponse(firstPage)),
    );
    vi.stubGlobal("fetch", fetchMock);

    await act(async () => root.render(createElement(AuditSelectorFilterComposition)));
    const filterButtons = Array.from(container.querySelectorAll("button"));
    (filterButtons.find((button) => button.textContent?.includes("Exclude home-only")) as HTMLButtonElement).click();
    const pathTrigger = Array.from(container.querySelectorAll('button[role="combobox"]'))[1] as HTMLButtonElement;
    await act(async () => pathTrigger.click());
    const pathOption = Array.from(container.querySelectorAll('button[role="option"]')).find((button) => button.textContent?.includes("/var/log"));
    await act(async () => (pathOption as HTMLButtonElement).click());

    const sessionTrigger = Array.from(container.querySelectorAll('button[role="combobox"]'))[0] as HTMLButtonElement;
    await act(async () => sessionTrigger.click());
    const search = container.querySelector('input[role="searchbox"]') as HTMLInputElement;
    await act(async () => fireInputChange(search, "attack"));
    await act(async () => vi.advanceTimersByTimeAsync(260));

    expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining("q=attack"),
    );
    expect(fetchMock.mock.calls[0][0]).toContain("hideHome=1");
    expect(fetchMock.mock.calls[0][0]).toContain("targetPath=%2Fvar%2Flog");
    expect(container.textContent).toContain("198.51.100.1");

    const loadMore = Array.from(container.querySelectorAll("button")).find((button) => button.textContent?.includes("Load more matching sessions"));
    await act(async () => (loadMore as HTMLButtonElement).click());
    expect(fetchMock.mock.calls[1][0]).toContain("cursor=page-two");
    expect(container.querySelectorAll('[role="listbox"]')[0].querySelectorAll('button[role="option"]').length).toBe(3);
    expect(container.textContent).toContain("All matching search results loaded (3)");

    let resolveStale!: (response: Response) => void;
    const stale = new Promise<Response>((resolve) => { resolveStale = resolve; });
    fetchMock.mockImplementation((url: string) => {
      if (url.includes("q=new-query")) return Promise.resolve(jsonResponse({ items: [emptyClosedSession("closed-new")], nextCursor: null }));
      if (url.includes("cursor=page-two")) return stale;
      return Promise.resolve(jsonResponse(firstPage));
    });
    const remounted = Array.from(container.querySelectorAll("button")).find((button) => button.textContent?.includes("Load more"));
    expect(remounted).toBeUndefined();
    await act(async () => fireInputChange(search, "new-query"));
    await act(async () => vi.advanceTimersByTimeAsync(260));
    expect(container.textContent).toContain("closed-n");
    resolveStale(jsonResponse({ items: [emptyClosedSession("stale-page-two")], nextCursor: null }));
    await act(async () => Promise.resolve());
    expect(container.textContent).not.toContain("stale-page-two");
  });

  it("B: resolves a retained deep hop, keeps the URL anchor, and reconciles when earlier history loads", async () => {
    const first = [event("event-3", "2026-09-19T00:00:30.000Z", "/three"), event("event-2", "2026-09-19T00:00:20.000Z", "/two")];
    const anchored = event("event-1", "2026-09-19T00:00:10.000Z", "/one");
    const fetchMock = vi.fn((url: string) => {
      if (url.includes("hop=event-1")) return Promise.resolve(jsonResponse({ item: anchored, hopNumber: 1 }));
      if (url.includes("cursor=earlier")) return Promise.resolve(jsonResponse({ items: [anchored, first[1]], nextCursor: null, totalItems: 3, totalSuccessfulItems: 3, complete: true }));
      return Promise.resolve(jsonResponse({ items: first, nextCursor: "earlier", totalItems: 3, totalSuccessfulItems: 3, complete: false }));
    });
    vi.stubGlobal("fetch", fetchMock);
    window.history.replaceState(null, "", "/filesystem-activity?view=audit&sessionId=audit-session&hop=event-1");

    await act(async () => root.render(createElement(DeepLinkHistoryComposition, { hopId: "event-1" })));
    await act(async () => Promise.resolve());
    expect(window.location.search).toContain("hop=event-1");
    expect(container.querySelector('[data-testid="anchored-hop-banner"]')).not.toBeNull();
    expect(container.textContent).toContain("Anchored deep hop");

    const loadEarlier = Array.from(container.querySelectorAll("button")).find((button) => button.textContent?.includes("Load earlier hops"));
    await act(async () => (loadEarlier as HTMLButtonElement).click());
    await act(async () => Promise.resolve());
    expect(container.querySelector('[data-testid="anchored-hop-banner"]')).toBeNull();
    expect(container.textContent).toContain("/one");
    expect(window.location.search).toContain("hop=event-1");

    await act(async () => root.render(createElement(DeepLinkHistoryComposition, { hopId: "missing-hop" })));
    await act(async () => Promise.resolve());
    expect(window.location.search).toContain("hop=event-1");
  });

  it("E: polls the controlled Response tab with bounded cadence and aborts on disable", async () => {
    vi.useFakeTimers();
    const requestedAt = new Date(Date.now()).toISOString();
    const pending = {
      actionId: "action-1",
      sessionId: session.sessionId,
      action: "terminate_session",
      status: "requested",
      requestedBy: "operator",
      requestedAt,
      deliveredAt: null,
      verifiedAt: null,
      failureCategory: null,
    } as const;
    const verified = { ...pending, status: "verified", verifiedAt: requestedAt };
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse({ available: true, action: pending }))
      .mockResolvedValueOnce(jsonResponse({ available: true, action: pending }))
      .mockResolvedValueOnce(jsonResponse({ available: true, action: verified }));
    vi.stubGlobal("fetch", fetchMock);

    await act(async () => root.render(createElement(ResponseComposition, { enabled: true })));
    await act(async () => Promise.resolve());
    expect(fetchMock).toHaveBeenCalledTimes(1);
    await act(async () => vi.advanceTimersByTimeAsync(100));
    await act(async () => Promise.resolve());
    expect(fetchMock).toHaveBeenCalledTimes(2);
    await act(async () => vi.advanceTimersByTimeAsync(150));
    await act(async () => Promise.resolve());
    expect(fetchMock).toHaveBeenCalledTimes(3);
    expect(container.textContent).toContain("Session disconnected");

    const abortingFetch = vi.fn((_url: string, init?: RequestInit) => new Promise<Response>((resolve) => {
      init?.signal?.addEventListener("abort", () => resolve(jsonResponse({ available: true, action: pending })));
    }));
    vi.stubGlobal("fetch", abortingFetch);
    await act(async () => root.render(createElement(ResponseComposition, { enabled: false })));
    await act(async () => root.render(createElement(ResponseComposition, { enabled: true })));
    await act(async () => Promise.resolve());
    const signal = abortingFetch.mock.calls[0][1]?.signal as AbortSignal;
    await act(async () => root.render(createElement(ResponseComposition, { enabled: false })));
    expect(signal.aborted).toBe(true);
  });

  it("F: renders a valid empty topology as live no-activity without creating a freshness owner", async () => {
    vi.useFakeTimers();
    const snapshot: FilesystemTopologySnapshot = {
      nodes: [],
      sessions: [],
      recentClosedSessions: [],
      truncated: false,
      generatedAt: "2026-09-19T00:00:00.000Z",
      latestTelemetryAt: null,
    };
    const freshnessState = {
      classification: "fresh" as const,
      label: "Live · No activity",
      detail: "No authoritative telemetry activity has been observed yet.",
      badgeClass: "",
      dotClass: "",
      isDegraded: false,
      isStale: false,
      telemetryAgeMs: null,
      snapshotReceiptAgeMs: 0,
      retrievalAgeMs: 0,
      telemetryStatus: "none" as const,
    };
    await act(async () => root.render(createElement(TopologyCanvas, {
      snapshot,
      regionStatus: "ready",
      streamState: "live",
      freshnessState,
      selectedSessionId: null,
      selectedPath: null,
      onSelectSession: () => {},
      onSelectPath: () => {},
      staleThresholdMs: 30_000,
    })));
    expect(container.textContent).toContain("No observed working directories yet");
    expect(container.textContent).not.toContain("Offline");
    expect(container.textContent).not.toContain("Stale");
    expect(vi.getTimerCount()).toBe(0);
  });

  it("I: drives the production scrubber by elapsed position and hop-key fallback", async () => {
    const events = [event("event-c", "2026-09-19T00:30:00.000Z", "/c"), event("event-b", "2026-09-19T00:00:05.000Z", "/b"), event("event-a", "2026-09-19T00:00:00.000Z", "/a")];
    const selected = vi.fn();
    function ReplayHarness() {
      const [selectedId, setSelectedId] = useState("event-a");
      const replay = useAuditReplay({
        viewMode: "audit",
        history: events,
        anchoredHop: null,
        historyTotalItems: 3,
        historyTotalSuccessfulItems: 3,
        historyComplete: true,
        selectedHistoryEventId: selectedId,
        onSelectHistoryEventId: (id) => {
          if (id) setSelectedId(id);
          selected(id);
        },
      });
      return createElement(CwdRouteHistory, {
        selectedSession: { ...session, sessionId: "audit-session" },
        history: events,
        historyStatus: "ready",
        historyCursor: null,
        historyTotalItems: 3,
        historyTotalSuccessfulItems: 3,
        historyComplete: true,
        replay: replay.presentation,
        activeTab: "replay",
        responsePanel: null,
        onClearHop: () => {},
        onShowLatestHop: () => {},
        onSelectHistoryEventId: (id) => {
          if (id) setSelectedId(id);
          selected(id);
        },
        onLoadEarlier: () => {},
      });
    }
    await act(async () => root.render(createElement(ReplayHarness)));
    const range = container.querySelector('input[type="range"]') as HTMLInputElement;
    expect(range.max).toBe("1800000");
    await act(async () => fireInputChange(range, "5000"));
    expect(selected).toHaveBeenCalledWith("event-b");
    await act(async () => fireKey(range, "Home"));
    await act(async () => fireKey(range, "End"));
    expect(selected).toHaveBeenLastCalledWith("event-c");
  });
});
