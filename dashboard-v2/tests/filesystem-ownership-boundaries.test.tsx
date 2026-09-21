// @vitest-environment happy-dom
import { act, createElement, useState } from "react";
import { createRoot, type Root } from "react-dom/client";
import { MotionGlobalConfig } from "framer-motion";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { FilesystemTopologySession, SessionCwdHistoryEvent } from "../src/lib/dashboardTypes";
import { FilesystemTimelinePanel } from "../src/components/filesystem/FilesystemTimelinePanel";
import { ResponseActionPanel } from "../src/components/filesystem/ResponseActionPanel";
import { useAuditReplay } from "../src/components/filesystem/useAuditReplay";
import { useResponseActionController } from "../src/components/filesystem/ResponseActionController";
import { TopologyCanvas } from "../src/components/filesystem/TopologyCanvas";

// @ts-expect-error React act environment flag
globalThis.IS_REACT_ACT_ENVIRONMENT = true;
MotionGlobalConfig.skipAnimations = true;

vi.mock("server-only", () => ({}));

const session: FilesystemTopologySession = {
  sessionId: "session-a",
  sourceIp: "192.0.2.10",
  cwdState: {
    path: "/",
    status: "confirmed",
    observedAt: "2026-09-19T00:00:00.000Z",
    sourceEventId: null,
  },
  auditSummary: { visitedPaths: ["/"], homeOnly: false, eventCount: 3 },
};

const history: SessionCwdHistoryEvent[] = [
  { id: "event-c", sessionId: "session-a", fromPath: "/b", toPath: "/c", command: "cd /c", action: "change", status: "confirmed", at: "2026-09-19T00:00:10.000Z" },
  { id: "event-b", sessionId: "session-a", fromPath: "/a", toPath: "/b", command: "cd /b", action: "change", status: "confirmed", at: "2026-09-19T00:00:05.000Z" },
  { id: "event-a", sessionId: "session-a", fromPath: "/", toPath: "/a", command: "cd /a", action: "change", status: "confirmed", at: "2026-09-19T00:00:00.000Z" },
];

function jsonResponse(payload: unknown): Response {
  return { ok: true, json: async () => payload } as Response;
}

function ProductionFilesystemCompositionProbe({
  onSelect,
  noise = 0,
}: {
  onSelect?: (id: string | null, source?: "user" | "playback") => void;
  noise?: number;
}) {
  const [activeTab, setActiveTab] = useState<"replay" | "commands" | "actions">("replay");
  const [selectedId, setSelectedId] = useState<string | null>("event-a");
  const replay = useAuditReplay({
    viewMode: "audit",
    history,
    anchoredHop: null,
    historyTotalItems: 3,
    historyTotalSuccessfulItems: 3,
    historyComplete: true,
    selectedHistoryEventId: selectedId,
    initialPacingMode: "uniform",
    onSelectHistoryEventId: (id, source) => {
      if (id) setSelectedId(id);
      onSelect?.(id, source);
    },
  });
  const responseAction = useResponseActionController({
    selectedSession: session,
    sessionIsLive: true,
    enabled: activeTab === "actions",
  });

  const responsePanel = createElement(ResponseActionPanel, {
    selectedSession: session,
    sessionIsLive: true,
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

  return createElement(
    "div",
    { "data-noise": noise },
    createElement(FilesystemTimelinePanel, {
      collapsed: false,
      isDragging: Boolean(noise),
      width: 480 + noise,
      variant: "page",
      selectedSession: session,
      history,
      anchoredHop: null,
      historyStatus: "ready",
      historyCursor: null,
      historyTotalItems: 3,
      historyTotalSuccessfulItems: 3,
      historyComplete: true,
      replay: replay.presentation,
      activeTab,
      onTabChange: setActiveTab,
      responsePanel,
      hopResolutionStatus: "idle",
      requestedHop: null,
      onClearHop: () => {},
      onShowLatestHop: () => {},
      onSelectHistoryEventId: (id) => {
        if (id) setSelectedId(id);
        onSelect?.(id, "user");
      },
      onLoadEarlier: () => {},
    }),
  );
}

describe("FA-012 ownership boundaries", () => {
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

  it("renders the production timeline composition with one required replay presentation model", async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ available: true, action: null }));
    vi.stubGlobal("fetch", fetchMock);

    await act(async () => {
      root.render(createElement(ProductionFilesystemCompositionProbe));
      await Promise.resolve();
    });

    expect(container.querySelector('[aria-label="Replay timeline scrubber"]')).not.toBeNull();
    expect(container.querySelector('[aria-label="Forensic studio views"]')).not.toBeNull();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("keeps response capability request, abort, and reopen lifecycles on the controlled production tab", async () => {
    vi.useFakeTimers();
    let firstSignal: AbortSignal | undefined;
    let resolveFirst: ((value: Response) => void) | undefined;
    const firstResponse = new Promise<Response>((resolve) => {
      resolveFirst = resolve;
    });
    const fetchMock = vi.fn()
      .mockImplementationOnce((_url: string, init?: RequestInit) => {
        firstSignal = init?.signal as AbortSignal | undefined;
        return firstResponse;
      })
      .mockResolvedValue(jsonResponse({ available: true, action: null }));
    vi.stubGlobal("fetch", fetchMock);

    await act(async () => {
      root.render(createElement(ProductionFilesystemCompositionProbe, { noise: 1 }));
      await Promise.resolve();
    });
    expect(fetchMock).not.toHaveBeenCalled();

    await act(async () => {
      (Array.from(container.querySelectorAll("button")).find((button) => button.textContent?.includes("Response")) as HTMLButtonElement).click();
      await Promise.resolve();
    });
    expect(fetchMock).toHaveBeenCalledTimes(1);

    await act(async () => {
      root.render(createElement(ProductionFilesystemCompositionProbe, { noise: 2 }));
      await Promise.resolve();
    });
    expect(fetchMock).toHaveBeenCalledTimes(1);

    await act(async () => {
      (Array.from(container.querySelectorAll("button")).find((button) => button.textContent?.includes("Route Replay")) as HTMLButtonElement).click();
      await Promise.resolve();
    });
    expect(firstSignal?.aborted).toBe(true);

    await act(async () => {
      (Array.from(container.querySelectorAll("button")).find((button) => button.textContent?.includes("Response")) as HTMLButtonElement).click();
      await Promise.resolve();
    });
    expect(fetchMock).toHaveBeenCalledTimes(2);
    resolveFirst?.(jsonResponse({ available: true, action: null }));
  });

  it("advances exactly one autoplay hop after presentational width and rerender changes", async () => {
    vi.useFakeTimers();
    const onSelect = vi.fn();
    await act(async () => {
      root.render(createElement(ProductionFilesystemCompositionProbe, { onSelect }));
      await Promise.resolve();
    });

    await act(async () => {
      (container.querySelector('button[aria-label="Play"]') as HTMLButtonElement).click();
      await Promise.resolve();
    });
    expect(vi.getTimerCount()).toBe(1);

    await act(async () => {
      root.render(createElement(ProductionFilesystemCompositionProbe, { onSelect, noise: 1 }));
      await Promise.resolve();
    });
    await act(async () => {
      await vi.advanceTimersToNextTimerAsync();
      await Promise.resolve();
    });

    expect(onSelect).toHaveBeenCalledTimes(1);
    expect(onSelect).toHaveBeenCalledWith("event-b", "playback");
    expect(vi.getTimerCount()).toBe(1);
  });

  it("renders TopologyCanvas with authoritative freshness and creates no fallback freshness interval", async () => {
    vi.useFakeTimers();
    const freshnessState = {
      classification: "fresh" as const,
      label: "Live",
      detail: "Authoritative telemetry is current.",
      badgeClass: "",
      dotClass: "",
      isDegraded: false,
      isStale: false,
      telemetryAgeMs: 0,
      snapshotReceiptAgeMs: 0,
      retrievalAgeMs: 0,
      telemetryStatus: "valid" as const,
    };
    await act(async () => {
      root.render(createElement(TopologyCanvas, {
        snapshot: {
          nodes: [],
          sessions: [],
          recentClosedSessions: [],
          truncated: false,
          generatedAt: "2026-09-19T00:00:00.000Z",
          latestTelemetryAt: null,
        },
        regionStatus: "ready",
        streamState: "live",
        freshnessState,
        selectedSessionId: null,
        selectedPath: null,
        onSelectSession: () => {},
        onSelectPath: () => {},
        staleThresholdMs: 30_000,
      }));
      await Promise.resolve();
    });

    expect(container.textContent).toContain("No observed working directories yet");
    expect(vi.getTimerCount()).toBe(0);
  });
});
