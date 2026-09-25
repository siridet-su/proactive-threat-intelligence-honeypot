// @vitest-environment happy-dom
import { act, createElement, useState } from "react";
import { createRoot, type Root } from "react-dom/client";
import { MotionGlobalConfig } from "framer-motion";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { FilesystemTopologySession, SessionCwdHistoryEvent } from "../src/lib/dashboardTypes";
import { FilesystemTimelinePanel } from "../src/components/filesystem/FilesystemTimelinePanel";
import { useAuditReplay } from "../src/components/filesystem/useAuditReplay";
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
  { id: "event-c", sessionId: "session-a", fromPath: "/b", toPath: "/c", command: "cd /c", action: "changed", status: "confirmed", at: "2026-09-19T00:00:10.000Z" },
  { id: "event-b", sessionId: "session-a", fromPath: "/a", toPath: "/b", command: "cd /b", action: "changed", status: "confirmed", at: "2026-09-19T00:00:05.000Z" },
  { id: "event-a", sessionId: "session-a", fromPath: "/", toPath: "/a", command: "cd /a", action: "changed", status: "confirmed", at: "2026-09-19T00:00:00.000Z" },
];

function ProductionFilesystemCompositionProbe({
  onSelect,
  noise = 0,
}: {
  onSelect?: (id: string | null, source?: "user" | "playback") => void;
  noise?: number;
}) {
  const [activeTab, setActiveTab] = useState<"replay" | "evidence">("replay");
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
    vi.unstubAllGlobals();
    act(() => root.unmount());
    container.remove();
  });

  it("renders the production timeline composition with one required replay presentation model", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    await act(async () => {
      root.render(createElement(ProductionFilesystemCompositionProbe));
      await Promise.resolve();
    });

    expect(container.querySelector('[aria-label="Replay timeline scrubber"]')).not.toBeNull();
    expect(container.querySelector('[aria-label="Forensic studio views"]')).not.toBeNull();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("FSV-010A renders exactly one stateful AuditFilesystemWorkspace across page and fullscreen shells", () => {
    const source = readFileSync(
      resolve(process.cwd(), "src/components/filesystem/FilesystemActivity.tsx"),
      "utf8",
    );

    expect(source.match(/<AuditFilesystemWorkspace\b/g) ?? []).toHaveLength(1);
    expect(source).toContain("isFullscreen={isAuditFullscreen}");
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
        presentationContext: { mode: "live" },
      }));
      await Promise.resolve();
    });

    expect(container.textContent).toContain("No active honeypot sessions");
    expect(vi.getTimerCount()).toBe(0);
  });

  it("observes rendered nodes and source callouts so connector bounds follow disclosure resizing", async () => {
    const observedElements: Element[] = [];
    class TrackingResizeObserver {
      constructor() {}
      observe(target: Element) { observedElements.push(target); }
      unobserve() {}
      disconnect() {}
    }
    vi.stubGlobal("ResizeObserver", TrackingResizeObserver);
    const sessions: FilesystemTopologySession[] = [
      {
        ...session,
        sessionId: "cluster-one",
        sourceIp: "192.0.2.44",
        cwdState: { ...session.cwdState, path: "/etc" },
      },
      {
        ...session,
        sessionId: "cluster-two",
        sourceIp: "192.0.2.44",
        cwdState: { ...session.cwdState, path: "/tmp" },
      },
    ];

    await act(async () => {
      root.render(createElement(TopologyCanvas, {
        snapshot: {
          nodes: [
            { path: "/", parentPath: null, depth: 0, sessionIds: ["cluster-one", "cluster-two"], observedAt: null },
            { path: "/etc", parentPath: "/", depth: 1, sessionIds: ["cluster-one"], observedAt: null },
            { path: "/tmp", parentPath: "/", depth: 1, sessionIds: ["cluster-two"], observedAt: null },
          ],
          sessions,
          recentClosedSessions: [],
          truncated: false,
          generatedAt: "2026-09-19T00:00:00.000Z",
          latestTelemetryAt: "2026-09-19T00:00:00.000Z",
        },
        regionStatus: "ready",
        streamState: "live",
        freshnessState: {
          classification: "fresh",
          label: "Live",
          detail: "Authoritative telemetry is current.",
          badgeClass: "",
          dotClass: "",
          isDegraded: false,
          isStale: false,
          telemetryAgeMs: 0,
          snapshotReceiptAgeMs: 0,
          retrievalAgeMs: 0,
          telemetryStatus: "valid",
        },
        selectedSessionId: "cluster-one",
        selectedPath: "/etc",
        onSelectSession: () => {},
        onSelectPath: () => {},
        staleThresholdMs: 30_000,
        presentationContext: { mode: "live" },
      }));
      await Promise.resolve();
    });

    expect(observedElements.some((element) => element.matches('button[aria-label^="Inspect directory"]'))).toBe(true);
    expect(observedElements.some((element) => element.querySelector('button[aria-haspopup="listbox"]'))).toBe(true);
  });
});
