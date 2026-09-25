// @vitest-environment happy-dom
import { act, createElement, createRef, useState } from "react";
import { createRoot, type Root } from "react-dom/client";
import { MotionGlobalConfig } from "framer-motion";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type {
  FilesystemTopologySession,
  FilesystemTopologySnapshot,
  SessionCwdHistoryEvent,
} from "../src/lib/dashboardTypes";
import { CwdRouteHistory } from "../src/components/filesystem/CwdRouteHistory";
import { ReplayTransport } from "../src/components/filesystem/ReplayTransport";
import { RouteEventList } from "../src/components/filesystem/RouteEventList";
import { TopologyCanvas } from "../src/components/filesystem/TopologyCanvas";
import * as topologyViewportModule from "../src/components/filesystem/useTopologyViewport";
import {
  buildAuditSnapshot,
  buildReplayTimeline,
  calculateHistoryTimeMetrics,
  deriveActiveHopCanvasSemantics,
  formatFailedChangeMessage,
  getHistoryWindowMetrics,
} from "../src/components/filesystem/filesystemUtils";
import {
  calculateNextHistoryEventId,
  deriveActiveHopRoute,
  filterDisplayedHistory,
  useAuditReplay,
} from "../src/components/filesystem/useAuditReplay";
import { deriveVerifiedCwdTransitions } from "../src/components/filesystem/filesystemTransitions";

// @ts-expect-error React act environment flag
globalThis.IS_REACT_ACT_ENVIRONMENT = true;

vi.mock("server-only", () => ({}));
MotionGlobalConfig.skipAnimations = true;

const HOSTILE_DESTINATION = "/attacker-controlled/unverified-target";
const VERIFIED_ORIGIN = "/etc/nginx";
const VERIFIED_DESTINATION = "/var/log";

function event(
  id: string,
  action: SessionCwdHistoryEvent["action"],
  fromPath: string | null,
  toPath: string | null,
  at = "2026-09-23T10:00:00.000Z",
  overrides: Partial<SessionCwdHistoryEvent> = {},
): SessionCwdHistoryEvent {
  return {
    id,
    sessionId: "session-fsv-005",
    sequence: null,
    sourceEventId: null,
    at,
    fromPath,
    toPath,
    action,
    status: action === "failed_change" ? "conditional_candidate" : "confirmed",
    ...overrides,
  };
}

const failedEvent = event("failed-hop", "failed_change", VERIFIED_ORIGIN, HOSTILE_DESTINATION);
const successfulChangedEvent = event("changed-hop", "changed", VERIFIED_ORIGIN, VERIFIED_DESTINATION);
const successfulAdjacentEvent = event("adjacent-changed-hop", "changed", "/etc", VERIFIED_ORIGIN);
const successfulEnteredEvent = event("entered-hop", "entered", null, "/home/cowrie");

const session: FilesystemTopologySession = {
  sessionId: "session-fsv-005",
  sourceIp: "192.0.2.55",
  cwdState: {
    path: VERIFIED_ORIGIN,
    status: "confirmed",
    observedAt: "2026-09-23T10:00:00.000Z",
    sourceEventId: null,
  },
  auditSummary: {
    visitedPaths: ["/", "/etc", VERIFIED_ORIGIN],
    homeOnly: false,
    eventCount: 1,
  },
};

const snapshot: FilesystemTopologySnapshot = {
  nodes: [
    { path: "/", parentPath: null, depth: 0, sessionIds: [session.sessionId], observedAt: null },
    { path: "/etc", parentPath: "/", depth: 1, sessionIds: [session.sessionId], observedAt: null },
    { path: VERIFIED_ORIGIN, parentPath: "/etc", depth: 2, sessionIds: [session.sessionId], observedAt: null },
    { path: "/var", parentPath: "/", depth: 1, sessionIds: [session.sessionId], observedAt: null },
    { path: VERIFIED_DESTINATION, parentPath: "/var", depth: 2, sessionIds: [session.sessionId], observedAt: null },
  ],
  sessions: [session],
  recentClosedSessions: [],
  truncated: false,
  generatedAt: "2026-09-23T10:00:00.000Z",
  latestTelemetryAt: "2026-09-23T10:00:00.000Z",
};

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

function assertHostileDestinationAbsent(container: HTMLElement): void {
  expect(container.textContent).not.toContain(HOSTILE_DESTINATION);
  expect(container.innerHTML).not.toContain(HOSTILE_DESTINATION);
  for (const element of Array.from(container.querySelectorAll("*"))) {
    for (const attribute of Array.from(element.attributes)) {
      expect(attribute.value).not.toContain(HOSTILE_DESTINATION);
    }
  }
}

function assertNoFailedTargetPresentation(container: HTMLElement): void {
  expect(container.querySelector('[data-testid="active-hop-target-badge"]')).toBeNull();
  expect(container.querySelector('[data-active-hop-connector="true"]')).toBeNull();
  expect(container.querySelector(".pti-hop-energy")).toBeNull();
  expect(container.textContent?.toLowerCase()).not.toMatch(/(?:active|current|failed attempt) hop target/);

  for (const element of Array.from(container.querySelectorAll("*"))) {
    for (const attribute of Array.from(element.attributes)) {
      if (attribute.name === "aria-label" || attribute.name === "aria-description" || attribute.name === "title") {
        expect(attribute.value).not.toMatch(/(?:active|current|failed attempt) hop target/i);
      }
    }
  }
}

function replayTimelineFor(events: SessionCwdHistoryEvent[], selectedIndex = events.length - 1) {
  return buildReplayTimeline(events, selectedIndex, true);
}

function ReplayHistoryHarness({
  history,
  selectedId,
  anchoredHop = null,
  activeTab = "replay",
}: {
  history: SessionCwdHistoryEvent[];
  selectedId: string | null;
  anchoredHop?: SessionCwdHistoryEvent | null;
  activeTab?: "replay" | "evidence";
}) {
  const [currentId, setCurrentId] = useState(selectedId);
  const replay = useAuditReplay({
    viewMode: "audit",
    history,
    anchoredHop,
    historyTotalItems: history.length + (anchoredHop && !history.some((item) => item.id === anchoredHop.id) ? 1 : 0),
    historyTotalSuccessfulItems: history.filter((item) => item.action !== "failed_change").length,
    historyComplete: !anchoredHop,
    selectedHistoryEventId: currentId,
    onSelectHistoryEventId: (id) => setCurrentId(id),
  });

  return createElement(CwdRouteHistory, {
    selectedSession: session,
    history,
    anchoredHop,
    historyStatus: "ready",
    historyCursor: null,
    historyTotalItems: history.length + (anchoredHop && !history.some((item) => item.id === anchoredHop.id) ? 1 : 0),
    historyTotalSuccessfulItems: history.filter((item) => item.action !== "failed_change").length,
    historyComplete: !anchoredHop,
    replay: replay.presentation,
    activeTab,
    onTabChange: () => {},
    onClearHop: () => {},
    onShowLatestHop: () => {},
    onSelectHistoryEventId: (id) => setCurrentId(id),
    onLoadEarlier: () => {},
  });
}

function ActiveHopProbe({
  history,
  selectedId,
  anchoredHop = null,
}: {
  history: SessionCwdHistoryEvent[];
  selectedId: string;
  anchoredHop?: SessionCwdHistoryEvent | null;
}) {
  const replay = useAuditReplay({
    viewMode: "audit",
    history,
    anchoredHop,
    historyTotalItems: history.length + (anchoredHop && !history.some((item) => item.id === anchoredHop.id) ? 1 : 0),
    historyTotalSuccessfulItems: history.filter((item) => item.action !== "failed_change").length,
    historyComplete: !anchoredHop,
    selectedHistoryEventId: selectedId,
    onSelectHistoryEventId: () => {},
  });
  return createElement("pre", null, JSON.stringify(replay.activeHop));
}

describe("FSV-005 failed-change visualization", () => {
  let container: HTMLDivElement;
  let root: Root;

  beforeEach(() => {
    container = document.createElement("div");
    document.body.appendChild(container);
    root = createRoot(container);
  });

  afterEach(() => {
    vi.restoreAllMocks();
    act(() => root.unmount());
    container.remove();
  });

  it("derives a loaded failed hop at its verified origin without a destination", () => {
    const route = deriveActiveHopRoute(
      [failedEvent],
      0,
      getHistoryWindowMetrics(1, 1, 0),
    );

    expect(route).toMatchObject({
      eventId: failedEvent.id,
      fromPath: VERIFIED_ORIGIN,
      toPath: null,
      action: "failed_change",
      status: failedEvent.status,
      at: failedEvent.at,
      stepIndex: 0,
      totalSteps: 1,
      isFailedAttempt: true,
    });
    expect(route?.visitedPaths).not.toContain(HOSTILE_DESTINATION);
    expect(route?.visitedStepMap).not.toHaveProperty(HOSTILE_DESTINATION);
  });

  it("preserves prior verified paths when a later failed hop is selected", () => {
    const history = [
      event("later-failure", "failed_change", VERIFIED_DESTINATION, HOSTILE_DESTINATION, "2026-09-23T10:02:00.000Z"),
      successfulChangedEvent,
    ].reverse();
    const route = deriveActiveHopRoute(history, 1, getHistoryWindowMetrics(2, 2, 1));

    expect(route?.fromPath).toBe(VERIFIED_DESTINATION);
    expect(route?.toPath).toBeNull();
    expect(route?.visitedPaths).toContain(VERIFIED_DESTINATION);
    expect(route?.visitedPaths).not.toContain(HOSTILE_DESTINATION);
    expect(route?.visitedStepMap).not.toHaveProperty(HOSTILE_DESTINATION);
  });

  it("derives an anchored failed hop without materializing its legacy destination", async () => {
    await act(async () => {
      root.render(createElement(ActiveHopProbe, {
        history: [successfulChangedEvent],
        selectedId: failedEvent.id,
        anchoredHop: failedEvent,
      }));
      await Promise.resolve();
    });

    const activeHop = JSON.parse(container.querySelector("pre")?.textContent ?? "null");
    expect(activeHop).toMatchObject({
      eventId: failedEvent.id,
      fromPath: VERIFIED_ORIGIN,
      toPath: null,
      isFailedAttempt: true,
    });
    expect(activeHop.visitedPaths).not.toContain(HOSTILE_DESTINATION);
    expect(activeHop.visitedStepMap).not.toHaveProperty(HOSTILE_DESTINATION);
    assertHostileDestinationAbsent(container);
  });

  it("keeps successful changed and entered route derivation intact", () => {
    const changed = deriveActiveHopRoute(
      [successfulChangedEvent],
      0,
      getHistoryWindowMetrics(1, 1, 0),
    );
    const entered = deriveActiveHopRoute(
      [successfulEnteredEvent],
      0,
      getHistoryWindowMetrics(1, 1, 0),
    );

    expect(changed).toMatchObject({ fromPath: VERIFIED_ORIGIN, toPath: VERIFIED_DESTINATION, isFailedAttempt: false });
    expect(entered).toMatchObject({ fromPath: null, toPath: "/home/cowrie", action: "entered", isFailedAttempt: false });
  });

  it("separates failed replay context from target, layout, and camera semantics", () => {
    const failedRoute = deriveActiveHopRoute([failedEvent], 0, getHistoryWindowMetrics(1, 1, 0));
    const changedRoute = deriveActiveHopRoute([successfulChangedEvent], 0, getHistoryWindowMetrics(1, 1, 0));

    expect(deriveActiveHopCanvasSemantics(failedRoute)).toEqual({
      replayContextPath: VERIFIED_ORIGIN,
      verifiedTargetPath: null,
      layoutFocusPath: null,
      autoCenterPath: null,
      failedAnnotationPath: VERIFIED_ORIGIN,
    });
    expect(deriveActiveHopCanvasSemantics(changedRoute)).toEqual({
      replayContextPath: VERIFIED_DESTINATION,
      verifiedTargetPath: VERIFIED_DESTINATION,
      layoutFocusPath: VERIFIED_DESTINATION,
      autoCenterPath: VERIFIED_DESTINATION,
      failedAnnotationPath: null,
    });
  });

  it("uses the truthful unknown-origin fallback without exposing a destination", () => {
    expect(formatFailedChangeMessage(null)).toBe(
      "Directory change failed while at an unknown verified origin; attempted destination unavailable or unverified",
    );
    expect(formatFailedChangeMessage("  ")).toBe(
      "Directory change failed while at an unknown verified origin; attempted destination unavailable or unverified",
    );
  });

  it("reprocesses a successful hop after a failed hop transition", async () => {
    const originalUseTopologyViewport = topologyViewportModule.useTopologyViewport;
    const centerMapOn = vi.fn();
    vi.spyOn(topologyViewportModule, "useTopologyViewport").mockImplementation((options) => ({
      ...originalUseTopologyViewport(options),
      centerMapOn,
    }));

    const successRoute = deriveActiveHopRoute(
      [successfulChangedEvent],
      0,
      getHistoryWindowMetrics(1, 1, 0),
    );
    const failedRoute = deriveActiveHopRoute(
      [failedEvent],
      0,
      getHistoryWindowMetrics(1, 1, 0),
    );

    await act(async () => {
      root.render(createElement(TopologyCanvas, {
        snapshot,
        regionStatus: "ready",
        streamState: "live",
        freshnessState,
        selectedSessionId: session.sessionId,
        selectedPath: null,
        activeHop: successRoute,
        onSelectSession: () => {},
        onSelectPath: () => {},
        staleThresholdMs: 30_000,
        presentationContext: { mode: "live" },
      }));
      await Promise.resolve();
    });
    const centeredForInitialSuccess = centerMapOn.mock.calls.length;
    expect(centeredForInitialSuccess).toBeGreaterThan(0);

    await act(async () => {
      root.render(createElement(TopologyCanvas, {
        snapshot,
        regionStatus: "ready",
        streamState: "live",
        freshnessState,
        selectedSessionId: session.sessionId,
        selectedPath: null,
        activeHop: failedRoute,
        onSelectSession: () => {},
        onSelectPath: () => {},
        staleThresholdMs: 30_000,
        presentationContext: { mode: "live" },
      }));
      await Promise.resolve();
    });
    expect(centerMapOn).toHaveBeenCalledTimes(centeredForInitialSuccess);

    await act(async () => {
      root.render(createElement(TopologyCanvas, {
        snapshot,
        regionStatus: "ready",
        streamState: "live",
        freshnessState,
        selectedSessionId: session.sessionId,
        selectedPath: null,
        activeHop: successRoute,
        onSelectSession: () => {},
        onSelectPath: () => {},
        staleThresholdMs: 30_000,
        presentationContext: { mode: "live" },
      }));
      await Promise.resolve();
    });
    expect(centerMapOn).toHaveBeenCalledTimes(centeredForInitialSuccess + 1);

    await act(async () => {
      root.render(createElement(TopologyCanvas, {
        snapshot,
        regionStatus: "ready",
        streamState: "live",
        freshnessState,
        selectedSessionId: session.sessionId,
        selectedPath: null,
        activeHop: successRoute,
        onSelectSession: () => {},
        onSelectPath: () => {},
        staleThresholdMs: 30_000,
        presentationContext: { mode: "live" },
      }));
      await Promise.resolve();
    });
    expect(centerMapOn).toHaveBeenCalledTimes(centeredForInitialSuccess + 1);
  });

  it("keeps failed events displayed and selectable by event ID", async () => {
    const selected = vi.fn();
    const timeline = replayTimelineFor([failedEvent]);
    await act(async () => {
      root.render(createElement(RouteEventList, {
        historyComplete: true,
        historyCursor: null,
        historyStatus: "ready",
        historyLength: 1,
        historyTotalItems: 1,
        replayTimeline: timeline,
        onLoadEarlier: () => {},
        timelineContainerRef: createRef<HTMLDivElement>(),
        isSidebar: false,
        displayedHistory: [failedEvent],
        activeHistoryEventId: failedEvent.id,
        timeMetrics: { hopMetrics: timeline.hopMetrics },
        activeItemRef: createRef<HTMLButtonElement>(),
        handlePause: () => {},
        onSelectHistoryEventId: selected,
        displayedHistoryMetrics: { indexOffset: 0 },
        anchoredHop: null,
        isAnchoredSelected: false,
        showFailedAttempts: true,
      }));
      await Promise.resolve();
    });

    expect(container.textContent).toContain("Directory change failed");
    (container.querySelector("button") as HTMLButtonElement).click();
    expect(selected).toHaveBeenCalledWith(failedEvent.id);
  });

  it("crosses a failed event with previous and next navigation while filtering only when disabled", () => {
    const history = [successfulChangedEvent, failedEvent, successfulEnteredEvent];
    expect(filterDisplayedHistory(history, true).map((item) => item.id)).toEqual([
      successfulChangedEvent.id,
      failedEvent.id,
      successfulEnteredEvent.id,
    ]);
    expect(filterDisplayedHistory(history, false).map((item) => item.id)).toEqual([
      successfulChangedEvent.id,
      successfulEnteredEvent.id,
    ]);
    expect(calculateNextHistoryEventId(history, 0, "next")).toBe(failedEvent.id);
    expect(calculateNextHistoryEventId(history, 1, "prev")).toBe(successfulChangedEvent.id);
    expect(calculateNextHistoryEventId(history, 1, "next")).toBe(successfulEnteredEvent.id);
  });

  it("renders the normal failed timeline card with origin-only failure wording", async () => {
    await act(async () => {
      root.render(createElement(RouteEventList, {
        historyComplete: true,
        historyCursor: null,
        historyStatus: "ready",
        historyLength: 1,
        historyTotalItems: 1,
        replayTimeline: replayTimelineFor([failedEvent]),
        onLoadEarlier: () => {},
        timelineContainerRef: createRef<HTMLDivElement>(),
        isSidebar: false,
        displayedHistory: [failedEvent],
        activeHistoryEventId: failedEvent.id,
        timeMetrics: { hopMetrics: replayTimelineFor([failedEvent]).hopMetrics },
        activeItemRef: createRef<HTMLButtonElement>(),
        handlePause: () => {},
        onSelectHistoryEventId: () => {},
        displayedHistoryMetrics: { indexOffset: 0 },
        anchoredHop: null,
        isAnchoredSelected: false,
        showFailedAttempts: true,
      }));
      await Promise.resolve();
    });

    expect(container.textContent).toContain(
      `Directory change failed while at ${VERIFIED_ORIGIN}; attempted destination unavailable or unverified`,
    );
    expect(container.textContent).toContain("Failed");
    expect(container.querySelector("svg")).not.toBeNull();
    assertHostileDestinationAbsent(container);
  });

  it("renders an anchored failed card with the same origin-only failure wording", async () => {
    await act(async () => {
      root.render(createElement(RouteEventList, {
        historyComplete: false,
        historyCursor: "older",
        historyStatus: "ready",
        historyLength: 1,
        historyTotalItems: 2,
        replayTimeline: replayTimelineFor([successfulChangedEvent]),
        onLoadEarlier: () => {},
        timelineContainerRef: createRef<HTMLDivElement>(),
        isSidebar: false,
        displayedHistory: [successfulChangedEvent],
        activeHistoryEventId: failedEvent.id,
        timeMetrics: { hopMetrics: replayTimelineFor([successfulChangedEvent]).hopMetrics },
        activeItemRef: createRef<HTMLButtonElement>(),
        handlePause: () => {},
        onSelectHistoryEventId: () => {},
        displayedHistoryMetrics: { indexOffset: 0 },
        anchoredHop: failedEvent,
        isAnchoredSelected: true,
        showFailedAttempts: true,
      }));
      await Promise.resolve();
    });

    expect(container.textContent).toContain(
      `Directory change failed while at ${VERIFIED_ORIGIN}; attempted destination unavailable or unverified`,
    );
    expect(container.textContent).toContain("Anchored");
    assertHostileDestinationAbsent(container);
  });

  it("renders the failed replay transport without a destination", async () => {
    const timeline = replayTimelineFor([failedEvent]);
    await act(async () => {
      root.render(createElement(ReplayTransport, {
        isAnchoredSelected: false,
        historyComplete: true,
        onLoadEarlier: () => {},
        selectedHistoryIndex: 0,
        displayedHistoryLength: 1,
        selectDisplayedHistoryIndex: () => {},
        handleTogglePlay: () => {},
        isPlaying: false,
        onToggleSpeed: () => {},
        playbackSpeed: 1400,
        onTogglePacingMode: () => {},
        pacingMode: "realistic",
        failedCount: 1,
        showFailedAttempts: true,
        onToggleShowFailedAttempts: () => {},
        displayedHistoryMetrics: { selectedNumber: 1, totalItems: 1 },
        timeMetrics: { summary: timeline.summary },
        replayTimeline: timeline,
        handleScrubberKeyDown: () => {},
        isFailedHop: true,
        selectedHistoryEvent: failedEvent,
      }));
      await Promise.resolve();
    });

    expect(container.textContent).toContain(
      `Directory change failed while at ${VERIFIED_ORIGIN}; attempted destination unavailable or unverified`,
    );
    expect(container.textContent).toContain("Failed");
    expect(container.querySelector("svg")).not.toBeNull();
    assertHostileDestinationAbsent(container);
  });

  it("uses the verified origin as selected CWD context in the Evidence tab", async () => {
    await act(async () => {
      root.render(createElement(ReplayHistoryHarness, {
        history: [failedEvent],
        selectedId: failedEvent.id,
        activeTab: "evidence",
      }));
      await Promise.resolve();
    });

    expect(container.textContent).toContain("Selected CWD context");
    expect(container.textContent).toContain(VERIFIED_ORIGIN);
    expect(container.textContent).toContain("attempted destination unavailable or unverified");
    assertHostileDestinationAbsent(container);
  });

  it("omits the duplicated failure explanation from the topology canvas", async () => {
    const failedRoute = deriveActiveHopRoute([failedEvent], 0, getHistoryWindowMetrics(1, 1, 0));
    await act(async () => {
      root.render(createElement(TopologyCanvas, {
        snapshot,
        regionStatus: "ready",
        streamState: "live",
        freshnessState,
        selectedSessionId: session.sessionId,
        selectedPath: null,
        activeHop: failedRoute,
        onSelectSession: () => {},
        onSelectPath: () => {},
        staleThresholdMs: 30_000,
        presentationContext: { mode: "live" },
      }));
      await Promise.resolve();
    });

    expect(container.querySelector('[data-testid="failed-change-annotation"]')).toBeNull();
    expect(container.querySelector('[data-testid="failed-change-canvas-status"]')).toBeNull();
    assertNoFailedTargetPresentation(container);
    assertHostileDestinationAbsent(container);
  });

  it("keeps the real target badge and adjacent connector for a successful hop", async () => {
    const successfulRoute = deriveActiveHopRoute(
      [successfulAdjacentEvent],
      0,
      getHistoryWindowMetrics(1, 1, 0),
    );
    const successfulTransitions = deriveVerifiedCwdTransitions([successfulAdjacentEvent], 1);
    await act(async () => {
      root.render(createElement(TopologyCanvas, {
        snapshot,
        regionStatus: "ready",
        streamState: "live",
        freshnessState,
        selectedSessionId: session.sessionId,
        selectedPath: null,
        activeHop: successfulRoute,
        displayedTransitions: successfulTransitions,
        currentTransition: successfulTransitions[0],
        onSelectSession: () => {},
        onSelectPath: () => {},
        staleThresholdMs: 30_000,
        presentationContext: { mode: "live" },
      }));
      await Promise.resolve();
    });

    expect(container.querySelector('[data-testid="active-hop-target-badge"]')).not.toBeNull();
    expect(container.querySelector('[data-transition-event-id="adjacent-changed-hop"][data-transition-kind="directed"]')).not.toBeNull();
    expect(container.querySelector('[data-edge-kind="hierarchy"][marker-end]')).toBeNull();
  });

  it("does not add a canvas warning when the failed origin is outside a partial graph", async () => {
    const failedRoute = deriveActiveHopRoute(
      [event("missing-origin", "failed_change", "/missing/origin", HOSTILE_DESTINATION)],
      0,
      getHistoryWindowMetrics(1, 1, 0),
    );
    await act(async () => {
      root.render(createElement(TopologyCanvas, {
        snapshot: { ...snapshot, sessions: [], nodes: snapshot.nodes.filter((node) => node.path !== VERIFIED_ORIGIN) },
        regionStatus: "ready",
        streamState: "live",
        freshnessState,
        selectedSessionId: null,
        selectedPath: null,
        activeHop: failedRoute,
        onSelectSession: () => {},
        onSelectPath: () => {},
        staleThresholdMs: 30_000,
        presentationContext: { mode: "live" },
      }));
      await Promise.resolve();
    });

    expect(container.querySelector('[data-testid="failed-change-canvas-status"]')).toBeNull();
    expect(container.querySelector('[data-testid="failed-change-annotation"]')).toBeNull();
    assertHostileDestinationAbsent(container);
  });

  it("preserves successful timeline and transport destination presentation", async () => {
    const timeline = replayTimelineFor([successfulChangedEvent]);
    await act(async () => {
      root.render(createElement("div", null,
        createElement(ReplayTransport, {
          isAnchoredSelected: false,
          historyComplete: true,
          onLoadEarlier: () => {},
          selectedHistoryIndex: 0,
          displayedHistoryLength: 1,
          selectDisplayedHistoryIndex: () => {},
          handleTogglePlay: () => {},
          isPlaying: false,
          onToggleSpeed: () => {},
          playbackSpeed: 1400,
          onTogglePacingMode: () => {},
          pacingMode: "realistic",
          failedCount: 0,
          showFailedAttempts: true,
          onToggleShowFailedAttempts: () => {},
          displayedHistoryMetrics: { selectedNumber: 1, totalItems: 1 },
          timeMetrics: { summary: timeline.summary },
          replayTimeline: timeline,
          handleScrubberKeyDown: () => {},
          isFailedHop: false,
          selectedHistoryEvent: successfulChangedEvent,
        }),
        createElement(RouteEventList, {
          historyComplete: true,
          historyCursor: null,
          historyStatus: "ready",
          historyLength: 1,
          historyTotalItems: 1,
          replayTimeline: timeline,
          onLoadEarlier: () => {},
          timelineContainerRef: createRef<HTMLDivElement>(),
          isSidebar: false,
          displayedHistory: [successfulChangedEvent],
          activeHistoryEventId: successfulChangedEvent.id,
          timeMetrics: { hopMetrics: timeline.hopMetrics },
          activeItemRef: createRef<HTMLButtonElement>(),
          handlePause: () => {},
          onSelectHistoryEventId: () => {},
          displayedHistoryMetrics: { indexOffset: 0 },
          anchoredHop: null,
          isAnchoredSelected: false,
          showFailedAttempts: true,
        }),
      ));
      await Promise.resolve();
    });

    expect(container.textContent).toContain(VERIFIED_DESTINATION);
    expect(container.textContent).toContain("to");
  });

  it("keeps failed snapshot destinations and ancestors out of materialized topology", () => {
    const auditSnapshot = buildAuditSnapshot(null, session, [failedEvent]);
    const paths = auditSnapshot.nodes.map((node) => node.path);

    expect(paths).toContain(VERIFIED_ORIGIN);
    expect(paths).not.toContain(HOSTILE_DESTINATION);
    expect(paths).not.toContain("/attacker-controlled");
    expect(auditSnapshot.nodes.some((node) => node.path === HOSTILE_DESTINATION)).toBe(false);
    expect(auditSnapshot.nodes.some((node) => node.parentPath === HOSTILE_DESTINATION)).toBe(false);
  });

  it("keeps failed hop numbering, event identity, timestamps, and dwell metrics intact", () => {
    const history = [successfulChangedEvent, failedEvent];
    const metrics = getHistoryWindowMetrics(history.length, history.length, 1, 2);
    const route = deriveActiveHopRoute(history, 1, metrics);
    const time = calculateHistoryTimeMetrics(history, 1);

    expect(route).toMatchObject({
      eventId: failedEvent.id,
      at: failedEvent.at,
      stepIndex: 1,
      totalSteps: 2,
    });
    expect(time.hopMetrics).toHaveLength(2);
    expect(time.hopMetrics[1].formattedDelta).toBe("0s");
  });
});
