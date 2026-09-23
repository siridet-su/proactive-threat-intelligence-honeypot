// @vitest-environment happy-dom
import { act, createElement } from "react";
import { createRoot, type Root } from "react-dom/client";
import { MotionGlobalConfig } from "framer-motion";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { FilesystemTopologySnapshot, SessionCwdHistoryEvent } from "../src/lib/dashboardTypes";
import { TopologyCanvas } from "../src/components/filesystem/TopologyCanvas";
import {
  TransitionOverlay,
  deriveDirectedTransitionGeometry,
  planTransitionOverlayRoutes,
  deriveTransitionOverlayItems,
} from "../src/components/filesystem/TransitionOverlay";
import { deriveVerifiedCwdTransitions } from "../src/components/filesystem/filesystemTransitions";
import type { GraphNode } from "../src/components/filesystem/filesystemUtils";

// @ts-expect-error React act environment flag
globalThis.IS_REACT_ACT_ENVIRONMENT = true;

vi.mock("server-only", () => ({}));
MotionGlobalConfig.skipAnimations = true;

function cwdEvent(
  id: string,
  action: SessionCwdHistoryEvent["action"],
  fromPath: string | null,
  toPath: string | null,
): SessionCwdHistoryEvent {
  return {
    id,
    sessionId: "session-transition-overlay",
    sequence: null,
    sourceEventId: null,
    at: `2026-09-23T10:00:0${id.length}.000Z`,
    fromPath,
    toPath,
    action,
    status: action === "failed_change" ? "conditional_candidate" : "confirmed",
  };
}

const events = [
  cwdEvent("entry", "entered", null, "/home/a"),
  cwdEvent("cross-one", "changed", "/home/a", "/tmp"),
  cwdEvent("cross-two", "changed", "/home/a", "/tmp"),
  cwdEvent("reverse", "changed", "/tmp", "/home/a"),
  cwdEvent("self", "changed", "/tmp", "/tmp"),
  cwdEvent("failed", "failed_change", "/tmp", "/hostile/unverified"),
] satisfies SessionCwdHistoryEvent[];

const transitions = deriveVerifiedCwdTransitions(events, events.length);

const nodes: GraphNode[] = [
  { path: "/", parentPath: null, depth: 0, sessionIds: ["session-transition-overlay"], observedAt: null, x: 50, y: 10 },
  { path: "/home", parentPath: "/", depth: 1, sessionIds: ["session-transition-overlay"], observedAt: null, x: 28, y: 35 },
  { path: "/home/a", parentPath: "/home", depth: 2, sessionIds: ["session-transition-overlay"], observedAt: null, x: 22, y: 68 },
  { path: "/tmp", parentPath: "/", depth: 1, sessionIds: ["session-transition-overlay"], observedAt: null, x: 76, y: 55 },
];

describe("FSV-007B: separate verified transition overlay", () => {
  let container: HTMLDivElement;
  let root: Root;

  beforeEach(() => {
    container = document.createElement("div");
    document.body.appendChild(container);
    root = createRoot(container);
  });

  afterEach(async () => {
    await act(async () => root.unmount());
    container.remove();
    vi.restoreAllMocks();
  });

  it.each([
    {
      name: "horizontal",
      from: { x: 20, y: 30, width: 20, height: 10 },
      to: { x: 80, y: 30, width: 12, height: 8 },
    },
    {
      name: "vertical",
      from: { x: 45, y: 20, width: 16, height: 8 },
      to: { x: 45, y: 80, width: 18, height: 12 },
    },
    {
      name: "diagonal",
      from: { x: 18, y: 22, width: 14, height: 9 },
      to: { x: 76, y: 73, width: 20, height: 11 },
    },
  ])("anchors $name transition endpoints on the rendered node borders", ({ from, to }) => {
    const transition = deriveVerifiedCwdTransitions([
      cwdEvent(`border-${from.x}`, "changed", "/from", "/to"),
    ], 1)[0];
    const geometry = deriveDirectedTransitionGeometry(
      transition,
      new Map([
        ["/from", { path: "/from", parentPath: "/", depth: 1, sessionIds: [], observedAt: null, x: from.x, y: from.y }],
        ["/to", { path: "/to", parentPath: "/", depth: 1, sessionIds: [], observedAt: null, x: to.x, y: to.y }],
      ]),
      { "/from": from, "/to": to },
      0,
    );

    expect(geometry).not.toBeNull();
    const onBorder = (
      point: { x: number; y: number },
      bounds: { x: number; y: number; width: number; height: number },
    ) => {
      const relativeX = Math.abs(point.x - bounds.x);
      const relativeY = Math.abs(point.y - bounds.y);
      const halfWidth = bounds.width / 2;
      const halfHeight = bounds.height / 2;
      return (
        (Math.abs(relativeX - halfWidth) < 0.0001 && relativeY <= halfHeight + 0.0001) ||
        (Math.abs(relativeY - halfHeight) < 0.0001 && relativeX <= halfWidth + 0.0001)
      );
    };
    expect(onBorder({ x: geometry!.startX, y: geometry!.startY }, from)).toBe(true);
    expect(onBorder({ x: geometry!.targetX, y: geometry!.targetY }, to)).toBe(true);
  });

  it("classifies previous, current, and future events without deduplicating revisits", () => {
    const items = deriveTransitionOverlayItems(transitions, transitions[2]);

    expect(items.map((item) => [item.transition.eventId, item.state])).toEqual([
      ["entry", "previous"],
      ["cross-one", "previous"],
      ["cross-two", "current"],
      ["reverse", "future"],
      ["self", "future"],
      ["failed", "future"],
    ]);
    expect(items.filter((item) => item.transition.fromPath === "/home/a" && item.transition.toPath === "/tmp")).toHaveLength(2);
  });

  it("plans repeated and reverse transitions on distinct node ports with collision-free labels", () => {
    const items = deriveTransitionOverlayItems(transitions, transitions[2]);
    const plans = planTransitionOverlayRoutes(
      items,
      new Map(nodes.map((node) => [node.path, node])),
      {
        "/home/a": { x: 22, y: 68, width: 14, height: 8 },
        "/tmp": { x: 76, y: 55, width: 12, height: 8 },
      },
    ).filter((plan) => plan.geometry !== null);

    const repeated = plans.filter((plan) => plan.item.transition.fromPath === "/home/a");
    const reverse = plans.find((plan) => plan.item.transition.eventId === "reverse");
    expect(repeated).toHaveLength(2);
    expect(reverse?.geometry).not.toBeNull();
    expect(repeated[0].geometry?.startY).not.toBe(repeated[1].geometry?.startY);

    const forwardSide = Math.sign((repeated[0].geometry?.controlY ?? 0) - 61.5);
    const reverseSide = Math.sign((reverse?.geometry?.controlY ?? 0) - 61.5);
    expect(forwardSide).toBe(-reverseSide);
    const curveMidpoint = (geometry: NonNullable<(typeof plans)[number]["geometry"]>) => ({
      x: (geometry.startX + 2 * geometry.controlX + geometry.targetX) / 4,
      y: (geometry.startY + 2 * geometry.controlY + geometry.targetY) / 4,
    });
    const forwardMidpoint = curveMidpoint(repeated[0].geometry!);
    const reverseMidpoint = curveMidpoint(reverse!.geometry!);
    expect(Math.hypot(
      forwardMidpoint.x - reverseMidpoint.x,
      forwardMidpoint.y - reverseMidpoint.y,
    )).toBeGreaterThanOrEqual(8);
    expect(Math.hypot(
      repeated[0].geometry!.targetX - reverse!.geometry!.startX,
      repeated[0].geometry!.targetY - reverse!.geometry!.startY,
    )).toBeGreaterThanOrEqual(3);

    const labels = plans.map((plan) => plan.geometry!).map((geometry) => ({
      left: geometry.labelX - 2.25,
      right: geometry.labelX + 2.25,
      top: geometry.labelY - 1.7,
      bottom: geometry.labelY + 1.7,
    }));
    for (let index = 0; index < labels.length; index += 1) {
      for (let otherIndex = index + 1; otherIndex < labels.length; otherIndex += 1) {
        const a = labels[index];
        const b = labels[otherIndex];
        const overlaps = a.left < b.right && a.right > b.left && a.top < b.bottom && a.bottom > b.top;
        expect(overlaps).toBe(false);
      }
    }
  });

  it("routes a transition around an unrelated node occupying the direct corridor", () => {
    const transition = deriveVerifiedCwdTransitions([
      cwdEvent("obstacle-route", "changed", "/from", "/to"),
    ], 1)[0];
    const routeNodes: GraphNode[] = [
      { path: "/from", parentPath: "/", depth: 1, sessionIds: [], observedAt: null, x: 20, y: 50 },
      { path: "/obstacle", parentPath: "/", depth: 1, sessionIds: [], observedAt: null, x: 50, y: 50 },
      { path: "/to", parentPath: "/", depth: 1, sessionIds: [], observedAt: null, x: 80, y: 50 },
    ];
    const plan = planTransitionOverlayRoutes(
      [{ transition, state: "current", isAnchored: false }],
      new Map(routeNodes.map((node) => [node.path, node])),
      {
        "/from": { x: 20, y: 50, width: 12, height: 8 },
        "/obstacle": { x: 50, y: 50, width: 16, height: 10 },
        "/to": { x: 80, y: 50, width: 12, height: 8 },
      },
    )[0];

    expect(plan.geometry).not.toBeNull();
    expect(Math.abs((plan.geometry?.controlY ?? 50) - 50)).toBeGreaterThan(7);
    expect(
      (plan.geometry?.labelY ?? 50) < 43.3 || (plan.geometry?.labelY ?? 50) > 56.7,
    ).toBe(true);
  });

  it("adds an anchored current event without mutating or appending it to the displayed input", () => {
    const anchored = { ...transitions[1], eventId: "anchored", absoluteHop: 20 };
    const original = [...transitions];
    const items = deriveTransitionOverlayItems(transitions, anchored);

    expect(transitions).toEqual(original);
    expect(items).toHaveLength(transitions.length + 1);
    expect(items.at(-1)).toMatchObject({ state: "current", isAnchored: true });
  });

  it("discloses an anchored unloaded gap without inferring intermediate transitions", async () => {
    const anchored = { ...transitions[1], eventId: "anchored", absoluteHop: 20 };
    await act(async () => {
      root.render(createElement(TransitionOverlay, {
        transitions: transitions.slice(0, 2),
        currentTransition: anchored,
        nodes,
        reducedMotion: true,
        durationMs: 1400,
      }));
    });

    const gap = container.querySelector('[data-testid="transition-unloaded-gap"]');
    expect(gap?.textContent).toContain("Unloaded history gap");
    expect(gap?.getAttribute("data-gap-rendering")).toBe("explicit-not-inferred");
    expect(container.querySelectorAll('[data-transition-event-id="anchored"]')).not.toHaveLength(0);
    expect(container.querySelectorAll('[data-anchored-transition="true"]')).not.toHaveLength(0);
  });

  it("draws non-parent, repeated, reverse, and self transitions as distinct directed events", async () => {
    await act(async () => {
      root.render(createElement(TransitionOverlay, {
        transitions,
        currentTransition: transitions[2],
        nodes,
        reducedMotion: false,
        durationMs: 1400,
        displayMode: "all",
      }));
    });

    const directed = container.querySelectorAll('[data-transition-kind="directed"]');
    expect(directed).toHaveLength(4);
    expect(container.querySelectorAll('[data-transition-route="/home/a→/tmp"]')).toHaveLength(2);
    expect(container.querySelector('[data-transition-event-id="reverse"][data-transition-route="/tmp→/home/a"]')).not.toBeNull();
    expect(container.querySelector('[data-transition-event-id="cross-two"]')?.getAttribute("marker-end")).toBeNull();
    expect(container.querySelector('[data-transition-event-id="reverse"]')?.getAttribute("marker-end")).toContain("future-transition-arrow");
    expect(container.querySelector('[data-transition-event-id="self"][data-transition-self-loop="true"]')).not.toBeNull();
    expect(container.querySelectorAll('[data-transition-hop-label]')).toHaveLength(events.length);
  });

  it("renders entry and failed-origin markers without inventing a failed destination edge", async () => {
    await act(async () => {
      root.render(createElement(TransitionOverlay, {
        transitions,
        currentTransition: transitions[5],
        nodes,
        reducedMotion: false,
        durationMs: 1400,
        displayMode: "all",
      }));
    });

    expect(container.querySelector('[data-transition-kind="entry"][data-transition-marker-path="/home/a"]')).not.toBeNull();
    expect(container.querySelector('[data-transition-kind="failed-origin"][data-transition-marker-path="/tmp"]')).not.toBeNull();
    expect(container.querySelector('[data-transition-event-id="failed"][data-transition-kind="directed"]')).toBeNull();
    expect(container.innerHTML).not.toContain("/hostile/unverified");
  });

  it("defaults to one focused hop while retaining the complete accessible sequence", async () => {
    await act(async () => {
      root.render(createElement(TransitionOverlay, {
        transitions,
        currentTransition: transitions[2],
        nodes,
        nodeBounds: {
          "/home/a": { x: 22, y: 68, width: 14, height: 8 },
          "/tmp": { x: 76, y: 55, width: 12, height: 8 },
        },
        reducedMotion: false,
        durationMs: 1400,
      }));
    });

    expect(container.querySelectorAll('[data-transition-kind="directed"]')).toHaveLength(1);
    const focusedTransition = container.querySelector('[data-transition-event-id="cross-two"][data-transition-state="current"]');
    expect(focusedTransition).not.toBeNull();
    expect(focusedTransition?.getAttribute("marker-end")).toBeNull();
    expect(container.querySelector('[data-transition-event-id="cross-one"]')).toBeNull();
    expect(container.querySelector('[data-transition-event-id="reverse"]')).toBeNull();
    expect(container.querySelectorAll('[data-transition-hop-label]')).toHaveLength(0);
    expect(container.querySelectorAll(".pti-hop-packet")).toHaveLength(6);
    expect(container.querySelector('[data-testid="transition-impact-wave"]')).not.toBeNull();
    expect(container.querySelector('[aria-label="Verified CWD transition sequence"]')?.querySelectorAll("li")).toHaveLength(events.length);
  });

  it("offers an arrowless previous-hop trail without showing future transitions", async () => {
    await act(async () => {
      root.render(createElement(TransitionOverlay, {
        transitions,
        currentTransition: transitions[2],
        nodes,
        reducedMotion: false,
        durationMs: 1400,
        displayMode: "trail",
      }));
    });

    expect(container.querySelector('[data-transition-event-id="entry"][data-transition-state="previous"]')).not.toBeNull();
    const previous = container.querySelector('[data-transition-event-id="cross-one"][data-transition-state="previous"]');
    expect(previous).not.toBeNull();
    expect(previous?.getAttribute("marker-end")).toBeNull();
    expect(previous?.getAttribute("data-transition-trail")).toBe("true");
    expect(container.querySelector('[data-transition-event-id="reverse"]')).toBeNull();
    expect(container.querySelectorAll('[data-transition-hop-label]')).toHaveLength(0);
  });

  it("keeps static current state but removes travel and pulse under reduced motion", async () => {
    await act(async () => {
      root.render(createElement(TransitionOverlay, {
        transitions,
        currentTransition: transitions[2],
        nodes,
        reducedMotion: true,
        durationMs: 1400,
      }));
    });

    expect(container.querySelector('[data-transition-event-id="cross-two"][data-transition-state="current"]')).not.toBeNull();
    expect(container.querySelector('[data-transition-event-id="cross-two"]')?.getAttribute("marker-end")).toBeNull();
    expect(container.querySelector('[data-testid="current-transition-indicator"]')).not.toBeNull();
    expect(container.querySelector('[data-testid="transition-travel-packet"]')).toBeNull();
    expect(container.querySelector('[data-testid="transition-current-pulse"]')).toBeNull();
    expect(container.querySelector('[data-testid="transition-impact-wave"]')).toBeNull();
  });

  it("paints the current endpoint indicator behind the transition arrowhead", async () => {
    await act(async () => {
      root.render(createElement(TransitionOverlay, {
        transitions,
        currentTransition: transitions[2],
        nodes,
        reducedMotion: false,
        durationMs: 1400,
        displayMode: "all",
      }));
    });

    const currentPath = container.querySelector('[data-transition-event-id="cross-two"][data-transition-kind="directed"]');
    const indicator = container.querySelector('[data-testid="current-transition-indicator"]');
    const pulse = container.querySelector('[data-testid="transition-current-pulse"]');
    expect(currentPath).not.toBeNull();
    expect(indicator).not.toBeNull();
    expect(pulse).not.toBeNull();
    expect(indicator!.compareDocumentPosition(currentPath!) & Node.DOCUMENT_POSITION_FOLLOWING).not.toBe(0);
  });

  it("exposes a legend and chronological accessible sequence that match every rendered state", async () => {
    await act(async () => {
      root.render(createElement(TransitionOverlay, {
        transitions,
        currentTransition: transitions[2],
        nodes,
        reducedMotion: false,
        durationMs: 1400,
        displayMode: "all",
      }));
    });

    const legend = container.querySelector('[aria-label="Topology and transition legend"]');
    expect(legend?.textContent).toContain("Filesystem hierarchy");
    expect(legend?.textContent).toContain("Previous trail");
    expect(legend?.textContent).toContain("Current hop");
    expect(legend?.textContent).toContain("Future transition");
    expect(legend?.textContent).toContain("Entry marker");
    expect(legend?.textContent).toContain("Failed at origin");

    const sequence = container.querySelector('[aria-label="Verified CWD transition sequence"]');
    expect(sequence?.querySelectorAll("li")).toHaveLength(events.length);
    expect(sequence?.textContent).toContain("Hop 2: previous transition from /home/a to /tmp");
    expect(sequence?.textContent).toContain("Hop 3: current transition from /home/a to /tmp");
    expect(sequence?.textContent).toContain("Hop 6: future failed change at origin /tmp; destination unavailable or unverified");
  });

  it("keeps hierarchy paths thin, neutral, solid, and arrowless while the overlay owns transition styling", async () => {
    const session = {
      sessionId: "session-transition-overlay",
      sourceIp: "192.0.2.70",
      cwdState: {
        path: "/tmp",
        status: "confirmed" as const,
        observedAt: "2026-09-23T10:00:09.000Z",
        sourceEventId: null,
      },
      auditSummary: { visitedPaths: ["/", "/home", "/home/a", "/tmp"], homeOnly: false, eventCount: 6 },
    };
    const snapshot: FilesystemTopologySnapshot = {
      nodes: nodes.map((node) => ({
        path: node.path,
        parentPath: node.parentPath,
        depth: node.depth,
        sessionIds: node.sessionIds,
        observedAt: node.observedAt,
      })),
      sessions: [session],
      recentClosedSessions: [],
      truncated: false,
      generatedAt: "2026-09-23T10:00:09.000Z",
      latestTelemetryAt: "2026-09-23T10:00:09.000Z",
    };

    await act(async () => {
      root.render(createElement(TopologyCanvas, {
        snapshot,
        regionStatus: "ready",
        streamState: "live",
        freshnessState: {
          classification: "fresh",
          label: "Live",
          detail: "Current",
          badgeClass: "",
          dotClass: "",
          isDegraded: false,
          isStale: false,
          telemetryAgeMs: 0,
          snapshotReceiptAgeMs: 0,
          retrievalAgeMs: 0,
          telemetryStatus: "valid",
        },
        selectedSessionId: session.sessionId,
        selectedPath: null,
        displayedTransitions: transitions,
        currentTransition: transitions[2],
        onSelectSession: () => {},
        onSelectPath: () => {},
        staleThresholdMs: 30_000,
        presentationContext: { mode: "audit", session: null },
      }));
      await Promise.resolve();
    });

    const hierarchyEdges = Array.from(container.querySelectorAll<SVGPathElement>('[data-edge-kind="hierarchy"]'));
    expect(hierarchyEdges.length).toBeGreaterThan(0);
    for (const edge of hierarchyEdges) {
      expect(edge.getAttribute("stroke")).toBe("var(--border-strong)");
      expect(edge.getAttribute("stroke-dasharray")).toBe("none");
      expect(edge.getAttribute("marker-end")).toBeNull();
      expect(edge.getAttribute("data-transition-event-id")).toBeNull();
    }
    expect(container.querySelector('[data-transition-event-id="cross-one"]')).toBeNull();
    expect(container.querySelector('[data-transition-event-id="cross-two"]')).not.toBeNull();
  });
});
