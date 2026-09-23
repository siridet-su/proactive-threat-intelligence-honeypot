// @vitest-environment happy-dom
import { act, createElement } from "react";
import { createRoot, type Root } from "react-dom/client";
import { MotionGlobalConfig } from "framer-motion";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { FilesystemTopologyNode, FilesystemTopologySnapshot } from "../src/lib/dashboardTypes";
import { TopologyCanvas } from "../src/components/filesystem/TopologyCanvas";
import { TopologyToolbar } from "../src/components/filesystem/TopologyToolbar";
import {
  deriveMinimapVisibility,
  deriveTransitionEndpointCoverage,
  requiredTransitionEndpointPaths,
} from "../src/components/filesystem/topologyDensity";
import { deriveVerifiedCwdTransition } from "../src/components/filesystem/filesystemTransitions";
import { pointForGraph } from "../src/components/filesystem/filesystemUtils";

// @ts-expect-error React act environment flag
globalThis.IS_REACT_ACT_ENVIRONMENT = true;

vi.mock("server-only", () => ({}));
MotionGlobalConfig.skipAnimations = true;

const freshnessState = {
  classification: "fresh" as const,
  label: "Live",
  detail: "Current",
  badgeClass: "",
  dotClass: "",
  isDegraded: false,
  isStale: false,
  telemetryAgeMs: 0,
  snapshotReceiptAgeMs: 0,
  retrievalAgeMs: 0,
  telemetryStatus: "valid" as const,
};

function topologyNodes(count: number): FilesystemTopologyNode[] {
  return [
    { path: "/", parentPath: null, depth: 0, sessionIds: [], observedAt: null },
    ...Array.from({ length: Math.max(0, count - 1) }, (_, index) => ({
      path: `/branch-${index}`,
      parentPath: "/",
      depth: 1,
      sessionIds: [],
      observedAt: `2026-09-23T10:${String(index).padStart(2, "0")}:00.000Z`,
    })),
  ];
}

function snapshotWithNodes(count: number): FilesystemTopologySnapshot {
  return {
    nodes: topologyNodes(count),
    sessions: [],
    recentClosedSessions: [],
    truncated: false,
    generatedAt: "2026-09-23T10:00:00.000Z",
    latestTelemetryAt: "2026-09-23T10:00:00.000Z",
  };
}

describe("FSV-007C: density-aware fit, minimap, and endpoint coverage", () => {
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

  it("shows the minimap only for dense topology, zoom away from fit, or explicit show preference", () => {
    const base = { totalNodes: 4, totalSources: 1, currentZoom: 1, fitZoom: 1 };
    expect(deriveMinimapVisibility({ ...base, preference: "auto" })).toBe(false);
    expect(deriveMinimapVisibility({ ...base, preference: "auto", totalNodes: 16 })).toBe(true);
    expect(deriveMinimapVisibility({ ...base, preference: "auto", totalSources: 5 })).toBe(true);
    expect(deriveMinimapVisibility({ ...base, preference: "auto", currentZoom: 0.8 })).toBe(true);
    expect(deriveMinimapVisibility({ ...base, preference: "show" })).toBe(true);
    expect(deriveMinimapVisibility({ ...base, preference: "hide", totalNodes: 100, currentZoom: 0.7 })).toBe(false);
    expect(deriveMinimapVisibility({ ...base, preference: "auto", fitZoom: null, currentZoom: 0.8 })).toBe(false);
  });

  it("preserves both verified endpoints through aggregated density and never includes a failed destination", () => {
    const allNodes: FilesystemTopologyNode[] = [
      { path: "/", parentPath: null, depth: 0, sessionIds: [], observedAt: null },
      { path: "/home", parentPath: "/", depth: 1, sessionIds: [], observedAt: null },
      { path: "/home/a", parentPath: "/home", depth: 2, sessionIds: [], observedAt: null },
      { path: "/tmp", parentPath: "/", depth: 1, sessionIds: [], observedAt: null },
      ...topologyNodes(30).slice(1),
    ];
    const changed = deriveVerifiedCwdTransition({
      id: "changed",
      sessionId: "session-density",
      sequence: null,
      sourceEventId: null,
      at: "2026-09-23T10:00:00.000Z",
      fromPath: "/home/a",
      toPath: "/tmp",
      action: "changed",
      status: "confirmed",
    }, 8);
    const requiredPaths = requiredTransitionEndpointPaths(changed);
    const rendered = pointForGraph(allNodes, [], null, false, {
      densityMode: "aggregated",
      nodeLimit: 5,
      requiredPaths,
    });

    expect(requiredPaths).toEqual(["/home/a", "/tmp"]);
    expect(rendered.map((node) => node.path)).toEqual(expect.arrayContaining(["/", "/home", "/home/a", "/tmp"]));

    const failed = deriveVerifiedCwdTransition({
      id: "failed",
      sessionId: "session-density",
      sequence: null,
      sourceEventId: null,
      at: "2026-09-23T10:00:01.000Z",
      fromPath: "/tmp",
      toPath: "/hostile/unverified",
      action: "failed_change",
      status: "conditional_candidate",
    }, 9);
    expect(requiredTransitionEndpointPaths(failed)).toEqual(["/tmp"]);
  });

  it("reports hidden endpoints through their nearest aggregate and missing endpoints as unavailable", () => {
    const allNodes: FilesystemTopologyNode[] = [
      { path: "/", parentPath: null, depth: 0, sessionIds: [], observedAt: null },
      { path: "/var", parentPath: "/", depth: 1, sessionIds: [], observedAt: null },
      { path: "/var/log", parentPath: "/var", depth: 2, sessionIds: [], observedAt: null },
    ];
    const rendered = [{ ...allNodes[0], x: 50, y: 10, hiddenChildCount: 2, isAggregated: true }];

    expect(deriveTransitionEndpointCoverage(["/var/log", "/missing"], allNodes, rendered)).toEqual([
      { path: "/var/log", status: "aggregated", aggregatePath: "/" },
      { path: "/missing", status: "unavailable", aggregatePath: null },
    ]);
  });

  it("hides the automatic minimap for a sparse topology at its fitted zoom and shows it above threshold", async () => {
    const renderCanvas = async (snapshot: FilesystemTopologySnapshot) => {
      await act(async () => {
        root.render(createElement(TopologyCanvas, {
          snapshot,
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
    };

    await renderCanvas(snapshotWithNodes(4));
    expect(container.querySelector('[data-testid="topology-minimap"]')).toBeNull();

    await renderCanvas(snapshotWithNodes(16));
    const minimap = container.querySelector('[data-testid="topology-minimap"]');
    expect(minimap).not.toBeNull();
    expect(minimap?.classList.contains("hidden")).toBe(false);
  });

  it("discloses a verified current endpoint that is unavailable in the loaded topology", async () => {
    const currentTransition = deriveVerifiedCwdTransition({
      id: "partial-topology-hop",
      sessionId: "session-density",
      sequence: null,
      sourceEventId: null,
      at: "2026-09-23T10:00:02.000Z",
      fromPath: "/missing-origin",
      toPath: "/branch-0",
      action: "changed",
      status: "confirmed",
    }, 12);
    await act(async () => {
      root.render(createElement(TopologyCanvas, {
        snapshot: snapshotWithNodes(4),
        regionStatus: "ready",
        streamState: "live",
        freshnessState,
        selectedSessionId: null,
        selectedPath: null,
        displayedTransitions: [currentTransition],
        currentTransition,
        onSelectSession: () => {},
        onSelectPath: () => {},
        staleThresholdMs: 30_000,
        presentationContext: { mode: "audit", session: null },
      }));
      await Promise.resolve();
    });

    const coverage = container.querySelector('[data-testid="transition-endpoint-coverage"]');
    expect(coverage?.textContent).toContain("/missing-origin");
    expect(coverage?.textContent).toContain("unavailable in the loaded topology");
    expect(coverage?.querySelector('[data-transition-endpoint-status="unavailable"]')).not.toBeNull();
  });

  it("keeps zoom, fit, and locate direct while density, layout, grid, reset, and minimap preference stay under View", async () => {
    const setMinimapPreference = vi.fn();
    const props = {
      zoom: 1,
      zoomIn: () => {},
      zoomOut: () => {},
      fitTopology: () => {},
      selectedGraphCallout: null,
      markUserAdjusted: () => {},
      centerSelectedSource: () => {},
      isArrangeMode: false,
      setIsArrangeMode: () => {},
      canUndoLayout: false,
      undoLayoutChange: () => {},
      totalOverlaps: 0,
      autoArrangeTopology: () => {},
      resetMapWorkspace: () => {},
      densityPreference: "auto" as const,
      setDensityPreference: () => {},
      minimapPreference: "auto" as const,
      setMinimapPreference,
      minimapVisible: false,
      showGrid: true,
      setShowGrid: () => {},
      effectiveDensityMode: "detailed" as const,
      densityAnalysisHiddenNodes: 0,
      isTopologyExpanded: false,
      isAuditMode: true,
      handleToggleExpand: () => {},
    };
    await act(async () => root.render(createElement(TopologyToolbar, props)));

    expect(container.querySelector('[aria-label="Zoom out"]')).not.toBeNull();
    expect(container.querySelector('[aria-label="Zoom in"]')).not.toBeNull();
    expect(container.querySelector('[aria-label="Fit topology in view"]')).not.toBeNull();
    expect(container.querySelector('[aria-label="Center selected IP"]')).not.toBeNull();
    expect(container.textContent).not.toContain("Density Mode");
    expect(container.textContent).not.toContain("Auto arrange");

    await act(async () => {
      (container.querySelector('[aria-label="View settings"]') as HTMLButtonElement).click();
    });
    expect(container.textContent).toContain("Density Mode");
    expect(container.textContent).toContain("Auto arrange");
    expect(container.querySelector('[aria-label="Minimap visibility"]')).not.toBeNull();
    expect(container.textContent).toContain("Restore default layout");
    await act(async () => {
      (Array.from(container.querySelectorAll("button")).find((button) => button.textContent?.trim() === "show") as HTMLButtonElement).click();
    });
    expect(setMinimapPreference).toHaveBeenCalledWith("show");
  });
});
