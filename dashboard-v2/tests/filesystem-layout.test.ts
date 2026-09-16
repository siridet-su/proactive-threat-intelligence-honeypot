import { describe, expect, it } from "vitest";

import type {
  FilesystemTopologyNode,
  FilesystemTopologySession,
  GraphCallout,
  GraphNode,
} from "../src/components/filesystem/filesystemUtils";
import {
  analyzeTopologyDensity,
  calculateTwoDimensionalFit,
  calculateWorldBounds,
  calloutsForGraph,
  DEFAULT_DENSITY_THRESHOLDS,
  DEFAULT_STALE_THRESHOLD_MS,
  formatUpdateAge,
  getDirectorySessionCounts,
  getFreshnessState,
  getToolbarGroupContract,
  GRAPH_CALLOUT_LIMIT,
  GRAPH_NODE_LIMIT,
  pointForGraph,
  sourceRailPositions,
} from "../src/components/filesystem/filesystemUtils";

function graphNode(path: string, x: number, y: number, depth = 0): GraphNode {
  return {
    path,
    parentPath: path === "/" ? null : "/",
    depth,
    sessionIds: [],
    observedAt: null,
    x,
    y,
  };
}

function callout(sourceIp: string, path: string): GraphCallout {
  return {
    sourceIp,
    path,
    sessionIds: [`session-${sourceIp}`],
    sessions: [{ sessionId: `session-${sourceIp}`, path, observedAt: null }],
    targetPaths: [path],
  };
}

function makeNode(path: string, observedAt: string, depth = 1): FilesystemTopologyNode {
  return {
    path,
    parentPath: path === "/" ? null : "/",
    depth: path === "/" ? 0 : depth,
    sessionIds: ["session-1"],
    observedAt,
  };
}

function makeSession(
  sessionId: string,
  sourceIp: string,
  path: string,
  observedAt = "2026-09-15T10:00:00.000Z",
): FilesystemTopologySession {
  return {
    sessionId,
    sourceIp,
    cwdState: {
      path,
      observedAt,
      sequence: "1",
    },
    auditSummary: {
      visitedPaths: [path],
      homeOnly: path.startsWith("/home"),
      eventCount: 1,
    },
  };
}

describe("filesystem source layout", () => {
  it("keeps a single live source close to and level with its directory", () => {
    const nodes = new Map<string, GraphNode>([
      ["/", graphNode("/", 50, 12)],
      ["/home", graphNode("/home", 50, 32, 1)],
      ["/home/arch", graphNode("/home/arch", 50, 52, 2)],
    ]);

    const positions = sourceRailPositions([callout("10.58.33.209", "/home/arch")], nodes);

    expect(positions.get("10.58.33.209")).toEqual({ x: 32, y: 52 });
  });

  it("places a lone live source on the same side as an off-center target", () => {
    const nodes = new Map<string, GraphNode>([
      ["/left", graphNode("/left", 35, 36, 1)],
      ["/right", graphNode("/right", 65, 54, 1)],
    ]);

    const positions = sourceRailPositions([callout("10.58.33.210", "/right")], nodes);

    expect(positions.get("10.58.33.210")).toEqual({ x: 83, y: 54 });
  });

  it("moves rails outward as the topology and source count become denser", () => {
    const nodes = new Map<string, GraphNode>([
      ["/left", graphNode("/left", 35, 30, 1)],
      ["/center", graphNode("/center", 50, 48, 1)],
      ["/right", graphNode("/right", 65, 62, 1)],
    ]);
    const callouts = [
      callout("10.0.0.1", "/left"),
      callout("10.0.0.2", "/left"),
      callout("10.0.0.3", "/center"),
      callout("10.0.0.4", "/center"),
      callout("10.0.0.5", "/right"),
      callout("10.0.0.6", "/right"),
    ];

    const positions = sourceRailPositions(callouts, nodes);
    const xs = [...positions.values()].map((position) => position.x);

    expect(new Set(xs)).toEqual(new Set([13, 87]));
    expect([...positions.values()].every(({ x, y }) => x >= 10 && x <= 90 && y >= 18 && y <= 80)).toBe(true);
  });

  it("keeps the audit source stationary while replay targets change", () => {
    const nodes = new Map<string, GraphNode>([
      ["/etc", graphNode("/etc", 42, 38, 1)],
      ["/etc/profile.d", graphNode("/etc/profile.d", 58, 68, 2)],
    ]);

    const first = sourceRailPositions([callout("10.58.33.21", "/etc")], nodes, true);
    const latest = sourceRailPositions([callout("10.58.33.21", "/etc/profile.d")], nodes, true);

    expect(first.get("10.58.33.21")).toEqual(latest.get("10.58.33.21"));
    expect(first.get("10.58.33.21")?.y).toBe(25);
  });

  it("relaxes vertical spacing when large numbers of callouts are placed on a rail", () => {
    const nodes = new Map<string, GraphNode>([
      ["/", graphNode("/", 50, 12)],
      ["/left", graphNode("/left", 30, 30, 1)],
    ]);
    const callouts: GraphCallout[] = Array.from({ length: 12 }, (_, i) => ({
      sourceIp: `10.0.0.${i + 1}`,
      path: "/left",
      sessionIds: [`sess-${i + 1}`],
    }));

    const positions = sourceRailPositions(callouts, nodes);
    expect(positions.size).toBe(12);
    for (const pos of positions.values()) {
      expect(pos.y).toBeGreaterThanOrEqual(18);
      expect(pos.y).toBeLessThanOrEqual(80);
    }
  });
});

describe("pointForGraph render limits", () => {
  it("limits rendered nodes to GRAPH_NODE_LIMIT by default and omits older paths", () => {
    const baseTime = 1773600000000;
    const nodes: FilesystemTopologyNode[] = [
      makeNode("/", new Date(baseTime).toISOString(), 0),
      ...Array.from({ length: 60 }, (_, i) =>
        makeNode(`/path-${i + 1}`, new Date(baseTime + (i + 1) * 1000).toISOString()),
      ),
    ];

    const result = pointForGraph(nodes, [], null);
    expect(result.length).toBeLessThanOrEqual(GRAPH_NODE_LIMIT);
    // Node with latest timestamp should be included
    expect(result.some((n) => n.path === "/path-60")).toBe(true);
    // Older nodes beyond limit should be omitted
    expect(result.some((n) => n.path === "/path-1")).toBe(false);
  });

  it("expands to render all nodes when nodeLimit: null is passed", () => {
    const nodes: FilesystemTopologyNode[] = [
      makeNode("/", "2026-09-15T00:00:00.000Z", 0),
      ...Array.from({ length: 50 }, (_, i) =>
        makeNode(`/path-${i + 1}`, `2026-09-15T00:${String(i + 1).padStart(2, "0")}:00.000Z`),
      ),
    ];

    const result = pointForGraph(nodes, [], null, false, { nodeLimit: null });
    expect(result.length).toBe(51); // root + 50
    expect(result.some((n) => n.path === "/path-1")).toBe(true);
    expect(result.some((n) => n.path === "/path-50")).toBe(true);
  });

  it("prioritizes selectedSessionId directory even when its timestamp is older than the limit cut-off", () => {
    const nodes: FilesystemTopologyNode[] = [
      makeNode("/", "2026-09-15T00:00:00.000Z", 0),
      makeNode("/old-target", "2026-09-01T00:00:00.000Z"),
      ...Array.from({ length: 50 }, (_, i) =>
        makeNode(`/path-${i + 1}`, `2026-09-15T00:${String(i + 1).padStart(2, "0")}:00.000Z`),
      ),
    ];
    const session = makeSession("session-pinned", "192.168.1.100", "/old-target");

    const result = pointForGraph(nodes, [session], null, false, {
      selectedSessionId: "session-pinned",
    });

    expect(result.some((n) => n.path === "/old-target")).toBe(true);
  });

  it("defaults to full path rendering in audit mode", () => {
    const nodes: FilesystemTopologyNode[] = [
      makeNode("/", "2026-09-15T00:00:00.000Z", 0),
      ...Array.from({ length: 55 }, (_, i) =>
        makeNode(`/audit-${i + 1}`, `2026-09-15T00:${String(i + 1).padStart(2, "0")}:00.000Z`),
      ),
    ];

    const result = pointForGraph(nodes, [], null, true);
    expect(result.length).toBe(56);
  });
});

describe("calloutsForGraph render limits", () => {
  const nodeMap = new Map<string, GraphNode>([
    ["/", graphNode("/", 50, 10)],
    ["/target", graphNode("/target", 50, 30, 1)],
  ]);

  it("limits source clusters to GRAPH_CALLOUT_LIMIT by default", () => {
    const sessions = Array.from({ length: 15 }, (_, i) =>
      makeSession(`sess-${i + 1}`, `10.0.0.${i + 1}`, "/target"),
    );

    const result = calloutsForGraph(sessions, nodeMap);
    expect(result.length).toBe(GRAPH_CALLOUT_LIMIT);
  });

  it("returns all source clusters when calloutLimit: null is passed", () => {
    const sessions = Array.from({ length: 15 }, (_, i) =>
      makeSession(`sess-${i + 1}`, `10.0.0.${i + 1}`, "/target"),
    );

    const result = calloutsForGraph(sessions, nodeMap, { calloutLimit: null });
    expect(result.length).toBe(15);
  });

  it("prioritizes selectedSessionId so its callout is never omitted even if sorted outside top limit", () => {
    // 10 sessions. 10.0.0.99 sorts last alphabetically.
    const sessions = [
      ...Array.from({ length: 9 }, (_, i) =>
        makeSession(`sess-${i + 1}`, `10.0.0.${i + 1}`, "/target"),
      ),
      makeSession("sess-target", "10.0.0.99", "/target"),
    ];

    const result = calloutsForGraph(sessions, nodeMap, {
      selectedSessionId: "sess-target",
    });

    expect(result.length).toBe(GRAPH_CALLOUT_LIMIT);
    expect(result.some((c) => c.sourceIp === "10.0.0.99")).toBe(true);
    expect(result.some((c) => c.sessionIds.includes("sess-target"))).toBe(true);
  });
});

describe("multi-session IP cluster callouts", () => {
  const nodeMap = new Map<string, GraphNode>([
    ["/", graphNode("/", 50, 10)],
    ["/etc", graphNode("/etc", 35, 30, 1)],
    ["/var/log", graphNode("/var/log", 65, 30, 1)],
    ["/tmp", graphNode("/tmp", 50, 50, 1)],
  ]);

  it("groups multiple active sessions from the same IP into a single cluster", () => {
    const sessions = [
      makeSession("sess-1", "192.168.1.50", "/etc", "2026-09-15T10:00:00.000Z"),
      makeSession("sess-2", "192.168.1.50", "/var/log", "2026-09-15T10:05:00.000Z"),
      makeSession("sess-3", "192.168.1.50", "/tmp", "2026-09-15T10:02:00.000Z"),
    ];

    const result = calloutsForGraph(sessions, nodeMap);
    expect(result.length).toBe(1);

    const cluster = result[0];
    expect(cluster.sourceIp).toBe("192.168.1.50");
    expect(cluster.sessions.length).toBe(3);
    expect(cluster.sessionIds).toEqual(["sess-2", "sess-3", "sess-1"]);
  });

  it("sorts cluster sessions by observedAt descending and points cluster.path to latest", () => {
    const sessions = [
      makeSession("sess-old", "192.168.1.50", "/etc", "2026-09-15T09:00:00.000Z"),
      makeSession("sess-latest", "192.168.1.50", "/var/log", "2026-09-15T11:00:00.000Z"),
      makeSession("sess-mid", "192.168.1.50", "/tmp", "2026-09-15T10:00:00.000Z"),
    ];

    const result = calloutsForGraph(sessions, nodeMap);
    const cluster = result[0];

    expect(cluster.path).toBe("/var/log");
    expect(cluster.sessions[0].sessionId).toBe("sess-latest");
    expect(cluster.sessions[1].sessionId).toBe("sess-mid");
    expect(cluster.sessions[2].sessionId).toBe("sess-old");
  });

  it("collects all distinct paths in targetPaths without dropping any active route", () => {
    const sessions = [
      makeSession("sess-1", "192.168.1.50", "/etc", "2026-09-15T10:00:00.000Z"),
      makeSession("sess-2", "192.168.1.50", "/var/log", "2026-09-15T10:05:00.000Z"),
      makeSession("sess-3", "192.168.1.50", "/etc", "2026-09-15T10:02:00.000Z"),
    ];

    const result = calloutsForGraph(sessions, nodeMap);
    const cluster = result[0];

    expect(cluster.targetPaths.length).toBe(2);
    expect(cluster.targetPaths).toContain("/var/log");
    expect(cluster.targetPaths).toContain("/etc");
  });
});

describe("two-dimensional world bounds", () => {
  it("calculates 2D bounds incorporating node sizes and visual padding", () => {
    const nodes: GraphNode[] = [
      graphNode("/", 50, 10),
      graphNode("/var", 30, 40, 1),
      graphNode("/var/log", 70, 70, 2),
    ];
    const callouts: GraphCallout[] = [callout("192.168.1.1", "/var/log")];

    const bounds = calculateWorldBounds(nodes, callouts);

    expect(bounds.minX).toBeLessThan(30);
    expect(bounds.maxX).toBeGreaterThan(70);
    expect(bounds.minY).toBeLessThan(10);
    expect(bounds.maxY).toBeGreaterThan(70);
    expect(bounds.width).toBe(bounds.maxX - bounds.minX);
    expect(bounds.height).toBe(bounds.maxY - bounds.minY);
  });

  it("includes manual node positions dragged outside 0..100 without clamping", () => {
    const nodes: GraphNode[] = [
      graphNode("/", 50, 50),
      graphNode("/dragged-left", 50, 50),
      graphNode("/dragged-far-down", 50, 50),
    ];
    const manualNodes = {
      "/dragged-left": { x: -35, y: 20 },
      "/dragged-far-down": { x: 60, y: 145 },
    };

    const bounds = calculateWorldBounds(nodes, [], manualNodes);

    // Negative X and Y > 100 must not be clamped to 0 or 100
    expect(bounds.minX).toBeLessThan(-35);
    expect(bounds.maxY).toBeGreaterThan(145);
  });

  it("incorporates measured element sizes when available", () => {
    const nodes: GraphNode[] = [graphNode("/etc", 50, 50)];
    const nodeElementBounds = {
      "/etc": { x: 50, y: 50, width: 24, height: 12 },
    };

    const bounds = calculateWorldBounds(nodes, [], {}, {}, new Map(), nodeElementBounds);

    // half-width 12, padding 2.5 -> minX <= 50 - 12 - 2.5 = 35.5
    expect(bounds.minX).toBeLessThanOrEqual(35.5);
    // half-height 6, padding 2.5 -> maxY >= 50 + 6 + 2.5 = 58.5
    expect(bounds.maxY).toBeGreaterThanOrEqual(58.5);
  });
});

describe("two-dimensional fit viewport", () => {
  const normalBounds = {
    minX: 10,
    maxX: 90,
    minY: 10,
    maxY: 90,
    width: 80,
    height: 80,
    centerX: 50,
    centerY: 50,
  };

  it("calculates 2D pan and zoom that centers both X and Y", () => {
    const fit = calculateTwoDimensionalFit(normalBounds, {
      surfaceWidth: 1000,
      surfaceHeight: 600,
      planeWidth: 860,
      planeHeight: 500,
      planeOffsetLeft: 0,
      planeOffsetTop: 0,
      hasMinimap: false,
    });

    expect(fit).not.toBeNull();
    expect(fit!.zoom).toBeGreaterThan(0.35);
    expect(fit!.zoom).toBeLessThanOrEqual(1.0);
    // Y pan must NOT be hardcoded to 0; it should vertically center the content
    expect(fit!.pan.y).not.toBe(0);
  });

  it("adapts zoom appropriately for compact canvas vs fullscreen canvas", () => {
    const tallBounds = {
      minX: 20,
      maxX: 80,
      minY: 0,
      maxY: 120, // Tall vertical tree
      width: 60,
      height: 120,
      centerX: 50,
      centerY: 60,
    };

    const compactFit = calculateTwoDimensionalFit(tallBounds, {
      surfaceWidth: 900,
      surfaceHeight: 380, // Compact height
      planeWidth: 860,
      planeHeight: 500,
      planeOffsetLeft: 0,
      planeOffsetTop: 0,
    });

    const fullscreenFit = calculateTwoDimensionalFit(tallBounds, {
      surfaceWidth: 1920,
      surfaceHeight: 1080, // Fullscreen height
      planeWidth: 860,
      planeHeight: 500,
      planeOffsetLeft: 0,
      planeOffsetTop: 0,
    });

    expect(compactFit).not.toBeNull();
    expect(fullscreenFit).not.toBeNull();
    // Compact canvas must scale down zoom more to fit vertical extent
    expect(compactFit!.zoom).toBeLessThan(fullscreenFit!.zoom);
  });

  it("ensures minimap clearance when minimap is active on desktop screens", () => {
    // Content extends into bottom-right quadrant
    const bottomRightBounds = {
      minX: 30,
      maxX: 98,
      minY: 30,
      maxY: 98,
      width: 68,
      height: 68,
      centerX: 64,
      centerY: 64,
    };

    const fitWithMinimap = calculateTwoDimensionalFit(bottomRightBounds, {
      surfaceWidth: 1000,
      surfaceHeight: 600,
      planeWidth: 860,
      planeHeight: 500,
      planeOffsetLeft: 0,
      planeOffsetTop: 0,
      hasMinimap: true,
      isMinimapCollapsed: false,
    });

    const fitWithoutMinimap = calculateTwoDimensionalFit(bottomRightBounds, {
      surfaceWidth: 1000,
      surfaceHeight: 600,
      planeWidth: 860,
      planeHeight: 500,
      planeOffsetLeft: 0,
      planeOffsetTop: 0,
      hasMinimap: false,
    });

    expect(fitWithMinimap).not.toBeNull();
    expect(fitWithoutMinimap).not.toBeNull();

    // With minimap active, pan/zoom adjusts so content avoids the bottom-right minimap box
    expect(fitWithMinimap!.pan.x !== fitWithoutMinimap!.pan.x || fitWithMinimap!.pan.y !== fitWithoutMinimap!.pan.y).toBe(true);
  });
});

describe("getDirectorySessionCounts", () => {
  function makeSession(sessionId: string, sourceIp: string, path: string): FilesystemTopologySession {
    return {
      sessionId,
      sourceIp,
      cwdState: {
        path,
        observedAt: "2026-09-15T12:00:00Z",
        previousPath: null,
        changeType: "initial",
        source: "prompt",
      },
      auditSummary: {
        visitedPaths: [path],
        homeOnly: path.startsWith("/home"),
      },
    };
  }

  it("distinguishes exact path vs descendant sessions in a directory branch", () => {
    const sessions = [
      makeSession("s1", "192.168.1.1", "/var"),
      makeSession("s2", "192.168.1.2", "/var/log"),
      makeSession("s3", "192.168.1.3", "/var/log/nginx"),
      makeSession("s4", "192.168.1.4", "/etc"),
    ];

    // For node /var: s1 is at /var, s2 and s3 are in subdirectories
    const counts = getDirectorySessionCounts("/var", ["s1", "s2", "s3"], sessions);

    expect(counts.exactCount).toBe(1);
    expect(counts.descendantCount).toBe(2);
    expect(counts.branchCount).toBe(3);
    expect(counts.uniqueSourcesCount).toBe(3);
  });

  it("computes correct unique sources count when multiple sessions share an IP", () => {
    const sessions = [
      makeSession("s1", "10.0.0.99", "/var"),
      makeSession("s2", "10.0.0.99", "/var/log"),
      makeSession("s3", "10.0.0.99", "/var/tmp"),
      makeSession("s4", "10.0.0.100", "/var/cache"),
    ];

    const counts = getDirectorySessionCounts("/var", ["s1", "s2", "s3", "s4"], sessions);

    expect(counts.exactCount).toBe(1);
    expect(counts.descendantCount).toBe(3);
    expect(counts.branchCount).toBe(4);
    // 4 sessions across 2 unique sources (10.0.0.99 and 10.0.0.100)
    expect(counts.uniqueSourcesCount).toBe(2);
  });

  it("handles empty sessions and unknown session IDs gracefully", () => {
    const countsEmpty = getDirectorySessionCounts("/opt", [], []);
    expect(countsEmpty).toEqual({
      exactCount: 0,
      descendantCount: 0,
      branchCount: 0,
      uniqueSourcesCount: 0,
    });

    const sessions = [makeSession("s1", "10.0.0.1", "/tmp")];
    const countsMissing = getDirectorySessionCounts("/opt", ["non-existent-id"], sessions);
    expect(countsMissing).toEqual({
      exactCount: 0,
      descendantCount: 0,
      branchCount: 0,
      uniqueSourcesCount: 0,
    });
  });

  it("calculates counts for root directory correctly", () => {
    const sessions = [
      makeSession("s1", "192.168.1.1", "/"),
      makeSession("s2", "192.168.1.2", "/home/user"),
      makeSession("s3", "192.168.1.3", "/var/log"),
    ];

    const counts = getDirectorySessionCounts("/", ["s1", "s2", "s3"], sessions);

    expect(counts.exactCount).toBe(1);
    expect(counts.descendantCount).toBe(2);
    expect(counts.branchCount).toBe(3);
    expect(counts.uniqueSourcesCount).toBe(3);
  });

  it("calculates counts when all branch sessions are inside subdirectories (zero exact sessions)", () => {
    const sessions = [
      makeSession("s1", "172.16.0.5", "/home/admin/documents"),
      makeSession("s2", "172.16.0.6", "/home/admin/downloads"),
    ];

    // Node is /home, but no session is directly at /home
    const counts = getDirectorySessionCounts("/home", ["s1", "s2"], sessions);

    expect(counts.exactCount).toBe(0);
    expect(counts.descendantCount).toBe(2);
    expect(counts.branchCount).toBe(2);
    expect(counts.uniqueSourcesCount).toBe(2);
  });
});

describe("filesystem freshness and degraded state semantics (FS-012)", () => {
  describe("formatUpdateAge", () => {
    it("formats sub-3s intervals as 'Just now'", () => {
      expect(formatUpdateAge(0)).toBe("Just now");
      expect(formatUpdateAge(1500)).toBe("Just now");
      expect(formatUpdateAge(2999)).toBe("Just now");
      expect(formatUpdateAge(-500)).toBe("Just now");
      expect(formatUpdateAge(Number.NaN)).toBe("Just now");
    });

    it("formats seconds accurately under 60 seconds", () => {
      expect(formatUpdateAge(3000)).toBe("3s ago");
      expect(formatUpdateAge(14900)).toBe("14s ago");
      expect(formatUpdateAge(45000)).toBe("45s ago");
      expect(formatUpdateAge(59999)).toBe("59s ago");
    });

    it("formats minutes accurately under 60 minutes", () => {
      expect(formatUpdateAge(60_000)).toBe("1m ago");
      expect(formatUpdateAge(135_000)).toBe("2m ago");
      expect(formatUpdateAge(3_500_000)).toBe("58m ago");
    });

    it("formats hours for 60 minutes and beyond", () => {
      expect(formatUpdateAge(3_600_000)).toBe("1h ago");
      expect(formatUpdateAge(7_500_000)).toBe("2h ago");
      expect(formatUpdateAge(86_400_000)).toBe("24h ago");
    });
  });

  describe("getFreshnessState", () => {
    it("returns connecting offline state when snapshot has not loaded yet", () => {
      const state = getFreshnessState({
        lastUpdateAgeMs: 0,
        streamState: "connecting",
        regionStatus: "loading",
        hasSnapshot: false,
      });

      expect(state.classification).toBe("offline");
      expect(state.label).toBe("Connecting");
      expect(state.isDegraded).toBe(false);
      expect(state.isStale).toBe(false);
    });

    it("returns offline error state when transport fails without an existing snapshot", () => {
      const state = getFreshnessState({
        lastUpdateAgeMs: 0,
        streamState: "stale",
        regionStatus: "error",
        hasSnapshot: false,
      });

      expect(state.classification).toBe("offline");
      expect(state.label).toBe("Offline");
      expect(state.isDegraded).toBe(true);
      expect(state.isStale).toBe(true);
    });

    it("returns fresh state when stream is live and age is within threshold", () => {
      const state = getFreshnessState({
        lastUpdateAgeMs: 8_000,
        streamState: "live",
        regionStatus: "ready",
        hasSnapshot: true,
      });

      expect(state.classification).toBe("fresh");
      expect(state.label).toBe("Live & Fresh");
      expect(state.isDegraded).toBe(false);
      expect(state.isStale).toBe(false);
    });

    it("returns stale state when stream is live but telemetry age exceeds threshold", () => {
      const state = getFreshnessState({
        lastUpdateAgeMs: 35_000,
        streamState: "live",
        regionStatus: "ready",
        hasSnapshot: true,
        staleThresholdMs: DEFAULT_STALE_THRESHOLD_MS, // 30s
      });

      expect(state.classification).toBe("stale");
      expect(state.label).toBe("Stale");
      expect(state.isDegraded).toBe(false);
      expect(state.isStale).toBe(true);
      expect(state.detail).toContain("no new telemetry for 35s ago");
    });

    it("returns degraded state when transport disconnects/reconnects with retained snapshot", () => {
      const state = getFreshnessState({
        lastUpdateAgeMs: 12_000,
        streamState: "stale",
        regionStatus: "ready",
        hasSnapshot: true,
      });

      expect(state.classification).toBe("degraded");
      expect(state.label).toBe("Degraded");
      expect(state.isDegraded).toBe(true);
      expect(state.detail).toContain("retained snapshot from 12s ago");
    });

    it("returns degraded state when region status is error with retained snapshot", () => {
      const state = getFreshnessState({
        lastUpdateAgeMs: 40_000,
        streamState: "connecting",
        regionStatus: "error",
        hasSnapshot: true,
      });

      expect(state.classification).toBe("degraded");
      expect(state.label).toBe("Degraded");
      expect(state.isDegraded).toBe(true);
      expect(state.isStale).toBe(true);
    });

    it("respects custom staleThresholdMs parameter", () => {
      const stateWithin = getFreshnessState({
        lastUpdateAgeMs: 8_000,
        streamState: "live",
        regionStatus: "ready",
        hasSnapshot: true,
        staleThresholdMs: 10_000,
      });
      expect(stateWithin.classification).toBe("fresh");

      const stateExceeded = getFreshnessState({
        lastUpdateAgeMs: 11_000,
        streamState: "live",
        regionStatus: "ready",
        hasSnapshot: true,
        staleThresholdMs: 10_000,
      });
      expect(stateExceeded.classification).toBe("stale");
      expect(stateExceeded.isStale).toBe(true);
    });
  });

  describe("Toolbar hierarchy and responsive contracts (FS-014)", () => {
    it("defines distinct contracts for all 4 functional toolbar domains", () => {
      const domains = ["global-views", "canvas-navigation", "layout-editing", "replay-actions"] as const;

      for (const domain of domains) {
        const contract = getToolbarGroupContract(domain);
        expect(contract).toBeDefined();
        expect(contract.domain).toBe(domain);
        expect(typeof contract.ariaLabel).toBe("string");
        expect(contract.ariaLabel.length).toBeGreaterThan(0);
        expect(["toolbar", "group", "tablist", "region"]).toContain(contract.role);
      }
    });

    it("mandates atomic non-wrapping behavior for canvas navigation and layout editing", () => {
      const navContract = getToolbarGroupContract("canvas-navigation");
      const editContract = getToolbarGroupContract("layout-editing");

      // Navigation and Layout Editing must be atomic groups (flex-nowrap)
      // to avoid breaking zoom, pan, explore, and arrange across arbitrary wrapped lines
      expect(navContract.isAtomic).toBe(true);
      expect(editContract.isAtomic).toBe(true);
      expect(navContract.role).toBe("group");
      expect(editContract.role).toBe("group");
    });

    it("verifies expected functional subgroups for canvas navigation", () => {
      const contract = getToolbarGroupContract("canvas-navigation");
      expect(contract.subgroups).toContain("Zoom controls");
      expect(contract.subgroups).toContain("Camera alignment");
    });

    it("verifies expected functional subgroups for layout editing", () => {
      const contract = getToolbarGroupContract("layout-editing");
      expect(contract.subgroups).toContain("Interaction mode");
      expect(contract.subgroups).toContain("Layout options");
    });

    it("verifies expected functional subgroups for global views and replay actions", () => {
      const globalContract = getToolbarGroupContract("global-views");
      expect(globalContract.subgroups).toContain("Filesystem view modes");
      expect(globalContract.subgroups).toContain("Stream telemetry status");

      const replayContract = getToolbarGroupContract("replay-actions");
      expect(replayContract.subgroups).toContain("Audited session and filter controls");
      expect(replayContract.subgroups).toContain("Replay and workspace actions");
    });
  });

  describe("Density-aware topology modes (FS-015)", () => {
    describe("analyzeTopologyDensity", () => {
      it("exports expected default density thresholds", () => {
        expect(DEFAULT_DENSITY_THRESHOLDS.detailedMaxNodes).toBe(15);
        expect(DEFAULT_DENSITY_THRESHOLDS.detailedMaxSources).toBe(4);
        expect(DEFAULT_DENSITY_THRESHOLDS.clusteredMaxNodes).toBe(42);
        expect(DEFAULT_DENSITY_THRESHOLDS.clusteredMaxSources).toBe(10);
      });

      it("classifies small sets as detailed mode under auto preference", () => {
        const nodes = [
          makeNode("/", "2026-09-15T00:00:00.000Z", 0),
          ...Array.from({ length: 10 }, (_, i) => makeNode(`/dir-${i}`, "2026-09-15T00:00:00.000Z", 1)),
        ];
        const sessions = [
          makeSession("s1", "1.1.1.1", "/dir-1"),
          makeSession("s2", "2.2.2.2", "/dir-2"),
        ];

        const analysis = analyzeTopologyDensity(nodes, sessions, "auto");
        expect(analysis.mode).toBe("detailed");
        expect(analysis.isAuto).toBe(true);
        expect(analysis.totalNodes).toBe(11);
        expect(analysis.totalSources).toBe(2);
        expect(analysis.hiddenNodes).toBe(0);
        expect(analysis.hasAggregatedBranches).toBe(false);
      });

      it("classifies medium sets as clustered mode under auto preference", () => {
        const nodes = [
          makeNode("/", "2026-09-15T00:00:00.000Z", 0),
          ...Array.from({ length: 25 }, (_, i) => makeNode(`/dir-${i}`, "2026-09-15T00:00:00.000Z", 1)),
        ];
        const sessions = [
          makeSession("s1", "1.1.1.1", "/dir-1"),
          makeSession("s2", "2.2.2.2", "/dir-2"),
          makeSession("s3", "3.3.3.3", "/dir-3"),
          makeSession("s4", "4.4.4.4", "/dir-4"),
          makeSession("s5", "5.5.5.5", "/dir-5"),
        ];

        const analysis = analyzeTopologyDensity(nodes, sessions, "auto");
        expect(analysis.mode).toBe("clustered");
        expect(analysis.isAuto).toBe(true);
        expect(analysis.totalNodes).toBe(26);
        expect(analysis.totalSources).toBe(5);
      });

      it("classifies large sets (>42 nodes or >10 sources) as aggregated mode under auto preference", () => {
        const nodes = [
          makeNode("/", "2026-09-15T00:00:00.000Z", 0),
          ...Array.from({ length: 50 }, (_, i) => makeNode(`/dir-${i}`, "2026-09-15T00:00:00.000Z", 1)),
        ];
        const sessions = [makeSession("s1", "1.1.1.1", "/dir-1")];

        const analysis = analyzeTopologyDensity(nodes, sessions, "auto");
        expect(analysis.mode).toBe("aggregated");
        expect(analysis.isAuto).toBe(true);
        expect(analysis.totalNodes).toBe(51);

        // Also test > 10 sources
        const fewNodes = [
          makeNode("/", "2026-09-15T00:00:00.000Z", 0),
          makeNode("/tmp", "2026-09-15T00:00:00.000Z", 1),
        ];
        const manySources = Array.from({ length: 12 }, (_, i) =>
          makeSession(`s${i}`, `10.0.0.${i + 1}`, "/tmp")
        );
        const sourceAnalysis = analyzeTopologyDensity(fewNodes, manySources, "auto");
        expect(sourceAnalysis.mode).toBe("aggregated");
      });

      it("respects explicit density preferences overriding auto classification", () => {
        const largeNodes = [
          makeNode("/", "2026-09-15T00:00:00.000Z", 0),
          ...Array.from({ length: 60 }, (_, i) => makeNode(`/dir-${i}`, "2026-09-15T00:00:00.000Z", 1)),
        ];
        const sessions = [makeSession("s1", "1.1.1.1", "/dir-1")];

        const analysisDetailed = analyzeTopologyDensity(largeNodes, sessions, "detailed");
        expect(analysisDetailed.mode).toBe("detailed");
        expect(analysisDetailed.isAuto).toBe(false);

        const smallNodes = [makeNode("/", "2026-09-15T00:00:00.000Z", 0)];
        const analysisAggregated = analyzeTopologyDensity(smallNodes, sessions, "aggregated");
        expect(analysisAggregated.mode).toBe("aggregated");
        expect(analysisAggregated.isAuto).toBe(false);
      });

      it("truthfully reports hidden and rendered counts when rendered nodes and callouts are supplied", () => {
        const nodes = [
          makeNode("/", "2026-09-15T00:00:00.000Z", 0),
          makeNode("/var", "2026-09-15T00:00:00.000Z", 1),
          makeNode("/var/log", "2026-09-15T00:00:00.000Z", 2),
        ];
        const sessions = [
          makeSession("s1", "1.1.1.1", "/var"),
          makeSession("s2", "2.2.2.2", "/var/log"),
        ];

        const renderedNodes: GraphNode[] = [
          graphNode("/", 50, 10, 0),
          graphNode("/var", 50, 30, 1),
        ];
        const renderedCallouts: GraphCallout[] = [callout("1.1.1.1", "/var")];

        const analysis = analyzeTopologyDensity(
          nodes,
          sessions,
          "aggregated",
          "/var",
          renderedNodes,
          renderedCallouts
        );

        expect(analysis.totalNodes).toBe(3);
        expect(analysis.renderedNodes).toBe(2);
        expect(analysis.hiddenNodes).toBe(1);
        expect(analysis.totalSources).toBe(2);
        expect(analysis.renderedSources).toBe(1);
        expect(analysis.hiddenSources).toBe(1);
        expect(analysis.hasAggregatedBranches).toBe(true);
        expect(analysis.focusedBranchPath).toBe("/var");
      });
    });

    describe("pointForGraph density modes and expand-on-focus", () => {
      it("renders all nodes without limit in detailed mode", () => {
        const nodes = [
          makeNode("/", "2026-09-15T00:00:00.000Z", 0),
          ...Array.from({ length: 60 }, (_, i) => makeNode(`/p${i}`, "2026-09-15T00:00:00.000Z", 1)),
        ];
        const sessions = [makeSession("s1", "1.1.1.1", "/p0")];

        const result = pointForGraph(nodes, sessions, null, false, {
          densityMode: "detailed",
        });

        expect(result.length).toBe(61);
        for (const node of result) {
          expect(node.hiddenChildCount).toBe(0);
          expect(node.isAggregated).toBe(false);
        }
      });

      it("aggregates deep branches in aggregated mode and displays hidden child count", () => {
        const nodes: FilesystemTopologyNode[] = [
          { path: "/", parentPath: null, depth: 0, sessionIds: [], observedAt: "2026-09-15T00:00:00.000Z" },
          { path: "/var", parentPath: "/", depth: 1, sessionIds: [], observedAt: "2026-09-15T00:00:00.000Z" },
          { path: "/var/log", parentPath: "/var", depth: 2, sessionIds: [], observedAt: "2026-09-15T00:00:00.000Z" },
          { path: "/var/log/nginx", parentPath: "/var/log", depth: 3, sessionIds: [], observedAt: "2026-09-15T00:00:00.000Z" },
          { path: "/etc", parentPath: "/", depth: 1, sessionIds: [], observedAt: "2026-09-15T00:00:00.000Z" },
          { path: "/etc/cron.d", parentPath: "/etc", depth: 2, sessionIds: [], observedAt: "2026-09-15T00:00:00.000Z" },
        ];
        const sessions: FilesystemTopologySession[] = [];

        // Aggregated mode without focus: keeps depth <= 1 (/, /var, /etc)
        const result = pointForGraph(nodes, sessions, null, false, {
          densityMode: "aggregated",
          focusedPath: null,
        });

        const paths = result.map((n) => n.path);
        expect(paths).toContain("/");
        expect(paths).toContain("/var");
        expect(paths).toContain("/etc");
        expect(paths).not.toContain("/var/log");
        expect(paths).not.toContain("/var/log/nginx");
        expect(paths).not.toContain("/etc/cron.d");

        // Verify hidden child counts
        const varNode = result.find((n) => n.path === "/var");
        expect(varNode).toBeDefined();
        // /var has 2 descendants (/var/log, /var/log/nginx)
        expect(varNode?.hiddenChildCount).toBe(2);
        expect(varNode?.isAggregated).toBe(true);

        const etcNode = result.find((n) => n.path === "/etc");
        expect(etcNode).toBeDefined();
        // /etc has 1 descendant (/etc/cron.d)
        expect(etcNode?.hiddenChildCount).toBe(1);
        expect(etcNode?.isAggregated).toBe(true);
      });

      it("expands focused branch subtree on focus while keeping other branches aggregated", () => {
        const nodes: FilesystemTopologyNode[] = [
          { path: "/", parentPath: null, depth: 0, sessionIds: [], observedAt: "2026-09-15T00:00:00.000Z" },
          { path: "/var", parentPath: "/", depth: 1, sessionIds: [], observedAt: "2026-09-15T00:00:00.000Z" },
          { path: "/var/log", parentPath: "/var", depth: 2, sessionIds: [], observedAt: "2026-09-15T00:00:00.000Z" },
          { path: "/var/log/nginx", parentPath: "/var/log", depth: 3, sessionIds: [], observedAt: "2026-09-15T00:00:00.000Z" },
          { path: "/etc", parentPath: "/", depth: 1, sessionIds: [], observedAt: "2026-09-15T00:00:00.000Z" },
          { path: "/etc/cron.d", parentPath: "/etc", depth: 2, sessionIds: [], observedAt: "2026-09-15T00:00:00.000Z" },
        ];
        const sessions: FilesystemTopologySession[] = [];

        // Focus on /var: /var and its entire subtree should expand!
        const result = pointForGraph(nodes, sessions, null, false, {
          densityMode: "aggregated",
          focusedPath: "/var",
        });

        const paths = result.map((n) => n.path);
        expect(paths).toContain("/");
        expect(paths).toContain("/var");
        expect(paths).toContain("/var/log");
        expect(paths).toContain("/var/log/nginx");
        // /etc is kept as depth 1 hub, but /etc/cron.d remains aggregated
        expect(paths).toContain("/etc");
        expect(paths).not.toContain("/etc/cron.d");

        const varNode = result.find((n) => n.path === "/var");
        expect(varNode?.hiddenChildCount).toBe(0);
        expect(varNode?.isAggregated).toBe(false);

        const etcNode = result.find((n) => n.path === "/etc");
        expect(etcNode?.hiddenChildCount).toBe(1);
        expect(etcNode?.isAggregated).toBe(true);
      });
    });
  });
});
