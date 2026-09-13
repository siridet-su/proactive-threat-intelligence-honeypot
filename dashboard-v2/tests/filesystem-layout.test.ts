import { describe, expect, it } from "vitest";

import type { GraphCallout, GraphNode } from "../src/components/filesystem/filesystemUtils";
import { sourceRailPositions } from "../src/components/filesystem/filesystemUtils";

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
  return { sourceIp, path, sessionIds: [`session-${sourceIp}`] };
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
});
