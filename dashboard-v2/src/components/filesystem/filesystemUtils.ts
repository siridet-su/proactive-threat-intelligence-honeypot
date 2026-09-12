import type {
  FilesystemClosedSession,
  FilesystemTopologyNode,
  FilesystemTopologySession,
  FilesystemTopologySnapshot,
  SessionCwdHistoryEvent,
  SessionCwdHistoryPage,
} from "@/lib/dashboardTypes";

export type StreamState = "connecting" | "live" | "stale";
export type Pan = { x: number; y: number };
export type LabelPosition = { x: number; y: number };
export type LabelDrag = { sourceIp: string; startX: number; startY: number; origin: LabelPosition };
export type NodeDrag = { path: string; startX: number; startY: number; origin: LabelPosition };
export type MapMetrics = { surfaceWidth: number; surfaceHeight: number; planeWidth: number; planeHeight: number; planeLeft: number; planeTop: number };

export interface ActiveHopRoute {
  eventId: string;
  fromPath: string | null;
  toPath: string | null;
  action: string;
  status: string;
  at: string | null;
  stepIndex: number;
  totalSteps: number;
  visitedPaths: string[];
  visitedStepMap: Record<string, number>;
  isFailedAttempt?: boolean;
}

export const INSPECTOR_PAGE_SIZE = 12;
export const GRAPH_CALLOUT_LIMIT = 8;
export const GRAPH_NODE_LIMIT = 42;
export const LABEL_LAYOUT_STORAGE_KEY = "pti-filesystem-label-layout-v1";
export const TIMELINE_SIDEBAR_STORAGE_KEY = "pti-timeline-sidebar-width-v1";
export const MIN_TIMELINE_SIDEBAR_WIDTH = 360;
export const MAX_TIMELINE_SIDEBAR_WIDTH = 760;
export const DEFAULT_TIMELINE_SIDEBAR_WIDTH = 420;
export const MAP_MIN_ZOOM = 0.35;
export const MAP_MAX_ZOOM = 2.75;

export function isSnapshot(value: unknown): value is FilesystemTopologySnapshot {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Partial<FilesystemTopologySnapshot>;
  return Array.isArray(candidate.nodes) && Array.isArray(candidate.sessions) && Array.isArray(candidate.recentClosedSessions) &&
    typeof candidate.truncated === "boolean" && typeof candidate.generatedAt === "string";
}

export function isHistoryPage(value: unknown): value is SessionCwdHistoryPage {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Partial<SessionCwdHistoryPage>;
  return Array.isArray(candidate.items) && (typeof candidate.nextCursor === "string" || candidate.nextCursor === null);
}

export function formatTimestamp(value: string | null): string {
  if (!value) return "No timestamp";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "No timestamp";
  return new Intl.DateTimeFormat("en-GB", { dateStyle: "medium", timeStyle: "medium" }).format(date);
}

export function directorySegment(path: string): string {
  if (path === "/") return "/";
  const normalized = path.replace(/\/+$/, "");
  return normalized.slice(normalized.lastIndexOf("/") + 1) || path;
}

export function compactDirectoryPath(path: string): string {
  return path === "/" ? path : `…/${directorySegment(path)}`;
}

export function isSensitiveDirectory(path: string): boolean {
  const p = path.toLowerCase();
  return (
    p === "/root" ||
    p.startsWith("/root/") ||
    p === "/tmp" ||
    p.startsWith("/tmp/") ||
    p === "/var/tmp" ||
    p.startsWith("/var/tmp/") ||
    p === "/dev/shm" ||
    p.startsWith("/dev/shm/") ||
    p === "/etc" ||
    p.startsWith("/etc/")
  );
}

export interface BreadcrumbSegment {
  name: string;
  path: string;
}

export function pathBreadcrumbs(path: string): BreadcrumbSegment[] {
  if (path === "/") return [{ name: "/", path: "/" }];
  const parts = path.split("/").filter(Boolean);
  const breadcrumbs: BreadcrumbSegment[] = [{ name: "/", path: "/" }];
  let current = "";
  for (const part of parts) {
    current += `/${part}`;
    breadcrumbs.push({ name: part, path: current });
  }
  return breadcrumbs;
}

export function statusLabel(status: FilesystemTopologySession["cwdState"]["status"]): string {
  if (status === "confirmed") return "Confirmed";
  if (status === "observed") return "Observed";
  if (status === "conditional_candidate") return "Conditional";
  return "Unknown";
}

export function statusBadgeClass(status: FilesystemTopologySession["cwdState"]["status"]): string {
  if (status === "confirmed") return "border-success-border bg-success-subtle text-success";
  if (status === "conditional_candidate") return "border-warning-border bg-warning-subtle text-warning";
  if (status === "observed") return "border-info-border bg-info-subtle text-info";
  return "border-border bg-surface-subtle text-text-subtle";
}

export function isInitialSshEntry(event: SessionCwdHistoryEvent | null | undefined): boolean {
  if (!event) return false;
  return event.action === "entered" && (!event.fromPath || event.fromPath.toLowerCase() === "unknown");
}

export function formatFromPath(event: SessionCwdHistoryEvent | null | undefined): string {
  if (!event) return "Unknown";
  if (isInitialSshEntry(event)) {
    return "[SSH Login]";
  }
  return event.fromPath ?? "Unknown";
}

export function actionLabel(event: SessionCwdHistoryEvent): string {
  if (event.action === "entered") return "Entered directory";
  if (event.action === "failed_change") return "Directory change failed";
  return "Changed directory";
}


export type GraphNode = FilesystemTopologyNode & { x: number; y: number };
export type GraphElementSize = { width: number; height: number };
export type GraphElementBounds = GraphElementSize & { x: number; y: number };
export type GraphCallout = {
  sourceIp: string;
  sessionIds: string[];
  path: string;
};

export function pointForGraph(
  nodes: FilesystemTopologyNode[],
  sessions: FilesystemTopologySession[],
  selectedPath: string | null,
  isAuditMode = false,
): GraphNode[] {
  const byPath = new Map(nodes.map((node) => [node.path, node]));
  const included = new Set<string>(["/"]);
  const recentSessions = [...sessions].sort((left, right) => {
    return Date.parse(right.cwdState.observedAt ?? "") - Date.parse(left.cwdState.observedAt ?? "");
  }).slice(0, GRAPH_CALLOUT_LIMIT);
  const includePath = (path: string | null) => {
    let current = path;
    while (current) {
      included.add(current);
      current = byPath.get(current)?.parentPath ?? null;
    }
  };
  for (const session of recentSessions) includePath(session.cwdState.path);
  includePath(selectedPath);
  for (const node of [...nodes].sort((left, right) => Date.parse(right.observedAt ?? "") - Date.parse(left.observedAt ?? ""))) {
    if (included.size >= GRAPH_NODE_LIMIT) break;
    includePath(node.path);
  }

  const selected = nodes.filter((node) => included.has(node.path));
  const selectedByPath = new Map(selected.map((node) => [node.path, node]));
  const childrenByPath = new Map<string, FilesystemTopologyNode[]>();
  for (const node of selected) {
    if (!node.parentPath || !selectedByPath.has(node.parentPath)) continue;
    const children = childrenByPath.get(node.parentPath) ?? [];
    children.push(node);
    childrenByPath.set(node.parentPath, children);
  }
  for (const children of childrenByPath.values()) {
    children.sort((left, right) => left.path.localeCompare(right.path));
  }

  // Tidy tree assignment:
  // Each leaf receives an ordered horizontal index.
  // Each parent is centered over the midpoint of its first and last children.
  const horizontalByPath = new Map<string, number>();
  let leafIndex = 0;
  const assignHorizontalPosition = (path: string): number => {
    const children = childrenByPath.get(path) ?? [];
    if (!children.length) {
      const position = leafIndex;
      leafIndex += 1;
      horizontalByPath.set(path, position);
      return position;
    }
    const childPositions = children.map((child) => assignHorizontalPosition(child.path));
    const position = (childPositions[0] + childPositions[childPositions.length - 1]) / 2;
    horizontalByPath.set(path, position);
    return position;
  };

  if (selectedByPath.has("/")) assignHorizontalPosition("/");
  for (const node of [...selected].sort((left, right) => left.path.localeCompare(right.path))) {
    if (!horizontalByPath.has(node.path)) assignHorizontalPosition(node.path);
  }

  const maxDepth = Math.max(1, ...selected.map((node) => node.depth));
  const leafCount = Math.max(1, leafIndex);

  // Dynamic tree width:
  // Allocate generous horizontal separation between branches so nodes never crowd or overlap.
  let totalTreeWidth = 0;
  if (isAuditMode) {
    if (leafCount === 1) {
      totalTreeWidth = 0;
    } else if (leafCount === 2) {
      totalTreeWidth = 32;
    } else if (leafCount === 3) {
      totalTreeWidth = 46;
    } else if (leafCount === 4) {
      totalTreeWidth = 63;
    } else {
      totalTreeWidth = Math.min(72, (leafCount - 1) * 19);
    }
  } else {
    // Live mode: preserve outer lanes for IP callouts on both rails
    if (leafCount === 2) {
      totalTreeWidth = 28;
    } else if (leafCount === 3) {
      totalTreeWidth = 40;
    } else if (leafCount === 4) {
      totalTreeWidth = 48;
    } else if (leafCount > 4) {
      totalTreeWidth = Math.min(50, Math.max(46, (leafCount - 1) * 11));
    }
  }
  const treeLeft = 50 - totalTreeWidth / 2;

  // Consistent vertical step per depth level so nodes are never too close to parents
  // In Audit mode: allocate generous vertical spacing (18% - 26%) so folders, hop badges,
  // and active beacons have ample clear air.
  // In Live mode: allocate 14% - 20%.
  const depthStep = isAuditMode
    ? Math.min(26, Math.max(18, 64 / maxDepth))
    : Math.min(20, Math.max(14, 54 / maxDepth));
  const startY = isAuditMode ? 10 : 12;

  const positioned = selected.map((node) => {
    const leafPosition = horizontalByPath.get(node.path) ?? 0;
    const x = leafCount === 1 ? 50 : treeLeft + (totalTreeWidth * leafPosition) / (leafCount - 1);
    const y = startY + node.depth * depthStep;
    return { ...node, x, y };
  });

  // Intelligent horizontal clearance enforcement:
  // Ensure no two sibling or adjacent nodes at the same depth level are positioned closer
  // than the required button clearance width (minimum 21% in audit mode, 16% in live mode).
  const minClearance = isAuditMode ? 21 : 16;
  const byDepth = new Map<number, GraphNode[]>();
  for (const node of positioned) {
    const list = byDepth.get(node.depth) ?? [];
    list.push(node);
    byDepth.set(node.depth, list);
  }

  for (const list of byDepth.values()) {
    if (list.length <= 1) continue;
    list.sort((a, b) => a.x - b.x);
    for (let pass = 0; pass < 3; pass++) {
      let moved = false;
      for (let i = 0; i < list.length - 1; i++) {
        const a = list[i];
        const b = list[i + 1];
        const gap = b.x - a.x;
        if (gap < minClearance) {
          const needed = minClearance - gap;
          a.x = Math.max(12, a.x - needed / 2);
          b.x = Math.min(88, b.x + needed / 2);
          moved = true;
        }
      }
      if (!moved) break;
    }
  }

  return positioned;
}

export function calloutsForGraph(sessions: FilesystemTopologySession[], graphNodeByPath: Map<string, GraphNode>): GraphCallout[] {
  const groups = new Map<string, FilesystemTopologySession[]>();
  for (const session of sessions) {
    if (!session.cwdState.path) continue;
    let effectivePath: string | null = session.cwdState.path;
    while (effectivePath && !graphNodeByPath.has(effectivePath)) {
      const slashIndex = effectivePath.lastIndexOf("/");
      effectivePath = slashIndex <= 0 ? (slashIndex === 0 ? "/" : null) : effectivePath.slice(0, slashIndex);
    }
    if (!effectivePath || !graphNodeByPath.has(effectivePath)) continue;
    const group = groups.get(session.sourceIp) ?? [];
    group.push({ ...session, cwdState: { ...session.cwdState, path: effectivePath } });
    groups.set(session.sourceIp, group);
  }
  return [...groups.entries()]
    .map(([sourceIp, group]) => {
      const ordered = [...group].sort((left, right) => Date.parse(right.cwdState.observedAt ?? "") - Date.parse(left.cwdState.observedAt ?? ""));
      return { sourceIp, sessionIds: ordered.map((session) => session.sessionId), path: ordered[0].cwdState.path! };
    })
    .sort((left, right) => left.sourceIp.localeCompare(right.sourceIp, undefined, { numeric: true }))
    .slice(0, GRAPH_CALLOUT_LIMIT);
}

export function sourceRailPositions(
  callouts: GraphCallout[],
  graphNodeByPath: Map<string, GraphNode>,
  isAuditMode = false,
): Map<string, LabelPosition> {
  const leftRail: GraphCallout[] = [];
  const rightRail: GraphCallout[] = [];

  for (const [index, callout] of callouts.entries()) {
    const target = graphNodeByPath.get(callout.path);
    // In Audit Replay or when there is only 1 callout, always anchor on the RIGHT rail.
    // This keeps the IP callout steady and prevents it from jumping across the tree
    // between left and right rails when the attacker hops between directories.
    // When there are multiple callouts in Live mode:
    // - If target is centered, alternate between right and left rails.
    // - Otherwise, place on left rail if target is on the left (target.x < 50), else right rail.
    const isCentered = !target || Math.abs(target.x - 50) < 0.1;
    const useLeftRail =
      isAuditMode || callouts.length === 1
        ? false
        : isCentered
          ? index % 2 !== 0
          : target.x < 50;
    (useLeftRail ? leftRail : rightRail).push(callout);
  }

  // Rail rebalancing: if one rail is heavily loaded and the other is sparse,
  // balance callouts whose target directory is closest to center so lines don't cross.
  if (!isAuditMode) {
    while (rightRail.length - leftRail.length > 2) {
      let bestIdx = -1;
      let minX = Infinity;
      for (let i = 0; i < rightRail.length; i++) {
        const tx = graphNodeByPath.get(rightRail[i].path)?.x ?? 50;
        if (tx < minX) {
          minX = tx;
          bestIdx = i;
        }
      }
      if (bestIdx >= 0) {
        const [moved] = rightRail.splice(bestIdx, 1);
        leftRail.push(moved);
      } else break;
    }

    while (leftRail.length - rightRail.length > 2) {
      let bestIdx = -1;
      let maxX = -Infinity;
      for (let i = 0; i < leftRail.length; i++) {
        const tx = graphNodeByPath.get(leftRail[i].path)?.x ?? 50;
        if (tx > maxX) {
          maxX = tx;
          bestIdx = i;
        }
      }
      if (bestIdx >= 0) {
        const [moved] = leftRail.splice(bestIdx, 1);
        rightRail.push(moved);
      } else break;
    }
  }

  // Adaptive rail positions:
  // When both rails are occupied, use generous outer lanes (9% on left, 91% on right).
  // When only one rail is occupied (e.g. single-session audit mode), adaptively position the rail
  // closer to the tree envelope so that callouts feel connected to the cluster without giant voids.
  const nodeXs = [...graphNodeByPath.values()].map((n) => n.x);
  const minTreeX = nodeXs.length ? Math.min(...nodeXs) : 50;
  const maxTreeX = nodeXs.length ? Math.max(...nodeXs) : 50;

  let leftRailX = 9;
  let rightRailX = 91;

  if (leftRail.length === 0 && rightRail.length <= 2) {
    rightRailX = Math.min(88, Math.max(82, maxTreeX + 22));
  } else if (rightRail.length === 0 && leftRail.length <= 2) {
    leftRailX = Math.max(12, Math.min(18, minTreeX - 22));
  }

  const positions = new Map<string, LabelPosition>();

  const placeOnRail = (rail: GraphCallout[], x: number) => {
    if (!rail.length) return;
    const isRightRail = x > 50;
    // The bottom-right corner houses the minimap (approx y >= 70% in the right corner).
    // To avoid overlapping the minimap upon auto-arrange or reset, right-rail callouts are capped at y <= 66%.
    const maxRailY = isRightRail ? 66 : 82;

    rail.sort((left, right) => {
      const leftY = graphNodeByPath.get(left.path)?.y ?? 50;
      const rightY = graphNodeByPath.get(right.path)?.y ?? 50;
      return leftY - rightY || left.sourceIp.localeCompare(right.sourceIp, undefined, { numeric: true });
    });

    if (rail.length === 1) {
      // In Audit mode: keep callout vertically steady at the vertical center of the tree
      // so the card stays calm and stationary while stepping through hops during replay.
      // In Live mode: gently level with the active directory row.
      const nodeYs = [...graphNodeByPath.values()].map((n) => n.y);
      const avgTreeY = nodeYs.length ? (Math.min(...nodeYs) + Math.max(...nodeYs)) / 2 : 50;
      let targetY = isAuditMode
        ? Math.min(maxRailY, Math.max(22, avgTreeY))
        : graphNodeByPath.get(rail[0].path)?.y ?? 50;

      // In Audit mode: if any directory node on this rail's side is at a similar Y (within 11%),
      // offset targetY so the card doesn't level horizontally right next to that folder!
      if (isAuditMode) {
        const hasNearbyNodeOnSide = [...graphNodeByPath.values()].some(
          (n) => (isRightRail ? n.x > 66 : n.x < 34) && Math.abs(n.y - targetY) < 11,
        );
        if (hasNearbyNodeOnSide) {
          targetY = targetY + 14 <= maxRailY ? targetY + 14 : targetY - 14;
        }
      }

      positions.set(rail[0].sourceIp, { x, y: Math.min(maxRailY, Math.max(18, targetY)) });
      return;
    }

    // When a rail has 4 or more callouts, use staggered double columns (outer lane & inner lane)
    // to guarantee generous clearance and eliminate crowding
    const useDoubleColumn = rail.length >= 4;
    const innerX = isRightRail ? Math.max(73, x - 16) : Math.min(27, x + 16);

    const minGap = useDoubleColumn ? 11.5 : 14.0;
    const count = rail.length;
    const targetYs = rail.map((c) => Math.min(maxRailY, Math.max(18, graphNodeByPath.get(c.path)?.y ?? 50)));

    const ys = [...targetYs];
    for (let i = 1; i < count; i++) {
      if (ys[i] < ys[i - 1] + minGap) {
        ys[i] = ys[i - 1] + minGap;
      }
    }

    if (ys[count - 1] > maxRailY) {
      ys[count - 1] = maxRailY;
      for (let i = count - 2; i >= 0; i--) {
        if (ys[i] > ys[i + 1] - minGap) {
          ys[i] = ys[i + 1] - minGap;
        }
      }
    }

    // Defensive forward relaxation: if upward adjustment pushed ys[0] below min boundary (16%),
    // clamp ys[0] = 16 and re-propagate minGap downwards so no cards are squeezed
    if (ys[0] < 16) {
      ys[0] = 16;
      for (let i = 1; i < count; i++) {
        if (ys[i] < ys[i - 1] + minGap) {
          ys[i] = ys[i - 1] + minGap;
        }
      }
    }

    rail.forEach((callout, index) => {
      const calloutX = useDoubleColumn && index % 2 !== 0 ? innerX : x;
      positions.set(callout.sourceIp, { x: calloutX, y: ys[index] });
    });
  };

  placeOnRail(leftRail, leftRailX);
  placeOnRail(rightRail, rightRailX);
  return positions;
}

/**
 * Callout position resolver:
 * Gives users complete freedom to position nodes without unexpected system interference or pushing.
 * Seeds callouts with manual coordinates if dragged, or automatic rail coordinates if unplaced.
 */
export function resolveCalloutPositions(
  callouts: GraphCallout[],
  automaticPositions: Map<string, LabelPosition>,
  manualPositions: Record<string, LabelPosition>,
): Map<string, LabelPosition> {
  const resolved = new Map<string, LabelPosition>();

  for (const [index, callout] of callouts.entries()) {
    const autoPos = automaticPositions.get(callout.sourceIp) ?? { x: index % 2 === 0 ? 10 : 90, y: 50 };
    const manualPos = manualPositions[callout.sourceIp];
    resolved.set(callout.sourceIp, manualPos ? { ...manualPos } : { ...autoPos });
  }

  return resolved;
}

export function leaderEndpoints(
  node: GraphNode,
  label: LabelPosition,
  nodeBounds?: GraphElementBounds,
  sourceBounds?: GraphElementBounds,
): { startX: number; startY: number; endX: number; endY: number } {
  // Always anchor to the exact mathematical center of node and label
  const nodeCenterX = node.x;
  const nodeCenterY = node.y;
  const sourceCenterX = label.x;
  const sourceCenterY = label.y;
  const deltaX = sourceCenterX - nodeCenterX;
  const deltaY = sourceCenterY - nodeCenterY;
  if (deltaX === 0 && deltaY === 0) {
    return { startX: nodeCenterX, startY: nodeCenterY, endX: sourceCenterX, endY: sourceCenterY };
  }

  // Directory labels are content-sized, while source labels have a fixed 11rem width.
  const segLen = directorySegment(node.path).length;
  const nodeHalfWidth = nodeBounds?.width ? nodeBounds.width / 2 : Math.min(6.2, Math.max(2.8, 2.2 + segLen * 0.32));
  const nodeHalfHeight = nodeBounds?.height ? nodeBounds.height / 2 : 2.5;
  const sourceHalfWidth = sourceBounds?.width ? sourceBounds.width / 2 : 6.0;
  const sourceHalfHeight = sourceBounds?.height ? sourceBounds.height / 2 : 2.8;

  const nodeScale = 1 / Math.max(Math.abs(deltaX) / nodeHalfWidth, Math.abs(deltaY) / nodeHalfHeight);
  const labelScale = 1 / Math.max(Math.abs(deltaX) / sourceHalfWidth, Math.abs(deltaY) / sourceHalfHeight);
  return {
    startX: nodeCenterX + deltaX * Math.min(1, nodeScale),
    startY: nodeCenterY + deltaY * Math.min(1, nodeScale),
    endX: sourceCenterX - deltaX * Math.min(1, labelScale),
    endY: sourceCenterY - deltaY * Math.min(1, labelScale),
  };
}

/**
 * Materializes the complete historical directory tree touched by a specific session.
 * This ensures that even paths that the attacker exited via 'cd ..' or lateral jumps
 * remain fully visible and interconnected on the audit canvas.
 */
export function buildAuditSnapshot(
  baseSnapshot: FilesystemTopologySnapshot | null,
  session: FilesystemTopologySession | FilesystemClosedSession | null,
  history: SessionCwdHistoryEvent[],
): FilesystemTopologySnapshot {
  if (!session) {
    return (
      baseSnapshot ?? {
        nodes: [],
        sessions: [],
        recentClosedSessions: [],
        truncated: false,
        generatedAt: new Date().toISOString(),
      }
    );
  }

  const nodesMap = new Map<string, FilesystemTopologyNode>();

  const registerPath = (rawPath: string | null, observedAt: string | null) => {
    if (!rawPath || !rawPath.startsWith("/")) return;
    const segments = rawPath.split("/").filter(Boolean);
    const paths = ["/"];
    let current = "";
    for (const segment of segments) {
      current += `/${segment}`;
      paths.push(current);
    }

    for (const p of paths) {
      const existing = nodesMap.get(p);
      if (existing) {
        if (!existing.sessionIds.includes(session.sessionId)) {
          existing.sessionIds.push(session.sessionId);
        }
        if (observedAt && (!existing.observedAt || observedAt > existing.observedAt)) {
          existing.observedAt = observedAt;
        }
      } else {
        const segs = p.split("/").filter(Boolean);
        const parentPath = p === "/" ? null : segs.length > 1 ? `/${segs.slice(0, -1).join("/")}` : "/";
        nodesMap.set(p, {
          path: p,
          parentPath,
          depth: p === "/" ? 0 : segs.length,
          sessionIds: [session.sessionId],
          observedAt,
        });
      }
    }
  };

  // 1. Register session's cwdState path
  registerPath(session.cwdState.path, session.cwdState.observedAt);

  // 2. Register all paths from history events (only toPath for non-failed moves to avoid typo nodes)
  for (const event of history) {
    registerPath(event.fromPath, event.at);
    if (event.action !== "failed_change") {
      registerPath(event.toPath, event.at);
    }
  }

  // 3. Guarantee root node exists
  if (!nodesMap.has("/")) {
    nodesMap.set("/", {
      path: "/",
      parentPath: null,
      depth: 0,
      sessionIds: [session.sessionId],
      observedAt: session.cwdState.observedAt,
    });
  }

  return {
    nodes: [...nodesMap.values()].sort((a, b) => a.path.localeCompare(b.path)),
    sessions: [
      {
        sessionId: session.sessionId,
        sourceIp: session.sourceIp,
        cwdState: session.cwdState,
      },
    ],
    recentClosedSessions: [],
    truncated: false,
    generatedAt: new Date().toISOString(),
  };
}

