import type {
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

export const INSPECTOR_PAGE_SIZE = 12;
export const GRAPH_CALLOUT_LIMIT = 8;
export const GRAPH_NODE_LIMIT = 42;
export const LABEL_LAYOUT_STORAGE_KEY = "pti-filesystem-label-layout-v1";
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

export function pointForGraph(nodes: FilesystemTopologyNode[], sessions: FilesystemTopologySession[], selectedPath: string | null): GraphNode[] {
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
  // Keep tree envelope bounded between 27% and 73% so dedicated rail margin lanes have at least 18-25% clearance.
  const minSlotGap = 10;
  const maxSlotGap = 16;
  const naturalWidth = (leafCount - 1) * maxSlotGap;
  const totalTreeWidth = leafCount === 1 ? 0 : Math.min(46, Math.max((leafCount - 1) * minSlotGap, naturalWidth));
  const treeLeft = 50 - totalTreeWidth / 2;

  // Consistent vertical step per depth level so nodes are never too far from parent
  const idealDepthStep = 14;
  const maxVerticalSpan = 72;
  const verticalSpan = Math.min(maxVerticalSpan, Math.max(idealDepthStep, maxDepth * idealDepthStep));
  const depthStep = verticalSpan / maxDepth;
  const startY = 10;

  return selected.map((node) => {
    const leafPosition = horizontalByPath.get(node.path) ?? 0;
    const x = leafCount === 1 ? 50 : treeLeft + (totalTreeWidth * leafPosition) / (leafCount - 1);
    const y = startY + node.depth * depthStep;
    return { ...node, x, y };
  });
}

export function calloutsForGraph(sessions: FilesystemTopologySession[], graphNodeByPath: Map<string, GraphNode>): GraphCallout[] {
  const groups = new Map<string, FilesystemTopologySession[]>();
  for (const session of sessions) {
    if (!session.cwdState.path || !graphNodeByPath.has(session.cwdState.path)) continue;
    const group = groups.get(session.sourceIp) ?? [];
    group.push(session);
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

export function sourceRailPositions(callouts: GraphCallout[], graphNodeByPath: Map<string, GraphNode>): Map<string, LabelPosition> {
  const leftRail: GraphCallout[] = [];
  const rightRail: GraphCallout[] = [];

  for (const [index, callout] of callouts.entries()) {
    const target = graphNodeByPath.get(callout.path);
    // A source whose target is centered alternates rails.
    const useLeftRail = !target || Math.abs(target.x - 50) < 0.1 ? index % 2 === 0 : target.x < 50;
    (useLeftRail ? leftRail : rightRail).push(callout);
  }

  // Dedicated outer margin lanes: 9% on the left, 91% on the right.
  // With the tree envelope constrained within 27%-73%, this guarantees >= 18% horizontal clearance on all screens.
  const leftRailX = 9;
  const rightRailX = 91;

  const positions = new Map<string, LabelPosition>();

  const placeOnRail = (rail: GraphCallout[], x: number) => {
    if (!rail.length) return;

    rail.sort((left, right) => {
      const leftY = graphNodeByPath.get(left.path)?.y ?? 50;
      const rightY = graphNodeByPath.get(right.path)?.y ?? 50;
      return leftY - rightY || left.sourceIp.localeCompare(right.sourceIp, undefined, { numeric: true });
    });

    if (rail.length === 1) {
      const targetY = graphNodeByPath.get(rail[0].path)?.y ?? 50;
      positions.set(rail[0].sourceIp, { x, y: Math.min(80, Math.max(18, targetY)) });
      return;
    }

    // Multiple callouts: enforce minimum vertical separation of at least 13%
    const minGap = 13;
    const count = rail.length;
    const targetYs = rail.map((c) => Math.min(82, Math.max(18, graphNodeByPath.get(c.path)?.y ?? 50)));

    const ys = [...targetYs];
    for (let i = 1; i < count; i++) {
      if (ys[i] < ys[i - 1] + minGap) {
        ys[i] = ys[i - 1] + minGap;
      }
    }

    if (ys[count - 1] > 84) {
      ys[count - 1] = 84;
      for (let i = count - 2; i >= 0; i--) {
        if (ys[i] > ys[i + 1] - minGap) {
          ys[i] = ys[i + 1] - minGap;
        }
      }
    }

    rail.forEach((callout, index) => {
      positions.set(callout.sourceIp, { x, y: Math.max(16, ys[index]) });
    });
  };

  placeOnRail(leftRail, leftRailX);
  placeOnRail(rightRail, rightRailX);
  return positions;
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
