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
export type MapMetrics = { surfaceWidth: number; surfaceHeight: number; planeWidth: number; planeHeight: number; planeLeft: number; planeTop: number };

export const INSPECTOR_PAGE_SIZE = 12;
export const GRAPH_CALLOUT_LIMIT = 8;
export const GRAPH_NODE_LIMIT = 42;
export const LABEL_LAYOUT_STORAGE_KEY = "pti-filesystem-label-layout-v1";
export const MAP_MIN_ZOOM = 0.6;
export const MAP_MAX_ZOOM = 1.6;

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

export function snapLabelPosition(position: LabelPosition): LabelPosition {
  return {
    x: Math.min(94, Math.max(6, Math.round(position.x / 2) * 2)),
    y: Math.min(94, Math.max(6, Math.round(position.y / 2) * 2)),
  };
}

export type GraphNode = FilesystemTopologyNode & { x: number; y: number };
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
  const maxDepth = Math.max(1, ...selected.map((node) => node.depth));
  const levels = new Map<number, FilesystemTopologyNode[]>();
  for (const node of selected) {
    const group = levels.get(node.depth) ?? [];
    group.push(node);
    levels.set(node.depth, group);
  }
  return selected.map((node) => {
    const level = [...(levels.get(node.depth) ?? [])].sort((left, right) => left.path.localeCompare(right.path));
    const index = level.findIndex((item) => item.path === node.path);
    const x = level.length === 1 ? 50 : 9 + (82 * index) / (level.length - 1);
    const y = 13 + (72 * node.depth) / maxDepth;
    return { ...node, x, y };
  });
}

export function calloutsForGraph(sessions: FilesystemTopologySession[], graphNodeByPath: Map<string, GraphNode>, selectedSessionId: string | null): GraphCallout[] {
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
    .sort((left, right) => {
      const leftSelected = left.sessionIds.includes(selectedSessionId ?? "");
      const rightSelected = right.sessionIds.includes(selectedSessionId ?? "");
      if (leftSelected !== rightSelected) return leftSelected ? -1 : 1;
      const leftObservedAt = sessions.find((session) => session.sessionId === left.sessionIds[0])?.cwdState.observedAt ?? "";
      const rightObservedAt = sessions.find((session) => session.sessionId === right.sessionIds[0])?.cwdState.observedAt ?? "";
      return Date.parse(rightObservedAt) - Date.parse(leftObservedAt);
    })
    .slice(0, GRAPH_CALLOUT_LIMIT);
}

export function calloutSlot(index: number, count: number): { left: boolean; x: number; y: number } {
  const left = index % 2 === 0;
  const slotsPerSide = Math.max(1, Math.ceil(count / 2));
  const slot = Math.floor(index / 2);
  return {
    left,
    x: left ? 10 : 90,
    y: slotsPerSide === 1 ? 50 : 16 + (68 * slot) / (slotsPerSide - 1),
  };
}

export function leaderEndpoints(node: GraphNode, label: LabelPosition): { startX: number; startY: number; endX: number; endY: number } {
  const deltaX = label.x - node.x;
  const deltaY = label.y - node.y;
  if (deltaX === 0 && deltaY === 0) return { startX: node.x, startY: node.y, endX: label.x, endY: label.y };
  const nodeScale = 1 / Math.max(Math.abs(deltaX) / 8, Math.abs(deltaY) / 3.5);
  const labelScale = 1 / Math.max(Math.abs(deltaX) / 9, Math.abs(deltaY) / 4);
  return {
    startX: node.x + deltaX * nodeScale,
    startY: node.y + deltaY * nodeScale,
    endX: label.x - deltaX * labelScale,
    endY: label.y - deltaY * labelScale,
  };
}
