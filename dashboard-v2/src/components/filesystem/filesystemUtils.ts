import type { RegionStatus } from "@/components/ui/RegionState";
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

export function clampTimelineSidebarWidth(targetWidth: number, viewportWidth?: number): number {
  if (!Number.isFinite(targetWidth)) return DEFAULT_TIMELINE_SIDEBAR_WIDTH;
  const maxAllowed = viewportWidth && Number.isFinite(viewportWidth)
    ? Math.min(MAX_TIMELINE_SIDEBAR_WIDTH, Math.floor(viewportWidth * 0.65))
    : MAX_TIMELINE_SIDEBAR_WIDTH;
  const effectiveMax = Math.max(MIN_TIMELINE_SIDEBAR_WIDTH, maxAllowed);
  return Math.max(MIN_TIMELINE_SIDEBAR_WIDTH, Math.min(effectiveMax, Math.round(targetWidth)));
}

export function getMotionDuration(shouldReduceMotion: boolean, normalDuration = 0.55): number {
  return shouldReduceMotion ? 0 : normalDuration;
}

export function isSnapshot(value: unknown): value is FilesystemTopologySnapshot {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Partial<FilesystemTopologySnapshot>;
  const hasAuditSummary = (session: unknown) => {
    if (!session || typeof session !== "object") return false;
    const summary = (session as Partial<FilesystemTopologySession>).auditSummary;
    return Boolean(summary && Array.isArray(summary.visitedPaths) && typeof summary.homeOnly === "boolean" &&
      typeof summary.eventCount === "number");
  };
  return Array.isArray(candidate.nodes) && Array.isArray(candidate.sessions) && candidate.sessions.every(hasAuditSummary) &&
    Array.isArray(candidate.recentClosedSessions) && candidate.recentClosedSessions.every(hasAuditSummary) &&
    typeof candidate.truncated === "boolean" && typeof candidate.generatedAt === "string";
}

export function isHistoryPage(value: unknown): value is SessionCwdHistoryPage {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Partial<SessionCwdHistoryPage>;
  return Array.isArray(candidate.items) && (typeof candidate.nextCursor === "string" || candidate.nextCursor === null) &&
    Number.isSafeInteger(candidate.totalItems) && (candidate.totalItems ?? -1) >= 0 &&
    Number.isSafeInteger(candidate.totalSuccessfulItems) && (candidate.totalSuccessfulItems ?? -1) >= 0 &&
    (candidate.totalSuccessfulItems ?? 1) <= (candidate.totalItems ?? 0) &&
    typeof candidate.complete === "boolean";
}

export interface HistoryWindowMetrics {
  totalItems: number;
  loadedItems: number;
  unloadedItems: number;
  indexOffset: number;
  selectedNumber: number;
}

/**
 * Maps a selected index in the newest loaded history window to its stable,
 * one-based position in the complete retained route.
 */
export function getHistoryWindowMetrics(
  loadedItems: number,
  reportedTotalItems: number,
  selectedIndex: number,
): HistoryWindowMetrics {
  const safeLoadedItems = Math.max(0, Math.trunc(loadedItems));
  const totalItems = Math.max(safeLoadedItems, Math.trunc(reportedTotalItems));
  const indexOffset = totalItems - safeLoadedItems;
  return {
    totalItems,
    loadedItems: safeLoadedItems,
    unloadedItems: indexOffset,
    indexOffset,
    selectedNumber: selectedIndex >= 0 ? indexOffset + selectedIndex + 1 : 0,
  };
}

export function formatTimestamp(value: string | null): string {
  if (!value) return "No timestamp";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "No timestamp";
  return new Intl.DateTimeFormat("en-GB", { dateStyle: "medium", timeStyle: "medium" }).format(date);
}

/**
 * Format a duration in milliseconds into a concise forensic time delta.
 */
export function formatTimeDelta(ms: number): string {
  if (!Number.isFinite(ms) || ms <= 0) return "0s";
  if (ms < 1000) return "<1s";
  const totalSeconds = Math.round(ms / 1000);
  if (totalSeconds < 60) return `${totalSeconds}s`;
  const totalMinutes = Math.floor(totalSeconds / 60);
  const remainingSeconds = totalSeconds % 60;
  if (totalMinutes < 60) {
    return `${totalMinutes}m ${String(remainingSeconds).padStart(2, "0")}s`;
  }
  const totalHours = Math.floor(totalMinutes / 60);
  const remainingMinutes = totalMinutes % 60;
  if (totalHours < 24) {
    return `${totalHours}h ${String(remainingMinutes).padStart(2, "0")}m`;
  }
  const totalDays = Math.floor(totalHours / 24);
  const remainingHours = totalHours % 24;
  return `${totalDays}d ${String(remainingHours).padStart(2, "0")}h`;
}

/**
 * Format relative elapsed time (e.g. from session start) in mm:ss or hh:mm:ss.
 */
export function formatElapsedTime(ms: number): string {
  if (!Number.isFinite(ms) || ms <= 0) return "+00:00";
  const totalSeconds = Math.floor(ms / 1000);
  const seconds = totalSeconds % 60;
  const totalMinutes = Math.floor(totalSeconds / 60);
  const minutes = totalMinutes % 60;
  const hours = Math.floor(totalMinutes / 60);
  if (hours > 0) {
    return `+${String(hours).padStart(2, "0")}:${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}`;
  }
  return `+${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}`;
}

export interface HopTimeMetrics {
  eventId: string;
  deltaMs: number;
  formattedDelta: string;
  elapsedMs: number;
  formattedElapsed: string;
  timeProgressPercent: number;
}

export interface SessionReplayTimeSummary {
  totalDurationMs: number;
  formattedTotalDuration: string;
  currentElapsedMs: number;
  formattedCurrentElapsed: string;
  currentDeltaMs: number;
  formattedCurrentDelta: string;
  timeProgressPercent: number;
}

/**
 * Calculates per-hop time deltas and cumulative elapsed times for a chronological history list.
 */
export function calculateHistoryTimeMetrics(
  displayedHistory: readonly SessionCwdHistoryEvent[],
  selectedIndex: number,
): {
  hopMetrics: HopTimeMetrics[];
  summary: SessionReplayTimeSummary;
} {
  if (!displayedHistory.length) {
    return {
      hopMetrics: [],
      summary: {
        totalDurationMs: 0,
        formattedTotalDuration: "0s",
        currentElapsedMs: 0,
        formattedCurrentElapsed: "+00:00",
        currentDeltaMs: 0,
        formattedCurrentDelta: "0s",
        timeProgressPercent: 0,
      },
    };
  }

  const parsedTimes = displayedHistory.map((ev) => (ev.at ? new Date(ev.at).getTime() : NaN));
  const validTimes = parsedTimes.filter((t) => Number.isFinite(t));
  const firstTime = validTimes.length > 0 ? validTimes[0] : NaN;
  const lastTime = validTimes.length > 0 ? validTimes[validTimes.length - 1] : NaN;
  const totalDurationMs = Number.isFinite(firstTime) && Number.isFinite(lastTime) ? Math.max(0, lastTime - firstTime) : 0;

  const hopMetrics: HopTimeMetrics[] = [];
  let prevTime = firstTime;

  for (let i = 0; i < displayedHistory.length; i++) {
    const ev = displayedHistory[i];
    const currTime = parsedTimes[i];
    let deltaMs = 0;
    let elapsedMs = 0;

    if (Number.isFinite(currTime) && Number.isFinite(firstTime)) {
      if (i > 0 && Number.isFinite(prevTime)) {
        deltaMs = Math.max(0, currTime - prevTime);
      }
      elapsedMs = Math.max(0, currTime - firstTime);
      prevTime = currTime;
    }

    const timeProgressPercent =
      totalDurationMs > 0
        ? Math.min(100, Math.max(0, (elapsedMs / totalDurationMs) * 100))
        : displayedHistory.length > 1
          ? (i / (displayedHistory.length - 1)) * 100
          : 0;

    hopMetrics.push({
      eventId: ev.id,
      deltaMs,
      formattedDelta: formatTimeDelta(deltaMs),
      elapsedMs,
      formattedElapsed: formatElapsedTime(elapsedMs),
      timeProgressPercent,
    });
  }

  const safeIndex = Math.max(0, Math.min(displayedHistory.length - 1, selectedIndex >= 0 ? selectedIndex : 0));
  const currentMetric = hopMetrics[safeIndex] ?? {
    eventId: displayedHistory[safeIndex]?.id ?? "",
    deltaMs: 0,
    formattedDelta: "0s",
    elapsedMs: 0,
    formattedElapsed: "+00:00",
    timeProgressPercent: 0,
  };

  const summary: SessionReplayTimeSummary = {
    totalDurationMs,
    formattedTotalDuration: formatTimeDelta(totalDurationMs),
    currentElapsedMs: currentMetric.elapsedMs,
    formattedCurrentElapsed: currentMetric.formattedElapsed,
    currentDeltaMs: currentMetric.deltaMs,
    formattedCurrentDelta: currentMetric.formattedDelta,
    timeProgressPercent: currentMetric.timeProgressPercent,
  };

  return { hopMetrics, summary };
}

export type ReplayPacingMode = "realistic" | "uniform";

/**
 * Calculates playback delay based on pacing mode and real event dwell delta.
 * In "uniform" mode: returns fixed playbackSpeed (e.g. 1400ms or 700ms).
 * In "realistic" mode: returns dynamic delay clamped between 300ms and 3200ms.
 */
export function calculateReplayPacingDelay(
  deltaMs: number,
  playbackSpeed: number,
  pacingMode: ReplayPacingMode = "realistic",
): number {
  if (pacingMode === "uniform") {
    return playbackSpeed;
  }

  const speedFactor = playbackSpeed === 700 ? 2 : 1;
  const safeDelta = Math.max(0, Number.isFinite(deltaMs) ? deltaMs : 0);

  let unscaledDelay: number;
  if (safeDelta <= 1000) {
    unscaledDelay = 600;
  } else if (safeDelta <= 10_000) {
    unscaledDelay = 600 + (safeDelta / 10_000) * 800;
  } else if (safeDelta <= 60_000) {
    unscaledDelay = 1400 + (Math.log10(safeDelta / 10_000) / Math.log10(6)) * 800;
  } else {
    unscaledDelay = 2200 + Math.min(1000, Math.log10(safeDelta / 60_000) * 500);
  }

  const finalDelay = Math.round(unscaledDelay / speedFactor);
  return Math.min(3200, Math.max(300, finalDelay));
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


export type TopologyDensityMode = "detailed" | "clustered" | "aggregated";
export type TopologyDensityPreference = "auto" | TopologyDensityMode;

export interface DensityThresholds {
  detailedMaxNodes: number;
  detailedMaxSources: number;
  clusteredMaxNodes: number;
  clusteredMaxSources: number;
}

export const DEFAULT_DENSITY_THRESHOLDS: DensityThresholds = {
  detailedMaxNodes: 15,
  detailedMaxSources: 4,
  clusteredMaxNodes: 42,
  clusteredMaxSources: 10,
};

export interface TopologyDensityAnalysis {
  mode: TopologyDensityMode;
  isAuto: boolean;
  totalNodes: number;
  renderedNodes: number;
  hiddenNodes: number;
  totalSources: number;
  renderedSources: number;
  hiddenSources: number;
  hasAggregatedBranches: boolean;
  focusedBranchPath: string | null;
}

export type GraphNode = FilesystemTopologyNode & {
  x: number;
  y: number;
  hiddenChildCount?: number;
  isAggregated?: boolean;
};
export type GraphElementSize = { width: number; height: number };
export type GraphElementBounds = GraphElementSize & { x: number; y: number };

export interface GraphCalloutSession {
  sessionId: string;
  path: string;
  observedAt: string | null;
}

export type GraphCallout = {
  sourceIp: string;
  sessionIds: string[];
  path: string;
  sessions: GraphCalloutSession[];
  targetPaths: string[];
};

export interface PointForGraphOptions {
  nodeLimit?: number | null;
  selectedSessionId?: string | null;
  densityMode?: TopologyDensityMode;
  focusedPath?: string | null;
}

export function pointForGraph(
  nodes: FilesystemTopologyNode[],
  sessions: FilesystemTopologySession[],
  selectedPath: string | null,
  isAuditMode = false,
  options?: PointForGraphOptions,
): GraphNode[] {
  const densityMode = options?.densityMode ?? "clustered";
  const focusedPath = options?.focusedPath ?? selectedPath ?? null;

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
  if (options?.selectedSessionId) {
    const selectedSession = sessions.find((session) => session.sessionId === options.selectedSessionId);
    if (selectedSession?.cwdState?.path) {
      includePath(selectedSession.cwdState.path);
    }
  }

  if (densityMode === "detailed") {
    const effectiveLimit = options?.nodeLimit !== undefined ? options.nodeLimit : null;
    for (const node of [...nodes].sort((left, right) => Date.parse(right.observedAt ?? "") - Date.parse(left.observedAt ?? ""))) {
      if (effectiveLimit !== null && included.size >= effectiveLimit) break;
      includePath(node.path);
    }
  } else if (densityMode === "aggregated") {
    // Aggregated mode:
    // 1) Expand on focus: If focusedPath is given, expand its whole subtree!
    if (focusedPath) {
      includePath(focusedPath);
      const prefix = focusedPath === "/" ? "/" : `${focusedPath}/`;
      for (const node of nodes) {
        if (node.path.startsWith(prefix)) {
          includePath(node.path);
        }
      }
    }

    // 2) Keep primary hubs at depth <= 1 (root's immediate children)
    for (const node of nodes) {
      if (node.depth <= 1) {
        includePath(node.path);
      }
    }

    // 3) Respect explicit nodeLimit if specified
    if (options?.nodeLimit) {
      const sorted = [...nodes].sort((a, b) => Date.parse(b.observedAt ?? "") - Date.parse(a.observedAt ?? ""));
      for (const node of sorted) {
        if (included.size >= options.nodeLimit) break;
        includePath(node.path);
      }
    }
  } else {
    // Clustered mode (balanced default):
    const effectiveLimit =
      options?.nodeLimit !== undefined
        ? options.nodeLimit
        : isAuditMode
          ? null
          : GRAPH_NODE_LIMIT;

    for (const node of [...nodes].sort((left, right) => Date.parse(right.observedAt ?? "") - Date.parse(left.observedAt ?? ""))) {
      if (effectiveLimit !== null && included.size >= effectiveLimit) break;
      includePath(node.path);
    }
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
  // Allocate generous horizontal separation between branches while strictly preserving
  // clear outer lanes (0-20% and 80-100%) for IP callouts and attacker sources.
  let totalTreeWidth = 0;
  if (leafCount === 1) {
    totalTreeWidth = 0;
  } else if (leafCount === 2) {
    totalTreeWidth = isAuditMode ? 28 : 26;
  } else if (leafCount === 3) {
    totalTreeWidth = isAuditMode ? 40 : 38;
  } else if (leafCount === 4) {
    totalTreeWidth = isAuditMode ? 55 : 48;
  } else {
    totalTreeWidth = isAuditMode
      ? Math.min(58, (leafCount - 1) * 18.5)
      : Math.min(52, Math.max(46, (leafCount - 1) * 10));
  }
  const treeLeft = 50 - totalTreeWidth / 2;

  // Dynamic vertical auto-fit:
  // Dynamically scale vertical depthStep to fit the entire tree within the visible canvas (12% to 82%).
  // Prevents deep directory chains (5-7+ levels deep) from running off the bottom edge of the canvas.
  const targetAvailableHeight = isAuditMode ? 70 : 66;
  const rawStep = targetAvailableHeight / maxDepth;
  const depthStep = isAuditMode
    ? Math.min(24, Math.max(10.5, rawStep))
    : Math.min(20, Math.max(9.5, rawStep));
  const startY = 12;

  const positioned = selected.map((node) => {
    const leafPosition = horizontalByPath.get(node.path) ?? 0;
    const x = leafCount === 1 ? 50 : treeLeft + (totalTreeWidth * leafPosition) / (leafCount - 1);
    const y = startY + node.depth * depthStep;

    const prefix = node.path === "/" ? "/" : `${node.path}/`;
    const totalDescendants = nodes.filter((n) => n.path !== node.path && n.path.startsWith(prefix)).length;
    const renderedDescendants = selected.filter((n) => n.path !== node.path && n.path.startsWith(prefix)).length;
    const hiddenChildCount = Math.max(0, totalDescendants - renderedDescendants);
    const isAggregated = hiddenChildCount > 0;

    return {
      ...node,
      x,
      y,
      hiddenChildCount,
      isAggregated,
    };
  });

  // Intelligent horizontal clearance enforcement:
  // Ensure no two sibling or adjacent nodes at the same depth level are positioned closer
  // than the required button clearance width (minimum 18.5% in audit mode, 15.5% in live mode).
  const minClearance = isAuditMode ? 18.5 : 15.5;
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
          a.x = Math.max(14, a.x - needed / 2);
          b.x = Math.min(86, b.x + needed / 2);
          moved = true;
        }
      }
      if (!moved) break;
    }
  }

  return positioned;
}

export interface CalloutsForGraphOptions {
  calloutLimit?: number | null;
  selectedSessionId?: string | null;
  densityMode?: TopologyDensityMode;
}

export function calloutsForGraph(
  sessions: FilesystemTopologySession[],
  graphNodeByPath: Map<string, GraphNode>,
  options?: CalloutsForGraphOptions,
): GraphCallout[] {
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
  const allCallouts: GraphCallout[] = [...groups.entries()]
    .map(([sourceIp, group]) => {
      const ordered = [...group].sort((left, right) => Date.parse(right.cwdState.observedAt ?? "") - Date.parse(left.cwdState.observedAt ?? ""));
      const clusterSessions: GraphCalloutSession[] = ordered.map((s) => ({
        sessionId: s.sessionId,
        path: s.cwdState.path!,
        observedAt: s.cwdState.observedAt,
      }));
      const distinctPaths = [...new Set(clusterSessions.map((s) => s.path))];
      return {
        sourceIp,
        sessionIds: ordered.map((session) => session.sessionId),
        path: ordered[0].cwdState.path!,
        sessions: clusterSessions,
        targetPaths: distinctPaths,
      };
    })
    .sort((left, right) => left.sourceIp.localeCompare(right.sourceIp, undefined, { numeric: true }));

  const defaultLimit =
    options?.densityMode === "detailed"
      ? null
      : options?.densityMode === "aggregated"
        ? 6
        : GRAPH_CALLOUT_LIMIT;

  const limit = options?.calloutLimit !== undefined ? options.calloutLimit : defaultLimit;
  if (limit === null || allCallouts.length <= limit) {
    return allCallouts;
  }

  const slice = allCallouts.slice(0, limit);
  if (options?.selectedSessionId) {
    const isSelectedInSlice = slice.some((c) => c.sessionIds.includes(options.selectedSessionId!));
    if (!isSelectedInSlice) {
      const selectedCallout = allCallouts.find((c) => c.sessionIds.includes(options.selectedSessionId!));
      if (selectedCallout) {
        slice[slice.length - 1] = selectedCallout;
        slice.sort((left, right) => left.sourceIp.localeCompare(right.sourceIp, undefined, { numeric: true }));
      }
    }
  }
  return slice;
}

export function sourceRailPositions(
  callouts: GraphCallout[],
  graphNodeByPath: Map<string, GraphNode>,
  isAuditMode = false,
): Map<string, LabelPosition> {
  const leftRail: GraphCallout[] = [];
  const rightRail: GraphCallout[] = [];

  for (const callout of callouts) {
    let useLeftRail: boolean;
    if (isAuditMode) {
      // In Audit mode:
      // The session callout MUST remain completely stationary on ONE stable rail throughout
      // the entire replay. It should NEVER jump back and forth when stepping through hops.
      // Choose the quieter side of the complete tree rather than following the active hop.
      const leftNodeCount = [...graphNodeByPath.values()].filter((n) => n.x < 50).length;
      const rightNodeCount = [...graphNodeByPath.values()].filter((n) => n.x > 50).length;
      useLeftRail = leftNodeCount <= rightNodeCount;
    } else if (callouts.length === 1) {
      // A lone live source belongs beside its target branch. Centered targets use the
      // quieter half of the tree so the connector remains short without adding clutter.
      const target = graphNodeByPath.get(callout.path);
      if (target && Math.abs(target.x - 50) >= 0.1) {
        useLeftRail = target.x < 50;
      } else {
        const leftNodeCount = [...graphNodeByPath.values()].filter((n) => n.x < 50).length;
        const rightNodeCount = [...graphNodeByPath.values()].filter((n) => n.x > 50).length;
        useLeftRail = leftNodeCount <= rightNodeCount;
      }
    } else {
      const target = graphNodeByPath.get(callout.path);
      const isCentered = !target || Math.abs(target.x - 50) < 0.1;
      useLeftRail = isCentered ? leftRail.length <= rightRail.length : target.x < 50;
    }
    (useLeftRail ? leftRail : rightRail).push(callout);
  }

  // Rail rebalancing (Live mode): if one rail is heavily loaded and the other is sparse,
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

  // Target-aware adaptive rails:
  // Sparse topologies keep sources close to their related directory. As density grows,
  // the rails progressively move outward to preserve a clean directory-tree silhouette.
  const nodeXs = [...graphNodeByPath.values()].map((n) => n.x);
  const minTreeX = nodeXs.length ? Math.min(...nodeXs) : 50;
  const maxTreeX = nodeXs.length ? Math.max(...nodeXs) : 50;
  const railGap = callouts.length <= 2 ? 18 : callouts.length <= 4 ? 20 : 22;
  const leftRailX = Math.max(10, minTreeX - railGap);
  const rightRailX = Math.min(90, maxTreeX + railGap);

  const positions = new Map<string, LabelPosition>();

  const placeOnRail = (rail: GraphCallout[], x: number) => {
    if (!rail.length) return;
    const isRightRail = x > 50;
    // The bottom-right corner houses the minimap (approx y >= 70% in the right corner).
    // To avoid overlapping the minimap upon auto-arrange or reset, right-rail callouts are capped at y <= 66%.
    const maxRailY = isRightRail ? 66 : 80;

    rail.sort((left, right) => {
      const leftY = graphNodeByPath.get(left.path)?.y ?? 50;
      const rightY = graphNodeByPath.get(right.path)?.y ?? 50;
      return leftY - rightY || left.sourceIp.localeCompare(right.sourceIp, undefined, { numeric: true });
    });

    if (rail.length === 1) {
      const callout = rail[0];
      // Audit sources stay fixed while replay hops change. Live sources align with their
      // target so the relationship is readable without scanning two distant focal points.
      const targetY = isAuditMode ? 25 : (graphNodeByPath.get(callout.path)?.y ?? 50);
      positions.set(callout.sourceIp, { x, y: Math.min(maxRailY, Math.max(18, targetY)) });
      return;
    }

    // Adaptive vertical spacing: relax minimum separation as count grows to stay within canvas bounds.
    const count = rail.length;
    const nominalGap = rail.length >= 4 ? 11.5 : 14;
    const availableSpace = Math.max(10, maxRailY - 18);
    const minGap = count > 1 ? Math.min(nominalGap, availableSpace / (count - 1)) : nominalGap;
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

    // Defensive forward relaxation: keep every callout inside the usable canvas and
    // re-propagate the minimum separation after clamping.
    if (ys[0] < 18) {
      ys[0] = 18;
      for (let i = 1; i < count; i++) {
        if (ys[i] < ys[i - 1] + minGap) {
          ys[i] = ys[i - 1] + minGap;
        }
      }
    }

    rail.forEach((callout, index) => {
      positions.set(callout.sourceIp, { x, y: ys[index] });
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

export interface WorldBounds {
  minX: number;
  maxX: number;
  minY: number;
  maxY: number;
  width: number;
  height: number;
  centerX: number;
  centerY: number;
}

export interface FitViewportOptions {
  surfaceWidth: number;
  surfaceHeight: number;
  planeWidth: number;
  planeHeight: number;
  planeOffsetLeft?: number;
  planeOffsetTop?: number;
  hasMinimap?: boolean;
  isMinimapCollapsed?: boolean;
  minPadding?: number;
}

/**
 * Calculates two-dimensional world bounds in plane coordinates (%) for all active nodes and callouts.
 * Considers actual measured element sizes, manual drag offsets (including positions outside 0..100),
 * and adds defensive visual breathing room.
 */
export function calculateWorldBounds(
  nodes: readonly GraphNode[],
  callouts: readonly GraphCallout[],
  manualNodes: Record<string, LabelPosition> = {},
  manualLabels: Record<string, LabelPosition> = {},
  automaticCalloutPositions: Map<string, LabelPosition> = new Map(),
  nodeElementBounds: Record<string, GraphElementBounds> = {},
  calloutElementBounds: Record<string, GraphElementBounds> = {},
): WorldBounds {
  let minX = Infinity;
  let maxX = -Infinity;
  let minY = Infinity;
  let maxY = -Infinity;

  for (const node of nodes) {
    const bounds = nodeElementBounds[node.path];
    const halfWidth = bounds?.width ? bounds.width / 2 : 8;
    const halfHeight = bounds?.height ? bounds.height / 2 : 4;
    const posX = manualNodes[node.path]?.x ?? node.x;
    const posY = manualNodes[node.path]?.y ?? node.y;

    const left = posX - halfWidth;
    const right = posX + halfWidth;
    const top = posY - halfHeight;
    const bottom = posY + halfHeight;

    if (left < minX) minX = left;
    if (right > maxX) maxX = right;
    if (top < minY) minY = top;
    if (bottom > maxY) maxY = bottom;
  }

  for (const callout of callouts) {
    const bounds = calloutElementBounds[callout.sourceIp];
    const halfWidth = bounds?.width ? bounds.width / 2 : 8.5;
    const halfHeight = bounds?.height ? bounds.height / 2 : 5;
    const pos = manualLabels[callout.sourceIp] ?? automaticCalloutPositions.get(callout.sourceIp) ?? { x: 90, y: 50 };
    const posX = pos.x;
    const posY = pos.y;

    const left = posX - halfWidth;
    const right = posX + halfWidth;
    const top = posY - halfHeight;
    const bottom = posY + halfHeight;

    if (left < minX) minX = left;
    if (right > maxX) maxX = right;
    if (top < minY) minY = top;
    if (bottom > maxY) maxY = bottom;
  }

  if (!Number.isFinite(minX) || !Number.isFinite(maxX) || minX >= maxX) {
    minX = 20;
    maxX = 80;
  }
  if (!Number.isFinite(minY) || !Number.isFinite(maxY) || minY >= maxY) {
    minY = 15;
    maxY = 85;
  }

  // Visual breathing room (padding in coordinate percentage, default 2.5%)
  const PADDING_PERCENT = 2.5;
  const safeMinX = minX - PADDING_PERCENT;
  const safeMaxX = maxX + PADDING_PERCENT;
  const safeMinY = minY - PADDING_PERCENT;
  const safeMaxY = maxY + PADDING_PERCENT;

  return {
    minX: safeMinX,
    maxX: safeMaxX,
    minY: safeMinY,
    maxY: safeMaxY,
    width: safeMaxX - safeMinX,
    height: safeMaxY - safeMinY,
    centerX: (safeMinX + safeMaxX) / 2,
    centerY: (safeMinY + safeMaxY) / 2,
  };
}

/**
 * Calculates zoom and 2D pan to fit the topology within the viewport.
 * Considers:
 * - 2D world bounds across X and Y
 * - Surface dimensions (compact vs fullscreen)
 * - Rendered element sizes
 * - Coordinates outside 0..100
 * - Minimap clearance
 */
export function calculateTwoDimensionalFit(
  bounds: WorldBounds,
  options: FitViewportOptions,
): { zoom: number; pan: Pan } | null {
  const {
    surfaceWidth,
    surfaceHeight,
    planeWidth,
    planeHeight,
    planeOffsetLeft = 0,
    planeOffsetTop = 0,
    hasMinimap = false,
    isMinimapCollapsed = false,
    minPadding = 24,
  } = options;

  if (!surfaceWidth || !surfaceHeight || !planeWidth || !planeHeight) return null;

  // Actual unscaled content dimensions in plane pixels
  const unscaledContentWidthPx = (bounds.width / 100) * planeWidth;
  const unscaledContentHeightPx = (bounds.height / 100) * planeHeight;

  if (unscaledContentWidthPx <= 0 || unscaledContentHeightPx <= 0) return null;

  // Surface clearance padding
  const paddingLeft = minPadding;
  let paddingRight = minPadding;
  const paddingTop = minPadding;
  let paddingBottom = minPadding;

  // Minimap clearance: When minimap is active and not collapsed, it takes bottom-right corner (~140px width, ~95px height)
  // on screens >= sm (640px)
  if (hasMinimap && !isMinimapCollapsed && surfaceWidth >= 640) {
    paddingRight = Math.max(paddingRight, 48);
    paddingBottom = Math.max(paddingBottom, 60);
  }

  const availableWidth = Math.max(80, surfaceWidth - (paddingLeft + paddingRight));
  const availableHeight = Math.max(80, surfaceHeight - (paddingTop + paddingBottom));

  const scaleX = availableWidth / unscaledContentWidthPx;
  const scaleY = availableHeight / unscaledContentHeightPx;

  // Choose the scale that fits both dimensions, bounded by MAP_MIN_ZOOM and 1.0
  const idealZoom = Math.min(scaleX, scaleY);
  const fitZoom = Math.min(1.0, Math.max(MAP_MIN_ZOOM, Number(idealZoom.toFixed(2))));

  // Center the bounding box in the available surface area (taking padding asymmetry into account)
  const targetSurfaceCenterX = paddingLeft + availableWidth / 2;
  const targetSurfaceCenterY = paddingTop + availableHeight / 2;

  const contentCenterPxX = (bounds.centerX / 100) * planeWidth * fitZoom;
  const contentCenterPxY = (bounds.centerY / 100) * planeHeight * fitZoom;

  let panX = Math.round(targetSurfaceCenterX - planeOffsetLeft - contentCenterPxX);
  let panY = Math.round(targetSurfaceCenterY - planeOffsetTop - contentCenterPxY);

  // Screen-space bounding box check
  const screenLeft = planeOffsetLeft + panX + (bounds.minX / 100) * planeWidth * fitZoom;
  const screenRight = planeOffsetLeft + panX + (bounds.maxX / 100) * planeWidth * fitZoom;
  const screenTop = planeOffsetTop + panY + (bounds.minY / 100) * planeHeight * fitZoom;
  const screenBottom = planeOffsetTop + panY + (bounds.maxY / 100) * planeHeight * fitZoom;

  // Defensive screen edge clearance
  if (screenLeft < paddingLeft) {
    panX += Math.round(paddingLeft - screenLeft);
  } else if (screenRight > surfaceWidth - paddingRight) {
    panX -= Math.round(screenRight - (surfaceWidth - paddingRight));
  }

  if (screenTop < paddingTop) {
    panY += Math.round(paddingTop - screenTop);
  } else if (screenBottom > surfaceHeight - paddingBottom) {
    panY -= Math.round(screenBottom - (surfaceHeight - paddingBottom));
  }

  // Final minimap clearance: if the content bottom-right specifically intersects the minimap rectangle
  if (hasMinimap && !isMinimapCollapsed && surfaceWidth >= 640) {
    const currentScreenRight = planeOffsetLeft + panX + (bounds.maxX / 100) * planeWidth * fitZoom;
    const currentScreenBottom = planeOffsetTop + panY + (bounds.maxY / 100) * planeHeight * fitZoom;
    const minimapLeft = surfaceWidth - 140;
    const minimapTop = surfaceHeight - 95;

    if (currentScreenRight > minimapLeft && currentScreenBottom > minimapTop) {
      const currentScreenLeft = planeOffsetLeft + panX + (bounds.minX / 100) * planeWidth * fitZoom;
      const shiftX = Math.round(currentScreenRight - minimapLeft + 8);
      if (currentScreenLeft - shiftX >= minPadding) {
        panX -= shiftX;
      } else {
        const currentScreenTop = planeOffsetTop + panY + (bounds.minY / 100) * planeHeight * fitZoom;
        const shiftY = Math.round(currentScreenBottom - minimapTop + 8);
        if (currentScreenTop - shiftY >= minPadding) {
          panY -= shiftY;
        }
      }
    }
  }

  return {
    zoom: fitZoom,
    pan: { x: panX, y: panY },
  };
}

export interface DirectorySessionCounts {
  exactCount: number;
  descendantCount: number;
  branchCount: number;
  uniqueSourcesCount: number;
}

/**
 * Calculates authoritative session counts for a directory node:
 * - exactCount: sessions currently verified directly in this path
 * - descendantCount: sessions currently in subdirectories below this path
 * - branchCount: total sessions in this subtree (exactCount + descendantCount)
 * - uniqueSourcesCount: unique IP sources touching this subtree
 */
export function getDirectorySessionCounts(
  nodePath: string,
  nodeSessionIds: readonly string[],
  sessions: readonly FilesystemTopologySession[],
): DirectorySessionCounts {
  const sessionIdsSet = new Set(nodeSessionIds);
  const branch = sessions.filter((s) => sessionIdsSet.has(s.sessionId));
  const exact = branch.filter((s) => s.cwdState.path === nodePath);
  const descendant = branch.filter((s) => s.cwdState.path !== nodePath);
  const uniqueSources = new Set(branch.map((s) => s.sourceIp)).size;

  return {
    exactCount: exact.length,
    descendantCount: descendant.length,
    branchCount: branch.length,
    uniqueSourcesCount: uniqueSources,
  };
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
    return {
      nodes: [],
      sessions: [],
      recentClosedSessions: [],
      truncated: false,
      generatedAt: new Date().toISOString(),
    };
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
        auditSummary: session.auditSummary,
      },
    ],
    recentClosedSessions: [],
    truncated: false,
    generatedAt: new Date().toISOString(),
  };
}

/**
 * Checks whether a session strictly stayed within `/home` (and its subdirectories)
 * without traversing into any sensitive or system directories (e.g. /etc, /var, /tmp, /root).
 */
export function isHomeOnlySession(
  session: FilesystemTopologySession | FilesystemClosedSession,
): boolean {
  return session.auditSummary.homeOnly;
}

/**
 * Checks whether a session touched or traversed into a specific target path of interest.
 * Matches exact path or descendant subpaths (e.g. target "/etc" matches "/etc" and "/etc/shadow").
 */
export function sessionTouchesPath(
  session: FilesystemTopologySession | FilesystemClosedSession,
  targetPath: string,
): boolean {
  if (!targetPath || targetPath === "" || targetPath === "all") return true;

  const normalize = (p: string | null | undefined): string | null => {
    if (!p) return null;
    let s = p.trim();
    if (s.length > 1 && s.endsWith("/")) s = s.slice(0, -1);
    return s;
  };

  const normTarget = normalize(targetPath);
  if (!normTarget || normTarget === "/") return true;

  const matches = (p: string | null | undefined): boolean => {
    const norm = normalize(p);
    if (!norm) return false;
    return norm === normTarget || norm.startsWith(`${normTarget}/`);
  };

  return session.auditSummary.visitedPaths.some(matches);
}

export interface DistinctPathOption {
  path: string;
  sessionCount: number;
}

/**
 * Extracts distinct paths observed across all sessions with session counts,
 * sorted by session count descending, then path ascending.
 */
export function getDistinctSessionPaths(
  sessions: readonly FilesystemTopologySession[] = [],
  recentClosedSessions: readonly FilesystemClosedSession[] = [],
): DistinctPathOption[] {
  const pathSessionMap = new Map<string, Set<string>>();

  const addPathSession = (path: string | null | undefined, sessionId: string) => {
    if (!path || path === "/") return;
    const norm = path.length > 1 && path.endsWith("/") ? path.slice(0, -1) : path;
    if (!pathSessionMap.has(norm)) {
      pathSessionMap.set(norm, new Set());
    }
    pathSessionMap.get(norm)?.add(sessionId);
  };

  for (const s of sessions) {
    for (const path of s.auditSummary.visitedPaths) addPathSession(path, s.sessionId);
  }

  for (const s of recentClosedSessions) {
    for (const path of s.auditSummary.visitedPaths) addPathSession(path, s.sessionId);
  }

  return [...pathSessionMap.entries()]
    .map(([path, sessionSet]) => ({
      path,
      sessionCount: sessionSet.size,
    }))
    .sort((a, b) => {
      if (b.sessionCount !== a.sessionCount) {
        return b.sessionCount - a.sessionCount;
      }
      return a.path.localeCompare(b.path);
    });
}

export interface AuditUrlParams {
  view?: "live" | "audit";
  sessionId?: string | null;
  hideHome?: boolean;
  targetPath?: string | null;
  hop?: string | null;
}

export function parseAuditUrlParams(search: string): AuditUrlParams {
  const params = new URLSearchParams(search);
  const viewParam = params.get("view");
  const view = viewParam === "audit" ? "audit" : "live";
  const sessionId = params.get("sessionId");
  const hideHomeParam = params.get("hideHome");
  const hideHome = hideHomeParam === "1" || hideHomeParam === "true";
  const targetPath = params.get("targetPath");
  const hop = params.get("hop");

  return {
    view,
    sessionId: sessionId || null,
    hideHome,
    targetPath: targetPath || null,
    hop: hop || null,
  };
}

export function buildAuditUrlSearch(params: AuditUrlParams): string {
  if (params.view !== "audit") return "";

  const sp = new URLSearchParams();
  sp.set("view", "audit");
  if (params.sessionId) sp.set("sessionId", params.sessionId);
  if (params.hideHome) sp.set("hideHome", "1");
  if (params.targetPath) sp.set("targetPath", params.targetPath);
  if (params.hop) sp.set("hop", params.hop);

  const str = sp.toString();
  return str ? `?${str}` : "";
}

export interface SessionResolutionResult {
  sessionId: string | null;
  expiredSessionId: string | null;
}

/**
 * Resolves session selection without silent hijacking.
 * If a requested or current candidate does not exist in known sessions:
 * - In Audit mode or when explicitly requested, returns { sessionId: null, expiredSessionId: candidateId }
 * - In Live mode without an explicit URL request, falls back to the first available live session.
 */
export function resolveSessionSelection(
  requestedSessionId: string | null,
  currentSessionId: string | null,
  knownSessions: readonly { sessionId: string }[],
  isAuditMode: boolean,
): SessionResolutionResult {
  const candidateId = requestedSessionId ?? currentSessionId;
  if (!candidateId) {
    const fallback = knownSessions[0]?.sessionId ?? null;
    return { sessionId: fallback, expiredSessionId: null };
  }

  const exists = knownSessions.some((s) => s.sessionId === candidateId);
  if (exists) {
    return { sessionId: candidateId, expiredSessionId: null };
  }

  if (isAuditMode || requestedSessionId !== null) {
    return { sessionId: null, expiredSessionId: candidateId };
  }

  const fallback = knownSessions[0]?.sessionId ?? null;
  return { sessionId: fallback, expiredSessionId: null };
}

export const DEFAULT_STALE_THRESHOLD_MS = 30_000;

export function formatUpdateAge(ageMs: number): string {
  if (typeof ageMs !== "number" || isNaN(ageMs) || ageMs < 0) return "Just now";
  if (ageMs < 3_000) return "Just now";
  if (ageMs < 60_000) return `${Math.floor(ageMs / 1_000)}s ago`;
  if (ageMs < 3_600_000) return `${Math.floor(ageMs / 60_000)}m ago`;
  return `${Math.floor(ageMs / 3_600_000)}h ago`;
}

export type FreshnessClassification = "fresh" | "stale" | "degraded" | "offline";

export interface FreshnessState {
  classification: FreshnessClassification;
  label: string;
  detail: string;
  badgeClass: string;
  dotClass: string;
  isDegraded: boolean;
  isStale: boolean;
}

export function getFreshnessState(params: {
  lastUpdateAgeMs: number;
  staleThresholdMs?: number;
  streamState: StreamState;
  regionStatus: RegionStatus;
  hasSnapshot: boolean;
}): FreshnessState {
  const {
    lastUpdateAgeMs,
    staleThresholdMs = DEFAULT_STALE_THRESHOLD_MS,
    streamState,
    regionStatus,
    hasSnapshot,
  } = params;

  if (!hasSnapshot) {
    if (regionStatus === "loading" || streamState === "connecting") {
      return {
        classification: "offline",
        label: "Connecting",
        detail: "Connecting to real-time filesystem stream...",
        badgeClass: "border-border bg-surface-subtle text-text-subtle",
        dotClass: "bg-text-subtle animate-pulse",
        isDegraded: false,
        isStale: false,
      };
    }
    return {
      classification: "offline",
      label: "Offline",
      detail: "Topology stream unavailable. No valid snapshot loaded.",
      badgeClass: "border-danger-border bg-danger-subtle text-danger",
      dotClass: "bg-danger",
      isDegraded: true,
      isStale: true,
    };
  }

  const isTransportLive = streamState === "live";
  const isTimeStale = lastUpdateAgeMs > staleThresholdMs;

  if (!isTransportLive || regionStatus === "stale" || regionStatus === "error") {
    return {
      classification: "degraded",
      label: "Degraded",
      detail: `Reconnecting transport — displaying retained snapshot from ${formatUpdateAge(lastUpdateAgeMs)}.`,
      badgeClass: "border-warning-border bg-warning-subtle text-warning",
      dotClass: "bg-warning animate-pulse",
      isDegraded: true,
      isStale: isTimeStale,
    };
  }

  if (isTimeStale) {
    return {
      classification: "stale",
      label: "Stale",
      detail: `Connected, but no new telemetry for ${formatUpdateAge(lastUpdateAgeMs)} (threshold: ${Math.round(staleThresholdMs / 1000)}s).`,
      badgeClass: "border-warning-border bg-warning-subtle text-warning",
      dotClass: "bg-warning",
      isDegraded: false,
      isStale: true,
    };
  }

  return {
    classification: "fresh",
    label: "Live & Fresh",
    detail: `Live stream active · updated ${formatUpdateAge(lastUpdateAgeMs)}.`,
    badgeClass: "border-success-border bg-success-subtle text-success",
    dotClass: "bg-success",
    isDegraded: false,
    isStale: false,
  };
}

export type ToolbarDomain =
  | "global-views"
  | "canvas-navigation"
  | "layout-editing"
  | "replay-actions";

export interface ToolbarGroupContract {
  domain: ToolbarDomain;
  role: "toolbar" | "group" | "tablist" | "region";
  ariaLabel: string;
  isAtomic: boolean;
  subgroups?: string[];
}

export const TOOLBAR_HIERARCHY_CONTRACT: Record<ToolbarDomain, ToolbarGroupContract> = {
  "global-views": {
    domain: "global-views",
    role: "toolbar",
    ariaLabel: "Global filesystem controls",
    isAtomic: false,
    subgroups: ["Filesystem view modes", "Stream telemetry status"],
  },
  "canvas-navigation": {
    domain: "canvas-navigation",
    role: "group",
    ariaLabel: "Canvas navigation",
    isAtomic: true,
    subgroups: ["Zoom controls", "Camera alignment"],
  },
  "layout-editing": {
    domain: "layout-editing",
    role: "group",
    ariaLabel: "Layout editing",
    isAtomic: true,
    subgroups: ["Interaction mode", "Layout options"],
  },
  "replay-actions": {
    domain: "replay-actions",
    role: "toolbar",
    ariaLabel: "Audit session and replay toolbar",
    isAtomic: false,
    subgroups: ["Audited session and filter controls", "Replay and workspace actions"],
  },
};

export function getToolbarGroupContract(domain: ToolbarDomain): ToolbarGroupContract {
  return TOOLBAR_HIERARCHY_CONTRACT[domain];
}

export function analyzeTopologyDensity(
  nodes: readonly FilesystemTopologyNode[],
  sessions: readonly FilesystemTopologySession[],
  preference: TopologyDensityPreference = "auto",
  focusedPath: string | null = null,
  renderedGraphNodes?: readonly GraphNode[],
  renderedGraphCallouts?: readonly GraphCallout[],
  thresholds: DensityThresholds = DEFAULT_DENSITY_THRESHOLDS,
): TopologyDensityAnalysis {
  const totalNodes = nodes.length;
  const uniqueSources = new Set(sessions.map((s) => s.sourceIp));
  const totalSources = uniqueSources.size;

  let mode: TopologyDensityMode;
  if (preference !== "auto") {
    mode = preference;
  } else {
    if (totalNodes <= thresholds.detailedMaxNodes && totalSources <= thresholds.detailedMaxSources) {
      mode = "detailed";
    } else if (totalNodes <= thresholds.clusteredMaxNodes && totalSources <= thresholds.clusteredMaxSources) {
      mode = "clustered";
    } else {
      mode = "aggregated";
    }
  }

  const renderedNodes = renderedGraphNodes ? renderedGraphNodes.length : totalNodes;
  const hiddenNodes = Math.max(0, totalNodes - renderedNodes);
  const renderedSources = renderedGraphCallouts
    ? new Set(renderedGraphCallouts.map((c) => c.sourceIp)).size
    : totalSources;
  const hiddenSources = Math.max(0, totalSources - renderedSources);

  return {
    mode,
    isAuto: preference === "auto",
    totalNodes,
    renderedNodes,
    hiddenNodes,
    totalSources,
    renderedSources,
    hiddenSources,
    hasAggregatedBranches: mode === "aggregated" || hiddenNodes > 0,
    focusedBranchPath: focusedPath,
  };
}
