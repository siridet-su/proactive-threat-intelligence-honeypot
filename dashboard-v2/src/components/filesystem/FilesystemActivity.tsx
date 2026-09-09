// @refresh reset
"use client";

import { motion, useReducedMotion } from "framer-motion";
import { ChevronLeft, ChevronRight, CircleDot, Crosshair, FastForward, Grip, History, Maximize2, Minimize2, MousePointer2, Plus, Radio, RefreshCw, Route, Search, ShieldAlert, Terminal, ZoomIn, ZoomOut } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState, type PointerEvent } from "react";

import { RegionState, type RegionStatus } from "@/components/ui/RegionState";
import type { FilesystemTopologyNode, FilesystemTopologySession, FilesystemTopologySnapshot, SessionCwdHistoryEvent, SessionCwdHistoryPage } from "@/lib/dashboardTypes";

type StreamState = "connecting" | "live" | "stale";
type Pan = { x: number; y: number };
type LabelPosition = { x: number; y: number };
type LabelDrag = { sourceIp: string; startX: number; startY: number; origin: LabelPosition };

function isSnapshot(value: unknown): value is FilesystemTopologySnapshot {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Partial<FilesystemTopologySnapshot>;
  return Array.isArray(candidate.nodes) && Array.isArray(candidate.sessions) && Array.isArray(candidate.recentClosedSessions) &&
    typeof candidate.truncated === "boolean" && typeof candidate.generatedAt === "string";
}

function isHistoryPage(value: unknown): value is SessionCwdHistoryPage {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Partial<SessionCwdHistoryPage>;
  return Array.isArray(candidate.items) && (typeof candidate.nextCursor === "string" || candidate.nextCursor === null);
}

function formatTimestamp(value: string | null) {
  if (!value) return "No timestamp";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "No timestamp";
  return new Intl.DateTimeFormat("en-GB", { dateStyle: "medium", timeStyle: "medium" }).format(date);
}

function statusLabel(status: FilesystemTopologySession["cwdState"]["status"]) {
  if (status === "confirmed") return "Confirmed";
  if (status === "observed") return "Observed";
  if (status === "conditional_candidate") return "Conditional";
  return "Unknown";
}

function actionLabel(event: SessionCwdHistoryEvent) {
  if (event.action === "entered") return "Entered directory";
  if (event.action === "failed_change") return "Directory change failed";
  return "Changed directory";
}

const INSPECTOR_PAGE_SIZE = 12;
const GRAPH_CALLOUT_LIMIT = 8;
const GRAPH_NODE_LIMIT = 42;
const LABEL_LAYOUT_STORAGE_KEY = "pti-filesystem-label-layout-v1";
const MAP_MIN_ZOOM = 0.6;
const MAP_MAX_ZOOM = 1.6;

function snapLabelPosition(position: LabelPosition): LabelPosition {
  return {
    x: Math.round(position.x / 2) * 2,
    y: Math.round(position.y / 2) * 2,
  };
}

type GraphNode = FilesystemTopologyNode & { x: number; y: number };
type GraphCallout = {
  sourceIp: string;
  sessionIds: string[];
  path: string;
};

function pointForGraph(nodes: FilesystemTopologyNode[], sessions: FilesystemTopologySession[], selectedPath: string | null): GraphNode[] {
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

/**
 * The topology is a map, not a table. Grouping by source IP prevents a noisy
 * scanner from pinning several overlapping labels while retaining every
 * session in its path inspector. The group's newest session anchors its line.
 */
function calloutsForGraph(sessions: FilesystemTopologySession[], graphNodeByPath: Map<string, GraphNode>, selectedSessionId: string | null): GraphCallout[] {
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

function calloutSlot(index: number, count: number) {
  const left = index % 2 === 0;
  const slotsPerSide = Math.max(1, Math.ceil(count / 2));
  const slot = Math.floor(index / 2);
  return {
    left,
    // The card is 11rem wide and is anchored 1% from either edge, so this
    // approximates its centre in the SVG coordinate system.
    x: left ? 10 : 90,
    y: slotsPerSide === 1 ? 50 : 16 + (68 * slot) / (slotsPerSide - 1),
  };
}

/**
 * Node and label cards sit above the SVG layer. Terminate the leader at their
 * nearest visible edges instead of their centres, so no line appears to vanish
 * underneath a card border while the operator rearranges labels.
 */
function leaderEndpoints(node: GraphNode, label: LabelPosition) {
  const deltaX = label.x - node.x;
  const deltaY = label.y - node.y;
  if (deltaX === 0 && deltaY === 0) return { startX: node.x, startY: node.y, endX: label.x, endY: label.y };
  // Approximate half-card dimensions in the SVG's 100 × 100 viewBox.
  const nodeScale = 1 / Math.max(Math.abs(deltaX) / 8, Math.abs(deltaY) / 3.5);
  const labelScale = 1 / Math.max(Math.abs(deltaX) / 9, Math.abs(deltaY) / 4);
  return {
    startX: node.x + deltaX * nodeScale,
    startY: node.y + deltaY * nodeScale,
    endX: label.x - deltaX * labelScale,
    endY: label.y - deltaY * labelScale,
  };
}

export function FilesystemActivity() {
  const reducedMotion = useReducedMotion();
  const [snapshot, setSnapshot] = useState<FilesystemTopologySnapshot | null>(null);
  const [regionStatus, setRegionStatus] = useState<RegionStatus>("loading");
  const [streamState, setStreamState] = useState<StreamState>("connecting");
  const [selectedSessionId, setSelectedSessionId] = useState<string | null>(null);
  const [selectedPath, setSelectedPath] = useState<string | null>(null);
  const [history, setHistory] = useState<SessionCwdHistoryEvent[]>([]);
  const [historyCursor, setHistoryCursor] = useState<string | null>(null);
  const [historyStatus, setHistoryStatus] = useState<RegionStatus>("loading");
  const [selectedHistoryEventId, setSelectedHistoryEventId] = useState<string | null>(null);
  const [pan, setPan] = useState<Pan>({ x: 0, y: 0 });
  const [zoom, setZoom] = useState(1);
  const [pathSessionQuery, setPathSessionQuery] = useState("");
  const [pathSessionPage, setPathSessionPage] = useState(0);
  const [isTopologyExpanded, setIsTopologyExpanded] = useState(false);
  const [labelPositions, setLabelPositions] = useState<Record<string, LabelPosition>>({});
  // The initial live connection enables manual refresh after hydration.
  const [isHydrated, setIsHydrated] = useState(false);
  const dragStart = useRef<{ x: number; y: number; pan: Pan } | null>(null);
  const panRef = useRef<Pan>({ x: 0, y: 0 });
  const zoomRef = useRef(1);
  const historyRequest = useRef<{ generation: number; sessionId: string; controller: AbortController } | null>(null);
  const latestSnapshotAt = useRef(0);
  const initializedSelection = useRef(false);
  const mapSurfaceRef = useRef<HTMLDivElement>(null);
  const graphPlaneRef = useRef<HTMLDivElement>(null);
  const labelDrag = useRef<LabelDrag | null>(null);
  const suppressCalloutClick = useRef(false);
  const labelLayoutReady = useRef(false);

  useEffect(() => {
    const restore = window.setTimeout(() => {
      try {
        const raw = window.localStorage.getItem(LABEL_LAYOUT_STORAGE_KEY);
        const parsed: unknown = raw ? JSON.parse(raw) : {};
        if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
          const restored = Object.fromEntries(Object.entries(parsed).flatMap(([sourceIp, position]) => {
            if (!position || typeof position !== "object" || Array.isArray(position)) return [];
            const candidate = position as Partial<LabelPosition>;
            return typeof candidate.x === "number" && typeof candidate.y === "number"
              ? [[sourceIp, snapLabelPosition({ x: candidate.x, y: candidate.y })]]
              : [];
          }));
          setLabelPositions(restored);
        }
      } catch {
        window.localStorage.removeItem(LABEL_LAYOUT_STORAGE_KEY);
      } finally {
        labelLayoutReady.current = true;
      }
    }, 0);
    return () => window.clearTimeout(restore);
  }, []);

  useEffect(() => {
    if (!labelLayoutReady.current) return;
    window.localStorage.setItem(LABEL_LAYOUT_STORAGE_KEY, JSON.stringify(labelPositions));
  }, [labelPositions]);

  const applySnapshot = useCallback((data: FilesystemTopologySnapshot) => {
    const timestamp = Date.parse(data.generatedAt);
    if (Number.isFinite(timestamp) && timestamp < latestSnapshotAt.current) return;
    if (Number.isFinite(timestamp)) latestSnapshotAt.current = timestamp;
    const selectingInitialSession = !initializedSelection.current && Boolean(data.sessions[0]);
    if (selectingInitialSession) initializedSelection.current = true;
    setSnapshot(data);
    setRegionStatus("ready");
    setSelectedSessionId((current) => {
      if (current) {
        return [...data.sessions, ...data.recentClosedSessions].some((session) => session.sessionId === current) ? current : null;
      }
      if (selectingInitialSession) return data.sessions[0].sessionId;
      return null;
    });
    setSelectedPath((current) => {
      if (current) return data.nodes.some((node) => node.path === current) ? current : null;
      return selectingInitialSession ? data.nodes[0]?.path ?? null : null;
    });
  }, []);

  const refresh = useCallback(async () => {
    setRegionStatus((current) => snapshot ? "refreshing" : current === "error" ? "loading" : current);
    try {
      const response = await fetch("/api/filesystem-topology", { cache: "no-store" });
      if (!response.ok) throw new Error("Topology request failed");
      const data: unknown = await response.json();
      if (!isSnapshot(data)) throw new Error("Topology response unavailable");
      applySnapshot(data);
    } catch {
      setRegionStatus(snapshot ? "stale" : "error");
    }
  }, [applySnapshot, snapshot]);

  useEffect(() => {
    let disposed = false;
    let source: EventSource | null = null;
    let retry: number | null = null;
    const fetchSnapshot = async () => {
      try {
        const response = await fetch("/api/filesystem-topology", { cache: "no-store" });
        if (!response.ok) throw new Error("Topology fallback failed");
        const data: unknown = await response.json();
        if (!isSnapshot(data) || disposed) return;
        applySnapshot(data);
      } catch {
        if (!disposed) setRegionStatus((current) => current === "ready" ? "stale" : "error");
      }
    };
    const connect = () => {
      source = new EventSource("/api/filesystem-topology/stream");
      source.addEventListener("snapshot", onMessage as EventListener);
      source.addEventListener("topology.update", onMessage as EventListener);
      source.onopen = () => {
        if (disposed) return;
        setIsHydrated(true);
        setStreamState("live");
      };
      source.onerror = () => {
        if (disposed || source === null) return;
        setIsHydrated(true);
        setStreamState("stale");
        source.close();
        source = null;
        void fetchSnapshot();
        retry = window.setTimeout(connect, 5_000);
      };
    };
    const onMessage = (event: MessageEvent<string>) => {
      try {
        const message: unknown = JSON.parse(event.data);
        if (!message || typeof message !== "object") return;
        const data = (message as { data?: unknown }).data;
        if (!isSnapshot(data)) return;
        applySnapshot(data);
        setStreamState("live");
      } catch { /* retain the last valid topology */ }
    };
    connect();
    return () => {
      disposed = true;
      source?.close();
      if (retry !== null) window.clearTimeout(retry);
    };
  }, [applySnapshot]);

  const loadHistory = useCallback(async (sessionId: string, cursor: string | null, append = false) => {
    const generation = (historyRequest.current?.generation ?? 0) + 1;
    historyRequest.current?.controller.abort();
    const controller = new AbortController();
    historyRequest.current = { generation, sessionId, controller };
    if (!append) {
      setHistory([]);
      setHistoryCursor(null);
      setSelectedHistoryEventId(null);
    }
    setHistoryStatus(append ? "refreshing" : "loading");
    try {
      const params = cursor ? `?cursor=${encodeURIComponent(cursor)}` : "";
      const response = await fetch(`/api/sessions/${encodeURIComponent(sessionId)}/cwd-history${params}`, {
        cache: "no-store",
        signal: controller.signal,
      });
      if (!response.ok) throw new Error("History request failed");
      const data: unknown = await response.json();
      if (!isHistoryPage(data)) throw new Error("History response unavailable");
      const active = historyRequest.current;
      if (!active || active.generation !== generation || active.sessionId !== sessionId) return;
      setHistory((current) => append ? [...current, ...data.items] : data.items);
      setHistoryCursor(data.nextCursor);
      setHistoryStatus("ready");
    } catch {
      if (controller.signal.aborted || historyRequest.current?.generation !== generation) return;
      setHistoryStatus("error");
    }
  }, []);

  const selectedNode = useMemo(() => snapshot?.nodes.find((node) => node.path === selectedPath) ?? null, [selectedPath, snapshot]);
  const allSessions = useMemo(() => [...(snapshot?.sessions ?? []), ...(snapshot?.recentClosedSessions ?? [])], [snapshot]);
  const sessionById = useMemo(() => new Map(allSessions.map((session) => [session.sessionId, session])), [allSessions]);
  const selectedSession = useMemo(() => sessionById.get(selectedSessionId ?? "") ?? null, [selectedSessionId, sessionById]);
  const selectedClosedSession = useMemo(() => snapshot?.recentClosedSessions.find((session) => session.sessionId === selectedSessionId) ?? null, [selectedSessionId, snapshot]);
  const chronologicalHistory = useMemo(() => [...history].reverse(), [history]);
  const selectedHistoryIndex = useMemo(() => {
    if (!chronologicalHistory.length) return -1;
    const index = chronologicalHistory.findIndex((event) => event.id === selectedHistoryEventId);
    return index >= 0 ? index : chronologicalHistory.length - 1;
  }, [chronologicalHistory, selectedHistoryEventId]);
  const selectedHistoryEvent = selectedHistoryIndex >= 0 ? chronologicalHistory[selectedHistoryIndex] : null;
  const activeHistoryEventId = selectedHistoryEvent?.id ?? null;

  // A fresh CWD source event arrives through the topology SSE stream. Reload
  // the selected route so the Next control immediately exposes the new move.
  useEffect(() => {
    if (!selectedSessionId) {
      historyRequest.current?.controller.abort();
      return;
    }
    const request = window.setTimeout(() => { void loadHistory(selectedSessionId, null); }, 0);
    return () => {
      window.clearTimeout(request);
      if (historyRequest.current?.sessionId === selectedSessionId) historyRequest.current.controller.abort();
    };
  }, [loadHistory, selectedSession?.cwdState.sourceEventId, selectedSessionId]);
  const graphNodes = useMemo(
    () => pointForGraph(snapshot?.nodes ?? [], snapshot?.sessions ?? [], selectedPath),
    [selectedPath, snapshot?.nodes, snapshot?.sessions],
  );
  const graphNodeByPath = useMemo(() => new Map(graphNodes.map((node) => [node.path, node])), [graphNodes]);
  const graphCallouts = useMemo(
    () => calloutsForGraph(snapshot?.sessions ?? [], graphNodeByPath, selectedSessionId),
    [graphNodeByPath, selectedSessionId, snapshot?.sessions],
  );
  const liveSessionById = useMemo(() => new Map((snapshot?.sessions ?? []).map((session) => [session.sessionId, session])), [snapshot?.sessions]);
  const selectedGraphCallout = useMemo(
    () => graphCallouts.find((callout) => callout.sessionIds.includes(selectedSessionId ?? "")) ?? null,
    [graphCallouts, selectedSessionId],
  );
  const liveSourceCount = useMemo(() => new Set((snapshot?.sessions ?? []).map((session) => session.sourceIp)).size, [snapshot?.sessions]);

  const matchingPathSessionIds = useMemo(() => {
    const query = pathSessionQuery.trim().toLowerCase();
    const sessionIds = selectedNode?.sessionIds ?? [];
    if (!query) return sessionIds;
    return sessionIds.filter((id) => {
      const session = sessionById.get(id);
      return id.toLowerCase().includes(query) || session?.sourceIp.toLowerCase().includes(query);
    });
  }, [pathSessionQuery, selectedNode?.sessionIds, sessionById]);
  const pathSessionPageCount = Math.max(1, Math.ceil(matchingPathSessionIds.length / INSPECTOR_PAGE_SIZE));
  const safePathSessionPage = Math.min(pathSessionPage, pathSessionPageCount - 1);
  const visiblePathSessionIds = matchingPathSessionIds.slice(
    safePathSessionPage * INSPECTOR_PAGE_SIZE,
    (safePathSessionPage + 1) * INSPECTOR_PAGE_SIZE,
  );

  const selectSession = (sessionId: string) => {
    const session = sessionById.get(sessionId);
    historyRequest.current?.controller.abort();
    setHistory([]);
    setHistoryCursor(null);
    setSelectedHistoryEventId(null);
    setSelectedSessionId(sessionId);
    if (session?.cwdState.path) {
      setPathSessionQuery("");
      setPathSessionPage(0);
      setSelectedPath(snapshot?.nodes.some((node) => node.path === session.cwdState.path) ? session.cwdState.path : null);
    }
  };

  const setMapZoom = useCallback((value: number, focalPoint?: Pan) => {
    const nextZoom = Math.min(MAP_MAX_ZOOM, Math.max(MAP_MIN_ZOOM, Number(value.toFixed(3))));
    const currentZoom = zoomRef.current;
    const currentPan = panRef.current;
    const nextPan = focalPoint
      ? {
        x: focalPoint.x - ((focalPoint.x - currentPan.x) / currentZoom) * nextZoom,
        y: focalPoint.y - ((focalPoint.y - currentPan.y) / currentZoom) * nextZoom,
      }
      : currentPan;
    zoomRef.current = nextZoom;
    panRef.current = nextPan;
    setZoom(nextZoom);
    setPan(nextPan);
  }, []);
  const resetViewport = () => {
    panRef.current = { x: 0, y: 0 };
    zoomRef.current = 1;
    setPan(panRef.current);
    setZoom(zoomRef.current);
  };
  const resetLabelLayout = () => {
    setLabelPositions({});
    window.localStorage.removeItem(LABEL_LAYOUT_STORAGE_KEY);
  };
  const resetMapWorkspace = () => {
    resetViewport();
    resetLabelLayout();
  };
  const positionForCallout = (callout: GraphCallout, index: number): LabelPosition => labelPositions[callout.sourceIp] ?? calloutSlot(index, graphCallouts.length);
  const onCalloutPointerDown = (event: PointerEvent<HTMLButtonElement>, sourceIp: string, origin: LabelPosition) => {
    event.stopPropagation();
    event.currentTarget.focus();
    suppressCalloutClick.current = false;
    event.currentTarget.setPointerCapture(event.pointerId);
    labelDrag.current = { sourceIp, startX: event.clientX, startY: event.clientY, origin };
  };
  const onCalloutPointerMove = (event: PointerEvent<HTMLButtonElement>) => {
    const dragging = labelDrag.current;
    const plane = graphPlaneRef.current;
    if (!dragging || !plane) return;
    const rect = plane.getBoundingClientRect();
    if (!rect.width || !rect.height) return;
    const deltaX = ((event.clientX - dragging.startX) / rect.width) * 100;
    const deltaY = ((event.clientY - dragging.startY) / rect.height) * 100;
    if (Math.abs(deltaX) > 0.25 || Math.abs(deltaY) > 0.25) suppressCalloutClick.current = true;
    setLabelPositions((current) => ({
      ...current,
      [dragging.sourceIp]: {
        x: dragging.origin.x + deltaX,
        y: dragging.origin.y + deltaY,
      },
    }));
  };
  const onCalloutPointerEnd = (event: PointerEvent<HTMLButtonElement>) => {
    const dragging = labelDrag.current;
    if (dragging) {
      setLabelPositions((current) => ({
        ...current,
        [dragging.sourceIp]: snapLabelPosition(current[dragging.sourceIp] ?? dragging.origin),
      }));
    }
    labelDrag.current = null;
    if (event.currentTarget.hasPointerCapture(event.pointerId)) event.currentTarget.releasePointerCapture(event.pointerId);
  };
  const onPointerDown = (event: PointerEvent<HTMLDivElement>) => {
    if ((event.target as HTMLElement).closest("button")) return;
    event.currentTarget.setPointerCapture(event.pointerId);
    dragStart.current = { x: event.clientX, y: event.clientY, pan: panRef.current };
  };
  const onPointerMove = (event: PointerEvent<HTMLDivElement>) => {
    if (!dragStart.current) return;
    const nextPan = { x: dragStart.current.pan.x + event.clientX - dragStart.current.x, y: dragStart.current.pan.y + event.clientY - dragStart.current.y };
    panRef.current = nextPan;
    setPan(nextPan);
  };
  const onPointerEnd = (event: PointerEvent<HTMLDivElement>) => {
    dragStart.current = null;
    if (event.currentTarget.hasPointerCapture(event.pointerId)) event.currentTarget.releasePointerCapture(event.pointerId);
  };
  useEffect(() => {
    const surface = mapSurfaceRef.current;
    if (!surface) return;
    const onWheel = (event: WheelEvent) => {
      const plane = graphPlaneRef.current;
      if (!plane) return;
      // React's delegated wheel handler may be passive in some browsers. This
      // listener is intentionally non-passive so scrolling over the map never
      // scrolls the surrounding dashboard.
      event.preventDefault();
      const bounds = surface.getBoundingClientRect();
      setMapZoom(zoomRef.current * Math.exp(-event.deltaY * 0.0015), {
        x: event.clientX - bounds.left - plane.offsetLeft,
        y: event.clientY - bounds.top - plane.offsetTop,
      });
    };
    surface.addEventListener("wheel", onWheel, { passive: false });
    return () => surface.removeEventListener("wheel", onWheel);
  }, [isTopologyExpanded, setMapZoom, snapshot?.nodes.length]);

  useEffect(() => {
    if (!isTopologyExpanded) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") setIsTopologyExpanded(false);
    };
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    window.addEventListener("keydown", onKeyDown);
    return () => {
      document.body.style.overflow = previousOverflow;
      window.removeEventListener("keydown", onKeyDown);
    };
  }, [isTopologyExpanded]);

  return <div className="space-y-6">
    <section className="flex flex-col gap-4 border-b border-border pb-6 md:flex-row md:items-end md:justify-between">
      <div>
        <p className="mb-2 text-xs font-semibold uppercase tracking-[0.14em] text-primary">Runtime filesystem</p>
        <h1 className="text-2xl font-semibold tracking-tight text-text">Filesystem activity</h1>
        <p className="mt-2 max-w-2xl text-sm text-text-muted">Inspect the observed Cowrie working-directory topology, then audit a selected session&apos;s recorded path changes.</p>
      </div>
      <div className="flex flex-wrap items-center gap-3">
        <span className={`ui-badge ${streamState === "live" ? "border-success-border bg-success-subtle text-success" : "border-warning-border bg-warning-subtle text-warning"}`}><Radio className="h-3.5 w-3.5" aria-hidden="true" />{streamState === "live" ? "Live updates" : streamState === "connecting" ? "Connecting" : "Reconnecting"}</span>
        <button type="button" className="ui-button" onClick={() => {
          if (!isHydrated || regionStatus === "loading" || regionStatus === "refreshing") return;
          void refresh();
        }}><RefreshCw className="h-4 w-4" aria-hidden="true" />Refresh</button>
      </div>
    </section>

    <section className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_22rem]">
      <div className={`ui-panel overflow-hidden ${isTopologyExpanded ? "fixed inset-3 z-50 flex flex-col bg-surface" : ""}`} aria-busy={regionStatus === "loading"}>
        <div className="flex flex-col gap-3 border-b border-border p-5 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <div className="flex items-center gap-2"><Route className="h-4 w-4 text-primary" aria-hidden="true" /><h2 className="font-semibold text-text">Live filesystem topology</h2></div>
            <p className="mt-1 text-xs text-text-subtle">Observed paths form the topology; compact source-IP clusters point to their most recently verified location.</p>
          </div>
          <div className="flex items-center gap-1">
            <button type="button" className="ui-button h-9 min-h-9 w-9 p-0" aria-label="Zoom out" onClick={() => setMapZoom(zoomRef.current - 0.1)}><ZoomOut className="h-4 w-4" /></button>
            <button type="button" className="ui-button h-9 min-h-9 w-9 p-0" aria-label="Reset map view and label layout" onClick={resetMapWorkspace}><MousePointer2 className="h-4 w-4" /></button>
            <button type="button" className="ui-button h-9 min-h-9 w-9 p-0" aria-label="Zoom in" onClick={() => setMapZoom(zoomRef.current + 0.1)}><ZoomIn className="h-4 w-4" /></button>
            <button type="button" className="ui-button h-9 min-h-9 w-9 p-0" aria-label={isTopologyExpanded ? "Exit expanded map" : "Expand map workspace"} aria-pressed={isTopologyExpanded} onClick={() => setIsTopologyExpanded((expanded) => !expanded)}>{isTopologyExpanded ? <Minimize2 className="h-4 w-4" /> : <Maximize2 className="h-4 w-4" />}</button>
          </div>
        </div>
        {regionStatus === "error" ? <div className="p-5"><RegionState kind="error" title="Filesystem activity unavailable" description="The topology could not be loaded. Other dashboard views remain available." /></div> : regionStatus === "loading" && !snapshot ? <div className="p-5"><RegionState kind="loading" title="Loading filesystem activity" /></div> : !snapshot?.nodes.length ? <div className="p-5"><RegionState kind="empty" title="No observed working directories yet" description="The live view will populate after verified CWD telemetry is recorded." /></div> : <>
          <div className={isTopologyExpanded ? "grid min-h-0 flex-1 lg:grid-cols-[minmax(0,1fr)_20rem]" : ""}>
          <div className={isTopologyExpanded ? "flex min-h-0 min-w-0 flex-col" : ""}>
          <div ref={mapSurfaceRef} className={`relative overflow-hidden bg-surface-subtle p-5 sm:p-8 ${isTopologyExpanded ? "min-h-[540px] flex-1" : "min-h-[540px]"}`} onPointerDown={onPointerDown} onPointerMove={onPointerMove} onPointerUp={onPointerEnd} onPointerCancel={onPointerEnd}>
            <div className="pointer-events-none absolute inset-0 opacity-50 [background-image:linear-gradient(var(--border)_1px,transparent_1px),linear-gradient(90deg,var(--border)_1px,transparent_1px)] [background-size:28px_28px]" aria-hidden="true" />
            <div className="pointer-events-none absolute left-5 top-5 flex items-center gap-2 text-xs text-text-subtle"><Grip className="h-3.5 w-3.5" aria-hidden="true" />Drag surface to pan · Scroll to zoom · Drag IP labels freely · Use reset if a label leaves the view</div>
            <motion.div ref={graphPlaneRef} className={`relative origin-top-left ${isTopologyExpanded ? "h-full min-h-[500px]" : "h-[500px]"}`} animate={reducedMotion ? undefined : { x: pan.x, y: pan.y, scale: zoom }} style={reducedMotion ? { transform: `translate(${pan.x}px, ${pan.y}px) scale(${zoom})` } : undefined} transition={{ type: "spring", stiffness: 260, damping: 28 }}>
              <svg viewBox="0 0 100 100" preserveAspectRatio="none" className="pointer-events-none absolute inset-0 h-full w-full" aria-hidden="true">
                {graphNodes.map((node) => {
                  const parent = node.parentPath ? graphNodeByPath.get(node.parentPath) : null;
                  if (!parent) return null;
                  return <path key={`${parent.path}-${node.path}`} d={`M ${parent.x} ${parent.y} C ${parent.x} ${(parent.y + node.y) / 2}, ${node.x} ${(parent.y + node.y) / 2}, ${node.x} ${node.y}`} fill="none" stroke="var(--border-strong)" strokeWidth="0.35" />;
                })}
              </svg>
              <svg viewBox="0 0 100 100" preserveAspectRatio="none" className="pointer-events-none absolute inset-0 z-30 h-full w-full overflow-visible" aria-hidden="true">
                {graphCallouts.map((callout, index) => {
                  const position = positionForCallout(callout, index);
                  const selected = callout.sessionIds.includes(selectedSessionId ?? "");
                  const targetPaths = selected
                    ? [...new Set(callout.sessionIds.map((sessionId) => liveSessionById.get(sessionId)?.cwdState.path).filter((path): path is string => Boolean(path)))]
                    : [callout.path];
                  return <g key={`leader-${callout.sourceIp}`}>{targetPaths.map((path) => {
                    const node = graphNodeByPath.get(path);
                    if (!node) return null;
                    const endpoint = leaderEndpoints(node, position);
                    const controlX = (endpoint.startX + endpoint.endX) / 2;
                    return <g key={path}><path d={`M ${endpoint.startX} ${endpoint.startY} C ${controlX} ${endpoint.startY}, ${controlX} ${endpoint.endY}, ${endpoint.endX} ${endpoint.endY}`} fill="none" stroke="var(--primary)" strokeWidth={selected ? "0.42" : "0.32"} strokeDasharray={selected ? "none" : "1.1 1.4"} /><circle cx={endpoint.startX} cy={endpoint.startY} r="1.15" fill="var(--surface)" stroke="var(--primary)" strokeWidth="0.48" /></g>;
                  })}</g>;
                })}
              </svg>
              {graphNodes.map((node) => <button key={node.path} type="button" aria-pressed={node.path === selectedPath} onClick={() => { setPathSessionQuery(""); setPathSessionPage(0); setSelectedPath(node.path); }} style={{ left: `${node.x}%`, top: `${node.y}%` }} className={`absolute z-10 flex max-w-40 -translate-x-1/2 -translate-y-1/2 items-center gap-2 rounded-lg border px-2.5 py-1.5 text-left shadow-sm transition-colors duration-150 ${node.path === selectedPath ? "border-primary-border bg-primary-subtle text-text" : "border-border bg-surface text-text hover:border-border-strong hover:bg-surface-hover"}`}><Crosshair className="h-3.5 w-3.5 shrink-0 text-primary" aria-hidden="true" /><span className="truncate font-mono text-xs">{node.path}</span><span className="rounded-full bg-info-subtle px-1.5 text-xs font-semibold text-info">{node.sessionIds.length}</span></button>)}
              {graphCallouts.map((callout, index) => {
                const position = positionForCallout(callout, index);
                const selected = callout.sessionIds.includes(selectedSessionId ?? "");
                return <button key={`callout-${callout.sourceIp}`} type="button" aria-pressed={selected} onPointerDown={(event) => onCalloutPointerDown(event, callout.sourceIp, position)} onPointerMove={onCalloutPointerMove} onPointerUp={onCalloutPointerEnd} onPointerCancel={onCalloutPointerEnd} onClick={() => { if (suppressCalloutClick.current) { suppressCalloutClick.current = false; return; } selectSession(callout.sessionIds[0]); }} style={{ left: `${position.x}%`, top: `${position.y}%` }} className={`absolute z-40 flex w-44 -translate-x-1/2 -translate-y-1/2 touch-none items-center gap-2 rounded-lg border px-2.5 py-2 text-left shadow-sm transition-colors duration-150 ${selected ? "border-primary-border bg-primary-subtle" : "border-border bg-surface hover:border-border-strong hover:bg-surface-hover"}`}><span className={`h-2 w-2 shrink-0 rounded-full ${streamState === "live" ? "bg-success" : "bg-warning"}`} aria-hidden="true" /><span className="min-w-0"><span className="block truncate font-mono text-xs text-text">{callout.sourceIp}</span><span className="mt-0.5 flex items-center gap-1 text-[11px] text-text-subtle"><span>{callout.sessionIds.length} {callout.sessionIds.length === 1 ? "session" : "sessions"}</span><span aria-hidden="true">·</span><span className="truncate font-mono">{callout.path}</span></span></span></button>;
              })}
              <div className="pointer-events-none absolute bottom-2 left-1/2 -translate-x-1/2 rounded-full border border-border bg-surface px-3 py-1.5 text-xs text-text-muted shadow-sm"><span className="font-semibold text-text">{graphNodes.length}</span> paths mapped · <span className="font-semibold text-text">{graphCallouts.length}</span> of {liveSourceCount} IP labels</div>
            </motion.div>
          </div>
          <div className="flex flex-wrap gap-x-5 gap-y-2 border-t border-border px-5 py-3 text-xs text-text-muted"><span><strong className="text-text">{snapshot.nodes.length}</strong> observed paths</span><span><strong className="text-text">{snapshot.sessions.length}</strong> sessions with a known CWD</span><span>Snapshot {formatTimestamp(snapshot.generatedAt)}</span></div>
          {snapshot.truncated && <div className="flex gap-2 border-t border-warning-border bg-warning-subtle px-5 py-3 text-xs text-text-muted"><ShieldAlert className="h-4 w-4 shrink-0 text-warning" aria-hidden="true" /><p>Showing the latest {snapshot.sessions.length} observed sessions. Older sessions are not included in this live topology.</p></div>}
          </div>
          {isTopologyExpanded && <aside className="min-h-0 overflow-y-auto border-t border-border bg-surface p-5 lg:border-l lg:border-t-0" aria-label="Expanded map controls">
            <div className="flex items-center justify-between gap-3"><div><p className="text-xs font-semibold uppercase tracking-[0.12em] text-primary">Map controls</p><h3 className="mt-1 font-semibold text-text">Live source clusters</h3></div><span className={`ui-badge ${streamState === "live" ? "border-success-border bg-success-subtle text-success" : "border-warning-border bg-warning-subtle text-warning"}`}>{streamState === "live" ? "Live" : "Reconnecting"}</span></div>
            <p className="mt-3 text-xs text-text-subtle">Choose an IP to fan its leader line out to every current verified path. Drag labels on the map to arrange them. Press Escape to exit this workspace.</p>
            <button type="button" className="ui-button mt-4 w-full" onClick={resetLabelLayout}><MousePointer2 className="h-4 w-4" />Auto arrange labels</button>
            <div className="mt-5 space-y-2">{graphCallouts.map((callout) => {
              const selected = callout === selectedGraphCallout;
              return <button key={`control-${callout.sourceIp}`} type="button" aria-pressed={selected} onClick={() => selectSession(callout.sessionIds[0])} className={`w-full rounded-lg border px-3 py-3 text-left transition-colors duration-150 ${selected ? "border-primary-border bg-primary-subtle" : "border-border hover:border-border-strong hover:bg-surface-hover"}`}><div className="flex items-center justify-between gap-3"><span className="font-mono text-xs text-text">{callout.sourceIp}</span><span className="ui-badge border-info-border bg-info-subtle text-info">{callout.sessionIds.length}</span></div><p className="mt-1 truncate font-mono text-xs text-text-muted">Latest: {callout.path}</p></button>;
            })}</div>
            {selectedGraphCallout && <div className="mt-5 border-t border-border pt-4"><p className="text-xs font-semibold uppercase tracking-[0.12em] text-text-subtle">Selected IP paths</p><div className="mt-3 space-y-2">{selectedGraphCallout.sessionIds.map((sessionId) => { const session = liveSessionById.get(sessionId); return <button key={sessionId} type="button" onClick={() => selectSession(sessionId)} className={`flex w-full items-center justify-between gap-3 rounded-lg border px-3 py-2 text-left transition-colors duration-150 ${sessionId === selectedSessionId ? "border-primary-border bg-primary-subtle" : "border-border hover:bg-surface-hover"}`}><span className="min-w-0"><span className="block truncate font-mono text-xs text-text">{session?.cwdState.path ?? "Unknown"}</span><span className="mt-0.5 block truncate font-mono text-[11px] text-text-subtle">{sessionId}</span></span><ChevronRight className="h-4 w-4 shrink-0 text-text-subtle" /></button>; })}</div></div>}
          </aside>}
          </div>
        </>}
      </div>

      <aside className="space-y-4" aria-live="polite">
        <div className="ui-panel h-fit p-5">
          <div className="flex items-center gap-2"><CircleDot className="h-4 w-4 text-primary" aria-hidden="true" /><h2 className="font-semibold">Path inspector</h2></div>
          {selectedNode ? <>
            <p className="mt-5 break-all font-mono text-sm text-text">{selectedNode.path}</p>
            <dl className="mt-5 space-y-3 text-sm"><div className="flex justify-between gap-4"><dt className="text-text-subtle">Observed sessions</dt><dd className="font-semibold text-text">{selectedNode.sessionIds.length}</dd></div><div className="flex justify-between gap-4"><dt className="text-text-subtle">Latest observation</dt><dd className="text-right text-text-muted">{formatTimestamp(selectedNode.observedAt)}</dd></div></dl>
            <div className="mt-6 border-t border-border pt-4">
              <div className="mb-3 flex items-center justify-between gap-3"><p className="text-xs font-semibold uppercase tracking-[0.12em] text-text-subtle">Sessions at this path</p><span className="text-xs text-text-subtle">{matchingPathSessionIds.length}</span></div>
              <label className="relative block"><Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-text-subtle" aria-hidden="true" /><span className="sr-only">Filter sessions at this path</span><input type="search" value={pathSessionQuery} onChange={(event) => { setPathSessionQuery(event.target.value); setPathSessionPage(0); }} className="ui-field h-9 min-h-9 pl-9 text-xs" placeholder="Find session or source IP" /></label>
              <div className="mt-3 space-y-2">{visiblePathSessionIds.map((id) => { const session = sessionById.get(id); return <button key={id} type="button" onClick={() => selectSession(id)} className={`flex w-full items-center justify-between gap-3 rounded-lg border px-3 py-2 text-left transition-colors ${id === selectedSessionId ? "border-primary-border bg-primary-subtle" : "border-border hover:bg-surface-hover"}`}><span className="min-w-0"><span className="block truncate font-mono text-xs text-text">{id}</span><span className="mt-0.5 block font-mono text-xs text-text-subtle">{session?.sourceIp ?? "Unknown"}</span></span><ChevronRight className="h-4 w-4 shrink-0 text-text-subtle" /></button>; })}</div>
              {matchingPathSessionIds.length === 0 && <p className="mt-3 text-xs text-text-subtle">No sessions match this filter.</p>}
              {pathSessionPageCount > 1 && <div className="mt-3 flex items-center justify-between gap-2"><button type="button" className="ui-button h-8 min-h-8 px-2 text-xs" disabled={safePathSessionPage === 0} onClick={() => setPathSessionPage((page) => Math.max(0, page - 1))}><ChevronLeft className="h-3.5 w-3.5" />Previous</button><span className="text-xs text-text-subtle">{safePathSessionPage + 1} / {pathSessionPageCount}</span><button type="button" className="ui-button h-8 min-h-8 px-2 text-xs" disabled={safePathSessionPage >= pathSessionPageCount - 1} onClick={() => setPathSessionPage((page) => Math.min(pathSessionPageCount - 1, page + 1))}>Next<ChevronRight className="h-3.5 w-3.5" /></button></div>}
            </div>
          </> : <p className="mt-5 text-sm text-text-muted">Select a live directory to inspect the sessions observed there.</p>}
        </div>

        <div className="ui-panel h-fit p-5">
          <div className="flex items-center justify-between gap-3"><div className="flex items-center gap-2"><History className="h-4 w-4 text-warning" aria-hidden="true" /><h2 className="font-semibold">Recent closed sessions</h2></div><span className="ui-badge border-warning-border bg-warning-subtle text-warning">{snapshot?.recentClosedSessions.length ?? 0}</span></div>
          <p className="mt-2 text-xs text-text-subtle">Closed connections remain audit-ready until telemetry retention expires.</p>
          {snapshot?.recentClosedSessions.length ? <div className="mt-4 max-h-[34rem] space-y-2 overflow-y-auto overscroll-contain pr-1" aria-label="Recent closed sessions">{snapshot.recentClosedSessions.map((session) => <button key={session.sessionId} type="button" onClick={() => selectSession(session.sessionId)} className={`flex w-full items-center justify-between gap-3 rounded-lg border px-3 py-2.5 text-left transition-colors duration-150 ${session.sessionId === selectedSessionId ? "border-warning-border bg-warning-subtle" : "border-border hover:border-border-strong hover:bg-surface-hover"}`}><span className="min-w-0"><span className="block truncate font-mono text-xs text-text">{session.sourceIp}</span><span className="mt-0.5 block truncate font-mono text-[11px] text-text-subtle">{session.sessionId}</span><span className="mt-1 block truncate font-mono text-[11px] text-text-muted">{session.cwdState.path ?? "Unknown path"}</span></span><span className="shrink-0 text-right"><span className="block text-xs font-medium text-warning">Closed</span><span className="mt-0.5 block text-[11px] text-text-subtle">{formatTimestamp(session.lifecycle.closedAt)}</span></span></button>)}</div> : <p className="mt-4 text-sm text-text-muted">No closed sessions are retained yet.</p>}
        </div>
      </aside>
    </section>

    <section className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_22rem]">
      <div className="ui-panel overflow-hidden">
        <div className="flex flex-col gap-3 border-b border-border p-5 sm:flex-row sm:items-center sm:justify-between"><div><div className="flex items-center gap-2"><History className="h-4 w-4 text-primary" aria-hidden="true" /><h2 className="font-semibold">Verified CWD route</h2></div><p className="mt-1 text-xs text-text-subtle">Step through Cowrie-confirmed directory transitions. Command text never creates a guessed path.</p></div>{selectedSession && <span className="ui-badge font-mono text-xs">{selectedSession.sessionId}</span>}</div>
        <div className="p-5">
          {!selectedSession ? <RegionState kind="empty" title="Select a session to inspect its path history" description="Choose a session from the topology or inspector." /> : historyStatus === "error" && !history.length ? <RegionState kind="error" title="Session history unavailable" description="The selected CWD history could not be loaded." /> : historyStatus === "loading" && !history.length ? <RegionState kind="loading" title="Loading session history" /> : !history.length ? <RegionState kind="empty" title="No verified directory transitions" description="This session has a known observed path, but Cowrie has not recorded a successful directory move. It may have ended after a non-interactive probe." /> : <>
            <div className="rounded-xl border border-border bg-surface-subtle p-3 sm:p-4" aria-live="polite">
              <div className="grid grid-cols-[auto_minmax(0,1fr)_auto] items-stretch gap-2 sm:gap-3">
                <button type="button" className="ui-button h-auto min-h-0 w-10 shrink-0 p-0 sm:w-auto sm:px-3" aria-label="Show previous verified directory move" disabled={selectedHistoryIndex <= 0} onClick={() => setSelectedHistoryEventId(chronologicalHistory[selectedHistoryIndex - 1]?.id ?? null)}><ChevronLeft className="h-4 w-4" /><span className="hidden sm:inline">Previous</span></button>
                <div className="min-w-0 rounded-lg border border-primary-border bg-primary-subtle px-3 py-2.5 text-center sm:px-5"><p className="text-xs font-semibold uppercase tracking-[0.12em] text-primary">Checkpoint {selectedHistoryIndex + 1} of {chronologicalHistory.length}</p><p className="mt-1 font-medium text-text">{selectedHistoryEvent ? actionLabel(selectedHistoryEvent) : "Loading checkpoint"}</p><p className="mt-1 truncate font-mono text-xs text-text-muted">{selectedHistoryEvent?.fromPath ?? "Unknown"}<span className="px-1.5 text-primary">→</span>{selectedHistoryEvent?.toPath ?? "Unknown"}</p></div>
                <button type="button" className="ui-button h-auto min-h-0 w-10 shrink-0 p-0 sm:w-auto sm:px-3" aria-label="Show next verified directory move" disabled={selectedHistoryIndex < 0 || selectedHistoryIndex >= chronologicalHistory.length - 1} onClick={() => setSelectedHistoryEventId(chronologicalHistory[selectedHistoryIndex + 1]?.id ?? null)}><span className="hidden sm:inline">Next</span><ChevronRight className="h-4 w-4" /></button>
              </div>
              <div className="mt-3 flex flex-wrap items-center justify-between gap-2 text-xs text-text-subtle"><time className="font-mono">{selectedHistoryEvent ? formatTimestamp(selectedHistoryEvent.at) : ""}</time><button type="button" className="ui-button h-8 min-h-8 px-2.5 text-xs" disabled={selectedHistoryIndex === chronologicalHistory.length - 1} onClick={() => setSelectedHistoryEventId(chronologicalHistory.at(-1)?.id ?? null)}><FastForward className="h-3.5 w-3.5" />Latest recorded move</button></div>
            </div>
            {historyCursor && <button type="button" className="ui-button mt-4" onClick={() => selectedSessionId && void loadHistory(selectedSessionId, historyCursor, true)} disabled={historyStatus === "refreshing"}>{historyStatus === "refreshing" ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4" />}Load earlier moves</button>}
            <ol className="relative mt-5 space-y-0 border-l border-border pl-6" aria-label="Verified directory route">{chronologicalHistory.map((event, index) => <li key={event.id} className="relative pb-5 last:pb-0"><span className={`absolute -left-[31px] top-3 flex h-3 w-3 rounded-full border-2 border-surface ${event.action === "failed_change" ? "bg-danger" : event.id === activeHistoryEventId ? "bg-primary" : "bg-info"}`} aria-hidden="true" /><button type="button" aria-current={event.id === activeHistoryEventId ? "step" : undefined} onClick={() => setSelectedHistoryEventId(event.id)} className={`w-full rounded-lg border px-3 py-3 text-left transition-colors duration-150 ${event.id === activeHistoryEventId ? "border-primary-border bg-primary-subtle" : "border-transparent hover:border-border hover:bg-surface-hover"}`}><div className="flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between"><p className="font-medium text-text"><span className="mr-2 font-mono text-xs text-text-subtle">{String(index + 1).padStart(2, "0")}</span>{actionLabel(event)}</p><time className="font-mono text-xs text-text-subtle">{formatTimestamp(event.at)}</time></div><p className="mt-2 break-all font-mono text-xs text-text-muted"><span>{event.fromPath ?? "Unknown"}</span><span className="px-2 text-primary">→</span><span>{event.toPath ?? "Unknown"}</span></p><p className="mt-1 text-xs text-text-subtle">{statusLabel(event.status)}{event.sequence !== null ? ` · event ${event.sequence}` : ""}</p></button></li>)}</ol>
          </>}
        </div>
      </div>
      <aside className="ui-panel h-fit p-5"><div className="flex items-center gap-2"><Terminal className="h-4 w-4 text-primary" aria-hidden="true" /><h2 className="font-semibold">Session context</h2></div>{selectedSession ? <dl className="mt-5 space-y-4 text-sm"><div><dt className="text-xs text-text-subtle">Source IP</dt><dd className="mt-1 font-mono text-text">{selectedSession.sourceIp}</dd></div><div><dt className="text-xs text-text-subtle">{selectedClosedSession ? "Last observed path" : "Current observed path"}</dt><dd className="mt-1 break-all font-mono text-text">{selectedSession.cwdState.path ?? "Unknown"}</dd></div><div><dt className="text-xs text-text-subtle">Confidence</dt><dd className="mt-1"><span className="ui-badge border-info-border bg-info-subtle text-info">{statusLabel(selectedSession.cwdState.status)}</span></dd></div><div><dt className="text-xs text-text-subtle">Observed at</dt><dd className="mt-1 text-text-muted">{formatTimestamp(selectedSession.cwdState.observedAt)}</dd></div>{selectedClosedSession && <><div><dt className="text-xs text-text-subtle">Connection state</dt><dd className="mt-1"><span className="ui-badge border-warning-border bg-warning-subtle text-warning">Closed</span></dd></div><div><dt className="text-xs text-text-subtle">Closed at</dt><dd className="mt-1 text-text-muted">{formatTimestamp(selectedClosedSession.lifecycle.closedAt)}</dd></div></>}</dl> : <p className="mt-5 text-sm text-text-muted">No session is selected.</p>}<div className="mt-6 flex gap-2 rounded-lg border border-warning-border bg-warning-subtle p-3 text-xs text-text-muted"><ShieldAlert className="h-4 w-4 shrink-0 text-warning" aria-hidden="true" /><p>Unknown paths remain unknown. This view never fills a missing directory with a guessed Linux path.</p></div></aside>
    </section>
  </div>;
}
