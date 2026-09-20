"use client";

import { AnimatePresence, motion, useReducedMotion, type Transition } from "framer-motion";
import {
  AlertTriangle,
  Check,
  ChevronDown,
  ChevronRight,
  Folder,
  FolderOpen,
  HardDrive,
  Move,
  RotateCcw,
  Route,
  ScanLine,
  ShieldAlert,
  Undo2,
} from "lucide-react";
import {
  useCallback,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
} from "react";

import { RegionState, type RegionStatus } from "@/components/ui/RegionState";
import type { FilesystemTopologySnapshot } from "@/lib/dashboardTypes";
import { TopologyToolbar } from "./TopologyToolbar";
import { TopologySummaryBar } from "./TopologySummaryBar";
import { TopologyMinimap } from "./TopologyMinimap";
import { HopEnergy } from "./HopEnergy";
import {
  analyzeTopologyDensity,
  calloutsForGraph,
  compactDirectoryPath,
  DEFAULT_DENSITY_THRESHOLDS,
  directorySegment,
  formatUpdateAge,
  GRAPH_CALLOUT_LIMIT,
  GRAPH_NODE_LIMIT,
  isSensitiveDirectory,
  leaderEndpoints,
  pointForGraph,
  resolveCalloutPositions,
  sourceRailPositions,
  type ActiveHopRoute,
  type FreshnessState,
  type GraphCallout,
  type GraphElementBounds,
  type LabelPosition,
  type Pan,
  type StreamState,
  type TopologyDensityMode,
  type TopologyDensityPreference,
} from "./filesystemUtils";
import { useTopologyViewport } from "./useTopologyViewport";
import { useTopologyArrange } from "./useTopologyArrange";
import { getLayoutStorageKeys } from "./layoutPersistence";
import { TopologyCanvasHeader } from "./TopologyCanvasHeader";

const TOPOLOGY_TRANSITION: Transition = { duration: 0.55, ease: [0.22, 1, 0.36, 1] };

function sameElementBounds(
  left: Record<string, GraphElementBounds>,
  right: Record<string, GraphElementBounds>,
) {
  const leftKeys = Object.keys(left);
  const rightKeys = Object.keys(right);
  return leftKeys.length === rightKeys.length && leftKeys.every((key) => {
    const next = right[key];
    const current = left[key];
    return next && current &&
      Math.abs(next.x - current.x) < 0.01 &&
      Math.abs(next.y - current.y) < 0.01 &&
      Math.abs(next.width - current.width) < 0.01 &&
      Math.abs(next.height - current.height) < 0.01;
  });
}

interface TopologyCanvasProps {
  snapshot: FilesystemTopologySnapshot | null;
  regionStatus: RegionStatus;
  streamState: StreamState;
  freshnessState: FreshnessState;
  selectedSessionId: string | null;
  selectedPath: string | null;
  activeHop?: ActiveHopRoute | null;
  hopDurationMs?: number;
  title?: string;
  subtitle?: string;
  onSelectSession: (sessionId: string) => void;
  onSelectPath: (path: string | null) => void;
  isExpanded?: boolean;
  onToggleExpand?: () => void;
  onRefresh?: () => void;
  onReconnect?: () => void;
  staleThresholdMs: number;
  isAuditMode?: boolean;
  isResizingContainer?: boolean;
  className?: string;
}

export function TopologyCanvas({
  snapshot,
  regionStatus,
  streamState,
  freshnessState,
  selectedSessionId,
  selectedPath,
  activeHop,
  hopDurationMs = 1400,
  title,
  subtitle,
  onSelectSession,
  onSelectPath,
  isExpanded: controlledIsExpanded,
  onToggleExpand,
  onRefresh,
  onReconnect,
  staleThresholdMs,
  isAuditMode = false,
  isResizingContainer = false,
  className,
}: TopologyCanvasProps) {
  const reducedMotion = useReducedMotion();
  const [internalIsTopologyExpanded, setInternalIsTopologyExpanded] = useState(false);
  const isTopologyExpanded = controlledIsExpanded !== undefined ? controlledIsExpanded : internalIsTopologyExpanded;
  const isControlledExpansion = onToggleExpand !== undefined;
  const isStandaloneExpanded = isTopologyExpanded && !isControlledExpansion;

  const handleToggleExpand = useCallback(() => {
    if (onToggleExpand) {
      onToggleExpand();
    } else {
      setInternalIsTopologyExpanded((prev) => !prev);
    }
  }, [onToggleExpand]);

  // Scope layout persistence so audit session inspection never overrides live global topology
  const { labelStorageKey, nodeStorageKey } = useMemo(
    () => getLayoutStorageKeys(isAuditMode, selectedSessionId),
    [isAuditMode, selectedSessionId],
  );

  const [nodeElementBounds, setNodeElementBounds] = useState<Record<string, GraphElementBounds>>({});
  const [calloutElementBounds, setCalloutElementBounds] = useState<Record<string, GraphElementBounds>>({});

  const mapSurfaceRef = useRef<HTMLDivElement>(null);
  const graphPlaneRef = useRef<HTMLDivElement>(null);
  const nodeElementRefs = useRef(new Map<string, HTMLButtonElement>());
  const calloutElementRefs = useRef(new Map<string, HTMLElement>());
  const clusterSessionRefs = useRef(new Map<string, HTMLButtonElement>());
  const [userCollapsedIps, setUserCollapsedIps] = useState<Set<string>>(new Set());
  const [userExpandedIps, setUserExpandedIps] = useState<Set<string>>(new Set());

  const isClusterExpanded = useCallback(
    (callout: GraphCallout) => {
      if (callout.sessions.length <= 1) return false;
      if (userCollapsedIps.has(callout.sourceIp)) return false;
      if (userExpandedIps.has(callout.sourceIp)) return true;
      return callout.sessionIds.includes(selectedSessionId ?? "");
    },
    [selectedSessionId, userCollapsedIps, userExpandedIps],
  );

  const toggleClusterExpand = useCallback((sourceIp: string, isCurrentlyExpanded: boolean) => {
    if (isCurrentlyExpanded) {
      setUserCollapsedIps((prev) => new Set(prev).add(sourceIp));
      setUserExpandedIps((prev) => {
        const next = new Set(prev);
        next.delete(sourceIp);
        return next;
      });
    } else {
      setUserExpandedIps((prev) => new Set(prev).add(sourceIp));
      setUserCollapsedIps((prev) => {
        const next = new Set(prev);
        next.delete(sourceIp);
        return next;
      });
    }
  }, []);

  const getViewportSnapshotRef = useRef<(() => { pan: Pan; zoom: number }) | null>(null);
  const restoreViewportRef = useRef<((snapshot: { pan: Pan; zoom: number }) => void) | null>(null);
  const resetViewportRef = useRef<((overrideLabels?: Record<string, LabelPosition>, overrideNodes?: Record<string, LabelPosition>) => void) | null>(null);

  // TopologyCanvas is the sole mounted owner of arrangement state for this
  // topology instance. Presentational header/scene/overlay children receive
  // focused values and callbacks; they never call viewport or arrangement hooks.
  const {
    isArrangeMode,
    setIsArrangeMode,
    labelPositions,
    nodePositions,
    draggedCalloutIp,
    draggedNodePath,
    canUndoLayout,
    undoLayoutChange,
    autoArrangeTopology,
    resetMapWorkspace,
    onCalloutPointerDown,
    onCalloutPointerMove,
    onCalloutPointerEnd,
    consumeCalloutClickSuppression,
    onNodePointerDown,
    onNodePointerMove,
    onNodePointerEnd,
    consumeNodeClickSuppression,
  } = useTopologyArrange({
    labelStorageKey,
    nodeStorageKey,
    graphPlaneRef,
    onCaptureViewport: () => getViewportSnapshotRef.current?.() ?? { pan: { x: 0, y: 0 }, zoom: 1 },
    onRestoreViewport: (snapshot) => restoreViewportRef.current?.(snapshot),
    onResetViewport: (labels, nodes) => resetViewportRef.current?.(labels, nodes),
    onClearElementBounds: () => {
      setNodeElementBounds({});
      setCalloutElementBounds({});
    },
  });

  const [densityPreference, setDensityPreference] = useState<TopologyDensityPreference>("auto");

  // Render limits state
  const [isPathsExpanded, setIsPathsExpanded] = useState(false);
  const [isSourcesExpanded, setIsSourcesExpanded] = useState(false);

  // Derived graph layout
  const effectiveDensityMode: TopologyDensityMode = useMemo(() => {
    if (densityPreference !== "auto") return densityPreference;
    const totalNodes = snapshot?.nodes.length ?? 0;
    const uniqueSources = new Set((snapshot?.sessions ?? []).map((s) => s.sourceIp)).size;
    if (
      totalNodes <= DEFAULT_DENSITY_THRESHOLDS.detailedMaxNodes &&
      uniqueSources <= DEFAULT_DENSITY_THRESHOLDS.detailedMaxSources
    ) {
      return "detailed";
    }
    if (
      totalNodes <= DEFAULT_DENSITY_THRESHOLDS.clusteredMaxNodes &&
      uniqueSources <= DEFAULT_DENSITY_THRESHOLDS.clusteredMaxSources
    ) {
      return "clustered";
    }
    return "aggregated";
  }, [densityPreference, snapshot?.nodes.length, snapshot?.sessions]);

  const focusedGraphPath = selectedPath ?? activeHop?.toPath ?? null;

  const automaticGraphNodes = useMemo(
    () =>
      pointForGraph(
        snapshot?.nodes ?? [],
        snapshot?.sessions ?? [],
        selectedPath,
        isAuditMode,
        {
          nodeLimit: isPathsExpanded || densityPreference === "detailed" || isAuditMode ? null : GRAPH_NODE_LIMIT,
          selectedSessionId,
          densityMode: effectiveDensityMode,
          focusedPath: focusedGraphPath,
        },
      ),
    [
      effectiveDensityMode,
      focusedGraphPath,
      isAuditMode,
      isPathsExpanded,
      densityPreference,
      selectedPath,
      selectedSessionId,
      snapshot?.nodes,
      snapshot?.sessions,
    ],
  );
  const graphNodes = useMemo(
    () => automaticGraphNodes.map((node) => ({ ...node, ...(nodePositions[node.path] ?? {}) })),
    [automaticGraphNodes, nodePositions],
  );
  const graphNodeByPath = useMemo(() => new Map(graphNodes.map((node) => [node.path, node])), [graphNodes]);
  const effectiveSessions = useMemo(() => {
    if (!activeHop?.toPath || !selectedSessionId) return snapshot?.sessions ?? [];
    return (snapshot?.sessions ?? []).map((session) => {
      if (session.sessionId === selectedSessionId) {
        return {
          ...session,
          cwdState: {
            ...session.cwdState,
            path: activeHop.toPath,
          },
        };
      }
      return session;
    });
  }, [activeHop, selectedSessionId, snapshot?.sessions]);

  const automaticGraphNodeByPath = useMemo(
    () => new Map(automaticGraphNodes.map((node) => [node.path, node])),
    [automaticGraphNodes],
  );

  const graphCallouts = useMemo(
    () =>
      calloutsForGraph(effectiveSessions, automaticGraphNodeByPath, {
        calloutLimit: isSourcesExpanded || densityPreference === "detailed" || isAuditMode ? null : GRAPH_CALLOUT_LIMIT,
        selectedSessionId,
        densityMode: effectiveDensityMode,
      }),
    [
      effectiveSessions,
      automaticGraphNodeByPath,
      isSourcesExpanded,
      densityPreference,
      isAuditMode,
      selectedSessionId,
      effectiveDensityMode,
    ],
  );
  const allSourceClusters = useMemo(
    () =>
      calloutsForGraph(effectiveSessions, automaticGraphNodeByPath, {
        calloutLimit: null,
        selectedSessionId,
      }),
    [effectiveSessions, automaticGraphNodeByPath, selectedSessionId],
  );

  const densityAnalysis = useMemo(
    () =>
      analyzeTopologyDensity(
        snapshot?.nodes ?? [],
        snapshot?.sessions ?? [],
        densityPreference,
        focusedGraphPath,
        graphNodes,
        graphCallouts,
      ),
    [snapshot?.nodes, snapshot?.sessions, densityPreference, focusedGraphPath, graphNodes, graphCallouts],
  );
  const automaticCalloutPositions = useMemo(
    () => sourceRailPositions(graphCallouts, automaticGraphNodeByPath, isAuditMode),
    [graphCallouts, automaticGraphNodeByPath, isAuditMode],
  );
  const effectiveCalloutPositions = useMemo(
    () => resolveCalloutPositions(graphCallouts, automaticCalloutPositions, labelPositions),
    [graphCallouts, automaticCalloutPositions, labelPositions],
  );
  const positionForCallout = useCallback(
    (callout: GraphCallout, _index: number): LabelPosition =>
      effectiveCalloutPositions.get(callout.sourceIp) ??
      automaticCalloutPositions.get(callout.sourceIp) ??
      { x: _index % 2 === 0 ? 10 : 90, y: 50 },
    [automaticCalloutPositions, effectiveCalloutPositions],
  );
  const liveSessionById = useMemo(
    () => new Map(effectiveSessions.map((session) => [session.sessionId, session])),
    [effectiveSessions],
  );
  const selectedGraphCallout = useMemo(
    () => graphCallouts.find((callout) => callout.sessionIds.includes(selectedSessionId ?? "")) ?? null,
    [graphCallouts, selectedSessionId],
  );
  const liveSourceCount = useMemo(
    () => new Set(effectiveSessions.map((session) => session.sourceIp)).size,
    [effectiveSessions],
  );
  const exactSessionCountByPath = useMemo(() => {
    const counts = new Map<string, number>();
    for (const session of effectiveSessions) {
      const p = session.cwdState.path;
      if (p) {
        counts.set(p, (counts.get(p) ?? 0) + 1);
      }
    }
    return counts;
  }, [effectiveSessions]);

  const totalLiveSources = liveSourceCount;
  const renderedSourcesCount = graphCallouts.length;
  const isSourcesTruncated = totalLiveSources > renderedSourcesCount;



  const measureElementBounds = useCallback(() => {
    const plane = graphPlaneRef.current;
    if (!plane?.offsetWidth || !plane.offsetHeight) return;
    const planeBounds = plane.getBoundingClientRect();
    if (!planeBounds.width || !planeBounds.height) return;
    const toRelativeBounds = (element: HTMLElement): GraphElementBounds => {
      const bounds = element.getBoundingClientRect();
      return {
        x: ((bounds.left + bounds.width / 2 - planeBounds.left) / planeBounds.width) * 100,
        y: ((bounds.top + bounds.height / 2 - planeBounds.top) / planeBounds.height) * 100,
        width: (bounds.width / planeBounds.width) * 100,
        height: (bounds.height / planeBounds.height) * 100,
      };
    };
    const measuredNodes = Object.fromEntries(
      [...nodeElementRefs.current.entries()].map(([path, element]) => [path, toRelativeBounds(element)]),
    );
    const measuredCallouts = Object.fromEntries(
      [...calloutElementRefs.current.entries()].map(([sourceIp, element]) => [sourceIp, toRelativeBounds(element)]),
    );
    setNodeElementBounds((current) => sameElementBounds(current, measuredNodes) ? current : measuredNodes);
    setCalloutElementBounds((current) => sameElementBounds(current, measuredCallouts) ? current : measuredCallouts);
  }, []);

  // Connector endpoints use rendered bounds, including their actual centers. This keeps a line
  // attached to the same visual edge in compact, expanded, zoomed, and manually arranged views.
  useLayoutEffect(() => {
    measureElementBounds();
    const plane = graphPlaneRef.current;
    if (!plane) return;
    const observer = new ResizeObserver(measureElementBounds);
    observer.observe(plane);
    return () => observer.disconnect();
  }, [graphCallouts, graphNodes, isTopologyExpanded, labelPositions, measureElementBounds, nodePositions]);

  // Overlap detection: Identify any directory nodes or IP callouts that overlap each other
  const { overlappingNodePaths, overlappingCalloutIps } = useMemo(() => {
    const overlappingNodes = new Set<string>();
    const overlappingCallouts = new Set<string>();

    type BoundingBox = { id: string; type: "node" | "callout"; x: number; y: number; hw: number; hh: number };
    const boxes: BoundingBox[] = [];

    // Collect directory nodes
    for (const node of graphNodes) {
      const bounds = nodeElementBounds[node.path];
      const hw = bounds?.width ? bounds.width / 2 : 7.5;
      const hh = bounds?.height ? bounds.height / 2 : 4.0;
      boxes.push({ id: node.path, type: "node", x: node.x, y: node.y, hw, hh });
    }

    // Collect callouts
    for (const [index, callout] of graphCallouts.entries()) {
      const pos = positionForCallout(callout, index);
      const bounds = calloutElementBounds[callout.sourceIp];
      const hw = bounds?.width ? bounds.width / 2 : 8.35;
      const hh = bounds?.height ? bounds.height / 2 : 5.2;
      boxes.push({ id: callout.sourceIp, type: "callout", x: pos.x, y: pos.y, hw, hh });
    }

    // Compare all pairs for AABB intersection
    for (let i = 0; i < boxes.length; i++) {
      for (let j = i + 1; j < boxes.length; j++) {
        const a = boxes[i];
        const b = boxes[j];

        // An overlap occurs when both X and Y center distances are smaller than the sum of their half-sizes (with small tolerance)
        const overlapX = Math.abs(a.x - b.x) < a.hw + b.hw - 0.4;
        const overlapY = Math.abs(a.y - b.y) < a.hh + b.hh - 0.4;

        if (overlapX && overlapY) {
          if (a.type === "node") overlappingNodes.add(a.id);
          else overlappingCallouts.add(a.id);

          if (b.type === "node") overlappingNodes.add(b.id);
          else overlappingCallouts.add(b.id);
        }
      }
    }

    return { overlappingNodePaths: overlappingNodes, overlappingCalloutIps: overlappingCallouts };
  }, [calloutElementBounds, graphCallouts, graphNodes, nodeElementBounds, positionForCallout]);

  const totalOverlaps = overlappingNodePaths.size + overlappingCalloutIps.size;
  const showMinimap = isTopologyExpanded || graphNodes.length > 8 || graphCallouts.length > 2;

  const {
    pan,
    setPan,
    zoom,
    setZoom,
    panRef,
    zoomRef,
    isDraggingSurface,
    mapMetrics,
    zoomIn,
    zoomOut,
    markUserAdjusted,
    centerMapOn,
    resetViewport,
    fitTopology,
    onPointerDown,
    onPointerMove,
    onPointerEnd,
    onSurfaceKeyDown,
  } = useTopologyViewport({
    mapSurfaceRef,
    graphPlaneRef,
    isTopologyExpanded,
    showMinimap,
    automaticGraphNodes,
    graphCallouts,
    nodePositions,
    labelPositions,
    automaticCalloutPositions,
    nodeElementBounds,
    calloutElementBounds,
    nodesCount: snapshot?.nodes.length ?? 0,
  });

  useEffect(() => {
    getViewportSnapshotRef.current = () => ({ pan: panRef.current, zoom: zoomRef.current });
    restoreViewportRef.current = (snapshot) => {
      markUserAdjusted();
      panRef.current = snapshot.pan;
      zoomRef.current = snapshot.zoom;
      setPan(snapshot.pan);
      setZoom(snapshot.zoom);
    };
    resetViewportRef.current = resetViewport;
  }, [markUserAdjusted, panRef, resetViewport, setPan, setZoom, zoomRef]);

  const centerSelectedSource = useCallback(() => {
    if (!selectedGraphCallout) return;
    const index = graphCallouts.findIndex((callout) => callout.sourceIp === selectedGraphCallout.sourceIp);
    if (index < 0) return;
    centerMapOn(positionForCallout(selectedGraphCallout, index));
  }, [centerMapOn, graphCallouts, positionForCallout, selectedGraphCallout]);

  // Keep camera steady; only bring target node into view when hop changes AND it is outside the viewport
  const lastCenteredHopEventId = useRef<string | null>(null);
  useEffect(() => {
    if (!activeHop?.eventId || !activeHop?.toPath) return;
    if (activeHop.eventId === lastCenteredHopEventId.current) return;
    lastCenteredHopEventId.current = activeHop.eventId;

    // Never auto-center while user is actively dragging or interacting with the canvas
    if (draggedNodePath || draggedCalloutIp || isDraggingSurface) return;

    const targetNode = graphNodeByPath.get(activeHop.toPath);
    if (!targetNode) return;

    const surface = mapSurfaceRef.current;
    const plane = graphPlaneRef.current;
    if (!surface || !plane) return;

    const screenX = plane.offsetLeft + panRef.current.x + ((plane.offsetWidth * targetNode.x) / 100) * zoomRef.current;
    const screenY = plane.offsetTop + panRef.current.y + ((plane.offsetHeight * targetNode.y) / 100) * zoomRef.current;

    const margin = 60;
    const isVisible =
      screenX >= margin &&
      screenX <= surface.clientWidth - margin &&
      screenY >= margin &&
      screenY <= surface.clientHeight - margin;

    if (!isVisible) {
      centerMapOn(targetNode);
    }
  }, [
    activeHop?.eventId,
    activeHop?.toPath,
    centerMapOn,
    graphNodeByPath,
    isDraggingSurface,
    draggedNodePath,
    draggedCalloutIp,
    panRef,
    zoomRef,
  ]);

  // Minimap viewport box calculation
  const minimapViewport = useMemo(() => {
    if (!mapMetrics || !mapMetrics.planeWidth || !mapMetrics.planeHeight) return null;
    const rawLeft = ((-mapMetrics.planeLeft - pan.x) / (zoom * mapMetrics.planeWidth)) * 100;
    const rawTop = ((-mapMetrics.planeTop - pan.y) / (zoom * mapMetrics.planeHeight)) * 100;
    const rawRight = rawLeft + (mapMetrics.surfaceWidth / (zoom * mapMetrics.planeWidth)) * 100;
    const rawBottom = rawTop + (mapMetrics.surfaceHeight / (zoom * mapMetrics.planeHeight)) * 100;
    return {
      x: rawLeft,
      y: rawTop,
      width: Math.max(2, rawRight - rawLeft),
      height: Math.max(2, rawBottom - rawTop),
    };
  }, [mapMetrics, pan, zoom]);

  // Escape key exits expanded workspace (when running standalone)
  useEffect(() => {
    if (!isStandaloneExpanded) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") setInternalIsTopologyExpanded(false);
    };
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    window.addEventListener("keydown", onKeyDown);
    return () => {
      document.body.style.overflow = previousOverflow;
      window.removeEventListener("keydown", onKeyDown);
    };
  }, [isStandaloneExpanded]);

  return (
    <div
      className={`ui-panel overflow-hidden flex flex-col ${
        isStandaloneExpanded ? "fixed inset-3 z-50 bg-surface" : ""
      } ${className ?? ""}`}
      aria-busy={regionStatus === "loading"}
    >
      <TopologyCanvasHeader title={title} subtitle={subtitle}>
        <TopologyToolbar
          zoom={zoom}
          zoomIn={zoomIn}
          zoomOut={zoomOut}
          fitTopology={fitTopology}
          selectedGraphCallout={selectedGraphCallout}
          markUserAdjusted={markUserAdjusted}
          centerSelectedSource={centerSelectedSource}
          isArrangeMode={isArrangeMode}
          setIsArrangeMode={setIsArrangeMode}
          canUndoLayout={canUndoLayout}
          undoLayoutChange={undoLayoutChange}
          totalOverlaps={totalOverlaps}
          autoArrangeTopology={autoArrangeTopology}
          resetMapWorkspace={resetMapWorkspace}
          densityPreference={densityPreference}
          setDensityPreference={setDensityPreference}
          effectiveDensityMode={effectiveDensityMode}
          densityAnalysisHiddenNodes={densityAnalysis.hiddenNodes}
          isTopologyExpanded={isTopologyExpanded}
          isAuditMode={isAuditMode}
          handleToggleExpand={handleToggleExpand}
        />
      </TopologyCanvasHeader>

      {regionStatus === "error" && !snapshot ? (
        <div className="p-5">
          <RegionState
            kind="error"
            title="Filesystem activity unavailable"
            description="The topology could not be loaded. Other dashboard views remain available."
          />
        </div>
      ) : regionStatus === "loading" && !snapshot ? (
        <div className="p-5">
          <RegionState kind="loading" title="Loading filesystem activity" />
        </div>
      ) : !snapshot?.nodes.length ? (
        <div className="p-5">
          {!isAuditMode && freshnessState.isDegraded && (
            <div role="status" className="mb-4 rounded-lg border border-warning-border bg-surface-raised px-3 py-2 text-xs text-text">
              <strong className="font-semibold text-warning">Degraded connection:</strong>{" "}
              Showing retained snapshot.
            </div>
          )}
          <RegionState
            kind="empty"
            title={isAuditMode ? "No session selected for audit" : "No observed working directories yet"}
            description={
              isAuditMode
                ? "Choose a session from the dropdown above or reset active filters."
                : "The live view will populate after verified CWD telemetry is recorded."
            }
          />
        </div>
      ) : (
        <>
          <div
            className={
              isStandaloneExpanded
                ? "grid min-h-0 flex-1 lg:grid-cols-[minmax(0,1fr)_20rem]"
                : "flex min-h-0 flex-1 flex-col"
            }
          >
            <div className="flex min-h-0 min-w-0 flex-1 flex-col">
              <div
                ref={mapSurfaceRef}
                tabIndex={0}
                role="region"
                aria-label="Filesystem topology map workspace. Use arrow keys to pan, scroll or pinch to zoom."
                onKeyDown={onSurfaceKeyDown}
                className="relative min-h-[380px] flex-1 overflow-hidden bg-surface-subtle p-5 sm:p-8 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"
                onPointerDown={onPointerDown}
                onPointerMove={onPointerMove}
                onPointerUp={onPointerEnd}
                onPointerCancel={onPointerEnd}
              >
                <div
                  className="pointer-events-none absolute inset-0 opacity-50 [background-image:linear-gradient(var(--border)_1px,transparent_1px),linear-gradient(90deg,var(--border)_1px,transparent_1px)] [background-size:28px_28px]"
                  aria-hidden="true"
                />

                <AnimatePresence initial={false}>
                  {!isAuditMode && freshnessState.isDegraded && (
                    <motion.div
                      key="degraded-banner"
                      role="status"
                      initial={reducedMotion ? { opacity: 1 } : { opacity: 0, y: -6 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={reducedMotion ? { opacity: 0 } : { opacity: 0, y: -6 }}
                      transition={{ duration: reducedMotion ? 0 : 0.15, ease: "easeOut" }}
                      className="absolute left-1/2 top-4 z-50 flex -translate-x-1/2 items-center gap-2.5 rounded-lg border border-warning-border bg-surface-raised/95 px-3 py-1.5 text-xs text-text shadow-md backdrop-blur-xs"
                    >
                      <AlertTriangle className="h-4 w-4 shrink-0 text-warning" aria-hidden="true" />
                      <span>
                        <strong className="font-semibold text-warning">Degraded connection:</strong> Showing retained snapshot (received{" "}
                        {formatUpdateAge(freshnessState.snapshotReceiptAgeMs)}).
                      </span>
                      <span className="hidden sm:inline text-text-subtle text-[11px]">
                        (Threshold: {Math.round(staleThresholdMs / 1000)}s)
                      </span>
                      {onRefresh && (
                        <button
                          type="button"
                          onClick={onRefresh}
                          className="ml-1 rounded border border-border bg-surface px-2 py-0.5 text-xs font-semibold text-text hover:bg-surface-hover transition-colors"
                        >
                          Refresh snapshot
                        </button>
                      )}
                      {onReconnect && (
                        <button
                          type="button"
                          onClick={onReconnect}
                          className="ml-1 rounded border border-warning-border bg-warning-subtle px-2 py-0.5 text-xs font-semibold text-warning hover:bg-warning/20 transition-colors"
                        >
                          Reconnect now
                        </button>
                      )}
                    </motion.div>
                  )}
                  {isArrangeMode && (
                    <motion.div
                      role="status"
                      initial={reducedMotion ? { opacity: 1 } : { opacity: 0, y: -6 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={reducedMotion ? { opacity: 0 } : { opacity: 0, y: -6 }}
                      transition={{ duration: reducedMotion ? 0 : 0.15, ease: "easeOut" }}
                      className="pointer-events-none absolute left-4 top-4 z-50 flex min-h-9 items-center gap-2 rounded-lg border border-primary-border bg-surface-raised px-3 text-xs text-text shadow-sm sm:left-5 sm:top-5"
                    >
                      <Move className="h-4 w-4 shrink-0 text-primary" aria-hidden="true" />
                      <strong className="font-semibold text-primary">Arrange mode</strong>
                      <span className="text-text-muted">Drag nodes</span>
                      <span className="text-border" aria-hidden="true">·</span>
                      <kbd className="rounded border border-border bg-surface-subtle px-1.5 py-0.5 font-mono text-xs">Esc</kbd>
                      <span className="text-text-muted">to finish</span>
                    </motion.div>
                  )}
                  {activeHop?.toPath && selectedPath && selectedPath !== activeHop.toPath && (
                    <motion.div
                      role="status"
                      initial={reducedMotion ? { opacity: 1 } : { opacity: 0, y: -6 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={reducedMotion ? { opacity: 0 } : { opacity: 0, y: -6 }}
                      transition={{ duration: reducedMotion ? 0 : 0.15, ease: "easeOut" }}
                      className="pointer-events-none absolute left-1/2 top-4 z-50 flex min-h-9 -translate-x-1/2 items-center gap-2 rounded-lg border border-primary-border bg-surface-raised px-3 text-xs text-text shadow-sm"
                    >
                      <ScanLine className="h-4 w-4 shrink-0 text-primary" aria-hidden="true" />
                      <strong className="font-semibold text-primary">Inspecting directory</strong>
                      <span className="text-border" aria-hidden="true">·</span>
                      <button
                        type="button"
                        onClick={() => onSelectPath(activeHop.toPath)}
                        className="pointer-events-auto rounded border border-border bg-surface-subtle px-2 py-0.5 font-semibold text-text hover:bg-surface hover:text-text transition-colors shadow-2xs"
                      >
                        Return to current hop
                      </button>
                    </motion.div>
                  )}
                </AnimatePresence>

                <motion.div
                  ref={graphPlaneRef}
                  className="absolute h-[2000px] w-[2000px] origin-top-left overflow-visible"
                  animate={reducedMotion ? undefined : { x: pan.x, y: pan.y, scale: zoom }}
                  style={
                    reducedMotion
                      ? {
                          transform: `translate(${pan.x}px, ${pan.y}px) scale(${zoom})`,
                        }
                      : undefined
                  }
                  transition={
                    reducedMotion || isDraggingSurface || isResizingContainer
                      ? { duration: 0 }
                      : { type: "spring", stiffness: 260, damping: 28 }
                  }
                >
                  <svg viewBox="0 0 100 100" preserveAspectRatio="none" className="pointer-events-none absolute inset-0 h-full w-full overflow-visible" aria-hidden="true">
                    <defs>
                      <marker id="arrowhead-primary" markerWidth="4" markerHeight="4" refX="2" refY="2" orient="auto">
                        <polygon points="0 0, 4 2, 0 4" fill="var(--primary)" opacity="0.6" />
                      </marker>
                    </defs>
                    <AnimatePresence initial={false}>
                      {graphNodes.map((node) => {
                        const parent = node.parentPath ? graphNodeByPath.get(node.parentPath) : null;
                        if (!parent) return null;
                        const cpOffset = Math.min(25, Math.max(8, Math.abs(node.y - parent.y) * 0.5));
                        const cp1Y = parent.y <= node.y ? parent.y + cpOffset : parent.y - cpOffset;
                        const cp2Y = parent.y <= node.y ? node.y - cpOffset : node.y + cpOffset;
                        const filesystemRoute = `M ${parent.x} ${parent.y} C ${parent.x} ${cp1Y}, ${node.x} ${cp2Y}, ${node.x} ${node.y}`;

                        const isActiveHopEdge = Boolean(
                          activeHop && (
                            (activeHop.fromPath === parent.path && activeHop.toPath === node.path) ||
                            (activeHop.fromPath === node.path && activeHop.toPath === parent.path)
                          )
                        );

                        const isTrailEdge = Boolean(
                          activeHop &&
                          activeHop.visitedPaths.includes(node.path) &&
                          activeHop.visitedPaths.includes(parent.path)
                        );

                        const hopColor = activeHop?.isFailedAttempt ? "var(--warning)" : "var(--primary)";

                        return (
                          <motion.g
                            key={`${parent.path}-${node.path}`}
                            initial={reducedMotion ? false : { opacity: 0 }}
                            animate={{ opacity: 1 }}
                            exit={reducedMotion ? undefined : { opacity: 0 }}
                            transition={reducedMotion ? { duration: 0 } : { duration: 0.3, ease: "easeOut" }}
                          >
                            {/* The active connector is drawn with its packet in HopEnergy. */}
                            <motion.path
                              initial={false}
                              animate={{ d: filesystemRoute }}
                              transition={
                                reducedMotion || Boolean(draggedNodePath)
                                  ? { duration: 0 }
                                  : TOPOLOGY_TRANSITION
                              }
                              fill="none"
                              stroke={
                                isActiveHopEdge
                                  ? hopColor
                                  : isTrailEdge
                                    ? "var(--primary)"
                                    : "var(--border-strong)"
                              }
                              strokeWidth={
                                isActiveHopEdge
                                  ? "0.55"
                                  : isTrailEdge
                                    ? "0.24"
                                    : "0.35"
                              }
                              strokeOpacity={
                                isActiveHopEdge
                                  ? 0
                                  : isTrailEdge
                                    ? 0.42
                                    : 0.4
                              }
                              strokeDasharray={
                                isActiveHopEdge
                                  ? "none"
                                  : isTrailEdge
                                    ? "1.2 0.8"
                                    : "none"
                              }
                              markerEnd={isTrailEdge ? "url(#arrowhead-primary)" : undefined}
                            />
                          </motion.g>
                        );
                      })}
                    </AnimatePresence>
                  </svg>
                  <svg viewBox="0 0 100 100" preserveAspectRatio="none" className="pointer-events-none absolute inset-0 z-0 h-full w-full overflow-visible" aria-hidden="true">
                    <AnimatePresence initial={false}>
                      {graphCallouts.map((callout, index) => {
                        const position = positionForCallout(callout, index);
                        const selectedSource = callout.sessionIds.includes(selectedSessionId ?? "");
                        const selectedSessionPath = selectedSessionId
                          ? callout.sessions?.find((s) => s.sessionId === selectedSessionId)?.path ?? liveSessionById.get(selectedSessionId)?.cwdState.path
                          : null;
                        const targetPaths = callout.targetPaths?.length
                          ? callout.targetPaths
                          : [callout.path];
                        return (
                          <motion.g
                            key={`leader-${callout.sourceIp}`}
                            initial={reducedMotion ? false : { opacity: 0 }}
                            animate={{ opacity: 1 }}
                            exit={reducedMotion ? undefined : { opacity: 0 }}
                            transition={reducedMotion ? { duration: 0 } : { duration: 0.3, ease: "easeOut" }}
                          >
                            {targetPaths.map((path, routeIndex) => {
                              const node = graphNodeByPath.get(path);
                              if (!node) return null;
                              const isPrimarySelected = selectedSource && (path === selectedSessionPath || (!selectedSessionPath && path === callout.path));
                              const isClusterSelected = selectedSource;
                              const endpoint = leaderEndpoints(
                                node,
                                position,
                                nodeElementBounds[node.path],
                                calloutElementBounds[callout.sourceIp],
                              );
                              const controlX = (endpoint.startX + endpoint.endX) / 2;
                              const routePath = `M ${endpoint.startX} ${endpoint.startY} C ${controlX} ${endpoint.startY}, ${controlX} ${endpoint.endY}, ${endpoint.endX} ${endpoint.endY}`;
                              return (
                                <g key={`${callout.sourceIp}-route-${path}-${routeIndex}`}>
                                  <motion.path
                                    initial={false}
                                    animate={{ d: routePath }}
                                    transition={
                                      reducedMotion || Boolean(draggedNodePath || draggedCalloutIp)
                                        ? { duration: 0 }
                                        : TOPOLOGY_TRANSITION
                                    }
                                    fill="none"
                                    stroke={isPrimarySelected ? "var(--primary)" : isClusterSelected ? "var(--primary)" : "var(--border-strong)"}
                                    strokeOpacity={isPrimarySelected ? 1 : isClusterSelected ? 0.68 : 0.45}
                                    strokeWidth={isPrimarySelected ? "0.42" : isClusterSelected ? "0.28" : "0.2"}
                                    strokeDasharray={isPrimarySelected ? "none" : isClusterSelected ? "1.5 1.5" : "0.75 1.6"}
                                  />
                                  <motion.circle
                                    initial={false}
                                    animate={{ cx: endpoint.startX, cy: endpoint.startY }}
                                    transition={
                                      reducedMotion || Boolean(draggedNodePath || draggedCalloutIp)
                                        ? { duration: 0 }
                                        : TOPOLOGY_TRANSITION
                                    }
                                    r={isPrimarySelected ? "0.8" : isClusterSelected ? "0.6" : "0.45"}
                                    fill={isPrimarySelected ? "var(--primary)" : isClusterSelected ? "var(--primary)" : "var(--border-strong)"}
                                    fillOpacity={isPrimarySelected ? 1 : isClusterSelected ? 0.7 : 0.45}
                                  />
                                </g>
                              );
                            })}
                          </motion.g>
                        );
                      })}
                    </AnimatePresence>
                  </svg>
                  {activeHop?.toPath && !activeHop.isFailedAttempt && graphNodeByPath.has(activeHop.toPath) && (
                    <HopEnergy
                      key={`${selectedSessionId}:${activeHop.eventId}`}
                      from={activeHop.fromPath ? graphNodeByPath.get(activeHop.fromPath) : undefined}
                      to={graphNodeByPath.get(activeHop.toPath)!}
                      fromBounds={activeHop.fromPath ? nodeElementBounds[activeHop.fromPath] : undefined}
                      toBounds={nodeElementBounds[activeHop.toPath]}
                      durationMs={hopDurationMs}
                      reducedMotion={Boolean(reducedMotion)}
                      transition={reducedMotion || Boolean(draggedNodePath) ? { duration: 0 } : TOPOLOGY_TRANSITION}
                    />
                  )}
                  <AnimatePresence initial={false}>
                    {graphNodes.map((node) => {
                      const isSelected = node.path === selectedPath;
                      const isRoot = node.path === "/";
                      const isSensitive = isSensitiveDirectory(node.path);
                      const isHopTarget = activeHop?.toPath === node.path;
                      const isHopVisited = Boolean(activeHop?.visitedPaths.includes(node.path));
                      const visitedStep = activeHop?.visitedStepMap[node.path];
                      const isOverlapping = overlappingNodePaths.has(node.path);
                      const exactCount = exactSessionCountByPath.get(node.path) ?? 0;
                      const branchCount = node.sessionIds.length;
                      const descendantCount = Math.max(0, branchCount - exactCount);

                      return (
                        <motion.button
                          key={node.path}
                          ref={(element) => {
                            if (element) nodeElementRefs.current.set(node.path, element);
                            else nodeElementRefs.current.delete(node.path);
                          }}
                          initial={reducedMotion ? false : { opacity: 0, scale: 0.92 }}
                          animate={{ left: `${node.x}%`, top: `${node.y}%`, opacity: 1, scale: 1 }}
                          exit={reducedMotion ? undefined : { opacity: 0, scale: 0.94 }}
                          transition={
                            reducedMotion || draggedNodePath === node.path
                              ? { duration: 0 }
                              : {
                                  left: TOPOLOGY_TRANSITION,
                                  top: TOPOLOGY_TRANSITION,
                                  opacity: { duration: 0.3, ease: "easeOut" },
                                  scale: { duration: 0.3, ease: "easeOut" },
                                }
                          }
                          type="button"
                          aria-pressed={isSelected}
                          aria-label={`Inspect directory ${node.path}${
                            exactCount > 0 && descendantCount > 0
                              ? ` (${exactCount} at exact path, ${descendantCount} in child directories)`
                              : exactCount > 0
                                ? ` (${exactCount} active ${exactCount === 1 ? "session" : "sessions"})`
                                : descendantCount > 0
                                  ? ` (${descendantCount} active ${descendantCount === 1 ? "session" : "sessions"} in child directories)`
                                  : ""
                          }${
                            (node.hiddenChildCount ?? 0) > 0
                              ? ` (${node.hiddenChildCount} child directories aggregated, click to expand)`
                              : ""
                          }${isSensitive ? " (sensitive target)" : ""}${
                            isHopTarget && activeHop ? ` (active hop target ${activeHop.stepIndex + 1} of ${activeHop.totalSteps})` : ""
                          }`}
                          title={
                            (node.hiddenChildCount ?? 0) > 0
                              ? `${node.path} (${node.hiddenChildCount} child directories aggregated, click to expand branch)`
                              : exactCount > 0 && descendantCount > 0
                                ? `${node.path} (${exactCount} at exact path, ${descendantCount} in child directories)`
                                : exactCount > 0
                                  ? `${node.path} (${exactCount} active)`
                                  : descendantCount > 0
                                    ? `${node.path} (${descendantCount} in child directories)`
                                    : node.path
                          }
                          onPointerDown={(event) => onNodePointerDown(event, node.path, node)}
                          onPointerMove={onNodePointerMove}
                          onPointerUp={onNodePointerEnd}
                          onPointerCancel={onNodePointerEnd}
                          onClick={() => {
                            if (consumeNodeClickSuppression()) return;
                            onSelectPath(node.path);
                          }}
                          className={`absolute flex max-w-56 -translate-x-1/2 -translate-y-1/2 touch-none items-center gap-1.5 rounded-lg border px-2 py-1.5 text-left shadow-sm transition-colors duration-200 ${isArrangeMode ? "cursor-grab active:cursor-grabbing" : "cursor-pointer"} ${
                            isOverlapping
                              ? "z-30 border-warning bg-warning-subtle/50 text-text ring-2 ring-warning/80 shadow-md shadow-warning/20"
                              : isHopTarget && activeHop?.isFailedAttempt
                                ? "z-20 border-warning bg-warning-subtle text-text"
                                : isHopTarget
                                  ? "z-20 border-primary bg-primary-subtle text-text"
                                  : isSelected
                                    ? "z-10 border-primary-border bg-primary-subtle text-text ring-1 ring-primary/40"
                                    : isHopVisited
                                      ? "z-10 border-primary/40 bg-surface text-text hover:border-primary/70 hover:bg-surface-hover"
                                      : isSensitive
                                        ? "z-10 border-warning-border/80 bg-surface text-text hover:border-warning hover:bg-surface-hover"
                                        : "z-10 border-border bg-surface text-text hover:border-border-strong hover:bg-surface-hover"
                          }`}
                        >
                          {isOverlapping && (
                            <span
                              className="pointer-events-none absolute -top-1.5 -right-1.5 z-40 flex h-4 w-4 items-center justify-center rounded-full bg-warning text-surface shadow ring-1 ring-surface"
                              title="Overlapping position with another node"
                              aria-label="Overlapping position with another node"
                            >
                              <AlertTriangle className="h-2.5 w-2.5 stroke-[2.5]" aria-hidden="true" />
                            </span>
                          )}
                          {isRoot ? (
                            <HardDrive
                              className={`h-3.5 w-3.5 shrink-0 ${isSelected || isHopTarget ? "text-primary" : "text-text-subtle"}`}
                              aria-hidden="true"
                            />
                          ) : isSelected || isHopTarget ? (
                            <FolderOpen className="h-3.5 w-3.5 shrink-0 text-primary" aria-hidden="true" />
                          ) : (
                            <Folder
                              className={`h-3.5 w-3.5 shrink-0 ${isSensitive ? "text-warning" : isHopVisited ? "text-primary/80" : "text-text-subtle"}`}
                              aria-hidden="true"
                            />
                          )}
                          <span className="truncate font-mono text-xs">{directorySegment(node.path)}</span>
                          {isSensitive && (
                            <span
                              className="h-1.5 w-1.5 shrink-0 rounded-full bg-warning"
                              title="Sensitive target / Drop directory"
                              aria-hidden="true"
                            />
                          )}
                          {isHopTarget && activeHop ? (
                            <span
                              className={`flex shrink-0 items-center gap-0.5 rounded px-1.5 py-0.5 font-mono text-xs font-bold shadow-xs ${
                                activeHop.isFailedAttempt ? "bg-warning text-surface" : "bg-primary text-surface"
                              }`}
                              title={
                                activeHop.isFailedAttempt
                                  ? `Failed attempt target (attempt ${activeHop.stepIndex + 1}/${activeHop.totalSteps})`
                                  : `Current hop target (${activeHop.stepIndex + 1}/${activeHop.totalSteps})`
                              }
                            >
                              <Route className="h-2.5 w-2.5" aria-hidden="true" />
                              <span>{activeHop.isFailedAttempt ? `Failed #${activeHop.stepIndex + 1}` : `Hop ${activeHop.stepIndex + 1}`}</span>
                            </span>
                          ) : isHopVisited && visitedStep !== undefined ? (
                            <span
                              className="shrink-0 rounded border border-primary/30 bg-primary/10 px-1 py-0.5 font-mono text-xs font-semibold text-primary"
                              title={`Route step ${visitedStep}`}
                            >
                              #{visitedStep}
                            </span>
                          ) : null}
                          {(node.hiddenChildCount ?? 0) > 0 && (
                            <span
                              className="shrink-0 rounded-full border border-primary/40 bg-primary/10 px-1.5 py-0.5 font-mono text-[10px] font-bold text-primary"
                              title={`${node.hiddenChildCount} child ${node.hiddenChildCount === 1 ? "directory" : "directories"} aggregated under this path. Click to expand.`}
                            >
                              +{node.hiddenChildCount}
                            </span>
                          )}
                          {!isAuditMode && (
                            <span
                              className="rounded-full border border-border bg-surface-subtle px-1.5 text-xs font-semibold text-text-subtle"
                              title={`${exactCount} at exact path, ${descendantCount} in child directories (${branchCount} across branch)`}
                            >
                              {exactCount > 0 && descendantCount > 0
                                ? `${exactCount} (${branchCount})`
                                : exactCount > 0
                                  ? exactCount
                                  : descendantCount > 0
                                    ? `↳${branchCount}`
                                    : 0}
                            </span>
                          )}
                        </motion.button>
                      );
                    })}
                  </AnimatePresence>
                  <AnimatePresence initial={false}>
                    {graphCallouts.map((callout, index) => {
                      const position = positionForCallout(callout, index);
                      const isClusterSelected = callout.sessionIds.includes(selectedSessionId ?? "");
                      const isOverlapping = overlappingCalloutIps.has(callout.sourceIp);
                      const isMulti = callout.sessions?.length > 1;
                      const expanded = isClusterExpanded(callout);

                      return (
                        <motion.div
                          key={`callout-${callout.sourceIp}`}
                          ref={(element) => {
                            if (element) calloutElementRefs.current.set(callout.sourceIp, element);
                            else calloutElementRefs.current.delete(callout.sourceIp);
                          }}
                          initial={reducedMotion ? false : { opacity: 0, scale: 0.94 }}
                          animate={{ left: `${position.x}%`, top: `${position.y}%`, opacity: 1, scale: 1 }}
                          exit={reducedMotion ? undefined : { opacity: 0, scale: 0.94 }}
                          transition={
                            reducedMotion || draggedCalloutIp === callout.sourceIp
                              ? { duration: 0 }
                              : {
                                  left: TOPOLOGY_TRANSITION,
                                  top: TOPOLOGY_TRANSITION,
                                  opacity: { duration: 0.3, ease: "easeOut" },
                                  scale: { duration: 0.3, ease: "easeOut" },
                                }
                          }
                          onPointerDown={(event) => onCalloutPointerDown(event, callout.sourceIp, position)}
                          onPointerMove={onCalloutPointerMove}
                          onPointerUp={onCalloutPointerEnd}
                          onPointerCancel={onCalloutPointerEnd}
                          className={`absolute z-40 flex flex-col -translate-x-1/2 -translate-y-1/2 touch-none rounded-xl border text-left shadow-sm transition-colors duration-200 ${
                            isMulti ? "w-44 sm:w-52" : "w-36"
                          } ${isArrangeMode ? "cursor-grab active:cursor-grabbing" : ""} ${
                            isOverlapping
                              ? "border-warning bg-warning-subtle/60 text-text ring-2 ring-warning/80 shadow-md shadow-warning/20"
                              : isClusterSelected
                                ? "border-primary-border bg-surface ring-1 ring-primary/40 shadow-md"
                                : "border-border bg-surface hover:border-border-strong hover:bg-surface-hover"
                          }`}
                        >
                          {isOverlapping && (
                            <span
                              className="pointer-events-none absolute -top-1.5 -right-1.5 z-50 flex h-4 w-4 items-center justify-center rounded-full bg-warning text-surface shadow ring-1 ring-surface"
                              title="Overlapping position with another node"
                              aria-label="Overlapping position with another node"
                            >
                              <AlertTriangle className="h-2.5 w-2.5 stroke-[2.5]" aria-hidden="true" />
                            </span>
                          )}

                          {/* Main Callout Trigger */}
                          <button
                            type="button"
                            aria-pressed={isClusterSelected}
                            aria-expanded={isMulti ? expanded : undefined}
                            aria-haspopup={isMulti ? "listbox" : undefined}
                            aria-label={`Source ${callout.sourceIp}; ${callout.sessionIds.length} ${
                              callout.sessionIds.length === 1 ? "session" : "sessions"
                            }${isMulti ? (expanded ? "; cluster expanded" : "; click to expand sessions") : ""}`}
                            onClick={() => {
                              if (consumeCalloutClickSuppression()) return;
                              if (!isMulti) {
                                onSelectSession(callout.sessionIds[0]);
                              } else {
                                if (!isClusterSelected) {
                                  onSelectSession(callout.sessions[0].sessionId);
                                  setUserCollapsedIps((prev) => {
                                    const next = new Set(prev);
                                    next.delete(callout.sourceIp);
                                    return next;
                                  });
                                  setUserExpandedIps((prev) => new Set(prev).add(callout.sourceIp));
                                } else {
                                  toggleClusterExpand(callout.sourceIp, expanded);
                                }
                              }
                            }}
                            onKeyDown={(event) => {
                              if (isMulti && event.key === "ArrowDown") {
                                event.preventDefault();
                                if (!expanded) {
                                  toggleClusterExpand(callout.sourceIp, false);
                                }
                                const firstId = callout.sessions[0]?.sessionId;
                                if (firstId) {
                                  window.requestAnimationFrame(() => {
                                    clusterSessionRefs.current.get(`${callout.sourceIp}:${firstId}`)?.focus();
                                  });
                                }
                              }
                            }}
                            className={`flex w-full items-center justify-between gap-1.5 p-2 rounded-xl text-left cursor-pointer transition-colors ${
                              isClusterSelected && !isMulti ? "bg-primary-subtle" : ""
                            }`}
                          >
                            <div className="flex items-center gap-1.5 min-w-0">
                              <span
                                className={`h-2 w-2 shrink-0 rounded-full ${
                                  streamState === "live" ? "bg-success" : "bg-warning"
                                }`}
                                aria-hidden="true"
                              />
                              <div className="min-w-0">
                                <span className="block truncate font-mono text-xs font-semibold text-text" title={callout.sourceIp}>
                                  {callout.sourceIp}
                                </span>
                                <span className="mt-0.5 flex items-center gap-1 text-[11px] text-text-subtle">
                                  <span>
                                    {callout.sessionIds.length} {callout.sessionIds.length === 1 ? "session" : "sessions"}
                                  </span>
                                  {isMulti && (
                                    <>
                                      <span>·</span>
                                      <span className="font-semibold text-text-muted">
                                        {callout.targetPaths.length} {callout.targetPaths.length === 1 ? "path" : "paths"}
                                      </span>
                                    </>
                                  )}
                                </span>
                              </div>
                            </div>
                            {isMulti && (
                              <ChevronDown
                                className={`h-3.5 w-3.5 text-text-subtle shrink-0 transition-transform duration-200 ${
                                  expanded ? "rotate-180 text-primary" : ""
                                }`}
                                aria-hidden="true"
                              />
                            )}
                          </button>

                          {/* Multi-Session Cluster Disclosure Panel */}
                          {isMulti && expanded && (
                            <div
                              role="listbox"
                              aria-label={`Active sessions for ${callout.sourceIp}`}
                              className="border-t border-border/70 p-1.5 space-y-1 bg-surface-subtle/60 rounded-b-xl max-h-48 overflow-y-auto overscroll-contain"
                            >
                              {callout.sessions.map((sess, sIdx) => {
                                const isSessSelected = sess.sessionId === selectedSessionId;
                                return (
                                  <button
                                    key={sess.sessionId}
                                    ref={(el) => {
                                      if (el) clusterSessionRefs.current.set(`${callout.sourceIp}:${sess.sessionId}`, el);
                                      else clusterSessionRefs.current.delete(`${callout.sourceIp}:${sess.sessionId}`);
                                    }}
                                    type="button"
                                    role="option"
                                    aria-selected={isSessSelected}
                                    onClick={(e) => {
                                      e.stopPropagation();
                                      onSelectSession(sess.sessionId);
                                    }}
                                    onKeyDown={(e) => {
                                      if (e.key === "ArrowDown") {
                                        e.preventDefault();
                                        const nextIdx = (sIdx + 1) % callout.sessions.length;
                                        const nextId = callout.sessions[nextIdx].sessionId;
                                        clusterSessionRefs.current.get(`${callout.sourceIp}:${nextId}`)?.focus();
                                      } else if (e.key === "ArrowUp") {
                                        e.preventDefault();
                                        if (sIdx === 0) {
                                          calloutElementRefs.current.get(callout.sourceIp)?.querySelector("button")?.focus();
                                        } else {
                                          const prevId = callout.sessions[sIdx - 1].sessionId;
                                          clusterSessionRefs.current.get(`${callout.sourceIp}:${prevId}`)?.focus();
                                        }
                                      } else if (e.key === "Escape") {
                                        e.preventDefault();
                                        toggleClusterExpand(callout.sourceIp, true);
                                        calloutElementRefs.current.get(callout.sourceIp)?.querySelector("button")?.focus();
                                      }
                                    }}
                                    className={`flex w-full items-center justify-between gap-1.5 rounded-lg px-2 py-1 text-left text-xs font-mono transition-colors cursor-pointer ${
                                      isSessSelected
                                        ? "bg-primary-subtle text-primary font-semibold border border-primary-border/60 shadow-2xs"
                                        : "text-text hover:bg-surface-hover hover:text-text border border-transparent"
                                    }`}
                                  >
                                    <div className="flex items-center gap-1.5 truncate min-w-0">
                                      <span
                                        className={`h-1.5 w-1.5 rounded-full shrink-0 ${
                                          isSessSelected ? "bg-primary animate-pulse" : "bg-text-subtle/50"
                                        }`}
                                      />
                                      <span className="truncate text-text-muted">{sess.sessionId.slice(0, 8)}…</span>
                                      <span
                                        className={`truncate px-1 py-0.2 rounded text-[10px] border ${
                                          isSessSelected
                                            ? "bg-surface text-primary border-primary-border"
                                            : "bg-surface text-text-subtle border-border/50"
                                        }`}
                                        title={sess.path}
                                      >
                                        {compactDirectoryPath(sess.path)}
                                      </span>
                                    </div>
                                    {isSessSelected && (
                                      <Check className="h-3 w-3 text-primary shrink-0" aria-hidden="true" />
                                    )}
                                  </button>
                                );
                              })}
                            </div>
                          )}
                        </motion.div>
                      );
                    })}
                  </AnimatePresence>
                </motion.div>

                <AnimatePresence>
                  {(showMinimap || zoom !== 1) && (
                    <TopologyMinimap
                      graphNodes={graphNodes}
                      graphNodeByPath={graphNodeByPath}
                      graphCallouts={graphCallouts}
                      selectedPath={selectedPath}
                      selectedSessionId={selectedSessionId}
                      minimapViewport={minimapViewport}
                      positionForCallout={positionForCallout}
                      onFit={fitTopology}
                    />
                  )}
                </AnimatePresence>
              </div>

              <TopologySummaryBar
                densityAnalysisHiddenNodes={densityAnalysis.hiddenNodes}
                densityAnalysisRenderedNodes={densityAnalysis.renderedNodes}
                densityAnalysisTotalNodes={densityAnalysis.totalNodes}
                densityPreference={densityPreference}
                setDensityPreference={setDensityPreference}
                setIsPathsExpanded={setIsPathsExpanded}
                effectiveSessionsLength={effectiveSessions.length}
                isSourcesTruncated={isSourcesTruncated}
                renderedSourcesCount={renderedSourcesCount}
                totalLiveSources={totalLiveSources}
                isSourcesExpanded={isSourcesExpanded}
                setIsSourcesExpanded={setIsSourcesExpanded}
                snapshotGeneratedAt={snapshot.generatedAt}
                freshnessState={freshnessState}
                staleThresholdMs={staleThresholdMs}
                totalOverlaps={totalOverlaps}
                autoArrangeTopology={autoArrangeTopology}
                reducedMotion={reducedMotion}
              />
              {snapshot.truncated && (
                <div className="flex shrink-0 gap-2 border-t border-warning-border bg-warning-subtle px-5 py-3 text-xs text-text-muted">
                  <ShieldAlert className="h-4 w-4 shrink-0 text-warning" aria-hidden="true" />
                  <p>
                    Showing the latest {snapshot.sessions.length} observed sessions. Live stream reached server limit (500). Older sessions are retained in Audit history.
                  </p>
                </div>
              )}
            </div>

            {isStandaloneExpanded && (
              <aside
                className="min-h-0 overflow-y-auto border-t border-border bg-surface p-5 lg:border-l lg:border-t-0"
                aria-label="Expanded map controls"
              >
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <p className="text-xs font-semibold uppercase tracking-[0.12em] text-primary">Map controls</p>
                    <h3 className="mt-1 font-semibold text-text">
                      Live source clusters ({graphCallouts.length}/{allSourceClusters.length} on map)
                    </h3>
                  </div>
                  <span
                    className={`ui-badge ${
                      streamState === "live"
                        ? "border-success-border bg-success-subtle text-success"
                        : "border-warning-border bg-warning-subtle text-warning"
                    }`}
                  >
                    {streamState === "live" ? "Live" : "Reconnecting"}
                  </span>
                </div>
                <p className="mt-3 text-xs text-text-subtle">
                  Choose an IP to fan its leader line out to every current verified path. Switch to Arrange to drag
                  directories and IP labels. Auto arrange rebuilds the subtree layout, returns sources to their rails,
                  and recenters the camera; undo restores this workspace. Press Escape to exit this workspace.
                </p>
                <button type="button" className="ui-button mt-4 w-full" onClick={autoArrangeTopology}>
                  <ScanLine className="h-4 w-4" />
                  Auto arrange topology
                </button>
                {canUndoLayout && (
                  <button type="button" className="ui-button mt-2 w-full" onClick={undoLayoutChange}>
                    <Undo2 className="h-4 w-4" />
                    Undo layout change
                  </button>
                )}
                <button type="button" className="ui-button mt-2 w-full" onClick={resetMapWorkspace}>
                  <RotateCcw className="h-4 w-4" />
                  Restore default workspace
                </button>
                {allSourceClusters.length > GRAPH_CALLOUT_LIMIT && (
                  <div className="mt-4 flex items-center justify-between rounded-lg border border-border bg-surface-subtle p-2.5 text-xs">
                    <span className="text-text-muted">
                      {isSourcesExpanded
                        ? `All ${allSourceClusters.length} sources rendered on map`
                        : `Showing top ${graphCallouts.length} of ${allSourceClusters.length} sources`}
                    </span>
                    <button
                      type="button"
                      onClick={() => setIsSourcesExpanded((prev) => !prev)}
                      className="rounded border border-primary-border bg-primary-subtle px-2 py-1 text-xs font-medium text-primary hover:bg-primary/20 transition-colors"
                    >
                      {isSourcesExpanded ? `Limit to ${GRAPH_CALLOUT_LIMIT}` : "Show all on map"}
                    </button>
                  </div>
                )}
                <div className="mt-4 space-y-2">
                  {allSourceClusters.map((callout) => {
                    const isRendered = graphCallouts.some((c) => c.sourceIp === callout.sourceIp);
                    const selected = callout === selectedGraphCallout;
                    return (
                      <button
                        key={`control-${callout.sourceIp}`}
                        type="button"
                        aria-pressed={selected}
                        onClick={() => onSelectSession(callout.sessionIds[0])}
                        className={`w-full rounded-lg border px-3 py-3 text-left transition-colors duration-150 ${
                          selected
                            ? "border-primary-border bg-primary-subtle"
                            : "border-border hover:border-border-strong hover:bg-surface-hover"
                        }`}
                      >
                        <div className="flex items-center justify-between gap-3">
                          <span className="font-mono text-xs text-text">{callout.sourceIp}</span>
                          <div className="flex items-center gap-1.5">
                            {!isRendered && (
                              <span className="ui-badge border-warning-border bg-warning-subtle text-[10px] text-warning">
                                Omitted (limit)
                              </span>
                            )}
                            <span className="ui-badge border-info-border bg-info-subtle text-info">
                              {callout.sessionIds.length}
                            </span>
                          </div>
                        </div>
                        <p className="mt-1 truncate font-mono text-xs text-text-muted">Latest: {callout.path}</p>
                      </button>
                    );
                  })}
                </div>
                {selectedGraphCallout && (
                  <div className="mt-5 border-t border-border pt-4">
                    <p className="text-xs font-semibold uppercase tracking-[0.12em] text-text-subtle">Selected IP paths</p>
                    <div className="mt-3 space-y-2">
                      {selectedGraphCallout.sessionIds.map((sessionId) => {
                        const session = liveSessionById.get(sessionId);
                        return (
                          <button
                            key={sessionId}
                            type="button"
                            onClick={() => onSelectSession(sessionId)}
                            className={`flex w-full items-center justify-between gap-3 rounded-lg border px-3 py-2 text-left transition-colors duration-150 ${
                              sessionId === selectedSessionId
                                ? "border-primary-border bg-primary-subtle"
                                : "border-border hover:bg-surface-hover"
                            }`}
                          >
                            <span className="min-w-0">
                              <span className="block truncate font-mono text-xs text-text">
                                {session?.cwdState.path ?? "Unknown"}
                              </span>
                              <span className="mt-0.5 block truncate font-mono text-xs text-text-subtle">
                                {sessionId}
                              </span>
                            </span>
                            <ChevronRight className="h-4 w-4 shrink-0 text-text-subtle" />
                          </button>
                        );
                      })}
                    </div>
                  </div>
                )}
              </aside>
            )}
          </div>
        </>
      )}
    </div>
  );
}
