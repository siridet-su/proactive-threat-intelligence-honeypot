"use client";

import { AnimatePresence, motion, useReducedMotion, type Transition } from "framer-motion";
import {
  ChevronRight,
  Folder,
  FolderOpen,
  Grip,
  HardDrive,
  LocateFixed,
  Maximize2,
  Minimize2,
  MousePointer2,
  RotateCcw,
  Route,
  ScanLine,
  ShieldAlert,
  Undo2,
  ZoomIn,
  ZoomOut,
} from "lucide-react";
import {
  useCallback,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
  type PointerEvent as ReactPointerEvent,
} from "react";

import { RegionState, type RegionStatus } from "@/components/ui/RegionState";
import type { FilesystemTopologySnapshot } from "@/lib/dashboardTypes";
import { TopologyMinimap } from "./TopologyMinimap";
import {
  calloutsForGraph,
  directorySegment,
  formatTimestamp,
  isSensitiveDirectory,
  leaderEndpoints,
  MAP_MAX_ZOOM,
  MAP_MIN_ZOOM,
  pointForGraph,
  sourceRailPositions,
  type ActiveHopRoute,
  type GraphCallout,
  type GraphElementBounds,
  type LabelDrag,
  type LabelPosition,
  type MapMetrics,
  type NodeDrag,
  type Pan,
  type StreamState,
} from "./filesystemUtils";

const NODE_WORKSPACE_LIMIT = 400;
const TOPOLOGY_TRANSITION: Transition = { duration: 0.55, ease: [0.22, 1, 0.36, 1] };


interface WorkspaceLayoutSnapshot {
  labelPositions: Record<string, LabelPosition>;
  nodePositions: Record<string, LabelPosition>;
  pan: Pan;
  zoom: number;
}

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

function unrestrictedNodeCoordinate(value: number) {
  return Math.min(NODE_WORKSPACE_LIMIT, Math.max(-NODE_WORKSPACE_LIMIT, value));
}

function readStoredLabelLayout(storageKey: string): Record<string, LabelPosition> {
  if (typeof window === "undefined") return {};
  try {
    const raw = window.localStorage.getItem(storageKey);
    const parsed: unknown = raw ? JSON.parse(raw) : null;
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      return Object.fromEntries(
        Object.entries(parsed).flatMap(([sourceIp, position]) => {
          if (!position || typeof position !== "object" || Array.isArray(position)) return [];
          const candidate = position as Partial<LabelPosition>;
          return typeof candidate.x === "number" && typeof candidate.y === "number"
            ? [[sourceIp, { x: unrestrictedNodeCoordinate(candidate.x), y: unrestrictedNodeCoordinate(candidate.y) }]]
            : [];
        }),
      );
    }
  } catch {
    // Ignore corrupt or blocked localStorage
  }
  return {};
}

function readStoredNodeLayout(storageKey: string): Record<string, LabelPosition> {
  if (typeof window === "undefined") return {};
  try {
    const raw = window.localStorage.getItem(storageKey);
    const parsed: unknown = raw ? JSON.parse(raw) : null;
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      return Object.fromEntries(
        Object.entries(parsed).flatMap(([path, position]) => {
          if (!position || typeof position !== "object" || Array.isArray(position)) return [];
          const candidate = position as Partial<LabelPosition>;
          return typeof candidate.x === "number" && typeof candidate.y === "number"
            ? [[path, { x: unrestrictedNodeCoordinate(candidate.x), y: unrestrictedNodeCoordinate(candidate.y) }]]
            : [];
        }),
      );
    }
  } catch {
    // Ignore corrupt or blocked localStorage
  }
  return {};
}

interface TopologyCanvasProps {
  snapshot: FilesystemTopologySnapshot | null;
  regionStatus: RegionStatus;
  streamState: StreamState;
  selectedSessionId: string | null;
  selectedPath: string | null;
  activeHop?: ActiveHopRoute | null;
  title?: string;
  subtitle?: string;
  onSelectSession: (sessionId: string) => void;
  onSelectPath: (path: string | null) => void;
  isExpanded?: boolean;
  onToggleExpand?: () => void;
  isAuditMode?: boolean;
  isResizingContainer?: boolean;
  className?: string;
}

export function TopologyCanvas({
  snapshot,
  regionStatus,
  streamState,
  selectedSessionId,
  selectedPath,
  activeHop,
  title,
  subtitle,
  onSelectSession,
  onSelectPath,
  isExpanded: controlledIsExpanded,
  onToggleExpand,
  isAuditMode = false,
  isResizingContainer = false,
  className,
}: TopologyCanvasProps) {
  const reducedMotion = useReducedMotion();
  const hasUserManuallyAdjustedView = useRef(false);
  const [pan, setPan] = useState<Pan>({ x: 0, y: 0 });
  const [zoom, setZoom] = useState(1);
  const [isDraggingSurface, setIsDraggingSurface] = useState(false);
  const [internalIsTopologyExpanded, setInternalIsTopologyExpanded] = useState(false);
  const isTopologyExpanded = controlledIsExpanded !== undefined ? controlledIsExpanded : internalIsTopologyExpanded;
  const isControlledExpansion = onToggleExpand !== undefined;
  const isStandaloneExpanded = isTopologyExpanded && !isControlledExpansion;

  const handleToggleExpand = useCallback(() => {
    hasUserManuallyAdjustedView.current = false;
    if (onToggleExpand) {
      onToggleExpand();
    } else {
      setInternalIsTopologyExpanded((prev) => !prev);
    }
  }, [onToggleExpand]);

  // Scope layout persistence so audit session inspection never overrides live global topology
  const labelStorageKey = useMemo(
    () => (isAuditMode ? `pti-label-layout-audit-${selectedSessionId ?? "default"}` : "pti-label-layout-live"),
    [isAuditMode, selectedSessionId],
  );
  const nodeStorageKey = useMemo(
    () => (isAuditMode ? `pti-node-layout-audit-${selectedSessionId ?? "default"}` : "pti-node-layout-live"),
    [isAuditMode, selectedSessionId],
  );

  const [labelPositions, setLabelPositions] = useState<Record<string, LabelPosition>>(() =>
    readStoredLabelLayout(labelStorageKey),
  );
  const [nodePositions, setNodePositions] = useState<Record<string, LabelPosition>>(() =>
    readStoredNodeLayout(nodeStorageKey),
  );

  // Sync state if storage key changes (e.g. switching between live and audit mode or changing session)
  const [prevLabelStorageKey, setPrevLabelStorageKey] = useState(labelStorageKey);
  if (prevLabelStorageKey !== labelStorageKey) {
    setPrevLabelStorageKey(labelStorageKey);
    setLabelPositions(readStoredLabelLayout(labelStorageKey));
  }

  const [prevNodeStorageKey, setPrevNodeStorageKey] = useState(nodeStorageKey);
  if (prevNodeStorageKey !== nodeStorageKey) {
    setPrevNodeStorageKey(nodeStorageKey);
    setNodePositions(readStoredNodeLayout(nodeStorageKey));
  }

  const [mapMetrics, setMapMetrics] = useState<MapMetrics | null>(null);
  const [draggedCalloutIp, setDraggedCalloutIp] = useState<string | null>(null);
  const [draggedNodePath, setDraggedNodePath] = useState<string | null>(null);
  const [nodeElementBounds, setNodeElementBounds] = useState<Record<string, GraphElementBounds>>({});
  const [calloutElementBounds, setCalloutElementBounds] = useState<Record<string, GraphElementBounds>>({});

  const dragStart = useRef<{ x: number; y: number; pan: Pan } | null>(null);
  const panRef = useRef<Pan>({ x: 0, y: 0 });
  const zoomRef = useRef(1);
  const mapSurfaceRef = useRef<HTMLDivElement>(null);
  const graphPlaneRef = useRef<HTMLDivElement>(null);
  const nodeElementRefs = useRef(new Map<string, HTMLButtonElement>());
  const calloutElementRefs = useRef(new Map<string, HTMLButtonElement>());
  const labelDrag = useRef<LabelDrag | null>(null);
  const nodeDrag = useRef<NodeDrag | null>(null);
  const suppressCalloutClick = useRef(false);
  const suppressNodeClick = useRef(false);
  const autoArrangeUndo = useRef<WorkspaceLayoutSnapshot | null>(null);
  const [canUndoAutoArrange, setCanUndoAutoArrange] = useState(false);

  // Save label layout to localStorage
  useEffect(() => {
    if (Object.keys(labelPositions).length === 0) {
      window.localStorage.removeItem(labelStorageKey);
    } else {
      window.localStorage.setItem(labelStorageKey, JSON.stringify(labelPositions));
    }
  }, [labelPositions, labelStorageKey]);

  // Directory layout is a workspace preference, independent from source-IP labels.
  useEffect(() => {
    if (Object.keys(nodePositions).length === 0) {
      window.localStorage.removeItem(nodeStorageKey);
    } else {
      window.localStorage.setItem(nodeStorageKey, JSON.stringify(nodePositions));
    }
  }, [nodePositions, nodeStorageKey]);

  // Derived graph layout
  const automaticGraphNodes = useMemo(
    () => pointForGraph(snapshot?.nodes ?? [], snapshot?.sessions ?? [], selectedPath),
    [selectedPath, snapshot?.nodes, snapshot?.sessions],
  );
  const graphNodes = useMemo(
    () => automaticGraphNodes.map((node) => ({ ...node, ...(nodePositions[node.path] ?? {}) })),
    [automaticGraphNodes, nodePositions],
  );
  const graphNodeByPath = useMemo(() => new Map(graphNodes.map((node) => [node.path, node])), [graphNodes]);
  const graphPlaneHeight = useMemo(
    () => Math.max(440, 144 + Math.max(0, ...graphNodes.map((node) => node.depth)) * 64),
    [graphNodes],
  );
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
    () => calloutsForGraph(effectiveSessions, automaticGraphNodeByPath),
    [effectiveSessions, automaticGraphNodeByPath],
  );
  const automaticCalloutPositions = useMemo(
    () => sourceRailPositions(graphCallouts, automaticGraphNodeByPath),
    [graphCallouts, automaticGraphNodeByPath],
  );
  const positionForCallout = useCallback(
    (callout: GraphCallout, _index: number): LabelPosition =>
      labelPositions[callout.sourceIp] ??
      automaticCalloutPositions.get(callout.sourceIp) ??
      { x: _index % 2 === 0 ? 10 : 90, y: 50 },
    [automaticCalloutPositions, labelPositions],
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

  // When a source's verified path changes, clear any manual drag override so it smoothly moves to the new directory
  const lastSourcePathByIp = useRef<Map<string, string>>(new Map());
  useEffect(() => {
    for (const callout of graphCallouts) {
      const previousPath = lastSourcePathByIp.current.get(callout.sourceIp);
      if (previousPath && previousPath !== callout.path) {
        setLabelPositions((current) => {
          if (!current[callout.sourceIp]) return current;
          const next = { ...current };
          delete next[callout.sourceIp];
          return next;
        });
      }
      lastSourcePathByIp.current.set(callout.sourceIp, callout.path);
    }
  }, [graphCallouts]);


  const measureElementBounds = useCallback(() => {
    const plane = graphPlaneRef.current;
    if (!plane?.offsetWidth || !plane.offsetHeight) return;
    const planeBounds = plane.getBoundingClientRect();
    if (!planeBounds.width || !planeBounds.height) return;
    const toRelativeBounds = (element: HTMLButtonElement): GraphElementBounds => {
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

  const calculateFitViewport = useCallback(
    (
      surface: HTMLDivElement,
      plane: HTMLDivElement,
      overrideLabels?: Record<string, LabelPosition>,
      overrideNodes?: Record<string, LabelPosition>,
    ) => {
      const surfaceWidth = surface.clientWidth;
      if (!surfaceWidth) return null;

      const baseWidth = plane.offsetWidth || 860;
      const effectiveNodes = overrideNodes ?? nodePositions;
      const effectiveLabels = overrideLabels ?? labelPositions;

      // 1. Calculate actual content horizontal bounding box in plane percentage (0 - 100)
      let minContentX = 100;
      let maxContentX = 0;

      // Folders
      for (const node of automaticGraphNodes) {
        const bounds = nodeElementBounds[node.path];
        // If rendered element bounds are measured, use actual rendered width in %
        // Otherwise fallback to safe default folder width (~16% of plane, half = 8%)
        const halfWidth = bounds?.width ? bounds.width / 2 : 8;
        const posX = effectiveNodes[node.path]?.x ?? node.x;
        const left = posX - halfWidth;
        const right = posX + halfWidth;
        if (left < minContentX) minContentX = left;
        if (right > maxContentX) maxContentX = right;
      }

      // IP Callouts
      for (const callout of graphCallouts) {
        const bounds = calloutElementBounds[callout.sourceIp];
        const pos =
          effectiveLabels[callout.sourceIp] ??
          automaticCalloutPositions.get(callout.sourceIp) ??
          { x: 90, y: 50 };
        // Callout is w-44 (176px). On an 860px plane, 176px is ~20.4%, half = 10.2%
        const halfWidth = bounds?.width ? bounds.width / 2 : 10.5;
        const posX = pos.x;
        const left = posX - halfWidth;
        const right = posX + halfWidth;
        if (left < minContentX) minContentX = left;
        if (right > maxContentX) maxContentX = right;
      }

      // If no nodes found or bounds invalid, fallback to balanced 20%-80%
      if (minContentX >= maxContentX) {
        minContentX = 20;
        maxContentX = 80;
      }

      // Add a small 2% padding around content bounds for visual breathing room
      const safeMinX = Math.max(0, minContentX - 2);
      const safeMaxX = Math.min(100, maxContentX + 2);

      const contentWidthPercent = safeMaxX - safeMinX;
      const contentCenterPercent = (safeMinX + safeMaxX) / 2;

      // Actual unscaled content width in pixels
      const unscaledContentWidthPx = (contentWidthPercent / 100) * baseWidth;
      const horizontalPadding = 48; // 24px clearance on each side of the screen
      const availableWidth = surfaceWidth - horizontalPadding;

      let fitZoom = 1;
      if (availableWidth < unscaledContentWidthPx) {
        fitZoom = Math.min(1, Math.max(MAP_MIN_ZOOM, Number((availableWidth / unscaledContentWidthPx).toFixed(2))));
      } else {
        fitZoom = 1;
      }

      // Calculate panX to place contentCenterPercent exactly at the center of surfaceWidth
      const contentCenterPx = (contentCenterPercent / 100) * baseWidth * fitZoom;
      let panX = Math.round(surfaceWidth / 2 - plane.offsetLeft - contentCenterPx);

      // Defensive safety clamp: Ensure the bounds never cross screen edges (minimum 24px clearance)
      const minPadding = 24;
      const screenLeft = plane.offsetLeft + panX + (safeMinX / 100) * baseWidth * fitZoom;
      const screenRight = plane.offsetLeft + panX + (safeMaxX / 100) * baseWidth * fitZoom;
      if (screenLeft < minPadding) {
        panX += Math.round(minPadding - screenLeft);
      } else if (screenRight > surfaceWidth - minPadding) {
        panX -= Math.round(screenRight - (surfaceWidth - minPadding));
      }

      return {
        zoom: fitZoom,
        pan: { x: panX, y: 0 },
      };
    },
    [automaticCalloutPositions, automaticGraphNodes, calloutElementBounds, graphCallouts, labelPositions, nodeElementBounds, nodePositions],
  );

  const resetViewport = useCallback(
    (overrideLabels?: Record<string, LabelPosition>, overrideNodes?: Record<string, LabelPosition>) => {
      hasUserManuallyAdjustedView.current = false;
      const surface = mapSurfaceRef.current;
      const plane = graphPlaneRef.current;
      if (surface && plane) {
        const fit = calculateFitViewport(surface, plane, overrideLabels, overrideNodes);
        if (fit) {
          panRef.current = fit.pan;
          zoomRef.current = fit.zoom;
          setPan(fit.pan);
          setZoom(fit.zoom);
          return;
        }
      }
      panRef.current = { x: 0, y: 0 };
      zoomRef.current = 1;
      setPan(panRef.current);
      setZoom(zoomRef.current);
    },
    [calculateFitViewport],
  );

  const resetLabelLayout = () => {
    labelDrag.current = null;
    setDraggedCalloutIp(null);
    setLabelPositions({});
    setCalloutElementBounds({});
    window.localStorage.removeItem(labelStorageKey);
  };

  const resetNodeLayout = () => {
    nodeDrag.current = null;
    setDraggedNodePath(null);
    setNodePositions({});
    setNodeElementBounds({});
    window.localStorage.removeItem(nodeStorageKey);
  };

  const resetMapWorkspace = () => {
    hasUserManuallyAdjustedView.current = false;
    resetLabelLayout();
    resetNodeLayout();
    resetViewport({}, {});
    autoArrangeUndo.current = null;
    setCanUndoAutoArrange(false);
  };

  const fitTopology = () => {
    hasUserManuallyAdjustedView.current = false;
    resetViewport();
  };

  const autoArrangeTopology = () => {
    hasUserManuallyAdjustedView.current = false;
    autoArrangeUndo.current = {
      labelPositions: { ...labelPositions },
      nodePositions: { ...nodePositions },
      pan: { ...panRef.current },
      zoom: zoomRef.current,
    };
    setCanUndoAutoArrange(true);
    resetLabelLayout();
    resetNodeLayout();
    resetViewport({}, {});
  };

  const undoAutoArrangeTopology = () => {
    const previous = autoArrangeUndo.current;
    if (!previous) return;
    hasUserManuallyAdjustedView.current = true;
    setLabelPositions(previous.labelPositions);
    setNodePositions(previous.nodePositions);
    panRef.current = previous.pan;
    zoomRef.current = previous.zoom;
    setPan(previous.pan);
    setZoom(previous.zoom);
    autoArrangeUndo.current = null;
    setCanUndoAutoArrange(false);
  };

  const clearAutoArrangeUndo = () => {
    if (!autoArrangeUndo.current) return;
    autoArrangeUndo.current = null;
    setCanUndoAutoArrange(false);
  };

  const centerMapOn = useCallback((position: LabelPosition) => {
    const surface = mapSurfaceRef.current;
    const plane = graphPlaneRef.current;
    if (!surface || !plane) return;
    const nextPan = {
      x: surface.clientWidth / 2 - plane.offsetLeft - ((plane.offsetWidth * position.x) / 100) * zoomRef.current,
      y: surface.clientHeight / 2 - plane.offsetTop - ((plane.offsetHeight * position.y) / 100) * zoomRef.current,
    };
    panRef.current = nextPan;
    setPan(nextPan);
  }, []);

  const centerSelectedSource = () => {
    if (!selectedGraphCallout) return;
    const index = graphCallouts.findIndex((callout) => callout.sourceIp === selectedGraphCallout.sourceIp);
    if (index < 0) return;
    centerMapOn(positionForCallout(selectedGraphCallout, index));
  };

  // Keep camera steady; only bring target node into view when hop changes AND it is outside the viewport
  const lastCenteredHopEventId = useRef<string | null>(null);
  useEffect(() => {
    if (!activeHop?.eventId || !activeHop?.toPath) return;
    if (activeHop.eventId === lastCenteredHopEventId.current) return;
    lastCenteredHopEventId.current = activeHop.eventId;

    // Never auto-center while user is actively dragging or interacting with the canvas
    if (nodeDrag.current || labelDrag.current || isDraggingSurface) return;

    const targetNode = graphNodeByPath.get(activeHop.toPath);
    if (!targetNode) return;

    const surface = mapSurfaceRef.current;
    const plane = graphPlaneRef.current;
    if (!surface || !plane) return;

    const screenX = (plane.offsetWidth * targetNode.x / 100) * zoomRef.current + panRef.current.x;
    const screenY = (plane.offsetHeight * targetNode.y / 100) * zoomRef.current + panRef.current.y;

    const margin = 60;
    const isVisible =
      screenX >= margin &&
      screenX <= surface.clientWidth - margin &&
      screenY >= margin &&
      screenY <= surface.clientHeight - margin;

    if (!isVisible) {
      centerMapOn(targetNode);
    }
  }, [activeHop?.eventId, activeHop?.toPath, centerMapOn, graphNodeByPath, isDraggingSurface]);

  // Label dragging handlers
  const onCalloutPointerDown = (event: ReactPointerEvent<HTMLButtonElement>, sourceIp: string, origin: LabelPosition) => {
    event.stopPropagation();
    event.currentTarget.focus();
    suppressCalloutClick.current = false;
    event.currentTarget.setPointerCapture(event.pointerId);
    labelDrag.current = { sourceIp, startX: event.clientX, startY: event.clientY, origin };
    setDraggedCalloutIp(sourceIp);
  };

  const onCalloutPointerMove = (event: ReactPointerEvent<HTMLButtonElement>) => {
    const dragging = labelDrag.current;
    const plane = graphPlaneRef.current;
    if (!dragging || !plane) return;
    const rect = plane.getBoundingClientRect();
    if (!rect.width || !rect.height) return;
    const deltaX = ((event.clientX - dragging.startX) / rect.width) * 100;
    const deltaY = ((event.clientY - dragging.startY) / rect.height) * 100;
    if (Math.abs(deltaX) > 0.25 || Math.abs(deltaY) > 0.25) {
      suppressCalloutClick.current = true;
      clearAutoArrangeUndo();
    }
    setLabelPositions((current) => ({
      ...current,
      [dragging.sourceIp]: {
        x: unrestrictedNodeCoordinate(dragging.origin.x + deltaX),
        y: unrestrictedNodeCoordinate(dragging.origin.y + deltaY),
      },
    }));
  };

  const onCalloutPointerEnd = (event: ReactPointerEvent<HTMLButtonElement>) => {
    const dragging = labelDrag.current;
    if (dragging) {
      setLabelPositions((current) => ({
        ...current,
        [dragging.sourceIp]: current[dragging.sourceIp] ?? dragging.origin,
      }));
    }
    labelDrag.current = null;
    setDraggedCalloutIp(null);
    if (event.currentTarget.hasPointerCapture(event.pointerId)) {
      event.currentTarget.releasePointerCapture(event.pointerId);
    }
  };

  // Manual node placement is unconstrained by the automatic tree layout.
  const onNodePointerDown = (event: ReactPointerEvent<HTMLButtonElement>, path: string, origin: LabelPosition) => {
    event.stopPropagation();
    event.currentTarget.focus();
    suppressNodeClick.current = false;
    event.currentTarget.setPointerCapture(event.pointerId);
    nodeDrag.current = { path, startX: event.clientX, startY: event.clientY, origin };
    setDraggedNodePath(path);
  };

  const onNodePointerMove = (event: ReactPointerEvent<HTMLButtonElement>) => {
    const dragging = nodeDrag.current;
    const plane = graphPlaneRef.current;
    if (!dragging || !plane) return;
    const rect = plane.getBoundingClientRect();
    if (!rect.width || !rect.height) return;
    const deltaX = ((event.clientX - dragging.startX) / rect.width) * 100;
    const deltaY = ((event.clientY - dragging.startY) / rect.height) * 100;
    if (Math.abs(deltaX) > 0.2 || Math.abs(deltaY) > 0.2) {
      suppressNodeClick.current = true;
      clearAutoArrangeUndo();
    }
    setNodePositions((current) => ({
      ...current,
      [dragging.path]: {
        x: unrestrictedNodeCoordinate(dragging.origin.x + deltaX),
        y: unrestrictedNodeCoordinate(dragging.origin.y + deltaY),
      },
    }));
  };

  const onNodePointerEnd = (event: ReactPointerEvent<HTMLButtonElement>) => {
    nodeDrag.current = null;
    setDraggedNodePath(null);
    if (event.currentTarget.hasPointerCapture(event.pointerId)) {
      event.currentTarget.releasePointerCapture(event.pointerId);
    }
  };

  // Surface pan handlers
  const onPointerDown = (event: ReactPointerEvent<HTMLDivElement>) => {
    if ((event.target as HTMLElement).closest("button")) return;
    event.currentTarget.setPointerCapture(event.pointerId);
    dragStart.current = { x: event.clientX, y: event.clientY, pan: panRef.current };
    setIsDraggingSurface(true);
  };

  const onPointerMove = (event: ReactPointerEvent<HTMLDivElement>) => {
    if (!dragStart.current) return;
    const deltaX = event.clientX - dragStart.current.x;
    const deltaY = event.clientY - dragStart.current.y;
    if (Math.abs(deltaX) > 3 || Math.abs(deltaY) > 3) {
      hasUserManuallyAdjustedView.current = true;
    }
    const nextPan = {
      x: dragStart.current.pan.x + deltaX,
      y: dragStart.current.pan.y + deltaY,
    };
    panRef.current = nextPan;
    setPan(nextPan);
  };

  const onPointerEnd = (event: ReactPointerEvent<HTMLDivElement>) => {
    dragStart.current = null;
    setIsDraggingSurface(false);
    if (event.currentTarget.hasPointerCapture(event.pointerId)) {
      event.currentTarget.releasePointerCapture(event.pointerId);
    }
  };

  // Keyboard navigation
  const onSurfaceKeyDown = (event: React.KeyboardEvent<HTMLDivElement>) => {
    if (["ArrowUp", "ArrowDown", "ArrowLeft", "ArrowRight"].includes(event.key)) {
      event.preventDefault();
      hasUserManuallyAdjustedView.current = true;
      const step = 40;
      setPan((current) => {
        const next = {
          x: event.key === "ArrowLeft" ? current.x + step : event.key === "ArrowRight" ? current.x - step : current.x,
          y: event.key === "ArrowUp" ? current.y + step : event.key === "ArrowDown" ? current.y - step : current.y,
        };
        panRef.current = next;
        return next;
      });
    }
  };

  // Wheel zoom
  useEffect(() => {
    const surface = mapSurfaceRef.current;
    if (!surface) return;
    const onWheel = (event: WheelEvent) => {
      const plane = graphPlaneRef.current;
      if (!plane) return;
      event.preventDefault();
      hasUserManuallyAdjustedView.current = true;
      const bounds = surface.getBoundingClientRect();
      setMapZoom(zoomRef.current * Math.exp(-event.deltaY * 0.0015), {
        x: event.clientX - bounds.left - plane.offsetLeft,
        y: event.clientY - bounds.top - plane.offsetTop,
      });
    };
    surface.addEventListener("wheel", onWheel, { passive: false });
    return () => surface.removeEventListener("wheel", onWheel);
  }, [isTopologyExpanded, setMapZoom, snapshot?.nodes.length]);

  // Touch pinch zoom
  useEffect(() => {
    const surface = mapSurfaceRef.current;
    if (!surface) return;
    let initialDistance: number | null = null;
    let initialZoom = 1;

    const onTouchStart = (e: TouchEvent) => {
      if (e.touches.length === 2) {
        const dx = e.touches[0].clientX - e.touches[1].clientX;
        const dy = e.touches[0].clientY - e.touches[1].clientY;
        initialDistance = Math.hypot(dx, dy);
        initialZoom = zoomRef.current;
      }
    };

    const onTouchMove = (e: TouchEvent) => {
      if (e.touches.length === 2 && initialDistance) {
        e.preventDefault();
        hasUserManuallyAdjustedView.current = true;
        const dx = e.touches[0].clientX - e.touches[1].clientX;
        const dy = e.touches[0].clientY - e.touches[1].clientY;
        const currentDistance = Math.hypot(dx, dy);
        const factor = currentDistance / initialDistance;
        setMapZoom(initialZoom * factor);
      }
    };

    const onTouchEnd = (e: TouchEvent) => {
      if (e.touches.length < 2) initialDistance = null;
    };

    surface.addEventListener("touchstart", onTouchStart, { passive: true });
    surface.addEventListener("touchmove", onTouchMove, { passive: false });
    surface.addEventListener("touchend", onTouchEnd, { passive: true });

    return () => {
      surface.removeEventListener("touchstart", onTouchStart);
      surface.removeEventListener("touchmove", onTouchMove);
      surface.removeEventListener("touchend", onTouchEnd);
    };
  }, [setMapZoom]);

  // ResizeObserver for metrics and responsive auto-fit viewport
  useEffect(() => {
    const surface = mapSurfaceRef.current;
    const plane = graphPlaneRef.current;
    if (!surface || !plane) return;
    const handleResize = () => {
      setMapMetrics({
        surfaceWidth: surface.clientWidth,
        surfaceHeight: surface.clientHeight,
        planeWidth: plane.offsetWidth,
        planeHeight: plane.offsetHeight,
        planeLeft: plane.offsetLeft,
        planeTop: plane.offsetTop,
      });

      // Automatically fit camera if the user hasn't manually panned or zoomed
      if (!hasUserManuallyAdjustedView.current) {
        const fit = calculateFitViewport(surface, plane);
        if (fit) {
          if (
            Math.abs(panRef.current.x - fit.pan.x) > 1 ||
            Math.abs(panRef.current.y - fit.pan.y) > 1 ||
            Math.abs(zoomRef.current - fit.zoom) > 0.005
          ) {
            panRef.current = fit.pan;
            zoomRef.current = fit.zoom;
            setPan(fit.pan);
            setZoom(fit.zoom);
          }
        }
      }
    };
    handleResize();
    const observer = new ResizeObserver(handleResize);
    observer.observe(surface);
    observer.observe(plane);
    return () => observer.disconnect();
  }, [calculateFitViewport, isTopologyExpanded, snapshot?.nodes.length]);

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
      <div className="flex shrink-0 flex-col gap-2.5 border-b border-border px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="min-w-0 flex-1 pr-3">
          <div className="flex items-center gap-2">
            <Route className="h-4 w-4 shrink-0 text-primary" aria-hidden="true" />
            <h2 className="truncate font-semibold text-text text-sm sm:text-base">{title ?? "Live filesystem topology"}</h2>
          </div>
          <p className="mt-0.5 truncate text-xs text-text-subtle">
            {subtitle ?? "Observed paths form the topology; compact source-IP clusters point to their most recently verified location."}
          </p>
        </div>

        {/* Toolbar Buttons: ALWAYS single row with flex-nowrap */}
        <div className="flex shrink-0 items-center gap-1 flex-nowrap">
          <button
            type="button"
            className="ui-button h-8 min-h-8 w-8 p-0"
            title="Zoom out"
            aria-label="Zoom out"
            onClick={() => {
              hasUserManuallyAdjustedView.current = true;
              setMapZoom(zoomRef.current - 0.1);
            }}
          >
            <ZoomOut className="h-3.5 w-3.5" />
          </button>
          <span
            className="ui-badge h-8 min-w-11 justify-center px-1 font-mono text-xs tabular-nums"
            aria-live="polite"
            aria-label={`Zoom ${Math.round(zoom * 100)} percent`}
          >
            {Math.round(zoom * 100)}%
          </span>
          <button
            type="button"
            className="ui-button h-8 min-h-8 w-8 p-0"
            title="Zoom in"
            aria-label="Zoom in"
            onClick={() => {
              hasUserManuallyAdjustedView.current = true;
              setMapZoom(zoomRef.current + 0.1);
            }}
          >
            <ZoomIn className="h-3.5 w-3.5" />
          </button>

          <div className="mx-0.5 h-4 w-px bg-border" />

          <button
            type="button"
            className="ui-button h-8 min-h-8 w-8 p-0"
            title="Reset view"
            aria-label="Reset map view"
            onClick={fitTopology}
          >
            <ScanLine className="h-3.5 w-3.5" />
          </button>
          <button
            type="button"
            className="ui-button h-8 min-h-8 w-8 p-0"
            title="Center selected IP"
            aria-label="Center selected IP"
            disabled={!selectedGraphCallout}
            onClick={() => {
              hasUserManuallyAdjustedView.current = true;
              centerSelectedSource();
            }}
          >
            <LocateFixed className="h-3.5 w-3.5" />
          </button>
          <button
            type="button"
            className="ui-button h-8 min-h-8 w-8 p-0"
            title="Auto arrange topology"
            aria-label="Auto arrange directory and IP labels"
            onClick={autoArrangeTopology}
          >
            <MousePointer2 className="h-3.5 w-3.5" />
          </button>
          {canUndoAutoArrange && (
            <button
              type="button"
              className="ui-button h-8 min-h-8 w-8 p-0"
              title="Undo auto arrange"
              aria-label="Undo auto arrange"
              onClick={undoAutoArrangeTopology}
            >
              <Undo2 className="h-3.5 w-3.5" />
            </button>
          )}
          <button
            type="button"
            className="ui-button h-8 min-h-8 w-8 p-0"
            title="Restore default workspace"
            aria-label="Restore default map view and layout"
            onClick={resetMapWorkspace}
          >
            <RotateCcw className="h-3.5 w-3.5" />
          </button>

          <div className="mx-0.5 h-4 w-px bg-border" />

          <button
            type="button"
            className="ui-button h-8 min-h-8 w-8 p-0"
            title={
              isTopologyExpanded
                ? isAuditMode
                  ? "Exit fullscreen audit studio"
                  : "Exit expanded map"
                : isAuditMode
                  ? "Open fullscreen audit studio"
                  : "Expand map workspace"
            }
            aria-label={
              isTopologyExpanded
                ? isAuditMode
                  ? "Exit fullscreen audit studio"
                  : "Exit expanded map"
                : isAuditMode
                  ? "Open fullscreen audit studio"
                  : "Expand map workspace"
            }
            aria-pressed={isTopologyExpanded}
            onClick={handleToggleExpand}
          >
            {isTopologyExpanded ? <Minimize2 className="h-3.5 w-3.5" /> : <Maximize2 className="h-3.5 w-3.5" />}
          </button>
        </div>
      </div>

      {regionStatus === "error" ? (
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
          <RegionState
            kind="empty"
            title="No observed working directories yet"
            description="The live view will populate after verified CWD telemetry is recorded."
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
                <div className="pointer-events-none absolute left-5 top-5 flex items-center gap-2 text-xs text-text-subtle">
                  <Grip className="h-3.5 w-3.5" aria-hidden="true" />
                  Drag surface to pan · Scroll or pinch to zoom · Drag directory or IP nodes beyond the tree frame · Use reset to recover
                </div>
                <motion.div
                  ref={graphPlaneRef}
                  className="relative min-h-[500px] min-w-[860px] origin-top-left overflow-visible"
                  animate={reducedMotion ? undefined : { x: pan.x, y: pan.y, scale: zoom }}
                  style={
                    reducedMotion
                      ? {
                          minHeight: graphPlaneHeight,
                          minWidth: 860,
                          height: isTopologyExpanded ? "100%" : undefined,
                          transform: `translate(${pan.x}px, ${pan.y}px) scale(${zoom})`,
                        }
                      : { minHeight: graphPlaneHeight, minWidth: 860, height: isTopologyExpanded ? "100%" : undefined }
                  }
                  transition={
                    reducedMotion || isDraggingSurface || isResizingContainer
                      ? { duration: 0 }
                      : { type: "spring", stiffness: 260, damping: 28 }
                  }
                >
                  <svg viewBox="0 0 100 100" preserveAspectRatio="none" className="pointer-events-none absolute inset-0 h-full w-full overflow-visible" aria-hidden="true">
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

                        return (
                          <motion.g
                            key={`${parent.path}-${node.path}`}
                            initial={reducedMotion ? false : { opacity: 0 }}
                            animate={{ opacity: 1 }}
                            exit={reducedMotion ? undefined : { opacity: 0 }}
                            transition={reducedMotion ? { duration: 0 } : { duration: 0.3, ease: "easeOut" }}
                          >
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
                                  ? "var(--primary)"
                                  : isTrailEdge
                                    ? "var(--primary)"
                                    : "var(--border-strong)"
                              }
                              strokeWidth={
                                isActiveHopEdge
                                  ? "0.65"
                                  : isTrailEdge
                                    ? "0.45"
                                    : "0.35"
                              }
                              strokeOpacity={
                                isActiveHopEdge
                                  ? 1
                                  : isTrailEdge
                                    ? 0.75
                                    : 0.4
                              }
                              strokeDasharray={
                                isActiveHopEdge
                                  ? "none"
                                  : isTrailEdge
                                    ? "1.2 0.8"
                                    : "none"
                              }
                            />
                            {isActiveHopEdge && (
                              <motion.path
                                initial={false}
                                animate={{ d: filesystemRoute }}
                                transition={
                                  reducedMotion || Boolean(draggedNodePath)
                                    ? { duration: 0 }
                                    : TOPOLOGY_TRANSITION
                                }
                                fill="none"
                                stroke="var(--primary)"
                                strokeWidth="1.2"
                                strokeOpacity={0.3}
                                className="animate-pulse"
                              />
                            )}
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
                        const targetPaths = selectedSource
                          ? [...new Set(callout.sessionIds.map((sessionId) => liveSessionById.get(sessionId)?.cwdState.path).filter((path): path is string => Boolean(path)))]
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
                              const focused = selectedSource;
                              const endpoint = leaderEndpoints(
                                node,
                                position,
                                nodeElementBounds[node.path],
                                calloutElementBounds[callout.sourceIp],
                              );
                              const controlX = (endpoint.startX + endpoint.endX) / 2;
                              const routePath = `M ${endpoint.startX} ${endpoint.startY} C ${controlX} ${endpoint.startY}, ${controlX} ${endpoint.endY}, ${endpoint.endX} ${endpoint.endY}`;
                              return (
                                <g key={`${callout.sourceIp}-route-${routeIndex}`}>
                                  <motion.path
                                    initial={false}
                                    animate={{ d: routePath }}
                                    transition={
                                      reducedMotion || Boolean(draggedNodePath || draggedCalloutIp)
                                        ? { duration: 0 }
                                        : TOPOLOGY_TRANSITION
                                    }
                                    fill="none"
                                    stroke={focused ? "var(--primary)" : "var(--border-strong)"}
                                    strokeOpacity={focused ? 1 : 0.52}
                                    strokeWidth={focused ? "0.42" : "0.24"}
                                    strokeDasharray={focused ? "none" : "0.75 1.6"}
                                  />
                                  <motion.circle
                                    initial={false}
                                    animate={{ cx: endpoint.startX, cy: endpoint.startY }}
                                    transition={
                                      reducedMotion || Boolean(draggedNodePath || draggedCalloutIp)
                                        ? { duration: 0 }
                                        : TOPOLOGY_TRANSITION
                                    }
                                    r={focused ? "1.05" : "0.5"}
                                    fill={focused ? "var(--surface)" : "var(--border-strong)"}
                                    fillOpacity={focused ? 1 : 0.68}
                                    stroke={focused ? "var(--primary)" : "var(--border-strong)"}
                                    strokeOpacity={focused ? 1 : 0.55}
                                    strokeWidth={focused ? "0.48" : "0.18"}
                                  />
                                </g>
                              );
                            })}
                          </motion.g>
                        );
                      })}
                    </AnimatePresence>
                  </svg>
                  <AnimatePresence initial={false}>
                    {graphNodes.map((node) => {
                    const isSelected = node.path === selectedPath;
                    const isRoot = node.path === "/";
                    const isSensitive = isSensitiveDirectory(node.path);
                    const isHopTarget = activeHop?.toPath === node.path;
                    const isHopVisited = Boolean(activeHop?.visitedPaths.includes(node.path));
                    const visitedStep = activeHop?.visitedStepMap[node.path];

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
                        aria-label={`Inspect directory ${node.path}${isSensitive ? " (sensitive target)" : ""}${
                          isHopTarget && activeHop ? ` (active hop target ${activeHop.stepIndex + 1} of ${activeHop.totalSteps})` : ""
                        }`}
                        title={node.path}
                        onPointerDown={(event) => onNodePointerDown(event, node.path, node)}
                        onPointerMove={onNodePointerMove}
                        onPointerUp={onNodePointerEnd}
                        onPointerCancel={onNodePointerEnd}
                        onClick={() => {
                          if (suppressNodeClick.current) {
                            suppressNodeClick.current = false;
                            return;
                          }
                          onSelectPath(node.path);
                        }}
                        className={`absolute flex max-w-56 -translate-x-1/2 -translate-y-1/2 touch-none items-center gap-1.5 rounded-lg border px-2.5 py-1.5 text-left shadow-sm transition-colors duration-200 ${
                          isHopTarget && activeHop?.isFailedAttempt
                            ? "z-20 border-warning bg-warning-subtle text-text ring-2 ring-warning ring-offset-2 ring-offset-surface shadow-md shadow-warning/20"
                            : isHopTarget
                              ? "z-20 border-primary bg-primary-subtle text-text ring-2 ring-primary ring-offset-2 ring-offset-surface shadow-md shadow-primary/20"
                              : isSelected
                                ? "z-10 border-primary-border bg-primary-subtle text-text ring-1 ring-primary/40"
                                : isHopVisited
                                  ? "z-10 border-primary/40 bg-surface text-text hover:border-primary/70 hover:bg-surface-hover"
                                  : isSensitive
                                    ? "z-10 border-warning-border/80 bg-surface text-text hover:border-warning hover:bg-surface-hover"
                                    : "z-10 border-border bg-surface text-text hover:border-border-strong hover:bg-surface-hover"
                        }`}
                      >
                        {isHopTarget && !reducedMotion && (
                          <span
                            className={`pointer-events-none absolute -inset-1 animate-ping rounded-lg border-2 opacity-40 ${
                              activeHop?.isFailedAttempt ? "border-warning/70" : "border-primary/50"
                            }`}
                            aria-hidden="true"
                          />
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
                            className={`flex shrink-0 items-center gap-0.5 rounded px-1.5 py-0.5 font-mono text-[10px] font-bold shadow-xs ${
                              activeHop.isFailedAttempt ? "bg-warning text-surface" : "bg-primary text-surface"
                            }`}
                            title={
                              activeHop.isFailedAttempt
                                ? `Attempted move failed (stayed at ${node.path})`
                                : `Current hop target (${activeHop.stepIndex + 1}/${activeHop.totalSteps})`
                            }
                          >
                            <Route className="h-2.5 w-2.5" aria-hidden="true" />
                            {activeHop.isFailedAttempt ? `Failed #${activeHop.stepIndex + 1}` : `Hop ${activeHop.stepIndex + 1}`}
                          </span>
                        ) : isHopVisited && visitedStep !== undefined ? (
                          <span
                            className="shrink-0 rounded border border-primary/30 bg-primary/10 px-1 py-0.5 font-mono text-[10px] font-semibold text-primary"
                            title={`Route step ${visitedStep}`}
                          >
                            #{visitedStep}
                          </span>
                        ) : null}
                        <span className="rounded-full border border-border bg-surface-subtle px-1.5 text-[11px] font-semibold text-text-subtle">
                          {node.sessionIds.length}
                        </span>
                      </motion.button>
                    );
                    })}
                  </AnimatePresence>
                  <AnimatePresence initial={false}>
                    {graphCallouts.map((callout, index) => {
                    const position = positionForCallout(callout, index);
                    const selected = callout.sessionIds.includes(selectedSessionId ?? "");
                    return (
                      <motion.button
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
                        type="button"
                        aria-pressed={selected}
                        aria-label={`Inspect source ${callout.sourceIp}; ${callout.sessionIds.length} ${
                          callout.sessionIds.length === 1 ? "session" : "sessions"
                        }`}
                        onPointerDown={(event) => onCalloutPointerDown(event, callout.sourceIp, position)}
                        onPointerMove={onCalloutPointerMove}
                        onPointerUp={onCalloutPointerEnd}
                        onPointerCancel={onCalloutPointerEnd}
                        onClick={() => {
                          if (suppressCalloutClick.current) {
                            suppressCalloutClick.current = false;
                            return;
                          }
                          onSelectSession(callout.sessionIds[0]);
                        }}
                        className={`absolute z-40 flex w-44 -translate-x-1/2 -translate-y-1/2 touch-none items-center gap-2 rounded-lg border px-2.5 py-2 text-left shadow-sm transition-colors duration-200 ${
                          selected
                            ? "border-primary-border bg-primary-subtle"
                            : "border-border bg-surface hover:border-border-strong hover:bg-surface-hover"
                        }`}
                      >
                        <span
                          className={`h-2 w-2 shrink-0 rounded-full ${
                            streamState === "live" ? "bg-success" : "bg-warning"
                          }`}
                          aria-hidden="true"
                        />
                        <span className="min-w-0">
                          <span className="block truncate font-mono text-xs text-text">{callout.sourceIp}</span>
                          <span className="mt-0.5 flex items-center gap-1 text-[11px] text-text-subtle">
                            <span>
                              {callout.sessionIds.length} {callout.sessionIds.length === 1 ? "session" : "sessions"}
                            </span>
                          </span>
                        </span>
                      </motion.button>
                    );
                    })}
                  </AnimatePresence>
                </motion.div>

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
              </div>

              <div className="flex shrink-0 flex-wrap items-center gap-x-5 gap-y-2 border-t border-border px-5 py-3 text-xs text-text-muted">
                <span>
                  <strong className="text-text">{snapshot.nodes.length}</strong> observed paths
                </span>
                <span>
                  <strong className="text-text">{snapshot.sessions.length}</strong> sessions with a known CWD
                </span>
                <span>
                  <strong className="text-text">{liveSourceCount}</strong> live {liveSourceCount === 1 ? "source" : "sources"}
                </span>
                <span>Snapshot {formatTimestamp(snapshot.generatedAt)}</span>
                <span className="flex items-center gap-3 sm:ml-auto" aria-label="Topology map legend">
                  <span className="flex items-center gap-1.5">
                    <span className="h-px w-3 bg-border-strong" aria-hidden="true" />
                    Filesystem route
                  </span>
                  <span className="flex items-center gap-1.5">
                    <span className="h-1.5 w-3 rounded-full bg-primary" aria-hidden="true" />
                    Selected source route
                  </span>
                </span>
              </div>
              {snapshot.truncated && (
                <div className="flex shrink-0 gap-2 border-t border-warning-border bg-warning-subtle px-5 py-3 text-xs text-text-muted">
                  <ShieldAlert className="h-4 w-4 shrink-0 text-warning" aria-hidden="true" />
                  <p>
                    Showing the latest {snapshot.sessions.length} observed sessions. Older sessions are not included in
                    this live topology.
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
                    <h3 className="mt-1 font-semibold text-text">Live source clusters</h3>
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
                  Choose an IP to fan its leader line out to every current verified path. Drag directories and IP labels
                  on the map to arrange them. Auto arrange rebuilds the subtree layout, returns sources to their rails,
                  and recenters the camera; undo restores this workspace. Press Escape to exit this workspace.
                </p>
                <button type="button" className="ui-button mt-4 w-full" onClick={autoArrangeTopology}>
                  <ScanLine className="h-4 w-4" />
                  Auto arrange topology
                </button>
                {canUndoAutoArrange && (
                  <button type="button" className="ui-button mt-2 w-full" onClick={undoAutoArrangeTopology}>
                    <Undo2 className="h-4 w-4" />
                    Undo auto arrange
                  </button>
                )}
                <button type="button" className="ui-button mt-2 w-full" onClick={resetMapWorkspace}>
                  <RotateCcw className="h-4 w-4" />
                  Restore default workspace
                </button>
                <div className="mt-5 space-y-2">
                  {graphCallouts.map((callout) => {
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
                          <span className="ui-badge border-info-border bg-info-subtle text-info">
                            {callout.sessionIds.length}
                          </span>
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
                              <span className="mt-0.5 block truncate font-mono text-[11px] text-text-subtle">
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
